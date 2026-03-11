//! Firecracker prerequisite detection.
//!
//! Checks whether the system can run Firecracker microVMs:
//! - Firecracker binary found (configurable path, then PATH)
//! - /dev/kvm accessible (KVM support required)
//! - Guest assets present (kernel, rootfs, oaie-guest agent)

use std::path::{Path, PathBuf};
use std::process::Command;

/// Known locations to search for the Firecracker binary.
/// Also checks `$HOME/tools/firecracker` at runtime (see `detect()`).
const FIRECRACKER_SEARCH_PATHS: &[&str] = &[
    "/usr/local/bin/firecracker",
    "/usr/bin/firecracker",
];

/// Result of Firecracker prerequisite detection.
#[derive(Clone, Debug)]
pub struct FirecrackerCaps {
    /// Whether all prerequisites are met.
    pub available: bool,

    /// Path to the Firecracker binary, if found.
    pub firecracker_path: Option<PathBuf>,

    /// Firecracker version string (e.g. "1.10.0").
    pub firecracker_version: Option<String>,

    /// Whether /dev/kvm is accessible.
    pub kvm_available: bool,

    /// Path to the kernel image, if found.
    pub kernel_path: Option<PathBuf>,

    /// Path to the rootfs image, if found.
    pub rootfs_path: Option<PathBuf>,

    /// Path to the oaie-guest binary, if found.
    pub guest_agent_path: Option<PathBuf>,

    /// Human-readable issues preventing Firecracker use.
    pub issues: Vec<String>,
}

/// Directory where Firecracker assets are stored.
pub fn assets_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    PathBuf::from(home).join(".oaie").join("firecracker")
}

/// Detect Firecracker capabilities on this system.
pub fn detect() -> FirecrackerCaps {
    let mut caps = FirecrackerCaps {
        available: false,
        firecracker_path: None,
        firecracker_version: None,
        kvm_available: false,
        kernel_path: None,
        rootfs_path: None,
        guest_agent_path: None,
        issues: Vec::new(),
    };

    // 1. Find Firecracker binary.
    caps.firecracker_path = find_firecracker_binary();
    if let Some(ref path) = caps.firecracker_path {
        caps.firecracker_version = get_firecracker_version(path);
    } else {
        caps.issues.push("Firecracker binary not found".into());
    }

    // 2. Check /dev/kvm.
    caps.kvm_available = check_kvm();
    if !caps.kvm_available {
        caps.issues
            .push("/dev/kvm not accessible (KVM required)".into());
    }

    // 3. Check guest assets.
    let assets = assets_dir();
    let kernel = assets.join("vmlinux");
    let rootfs = assets.join("rootfs.ext4");
    let guest = assets.join("oaie-guest");

    if kernel.exists() {
        caps.kernel_path = Some(kernel);
    } else {
        caps.issues.push(format!(
            "Kernel image not found at {}",
            kernel.display()
        ));
    }

    if rootfs.exists() {
        caps.rootfs_path = Some(rootfs);
    } else {
        caps.issues.push(format!(
            "Root filesystem not found at {}",
            rootfs.display()
        ));
    }

    if guest.exists() {
        caps.guest_agent_path = Some(guest);
    } else {
        caps.issues.push(format!(
            "Guest agent not found at {}",
            guest.display()
        ));
    }

    // Overall availability.
    caps.available = caps.firecracker_path.is_some()
        && caps.kvm_available
        && caps.kernel_path.is_some()
        && caps.rootfs_path.is_some()
        && caps.guest_agent_path.is_some();

    caps
}

/// Find the Firecracker binary by checking known paths, then PATH.
fn find_firecracker_binary() -> Option<PathBuf> {
    // Check $HOME/tools/firecracker (common developer setup).
    if let Ok(home) = std::env::var("HOME") {
        let home_fc = PathBuf::from(home).join("tools/firecracker");
        if home_fc.exists() && is_executable(&home_fc) {
            return Some(home_fc);
        }
    }

    // Check known system locations.
    for path in FIRECRACKER_SEARCH_PATHS {
        let p = Path::new(path);
        if p.exists() && is_executable(p) {
            return Some(p.to_path_buf());
        }
    }

    // Fall back to PATH lookup.
    which("firecracker")
}

/// Get the Firecracker version by running `firecracker --version`.
fn get_firecracker_version(path: &Path) -> Option<String> {
    let output = Command::new(path)
        .arg("--version")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Output format: "Firecracker v1.10.0\n..." — extract version.
    stdout
        .lines()
        .next()
        .and_then(|line| {
            line.strip_prefix("Firecracker v")
                .or_else(|| line.strip_prefix("firecracker "))
                .map(|v| v.trim().to_string())
        })
}

/// Check whether /dev/kvm is accessible for reading and writing.
fn check_kvm() -> bool {
    use std::fs::OpenOptions;
    // Just check that we can open it — don't need to actually do KVM ioctls.
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

/// Check if a path is an executable file.
fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            return meta.is_file() && meta.permissions().mode() & 0o111 != 0;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    false
}

/// Simple PATH-based executable lookup (avoids external `which` crate).
fn which(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var("PATH").ok()?;
    for dir in path_var.split(':') {
        let candidate = Path::new(dir).join(name);
        if candidate.exists() && is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assets_dir_is_under_home() {
        let dir = assets_dir();
        assert!(dir.to_str().unwrap().contains(".oaie/firecracker"));
    }

    #[test]
    fn detect_returns_issues_when_not_available() {
        // On most dev machines without full setup, detect() should report
        // issues for missing assets even if firecracker/kvm are present.
        let caps = detect();
        if !caps.available {
            assert!(!caps.issues.is_empty());
        }
    }

    #[test]
    fn is_executable_works() {
        // /bin/sh should be executable.
        assert!(is_executable(Path::new("/bin/sh")));
        // /etc/passwd should not be executable.
        assert!(!is_executable(Path::new("/etc/passwd")));
    }
}
