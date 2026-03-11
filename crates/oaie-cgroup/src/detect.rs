//! Cgroup v2 availability detection.
//!
//! Probes the system for cgroup v2 support, available creation methods
//! (systemd-run or oaie-priv), and which controllers are enabled.
//! Results are cached in a `OnceLock` for the process lifetime.

use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

/// Cached cgroup capabilities — probed once, reused for the process lifetime.
static CAPS: OnceLock<CgroupCaps> = OnceLock::new();

/// System capabilities for cgroup v2 isolation.
#[derive(Clone, Debug)]
pub struct CgroupCaps {
    /// Whether the kernel has a unified cgroup v2 hierarchy mounted.
    /// Checked by looking for `/sys/fs/cgroup/cgroup.controllers`.
    pub unified_v2: bool,
    /// Whether `systemd-run --user --scope` is available and working.
    pub systemd_run: bool,
    /// Whether the `oaie-priv` privileged helper is installed and responsive.
    pub oaie_priv: bool,
    /// The user's cgroup root path (e.g. `/sys/fs/cgroup/user.slice/user-1000.slice`).
    pub user_cgroup_root: Option<String>,
    /// Available cgroup v2 controllers (e.g. ["cpu", "memory", "pids", "io"]).
    pub controllers: Vec<String>,
    /// Whether eBPF tracing prerequisites are met (kernel 5.8+, BTF, caps).
    pub ebpf_available: bool,
}

/// Detect cgroup v2 capabilities. Cached after first call.
pub fn detect() -> &'static CgroupCaps {
    CAPS.get_or_init(detect_inner)
}

fn detect_inner() -> CgroupCaps {
    let unified_v2 = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();

    let controllers = if unified_v2 {
        read_controllers("/sys/fs/cgroup/cgroup.controllers")
    } else {
        vec![]
    };

    let user_cgroup_root = detect_user_cgroup_root();

    let systemd_run = unified_v2 && probe_systemd_run();

    let oaie_priv = probe_oaie_priv();

    let ebpf_available = crate::ebpf_detect::detect_ebpf().available;

    CgroupCaps {
        unified_v2,
        systemd_run,
        oaie_priv,
        user_cgroup_root,
        controllers,
        ebpf_available,
    }
}

/// Read available controllers from a cgroup.controllers file.
fn read_controllers(path: &str) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .split_whitespace()
        .map(String::from)
        .collect()
}

/// Find the user's cgroup root by reading `/proc/self/cgroup`.
///
/// In a unified v2 hierarchy, the file contains a single line like:
/// `0::/user.slice/user-1000.slice/session-2.scope`
fn detect_user_cgroup_root() -> Option<String> {
    let content = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    for line in content.lines() {
        // cgroup v2 unified: "0::/<path>"
        if let Some(path) = line.strip_prefix("0::") {
            let path = path.trim();
            if !path.is_empty() {
                return Some(format!("/sys/fs/cgroup{path}"));
            }
        }
    }
    None
}

/// Probe whether `systemd-run --user --scope` works.
///
/// Runs a quick test scope with `/bin/true` and checks the exit code.
/// Uses a PID-unique scope name to avoid collisions with concurrent probes.
/// Times out after 3 seconds to avoid hanging on broken systemd user sessions.
fn probe_systemd_run() -> bool {
    let pid = std::process::id();
    let unit_name = format!("oaie-probe-{pid}.scope");

    let child = Command::new("systemd-run")
        .args([
            "--user",
            "--scope",
            &format!("--unit={unit_name}"),
            "--quiet",
            "/bin/true",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Wait with 3-second timeout to avoid blocking on broken systemd sessions.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => return false,
        }
    }
}

/// Probe whether the oaie-priv helper is installed and responds to ping.
fn probe_oaie_priv() -> bool {
    let priv_path = Path::new("/usr/lib/oaie/oaie-priv");
    if !priv_path.exists() {
        return false;
    }

    // Try a ping via the priv client.
    crate::priv_client::ping().unwrap_or(false)
}
