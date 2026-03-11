//! eBPF capability detection.
//!
//! Probes the system for eBPF prerequisites without requiring the `ebpf`
//! feature flag. This allows `oaie doctor` to report eBPF availability
//! even when the binary was built without eBPF support.

use std::path::Path;

/// System capabilities for eBPF tracing.
#[derive(Clone, Debug)]
pub struct EbpfCaps {
    /// Whether the kernel supports BPF ring buffers (kernel >= 5.8).
    pub kernel_supports_ringbuf: bool,
    /// Whether BTF type information is available at `/sys/kernel/btf/vmlinux`.
    pub btf_available: bool,
    /// Whether oaie-priv has CAP_BPF and CAP_PERFMON capabilities.
    pub priv_has_bpf_caps: bool,
    /// Whether all prerequisites are met for eBPF tracing.
    pub available: bool,
}

/// Detect eBPF capabilities on the current system.
///
/// Checks kernel version (>= 5.8 for ring buffer), BTF availability,
/// and oaie-priv capabilities. No heavy dependencies — always compiled.
pub fn detect_ebpf() -> EbpfCaps {
    let kernel_supports_ringbuf = check_kernel_ringbuf_support();
    let btf_available = Path::new("/sys/kernel/btf/vmlinux").exists();
    let priv_has_bpf_caps = check_priv_bpf_caps();

    let available = kernel_supports_ringbuf && btf_available && priv_has_bpf_caps;

    EbpfCaps {
        kernel_supports_ringbuf,
        btf_available,
        priv_has_bpf_caps,
        available,
    }
}

/// Check if the kernel version is >= 5.8 (BPF ring buffer support).
fn check_kernel_ringbuf_support() -> bool {
    let Ok(info) = nix::sys::utsname::uname() else {
        return false;
    };
    let release = info.release().to_string_lossy();
    parse_kernel_version(&release)
        .map(|(major, minor)| (major, minor) >= (5, 8))
        .unwrap_or(false)
}

/// Parse kernel version from a release string like "6.8.0-101-generic".
fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor_str = parts.next()?;
    // Minor may contain non-digit suffix (e.g. "8" or "8-rc1").
    let minor: u32 = minor_str
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()?;
    Some((major, minor))
}

/// Check if oaie-priv has CAP_BPF and CAP_PERFMON capabilities.
///
/// Uses `getcap` to read the capabilities of the installed binary.
/// Also accepts `cap_sys_admin` which implies both.
fn check_priv_bpf_caps() -> bool {
    let priv_path = Path::new("/usr/lib/oaie/oaie-priv");
    if !priv_path.exists() {
        return false;
    }

    let output = match std::process::Command::new("getcap")
        .arg(priv_path)
        .output()
    {
        Ok(o) => o,
        Err(_) => return false,
    };

    let caps = String::from_utf8_lossy(&output.stdout);
    let caps_lower = caps.to_lowercase();

    // cap_sys_admin implies BPF capabilities.
    if caps_lower.contains("cap_sys_admin") {
        return true;
    }

    // Check for explicit BPF-related capabilities.
    caps_lower.contains("cap_bpf") && caps_lower.contains("cap_perfmon")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_kernel_version() {
        assert_eq!(parse_kernel_version("6.8.0-101-generic"), Some((6, 8)));
        assert_eq!(parse_kernel_version("5.8.0"), Some((5, 8)));
        assert_eq!(parse_kernel_version("5.7.99"), Some((5, 7)));
        assert_eq!(parse_kernel_version("4.15.0-213-generic"), Some((4, 15)));
        assert_eq!(parse_kernel_version(""), None);
        assert_eq!(parse_kernel_version("abc"), None);
    }
}
