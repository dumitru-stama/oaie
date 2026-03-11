//! System capability detection for namespace isolation.
//!
//! Probes the kernel to determine whether user namespaces are available
//! and what isolation level is achievable. Used by the Runner to decide
//! between sandboxed and unsandboxed execution, and by `oaie doctor`
//! to report system readiness.

use std::fs;
use std::path::Path;
use std::sync::OnceLock;

use nix::sys::utsname::uname;
use oaie_core::error::{OaieError, Result};
use oaie_core::manifest::IsolationLevel;

/// Cached system capabilities — avoids redundant `clone(CLONE_NEWUSER)` probes.
/// The first call performs the actual detection; subsequent calls return the
/// cached result. Safe across threads (OnceLock provides synchronization).
static CACHED_CAPS: OnceLock<SystemCaps> = OnceLock::new();

/// Detected system capabilities relevant to sandbox isolation.
#[derive(Debug, Clone)]
pub struct SystemCaps {
    /// Whether `clone(CLONE_NEWUSER)` succeeds on this kernel.
    pub user_ns: bool,
    /// Value of `/proc/sys/user/max_user_namespaces`, if readable.
    pub max_user_ns: Option<u64>,
    /// Current number of user namespaces in use on this system.
    /// Read from `/proc/sys/user/nr_user_namespaces` (kernel 6.7+).
    pub current_user_ns: Option<u64>,
    /// Kernel version as (major, minor).
    pub kernel_version: (u32, u32),
}

impl SystemCaps {
    /// Probe the running kernel for namespace support.
    ///
    /// Actually attempts `clone(CLONE_NEWUSER)` with a minimal child to
    /// confirm user namespace creation works — reading sysctl values alone
    /// isn't reliable (some distros enable the sysctl but block via LSM).
    ///
    /// Results are cached in a `OnceLock` — the probe runs once per process
    /// lifetime. At 500 concurrent runs, this avoids 500 redundant
    /// `clone(CLONE_NEWUSER) + waitpid` probes.
    pub fn detect() -> Self {
        CACHED_CAPS
            .get_or_init(|| {
                let user_ns = probe_userns();
                let max_user_ns = read_max_user_ns();
                let current_user_ns = read_current_user_ns();
                let kernel_version = read_kernel_version().unwrap_or((0, 0));
                Self {
                    user_ns,
                    max_user_ns,
                    current_user_ns,
                    kernel_version,
                }
            })
            .clone()
    }

    /// What isolation level is achievable on this system.
    pub fn isolation_level(&self) -> IsolationLevel {
        if self.user_ns {
            IsolationLevel::Full
        } else {
            IsolationLevel::None
        }
    }

    /// Returns a warning string if namespace usage exceeds 80% of the maximum.
    /// Used by the runner and doctor to alert before `clone()` starts failing
    /// with ENOSPC under high concurrency.
    pub fn namespace_headroom_warning(&self) -> Option<String> {
        let (current, max) = match (self.current_user_ns, self.max_user_ns) {
            (Some(c), Some(m)) if m > 0 => (c, m),
            _ => return None,
        };

        let usage_pct = (current as f64 / max as f64) * 100.0;
        if usage_pct > 80.0 {
            Some(format!(
                "namespace usage high: {current}/{max} ({usage_pct:.0}%). \
                 Increase with: sudo sysctl -w user.max_user_namespaces={}",
                max * 2
            ))
        } else {
            None
        }
    }

    /// Human-readable hint for fixing missing capabilities.
    /// Returns `None` if the system is fully capable.
    pub fn remediation_hint(&self) -> Option<String> {
        if self.user_ns {
            return None;
        }

        let mut hints = Vec::new();

        if let Some(max) = self.max_user_ns {
            if max == 0 {
                hints.push(
                    "User namespaces are disabled. Enable with:\n  \
                     sudo sysctl -w user.max_user_namespaces=65536"
                        .to_string(),
                );
            }
        }

        if is_inside_container() {
            hints.push(
                "Running inside a container. The container runtime may need \
                 --privileged or --security-opt seccomp=unconfined"
                    .to_string(),
            );
        }

        if hints.is_empty() {
            hints.push(
                "User namespace creation failed. Check:\n  \
                 - /proc/sys/user/max_user_namespaces (should be > 0)\n  \
                 - AppArmor/SELinux may restrict unprivileged userns\n  \
                 - On Ubuntu 24.04+: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"
                    .to_string(),
            );
        }

        Some(hints.join("\n\n"))
    }
}

/// Actually attempt `clone(CLONE_NEWUSER)` to verify user namespace support.
///
/// We use `clone3` via libc because reading sysctls alone is unreliable —
/// AppArmor, SELinux, or Yama can block userns even when the sysctl says yes.
fn probe_userns() -> bool {
    use nix::sched::CloneFlags;
    use nix::sys::wait::waitpid;

    // Allocate a small stack for the child (4 KiB is plenty for _exit).
    let mut stack = vec![0u8; 4096];

    // The child does nothing — just exits immediately.
    let child_fn = || -> isize { 0 };

    let flags = CloneFlags::CLONE_NEWUSER;

    // SAFETY: clone with CLONE_NEWUSER and a trivial child function.
    // The child calls _exit(0) immediately. We waitpid() below.
    match unsafe {
        nix::sched::clone(
            Box::new(child_fn),
            &mut stack,
            flags,
            Some(nix::sys::signal::Signal::SIGCHLD as i32),
        )
    } {
        Ok(pid) => {
            // Reap the child so we don't leak zombies.
            let _ = waitpid(pid, None);
            true
        }
        Err(_) => false,
    }
}

/// Read `/proc/sys/user/max_user_namespaces` if available.
pub fn read_max_user_ns() -> Option<u64> {
    fs::read_to_string("/proc/sys/user/max_user_namespaces")
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Read `/proc/sys/user/nr_user_namespaces` if available (kernel 6.7+).
fn read_current_user_ns() -> Option<u64> {
    fs::read_to_string("/proc/sys/user/nr_user_namespaces")
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Parse kernel version from uname into (major, minor).
fn read_kernel_version() -> Result<(u32, u32)> {
    let info = uname().map_err(|e| OaieError::SandboxError(format!("uname failed: {e}")))?;
    let release = info.release().to_string_lossy();
    parse_kernel_version(&release)
}

/// Parse "6.8.0-101-generic" → (6, 8).
pub fn parse_kernel_version(release: &str) -> Result<(u32, u32)> {
    let mut parts = release.split('.');
    let major: u32 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| OaieError::SandboxError(format!("cannot parse kernel version: {release}")))?;
    let minor: u32 = parts
        .next()
        // Minor might be "8" in "6.8.0" or might have trailing non-digits.
        .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| OaieError::SandboxError(format!("cannot parse kernel version: {release}")))?;
    Ok((major, minor))
}

/// Heuristic check for running inside a container.
///
/// Checks Docker, Podman, and cgroup-based indicators.
pub fn is_inside_container() -> bool {
    // Docker creates this sentinel file.
    if Path::new("/.dockerenv").exists() {
        return true;
    }
    // Podman / Buildah.
    if Path::new("/run/.containerenv").exists() {
        return true;
    }
    // cgroup-based: look for docker/lxc/containerd in /proc/1/cgroup.
    if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup") {
        if cgroup.contains("docker")
            || cgroup.contains("lxc")
            || cgroup.contains("containerd")
            || cgroup.contains("kubepods")
        {
            return true;
        }
    }
    false
}
