//! Input validation for oaie-priv requests.
//!
//! All inputs from the unprivileged client are validated before any
//! privileged operations are performed.

use oaie_core::cgroup::CgroupLimits;

/// Minimum ring buffer size: 256 KB.
const MIN_RING_BUF_SIZE: u32 = 256 * 1024;

/// Maximum ring buffer size: 4 MB.
const MAX_RING_BUF_SIZE: u32 = 4 * 1024 * 1024;

/// Validate a ring buffer size for BPF loading.
///
/// Must be a power of 2, between 256KB and 4MB inclusive.
/// The kernel requires ring buffer sizes to be powers of 2.
pub fn validate_ring_buffer_size(size: u32) -> Result<(), String> {
    if size == 0 || (size & (size - 1)) != 0 {
        return Err(format!("ring_buffer_size must be a power of 2, got {size}"));
    }
    if size < MIN_RING_BUF_SIZE {
        return Err(format!(
            "ring_buffer_size must be >= {MIN_RING_BUF_SIZE} (256KB), got {size}"
        ));
    }
    if size > MAX_RING_BUF_SIZE {
        return Err(format!(
            "ring_buffer_size must be <= {MAX_RING_BUF_SIZE} (4MB), got {size}"
        ));
    }
    Ok(())
}

/// Validate a run ID: alphanumeric + hyphens only, 1–64 characters.
///
/// Prevents path traversal and command injection via crafted run IDs.
pub fn validate_run_id(run_id: &str) -> Result<(), String> {
    if run_id.is_empty() || run_id.len() > 64 {
        return Err(format!(
            "run_id must be 1–64 characters, got {}",
            run_id.len()
        ));
    }

    if !run_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err("run_id contains invalid characters (only alphanumeric and hyphens allowed)".into());
    }

    Ok(())
}

/// Validate a cgroup path: must start with `/sys/fs/cgroup/oaie/` and contain no `..`.
///
/// Prevents arbitrary filesystem access via path traversal.
/// Also requires minimum depth (at least one component after the prefix)
/// to prevent deletion of the OAIE root cgroup directory itself.
pub fn validate_cgroup_path(path: &str) -> Result<(), String> {
    if !path.starts_with("/sys/fs/cgroup/oaie/") {
        return Err(format!(
            "cgroup_path must start with /sys/fs/cgroup/oaie/, got: {path}"
        ));
    }

    if path.contains("..") {
        return Err("cgroup_path contains path traversal (..)".into());
    }

    // Reject empty components (double slashes), NUL bytes.
    if path.contains('\0') || path.contains("//") {
        return Err("cgroup_path contains invalid characters".into());
    }

    // Require at least one path component after the prefix to prevent
    // deletion of the OAIE root cgroup directory itself.
    let suffix = &path["/sys/fs/cgroup/oaie/".len()..];
    let suffix = suffix.trim_end_matches('/');
    if suffix.is_empty() {
        return Err("cgroup_path must reference a scope under /sys/fs/cgroup/oaie/".into());
    }

    Ok(())
}

/// Validate cgroup limits: check ranges are sane.
///
/// Prevents resource exhaustion from unreasonable values.
/// Also validates coupling: cpu_quota_us and cpu_period_us must be set together.
pub fn validate_limits(limits: &CgroupLimits) -> Result<(), String> {
    if let Some(mem) = limits.memory_max {
        if mem < 1024 * 1024 {
            return Err(format!(
                "memory_max must be >= 1MB, got {mem} bytes"
            ));
        }
    }

    if let Some(pids) = limits.pids_max {
        if pids == 0 || pids > 1_000_000 {
            return Err(format!(
                "pids_max must be 1–1000000, got {pids}"
            ));
        }
    }

    if let Some(quota) = limits.cpu_quota_us {
        if quota == 0 {
            return Err("cpu_quota_us must be > 0".into());
        }
    }

    if let Some(period) = limits.cpu_period_us {
        if period == 0 || period > 1_000_000 {
            return Err(format!(
                "cpu_period_us must be 1–1000000, got {period}"
            ));
        }
    }

    // CPU quota and period must be set together — one without the other
    // means the cpu.max write is silently skipped, which is misleading.
    match (limits.cpu_quota_us, limits.cpu_period_us) {
        (Some(_), None) => return Err("cpu_quota_us set without cpu_period_us".into()),
        (None, Some(_)) => return Err("cpu_period_us set without cpu_quota_us".into()),
        _ => {}
    }

    Ok(())
}
