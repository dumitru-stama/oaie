//! Cgroup v2 operations for the privileged helper.
//!
//! Creates and manages cgroup directories under `/sys/fs/cgroup/oaie/`.
//! These operations require CAP_SYS_ADMIN or appropriate cgroup delegation.

use std::fs;
use std::path::Path;

use oaie_core::cgroup::CgroupLimits;

/// Root directory for all OAIE cgroups managed by the helper.
const OAIE_CGROUP_ROOT: &str = "/sys/fs/cgroup/oaie";

/// Create a cgroup scope for a run.
///
/// Creates `/sys/fs/cgroup/oaie/run-{id}/`, enables controllers,
/// writes limits (including `memory.swap.max = 0` when memory limit is set),
/// and chowns `cgroup.procs` to the caller's UID so the unprivileged OAIE
/// process can assign PIDs.
pub fn create_cgroup(run_id: &str, limits: &CgroupLimits, caller_uid: u32) -> Result<String, String> {
    // Ensure the OAIE root cgroup exists.
    let root = Path::new(OAIE_CGROUP_ROOT);
    if !root.exists() {
        fs::create_dir_all(root)
            .map_err(|e| format!("failed to create {OAIE_CGROUP_ROOT}: {e}"))?;

        // Enable controllers in the parent cgroup.
        // Read available controllers from the parent and enable them.
        let parent = Path::new("/sys/fs/cgroup");
        let controllers = fs::read_to_string(parent.join("cgroup.controllers"))
            .unwrap_or_default();
        let subtree_control: String = controllers
            .split_whitespace()
            .map(|c| format!("+{c}"))
            .collect::<Vec<_>>()
            .join(" ");
        if !subtree_control.is_empty() {
            let _ = fs::write(parent.join("cgroup.subtree_control"), &subtree_control);
        }
    }

    // Enable controllers in the OAIE root.
    let controllers = fs::read_to_string(root.join("cgroup.controllers"))
        .unwrap_or_default();
    let subtree_control: String = controllers
        .split_whitespace()
        .map(|c| format!("+{c}"))
        .collect::<Vec<_>>()
        .join(" ");
    if !subtree_control.is_empty() {
        let _ = fs::write(root.join("cgroup.subtree_control"), &subtree_control);
    }

    // Create the run-specific cgroup.
    let scope_name = format!("run-{run_id}");
    let scope_path = root.join(&scope_name);
    fs::create_dir_all(&scope_path)
        .map_err(|e| format!("failed to create cgroup {}: {e}", scope_path.display()))?;

    // Write limits.
    if let Some(memory_max) = limits.memory_max {
        let _ = fs::write(scope_path.join("memory.max"), format!("{memory_max}"));
        // Disable swap to prevent masking memory pressure.
        let _ = fs::write(scope_path.join("memory.swap.max"), "0");
    }
    if let Some(pids_max) = limits.pids_max {
        let _ = fs::write(scope_path.join("pids.max"), format!("{pids_max}"));
    }
    if let (Some(quota), Some(period)) = (limits.cpu_quota_us, limits.cpu_period_us) {
        let _ = fs::write(scope_path.join("cpu.max"), format!("{quota} {period}"));
    }

    // Chown cgroup.procs to the caller's UID so the unprivileged OAIE process
    // can assign its sandbox child's PID. The caller UID comes from SO_PEERCRED
    // on the Unix socket — kernel-verified, cannot be forged.
    let procs_path = scope_path.join("cgroup.procs");
    if procs_path.exists() {
        let procs_cstr = std::ffi::CString::new(procs_path.to_string_lossy().as_bytes())
            .map_err(|_| "cgroup.procs path contains NUL byte".to_string())?;
        // chown to caller UID, keep GID as root (group doesn't need write access).
        let ret = unsafe { libc::chown(procs_cstr.as_ptr(), caller_uid, u32::MAX) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            return Err(format!("failed to chown cgroup.procs to uid {caller_uid}: {err}"));
        }
    }

    Ok(scope_path.display().to_string())
}

/// Clean up (remove) a cgroup scope.
///
/// The cgroup must be empty (no processes) for rmdir to succeed.
pub fn cleanup_cgroup(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(()); // Already gone.
    }

    // Verify it's under our root.
    if !path.starts_with(OAIE_CGROUP_ROOT) {
        return Err(format!(
            "refusing to remove cgroup outside {OAIE_CGROUP_ROOT}: {}",
            path.display()
        ));
    }

    fs::remove_dir(path).map_err(|e| {
        format!(
            "failed to remove cgroup {}: {e} (processes may still be running)",
            path.display()
        )
    })
}
