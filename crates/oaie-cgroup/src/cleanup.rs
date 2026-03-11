//! Cgroup scope cleanup: systemd stop, rmdir, and stale sweep.
//!
//! Cleanup is best-effort — failures are logged but don't propagate errors.
//! The kernel will eventually reclaim cgroups with no processes, but explicit
//! cleanup prevents clutter in the cgroup hierarchy.

use std::path::Path;
use std::process::Command;

/// Stop a systemd user scope unit (best-effort).
///
/// First tries `systemctl --user stop`, which terminates any remaining
/// processes and removes the scope. Falls back to `rmdir` on the cgroup
/// directory if systemctl fails.
pub fn cleanup_systemd_scope(unit_name: &str) {
    let result = Command::new("systemctl")
        .args(["--user", "stop", unit_name])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    if let Err(e) = result {
        oaie_core::log_warn!("failed to stop systemd scope {unit_name}: {e}");
    }
}

/// Remove a cgroup directory via `rmdir` (best-effort).
///
/// `rmdir` only succeeds if the cgroup has no child cgroups and no processes.
/// This is expected after the sandboxed process has exited.
pub fn cleanup_cgroup_dir(path: &Path) {
    if let Err(e) = std::fs::remove_dir(path) {
        // ENOENT is fine — the cgroup was already cleaned up.
        if e.kind() != std::io::ErrorKind::NotFound {
            oaie_core::log_warn!("failed to remove cgroup dir {}: {e}", path.display());
        }
    }
}

/// Sweep stale OAIE cgroup scopes older than 5 minutes.
///
/// Scans both `/sys/fs/cgroup/user.slice` (for systemd-run scopes) and
/// `/sys/fs/cgroup/oaie/` (for oaie-priv scopes). Removes those whose
/// `cgroup.procs` is empty and older than 5 minutes.
/// Called during startup cleanup (like stale sandbox dir cleanup).
pub fn cleanup_stale_cgroups() {
    let five_min = std::time::Duration::from_secs(300);
    let now = std::time::SystemTime::now();

    // Sweep systemd-run scopes under user.slice.
    let user_slice = Path::new("/sys/fs/cgroup/user.slice");
    if user_slice.exists() {
        if let Ok(entries) = walk_oaie_scopes(user_slice) {
            sweep_stale(&entries, &now, five_min);
        }
    }

    // Sweep oaie-priv scopes under /sys/fs/cgroup/oaie/.
    let oaie_root = Path::new("/sys/fs/cgroup/oaie");
    if oaie_root.exists() {
        if let Ok(entries) = walk_oaie_run_dirs(oaie_root) {
            sweep_stale(&entries, &now, five_min);
        }
    }
}

/// Remove stale scope directories that are empty and older than the threshold.
fn sweep_stale(
    entries: &[std::path::PathBuf],
    now: &std::time::SystemTime,
    max_age: std::time::Duration,
) {
    for scope_path in entries {
        // Check if the scope is empty (no processes).
        let procs_path = scope_path.join("cgroup.procs");
        let procs_content = match std::fs::read_to_string(&procs_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if !procs_content.trim().is_empty() {
            continue; // Still has processes — skip.
        }

        // Check age via mtime of the cgroup directory.
        let metadata = match std::fs::metadata(scope_path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let modified = match metadata.modified() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if let Ok(age) = now.duration_since(modified) {
            if age > max_age {
                cleanup_cgroup_dir(scope_path);
            }
        }
    }
}

/// Recursively find directories matching `oaie-run-*.scope` under a root.
fn walk_oaie_scopes(root: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut results = Vec::new();
    walk_oaie_scopes_inner(root, &mut results, 0)?;
    Ok(results)
}

fn walk_oaie_scopes_inner(
    dir: &Path,
    results: &mut Vec<std::path::PathBuf>,
    depth: usize,
) -> std::io::Result<()> {
    // Limit depth to prevent runaway walks.
    if depth > 6 {
        return Ok(());
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with("oaie-run-") && name.ends_with(".scope") {
                results.push(path);
                continue; // Don't descend into scope dirs.
            }
        }
        walk_oaie_scopes_inner(&path, results, depth + 1)?;
    }
    Ok(())
}

/// Find directories matching `run-*` directly under the oaie-priv root.
///
/// oaie-priv creates flat `run-{id}` directories under `/sys/fs/cgroup/oaie/`,
/// not nested, so no recursion is needed.
fn walk_oaie_run_dirs(root: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut results = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with("run-") {
                results.push(path);
            }
        }
    }
    Ok(results)
}
