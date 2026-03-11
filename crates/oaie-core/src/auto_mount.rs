//! Auto-mount detection: scans command arguments for host file paths
//! and generates mount entries so the sandbox can access them.
//!
//! When `auto_mount` is enabled (the default), OAIE inspects each argument
//! to the command. If an argument is an existing file or directory on the
//! host, its parent directory is mounted so the tool can operate on it.
//! Element 0 (the executable) gets a read-only mount; subsequent arguments
//! get read-write mounts (so tools can write output next to input files).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A single auto-detected mount entry, recorded for audit trail.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AutoMountEntry {
    /// Original path from the command arguments.
    pub path: PathBuf,
    /// Parent directory that was actually mounted.
    pub mount_dir: PathBuf,
    /// Mount mode: "ro" or "rw".
    pub mode: String,
    /// Source of the detection: "executable" or "argument".
    pub source: String,
}

/// Scan command arguments for existing host paths.
///
/// Returns `(exec_paths, arg_paths)`:
/// - `exec_paths`: element 0 if it resolves to an existing file (the executable)
/// - `arg_paths`: subsequent elements that resolve to existing files/directories
///
/// Skips: flags starting with `-`, system paths (`/proc/`, `/sys/`, `/dev/`),
/// and arguments that don't exist on the host.
///
/// # TOCTOU note
///
/// This function uses `path.exists()` which is inherently racy — a path
/// could be created, deleted, or replaced between this check and the actual
/// mount. This is acceptable because auto-mount is a convenience heuristic,
/// not a security boundary. The actual mount and Landlock rules are the
/// security-relevant operations, and they operate on resolved paths.
pub fn detect_file_args(command: &[String]) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut exec_paths = Vec::new();
    let mut arg_paths = Vec::new();

    for (i, arg) in command.iter().enumerate() {
        // Skip flags.
        if arg.starts_with('-') {
            continue;
        }

        let path = Path::new(arg);

        // Only consider absolute paths or paths that exist.
        // Relative paths are checked against cwd.
        if !path.exists() {
            continue;
        }

        // Skip system virtual filesystems.
        if is_system_virtual_path(path) {
            continue;
        }

        if i == 0 {
            exec_paths.push(path.to_path_buf());
        } else {
            arg_paths.push(path.to_path_buf());
        }
    }

    (exec_paths, arg_paths)
}

/// Generate auto-mount entries from detected file arguments.
///
/// Files → mount their parent directory (tools often do atomic save via
/// write-to-temp + rename in the same directory). Directories → mount directly.
/// Deduplicates with a `HashSet`. Paths under system directories (/usr, /bin,
/// /lib, /lib64) are skipped (already mounted by the sandbox).
///
/// Prints notices to stderr so the user can see what was auto-mounted.
pub fn auto_mount_paths(
    exec_paths: &[PathBuf],
    arg_paths: &[PathBuf],
    extra_ro: &[PathBuf],
    extra_rw: &[PathBuf],
    deny_paths: &[PathBuf],
) -> Vec<AutoMountEntry> {
    let mut entries = Vec::new();
    let mut seen = HashSet::new();

    // Canonicalize deny paths to resolve symlinks. Paths that fail to
    // canonicalize (e.g. non-existent targets) are kept as-is — the
    // original path still provides partial protection.
    let canonical_deny: Vec<PathBuf> = deny_paths
        .iter()
        .map(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.clone()))
        .collect();

    // Collect already-mounted dirs to avoid duplicates.
    // Use canonical paths in `seen` so symlinks to the same directory
    // are properly deduplicated (prevents RO→RW escalation via symlinks).
    for p in extra_ro.iter().chain(extra_rw.iter()) {
        let canonical = std::fs::canonicalize(p).unwrap_or_else(|_| p.clone());
        seen.insert(canonical);
    }

    // Process executable paths (read-only).
    for path in exec_paths {
        let mount_dir = mount_dir_for(path);
        // Canonicalize to resolve symlinks before checking deny/system dirs.
        // If canonicalization fails (broken symlink, race), use the original.
        let canonical = std::fs::canonicalize(&mount_dir).unwrap_or_else(|_| mount_dir.clone());
        if is_under_system_dirs(&canonical) || seen.contains(&canonical) {
            continue;
        }
        // Skip if the canonicalized path falls under any deny path.
        if is_under_deny(&canonical, &canonical_deny) {
            continue;
        }
        seen.insert(canonical);
        eprintln!(
            "OAIE: auto-mount (ro): {} (for executable {})",
            mount_dir.display(),
            path.display()
        );
        entries.push(AutoMountEntry {
            path: path.clone(),
            mount_dir,
            mode: "ro".into(),
            source: "executable".into(),
        });
    }

    // Process argument paths (read-write).
    for path in arg_paths {
        let mount_dir = mount_dir_for(path);
        // Canonicalize to resolve symlinks before checking deny/system dirs.
        let canonical = std::fs::canonicalize(&mount_dir).unwrap_or_else(|_| mount_dir.clone());
        if is_under_system_dirs(&canonical) || seen.contains(&canonical) {
            continue;
        }
        // Skip if the canonicalized path falls under any deny path.
        if is_under_deny(&canonical, &canonical_deny) {
            continue;
        }
        seen.insert(canonical);
        eprintln!(
            "OAIE: auto-mount (rw): {} (for argument {})",
            mount_dir.display(),
            path.display()
        );
        entries.push(AutoMountEntry {
            path: path.clone(),
            mount_dir,
            mode: "rw".into(),
            source: "argument".into(),
        });
    }

    entries
}

/// Determine the directory to mount for a given path.
///
/// Files → parent directory (for atomic save patterns).
/// Directories → the directory itself.
fn mount_dir_for(path: &Path) -> PathBuf {
    if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent().unwrap_or(path).to_path_buf()
    }
}

/// Check if a path is under system virtual filesystems (/proc, /sys, /dev).
fn is_system_virtual_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.starts_with("/proc/") || s.starts_with("/sys/") || s.starts_with("/dev/")
        || s == "/proc" || s == "/sys" || s == "/dev"
}

/// Check if a path is under system directories that the sandbox already mounts,
/// or is the root filesystem itself (which must never be auto-mounted).
pub fn is_under_system_dirs(path: &Path) -> bool {
    // Root filesystem must never be auto-mounted — it would expose the entire host.
    if path == Path::new("/") {
        return true;
    }
    let prefixes = ["/usr", "/bin", "/lib", "/lib64", "/sbin"];
    for prefix in &prefixes {
        if path.starts_with(prefix) {
            return true;
        }
    }
    false
}

/// Check if a path falls under any deny path.
fn is_under_deny(path: &Path, deny_paths: &[PathBuf]) -> bool {
    for deny in deny_paths {
        if path.starts_with(deny) {
            return true;
        }
    }
    false
}
