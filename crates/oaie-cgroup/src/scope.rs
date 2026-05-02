//! Cgroup scope creation and lifecycle management.
//!
//! A `CgroupScope` represents a cgroup v2 scope that isolates a single OAIE
//! run. Created via `systemd-run --user --scope` or the `oaie-priv` helper,
//! it provides a directory under `/sys/fs/cgroup/` where limits can be written
//! and stats read. The scope is cleaned up on `Drop` unless `defuse()` is called.

use std::path::PathBuf;
use std::process::Command;

use oaie_core::cgroup::{CgroupLimits, CgroupMethod};
use oaie_core::error::{OaieError, Result};
use oaie_core::run_id::RunId;

/// A cgroup v2 scope for a single OAIE run.
///
/// Holds the filesystem path to the cgroup directory and the systemd unit
/// name (if created via systemd-run). Cleans up on drop unless defused.
pub struct CgroupScope {
    /// Filesystem path to the cgroup directory (e.g. `/sys/fs/cgroup/user.slice/.../oaie-run-abc.scope`).
    pub path: PathBuf,
    /// Systemd unit name (e.g. "oaie-run-abc12345.scope"), None for oaie-priv scopes.
    pub unit_name: Option<String>,
    /// Which method created this scope.
    pub method: CgroupMethod,
    /// Whether cleanup should run on drop. Set to false by `defuse()`.
    pub(crate) cleanup: bool,
    /// Holder process that keeps the scope alive until the sandbox PID is assigned.
    /// The scope lives as long as at least one process is in it — the holder
    /// prevents garbage-collection between scope creation and PID assignment.
    pub(crate) holder: Option<std::process::Child>,
}

impl CgroupScope {
    /// Create a cgroup scope via `systemd-run --user --scope`.
    ///
    /// The scope is created with `Delegate=yes` so OAIE can write limits
    /// and assign PIDs. A `sleep` holder process keeps the scope alive until
    /// `assign_pid()` is called, at which point the holder is killed.
    /// Without the holder, there's a race between `/bin/true` exiting and
    /// systemd garbage-collecting the empty scope.
    pub fn create_systemd(run_id: &RunId) -> Result<Self> {
        // Use the full simple-form UUID (32 hex chars, no hyphens) so the
        // unit name carries all 122 bits of the RunId. The hyphenated form's
        // 12-char prefix is timestamp-only and collides for concurrent runs.
        let short = run_id.as_uuid().simple().to_string();
        let unit_name = format!("oaie-run-{short}.scope");

        // Spawn systemd-run with `sleep 3600` as a holder process.
        // systemd-run --scope blocks until the command finishes, so we
        // spawn it in the background. The scope persists as long as at
        // least one process is assigned to it.
        let holder = Command::new("systemd-run")
            .args([
                "--user",
                "--scope",
                &format!("--unit={unit_name}"),
                "--property=Delegate=yes",
                "--quiet",
                "sleep", "3600",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| OaieError::SandboxError(format!("systemd-run failed: {e}")))?;

        // Poll for the cgroup path to appear AND be ready (cgroup.procs exists).
        // systemd-run creates the scope almost immediately, but we need to wait
        // until systemctl can report it and the cgroup is fully initialized.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let path = loop {
            let output = Command::new("systemctl")
                .args(["--user", "show", "-P", "ControlGroup", &unit_name])
                .output()
                .map_err(|e| OaieError::SandboxError(format!("systemctl show failed: {e}")))?;

            let cgroup_relative = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !cgroup_relative.is_empty() {
                let p = PathBuf::from(format!("/sys/fs/cgroup{cgroup_relative}"));
                // Verify cgroup.procs exists — this confirms the cgroup is fully
                // initialized and has a process (our holder) assigned to it.
                if p.join("cgroup.procs").exists() {
                    break p;
                }
            }

            if std::time::Instant::now() >= deadline {
                return Err(OaieError::SandboxError(
                    "timed out waiting for cgroup scope to appear".into(),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };

        Ok(Self {
            path,
            unit_name: Some(unit_name),
            method: CgroupMethod::SystemdRun,
            cleanup: true,
            holder: Some(holder),
        })
    }

    /// Create a cgroup scope via the `oaie-priv` privileged helper.
    pub fn create_via_priv(run_id: &RunId, limits: &CgroupLimits) -> Result<Self> {
        let scope = crate::priv_client::create_cgroup(run_id, limits)?;
        Ok(scope)
    }

    /// Assign a process to this cgroup by writing its PID to `cgroup.procs`.
    ///
    /// Called from the post_map_hook in the sandbox parent, after UID/GID maps
    /// are written but before the child is released from the sync pipe.
    ///
    /// After successful assignment, kills the holder process (if any) since
    /// the scope now has the sandbox PID to keep it alive.
    pub fn assign_pid(&mut self, pid: i32) -> Result<()> {
        let procs_path = self.path.join("cgroup.procs");
        std::fs::write(&procs_path, format!("{pid}\n")).map_err(|e| {
            OaieError::SandboxError(format!(
                "failed to assign PID {pid} to cgroup {}: {e}",
                procs_path.display()
            ))
        })?;

        // Kill the holder process — the scope now has the sandbox PID to stay alive.
        self.kill_holder();
        Ok(())
    }

    /// Prevent cleanup on drop (e.g. if the scope will be reused or was already cleaned).
    pub fn defuse(&mut self) {
        self.cleanup = false;
    }

    /// Kill the holder process if it's still running.
    fn kill_holder(&mut self) {
        if let Some(ref mut child) = self.holder {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.holder = None;
    }
}

impl Drop for CgroupScope {
    fn drop(&mut self) {
        // Always clean up the holder process.
        self.kill_holder();

        if !self.cleanup {
            return;
        }
        if let Some(ref unit) = self.unit_name {
            crate::cleanup::cleanup_systemd_scope(unit);
        } else if self.method == CgroupMethod::OaiePriv {
            // /sys/fs/cgroup/oaie/ is root-owned; the unprivileged supervisor
            // cannot rmdir under it. Ask oaie-priv to remove what it created.
            let _ = crate::priv_client::cleanup_cgroup(&self.path);
        } else {
            crate::cleanup::cleanup_cgroup_dir(&self.path);
        }
    }
}
