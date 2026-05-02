//! Write cgroup v2 resource limits to control files.
//!
//! Limits are written individually and non-fatally — a missing controller
//! (e.g. no `memory` controller enabled) results in that limit being skipped,
//! not a hard error. The caller gets a `LimitsApplied` struct showing which
//! limits were successfully written.

use std::path::Path;

use oaie_core::cgroup::CgroupLimits;

/// Which limits were successfully applied to the cgroup.
#[derive(Clone, Debug, Default)]
pub struct LimitsApplied {
    /// Whether `memory.max` was written successfully.
    pub memory: bool,
    /// Whether `memory.swap.max` was written successfully.
    pub swap: bool,
    /// Whether `pids.max` was written successfully.
    pub pids: bool,
    /// Whether `cpu.max` was written successfully.
    pub cpu: bool,
}

impl LimitsApplied {
    /// True if at least one limit was successfully applied.
    pub fn any_enforced(&self) -> bool {
        self.memory || self.pids || self.cpu
    }

    /// True if every limit that was REQUESTED was successfully written.
    /// `swap` is not checked: the swap controller may legitimately be
    /// unavailable and it is not a primary security limit.
    pub fn all_requested_applied(&self, limits: &CgroupLimits) -> bool {
        (limits.memory_max.is_none() || self.memory)
            && (limits.pids_max.is_none() || self.pids)
            && (limits.cpu_quota_us.is_none() || self.cpu)
    }
}

/// Apply cgroup v2 limits by writing to control files in `cgroup_path`.
///
/// Each limit is written independently — failures are logged but don't
/// prevent other limits from being applied. Returns which limits succeeded.
///
/// When a memory limit is set, also writes `memory.swap.max = 0` to prevent
/// swap from masking memory pressure (sandboxed processes shouldn't swap).
pub fn apply_limits(cgroup_path: &Path, limits: &CgroupLimits) -> LimitsApplied {
    let mut applied = LimitsApplied::default();

    // memory.max: bytes as a decimal string, or "max" for unlimited.
    if let Some(memory_max) = limits.memory_max {
        let path = cgroup_path.join("memory.max");
        match std::fs::write(&path, format!("{memory_max}")) {
            Ok(()) => applied.memory = true,
            Err(e) => {
                oaie_core::log_warn!("failed to write memory.max: {e}");
            }
        }

        // Disable swap to prevent masking memory pressure. Sandboxed processes
        // shouldn't spill into swap — if they hit memory.max, the OOM killer
        // should act immediately rather than degrading host performance.
        let swap_path = cgroup_path.join("memory.swap.max");
        match std::fs::write(&swap_path, "0") {
            Ok(()) => applied.swap = true,
            Err(e) => {
                // Non-fatal: swap controller may not be available.
                oaie_core::log_warn!("failed to write memory.swap.max: {e}");
            }
        }
    }

    // pids.max: count as a decimal string, or "max" for unlimited.
    if let Some(pids_max) = limits.pids_max {
        let path = cgroup_path.join("pids.max");
        match std::fs::write(&path, format!("{pids_max}")) {
            Ok(()) => applied.pids = true,
            Err(e) => {
                oaie_core::log_warn!("failed to write pids.max: {e}");
            }
        }
    }

    // cpu.max: format "{quota} {period}" in microseconds.
    if let (Some(quota), Some(period)) = (limits.cpu_quota_us, limits.cpu_period_us) {
        let path = cgroup_path.join("cpu.max");
        match std::fs::write(&path, format!("{quota} {period}")) {
            Ok(()) => applied.cpu = true,
            Err(e) => {
                oaie_core::log_warn!("failed to write cpu.max: {e}");
            }
        }
    }

    applied
}
