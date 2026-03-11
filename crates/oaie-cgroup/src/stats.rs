//! Read cgroup v2 resource accounting stats after a run completes.
//!
//! All fields are `Option` to handle missing control files gracefully —
//! not all kernels expose all stats, and not all controllers may be enabled.

use std::path::Path;

use oaie_core::cgroup::CgroupStats;

/// Collect resource accounting stats from cgroup v2 control files.
///
/// Reads `memory.peak`, `memory.max`, `memory.events`, `cpu.stat`,
/// `pids.peak` (with `pids.current` fallback), and `pids.max`.
/// Missing files are silently skipped (the corresponding field is `None`).
pub fn collect_stats(cgroup_path: &Path) -> CgroupStats {
    // Parse cpu.stat first since it populates multiple fields.
    let (cpu_user_us, cpu_system_us, cpu_throttled_periods, cpu_throttled_us) =
        parse_cpu_stat(cgroup_path);

    // Prefer pids.peak (kernel 6.4+) over pids.current (which reads 0 after exit).
    let pids_current = read_u64_file(&cgroup_path.join("pids.peak"))
        .or_else(|| read_u64_file(&cgroup_path.join("pids.current")))
        .map(|v| v as u32);

    CgroupStats {
        memory_peak: read_u64_file(&cgroup_path.join("memory.peak")),
        memory_limit: read_u64_file(&cgroup_path.join("memory.max")),
        cpu_user_us,
        cpu_system_us,
        cpu_throttled_periods,
        cpu_throttled_us,
        pids_current,
        pids_limit: read_u64_file(&cgroup_path.join("pids.max")).map(|v| v as u32),
        oom_kill_count: parse_memory_events_oom_kill(cgroup_path),
    }
}

/// Parse `cpu.stat` key-value pairs into individual fields.
fn parse_cpu_stat(cgroup_path: &Path) -> (Option<u64>, Option<u64>, Option<u64>, Option<u64>) {
    let content = match std::fs::read_to_string(cgroup_path.join("cpu.stat")) {
        Ok(c) => c,
        Err(_) => return (None, None, None, None),
    };

    let mut user = None;
    let mut system = None;
    let mut nr_throttled = None;
    let mut throttled = None;

    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let key = parts.next().unwrap_or("");
        let val: Option<u64> = parts.next().and_then(|v| v.parse().ok());
        match key {
            // user_usec is per-cgroup user CPU time (not usage_usec which is total).
            "user_usec" => user = val,
            "system_usec" => system = val,
            "nr_throttled" => nr_throttled = val,
            "throttled_usec" => throttled = val,
            _ => {}
        }
    }

    (user, system, nr_throttled, throttled)
}

/// Parse `memory.events` for `oom_kill` counter.
///
/// Returns `Some(count)` if the oom_kill key exists, `None` if the file
/// is missing or the key is absent.
fn parse_memory_events_oom_kill(cgroup_path: &Path) -> Option<u64> {
    let content = std::fs::read_to_string(cgroup_path.join("memory.events")).ok()?;
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some("oom_kill") {
            return parts.next().and_then(|v| v.parse().ok());
        }
    }
    None
}

/// Read a single u64 value from a cgroup control file.
///
/// Returns `None` if the file doesn't exist, can't be read, or contains
/// "max" (which means unlimited). Also handles trailing whitespace/newlines.
fn read_u64_file(path: &Path) -> Option<u64> {
    let content = std::fs::read_to_string(path).ok()?;
    let trimmed = content.trim();
    if trimmed == "max" {
        return None; // "max" means unlimited — no numeric value to return.
    }
    trimmed.parse().ok()
}
