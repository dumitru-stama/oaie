//! Cgroup v2 types shared across OAIE crates.
//!
//! These are lightweight data types with no heavy dependencies — they live in
//! oaie-core so both oaie-cgroup (library) and oaie-cli (runner) can use them
//! without pulling in cgroup-specific code.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::error::OaieError;

/// How the runner should handle cgroup isolation.
///
/// Controlled by the `--cgroup` CLI flag. `Auto` is the default: use cgroups
/// if available, fall back to rlimits-only if not.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CgroupMode {
    /// Use cgroups if available, fall back gracefully (default).
    #[default]
    Auto,
    /// Require cgroup isolation — fail if unavailable.
    Require,
    /// Disable cgroup isolation entirely (rlimits only).
    Off,
}

impl fmt::Display for CgroupMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::Require => write!(f, "require"),
            Self::Off => write!(f, "off"),
        }
    }
}

impl FromStr for CgroupMode {
    type Err = OaieError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auto" => Ok(Self::Auto),
            "require" => Ok(Self::Require),
            "off" => Ok(Self::Off),
            _ => Err(OaieError::InvalidJobSpec(format!(
                "unknown cgroup mode: {s} (expected: auto, require, off)"
            ))),
        }
    }
}

/// Which mechanism was used to create the cgroup scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CgroupMethod {
    /// Created via `systemd-run --user --scope`.
    SystemdRun,
    /// Created via the `oaie-priv` privileged helper binary.
    OaiePriv,
}

impl fmt::Display for CgroupMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SystemdRun => write!(f, "systemd-run"),
            Self::OaiePriv => write!(f, "oaie-priv"),
        }
    }
}

/// Resource limits to apply to a cgroup v2 scope.
///
/// All fields are optional — `None` means "don't set this limit" (inherit
/// from parent cgroup). Values map directly to cgroup v2 control files:
/// - `memory_max` → `memory.max` (bytes)
/// - `pids_max` → `pids.max` (count)
/// - `cpu_quota_us` + `cpu_period_us` → `cpu.max` (format: `{quota} {period}`)
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupLimits {
    /// Hard memory limit in bytes. Written to `memory.max`.
    /// When exceeded, the OOM killer targets processes in this cgroup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_max: Option<u64>,
    /// Maximum number of processes. Written to `pids.max`.
    /// fork()/clone() returns EAGAIN when exceeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pids_max: Option<u32>,
    /// CPU quota in microseconds per period. Written as part of `cpu.max`.
    /// e.g. 50000 with period 100000 = 50% of one CPU.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_quota_us: Option<u64>,
    /// CPU period in microseconds. Written as part of `cpu.max`.
    /// Default kernel period is 100000 (100ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_period_us: Option<u64>,
}

/// Resource accounting stats collected from a cgroup v2 scope after a run.
///
/// All fields are `Option` because some controllers may not be available
/// (depends on kernel version and cgroup configuration). Read from cgroup
/// v2 control files after the sandboxed process exits.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupStats {
    /// Peak memory usage in bytes. Read from `memory.peak`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_peak: Option<u64>,
    /// Memory limit that was in effect. Read from `memory.max`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_limit: Option<u64>,
    /// Total user-mode CPU time in microseconds. From `cpu.stat` `user_usec`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_user_us: Option<u64>,
    /// Total system-mode CPU time in microseconds. From `cpu.stat` `system_usec`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_system_us: Option<u64>,
    /// Number of periods in which the cgroup was CPU-throttled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_throttled_periods: Option<u64>,
    /// Total time throttled in microseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_throttled_us: Option<u64>,
    /// Current/peak number of processes. Read from `pids.peak` (or `pids.current` fallback).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pids_current: Option<u32>,
    /// PID limit that was in effect. Read from `pids.max`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pids_limit: Option<u32>,
    /// Number of times the OOM killer was invoked. Read from `memory.events` `oom_kill`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oom_kill_count: Option<u64>,
}

/// Cgroup metadata recorded in the manifest's `IsolationInfo`.
///
/// Tells the reader which cgroup mechanism was used and whether limits
/// are actually enforced via cgroup (vs advisory rlimits).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CgroupInfo {
    /// Cgroup scope name (e.g. "oaie-run-abc12345.scope").
    pub name: String,
    /// Which mechanism created the scope.
    pub method: CgroupMethod,
    /// Whether cgroup limits were successfully applied.
    /// `true` means memory/pids/cpu limits are hard-enforced by the kernel.
    pub enforced: bool,
}
