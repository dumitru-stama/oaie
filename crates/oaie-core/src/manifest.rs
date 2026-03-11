//! Run manifest: the complete record of what happened during an OAIE execution.
//!
//! Serialized as TOML to `manifest.toml` in each run directory and stored in CAS.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::artifact::ArtifactRef;
use crate::auto_mount::AutoMountEntry;
use crate::cgroup::CgroupInfo;
use crate::error::OaieError;
use crate::run_id::RunId;

/// Default hash algorithm string for serde deserialization of legacy manifests.
fn default_hash_algorithm() -> String {
    "blake3".into()
}

/// Default network mode string for backward compat with pre-Phase H manifests.
fn default_network_mode_str() -> String {
    "off".into()
}

/// Skip serializing `network_mode` when it's the default ("off").
/// "on" and "allowlist" are always serialized to avoid data loss on roundtrip.
fn is_default_network_mode(s: &str) -> bool {
    s == "off"
}

/// The complete record of a single run.
/// Serialized as TOML, stored alongside run artifacts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    /// Manifest format version, starts at 1.
    pub version: u32,
    /// Hash algorithm used for this run's CAS and chain ("blake3" or "sha256").
    #[serde(default = "default_hash_algorithm")]
    pub hash_algorithm: String,
    /// Unique identifier for this run (UUIDv7).
    pub run_id: RunId,
    /// When this run was created.
    pub created: DateTime<Utc>,
    /// The command that was executed inside the sandbox.
    pub command: Vec<String>,
    /// Process exit code, None if the process was killed or still running.
    pub exit_code: Option<i32>,
    /// Wall-clock duration of the run in milliseconds.
    pub duration_ms: u64,
    /// What isolation was applied during the run.
    pub isolation: IsolationInfo,
    /// All artifacts produced by this run (stdout, stderr, outputs, trace, etc.).
    pub artifacts: Vec<ArtifactRef>,
    /// Policy constraints that were applied to this run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyInfo>,
    /// Trace metadata, present when observation tracing was enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<TraceInfo>,
    /// Resource accounting from cgroup v2, present when cgroup isolation was active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceInfo>,
}

/// Trace metadata recorded in the manifest when observation tracing is enabled.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceInfo {
    /// Name of the trace backend: "ptrace", "ebpf", "synthetic".
    pub backend: String,
    /// Total number of events captured.
    pub event_count: u64,
    /// BLAKE3 hash of the final event (the chain tip), for verification.
    pub chain_tip: String,
    /// Number of events dropped (e.g. buffer overflow in eBPF). 0 for ptrace.
    pub dropped: u64,
    /// Number of CAS chunks in the trace (1 for small traces).
    #[serde(default)]
    pub chunks: u32,
    /// BLAKE3 hash of the trace_index.json stored in CAS, if chunked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_index_hash: Option<String>,
}

/// A serialized allow rule for the manifest (flattened, no Option fields).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AllowRuleSerialized {
    /// Target: hostname or CIDR.
    pub target: String,
    /// Destination port.
    pub port: u16,
    /// Transport protocol.
    pub protocol: String,
}

/// Policy constraints applied during a run, recorded in the manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyInfo {
    /// Policy name (e.g. "safe", "build").
    pub name: Option<String>,
    /// Whether network access was allowed by policy (backward compat).
    pub network: bool,
    /// Network allowlist rules, present when mode is "allowlist".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_rules: Option<Vec<AllowRuleSerialized>>,
    /// Maximum address space, human-readable (e.g. "512M").
    pub max_memory: String,
    /// Maximum wall-clock time, human-readable (e.g. "5m").
    pub max_time: String,
    /// Maximum number of processes.
    pub max_pids: u32,
    /// Maximum file size, human-readable (e.g. "1G").
    pub max_fsize: String,
    /// Whether `memfd_create()`/`execveat()` are allowed (for JIT runtimes).
    #[serde(default)]
    pub allow_memfd: bool,
    /// Paths denied from mounting into the sandbox.
    pub deny_paths: Vec<String>,
    /// Paths that were auto-mounted based on command arguments.
    #[serde(default)]
    pub auto_mounts: Vec<AutoMountEntry>,
    /// Which limits are actually enforced by the kernel.
    pub limits_enforced: LimitsEnforced,
}

/// Which resource limits are actually enforced by the kernel.
///
/// Some limits (e.g. RLIMIT_AS) are advisory — the OOM killer may step in
/// before the limit is reached. Others (RLIMIT_FSIZE) produce SIGXFSZ.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LimitsEnforced {
    /// Timeout enforced via waitpid deadline + SIGKILL.
    pub timeout: bool,
    /// Memory limit via RLIMIT_AS (advisory — OOM killer may intervene).
    pub memory: bool,
    /// PID limit via RLIMIT_NPROC (system-wide per-UID, not per-sandbox).
    pub pids: bool,
    /// File size limit via RLIMIT_FSIZE (produces SIGXFSZ on exceed).
    pub fsize: bool,
}

/// Describes the isolation environment applied during a run.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IsolationInfo {
    /// How much isolation was applied (full, partial, none, or microvm).
    pub level: IsolationLevel,
    /// Namespaces used: e.g. ["mount", "pid", "net", "user"].
    pub namespaces: Vec<String>,
    /// Whether network access was allowed (backward compat: true if On or Allowlist).
    pub network: bool,
    /// Network mode string: "off", "on", or "allowlist".
    #[serde(default = "default_network_mode_str", skip_serializing_if = "is_default_network_mode")]
    pub network_mode: String,
    /// Whether the kernel supports Landlock filesystem restrictions (≥ 5.13).
    /// Probed from the parent process — the child applies Landlock non-fatally,
    /// so true means "Landlock was attempted" (will succeed if probe succeeded).
    #[serde(default)]
    pub landlock: bool,
    /// Cgroup v2 scope metadata, present when cgroup isolation was used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<CgroupInfo>,
    /// Execution backend name: "namespace", "bare", "firecracker".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    /// Firecracker binary version string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firecracker_version: Option<String>,
    /// Kernel image used by the microVM (e.g. "vmlinux-5.10.225").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    /// Root filesystem image used by the microVM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootfs: Option<String>,
    /// Trace integrity level: "full" (host-side ptrace/eBPF) or "reduced"
    /// (guest-side ptrace — trace produced inside the VM trust boundary).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_integrity: Option<String>,
    /// Whether interactive PTY mode was used for this run.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub interactive: bool,
}

/// Resource accounting recorded in the manifest when cgroup v2 isolation is active.
///
/// Human-readable values for the report. Derived from `CgroupStats` after the run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceInfo {
    /// Memory limit that was applied (e.g. "512M").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_limit: Option<String>,
    /// Peak memory usage observed (e.g. "347M").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_peak: Option<String>,
    /// User-mode CPU time in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_user_ms: Option<u64>,
    /// System-mode CPU time in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_system_ms: Option<u64>,
    /// Peak number of processes observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pids_peak: Option<u32>,
}

/// How much namespace isolation was applied to the sandboxed process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IsolationLevel {
    /// All namespaces active (mount, PID, network, user, IPC).
    Full,
    /// Some namespaces active (e.g. no user namespace on this kernel).
    Partial,
    /// No isolation (--no-isolation was passed).
    None,
    /// Firecracker microVM — hardware-enforced (KVM) isolation with a
    /// separate kernel and rootfs.
    #[serde(rename = "microvm")]
    MicroVM,
}

impl IsolationLevel {
    /// Whether this level provides meaningful isolation (Full, MicroVM).
    pub fn is_isolated(&self) -> bool {
        matches!(self, Self::Full | Self::MicroVM)
    }
}

impl fmt::Display for IsolationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => write!(f, "full"),
            Self::Partial => write!(f, "partial"),
            Self::None => write!(f, "none"),
            Self::MicroVM => write!(f, "microvm"),
        }
    }
}

impl FromStr for IsolationLevel {
    type Err = OaieError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "full" => Ok(Self::Full),
            "partial" => Ok(Self::Partial),
            "none" => Ok(Self::None),
            "microvm" => Ok(Self::MicroVM),
            _ => Err(OaieError::InvalidJobSpec(format!(
                "unknown isolation level: {s}"
            ))),
        }
    }
}
