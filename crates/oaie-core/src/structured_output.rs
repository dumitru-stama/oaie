//! Structured machine-readable output for OAIE runs.
//!
//! [`StructuredRunResult`] is the canonical JSON output format shared by the
//! CLI (`--output=json`), the `oaie-agent` library crate, and the MCP server.
//! One format, one place to update.

use serde::{Deserialize, Serialize};

/// Machine-readable result of a completed OAIE run.
///
/// Contains everything an agent or programmatic consumer needs: exit code,
/// timing, artifact hashes, isolation metadata, and an optional trace summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredRunResult {
    /// Unique run identifier (UUIDv7).
    pub run_id: String,
    /// Process exit code (-1 if killed by signal).
    pub exit_code: i32,
    /// Wall-clock duration of the run in seconds.
    pub duration_secs: f64,
    /// Reference to captured stdout.
    pub stdout: OutputRef,
    /// Reference to captured stderr.
    pub stderr: OutputRef,
    /// Output files collected from the sandbox output directory.
    pub output_artifacts: Vec<ArtifactEntry>,
    /// Hash of the manifest stored in CAS.
    pub manifest_hash: String,
    /// Isolation metadata.
    pub isolation: IsolationSummary,
    /// Cgroup v2 resource accounting (present when cgroup isolation was active).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceSummary>,
    /// Trace summary (present when tracing was enabled).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<TraceSummaryOutput>,
    /// Filesystem path to the store used for this run.
    pub store_path: String,
}

/// Reference to a captured output stream (stdout or stderr).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputRef {
    /// Content hash (BLAKE3 or SHA-256 hex string) of the captured data.
    pub hash: String,
    /// Size of the captured data in bytes.
    pub size_bytes: u64,
}

/// An output artifact produced by the sandboxed command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactEntry {
    /// Human-readable label (e.g. "output/result.txt").
    pub name: String,
    /// Content hash in CAS.
    pub hash: String,
    /// Size in bytes.
    pub size_bytes: u64,
}

/// Summary of isolation applied during the run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationSummary {
    /// Isolation level: "full", "partial", "none", or "microvm".
    pub level: String,
    /// Execution backend: "namespace", "bare", or "firecracker".
    pub backend: String,
    /// Whether cgroup v2 limits were kernel-enforced.
    pub cgroup_enforced: bool,
    /// Network mode: "off", "on", or "allowlist".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_mode: Option<String>,
    /// Network allowlist rules (present when mode is "allowlist").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_rules: Option<Vec<NetworkRuleSummary>>,
    /// Whether interactive PTY mode was used.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub interactive: bool,
    /// Signer label if the manifest was signed (e.g. "work-laptop (a1b2c3d4..)").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
}

/// Summary of a network allow rule for structured output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRuleSummary {
    /// Target hostname or CIDR.
    pub target: String,
    /// Port number.
    pub port: u16,
    /// Protocol (tcp/udp).
    pub protocol: String,
}

/// Cgroup v2 resource accounting summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSummary {
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

/// Trace observations summary for machine consumption.
///
/// Simplified view of the full `TraceSummary` from oaie-observe — includes
/// counts and top items, not the full event log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSummaryOutput {
    /// Number of unique files read by the sandboxed process.
    pub files_read: u64,
    /// Number of unique files written.
    pub files_written: u64,
    /// Number of successful network connections.
    pub net_connects: u64,
    /// Number of denied network connections.
    pub net_denied: u64,
    /// Number of processes spawned (exec events).
    pub processes_spawned: u64,
    /// Number of suspicious activities detected.
    pub suspicious_count: u64,
    /// Total events captured by the tracer.
    pub total_events: u64,
}

// ── Session structured output ──

/// Machine-readable result of a completed session.
///
/// Used by `oaie session run --output=json` (future) and programmatic consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredSessionResult {
    /// Unique session identifier (UUIDv7).
    pub session_id: String,
    /// Optional human-readable name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Final session state ("stopped", "timed_out", "budget_exhausted").
    pub status: String,
    /// Containment profile name ("local", "cloud", "strict", "interactive").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containment: Option<String>,
    /// LLM provider metadata ("anthropic", "openai", "google", "local", "custom").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm_provider: Option<String>,
    /// Number of tool calls dispatched.
    pub tool_calls: u32,
    /// Total wall-clock time in seconds.
    pub wall_time_s: u64,
    /// Total cumulative tool execution time in seconds.
    pub total_tool_time_s: u64,
    /// Total output bytes across all tool calls.
    pub total_output_bytes: u64,
    /// Individual tool call results.
    pub calls: Vec<StructuredCallResult>,
    /// Hash of the session manifest in CAS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_hash: Option<String>,
}

/// Machine-readable result of a single tool call within a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredCallResult {
    /// Sequence number within the session (1-based).
    pub seq: u32,
    /// OAIE run ID for this tool call.
    pub run_id: String,
    /// Command that was executed (argv).
    pub command: Vec<String>,
    /// Process exit code.
    pub exit_code: i32,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}
