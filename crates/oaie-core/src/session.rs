//! Core types for session mode — persistent agent sandboxes with tool dispatch.
//!
//! A session hosts a long-running agent process inside a sandbox. The agent
//! communicates tool calls to the supervisor via a Unix domain socket, and
//! each tool call becomes a standard OAIE run (own sandbox, manifest, DB record).
//!
//! All types here are pure data (no I/O, no heavy deps) so they can be used
//! by any crate in the workspace.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{OaieError, Result};

/// Unique session identifier (UUIDv7, same as RunId).
pub type SessionId = uuid::Uuid;

/// Generate a new time-ordered session identifier.
pub fn new_session_id() -> SessionId {
    uuid::Uuid::now_v7()
}

/// Session lifecycle states.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// Session is starting up (agent sandbox being created).
    Starting,
    /// Agent process is running and dispatch loop is active.
    Running,
    /// Graceful shutdown in progress (SIGTERM sent to agent).
    Stopping,
    /// Agent exited normally or was stopped.
    Stopped,
    /// Wall-clock timeout expired.
    TimedOut,
    /// One or more budget limits were exhausted.
    BudgetExhausted,
}

impl SessionState {
    /// Convert to the string stored in the database.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::TimedOut => "timed_out",
            Self::BudgetExhausted => "budget_exhausted",
        }
    }

    /// Parse from database string representation.
    pub fn parse(s: &str) -> Self {
        match s {
            "starting" => Self::Starting,
            "running" => Self::Running,
            "stopping" => Self::Stopping,
            "stopped" => Self::Stopped,
            "timed_out" => Self::TimedOut,
            "budget_exhausted" => Self::BudgetExhausted,
            _ => {
                crate::log_warn!("unknown session state in DB: {s:?}, treating as Stopped");
                Self::Stopped
            }
        }
    }
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Resource budget for a session.
///
/// Limits are checked before each tool dispatch. When any limit is reached,
/// the dispatch is rejected and the session transitions to `BudgetExhausted`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionBudget {
    /// Maximum number of tool calls the session may dispatch (default: 50).
    pub max_tool_calls: u32,
    /// Maximum wall-clock time for the entire session in seconds (default: 1800 = 30min).
    pub max_wall_time_s: u64,
    /// Maximum cumulative tool execution time in seconds (default: 600 = 10min).
    pub max_tool_time_s: u64,
    /// Maximum cumulative output bytes across all tool calls (default: 1GB).
    pub max_output_bytes: u64,
    /// Maximum cumulative network bytes across all tool calls (0 = unlimited).
    /// Only enforced when nftables is active (allowlist mode).
    #[serde(default)]
    pub max_network_bytes: u64,
    /// Maximum per-second agent output rate in bytes (0 = unlimited).
    /// When exceeded, the agent process is killed.
    #[serde(default)]
    pub max_agent_output_rate: u64,
}

impl Default for SessionBudget {
    fn default() -> Self {
        Self {
            max_tool_calls: 50,
            max_wall_time_s: 1800,
            max_tool_time_s: 600,
            max_output_bytes: 1_073_741_824, // 1 GiB
            max_network_bytes: 0,            // 0 = unlimited
            max_agent_output_rate: 0,        // 0 = unlimited
        }
    }
}

/// Session configuration (from CLI flags + policy).
///
/// `deny_unknown_fields`: this struct carries `agent_sandbox`, the field
/// that decides whether an AI agent runs at supervisor UID. Without
/// deny_unknown_fields, a typo'd TOML key (`agent_sandbox_mode = ...`,
/// `agentSandbox = ...`) would be silently ignored and fall through to
/// the safe default — but the operator wouldn't know their config didn't
/// take. Better to fail at parse.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    /// Optional human-readable session name.
    pub name: Option<String>,
    /// Resource budget for the session.
    pub budget: SessionBudget,
    /// Containment profile name (if `--contained` was used).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containment: Option<String>,
    /// LLM provider metadata (if `--llm` was specified).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm_provider: Option<String>,
    /// Heartbeat interval in seconds (0 = disabled).
    #[serde(default)]
    pub heartbeat_interval_s: u64,
    /// Tool allowlist/denylist filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_filter: Option<ToolFilter>,
    /// Tools denied network access (glob patterns on command basename).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_network_tools: Vec<String>,
    /// Maximum agent stdout+stderr output in bytes (0 = unlimited).
    #[serde(default)]
    pub max_agent_output_bytes: u64,
    /// Whether the agent itself runs inside a sandbox.
    #[serde(default)]
    pub agent_sandbox: AgentSandboxMode,
    /// Approval policy for tool calls.
    #[serde(default)]
    pub approval: ApprovalPolicy,
    /// Maximum number of concurrent tool calls (default: 1).
    /// Defense-in-depth: rejects if a tool call is already executing.
    #[serde(default = "default_max_concurrent_tools")]
    pub max_concurrent_tools: u32,
}

fn default_max_concurrent_tools() -> u32 {
    1
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            name: None,
            budget: SessionBudget::default(),
            containment: None,
            llm_provider: None,
            heartbeat_interval_s: 0,
            tool_filter: None,
            deny_network_tools: Vec::new(),
            max_agent_output_bytes: 0,
            agent_sandbox: AgentSandboxMode::default(),
            approval: ApprovalPolicy::default(),
            max_concurrent_tools: 1,
        }
    }
}

/// Tool allowlist/denylist filter for session tool dispatch.
///
/// Deny takes precedence over allow. Both support simple `*` glob matching
/// on the command basename (first element of argv).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ToolFilter {
    /// If non-empty, only commands matching these patterns are allowed.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Commands matching these patterns are always denied (takes precedence over allow).
    #[serde(default)]
    pub deny: Vec<String>,
}

impl ToolFilter {
    /// Check if a command (basename) is allowed by this filter.
    ///
    /// Deny always takes precedence. If allow list is non-empty, command must
    /// match at least one allow pattern. Empty filter allows everything.
    ///
    /// WHAT THIS DOES AND DOESN'T GATE
    ///
    /// This is an argv[0] gate, not an execution gate. It checks
    /// `basename(command[0])` against allow/deny patterns. It does NOT
    /// inspect what the tool does once it runs.
    ///
    /// Consequence: any allowed tool that can fork+exec bypasses the deny
    /// list for what runs INSIDE its process tree. With allow=["sh"] and
    /// deny=["curl"], `["sh", "-c", "curl ..."]` passes — sh is allowed,
    /// what sh runs is invisible to this check. With allow=["python3"] and
    /// deny=["curl"], `["python3", "-c", "import os; os.system('curl')"]`
    /// passes for the same reason.
    ///
    /// The deny list is therefore only effective when the allow list
    /// excludes everything that can fork+exec arbitrary commands — which
    /// excludes shells, interpreters, `env`, `timeout`, `nice`, `xargs`,
    /// `find -exec`, and most build tools. That's a narrow allowlist.
    ///
    /// Where this IS useful: an allowlist of single-purpose tools that
    /// don't fork (`["jq", "sha256sum", "file"]`). The agent can run those
    /// and nothing else; the check holds because none of them exec argv.
    /// The deny list adds nothing in that case (everything not allowed is
    /// already denied) — drop it, use a tight allowlist alone.
    ///
    /// Where this is NOT a security boundary: any deployment that allows
    /// `sh` or any interpreter. The filter then expresses INTENT (the
    /// session author wanted to deny curl) without expressing a CONSTRAINT
    /// (curl runs anyway). That's documentation, not enforcement.
    ///
    /// This filter gates exec of argv[0]; the bypass is "any allowed tool
    /// execs the denied one". Don't gate sandbox-level capabilities (e.g.
    /// network access) on argv[0] — the bypass there is a full capability
    /// grant.
    pub fn is_allowed(&self, command: &str) -> bool {
        // Extract basename for matching.
        let basename = std::path::Path::new(command).file_name().and_then(|n| n.to_str()).unwrap_or(command);

        // Deny takes precedence.
        for pattern in &self.deny {
            if glob_match(pattern, basename) {
                return false;
            }
        }

        // If allow is empty, everything not denied is allowed.
        if self.allow.is_empty() {
            return true;
        }

        // Must match at least one allow pattern.
        for pattern in &self.allow {
            if glob_match(pattern, basename) {
                return true;
            }
        }

        false
    }
}

/// Simple glob matching: only `*` wildcard (matches any sequence of chars).
/// Public re-export for use in session_runner (deny_network_tools matching).
pub fn glob_match_public(pattern: &str, text: &str) -> bool {
    glob_match(pattern, text)
}

/// Simple glob matching: only `*` wildcard (matches any sequence of chars).
fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == text;
    }
    // Split pattern on `*` and check parts match in order.
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        match text[pos..].find(part) {
            Some(found) => {
                // First part must match at start, last part at end.
                if i == 0 && found != 0 {
                    return false;
                }
                pos += found + part.len();
            }
            None => return false,
        }
    }
    // If pattern ends with *, any trailing text is ok.
    // If not, the last non-empty part must anchor at the end of text.
    // The loop above used find() (first occurrence); when the part
    // appears more than once, pos lands mid-string. ends_with() is the
    // correct end-anchor check.
    if pattern.ends_with('*') {
        true
    } else {
        match parts.iter().rev().find(|p| !p.is_empty()) {
            Some(last) => text.ends_with(last),
            None => true,
        }
    }
}

/// Whether the agent process runs sandboxed or on the host.
///
/// **Default is `Sandboxed`.** The dangerous mode (running an AI-supplied
/// agent at supervisor UID with full host filesystem visibility) must be
/// an explicit operator opt-in, not a silent fallback for any code path
/// that builds `SessionConfig` via `..SessionConfig::default()` or any
/// session.toml that misspells the field name (serde silently ignores
/// unknown fields). The safe mode is the one you get when you forget.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSandboxMode {
    /// Agent runs directly on the host (tools still sandboxed). Operator
    /// opt-in only — for trusted local agents the operator wrote, never
    /// for AI-supplied programs. Reachable via `oaie session start
    /// --unsandboxed-agent`.
    Host,
    /// Agent runs inside a namespace sandbox. The default.
    #[default]
    Sandboxed,
}

/// Approval policy for tool execution in a session.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ApprovalPolicy {
    /// If true, each tool call requires human approval before execution.
    #[serde(default)]
    pub tool_call: bool,
}

/// Tool dispatch request sent by the agent to the supervisor over the Unix socket.
///
/// JSON newline-delimited wire format.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DispatchRequest {
    /// Unique call identifier (assigned by the agent).
    pub id: String,
    /// Command to execute (argv).
    pub command: Vec<String>,
    /// Input artifacts to make available: label → path inside agent sandbox.
    #[serde(default)]
    pub inputs: HashMap<String, String>,
    /// Per-call timeout override in seconds (capped by session budget).
    #[serde(default)]
    pub timeout_s: Option<u64>,
}

/// Tool dispatch response sent by the supervisor to the agent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DispatchResponse {
    /// Call identifier (matches the `DispatchRequest.id`).
    pub id: String,
    /// Run ID of the OAIE run created for this tool call.
    pub run_id: String,
    /// Process exit code of the tool.
    pub exit_code: i32,
    /// Output artifacts produced by the tool.
    pub outputs: Vec<OutputEntry>,
    /// Wall-clock duration of the tool call in milliseconds.
    pub duration_ms: u64,
    /// Error message if the dispatch was rejected (budget exceeded, invalid command).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Output artifact descriptor in a dispatch response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputEntry {
    /// Relative path of the artifact in the session artifacts directory.
    pub path: String,
    /// Content hash (BLAKE3 or SHA-256 hex).
    pub hash: String,
    /// Size in bytes.
    pub size: u64,
}

/// Session event types for the audit log.
///
/// Each event is hash-chained for tamper evidence, following the same
/// pattern as the trace event chain in `oaie-observe`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionEventKind {
    /// Session started.
    SessionStart {
        /// Command used to launch the agent.
        command: Vec<String>,
    },
    /// Session stopped (or was stopped).
    SessionStop {
        /// Final session state.
        status: String,
    },
    /// Tool call dispatched by the agent.
    ToolDispatch {
        /// Call identifier from DispatchRequest.
        call_id: String,
        /// Command being executed.
        command: Vec<String>,
    },
    /// Tool call completed.
    ToolResult {
        /// Call identifier.
        call_id: String,
        /// OAIE run ID for this tool call.
        run_id: String,
        /// Exit code of the tool process.
        exit_code: i32,
        /// Hash of the tool's trace chain tip (if tracing was active).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trace_hash: Option<String>,
    },
    /// Budget threshold warning (emitted at 80% usage).
    BudgetWarning {
        /// Which budget limit is approaching ("tool_calls", "wall_time", etc.).
        budget_name: String,
        /// Current usage value.
        used: u64,
        /// Configured limit.
        limit: u64,
    },
    /// Budget limit exhausted — no more tool calls will be accepted.
    BudgetExhausted {
        /// Which budget limit was reached.
        budget_name: String,
    },
    /// Budget was extended mid-session via `oaie session extend`.
    BudgetExtension {
        /// Which budget field was extended.
        budget_name: String,
        /// New limit value.
        new_limit: u64,
        /// Previous limit value.
        old_limit: u64,
    },
    /// Heartbeat timeout — agent hasn't dispatched any activity within the
    /// configured heartbeat interval.
    HeartbeatTimeout {
        /// Seconds since last activity.
        elapsed_s: u64,
        /// Configured heartbeat interval.
        interval_s: u64,
    },
    /// Periodic resource usage snapshot (emitted every 30s).
    ResourceSnapshot {
        /// Seconds since session start.
        elapsed_s: u64,
        /// Tool calls dispatched so far.
        tool_calls_used: u32,
        /// Cumulative tool execution time in seconds.
        tool_time_used_s: u64,
        /// Cumulative output bytes.
        output_bytes_used: u64,
    },
    /// Tool call was denied by tool filter (allowlist/denylist).
    ToolDenied {
        /// Call identifier.
        call_id: String,
        /// Command that was denied.
        command: Vec<String>,
        /// Reason for denial.
        reason: String,
    },
    /// Agent output chunk (when agent is sandboxed, I/O is mediated).
    AgentOutput {
        /// Output channel: "stdout" or "stderr".
        channel: String,
        /// Text content of the output chunk.
        text: String,
    },
    /// Tool call required approval from the user.
    ApprovalRequired {
        /// Call identifier.
        call_id: String,
        /// Command awaiting approval.
        command: Vec<String>,
        /// Whether the tool call was approved.
        approved: bool,
    },
}

/// Wire message envelope for mediated I/O (Phase O).
///
/// Wraps both dispatch protocol messages and I/O mediation messages
/// in a single envelope. The `msg_type` field discriminates.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "msg_type", rename_all = "snake_case")]
pub enum WireMessage {
    /// Standard tool dispatch request (backward-compatible).
    DispatchRequest(DispatchRequest),
    /// Standard tool dispatch response.
    DispatchResponse(DispatchResponse),
    /// Agent output (stdout/stderr) forwarded through supervisor.
    AgentOutput {
        /// "stdout" or "stderr".
        channel: String,
        /// Text content.
        text: String,
    },
    /// User input forwarded to agent stdin.
    UserInput {
        /// Text to send to agent's stdin.
        text: String,
    },
}

/// Budget extension request, written as `budget_extension.json` in session dir.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BudgetExtensionRequest {
    /// Additional tool calls to grant (0 = no change).
    #[serde(default)]
    pub add_tool_calls: u32,
    /// Additional wall time in seconds (0 = no change).
    #[serde(default)]
    pub add_wall_time_s: u64,
    /// Additional tool time in seconds (0 = no change).
    #[serde(default)]
    pub add_tool_time_s: u64,
    /// Additional output bytes (0 = no change).
    #[serde(default)]
    pub add_output_bytes: u64,
}

/// Single session event (hash-chained for tamper evidence).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionEvent {
    /// Monotonically increasing sequence number within this session.
    pub seq: u64,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Event payload.
    pub kind: SessionEventKind,
    /// Hash of the previous event (or genesis hash for seq=0).
    pub prev_hash: String,
}

// ── Containment profiles ──

/// Pre-built containment profile for session mode.
///
/// Bundles a per-tool sandbox [`Policy`] and a session-level [`SessionBudget`]
/// into an ergonomic preset selected via `--contained=<profile>`. The agent
/// process itself runs unsandboxed on the host; each tool call is individually
/// sandboxed using the profile's policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentProfile {
    /// Local LLM agent (ollama, llama.cpp, vLLM). No network for tools,
    /// generous budget. Agent calls local LLM directly.
    Local,
    /// Cloud LLM agent (Claude, GPT). No network for tools,
    /// moderate budget. Agent calls cloud API on the host.
    Cloud,
    /// Maximum restriction. No network, tight per-tool limits, small budget.
    Strict,
    /// Human-in-the-loop. Generous budget (human is watching),
    /// no network for tools.
    Interactive,
}

impl ContainmentProfile {
    /// String representation used in CLI, DB, and manifests.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Cloud => "cloud",
            Self::Strict => "strict",
            Self::Interactive => "interactive",
        }
    }

    /// Parse a profile name. Returns an error for unrecognized names.
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "local" => Ok(Self::Local),
            "cloud" => Ok(Self::Cloud),
            "strict" => Ok(Self::Strict),
            "interactive" => Ok(Self::Interactive),
            _ => Err(OaieError::Other(format!("unknown containment profile: {s:?} (valid: local, cloud, strict, interactive)"))),
        }
    }

    /// Name of the corresponding policy preset in [`Policy::from_name()`].
    pub fn policy_name(&self) -> &'static str {
        match self {
            Self::Local => "contained-local",
            Self::Cloud => "contained-cloud",
            Self::Strict => "contained-strict",
            Self::Interactive => "contained-interactive",
        }
    }

    /// Session-level budget for this profile.
    pub fn budget(&self) -> SessionBudget {
        match self {
            Self::Local => SessionBudget {
                max_tool_calls: 100,
                max_wall_time_s: 3600,           // 1h
                max_tool_time_s: 1800,           // 30m
                max_output_bytes: 2_147_483_648, // 2 GiB
                ..SessionBudget::default()
            },
            Self::Cloud => SessionBudget {
                max_tool_calls: 50,
                max_wall_time_s: 1800,           // 30m
                max_tool_time_s: 600,            // 10m
                max_output_bytes: 1_073_741_824, // 1 GiB
                ..SessionBudget::default()
            },
            Self::Strict => SessionBudget {
                max_tool_calls: 20,
                max_wall_time_s: 600,          // 10m
                max_tool_time_s: 300,          // 5m
                max_output_bytes: 268_435_456, // 256 MiB
                ..SessionBudget::default()
            },
            Self::Interactive => SessionBudget {
                max_tool_calls: 200,
                max_wall_time_s: 7200,           // 2h
                max_tool_time_s: 3600,           // 1h
                max_output_bytes: 2_147_483_648, // 2 GiB
                ..SessionBudget::default()
            },
        }
    }

    /// Human-readable description of this profile.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Local => "Local LLM agent: no network, generous budget (100 calls, 1h wall)",
            Self::Cloud => "Cloud LLM agent: no network, moderate budget (50 calls, 30m wall)",
            Self::Strict => "Maximum restriction: no network, tight limits (20 calls, 10m wall)",
            Self::Interactive => "Human-in-the-loop: no network, generous budget (200 calls, 2h wall)",
        }
    }

    /// Network mode for the agent process when running in sandbox mode (O.5).
    ///
    /// When the agent itself is sandboxed (`--sandbox-agent`), it needs network
    /// access to call LLM APIs. Cloud and interactive profiles get full host
    /// network (or narrowed via `agent_network_for_provider()`). Local and
    /// strict profiles deny agent network access.
    pub fn agent_network_mode(&self) -> crate::policy::NetworkMode {
        match self {
            Self::Cloud | Self::Interactive => {
                // Agent needs network for cloud LLM API calls.
                // Default to full access; narrowed by agent_network_for_provider().
                crate::policy::NetworkMode::On
            }
            Self::Local | Self::Strict => crate::policy::NetworkMode::Off,
        }
    }

    /// List all available containment profiles with descriptions.
    pub fn list_all() -> Vec<(&'static str, &'static str)> {
        vec![
            ("local", ContainmentProfile::Local.description()),
            ("cloud", ContainmentProfile::Cloud.description()),
            ("strict", ContainmentProfile::Strict.description()),
            ("interactive", ContainmentProfile::Interactive.description()),
        ]
    }
}

/// Narrow agent network to a specific LLM provider's API endpoints (O.5).
///
/// When `--llm=anthropic` (or openai/google) is specified alongside
/// `--sandbox-agent`, restricts the agent's network to only that provider's
/// API endpoint via allowlist. Returns `None` for "custom" or unknown
/// providers (use the profile's default `agent_network_mode()` instead).
pub fn agent_network_for_provider(provider: &str) -> Option<crate::policy::NetworkMode> {
    use crate::policy::{AllowRule, NetworkMode};

    match provider {
        "anthropic" => Some(NetworkMode::Allowlist(vec![AllowRule {
            host: Some("api.anthropic.com".into()),
            cidr: None,
            port: 443,
            protocol: "tcp".into(),
        }])),
        "openai" => Some(NetworkMode::Allowlist(vec![AllowRule {
            host: Some("api.openai.com".into()),
            cidr: None,
            port: 443,
            protocol: "tcp".into(),
        }])),
        "google" => Some(NetworkMode::Allowlist(vec![AllowRule {
            host: Some("generativelanguage.googleapis.com".into()),
            cidr: None,
            port: 443,
            protocol: "tcp".into(),
        }])),
        "local" => Some(NetworkMode::Off),
        _ => None, // "custom" or unknown: use profile default
    }
}

impl fmt::Display for ContainmentProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
