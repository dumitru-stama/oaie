//! The `oaie session` subcommand — manage agent sessions.
//!
//! Sessions host long-running agent processes inside persistent sandboxes.
//! Each tool call from the agent becomes a standard OAIE run with its own
//! sandbox, manifest, and DB record.

use clap::{Args, Subcommand};

use oaie_core::error::{OaieError, Result};
use oaie_core::session::{
    ApprovalPolicy, BudgetExtensionRequest, ContainmentProfile, SessionBudget, SessionConfig,
    ToolFilter,
};

use super::load_store;
use crate::output;

/// Manage agent sessions.
#[derive(Subcommand, Debug)]
pub enum SessionCmd {
    /// Run an agent process in a managed session
    Run(Box<SessionRunCmd>),

    /// List sessions (active + recent)
    List(SessionListCmd),

    /// Show session state and budget consumption
    Status(SessionStatusCmd),

    /// Gracefully stop a running session
    Stop(SessionStopCmd),

    /// Show detailed session report (calls, budget, trace)
    Inspect(SessionInspectCmd),

    /// View raw session event log
    Log(SessionLogCmd),

    /// Extend the budget of a running session
    Extend(SessionExtendCmd),

    /// Attach a shell to a running sandboxed session
    Attach(SessionAttachCmd),

    /// List and show containment profiles
    Profiles(SessionProfilesCmd),
}

impl SessionCmd {
    pub fn execute(&self) -> Result<()> {
        match self {
            Self::Run(cmd) => cmd.execute(),
            Self::List(cmd) => cmd.execute(),
            Self::Status(cmd) => cmd.execute(),
            Self::Stop(cmd) => cmd.execute(),
            Self::Inspect(cmd) => cmd.execute(),
            Self::Log(cmd) => cmd.execute(),
            Self::Extend(cmd) => cmd.execute(),
            Self::Attach(cmd) => cmd.execute(),
            Self::Profiles(cmd) => cmd.execute(),
        }
    }
}

// ── session run ──

/// Run an agent process in a managed session.
#[derive(Args, Debug)]
pub struct SessionRunCmd {
    /// Named policy preset or path to policy TOML file
    #[arg(long)]
    pub policy: Option<std::path::PathBuf>,

    /// Containment profile: local, cloud, strict, interactive
    #[arg(long, value_name = "PROFILE")]
    pub contained: Option<String>,

    /// LLM provider (metadata only): anthropic, openai, google, local, custom
    #[arg(long, value_name = "PROVIDER", value_parser = ["anthropic", "openai", "google", "local", "custom"])]
    pub llm: Option<String>,

    /// Network mode: on, off, allow:host:port, preset:name
    #[arg(long, value_name = "MODE", num_args = 0..=1, default_missing_value = "on")]
    pub net: Option<String>,

    /// Session wall-clock timeout (e.g. "30m", "1h")
    #[arg(long)]
    pub timeout: Option<String>,

    /// Human-readable session name
    #[arg(long)]
    pub name: Option<String>,

    /// Maximum number of tool calls (default: 50, or profile default with --contained)
    #[arg(long)]
    pub budget_tools: Option<u32>,

    /// Maximum wall-clock time in seconds (default: 1800, or profile default)
    #[arg(long)]
    pub budget_wall: Option<u64>,

    /// Maximum cumulative tool execution time in seconds (default: 600, or profile default)
    #[arg(long)]
    pub budget_tool_time: Option<u64>,

    /// Execution backend: namespace (default), bare
    #[arg(long, default_value = "namespace")]
    pub backend: String,

    /// Suppress agent output
    #[arg(long, short = 'q')]
    pub quiet: bool,

    /// Heartbeat interval in seconds (0 = disabled, default: 0)
    #[arg(long, default_value = "0")]
    pub heartbeat: u64,

    /// Allow only these tools (glob patterns on command basename, repeatable)
    #[arg(long, value_name = "PATTERN")]
    pub allow_tools: Vec<String>,

    /// Deny these tools (glob patterns on command basename, repeatable)
    #[arg(long, value_name = "PATTERN")]
    pub deny_tools: Vec<String>,

    /// Deny network access for specific tools (repeatable)
    #[arg(long, value_name = "PATTERN")]
    pub deny_net_tools: Vec<String>,

    /// Maximum agent stdout+stderr output in bytes (0 = unlimited)
    #[arg(long, default_value = "0")]
    pub max_agent_output: u64,

    /// Maximum agent output rate in bytes per second (0 = unlimited)
    #[arg(long, default_value = "0")]
    pub max_agent_rate: u64,

    /// Require human approval before each tool call
    #[arg(long)]
    pub require_approval: bool,

    /// Run agent inside a sandbox (experimental)
    #[arg(long)]
    pub sandbox_agent: bool,

    /// Agent command to run (after --)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

impl SessionRunCmd {
    pub fn execute(&self) -> Result<()> {
        if self.command.is_empty() {
            return Err(OaieError::InvalidJobSpec(
                "specify an agent command after --".into(),
            ));
        }

        // --contained and --policy are mutually exclusive.
        if self.contained.is_some() && self.policy.is_some() {
            return Err(OaieError::Other(
                "--contained and --policy are mutually exclusive".into(),
            ));
        }

        let store = load_store()?;

        // Resolve containment profile (if --contained is set).
        let profile = match &self.contained {
            Some(name) => Some(ContainmentProfile::parse(name)?),
            None => None,
        };

        // Determine the policy path: either from --contained profile or --policy flag.
        let policy_path_buf: Option<std::path::PathBuf>;
        let effective_policy = if let Some(ref p) = profile {
            // Containment profile resolves to a named policy preset.
            policy_path_buf = Some(std::path::PathBuf::from(p.policy_name()));
            policy_path_buf.as_ref()
        } else {
            self.policy.as_ref()
        };

        // Parse --net flag. If --contained is set and --net is not specified,
        // the profile's policy already has network Off. --net can override,
        // but warn if it enables network (weakens containment).
        let net_mode = match &self.net {
            Some(val) => {
                let mode = oaie_core::policy::parse_net_flag(val)?;
                if profile.is_some() && mode.has_connectivity() {
                    output::warn("--net enables network for tool sandboxes, weakening containment profile");
                }
                Some(mode)
            }
            None => None,
        };

        // Resolve policy using PolicyInput.
        let policy_input = oaie_cli::policy_resolve::PolicyInput {
            policy_path: effective_policy,
            net: net_mode,
            timeout: self.timeout.as_deref(),
            ro: &[],
            rw: &[],
            no_auto_mount: true,
            command: &self.command,
            input: None,
            out: None,
            store_default_timeout: Some(&store.timeouts.default_timeout),
            store_max_timeout: Some(&store.timeouts.max_timeout),
            cgroup: "auto",
        };
        let resolved = oaie_cli::policy_resolve::resolve_policy(&policy_input)?;

        // Build session budget. Start from profile defaults (if any), then
        // allow explicit CLI flags to override. Option<> fields let us
        // distinguish "user didn't pass the flag" from "user explicitly set a value".
        let budget = if let Some(ref p) = profile {
            let mut b = p.budget();
            if let Some(v) = self.budget_tools {
                b.max_tool_calls = v;
            }
            if let Some(v) = self.budget_wall {
                b.max_wall_time_s = v;
            }
            if let Some(v) = self.budget_tool_time {
                b.max_tool_time_s = v;
            }
            if self.max_agent_rate > 0 {
                b.max_agent_output_rate = self.max_agent_rate;
            }
            b
        } else {
            SessionBudget {
                max_tool_calls: self.budget_tools.unwrap_or(50),
                max_wall_time_s: self.budget_wall.unwrap_or(1800),
                max_tool_time_s: self.budget_tool_time.unwrap_or(600),
                max_agent_output_rate: self.max_agent_rate,
                ..SessionBudget::default()
            }
        };

        // Validate budget values.
        if budget.max_tool_calls == 0 {
            return Err(OaieError::Other("--budget-tools must be > 0".into()));
        }
        if budget.max_wall_time_s == 0 {
            return Err(OaieError::Other("--budget-wall must be > 0".into()));
        }
        if budget.max_tool_time_s == 0 {
            return Err(OaieError::Other("--budget-tool-time must be > 0".into()));
        }
        if budget.max_tool_time_s > budget.max_wall_time_s {
            output::warn("--budget-tool-time exceeds --budget-wall; tool time will be bounded by wall time");
        }

        // Build tool filter (N.2).
        let tool_filter = if self.allow_tools.is_empty() && self.deny_tools.is_empty() {
            None
        } else {
            Some(ToolFilter {
                allow: self.allow_tools.clone(),
                deny: self.deny_tools.clone(),
            })
        };

        // Build session config.
        let config = SessionConfig {
            name: self.name.clone(),
            budget,
            containment: profile.as_ref().map(|p| p.as_str().to_string()),
            llm_provider: self.llm.clone(),
            heartbeat_interval_s: self.heartbeat,
            tool_filter,
            deny_network_tools: self.deny_net_tools.clone(),
            max_agent_output_bytes: self.max_agent_output,
            agent_sandbox: if self.sandbox_agent {
                oaie_core::session::AgentSandboxMode::Sandboxed
            } else {
                oaie_core::session::AgentSandboxMode::Host
            },
            approval: ApprovalPolicy {
                tool_call: self.require_approval,
            },
            max_concurrent_tools: 1,
        };

        if !self.quiet {
            let profile_info = profile
                .as_ref()
                .map(|p| format!(" [contained: {}]", p.as_str()))
                .unwrap_or_default();
            output::info(&format!(
                "Starting session: {} (budget: {} tool calls, {}s wall time){}",
                output::shell_join(&self.command),
                config.budget.max_tool_calls,
                config.budget.max_wall_time_s,
                profile_info,
            ));
        }

        // Create and run the session.
        let session = oaie_cli::session_runner::SessionRunner::create(
            store,
            resolved,
            config,
            &self.command,
        )?;

        if !self.quiet {
            output::info(&format!("Session ID: {}", session.session_id()));
        }

        let result = session.run(&self.command, self.quiet)?;

        // Print summary.
        if !self.quiet {
            output::header("Session Complete");
            output::field("Session ID", &result.session_id.to_string());
            if let Some(ref name) = result.name {
                output::field("Name", name);
            }
            output::field("Status", &result.state.to_string());
            output::field("Tool calls", &result.tool_calls.to_string());
            output::field("Wall time", &format!("{}s", result.wall_time_s));
            output::field("Tool time", &format!("{}s", result.total_tool_time_s));
            output::field(
                "Output bytes",
                &oaie_cas::store::format_bytes(result.total_output_bytes),
            );
            if let Some(ref hash) = result.manifest_hash {
                output::field("Manifest", &format!("{}...", &hash[..16.min(hash.len())]));
            }
        }

        Ok(())
    }
}

// ── session list ──

/// List sessions (active + recent).
#[derive(Args, Debug)]
pub struct SessionListCmd {
    /// Maximum number of sessions to show (default: 20)
    #[arg(long, short = 'n', default_value = "20")]
    pub limit: usize,
}

impl SessionListCmd {
    pub fn execute(&self) -> Result<()> {
        let store = load_store()?;
        let db = oaie_db::OaieDb::open(&store.db_path)?;
        let sessions = db.list_sessions(self.limit)?;

        if sessions.is_empty() {
            output::info("No sessions found.");
            return Ok(());
        }

        output::header("Sessions");
        let hdr_id = "SESSION ID";
        let hdr_status = "STATUS";
        let hdr_calls = "CALLS";
        let hdr_cont = "CONTAINED";
        let hdr_name = "NAME";
        let hdr_created = "CREATED";
        println!(
            "{hdr_id:<38} {hdr_status:<12} {hdr_calls:<6} {hdr_cont:<12} {hdr_name:<6} {hdr_created}"
        );
        println!("{}", "-".repeat(100));

        for s in &sessions {
            let calls = db
                .list_session_calls(&s.session_id)
                .map(|c| c.len())
                .unwrap_or(0);
            let name = s.name.as_deref().unwrap_or("-");
            let containment = s.containment.as_deref().unwrap_or("-");
            // Truncate created timestamp for display.
            let created = if s.created.len() > 19 {
                &s.created[..19]
            } else {
                &s.created
            };
            println!(
                "{:<38} {:<12} {:<6} {:<12} {:<6} {}",
                s.session_id, s.status, calls, containment, name, created
            );
        }

        Ok(())
    }
}

// ── session status ──

/// Show session state and budget consumption.
#[derive(Args, Debug)]
pub struct SessionStatusCmd {
    /// Session ID (full or prefix)
    pub session_id: String,
}

impl SessionStatusCmd {
    pub fn execute(&self) -> Result<()> {
        let store = load_store()?;
        let db = oaie_db::OaieDb::open(&store.db_path)?;

        let session = db
            .get_session(&self.session_id)?
            .ok_or_else(|| OaieError::Database(format!("session not found: {}", self.session_id)))?;

        let calls = db.list_session_calls(&session.session_id)?;

        output::header("Session Status");
        output::field("Session ID", &session.session_id);
        if let Some(ref name) = session.name {
            output::field("Name", name);
        }
        output::field("Status", &session.status);
        output::field("Created", &session.created);
        if let Some(ref stopped) = session.stopped {
            output::field("Stopped", stopped);
        }

        // Parse and display budget consumption.
        if let Some(ref budget_json) = session.budget_json {
            if let Ok(budget) = serde_json::from_str::<SessionBudget>(budget_json) {
                output::field(
                    "Tool calls",
                    &format!("{} / {}", calls.len(), budget.max_tool_calls),
                );
                let total_time_ms: i64 = calls.iter().filter_map(|c| c.duration_ms).sum();
                output::field(
                    "Tool time",
                    &format!("{}s / {}s", total_time_ms / 1000, budget.max_tool_time_s),
                );
            }
        }

        if let Some(ref containment) = session.containment {
            output::field("Containment", containment);
        }
        if let Some(ref llm) = session.llm_provider {
            output::field("LLM provider", llm);
        }
        if let Some(ref policy) = session.policy {
            output::field("Policy", policy);
        }
        if let Some(ref net) = session.network_mode {
            output::field("Network", net);
        }
        if let Some(ref hash) = session.manifest_hash {
            output::field("Manifest", hash);
        }

        Ok(())
    }
}

// ── session stop ──

/// Gracefully stop a running session.
#[derive(Args, Debug)]
pub struct SessionStopCmd {
    /// Session ID to stop
    pub session_id: String,
}

impl SessionStopCmd {
    pub fn execute(&self) -> Result<()> {
        let store = load_store()?;
        let db = oaie_db::OaieDb::open(&store.db_path)?;

        oaie_cli::session_runner::stop_session(&db, &self.session_id, &store.root)?;
        output::info(&format!("Session {} stopped.", self.session_id));

        Ok(())
    }
}

// ── session inspect ──

/// Show detailed session report with all tool calls.
#[derive(Args, Debug)]
pub struct SessionInspectCmd {
    /// Session ID to inspect
    pub session_id: String,
}

impl SessionInspectCmd {
    pub fn execute(&self) -> Result<()> {
        let store = load_store()?;
        let db = oaie_db::OaieDb::open(&store.db_path)?;

        let session = db
            .get_session(&self.session_id)?
            .ok_or_else(|| OaieError::Database(format!("session not found: {}", self.session_id)))?;

        let calls = db.list_session_calls(&session.session_id)?;

        output::header("Session Report");
        output::field("Session ID", &session.session_id);
        if let Some(ref name) = session.name {
            output::field("Name", name);
        }
        output::field("Status", &session.status);
        output::field("Created", &session.created);
        if let Some(ref stopped) = session.stopped {
            output::field("Stopped", stopped);
        }

        // Command.
        if let Ok(cmd) = serde_json::from_str::<Vec<String>>(&session.command) {
            output::field("Command", &output::shell_join(&cmd));
        }

        // Containment and LLM provider.
        if let Some(ref containment) = session.containment {
            output::field("Containment", containment);
        }
        if let Some(ref llm) = session.llm_provider {
            output::field("LLM provider", llm);
        }

        // Policy and network.
        if let Some(ref policy) = session.policy {
            output::field("Policy", policy);
        }
        if let Some(ref net) = session.network_mode {
            output::field("Network", net);
        }

        // Budget.
        if let Some(ref budget_json) = session.budget_json {
            if let Ok(budget) = serde_json::from_str::<SessionBudget>(budget_json) {
                println!();
                output::header("Budget");
                output::field("Max tool calls", &budget.max_tool_calls.to_string());
                output::field("Max wall time", &format!("{}s", budget.max_wall_time_s));
                output::field("Max tool time", &format!("{}s", budget.max_tool_time_s));
                output::field(
                    "Max output bytes",
                    &oaie_cas::store::format_bytes(budget.max_output_bytes),
                );

                // Actual usage.
                let total_time_ms: i64 = calls.iter().filter_map(|c| c.duration_ms).sum();
                println!();
                output::header("Usage");
                output::field(
                    "Tool calls",
                    &format!("{} / {}", calls.len(), budget.max_tool_calls),
                );
                output::field(
                    "Tool time",
                    &format!("{}s / {}s", total_time_ms / 1000, budget.max_tool_time_s),
                );
            }
        }

        // Tool calls.
        if !calls.is_empty() {
            println!();
            output::header("Tool Calls");
            let h_seq = "SEQ";
            let h_run = "RUN ID";
            let h_dur = "DURATION";
            let h_exit = "EXIT";
            let h_cmd = "COMMAND";
            println!("{h_seq:<4} {h_run:<38} {h_dur:<10} {h_exit:<6} {h_cmd}");
            println!("{}", "-".repeat(90));

            for call in &calls {
                let cmd: Vec<String> = serde_json::from_str(&call.command).unwrap_or_default();
                let cmd_str = if cmd.is_empty() {
                    call.command.clone()
                } else {
                    output::shell_join(&cmd)
                };
                let duration = call
                    .duration_ms
                    .map(|ms| format!("{}ms", ms))
                    .unwrap_or_else(|| "-".into());
                let exit = call
                    .exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "-".into());
                println!(
                    "{:<4} {:<38} {:<10} {:<6} {}",
                    call.seq, call.run_id, duration, exit, cmd_str
                );
            }
        }

        // Manifest.
        if let Some(ref hash) = session.manifest_hash {
            println!();
            output::field("Manifest hash", hash);
        }

        Ok(())
    }
}

// ── session log (M.1) ──

/// View raw session event log.
#[derive(Args, Debug)]
pub struct SessionLogCmd {
    /// Session ID to view
    pub session_id: String,

    /// Filter by event type: all, tool_call, budget, io
    #[arg(long, default_value = "all", value_parser = ["all", "tool_call", "budget", "io"])]
    pub r#type: String,

    /// Output as raw JSON (one event per line)
    #[arg(long)]
    pub json: bool,
}

impl SessionLogCmd {
    pub fn execute(&self) -> Result<()> {
        let store = load_store()?;
        let db = oaie_db::OaieDb::open(&store.db_path)?;
        let cas = oaie_cas::store::CasStore::new(store.cas_dir.clone(), store.hash_algorithm);

        let session = db
            .get_session(&self.session_id)?
            .ok_or_else(|| OaieError::Database(format!("session not found: {}", self.session_id)))?;

        // Read session manifest to find event_log_hash.
        let session_dir = store.root.join("sessions").join(&session.session_id);
        let manifest_path = session_dir.join("session_manifest.toml");
        let manifest_content = std::fs::read_to_string(&manifest_path).map_err(|e| {
            OaieError::Other(format!("read session manifest: {e}"))
        })?;

        // Parse event_log_hash from manifest TOML.
        let manifest: toml::Value = manifest_content.parse().map_err(|e: toml::de::Error| {
            OaieError::Other(format!("parse session manifest: {e}"))
        })?;

        let event_log_hash_str = manifest
            .get("session")
            .and_then(|s| s.get("trace"))
            .and_then(|t| t.get("event_log_hash"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| OaieError::Other("no event_log_hash in manifest".into()))?;

        // Parse "algo:hex" format.
        let hash_hex = event_log_hash_str
            .split(':')
            .nth(1)
            .unwrap_or(event_log_hash_str);

        let hash = oaie_core::artifact::Hash::from_hex(hash_hex)?;
        let blob_path = cas.blob_path(&hash);
        let ndjson = std::fs::read_to_string(&blob_path).map_err(|e| {
            OaieError::Other(format!("read event log from CAS: {e}"))
        })?;

        let filter_type = &self.r#type;

        for line in ndjson.lines() {
            if line.trim().is_empty() {
                continue;
            }

            // Parse event to check type filter.
            let event: oaie_core::session::SessionEvent = match serde_json::from_str(line) {
                Ok(e) => e,
                Err(_) => continue,
            };

            let matches = match filter_type.as_str() {
                "all" => true,
                "tool_call" => matches!(
                    event.kind,
                    oaie_core::session::SessionEventKind::ToolDispatch { .. }
                        | oaie_core::session::SessionEventKind::ToolResult { .. }
                ),
                "budget" => matches!(
                    event.kind,
                    oaie_core::session::SessionEventKind::BudgetWarning { .. }
                        | oaie_core::session::SessionEventKind::BudgetExhausted { .. }
                        | oaie_core::session::SessionEventKind::BudgetExtension { .. }
                        | oaie_core::session::SessionEventKind::ResourceSnapshot { .. }
                ),
                "io" => matches!(
                    event.kind,
                    oaie_core::session::SessionEventKind::SessionStart { .. }
                        | oaie_core::session::SessionEventKind::SessionStop { .. }
                        | oaie_core::session::SessionEventKind::AgentOutput { .. }
                ),
                _ => true,
            };

            if !matches {
                continue;
            }

            if self.json {
                println!("{line}");
            } else {
                // Human-readable format.
                let kind_str = match &event.kind {
                    oaie_core::session::SessionEventKind::SessionStart { command } => {
                        format!("SESSION_START command={}", command.join(" "))
                    }
                    oaie_core::session::SessionEventKind::SessionStop { status } => {
                        format!("SESSION_STOP status={status}")
                    }
                    oaie_core::session::SessionEventKind::ToolDispatch { call_id, command } => {
                        format!("TOOL_DISPATCH call_id={call_id} command={}", command.join(" "))
                    }
                    oaie_core::session::SessionEventKind::ToolResult {
                        call_id,
                        run_id,
                        exit_code,
                        trace_hash,
                    } => {
                        let th = trace_hash.as_deref().unwrap_or("-");
                        format!("TOOL_RESULT call_id={call_id} run_id={run_id} exit={exit_code} trace={th}")
                    }
                    oaie_core::session::SessionEventKind::BudgetWarning {
                        budget_name,
                        used,
                        limit,
                    } => format!("BUDGET_WARNING {budget_name}: {used}/{limit}"),
                    oaie_core::session::SessionEventKind::BudgetExhausted { budget_name } => {
                        format!("BUDGET_EXHAUSTED {budget_name}")
                    }
                    oaie_core::session::SessionEventKind::BudgetExtension {
                        budget_name,
                        old_limit,
                        new_limit,
                    } => format!("BUDGET_EXTENSION {budget_name}: {old_limit} -> {new_limit}"),
                    oaie_core::session::SessionEventKind::HeartbeatTimeout {
                        elapsed_s,
                        interval_s,
                    } => format!("HEARTBEAT_TIMEOUT elapsed={elapsed_s}s interval={interval_s}s"),
                    oaie_core::session::SessionEventKind::ResourceSnapshot {
                        elapsed_s,
                        tool_calls_used,
                        tool_time_used_s,
                        output_bytes_used,
                    } => format!(
                        "RESOURCE_SNAPSHOT elapsed={elapsed_s}s calls={tool_calls_used} tool_time={tool_time_used_s}s output={output_bytes_used}B"
                    ),
                    oaie_core::session::SessionEventKind::ToolDenied {
                        call_id,
                        command,
                        reason,
                    } => format!("TOOL_DENIED call_id={call_id} command={} reason={reason}", command.join(" ")),
                    oaie_core::session::SessionEventKind::AgentOutput { channel, text } => {
                        format!("AGENT_OUTPUT channel={channel} text={text}")
                    }
                    oaie_core::session::SessionEventKind::ApprovalRequired {
                        call_id,
                        command,
                        approved,
                    } => format!(
                        "APPROVAL call_id={call_id} command={} approved={approved}",
                        command.join(" ")
                    ),
                };
                let ts = if event.timestamp.len() > 19 {
                    &event.timestamp[11..19]
                } else {
                    &event.timestamp
                };
                println!("[{ts}] #{:03} {kind_str}", event.seq);
            }
        }

        Ok(())
    }
}

// ── session extend (M.2) ──

/// Extend the budget of a running session.
#[derive(Args, Debug)]
pub struct SessionExtendCmd {
    /// Session ID to extend
    pub session_id: String,

    /// Additional tool calls to grant
    #[arg(long)]
    pub add_tool_calls: Option<u32>,

    /// Additional wall time in seconds
    #[arg(long)]
    pub add_wall_time: Option<u64>,

    /// Additional tool time in seconds
    #[arg(long)]
    pub add_tool_time: Option<u64>,

    /// Additional output bytes
    #[arg(long)]
    pub add_output_bytes: Option<u64>,
}

impl SessionExtendCmd {
    pub fn execute(&self) -> Result<()> {
        let store = load_store()?;
        let db = oaie_db::OaieDb::open(&store.db_path)?;

        let session = db
            .get_session(&self.session_id)?
            .ok_or_else(|| OaieError::Database(format!("session not found: {}", self.session_id)))?;

        // Only extend running or budget_exhausted sessions.
        if session.status != "running" && session.status != "budget_exhausted" {
            return Err(OaieError::Other(format!(
                "session {} is not running (status: {})",
                self.session_id, session.status
            )));
        }

        let ext = BudgetExtensionRequest {
            add_tool_calls: self.add_tool_calls.unwrap_or(0),
            add_wall_time_s: self.add_wall_time.unwrap_or(0),
            add_tool_time_s: self.add_tool_time.unwrap_or(0),
            add_output_bytes: self.add_output_bytes.unwrap_or(0),
        };

        if ext.add_tool_calls == 0
            && ext.add_wall_time_s == 0
            && ext.add_tool_time_s == 0
            && ext.add_output_bytes == 0
        {
            return Err(OaieError::Other(
                "at least one --add-* flag must be specified".into(),
            ));
        }

        // Write budget_extension.json to session dir for the dispatch loop to pick up.
        let session_dir = store
            .root
            .join("sessions")
            .join(&session.session_id);
        let ext_path = session_dir.join("budget_extension.json");
        let ext_json = serde_json::to_string_pretty(&ext)
            .map_err(|e| OaieError::Other(format!("serialize extension: {e}")))?;
        std::fs::write(&ext_path, ext_json)?;

        output::info(&format!("Budget extension written for session {}", self.session_id));
        if ext.add_tool_calls > 0 {
            output::field("Add tool calls", &ext.add_tool_calls.to_string());
        }
        if ext.add_wall_time_s > 0 {
            output::field("Add wall time", &format!("{}s", ext.add_wall_time_s));
        }
        if ext.add_tool_time_s > 0 {
            output::field("Add tool time", &format!("{}s", ext.add_tool_time_s));
        }
        if ext.add_output_bytes > 0 {
            output::field(
                "Add output bytes",
                &oaie_cas::store::format_bytes(ext.add_output_bytes),
            );
        }

        Ok(())
    }
}

// ── session profiles (Q.1.5 + Q.1.6) ──

/// List and show containment profiles.
#[derive(Args, Debug)]
pub struct SessionProfilesCmd {
    /// Show detailed info for a specific profile
    #[arg(long)]
    pub show: Option<String>,
}

impl SessionProfilesCmd {
    pub fn execute(&self) -> Result<()> {
        if let Some(ref name) = self.show {
            // Show detailed info for a specific profile.
            let profile = ContainmentProfile::parse(name)?;
            let budget = profile.budget();

            output::header(&format!("Profile: {}", profile.as_str()));
            output::field("Description", profile.description());
            output::field("Policy preset", profile.policy_name());
            let net_mode = match profile.agent_network_mode() {
                oaie_core::policy::NetworkMode::Off => "off",
                oaie_core::policy::NetworkMode::On => "on",
                oaie_core::policy::NetworkMode::Allowlist(_) => "allowlist",
            };
            output::field("Agent network", net_mode);

            println!();
            output::header("Budget");
            output::field("Max tool calls", &budget.max_tool_calls.to_string());
            output::field("Max wall time", &format!("{}s", budget.max_wall_time_s));
            output::field("Max tool time", &format!("{}s", budget.max_tool_time_s));
            output::field(
                "Max output bytes",
                &oaie_cas::store::format_bytes(budget.max_output_bytes),
            );
        } else {
            // List all profiles.
            output::header("Containment Profiles");
            let h_name = "PROFILE";
            let h_desc = "DESCRIPTION";
            println!("{h_name:<14} {h_desc}");
            println!("{}", "-".repeat(80));

            for (name, desc) in ContainmentProfile::list_all() {
                println!("{name:<14} {desc}");
            }
        }

        Ok(())
    }
}

// ── session attach (O.4) ──

/// Attach a shell to a running sandboxed session via nsenter.
///
/// Only available when the agent is running in sandboxed mode. Enters the
/// agent's namespaces (mount, UTS, IPC, PID, net) to run `/bin/sh`.
#[derive(Args, Debug)]
pub struct SessionAttachCmd {
    /// Session ID to attach to
    pub session_id: String,
}

impl SessionAttachCmd {
    pub fn execute(&self) -> Result<()> {
        let store = load_store()?;
        let db = oaie_db::OaieDb::open(&store.db_path)?;

        let session = db
            .get_session(&self.session_id)?
            .ok_or_else(|| OaieError::Database(format!("session not found: {}", self.session_id)))?;

        // Only attach to running sessions.
        if session.status != "running" {
            return Err(OaieError::Other(format!(
                "session {} is not running (status: {})",
                self.session_id, session.status
            )));
        }

        // Read agent PID from session dir.
        let session_dir = store.root.join("sessions").join(&session.session_id);
        let pid_path = session_dir.join("agent.pid");
        let pid_str = std::fs::read_to_string(&pid_path).map_err(|e| {
            OaieError::Other(format!(
                "read agent PID (is --sandbox-agent active?): {e}"
            ))
        })?;
        let pid: u32 = pid_str
            .trim()
            .parse()
            .map_err(|e| OaieError::Other(format!("invalid agent PID: {e}")))?;

        // Verify the process is still alive.
        let proc_dir = format!("/proc/{pid}");
        if !std::path::Path::new(&proc_dir).exists() {
            return Err(OaieError::Other(format!(
                "agent process {pid} is no longer running"
            )));
        }

        // Enter the agent's namespaces via nsenter.
        output::info(&format!(
            "Attaching to session {} (agent pid {pid})...",
            self.session_id,
        ));

        let status = std::process::Command::new("nsenter")
            .args([
                "-m", "-u", "-i", "-p", "-n",
                "-t", &pid.to_string(),
                "/bin/sh",
            ])
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
            .map_err(|e| OaieError::Other(format!("nsenter failed: {e}")))?;

        if !status.success() {
            output::warn(&format!("nsenter exited with status: {status}"));
        }

        Ok(())
    }
}
