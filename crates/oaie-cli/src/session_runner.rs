//! Session runner: persistent agent sandbox with tool dispatch.
//!
//! The `SessionRunner` supervises a long-running agent process inside a sandbox.
//! The agent communicates tool calls to the supervisor via a Unix domain socket,
//! and each tool call becomes a standard OAIE run (own sandbox, manifest, DB record)
//! with outputs shared back to the agent via a bind-mounted artifacts directory.
//!
//! Wire protocol: JSON newline-delimited over `dispatch.sock`.
//! - Agent → Supervisor: [`DispatchRequest`]
//! - Supervisor → Agent: [`DispatchResponse`]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixListener;
use std::path::{Component, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chrono::Utc;

use oaie_cas::store::CasStore;
use oaie_core::backend::BackendKind;
use oaie_core::config::OaieStore;
use oaie_core::error::{OaieError, Result};
use oaie_core::hash_algo::{HashAlgorithm, StreamingHasher};
use oaie_core::job::{JobSpec, TraceMode};
use oaie_core::session::{
    AgentSandboxMode, BudgetExtensionRequest, DispatchRequest, DispatchResponse, OutputEntry,
    SessionBudget, SessionConfig, SessionEvent, SessionEventKind, SessionId, SessionState,
};
use oaie_db::{OaieDb, SessionCallRecord, SessionRecord};

use crate::policy_resolve::ResolvedPolicy;
use crate::runner::Runner;

/// Maximum size of a single dispatch request line (1 MiB).
///
/// Prevents OOM via unbounded allocation from a malicious or buggy agent
/// sending a multi-GB line without a newline delimiter.
const MAX_DISPATCH_LINE: usize = 1_048_576;

// ── Budget tracking ──

/// Atomic budget counters for concurrent-safe tracking.
struct BudgetUsed {
    tool_calls: AtomicU32,
    tool_time_ms: AtomicU64,
    output_bytes: AtomicU64,
    /// Flags to prevent duplicate budget warning events.
    warned_tool_calls: AtomicBool,
    warned_tool_time: AtomicBool,
    warned_output_bytes: AtomicBool,
}

impl BudgetUsed {
    fn new() -> Self {
        Self {
            tool_calls: AtomicU32::new(0),
            tool_time_ms: AtomicU64::new(0),
            output_bytes: AtomicU64::new(0),
            warned_tool_calls: AtomicBool::new(false),
            warned_tool_time: AtomicBool::new(false),
            warned_output_bytes: AtomicBool::new(false),
        }
    }
}

/// RAII guard that decrements an `AtomicU32` on drop, ensuring the
/// concurrent tool counter is always released even on panic.
struct ActiveToolGuard<'a>(&'a AtomicU32);

impl Drop for ActiveToolGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

// ── Session event writer ──

/// Hash-chained session event log, following the same pattern as
/// `ChunkedEventWriter` in oaie-observe.
pub struct SessionEventWriter {
    events: Vec<SessionEvent>,
    seq: u64,
    prev_hash: String,
    hash_algo: HashAlgorithm,
}

impl SessionEventWriter {
    /// Create a new event writer with the given hash algorithm.
    pub fn new(hash_algo: HashAlgorithm) -> Self {
        // Genesis hash: deterministic per algorithm (same pattern as observe).
        let genesis = format!("oaie-session-genesis-{hash_algo}");
        let genesis_hash = Self::hash_bytes(hash_algo, genesis.as_bytes());
        Self {
            events: Vec::new(),
            seq: 0,
            prev_hash: genesis_hash,
            hash_algo,
        }
    }

    /// Emit a new event and return a reference to it.
    pub fn emit(&mut self, kind: SessionEventKind) -> &SessionEvent {
        let event = SessionEvent {
            seq: self.seq,
            timestamp: Utc::now().to_rfc3339(),
            kind,
            prev_hash: self.prev_hash.clone(),
        };

        // Hash this event to produce the chain link.
        // SessionEvent is always serializable — panic would indicate a logic bug.
        let event_json = serde_json::to_string(&event)
            .expect("SessionEvent must be JSON-serializable");
        self.prev_hash = Self::hash_bytes(self.hash_algo, event_json.as_bytes());
        self.seq += 1;

        self.events.push(event);
        self.events.last().unwrap()
    }

    /// Finalize the event log: returns NDJSON bytes and the chain tip hash.
    pub fn finalize(&self) -> (Vec<u8>, String) {
        let mut buf = Vec::new();
        for event in &self.events {
            // Events were already validated as serializable in emit().
            let line = serde_json::to_string(event)
                .expect("SessionEvent must be JSON-serializable");
            buf.extend_from_slice(line.as_bytes());
            buf.push(b'\n');
        }
        (buf, self.prev_hash.clone())
    }

    /// Number of events emitted so far.
    pub fn event_count(&self) -> u64 {
        self.seq
    }

    /// Hash bytes using the configured algorithm, returning hex string.
    fn hash_bytes(algo: HashAlgorithm, data: &[u8]) -> String {
        let mut hasher = StreamingHasher::new(algo);
        hasher.update(data);
        hasher.finalize().to_hex()
    }
}

// ── Agent process abstraction ──

/// Wraps either a host-side `std::process::Child` or a sandboxed `SandboxedChild`
/// so the dispatch loop code is agnostic to the spawning mechanism.
enum AgentProcess {
    /// Agent running directly on the host via std::process::Command.
    Host(std::process::Child),
    /// Agent running inside a namespace sandbox via spawn_sandboxed.
    Sandboxed {
        pid: nix::unistd::Pid,
        /// True once we've called waitpid (prevents double-wait).
        reaped: bool,
    },
}

impl AgentProcess {
    /// Get the agent's PID (as u32 for file writing).
    fn id(&self) -> u32 {
        match self {
            Self::Host(child) => child.id(),
            Self::Sandboxed { pid, .. } => pid.as_raw() as u32,
        }
    }

    /// Non-blocking check: has the agent exited?
    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        match self {
            Self::Host(child) => {
                child.try_wait().map(|opt| opt.map(|s| s.code().unwrap_or(-1)))
            }
            Self::Sandboxed { pid, reaped } => {
                use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
                match waitpid(*pid, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(_, code)) => {
                        *reaped = true;
                        Ok(Some(code))
                    }
                    Ok(WaitStatus::Signaled(_, sig, _)) => {
                        *reaped = true;
                        Ok(Some(128 + sig as i32))
                    }
                    Ok(WaitStatus::StillAlive) => Ok(None),
                    Ok(_) => Ok(None), // Other states (stopped, continued)
                    Err(nix::errno::Errno::ECHILD) => {
                        *reaped = true;
                        Ok(Some(-1))
                    }
                    Err(e) => Err(std::io::Error::other(e)),
                }
            }
        }
    }

    /// Send SIGKILL and reap the process.
    fn kill_and_wait(&mut self) {
        match self {
            Self::Host(child) => {
                let _ = child.kill();
                let _ = child.wait();
            }
            Self::Sandboxed { pid, reaped } => {
                if !*reaped {
                    let _ = nix::sys::signal::kill(*pid, nix::sys::signal::Signal::SIGKILL);
                    let _ = nix::sys::wait::waitpid(*pid, None);
                    *reaped = true;
                }
            }
        }
    }
}

impl Drop for AgentProcess {
    fn drop(&mut self) {
        // Sandboxed variant needs explicit cleanup to prevent zombie/ns leak.
        if let Self::Sandboxed { pid, reaped } = self {
            if !*reaped {
                let _ = nix::sys::signal::kill(*pid, nix::sys::signal::Signal::SIGKILL);
                let _ = nix::sys::wait::waitpid(*pid, None);
            }
        }
        // Host variant: std::process::Child's Drop handles cleanup.
    }
}

// ── Session runner ──

/// The core session supervisor.
///
/// Manages the lifecycle of a persistent agent sandbox and its tool dispatch loop.
pub struct SessionRunner {
    store: OaieStore,
    cas: CasStore,
    db: OaieDb,
    session_id: SessionId,
    policy: ResolvedPolicy,
    budget: SessionBudget,
    budget_used: BudgetUsed,
    session_dir: PathBuf,
    artifacts_dir: PathBuf,
    event_writer: SessionEventWriter,
    state: SessionState,
    /// ISO 8601 timestamp of session creation, used in manifest.
    created_at: String,
    /// Containment profile name, if `--contained` was used.
    containment: Option<String>,
    /// LLM provider metadata, if `--llm` was specified.
    llm_provider: Option<String>,
    /// Heartbeat interval (0 = disabled). Agent must dispatch at least one
    /// activity within this interval or the session is terminated.
    heartbeat_interval: Duration,
    /// Tool filter for allowlist/denylist (Phase N.2).
    tool_filter: Option<oaie_core::session::ToolFilter>,
    /// Tools denied network access (Phase N.3).
    deny_network_tools: Vec<String>,
    /// Approval policy (Phase O.3).
    approval: oaie_core::session::ApprovalPolicy,
    /// Maximum agent stdout+stderr output in bytes (0 = unlimited, Phase N.4).
    max_agent_output_bytes: u64,
    /// Whether the agent runs inside a sandbox (Phase O.1).
    agent_sandbox_mode: AgentSandboxMode,
    /// Maximum concurrent tool calls (Phase Q.1.2).
    max_concurrent_tools: u32,
    /// Counter for currently executing tool calls (Phase Q.1.2).
    active_tools: AtomicU32,
}

/// Result of a completed session.
#[derive(Debug)]
pub struct SessionResult {
    /// Session ID.
    pub session_id: SessionId,
    /// Human-readable name (if any).
    pub name: Option<String>,
    /// Final session state.
    pub state: SessionState,
    /// Number of tool calls dispatched.
    pub tool_calls: u32,
    /// Total wall-clock time in seconds.
    pub wall_time_s: u64,
    /// Total cumulative tool time in seconds.
    pub total_tool_time_s: u64,
    /// Total output bytes across all tool calls.
    pub total_output_bytes: u64,
    /// Hash of the session manifest in CAS.
    pub manifest_hash: Option<String>,
}

impl SessionRunner {
    /// Create a new session, allocating directories and DB record.
    pub fn create(
        store: OaieStore,
        policy: ResolvedPolicy,
        config: SessionConfig,
        command: &[String],
    ) -> Result<Self> {
        let session_id = oaie_core::session::new_session_id();
        let cas = CasStore::new(store.cas_dir.clone(), store.hash_algorithm);
        let db = OaieDb::open(&store.db_path)?;

        // Create session directory structure.
        let session_dir = store.root.join("sessions").join(session_id.to_string());
        let artifacts_dir = session_dir.join("artifacts");
        fs::create_dir_all(&artifacts_dir)?;

        // Insert session record in DB.
        let command_json = serde_json::to_string(command)
            .map_err(|e| OaieError::Io(std::io::Error::other(e)))?;
        let budget_json = serde_json::to_string(&config.budget)
            .map_err(|e| OaieError::Io(std::io::Error::other(e)))?;

        let network_mode_str = match &policy.network {
            oaie_core::policy::NetworkMode::Off => "off",
            oaie_core::policy::NetworkMode::On => "on",
            oaie_core::policy::NetworkMode::Allowlist(_) => "allowlist",
        };

        let created_at = Utc::now().to_rfc3339();
        db.insert_session(&SessionRecord {
            session_id: session_id.to_string(),
            name: config.name.clone(),
            created: created_at.clone(),
            stopped: None,
            status: SessionState::Running.as_str().to_string(),
            command: command_json,
            policy: policy.name.clone(),
            network_mode: Some(network_mode_str.to_string()),
            budget_json: Some(budget_json),
            manifest_hash: None,
            error_message: None,
            containment: config.containment.clone(),
            llm_provider: config.llm_provider.clone(),
        })?;

        let event_writer = SessionEventWriter::new(store.hash_algorithm);

        let heartbeat_interval = if config.heartbeat_interval_s > 0 {
            Duration::from_secs(config.heartbeat_interval_s)
        } else {
            Duration::ZERO
        };

        Ok(Self {
            store,
            cas,
            db,
            session_id,
            policy,
            budget: config.budget,
            budget_used: BudgetUsed::new(),
            session_dir,
            artifacts_dir,
            event_writer,
            state: SessionState::Running,
            created_at,
            containment: config.containment,
            llm_provider: config.llm_provider,
            heartbeat_interval,
            tool_filter: config.tool_filter,
            deny_network_tools: config.deny_network_tools,
            approval: config.approval,
            max_agent_output_bytes: config.max_agent_output_bytes,
            agent_sandbox_mode: config.agent_sandbox,
            max_concurrent_tools: config.max_concurrent_tools,
            active_tools: AtomicU32::new(0),
        })
    }

    /// Run the session: spawn agent, enter dispatch loop, finalize on exit.
    ///
    /// `command`: the agent command to run inside the sandbox.
    /// `quiet`: suppress status output.
    ///
    /// Returns the session result on completion.
    pub fn run(mut self, command: &[String], quiet: bool) -> Result<SessionResult> {
        let name_for_result = self.policy.name.clone();
        let start = Instant::now();

        // Emit SessionStart event.
        self.event_writer.emit(SessionEventKind::SessionStart {
            command: command.to_vec(),
        });

        // Set up the dispatch socket and artifacts directory.
        let sock_path = self.session_dir.join("dispatch.sock");

        // Remove any stale socket file.
        let _ = fs::remove_file(&sock_path);

        let listener = UnixListener::bind(&sock_path).map_err(|e| {
            OaieError::SandboxError(format!("bind dispatch socket: {e}"))
        })?;
        // Restrict socket access to the current user only.
        fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o600)).map_err(|e| {
            OaieError::SandboxError(format!("set socket permissions: {e}"))
        })?;
        // Non-blocking accept so we can check the agent process status.
        listener.set_nonblocking(true).map_err(|e| {
            OaieError::SandboxError(format!("set socket non-blocking: {e}"))
        })?;

        // Determine whether we need to count agent output (N.4).
        let counting_output = self.max_agent_output_bytes > 0 && !quiet;

        // Spawn the agent process.
        // Host mode: bare process with env vars pointing to host paths.
        // Sandboxed mode (O.1): namespace sandbox with dispatch socket and
        // artifacts dir bind-mounted at /oaie/ inside the sandbox.
        let sandboxed = self.agent_sandbox_mode == AgentSandboxMode::Sandboxed;

        // In-sandbox paths for the agent env vars.
        let (sock_env, artifacts_env) = if sandboxed {
            ("/oaie/dispatch.sock".to_string(), "/oaie/artifacts".to_string())
        } else {
            (
                sock_path.to_string_lossy().into_owned(),
                self.artifacts_dir.to_string_lossy().into_owned(),
            )
        };

        let agent_output_bytes = std::sync::Arc::new(AtomicU64::new(0));
        let agent_kill_flag = std::sync::Arc::new(AtomicBool::new(false));
        let mut tee_handles: Vec<std::thread::JoinHandle<()>> = Vec::new();

        let mut agent = if sandboxed {
            // O.1: Spawn agent inside a namespace sandbox.
            use oaie_sandbox::sandbox::{SandboxConfig, SessionMount};

            // Build sandbox config with session mounts for dispatch socket and artifacts.
            let sandbox_config = SandboxConfig {
                input_dir: PathBuf::from("."),
                output_dir: self.artifacts_dir.clone(),
                session_mounts: vec![
                    SessionMount {
                        source: sock_path.clone(),
                        target: "/oaie/dispatch.sock".into(),
                        writable: true,
                    },
                    SessionMount {
                        source: self.artifacts_dir.clone(),
                        target: "/oaie/artifacts".into(),
                        writable: true,
                    },
                ],
                network: self.policy.network.clone(),
                proc_mount: true,
                allow_memfd: self.policy.allow_memfd,
                ..SandboxConfig::default()
            };

            let env_vars = vec![
                ("OAIE_DISPATCH_SOCK".into(), sock_env.clone()),
                ("OAIE_SESSION_ID".into(), self.session_id.to_string()),
                ("OAIE_ARTIFACTS_DIR".into(), artifacts_env.clone()),
            ];

            let mut sandboxed_child = oaie_sandbox::sandbox::spawn_sandboxed(
                &sandbox_config,
                command,
                &env_vars,
                false, // no ptrace for agent
                None,  // no post_map_hook
            )?;

            let pid = sandboxed_child.pid;

            // Extract pipes for tee threads (both quiet/counting and inherit cases).
            // In sandboxed mode, stdout/stderr are always piped.
            let stdout_pipe = sandboxed_child.take_stdout();
            let stderr_pipe = sandboxed_child.take_stderr();
            sandboxed_child.mark_reaped(); // We manage lifecycle via AgentProcess.

            // Set up tee threads for sandboxed stdout/stderr.
            if !quiet {
                if let Some(stdout) = stdout_pipe {
                    let counter = agent_output_bytes.clone();
                    let limit = self.max_agent_output_bytes;
                    let kill = agent_kill_flag.clone();
                    tee_handles.push(std::thread::spawn(move || {
                        let mut reader = std::io::BufReader::new(stdout);
                        let mut real_stdout = std::io::stdout().lock();
                        let mut buf = [0u8; 8192];
                        loop {
                            let n = match Read::read(&mut reader, &mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            if counting_output {
                                let total = counter.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
                                let _ = std::io::Write::write_all(&mut real_stdout, &buf[..n]);
                                if total > limit {
                                    kill.store(true, Ordering::Relaxed);
                                    break;
                                }
                            } else {
                                let _ = std::io::Write::write_all(&mut real_stdout, &buf[..n]);
                            }
                        }
                    }));
                }
                if let Some(stderr) = stderr_pipe {
                    let counter = agent_output_bytes.clone();
                    let limit = self.max_agent_output_bytes;
                    let kill = agent_kill_flag.clone();
                    tee_handles.push(std::thread::spawn(move || {
                        let mut reader = std::io::BufReader::new(stderr);
                        let mut real_stderr = std::io::stderr().lock();
                        let mut buf = [0u8; 8192];
                        loop {
                            let n = match Read::read(&mut reader, &mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            if counting_output {
                                let total = counter.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
                                let _ = std::io::Write::write_all(&mut real_stderr, &buf[..n]);
                                if total > limit {
                                    kill.store(true, Ordering::Relaxed);
                                    break;
                                }
                            } else {
                                let _ = std::io::Write::write_all(&mut real_stderr, &buf[..n]);
                            }
                        }
                    }));
                }
            }

            AgentProcess::Sandboxed { pid, reaped: false }
        } else {
            // Host mode: standard process with env vars pointing to host paths.
            let mut child = std::process::Command::new(&command[0])
                .args(&command[1..])
                .env("OAIE_DISPATCH_SOCK", &sock_env)
                .env("OAIE_SESSION_ID", self.session_id.to_string())
                .env("OAIE_ARTIFACTS_DIR", &artifacts_env)
                .stdin(std::process::Stdio::null())
                .stdout(if quiet {
                    std::process::Stdio::null()
                } else if counting_output {
                    std::process::Stdio::piped()
                } else {
                    std::process::Stdio::inherit()
                })
                .stderr(if quiet {
                    std::process::Stdio::null()
                } else if counting_output {
                    std::process::Stdio::piped()
                } else {
                    std::process::Stdio::inherit()
                })
                .spawn()
                .map_err(|e| OaieError::SandboxError(format!("spawn agent: {e}")))?;

            // Agent output counting tee threads (N.4 + Q.1.3 rate limiting).
            if counting_output {
                let rate_limit = self.budget.max_agent_output_rate;
                if let Some(stdout) = child.stdout.take() {
                    let counter = agent_output_bytes.clone();
                    let limit = self.max_agent_output_bytes;
                    let kill = agent_kill_flag.clone();
                    tee_handles.push(std::thread::spawn(move || {
                        let mut reader = std::io::BufReader::new(stdout);
                        let mut real_stdout = std::io::stdout().lock();
                        let mut buf = [0u8; 8192];
                        let mut window_bytes: u64 = 0;
                        let mut window_start = Instant::now();
                        loop {
                            let n = match Read::read(&mut reader, &mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            let total = counter.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
                            let _ = std::io::Write::write_all(&mut real_stdout, &buf[..n]);
                            if total > limit {
                                kill.store(true, Ordering::Relaxed);
                                break;
                            }
                            // Rate limit check (Q.1.3).
                            if rate_limit > 0 {
                                if window_start.elapsed() >= Duration::from_secs(1) {
                                    window_bytes = 0;
                                    window_start = Instant::now();
                                }
                                window_bytes += n as u64;
                                if window_bytes > rate_limit {
                                    kill.store(true, Ordering::Relaxed);
                                    break;
                                }
                            }
                        }
                    }));
                }
                if let Some(stderr) = child.stderr.take() {
                    let counter = agent_output_bytes.clone();
                    let limit = self.max_agent_output_bytes;
                    let kill = agent_kill_flag.clone();
                    tee_handles.push(std::thread::spawn(move || {
                        let mut reader = std::io::BufReader::new(stderr);
                        let mut real_stderr = std::io::stderr().lock();
                        let mut buf = [0u8; 8192];
                        let mut window_bytes: u64 = 0;
                        let mut window_start = Instant::now();
                        loop {
                            let n = match Read::read(&mut reader, &mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            let total = counter.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
                            let _ = std::io::Write::write_all(&mut real_stderr, &buf[..n]);
                            if total > limit {
                                kill.store(true, Ordering::Relaxed);
                                break;
                            }
                            // Rate limit check (Q.1.3).
                            if rate_limit > 0 {
                                if window_start.elapsed() >= Duration::from_secs(1) {
                                    window_bytes = 0;
                                    window_start = Instant::now();
                                }
                                window_bytes += n as u64;
                                if window_bytes > rate_limit {
                                    kill.store(true, Ordering::Relaxed);
                                    break;
                                }
                            }
                        }
                    }));
                }
            }

            AgentProcess::Host(child)
        };

        // Write agent PID so `session stop` can send SIGTERM.
        let pid_path = self.session_dir.join("agent.pid");
        let _ = fs::write(&pid_path, agent.id().to_string());

        // Enter the dispatch loop.
        let expected_agent_pid = agent.id();
        let loop_result = self.dispatch_loop(
            &listener,
            &mut agent,
            start,
            &agent_kill_flag,
            Some(expected_agent_pid),
        );

        // Kill the agent if still running.
        agent.kill_and_wait();

        // Wait for tee threads to finish (they'll EOF after child exits).
        for handle in tee_handles {
            let _ = handle.join();
        }

        // Clean up the socket and PID files.
        let _ = fs::remove_file(&sock_path);
        let _ = fs::remove_file(&pid_path);

        // Handle dispatch loop errors.
        if let Err(ref e) = loop_result {
            self.state = SessionState::Stopped;
            self.event_writer.emit(SessionEventKind::SessionStop {
                status: format!("error: {e}"),
            });
        }

        let wall_time_s = start.elapsed().as_secs();

        // Finalize: write manifest, store event log, update DB.
        let manifest_hash = self.finalize(command, wall_time_s)?;

        let result = SessionResult {
            session_id: self.session_id,
            name: name_for_result,
            state: self.state.clone(),
            tool_calls: self.budget_used.tool_calls.load(Ordering::Relaxed),
            wall_time_s,
            total_tool_time_s: self.budget_used.tool_time_ms.load(Ordering::Relaxed) / 1000,
            total_output_bytes: self.budget_used.output_bytes.load(Ordering::Relaxed),
            manifest_hash: Some(manifest_hash),
        };

        loop_result?;
        Ok(result)
    }

    /// The main dispatch loop: accept connections, process tool calls.
    fn dispatch_loop(
        &mut self,
        listener: &UnixListener,
        agent: &mut AgentProcess,
        start: Instant,
        agent_kill_flag: &AtomicBool,
        agent_pid: Option<u32>,
    ) -> Result<()> {
        let wall_timeout = Duration::from_secs(self.budget.max_wall_time_s);
        let mut last_activity = Instant::now();
        let mut last_snapshot = Instant::now();
        let snapshot_interval = Duration::from_secs(30);

        loop {
            // Check agent output budget first (N.4): the tee thread may have
            // killed the pipe causing SIGPIPE on the child, so check this
            // before child exit to get the correct terminal state.
            if agent_kill_flag.load(Ordering::Relaxed) {
                self.state = SessionState::BudgetExhausted;
                self.event_writer.emit(SessionEventKind::BudgetExhausted {
                    budget_name: "agent_output".into(),
                });
                self.event_writer.emit(SessionEventKind::SessionStop {
                    status: "budget_exhausted".into(),
                });
                return Ok(());
            }

            // Check if agent exited.
            match agent.try_wait() {
                Ok(Some(_status)) => {
                    self.state = SessionState::Stopped;
                    self.event_writer.emit(SessionEventKind::SessionStop {
                        status: "stopped".into(),
                    });
                    return Ok(());
                }
                Ok(None) => {} // Still running.
                Err(e) => {
                    return Err(OaieError::SandboxError(format!(
                        "check agent status: {e}"
                    )));
                }
            }

            // Check wall time.
            if start.elapsed() >= wall_timeout {
                self.state = SessionState::TimedOut;
                self.event_writer.emit(SessionEventKind::SessionStop {
                    status: "timed_out".into(),
                });
                return Ok(());
            }

            // Check heartbeat (M.4): if enabled and no activity within interval.
            if !self.heartbeat_interval.is_zero()
                && last_activity.elapsed() >= self.heartbeat_interval
            {
                let elapsed_s = last_activity.elapsed().as_secs();
                self.event_writer.emit(SessionEventKind::HeartbeatTimeout {
                    elapsed_s,
                    interval_s: self.heartbeat_interval.as_secs(),
                });
                self.state = SessionState::Stopped;
                self.event_writer.emit(SessionEventKind::SessionStop {
                    status: "heartbeat_timeout".into(),
                });
                return Ok(());
            }

            // Poll for budget extension file (M.2).
            self.check_budget_extension();

            // Emit resource snapshot every 30s (M.7).
            if last_snapshot.elapsed() >= snapshot_interval {
                self.emit_resource_snapshot(start);
                last_snapshot = Instant::now();
            }

            // Try to accept a connection.
            match listener.accept() {
                Ok((stream, _addr)) => {
                    // SO_PEERCRED: verify connecting process matches the spawned agent (Q.1.1).
                    if let Some(expected_pid) = agent_pid {
                        match get_peer_pid(&stream) {
                            Some(peer_pid) if peer_pid != expected_pid => {
                                oaie_core::log_warn!(
                                    "rejecting connection from PID {peer_pid} (expected {expected_pid})"
                                );
                                continue;
                            }
                            _ => {} // Matched or couldn't determine — allow.
                        }
                    }
                    // Activity detected — reset heartbeat timer.
                    last_activity = Instant::now();
                    // Process all requests on this connection.
                    self.handle_connection(stream, start)?;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No connection ready — sleep briefly and retry.
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    return Err(OaieError::SandboxError(format!(
                        "accept dispatch connection: {e}"
                    )));
                }
            }
        }
    }

    /// Poll for budget extension file (M.2).
    ///
    /// If `budget_extension.json` exists in the session dir, read it, apply
    /// the extensions to the budget, emit an event, and remove the file.
    /// If the session was `BudgetExhausted`, transition back to `Running`.
    fn check_budget_extension(&mut self) {
        let ext_path = self.session_dir.join("budget_extension.json");
        if !ext_path.exists() {
            return;
        }

        let content = match fs::read_to_string(&ext_path) {
            Ok(c) => c,
            Err(e) => {
                oaie_core::log_warn!("read budget extension: {e}");
                let _ = fs::remove_file(&ext_path);
                return;
            }
        };

        // Remove file first to avoid re-processing.
        let _ = fs::remove_file(&ext_path);

        let ext: BudgetExtensionRequest = match serde_json::from_str(&content) {
            Ok(e) => e,
            Err(e) => {
                oaie_core::log_warn!("parse budget extension: {e}");
                return;
            }
        };

        // Apply extensions.
        if ext.add_tool_calls > 0 {
            let old = self.budget.max_tool_calls;
            self.budget.max_tool_calls = old.saturating_add(ext.add_tool_calls);
            self.event_writer.emit(SessionEventKind::BudgetExtension {
                budget_name: "tool_calls".into(),
                old_limit: old as u64,
                new_limit: self.budget.max_tool_calls as u64,
            });
        }
        if ext.add_wall_time_s > 0 {
            let old = self.budget.max_wall_time_s;
            self.budget.max_wall_time_s = old.saturating_add(ext.add_wall_time_s);
            self.event_writer.emit(SessionEventKind::BudgetExtension {
                budget_name: "wall_time".into(),
                old_limit: old,
                new_limit: self.budget.max_wall_time_s,
            });
        }
        if ext.add_tool_time_s > 0 {
            let old = self.budget.max_tool_time_s;
            self.budget.max_tool_time_s = old.saturating_add(ext.add_tool_time_s);
            self.event_writer.emit(SessionEventKind::BudgetExtension {
                budget_name: "tool_time".into(),
                old_limit: old,
                new_limit: self.budget.max_tool_time_s,
            });
        }
        if ext.add_output_bytes > 0 {
            let old = self.budget.max_output_bytes;
            self.budget.max_output_bytes = old.saturating_add(ext.add_output_bytes);
            self.event_writer.emit(SessionEventKind::BudgetExtension {
                budget_name: "output_bytes".into(),
                old_limit: old,
                new_limit: self.budget.max_output_bytes,
            });
        }

        // If session was budget_exhausted and we got more headroom, resume.
        if self.state == SessionState::BudgetExhausted {
            let calls_ok = self.budget_used.tool_calls.load(Ordering::Relaxed)
                < self.budget.max_tool_calls;
            let time_ok = self.budget_used.tool_time_ms.load(Ordering::Relaxed) / 1000
                < self.budget.max_tool_time_s;
            let bytes_ok = self.budget_used.output_bytes.load(Ordering::Relaxed)
                < self.budget.max_output_bytes;
            if calls_ok && time_ok && bytes_ok {
                self.state = SessionState::Running;
            }
        }

        // Update DB budget JSON.
        if let Ok(budget_json) = serde_json::to_string(&self.budget) {
            let _ = self
                .db
                .update_session_budget(&self.session_id.to_string(), &budget_json);
        }
    }

    /// Emit a ResourceSnapshot event with current usage stats (M.7).
    fn emit_resource_snapshot(&mut self, start: Instant) {
        self.event_writer.emit(SessionEventKind::ResourceSnapshot {
            elapsed_s: start.elapsed().as_secs(),
            tool_calls_used: self.budget_used.tool_calls.load(Ordering::Relaxed),
            tool_time_used_s: self.budget_used.tool_time_ms.load(Ordering::Relaxed) / 1000,
            output_bytes_used: self.budget_used.output_bytes.load(Ordering::Relaxed),
        });
    }

    /// Handle a single connection from the agent: read requests, send responses.
    fn handle_connection(
        &mut self,
        stream: std::os::unix::net::UnixStream,
        start: Instant,
    ) -> Result<()> {
        // Set stream to blocking for reads within this connection.
        stream.set_nonblocking(false).map_err(|e| {
            OaieError::SandboxError(format!("set stream blocking: {e}"))
        })?;
        // Timeout reads so we don't block forever if the agent hangs.
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| OaieError::SandboxError(format!("set read timeout: {e}")))?;

        let mut reader = BufReader::new(&stream);
        let mut writer = &stream;

        loop {
            let mut line = String::new();
            // Bounded read: Take limits allocation to MAX_DISPATCH_LINE + 1 bytes,
            // preventing OOM from a malicious agent sending a multi-GB line.
            let n = match BufRead::read_line(
                &mut reader.by_ref().take(MAX_DISPATCH_LINE as u64 + 1),
                &mut line,
            ) {
                Ok(n) => n,
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break; // Timeout on read — return to the dispatch loop.
                }
                Err(_) => break, // Connection closed or error.
            };

            if n == 0 {
                break; // Connection closed.
            }

            // Reject oversized requests.
            if line.len() > MAX_DISPATCH_LINE {
                let resp = DispatchResponse {
                    id: String::new(),
                    run_id: String::new(),
                    exit_code: -1,
                    outputs: vec![],
                    duration_ms: 0,
                    error: Some("dispatch request exceeds 1 MiB size limit".into()),
                };
                let _ = write_response(&mut writer, &resp);
                break; // Can't reliably find next message boundary.
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Parse the dispatch request.
            let request: DispatchRequest = match serde_json::from_str(trimmed) {
                Ok(r) => r,
                Err(e) => {
                    let resp = DispatchResponse {
                        id: String::new(),
                        run_id: String::new(),
                        exit_code: -1,
                        outputs: vec![],
                        duration_ms: 0,
                        error: Some(format!("invalid request: {e}")),
                    };
                    let _ = write_response(&mut writer, &resp);
                    continue;
                }
            };

            // Process the request.
            let response = self.dispatch_tool_call(&request, start);
            write_response(&mut writer, &response)?;
        }

        Ok(())
    }

    /// Process a single tool dispatch request.
    fn dispatch_tool_call(
        &mut self,
        request: &DispatchRequest,
        _start: Instant,
    ) -> DispatchResponse {
        let call_id = &request.id;

        // Validate call_id: reject excessively long, null bytes, or newlines.
        if call_id.len() > 256
            || call_id.contains('\0')
            || call_id.contains('\n')
            || call_id.contains('\r')
        {
            return DispatchResponse {
                id: call_id.chars().take(64).collect(),
                run_id: String::new(),
                exit_code: -1,
                outputs: vec![],
                duration_ms: 0,
                error: Some("invalid call_id: too long or contains control characters".into()),
            };
        }

        // Validate: command must not be empty.
        if request.command.is_empty() {
            return DispatchResponse {
                id: call_id.clone(),
                run_id: String::new(),
                exit_code: -1,
                outputs: vec![],
                duration_ms: 0,
                error: Some("empty command in dispatch request".into()),
            };
        }

        // Handle input artifacts: copy agent-provided files into session_dir/inputs/<call_id>/.
        let call_input_dir = if !request.inputs.is_empty() {
            let input_dir = self.session_dir.join("inputs").join(call_id);
            if let Err(e) = fs::create_dir_all(&input_dir) {
                return DispatchResponse {
                    id: call_id.clone(),
                    run_id: String::new(),
                    exit_code: -1,
                    outputs: vec![],
                    duration_ms: 0,
                    error: Some(format!("create input dir: {e}")),
                };
            }
            for (label, source_path) in &request.inputs {
                // Validate label (same rules as output artifact labels).
                if !is_safe_artifact_label(label) {
                    return DispatchResponse {
                        id: call_id.clone(),
                        run_id: String::new(),
                        exit_code: -1,
                        outputs: vec![],
                        duration_ms: 0,
                        error: Some(format!("unsafe input label: {label:?}")),
                    };
                }
                // Validate source path exists.
                let source = std::path::Path::new(source_path);
                if !source.exists() {
                    return DispatchResponse {
                        id: call_id.clone(),
                        run_id: String::new(),
                        exit_code: -1,
                        outputs: vec![],
                        duration_ms: 0,
                        error: Some(format!("input source not found: {source_path:?}")),
                    };
                }
                let dest = input_dir.join(label);
                // Defense-in-depth: resolved path must stay under input_dir.
                if !dest.starts_with(&input_dir) {
                    return DispatchResponse {
                        id: call_id.clone(),
                        run_id: String::new(),
                        exit_code: -1,
                        outputs: vec![],
                        duration_ms: 0,
                        error: Some(format!("input path escapes session directory: {label:?}")),
                    };
                }
                if let Some(parent) = dest.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if let Err(e) = fs::copy(source, &dest) {
                    return DispatchResponse {
                        id: call_id.clone(),
                        run_id: String::new(),
                        exit_code: -1,
                        outputs: vec![],
                        duration_ms: 0,
                        error: Some(format!("copy input {label:?}: {e}")),
                    };
                }
            }
            Some(input_dir)
        } else {
            None
        };

        // Tool filter check (N.2): deny takes precedence over allow.
        if let Some(ref filter) = self.tool_filter {
            let cmd_name = &request.command[0];
            if !filter.is_allowed(cmd_name) {
                self.event_writer.emit(SessionEventKind::ToolDenied {
                    call_id: call_id.clone(),
                    command: request.command.clone(),
                    reason: "denied by tool filter".into(),
                });
                return DispatchResponse {
                    id: call_id.clone(),
                    run_id: String::new(),
                    exit_code: -1,
                    outputs: vec![],
                    duration_ms: 0,
                    error: Some(format!("tool denied by filter: {cmd_name}")),
                };
            }
        }

        // Approval gate (O.3): if enabled, prompt user before execution.
        if self.approval.tool_call {
            let approved = prompt_approval(call_id, &request.command);
            self.event_writer.emit(SessionEventKind::ApprovalRequired {
                call_id: call_id.clone(),
                command: request.command.clone(),
                approved,
            });
            if !approved {
                return DispatchResponse {
                    id: call_id.clone(),
                    run_id: String::new(),
                    exit_code: -1,
                    outputs: vec![],
                    duration_ms: 0,
                    error: Some("tool call denied by user".into()),
                };
            }
        }

        // Budget check: tool calls.
        let current_calls = self.budget_used.tool_calls.load(Ordering::Relaxed);
        if current_calls >= self.budget.max_tool_calls {
            self.state = SessionState::BudgetExhausted;
            self.event_writer.emit(SessionEventKind::BudgetExhausted {
                budget_name: "tool_calls".into(),
            });
            return DispatchResponse {
                id: call_id.clone(),
                run_id: String::new(),
                exit_code: -1,
                outputs: vec![],
                duration_ms: 0,
                error: Some(format!(
                    "budget exhausted: max_tool_calls ({}) reached",
                    self.budget.max_tool_calls
                )),
            };
        }

        // Budget check: cumulative tool time.
        let used_time_ms = self.budget_used.tool_time_ms.load(Ordering::Relaxed);
        if used_time_ms / 1000 >= self.budget.max_tool_time_s {
            self.state = SessionState::BudgetExhausted;
            self.event_writer.emit(SessionEventKind::BudgetExhausted {
                budget_name: "tool_time".into(),
            });
            return DispatchResponse {
                id: call_id.clone(),
                run_id: String::new(),
                exit_code: -1,
                outputs: vec![],
                duration_ms: 0,
                error: Some(format!(
                    "budget exhausted: max_tool_time ({}s) reached",
                    self.budget.max_tool_time_s
                )),
            };
        }

        // Budget check: output bytes.
        let used_bytes = self.budget_used.output_bytes.load(Ordering::Relaxed);
        if used_bytes >= self.budget.max_output_bytes {
            self.state = SessionState::BudgetExhausted;
            self.event_writer.emit(SessionEventKind::BudgetExhausted {
                budget_name: "output_bytes".into(),
            });
            return DispatchResponse {
                id: call_id.clone(),
                run_id: String::new(),
                exit_code: -1,
                outputs: vec![],
                duration_ms: 0,
                error: Some(format!(
                    "budget exhausted: max_output_bytes ({}) reached",
                    self.budget.max_output_bytes
                )),
            };
        }

        // Emit 80% warnings.
        self.check_budget_warnings(current_calls, used_time_ms, used_bytes);

        // Emit ToolDispatch event.
        self.event_writer.emit(SessionEventKind::ToolDispatch {
            call_id: call_id.clone(),
            command: request.command.clone(),
        });

        // Cap per-call timeout by remaining session budget.
        let remaining_tool_time_s = self
            .budget
            .max_tool_time_s
            .saturating_sub(self.budget_used.tool_time_ms.load(Ordering::Relaxed) / 1000);
        let remaining_wall_time_s = self
            .budget
            .max_wall_time_s
            .saturating_sub(_start.elapsed().as_secs());
        let effective_timeout_s = match request.timeout_s {
            Some(t) => t.min(remaining_tool_time_s).min(remaining_wall_time_s),
            None => remaining_tool_time_s.min(remaining_wall_time_s),
        };

        // Per-tool network deny (N.3): override network to Off for specific tools.
        let tool_network = if self.policy.network.has_connectivity() {
            let cmd_name = &request.command[0];
            let basename = std::path::Path::new(cmd_name)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(cmd_name);
            let denied = self
                .deny_network_tools
                .iter()
                .any(|p| oaie_core::session::glob_match_public(p, basename));
            !denied
        } else {
            false
        };

        // Build a JobSpec for this tool call.
        let job = JobSpec {
            command: request.command.clone(),
            inputs: call_input_dir,
            outputs: None,
            network: tool_network,
            trace: TraceMode::Off,
            timeout: Some(Duration::from_secs(effective_timeout_s)),
            policy: None,
            extra_ro: vec![],
            extra_rw: vec![],
            no_isolation: false,
            backend: BackendKind::Namespace,
            interactive: false,
        };

        // Concurrent tool call semaphore (Q.1.2): reject if already at max.
        let active = self.active_tools.load(Ordering::Relaxed);
        if active >= self.max_concurrent_tools {
            return DispatchResponse {
                id: call_id.clone(),
                run_id: String::new(),
                exit_code: -1,
                outputs: vec![],
                duration_ms: 0,
                error: Some(format!(
                    "concurrent tool limit reached ({} active, max {})",
                    active, self.max_concurrent_tools
                )),
            };
        }
        // RAII guard: always decrements on drop, even on panic.
        self.active_tools.fetch_add(1, Ordering::Relaxed);
        let _tool_guard = ActiveToolGuard(&self.active_tools);

        // Execute via standard Runner pipeline.
        let runner = match Runner::new(self.store.clone()) {
            Ok(r) => r,
            Err(e) => {
                return DispatchResponse {
                    id: call_id.clone(),
                    run_id: String::new(),
                    exit_code: -1,
                    outputs: vec![],
                    duration_ms: 0,
                    error: Some(format!("runner init failed: {e}")),
                };
            }
        };

        let tool_start = Instant::now();
        let run_result = runner.execute(&job, &self.policy, true, None);
        let tool_duration = tool_start.elapsed();

        let response = match run_result {
            Ok(result) => {
                let run_id = result.run_id.full();
                let seq = self.budget_used.tool_calls.fetch_add(1, Ordering::Relaxed) as i64;
                let duration_ms = tool_duration.as_millis().min(u64::MAX as u128) as u64;

                // Update budget counters.
                self.budget_used
                    .tool_time_ms
                    .fetch_add(duration_ms, Ordering::Relaxed);

                // Copy output artifacts to session artifacts directory.
                let call_artifacts_dir = self.artifacts_dir.join(&run_id);
                if let Err(e) = fs::create_dir_all(&call_artifacts_dir) {
                    oaie_core::log_warn!("create session artifacts dir: {e}");
                }
                let mut outputs = Vec::new();
                let mut total_output_size: u64 = 0;

                for artifact in &result.output_artifacts {
                    // Validate artifact label to prevent path traversal.
                    if !is_safe_artifact_label(&artifact.label) {
                        oaie_core::log_warn!(
                            "skipping artifact with unsafe label: {:?}",
                            artifact.label
                        );
                        continue;
                    }
                    let artifact_path = call_artifacts_dir.join(&artifact.label);
                    // Defense-in-depth: resolved path must stay under artifacts dir.
                    if !artifact_path.starts_with(&call_artifacts_dir) {
                        oaie_core::log_warn!(
                            "artifact path escapes session directory: {:?}",
                            artifact.label
                        );
                        continue;
                    }
                    // Read the artifact from CAS and copy to session artifacts.
                    let blob_path = self.cas.blob_path(&artifact.hash);
                    if let Ok(data) = fs::read(&blob_path) {
                        if let Some(parent) = artifact_path.parent() {
                            if let Err(e) = fs::create_dir_all(parent) {
                                oaie_core::log_warn!("create artifact parent dir: {e}");
                                continue;
                            }
                        }
                        if let Err(e) = fs::write(&artifact_path, &data) {
                            oaie_core::log_warn!(
                                "write artifact {}: {e}",
                                artifact_path.display()
                            );
                            continue;
                        }
                        total_output_size += artifact.size;
                        outputs.push(OutputEntry {
                            path: format!("{}/{}", run_id, artifact.label),
                            hash: artifact.hash.to_hex(),
                            size: artifact.size,
                        });
                    }
                }

                // Per-tool workspace merging (Q.1.4): copy outputs to shared workspace.
                let workspace = self.session_dir.join("workspace");
                if let Err(e) = fs::create_dir_all(&workspace) {
                    oaie_core::log_warn!("create workspace dir: {e}");
                }
                for artifact in &result.output_artifacts {
                    if !is_safe_artifact_label(&artifact.label) {
                        continue;
                    }
                    let src = call_artifacts_dir.join(&artifact.label);
                    let dst = workspace.join(&artifact.label);
                    if src.exists() {
                        if let Some(parent) = dst.parent() {
                            let _ = fs::create_dir_all(parent);
                        }
                        // Later tool wins on name conflict (overwrite).
                        let _ = fs::copy(&src, &dst);
                    }
                }

                self.budget_used
                    .output_bytes
                    .fetch_add(total_output_size, Ordering::Relaxed);

                // Record session call in DB.
                let command_json = serde_json::to_string(&request.command).unwrap_or_default();
                if let Err(e) = self.db.insert_session_call(&SessionCallRecord {
                    call_id: call_id.clone(),
                    session_id: self.session_id.to_string(),
                    run_id: run_id.clone(),
                    seq: seq + 1, // 1-based for display.
                    command: command_json,
                    created: Utc::now().to_rfc3339(),
                    duration_ms: Some(duration_ms as i64),
                    exit_code: Some(result.exit_code),
                }) {
                    oaie_core::log_warn!("insert session call record: {e}");
                }

                // Extract trace_hash from run manifest (M.6).
                // Read the manifest to get the trace chain_tip if tracing was active.
                let trace_hash = {
                    let run_dir = self.store.runs_dir.join(result.run_id.full());
                    oaie_cas::store::read_manifest(&run_dir)
                        .ok()
                        .and_then(|m| m.trace.map(|t| t.chain_tip))
                };

                // Emit ToolResult event.
                self.event_writer.emit(SessionEventKind::ToolResult {
                    call_id: call_id.clone(),
                    run_id: run_id.clone(),
                    exit_code: result.exit_code,
                    trace_hash,
                });

                DispatchResponse {
                    id: call_id.clone(),
                    run_id,
                    exit_code: result.exit_code,
                    outputs,
                    duration_ms,
                    error: None,
                }
            }
            Err(e) => {
                self.event_writer.emit(SessionEventKind::ToolResult {
                    call_id: call_id.clone(),
                    run_id: String::new(),
                    exit_code: -1,
                    trace_hash: None,
                });

                DispatchResponse {
                    id: call_id.clone(),
                    run_id: String::new(),
                    exit_code: -1,
                    outputs: vec![],
                    duration_ms: tool_duration.as_millis().min(u64::MAX as u128) as u64,
                    error: Some(format!("tool execution failed: {e}")),
                }
            }
        };

        // active_tools counter is decremented by _tool_guard on drop.
        response
    }

    /// Emit budget warning events at 80% thresholds.
    ///
    /// Each warning fires at most once per session, tracked by AtomicBool flags.
    fn check_budget_warnings(&mut self, calls: u32, time_ms: u64, bytes: u64) {
        let warn_calls = (self.budget.max_tool_calls as f64 * 0.8) as u32;
        if calls >= warn_calls
            && calls > 0
            && !self
                .budget_used
                .warned_tool_calls
                .swap(true, Ordering::Relaxed)
        {
            self.event_writer.emit(SessionEventKind::BudgetWarning {
                budget_name: "tool_calls".into(),
                used: calls as u64,
                limit: self.budget.max_tool_calls as u64,
            });
        }

        let warn_time_ms = (self.budget.max_tool_time_s as f64 * 0.8 * 1000.0) as u64;
        if time_ms >= warn_time_ms
            && !self
                .budget_used
                .warned_tool_time
                .swap(true, Ordering::Relaxed)
        {
            self.event_writer.emit(SessionEventKind::BudgetWarning {
                budget_name: "tool_time".into(),
                used: time_ms / 1000,
                limit: self.budget.max_tool_time_s,
            });
        }

        let warn_bytes = (self.budget.max_output_bytes as f64 * 0.8) as u64;
        if bytes >= warn_bytes
            && !self
                .budget_used
                .warned_output_bytes
                .swap(true, Ordering::Relaxed)
        {
            self.event_writer.emit(SessionEventKind::BudgetWarning {
                budget_name: "output_bytes".into(),
                used: bytes,
                limit: self.budget.max_output_bytes,
            });
        }
    }

    /// Finalize the session: write manifest, store event log, update DB.
    fn finalize(&mut self, command: &[String], wall_time_s: u64) -> Result<String> {
        // Store event log in CAS.
        let (event_bytes, chain_tip) = self.event_writer.finalize();
        let (event_hash, _event_size) = self.cas.store_bytes(&event_bytes)?;

        let tool_calls = self.budget_used.tool_calls.load(Ordering::Relaxed);
        let total_tool_time_s = self.budget_used.tool_time_ms.load(Ordering::Relaxed) / 1000;
        let total_output_bytes = self.budget_used.output_bytes.load(Ordering::Relaxed);

        // Build session manifest TOML.
        let network_mode_str = match &self.policy.network {
            oaie_core::policy::NetworkMode::Off => "off",
            oaie_core::policy::NetworkMode::On => "on",
            oaie_core::policy::NetworkMode::Allowlist(_) => "allowlist",
        };

        // Build TOML array for argv with proper escaping.
        let argv_toml: Vec<String> = command
            .iter()
            .map(|s| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
            .collect();
        let argv_toml_str = format!("[{}]", argv_toml.join(", "));

        // Build calls section from DB.
        let calls = self.db.list_session_calls(&self.session_id.to_string()).unwrap_or_default();
        let calls_toml: Vec<String> = calls
            .iter()
            .map(|c| {
                let cmd: Vec<String> = serde_json::from_str(&c.command).unwrap_or_default();
                // Escape strings for safe TOML embedding.
                let call_id_esc = c.call_id.replace('\\', "\\\\").replace('"', "\\\"");
                let run_id_esc = c.run_id.replace('\\', "\\\\").replace('"', "\\\"");
                // Build TOML array for command.
                let cmd_array: Vec<String> = cmd
                    .iter()
                    .map(|s| {
                        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
                    })
                    .collect();
                format!(
                    "[[session.calls]]\nseq = {}\ncall_id = \"{}\"\nrun_id = \"{}\"\ncommand = [{}]\nexit_code = {}\nduration_ms = {}\n",
                    c.seq,
                    call_id_esc,
                    run_id_esc,
                    cmd_array.join(", "),
                    c.exit_code.unwrap_or(-1),
                    c.duration_ms.unwrap_or(0),
                )
            })
            .collect();

        let stopped_at = Utc::now().to_rfc3339();

        // Escape strings for safe TOML embedding (handles quotes and backslashes).
        let name_escaped = self
            .policy
            .name
            .as_deref()
            .unwrap_or("")
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        let policy_escaped = self
            .policy
            .name
            .as_deref()
            .unwrap_or("custom")
            .replace('\\', "\\\\")
            .replace('"', "\\\"");

        // Build optional [session.agent] section for containment metadata.
        let agent_section = {
            let mut lines = Vec::new();
            if self.containment.is_some() || self.llm_provider.is_some() {
                lines.push("[session.agent]".to_string());
                if let Some(ref c) = self.containment {
                    lines.push(format!(
                        "containment = \"{}\"",
                        c.replace('\\', "\\\\").replace('"', "\\\"")
                    ));
                }
                if let Some(ref p) = self.llm_provider {
                    lines.push(format!(
                        "llm_provider = \"{}\"",
                        p.replace('\\', "\\\\").replace('"', "\\\"")
                    ));
                }
                lines.push(String::new()); // blank line separator
            }
            lines.join("\n")
        };

        let manifest_content = format!(
            "[session]\n\
             version = 1\n\
             session_id = \"{}\"\n\
             name = \"{}\"\n\
             created = \"{}\"\n\
             stopped = \"{}\"\n\
             status = \"{}\"\n\
             hash_algorithm = \"{}\"\n\
             \n\
             [session.command]\n\
             argv = {}\n\
             \n\
             [session.policy]\n\
             name = \"{}\"\n\
             network_mode = \"{}\"\n\
             \n\
             {}\
             [session.budget]\n\
             max_tool_calls = {}\n\
             max_wall_time_s = {}\n\
             max_tool_time_s = {}\n\
             max_output_bytes = {}\n\
             \n\
             [session.stats]\n\
             tool_calls = {}\n\
             wall_time_s = {}\n\
             total_tool_time_s = {}\n\
             total_output_bytes = {}\n\
             \n\
             [session.trace]\n\
             event_count = {}\n\
             chain_tip = \"{}:{}\"\n\
             event_log_hash = \"{}:{}\"\n\
             \n\
             {}\n",
            self.session_id,
            name_escaped,
            self.created_at,
            stopped_at,
            self.state.as_str(),
            self.store.hash_algorithm,
            argv_toml_str,
            policy_escaped,
            network_mode_str,
            agent_section,
            self.budget.max_tool_calls,
            self.budget.max_wall_time_s,
            self.budget.max_tool_time_s,
            self.budget.max_output_bytes,
            tool_calls,
            wall_time_s,
            total_tool_time_s,
            total_output_bytes,
            self.event_writer.event_count(),
            self.store.hash_algorithm,
            chain_tip,
            self.store.hash_algorithm,
            event_hash.to_hex(),
            calls_toml.join("\n"),
        );

        // Write manifest to session dir.
        let manifest_path = self.session_dir.join("session_manifest.toml");
        fs::write(&manifest_path, &manifest_content)?;

        // Store manifest in CAS.
        let (manifest_hash, _) = self.cas.store_bytes(manifest_content.as_bytes())?;
        let manifest_hash_hex = manifest_hash.to_hex();

        // Update DB.
        self.db.complete_session(
            &self.session_id.to_string(),
            self.state.as_str(),
            Some(&manifest_hash_hex),
            None,
        )?;

        Ok(manifest_hash_hex)
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }
}

/// Write a JSON response followed by a newline to the socket.
fn write_response(writer: &mut impl Write, response: &DispatchResponse) -> Result<()> {
    let json = serde_json::to_string(response)
        .map_err(|e| OaieError::Io(std::io::Error::other(e)))?;
    writer
        .write_all(json.as_bytes())
        .map_err(OaieError::Io)?;
    writer
        .write_all(b"\n")
        .map_err(OaieError::Io)?;
    writer.flush().map_err(OaieError::Io)?;
    Ok(())
}

/// Stop a running session by sending SIGTERM to the agent process.
///
/// This is used by `oaie session stop <id>` — it reads the agent PID from
/// the session directory and sends SIGTERM. The session runner's dispatch loop
/// will detect the child exit and finalize normally.
///
/// The DB update uses a conditional check: we only mark the session as stopped
/// if it's still in "running" state. If the dispatch loop has already finalized
/// the session (with a manifest hash), this avoids overwriting that result.
pub fn stop_session(
    db: &OaieDb,
    session_id: &str,
    store_root: &std::path::Path,
) -> Result<()> {
    let session = db
        .get_session(session_id)?
        .ok_or_else(|| OaieError::Database(format!("session not found: {session_id}")))?;

    if session.status != "running" && session.status != "starting" {
        return Err(OaieError::Other(format!(
            "session {} is not running (status: {})",
            session_id, session.status
        )));
    }

    // Try to signal the agent process via the PID file.
    let pid_path = store_root
        .join("sessions")
        .join(session_id)
        .join("agent.pid");
    if let Ok(pid_str) = fs::read_to_string(&pid_path) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            if pid > 0 {
                // SIGTERM for graceful shutdown. Ignore error (process may have exited).
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGTERM,
                );
            }
        }
    }

    // Mark as stopped in DB — only if still running. If the dispatch loop
    // already finalized, this is a no-op (complete_session returns "not found"
    // only if session_id doesn't exist, but the session exists — just already
    // completed). We ignore the error in that case.
    if let Err(e) = db.complete_session(session_id, "stopped", None, Some("stopped by user")) {
        // If the session was already finalized by the dispatch loop, that's OK.
        if session.status == "running" {
            return Err(e);
        }
    }

    Ok(())
}

/// Validate an artifact label is safe for use as a filename.
///
/// Rejects absolute paths, parent directory traversal (`..`), and empty labels.
fn is_safe_artifact_label(label: &str) -> bool {
    if label.is_empty() {
        return false;
    }
    let path = std::path::Path::new(label);
    for component in path.components() {
        match component {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return false,
            _ => {}
        }
    }
    true
}

/// Get the PID of the peer process connected to a Unix domain socket (Q.1.1).
///
/// Uses `SO_PEERCRED` to retrieve the peer's credentials. Returns `None` if
/// the call fails (e.g., not a Unix socket).
fn get_peer_pid(stream: &std::os::unix::net::UnixStream) -> Option<u32> {
    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret == 0 && cred.pid > 0 {
        Some(cred.pid as u32)
    } else {
        None
    }
}

/// Prompt the user for approval before executing a tool call (O.3).
///
/// Writes a prompt to stderr, reads y/N from stdin. Returns true if approved.
fn prompt_approval(call_id: &str, command: &[String]) -> bool {
    use std::io::BufRead;
    let cmd_display = command.join(" ");
    eprint!("OAIE: Approve tool call {call_id}? [{cmd_display}] (y/N): ");
    let stdin = std::io::stdin();
    let mut line = String::new();
    if stdin.lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim(), "y" | "Y" | "yes" | "YES")
}
