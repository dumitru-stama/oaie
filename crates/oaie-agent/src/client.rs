//! Synchronous OAIE client for agent integration.
//!
//! [`OaieClient`] is a builder that opens an OAIE store, creates a runner,
//! executes commands, and returns structured results. Designed for embedding
//! in AI agent runtimes.

use std::path::PathBuf;

use serde::Serialize;

use oaie_cas::store::CasStore;
use oaie_cli::policy_resolve::{self, PolicyInput, ResolvedPolicy};
use oaie_cli::runner::Runner;
use oaie_cli::verify::verify_run;
use oaie_core::artifact::Hash;
use oaie_core::backend::BackendKind;
use oaie_core::config::OaieStore;
use oaie_core::error::{OaieError, Result};
use oaie_core::job::JobSpec;
use oaie_core::structured_output::StructuredRunResult;
use oaie_db::OaieDb;

use crate::types::VerifyReport;

/// Session status information returned by `OaieClient::session_status()`.
#[derive(Clone, Debug, Serialize)]
pub struct SessionStatusInfo {
    /// Session ID.
    pub session_id: String,
    /// Current status (running, stopped, timed_out, budget_exhausted).
    pub status: String,
    /// Number of tool calls dispatched.
    pub tool_calls: u32,
    /// ISO 8601 creation timestamp.
    pub created: String,
    /// ISO 8601 stop timestamp (if completed).
    pub stopped: Option<String>,
    /// Containment profile name (if `--contained` was used).
    pub containment: Option<String>,
    /// LLM provider (if `--llm` was specified).
    pub llm_provider: Option<String>,
}

/// Synchronous client for running commands through OAIE's sandbox.
///
/// Uses the builder pattern for configuration:
/// ```no_run
/// use oaie_agent::OaieClient;
///
/// let result = OaieClient::new("/home/user/.oaie")
///     .policy("agent-safe")
///     .run(&["echo", "hello"])
///     .unwrap();
/// ```
pub struct OaieClient {
    /// Path to the OAIE store root directory.
    store_path: PathBuf,
    /// Policy preset name or file path (default: "agent-safe").
    policy: String,
    /// Execution backend (default: Namespace).
    backend: BackendKind,
}

impl OaieClient {
    /// Create a new client pointing at the given store directory.
    pub fn new(store_path: impl Into<PathBuf>) -> Self {
        Self {
            store_path: store_path.into(),
            policy: "agent-safe".into(),
            backend: BackendKind::Namespace,
        }
    }

    /// Set the policy preset name or file path.
    pub fn policy(mut self, policy: &str) -> Self {
        self.policy = policy.into();
        self
    }

    /// Set the execution backend.
    pub fn backend(mut self, backend: BackendKind) -> Self {
        self.backend = backend;
        self
    }

    /// Run a command and return structured results.
    ///
    /// Shorthand for building a `JobSpec` with defaults and calling `run_job`.
    pub fn run(&self, command: &[&str]) -> Result<StructuredRunResult> {
        let job = JobSpec {
            command: command.iter().map(|s| (*s).to_string()).collect(),
            inputs: None,
            outputs: None,
            network: false,
            trace: Default::default(),
            timeout: None,
            policy: None,
            extra_ro: vec![],
            extra_rw: vec![],
            no_isolation: self.backend == BackendKind::Bare,
            backend: self.backend.clone(),
            interactive: false,
        };
        self.run_job(&job)
    }

    /// Run with full `JobSpec` control.
    pub fn run_job(&self, job: &JobSpec) -> Result<StructuredRunResult> {
        let store = self.open_store()?;
        let store_path_str = store.root.display().to_string();

        // Format JobSpec timeout as a string for PolicyInput (e.g. "45s").
        // Round up to avoid truncating sub-second precision (Duration 1.5s → "2s").
        let timeout_str = job.timeout.map(|d| {
            let secs = d.as_secs() + if d.subsec_nanos() > 0 { 1 } else { 0 };
            format!("{secs}s")
        });
        let policy_path = PathBuf::from(&self.policy);
        let resolved = self.resolve(&store, &policy_path, job, timeout_str.as_deref())?;

        let runner = Runner::new(store)?;
        let result = runner.execute(job, &resolved, true, None)?;

        Ok(result.to_structured(&job.backend, &store_path_str))
    }

    /// Verify a previous run's integrity.
    pub fn verify(&self, run_id: &str) -> Result<VerifyReport> {
        let store = self.open_store()?;
        let db = OaieDb::open(&store.db_path)?;

        let run = if run_id == "last" {
            db.get_latest_run()?
                .ok_or_else(|| OaieError::Other("no runs found".into()))?
        } else {
            db.get_run_by_prefix(run_id)?
        };

        let report = verify_run(&store, &run.run_id)?;
        Ok(VerifyReport::from(report))
    }

    /// Read an output artifact's raw bytes by label from a run.
    ///
    /// The label matches the artifact label stored in the DB:
    /// "stdout", "stderr", "output/result.txt", etc.
    pub fn read_output(&self, run_id: &str, label: &str) -> Result<Vec<u8>> {
        let store = self.open_store()?;
        let db = OaieDb::open(&store.db_path)?;
        let cas = CasStore::new(store.cas_dir.clone(), store.hash_algorithm);

        let run = if run_id == "last" {
            db.get_latest_run()?
                .ok_or_else(|| OaieError::Other("no runs found".into()))?
        } else {
            db.get_run_by_prefix(run_id)?
        };

        let artifacts = db.list_artifacts(&run.run_id)?;
        let artifact = artifacts
            .iter()
            .find(|a| a.label == label)
            .ok_or_else(|| {
                let available: Vec<&str> = artifacts.iter().map(|a| a.label.as_str()).collect();
                OaieError::ArtifactNotFound(format!(
                    "no artifact '{}' for run {}. available: {}",
                    label,
                    run.run_id.short(),
                    available.join(", ")
                ))
            })?;

        let hash = Hash::from_hex(&artifact.hash)?;
        let blob_path = cas.blob_path(&hash);
        std::fs::read(&blob_path).map_err(|e| {
            OaieError::Other(format!("failed to read blob {}: {e}", hash.short()))
        })
    }

    /// Open the OAIE store from the configured path.
    fn open_store(&self) -> Result<OaieStore> {
        let mut store = OaieStore::from_root(self.store_path.clone());
        if !store.is_initialized() {
            return Err(OaieError::StoreNotInitialized);
        }
        store.open()?;
        Ok(store)
    }

    /// Create a SessionRunner and run it in a background thread.
    ///
    /// Returns the session ID immediately. The session runs in the background.
    /// Use `session_status()` to check progress, `session_stop()` to stop it.
    pub fn session_run(
        &self,
        command: &[&str],
        budget: Option<oaie_core::session::SessionBudget>,
        policy_name: Option<&str>,
    ) -> Result<String> {
        use oaie_cli::session_runner::SessionRunner;
        use oaie_core::session::SessionConfig;

        let store = self.open_store()?;
        let policy_path_str = policy_name.unwrap_or("agent-safe").to_string();
        let cmd: Vec<String> = command.iter().map(|s| s.to_string()).collect();

        let policy_path = std::path::PathBuf::from(&policy_path_str);
        let policy_input = oaie_cli::policy_resolve::PolicyInput {
            policy_path: Some(&policy_path),
            net: None,
            timeout: None,
            ro: &[],
            rw: &[],
            bind_ro: &[],
            bind_rw: &[],
            bind_exec: &[],
            no_auto_mount: true,
            command: &cmd,
            input: None,
            out: None,
            store_default_timeout: Some(&store.timeouts.default_timeout),
            store_max_timeout: Some(&store.timeouts.max_timeout),
            cgroup: "auto",
        };
        let resolved = oaie_cli::policy_resolve::resolve_policy(&policy_input)?;

        let config = SessionConfig {
            budget: budget.unwrap_or_default(),
            // OaieClient is the agent-facing API (MCP / LLM tool calls). The
            // command IS the AI-supplied agent program — it MUST run inside
            // the sandbox, never on the host. SessionConfig::default() gives
            // AgentSandboxMode::Host (the operator-CLI default), which would
            // execute the AI's chosen binary at supervisor UID with full
            // host filesystem visibility.
            agent_sandbox: oaie_core::session::AgentSandboxMode::Sandboxed,
            ..SessionConfig::default()
        };

        let session = SessionRunner::create(store.clone(), resolved.clone(), config.clone(), &cmd)?;
        let session_id = session.session_id().to_string();

        // Run in the current thread (MCP uses background thread externally).
        // We can't move SessionRunner across threads due to OaieDb trait objects.
        // Caller should spawn their own thread if async operation is needed.
        // Propagate the run result so the MCP layer can report a real status
        // instead of an unconditional "completed".
        session.run(&cmd, true)?;

        Ok(session_id)
    }

    /// Query session status from the DB.
    pub fn session_status(&self, session_id: &str) -> Result<SessionStatusInfo> {
        let store = self.open_store()?;
        let db = OaieDb::open(&store.db_path)?;
        let session = db
            .get_session(session_id)?
            .ok_or_else(|| OaieError::Other(format!("session not found: {session_id}")))?;
        let calls = db.list_session_calls(&session.session_id)?;

        Ok(SessionStatusInfo {
            session_id: session.session_id,
            status: session.status,
            tool_calls: calls.len() as u32,
            created: session.created,
            stopped: session.stopped,
            containment: session.containment,
            llm_provider: session.llm_provider,
        })
    }

    /// Stop a running session by sending SIGTERM to the agent.
    pub fn session_stop(&self, session_id: &str) -> Result<()> {
        let store = self.open_store()?;
        let db = OaieDb::open(&store.db_path)?;
        oaie_cli::session_runner::stop_session(&db, session_id, &store.root)
    }

    /// Resolve policy for a job.
    fn resolve(
        &self,
        store: &OaieStore,
        policy_path: &PathBuf,
        job: &JobSpec,
        timeout: Option<&str>,
    ) -> Result<ResolvedPolicy> {
        let policy_input = PolicyInput {
            policy_path: Some(policy_path),
            net: if job.network { Some(oaie_core::policy::NetworkMode::On) } else { None },
            timeout,
            ro: &job.extra_ro,
            rw: &job.extra_rw,
            bind_ro: &[],
            bind_rw: &[],
            bind_exec: &[],
            // OaieClient is the agent-facing API: argv is chosen by an
            // untrusted caller (MCP / LLM tool calls), so the auto_mount
            // heuristic must NOT be allowed to derive host bind-mounts from
            // it. Matches the sibling PolicyInput at session_run / session.rs.
            no_auto_mount: true,
            command: &job.command,
            input: job.inputs.as_ref(),
            out: job.outputs.as_ref(),
            store_default_timeout: Some(&store.timeouts.default_timeout),
            store_max_timeout: Some(&store.timeouts.max_timeout),
            cgroup: "auto",
        };
        policy_resolve::resolve_policy(&policy_input)
    }
}

// ── SessionClient (P.2) ──

/// Typed client for agents running inside an OAIE session.
///
/// Communicates with the session supervisor via a Unix domain socket
/// using the JSON newline-delimited wire protocol. Typically created
/// via `from_env()` which reads `OAIE_DISPATCH_SOCK` and related env vars.
///
/// ```no_run
/// use oaie_agent::SessionClient;
///
/// let client = SessionClient::from_env().unwrap();
/// let resp = client.dispatch("echo", &["hello"]).unwrap();
/// println!("exit code: {}", resp.exit_code);
/// ```
pub struct SessionClient {
    /// Path to the dispatch Unix domain socket.
    sock_path: PathBuf,
    /// Session ID (from `OAIE_SESSION_ID` env var).
    session_id: String,
    /// Artifacts directory (from `OAIE_ARTIFACTS_DIR` env var).
    artifacts_dir: PathBuf,
}

impl SessionClient {
    /// Create a SessionClient from environment variables.
    ///
    /// Reads `OAIE_DISPATCH_SOCK`, `OAIE_SESSION_ID`, and `OAIE_ARTIFACTS_DIR`
    /// from the environment (set by the session runner when spawning the agent).
    pub fn from_env() -> Result<Self> {
        let sock_path = std::env::var("OAIE_DISPATCH_SOCK").map_err(|_| {
            OaieError::Other("OAIE_DISPATCH_SOCK not set (not running in a session?)".into())
        })?;
        let session_id = std::env::var("OAIE_SESSION_ID").map_err(|_| {
            OaieError::Other("OAIE_SESSION_ID not set".into())
        })?;
        let artifacts_dir = std::env::var("OAIE_ARTIFACTS_DIR").map_err(|_| {
            OaieError::Other("OAIE_ARTIFACTS_DIR not set".into())
        })?;

        Ok(Self {
            sock_path: PathBuf::from(sock_path),
            session_id,
            artifacts_dir: PathBuf::from(artifacts_dir),
        })
    }

    /// Create a SessionClient with explicit paths.
    pub fn new(sock_path: PathBuf, session_id: String, artifacts_dir: PathBuf) -> Self {
        Self {
            sock_path,
            session_id,
            artifacts_dir,
        }
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Get the artifacts directory path.
    pub fn artifacts_dir(&self) -> &std::path::Path {
        &self.artifacts_dir
    }

    /// Dispatch a tool call to the session supervisor.
    ///
    /// Connects to the dispatch socket, sends a `DispatchRequest`, reads back
    /// a `DispatchResponse`, and disconnects. Each call is a fresh connection.
    pub fn dispatch(
        &self,
        command: &str,
        args: &[&str],
    ) -> Result<oaie_core::session::DispatchResponse> {
        use std::collections::HashMap;
        let mut argv = vec![command.to_string()];
        argv.extend(args.iter().map(|s| s.to_string()));

        let request = oaie_core::session::DispatchRequest {
            id: generate_call_id(),
            command: argv,
            inputs: HashMap::new(),
            timeout_s: None,
        };

        self.dispatch_request(&request)
    }

    /// Dispatch a tool call with input artifacts.
    pub fn dispatch_with_inputs(
        &self,
        command: &str,
        args: &[&str],
        inputs: std::collections::HashMap<String, String>,
    ) -> Result<oaie_core::session::DispatchResponse> {
        let mut argv = vec![command.to_string()];
        argv.extend(args.iter().map(|s| s.to_string()));

        let request = oaie_core::session::DispatchRequest {
            id: generate_call_id(),
            command: argv,
            inputs,
            timeout_s: None,
        };

        self.dispatch_request(&request)
    }

    /// Get the dispatch socket path.
    pub fn sock_path(&self) -> &std::path::Path {
        &self.sock_path
    }

    /// Send a raw DispatchRequest and read the response.
    fn dispatch_request(
        &self,
        request: &oaie_core::session::DispatchRequest,
    ) -> Result<oaie_core::session::DispatchResponse> {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixStream;

        let stream = UnixStream::connect(&self.sock_path).map_err(|e| {
            OaieError::Other(format!("connect to dispatch socket: {e}"))
        })?;

        // Set a generous read timeout (tool calls can take a while).
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(3600)))
            .map_err(|e| OaieError::Other(format!("set read timeout: {e}")))?;

        let mut writer = &stream;
        let json = serde_json::to_string(request)
            .map_err(|e| OaieError::Other(format!("serialize request: {e}")))?;
        writer.write_all(json.as_bytes()).map_err(OaieError::Io)?;
        writer.write_all(b"\n").map_err(OaieError::Io)?;
        writer.flush().map_err(OaieError::Io)?;

        // Read response.
        let mut reader = BufReader::new(&stream);
        let mut line = String::new();
        reader.read_line(&mut line).map_err(OaieError::Io)?;

        serde_json::from_str(line.trim()).map_err(|e| {
            OaieError::Other(format!("parse dispatch response: {e}"))
        })
    }
}

/// Generate a unique call ID using timestamp + thread ID.
fn generate_call_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tid = std::thread::current().id();
    format!("client-{ts:x}-{tid:?}")
}

