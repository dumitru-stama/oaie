//! Database index for OAIE run and artifact metadata.
//!
//! Provides [`OaieDb`] which wraps a backend-specific implementation behind the
//! [`DbBackend`] trait. Two backends are available:
//!
//! - **SQLite** (default): local file, WAL mode, zero config.
//! - **PostgreSQL**: remote or local server, selected via `--pgsql` at init.
//!
//! The backend is selected at construction time via [`OaieDb::from_config()`] or
//! the convenience methods [`OaieDb::open()`] (SQLite file) and
//! [`OaieDb::open_in_memory()`] (SQLite in-memory for tests).
//!
//! All backend-specific errors are converted to `OaieError::Database(String)`
//! so that `oaie-core` never depends on any database driver crate.

use std::path::Path;

use chrono::{DateTime, Utc};
use oaie_core::error::{OaieError, Result};
use oaie_core::run_id::RunId;
use oaie_core::store_config::DatabaseConfig;

mod sqlite;
mod postgres_backend;

/// Current schema version. Bumped on migrations.
pub const SCHEMA_VERSION: i64 = 4;

// ── Data types ──

/// Database health check result from [`OaieDb::check_health()`].
#[derive(Clone, Debug)]
pub struct DbHealth {
    /// Number of run records in the database.
    pub run_count: u64,
    /// Whether the database is in WAL journal mode (always true for PostgreSQL).
    pub wal_mode: bool,
}

/// Run lifecycle state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunStatus {
    /// Run is currently executing.
    Running,
    /// Run finished successfully (exit code available).
    Completed,
    /// Run failed (error message available).
    Failed,
}

impl RunStatus {
    /// Convert to the string stored in the database.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    /// Parse from the string stored in the database.
    /// Defaults to `Running` only for the literal "running" string;
    /// any other value is also treated as `Running` with a warning log,
    /// since a corrupt DB value shouldn't crash the process.
    pub fn parse(s: &str) -> Self {
        match s {
            "running" => Self::Running,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            other => {
                oaie_core::log_warn!("unknown run status in DB: {other:?}, treating as Running");
                Self::Running
            }
        }
    }
}

impl std::fmt::Display for RunStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A stored run record mapping to the `runs` table.
#[derive(Clone, Debug)]
pub struct RunRecord {
    /// UUIDv7 identifying this run.
    pub run_id: RunId,
    /// When the run was created (ISO 8601).
    pub created: DateTime<Utc>,
    /// The command that was executed (stored as JSON array).
    pub command: Vec<String>,
    /// Process exit code, None if still running or killed.
    pub exit_code: Option<i32>,
    /// Wall-clock duration in milliseconds, None if still running.
    pub duration_ms: Option<i64>,
    /// Isolation level applied: "full", "partial", or "none".
    /// This is a summary string; the full `IsolationInfo` (with namespace list
    /// and network flag) lives in the manifest TOML, not in the DB index.
    pub isolation: String,
    /// Run lifecycle state.
    pub status: RunStatus,
    /// BLAKE3 hash of manifest.toml, set after run completion.
    pub manifest_hash: Option<String>,
    /// Error message if the run failed.
    pub error_message: Option<String>,
}

/// A stored artifact record mapping to the `artifacts` table.
#[derive(Clone, Debug)]
pub struct ArtifactRecord {
    /// BLAKE3 hex hash identifying the content blob in CAS.
    pub hash: String,
    /// The run this artifact belongs to.
    pub run_id: RunId,
    /// Human-readable label: "stdout", "stderr", "output/result.txt".
    pub label: String,
    /// Classification: "stdout", "stderr", "output", "trace", "report", "manifest".
    pub artifact_type: String,
    /// Blob size in bytes.
    pub size: i64,
    /// When this artifact was stored (ISO 8601).
    pub created: DateTime<Utc>,
}

/// A stored session record mapping to the `sessions` table.
#[derive(Clone, Debug)]
pub struct SessionRecord {
    /// UUIDv7 identifying this session.
    pub session_id: String,
    /// Optional human-readable name.
    pub name: Option<String>,
    /// When the session was created (ISO 8601).
    pub created: String,
    /// When the session stopped (ISO 8601), None if still running.
    pub stopped: Option<String>,
    /// Session lifecycle state: "running", "stopped", "timed_out", "budget_exhausted".
    pub status: String,
    /// Agent command (stored as JSON array).
    pub command: String,
    /// Policy name (if any).
    pub policy: Option<String>,
    /// Network mode string ("off", "on", "allowlist").
    pub network_mode: Option<String>,
    /// Session budget as JSON.
    pub budget_json: Option<String>,
    /// Hash of the session manifest in CAS (set on completion).
    pub manifest_hash: Option<String>,
    /// Error message if the session failed.
    pub error_message: Option<String>,
    /// Containment profile name ("local", "cloud", "strict", "interactive").
    pub containment: Option<String>,
    /// LLM provider metadata ("anthropic", "openai", "google", "local", "custom").
    pub llm_provider: Option<String>,
}

/// A stored session call record mapping to the `session_calls` table.
#[derive(Clone, Debug)]
pub struct SessionCallRecord {
    /// Unique call identifier.
    pub call_id: String,
    /// Parent session ID.
    pub session_id: String,
    /// OAIE run ID for this tool call.
    pub run_id: String,
    /// Sequence number within the session.
    pub seq: i64,
    /// Command that was executed (stored as JSON array).
    pub command: String,
    /// When this call was created (ISO 8601).
    pub created: String,
    /// Duration of the tool call in milliseconds.
    pub duration_ms: Option<i64>,
    /// Process exit code.
    pub exit_code: Option<i32>,
}

// ── Backend trait ──

/// Trait defining the database operations that each backend must implement.
///
/// All methods take `&self` for API consistency. Backends that need interior
/// mutability (e.g. PostgreSQL's `Client`) use `Mutex` internally.
pub trait DbBackend {
    /// Initialize the database schema. Idempotent — safe to call repeatedly.
    fn initialize(&self) -> Result<()>;

    /// Insert a new run record.
    fn insert_run(&self, run: &RunRecord) -> Result<()>;

    /// Mark a run as completed with its results.
    fn complete_run(
        &self,
        run_id: &RunId,
        exit_code: i32,
        duration_ms: i64,
        manifest_hash: &str,
    ) -> Result<()>;

    /// Mark a run as failed with an error message.
    fn fail_run(&self, run_id: &RunId, error: &str) -> Result<()>;

    /// Get a run by its full RunId.
    fn get_run(&self, run_id: &RunId) -> Result<Option<RunRecord>>;

    /// Find a run by prefix match on run_id.
    fn get_run_by_prefix(&self, prefix: &str) -> Result<RunRecord>;

    /// Get the most recent run by creation timestamp.
    fn get_latest_run(&self) -> Result<Option<RunRecord>>;

    /// List recent runs, most recent first.
    fn list_runs(&self, limit: usize) -> Result<Vec<RunRecord>>;

    /// List ALL runs (no limit), most recent first.
    fn list_all_runs(&self) -> Result<Vec<RunRecord>>;

    /// Insert an artifact record.
    fn insert_artifact(&self, artifact: &ArtifactRecord) -> Result<()>;

    /// List all artifacts for a given run.
    fn list_artifacts(&self, run_id: &RunId) -> Result<Vec<ArtifactRecord>>;

    /// Delete a run and its artifact records from the database (atomically).
    ///
    /// Does NOT handle filesystem cleanup — that's done by [`OaieDb::delete_run()`].
    fn delete_run_records(&self, run_id: &RunId) -> Result<()>;

    /// Complete a run and insert all its artifacts in a single transaction.
    /// Reduces lock acquisitions from N+1 to 1 under concurrent load.
    /// Default implementation calls `complete_run` + N × `insert_artifact`
    /// sequentially; backends may override with a single transaction.
    fn complete_run_with_artifacts(
        &self,
        run_id: &RunId,
        exit_code: i32,
        duration_ms: i64,
        manifest_hash: &str,
        artifacts: &[ArtifactRecord],
    ) -> Result<()> {
        self.complete_run(run_id, exit_code, duration_ms, manifest_hash)?;
        for artifact in artifacts {
            self.insert_artifact(artifact)?;
        }
        Ok(())
    }

    /// Check database health: run count and journal mode.
    fn check_health(&self) -> Result<DbHealth>;

    /// Get the current schema version.
    fn schema_version(&self) -> Result<i64>;

    /// Name of this backend for diagnostics ("sqlite" or "postgresql").
    fn backend_name(&self) -> &'static str;

    // ── Session operations ──

    /// Insert a new session record.
    fn insert_session(&self, session: &SessionRecord) -> Result<()> {
        let _ = session;
        Err(OaieError::Database("sessions not supported by this backend".into()))
    }

    /// Mark a session as completed with final state.
    fn complete_session(
        &self,
        session_id: &str,
        status: &str,
        manifest_hash: Option<&str>,
        error_message: Option<&str>,
    ) -> Result<()> {
        let _ = (session_id, status, manifest_hash, error_message);
        Err(OaieError::Database("sessions not supported by this backend".into()))
    }

    /// Get a session by its full ID.
    fn get_session(&self, session_id: &str) -> Result<Option<SessionRecord>> {
        let _ = session_id;
        Err(OaieError::Database("sessions not supported by this backend".into()))
    }

    /// List recent sessions, most recent first.
    fn list_sessions(&self, limit: usize) -> Result<Vec<SessionRecord>> {
        let _ = limit;
        Err(OaieError::Database("sessions not supported by this backend".into()))
    }

    /// Insert a session call record.
    fn insert_session_call(&self, call: &SessionCallRecord) -> Result<()> {
        let _ = call;
        Err(OaieError::Database("sessions not supported by this backend".into()))
    }

    /// List all calls for a given session, ordered by sequence number.
    fn list_session_calls(&self, session_id: &str) -> Result<Vec<SessionCallRecord>> {
        let _ = session_id;
        Err(OaieError::Database("sessions not supported by this backend".into()))
    }

    /// Update the budget JSON for a session (used by budget extension).
    fn update_session_budget(&self, session_id: &str, budget_json: &str) -> Result<()> {
        let _ = (session_id, budget_json);
        Err(OaieError::Database("sessions not supported by this backend".into()))
    }
}

// ── Shared helper ──

/// Raw row data extracted from either SQLite or PostgreSQL before parsing.
///
/// Used as a transfer struct so the shared `RawRow::into_record()` conversion
/// doesn't need 9 separate parameters.
pub(crate) struct RawRow {
    pub run_id: String,
    pub created: String,
    pub command: String,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<i64>,
    pub isolation: String,
    pub status: String,
    pub manifest_hash: Option<String>,
    pub error_message: Option<String>,
}

impl RawRow {
    /// Parse raw string fields into a typed RunRecord.
    pub fn into_record(self) -> Result<RunRecord> {
        let run_id: RunId = self
            .run_id
            .parse()
            .map_err(|_| OaieError::InvalidRunId(self.run_id.clone()))?;
        let created = DateTime::parse_from_rfc3339(&self.created)
            .map_err(|e| OaieError::Io(std::io::Error::other(e)))?
            .with_timezone(&Utc);
        let command: Vec<String> = serde_json::from_str(&self.command)
            .map_err(|e| OaieError::Io(std::io::Error::other(e)))?;

        Ok(RunRecord {
            run_id,
            created,
            command,
            exit_code: self.exit_code,
            duration_ms: self.duration_ms,
            isolation: self.isolation,
            status: RunStatus::parse(&self.status),
            manifest_hash: self.manifest_hash,
            error_message: self.error_message,
        })
    }
}

// ── OaieDb wrapper ──

/// Database index for OAIE run and artifact metadata.
///
/// Wraps a backend-specific implementation selected at construction time.
/// Use [`from_config()`](Self::from_config) for config-driven construction,
/// or [`open()`](Self::open) / [`open_in_memory()`](Self::open_in_memory)
/// for direct SQLite access.
pub struct OaieDb {
    backend: Box<dyn DbBackend>,
}

impl OaieDb {
    /// Open the database using a [`DatabaseConfig`] from `config.toml`.
    ///
    /// For SQLite, relative paths are resolved against `store_root`.
    /// For PostgreSQL, the `url` is used directly to connect.
    ///
    /// Returns an error if the requested backend feature is not compiled in.
    pub fn from_config(config: &DatabaseConfig, store_root: &Path) -> Result<Self> {
        match config {
            DatabaseConfig::Sqlite { path } => {
                let p = std::path::Path::new(path);
                let full_path = if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    store_root.join(path)
                };
                let backend = sqlite::SqliteBackend::open(&full_path)?;
                Ok(Self {
                    backend: Box::new(backend),
                })
            }
            DatabaseConfig::Postgresql { url } => {
                let backend = postgres_backend::PostgresBackend::connect(url)?;
                Ok(Self {
                    backend: Box::new(backend),
                })
            }
        }
    }

    /// Open (or create) a SQLite database at the given path.
    ///
    /// Convenience method — equivalent to `from_config(Sqlite { path }, ...)`.
    /// Kept for backward compatibility with existing callers.
    pub fn open(path: &Path) -> Result<Self> {
        let backend = sqlite::SqliteBackend::open(path)?;
        Ok(Self {
            backend: Box::new(backend),
        })
    }

    /// Open an in-memory SQLite database (for testing and dry runs).
    pub fn open_in_memory() -> Result<Self> {
        let backend = sqlite::SqliteBackend::open_in_memory()?;
        Ok(Self {
            backend: Box::new(backend),
        })
    }

    /// Name of the active backend ("sqlite" or "postgresql").
    pub fn backend_name(&self) -> &'static str {
        self.backend.backend_name()
    }

    // ── Delegated methods ──

    /// Initialize the database schema. Idempotent.
    pub fn initialize(&self) -> Result<()> {
        self.backend.initialize()
    }

    /// Insert a new run record.
    pub fn insert_run(&self, run: &RunRecord) -> Result<()> {
        self.backend.insert_run(run)
    }

    /// Mark a run as completed with its results.
    pub fn complete_run(
        &self,
        run_id: &RunId,
        exit_code: i32,
        duration_ms: i64,
        manifest_hash: &str,
    ) -> Result<()> {
        self.backend
            .complete_run(run_id, exit_code, duration_ms, manifest_hash)
    }

    /// Mark a run as failed with an error message.
    pub fn fail_run(&self, run_id: &RunId, error: &str) -> Result<()> {
        self.backend.fail_run(run_id, error)
    }

    /// Get a run by its full RunId.
    pub fn get_run(&self, run_id: &RunId) -> Result<Option<RunRecord>> {
        self.backend.get_run(run_id)
    }

    /// Find a run by prefix match on run_id.
    ///
    /// - Exactly one match: returns it
    /// - Zero matches: returns RunNotFound
    /// - Multiple matches: returns InvalidRunId listing the ambiguous matches
    pub fn get_run_by_prefix(&self, prefix: &str) -> Result<RunRecord> {
        self.backend.get_run_by_prefix(prefix)
    }

    /// Get the most recent run by creation timestamp.
    pub fn get_latest_run(&self) -> Result<Option<RunRecord>> {
        self.backend.get_latest_run()
    }

    /// List recent runs, most recent first.
    pub fn list_runs(&self, limit: usize) -> Result<Vec<RunRecord>> {
        self.backend.list_runs(limit)
    }

    /// List ALL runs (no limit), most recent first.
    /// Used by `oaie verify --all` and garbage collection.
    pub fn list_all_runs(&self) -> Result<Vec<RunRecord>> {
        self.backend.list_all_runs()
    }

    /// Insert an artifact record.
    pub fn insert_artifact(&self, artifact: &ArtifactRecord) -> Result<()> {
        self.backend.insert_artifact(artifact)
    }

    /// Complete a run and insert all its artifacts in a single transaction.
    pub fn complete_run_with_artifacts(
        &self,
        run_id: &RunId,
        exit_code: i32,
        duration_ms: i64,
        manifest_hash: &str,
        artifacts: &[ArtifactRecord],
    ) -> Result<()> {
        self.backend.complete_run_with_artifacts(
            run_id,
            exit_code,
            duration_ms,
            manifest_hash,
            artifacts,
        )
    }

    /// List all artifacts for a given run.
    pub fn list_artifacts(&self, run_id: &RunId) -> Result<Vec<ArtifactRecord>> {
        self.backend.list_artifacts(run_id)
    }

    /// Delete a run and all its artifact records from the database.
    ///
    /// Uses a transaction so the run and its artifacts are deleted atomically.
    /// Does NOT remove CAS blobs — those are handled by `oaie gc`.
    /// Also removes the run directory from disk if it exists.
    pub fn delete_run(
        &self,
        run_id: &RunId,
        runs_dir: &std::path::Path,
    ) -> Result<()> {
        // Database deletion (transactional).
        self.backend.delete_run_records(run_id)?;

        // Filesystem cleanup outside the transaction (can't be rolled back).
        let run_dir = runs_dir.join(run_id.full());
        if run_dir.exists() {
            std::fs::remove_dir_all(&run_dir)?;
        }

        Ok(())
    }

    /// Check database health: run count and journal mode.
    ///
    /// Used by `oaie doctor` to verify the DB is accessible and properly
    /// configured. Returns `DbHealth` with basic statistics.
    pub fn check_health(&self) -> Result<DbHealth> {
        self.backend.check_health()
    }

    /// Get the current schema version.
    pub fn schema_version(&self) -> Result<i64> {
        self.backend.schema_version()
    }

    // ── Session operations ──

    /// Insert a new session record.
    pub fn insert_session(&self, session: &SessionRecord) -> Result<()> {
        self.backend.insert_session(session)
    }

    /// Mark a session as completed with final state.
    pub fn complete_session(
        &self,
        session_id: &str,
        status: &str,
        manifest_hash: Option<&str>,
        error_message: Option<&str>,
    ) -> Result<()> {
        self.backend.complete_session(session_id, status, manifest_hash, error_message)
    }

    /// Get a session by its full ID.
    pub fn get_session(&self, session_id: &str) -> Result<Option<SessionRecord>> {
        self.backend.get_session(session_id)
    }

    /// List recent sessions, most recent first.
    pub fn list_sessions(&self, limit: usize) -> Result<Vec<SessionRecord>> {
        self.backend.list_sessions(limit)
    }

    /// Insert a session call record.
    pub fn insert_session_call(&self, call: &SessionCallRecord) -> Result<()> {
        self.backend.insert_session_call(call)
    }

    /// List all calls for a given session, ordered by sequence number.
    pub fn list_session_calls(&self, session_id: &str) -> Result<Vec<SessionCallRecord>> {
        self.backend.list_session_calls(session_id)
    }

    /// Update the budget JSON for a running session.
    pub fn update_session_budget(&self, session_id: &str, budget_json: &str) -> Result<()> {
        self.backend.update_session_budget(session_id, budget_json)
    }
}
