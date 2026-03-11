//! PostgreSQL backend for OAIE database operations.
//!
//! Uses the `postgres` crate (synchronous) for compatibility with the
//! existing synchronous codebase. The connection is wrapped in a `Mutex`
//! because `postgres::Client` requires `&mut self` for queries, while the
//! `DbBackend` trait uses `&self` for API consistency with the SQLite backend.

use std::sync::Mutex;

use oaie_core::error::{OaieError, Result};
use oaie_core::run_id::RunId;

use crate::{
    ArtifactRecord, DbBackend, DbHealth, RunRecord, SessionCallRecord, SessionRecord,
    SCHEMA_VERSION,
};

/// Redact credentials from PostgreSQL connection URLs in error messages.
///
/// Finds `postgresql://...` or `postgres://...` URLs and replaces the password
/// portion (between the last `:` before `@` and the `@`) with `****`.
/// If the string contains no recognizable URL, it is returned unchanged.
fn redact_url(s: &str) -> String {
    // Look for postgresql:// or postgres:// URLs.
    let prefixes = ["postgresql://", "postgres://"];
    let mut result = s.to_string();
    for prefix in &prefixes {
        if let Some(start) = result.find(prefix) {
            let rest = &result[start..];
            if let Some(at_offset) = rest.find('@') {
                // Only search for the password colon AFTER "://", not in the
                // scheme prefix. Without this, a URL without a password like
                // "postgresql://user@host" matches the scheme colon and mangles
                // the output.
                let creds_start = prefix.len();
                let before_at = &rest[creds_start..at_offset];
                if let Some(colon_offset) = before_at.rfind(':') {
                    let abs_colon = start + creds_start + colon_offset;
                    let abs_at = start + at_offset;
                    result = format!("{}****{}", &result[..abs_colon + 1], &result[abs_at..]);
                }
            }
        }
    }
    result
}

/// Bridge: convert postgres errors into OaieError::Database(String),
/// redacting any credentials that may appear in the error message.
fn pg_err(e: postgres::Error) -> OaieError {
    OaieError::Database(redact_url(&e.to_string()))
}

/// PostgreSQL backend wrapping a sync postgres client.
///
/// Uses `Mutex` for interior mutability because `postgres::Client` requires
/// `&mut self` while the `DbBackend` trait takes `&self`. A `Mutex` is used
/// instead of `RefCell` so the backend is safe to share across threads.
pub struct PostgresBackend {
    client: Mutex<postgres::Client>,
}

impl PostgresBackend {
    /// Connect to a PostgreSQL server using the given connection URL.
    ///
    /// URL format: `postgresql://user:password@host:port/database`
    ///
    /// # TLS
    ///
    /// Currently uses `NoTls` — connections are **not** encrypted. This is
    /// acceptable for localhost/Unix-socket connections (the common case for
    /// local OAIE stores). For remote PostgreSQL servers, either tunnel via
    /// SSH or use a TLS-capable connector (e.g. `postgres-openssl` or
    /// `postgres-native-tls`). Adding TLS support is tracked for v0.2.
    pub fn connect(url: &str) -> Result<Self> {
        let client = postgres::Client::connect(url, postgres::NoTls)
            .map_err(|e| OaieError::Database(redact_url(&e.to_string())))?;
        Ok(Self {
            client: Mutex::new(client),
        })
    }
}

/// Parse a PostgreSQL row into a RunRecord using the shared RawRow parser.
fn pg_row_to_record(row: &postgres::Row) -> Result<RunRecord> {
    crate::RawRow {
        run_id: row.get(0),
        created: row.get(1),
        command: row.get(2),
        exit_code: row.get(3),
        duration_ms: row.get(4),
        isolation: row.get(5),
        status: row.get(6),
        manifest_hash: row.get(7),
        error_message: row.get(8),
    }
    .into_record()
}

impl DbBackend for PostgresBackend {
    fn initialize(&self) -> Result<()> {
        let mut client = self.client.lock().map_err(|e| {
            OaieError::Database(format!("mutex poisoned: {e}"))
        })?;

        // Wrap the entire initialization in a transaction so that schema
        // creation and version upsert are atomic.
        let mut txn = client.transaction().map_err(pg_err)?;

        txn.batch_execute(
                "CREATE TABLE IF NOT EXISTS runs (
                    run_id        TEXT PRIMARY KEY,
                    created       TEXT NOT NULL,
                    command       TEXT NOT NULL,
                    exit_code     INTEGER,
                    duration_ms   BIGINT,
                    isolation     TEXT NOT NULL,
                    status        TEXT NOT NULL DEFAULT 'running',
                    manifest_hash TEXT,
                    error_message TEXT
                );

                CREATE TABLE IF NOT EXISTS artifacts (
                    hash          TEXT NOT NULL,
                    run_id        TEXT NOT NULL REFERENCES runs(run_id),
                    label         TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    size          BIGINT NOT NULL,
                    created       TEXT NOT NULL,
                    PRIMARY KEY (hash, run_id, label)
                );

                CREATE INDEX IF NOT EXISTS idx_artifacts_run ON artifacts(run_id);

                CREATE TABLE IF NOT EXISTS schema_version (
                    id      INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
                    version INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    session_id    TEXT PRIMARY KEY,
                    name          TEXT,
                    created       TEXT NOT NULL,
                    stopped       TEXT,
                    status        TEXT NOT NULL DEFAULT 'running',
                    command       TEXT NOT NULL,
                    policy        TEXT,
                    network_mode  TEXT,
                    budget_json   TEXT,
                    manifest_hash TEXT,
                    error_message TEXT,
                    containment   TEXT,
                    llm_provider  TEXT
                );

                CREATE TABLE IF NOT EXISTS session_calls (
                    call_id       TEXT PRIMARY KEY,
                    session_id    TEXT NOT NULL REFERENCES sessions(session_id),
                    run_id        TEXT NOT NULL REFERENCES runs(run_id),
                    seq           INTEGER NOT NULL,
                    command       TEXT NOT NULL,
                    created       TEXT NOT NULL,
                    duration_ms   BIGINT,
                    exit_code     INTEGER,
                    UNIQUE(session_id, seq)
                );",
            )
            .map_err(pg_err)?;

        // Schema v4 migration: add containment + llm_provider columns.
        // ALTER TABLE ADD COLUMN IF NOT EXISTS is PostgreSQL 9.6+.
        txn.batch_execute(
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS containment TEXT;
             ALTER TABLE sessions ADD COLUMN IF NOT EXISTS llm_provider TEXT;",
        )
        .map_err(pg_err)?;

        // Check schema version — never downgrade a DB created by a newer binary.
        let stored: Option<i64> = txn
            .query_opt("SELECT version FROM schema_version WHERE id = 1", &[])
            .map_err(pg_err)?
            .map(|row| row.get(0));

        if let Some(v) = stored {
            if v > SCHEMA_VERSION {
                return Err(OaieError::Database(format!(
                    "database schema version {v} is newer than this binary ({}); upgrade oaie",
                    SCHEMA_VERSION
                )));
            }
        }

        // Conditional upsert: only update if the new version is >= the existing
        // version. This prevents an older binary from overwriting a newer schema
        // version set by a newer binary (TOCTOU protection).
        txn.execute(
                "INSERT INTO schema_version (id, version) VALUES (1, $1)
                 ON CONFLICT (id) DO UPDATE SET version = $1 WHERE schema_version.version <= $1",
                &[&SCHEMA_VERSION],
            )
            .map_err(pg_err)?;

        txn.commit().map_err(pg_err)?;

        Ok(())
    }

    fn insert_run(&self, run: &RunRecord) -> Result<()> {
        let command_json = serde_json::to_string(&run.command)
            .map_err(|e| OaieError::Io(std::io::Error::other(e)))?;

        self.client
            .lock()
            .map_err(|e| OaieError::Database(format!("mutex poisoned: {e}")))?
            .execute(
                "INSERT INTO runs (run_id, created, command, exit_code, duration_ms, isolation, status, manifest_hash, error_message)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                &[
                    &run.run_id.full(),
                    &run.created.to_rfc3339(),
                    &command_json,
                    &run.exit_code,
                    &run.duration_ms,
                    &run.isolation,
                    &run.status.as_str(),
                    &run.manifest_hash,
                    &run.error_message,
                ],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    fn complete_run(
        &self,
        run_id: &RunId,
        exit_code: i32,
        duration_ms: i64,
        manifest_hash: &str,
    ) -> Result<()> {
        let rows = self
            .client
            .lock()
            .map_err(|e| OaieError::Database(format!("mutex poisoned: {e}")))?
            .execute(
                "UPDATE runs SET status = 'completed', exit_code = $1, duration_ms = $2, manifest_hash = $3
                 WHERE run_id = $4",
                &[&exit_code, &duration_ms, &manifest_hash, &run_id.full()],
            )
            .map_err(pg_err)?;
        if rows == 0 {
            return Err(OaieError::RunNotFound(run_id.full()));
        }
        Ok(())
    }

    fn fail_run(&self, run_id: &RunId, error: &str) -> Result<()> {
        let rows = self
            .client
            .lock()
            .map_err(|e| OaieError::Database(format!("mutex poisoned: {e}")))?
            .execute(
                "UPDATE runs SET status = 'failed', error_message = $1 WHERE run_id = $2",
                &[&error, &run_id.full()],
            )
            .map_err(pg_err)?;
        if rows == 0 {
            return Err(OaieError::RunNotFound(run_id.full()));
        }
        Ok(())
    }

    fn get_run(&self, run_id: &RunId) -> Result<Option<RunRecord>> {
        let row = self
            .client
            .lock()
            .map_err(|e| OaieError::Database(format!("mutex poisoned: {e}")))?
            .query_opt(
                "SELECT run_id, created, command, exit_code, duration_ms, isolation, status, manifest_hash, error_message
                 FROM runs WHERE run_id = $1",
                &[&run_id.full()],
            )
            .map_err(pg_err)?;

        match row {
            Some(r) => Ok(Some(pg_row_to_record(&r)?)),
            None => Ok(None),
        }
    }

    fn get_run_by_prefix(&self, prefix: &str) -> Result<RunRecord> {
        // Reject empty prefixes — they would match every run via LIKE '%'.
        if prefix.is_empty() {
            return Err(OaieError::InvalidRunId("empty run ID prefix".into()));
        }

        // Escape SQL LIKE wildcards.
        let escaped: String = prefix
            .chars()
            .flat_map(|c| match c {
                '%' => vec!['\\', '%'],
                '_' => vec!['\\', '_'],
                '\\' => vec!['\\', '\\'],
                _ => vec![c],
            })
            .collect();
        let pattern = format!("{escaped}%");

        let rows = self
            .client
            .lock()
            .map_err(|e| OaieError::Database(format!("mutex poisoned: {e}")))?
            .query(
                "SELECT run_id, created, command, exit_code, duration_ms, isolation, status, manifest_hash, error_message
                 FROM runs WHERE run_id LIKE $1 ESCAPE '\\'",
                &[&pattern],
            )
            .map_err(pg_err)?;

        match rows.len() {
            0 => Err(OaieError::RunNotFound(prefix.to_string())),
            1 => pg_row_to_record(&rows[0]),
            _ => {
                let show_len = (prefix.len() + 4).min(36);
                let ids: Vec<String> = rows
                    .iter()
                    .map(|r| {
                        let id: String = r.get(0);
                        id[..show_len.min(id.len())].to_string()
                    })
                    .collect();
                Err(OaieError::InvalidRunId(format!(
                    "ambiguous prefix '{prefix}', matches: {}",
                    ids.join(", ")
                )))
            }
        }
    }

    fn get_latest_run(&self) -> Result<Option<RunRecord>> {
        let row = self
            .client
            .lock()
            .map_err(|e| OaieError::Database(format!("mutex poisoned: {e}")))?
            .query_opt(
                "SELECT run_id, created, command, exit_code, duration_ms, isolation, status, manifest_hash, error_message
                 FROM runs ORDER BY created DESC LIMIT 1",
                &[],
            )
            .map_err(pg_err)?;

        match row {
            Some(r) => Ok(Some(pg_row_to_record(&r)?)),
            None => Ok(None),
        }
    }

    fn list_runs(&self, limit: usize) -> Result<Vec<RunRecord>> {
        let rows = self
            .client
            .lock()
            .map_err(|e| OaieError::Database(format!("mutex poisoned: {e}")))?
            .query(
                "SELECT run_id, created, command, exit_code, duration_ms, isolation, status, manifest_hash, error_message
                 FROM runs ORDER BY created DESC LIMIT $1",
                &[&(limit as i64)],
            )
            .map_err(pg_err)?;

        rows.iter().map(pg_row_to_record).collect()
    }

    fn list_all_runs(&self) -> Result<Vec<RunRecord>> {
        let rows = self
            .client
            .lock()
            .map_err(|e| OaieError::Database(format!("mutex poisoned: {e}")))?
            .query(
                "SELECT run_id, created, command, exit_code, duration_ms, isolation, status, manifest_hash, error_message
                 FROM runs ORDER BY created DESC",
                &[],
            )
            .map_err(pg_err)?;

        rows.iter().map(pg_row_to_record).collect()
    }

    fn insert_artifact(&self, artifact: &ArtifactRecord) -> Result<()> {
        self.client
            .lock()
            .map_err(|e| OaieError::Database(format!("mutex poisoned: {e}")))?
            .execute(
                "INSERT INTO artifacts (hash, run_id, label, artifact_type, size, created)
                 VALUES ($1, $2, $3, $4, $5, $6)",
                &[
                    &artifact.hash,
                    &artifact.run_id.full(),
                    &artifact.label,
                    &artifact.artifact_type,
                    &artifact.size,
                    &artifact.created.to_rfc3339(),
                ],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    fn list_artifacts(&self, run_id: &RunId) -> Result<Vec<ArtifactRecord>> {
        use chrono::{DateTime, Utc};

        let rows = self
            .client
            .lock()
            .map_err(|e| OaieError::Database(format!("mutex poisoned: {e}")))?
            .query(
                "SELECT hash, run_id, label, artifact_type, size, created
                 FROM artifacts WHERE run_id = $1",
                &[&run_id.full()],
            )
            .map_err(pg_err)?;

        let mut artifacts = Vec::new();
        for row in &rows {
            let hash: String = row.get(0);
            let run_id_str: String = row.get(1);
            let label: String = row.get(2);
            let artifact_type: String = row.get(3);
            let size: i64 = row.get(4);
            let created_str: String = row.get(5);

            let run_id: RunId = run_id_str
                .parse()
                .map_err(|_| OaieError::InvalidRunId(run_id_str.clone()))?;
            let created = DateTime::parse_from_rfc3339(&created_str)
                .map_err(|e| OaieError::Io(std::io::Error::other(e)))?
                .with_timezone(&Utc);

            artifacts.push(ArtifactRecord {
                hash,
                run_id,
                label,
                artifact_type,
                size,
                created,
            });
        }
        Ok(artifacts)
    }

    fn complete_run_with_artifacts(
        &self,
        run_id: &RunId,
        exit_code: i32,
        duration_ms: i64,
        manifest_hash: &str,
        artifacts: &[ArtifactRecord],
    ) -> Result<()> {
        let mut client = self.client.lock().map_err(|e| {
            OaieError::Database(format!("mutex poisoned: {e}"))
        })?;

        let mut tx = client.transaction().map_err(pg_err)?;

        let rows = tx
            .execute(
                "UPDATE runs SET status = 'completed', exit_code = $1, duration_ms = $2, manifest_hash = $3
                 WHERE run_id = $4",
                &[&exit_code, &duration_ms, &manifest_hash, &run_id.full()],
            )
            .map_err(pg_err)?;
        if rows == 0 {
            tx.rollback().map_err(pg_err)?;
            return Err(OaieError::RunNotFound(run_id.full()));
        }

        for artifact in artifacts {
            tx.execute(
                "INSERT INTO artifacts (hash, run_id, label, artifact_type, size, created)
                 VALUES ($1, $2, $3, $4, $5, $6)",
                &[
                    &artifact.hash,
                    &artifact.run_id.full(),
                    &artifact.label,
                    &artifact.artifact_type,
                    &artifact.size,
                    &artifact.created.to_rfc3339(),
                ],
            )
            .map_err(pg_err)?;
        }

        tx.commit().map_err(pg_err)?;
        Ok(())
    }

    fn delete_run_records(&self, run_id: &RunId) -> Result<()> {
        let mut client = self.client.lock().map_err(|e| {
            OaieError::Database(format!("mutex poisoned: {e}"))
        })?;

        let mut tx = client.transaction().map_err(pg_err)?;

        // Delete session_calls referencing this run (FK constraint).
        tx.execute(
            "DELETE FROM session_calls WHERE run_id = $1",
            &[&run_id.full()],
        )
        .map_err(pg_err)?;

        tx.execute(
            "DELETE FROM artifacts WHERE run_id = $1",
            &[&run_id.full()],
        )
        .map_err(pg_err)?;

        let rows = tx
            .execute("DELETE FROM runs WHERE run_id = $1", &[&run_id.full()])
            .map_err(pg_err)?;

        if rows == 0 {
            tx.rollback().map_err(pg_err)?;
            return Err(OaieError::RunNotFound(run_id.full()));
        }

        tx.commit().map_err(pg_err)?;
        Ok(())
    }

    fn check_health(&self) -> Result<DbHealth> {
        let row = self
            .client
            .lock()
            .map_err(|e| OaieError::Database(format!("mutex poisoned: {e}")))?
            .query_one("SELECT COUNT(*) FROM runs", &[])
            .map_err(pg_err)?;

        let run_count: i64 = row.get(0);

        Ok(DbHealth {
            run_count: run_count as u64,
            // PostgreSQL always uses WAL internally.
            wal_mode: true,
        })
    }

    fn schema_version(&self) -> Result<i64> {
        let row = self
            .client
            .lock()
            .map_err(|e| OaieError::Database(format!("mutex poisoned: {e}")))?
            .query_one("SELECT version FROM schema_version LIMIT 1", &[])
            .map_err(pg_err)?;

        Ok(row.get(0))
    }

    fn backend_name(&self) -> &'static str {
        "postgresql"
    }

    // ── Session operations ──

    fn insert_session(&self, session: &SessionRecord) -> Result<()> {
        self.client
            .lock()
            .map_err(|e| OaieError::Database(format!("mutex poisoned: {e}")))?
            .execute(
                "INSERT INTO sessions (session_id, name, created, stopped, status, command, policy, network_mode, budget_json, manifest_hash, error_message, containment, llm_provider)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
                &[
                    &session.session_id,
                    &session.name,
                    &session.created,
                    &session.stopped,
                    &session.status,
                    &session.command,
                    &session.policy,
                    &session.network_mode,
                    &session.budget_json,
                    &session.manifest_hash,
                    &session.error_message,
                    &session.containment,
                    &session.llm_provider,
                ],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    fn complete_session(
        &self,
        session_id: &str,
        status: &str,
        manifest_hash: Option<&str>,
        error_message: Option<&str>,
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let rows = self
            .client
            .lock()
            .map_err(|e| OaieError::Database(format!("mutex poisoned: {e}")))?
            .execute(
                "UPDATE sessions SET status = $1, stopped = $2, manifest_hash = $3, error_message = $4
                 WHERE session_id = $5",
                &[
                    &status,
                    &now,
                    &manifest_hash,
                    &error_message,
                    &session_id,
                ],
            )
            .map_err(pg_err)?;
        if rows == 0 {
            return Err(OaieError::Database(format!(
                "session not found: {session_id}"
            )));
        }
        Ok(())
    }

    fn get_session(&self, session_id: &str) -> Result<Option<SessionRecord>> {
        let mut client = self.client.lock().map_err(|e| {
            OaieError::Database(format!("mutex poisoned: {e}"))
        })?;
        let rows = client
            .query(
                "SELECT session_id, name, created, stopped, status, command, policy, network_mode, budget_json, manifest_hash, error_message, containment, llm_provider
                 FROM sessions WHERE session_id = $1",
                &[&session_id],
            )
            .map_err(pg_err)?;
        match rows.first() {
            Some(row) => Ok(Some(SessionRecord {
                session_id: row.get(0),
                name: row.get(1),
                created: row.get(2),
                stopped: row.get(3),
                status: row.get(4),
                command: row.get(5),
                policy: row.get(6),
                network_mode: row.get(7),
                budget_json: row.get(8),
                manifest_hash: row.get(9),
                error_message: row.get(10),
                containment: row.get(11),
                llm_provider: row.get(12),
            })),
            None => Ok(None),
        }
    }

    fn list_sessions(&self, limit: usize) -> Result<Vec<SessionRecord>> {
        let mut client = self.client.lock().map_err(|e| {
            OaieError::Database(format!("mutex poisoned: {e}"))
        })?;
        let rows = client
            .query(
                "SELECT session_id, name, created, stopped, status, command, policy, network_mode, budget_json, manifest_hash, error_message, containment, llm_provider
                 FROM sessions ORDER BY created DESC LIMIT $1",
                &[&(limit as i64)],
            )
            .map_err(pg_err)?;
        Ok(rows
            .iter()
            .map(|row| SessionRecord {
                session_id: row.get(0),
                name: row.get(1),
                created: row.get(2),
                stopped: row.get(3),
                status: row.get(4),
                command: row.get(5),
                policy: row.get(6),
                network_mode: row.get(7),
                budget_json: row.get(8),
                manifest_hash: row.get(9),
                error_message: row.get(10),
                containment: row.get(11),
                llm_provider: row.get(12),
            })
            .collect())
    }

    fn insert_session_call(&self, call: &SessionCallRecord) -> Result<()> {
        self.client
            .lock()
            .map_err(|e| OaieError::Database(format!("mutex poisoned: {e}")))?
            .execute(
                "INSERT INTO session_calls (call_id, session_id, run_id, seq, command, created, duration_ms, exit_code)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    &call.call_id,
                    &call.session_id,
                    &call.run_id,
                    &(call.seq as i32),
                    &call.command,
                    &call.created,
                    &call.duration_ms,
                    &call.exit_code,
                ],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    fn list_session_calls(&self, session_id: &str) -> Result<Vec<SessionCallRecord>> {
        let mut client = self.client.lock().map_err(|e| {
            OaieError::Database(format!("mutex poisoned: {e}"))
        })?;
        let rows = client
            .query(
                "SELECT call_id, session_id, run_id, seq, command, created, duration_ms, exit_code
                 FROM session_calls WHERE session_id = $1 ORDER BY seq ASC",
                &[&session_id],
            )
            .map_err(pg_err)?;
        Ok(rows
            .iter()
            .map(|row| {
                let seq: i32 = row.get(3);
                SessionCallRecord {
                    call_id: row.get(0),
                    session_id: row.get(1),
                    run_id: row.get(2),
                    seq: seq as i64,
                    command: row.get(4),
                    created: row.get(5),
                    duration_ms: row.get(6),
                    exit_code: row.get(7),
                }
            })
            .collect())
    }

    fn update_session_budget(&self, session_id: &str, budget_json: &str) -> Result<()> {
        let mut client = self.client.lock().map_err(|e| {
            OaieError::Database(format!("mutex poisoned: {e}"))
        })?;
        client
            .execute(
                "UPDATE sessions SET budget_json = $1 WHERE session_id = $2",
                &[&budget_json, &session_id],
            )
            .map_err(pg_err)?;
        Ok(())
    }
}
