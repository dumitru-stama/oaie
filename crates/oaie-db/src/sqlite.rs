//! SQLite backend for OAIE database operations.
//!
//! Uses rusqlite with WAL mode for crash-safe concurrent access.
//! All rusqlite errors are converted to `OaieError::Database(String)` at this
//! boundary so that oaie-core never depends on rusqlite.

use std::path::Path;

use rusqlite::{params, Connection, OpenFlags};

use oaie_core::error::{OaieError, Result};
use oaie_core::run_id::RunId;

use crate::{ArtifactRecord, DbBackend, DbHealth, RunRecord, SessionCallRecord, SessionRecord, SCHEMA_VERSION};

/// Bridge: convert rusqlite errors into OaieError::Database(String).
/// Keeps rusqlite out of oaie-core's dependency tree.
fn db_err(e: rusqlite::Error) -> OaieError {
    OaieError::Database(e.to_string())
}

/// SQLite backend wrapping a rusqlite connection.
pub struct SqliteBackend {
    conn: Connection,
}

impl SqliteBackend {
    /// Open (or create) the database at the given path.
    /// Uses O_CLOEXEC-equivalent flags to prevent FD leakage to child processes.
    pub fn open(path: &Path) -> Result<Self> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(path, flags).map_err(db_err)?;
        Ok(Self { conn })
    }

    /// Open an in-memory database (for testing and dry runs).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(db_err)?;
        Ok(Self { conn })
    }

    /// Migrate the legacy `schema_version` table (v0.1.0–v0.1.6 format) to the
    /// current format with an `id` column and CHECK constraint.
    ///
    /// The old table was just `(version INTEGER NOT NULL)`. The new table is
    /// `(id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL)`.
    /// `CREATE TABLE IF NOT EXISTS` doesn't modify existing tables, so we
    /// detect the old format by checking whether the `id` column exists.
    fn migrate_schema_version_table(&self) -> Result<()> {
        // Check if the `id` column exists by querying table_info.
        let has_id: bool = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('schema_version') WHERE name = 'id'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(db_err)?
            > 0;

        if has_id {
            return Ok(()); // Already migrated.
        }

        // Read the old version value (if any).
        let old_version: Option<i64> = self
            .conn
            .query_row(
                "SELECT version FROM schema_version LIMIT 1",
                [],
                |row| row.get(0),
            )
            .ok();

        // Drop old table and recreate with new schema.
        self.conn
            .execute_batch(
                "DROP TABLE schema_version;
                 CREATE TABLE schema_version (
                     id      INTEGER PRIMARY KEY CHECK (id = 1),
                     version INTEGER NOT NULL
                 );",
            )
            .map_err(db_err)?;

        // Restore the old version value.
        if let Some(v) = old_version {
            self.conn
                .execute(
                    "INSERT INTO schema_version (id, version) VALUES (1, ?1)",
                    params![v],
                )
                .map_err(db_err)?;
        }

        Ok(())
    }

    /// Schema v4 migration: add `containment` and `llm_provider` columns to `sessions`.
    ///
    /// Uses `pragma_table_info` to check whether columns already exist, avoiding
    /// errors on databases created with the new schema.
    fn migrate_sessions_containment_columns(&self) -> Result<()> {
        let has_containment: bool = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name = 'containment'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(db_err)?
            > 0;

        if !has_containment {
            self.conn
                .execute_batch("ALTER TABLE sessions ADD COLUMN containment TEXT;")
                .map_err(db_err)?;
        }

        let has_llm_provider: bool = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name = 'llm_provider'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(db_err)?
            > 0;

        if !has_llm_provider {
            self.conn
                .execute_batch("ALTER TABLE sessions ADD COLUMN llm_provider TEXT;")
                .map_err(db_err)?;
        }

        Ok(())
    }
}

use crate::RawRow;

/// Extract a RawRow from a rusqlite row.
fn row_to_raw(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawRow> {
    Ok(RawRow {
        run_id: row.get(0)?,
        created: row.get(1)?,
        command: row.get(2)?,
        exit_code: row.get(3)?,
        duration_ms: row.get(4)?,
        isolation: row.get(5)?,
        status: row.get(6)?,
        manifest_hash: row.get(7)?,
        error_message: row.get(8)?,
    })
}

/// SQL fragment for selecting all run columns in consistent order.
const RUNS_SELECT_SQL: &str =
    "SELECT run_id, created, command, exit_code, duration_ms, isolation, status, manifest_hash, error_message
     FROM runs WHERE run_id = ?1";

impl DbBackend for SqliteBackend {
    fn initialize(&self) -> Result<()> {
        self.conn
            .execute_batch("PRAGMA journal_mode = WAL;")
            .map_err(db_err)?;
        self.conn
            .execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(db_err)?;
        // Busy timeout: wait up to 5 seconds for locked tables instead of
        // failing immediately with SQLITE_BUSY. Handles concurrent oaie
        // invocations (e.g. two `oaie run` in parallel).
        self.conn
            .execute_batch("PRAGMA busy_timeout = 5000;")
            .map_err(db_err)?;

        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS runs (
                run_id        TEXT PRIMARY KEY,
                created       TEXT NOT NULL,
                command       TEXT NOT NULL,
                exit_code     INTEGER,
                duration_ms   INTEGER,
                isolation     TEXT NOT NULL,
                status        TEXT NOT NULL DEFAULT 'running',
                manifest_hash TEXT,
                error_message TEXT
            );

            -- Composite PK: the same blob (hash) can appear in multiple runs,
            -- and the same run can have multiple artifacts with different labels.
            -- (hash, run_id, label) is the minimal unique key.
            CREATE TABLE IF NOT EXISTS artifacts (
                hash          TEXT NOT NULL,
                run_id        TEXT NOT NULL REFERENCES runs(run_id),
                label         TEXT NOT NULL,
                artifact_type TEXT NOT NULL,
                size          INTEGER NOT NULL,
                created       TEXT NOT NULL,
                PRIMARY KEY (hash, run_id, label)
            );

            CREATE INDEX IF NOT EXISTS idx_artifacts_run ON artifacts(run_id);

            -- Session mode tables (Phase K + Phase L containment).
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
                call_id    TEXT PRIMARY KEY,
                session_id TEXT NOT NULL REFERENCES sessions(session_id),
                run_id     TEXT NOT NULL REFERENCES runs(run_id),
                seq        INTEGER NOT NULL,
                command    TEXT NOT NULL,
                created    TEXT NOT NULL,
                duration_ms INTEGER,
                exit_code  INTEGER,
                UNIQUE(session_id, seq)
            );

            CREATE INDEX IF NOT EXISTS idx_session_calls_session ON session_calls(session_id);

            CREATE TABLE IF NOT EXISTS schema_version (
                id      INTEGER PRIMARY KEY CHECK (id = 1),
                version INTEGER NOT NULL
            );",
            )
            .map_err(db_err)?;

        // Migrate legacy schema_version table (no `id` column) to the new format.
        // The old table had just `version INTEGER NOT NULL`. `CREATE TABLE IF NOT EXISTS`
        // above is a no-op when the table already exists with the old schema, so we
        // detect and migrate here.
        self.migrate_schema_version_table()?;

        // Schema v4 migration: add containment + llm_provider columns to sessions.
        // ALTER TABLE ADD COLUMN is a no-op if the column already exists (SQLite ≥3.35).
        // For older SQLite, we check pragma_table_info first.
        self.migrate_sessions_containment_columns()?;

        // Wrap schema version check + upsert in a transaction so the read-check-write
        // is atomic. Without this, two concurrent processes could both read the old
        // version and race to update it.
        self.conn.execute_batch("BEGIN IMMEDIATE").map_err(db_err)?;

        let schema_result = (|| -> Result<()> {
            let stored: Option<i64> = self
                .conn
                .query_row(
                    "SELECT version FROM schema_version WHERE id = 1",
                    [],
                    |row| row.get(0),
                )
                .ok();

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
            // version set by a newer binary.
            self.conn
                .execute(
                    "INSERT INTO schema_version (id, version) VALUES (1, ?1)
                     ON CONFLICT (id) DO UPDATE SET version = ?1 WHERE version <= ?1",
                    params![SCHEMA_VERSION],
                )
                .map_err(db_err)?;
            Ok(())
        })();

        match schema_result {
            Ok(()) => self.conn.execute_batch("COMMIT").map_err(db_err)?,
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        }

        Ok(())
    }

    fn insert_run(&self, run: &RunRecord) -> Result<()> {
        let command_json = serde_json::to_string(&run.command)
            .map_err(|e| OaieError::Io(std::io::Error::other(e)))?;

        self.conn
            .execute(
                "INSERT INTO runs (run_id, created, command, exit_code, duration_ms, isolation, status, manifest_hash, error_message)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    run.run_id.full(),
                    run.created.to_rfc3339(),
                    command_json,
                    run.exit_code,
                    run.duration_ms,
                    run.isolation,
                    run.status.as_str(),
                    run.manifest_hash,
                    run.error_message,
                ],
            )
            .map_err(db_err)?;
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
            .conn
            .execute(
                "UPDATE runs SET status = 'completed', exit_code = ?1, duration_ms = ?2, manifest_hash = ?3
             WHERE run_id = ?4",
                params![exit_code, duration_ms, manifest_hash, run_id.full()],
            )
            .map_err(db_err)?;
        if rows == 0 {
            return Err(OaieError::RunNotFound(run_id.full()));
        }
        Ok(())
    }

    fn fail_run(&self, run_id: &RunId, error: &str) -> Result<()> {
        let rows = self
            .conn
            .execute(
                "UPDATE runs SET status = 'failed', error_message = ?1 WHERE run_id = ?2",
                params![error, run_id.full()],
            )
            .map_err(db_err)?;
        if rows == 0 {
            return Err(OaieError::RunNotFound(run_id.full()));
        }
        Ok(())
    }

    fn get_run(&self, run_id: &RunId) -> Result<Option<RunRecord>> {
        let mut stmt = self.conn.prepare(RUNS_SELECT_SQL).map_err(db_err)?;

        let mut rows = stmt
            .query_map(params![run_id.full()], row_to_raw)
            .map_err(db_err)?;

        match rows.next() {
            Some(row) => Ok(Some(row.map_err(db_err)?.into_record()?)),
            None => Ok(None),
        }
    }

    fn get_run_by_prefix(&self, prefix: &str) -> Result<RunRecord> {
        // Reject empty prefixes — they would match every run via LIKE '%'.
        if prefix.is_empty() {
            return Err(OaieError::InvalidRunId("empty run ID prefix".into()));
        }

        // Escape SQL LIKE wildcards so user input like "%" or "_" doesn't
        // match unintended rows. UUIDs are hex-only, but the API is public.
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
        let mut stmt = self
            .conn
            .prepare(
                "SELECT run_id, created, command, exit_code, duration_ms, isolation, status, manifest_hash, error_message
                 FROM runs WHERE run_id LIKE ?1 ESCAPE '\\'",
            )
            .map_err(db_err)?;

        let rows: Vec<RawRow> = stmt
            .query_map(params![pattern], row_to_raw)
            .map_err(db_err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_err)?;

        match rows.len() {
            0 => Err(OaieError::RunNotFound(prefix.to_string())),
            1 => rows.into_iter().next().unwrap().into_record(),
            _ => {
                // Show enough chars to distinguish matches (at least prefix len + 4).
                let show_len = (prefix.len() + 4).min(36);
                let ids: Vec<String> = rows
                    .iter()
                    .map(|r| r.run_id[..show_len.min(r.run_id.len())].to_string())
                    .collect();
                Err(OaieError::InvalidRunId(format!(
                    "ambiguous prefix '{prefix}', matches: {}",
                    ids.join(", ")
                )))
            }
        }
    }

    fn get_latest_run(&self) -> Result<Option<RunRecord>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT run_id, created, command, exit_code, duration_ms, isolation, status, manifest_hash, error_message
             FROM runs ORDER BY created DESC LIMIT 1",
            )
            .map_err(db_err)?;

        let mut rows = stmt.query_map([], row_to_raw).map_err(db_err)?;

        match rows.next() {
            Some(row) => Ok(Some(row.map_err(db_err)?.into_record()?)),
            None => Ok(None),
        }
    }

    fn list_runs(&self, limit: usize) -> Result<Vec<RunRecord>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT run_id, created, command, exit_code, duration_ms, isolation, status, manifest_hash, error_message
                 FROM runs ORDER BY created DESC LIMIT ?1",
            )
            .map_err(db_err)?;

        let rows = stmt
            .query_map(params![limit as i64], row_to_raw)
            .map_err(db_err)?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(db_err)?.into_record()?);
        }
        Ok(records)
    }

    fn list_all_runs(&self) -> Result<Vec<RunRecord>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT run_id, created, command, exit_code, duration_ms, isolation, status, manifest_hash, error_message
                 FROM runs ORDER BY created DESC",
            )
            .map_err(db_err)?;

        let rows = stmt.query_map([], row_to_raw).map_err(db_err)?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(db_err)?.into_record()?);
        }
        Ok(records)
    }

    fn insert_artifact(&self, artifact: &ArtifactRecord) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO artifacts (hash, run_id, label, artifact_type, size, created)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    artifact.hash,
                    artifact.run_id.full(),
                    artifact.label,
                    artifact.artifact_type,
                    artifact.size,
                    artifact.created.to_rfc3339(),
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    fn list_artifacts(&self, run_id: &RunId) -> Result<Vec<ArtifactRecord>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT hash, run_id, label, artifact_type, size, created
             FROM artifacts WHERE run_id = ?1",
            )
            .map_err(db_err)?;

        let rows = stmt
            .query_map(params![run_id.full()], |row| {
                let run_id_str: String = row.get(1)?;
                let created_str: String = row.get(5)?;
                Ok((
                    row.get::<_, String>(0)?,
                    run_id_str,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    created_str,
                ))
            })
            .map_err(db_err)?;

        let mut artifacts = Vec::new();
        for row in rows {
            let (hash, run_id_str, label, artifact_type, size, created_str) =
                row.map_err(db_err)?;
            let run_id: RunId = run_id_str
                .parse()
                .map_err(|_| OaieError::InvalidRunId(run_id_str.clone()))?;
            let created = chrono::DateTime::parse_from_rfc3339(&created_str)
                .map_err(|e| OaieError::Io(std::io::Error::other(e)))?
                .with_timezone(&chrono::Utc);
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

    fn delete_run_records(&self, run_id: &RunId) -> Result<()> {
        // Wrap DB changes in a transaction for atomicity.
        self.conn.execute_batch("BEGIN IMMEDIATE").map_err(db_err)?;

        let result = (|| -> Result<()> {
            // Delete session_calls referencing this run (FK constraint).
            self.conn
                .execute(
                    "DELETE FROM session_calls WHERE run_id = ?1",
                    params![run_id.full()],
                )
                .map_err(db_err)?;

            // Delete artifact records (FK constraint).
            self.conn
                .execute(
                    "DELETE FROM artifacts WHERE run_id = ?1",
                    params![run_id.full()],
                )
                .map_err(db_err)?;

            let rows = self
                .conn
                .execute(
                    "DELETE FROM runs WHERE run_id = ?1",
                    params![run_id.full()],
                )
                .map_err(db_err)?;

            if rows == 0 {
                return Err(OaieError::RunNotFound(run_id.full()));
            }
            Ok(())
        })();

        match result {
            Ok(()) => {
                self.conn.execute_batch("COMMIT").map_err(db_err)?;
                Ok(())
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    fn complete_run_with_artifacts(
        &self,
        run_id: &RunId,
        exit_code: i32,
        duration_ms: i64,
        manifest_hash: &str,
        artifacts: &[crate::ArtifactRecord],
    ) -> Result<()> {
        // Single BEGIN IMMEDIATE transaction for the run completion + all
        // artifact inserts. Reduces lock acquisitions from N+1 to 1,
        // critical under 500 concurrent runs.
        self.conn.execute_batch("BEGIN IMMEDIATE").map_err(db_err)?;

        let result = (|| -> Result<()> {
            let rows = self
                .conn
                .execute(
                    "UPDATE runs SET status = 'completed', exit_code = ?1, duration_ms = ?2, manifest_hash = ?3
                     WHERE run_id = ?4",
                    params![exit_code, duration_ms, manifest_hash, run_id.full()],
                )
                .map_err(db_err)?;
            if rows == 0 {
                return Err(OaieError::RunNotFound(run_id.full()));
            }

            for artifact in artifacts {
                self.conn
                    .execute(
                        "INSERT INTO artifacts (hash, run_id, label, artifact_type, size, created)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![
                            artifact.hash,
                            artifact.run_id.full(),
                            artifact.label,
                            artifact.artifact_type,
                            artifact.size,
                            artifact.created.to_rfc3339(),
                        ],
                    )
                    .map_err(db_err)?;
            }
            Ok(())
        })();

        match result {
            Ok(()) => {
                self.conn.execute_batch("COMMIT").map_err(db_err)?;
                Ok(())
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    fn check_health(&self) -> Result<DbHealth> {
        let run_count: u64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM runs", [], |row| row.get(0))
            .map_err(db_err)?;

        let journal_mode: String = self
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(db_err)?;

        Ok(DbHealth {
            run_count,
            wal_mode: journal_mode.eq_ignore_ascii_case("wal"),
        })
    }

    fn schema_version(&self) -> Result<i64> {
        let version: i64 = self
            .conn
            .query_row("SELECT version FROM schema_version LIMIT 1", [], |row| {
                row.get(0)
            })
            .map_err(db_err)?;
        Ok(version)
    }

    fn backend_name(&self) -> &'static str {
        "sqlite"
    }

    // ── Session operations ──

    fn insert_session(&self, session: &SessionRecord) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO sessions (session_id, name, created, stopped, status, command, policy, network_mode, budget_json, manifest_hash, error_message, containment, llm_provider)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    session.session_id,
                    session.name,
                    session.created,
                    session.stopped,
                    session.status,
                    session.command,
                    session.policy,
                    session.network_mode,
                    session.budget_json,
                    session.manifest_hash,
                    session.error_message,
                    session.containment,
                    session.llm_provider,
                ],
            )
            .map_err(db_err)?;
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
            .conn
            .execute(
                "UPDATE sessions SET status = ?1, stopped = ?2, manifest_hash = ?3, error_message = ?4
                 WHERE session_id = ?5",
                params![status, now, manifest_hash, error_message, session_id],
            )
            .map_err(db_err)?;
        if rows == 0 {
            return Err(OaieError::Database(format!(
                "session not found: {session_id}"
            )));
        }
        Ok(())
    }

    fn get_session(&self, session_id: &str) -> Result<Option<SessionRecord>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT session_id, name, created, stopped, status, command, policy, network_mode, budget_json, manifest_hash, error_message, containment, llm_provider
                 FROM sessions WHERE session_id = ?1",
            )
            .map_err(db_err)?;

        let mut rows = stmt
            .query_map(params![session_id], |row| {
                Ok(SessionRecord {
                    session_id: row.get(0)?,
                    name: row.get(1)?,
                    created: row.get(2)?,
                    stopped: row.get(3)?,
                    status: row.get(4)?,
                    command: row.get(5)?,
                    policy: row.get(6)?,
                    network_mode: row.get(7)?,
                    budget_json: row.get(8)?,
                    manifest_hash: row.get(9)?,
                    error_message: row.get(10)?,
                    containment: row.get(11)?,
                    llm_provider: row.get(12)?,
                })
            })
            .map_err(db_err)?;

        match rows.next() {
            Some(row) => Ok(Some(row.map_err(db_err)?)),
            None => Ok(None),
        }
    }

    fn list_sessions(&self, limit: usize) -> Result<Vec<SessionRecord>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT session_id, name, created, stopped, status, command, policy, network_mode, budget_json, manifest_hash, error_message, containment, llm_provider
                 FROM sessions ORDER BY created DESC LIMIT ?1",
            )
            .map_err(db_err)?;

        let rows = stmt
            .query_map(params![limit as i64], |row| {
                Ok(SessionRecord {
                    session_id: row.get(0)?,
                    name: row.get(1)?,
                    created: row.get(2)?,
                    stopped: row.get(3)?,
                    status: row.get(4)?,
                    command: row.get(5)?,
                    policy: row.get(6)?,
                    network_mode: row.get(7)?,
                    budget_json: row.get(8)?,
                    manifest_hash: row.get(9)?,
                    error_message: row.get(10)?,
                    containment: row.get(11)?,
                    llm_provider: row.get(12)?,
                })
            })
            .map_err(db_err)?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(db_err)?);
        }
        Ok(records)
    }

    fn insert_session_call(&self, call: &SessionCallRecord) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO session_calls (call_id, session_id, run_id, seq, command, created, duration_ms, exit_code)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    call.call_id,
                    call.session_id,
                    call.run_id,
                    call.seq,
                    call.command,
                    call.created,
                    call.duration_ms,
                    call.exit_code,
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    fn list_session_calls(&self, session_id: &str) -> Result<Vec<SessionCallRecord>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT call_id, session_id, run_id, seq, command, created, duration_ms, exit_code
                 FROM session_calls WHERE session_id = ?1 ORDER BY seq ASC",
            )
            .map_err(db_err)?;

        let rows = stmt
            .query_map(params![session_id], |row| {
                Ok(SessionCallRecord {
                    call_id: row.get(0)?,
                    session_id: row.get(1)?,
                    run_id: row.get(2)?,
                    seq: row.get(3)?,
                    command: row.get(4)?,
                    created: row.get(5)?,
                    duration_ms: row.get(6)?,
                    exit_code: row.get(7)?,
                })
            })
            .map_err(db_err)?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(db_err)?);
        }
        Ok(records)
    }

    fn update_session_budget(&self, session_id: &str, budget_json: &str) -> Result<()> {
        self.conn
            .execute(
                "UPDATE sessions SET budget_json = ?1 WHERE session_id = ?2",
                params![budget_json, session_id],
            )
            .map_err(db_err)?;
        Ok(())
    }
}
