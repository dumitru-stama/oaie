//! Unified error type for all OAIE library crates.
//!
//! `OaieError::Database` holds a `String` (not `rusqlite::Error`) so that
//! rusqlite stays out of oaie-core's dependency tree. The conversion happens
//! in oaie-db via `db_err()`.

/// Shorthand for `std::result::Result<T, OaieError>`.
pub type Result<T> = std::result::Result<T, OaieError>;

/// All errors produced by OAIE library crates.
///
/// CLI commands return `Result<()>` directly; library consumers
/// can match on specific variants for programmatic handling.
#[derive(Debug)]
pub enum OaieError {
    /// The OAIE store directory hasn't been created yet.
    /// Returned when a command requires an initialized store but `~/.oaie/` doesn't exist.
    StoreNotInitialized,

    /// A run with the given ID (or prefix) was not found in the database or on disk.
    RunNotFound(String),

    /// A CAS blob with the given hash was not found in the store.
    ArtifactNotFound(String),

    /// A run ID string could not be parsed, or a prefix matched multiple runs.
    InvalidRunId(String),

    /// A hex hash string was malformed (wrong length or invalid hex chars).
    InvalidHash(String),

    /// A SQLite operation failed. Holds the error message as a `String`
    /// (not `rusqlite::Error`) to keep rusqlite out of oaie-core's deps.
    /// See `oaie_db::db_err()` for the conversion.
    Database(String),

    /// A job specification was invalid (empty command, bad timeout, etc.).
    InvalidJobSpec(String),

    /// Sandbox setup or enforcement failed (namespace creation, seccomp, etc.).
    SandboxError(String),

    /// A policy constraint was violated (denied mount, network blocked, etc.).
    PolicyViolation(String),

    /// A filesystem I/O operation failed.
    Io(std::io::Error),

    /// A CLI or operational error that doesn't fit other categories.
    Other(String),
}

impl std::fmt::Display for OaieError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StoreNotInitialized => {
                f.write_str("store not initialized (run 'oaie init' first)")
            }
            Self::RunNotFound(s) => write!(f, "run not found: {s}"),
            Self::ArtifactNotFound(s) => write!(f, "artifact not found: {s}"),
            Self::InvalidRunId(s) => write!(f, "invalid run ID: {s}"),
            Self::InvalidHash(s) => write!(f, "invalid hash: {s}"),
            Self::Database(s) => write!(f, "database error: {s}"),
            Self::InvalidJobSpec(s) => write!(f, "invalid job spec: {s}"),
            Self::SandboxError(s) => write!(f, "sandbox error: {s}"),
            Self::PolicyViolation(s) => write!(f, "policy violation: {s}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Other(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for OaieError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for OaieError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
