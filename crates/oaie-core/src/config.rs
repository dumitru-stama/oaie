//! OAIE store path configuration.
//!
//! Resolves the store root from `OAIE_HOME` env var or defaults to `~/.oaie/`.

use std::path::PathBuf;

use crate::error::{OaieError, Result};
use crate::hash_algo::HashAlgorithm;
use crate::store_config::{ArtifactLimits, DatabaseConfig, DefaultTimeouts, SigningConfig, StoreConfig};

/// Paths to OAIE's local store directories and database.
#[derive(Clone, Debug)]
pub struct OaieStore {
    /// Root directory of the store (default: `~/.oaie`).
    pub root: PathBuf,
    /// Directory containing per-run subdirectories (`<root>/runs`).
    pub runs_dir: PathBuf,
    /// Content-addressed blob store directory (`<root>/cas`).
    pub cas_dir: PathBuf,
    /// Path to the SQLite index database file (`<root>/db.sqlite`).
    ///
    /// For SQLite backends, this resolves to the configured path (relative to
    /// store root or absolute). For PostgreSQL backends, this is set to the
    /// store root's `db.sqlite` as a fallback reference but is not used.
    pub db_path: PathBuf,
    /// Hash algorithm for this store (BLAKE3 default, set by `open()`).
    pub hash_algorithm: HashAlgorithm,
    /// Artifact collection limits (set by `open()`).
    pub limits: ArtifactLimits,
    /// Default timeout settings (set by `open()`).
    pub timeouts: DefaultTimeouts,
    /// Database backend and connection configuration (set by `open()`).
    pub database: DatabaseConfig,
    /// Directory containing signing keys (`<root>/keys`).
    pub keys_dir: PathBuf,
    /// Signing configuration from `config.toml` (set by `open()`).
    pub signing: Option<SigningConfig>,
}

impl OaieStore {
    /// Construct store paths from a given root directory.
    /// Hash algorithm defaults to BLAKE3; call `open()` to read `config.toml`.
    pub fn from_root(root: PathBuf) -> Self {
        Self {
            runs_dir: root.join("runs"),
            cas_dir: root.join("cas"),
            db_path: root.join("db.sqlite"),
            keys_dir: root.join("keys"),
            root,
            hash_algorithm: HashAlgorithm::default(),
            limits: ArtifactLimits::default(),
            timeouts: DefaultTimeouts::default(),
            database: DatabaseConfig::default(),
            signing: None,
        }
    }

    /// Resolve store path from `OAIE_HOME` env var, falling back to `~/.oaie`.
    ///
    /// Returns an error if neither `OAIE_HOME` nor `HOME` is set (common in
    /// containers, CI, and cron environments).
    pub fn from_env() -> Result<Self> {
        if let Ok(path) = std::env::var("OAIE_HOME") {
            return Ok(Self::from_root(PathBuf::from(path)));
        }
        match std::env::var("HOME") {
            Ok(home) => Ok(Self::from_root(PathBuf::from(home).join(".oaie"))),
            Err(_) => Err(OaieError::StoreNotInitialized),
        }
    }

    /// Create all store directories if they don't exist.
    ///
    /// Sets the store root to mode 0700 so only the owner can access it.
    /// Subdirectories (cas/, runs/) inherit restricted access since the
    /// parent directory blocks traversal by other users.
    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        // Create root with restrictive permissions from the start to avoid
        // a TOCTOU window where another user could access the directory
        // between creation and chmod. DirBuilder sets mode atomically.
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.root)?;
        // Ensure permissions are correct even if the directory already existed
        // with wrong mode (e.g. created by an older version of oaie).
        std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o700))?;
        std::fs::create_dir_all(&self.runs_dir)?;
        std::fs::create_dir_all(&self.cas_dir)?;
        std::fs::create_dir_all(&self.keys_dir)?;
        // Restrict keys directory so other users can't list key file names.
        // The parent store root is already 0o700, but be explicit here too.
        std::fs::set_permissions(&self.keys_dir, std::fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    /// Check if the store has been initialized (root directory exists).
    ///
    /// For SQLite backends, verifies the database file exists. For PostgreSQL
    /// backends, only checks the store root (the DB is remote).
    pub fn is_initialized(&self) -> bool {
        match &self.database {
            DatabaseConfig::Sqlite { .. } => self.root.exists() && self.db_path.exists(),
            DatabaseConfig::Postgresql { .. } => self.root.exists(),
        }
    }

    /// Read `config.toml` and set the hash algorithm, limits, and database config.
    ///
    /// For legacy stores without `config.toml`, defaults to BLAKE3 + SQLite and
    /// writes the config file so future opens are explicit.
    pub fn open(&mut self) -> Result<()> {
        match StoreConfig::load(&self.root)? {
            Some(cfg) => {
                self.hash_algorithm = cfg.hash_algorithm;
                self.limits = cfg.limits;
                self.timeouts = cfg.timeouts;
                self.database = cfg.database;
                self.signing = cfg.signing;
            }
            None => {
                // Legacy store — assume BLAKE3 + SQLite defaults and write config.
                self.hash_algorithm = HashAlgorithm::Blake3;
                self.limits = ArtifactLimits::default();
                self.timeouts = DefaultTimeouts::default();
                self.database = DatabaseConfig::default();
                if self.root.exists() {
                    let cfg = StoreConfig::default();
                    cfg.write(&self.root)?;
                }
            }
        }

        // Resolve db_path from database config.
        if let DatabaseConfig::Sqlite { ref path } = self.database {
            let p = std::path::Path::new(path);
            self.db_path = if p.is_absolute() {
                p.to_path_buf()
            } else {
                self.root.join(path)
            };
        }

        Ok(())
    }

}
