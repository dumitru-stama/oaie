//! Store-level configuration persisted as `config.toml` in the store root.
//!
//! Written at `oaie init` time. Read on every subsequent command to determine
//! which hash algorithm and artifact limits the store uses.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{OaieError, Result};
use crate::hash_algo::HashAlgorithm;

/// Default maximum number of output files per run.
pub const DEFAULT_MAX_OUTPUT_FILES: u64 = 10_000;
/// Default maximum size of a single output file (256 MiB).
pub const DEFAULT_MAX_OUTPUT_FILE_SIZE: u64 = 256 * 1024 * 1024;
/// Default maximum total bytes across all output files (1 GiB).
pub const DEFAULT_MAX_OUTPUT_TOTAL: u64 = 1024 * 1024 * 1024;
/// Default wall-clock timeout when neither CLI nor policy specifies one.
pub const DEFAULT_TIMEOUT: &str = "5m";
/// Absolute maximum timeout — clamped even if CLI or policy requests more.
pub const DEFAULT_MAX_TIMEOUT: &str = "7d";

/// Database backend selection and connection configuration.
///
/// Stored in `config.toml` under `[database]`. The `backend` field selects
/// which database engine to use; the remaining fields depend on the backend.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "lowercase")]
pub enum DatabaseConfig {
    /// SQLite — local file, zero configuration. Default for new stores.
    Sqlite {
        /// Path to the SQLite file, relative to store root or absolute.
        #[serde(default = "default_sqlite_path")]
        path: String,
    },
    /// PostgreSQL — remote or local server.
    Postgresql {
        /// Connection URL, e.g. `postgresql://user:pass@localhost:5432/oaie`.
        url: String,
    },
}

impl std::fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite { path } => f.debug_struct("Sqlite").field("path", path).finish(),
            Self::Postgresql { url } => {
                // Redact password: show "postgresql://user:****@host:port/db"
                // Only redact if there's a colon AFTER the scheme "://" and before "@".
                // Without this check, a URL without a password (user@host) gets
                // the scheme colon matched, mangling the output.
                let redacted = if let Some(at) = url.find('@') {
                    let search_start = url.find("://").map(|i| i + 3).unwrap_or(0);
                    if let Some(colon_offset) = url[search_start..at].rfind(':') {
                        let colon = search_start + colon_offset;
                        format!("{}****@{}", &url[..colon + 1], &url[at + 1..])
                    } else {
                        url.clone()
                    }
                } else {
                    url.clone()
                };
                f.debug_struct("Postgresql").field("url", &redacted).finish()
            }
        }
    }
}

fn default_sqlite_path() -> String {
    "db.sqlite".into()
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self::Sqlite { path: default_sqlite_path() }
    }
}

impl std::fmt::Display for DatabaseConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite { path } => write!(f, "sqlite ({path})"),
            Self::Postgresql { url } => {
                // Redact password from display output — only if colon is after "://".
                if let Some(at) = url.find('@') {
                    let search_start = url.find("://").map(|i| i + 3).unwrap_or(0);
                    if let Some(colon_offset) = url[search_start..at].rfind(':') {
                        let colon = search_start + colon_offset;
                        return write!(f, "postgresql ({}****@{})", &url[..colon + 1], &url[at + 1..]);
                    }
                }
                write!(f, "postgresql ({url})")
            }
        }
    }
}

/// Store configuration written to `<store_root>/config.toml`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoreConfig {
    /// Config format version (starts at 1).
    pub version: u32,
    /// Canonical absolute path of the store root directory.
    ///
    /// Recorded at `oaie init` time. On re-init, the existing config's
    /// `store_path` takes priority — if it points to a different directory,
    /// init runs there instead of the resolved default.
    #[serde(default)]
    pub store_path: PathBuf,
    /// Hash algorithm used for CAS, event chains, and verification.
    #[serde(default)]
    pub hash_algorithm: HashAlgorithm,
    /// Artifact collection limits for output files.
    #[serde(default)]
    pub limits: ArtifactLimits,
    /// Default timeout settings for runs.
    #[serde(default)]
    pub timeouts: DefaultTimeouts,
    /// Database backend and connection configuration.
    #[serde(default)]
    pub database: DatabaseConfig,
    /// Signing configuration for manifest attestation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing: Option<SigningConfig>,
}

/// Configuration for manifest signing.
///
/// Stored in `config.toml` under `[signing]`. Controls automatic signing
/// behavior when `--sign` is not explicitly passed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningConfig {
    /// Default signing key (key ID prefix or label).
    ///
    /// When set, `oaie run` will automatically sign manifests with this key
    /// unless `--sign` overrides it or signing is explicitly disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_key: Option<String>,

    /// Public keys (hex-encoded Ed25519, 64 chars each) trusted for
    /// `oaie verify`.
    ///
    /// This is the trust anchor. Without it, `verify_signature()` could
    /// only check that A signature is valid for THE public key embedded
    /// in `signature.toml` — but `signature.toml` is the file under
    /// verification. Anyone with `ed25519-dalek` can generate a keypair,
    /// sign any manifest, and embed their pubkey + chosen `signer_label`
    /// in the sidecar; the Ed25519 math checks out, the trust does not.
    ///
    /// **Empty list** (the default) means `oaie verify` reports
    /// `CheckStatus::Skip` for the signature check, NOT `Pass`. There is
    /// no value of this list that admits a self-attesting signature.
    ///
    /// Populate from `oaie key list --json | jq '.[].public_key'` for
    /// keys you generated locally, plus any keys you've received
    /// out-of-band from collaborators whose runs you want to verify.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_public_keys: Vec<String>,
}

/// Configurable limits on output artifact collection per run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactLimits {
    /// Maximum number of output files to collect from a single run.
    #[serde(default = "default_max_output_files")]
    pub max_output_files: u64,
    /// Maximum size of a single output file in bytes.
    #[serde(default = "default_max_output_file_size")]
    pub max_output_file_size: u64,
    /// Maximum total bytes across all output files.
    #[serde(default = "default_max_output_total")]
    pub max_output_total: u64,
}

fn default_max_output_files() -> u64 {
    DEFAULT_MAX_OUTPUT_FILES
}
fn default_max_output_file_size() -> u64 {
    DEFAULT_MAX_OUTPUT_FILE_SIZE
}
fn default_max_output_total() -> u64 {
    DEFAULT_MAX_OUTPUT_TOTAL
}
fn default_timeout() -> String {
    DEFAULT_TIMEOUT.into()
}
fn default_max_timeout() -> String {
    DEFAULT_MAX_TIMEOUT.into()
}

impl Default for ArtifactLimits {
    fn default() -> Self {
        Self {
            max_output_files: DEFAULT_MAX_OUTPUT_FILES,
            max_output_file_size: DEFAULT_MAX_OUTPUT_FILE_SIZE,
            max_output_total: DEFAULT_MAX_OUTPUT_TOTAL,
        }
    }
}

/// Default timeout settings for runs.
///
/// `default_timeout` is used when neither `--timeout` nor a policy `max_time`
/// is specified. `max_timeout` is the absolute cap — even `--timeout 999h`
/// gets clamped to this value.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DefaultTimeouts {
    /// Default wall-clock timeout (human-readable: "5m", "1h", "30s").
    #[serde(default = "default_timeout")]
    pub default_timeout: String,
    /// Absolute maximum timeout — runs are clamped to this value.
    #[serde(default = "default_max_timeout")]
    pub max_timeout: String,
}

impl Default for DefaultTimeouts {
    fn default() -> Self {
        Self {
            default_timeout: DEFAULT_TIMEOUT.into(),
            max_timeout: DEFAULT_MAX_TIMEOUT.into(),
        }
    }
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            version: 1,
            store_path: PathBuf::new(),
            hash_algorithm: HashAlgorithm::default(),
            limits: ArtifactLimits::default(),
            timeouts: DefaultTimeouts::default(),
            database: DatabaseConfig::default(),
            signing: None,
        }
    }
}

impl StoreConfig {
    /// Read `config.toml` from the store root. Returns `None` if the file
    /// doesn't exist (legacy store).
    ///
    /// Validates that the config version is not from a future version that
    /// this binary doesn't understand.
    pub fn load(store_root: &Path) -> Result<Option<Self>> {
        let path = store_root.join("config.toml");
        if !path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(&path)?;
        let config: Self = toml::from_str(&content).map_err(|e| OaieError::Io(std::io::Error::other(format!("config.toml: {e}"))))?;

        // Reject configs from future versions we don't understand.
        if config.version > 1 {
            return Err(OaieError::Io(std::io::Error::other(format!("config.toml version {} is newer than this binary supports (1); upgrade oaie", config.version))));
        }

        Ok(Some(config))
    }

    /// Write `config.toml` to the store root atomically.
    ///
    /// Writes to a temporary file in the same directory, fsyncs, then renames
    /// over the target. This prevents partial writes if the process is
    /// interrupted (e.g. power loss, SIGKILL).
    pub fn write(&self, store_root: &Path) -> Result<()> {
        let config_path = store_root.join("config.toml");
        // Include PID + thread ID to avoid collisions between concurrent writers
        // in the same process (PID alone is not unique across threads).
        let tmp_name = format!(".config.toml.{}.{:?}.tmp", std::process::id(), std::thread::current().id(),);
        let tmp_path = store_root.join(tmp_name);
        let toml_str = toml::to_string_pretty(self).map_err(|e| OaieError::Io(std::io::Error::other(e)))?;
        let result = (|| -> Result<()> {
            let mut f = std::fs::File::create(&tmp_path)?;
            f.write_all(toml_str.as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp_path, &config_path)?;
            Ok(())
        })();
        if result.is_err() {
            // Clean up temp file on any failure to prevent accumulation.
            let _ = std::fs::remove_file(&tmp_path);
        }
        result
    }
}
