//! Job specification: what the user wants OAIE to run.
//!
//! A [`JobSpec`] can come from CLI flags or a `job.toml` file.
//! It describes the command, mounts, network, trace, and timeout settings.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use crate::backend::BackendKind;
use crate::error::{OaieError, Result};

/// A job is what the user asks OAIE to run.
/// Can come from CLI args or a job.toml file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobSpec {
    /// The command and arguments to execute inside the sandbox.
    pub command: Vec<String>,
    /// Input directory (default: cwd, mounted read-only).
    pub inputs: Option<PathBuf>,
    /// Output directory (default: ./oaie-out/<run_id>).
    pub outputs: Option<PathBuf>,
    /// Allow network access (default: false).
    #[serde(default)]
    pub network: bool,
    /// Trace mode.
    #[serde(default)]
    pub trace: TraceMode,
    /// Timeout for the run.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "duration_serde"
    )]
    pub timeout: Option<Duration>,
    /// Path to policy.toml.
    pub policy: Option<PathBuf>,
    /// Additional host paths mounted read-only inside the sandbox.
    #[serde(default)]
    pub extra_ro: Vec<PathBuf>,
    /// Additional host paths mounted read-write inside the sandbox.
    #[serde(default)]
    pub extra_rw: Vec<PathBuf>,
    /// Skip namespace isolation (user explicitly accepted the risk).
    #[serde(default)]
    pub no_isolation: bool,
    /// Execution backend: namespace (default), bare, or firecracker.
    #[serde(default)]
    pub backend: BackendKind,
    /// Run in interactive mode with a pseudoterminal (PTY).
    /// Enables terminal apps (vim, htop, less) inside the sandbox.
    #[serde(default)]
    pub interactive: bool,
}

/// How syscall tracing should be performed for the run.
///
/// Determines which backend (if any) observes the sandboxed process's
/// syscalls. Currently all modes are stubs; real backends come in weeks 6-7.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TraceMode {
    /// No syscall tracing.
    #[default]
    Off,
    /// User-facing name for ptrace-based syscall tracing.
    Strace,
    /// Advanced alias for ptrace-based tracing.
    Ptrace,
    /// eBPF-based kernel-level observation (tier 2).
    Ebpf,
    /// Use the best available backend (eBPF if available, falls back to ptrace).
    Auto,
}

impl fmt::Display for TraceMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Off => write!(f, "off"),
            Self::Strace => write!(f, "strace"),
            Self::Ptrace => write!(f, "ptrace"),
            Self::Ebpf => write!(f, "ebpf"),
            Self::Auto => write!(f, "auto"),
        }
    }
}

impl FromStr for TraceMode {
    type Err = OaieError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "off" => Ok(Self::Off),
            "strace" => Ok(Self::Strace),
            "ptrace" => Ok(Self::Ptrace),
            "ebpf" => Ok(Self::Ebpf),
            "auto" => Ok(Self::Auto),
            _ => Err(OaieError::InvalidJobSpec(format!("unknown trace mode: {s}"))),
        }
    }
}

/// Serde helper for Option<Duration> as seconds (f64 in TOML).
mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(
        duration: &Option<Duration>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match duration {
            Some(d) => d.as_secs_f64().serialize(serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Duration>, D::Error> {
        let opt: Option<f64> = Option::deserialize(deserializer)?;
        match opt {
            None => Ok(None),
            Some(v) if v < 0.0 || v.is_nan() || v.is_infinite() || v > 604_800.0 => {
                Err(serde::de::Error::custom(format!(
                    "invalid timeout value: {v}"
                )))
            }
            Some(0.0) => {
                Err(serde::de::Error::custom("timeout must be greater than zero"))
            }
            Some(v) => Ok(Some(Duration::from_secs_f64(v))),
        }
    }
}

impl JobSpec {
    /// Load a job spec from a TOML file, validate it, and return.
    pub fn from_toml_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| OaieError::InvalidJobSpec(format!("failed to read {}: {e}", path.display())))?;
        let spec: JobSpec = toml::from_str(&content)
            .map_err(|e| OaieError::InvalidJobSpec(format!("failed to parse {}: {e}", path.display())))?;
        spec.validate()?;
        Ok(spec)
    }

    /// Read a job spec from stdin, auto-detecting JSON vs TOML.
    ///
    /// If the first non-whitespace character is `{`, parse as JSON.
    /// Otherwise parse as TOML. This lets agents pipe job specs
    /// programmatically in either format.
    pub fn from_stdin() -> Result<Self> {
        use std::io::Read;
        // Cap stdin reads at 1 MiB to prevent DoS from unbounded input.
        const MAX_STDIN_BYTES: u64 = 1024 * 1024;
        let mut content = String::new();
        std::io::stdin()
            .take(MAX_STDIN_BYTES)
            .read_to_string(&mut content)
            .map_err(|e| OaieError::InvalidJobSpec(format!("failed to read stdin: {e}")))?;
        Self::from_string(&content, "<stdin>")
    }

    /// Parse a job spec from a string, auto-detecting JSON vs TOML.
    pub fn from_string(content: &str, source: &str) -> Result<Self> {
        let first_char = content.trim_start().chars().next().unwrap_or('\0');
        let spec: JobSpec = if first_char == '{' {
            serde_json::from_str(content)
                .map_err(|e| OaieError::InvalidJobSpec(format!("failed to parse JSON from {source}: {e}")))?
        } else {
            toml::from_str(content)
                .map_err(|e| OaieError::InvalidJobSpec(format!("failed to parse TOML from {source}: {e}")))?
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Validate the job spec for obvious errors.
    pub fn validate(&self) -> Result<()> {
        if self.command.is_empty() {
            return Err(OaieError::InvalidJobSpec("job spec has no command".into()));
        }
        if let Some(ref input) = self.inputs {
            if !input.exists() {
                return Err(OaieError::InvalidJobSpec(format!(
                    "input path does not exist: {}",
                    input.display()
                )));
            }
        }
        Ok(())
    }
}

/// Parse a human-readable timeout string into a Duration.
///
/// Supported formats: "30s", "5m", "1h", or plain seconds ("30").
pub fn parse_timeout(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return Err(OaieError::InvalidJobSpec("empty timeout string".into()));
    }

    // Parse the numeric part and suffix.
    let (num_str, multiplier) = if let Some(num) = s.strip_suffix('s') {
        (num, 1.0)
    } else if let Some(num) = s.strip_suffix('m') {
        (num, 60.0)
    } else if let Some(num) = s.strip_suffix('h') {
        (num, 3600.0)
    } else {
        (s, 1.0)
    };

    let value: f64 = num_str
        .parse()
        .map_err(|_| OaieError::InvalidJobSpec(format!("invalid timeout: {s}")))?;

    if value < 0.0 || value.is_nan() || value.is_infinite() {
        return Err(OaieError::InvalidJobSpec(format!(
            "invalid timeout value: {s}"
        )));
    }

    let seconds = value * multiplier;

    if seconds == 0.0 {
        return Err(OaieError::InvalidJobSpec("timeout must be greater than zero".into()));
    }
    // Cap at 7 days — Duration::from_secs_f64 panics on values > ~2^63 nanoseconds.
    const MAX_TIMEOUT_SECS: f64 = 7.0 * 24.0 * 3600.0; // 604800s
    if seconds > MAX_TIMEOUT_SECS {
        return Err(OaieError::InvalidJobSpec(format!(
            "timeout too large (max 7 days): {s}"
        )));
    }

    Ok(Duration::from_secs_f64(seconds))
}
