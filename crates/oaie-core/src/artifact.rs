//! Content-addressed artifact types.
//!
//! `Hash` wraps a 32-byte BLAKE3 digest with hex display/parse.
//! `ArtifactRef` and `ArtifactType` describe stored blobs in the CAS.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// BLAKE3 hash wrapping 32 raw bytes, displayed as a 64-char hex string.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Hash([u8; 32]);

impl Hash {
    /// Wrap raw bytes as a Hash.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Access the underlying 32-byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compute a hash of the given data using the specified algorithm.
    pub fn compute(algo: crate::hash_algo::HashAlgorithm, data: &[u8]) -> Self {
        use crate::hash_algo::HashAlgorithm;
        match algo {
            HashAlgorithm::Blake3 => Self(*blake3::hash(data).as_bytes()),
            HashAlgorithm::Sha256 => {
                use sha2::Digest;
                let digest = sha2::Sha256::digest(data);
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&digest);
                Self(bytes)
            }
        }
    }

    /// Compute the BLAKE3 hash of the given data (convenience for tests).
    pub fn from_data(data: &[u8]) -> Self {
        Self(*blake3::hash(data).as_bytes())
    }

    /// Construct from a blake3::Hash (used by CAS streaming hasher).
    pub fn from_blake3(h: blake3::Hash) -> Self {
        Self(*h.as_bytes())
    }

    /// Full 64-char hex string.
    pub fn to_hex(&self) -> String {
        self.to_string()
    }

    /// CAS directory components: two levels of 2 hex chars each.
    /// e.g. hash "abcdef01..." → ("ab", "cd").
    /// Produces layout: `cas/ab/cd/abcdef01...`
    pub fn cas_prefix(&self) -> (String, String) {
        (format!("{:02x}", self.0[0]), format!("{:02x}", self.0[1]))
    }

    /// First 6 hex chars for compact human display.
    pub fn short(&self) -> String {
        let hex = self.to_hex();
        hex[..6].to_string()
    }

    /// Parse from a 64-char hex string.
    pub fn from_hex(s: &str) -> crate::error::Result<Self> {
        s.parse()
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for Hash {
    type Err = crate::error::OaieError;

    fn from_str(s: &str) -> crate::error::Result<Self> {
        if s.len() != 64 {
            return Err(crate::error::OaieError::InvalidHash(format!(
                "expected 64 hex chars, got {}",
                s.len()
            )));
        }
        let mut bytes = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hex = std::str::from_utf8(chunk).map_err(|_| {
                crate::error::OaieError::InvalidHash("invalid utf-8 in hex".to_string())
            })?;
            bytes[i] = u8::from_str_radix(hex, 16).map_err(|_| {
                crate::error::OaieError::InvalidHash(format!("invalid hex byte: {hex}"))
            })?;
        }
        Ok(Self(bytes))
    }
}

impl Serialize for Hash {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A content-addressed reference to a stored blob.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ArtifactRef {
    /// BLAKE3 hash identifying the content blob in CAS.
    pub hash: Hash,
    /// Size of the blob in bytes.
    pub size: u64,
    /// Human-readable label: "stdout", "stderr", "output/result.txt".
    pub label: String,
    /// What kind of artifact this is (stdout, output file, trace, etc.).
    pub artifact_type: ArtifactType,
}

impl ArtifactRef {
    /// Validate that the label is safe for use in filesystem paths.
    /// Rejects path traversal attempts (`..` components, absolute paths, null bytes).
    pub fn validate_label(label: &str) -> crate::error::Result<()> {
        if label.is_empty() {
            return Err(crate::error::OaieError::Other(
                "artifact label is empty".into(),
            ));
        }
        if label.starts_with('/') {
            return Err(crate::error::OaieError::Other(format!(
                "artifact label is an absolute path: {label}"
            )));
        }
        if label.contains('\0') {
            return Err(crate::error::OaieError::Other(
                "artifact label contains null byte".into(),
            ));
        }
        // Reject ".." as a path component (but allow "..foo" or "foo..bar").
        for component in label.split('/') {
            if component == ".." {
                return Err(crate::error::OaieError::Other(format!(
                    "artifact label contains path traversal: {label}"
                )));
            }
        }
        Ok(())
    }
}

/// Classification of artifacts produced by a run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    /// Captured standard output of the sandboxed process.
    Stdout,
    /// Captured standard error of the sandboxed process.
    Stderr,
    /// File produced in the /out directory.
    Output,
    /// Syscall observation trace (ptrace/eBPF).
    Trace,
    /// Generated REPORT.md summarizing the run.
    Report,
    /// Serialized manifest.toml recording all run metadata.
    Manifest,
    /// Cgroup v2 resource accounting stats (cgroup_stats.json).
    ResourceStats,
    /// Ed25519 manifest signature sidecar (signature.toml).
    Signature,
}

impl fmt::Display for ArtifactType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stdout => write!(f, "stdout"),
            Self::Stderr => write!(f, "stderr"),
            Self::Output => write!(f, "output"),
            Self::Trace => write!(f, "trace"),
            Self::Report => write!(f, "report"),
            Self::Manifest => write!(f, "manifest"),
            Self::ResourceStats => write!(f, "resource_stats"),
            Self::Signature => write!(f, "signature"),
        }
    }
}

impl FromStr for ArtifactType {
    type Err = crate::error::OaieError;

    fn from_str(s: &str) -> crate::error::Result<Self> {
        match s {
            "stdout" => Ok(Self::Stdout),
            "stderr" => Ok(Self::Stderr),
            "output" => Ok(Self::Output),
            "trace" => Ok(Self::Trace),
            "report" => Ok(Self::Report),
            "manifest" => Ok(Self::Manifest),
            "resource_stats" => Ok(Self::ResourceStats),
            "signature" => Ok(Self::Signature),
            _ => Err(crate::error::OaieError::InvalidJobSpec(format!(
                "unknown artifact type: {s}"
            ))),
        }
    }
}
