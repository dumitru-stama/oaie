//! Hash algorithm selection and streaming hasher.
//!
//! OAIE supports BLAKE3 (default, fast) and SHA-256 (compliance).
//! The algorithm is chosen at `oaie init` time and stored in `config.toml`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::artifact::Hash;
use crate::error::OaieError;

/// Which hash algorithm the store uses for CAS, event chains, and verification.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    /// BLAKE3 — fast, default.
    #[default]
    Blake3,
    /// SHA-256 — FIPS/compliance.
    Sha256,
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blake3 => write!(f, "blake3"),
            Self::Sha256 => write!(f, "sha256"),
        }
    }
}

impl FromStr for HashAlgorithm {
    type Err = OaieError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "blake3" => Ok(Self::Blake3),
            "sha256" => Ok(Self::Sha256),
            _ => Err(OaieError::InvalidJobSpec(format!(
                "unknown hash algorithm: {s} (expected blake3 or sha256)"
            ))),
        }
    }
}

/// Streaming hasher that wraps either BLAKE3 or SHA-256.
///
/// Both produce 32-byte digests, so the output `Hash` type is the same.
pub enum StreamingHasher {
    /// BLAKE3 streaming hasher (boxed — blake3::Hasher is ~1920 bytes).
    Blake3(Box<blake3::Hasher>),
    /// SHA-256 streaming hasher.
    Sha256(sha2::Sha256),
}

impl StreamingHasher {
    /// Create a new streaming hasher for the given algorithm.
    pub fn new(algo: HashAlgorithm) -> Self {
        match algo {
            HashAlgorithm::Blake3 => Self::Blake3(Box::new(blake3::Hasher::new())),
            HashAlgorithm::Sha256 => Self::Sha256(sha2::Sha256::new()),
        }
    }

    /// Feed data into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Blake3(h) => { h.update(data); }
            Self::Sha256(h) => { h.update(data); }
        }
    }

    /// Finalize and return the 32-byte hash.
    pub fn finalize(self) -> Hash {
        match self {
            Self::Blake3(h) => Hash::from_blake3(h.finalize()),
            Self::Sha256(h) => {
                let digest = h.finalize();
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&digest);
                Hash::new(bytes)
            }
        }
    }
}
