//! Signing and attestation types for Ed25519 manifest signing.
//!
//! Pure data types only — no crypto dependencies. oaie-core stays lightweight.
//! The actual Ed25519 operations live in oaie-cli's `signing` module.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::OaieError;

/// Supported signing algorithms.
///
/// Currently only Ed25519, following the `HashAlgorithm` pattern for future
/// extensibility (e.g. Ed448, ECDSA P-256).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SigningAlgorithm {
    /// Ed25519 — compact 32-byte keys, 64-byte signatures, widely supported.
    Ed25519,
}

impl fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519 => write!(f, "ed25519"),
        }
    }
}

impl FromStr for SigningAlgorithm {
    type Err = OaieError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "ed25519" => Ok(Self::Ed25519),
            _ => Err(OaieError::Other(format!(
                "unknown signing algorithm: {s} (expected ed25519)"
            ))),
        }
    }
}

/// Contents of the `signature.toml` sidecar file.
///
/// Stored alongside the manifest in the run directory and CAS.
/// Contains everything needed to verify the signature independently:
/// the public key, the hash of the manifest bytes, and the Ed25519 signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureInfo {
    /// Sidecar format version (starts at 1).
    pub version: u32,
    /// Signing algorithm used.
    pub algorithm: SigningAlgorithm,
    /// Signer's public key (32 bytes, hex-encoded).
    pub public_key: String,
    /// Human-readable label for the signing key (e.g. "work-laptop").
    pub signer_label: String,
    /// Hash algorithm used to hash the manifest bytes (e.g. "blake3").
    pub hash_algorithm: String,
    /// Hash of the raw manifest.toml bytes (hex-encoded).
    pub manifest_hash: String,
    /// Ed25519 signature over the manifest hash bytes (64 bytes, hex-encoded).
    pub signature: String,
    /// ISO 8601 timestamp of when the signature was created.
    pub signed_at: String,
}

/// Metadata about a signing key.
///
/// Stored in key files under `<store_root>/keys/<key_id>.toml`.
/// The secret key is NOT included here — it lives in the key file only.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Key file format version (starts at 1).
    pub version: u32,
    /// Signing algorithm.
    pub algorithm: SigningAlgorithm,
    /// Human-readable label (e.g. "work-laptop", "ci-server").
    pub label: String,
    /// Key ID: first 8 hex chars of BLAKE3(public_key_bytes).
    pub key_id: String,
    /// ISO 8601 timestamp of key creation.
    pub created: String,
    /// Public key (32 bytes, hex-encoded).
    pub public_key: String,
}
