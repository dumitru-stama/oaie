//! Ed25519 signing operations and key management.
//!
//! Provides keypair generation, manifest signing, signature verification,
//! and key file I/O. Lives in oaie-cli to keep crypto deps out of oaie-core.

use std::path::Path;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroize;

use oaie_core::error::{OaieError, Result};
use oaie_core::hash_algo::HashAlgorithm;
use oaie_core::signing::{KeyInfo, SignatureInfo, SigningAlgorithm};

/// Key file stored at `<store_root>/keys/<key_id>.toml`.
///
/// Contains both the public and secret key material. File permissions
/// should be 0o600 to protect the secret key.
#[derive(serde::Serialize, serde::Deserialize)]
struct KeyFile {
    version: u32,
    algorithm: SigningAlgorithm,
    label: String,
    key_id: String,
    created: String,
    public_key: String,
    secret_key: String,
}

/// Generate a new Ed25519 keypair.
///
/// Returns the key metadata and the hex-encoded secret key.
/// The key ID is the first 8 hex chars of BLAKE3(public_key_bytes).
pub fn generate_keypair(label: &str) -> Result<(KeyInfo, String)> {
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let public_hex = hex_encode(verifying_key.as_bytes());
    let secret_hex = hex_encode(signing_key.as_bytes());

    // Key ID = first 8 hex chars of BLAKE3(public_key_bytes).
    let id_hash = blake3::hash(verifying_key.as_bytes());
    let key_id = hex_encode(&id_hash.as_bytes()[..4]);

    let now = chrono::Utc::now().to_rfc3339();

    let info = KeyInfo {
        version: 1,
        algorithm: SigningAlgorithm::Ed25519,
        label: label.to_string(),
        key_id,
        created: now,
        public_key: public_hex,
    };

    Ok((info, secret_hex))
}

/// Sign manifest bytes with an Ed25519 key.
///
/// 1. Hashes the raw manifest bytes with the store's hash algorithm.
/// 2. Signs the 32-byte hash with the Ed25519 secret key.
/// 3. Returns a `SignatureInfo` sidecar ready for serialization.
pub fn sign_manifest(
    manifest_bytes: &[u8],
    secret_key_hex: &str,
    key_info: &KeyInfo,
    hash_algo: HashAlgorithm,
) -> Result<SignatureInfo> {
    let mut secret_bytes = hex_decode(secret_key_hex)?;
    if secret_bytes.len() != 32 {
        secret_bytes.zeroize();
        return Err(OaieError::Other(format!(
            "secret key must be 32 bytes, got {}",
            secret_bytes.len()
        )));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&secret_bytes);
    secret_bytes.zeroize();
    let signing_key = SigningKey::from_bytes(&key_bytes);
    key_bytes.zeroize();

    // Hash manifest bytes.
    let manifest_hash = oaie_core::artifact::Hash::compute(hash_algo, manifest_bytes);

    // Sign the 32-byte hash.
    let signature = signing_key.sign(manifest_hash.as_bytes());

    Ok(SignatureInfo {
        version: 1,
        algorithm: SigningAlgorithm::Ed25519,
        public_key: key_info.public_key.clone(),
        signer_label: key_info.label.clone(),
        hash_algorithm: hash_algo.to_string(),
        manifest_hash: manifest_hash.to_hex(),
        signature: hex_encode(&signature.to_bytes()),
        signed_at: chrono::Utc::now().to_rfc3339(),
    })
}

/// Verify an Ed25519 signature over manifest bytes.
///
/// 1. Hashes the raw manifest bytes with the specified algorithm.
/// 2. Checks that the computed hash matches the claimed manifest_hash.
/// 3. Verifies the Ed25519 signature over the hash bytes.
///
/// Returns `true` if the signature is valid, `false` otherwise.
pub fn verify_signature(
    manifest_bytes: &[u8],
    sig: &SignatureInfo,
    hash_algo: HashAlgorithm,
) -> Result<bool> {
    // Recompute manifest hash.
    let computed_hash = oaie_core::artifact::Hash::compute(hash_algo, manifest_bytes);
    if computed_hash.to_hex() != sig.manifest_hash {
        return Ok(false);
    }

    // Parse public key.
    let pub_bytes = hex_decode(&sig.public_key)?;
    if pub_bytes.len() != 32 {
        return Err(OaieError::Other(format!(
            "public key must be 32 bytes, got {}",
            pub_bytes.len()
        )));
    }
    let mut pk_array = [0u8; 32];
    pk_array.copy_from_slice(&pub_bytes);
    let verifying_key = VerifyingKey::from_bytes(&pk_array)
        .map_err(|e| OaieError::Other(format!("invalid public key: {e}")))?;

    // Parse signature.
    let sig_bytes = hex_decode(&sig.signature)?;
    if sig_bytes.len() != 64 {
        return Err(OaieError::Other(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        )));
    }
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&sig_bytes);
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    // Verify.
    Ok(verifying_key.verify(computed_hash.as_bytes(), &signature).is_ok())
}

/// Save a key to the keys directory.
///
/// Creates `<keys_dir>/<key_id>.toml` with file permissions 0o600.
/// Uses atomic write (temp file + rename) so a crash can't leave a
/// partial key file, and sets the mode at file creation time to avoid
/// a TOCTOU window where the secret key is briefly world-readable.
pub fn save_key(keys_dir: &Path, info: &KeyInfo, secret_hex: &str) -> Result<()> {
    std::fs::create_dir_all(keys_dir)?;

    let key_file = KeyFile {
        version: info.version,
        algorithm: info.algorithm,
        label: info.label.clone(),
        key_id: info.key_id.clone(),
        created: info.created.clone(),
        public_key: info.public_key.clone(),
        secret_key: secret_hex.to_string(),
    };

    let toml_str = toml::to_string_pretty(&key_file)
        .map_err(|e| OaieError::Io(std::io::Error::other(e)))?;

    let final_path = keys_dir.join(format!("{}.toml", info.key_id));

    // Atomic write: create a temp file with restricted permissions, write
    // the content, fsync, then rename into place. This avoids both a
    // TOCTOU window (file is 0o600 from creation) and partial writes.
    let tmp_path = keys_dir.join(format!(".{}.toml.tmp", info.key_id));

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)?;
        f.write_all(toml_str.as_bytes())?;
        f.sync_all()?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(&tmp_path, &toml_str)?;
    }

    std::fs::rename(&tmp_path, &final_path)?;

    Ok(())
}

/// Load a key by ID prefix or label.
///
/// Searches all `.toml` files in the keys directory.
/// Returns the key info and hex-encoded secret key.
pub fn load_key(keys_dir: &Path, id_or_label: &str) -> Result<(KeyInfo, String)> {
    if !keys_dir.is_dir() {
        return Err(OaieError::Other(format!(
            "keys directory not found: {}",
            keys_dir.display()
        )));
    }

    let mut matches = Vec::new();

    for entry in std::fs::read_dir(keys_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }

        let content = std::fs::read_to_string(&path)?;
        let key_file: KeyFile = match toml::from_str(&content) {
            Ok(k) => k,
            Err(e) => {
                eprintln!(
                    "OAIE: Warning: skipping malformed key file {}: {e}",
                    path.display()
                );
                continue;
            }
        };

        // Match by key_id prefix or exact label.
        if key_file.key_id.starts_with(id_or_label) || key_file.label == id_or_label {
            let info = KeyInfo {
                version: key_file.version,
                algorithm: key_file.algorithm,
                label: key_file.label,
                key_id: key_file.key_id,
                created: key_file.created,
                public_key: key_file.public_key,
            };
            matches.push((info, key_file.secret_key));
        }
    }

    match matches.len() {
        0 => Err(OaieError::Other(format!(
            "no signing key found matching '{id_or_label}'"
        ))),
        1 => Ok(matches.into_iter().next().unwrap()),
        n => Err(OaieError::Other(format!(
            "ambiguous key '{id_or_label}': matches {n} keys"
        ))),
    }
}

/// List all signing keys in the keys directory.
pub fn list_keys(keys_dir: &Path) -> Result<Vec<KeyInfo>> {
    if !keys_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut keys = Vec::new();

    for entry in std::fs::read_dir(keys_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }

        let content = std::fs::read_to_string(&path)?;
        match toml::from_str::<KeyFile>(&content) {
            Ok(key_file) => {
                keys.push(KeyInfo {
                    version: key_file.version,
                    algorithm: key_file.algorithm,
                    label: key_file.label,
                    key_id: key_file.key_id,
                    created: key_file.created,
                    public_key: key_file.public_key,
                });
            }
            Err(e) => {
                eprintln!(
                    "OAIE: Warning: skipping malformed key file {}: {e}",
                    path.display()
                );
            }
        }
    }

    // Sort by creation date for consistent display.
    keys.sort_by(|a, b| a.created.cmp(&b.created));

    Ok(keys)
}

/// Delete a signing key by ID prefix or label.
pub fn delete_key(keys_dir: &Path, id_or_label: &str) -> Result<()> {
    if !keys_dir.is_dir() {
        return Err(OaieError::Other(format!(
            "keys directory not found: {}",
            keys_dir.display()
        )));
    }

    let mut matches = Vec::new();

    for entry in std::fs::read_dir(keys_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }

        let content = std::fs::read_to_string(&path)?;
        match toml::from_str::<KeyFile>(&content) {
            Ok(key_file) => {
                if key_file.key_id.starts_with(id_or_label) || key_file.label == id_or_label {
                    matches.push(path);
                }
            }
            Err(e) => {
                eprintln!(
                    "OAIE: Warning: skipping malformed key file {}: {e}",
                    path.display()
                );
            }
        }
    }

    match matches.len() {
        0 => Err(OaieError::Other(format!(
            "no signing key found matching '{id_or_label}'"
        ))),
        1 => {
            std::fs::remove_file(&matches[0])?;
            Ok(())
        }
        n => Err(OaieError::Other(format!(
            "ambiguous key '{id_or_label}': matches {n} keys"
        ))),
    }
}

// ── Hex encoding helpers ──

/// Encode bytes as a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a hex string into bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(OaieError::Other(format!(
            "hex string has odd length: {}",
            s.len()
        )));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| {
                OaieError::Other(format!("invalid hex byte at position {i}: {}", &s[i..i + 2]))
            })
        })
        .collect()
}
