//! Content-addressed store: atomic writes, two-level prefix layout, configurable hashing.
//!
//! Blobs are stored at `<cas_root>/<byte0>/<byte1>/<full-hex-hash>` with 0o444
//! permissions. Writes are atomic (temp file, fsync, rename on same filesystem).
//! Deduplication is free — storing the same content twice is a no-op.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use oaie_core::artifact::Hash;
use oaie_core::error::{OaieError, Result};
use oaie_core::hash_algo::{HashAlgorithm, StreamingHasher};
use oaie_core::manifest::Manifest;

/// Content-addressed blob store.
///
/// Blobs are stored under a two-level prefix directory:
/// `<root>/<byte0>/<byte1>/<64-char hex hash>`
/// e.g. `cas/ab/cd/abcdef0123456789...`
///
/// This prevents too many entries in any single directory (max 256 per level).
/// Files are made read-only (0o444) after creation. Deduplication is
/// automatic: storing the same content twice is a no-op.
#[derive(Clone, Debug)]
pub struct CasStore {
    /// Root directory of the CAS (e.g. `~/.oaie/cas`).
    root: PathBuf,
    /// Hash algorithm used for content addressing.
    algo: HashAlgorithm,
}

/// Result of verifying a blob's integrity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyResult {
    /// Blob exists and its hash matches.
    Ok,
    /// Blob does not exist in the store.
    Missing,
    /// Blob exists but its content hash doesn't match its filename.
    Corrupted {
        /// The hash expected based on the blob's filename.
        expected: Hash,
        /// The hash computed by re-reading the blob content.
        actual: Hash,
    },
}

impl CasStore {
    /// Create a CasStore rooted at the given directory with the specified hash algorithm.
    pub fn new(root: PathBuf, algo: HashAlgorithm) -> Self {
        Self { root, algo }
    }

    /// Store a file from disk, return its hash and size.
    /// Deduplicates: if the blob already exists, skips the write.
    pub fn store_file(&self, path: &Path) -> Result<(Hash, u64)> {
        let mut file = File::open(path)?;
        self.store_impl(&mut file)
    }

    /// Store raw bytes, return their hash and size.
    pub fn store_bytes(&self, data: &[u8]) -> Result<(Hash, u64)> {
        let mut cursor = std::io::Cursor::new(data);
        self.store_impl(&mut cursor)
    }

    /// Store by streaming from a reader (for large files).
    /// Hashes while writing to avoid a second pass over the data.
    pub fn store_reader(&self, reader: &mut dyn Read) -> Result<(Hash, u64)> {
        self.store_impl(reader)
    }

    /// Check if a blob with this hash exists in the store.
    pub fn exists(&self, hash: &Hash) -> bool {
        self.blob_path(hash).exists()
    }

    /// Return the filesystem path where this blob is stored.
    /// Layout: `<root>/<byte0>/<byte1>/<full hex hash>`
    pub fn blob_path(&self, hash: &Hash) -> PathBuf {
        let (l1, l2) = hash.cas_prefix();
        self.root.join(l1).join(l2).join(hash.to_hex())
    }

    /// Open a stored blob for reading.
    pub fn open(&self, hash: &Hash) -> Result<File> {
        let path = self.blob_path(hash);
        File::open(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                OaieError::ArtifactNotFound(hash.short())
            } else {
                OaieError::Io(e)
            }
        })
    }

    /// Get the size of a stored blob in bytes.
    pub fn blob_size(&self, hash: &Hash) -> Result<u64> {
        let path = self.blob_path(hash);
        fs::metadata(&path).map(|m| m.len()).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                OaieError::ArtifactNotFound(hash.short())
            } else {
                OaieError::Io(e)
            }
        })
    }

    /// Re-hash a blob and compare against its expected hash.
    pub fn verify(&self, hash: &Hash) -> Result<VerifyResult> {
        let path = self.blob_path(hash);
        if !path.exists() {
            return Ok(VerifyResult::Missing);
        }
        let mut file = File::open(&path)?;
        let mut hasher = StreamingHasher::new(self.algo);
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let actual = hasher.finalize();
        if &actual == hash {
            Ok(VerifyResult::Ok)
        } else {
            Ok(VerifyResult::Corrupted {
                expected: hash.clone(),
                actual,
            })
        }
    }

    /// List all blobs in the store with their sizes.
    /// Walks the two-level prefix directory structure.
    pub fn list_all(&self) -> Result<Vec<(Hash, u64)>> {
        let mut blobs = Vec::new();
        if !self.root.exists() {
            return Ok(blobs);
        }
        for l1_entry in fs::read_dir(&self.root)? {
            let l1_entry = l1_entry?;
            if !l1_entry.file_type()?.is_dir() {
                continue;
            }
            let l1_name = l1_entry.file_name();
            let l1_str = l1_name.to_string_lossy();
            if !is_hex_prefix(&l1_str) {
                continue;
            }
            for l2_entry in fs::read_dir(l1_entry.path())? {
                let l2_entry = l2_entry?;
                if !l2_entry.file_type()?.is_dir() {
                    continue;
                }
                let l2_name = l2_entry.file_name();
                let l2_str = l2_name.to_string_lossy();
                if !is_hex_prefix(&l2_str) {
                    continue;
                }
                for blob_entry in fs::read_dir(l2_entry.path())? {
                    let blob_entry = blob_entry?;
                    let blob_name = blob_entry.file_name();
                    let blob_str = blob_name.to_string_lossy();
                    if let Ok(hash) = Hash::from_hex(&blob_str) {
                        let size = blob_entry.metadata()?.len();
                        blobs.push((hash, size));
                    }
                }
            }
        }
        Ok(blobs)
    }

    /// Remove leftover temp files from interrupted writes, skipping files
    /// newer than 1 hour (which may belong to concurrent writers still in
    /// progress). Called opportunistically from `Runner::new()`.
    pub fn cleanup_temps(&self) -> Result<usize> {
        self.cleanup_temps_impl(Some(std::time::Duration::from_secs(3600)))
    }

    /// Remove ALL temp files regardless of age. Called from `oaie init` where
    /// no concurrent writers are expected.
    pub fn cleanup_temps_all(&self) -> Result<usize> {
        self.cleanup_temps_impl(None)
    }

    /// Remove temp files, optionally filtering by minimum age.
    fn cleanup_temps_impl(&self, min_age: Option<std::time::Duration>) -> Result<usize> {
        let mut count = 0;
        if !self.root.exists() {
            return Ok(0);
        }
        let now = std::time::SystemTime::now();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with(".tmp-") {
                // Skip files newer than min_age — they may belong to
                // concurrent store operations still in progress.
                if let Some(min_age) = min_age {
                    if let Ok(meta) = entry.metadata() {
                        if let Ok(modified) = meta.modified() {
                            if now.duration_since(modified).unwrap_or_default() < min_age {
                                continue;
                            }
                        }
                    }
                }
                // Best-effort: don't fail the entire cleanup if one temp file
                // can't be removed (e.g. held by another process).
                if fs::remove_file(entry.path()).is_ok() {
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    /// Write a manifest to a run directory and store it in CAS.
    /// Returns the CAS hash of the manifest TOML.
    ///
    /// This lives in oaie-cas (not oaie-core) because it needs both
    /// Manifest (from oaie-core) and CasStore (from oaie-cas), and
    /// oaie-cas already depends on oaie-core.
    pub fn write_manifest(&self, manifest: &Manifest, run_dir: &Path) -> Result<Hash> {
        let toml_str = toml::to_string_pretty(manifest)
            .map_err(|e| OaieError::Io(std::io::Error::other(e)))?;

        // Store content-addressed copy in CAS first (authoritative record).
        // If we crash after this but before the run_dir write, the CAS is
        // consistent and the run_dir copy can be reconstructed.
        let (hash, _) = self.store_bytes(toml_str.as_bytes())?;

        // Write human-readable copy to run directory (best-effort convenience).
        let _ = fs::write(run_dir.join("manifest.toml"), &toml_str);

        Ok(hash)
    }

    /// Core store implementation: hash while writing to temp file, then atomic rename.
    ///
    /// If any step fails after the temp file is created, the temp file is
    /// cleaned up to avoid leaking partial writes.
    fn store_impl(&self, reader: &mut dyn Read) -> Result<(Hash, u64)> {
        // Write to a temp file in the CAS root (same filesystem for atomic rename).
        let tmp_name = format!(".tmp-{}", uuid::Uuid::now_v7());
        let tmp_path = self.root.join(&tmp_name);
        let mut tmp_file = File::create(&tmp_path)?;

        // Closure to clean up the temp file on error.
        let cleanup = |path: &Path| {
            let _ = fs::remove_file(path);
        };

        let mut hasher = StreamingHasher::new(self.algo);
        let mut size = 0u64;
        let mut buf = [0u8; 64 * 1024]; // 64KB read buffer.

        // Single-pass: hash and write simultaneously.
        let rw_result: Result<()> = (|| {
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                tmp_file.write_all(&buf[..n])?;
                size += n as u64;
            }

            // fsync before rename to ensure data is on disk.
            tmp_file.sync_all()?;
            Ok(())
        })();

        if let Err(e) = rw_result {
            drop(tmp_file);
            cleanup(&tmp_path);
            return Err(e);
        }
        drop(tmp_file);

        let hash = hasher.finalize();

        // Create the two-level prefix directory if needed.
        let (l1, l2) = hash.cas_prefix();
        let prefix_dir = self.root.join(l1).join(l2);
        if let Err(e) = fs::create_dir_all(&prefix_dir) {
            cleanup(&tmp_path);
            return Err(e.into());
        }

        let final_path = prefix_dir.join(hash.to_hex());
        if final_path.exists() {
            // Deduplication: verify existing blob isn't corrupted before trusting it.
            // If corrupted (bit rot, disk error), replace with our fresh copy.
            let algo = self.algo;
            let existing_ok = (|| -> std::result::Result<bool, std::io::Error> {
                let mut f = File::open(&final_path)?;
                let mut h = StreamingHasher::new(algo);
                let mut b = [0u8; 64 * 1024];
                loop {
                    let n = f.read(&mut b)?;
                    if n == 0 { break; }
                    h.update(&b[..n]);
                }
                Ok(h.finalize() == hash)
            })().unwrap_or(false);

            if existing_ok {
                let _ = fs::remove_file(&tmp_path);
            } else {
                // Existing blob is corrupted — replace it with the correct content.
                // Remove the corrupted blob first so that rename cannot fail due to
                // a stale target.  If removal fails, try rename anyway (rename(2)
                // atomically replaces existing targets on the same filesystem).
                let _ = fs::remove_file(&final_path);
                // Set read-only on temp file BEFORE rename so the replacement blob
                // is never visible as writable.
                let mut perms = fs::metadata(&tmp_path)?.permissions();
                perms.set_mode(0o444);
                fs::set_permissions(&tmp_path, perms)?;
                if let Err(e) = fs::rename(&tmp_path, &final_path) {
                    cleanup(&tmp_path);
                    return Err(e.into());
                }
                sync_parent_dir(&final_path);
            }
        } else {
            // Set read-only BEFORE rename so blob is never visible as writable.
            let mut perms = fs::metadata(&tmp_path)?.permissions();
            perms.set_mode(0o444);
            fs::set_permissions(&tmp_path, perms)?;
            // Atomic rename into place.
            if let Err(e) = fs::rename(&tmp_path, &final_path) {
                cleanup(&tmp_path);
                return Err(e.into());
            }
            // Sync parent directory so the directory entry is durable on power loss.
            sync_parent_dir(&final_path);
        }

        Ok((hash, size))
    }
}

/// Read a manifest from a run directory.
pub fn read_manifest(run_dir: &Path) -> Result<Manifest> {
    let path = run_dir.join("manifest.toml");
    let content = fs::read_to_string(&path)?;
    toml::from_str(&content).map_err(|e| OaieError::Io(std::io::Error::other(e)))
}

/// Fsync the parent directory of a path to ensure directory entries are durable.
/// Best-effort: logs errors but doesn't fail (some filesystems don't support this).
fn sync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        match File::open(parent) {
            Ok(dir) => {
                if let Err(e) = dir.sync_all() {
                    eprintln!("oaie-cas: sync_parent_dir {}: sync_all failed: {e}", parent.display());
                }
            }
            Err(e) => {
                eprintln!("oaie-cas: sync_parent_dir {}: open failed: {e}", parent.display());
            }
        }
    }
}

/// Check if a string is a valid 2-char hex prefix.
fn is_hex_prefix(s: &str) -> bool {
    s.len() == 2 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Format a byte count for human display.
pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Format milliseconds as a human-readable duration.
pub fn format_duration(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.3}s", ms as f64 / 1000.0)
    } else {
        let secs = ms / 1000;
        let mins = secs / 60;
        let rem = secs % 60;
        format!("{mins}m{rem}s")
    }
}
