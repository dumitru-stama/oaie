//! Store cleanup: prune old runs and remove unreferenced CAS blobs.
//!
//! Two phases:
//! 1. **Prune** (optional, `--older-than`): delete runs older than a threshold.
//! 2. **Sweep**: remove CAS blobs not referenced by any remaining run,
//!    subject to a minimum age to protect in-progress runs.

use std::collections::HashSet;
use std::fs::{self, File};
use std::time::{Duration, SystemTime};

use chrono::Utc;
use oaie_cas::store::{format_bytes, read_manifest, CasStore};
use oaie_core::artifact::Hash;
use oaie_core::config::OaieStore;
use oaie_core::error::{OaieError, Result};
use oaie_db::OaieDb;
use oaie_observe::TraceIndex;

/// RAII guard for the clean lock file. Dropped automatically when done.
struct CleanLock {
    _file: File,
}

impl CleanLock {
    /// Try to acquire an exclusive advisory lock on `{store_root}/gc.lock`.
    /// Returns `Err` if another clean/gc is already running.
    fn acquire(store: &OaieStore) -> Result<Self> {
        use std::os::unix::io::AsRawFd;
        let lock_path = store.root.join("gc.lock");
        let file = File::create(&lock_path).map_err(|e| {
            OaieError::Io(std::io::Error::other(format!("cannot create gc.lock: {e}")))
        })?;
        // SAFETY: file is a valid open fd from File::create; flock is signal-safe
        // and doesn't affect memory safety. LOCK_NB returns EWOULDBLOCK if held.
        let ret = unsafe {
            libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB)
        };
        if ret != 0 {
            return Err(OaieError::InvalidJobSpec(
                "cleanup already in progress (gc.lock held)".into(),
            ));
        }
        Ok(CleanLock { _file: file })
    }
}

/// Result of pruning old runs.
#[derive(Debug)]
pub struct PruneResult {
    /// Number of runs deleted.
    pub runs_deleted: u64,
    /// Number of runs retained.
    pub runs_retained: u64,
}

/// Result of sweeping unreferenced CAS blobs.
#[derive(Debug)]
pub struct SweepResult {
    /// Total blobs scanned in the CAS.
    pub blobs_scanned: u64,
    /// Blobs removed (or would be removed in dry-run).
    pub blobs_removed: u64,
    /// Bytes freed (or would be freed in dry-run).
    pub bytes_freed: u64,
    /// Blobs retained (referenced or too recent).
    pub blobs_retained: u64,
}

/// Result of a full cleanup operation (prune + sweep).
#[derive(Debug)]
pub struct CleanResult {
    /// Run pruning results, present only when `--older-than` was specified.
    pub prune: Option<PruneResult>,
    /// CAS blob sweep results.
    pub sweep: SweepResult,
}

// Keep the old name as an alias so existing tests compile without changes.
pub type GcResult = SweepResult;

/// Run the full cleanup: optionally prune old runs, then sweep orphaned blobs.
///
/// `older_than`: if `Some`, delete runs created before `now - older_than`.
/// `min_age`: don't remove blobs newer than this (protects in-progress runs).
/// `dry_run`: if true, report what would be done without doing it.
pub fn clean(
    store: &OaieStore,
    older_than: Option<Duration>,
    min_age: Duration,
    dry_run: bool,
) -> Result<CleanResult> {
    let _lock = CleanLock::acquire(store)?;

    let db = OaieDb::open(&store.db_path)?;

    // Phase 1: Prune old runs.
    let prune = if let Some(threshold) = older_than {
        Some(prune_runs(store, &db, threshold, dry_run)?)
    } else {
        None
    };

    // Phase 2: Sweep unreferenced CAS blobs.
    let cas = CasStore::new(store.cas_dir.clone(), store.hash_algorithm);
    let sweep = sweep_blobs(store, &db, &cas, min_age, dry_run)?;

    Ok(CleanResult { prune, sweep })
}

/// Backward-compatible entry point used by existing tests.
pub fn gc(store: &OaieStore, min_age: Duration, dry_run: bool) -> Result<GcResult> {
    let result = clean(store, None, min_age, dry_run)?;
    Ok(result.sweep)
}

/// Delete runs older than `threshold` from the database and filesystem.
fn prune_runs(
    store: &OaieStore,
    db: &OaieDb,
    threshold: Duration,
    dry_run: bool,
) -> Result<PruneResult> {
    let cutoff = Utc::now() - chrono::Duration::from_std(threshold)
        .map_err(|e| OaieError::Other(format!("duration conversion: {e}")))?;

    let runs = db.list_all_runs()?;
    let mut result = PruneResult {
        runs_deleted: 0,
        runs_retained: 0,
    };

    for run in &runs {
        if run.created < cutoff {
            if dry_run {
                eprintln!(
                    "  would delete run {} ({})",
                    run.run_id.short(),
                    run.created.format("%Y-%m-%d %H:%M"),
                );
            } else {
                db.delete_run(&run.run_id, &store.runs_dir)?;
            }
            result.runs_deleted += 1;
        } else {
            result.runs_retained += 1;
        }
    }

    Ok(result)
}

/// Collect all hashes referenced by remaining runs, then remove unreferenced blobs.
fn sweep_blobs(
    store: &OaieStore,
    db: &OaieDb,
    cas: &CasStore,
    min_age: Duration,
    dry_run: bool,
) -> Result<SweepResult> {
    // Collect all referenced hashes from every remaining run's manifest.
    let mut referenced: HashSet<String> = HashSet::new();
    let runs = db.list_all_runs()?;

    for run_meta in &runs {
        let run_dir = store.runs_dir.join(run_meta.run_id.full());
        let manifest = match read_manifest(&run_dir) {
            Ok(m) => m,
            Err(_) => continue,
        };

        for artifact in &manifest.artifacts {
            referenced.insert(artifact.hash.to_hex());
        }

        if let Some(ref trace) = manifest.trace {
            if let Some(ref index_hash_str) = trace.trace_index_hash {
                referenced.insert(index_hash_str.clone());

                if let Ok(index_hash) = Hash::from_hex(index_hash_str) {
                    let index_path = cas.blob_path(&index_hash);
                    if let Ok(index_bytes) = fs::read(&index_path) {
                        if let Ok(index) = serde_json::from_slice::<TraceIndex>(&index_bytes) {
                            for chunk in &index.chunks {
                                referenced.insert(chunk.hash.clone());
                            }
                        }
                    }
                }
            }
        }

        if let Some(ref mh) = run_meta.manifest_hash {
            referenced.insert(mh.clone());
        }
    }

    // Scan CAS and remove unreferenced blobs.
    let mut result = SweepResult {
        blobs_scanned: 0,
        blobs_removed: 0,
        bytes_freed: 0,
        blobs_retained: 0,
    };

    let now = SystemTime::now();
    let all_blobs = cas.list_all()?;

    for (hash, size) in &all_blobs {
        result.blobs_scanned += 1;
        let hex = hash.to_hex();

        if referenced.contains(&hex) {
            result.blobs_retained += 1;
            continue;
        }

        let blob_path = cas.blob_path(hash);
        // Use symlink_metadata (lstat) to avoid following symlinks — a blob
        // replaced with a symlink between the age check and remove_file could
        // point elsewhere. Also skip non-regular files.
        let age_ok = match fs::symlink_metadata(&blob_path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() {
                    // Not a regular file (symlink, dir, etc.) — skip.
                    result.blobs_retained += 1;
                    continue;
                }
                match metadata.modified() {
                    Ok(modified) => {
                        let age = now.duration_since(modified).unwrap_or(Duration::ZERO);
                        age >= min_age
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        };
        if !age_ok {
            result.blobs_retained += 1;
            continue;
        }

        if dry_run {
            eprintln!(
                "  would remove: {} ({} bytes)",
                &hex[..12],
                size
            );
            result.blobs_removed += 1;
            result.bytes_freed += size;
        } else {
            let blob_path = cas.blob_path(hash);
            if fs::set_permissions(
                &blob_path,
                std::os::unix::fs::PermissionsExt::from_mode(0o644),
            ).is_err() {
                result.blobs_retained += 1;
                continue;
            }
            if fs::remove_file(&blob_path).is_ok() {
                result.blobs_removed += 1;
                result.bytes_freed += size;
            } else {
                // Restore read-only permissions — don't leave the blob writable.
                let _ = fs::set_permissions(
                    &blob_path,
                    std::os::unix::fs::PermissionsExt::from_mode(0o444),
                );
                result.blobs_retained += 1;
            }
        }
    }

    Ok(result)
}

/// Parse a human-readable duration string like "7d", "12h", "30m".
pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return Err(OaieError::InvalidJobSpec("empty duration string".into()));
    }

    let (num_str, multiplier) = if let Some(num) = s.strip_suffix('d') {
        (num, 86400u64)
    } else if let Some(num) = s.strip_suffix('h') {
        (num, 3600u64)
    } else if let Some(num) = s.strip_suffix('m') {
        (num, 60u64)
    } else if let Some(num) = s.strip_suffix('s') {
        (num, 1u64)
    } else {
        (s, 86400u64) // Default unit is days.
    };

    let value: u64 = num_str
        .parse()
        .map_err(|_| OaieError::InvalidJobSpec(format!("invalid duration: {s}")))?;

    let secs = value.checked_mul(multiplier).ok_or_else(|| {
        OaieError::InvalidJobSpec(format!("duration overflow: {s}"))
    })?;
    Ok(Duration::from_secs(secs))
}

// Backward-compatible aliases so existing callers/tests keep working.
pub fn parse_gc_duration(s: &str) -> Result<Duration> {
    parse_duration(s)
}

/// Format bytes as human-readable (e.g. "14.2 MB").
pub fn humanize_bytes(bytes: u64) -> String {
    format_bytes(bytes)
}
