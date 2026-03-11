//! Run directory management.
//!
//! Each run gets its own directory under `~/.oaie/runs/<uuid>/` containing the
//! manifest, captured stdout/stderr, events log, and generated report.
//! [`RunDir`] provides creation, lookup (by ID, prefix, or "last"), and path helpers.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{OaieError, Result};
use crate::run_id::RunId;

/// A run directory under `~/.oaie/runs/<run_id>/`.
///
/// Contains the manifest, stdout/stderr captures, events log,
/// and generated report for a single execution run.
#[derive(Clone, Debug)]
pub struct RunDir {
    /// Filesystem path to this run directory.
    pub path: PathBuf,
    /// The run's unique identifier (UUIDv7).
    pub run_id: RunId,
}

impl RunDir {
    /// Create a new run directory.
    /// The directory name is the full UUID of the run.
    pub fn create(runs_dir: &Path, run_id: &RunId) -> Result<Self> {
        let path = runs_dir.join(run_id.full());
        fs::create_dir_all(&path)?;
        Ok(Self {
            path,
            run_id: run_id.clone(),
        })
    }

    /// Open an existing run directory by run ID.
    /// Returns an error if the directory doesn't exist.
    pub fn open(runs_dir: &Path, run_id: &RunId) -> Result<Self> {
        let path = runs_dir.join(run_id.full());
        if !path.is_dir() {
            return Err(OaieError::RunNotFound(run_id.full()));
        }
        Ok(Self {
            path,
            run_id: run_id.clone(),
        })
    }

    /// Open the most recent run directory (by name sort, since UUIDv7 is time-ordered).
    /// Returns `None` if no runs exist.
    pub fn open_latest(runs_dir: &Path) -> Result<Option<Self>> {
        if !runs_dir.is_dir() {
            return Ok(None);
        }
        // Collect only directories whose names parse as valid UUIDs.
        // Stray directories (e.g. ".tmp", editor backups) are silently skipped.
        let valid_runs: Vec<(RunId, PathBuf)> = fs::read_dir(runs_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
            .filter_map(|e| {
                let name = e.file_name();
                let name_str = name.to_string_lossy();
                name_str.parse::<RunId>().ok().map(|id| (id, e.path()))
            })
            .collect();
        if valid_runs.is_empty() {
            return Ok(None);
        }
        // UUIDv7 sorts chronologically as strings, so lexicographic max = most recent.
        // Safety: we checked `valid_runs.is_empty()` above, so this cannot be None.
        let (run_id, path) = valid_runs
            .into_iter()
            .max_by(|a, b| a.0.full().cmp(&b.0.full()))
            .ok_or_else(|| OaieError::RunNotFound("no runs found".into()))?;
        Ok(Some(Self { path, run_id }))
    }

    /// Resolve a user-provided string to a RunId.
    ///
    /// Accepts:
    /// - `"last"` — resolves to the most recent run
    /// - A full UUID string — parsed directly
    /// - A short hex prefix — scans run directories for a unique match
    ///
    /// Returns an error if no match or multiple matches (ambiguous prefix).
    pub fn resolve_run_id(runs_dir: &Path, input: &str) -> Result<RunId> {
        if input == "last" {
            return Self::open_latest(runs_dir)?
                .map(|rd| rd.run_id)
                .ok_or_else(|| OaieError::RunNotFound("no runs found".into()));
        }

        // Try full UUID parse first.
        if let Ok(id) = input.parse::<RunId>() {
            let path = runs_dir.join(id.full());
            if path.is_dir() {
                return Ok(id);
            }
            return Err(OaieError::RunNotFound(input.to_string()));
        }

        // Reject empty prefixes — they would match every run.
        if input.is_empty() {
            return Err(OaieError::InvalidRunId("empty run ID prefix".into()));
        }

        // Prefix search: scan run directories for matching names.
        if !runs_dir.is_dir() {
            return Err(OaieError::RunNotFound(input.to_string()));
        }
        // Strip hyphens from user input so "019-0ab" matches "0190abcd-...".
        let input_normalized = input.replace('-', "");
        let mut matches = Vec::new();
        for entry in fs::read_dir(runs_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            // Compare against the simple (no-hyphen) hex representation.
            let no_hyphens = name_str.replace('-', "");
            if no_hyphens.starts_with(&input_normalized) {
                if let Ok(id) = name_str.parse::<RunId>() {
                    matches.push(id);
                }
            }
        }

        match matches.len() {
            0 => Err(OaieError::RunNotFound(input.to_string())),
            1 => Ok(matches.into_iter().next()
                .ok_or_else(|| OaieError::InvalidRunId(input.to_string()))?),
            _ => {
                let ids: Vec<String> = matches.iter().map(|id| id.short()).collect();
                Err(OaieError::InvalidRunId(format!(
                    "ambiguous prefix '{input}', matches: {}",
                    ids.join(", ")
                )))
            }
        }
    }

    // --- Path helpers for standard files within a run directory ---

    /// Path to the TOML manifest.
    pub fn manifest_path(&self) -> PathBuf {
        self.path.join("manifest.toml")
    }

    /// Path to the generated REPORT.md.
    pub fn report_path(&self) -> PathBuf {
        self.path.join("REPORT.md")
    }

    /// Path to the events log (syscall observations, etc.).
    pub fn events_path(&self) -> PathBuf {
        self.path.join("events.log")
    }

    /// Path to the captured stdout.
    pub fn stdout_path(&self) -> PathBuf {
        self.path.join("stdout")
    }

    /// Path to the captured stderr.
    pub fn stderr_path(&self) -> PathBuf {
        self.path.join("stderr")
    }

    /// Path to the Ed25519 signature sidecar file.
    pub fn signature_path(&self) -> PathBuf {
        self.path.join("signature.toml")
    }
}
