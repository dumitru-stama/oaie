//! The `oaie cat` subcommand — dump an artifact's content to stdout.
//!
//! Resolves a run by ID/prefix/"last", looks up the named artifact in the DB,
//! and writes the raw CAS blob to stdout.

use std::io::{self, Write};

use clap::Args;

use oaie_cas::store::CasStore;
use oaie_core::artifact::Hash;
use oaie_core::error::{OaieError, Result};
use oaie_db::OaieDb;

use super::load_store;

/// Dump a run's artifact to stdout.
///
/// Usage: `oaie cat <run_id> <artifact>`
///
/// The artifact name matches the label stored in the DB:
/// stdout, stderr, manifest, report, trace_index.json, or any output file label.
#[derive(Args, Debug)]
pub struct CatCmd {
    /// Run ID, short prefix, or "last" for most recent.
    pub run_id: String,

    /// Artifact label: stdout, stderr, manifest, report, trace_index.json, etc.
    pub artifact: String,
}

impl CatCmd {
    pub fn execute(&self) -> Result<()> {
        let store = load_store()?;
        let db = OaieDb::open(&store.db_path)?;
        let cas = CasStore::new(store.cas_dir.clone(), store.hash_algorithm);

        // Resolve run.
        let run = if self.run_id == "last" {
            db.get_latest_run()?
                .ok_or_else(|| OaieError::Other("no runs found".into()))?
        } else {
            db.get_run_by_prefix(&self.run_id)?
        };

        // Find the artifact by label.
        let artifacts = db.list_artifacts(&run.run_id)?;
        let artifact = artifacts
            .iter()
            .find(|a| a.label == self.artifact)
            .ok_or_else(|| {
                let available: Vec<&str> = artifacts.iter().map(|a| a.label.as_str()).collect();
                OaieError::Other(format!(
                    "no artifact '{}' for run {}. available: {}",
                    self.artifact,
                    run.run_id.short(),
                    available.join(", ")
                ))
            })?;

        // Read blob and write to stdout.
        let hash = Hash::from_hex(&artifact.hash)?;
        let blob_path = cas.blob_path(&hash);
        let content = std::fs::read(&blob_path).map_err(|e| {
            OaieError::Other(format!("failed to read blob {}: {e}", hash.short()))
        })?;

        io::stdout().write_all(&content).map_err(|e| {
            OaieError::Other(format!("failed to write to stdout: {e}"))
        })?;

        Ok(())
    }
}
