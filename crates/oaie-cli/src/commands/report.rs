//! The `oaie report` subcommand — print the stored REPORT.md for a past run.
//!
//! By default reads the report blob from CAS. With `--regenerate`, rebuilds
//! the report from the manifest and trace events.

use std::io::Read;

use clap::Args;

use oaie_cas::store::{read_manifest, CasStore};
use oaie_core::artifact::Hash;
use oaie_db::OaieDb;
use oaie_observe::{summarize_events, ChunkedEventWriter, EventReader, TraceIndex};

use oaie_core::error::{OaieError, Result};

use super::load_store;

/// Print the REPORT.md for a completed run.
#[derive(Args, Debug)]
pub struct ReportCmd {
    /// Run ID, short prefix, or "last" for most recent.
    pub run_id: String,

    /// Regenerate the report from manifest and trace instead of reading the stored blob.
    #[arg(long)]
    pub regenerate: bool,
}

impl ReportCmd {
    pub fn execute(&self) -> Result<()> {
        let store = load_store()?;
        let db = OaieDb::open(&store.db_path)?;
        let cas = CasStore::new(store.cas_dir.clone(), store.hash_algorithm);

        // Resolve run ID.
        let run = if self.run_id == "last" {
            db.get_latest_run()?
                .ok_or_else(|| OaieError::Other("no runs found".into()))?
        } else {
            db.get_run_by_prefix(&self.run_id)?
        };

        let run_dir = store.runs_dir.join(run.run_id.full());

        if self.regenerate {
            self.regenerate_report(&run_dir, &cas)?;
        } else {
            self.print_stored_report(&db, &run, &cas)?;
        }

        Ok(())
    }

    /// Read the stored report blob from CAS and print it.
    fn print_stored_report(
        &self,
        db: &OaieDb,
        run: &oaie_db::RunRecord,
        cas: &CasStore,
    ) -> Result<()> {
        let artifacts = db.list_artifacts(&run.run_id)?;

        // Find the report artifact.
        let report_artifact = artifacts
            .iter()
            .find(|a| a.artifact_type == "report")
            .ok_or_else(|| OaieError::Other("no report artifact found for this run".into()))?;

        let hash = Hash::from_hex(&report_artifact.hash)?;
        let mut file = cas.open(&hash)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;

        print!("{content}");
        Ok(())
    }

    /// Regenerate the report from manifest + trace events and print it.
    fn regenerate_report(
        &self,
        run_dir: &std::path::Path,
        cas: &CasStore,
    ) -> Result<()> {
        let manifest = read_manifest(run_dir)?;

        // Try to load trace events for the observation summary.
        let trace_summary = self.load_trace_summary(run_dir, cas, &manifest);

        let report = oaie_report::generate_report(&manifest, trace_summary.as_ref());
        print!("{report}");
        Ok(())
    }

    /// Load trace events and produce a TraceSummary, if tracing was enabled.
    fn load_trace_summary(
        &self,
        run_dir: &std::path::Path,
        cas: &CasStore,
        manifest: &oaie_core::manifest::Manifest,
    ) -> Option<oaie_observe::TraceSummary> {
        // Try chunked index first.
        if let Some(index) = self.load_trace_index(run_dir, cas, manifest) {
            if let Ok(events) = ChunkedEventWriter::read_events_from_index(cas, &index) {
                return Some(summarize_events(&events));
            }
        }

        // Fall back to legacy events.log.
        let events_path = run_dir.join("events.log");
        if events_path.exists() {
            if let Ok(mut reader) = EventReader::open(&events_path) {
                if let Ok(events) = reader.read_all() {
                    return Some(summarize_events(&events));
                }
            }
        }

        None
    }

    /// Try to load a TraceIndex from the run directory or CAS.
    fn load_trace_index(
        &self,
        run_dir: &std::path::Path,
        cas: &CasStore,
        manifest: &oaie_core::manifest::Manifest,
    ) -> Option<TraceIndex> {
        // Direct file first.
        let index_path = run_dir.join("trace_index.json");
        if index_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&index_path) {
                if let Ok(index) = serde_json::from_str::<TraceIndex>(&content) {
                    return Some(index);
                }
            }
        }

        // Fall back to CAS via manifest.
        if let Some(trace) = manifest.trace.as_ref() {
            if let Some(ref hash_str) = trace.trace_index_hash {
                if let Ok(hash) = Hash::from_hex(hash_str) {
                    let blob_path = cas.blob_path(&hash);
                    if let Ok(content) = std::fs::read_to_string(blob_path) {
                        if let Ok(index) = serde_json::from_str::<TraceIndex>(&content) {
                            return Some(index);
                        }
                    }
                }
            }
        }

        None
    }
}
