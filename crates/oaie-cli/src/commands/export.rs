//! The `oaie export` subcommand — package a run into a self-contained `.tar.gz` archive.
//!
//! Produces a gzipped tar archive containing the manifest, a generated report,
//! an `artifacts.json` index, and all blob content from the CAS. This archive
//! can be shared with auditors or stored independently from the local OAIE store.

use std::path::PathBuf;

use clap::Args;

use oaie_cas::store::{format_bytes, read_manifest, CasStore};
use oaie_core::artifact::Hash;
use oaie_core::manifest::Manifest;
use oaie_db::OaieDb;
use oaie_observe::{summarize_events, ChunkedEventWriter, EventReader, TraceIndex};

use oaie_core::error::{OaieError, Result};

use super::load_store;
use crate::output;

/// Package a run into a self-contained `.tar.gz` archive for sharing.
#[derive(Args, Debug)]
pub struct ExportCmd {
    /// Run ID, short prefix, or "last" for most recent.
    pub run_id: String,

    /// Output path (default: `oaie-<short_id>.tar.gz`).
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

/// Entry in the `artifacts.json` index inside the archive.
#[derive(serde::Serialize)]
struct ArtifactEntry {
    /// Human-readable label: "stdout", "stderr", "output/result.txt".
    label: String,
    /// Classification: "stdout", "stderr", "output", "trace", "report", "manifest".
    artifact_type: String,
    /// Full hex hash identifying the blob in `blobs/`.
    hash: String,
    /// Blob size in bytes.
    size: i64,
}

impl ExportCmd {
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

        let short_id = run.run_id.short();
        let run_dir = store.runs_dir.join(run.run_id.full());

        // Determine output path.
        let out_path = self
            .output
            .clone()
            .unwrap_or_else(|| PathBuf::from(format!("oaie-{short_id}.tar.gz")));

        let manifest = read_manifest(&run_dir)?;
        let artifacts = db.list_artifacts(&run.run_id)?;

        // Archive prefix directory: "oaie-<short_id>/".
        let prefix = format!("oaie-{short_id}");

        // Create gzipped tar.
        let out_file = std::fs::File::create(&out_path)?;
        let gz = flate2::write::GzEncoder::new(out_file, flate2::Compression::default());
        let mut tar = tar::Builder::new(gz);

        // 1. manifest.toml — the human-readable run record.
        let manifest_path = run_dir.join("manifest.toml");
        let manifest_bytes = std::fs::read(&manifest_path)?;
        append_bytes(&mut tar, &format!("{prefix}/manifest.toml"), &manifest_bytes)?;

        // 1b. signature.toml — manifest signature sidecar (if present).
        let sig_path = run_dir.join("signature.toml");
        if sig_path.exists() {
            let sig_bytes = std::fs::read(&sig_path)?;
            append_bytes(&mut tar, &format!("{prefix}/signature.toml"), &sig_bytes)?;
        }

        // 2. REPORT.md — generated report.
        let report_content = generate_report(&run_dir, &cas, &manifest);
        append_bytes(&mut tar, &format!("{prefix}/REPORT.md"), report_content.as_bytes())?;

        // 3. Blobs — all artifact content from CAS, streamed to avoid OOM on large files.
        let mut blob_count = 0u32;
        let mut total_blob_bytes: u64 = 0;
        for ar in &artifacts {
            if let Ok(hash) = Hash::from_hex(&ar.hash) {
                if cas.exists(&hash) {
                    let blob_path = cas.blob_path(&hash);
                    let meta = std::fs::metadata(&blob_path)?;
                    let file = cas.open(&hash)?;
                    total_blob_bytes = total_blob_bytes.saturating_add(meta.len());
                    append_stream(
                        &mut tar,
                        &format!("{prefix}/blobs/{}", ar.hash),
                        file,
                        meta.len(),
                    )?;
                    blob_count += 1;
                }
            }
        }

        // 4. Trace blobs — include trace index and chunk blobs if present.
        let trace_blob_count = export_trace_blobs(&mut tar, &prefix, &run_dir, &cas, &manifest)?;

        // 5. artifacts.json — the index mapping labels to blob hashes.
        let entries: Vec<ArtifactEntry> = artifacts
            .iter()
            .map(|ar| ArtifactEntry {
                label: ar.label.clone(),
                artifact_type: ar.artifact_type.clone(),
                hash: ar.hash.clone(),
                size: ar.size,
            })
            .collect();
        let index_json = serde_json::to_string_pretty(&entries)
            .map_err(|e| OaieError::Io(std::io::Error::other(e)))?;
        append_bytes(&mut tar, &format!("{prefix}/artifacts.json"), index_json.as_bytes())?;

        // Finish the archive.
        let gz = tar.into_inner().map_err(OaieError::Io)?;
        gz.finish().map_err(OaieError::Io)?;

        // Print summary.
        let archive_size = std::fs::metadata(&out_path)?.len();
        let total_blobs = blob_count + trace_blob_count;

        println!();
        output::info(&format!("exported run {short_id}"));
        output::field("Artifacts", &total_blobs.to_string());
        output::field("Archive size", &format_bytes(archive_size));
        output::field("Output", &out_path.display().to_string());

        // Warn about large archives that may be slow to transfer.
        if archive_size > 100 * 1024 * 1024 {
            output::warn(&format!(
                "archive is {} — consider using --trace=off for smaller exports",
                format_bytes(archive_size)
            ));
        }
        println!();

        Ok(())
    }
}

/// Append raw bytes as a file entry in the tar archive.
fn append_bytes<W: std::io::Write>(
    tar: &mut tar::Builder<W>,
    path: &str,
    data: &[u8],
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );
    header.set_cksum();
    tar.append_data(&mut header, path, data)
        .map_err(OaieError::Io)
}

/// Stream a file into the tar archive without reading it entirely into memory.
fn append_stream<W: std::io::Write>(
    tar: &mut tar::Builder<W>,
    path: &str,
    mut reader: impl std::io::Read,
    size: u64,
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(size);
    header.set_mode(0o644);
    header.set_mtime(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );
    header.set_cksum();
    tar.append_data(&mut header, path, &mut reader)
        .map_err(OaieError::Io)
}

/// Generate a report for the archive (best-effort — returns empty string on failure).
fn generate_report(run_dir: &std::path::Path, cas: &CasStore, manifest: &Manifest) -> String {
    let trace_summary = load_trace_summary(run_dir, cas, manifest);
    oaie_report::generate_report(manifest, trace_summary.as_ref())
}

/// Load trace events and produce a TraceSummary, if tracing was enabled.
fn load_trace_summary(
    run_dir: &std::path::Path,
    cas: &CasStore,
    manifest: &Manifest,
) -> Option<oaie_observe::TraceSummary> {
    if let Some(index) = load_trace_index(run_dir, cas, manifest) {
        if let Ok(events) = ChunkedEventWriter::read_events_from_index(cas, &index) {
            return Some(summarize_events(&events));
        }
    }
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
    run_dir: &std::path::Path,
    cas: &CasStore,
    manifest: &Manifest,
) -> Option<TraceIndex> {
    let index_path = run_dir.join("trace_index.json");
    if index_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&index_path) {
            if let Ok(index) = serde_json::from_str::<TraceIndex>(&content) {
                return Some(index);
            }
        }
    }
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

/// Export trace index and chunk blobs into the archive. Returns the number of trace blobs added.
fn export_trace_blobs<W: std::io::Write>(
    tar: &mut tar::Builder<W>,
    prefix: &str,
    run_dir: &std::path::Path,
    cas: &CasStore,
    manifest: &Manifest,
) -> Result<u32> {
    let index = match load_trace_index(run_dir, cas, manifest) {
        Some(idx) => idx,
        None => return Ok(0),
    };

    let mut count = 0u32;

    // Export the trace index itself.
    let index_json = serde_json::to_string_pretty(&index)
        .map_err(|e| OaieError::Io(std::io::Error::other(e)))?;
    append_bytes(tar, &format!("{prefix}/blobs/trace_index.json"), index_json.as_bytes())?;
    count += 1;

    // Export each chunk blob (streamed to avoid OOM).
    for chunk in &index.chunks {
        if let Ok(hash) = Hash::from_hex(&chunk.hash) {
            if cas.exists(&hash) {
                let blob_path = cas.blob_path(&hash);
                let meta = std::fs::metadata(&blob_path)?;
                let file = cas.open(&hash)?;
                append_stream(tar, &format!("{prefix}/blobs/{}", chunk.hash), file, meta.len())?;
                count += 1;
            }
        }
    }

    Ok(count)
}
