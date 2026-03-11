//! The `oaie diff` subcommand — compare two historical runs side-by-side.
//!
//! Compares metadata (command, exit code, duration, isolation) and artifact
//! hashes between two past runs. With `--trace`, also diffs observed file
//! and network accesses.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use clap::Args;

use oaie_cas::store::{format_duration, read_manifest, CasStore};
use oaie_core::artifact::{ArtifactRef, Hash};
use oaie_core::config::OaieStore;
use oaie_core::manifest::Manifest;
use oaie_db::OaieDb;
use oaie_observe::{
    summarize_events, ChunkedEventWriter, EventReader, TraceIndex, TraceSummary,
};

use oaie_core::error::{OaieError, Result};

use super::load_store;
use crate::output;

/// Compare two past runs side-by-side.
#[derive(Args, Debug)]
pub struct DiffCmd {
    /// First run ID (or prefix, or "last").
    pub run_a: String,

    /// Second run ID (or prefix, or "last").
    pub run_b: String,

    /// Also compare observed file/network access (requires traced runs).
    #[arg(long)]
    pub trace: bool,
}

/// Comparison result for a single artifact label.
enum ArtifactDiff {
    /// Same label exists in both runs with matching hashes.
    Identical { label: String },
    /// Same label exists in both runs with different hashes.
    Differs {
        label: String,
        hash_a: Hash,
        hash_b: Hash,
    },
    /// Label exists only in run A.
    OnlyInA { label: String },
    /// Label exists only in run B.
    OnlyInB { label: String },
}

impl DiffCmd {
    pub fn execute(&self) -> Result<()> {
        let store = load_store()?;
        let db = OaieDb::open(&store.db_path)?;
        let cas = CasStore::new(store.cas_dir.clone(), store.hash_algorithm);

        // Resolve both run IDs.
        let run_a = if self.run_a == "last" {
            db.get_latest_run()?
                .ok_or_else(|| OaieError::Other("no runs found".into()))?
        } else {
            db.get_run_by_prefix(&self.run_a)?
        };

        let run_b = if self.run_b == "last" {
            db.get_latest_run()?
                .ok_or_else(|| OaieError::Other("no runs found".into()))?
        } else {
            db.get_run_by_prefix(&self.run_b)?
        };

        // Reject comparing a run to itself (e.g. "oaie diff last last").
        if run_a.run_id.full() == run_b.run_id.full() {
            return Err(OaieError::InvalidJobSpec(
                "both runs resolve to the same ID; nothing to diff".into(),
            ));
        }

        // Load manifests.
        let dir_a = store.runs_dir.join(run_a.run_id.full());
        let dir_b = store.runs_dir.join(run_b.run_id.full());

        let manifest_a = read_manifest(&dir_a)?;
        let manifest_b = read_manifest(&dir_b)?;

        let id_a = run_a.run_id.short();
        let id_b = run_b.run_id.short();

        // Metadata comparison.
        output::header(&format!("Diff: {id_a} vs {id_b}"));

        let cmd_a = output::shell_join(&manifest_a.command);
        let cmd_b = output::shell_join(&manifest_b.command);
        print_side("Command", &cmd_a, &cmd_b);

        let exit_a = manifest_a
            .exit_code
            .map_or("–".into(), |c| c.to_string());
        let exit_b = manifest_b
            .exit_code
            .map_or("–".into(), |c| c.to_string());
        print_side("Exit code", &exit_a, &exit_b);

        print_side(
            "Duration",
            &format_duration(manifest_a.duration_ms),
            &format_duration(manifest_b.duration_ms),
        );

        let iso_a = manifest_a.isolation.level.to_string().to_lowercase();
        let iso_b = manifest_b.isolation.level.to_string().to_lowercase();
        print_side("Isolation", &iso_a, &iso_b);

        // Artifact comparison.
        let diffs = compare_artifacts(&manifest_a, &manifest_b);
        print_artifact_diffs(&diffs);

        // Trace comparison (optional).
        if self.trace {
            print_trace_diff(&dir_a, &dir_b, &store, &cas, &manifest_a, &manifest_b, &id_a, &id_b);
        }

        println!();
        Ok(())
    }
}

/// Print a side-by-side metadata field.
fn print_side(key: &str, val_a: &str, val_b: &str) {
    if val_a == val_b {
        output::field(key, val_a);
    } else {
        let label = format!("{key}:");
        println!("  {label:<16}{val_a}  |  {val_b}");
    }
}

/// Compare artifacts between two manifests by label.
fn compare_artifacts(a: &Manifest, b: &Manifest) -> Vec<ArtifactDiff> {
    let map_a: HashMap<&str, &ArtifactRef> = a
        .artifacts
        .iter()
        .map(|ar| (ar.label.as_str(), ar))
        .collect();
    let map_b: HashMap<&str, &ArtifactRef> = b
        .artifacts
        .iter()
        .map(|ar| (ar.label.as_str(), ar))
        .collect();

    let mut diffs = Vec::new();

    // All labels from A.
    for ar in &a.artifacts {
        match map_b.get(ar.label.as_str()) {
            Some(br) => {
                if ar.hash == br.hash {
                    diffs.push(ArtifactDiff::Identical {
                        label: ar.label.clone(),
                    });
                } else {
                    diffs.push(ArtifactDiff::Differs {
                        label: ar.label.clone(),
                        hash_a: ar.hash.clone(),
                        hash_b: br.hash.clone(),
                    });
                }
            }
            None => {
                diffs.push(ArtifactDiff::OnlyInA {
                    label: ar.label.clone(),
                });
            }
        }
    }

    // Labels only in B.
    for br in &b.artifacts {
        if !map_a.contains_key(br.label.as_str()) {
            diffs.push(ArtifactDiff::OnlyInB {
                label: br.label.clone(),
            });
        }
    }

    diffs
}

/// Print the artifact diff table.
fn print_artifact_diffs(diffs: &[ArtifactDiff]) {
    println!();
    output::header("Artifacts");

    let mut identical = 0u32;
    let mut differ = 0u32;
    let mut only_one = 0u32;

    for d in diffs {
        match d {
            ArtifactDiff::Identical { label } => {
                println!("  {} {:<20} -- identical", output::pass_icon(), label);
                identical += 1;
            }
            ArtifactDiff::Differs {
                label,
                hash_a,
                hash_b,
            } => {
                println!(
                    "  {} {:<20} -- differs ({} vs {})",
                    output::fail_icon(),
                    label,
                    hash_a.short(),
                    hash_b.short()
                );
                differ += 1;
            }
            ArtifactDiff::OnlyInA { label } => {
                println!(
                    "  {} {:<20} -- only in first run",
                    output::skip_icon(),
                    label
                );
                only_one += 1;
            }
            ArtifactDiff::OnlyInB { label } => {
                println!(
                    "  {} {:<20} -- only in second run",
                    output::skip_icon(),
                    label
                );
                only_one += 1;
            }
        }
    }

    let total = identical + differ + only_one;
    println!();
    println!(
        "  {total} compared: {identical} identical, {differ} differ, {only_one} only in one run"
    );
}

/// Try to load a TraceIndex from a run directory or CAS (same logic as inspect.rs).
fn load_trace_index(
    run_dir: &Path,
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

/// Read all events for a run from the best available source.
fn read_events(
    run_dir: &Path,
    cas: &CasStore,
    manifest: &Manifest,
) -> Option<Vec<oaie_observe::OaieEvent>> {
    if let Some(index) = load_trace_index(run_dir, cas, manifest) {
        if let Ok(events) = ChunkedEventWriter::read_events_from_index(cas, &index) {
            return Some(events);
        }
    }
    let events_path = run_dir.join("events.log");
    if events_path.exists() {
        if let Ok(mut reader) = EventReader::open(&events_path) {
            if let Ok(events) = reader.read_all() {
                return Some(events);
            }
        }
    }
    None
}

/// Print trace diff section: files and network that differ between runs.
#[allow(clippy::too_many_arguments)]
fn print_trace_diff(
    dir_a: &Path,
    dir_b: &Path,
    _store: &OaieStore,
    cas: &CasStore,
    manifest_a: &Manifest,
    manifest_b: &Manifest,
    id_a: &str,
    id_b: &str,
) {
    let events_a = read_events(dir_a, cas, manifest_a);
    let events_b = read_events(dir_b, cas, manifest_b);

    println!();

    match (&events_a, &events_b) {
        (None, None) => {
            output::header("Trace Diff");
            println!("  Neither run has trace data.");
            return;
        }
        (None, _) => {
            output::header("Trace Diff");
            println!("  Run {id_a} has no trace data.");
            return;
        }
        (_, None) => {
            output::header("Trace Diff");
            println!("  Run {id_b} has no trace data.");
            return;
        }
        _ => {}
    }

    let sum_a = summarize_events(events_a.as_ref().unwrap());
    let sum_b = summarize_events(events_b.as_ref().unwrap());

    print_path_diff(
        "Files Read",
        &file_path_set(&sum_a.files_read),
        &file_path_set(&sum_b.files_read),
        id_a,
        id_b,
    );

    print_path_diff(
        "Files Written",
        &file_path_set(&sum_a.files_written),
        &file_path_set(&sum_b.files_written),
        id_a,
        id_b,
    );

    let net_a: BTreeSet<&str> = sum_a.net_connects.iter().map(|n| n.address.as_str()).collect();
    let net_b: BTreeSet<&str> = sum_b.net_connects.iter().map(|n| n.address.as_str()).collect();
    print_path_diff("Network", &net_a, &net_b, id_a, id_b);

    let dns_a: BTreeSet<&str> = sum_a.dns_queries.iter().map(|d| d.name.as_str()).collect();
    let dns_b: BTreeSet<&str> = sum_b.dns_queries.iter().map(|d| d.name.as_str()).collect();
    print_path_diff("DNS queries", &dns_a, &dns_b, id_a, id_b);

    print_suspicious_diff(&sum_a, &sum_b, id_a, id_b);
}

/// Extract file paths from a FileAccessEntry slice into a BTreeSet.
fn file_path_set(entries: &[oaie_observe::FileAccessEntry]) -> BTreeSet<&str> {
    entries.iter().map(|e| e.path.as_str()).collect()
}

/// Print a set-difference section for paths/addresses.
fn print_path_diff(
    section: &str,
    set_a: &BTreeSet<&str>,
    set_b: &BTreeSet<&str>,
    id_a: &str,
    id_b: &str,
) {
    let only_a: Vec<&&str> = set_a.difference(set_b).collect();
    let only_b: Vec<&&str> = set_b.difference(set_a).collect();

    if only_a.is_empty() && only_b.is_empty() {
        return;
    }

    output::header(&format!("{section} Diff"));

    if !only_a.is_empty() {
        println!("  Only in {id_a}:");
        for p in &only_a {
            println!("    {}", p);
        }
    }
    if !only_b.is_empty() {
        println!("  Only in {id_b}:");
        for p in &only_b {
            println!("    {}", p);
        }
    }
}

/// Print suspicious activity differences between two trace summaries.
fn print_suspicious_diff(
    sum_a: &TraceSummary,
    sum_b: &TraceSummary,
    id_a: &str,
    id_b: &str,
) {
    if sum_a.suspicious_activity.is_empty() && sum_b.suspicious_activity.is_empty() {
        return;
    }

    let cats_a: BTreeSet<String> = sum_a
        .suspicious_activity
        .iter()
        .map(|s| format!("{}", s.category))
        .collect();
    let cats_b: BTreeSet<String> = sum_b
        .suspicious_activity
        .iter()
        .map(|s| format!("{}", s.category))
        .collect();

    if cats_a == cats_b {
        return;
    }

    output::header("Suspicious Activity Diff");

    let only_a: Vec<&String> = cats_a.difference(&cats_b).collect();
    let only_b: Vec<&String> = cats_b.difference(&cats_a).collect();

    if !only_a.is_empty() {
        println!("  Only in {id_a}:");
        for cat in &only_a {
            println!("    {cat}");
        }
    }
    if !only_b.is_empty() {
        println!("  Only in {id_b}:");
        for cat in &only_b {
            println!("    {cat}");
        }
    }
}
