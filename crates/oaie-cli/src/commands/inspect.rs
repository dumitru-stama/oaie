//! The `oaie inspect` subcommand — display a run's metadata, artifacts, and reports.
//!
//! Three display modes:
//! 1. Default: StreamingSummarizer → rich summary with directory grouping
//! 2. `--trace-full`: raw NDJSON line by line from CAS chunks
//! 3. `--trace-stats`: counters only (events, files, duration, chunks)

use std::path::Path;

use clap::Args;

use oaie_cas::store::{format_bytes, format_duration, read_manifest, CasStore};
use oaie_core::artifact::Hash;
use oaie_core::config::OaieStore;
use oaie_core::manifest::Manifest;
use oaie_db::OaieDb;
use oaie_observe::{
    summarize_events, verify_chain, ChainVerifyResult, ChunkedEventWriter, EventReader,
    StreamingSummarizer, TraceIndex,
};

use oaie_core::error::{OaieError, Result};

use super::load_store;
use crate::output;

/// Inspect a completed run's artifacts and metadata.
#[derive(Args, Debug)]
pub struct InspectCmd {
    /// Run ID, short prefix, or "last" for most recent
    pub run_id: String,
    /// Show raw NDJSON events (full trace dump)
    #[arg(long)]
    pub trace_full: bool,
    /// Show trace statistics only (counters, no details)
    #[arg(long)]
    pub trace_stats: bool,
}

impl InspectCmd {
    /// Resolve the run ID, load its DB record, and print metadata + artifacts.
    pub fn execute(&self) -> Result<()> {
        let store = load_store()?;
        let db = OaieDb::open(&store.db_path)?;
        let cas = CasStore::new(store.cas_dir.clone(), store.hash_algorithm);

        // Resolve "last" or prefix to a run record.
        let run = if self.run_id == "last" {
            db.get_latest_run()?
                .ok_or_else(|| OaieError::Other("no runs found".into()))?
        } else {
            db.get_run_by_prefix(&self.run_id)?
        };

        let artifacts = db.list_artifacts(&run.run_id)?;
        let run_dir = store.runs_dir.join(run.run_id.full());

        output::header(&format!("Run {}", run.run_id));
        output::field("Created", &run.created.to_rfc3339());
        output::field("Command", &output::shell_join(&run.command));
        output::field("Status", &run.status.to_string());

        if let Some(code) = run.exit_code {
            output::field("Exit code", &code.to_string());
        }
        if let Some(ms) = run.duration_ms {
            output::field("Duration", &format_duration(ms.max(0) as u64));
        }
        if let Some(ref msg) = run.error_message {
            output::field("Error", msg);
        }

        output::field("Isolation", &run.isolation);

        // Load manifest for policy info (reachable paths).
        let manifest = read_manifest(&run_dir).ok();

        // Show interactive mode if recorded in manifest.
        if let Some(ref m) = manifest {
            if m.isolation.interactive {
                output::field("Interactive", "yes (PTY)");
            }
        }

        // Show attestation info if signature.toml exists.
        let sig_path = run_dir.join("signature.toml");
        if let Ok(sig_content) = std::fs::read_to_string(&sig_path) {
            if let Ok(sig) = toml::from_str::<oaie_core::signing::SignatureInfo>(&sig_content) {
                let pub_short = if sig.public_key.len() >= 12 {
                    &sig.public_key[..12]
                } else {
                    &sig.public_key
                };
                output::field("Signed by", &format!("{} ({pub_short}..)", sig.signer_label));
            }
        }

        // Show network policy section for allowlist mode.
        if let Some(ref m) = manifest {
            if m.isolation.network_mode == "allowlist" {
                println!();
                output::header("Network Policy");
                output::field("Mode", "allowlist");
                if let Some(ref pol) = m.policy {
                    if let Some(ref rules) = pol.network_rules {
                        for rule in rules {
                            output::field(
                                "  allow",
                                &format!("{}:{}/{}", rule.target, rule.port, rule.protocol),
                            );
                        }
                    }
                }
            }
        }

        // Observation section — mode depends on flags.
        if self.trace_full {
            show_trace_full(&run_dir, &cas, manifest.as_ref());
        } else if self.trace_stats {
            show_trace_stats(&run_dir, &cas, manifest.as_ref());
        } else {
            show_trace_summary(&run_dir, &store, &cas, manifest.as_ref());
        }

        if !artifacts.is_empty() {
            output::header("Artifacts");
            for a in &artifacts {
                let hash_short = if a.hash.len() >= 6 {
                    &a.hash[..6]
                } else {
                    &a.hash
                };
                output::field(
                    &a.label,
                    &format!("{}..  ({})", hash_short, format_bytes(a.size.max(0) as u64)),
                );
            }
        }

        // CAS store statistics (Q.1.8).
        show_store_stats(&store);

        Ok(())
    }
}

/// Walk the CAS directory and print blob count + total size.
///
/// Warns if total size exceeds 1 GiB.
fn show_store_stats(store: &OaieStore) {
    let cas_dir = &store.cas_dir;
    if !cas_dir.exists() {
        return;
    }
    let mut count: u64 = 0;
    let mut total_size: u64 = 0;

    // Walk two-level prefix directories: cas/<byte0>/<byte1>/<hash>
    if let Ok(level0) = std::fs::read_dir(cas_dir) {
        for entry0 in level0.flatten() {
            if !entry0.path().is_dir() {
                continue;
            }
            if let Ok(level1) = std::fs::read_dir(entry0.path()) {
                for entry1 in level1.flatten() {
                    if !entry1.path().is_dir() {
                        continue;
                    }
                    if let Ok(blobs) = std::fs::read_dir(entry1.path()) {
                        for blob in blobs.flatten() {
                            if let Ok(meta) = blob.metadata() {
                                if meta.is_file() {
                                    count += 1;
                                    total_size += meta.len();
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    println!();
    output::header("Store");
    output::field("CAS objects", &count.to_string());
    output::field("CAS size", &format_bytes(total_size));
    if total_size > 1_073_741_824 {
        output::warn("CAS exceeds 1 GiB — consider running 'oaie clean'");
    }
}

/// Try to load a TraceIndex from the run directory or CAS.
fn load_trace_index(run_dir: &Path, cas: &CasStore, manifest: Option<&Manifest>) -> Option<TraceIndex> {
    // First try reading trace_index.json directly from the run dir.
    let index_path = run_dir.join("trace_index.json");
    if index_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&index_path) {
            if let Ok(index) = serde_json::from_str::<TraceIndex>(&content) {
                return Some(index);
            }
        }
    }

    // Fall back to reading from CAS via manifest's trace_index_hash.
    if let Some(trace) = manifest.and_then(|m| m.trace.as_ref()) {
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

/// Read events from the best available source: chunked CAS or legacy events.log.
fn read_all_events(
    run_dir: &Path,
    cas: &CasStore,
    manifest: Option<&Manifest>,
) -> Option<(Vec<oaie_observe::OaieEvent>, String)> {
    // Try chunked index first.
    if let Some(index) = load_trace_index(run_dir, cas, manifest) {
        if let Ok(events) = ChunkedEventWriter::read_events_from_index(cas, &index) {
            return Some((events, index.genesis_hash));
        }
    }

    // Fall back to legacy events.log.
    let events_path = run_dir.join("events.log");
    if events_path.exists() {
        if let Ok(mut reader) = EventReader::open(&events_path) {
            let genesis = reader.header().genesis_hash.clone();
            if let Ok(events) = reader.read_all() {
                return Some((events, genesis));
            }
        }
    }

    None
}

// ── Display Mode: Default (summary with directory grouping) ──

/// Display the observation/trace section as a rich summary.
fn show_trace_summary(run_dir: &Path, store: &OaieStore, cas: &CasStore, manifest: Option<&Manifest>) {
    show_reachable_section(manifest);

    let (events, genesis_hash) = match read_all_events(run_dir, cas, manifest) {
        Some(r) => r,
        None => {
            output::header("Observation");
            println!("  Tracing not enabled for this run. Use --trace=auto to observe syscalls.");
            return;
        }
    };

    let trace_info = manifest.and_then(|m| m.trace.as_ref());

    output::header("Observation");
    if let Some(ti) = trace_info {
        output::field("Trace backend", &ti.backend);
    }
    output::field("Events captured", &events.len().to_string());

    // Verify chain integrity.
    let verify_result = verify_chain(&events, &genesis_hash, store.hash_algorithm);
    match &verify_result {
        ChainVerifyResult::Valid { tip_hash, .. } => {
            let short_tip = if tip_hash.len() >= 12 {
                &tip_hash[..12]
            } else {
                tip_hash
            };
            output::field("Chain tip", short_tip);
        }
        ChainVerifyResult::Broken { event_index, .. } => {
            output::warn(&format!(
                "hash chain broken at event {event_index} — trace may have been tampered with"
            ));
        }
        ChainVerifyResult::Empty => {
            output::field("Chain", "(empty trace)");
        }
    }

    if let Some(ti) = trace_info {
        if ti.chunks > 1 {
            output::field("Chunks", &ti.chunks.to_string());
        }
    }

    // Summarize observations.
    let summary = summarize_events(&events);

    output::header("Observed Accesses");
    println!("  What the tool actually touched:");

    if summary.files_read.is_empty()
        && summary.files_written.is_empty()
        && summary.net_connects.is_empty()
        && summary.net_denied.is_empty()
    {
        println!("    (no file or network access observed)");
    } else {
        if !summary.files_read.is_empty() {
            // Use directory grouping when there are many files.
            let display = oaie_observe::group_by_directory(&summary.files_read, 15);
            println!("  Files read:");
            for entry in &display {
                match entry {
                    oaie_observe::DisplayEntry::File(f) => {
                        let times = if f.count == 1 { "time" } else { "times" };
                        output::field(
                            &format!("    {} [{}]", f.path, f.category),
                            &format!("({} {times})", f.count),
                        );
                    }
                    oaie_observe::DisplayEntry::Directory { path, file_count, total_accesses } => {
                        output::field(
                            &format!("    {path}/"),
                            &format!("({file_count} files, {total_accesses} accesses)"),
                        );
                    }
                }
            }
        }
        if !summary.files_written.is_empty() {
            println!("  Files written:");
            for entry in &summary.files_written {
                println!("    {}", entry.path);
            }
        }
        if !summary.file_access_denied.is_empty() {
            println!("  Access denied:");
            for entry in &summary.file_access_denied {
                let times = if entry.count == 1 { "attempt" } else { "attempts" };
                output::field(
                    &format!("    {}", entry.path),
                    &format!("({} {times})", entry.count),
                );
            }
        }
        if !summary.net_connects.is_empty() || !summary.net_denied.is_empty() {
            println!("  Network:");
            for entry in &summary.net_connects {
                output::field(&format!("    {}", entry.address), "connected");
            }
            for entry in &summary.net_denied {
                output::field(&format!("    {}", entry.address), "denied");
            }
        }
    }

    // io_uring hard warning.
    let io_uring_detected = summary
        .suspicious_activity
        .iter()
        .any(|s| s.category == oaie_observe::SuspiciousCategory::IoUringSetup);
    if io_uring_detected {
        output::header("WARNING: Incomplete Trace");
        output::warn("io_uring detected — ptrace cannot observe io_uring async operations.");
        output::warn("File/network access performed via io_uring is MISSING from this trace.");
        output::warn("The trace is INCOMPLETE. Use --trace=ebpf (v0.2) for full coverage.");
    }

    // Suspicious activity.
    if !summary.suspicious_activity.is_empty() {
        output::header("Suspicious Activity");
        for entry in &summary.suspicious_activity {
            let times = if entry.count == 1 { "time" } else { "times" };
            output::warn(&format!("{} ({} {times})", entry.category, entry.count));
            println!("    {}", entry.detail);
        }
    }

    // Process tree with exit codes.
    if !summary.process_tree.is_empty() {
        output::header("Process Tree");
        for proc in &summary.process_tree {
            let indent = "  ".repeat(proc.depth + 1);
            let exit_str = match proc.exit_code {
                Some(0) => String::new(),
                Some(code) => format!(" (exit {code})"),
                None => String::new(),
            };
            println!("{indent}[{}] {}{}", proc.pid, proc.command, exit_str);
        }
    }
}

// ── Display Mode: --trace-full (raw NDJSON) ──

/// Dump raw NDJSON events to stdout.
fn show_trace_full(run_dir: &Path, cas: &CasStore, manifest: Option<&Manifest>) {
    // Try chunked index first.
    if let Some(index) = load_trace_index(run_dir, cas, manifest) {
        for chunk_ref in &index.chunks {
            if let Ok(hash) = Hash::from_hex(&chunk_ref.hash) {
                let blob_path = cas.blob_path(&hash);
                if let Ok(content) = std::fs::read_to_string(blob_path) {
                    for (i, line) in content.lines().enumerate() {
                        // Skip header line in first chunk.
                        if chunk_ref.index == 0 && i == 0 && line.contains("format_version") {
                            continue;
                        }
                        println!("{line}");
                    }
                }
            }
        }
        return;
    }

    // Fall back to legacy events.log.
    let events_path = run_dir.join("events.log");
    if events_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&events_path) {
            for (i, line) in content.lines().enumerate() {
                // Skip header line.
                if i == 0 && line.contains("format_version") {
                    continue;
                }
                println!("{line}");
            }
        }
    } else {
        output::header("Observation");
        println!("  Tracing not enabled for this run.");
    }
}

// ── Display Mode: --trace-stats (counters only) ──

/// Show trace statistics counters.
fn show_trace_stats(run_dir: &Path, cas: &CasStore, manifest: Option<&Manifest>) {
    let (events, _genesis_hash) = match read_all_events(run_dir, cas, manifest) {
        Some(r) => r,
        None => {
            output::header("Trace Statistics");
            println!("  Tracing not enabled for this run.");
            return;
        }
    };

    let trace_info = manifest.and_then(|m| m.trace.as_ref());

    let mut summarizer = StreamingSummarizer::new();
    for event in &events {
        summarizer.ingest(event);
    }
    let summary = summarizer.finish();

    output::header("Trace Statistics");
    if let Some(ti) = trace_info {
        output::field("Backend", &ti.backend);
        output::field("Chunks", &ti.chunks.to_string());
        let short_tip = if ti.chain_tip.len() >= 12 {
            &ti.chain_tip[..12]
        } else {
            &ti.chain_tip
        };
        output::field("Chain tip", short_tip);
    }
    output::field("Total events", &summary.total_events.to_string());
    output::field("File events", &summary.total_file_events.to_string());
    output::field("Net events", &summary.total_net_events.to_string());
    output::field("Exec events", &summary.total_exec_events.to_string());
    output::field("Unique files read", &summary.unique_files_read.to_string());
    output::field("Unique files written", &summary.unique_files_written.to_string());
    if summary.trace_duration_ns > 0 {
        let duration_ms = summary.trace_duration_ns / 1_000_000;
        output::field("Trace duration", &format_duration(duration_ms));
    }
}

/// Show "Reachable Inputs" section from the manifest's policy auto-mounts.
fn show_reachable_section(manifest: Option<&Manifest>) {
    let policy = match manifest.and_then(|m| m.policy.as_ref()) {
        Some(p) => p,
        None => return,
    };

    if policy.auto_mounts.is_empty() {
        return;
    }

    output::header("Reachable Inputs");
    println!("  What the sandbox allowed access to:");

    for mount in &policy.auto_mounts {
        let mode = mount.mode.to_uppercase();
        output::field(
            &format!("    {mode}"),
            &mount.mount_dir.display().to_string(),
        );
    }
}
