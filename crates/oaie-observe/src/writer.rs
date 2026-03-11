//! Event log writer — writes NDJSON events to a file during a run.
//!
//! The writer maintains a hash chain, writes the stream header as the first
//! line, and flushes periodically to minimize data loss on crash.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::Instant;

use oaie_core::hash_algo::HashAlgorithm;
use oaie_core::run_id::RunId;

use crate::chain::EventChain;
use crate::event::{EventStreamHeader, OaieEvent};

/// Writes observation events to an NDJSON log file.
///
/// Usage:
/// 1. Create with `new()` — writes the header as the first line.
/// 2. Call `write_event()` for each event — sets timestamp, chains, writes.
/// 3. Call `finalize()` — flushes and returns the event count + chain tip.
pub struct EventWriter {
    /// Buffered writer for the events log file.
    file: BufWriter<File>,
    /// Hash chain state — each event links to the previous.
    chain: EventChain,
    /// Number of events written so far.
    count: u64,
    /// When this writer was created, for relative timestamps.
    start_time: Instant,
}

impl EventWriter {
    /// Create a new event writer, writing the stream header as the first line.
    ///
    /// The header includes the genesis hash so readers can verify the chain
    /// without needing to recompute it.
    pub fn new(path: &Path, run_id: &RunId, trace_backend: &str, algo: HashAlgorithm) -> std::io::Result<Self> {
        let mut file = BufWriter::new(File::create(path)?);
        let chain = EventChain::new(algo);

        let header = EventStreamHeader {
            format_version: 1,
            run_id: run_id.full(),
            created: chrono::Utc::now().to_rfc3339(),
            trace_backend: trace_backend.into(),
            genesis_hash: chain.tip_hash().to_string(),
        };

        // Header is metadata, not part of the hash chain.
        serde_json::to_writer(&mut file, &header)
            .map_err(std::io::Error::other)?;
        file.write_all(b"\n")?;

        Ok(Self {
            file,
            chain,
            count: 0,
            start_time: Instant::now(),
        })
    }

    /// Write an event to the log.
    ///
    /// If `ts_ns` is 0, it's set to the elapsed time since writer creation.
    /// The event's `hash_prev` is set by the chain. The exact serialized bytes
    /// are written to the file — callers must not re-serialize.
    pub fn write_event(&mut self, mut event: OaieEvent) -> std::io::Result<()> {
        // Auto-set timestamp if not provided.
        if event.ts_ns == 0 {
            event.ts_ns = self.start_time.elapsed().as_nanos() as u64;
        }

        // Save chain state before append so we can restore on write failure.
        // chain.append() advances the chain tip; if the subsequent write fails,
        // the chain would be permanently desynced without this save/restore.
        let prev_hash_backup = self.chain.tip_hash().to_string();
        let serialized = self.chain.append(&mut event);

        if let Err(e) = self.file.write_all(&serialized)
            .and_then(|_| self.file.write_all(b"\n"))
        {
            self.chain.restore_tip(prev_hash_backup);
            return Err(e);
        }

        self.count += 1;

        // Flush every 100 events to limit data loss on crash.
        if self.count.is_multiple_of(100) {
            self.file.flush()?;
        }

        Ok(())
    }

    /// Flush the buffer and return the final count + chain tip.
    pub fn finalize(mut self) -> std::io::Result<EventWriterResult> {
        self.file.flush()?;
        Ok(EventWriterResult {
            event_count: self.count,
            chain_tip: self.chain.tip_hash().to_string(),
        })
    }
}

/// Result returned by `EventWriter::finalize()`.
#[derive(Debug)]
pub struct EventWriterResult {
    /// Total number of events written to the log.
    pub event_count: u64,
    /// BLAKE3 hash of the last event — the chain tip for the manifest.
    pub chain_tip: String,
}
