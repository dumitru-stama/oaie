//! Chunked event writer — writes events into CAS-stored chunks for scalable traces.
//!
//! Instead of a single `events.log` file, events are written to temporary chunk
//! files that are rotated at a configurable size threshold. Each chunk is stored
//! in CAS via `cas.store_file()`, and a `TraceIndex` is written at finalization
//! that lists all chunks in order with metadata.
//!
//! The hash chain spans chunk boundaries — a single [`EventChain`] runs across
//! all chunks, so the chain tip in the index covers the entire trace.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use oaie_cas::store::CasStore;
use oaie_core::artifact::Hash;
use oaie_core::hash_algo::HashAlgorithm;

use crate::chain::{self, EventChain};
use crate::event::{EventStreamHeader, OaieEvent};

/// Default chunk rotation threshold: 1 MB.
const DEFAULT_CHUNK_THRESHOLD: u64 = 1024 * 1024;

/// Per-chunk metadata stored in the trace index.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkRef {
    /// Zero-based chunk index.
    pub index: u32,
    /// BLAKE3 hash of the chunk file stored in CAS.
    pub hash: String,
    /// Size of the chunk file in bytes.
    pub size: u64,
    /// Number of events in this chunk.
    pub events: u64,
    /// Nanosecond timestamp of the first event in this chunk.
    pub first_ts_ns: u64,
    /// Nanosecond timestamp of the last event in this chunk.
    pub last_ts_ns: u64,
}

/// Index file listing all chunks in a trace, stored in CAS at finalization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceIndex {
    /// Format version (starts at 1).
    pub format_version: u32,
    /// Run ID this trace belongs to.
    pub run_id: String,
    /// Trace backend name ("ptrace", "ebpf", etc.).
    pub trace_backend: String,
    /// Total events across all chunks.
    pub total_events: u64,
    /// Number of chunks.
    pub total_chunks: u32,
    /// BLAKE3 hash of the final event — the chain tip for the manifest.
    pub chain_tip: String,
    /// Genesis hash for chain verification.
    pub genesis_hash: String,
    /// Ordered list of chunk references.
    pub chunks: Vec<ChunkRef>,
}

/// Writes observation events into CAS-chunked storage.
///
/// Usage:
/// 1. Create with `new()` — opens the first chunk temp file.
/// 2. Call `write_event()` for each event — rotates chunks at the threshold.
/// 3. Call `finalize()` — stores the last chunk + writes `trace_index.json`.
pub struct ChunkedEventWriter {
    /// CAS store for persisting completed chunks.
    cas: CasStore,
    /// Directory for temporary chunk files (the run directory).
    work_dir: PathBuf,
    /// Hash algorithm used for the chain and trace index.
    algo: HashAlgorithm,
    /// Hash chain spanning all chunks.
    chain: EventChain,
    /// Current chunk's buffered writer.
    current_file: BufWriter<File>,
    /// Path to the current chunk's temp file.
    current_path: PathBuf,
    /// Bytes written to the current chunk so far.
    current_bytes: u64,
    /// Events written to the current chunk so far.
    current_events: u64,
    /// First event timestamp in the current chunk (0 if no events yet).
    current_first_ts: u64,
    /// Last event timestamp in the current chunk.
    current_last_ts: u64,
    /// Size threshold for chunk rotation.
    chunk_threshold: u64,
    /// Completed chunk references.
    completed_chunks: Vec<ChunkRef>,
    /// Total events written across all chunks.
    total_events: u64,
    /// Monotonic start time for relative timestamp calculation.
    start_time: Instant,
}

impl ChunkedEventWriter {
    /// Create a new chunked event writer.
    ///
    /// Writes the stream header to the first chunk file. The header is metadata,
    /// not part of the hash chain.
    pub fn new(
        work_dir: &Path,
        cas: CasStore,
        run_id: &str,
        trace_backend: &str,
        algo: HashAlgorithm,
    ) -> std::io::Result<Self> {
        Self::with_threshold(work_dir, cas, run_id, trace_backend, DEFAULT_CHUNK_THRESHOLD, algo)
    }

    /// Create with a custom chunk size threshold (for testing).
    pub fn with_threshold(
        work_dir: &Path,
        cas: CasStore,
        run_id: &str,
        trace_backend: &str,
        chunk_threshold: u64,
        algo: HashAlgorithm,
    ) -> std::io::Result<Self> {
        let chunk_path = work_dir.join("chunk_0.tmp");
        let mut file = BufWriter::new(File::create(&chunk_path)?);
        let chain = EventChain::new(algo);

        let header = EventStreamHeader {
            format_version: 1,
            run_id: run_id.into(),
            created: chrono::Utc::now().to_rfc3339(),
            trace_backend: trace_backend.into(),
            genesis_hash: chain.tip_hash().to_string(),
        };

        // Serialize once and reuse for both writing and size accounting
        // to avoid fragile double-serialization.
        let header_bytes = serde_json::to_vec(&header)
            .map_err(std::io::Error::other)?;
        file.write_all(&header_bytes)?;
        file.write_all(b"\n")?;

        let header_size = header_bytes.len() as u64 + 1; // +1 for newline

        Ok(Self {
            cas,
            work_dir: work_dir.to_path_buf(),
            algo,
            chain,
            current_file: file,
            current_path: chunk_path,
            current_bytes: header_size,
            current_events: 0,
            current_first_ts: 0,
            current_last_ts: 0,
            chunk_threshold,
            completed_chunks: Vec::new(),
            total_events: 0,
            start_time: Instant::now(),
        })
    }

    /// Write an event to the current chunk.
    ///
    /// If `ts_ns` is 0, it's set to elapsed time since writer creation.
    /// Rotates to a new chunk if the current one exceeds the threshold.
    pub fn write_event(&mut self, mut event: OaieEvent) -> std::io::Result<()> {
        // Auto-set timestamp if not provided.
        if event.ts_ns == 0 {
            event.ts_ns = self.start_time.elapsed().as_nanos() as u64;
        }

        let ts = event.ts_ns;

        // Save chain state before append so we can restore on write failure.
        // chain.append() advances the chain tip; if the subsequent write fails,
        // the chain would be permanently desynced without this save/restore.
        let prev_hash_backup = self.chain.tip_hash().to_string();
        let serialized = self.chain.append(&mut event);
        let line_size = serialized.len() as u64 + 1; // +1 for newline

        // Check if we should rotate before writing (but always write at least one
        // event per chunk — don't rotate on the very first event).
        if self.current_events > 0
            && self.current_bytes + line_size > self.chunk_threshold
        {
            if let Err(e) = self.rotate_chunk() {
                self.chain.restore_tip(prev_hash_backup);
                return Err(e);
            }
        }

        if let Err(e) = self.current_file.write_all(&serialized)
            .and_then(|_| self.current_file.write_all(b"\n"))
        {
            self.chain.restore_tip(prev_hash_backup);
            return Err(e);
        }

        self.current_bytes += line_size;
        self.current_events += 1;
        self.total_events += 1;

        if self.current_events == 1 {
            self.current_first_ts = ts;
        }
        self.current_last_ts = ts;

        // Flush every 100 events to limit data loss on crash.
        if self.total_events.is_multiple_of(100) {
            self.current_file.flush()?;
        }

        Ok(())
    }

    /// Finalize the trace: store the last chunk and write the trace index.
    ///
    /// Returns the `TraceIndex` containing all chunk metadata and the chain tip.
    pub fn finalize(mut self, run_id: &str, trace_backend: &str) -> std::io::Result<TraceIndex> {
        // Store the current (last) chunk.
        self.store_current_chunk()?;

        let index = TraceIndex {
            format_version: 1,
            run_id: run_id.into(),
            trace_backend: trace_backend.into(),
            total_events: self.total_events,
            total_chunks: self.completed_chunks.len() as u32,
            chain_tip: self.chain.tip_hash().to_string(),
            genesis_hash: chain::genesis_hash(self.algo),
            chunks: self.completed_chunks,
        };

        // Write trace_index.json to the work directory.
        let index_path = self.work_dir.join("trace_index.json");
        let index_json = serde_json::to_string_pretty(&index)
            .map_err(std::io::Error::other)?;
        fs::write(&index_path, &index_json)?;

        Ok(index)
    }

    /// Rotate the current chunk: flush, store in CAS, open a new chunk file.
    ///
    /// If the new chunk file cannot be opened, the stored chunk is popped from
    /// `completed_chunks` so that the caller's chain restore produces a consistent
    /// state (chain tip matches the last event in the current chunk).
    fn rotate_chunk(&mut self) -> std::io::Result<()> {
        // Create the new chunk file BEFORE storing the old one in CAS.
        // This avoids an inconsistent state where the old chunk is stored
        // and deleted but the new file can't be created — which would leave
        // the writer with a defunct current_file and no temp file on disk.
        let next_index = (self.completed_chunks.len() + 1) as u32;
        let next_path = self.work_dir.join(format!("chunk_{next_index}.tmp"));
        let file = BufWriter::new(File::create(&next_path)?);

        // Now store the current chunk. If this fails, clean up the new file.
        if let Err(e) = self.store_current_chunk() {
            let _ = fs::remove_file(&next_path);
            return Err(e);
        }

        self.current_file = file;
        self.current_path = next_path;
        self.current_bytes = 0;
        self.current_events = 0;
        self.current_first_ts = 0;
        self.current_last_ts = 0;

        Ok(())
    }

    /// Flush and store the current chunk in CAS, then remove the temp file.
    fn store_current_chunk(&mut self) -> std::io::Result<()> {
        self.current_file.flush()?;

        // Store in CAS.
        let (hash, size) = self.cas.store_file(&self.current_path)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        self.completed_chunks.push(ChunkRef {
            index: self.completed_chunks.len() as u32,
            hash: hash.to_hex(),
            size,
            events: self.current_events,
            first_ts_ns: self.current_first_ts,
            last_ts_ns: self.current_last_ts,
        });

        // Remove the temp file — it's now in CAS.
        let _ = fs::remove_file(&self.current_path);

        Ok(())
    }

    /// Read events back from CAS chunks for summarization.
    ///
    /// Yields events in order across all stored chunks. The first chunk
    /// includes a header line that is skipped.
    pub fn read_events_from_index(
        cas: &CasStore,
        index: &TraceIndex,
    ) -> std::io::Result<Vec<OaieEvent>> {
        // Cap pre-allocation to prevent OOM from a corrupt/malicious trace index.
        let capacity = (index.total_events as usize).min(1_000_000);
        let mut all_events = Vec::with_capacity(capacity);

        for (i, chunk_ref) in index.chunks.iter().enumerate() {
            let hash = Hash::from_hex(&chunk_ref.hash)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            let blob_path = cas.blob_path(&hash);
            let content = fs::read_to_string(&blob_path)?;

            for (line_idx, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                // First chunk's first line is always the stream header — skip it
                // unconditionally. We don't check content because an event
                // containing "format_version" in its payload could be mis-skipped.
                if i == 0 && line_idx == 0 {
                    continue;
                }

                let event: OaieEvent = serde_json::from_str(trimmed)
                    .map_err(|e| std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("chunk {}, line {}: {}", chunk_ref.index, line_idx, e),
                    ))?;
                all_events.push(event);
            }
        }

        Ok(all_events)
    }

    /// Streaming iterator over events from CAS chunks.
    ///
    /// Reads one chunk at a time into memory, yielding events without loading
    /// the entire trace at once.
    pub fn iter_events_from_index(
        cas: &CasStore,
        index: &TraceIndex,
    ) -> ChunkedEventIterator {
        ChunkedEventIterator {
            cas: cas.clone(),
            chunks: index.chunks.clone(),
            chunk_idx: 0,
            is_first_chunk: true,
            current_events: Vec::new(),
            event_idx: 0,
        }
    }
}

/// Streaming iterator over events stored across CAS chunks.
pub struct ChunkedEventIterator {
    cas: CasStore,
    chunks: Vec<ChunkRef>,
    chunk_idx: usize,
    is_first_chunk: bool,
    current_events: Vec<OaieEvent>,
    event_idx: usize,
}

impl Iterator for ChunkedEventIterator {
    type Item = std::io::Result<OaieEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // If we have events from the current chunk, yield the next one.
            if self.event_idx < self.current_events.len() {
                let event = self.current_events[self.event_idx].clone();
                self.event_idx += 1;
                return Some(Ok(event));
            }

            // Load the next chunk.
            if self.chunk_idx >= self.chunks.len() {
                return None;
            }

            let chunk_ref = &self.chunks[self.chunk_idx];
            let hash = match Hash::from_hex(&chunk_ref.hash) {
                Ok(h) => h,
                Err(e) => return Some(Err(std::io::Error::other(e.to_string()))),
            };

            let blob_path = self.cas.blob_path(&hash);
            let content = match fs::read_to_string(&blob_path) {
                Ok(c) => c,
                Err(e) => return Some(Err(e)),
            };

            let mut events = Vec::new();
            for (line_idx, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                // First chunk's first line is always the stream header — skip it
                // unconditionally (don't check content to avoid false matches).
                if self.is_first_chunk && line_idx == 0 {
                    continue;
                }
                match serde_json::from_str::<OaieEvent>(trimmed) {
                    Ok(event) => events.push(event),
                    Err(e) => return Some(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("chunk {}, line {}: {}", chunk_ref.index, line_idx, e),
                    ))),
                }
            }

            self.chunk_idx += 1;
            if self.is_first_chunk {
                self.is_first_chunk = false;
            }
            self.current_events = events;
            self.event_idx = 0;
        }
    }
}
