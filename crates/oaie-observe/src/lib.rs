//! Syscall observation and tracing for OAIE runs.
//!
//! Provides the event format, hash chain, writer/reader, summarizer,
//! and the `Observer` trait that trace backends (ptrace, eBPF) implement.
//!
//! ## Architecture
//!
//! Events are written as NDJSON (newline-delimited JSON), one event per line,
//! with a hash chain linking each event to the previous for tamper evidence.
//!
//! ```text
//! ChunkedEventWriter → chunk_N.tmp → CAS (rotated at 1MB)
//!   ↓
//! TraceIndex → trace_index.json (lists all chunks)
//!   ↓
//! ChunkedEventIterator → streams events from CAS chunks
//!   ↓
//! StreamingSummarizer → TraceSummary
//! verify_chain()      → ChainVerifyResult
//! ```

pub mod chain;
pub mod chunked_writer;
#[cfg(feature = "ebpf")]
pub mod ebpf_tracer;
pub mod event;
pub mod memory;
pub mod observer;
pub mod ptrace_tracer;
pub mod reader;
pub mod summary;
pub mod syscall_table;
pub mod writer;

// Re-exports for convenience.
pub use chain::{genesis_hash, verify_chain, ChainVerifyResult, EventChain};
pub use oaie_core::hash_algo::HashAlgorithm;
pub use chunked_writer::{ChunkedEventIterator, ChunkedEventWriter, ChunkRef, TraceIndex};
#[cfg(feature = "ebpf")]
pub use ebpf_tracer::{convert_raw_event, EbpfTracer};
pub use event::{EventDetail, EventStreamHeader, EventType, OaieEvent};
pub use observer::{NullObserver, Observer};
pub use ptrace_tracer::{child_traceme, PtraceTracer, TracerError};
pub use reader::{EventIterator, EventReader};
pub use summary::{
    group_by_directory, summarize_events, DisplayEntry, DnsQueryEntry, FileAccessEntry,
    FileCategory, NetConnectEntry, ProcessNode, StreamingSummarizer, SuspiciousCategory,
    SuspiciousEntry, TraceSummary,
};
pub use writer::{EventWriter, EventWriterResult};
