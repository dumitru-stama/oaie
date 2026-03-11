//! Observer trait — the abstraction that ptrace and eBPF backends implement.
//!
//! The runner calls `start()` before spawning the tool and `stop()` after
//! the tool exits. The backend emits events to the provided [`EventWriter`].

use crate::writer::EventWriter;

/// Trait for trace backends.
///
/// Week 7 adds `PtraceObserver`; v0.2 adds `EbpfObserver`.
/// Each backend is responsible for emitting events between start/stop.
pub trait Observer: Send {
    /// Called before the tool process starts.
    ///
    /// The backend should prepare for tracing (e.g. set up ptrace, attach
    /// eBPF programs). It may write initial events to the writer.
    fn start(&mut self, writer: &mut EventWriter) -> std::io::Result<()>;

    /// Called after the tool process exits.
    ///
    /// The backend should finalize any pending events (e.g. drain buffers,
    /// emit final statistics) and write them to the writer.
    fn stop(&mut self, writer: &mut EventWriter) -> std::io::Result<()>;

    /// Name of this trace backend, for manifest and report metadata.
    /// Returns "ptrace", "ebpf", "none", etc.
    fn backend_name(&self) -> &str;
}

/// A no-op observer for runs without tracing enabled.
///
/// Does nothing on start/stop, reports backend name "none".
pub struct NullObserver;

impl Observer for NullObserver {
    fn start(&mut self, _writer: &mut EventWriter) -> std::io::Result<()> {
        Ok(())
    }

    fn stop(&mut self, _writer: &mut EventWriter) -> std::io::Result<()> {
        Ok(())
    }

    fn backend_name(&self) -> &str {
        "none"
    }
}
