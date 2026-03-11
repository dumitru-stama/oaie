//! eBPF-based tracer — low-overhead kernel-boundary event capture.
//!
//! Unlike [`PtraceTracer`], the eBPF tracer does NOT own the waitpid loop.
//! It runs in a background thread, consuming events from the BPF ring buffer
//! and writing them to the [`ChunkedEventWriter`]. The runner's existing
//! waitpid loop handles process lifecycle.
//!
//! ## Architecture
//!
//! ```text
//! BPF programs (kernel)
//!   → ring buffer (shared memory)
//!     → EbpfTracer::run() (background thread)
//!       → convert_raw_event()
//!         → ChunkedEventWriter
//! ```
//!
//! Uses the raw `libbpf_sys` C API for ring buffer creation from a raw FD
//! (the ring buffer map FD is received from oaie-priv via SCM_RIGHTS, so
//! we don't have a `MapCore` object — only a raw file descriptor).
//!
//! This module is only compiled with the `ebpf` feature flag.

use std::ffi::c_void;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use oaie_bpf_common::{
    cstr_from_bytes, format_connect_addr, BpfEventType, ConnectPayload, ExecPayload,
    ExitPayload, OpenPayload, RawEvent,
};

use crate::chunked_writer::ChunkedEventWriter;
use crate::event::{EventDetail, EventType, OaieEvent};
use crate::ptrace_tracer::TracerError;

/// Context passed to the ring buffer callback via a `*mut c_void` pointer.
///
/// Lives on the stack of `EbpfTracer::run()` for the duration of the poll
/// loop. The callback is invoked synchronously during `ring_buffer__poll`,
/// so no cross-thread access occurs.
struct RingBufferCtx {
    /// Owned writer — moved into ctx during run(), moved back out after.
    writer: ChunkedEventWriter,
    /// CLOCK_MONOTONIC nanoseconds at tracer start, for timestamp correlation.
    start_mono_ns: u64,
    /// Shared dropped event counter.
    dropped: Arc<AtomicU64>,
    /// Consecutive poll error counter.
    poll_errors: u32,
}

/// Ring buffer sample callback (called by libbpf for each event).
///
/// # Safety
///
/// `ctx` must point to a valid `RingBufferCtx` for the duration of the call.
/// `data` must point to `size` readable bytes. Both are guaranteed by libbpf
/// when called from `ring_buffer__poll`.
unsafe extern "C" fn ring_buffer_callback(
    ctx: *mut c_void,
    data: *mut c_void,
    size: std::os::raw::c_ulong,
) -> i32 {
    let ctx = &mut *(ctx as *mut RingBufferCtx);

    if (size as usize) < std::mem::size_of::<RawEvent>() {
        return 0; // Short read — skip.
    }

    let raw = &*(data as *const RawEvent);

    if let Some(event) = convert_raw_event(raw, ctx.start_mono_ns) {
        if ctx.writer.write_event(event).is_err() {
            ctx.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    0 // Return 0 to continue processing.
}

/// eBPF-based tracer that consumes events from a BPF ring buffer.
///
/// Created after oaie-priv loads BPF programs and passes back the
/// ring buffer FD. Runs in a background thread; signal `stop_flag`
/// to terminate gracefully.
pub struct EbpfTracer {
    /// Ring buffer map file descriptor (received from oaie-priv).
    ring_buffer_fd: RawFd,
    /// Tracepoint link file descriptors (kept alive to maintain attachment).
    #[allow(dead_code)]
    link_fds: Vec<RawFd>,
    /// Event writer for persisting events to CAS chunks.
    writer: ChunkedEventWriter,
    /// CLOCK_MONOTONIC nanoseconds at construction time.
    start_mono_ns: u64,
    /// Counter for events dropped due to write errors.
    dropped_events: Arc<AtomicU64>,
    /// Flag to signal the consumer thread to stop.
    stop_flag: Arc<AtomicBool>,
}

impl EbpfTracer {
    /// Create a new eBPF tracer.
    ///
    /// `ring_buffer_fd` and `link_fds` come from `bpf_client::load_bpf()`.
    /// `writer` is the chunked event writer that persists events to CAS.
    pub fn new(
        ring_buffer_fd: RawFd,
        link_fds: Vec<RawFd>,
        writer: ChunkedEventWriter,
    ) -> Self {
        Self {
            ring_buffer_fd,
            link_fds,
            writer,
            start_mono_ns: clock_monotonic_ns(),
            dropped_events: Arc::new(AtomicU64::new(0)),
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get a handle to signal the tracer to stop.
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop_flag)
    }

    /// Run the ring buffer consumer loop.
    ///
    /// Polls the BPF ring buffer, converts raw events to `OaieEvent`,
    /// and writes them to the chunked event writer.
    ///
    /// Returns the writer (for finalization) and the dropped event count.
    /// Exits when `stop_flag` is set.
    pub fn run(self) -> Result<(ChunkedEventWriter, u64), TracerError> {
        // Move the writer into the context struct. This avoids raw pointers
        // aliasing &mut self.writer — the writer is exclusively owned by ctx
        // during the poll loop.
        let mut ctx = RingBufferCtx {
            writer: self.writer,
            start_mono_ns: self.start_mono_ns,
            dropped: Arc::clone(&self.dropped_events),
            poll_errors: 0,
        };

        // Create ring buffer using the raw libbpf C API.
        // This accepts a raw FD directly, bypassing the MapCore requirement
        // of the Rust wrapper (we only have a raw FD from SCM_RIGHTS).
        let rb = unsafe {
            libbpf_sys::ring_buffer__new(
                self.ring_buffer_fd,
                Some(ring_buffer_callback),
                &mut ctx as *mut RingBufferCtx as *mut c_void,
                std::ptr::null(),
            )
        };
        if rb.is_null() {
            return Err(TracerError::Unexpected(
                "failed to create ring buffer from FD".into(),
            ));
        }

        // Poll loop: 100ms timeout so we check stop_flag regularly.
        while !self.stop_flag.load(Ordering::Relaxed) {
            let ret = unsafe { libbpf_sys::ring_buffer__poll(rb, 100) };
            if ret < 0 {
                ctx.poll_errors += 1;
                // Break on persistent errors (100 consecutive = ~10s of failures).
                if ctx.poll_errors > 100 {
                    unsafe { libbpf_sys::ring_buffer__free(rb) };
                    return Err(TracerError::Unexpected(format!(
                        "ring buffer poll failed {} consecutive times (errno {})",
                        ctx.poll_errors, -ret,
                    )));
                }
            } else {
                ctx.poll_errors = 0;
            }
        }

        // Final drain: poll once more with a short timeout to catch any
        // events that arrived between the last poll and stop signal.
        unsafe { libbpf_sys::ring_buffer__poll(rb, 50) };

        // Free the ring buffer (detaches from the FD, does NOT close the FD).
        unsafe { libbpf_sys::ring_buffer__free(rb) };

        let dropped_count = self.dropped_events.load(Ordering::Relaxed);
        Ok((ctx.writer, dropped_count))
    }
}

/// Get CLOCK_MONOTONIC time in nanoseconds.
///
/// Uses the same clock source as `bpf_ktime_get_ns()` in BPF programs,
/// allowing accurate timestamp correlation between kernel events and
/// userspace measurement.
fn clock_monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if ret != 0 {
        // CLOCK_MONOTONIC should never fail, but don't silently return 0.
        log::error!("clock_gettime(CLOCK_MONOTONIC) failed: errno {}", unsafe {
            *libc::__errno_location()
        });
        return 0;
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Convert a raw BPF event to an `OaieEvent`.
///
/// `start_mono_ns` is the CLOCK_MONOTONIC value at tracer start time.
/// Event timestamps are computed as `raw.ts_ns - start_mono_ns`, giving
/// nanosecond-accurate relative time from the kernel's perspective.
///
/// Returns `None` for unknown event types.
pub fn convert_raw_event(raw: &RawEvent, start_mono_ns: u64) -> Option<OaieEvent> {
    let event_type_val = BpfEventType::from_u32(raw.event_type)?;

    // Calculate relative timestamp using kernel monotonic time.
    // Both bpf_ktime_get_ns() and CLOCK_MONOTONIC use the same clock source.
    let ts_ns = raw.ts_ns.saturating_sub(start_mono_ns);

    let (event_type, detail) = match event_type_val {
        BpfEventType::Exec => {
            let payload =
                unsafe { &*(raw.payload.as_ptr() as *const ExecPayload) };
            let filename = cstr_from_bytes(&payload.filename);
            (
                EventType::ProcessExec,
                EventDetail::Exec {
                    filename: filename.clone(),
                    argv: vec![filename], // BPF cannot capture full argv.
                },
            )
        }
        BpfEventType::Exit => {
            let payload =
                unsafe { &*(raw.payload.as_ptr() as *const ExitPayload) };
            (
                EventType::ProcessExit,
                EventDetail::Exit {
                    exit_code: payload.exit_code,
                    signal: if payload.signal != 0 {
                        Some(payload.signal)
                    } else {
                        None
                    },
                },
            )
        }
        BpfEventType::Open => {
            let payload =
                unsafe { &*(raw.payload.as_ptr() as *const OpenPayload) };
            let path = cstr_from_bytes(&payload.filename);
            (
                EventType::FileOpen,
                EventDetail::FileAccess {
                    path,
                    flags: payload.flags,
                    result: 0, // sys_enter has no return value.
                },
            )
        }
        BpfEventType::Connect => {
            let payload =
                unsafe { &*(raw.payload.as_ptr() as *const ConnectPayload) };
            let (family, address) = format_connect_addr(payload);
            (
                EventType::NetConnect,
                EventDetail::NetConnect {
                    family,
                    address,
                    result: 0, // sys_enter has no return value.
                },
            )
        }
    };

    Some(OaieEvent {
        ts_ns,
        event_type,
        pid: raw.pid,
        ppid: Some(raw.ppid),
        detail,
        hash_prev: String::new(), // Filled by the event chain.
    })
}
