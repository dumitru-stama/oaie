//! Event data model for OAIE observation traces.
//!
//! Defines the format that all trace backends (ptrace, eBPF) emit.
//! Events are serialized as NDJSON (newline-delimited JSON) — streamable,
//! parseable line-by-line, and human-readable.
//!
//! This format is versioned via [`EventStreamHeader::format_version`].
//! Changing it means bumping the version and adding migration logic to readers.

use serde::{Deserialize, Serialize};

/// A single observation event.
///
/// Compact, versioned, serializable. Every event links to the previous
/// via `hash_prev`, forming a tamper-evident chain (see `chain.rs`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OaieEvent {
    /// Monotonic nanosecond timestamp relative to run start.
    /// Set by the event writer if left as 0.
    pub ts_ns: u64,

    /// What kind of event this is.
    pub event_type: EventType,

    /// Process ID that triggered the event.
    /// 0 for OAIE-internal events (RunStart, RunEnd).
    pub pid: u32,

    /// Parent PID, present for process events to reconstruct the process tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,

    /// Event-specific payload.
    pub detail: EventDetail,

    /// BLAKE3 hash of the previous event's serialized bytes.
    /// First event uses BLAKE3("OAIE_CHAIN_GENESIS").
    pub hash_prev: String,
}

/// Classification of observation events.
///
/// Each variant maps to exactly one [`EventDetail`] variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Process executed a new binary (execve).
    ProcessExec,
    /// Process exited.
    ProcessExit,
    /// File opened (or attempted).
    FileOpen,
    /// File stat'd (stat, lstat, fstat).
    FileStat,
    /// Network connect attempted (connect syscall).
    NetConnect,
    /// DNS query observed (sendto to UDP port 53).
    DnsQuery,
    /// OAIE internal: run started.
    RunStart,
    /// OAIE internal: run completed.
    RunEnd,
    /// Security-relevant syscall detected (mount, ptrace, memfd_create, etc.).
    SecurityRelevant,
}

/// Event-specific payload, tagged by `kind` for unambiguous deserialization.
///
/// Each variant corresponds to one [`EventType`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum EventDetail {
    /// A process executed a new binary via execve.
    Exec {
        /// Path to the executable.
        filename: String,
        /// Full argument vector.
        argv: Vec<String>,
    },
    /// A process exited.
    Exit {
        /// Exit code (from waitpid).
        exit_code: i32,
        /// Signal number if killed by signal, None for normal exit.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signal: Option<i32>,
    },
    /// A file was opened (or the open was attempted and failed).
    FileAccess {
        /// Filesystem path that was opened.
        path: String,
        /// Open flags (O_RDONLY=0, O_WRONLY=1, O_RDWR=2, etc.).
        flags: u32,
        /// 0 = success, >0 = errno, -1 = not captured.
        ///
        /// The -1 case is the eBPF backend (ebpf_tracer.rs) which hooks
        /// `sys_enter_*` tracepoints — the syscall hasn't returned yet,
        /// so the kernel return value is unknowable. The ptrace backend
        /// reads the actual return register at syscall-exit-stop and
        /// always populates 0 or errno. Consumers (summary.rs) MUST
        /// check `> 0`, not `!= 0`, to bucket failures, so that the
        /// eBPF `-1` falls through to the presume-success path instead
        /// of colliding with ptrace's "actually succeeded".
        result: i32,
    },
    /// A file was stat'd.
    FileStat {
        /// Filesystem path that was stat'd.
        path: String,
        /// 0 = success, >0 = errno, -1 = not captured (see FileAccess.result).
        result: i32,
    },
    /// A network connect was attempted.
    NetConnect {
        /// Address family: "AF_INET", "AF_INET6", "AF_UNIX".
        family: String,
        /// Address and port: "93.184.216.34:80" or "/var/run/sock".
        address: String,
        /// 0 = success, >0 = errno, -1 = not captured (see FileAccess.result).
        result: i32,
    },
    /// A DNS query was observed (sendto to UDP port 53).
    DnsQuery {
        /// Domain name being queried (parsed from DNS wire format).
        name: String,
        /// DNS server address (e.g. "8.8.8.8:53").
        server: String,
        /// 0 = sendto succeeded, otherwise the errno value.
        result: i32,
    },
    /// OAIE run lifecycle event (start/end).
    RunLifecycle {
        /// "started", "completed", "failed", "timed_out".
        status: String,
        /// The command being run (present on start events).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command: Option<Vec<String>>,
        /// Exit code (present on end events).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
    },
    /// A security-relevant syscall was attempted (mount, ptrace, memfd_create, etc.).
    ///
    /// These don't need full argument extraction — just flagging the attempt
    /// is valuable. The summarizer (week 8) uses these for risk assessment.
    SecurityRelevant {
        /// Human-readable syscall name (e.g. "mount", "fileless_exec_detected").
        syscall: String,
        /// Raw syscall number for the current architecture.
        syscall_nr: u64,
    },
}

/// Header written as the first line of an events.log file.
///
/// Not part of the hash chain — it's metadata about the stream.
/// Readers check `format_version` to decide how to parse events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventStreamHeader {
    /// Format version, starts at 1. Bump on breaking changes.
    pub format_version: u32,
    /// Run ID (full UUID) this event stream belongs to.
    pub run_id: String,
    /// ISO 8601 timestamp when this stream was created.
    pub created: String,
    /// Name of the trace backend: "ptrace", "ebpf", "synthetic", "none".
    pub trace_backend: String,
    /// BLAKE3 hash of "OAIE_CHAIN_GENESIS" — the chain's starting point.
    pub genesis_hash: String,
}
