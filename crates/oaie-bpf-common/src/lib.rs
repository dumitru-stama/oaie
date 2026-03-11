//! Shared types between BPF C programs and Rust userspace.
//!
//! All types are `#[repr(C)]` to match the layout emitted by clang for the
//! BPF programs in `bpf/`. The C header `bpf/oaie_events.h` must be kept
//! in sync with these definitions.
//!
//! Zero dependencies — this crate is imported by both `oaie-priv` (privileged
//! loader) and `oaie-observe` (unprivileged consumer).

/// BPF event type discriminant. Matches the C enum in `oaie_events.h`.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BpfEventType {
    /// Process executed a new binary (sched_process_exec tracepoint).
    Exec = 1,
    /// Process exited (sched_process_exit tracepoint).
    Exit = 2,
    /// File opened via openat (sys_enter_openat tracepoint).
    Open = 3,
    /// Network connect attempted (sys_enter_connect tracepoint).
    Connect = 4,
}

impl BpfEventType {
    /// Convert from raw u32 discriminant. Returns `None` for unknown values.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Exec),
            2 => Some(Self::Exit),
            3 => Some(Self::Open),
            4 => Some(Self::Connect),
            _ => None,
        }
    }
}

/// Raw event structure shared between BPF ring buffer and userspace.
///
/// Total size: 288 bytes. BPF programs write this via `bpf_ringbuf_reserve`,
/// and userspace reads it from the ring buffer file descriptor.
///
/// The `payload` field is a union-like byte array interpreted based on
/// `event_type` — use the typed payload structs below for safe access.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawEvent {
    /// Event type discriminant (see [`BpfEventType`]).
    pub event_type: u32,
    /// PID of the process that triggered the event.
    pub pid: u32,
    /// Parent PID of the triggering process.
    pub ppid: u32,
    /// Padding to align `ts_ns` to 8-byte boundary.
    pub _pad: u32,
    /// Kernel timestamp in nanoseconds (from `bpf_ktime_get_ns`).
    pub ts_ns: u64,
    /// Cgroup ID of the triggering process (from `bpf_get_current_cgroup_id`).
    pub cgroup_id: u64,
    /// Event-specific payload, interpreted based on `event_type`.
    pub payload: [u8; 256],
}

// Compile-time size assertion.
const _: () = assert!(core::mem::size_of::<RawEvent>() == 288);

/// Payload for `BpfEventType::Exec` events.
///
/// Contains the filename of the executed binary, captured from
/// `sched_process_exec` tracepoint args.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecPayload {
    /// Null-terminated filename of the executed binary.
    pub filename: [u8; 256],
}

/// Payload for `BpfEventType::Exit` events.
///
/// Contains exit code and signal from `task->exit_code`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExitPayload {
    /// Process exit code (0 for normal exit).
    pub exit_code: i32,
    /// Signal number if killed by signal, 0 otherwise.
    pub signal: i32,
}

/// Payload for `BpfEventType::Open` events.
///
/// Contains the filename and flags from `sys_enter_openat`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OpenPayload {
    /// Open flags (O_RDONLY, O_WRONLY, O_RDWR, etc.).
    pub flags: u32,
    /// Padding for alignment.
    pub _pad: u32,
    /// Null-terminated filename being opened.
    pub filename: [u8; 248],
}

/// Payload for `BpfEventType::Connect` events.
///
/// Contains the socket address from `sys_enter_connect`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectPayload {
    /// Address family (AF_INET=2, AF_INET6=10, AF_UNIX=1).
    pub family: u16,
    /// Port number (network byte order for AF_INET/AF_INET6).
    pub port: u16,
    /// Padding for alignment.
    pub _pad: [u8; 4],
    /// Raw address bytes (sockaddr content after family+port).
    /// For AF_INET: 4-byte IPv4 address at offset 0.
    /// For AF_INET6: 16-byte IPv6 address at offset 0.
    /// For AF_UNIX: null-terminated path.
    pub addr: [u8; 240],
}

// Payload size assertions — all must fit in the 256-byte payload field.
const _: () = assert!(core::mem::size_of::<ExecPayload>() == 256);
const _: () = assert!(core::mem::size_of::<ExitPayload>() <= 256);
const _: () = assert!(core::mem::size_of::<OpenPayload>() == 256);
const _: () = assert!(core::mem::size_of::<ConnectPayload>() == 248);

/// Extract a null-terminated C string from a byte slice.
///
/// Returns everything up to the first NUL byte (or the entire slice if no
/// NUL is found), decoded as UTF-8 with lossy replacement.
pub fn cstr_from_bytes(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Format a connect address from a [`ConnectPayload`] into a human-readable string.
///
/// Returns `"family:address:port"` for known families, or `"AF_UNKNOWN(N)"` for others.
pub fn format_connect_addr(payload: &ConnectPayload) -> (String, String) {
    match payload.family {
        2 => {
            // AF_INET: 4-byte IPv4 address at addr[0..4].
            let addr = format!(
                "{}.{}.{}.{}",
                payload.addr[0], payload.addr[1], payload.addr[2], payload.addr[3]
            );
            let port = u16::from_be(payload.port);
            ("AF_INET".into(), format!("{addr}:{port}"))
        }
        10 => {
            // AF_INET6: 16-byte IPv6 address at addr[0..16].
            // Use Rust's standard Ipv6Addr formatting for compressed notation
            // (e.g. "::1" instead of "0:0:0:0:0:0:0:1").
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&payload.addr[..16]);
            let addr = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be(payload.port);
            ("AF_INET6".into(), format!("[{addr}]:{port}"))
        }
        1 => {
            // AF_UNIX: null-terminated path.
            let path = cstr_from_bytes(&payload.addr);
            ("AF_UNIX".into(), path)
        }
        other => {
            (format!("AF_UNKNOWN({other})"), String::new())
        }
    }
}

impl core::fmt::Debug for RawEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawEvent")
            .field("event_type", &self.event_type)
            .field("pid", &self.pid)
            .field("ppid", &self.ppid)
            .field("ts_ns", &self.ts_ns)
            .field("cgroup_id", &self.cgroup_id)
            .finish()
    }
}
