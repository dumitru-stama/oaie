//! eBPF tracer tests.
//!
//! Unit tests always run (they test shared types and protocol).
//! Integration tests are conditional on eBPF + cgroup support.

use oaie_bpf_common::{
    cstr_from_bytes, format_connect_addr, BpfEventType, ConnectPayload, ExecPayload,
    ExitPayload, OpenPayload, RawEvent,
};

// ── Unit tests: shared types ──

#[test]
fn raw_event_size_is_288_bytes() {
    assert_eq!(std::mem::size_of::<RawEvent>(), 288);
}

#[test]
fn exec_payload_size_is_256_bytes() {
    assert_eq!(std::mem::size_of::<ExecPayload>(), 256);
}

#[test]
fn exit_payload_fits_in_256_bytes() {
    assert!(std::mem::size_of::<ExitPayload>() <= 256);
    assert_eq!(std::mem::size_of::<ExitPayload>(), 8);
}

#[test]
fn open_payload_size_is_256_bytes() {
    assert_eq!(std::mem::size_of::<OpenPayload>(), 256);
}

#[test]
fn connect_payload_fits_in_256_bytes() {
    assert!(std::mem::size_of::<ConnectPayload>() <= 256);
}

// ── Unit tests: BpfEventType ──

#[test]
fn bpf_event_type_discriminants() {
    assert_eq!(BpfEventType::Exec as u32, 1);
    assert_eq!(BpfEventType::Exit as u32, 2);
    assert_eq!(BpfEventType::Open as u32, 3);
    assert_eq!(BpfEventType::Connect as u32, 4);
}

#[test]
fn bpf_event_type_from_u32() {
    assert_eq!(BpfEventType::from_u32(1), Some(BpfEventType::Exec));
    assert_eq!(BpfEventType::from_u32(2), Some(BpfEventType::Exit));
    assert_eq!(BpfEventType::from_u32(3), Some(BpfEventType::Open));
    assert_eq!(BpfEventType::from_u32(4), Some(BpfEventType::Connect));
    assert_eq!(BpfEventType::from_u32(0), None);
    assert_eq!(BpfEventType::from_u32(5), None);
    assert_eq!(BpfEventType::from_u32(u32::MAX), None);
}

// ── Unit tests: cstr_from_bytes ──

#[test]
fn cstr_from_bytes_null_terminated() {
    let buf = b"hello\0world";
    assert_eq!(cstr_from_bytes(buf), "hello");
}

#[test]
fn cstr_from_bytes_empty() {
    let buf = b"\0";
    assert_eq!(cstr_from_bytes(buf), "");
}

#[test]
fn cstr_from_bytes_no_null() {
    let buf = b"no null here";
    assert_eq!(cstr_from_bytes(buf), "no null here");
}

#[test]
fn cstr_from_bytes_max_length() {
    let mut buf = [b'A'; 256];
    assert_eq!(cstr_from_bytes(&buf), "A".repeat(256));

    // With null at end
    buf[255] = 0;
    assert_eq!(cstr_from_bytes(&buf), "A".repeat(255));
}

#[test]
fn cstr_from_bytes_empty_slice() {
    let buf: &[u8] = &[];
    assert_eq!(cstr_from_bytes(buf), "");
}

// ── Unit tests: format_connect_addr ──

#[test]
fn format_connect_addr_ipv4() {
    let mut payload: ConnectPayload = unsafe { std::mem::zeroed() };
    payload.family = 2; // AF_INET
    payload.port = 80u16.to_be(); // port 80 in network byte order
    payload.addr[0] = 127;
    payload.addr[1] = 0;
    payload.addr[2] = 0;
    payload.addr[3] = 1;

    let (family, address) = format_connect_addr(&payload);
    assert_eq!(family, "AF_INET");
    assert_eq!(address, "127.0.0.1:80");
}

#[test]
fn format_connect_addr_ipv6() {
    let mut payload: ConnectPayload = unsafe { std::mem::zeroed() };
    payload.family = 10; // AF_INET6
    payload.port = 443u16.to_be();
    // ::1 (loopback)
    payload.addr[15] = 1;

    let (family, address) = format_connect_addr(&payload);
    assert_eq!(family, "AF_INET6");
    assert_eq!(address, "[::1]:443");
}

#[test]
fn format_connect_addr_unix() {
    let mut payload: ConnectPayload = unsafe { std::mem::zeroed() };
    payload.family = 1; // AF_UNIX
    let path = b"/var/run/test.sock\0";
    payload.addr[..path.len()].copy_from_slice(path);

    let (family, address) = format_connect_addr(&payload);
    assert_eq!(family, "AF_UNIX");
    assert_eq!(address, "/var/run/test.sock");
}

#[test]
fn format_connect_addr_unknown_family() {
    let mut payload: ConnectPayload = unsafe { std::mem::zeroed() };
    payload.family = 99;

    let (family, address) = format_connect_addr(&payload);
    assert_eq!(family, "AF_UNKNOWN(99)");
    assert!(address.is_empty());
}

// ── Unit tests: protocol serialization ──

#[test]
fn protocol_load_bpf_round_trip() {
    use oaie_priv::protocol::Request;

    let req = Request::LoadBpf {
        cgroup_id: 12345,
        ring_buffer_size: 1_048_576,
    };
    let json = serde_json::to_string(&req).unwrap();
    let parsed: Request = serde_json::from_str(&json).unwrap();
    match parsed {
        Request::LoadBpf { cgroup_id, ring_buffer_size } => {
            assert_eq!(cgroup_id, 12345);
            assert_eq!(ring_buffer_size, 1_048_576);
        }
        _ => panic!("expected LoadBpf"),
    }
}

#[test]
fn protocol_unload_bpf_round_trip() {
    use oaie_priv::protocol::Request;

    let req = Request::UnloadBpf;
    let json = serde_json::to_string(&req).unwrap();
    let parsed: Request = serde_json::from_str(&json).unwrap();
    assert!(matches!(parsed, Request::UnloadBpf));
}

#[test]
fn response_ok_with_fds() {
    use oaie_priv::protocol::Response;

    let resp = Response::ok_with_fds(5);
    assert!(resp.ok);
    assert_eq!(resp.bpf_fd_count, Some(5));
    assert!(resp.error.is_none());

    // Serialization round-trip.
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: Response = serde_json::from_str(&json).unwrap();
    assert!(parsed.ok);
    assert_eq!(parsed.bpf_fd_count, Some(5));
}

// ── Unit tests: validation ──

#[test]
fn validate_ring_buffer_size_valid() {
    use oaie_priv::validate::validate_ring_buffer_size;

    assert!(validate_ring_buffer_size(256 * 1024).is_ok()); // 256KB min
    assert!(validate_ring_buffer_size(512 * 1024).is_ok());
    assert!(validate_ring_buffer_size(1024 * 1024).is_ok()); // 1MB
    assert!(validate_ring_buffer_size(2 * 1024 * 1024).is_ok());
    assert!(validate_ring_buffer_size(4 * 1024 * 1024).is_ok()); // 4MB max
}

#[test]
fn validate_ring_buffer_size_invalid() {
    use oaie_priv::validate::validate_ring_buffer_size;

    // Not power of 2
    assert!(validate_ring_buffer_size(300_000).is_err());
    assert!(validate_ring_buffer_size(1_000_000).is_err());
    // Too small
    assert!(validate_ring_buffer_size(128 * 1024).is_err());
    assert!(validate_ring_buffer_size(0).is_err());
    // Too large
    assert!(validate_ring_buffer_size(8 * 1024 * 1024).is_err());
}

// ── Unit tests: eBPF detection ──

#[test]
fn ebpf_detection_returns_caps() {
    let caps = oaie_cgroup::ebpf_detect::detect_ebpf();
    // On this system with kernel 6.8, ring buffer and BTF should be available.
    // The priv capability check depends on oaie-priv installation.
    // Just verify the struct is populated and `available` is consistent.
    if caps.kernel_supports_ringbuf && caps.btf_available && caps.priv_has_bpf_caps {
        assert!(caps.available);
    } else {
        assert!(!caps.available);
    }
}

// ── Unit tests: convert_raw_event (requires ebpf feature) ──

#[cfg(feature = "ebpf")]
mod convert_tests {
    use oaie_bpf_common::{BpfEventType, ConnectPayload, RawEvent, ExecPayload, ExitPayload, OpenPayload};
    use oaie_observe::convert_raw_event;
    use oaie_observe::{EventType, EventDetail};

    /// Base timestamp: 500_000 ns. Events at ts_ns=1_000_000 will have
    /// a relative timestamp of 500_000 ns.
    const START_MONO_NS: u64 = 500_000;

    fn make_raw_event(event_type: BpfEventType) -> RawEvent {
        RawEvent {
            event_type: event_type as u32,
            pid: 42,
            ppid: 1,
            _pad: 0,
            ts_ns: 1_000_000,
            cgroup_id: 99,
            payload: [0u8; 256],
        }
    }

    #[test]
    fn convert_exec_event() {
        let mut raw = make_raw_event(BpfEventType::Exec);
        let payload = unsafe { &mut *(raw.payload.as_mut_ptr() as *mut ExecPayload) };
        let path = b"/bin/echo\0";
        payload.filename[..path.len()].copy_from_slice(path);

        let event = convert_raw_event(&raw, START_MONO_NS).unwrap();
        assert_eq!(event.event_type, EventType::ProcessExec);
        assert_eq!(event.pid, 42);
        assert_eq!(event.ppid, Some(1));
        assert_eq!(event.ts_ns, 500_000); // 1_000_000 - 500_000
        match event.detail {
            EventDetail::Exec { filename, argv } => {
                assert_eq!(filename, "/bin/echo");
                assert_eq!(argv, vec!["/bin/echo"]);
            }
            _ => panic!("expected Exec detail"),
        }
    }

    #[test]
    fn convert_exit_event() {
        let mut raw = make_raw_event(BpfEventType::Exit);
        let payload = unsafe { &mut *(raw.payload.as_mut_ptr() as *mut ExitPayload) };
        payload.exit_code = 0;
        payload.signal = 0;

        let event = convert_raw_event(&raw, START_MONO_NS).unwrap();
        assert_eq!(event.event_type, EventType::ProcessExit);
        match event.detail {
            EventDetail::Exit { exit_code, signal } => {
                assert_eq!(exit_code, 0);
                assert_eq!(signal, None);
            }
            _ => panic!("expected Exit detail"),
        }
    }

    #[test]
    fn convert_exit_event_with_signal() {
        let mut raw = make_raw_event(BpfEventType::Exit);
        let payload = unsafe { &mut *(raw.payload.as_mut_ptr() as *mut ExitPayload) };
        payload.exit_code = 1;
        payload.signal = 9; // SIGKILL

        let event = convert_raw_event(&raw, START_MONO_NS).unwrap();
        match event.detail {
            EventDetail::Exit { exit_code, signal } => {
                assert_eq!(exit_code, 1);
                assert_eq!(signal, Some(9));
            }
            _ => panic!("expected Exit detail"),
        }
    }

    #[test]
    fn convert_open_event() {
        let mut raw = make_raw_event(BpfEventType::Open);
        let payload = unsafe { &mut *(raw.payload.as_mut_ptr() as *mut OpenPayload) };
        payload.flags = 0; // O_RDONLY
        let path = b"/etc/hosts\0";
        payload.filename[..path.len()].copy_from_slice(path);

        let event = convert_raw_event(&raw, START_MONO_NS).unwrap();
        assert_eq!(event.event_type, EventType::FileOpen);
        match event.detail {
            EventDetail::FileAccess { path, flags, result } => {
                assert_eq!(path, "/etc/hosts");
                assert_eq!(flags, 0);
                assert_eq!(result, 0);
            }
            _ => panic!("expected FileAccess detail"),
        }
    }

    #[test]
    fn convert_connect_event() {
        let mut raw = make_raw_event(BpfEventType::Connect);
        let payload = unsafe { &mut *(raw.payload.as_mut_ptr() as *mut ConnectPayload) };
        payload.family = 2; // AF_INET
        payload.port = 80u16.to_be();
        payload.addr[0] = 93;
        payload.addr[1] = 184;
        payload.addr[2] = 216;
        payload.addr[3] = 34;

        let event = convert_raw_event(&raw, START_MONO_NS).unwrap();
        assert_eq!(event.event_type, EventType::NetConnect);
        match event.detail {
            EventDetail::NetConnect { family, address, result } => {
                assert_eq!(family, "AF_INET");
                assert_eq!(address, "93.184.216.34:80");
                assert_eq!(result, 0);
            }
            _ => panic!("expected NetConnect detail"),
        }
    }

    #[test]
    fn convert_unknown_event_type_returns_none() {
        let raw = RawEvent {
            event_type: 255,
            pid: 1,
            ppid: 0,
            _pad: 0,
            ts_ns: 0,
            cgroup_id: 0,
            payload: [0u8; 256],
        };

        assert!(convert_raw_event(&raw, 0).is_none());
    }
}

// ── Integration tests (conditional) ──

#[test]
fn cgroup_id_from_path_returns_valid_inode() {
    // This test works even without eBPF — it just tests the stat() call.
    let path = std::path::Path::new("/sys/fs/cgroup");
    if !path.exists() {
        return; // Skip on systems without cgroup v2.
    }

    let id = oaie_cgroup::bpf_client::cgroup_id_from_path(path);
    assert!(id.is_ok());
    let id = id.unwrap();
    assert!(id > 0, "cgroup inode should be > 0, got {id}");
}

// FD passing round-trip test (uses Unix socketpair).
#[test]
fn fd_passing_round_trip() {
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

    let (sender, receiver) = UnixStream::pair().unwrap();

    // Create a temporary file to get a valid FD.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let fd = tmp.as_file().as_raw_fd();

    // Send FDs.
    let payload = b"test response";
    oaie_priv::fd_passing::send_response_with_fds(&sender, payload, &[fd]).unwrap();

    // Receive FDs.
    let (data, fds) = oaie_cgroup::fd_passing::recv_response_with_fds(&receiver, 1024, 4).unwrap();
    assert_eq!(data, b"test response");
    assert_eq!(fds.len(), 1);

    // The received FD should be valid (different number but same file).
    let received_fd = fds[0];
    assert!(received_fd >= 0);

    // Clean up.
    unsafe { libc::close(received_fd); }
}
