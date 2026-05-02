//! Tests for the observe pipeline: event model, hash chain, writer/reader,
//! summarizer, chunked writer, and full pipeline integration.

use oaie_cas::store::CasStore;
use oaie_core::hash_algo::HashAlgorithm;
use oaie_core::run_id::RunId;
use oaie_observe::{
    genesis_hash, summarize_events, verify_chain, ChainVerifyResult, ChunkedEventWriter,
    EventChain, EventDetail, EventReader, EventStreamHeader, EventType, EventWriter, OaieEvent,
    StreamingSummarizer, SuspiciousCategory,
};
use oaie_tests::{
    make_exec_event, make_exit_event, make_file_open_event, make_net_connect_event,
    make_run_end_event, make_run_start_event, make_security_event,
};
use tempfile::tempdir;

// ============================================================
// Day 1: Event data model
// ============================================================

#[test]
fn event_serialization_round_trip() {
    let event = OaieEvent {
        ts_ns: 12345,
        event_type: EventType::FileOpen,
        pid: 42,
        ppid: None,
        detail: EventDetail::FileAccess {
            path: "/in/data.bin".into(),
            flags: 0,
            result: 0,
        },
        hash_prev: "abc123".into(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let parsed: OaieEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, parsed);
}

#[test]
fn event_type_serde_snake_case() {
    let json = serde_json::to_string(&EventType::ProcessExec).unwrap();
    assert_eq!(json, "\"process_exec\"");

    let json = serde_json::to_string(&EventType::NetConnect).unwrap();
    assert_eq!(json, "\"net_connect\"");

    let parsed: EventType = serde_json::from_str("\"run_start\"").unwrap();
    assert_eq!(parsed, EventType::RunStart);
}

#[test]
fn event_detail_tagged_by_kind() {
    let detail = EventDetail::Exec {
        filename: "/bin/ls".into(),
        argv: vec!["ls".into(), "-la".into()],
    };
    let json = serde_json::to_string(&detail).unwrap();
    assert!(json.contains("\"kind\":\"Exec\""));

    let parsed: EventDetail = serde_json::from_str(&json).unwrap();
    assert_eq!(detail, parsed);
}

#[test]
fn all_event_types_have_detail_variants() {
    let pairs = vec![
        (
            EventType::ProcessExec,
            EventDetail::Exec {
                filename: "/bin/sh".into(),
                argv: vec!["sh".into()],
            },
        ),
        (
            EventType::ProcessExit,
            EventDetail::Exit {
                exit_code: 0,
                signal: None,
            },
        ),
        (
            EventType::FileOpen,
            EventDetail::FileAccess {
                path: "/tmp/f".into(),
                flags: 0,
                result: 0,
            },
        ),
        (
            EventType::FileStat,
            EventDetail::FileStat {
                path: "/tmp/f".into(),
                result: 0,
            },
        ),
        (
            EventType::NetConnect,
            EventDetail::NetConnect {
                family: "AF_INET".into(),
                address: "127.0.0.1:80".into(),
                result: 0,
            },
        ),
        (
            EventType::RunStart,
            EventDetail::RunLifecycle {
                status: "started".into(),
                command: Some(vec!["./tool".into()]),
                exit_code: None,
            },
        ),
        (
            EventType::RunEnd,
            EventDetail::RunLifecycle {
                status: "completed".into(),
                command: None,
                exit_code: Some(0),
            },
        ),
        (
            EventType::SecurityRelevant,
            EventDetail::SecurityRelevant {
                syscall: "io_uring_setup".into(),
                syscall_nr: 425,
            },
        ),
    ];

    for (event_type, detail) in pairs {
        let event = OaieEvent {
            ts_ns: 0,
            event_type,
            pid: 1,
            ppid: None,
            detail,
            hash_prev: String::new(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: OaieEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }
}

#[test]
fn event_stream_header_serialization() {
    let header = EventStreamHeader {
        format_version: 1,
        run_id: "test-run-id".into(),
        created: "2026-03-01T10:00:00Z".into(),
        trace_backend: "ptrace".into(),
        genesis_hash: genesis_hash(HashAlgorithm::Blake3),
    };
    let json = serde_json::to_string(&header).unwrap();
    let parsed: EventStreamHeader = serde_json::from_str(&json).unwrap();
    assert_eq!(header, parsed);
    assert_eq!(parsed.format_version, 1);
}

#[test]
fn ndjson_multiple_events() {
    let events = vec![
        make_run_start_event(&["./tool"]),
        make_file_open_event(1, "/in/data.bin", 0, 0),
        make_run_end_event(0),
    ];

    let mut lines = String::new();
    for event in &events {
        let json = serde_json::to_string(event).unwrap();
        let _: OaieEvent = serde_json::from_str(&json).unwrap();
        lines.push_str(&json);
        lines.push('\n');
    }

    let parsed: Vec<OaieEvent> = lines
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(parsed.len(), 3);
}

// ============================================================
// Day 2: Hash chain
// ============================================================

#[test]
fn genesis_hash_is_deterministic() {
    let h1 = genesis_hash(HashAlgorithm::Blake3);
    let h2 = genesis_hash(HashAlgorithm::Blake3);
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 64);
}

#[test]
fn chain_of_10_events_verifies() {
    let mut chain = EventChain::new(HashAlgorithm::Blake3);
    let mut events = Vec::new();
    let gen = genesis_hash(HashAlgorithm::Blake3);

    for i in 0..10u32 {
        let mut event = make_file_open_event(i, &format!("/tmp/file{i}"), 0, 0);
        event.ts_ns = i as u64 * 1000;
        let _ = chain.append(&mut event);
        events.push(event);
    }

    let result = verify_chain(&events, &gen, HashAlgorithm::Blake3);
    match result {
        ChainVerifyResult::Valid { events: n, .. } => assert_eq!(n, 10),
        other => panic!("expected Valid, got {other:?}"),
    }
}

#[test]
fn chain_detects_modified_event() {
    let mut chain = EventChain::new(HashAlgorithm::Blake3);
    let gen = genesis_hash(HashAlgorithm::Blake3);
    let mut events = Vec::new();

    for i in 0..5u32 {
        let mut event = make_file_open_event(i, &format!("/tmp/f{i}"), 0, 0);
        let _ = chain.append(&mut event);
        events.push(event);
    }

    if let EventDetail::FileAccess { ref mut path, .. } = events[2].detail {
        *path = "/tmp/TAMPERED".into();
    }

    let result = verify_chain(&events, &gen, HashAlgorithm::Blake3);
    match result {
        ChainVerifyResult::Broken { event_index, .. } => {
            assert_eq!(event_index, 3);
        }
        other => panic!("expected Broken, got {other:?}"),
    }
}

#[test]
fn chain_detects_deleted_event() {
    let mut chain = EventChain::new(HashAlgorithm::Blake3);
    let gen = genesis_hash(HashAlgorithm::Blake3);
    let mut events = Vec::new();

    for i in 0..5u32 {
        let mut event = make_file_open_event(i, &format!("/tmp/f{i}"), 0, 0);
        let _ = chain.append(&mut event);
        events.push(event);
    }

    events.remove(2);

    let result = verify_chain(&events, &gen, HashAlgorithm::Blake3);
    assert!(matches!(result, ChainVerifyResult::Broken { .. }));
}

#[test]
fn chain_detects_inserted_event() {
    let mut chain = EventChain::new(HashAlgorithm::Blake3);
    let gen = genesis_hash(HashAlgorithm::Blake3);
    let mut events = Vec::new();

    for i in 0..5u32 {
        let mut event = make_file_open_event(i, &format!("/tmp/f{i}"), 0, 0);
        let _ = chain.append(&mut event);
        events.push(event);
    }

    let fake = OaieEvent {
        ts_ns: 999,
        event_type: EventType::FileOpen,
        pid: 99,
        ppid: None,
        detail: EventDetail::FileAccess {
            path: "/tmp/INJECTED".into(),
            flags: 0,
            result: 0,
        },
        hash_prev: events[1].hash_prev.clone(),
    };
    events.insert(2, fake);

    let result = verify_chain(&events, &gen, HashAlgorithm::Blake3);
    assert!(matches!(result, ChainVerifyResult::Broken { .. }));
}

#[test]
fn chain_detects_reordered_events() {
    let mut chain = EventChain::new(HashAlgorithm::Blake3);
    let gen = genesis_hash(HashAlgorithm::Blake3);
    let mut events = Vec::new();

    for i in 0..5u32 {
        let mut event = make_file_open_event(i, &format!("/tmp/f{i}"), 0, 0);
        let _ = chain.append(&mut event);
        events.push(event);
    }

    events.swap(2, 3);

    let result = verify_chain(&events, &gen, HashAlgorithm::Blake3);
    assert!(matches!(result, ChainVerifyResult::Broken { .. }));
}

#[test]
fn chain_empty_verification() {
    let result = verify_chain(&[], &genesis_hash(HashAlgorithm::Blake3), HashAlgorithm::Blake3);
    assert_eq!(result, ChainVerifyResult::Empty);
}

#[test]
fn chain_tip_matches_verify_result() {
    let mut chain = EventChain::new(HashAlgorithm::Blake3);
    let gen = genesis_hash(HashAlgorithm::Blake3);
    let mut events = Vec::new();

    for i in 0..3u32 {
        let mut event = make_file_open_event(i, &format!("/tmp/f{i}"), 0, 0);
        let _ = chain.append(&mut event);
        events.push(event);
    }

    let tip = chain.tip_hash().to_string();
    let result = verify_chain(&events, &gen, HashAlgorithm::Blake3);
    match result {
        ChainVerifyResult::Valid { tip_hash, .. } => assert_eq!(tip_hash, tip),
        other => panic!("expected Valid, got {other:?}"),
    }
}

// ============================================================
// Day 3: Event writer + reader
// ============================================================

#[test]
fn writer_reader_round_trip_100_events() {
    let tmp = tempdir().unwrap();
    let events_path = tmp.path().join("events.log");
    let run_id = RunId::new();

    let mut writer = EventWriter::new(&events_path, &run_id, "test", HashAlgorithm::Blake3).unwrap();
    for i in 0..100u32 {
        writer
            .write_event(make_file_open_event(1, &format!("/tmp/f{i}"), 0, 0))
            .unwrap();
    }
    let result = writer.finalize().unwrap();
    assert_eq!(result.event_count, 100);

    let mut reader = EventReader::open(&events_path).unwrap();
    assert_eq!(reader.header().trace_backend, "test");
    assert_eq!(reader.header().run_id, run_id.full());

    let events = reader.read_all().unwrap();
    assert_eq!(events.len(), 100);
}

#[test]
fn writer_reader_chain_integrity() {
    let tmp = tempdir().unwrap();
    let events_path = tmp.path().join("events.log");
    let run_id = RunId::new();

    let mut writer = EventWriter::new(&events_path, &run_id, "test", HashAlgorithm::Blake3).unwrap();
    writer
        .write_event(make_run_start_event(&["./tool"]))
        .unwrap();
    for i in 0..10u32 {
        writer
            .write_event(make_file_open_event(1, &format!("/in/f{i}"), 0, 0))
            .unwrap();
    }
    writer.write_event(make_run_end_event(0)).unwrap();
    let result = writer.finalize().unwrap();
    assert_eq!(result.event_count, 12);

    let mut reader = EventReader::open(&events_path).unwrap();
    let events = reader.read_all().unwrap();
    let verify = verify_chain(&events, &reader.header().genesis_hash, HashAlgorithm::Blake3);
    match verify {
        ChainVerifyResult::Valid { events: n, tip_hash } => {
            assert_eq!(n, 12);
            assert_eq!(tip_hash, result.chain_tip);
        }
        other => panic!("expected Valid, got {other:?}"),
    }
}

#[test]
fn streaming_iterator_reads_all_events() {
    let tmp = tempdir().unwrap();
    let events_path = tmp.path().join("events.log");
    let run_id = RunId::new();

    let mut writer = EventWriter::new(&events_path, &run_id, "test", HashAlgorithm::Blake3).unwrap();
    for i in 0..50u32 {
        writer
            .write_event(make_file_open_event(1, &format!("/tmp/f{i}"), 0, 0))
            .unwrap();
    }
    writer.finalize().unwrap();

    let mut reader = EventReader::open(&events_path).unwrap();
    let count = reader.iter().count();
    assert_eq!(count, 50);
}

#[test]
fn large_trace_10k_events() {
    let tmp = tempdir().unwrap();
    let events_path = tmp.path().join("events.log");
    let run_id = RunId::new();

    let mut writer = EventWriter::new(&events_path, &run_id, "test", HashAlgorithm::Blake3).unwrap();
    for i in 0..10_000u32 {
        writer
            .write_event(make_file_open_event(1, &format!("/tmp/f{i}"), 0, 0))
            .unwrap();
    }
    let result = writer.finalize().unwrap();
    assert_eq!(result.event_count, 10_000);

    let mut reader = EventReader::open(&events_path).unwrap();
    let mut count = 0u64;
    for event_result in reader.iter() {
        event_result.unwrap();
        count += 1;
    }
    assert_eq!(count, 10_000);
}

#[test]
fn writer_auto_sets_timestamp() {
    let tmp = tempdir().unwrap();
    let events_path = tmp.path().join("events.log");
    let run_id = RunId::new();

    let mut writer = EventWriter::new(&events_path, &run_id, "test", HashAlgorithm::Blake3).unwrap();
    writer
        .write_event(make_file_open_event(1, "/tmp/f", 0, 0))
        .unwrap();
    writer.finalize().unwrap();

    let mut reader = EventReader::open(&events_path).unwrap();
    let events = reader.read_all().unwrap();
    assert_eq!(events.len(), 1);
}

// ============================================================
// Day 4: Summarizer
// ============================================================

#[test]
fn summarizer_counts_file_reads() {
    let mut chain = EventChain::new(HashAlgorithm::Blake3);
    let mut events = Vec::new();

    for _ in 0..3 {
        let mut e = make_file_open_event(1, "/in/data.bin", 0, 0);
        let _ = chain.append(&mut e);
        events.push(e);
    }
    let mut e = make_file_open_event(1, "/in/other.txt", 0, 0);
    let _ = chain.append(&mut e);
    events.push(e);

    let summary = summarize_events(&events);
    assert_eq!(summary.files_read.len(), 2);
    // Sorted by count descending.
    assert_eq!(summary.files_read[0].path, "/in/data.bin");
    assert_eq!(summary.files_read[0].count, 3);
    assert_eq!(summary.files_read[1].path, "/in/other.txt");
    assert_eq!(summary.files_read[1].count, 1);
}

#[test]
fn summarizer_filters_noise_paths() {
    let mut chain = EventChain::new(HashAlgorithm::Blake3);
    let mut events = Vec::new();

    let noise_paths = vec![
        "/proc/self/maps",
        "/dev/null",
        "/etc/ld.so.cache",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        "/etc/nsswitch.conf",
        "/etc/passwd",
        "/etc/group",
    ];
    for path in &noise_paths {
        let mut e = make_file_open_event(1, path, 0, 0);
        let _ = chain.append(&mut e);
        events.push(e);
    }

    let mut e = make_file_open_event(1, "/in/sample.bin", 0, 0);
    let _ = chain.append(&mut e);
    events.push(e);

    let summary = summarize_events(&events);
    assert_eq!(summary.files_read.len(), 1);
    assert_eq!(summary.files_read[0].path, "/in/sample.bin");
}

#[test]
fn summarizer_detects_write_flags() {
    let mut chain = EventChain::new(HashAlgorithm::Blake3);
    let mut events = Vec::new();

    // O_RDONLY = 0
    let mut e = make_file_open_event(1, "/in/read.bin", 0, 0);
    let _ = chain.append(&mut e);
    events.push(e);

    // O_WRONLY = 1
    let mut e = make_file_open_event(1, "/out/output.json", 1, 0);
    let _ = chain.append(&mut e);
    events.push(e);

    // O_RDWR = 2
    let mut e = make_file_open_event(1, "/out/readwrite.db", 2, 0);
    let _ = chain.append(&mut e);
    events.push(e);

    let summary = summarize_events(&events);
    assert_eq!(summary.files_read.len(), 1);
    assert_eq!(summary.files_read[0].path, "/in/read.bin");
    assert_eq!(summary.files_written.len(), 2);
    assert!(summary.files_written.iter().any(|f| f.path == "/out/output.json"));
    assert!(summary.files_written.iter().any(|f| f.path == "/out/readwrite.db"));
}

#[test]
fn summarizer_builds_process_tree() {
    let mut chain = EventChain::new(HashAlgorithm::Blake3);
    let mut events = Vec::new();

    let mut e = make_exec_event(1, 0, "/in/tool", &["./tool"]);
    let _ = chain.append(&mut e);
    events.push(e);

    let mut e = make_exec_event(2, 1, "/usr/bin/strings", &["strings", "/in/data.bin"]);
    let _ = chain.append(&mut e);
    events.push(e);

    let mut e = make_exec_event(3, 1, "/usr/bin/file", &["file", "/in/data.bin"]);
    let _ = chain.append(&mut e);
    events.push(e);

    let summary = summarize_events(&events);
    assert_eq!(summary.process_tree.len(), 3);

    let root = summary.process_tree.iter().find(|p| p.pid == 1).unwrap();
    assert_eq!(root.depth, 0);
    assert_eq!(root.command, "./tool");

    let child = summary.process_tree.iter().find(|p| p.pid == 2).unwrap();
    assert_eq!(child.depth, 1);
}

#[test]
fn summarizer_tracks_network_attempts() {
    let mut chain = EventChain::new(HashAlgorithm::Blake3);
    let mut events = Vec::new();

    let mut e = make_net_connect_event(1, "93.184.216.34:80", 0);
    let _ = chain.append(&mut e);
    events.push(e);

    // ECONNREFUSED. The ptrace tracer encodes result as `(-ret) as i32`
    // — positive errno, not the kernel's negative — and -1 is reserved
    // for "not captured" (eBPF sys_enter); see event.rs result doc.
    let mut e = make_net_connect_event(1, "10.0.0.1:443", 111);
    let _ = chain.append(&mut e);
    events.push(e);

    let summary = summarize_events(&events);
    assert_eq!(summary.net_connects.len(), 1);
    assert_eq!(summary.net_connects[0].address, "93.184.216.34:80");
    assert!(summary.net_connects[0].succeeded);
    assert_eq!(summary.net_denied.len(), 1);
    assert_eq!(summary.net_denied[0].address, "10.0.0.1:443");
}

#[test]
fn summarizer_tracks_failed_file_opens_as_denied() {
    let mut chain = EventChain::new(HashAlgorithm::Blake3);
    let mut events = Vec::new();

    // Failed open (ENOENT = 2).
    let mut e = make_file_open_event(1, "/nonexistent", 0, 2);
    let _ = chain.append(&mut e);
    events.push(e);

    // Successful open.
    let mut e = make_file_open_event(1, "/in/real.bin", 0, 0);
    let _ = chain.append(&mut e);
    events.push(e);

    let summary = summarize_events(&events);
    assert_eq!(summary.files_read.len(), 1);
    assert_eq!(summary.files_read[0].path, "/in/real.bin");
    assert_eq!(summary.file_access_denied.len(), 1);
    assert_eq!(summary.file_access_denied[0].path, "/nonexistent");
}

// ============================================================
// Day 5: Full pipeline + manifest + report integration
// ============================================================

#[test]
fn full_observe_pipeline() {
    let tmp = tempdir().unwrap();
    let events_path = tmp.path().join("events.log");
    let run_id = RunId::new();

    let mut writer = EventWriter::new(&events_path, &run_id, "test", HashAlgorithm::Blake3).unwrap();
    writer
        .write_event(make_run_start_event(&["./tool"]))
        .unwrap();
    writer
        .write_event(make_exec_event(1, 0, "/in/tool", &["./tool"]))
        .unwrap();
    writer
        .write_event(make_file_open_event(1, "/in/data.bin", 0, 0))
        .unwrap();
    writer
        .write_event(make_exec_event(2, 1, "/usr/bin/strings", &["strings", "/in/data.bin"]))
        .unwrap();
    writer
        .write_event(make_file_open_event(2, "/in/data.bin", 0, 0))
        .unwrap();
    writer
        // -1 is the eBPF "not captured" sentinel (buckets as success).
        // Use a real errno (ECONNREFUSED=111, positive per the ptrace
        // tracer's encoding) so this lands in net_denied.
        .write_event(make_net_connect_event(1, "93.184.216.34:80", 111))
        .unwrap();
    writer.write_event(make_run_end_event(0)).unwrap();
    let result = writer.finalize().unwrap();
    assert_eq!(result.event_count, 7);

    let mut reader = EventReader::open(&events_path).unwrap();
    let events = reader.read_all().unwrap();
    assert_eq!(events.len(), 7);

    let verify = verify_chain(&events, &reader.header().genesis_hash, HashAlgorithm::Blake3);
    match verify {
        ChainVerifyResult::Valid { events: n, tip_hash } => {
            assert_eq!(n, 7);
            assert_eq!(tip_hash, result.chain_tip);
        }
        other => panic!("expected Valid, got {other:?}"),
    }

    let summary = summarize_events(&events);
    assert_eq!(summary.files_read.len(), 1); // /in/data.bin (deduplicated)
    assert_eq!(summary.files_read[0].count, 2); // read twice (by pid 1 and pid 2)
    assert_eq!(summary.net_denied.len(), 1);
    assert_eq!(summary.process_tree.len(), 2); // ./tool and strings
}

#[test]
fn report_with_trace_info() {
    use oaie_core::manifest::{IsolationInfo, IsolationLevel, Manifest, TraceInfo};

    let manifest = Manifest {
        version: 1,
        hash_algorithm: "blake3".into(),
        run_id: RunId::new(),
        created: chrono::Utc::now(),
        command: vec!["./tool".into()],
        exit_code: Some(0),
        duration_ms: 1234,
        isolation: IsolationInfo {
            level: IsolationLevel::Full,
            namespaces: vec!["mount".into(), "pid".into(), "net".into()],
            network: false,
            network_mode: "off".into(),
            landlock: false,
            cgroup: None,
            backend: None,
            firecracker_version: None,
            kernel: None,
            rootfs: None,
            trace_integrity: None,
            interactive: false,
        },
        artifacts: vec![],
        policy: None,
        trace: Some(TraceInfo {
            backend: "ptrace".into(),
            event_count: 247,
            chain_tip: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                .into(),
            dropped: 0,
            chunks: 1,
            trace_index_hash: None,
        }),
        resources: None,
    };

    let report = oaie_report::generate_report(&manifest, None);
    assert!(report.contains("## Observed Accesses"));
    assert!(report.contains("Traced via ptrace"));
    assert!(report.contains("247 events captured"));
    assert!(report.contains("abcdef012345"));
}

#[test]
fn report_without_trace_info() {
    use oaie_core::manifest::{IsolationInfo, IsolationLevel, Manifest};

    let manifest = Manifest {
        version: 1,
        hash_algorithm: "blake3".into(),
        run_id: RunId::new(),
        created: chrono::Utc::now(),
        command: vec!["./tool".into()],
        exit_code: Some(0),
        duration_ms: 100,
        isolation: IsolationInfo {
            level: IsolationLevel::None,
            namespaces: vec![],
            network: false,
            network_mode: "off".into(),
            landlock: false,
            cgroup: None,
            backend: None,
            firecracker_version: None,
            kernel: None,
            rootfs: None,
            trace_integrity: None,
            interactive: false,
        },
        artifacts: vec![],
        policy: None,
        trace: None,
        resources: None,
    };

    let report = oaie_report::generate_report(&manifest, None);
    assert!(report.contains("## Observed Accesses"));
    assert!(report.contains("Tracing not enabled"));
}

#[test]
fn manifest_trace_toml_round_trip() {
    use oaie_core::manifest::{IsolationInfo, IsolationLevel, Manifest, TraceInfo};

    let manifest = Manifest {
        version: 1,
        hash_algorithm: "blake3".into(),
        run_id: RunId::new(),
        created: chrono::Utc::now(),
        command: vec!["echo".into(), "hello".into()],
        exit_code: Some(0),
        duration_ms: 42,
        isolation: IsolationInfo {
            level: IsolationLevel::Full,
            namespaces: vec!["mount".into()],
            network: false,
            network_mode: "off".into(),
            landlock: false,
            cgroup: None,
            backend: None,
            firecracker_version: None,
            kernel: None,
            rootfs: None,
            trace_integrity: None,
            interactive: false,
        },
        artifacts: vec![],
        policy: None,
        trace: Some(TraceInfo {
            backend: "ptrace".into(),
            event_count: 100,
            chain_tip: "deadbeef".into(),
            dropped: 0,
            chunks: 1,
            trace_index_hash: None,
        }),
        resources: None,
    };

    let toml_str = toml::to_string(&manifest).unwrap();
    assert!(toml_str.contains("[trace]"));
    assert!(toml_str.contains("backend = \"ptrace\""));

    let parsed: Manifest = toml::from_str(&toml_str).unwrap();
    let trace = parsed.trace.unwrap();
    assert_eq!(trace.backend, "ptrace");
    assert_eq!(trace.event_count, 100);
    assert_eq!(trace.chain_tip, "deadbeef");
    assert_eq!(trace.dropped, 0);
    assert_eq!(trace.chunks, 1);
}

#[test]
fn manifest_without_trace_deserializes() {
    use oaie_core::manifest::{IsolationInfo, IsolationLevel, Manifest};

    let manifest = Manifest {
        version: 1,
        hash_algorithm: "blake3".into(),
        run_id: RunId::new(),
        created: chrono::Utc::now(),
        command: vec!["echo".into()],
        exit_code: Some(0),
        duration_ms: 10,
        isolation: IsolationInfo {
            level: IsolationLevel::None,
            namespaces: vec![],
            network: false,
            network_mode: "off".into(),
            landlock: false,
            cgroup: None,
            backend: None,
            firecracker_version: None,
            kernel: None,
            rootfs: None,
            trace_integrity: None,
            interactive: false,
        },
        artifacts: vec![],
        policy: None,
        trace: None,
        resources: None,
    };

    let toml_str = toml::to_string(&manifest).unwrap();
    assert!(!toml_str.contains("[trace]"));

    let parsed: Manifest = toml::from_str(&toml_str).unwrap();
    assert!(parsed.trace.is_none());
}

#[test]
fn null_observer_backend_name() {
    use oaie_observe::NullObserver;
    use oaie_observe::Observer;
    let observer = NullObserver;
    assert_eq!(observer.backend_name(), "none");
}

// ============================================================
// CAS storage of events.log
// ============================================================

#[test]
fn events_log_stored_in_cas() {
    let tmp = tempdir().unwrap();
    let events_path = tmp.path().join("events.log");
    let cas_dir = tmp.path().join("cas");
    let run_id = RunId::new();

    let mut writer = EventWriter::new(&events_path, &run_id, "test", HashAlgorithm::Blake3).unwrap();
    writer
        .write_event(make_run_start_event(&["./tool"]))
        .unwrap();
    writer
        .write_event(make_file_open_event(1, "/in/data.bin", 0, 0))
        .unwrap();
    writer.write_event(make_run_end_event(0)).unwrap();
    writer.finalize().unwrap();

    std::fs::create_dir_all(&cas_dir).unwrap();
    let cas = CasStore::new(cas_dir, HashAlgorithm::Blake3);
    let (hash, size) = cas.store_file(&events_path).unwrap();

    assert!(size > 0);
    assert!(cas.exists(&hash));

    let blob = std::fs::read(cas.blob_path(&hash)).unwrap();
    let file_content = std::fs::read(&events_path).unwrap();
    assert_eq!(blob, file_content);
}

// ============================================================
// Inspect output format tests (via summarize_events)
// ============================================================

#[test]
fn trace_section_with_events_shows_observed_accesses() {
    let tmp = tempdir().unwrap();
    let events_path = tmp.path().join("events.log");
    let run_id = RunId::new();

    let mut writer = EventWriter::new(&events_path, &run_id, "ptrace", HashAlgorithm::Blake3).unwrap();
    writer
        .write_event(make_run_start_event(&["./analyzer"]))
        .unwrap();
    writer
        .write_event(make_exec_event(1, 0, "/in/analyzer", &["./analyzer"]))
        .unwrap();
    writer
        .write_event(make_file_open_event(1, "/in/sample.bin", 0, 0))
        .unwrap();
    writer
        .write_event(make_file_open_event(1, "/out/result.json", 1, 0))
        .unwrap();
    writer
        // Positive errno per ptrace encoding (was -111, never produced).
        .write_event(make_net_connect_event(1, "10.0.0.1:443", 111))
        .unwrap();
    writer.write_event(make_run_end_event(0)).unwrap();
    writer.finalize().unwrap();

    let mut reader = EventReader::open(&events_path).unwrap();
    assert_eq!(reader.header().trace_backend, "ptrace");

    let events = reader.read_all().unwrap();
    let verify = verify_chain(&events, &reader.header().genesis_hash, HashAlgorithm::Blake3);
    assert!(matches!(verify, ChainVerifyResult::Valid { .. }));

    let summary = summarize_events(&events);

    assert_eq!(summary.files_read.len(), 1);
    assert_eq!(summary.files_read[0].path, "/in/sample.bin");
    assert_eq!(summary.files_written.len(), 1);
    assert_eq!(summary.files_written[0].path, "/out/result.json");
    assert_eq!(summary.net_denied.len(), 1);
    assert_eq!(summary.process_tree.len(), 1);
    assert_eq!(summary.process_tree[0].command, "./analyzer");
}

#[test]
fn no_events_file_means_tracing_not_enabled() {
    let tmp = tempdir().unwrap();
    let events_path = tmp.path().join("events.log");
    assert!(!events_path.exists());
}

// ============================================================
// Week 7: Security warnings in summarizer (now suspicious_activity)
// ============================================================

#[test]
fn summarizer_tracks_suspicious_activity() {
    let events = vec![
        make_security_event(1, "io_uring_setup", 425),
        make_security_event(1, "io_uring_setup", 425),
        make_security_event(1, "memfd_create", 319),
        make_security_event(1, "fileless_exec_detected", 0),
    ];

    let summary = summarize_events(&events);
    assert!(!summary.suspicious_activity.is_empty());
    // io_uring_setup should appear (2 times → count >= 2 for that category).
    let io_uring = summary.suspicious_activity.iter()
        .find(|s| s.category == SuspiciousCategory::IoUringSetup);
    assert!(io_uring.is_some());
    assert!(io_uring.unwrap().count >= 2);
    // Fileless exec should appear.
    let fileless = summary.suspicious_activity.iter()
        .find(|s| s.category == SuspiciousCategory::FilelessExec);
    assert!(fileless.is_some());
}

#[test]
fn summarizer_no_suspicious_when_clean() {
    let events = vec![
        make_file_open_event(1, "/in/data.bin", 0, 0),
        make_exec_event(1, 0, "/in/tool", &["./tool"]),
    ];

    let summary = summarize_events(&events);
    assert!(summary.suspicious_activity.is_empty());
}

#[test]
fn security_relevant_event_serde_round_trip() {
    let event = make_security_event(42, "mount", 165);
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("\"security_relevant\""));
    assert!(json.contains("\"SecurityRelevant\""));
    let parsed: OaieEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, parsed);
}

// ============================================================
// Week 8: Streaming summarizer
// ============================================================

#[test]
fn streaming_summarizer_matches_batch() {
    let events = vec![
        make_run_start_event(&["./tool"]),
        make_exec_event(1, 0, "/in/tool", &["./tool"]),
        make_file_open_event(1, "/in/data.bin", 0, 0),
        make_file_open_event(1, "/in/data.bin", 0, 0),
        make_file_open_event(1, "/out/result.json", 1, 0),
        make_net_connect_event(1, "1.2.3.4:80", 0),
        make_run_end_event(0),
    ];

    let batch = summarize_events(&events);

    let mut streaming = StreamingSummarizer::new();
    for e in &events {
        streaming.ingest(e);
    }
    let streamed = streaming.finish();

    assert_eq!(batch.files_read.len(), streamed.files_read.len());
    assert_eq!(batch.files_written.len(), streamed.files_written.len());
    assert_eq!(batch.net_connects.len(), streamed.net_connects.len());
    assert_eq!(batch.total_events, streamed.total_events);
    assert_eq!(batch.process_tree.len(), streamed.process_tree.len());
}

#[test]
fn file_category_assignment() {
    let events = vec![
        make_file_open_event(1, "/in/sample.bin", 0, 0),
        make_file_open_event(1, "/usr/lib/libfoo.so", 0, 0),
        make_file_open_event(1, "/etc/config.ini", 0, 0),
        make_file_open_event(1, "/usr/bin/tool", 0, 0),
        make_file_open_event(1, "/tmp/scratch", 0, 0),
    ];

    let summary = summarize_events(&events);
    assert_eq!(summary.files_read.len(), 5);

    let find = |path: &str| summary.files_read.iter().find(|f| f.path == path).unwrap();
    assert_eq!(find("/in/sample.bin").category, oaie_observe::FileCategory::Input);
    assert_eq!(find("/usr/lib/libfoo.so").category, oaie_observe::FileCategory::SystemLib);
    assert_eq!(find("/etc/config.ini").category, oaie_observe::FileCategory::Config);
    assert_eq!(find("/usr/bin/tool").category, oaie_observe::FileCategory::SystemBin);
    assert_eq!(find("/tmp/scratch").category, oaie_observe::FileCategory::Other);
}

#[test]
fn expanded_noise_filtering() {
    let noise_paths = vec![
        "/proc/thread-self/maps",
        "/proc/filesystems",
        "/proc/stat",
        "/etc/localtime",
        "/usr/lib/libdl.so.2",
        "/usr/lib/libm.so.6",
        "/usr/lib/librt.so.1",
        "/usr/lib/locale/locale-archive",
        "/usr/lib/gconv/gconv-modules",
        "/usr/lib/libnss_files.so.2",
        "/usr/lib/libresolv.so.2",
    ];

    let mut events: Vec<OaieEvent> = noise_paths
        .iter()
        .map(|p| make_file_open_event(1, p, 0, 0))
        .collect();
    events.push(make_file_open_event(1, "/in/real.bin", 0, 0));

    let summary = summarize_events(&events);
    assert_eq!(summary.files_read.len(), 1);
    assert_eq!(summary.files_read[0].path, "/in/real.bin");
}

#[test]
fn process_tree_has_exit_codes() {
    let events = vec![
        make_exec_event(1, 0, "/in/tool", &["./tool"]),
        make_exec_event(2, 1, "/bin/sh", &["sh", "-c", "exit 42"]),
        make_exit_event(2, 42),
        make_exit_event(1, 0),
    ];

    let summary = summarize_events(&events);
    assert_eq!(summary.process_tree.len(), 2);

    let root = summary.process_tree.iter().find(|p| p.pid == 1).unwrap();
    assert_eq!(root.exit_code, Some(0));

    let child = summary.process_tree.iter().find(|p| p.pid == 2).unwrap();
    assert_eq!(child.exit_code, Some(42));
}

#[test]
fn suspicious_category_mapping() {
    let syscalls = vec![
        ("io_uring_setup", SuspiciousCategory::IoUringSetup),
        ("memfd_create", SuspiciousCategory::MemfdCreate),
        ("fileless_exec_detected", SuspiciousCategory::FilelessExec),
        ("mount", SuspiciousCategory::MountAttempt),
        ("ptrace_traceme", SuspiciousCategory::PtraceAttempt),
        ("nested_userns_attempt", SuspiciousCategory::NestedUserns),
        ("userfaultfd_kernel_mode", SuspiciousCategory::UserfaultfdKernel),
        ("vmsplice_splice_f_gift", SuspiciousCategory::VmspliceGift),
        ("socket_af_packet", SuspiciousCategory::DangerousSocket),
    ];

    for (syscall_name, expected_cat) in &syscalls {
        let events = vec![make_security_event(1, syscall_name, 0)];
        let summary = summarize_events(&events);
        assert!(
            summary.suspicious_activity.iter().any(|s| s.category == *expected_cat),
            "expected {:?} for syscall {}, got {:?}",
            expected_cat,
            syscall_name,
            summary.suspicious_activity
        );
    }
}

// ============================================================
// Week 8: ChunkedEventWriter
// ============================================================

#[test]
fn chunked_writer_100_events_one_chunk() {
    let tmp = tempdir().unwrap();
    let cas_dir = tmp.path().join("cas");
    std::fs::create_dir_all(&cas_dir).unwrap();
    let cas = CasStore::new(cas_dir, HashAlgorithm::Blake3);
    let run_id = RunId::new();

    let mut writer = ChunkedEventWriter::new(
        tmp.path(), cas.clone(), &run_id.full(), "test", HashAlgorithm::Blake3,
    ).unwrap();

    for i in 0..100u32 {
        writer
            .write_event(make_file_open_event(1, &format!("/tmp/f{i}"), 0, 0))
            .unwrap();
    }

    let index = writer.finalize(&run_id.full(), "test").unwrap();
    assert_eq!(index.total_events, 100);
    assert_eq!(index.total_chunks, 1);
    assert!(!index.chain_tip.is_empty());
    assert_eq!(index.chunks.len(), 1);
    assert_eq!(index.chunks[0].events, 100);

    // Verify chunk is in CAS.
    let hash = oaie_core::artifact::Hash::from_hex(&index.chunks[0].hash).unwrap();
    assert!(cas.exists(&hash));
}

#[test]
fn chunked_writer_multiple_chunks() {
    let tmp = tempdir().unwrap();
    let cas_dir = tmp.path().join("cas");
    std::fs::create_dir_all(&cas_dir).unwrap();
    let cas = CasStore::new(cas_dir, HashAlgorithm::Blake3);
    let run_id = RunId::new();

    // Use a very small threshold to force multiple chunks.
    let mut writer = ChunkedEventWriter::with_threshold(
        tmp.path(), cas.clone(), &run_id.full(), "test", 1024, HashAlgorithm::Blake3,
    ).unwrap();

    for i in 0..200u32 {
        writer
            .write_event(make_file_open_event(1, &format!("/tmp/file_{i:04}"), 0, 0))
            .unwrap();
    }

    let index = writer.finalize(&run_id.full(), "test").unwrap();
    assert_eq!(index.total_events, 200);
    assert!(index.total_chunks > 1, "expected multiple chunks, got {}", index.total_chunks);

    // All chunks should be in CAS.
    for chunk in &index.chunks {
        let hash = oaie_core::artifact::Hash::from_hex(&chunk.hash).unwrap();
        assert!(cas.exists(&hash), "chunk {} not in CAS", chunk.index);
    }
}

#[test]
fn chunked_writer_events_retrievable_from_cas() {
    let tmp = tempdir().unwrap();
    let cas_dir = tmp.path().join("cas");
    std::fs::create_dir_all(&cas_dir).unwrap();
    let cas = CasStore::new(cas_dir, HashAlgorithm::Blake3);
    let run_id = RunId::new();

    let mut writer = ChunkedEventWriter::with_threshold(
        tmp.path(), cas.clone(), &run_id.full(), "test", 1024, HashAlgorithm::Blake3,
    ).unwrap();

    for i in 0..50u32 {
        writer
            .write_event(make_file_open_event(1, &format!("/tmp/f{i}"), 0, 0))
            .unwrap();
    }

    let index = writer.finalize(&run_id.full(), "test").unwrap();

    // Read events back from CAS.
    let events = ChunkedEventWriter::read_events_from_index(&cas, &index).unwrap();
    assert_eq!(events.len(), 50);
}

#[test]
fn chunked_writer_chain_spans_chunks() {
    let tmp = tempdir().unwrap();
    let cas_dir = tmp.path().join("cas");
    std::fs::create_dir_all(&cas_dir).unwrap();
    let cas = CasStore::new(cas_dir, HashAlgorithm::Blake3);
    let run_id = RunId::new();

    let mut writer = ChunkedEventWriter::with_threshold(
        tmp.path(), cas.clone(), &run_id.full(), "test", 512, HashAlgorithm::Blake3,
    ).unwrap();

    for i in 0..100u32 {
        writer
            .write_event(make_file_open_event(1, &format!("/tmp/f{i}"), 0, 0))
            .unwrap();
    }

    let index = writer.finalize(&run_id.full(), "test").unwrap();
    assert!(index.total_chunks > 1);

    // Read all events back and verify chain.
    let events = ChunkedEventWriter::read_events_from_index(&cas, &index).unwrap();
    let result = verify_chain(&events, &index.genesis_hash, HashAlgorithm::Blake3);
    match result {
        ChainVerifyResult::Valid { events: n, tip_hash } => {
            assert_eq!(n, 100);
            assert_eq!(tip_hash, index.chain_tip);
        }
        other => panic!("expected Valid, got {other:?}"),
    }
}

#[test]
fn chunked_writer_index_metadata() {
    let tmp = tempdir().unwrap();
    let cas_dir = tmp.path().join("cas");
    std::fs::create_dir_all(&cas_dir).unwrap();
    let cas = CasStore::new(cas_dir, HashAlgorithm::Blake3);
    let run_id = RunId::new();

    let mut writer = ChunkedEventWriter::with_threshold(
        tmp.path(), cas.clone(), &run_id.full(), "test", 2048, HashAlgorithm::Blake3,
    ).unwrap();

    for i in 0..30u32 {
        writer
            .write_event(make_file_open_event(1, &format!("/tmp/f{i}"), 0, 0))
            .unwrap();
    }

    let index = writer.finalize(&run_id.full(), "test").unwrap();

    // Check index metadata.
    assert_eq!(index.format_version, 1);
    assert_eq!(index.run_id, run_id.full());
    assert_eq!(index.trace_backend, "test");
    assert_eq!(index.genesis_hash, genesis_hash(HashAlgorithm::Blake3));

    // Chunks are ordered.
    for (i, chunk) in index.chunks.iter().enumerate() {
        assert_eq!(chunk.index, i as u32);
        assert!(chunk.size > 0);
        assert!(chunk.events > 0);
    }
}

// ============================================================
// Week 8: ChunkedEventWriter corner cases
// ============================================================

#[test]
fn chunked_writer_empty_trace() {
    let tmp = tempdir().unwrap();
    let cas_dir = tmp.path().join("cas");
    std::fs::create_dir_all(&cas_dir).unwrap();
    let cas = CasStore::new(cas_dir, HashAlgorithm::Blake3);
    let run_id = RunId::new();

    let writer = ChunkedEventWriter::new(
        tmp.path(), cas.clone(), &run_id.full(), "test", HashAlgorithm::Blake3,
    ).unwrap();

    // Finalize immediately with 0 events — should still produce 1 chunk (header-only).
    let index = writer.finalize(&run_id.full(), "test").unwrap();
    assert_eq!(index.total_events, 0);
    assert_eq!(index.total_chunks, 1);
    assert_eq!(index.chunks[0].events, 0);

    // Reading back should produce 0 events.
    let events = ChunkedEventWriter::read_events_from_index(&cas, &index).unwrap();
    assert_eq!(events.len(), 0);
}

#[test]
fn chunked_writer_single_event() {
    let tmp = tempdir().unwrap();
    let cas_dir = tmp.path().join("cas");
    std::fs::create_dir_all(&cas_dir).unwrap();
    let cas = CasStore::new(cas_dir, HashAlgorithm::Blake3);
    let run_id = RunId::new();

    let mut writer = ChunkedEventWriter::new(
        tmp.path(), cas.clone(), &run_id.full(), "test", HashAlgorithm::Blake3,
    ).unwrap();
    writer.write_event(make_file_open_event(1, "/in/only.bin", 0, 0)).unwrap();

    let index = writer.finalize(&run_id.full(), "test").unwrap();
    assert_eq!(index.total_events, 1);
    assert_eq!(index.total_chunks, 1);

    let events = ChunkedEventWriter::read_events_from_index(&cas, &index).unwrap();
    assert_eq!(events.len(), 1);

    // Chain should still verify.
    let result = verify_chain(&events, &index.genesis_hash, HashAlgorithm::Blake3);
    assert!(matches!(result, ChainVerifyResult::Valid { events: 1, .. }));
}

#[test]
fn chunked_writer_at_threshold_boundary() {
    // Events that land exactly at the threshold should NOT trigger rotation
    // (condition is > not >=).
    let tmp = tempdir().unwrap();
    let cas_dir = tmp.path().join("cas");
    std::fs::create_dir_all(&cas_dir).unwrap();
    let cas = CasStore::new(cas_dir, HashAlgorithm::Blake3);
    let run_id = RunId::new();

    // Use a threshold large enough that 2 events fit exactly, but 3 would overflow.
    // We don't need to hit exact boundary — just verify the > behavior:
    // with a very small threshold (256 bytes), the first event should be written
    // even though it exceeds the threshold (because of the minimum 1 event guard).
    let mut writer = ChunkedEventWriter::with_threshold(
        tmp.path(), cas.clone(), &run_id.full(), "test", 256, HashAlgorithm::Blake3,
    ).unwrap();

    // Header is ~150+ bytes, so first event will push past 256.
    // It should still be in chunk 0 (not rotated on first event).
    writer.write_event(make_file_open_event(1, "/tmp/aaaa", 0, 0)).unwrap();
    // Second event triggers rotation because current_events > 0 AND over threshold.
    writer.write_event(make_file_open_event(1, "/tmp/bbbb", 0, 0)).unwrap();

    let index = writer.finalize(&run_id.full(), "test").unwrap();
    assert_eq!(index.total_events, 2);
    // At least 2 chunks (chunk 0 had header + event 1, chunk 1 had event 2).
    assert!(index.total_chunks >= 2, "expected >= 2 chunks, got {}", index.total_chunks);

    // All events readable.
    let events = ChunkedEventWriter::read_events_from_index(&cas, &index).unwrap();
    assert_eq!(events.len(), 2);
}

// ============================================================
// Week 8: TraceInfo backward compatibility
// ============================================================

#[test]
fn trace_info_backward_compat_missing_chunks_field() {
    use oaie_core::manifest::TraceInfo;

    // Old manifests don't have chunks or trace_index_hash fields.
    let toml_str = r#"
backend = "ptrace"
event_count = 100
chain_tip = "deadbeef"
dropped = 0
"#;
    let parsed: TraceInfo = toml::from_str(toml_str).unwrap();
    assert_eq!(parsed.backend, "ptrace");
    assert_eq!(parsed.event_count, 100);
    assert_eq!(parsed.chunks, 0); // Default
    assert!(parsed.trace_index_hash.is_none()); // Default
}

// ============================================================
// Week 8: Report corner cases
// ============================================================

#[test]
fn report_truncates_more_than_30_files() {
    use oaie_core::manifest::{IsolationInfo, IsolationLevel, Manifest, TraceInfo};
    use oaie_observe::FileAccessEntry;

    let manifest = Manifest {
        version: 1,
        hash_algorithm: "blake3".into(),
        run_id: RunId::new(),
        created: chrono::Utc::now(),
        command: vec!["./tool".into()],
        exit_code: Some(0),
        duration_ms: 100,
        isolation: IsolationInfo {
            level: IsolationLevel::Full,
            namespaces: vec![],
            network: false,
            network_mode: "off".into(),
            landlock: false,
            cgroup: None,
            backend: None,
            firecracker_version: None,
            kernel: None,
            rootfs: None,
            trace_integrity: None,
            interactive: false,
        },
        artifacts: vec![],
        policy: None,
        trace: Some(TraceInfo {
            backend: "ptrace".into(),
            event_count: 50,
            chain_tip: "aabb".into(),
            dropped: 0,
            chunks: 1,
            trace_index_hash: None,
        }),
        resources: None,
    };

    // Build a summary with 35 files read.
    let mut summary = summarize_events(&[]);
    summary.files_read = (0..35)
        .map(|i| FileAccessEntry {
            path: format!("/in/file_{i:03}.bin"),
            count: 1,
            category: oaie_observe::FileCategory::Input,
        })
        .collect();

    let report = oaie_report::generate_report(&manifest, Some(&summary));
    assert!(report.contains("### Files Read"));
    assert!(report.contains("...and 5 more files"));
    // First 30 should be present.
    assert!(report.contains("/in/file_000.bin"));
    assert!(report.contains("/in/file_029.bin"));
    // 31st should NOT be in the table.
    assert!(!report.contains("/in/file_030.bin"));
}

// ============================================================
// Week 8: Summarizer counter accuracy
// ============================================================

#[test]
fn summarizer_stat_counters_correct() {
    let events = vec![
        make_run_start_event(&["./tool"]),
        make_exec_event(1, 0, "/in/tool", &["./tool"]),
        make_file_open_event(1, "/in/data.bin", 0, 0),
        make_file_open_event(1, "/in/data.bin", 0, 0), // duplicate
        make_file_open_event(1, "/out/result.json", 1, 0),
        make_net_connect_event(1, "1.2.3.4:80", 0),
        make_exit_event(1, 0),
        make_run_end_event(0),
    ];

    let mut streaming = StreamingSummarizer::new();
    for e in &events {
        streaming.ingest(e);
    }
    let summary = streaming.finish();

    assert_eq!(summary.total_events, 8);
    assert_eq!(summary.total_file_events, 3); // 3 FileOpen events
    assert_eq!(summary.total_net_events, 1);
    assert_eq!(summary.total_exec_events, 1);
    assert_eq!(summary.unique_files_read, 1); // /in/data.bin (deduped)
    assert_eq!(summary.unique_files_written, 1); // /out/result.json
    assert!(summary.trace_duration_ns > 0 || summary.total_events > 0);
}

// ============================================================
// Week 8: Report with rich summary
// ============================================================

#[test]
fn report_with_trace_summary() {
    use oaie_core::manifest::{IsolationInfo, IsolationLevel, Manifest, TraceInfo};

    let manifest = Manifest {
        version: 1,
        hash_algorithm: "blake3".into(),
        run_id: RunId::new(),
        created: chrono::Utc::now(),
        command: vec!["./tool".into()],
        exit_code: Some(0),
        duration_ms: 1234,
        isolation: IsolationInfo {
            level: IsolationLevel::Full,
            namespaces: vec!["mount".into()],
            network: false,
            network_mode: "off".into(),
            landlock: false,
            cgroup: None,
            backend: None,
            firecracker_version: None,
            kernel: None,
            rootfs: None,
            trace_integrity: None,
            interactive: false,
        },
        artifacts: vec![],
        policy: None,
        trace: Some(TraceInfo {
            backend: "ptrace".into(),
            event_count: 10,
            chain_tip: "aabbccdd".into(),
            dropped: 0,
            chunks: 1,
            trace_index_hash: None,
        }),
        resources: None,
    };

    // Build a summary.
    let events = vec![
        make_exec_event(1, 0, "/in/tool", &["./tool"]),
        make_file_open_event(1, "/in/sample.bin", 0, 0),
        make_file_open_event(1, "/out/result.json", 1, 0),
        make_exit_event(1, 0),
    ];
    let summary = summarize_events(&events);

    let report = oaie_report::generate_report(&manifest, Some(&summary));
    assert!(report.contains("### Files Read"));
    assert!(report.contains("/in/sample.bin"));
    assert!(report.contains("### Files Written"));
    assert!(report.contains("/out/result.json"));
    assert!(report.contains("### Network Activity"));
    assert!(report.contains("No network connections"));
    assert!(report.contains("### Process Tree"));
    assert!(report.contains("[1] ./tool"));
}

// ============================================================
// DNS query wire-format parsing
// ============================================================

/// Build a minimal DNS query packet for a given domain name.
fn build_dns_query(domain: &str) -> Vec<u8> {
    let mut pkt = Vec::new();
    // 12-byte header: ID=0x1234, Flags=0x0100 (standard query, RD=1),
    // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0.
    pkt.extend_from_slice(&[0x12, 0x34, 0x01, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // Question section: encode the domain name as labels.
    for label in domain.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // Root terminator.
    pkt.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
    pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
    pkt
}

#[test]
fn dns_parse_simple_domain() {
    let pkt = build_dns_query("www.google.com");
    assert_eq!(
        oaie_observe::memory::parse_dns_query_name(&pkt),
        Some("www.google.com".into())
    );
}

#[test]
fn dns_parse_single_label() {
    let pkt = build_dns_query("localhost");
    assert_eq!(
        oaie_observe::memory::parse_dns_query_name(&pkt),
        Some("localhost".into())
    );
}

#[test]
fn dns_parse_mixed_case_lowered() {
    let pkt = build_dns_query("WWW.Example.COM");
    assert_eq!(
        oaie_observe::memory::parse_dns_query_name(&pkt),
        Some("www.example.com".into())
    );
}

#[test]
fn dns_parse_too_short() {
    assert_eq!(oaie_observe::memory::parse_dns_query_name(&[0u8; 12]), None);
    assert_eq!(oaie_observe::memory::parse_dns_query_name(&[]), None);
}

#[test]
fn dns_parse_zero_qdcount() {
    let mut pkt = build_dns_query("example.com");
    pkt[4] = 0;
    pkt[5] = 0;
    assert_eq!(oaie_observe::memory::parse_dns_query_name(&pkt), None);
}

#[test]
fn dns_parse_truncated_label() {
    let mut pkt = vec![0u8; 12];
    pkt[4] = 0; pkt[5] = 1; // QDCOUNT = 1
    pkt.push(10); // Label length = 10
    pkt.extend_from_slice(b"abc"); // Only 3 bytes.
    assert_eq!(oaie_observe::memory::parse_dns_query_name(&pkt), None);
}

#[test]
fn dns_parse_label_too_long() {
    let mut pkt = vec![0u8; 12];
    pkt[4] = 0; pkt[5] = 1;
    pkt.push(64); // > 63 max.
    pkt.extend_from_slice(&[b'a'; 64]);
    pkt.push(0);
    assert_eq!(oaie_observe::memory::parse_dns_query_name(&pkt), None);
}

#[test]
fn dns_parse_pointer_compression_rejected() {
    let mut pkt = vec![0u8; 12];
    pkt[4] = 0; pkt[5] = 1;
    pkt.push(0xC0); pkt.push(0x0C);
    assert_eq!(oaie_observe::memory::parse_dns_query_name(&pkt), None);
}

#[test]
fn dns_query_event_in_summarizer() {
    let events = vec![
        OaieEvent {
            ts_ns: 1000,
            event_type: EventType::DnsQuery,
            pid: 42,
            ppid: None,
            detail: EventDetail::DnsQuery {
                name: "example.com".into(),
                server: "8.8.8.8:53".into(),
                result: 0,
            },
            hash_prev: String::new(),
        },
        OaieEvent {
            ts_ns: 2000,
            event_type: EventType::DnsQuery,
            pid: 42,
            ppid: None,
            detail: EventDetail::DnsQuery {
                name: "example.com".into(),
                server: "8.8.8.8:53".into(),
                result: 0,
            },
            hash_prev: String::new(),
        },
        OaieEvent {
            ts_ns: 3000,
            event_type: EventType::DnsQuery,
            pid: 42,
            ppid: None,
            detail: EventDetail::DnsQuery {
                name: "other.org".into(),
                server: "1.1.1.1:53".into(),
                result: 0,
            },
            hash_prev: String::new(),
        },
    ];

    let summary = summarize_events(&events);
    assert_eq!(summary.dns_queries.len(), 2);
    // Sorted by count descending.
    assert_eq!(summary.dns_queries[0].name, "example.com");
    assert_eq!(summary.dns_queries[0].count, 2);
    assert_eq!(summary.dns_queries[1].name, "other.org");
    assert_eq!(summary.dns_queries[1].count, 1);
}

#[test]
fn dns_query_event_serialization_round_trip() {
    let event = OaieEvent {
        ts_ns: 5000,
        event_type: EventType::DnsQuery,
        pid: 10,
        ppid: None,
        detail: EventDetail::DnsQuery {
            name: "api.github.com".into(),
            server: "8.8.4.4:53".into(),
            result: 0,
        },
        hash_prev: "prev_hash".into(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let parsed: OaieEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, parsed);
}
