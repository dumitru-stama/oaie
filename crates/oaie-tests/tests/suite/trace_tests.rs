//! Integration tests for ptrace-traced runs.
//!
//! These tests run actual sandboxed commands with --trace=ptrace enabled,
//! verifying the full pipeline: sandbox + ptrace tracer + chunked event writer +
//! CAS storage + manifest + inspect.
//!
//! All tests skip gracefully if user namespaces are not available.

use std::io::Read;

use oaie_cas::store::CasStore;
use oaie_cli::runner::Runner;
use oaie_core::artifact::ArtifactType;
use oaie_core::hash_algo::HashAlgorithm;
use oaie_core::job::TraceMode;
use oaie_db::{OaieDb, RunStatus};
use oaie_observe::{verify_chain, ChainVerifyResult, ChunkedEventWriter, EventType, TraceIndex};
use oaie_tests::{default_resolved_policy, setup_store, traced_sandboxed_job, userns_available};

/// Build a resolved policy with tracing enabled.
fn traced_policy() -> oaie_cli::policy_resolve::ResolvedPolicy {
    let mut policy = default_resolved_policy(Some(std::time::Duration::from_secs(30)));
    policy.trace = TraceMode::Ptrace;
    policy
}

/// Load the TraceIndex from the run directory's trace_index.json.
fn load_trace_index(run_dir: &std::path::Path) -> TraceIndex {
    let index_path = run_dir.join("trace_index.json");
    let content = std::fs::read_to_string(&index_path)
        .expect("trace_index.json should exist in run directory");
    serde_json::from_str(&content).expect("trace_index.json should be valid JSON")
}

/// Read all events from a traced run using the chunked storage.
fn read_trace_events(
    run_dir: &std::path::Path,
    cas: &CasStore,
) -> (Vec<oaie_observe::OaieEvent>, TraceIndex) {
    let index = load_trace_index(run_dir);
    let events = ChunkedEventWriter::read_events_from_index(cas, &index)
        .expect("should read events from CAS chunks");
    (events, index)
}

#[test]
fn traced_run_echo() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = traced_sandboxed_job(&["echo", "traced hello"]);
    let policy = traced_policy();

    let result = runner.execute(&job, &policy, true, None).unwrap();

    assert_eq!(result.exit_code, 0);
    assert!(result.stdout_size > 0);

    // Verify stdout content.
    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let mut file = cas.open(&result.stdout_hash).unwrap();
    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();
    assert_eq!(content.trim(), "traced hello");

    // Verify DB record.
    let db = OaieDb::open(&store.db_path).unwrap();
    let run = db.get_latest_run().unwrap().unwrap();
    assert_eq!(run.status, RunStatus::Completed);
    assert_eq!(run.exit_code, Some(0));
}

#[test]
fn traced_run_produces_trace_index() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = traced_sandboxed_job(&["echo", "event test"]);
    let policy = traced_policy();

    let result = runner.execute(&job, &policy, true, None).unwrap();
    assert_eq!(result.exit_code, 0);

    // Should have a trace_index.json artifact.
    let db = OaieDb::open(&store.db_path).unwrap();
    let artifacts = db.list_artifacts(&result.run_id).unwrap();
    let trace_artifact = artifacts
        .iter()
        .find(|a| a.label == "trace_index.json")
        .expect("trace_index.json artifact should exist");
    assert_eq!(trace_artifact.artifact_type, ArtifactType::Trace.to_string());
    assert!(trace_artifact.size > 0);

    // Read events from chunked CAS storage.
    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let run_dir = store.runs_dir.join(result.run_id.full());
    let (events, index) = read_trace_events(&run_dir, &cas);

    assert_eq!(index.trace_backend, "ptrace");
    // At minimum: RunStart + some syscall events + RunEnd.
    assert!(events.len() >= 2, "expected at least RunStart + RunEnd, got {}", events.len());

    // First event should be RunStart.
    assert_eq!(events[0].event_type, EventType::RunStart);
    // Last event should be RunEnd.
    assert_eq!(events.last().unwrap().event_type, EventType::RunEnd);

    // Verify chain integrity.
    let verify = verify_chain(&events, &index.genesis_hash, HashAlgorithm::Blake3);
    match verify {
        ChainVerifyResult::Valid { events: n, .. } => {
            assert_eq!(n, events.len());
        }
        other => panic!("expected Valid chain, got {other:?}"),
    }
}

#[test]
fn traced_run_captures_file_access() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    // ls reads directory entries — should produce file access events.
    let job = traced_sandboxed_job(&["ls", "/in"]);
    let policy = traced_policy();

    let result = runner.execute(&job, &policy, true, None).unwrap();
    // ls /in may fail (empty dir) but should still produce trace events.

    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let run_dir = store.runs_dir.join(result.run_id.full());
    let (events, _index) = read_trace_events(&run_dir, &cas);

    // Should have ProcessExec events (ls gets exec'd).
    let exec_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == EventType::ProcessExec)
        .collect();
    assert!(!exec_events.is_empty(), "should observe at least one exec event");

    // Should have FileOpen events (ls opens directory entries).
    let file_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == EventType::FileOpen)
        .collect();
    // ls typically opens the directory and shared libraries.
    assert!(!file_events.is_empty(), "should observe file open events");
}

#[test]
fn traced_run_captures_process_exit() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = traced_sandboxed_job(&["true"]);
    let policy = traced_policy();

    let result = runner.execute(&job, &policy, true, None).unwrap();
    assert_eq!(result.exit_code, 0);

    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let run_dir = store.runs_dir.join(result.run_id.full());
    let (events, _index) = read_trace_events(&run_dir, &cas);

    // Should have ProcessExit events.
    let exit_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == EventType::ProcessExit)
        .collect();
    assert!(!exit_events.is_empty(), "should observe process exit events");
}

#[test]
fn traced_run_nonzero_exit_preserved() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = traced_sandboxed_job(&["sh", "-c", "exit 42"]);
    let policy = traced_policy();

    let result = runner.execute(&job, &policy, true, None).unwrap();
    assert_eq!(result.exit_code, 42);

    // DB should also record the nonzero exit code.
    let db = OaieDb::open(&store.db_path).unwrap();
    let run = db.get_latest_run().unwrap().unwrap();
    assert_eq!(run.exit_code, Some(42));
    assert_eq!(run.status, RunStatus::Completed);
}

#[test]
fn traced_run_manifest_has_trace_info() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = traced_sandboxed_job(&["echo", "manifest test"]);
    let policy = traced_policy();

    let result = runner.execute(&job, &policy, true, None).unwrap();
    assert_eq!(result.exit_code, 0);

    // Load and check manifest.
    let run_dir = store.runs_dir.join(result.run_id.full());
    let manifest = oaie_cas::store::read_manifest(&run_dir).unwrap();

    let trace = manifest.trace.expect("manifest should have trace info");
    assert_eq!(trace.backend, "ptrace");
    assert!(trace.event_count > 0, "should have captured events");
    assert!(!trace.chain_tip.is_empty(), "chain tip should be set");
    assert_eq!(trace.dropped, 0);
    assert!(trace.chunks >= 1, "should have at least 1 chunk");
    assert!(trace.trace_index_hash.is_some(), "should have trace_index_hash");
}

#[test]
fn traced_run_multi_process() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    // sh -c forks a child shell that runs the commands.
    let job = traced_sandboxed_job(&["sh", "-c", "echo a; echo b"]);
    let policy = traced_policy();

    let result = runner.execute(&job, &policy, true, None).unwrap();
    assert_eq!(result.exit_code, 0);

    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let run_dir = store.runs_dir.join(result.run_id.full());
    let (events, index) = read_trace_events(&run_dir, &cas);

    // Should observe exec events — at minimum the sh process.
    let exec_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == EventType::ProcessExec)
        .collect();
    assert!(!exec_events.is_empty(), "should observe exec events in multi-process run");

    // Verify chain integrity across all events.
    let verify = verify_chain(&events, &index.genesis_hash, HashAlgorithm::Blake3);
    assert!(matches!(verify, ChainVerifyResult::Valid { .. }));
}

#[test]
fn traced_run_with_output_file() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = traced_sandboxed_job(&["sh", "-c", "echo result > /out/test.txt"]);
    let policy = traced_policy();

    let result = runner.execute(&job, &policy, true, None).unwrap();
    assert_eq!(result.exit_code, 0);

    // Should have output artifact.
    assert!(!result.output_artifacts.is_empty(), "should capture output file");
    let output = &result.output_artifacts[0];
    assert_eq!(output.label, "output/test.txt");

    // Trace should capture the write.
    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let run_dir = store.runs_dir.join(result.run_id.full());
    let (events, _index) = read_trace_events(&run_dir, &cas);

    // Should have file open events for /out/test.txt.
    let write_events: Vec<_> = events
        .iter()
        .filter(|e| {
            matches!(
                &e.detail,
                oaie_observe::EventDetail::FileAccess { path, flags, .. }
                if path.contains("test.txt") && (*flags & 0x03) != 0 // O_WRONLY or O_RDWR
            )
        })
        .collect();
    assert!(!write_events.is_empty(), "should observe file write to /out/test.txt");
}

#[test]
fn traced_run_pipe_multiple_exits() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    // Pipe: sh forks children for both sides — should see >= 2 ProcessExit.
    let job = traced_sandboxed_job(&["sh", "-c", "echo hello | cat"]);
    let policy = traced_policy();

    let result = runner.execute(&job, &policy, true, None).unwrap();
    assert_eq!(result.exit_code, 0);

    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let run_dir = store.runs_dir.join(result.run_id.full());
    let (events, _index) = read_trace_events(&run_dir, &cas);

    let exit_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == EventType::ProcessExit)
        .collect();
    assert!(
        exit_events.len() >= 2,
        "pipe should produce >= 2 exit events, got {}",
        exit_events.len()
    );
}

#[test]
fn traced_run_many_children_no_orphans() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    // Run a loop that spawns several child processes.
    let job = traced_sandboxed_job(&["sh", "-c", "for i in 1 2 3 4 5; do true; done"]);
    let policy = traced_policy();

    let result = runner.execute(&job, &policy, true, None).unwrap();
    assert_eq!(result.exit_code, 0);

    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let run_dir = store.runs_dir.join(result.run_id.full());
    let (events, _index) = read_trace_events(&run_dir, &cas);

    // Verify no orphaned processes: every PID that exec'd should also have exited.
    let exec_pids: std::collections::HashSet<u32> = events
        .iter()
        .filter(|e| e.event_type == EventType::ProcessExec)
        .map(|e| e.pid)
        .collect();
    let exit_pids: std::collections::HashSet<u32> = events
        .iter()
        .filter(|e| e.event_type == EventType::ProcessExit)
        .map(|e| e.pid)
        .collect();

    for pid in &exec_pids {
        assert!(
            exit_pids.contains(pid),
            "PID {} started (exec) but never exited",
            pid
        );
    }
}

#[test]
fn traced_run_observes_file_read() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    // cat /etc/hostname reads a specific file — should see openat for it.
    let job = traced_sandboxed_job(&["cat", "/etc/hostname"]);
    let policy = traced_policy();

    let result = runner.execute(&job, &policy, true, None).unwrap();
    // May fail if /etc/hostname doesn't exist in sandbox, but trace should still capture the attempt.

    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let run_dir = store.runs_dir.join(result.run_id.full());
    let (events, _index) = read_trace_events(&run_dir, &cas);

    // Should see an openat for /etc/hostname (success or failure).
    let hostname_opens: Vec<_> = events
        .iter()
        .filter(|e| {
            matches!(
                &e.detail,
                oaie_observe::EventDetail::FileAccess { path, .. }
                if path.contains("hostname")
            )
        })
        .collect();
    assert!(
        !hostname_opens.is_empty(),
        "should observe openat for /etc/hostname"
    );
}
