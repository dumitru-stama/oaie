//! Shared test helpers for all OAIE tests.
//!
//! Provides setup functions for temp stores, databases, and job specs
//! used across multiple test modules.

use std::time::Duration;

use chrono::{DateTime, Utc};
use oaie_cas::store::CasStore;
use oaie_cli::policy_resolve::ResolvedPolicy;
use oaie_core::config::OaieStore;
use oaie_core::hash_algo::HashAlgorithm;
use oaie_core::job::{JobSpec, TraceMode};
use oaie_core::manifest::IsolationLevel;
use oaie_core::policy;
use oaie_core::run_id::RunId;
use oaie_db::{OaieDb, RunRecord, RunStatus};
use oaie_sandbox::probe::SystemCaps;

/// Create an initialized temp store with CAS dirs and DB schema.
pub fn setup_store() -> (OaieStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = OaieStore::from_root(dir.path().to_path_buf());
    store.ensure_dirs().unwrap();
    let db = OaieDb::open(&store.db_path).unwrap();
    db.initialize().unwrap();
    (store, dir)
}

/// Create a CasStore in a temp directory.
pub fn temp_cas() -> (CasStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let cas = CasStore::new(dir.path().to_path_buf(), HashAlgorithm::Blake3);
    (cas, dir)
}

/// Create an initialized in-memory database.
pub fn test_db() -> OaieDb {
    let db = OaieDb::open_in_memory().unwrap();
    db.initialize().unwrap();
    db
}

/// Insert a run with defaults and return its RunId.
pub fn insert_test_run(db: &OaieDb, command: &[&str], status: RunStatus) -> RunId {
    let run_id = RunId::new();
    db.insert_run(&RunRecord {
        run_id: run_id.clone(),
        created: Utc::now(),
        command: command.iter().map(|s| s.to_string()).collect(),
        exit_code: if status == RunStatus::Completed {
            Some(0)
        } else {
            None
        },
        duration_ms: if status == RunStatus::Completed {
            Some(42)
        } else {
            None
        },
        isolation: "none".into(),
        status,
        manifest_hash: None,
        error_message: None,
    })
    .unwrap();
    run_id
}

/// Build a simple job spec (no isolation) for basic tests.
pub fn simple_job(command: &[&str]) -> JobSpec {
    JobSpec {
        command: command.iter().map(|s| s.to_string()).collect(),
        inputs: None,
        outputs: None,
        network: false,
        trace: TraceMode::Off,
        timeout: None,
        policy: None,
        extra_ro: vec![],
        extra_rw: vec![],
        no_isolation: true,
        backend: Default::default(),
        interactive: false,
    }
}

/// Build a job spec with a timeout.
pub fn job_with_timeout(command: &[&str], timeout: Duration) -> JobSpec {
    JobSpec {
        timeout: Some(timeout),
        ..simple_job(command)
    }
}

/// Build a sandboxed job spec (no_isolation = false).
pub fn sandboxed_job(command: &[&str]) -> JobSpec {
    JobSpec {
        command: command.iter().map(|s| s.to_string()).collect(),
        inputs: None,
        outputs: None,
        network: false,
        trace: TraceMode::Off,
        timeout: None,
        policy: None,
        extra_ro: vec![],
        extra_rw: vec![],
        no_isolation: false,
        backend: Default::default(),
        interactive: false,
    }
}

/// Check if user namespaces are available on this system.
pub fn userns_available() -> bool {
    let caps = SystemCaps::detect();
    caps.isolation_level() == IsolationLevel::Full
}

/// Build a default resolved policy (safe preset) for tests.
///
/// Uses the safe preset's limits with an optional timeout override.
pub fn default_resolved_policy(timeout: Option<Duration>) -> ResolvedPolicy {
    let safe = policy::Policy::preset_safe();
    let deny_paths = safe
        .mounts
        .deny
        .iter()
        .map(|p| policy::expand_tilde(p))
        .collect();

    ResolvedPolicy {
        name: Some("safe".into()),
        network: oaie_core::policy::NetworkMode::Off,
        timeout: timeout.or(Some(Duration::from_secs(300))),
        trace: TraceMode::Off,
        input_dir: std::path::PathBuf::from("."),
        output_dir: None,
        ro_mounts: vec![],
        rw_mounts: vec![],
        bind_mounts: vec![],
        deny_paths,
        max_memory: 512 * 1024 * 1024,
        max_time: Duration::from_secs(300),
        max_pids: 64,
        max_fsize: 1024 * 1024 * 1024,
        max_files: 1024,
        allow_memfd: false,
        retain_caps: 0,
        auto_mounts: vec![],
        cpu_quota: None,
        cgroup_mode: oaie_core::cgroup::CgroupMode::Off,
    }
}

// ---- Event test helpers ----

use oaie_observe::{EventDetail, EventType, OaieEvent};

/// Create a RunStart event.
pub fn make_run_start_event(command: &[&str]) -> OaieEvent {
    OaieEvent {
        ts_ns: 0,
        event_type: EventType::RunStart,
        pid: 0,
        ppid: None,
        detail: EventDetail::RunLifecycle {
            status: "started".into(),
            command: Some(command.iter().map(|s| s.to_string()).collect()),
            exit_code: None,
        },
        hash_prev: String::new(),
    }
}

/// Create a RunEnd event.
pub fn make_run_end_event(exit_code: i32) -> OaieEvent {
    OaieEvent {
        ts_ns: 0,
        event_type: EventType::RunEnd,
        pid: 0,
        ppid: None,
        detail: EventDetail::RunLifecycle {
            status: "completed".into(),
            command: None,
            exit_code: Some(exit_code),
        },
        hash_prev: String::new(),
    }
}

/// Create a FileOpen event.
pub fn make_file_open_event(pid: u32, path: &str, flags: u32, result: i32) -> OaieEvent {
    OaieEvent {
        ts_ns: 0,
        event_type: EventType::FileOpen,
        pid,
        ppid: None,
        detail: EventDetail::FileAccess {
            path: path.into(),
            flags,
            result,
        },
        hash_prev: String::new(),
    }
}

/// Create a ProcessExec event.
pub fn make_exec_event(pid: u32, ppid: u32, filename: &str, argv: &[&str]) -> OaieEvent {
    OaieEvent {
        ts_ns: 0,
        event_type: EventType::ProcessExec,
        pid,
        ppid: Some(ppid),
        detail: EventDetail::Exec {
            filename: filename.into(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
        },
        hash_prev: String::new(),
    }
}

/// Create a ProcessExit event.
pub fn make_exit_event(pid: u32, exit_code: i32) -> OaieEvent {
    OaieEvent {
        ts_ns: 0,
        event_type: EventType::ProcessExit,
        pid,
        ppid: None,
        detail: EventDetail::Exit {
            exit_code,
            signal: None,
        },
        hash_prev: String::new(),
    }
}

/// Create a NetConnect event.
pub fn make_net_connect_event(pid: u32, address: &str, result: i32) -> OaieEvent {
    OaieEvent {
        ts_ns: 0,
        event_type: EventType::NetConnect,
        pid,
        ppid: None,
        detail: EventDetail::NetConnect {
            family: "AF_INET".into(),
            address: address.into(),
            result,
        },
        hash_prev: String::new(),
    }
}

/// Create a FileStat event.
pub fn make_file_stat_event(pid: u32, path: &str, result: i32) -> OaieEvent {
    OaieEvent {
        ts_ns: 0,
        event_type: EventType::FileStat,
        pid,
        ppid: None,
        detail: EventDetail::FileStat {
            path: path.into(),
            result,
        },
        hash_prev: String::new(),
    }
}

/// Build a sandboxed job spec with ptrace tracing enabled.
pub fn traced_sandboxed_job(command: &[&str]) -> JobSpec {
    JobSpec {
        command: command.iter().map(|s| s.to_string()).collect(),
        inputs: None,
        outputs: None,
        network: false,
        trace: TraceMode::Ptrace,
        timeout: None,
        policy: None,
        extra_ro: vec![],
        extra_rw: vec![],
        no_isolation: false,
        backend: Default::default(),
        interactive: false,
    }
}

/// Create a SecurityRelevant event.
pub fn make_security_event(pid: u32, syscall: &str, syscall_nr: u64) -> OaieEvent {
    OaieEvent {
        ts_ns: 0,
        event_type: EventType::SecurityRelevant,
        pid,
        ppid: None,
        detail: EventDetail::SecurityRelevant {
            syscall: syscall.into(),
            syscall_nr,
        },
        hash_prev: String::new(),
    }
}

/// Create a RunRecord with the given parameters for DB insertion.
pub fn make_run_record(
    run_id: RunId,
    created: DateTime<Utc>,
    command: Vec<String>,
    exit_code: Option<i32>,
    duration_ms: Option<i64>,
    isolation: &str,
    status: RunStatus,
) -> RunRecord {
    RunRecord {
        run_id,
        created,
        command,
        exit_code,
        duration_ms,
        isolation: isolation.into(),
        status,
        manifest_hash: None,
        error_message: None,
    }
}
