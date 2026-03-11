//! Tests extracted from oaie-core: run_id, artifact, config, manifest, job, run_dir.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use chrono::Utc;
use oaie_core::artifact::{ArtifactRef, ArtifactType, Hash};
use oaie_core::config::OaieStore;
use oaie_core::error::OaieError;
use oaie_core::job::{parse_timeout, JobSpec, TraceMode};
use oaie_core::manifest::{IsolationInfo, IsolationLevel, Manifest};
use oaie_core::run_dir::RunDir;
use oaie_core::run_id::RunId;

// ---- run_id tests ----

#[test]
fn run_id_round_trip_display_parse() {
    let id = RunId::new();
    let full = id.full();
    let parsed: RunId = full.parse().unwrap();
    assert_eq!(id, parsed);
}

#[test]
fn run_id_short_display_is_8_chars() {
    let id = RunId::new();
    let short = format!("{id}");
    assert_eq!(short.len(), 8);
    // Must be valid hex.
    assert!(short.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn run_id_prefix_matching() {
    let id = RunId::new();
    let short = id.short();
    assert!(id.matches_prefix(&short));
    assert!(id.matches_prefix(&short[..4]));
    assert!(!id.matches_prefix("zzzzzzzz"));
}

#[test]
fn run_id_serde_round_trip() {
    let id = RunId::new();
    let json = serde_json::to_string(&id).unwrap();
    let parsed: RunId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, parsed);
}

#[test]
fn run_id_invalid_string_rejected() {
    assert!("not-a-uuid".parse::<RunId>().is_err());
}

// ---- artifact tests ----

#[test]
fn hash_display_parse_round_trip() {
    let hash = Hash::from_data(b"hello world");
    let hex = hash.to_string();
    assert_eq!(hex.len(), 64);
    let parsed: Hash = hex.parse().unwrap();
    assert_eq!(hash, parsed);
}

#[test]
fn hash_invalid_length_rejected() {
    assert!("abcd".parse::<Hash>().is_err());
}

#[test]
fn hash_invalid_hex_chars_rejected() {
    // 64 chars but not valid hex.
    let bad = "g".repeat(64);
    assert!(bad.parse::<Hash>().is_err());
}

#[test]
fn artifact_type_round_trip() {
    for ty in [
        ArtifactType::Stdout,
        ArtifactType::Stderr,
        ArtifactType::Output,
        ArtifactType::Trace,
        ArtifactType::Report,
        ArtifactType::Manifest,
    ] {
        let s = ty.to_string();
        let parsed: ArtifactType = s.parse().unwrap();
        assert_eq!(ty, parsed);
    }
}

#[test]
fn artifact_ref_serde() {
    let aref = ArtifactRef {
        hash: Hash::from_data(b"test"),
        size: 42,
        label: "stdout".to_string(),
        artifact_type: ArtifactType::Stdout,
    };
    let json = serde_json::to_string(&aref).unwrap();
    let parsed: ArtifactRef = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.size, 42);
    assert_eq!(parsed.label, "stdout");
}

// ---- config tests ----

#[test]
fn config_default_path_construction() {
    // from_env() uses HOME or OAIE_HOME — both set in test environments.
    let store = OaieStore::from_env().unwrap();
    assert!(store.root.ends_with(".oaie"));
    assert!(store.runs_dir.ends_with("runs"));
    assert!(store.cas_dir.ends_with("cas"));
    assert!(store.db_path.ends_with("db.sqlite"));
}

#[test]
fn config_from_root_path_construction() {
    let store = OaieStore::from_root(PathBuf::from("/tmp/test-oaie"));
    assert_eq!(store.root, PathBuf::from("/tmp/test-oaie"));
    assert_eq!(store.runs_dir, PathBuf::from("/tmp/test-oaie/runs"));
    assert_eq!(store.cas_dir, PathBuf::from("/tmp/test-oaie/cas"));
    assert_eq!(store.db_path, PathBuf::from("/tmp/test-oaie/db.sqlite"));
}

#[test]
fn config_ensure_dirs_creates_structure() {
    let dir = std::env::temp_dir().join(format!("oaie-test-{}", std::process::id()));
    let store = OaieStore::from_root(dir.clone());
    store.ensure_dirs().unwrap();
    assert!(store.root.exists());
    assert!(store.runs_dir.exists());
    assert!(store.cas_dir.exists());
    let _ = fs::remove_dir_all(&dir);
}

// ---- manifest tests ----

#[test]
fn manifest_toml_round_trip() {
    let manifest = Manifest {
        version: 1,
        hash_algorithm: "blake3".into(),
        run_id: RunId::new(),
        created: Utc::now(),
        command: vec!["echo".into(), "hello".into()],
        exit_code: Some(0),
        duration_ms: 123,
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
        artifacts: vec![ArtifactRef {
            hash: Hash::from_data(b"test"),
            size: 5,
            label: "stdout".into(),
            artifact_type: ArtifactType::Stdout,
        }],
        policy: None,
        trace: None,
        resources: None,
    };

    let toml_str = toml::to_string(&manifest).unwrap();
    let parsed: Manifest = toml::from_str(&toml_str).unwrap();
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.command, vec!["echo", "hello"]);
    assert_eq!(parsed.exit_code, Some(0));
    assert_eq!(parsed.isolation.level, IsolationLevel::Full);
}

#[test]
fn manifest_with_none_exit_code() {
    let manifest = Manifest {
        version: 1,
        hash_algorithm: "blake3".into(),
        run_id: RunId::new(),
        created: Utc::now(),
        command: vec!["sleep".into(), "999".into()],
        exit_code: None,
        duration_ms: 5000,
        isolation: IsolationInfo {
            level: IsolationLevel::None,
            namespaces: vec![],
            network: true,
            network_mode: "on".into(),
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
    let parsed: Manifest = toml::from_str(&toml_str).unwrap();
    assert!(parsed.exit_code.is_none());
    assert!(parsed.artifacts.is_empty());
    assert!(parsed.isolation.namespaces.is_empty());
}

#[test]
fn isolation_level_display_parse() {
    for level in [
        IsolationLevel::Full,
        IsolationLevel::Partial,
        IsolationLevel::None,
        IsolationLevel::MicroVM,
    ] {
        let s = level.to_string();
        let parsed: IsolationLevel = s.parse().unwrap();
        assert_eq!(level, parsed);
    }
}

// ---- job tests ----

#[test]
fn job_spec_toml_round_trip() {
    let toml_input = r#"
command = ["gcc", "-o", "hello", "hello.c"]
inputs = "/src"
outputs = "/out"
network = false
trace = "strace"
timeout = 30.0
"#;
    let spec: JobSpec = toml::from_str(toml_input).unwrap();
    assert_eq!(spec.command, vec!["gcc", "-o", "hello", "hello.c"]);
    assert_eq!(spec.inputs, Some(PathBuf::from("/src")));
    assert!(!spec.network);
    assert_eq!(spec.trace, TraceMode::Strace);
    assert_eq!(spec.timeout, Some(Duration::from_secs(30)));

    // Round-trip.
    let toml_output = toml::to_string(&spec).unwrap();
    let reparsed: JobSpec = toml::from_str(&toml_output).unwrap();
    assert_eq!(reparsed.command, spec.command);
}

#[test]
fn trace_mode_display_parse() {
    for mode in [
        TraceMode::Off,
        TraceMode::Strace,
        TraceMode::Ptrace,
        TraceMode::Ebpf,
        TraceMode::Auto,
    ] {
        let s = mode.to_string();
        let parsed: TraceMode = s.parse().unwrap();
        assert_eq!(mode, parsed);
    }
}

#[test]
fn parse_timeout_seconds_suffix() {
    assert_eq!(parse_timeout("30s").unwrap(), Duration::from_secs(30));
    assert_eq!(parse_timeout("1.5s").unwrap(), Duration::from_secs_f64(1.5));
}

#[test]
fn parse_timeout_minutes_suffix() {
    assert_eq!(parse_timeout("5m").unwrap(), Duration::from_secs(300));
}

#[test]
fn parse_timeout_hours_suffix() {
    assert_eq!(parse_timeout("1h").unwrap(), Duration::from_secs(3600));
}

#[test]
fn parse_timeout_plain_number() {
    assert_eq!(parse_timeout("60").unwrap(), Duration::from_secs(60));
}

#[test]
fn parse_timeout_invalid() {
    assert!(parse_timeout("").is_err());
    assert!(parse_timeout("abc").is_err());
    assert!(parse_timeout("xs").is_err());
}

#[test]
fn parse_timeout_negative() {
    assert!(parse_timeout("-5s").is_err());
    assert!(parse_timeout("-1m").is_err());
    assert!(parse_timeout("-10").is_err());
}

#[test]
fn parse_timeout_nan_and_infinity() {
    assert!(parse_timeout("NaN").is_err());
    assert!(parse_timeout("inf").is_err());
    assert!(parse_timeout("infinity").is_err());
    assert!(parse_timeout("-inf").is_err());
}

#[test]
fn from_toml_file_valid() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("job.toml");
    fs::write(
        &path,
        r#"
command = ["echo", "hello"]
network = false
trace = "off"
timeout = 30.0
"#,
    )
    .unwrap();
    let spec = JobSpec::from_toml_file(&path).unwrap();
    assert_eq!(spec.command, vec!["echo", "hello"]);
    assert_eq!(spec.timeout, Some(Duration::from_secs(30)));
}

#[test]
fn from_toml_file_missing_command() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.toml");
    // TOML requires command to be present since it's not Option.
    // A file with no command field will fail at parse time.
    fs::write(&path, "network = true\n").unwrap();
    assert!(JobSpec::from_toml_file(&path).is_err());
}

#[test]
fn validate_empty_command() {
    let spec = JobSpec {
        command: vec![],
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
    };
    assert!(spec.validate().is_err());
}

#[test]
fn validate_nonexistent_input() {
    let spec = JobSpec {
        command: vec!["echo".into()],
        inputs: Some(PathBuf::from("/nonexistent/path/xyz")),
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
    };
    assert!(spec.validate().is_err());
}

// ---- run_dir tests ----

#[test]
fn run_dir_create_and_open() {
    let dir = tempfile::tempdir().unwrap();
    let runs_dir = dir.path().join("runs");
    fs::create_dir_all(&runs_dir).unwrap();

    let run_id = RunId::new();
    let rd = RunDir::create(&runs_dir, &run_id).unwrap();
    assert!(rd.path.is_dir());
    assert_eq!(rd.run_id, run_id);

    // Open it back.
    let opened = RunDir::open(&runs_dir, &run_id).unwrap();
    assert_eq!(opened.run_id, run_id);
}

#[test]
fn run_dir_open_nonexistent_errors() {
    let dir = tempfile::tempdir().unwrap();
    let runs_dir = dir.path().join("runs");
    fs::create_dir_all(&runs_dir).unwrap();

    let run_id = RunId::new();
    assert!(RunDir::open(&runs_dir, &run_id).is_err());
}

#[test]
fn run_dir_open_latest_returns_most_recent() {
    let dir = tempfile::tempdir().unwrap();
    let runs_dir = dir.path().join("runs");
    fs::create_dir_all(&runs_dir).unwrap();

    let id1 = RunId::new();
    RunDir::create(&runs_dir, &id1).unwrap();
    // UUIDv7 is time-ordered; sleep a tiny bit to ensure different timestamp.
    std::thread::sleep(std::time::Duration::from_millis(2));
    let id2 = RunId::new();
    RunDir::create(&runs_dir, &id2).unwrap();

    let latest = RunDir::open_latest(&runs_dir).unwrap().unwrap();
    assert_eq!(latest.run_id, id2);
}

#[test]
fn run_dir_open_latest_empty() {
    let dir = tempfile::tempdir().unwrap();
    let runs_dir = dir.path().join("runs");
    fs::create_dir_all(&runs_dir).unwrap();

    assert!(RunDir::open_latest(&runs_dir).unwrap().is_none());
}

#[test]
fn run_dir_resolve_last() {
    let dir = tempfile::tempdir().unwrap();
    let runs_dir = dir.path().join("runs");
    fs::create_dir_all(&runs_dir).unwrap();

    let id = RunId::new();
    RunDir::create(&runs_dir, &id).unwrap();

    let resolved = RunDir::resolve_run_id(&runs_dir, "last").unwrap();
    assert_eq!(resolved, id);
}

#[test]
fn run_dir_resolve_full_uuid() {
    let dir = tempfile::tempdir().unwrap();
    let runs_dir = dir.path().join("runs");
    fs::create_dir_all(&runs_dir).unwrap();

    let id = RunId::new();
    RunDir::create(&runs_dir, &id).unwrap();

    let resolved = RunDir::resolve_run_id(&runs_dir, &id.full()).unwrap();
    assert_eq!(resolved, id);
}

#[test]
fn run_dir_resolve_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let runs_dir = dir.path().join("runs");
    fs::create_dir_all(&runs_dir).unwrap();

    let id = RunId::new();
    RunDir::create(&runs_dir, &id).unwrap();

    // Use a 4-char prefix from the simple (no-hyphen) hex.
    let prefix = &id.short()[..4];
    let resolved = RunDir::resolve_run_id(&runs_dir, prefix).unwrap();
    assert_eq!(resolved, id);
}

#[test]
fn run_dir_resolve_nonexistent_errors() {
    let dir = tempfile::tempdir().unwrap();
    let runs_dir = dir.path().join("runs");
    fs::create_dir_all(&runs_dir).unwrap();

    assert!(RunDir::resolve_run_id(&runs_dir, "deadbeef").is_err());
}

#[test]
fn run_dir_path_helpers() {
    let dir = tempfile::tempdir().unwrap();
    let runs_dir = dir.path().join("runs");
    fs::create_dir_all(&runs_dir).unwrap();

    let id = RunId::new();
    let rd = RunDir::create(&runs_dir, &id).unwrap();

    assert!(rd.manifest_path().ends_with("manifest.toml"));
    assert!(rd.report_path().ends_with("REPORT.md"));
    assert!(rd.events_path().ends_with("events.log"));
    assert!(rd.stdout_path().ends_with("stdout"));
    assert!(rd.stderr_path().ends_with("stderr"));
}

#[test]
fn run_dir_open_latest_ignores_stray_directories() {
    let dir = tempfile::tempdir().unwrap();
    let runs_dir = dir.path().join("runs");
    fs::create_dir_all(&runs_dir).unwrap();

    let id = RunId::new();
    RunDir::create(&runs_dir, &id).unwrap();

    // Create stray directories that are NOT valid UUIDs.
    fs::create_dir_all(runs_dir.join(".tmp-cleanup")).unwrap();
    fs::create_dir_all(runs_dir.join("zzz-invalid")).unwrap();

    // open_latest should skip the stray dirs and return the real run.
    let latest = RunDir::open_latest(&runs_dir).unwrap().unwrap();
    assert_eq!(latest.run_id, id);
}

#[test]
fn run_dir_resolve_ambiguous_prefix_errors() {
    let dir = tempfile::tempdir().unwrap();
    let runs_dir = dir.path().join("runs");
    fs::create_dir_all(&runs_dir).unwrap();

    // Create 3 runs within milliseconds — UUIDv7 shares time prefix.
    let ids: Vec<RunId> = (0..3)
        .map(|_| {
            let id = RunId::new();
            RunDir::create(&runs_dir, &id).unwrap();
            id
        })
        .collect();

    // Use a 1-char prefix that should match multiple runs.
    let prefix = &ids[0].short()[..1];
    let result = RunDir::resolve_run_id(&runs_dir, prefix);

    match result {
        Err(OaieError::InvalidRunId(msg)) => {
            assert!(msg.contains("ambiguous"), "expected 'ambiguous' in: {msg}");
        }
        Ok(id) => {
            // Prefix happened to be unique — still valid.
            assert!(ids.contains(&id));
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}

// ---- SHA-256 / hash algorithm tests ----

use oaie_core::hash_algo::HashAlgorithm;
use oaie_core::store_config::StoreConfig;

#[test]
fn sha256_hash_differs_from_blake3() {
    let data = b"hello world";
    let b3 = Hash::compute(HashAlgorithm::Blake3, data);
    let sha = Hash::compute(HashAlgorithm::Sha256, data);
    assert_ne!(b3, sha, "BLAKE3 and SHA-256 must produce different digests");
    // Both are 32 bytes → 64 hex chars.
    assert_eq!(b3.to_hex().len(), 64);
    assert_eq!(sha.to_hex().len(), 64);
}

#[test]
fn hash_compute_matches_from_data_for_blake3() {
    let data = b"consistency check";
    let via_compute = Hash::compute(HashAlgorithm::Blake3, data);
    let via_from_data = Hash::from_data(data);
    assert_eq!(via_compute, via_from_data);
}

#[test]
fn config_toml_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = StoreConfig {
        version: 1,
        hash_algorithm: HashAlgorithm::Sha256,
        ..StoreConfig::default()
    };
    cfg.write(dir.path()).unwrap();

    let loaded = StoreConfig::load(dir.path()).unwrap().unwrap();
    assert_eq!(loaded.version, 1);
    assert_eq!(loaded.hash_algorithm, HashAlgorithm::Sha256);
}

#[test]
fn legacy_store_gets_config() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    // No config.toml — legacy store.
    let mut store = OaieStore::from_root(root.clone());
    store.ensure_dirs().unwrap();
    store.open().unwrap();
    assert_eq!(store.hash_algorithm, HashAlgorithm::Blake3);
    // config.toml should now exist.
    assert!(root.join("config.toml").exists());
}

#[test]
fn hash_algorithm_display_parse() {
    for algo in [HashAlgorithm::Blake3, HashAlgorithm::Sha256] {
        let s = algo.to_string();
        let parsed: HashAlgorithm = s.parse().unwrap();
        assert_eq!(algo, parsed);
    }
}

#[test]
fn config_toml_limits_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = StoreConfig {
        version: 1,
        hash_algorithm: HashAlgorithm::Blake3,
        limits: oaie_core::store_config::ArtifactLimits {
            max_output_files: 500,
            max_output_file_size: 128 * 1024 * 1024,
            max_output_total: 512 * 1024 * 1024,
        },
        ..StoreConfig::default()
    };
    cfg.write(dir.path()).unwrap();
    let loaded = StoreConfig::load(dir.path()).unwrap().unwrap();
    assert_eq!(loaded.limits.max_output_files, 500);
    assert_eq!(loaded.limits.max_output_file_size, 128 * 1024 * 1024);
    assert_eq!(loaded.limits.max_output_total, 512 * 1024 * 1024);
}

#[test]
fn config_toml_timeouts_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = StoreConfig {
        version: 1,
        timeouts: oaie_core::store_config::DefaultTimeouts {
            default_timeout: "10m".into(),
            max_timeout: "2h".into(),
        },
        ..StoreConfig::default()
    };
    cfg.write(dir.path()).unwrap();
    let loaded = StoreConfig::load(dir.path()).unwrap().unwrap();
    assert_eq!(loaded.timeouts.default_timeout, "10m");
    assert_eq!(loaded.timeouts.max_timeout, "2h");
}

#[test]
fn config_toml_store_path_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let store_path = dir.path().join("my-store");
    let cfg = StoreConfig {
        version: 1,
        store_path: store_path.clone(),
        ..StoreConfig::default()
    };
    cfg.write(dir.path()).unwrap();
    let loaded = StoreConfig::load(dir.path()).unwrap().unwrap();
    assert_eq!(loaded.store_path, store_path);
}

#[test]
fn config_toml_legacy_missing_store_path_defaults_empty() {
    // A config.toml without store_path (legacy) should deserialize with empty path.
    let dir = tempfile::tempdir().unwrap();
    let content = r#"
version = 1
hash_algorithm = "blake3"
"#;
    std::fs::write(dir.path().join("config.toml"), content).unwrap();
    let loaded = StoreConfig::load(dir.path()).unwrap().unwrap();
    assert!(loaded.store_path.as_os_str().is_empty());
}
