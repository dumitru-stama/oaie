//! Integration tests: full CAS → DB → inspect flow.
//!
//! Simulates complete runs without actually executing sandboxed commands.
//! Tests that all pieces (CAS store, run directory, manifest, database)
//! work together end-to-end.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use chrono::Utc;
use oaie_cas::store::{read_manifest, CasStore, VerifyResult};
use oaie_core::artifact::{ArtifactRef, ArtifactType, Hash};
use oaie_core::config::OaieStore;
use oaie_core::hash_algo::HashAlgorithm;
use oaie_core::manifest::{IsolationInfo, IsolationLevel, Manifest};
use oaie_core::run_dir::RunDir;
use oaie_core::run_id::RunId;
use oaie_db::{ArtifactRecord, OaieDb, RunRecord, RunStatus};

/// Full end-to-end: create store → simulate run → store artifacts → index → query back.
#[test]
fn full_store_and_inspect_flow() {
    let tmp = tempfile::tempdir().unwrap();
    let store = OaieStore::from_root(tmp.path().to_path_buf());
    store.ensure_dirs().unwrap();

    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let db = OaieDb::open(&store.db_path).unwrap();
    db.initialize().unwrap();

    // --- Simulate a run ---
    let run_id = RunId::new();
    let run_dir = RunDir::create(&store.runs_dir, &run_id).unwrap();

    // Store stdout as an artifact.
    let (stdout_hash, stdout_size) = cas.store_bytes(b"hello world\n").unwrap();
    assert_eq!(stdout_size, 12);

    // Store stderr (empty).
    let (stderr_hash, stderr_size) = cas.store_bytes(b"").unwrap();
    assert_eq!(stderr_size, 0);

    // Create manifest.
    let manifest = Manifest {
        version: 1,
        hash_algorithm: "blake3".into(),
        run_id: run_id.clone(),
        created: Utc::now(),
        command: vec!["echo".into(), "hello world".into()],
        exit_code: Some(0),
        duration_ms: 12,
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
        artifacts: vec![
            ArtifactRef {
                hash: stdout_hash.clone(),
                size: stdout_size,
                label: "stdout".into(),
                artifact_type: ArtifactType::Stdout,
            },
            ArtifactRef {
                hash: stderr_hash.clone(),
                size: stderr_size,
                label: "stderr".into(),
                artifact_type: ArtifactType::Stderr,
            },
        ],
        policy: None,
        trace: None,
        resources: None,
    };

    // Write manifest to run dir and CAS.
    let manifest_hash = cas.write_manifest(&manifest, &run_dir.path).unwrap();
    assert!(cas.exists(&manifest_hash));

    // --- Index in database ---
    db.insert_run(&RunRecord {
        run_id: run_id.clone(),
        created: manifest.created,
        command: manifest.command.clone(),
        exit_code: None,
        duration_ms: None,
        isolation: "none".into(),
        status: RunStatus::Running,
        manifest_hash: None,
        error_message: None,
    })
    .unwrap();

    // Complete the run.
    db.complete_run(&run_id, 0, 12, &manifest_hash.to_hex())
        .unwrap();

    // Insert artifacts.
    for a in &manifest.artifacts {
        db.insert_artifact(&ArtifactRecord {
            hash: a.hash.to_hex(),
            run_id: run_id.clone(),
            label: a.label.clone(),
            artifact_type: a.artifact_type.to_string(),
            size: a.size as i64,
            created: manifest.created,
        })
        .unwrap();
    }

    // --- Query back ---
    let fetched = db.get_run(&run_id).unwrap().unwrap();
    assert_eq!(fetched.run_id, run_id);
    assert_eq!(fetched.status, RunStatus::Completed);
    assert_eq!(fetched.exit_code, Some(0));
    assert_eq!(fetched.duration_ms, Some(12));
    assert_eq!(
        fetched.manifest_hash.as_deref(),
        Some(manifest_hash.to_hex().as_str())
    );

    // Prefix query.
    let prefix = &run_id.full()[..8];
    let by_prefix = db.get_run_by_prefix(prefix).unwrap();
    assert_eq!(by_prefix.run_id, run_id);

    // Latest run.
    let latest = db.get_latest_run().unwrap().unwrap();
    assert_eq!(latest.run_id, run_id);

    // List artifacts.
    let arts = db.list_artifacts(&run_id).unwrap();
    assert_eq!(arts.len(), 2);

    // --- Verify CAS integrity ---
    assert!(matches!(
        cas.verify(&stdout_hash).unwrap(),
        VerifyResult::Ok
    ));
    assert!(matches!(
        cas.verify(&stderr_hash).unwrap(),
        VerifyResult::Ok
    ));
    assert!(matches!(
        cas.verify(&manifest_hash).unwrap(),
        VerifyResult::Ok
    ));

    // --- Read manifest back from disk ---
    let read_back = read_manifest(&run_dir.path).unwrap();
    assert_eq!(read_back.command, manifest.command);
    assert_eq!(read_back.exit_code, Some(0));
    assert_eq!(read_back.artifacts.len(), 2);

    // --- Run directory path helpers ---
    assert!(run_dir.manifest_path().exists());
}

/// CAS dedup across run boundaries: two runs storing the same stdout
/// should result in only one CAS blob.
#[test]
fn dedup_across_runs() {
    let tmp = tempfile::tempdir().unwrap();
    let store = OaieStore::from_root(tmp.path().to_path_buf());
    store.ensure_dirs().unwrap();

    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);

    let (hash1, _) = cas.store_bytes(b"shared output").unwrap();
    let (hash2, _) = cas.store_bytes(b"shared output").unwrap();
    assert_eq!(hash1, hash2);

    // Only one blob on disk.
    let all = cas.list_all().unwrap();
    assert_eq!(all.len(), 1);
}

/// Run directory resolve_run_id with "last".
#[test]
fn integration_run_dir_resolve_last() {
    let tmp = tempfile::tempdir().unwrap();
    let store = OaieStore::from_root(tmp.path().to_path_buf());
    store.ensure_dirs().unwrap();

    let id = RunId::new();
    RunDir::create(&store.runs_dir, &id).unwrap();

    let resolved = RunDir::resolve_run_id(&store.runs_dir, "last").unwrap();
    assert_eq!(resolved, id);
}

/// DB fail_run and list_runs.
#[test]
fn db_fail_and_list() {
    let tmp = tempfile::tempdir().unwrap();
    let store = OaieStore::from_root(tmp.path().to_path_buf());
    store.ensure_dirs().unwrap();

    let db = OaieDb::open(&store.db_path).unwrap();
    db.initialize().unwrap();

    let id1 = RunId::new();
    db.insert_run(&RunRecord {
        run_id: id1.clone(),
        created: Utc::now(),
        command: vec!["good".into()],
        exit_code: None,
        duration_ms: None,
        isolation: "none".into(),
        status: RunStatus::Running,
        manifest_hash: None,
        error_message: None,
    })
    .unwrap();
    db.complete_run(&id1, 0, 100, "hash1").unwrap();

    let id2 = RunId::new();
    db.insert_run(&RunRecord {
        run_id: id2.clone(),
        created: Utc::now(),
        command: vec!["bad".into()],
        exit_code: None,
        duration_ms: None,
        isolation: "none".into(),
        status: RunStatus::Running,
        manifest_hash: None,
        error_message: None,
    })
    .unwrap();
    db.fail_run(&id2, "sandbox crashed").unwrap();

    let runs = db.list_runs(10).unwrap();
    assert_eq!(runs.len(), 2);

    let failed = runs.iter().find(|r| r.status == RunStatus::Failed).unwrap();
    assert_eq!(
        failed.error_message.as_deref(),
        Some("sandbox crashed")
    );
}

/// CAS blob verification catches corruption.
#[test]
fn cas_corruption_detection() {
    let tmp = tempfile::tempdir().unwrap();
    let cas = CasStore::new(tmp.path().to_path_buf(), HashAlgorithm::Blake3);

    let (hash, _) = cas.store_bytes(b"important data").unwrap();
    assert!(matches!(cas.verify(&hash).unwrap(), VerifyResult::Ok));

    // Corrupt the blob.
    let path = cas.blob_path(&hash);
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o644);
    fs::set_permissions(&path, perms).unwrap();
    fs::write(&path, b"corrupted!").unwrap();

    match cas.verify(&hash).unwrap() {
        VerifyResult::Corrupted { expected, actual } => {
            assert_eq!(expected, hash);
            assert_ne!(actual, hash);
        }
        other => panic!("expected Corrupted, got {other:?}"),
    }
}

/// Hash round-trip: from_data → to_hex → from_hex.
#[test]
fn hash_hex_round_trip() {
    let hash = Hash::from_data(b"test data");
    let hex = hash.to_hex();
    let parsed = Hash::from_hex(&hex).unwrap();
    assert_eq!(hash, parsed);
}
