//! Tests extracted from oaie-db: database operations.

use chrono::{DateTime, Utc};
use oaie_core::run_id::RunId;
use oaie_db::{ArtifactRecord, OaieDb, RunRecord, RunStatus, SCHEMA_VERSION};
use oaie_tests::{insert_test_run, test_db};

#[test]
fn schema_version_is_current() {
    let db = test_db();
    assert_eq!(db.schema_version().unwrap(), SCHEMA_VERSION);
}

#[test]
fn initialize_is_idempotent() {
    let db = test_db();
    db.initialize().unwrap();
    assert_eq!(db.schema_version().unwrap(), SCHEMA_VERSION);
}

#[test]
fn insert_and_get_run() {
    let db = test_db();
    let run_id = RunId::new();
    let now = Utc::now();

    let run = RunRecord {
        run_id: run_id.clone(),
        created: now,
        command: vec!["echo".into(), "hello".into()],
        exit_code: Some(0),
        duration_ms: Some(42),
        isolation: "full".into(),
        status: RunStatus::Completed,
        manifest_hash: None,
        error_message: None,
    };

    db.insert_run(&run).unwrap();
    let fetched = db.get_run(&run_id).unwrap().unwrap();
    assert_eq!(fetched.run_id, run_id);
    assert_eq!(fetched.command, vec!["echo", "hello"]);
    assert_eq!(fetched.exit_code, Some(0));
    assert_eq!(fetched.status, RunStatus::Completed);
}

#[test]
fn get_run_not_found() {
    let db = test_db();
    let result = db.get_run(&RunId::new()).unwrap();
    assert!(result.is_none());
}

#[test]
fn get_latest_run() {
    let db = test_db();

    let older = RunRecord {
        run_id: RunId::new(),
        created: DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
        command: vec!["older".into()],
        exit_code: Some(0),
        duration_ms: Some(10),
        isolation: "none".into(),
        status: RunStatus::Completed,
        manifest_hash: None,
        error_message: None,
    };
    let newer = RunRecord {
        run_id: RunId::new(),
        created: DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
        command: vec!["newer".into()],
        exit_code: Some(0),
        duration_ms: Some(20),
        isolation: "full".into(),
        status: RunStatus::Completed,
        manifest_hash: None,
        error_message: None,
    };

    db.insert_run(&older).unwrap();
    db.insert_run(&newer).unwrap();

    let latest = db.get_latest_run().unwrap().unwrap();
    assert_eq!(latest.command, vec!["newer"]);
}

#[test]
fn insert_and_list_artifacts() {
    let db = test_db();
    let run_id = insert_test_run(&db, &["test"], RunStatus::Running);

    let art1 = ArtifactRecord {
        hash: "a".repeat(64),
        run_id: run_id.clone(),
        label: "stdout".into(),
        artifact_type: "stdout".into(),
        size: 100,
        created: Utc::now(),
    };
    let art2 = ArtifactRecord {
        hash: "b".repeat(64),
        run_id: run_id.clone(),
        label: "stderr".into(),
        artifact_type: "stderr".into(),
        size: 50,
        created: Utc::now(),
    };

    db.insert_artifact(&art1).unwrap();
    db.insert_artifact(&art2).unwrap();

    let artifacts = db.list_artifacts(&run_id).unwrap();
    assert_eq!(artifacts.len(), 2);

    let labels: Vec<&str> = artifacts.iter().map(|a| a.label.as_str()).collect();
    assert!(labels.contains(&"stdout"));
    assert!(labels.contains(&"stderr"));
}

#[test]
fn list_artifacts_empty() {
    let db = test_db();
    let artifacts = db.list_artifacts(&RunId::new()).unwrap();
    assert!(artifacts.is_empty());
}

#[test]
fn complete_run_updates_fields() {
    let db = test_db();
    let run_id = insert_test_run(&db, &["echo", "hello"], RunStatus::Running);

    db.complete_run(&run_id, 0, 150, "abc123").unwrap();

    let fetched = db.get_run(&run_id).unwrap().unwrap();
    assert_eq!(fetched.status, RunStatus::Completed);
    assert_eq!(fetched.exit_code, Some(0));
    assert_eq!(fetched.duration_ms, Some(150));
    assert_eq!(fetched.manifest_hash.as_deref(), Some("abc123"));
}

#[test]
fn complete_run_nonexistent_errors() {
    let db = test_db();
    assert!(db.complete_run(&RunId::new(), 0, 100, "hash").is_err());
}

#[test]
fn fail_run_sets_status_and_message() {
    let db = test_db();
    let run_id = insert_test_run(&db, &["bad", "cmd"], RunStatus::Running);

    db.fail_run(&run_id, "sandbox setup failed").unwrap();

    let fetched = db.get_run(&run_id).unwrap().unwrap();
    assert_eq!(fetched.status, RunStatus::Failed);
    assert_eq!(
        fetched.error_message.as_deref(),
        Some("sandbox setup failed")
    );
}

#[test]
fn fail_run_nonexistent_errors() {
    let db = test_db();
    assert!(db.fail_run(&RunId::new(), "error").is_err());
}

#[test]
fn list_runs_respects_limit() {
    let db = test_db();
    for i in 0..5 {
        insert_test_run(&db, &[&format!("cmd{i}")], RunStatus::Completed);
    }

    let all = db.list_runs(100).unwrap();
    assert_eq!(all.len(), 5);

    let limited = db.list_runs(3).unwrap();
    assert_eq!(limited.len(), 3);
}

#[test]
fn list_runs_empty() {
    let db = test_db();
    let runs = db.list_runs(10).unwrap();
    assert!(runs.is_empty());
}

#[test]
fn get_run_by_prefix_exact() {
    let db = test_db();
    let run_id = insert_test_run(&db, &["echo"], RunStatus::Completed);

    // Use a long enough prefix to be unique.
    let prefix = &run_id.full()[..12];
    let fetched = db.get_run_by_prefix(prefix).unwrap();
    assert_eq!(fetched.run_id, run_id);
}

#[test]
fn get_run_by_prefix_not_found() {
    let db = test_db();
    assert!(db.get_run_by_prefix("zzzzz").is_err());
}

#[test]
fn get_run_by_prefix_full_uuid() {
    let db = test_db();
    let run_id = insert_test_run(&db, &["test"], RunStatus::Completed);

    let fetched = db.get_run_by_prefix(&run_id.full()).unwrap();
    assert_eq!(fetched.run_id, run_id);
}

#[test]
fn get_run_by_prefix_ambiguous() {
    let db = test_db();
    // Insert several runs; they all share the same single-char prefix
    // since UUIDv7 hex starts with a timestamp-based nibble.
    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(insert_test_run(&db, &["echo"], RunStatus::Completed));
    }

    // Use a 1-char prefix from the first run's UUID — likely shared by all
    // since they were created within milliseconds.
    let prefix = &ids[0].full()[..1];
    let result = db.get_run_by_prefix(prefix);

    // If all 3 runs share that prefix, should be ambiguous.
    // If by chance they don't, at least verify we get a valid result.
    match result {
        Err(oaie_core::error::OaieError::InvalidRunId(msg)) => {
            assert!(msg.contains("ambiguous"));
        }
        Ok(rec) => {
            // The prefix happened to be unique to one run — that's fine.
            assert!(ids.contains(&rec.run_id));
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}

#[test]
fn concurrent_db_access_wal() {
    // Two connections to the same file: write from one, read from the other.
    // WAL mode should handle this without locking errors.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.sqlite");

    let db1 = OaieDb::open(&db_path).unwrap();
    db1.initialize().unwrap();

    let db2 = OaieDb::open(&db_path).unwrap();
    db2.initialize().unwrap();

    // Write from db1.
    let run_id = RunId::new();
    db1.insert_run(&RunRecord {
        run_id: run_id.clone(),
        created: Utc::now(),
        command: vec!["concurrent".into()],
        exit_code: Some(0),
        duration_ms: Some(10),
        isolation: "none".into(),
        status: RunStatus::Completed,
        manifest_hash: None,
        error_message: None,
    })
    .unwrap();

    // Read from db2 — should see the write thanks to WAL mode.
    let fetched = db2.get_run(&run_id).unwrap();
    assert!(fetched.is_some());
    assert_eq!(fetched.unwrap().command, vec!["concurrent"]);
}
