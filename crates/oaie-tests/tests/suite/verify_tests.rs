//! Tests for the verify, replay, and GC subsystems.
//!
//! Covers: verify_run (pass/fail/skip), artifact tampering detection,
//! event chain verification, GC reference tracking, and replay output comparison.

use std::fs;
use std::time::Duration;

use oaie_cas::store::CasStore;
use oaie_cli::clean::{gc, parse_gc_duration};
use oaie_cli::runner::Runner;
use oaie_cli::verify::verify_run;
use oaie_core::artifact::Hash;
use oaie_core::hash_algo::HashAlgorithm;
use oaie_core::job::TraceMode;
use oaie_core::verify::{CheckKind, CheckStatus};
use oaie_db::{OaieDb, RunStatus};
use oaie_tests::{
    default_resolved_policy, insert_test_run, sandboxed_job, setup_store, traced_sandboxed_job,
    userns_available,
};

/// Build a resolved policy with tracing enabled and a timeout.
fn traced_policy() -> oaie_cli::policy_resolve::ResolvedPolicy {
    let mut policy = default_resolved_policy(Some(Duration::from_secs(30)));
    policy.trace = TraceMode::Ptrace;
    policy
}

/// Helper: find a check by kind.
fn find_check(
    report: &oaie_core::verify::VerifyReport,
    kind: CheckKind,
) -> &oaie_core::verify::CheckResult {
    report
        .checks
        .iter()
        .find(|c| c.check == kind)
        .unwrap_or_else(|| panic!("expected check {kind:?} in report"))
}

// ── Verify: basic pass ──

#[test]
fn verify_passes_for_good_run() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = sandboxed_job(&["echo", "verify me"]);
    let policy = default_resolved_policy(Some(Duration::from_secs(30)));

    let result = runner.execute(&job, &policy, true, None).unwrap();
    assert_eq!(result.exit_code, 0);

    let report = verify_run(&store, &result.run_id).unwrap();
    assert!(
        report.passed(),
        "fresh run should verify: {:?}",
        report
            .checks
            .iter()
            .filter(|c| c.status == CheckStatus::Fail)
            .collect::<Vec<_>>()
    );
}

#[test]
fn verify_passes_for_traced_run() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = traced_sandboxed_job(&["echo", "traced verify"]);
    let policy = traced_policy();

    let result = runner.execute(&job, &policy, true, None).unwrap();
    assert_eq!(result.exit_code, 0);

    let report = verify_run(&store, &result.run_id).unwrap();
    assert!(
        report.passed(),
        "traced run should verify: {:?}",
        report
            .checks
            .iter()
            .filter(|c| c.status == CheckStatus::Fail)
            .collect::<Vec<_>>()
    );

    // Trace checks should pass, not skip.
    let chain_check = find_check(&report, CheckKind::EventChainIntegrity);
    assert_eq!(chain_check.status, CheckStatus::Pass);
    let tip_check = find_check(&report, CheckKind::EventChainTip);
    assert_eq!(tip_check.status, CheckStatus::Pass);
}

// ── Verify: missing manifest ──

#[test]
fn verify_fails_for_missing_manifest() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = sandboxed_job(&["echo", "delete me"]);
    let policy = default_resolved_policy(Some(Duration::from_secs(30)));

    let result = runner.execute(&job, &policy, true, None).unwrap();

    // Delete the manifest.
    let manifest_path = store
        .runs_dir
        .join(result.run_id.full())
        .join("manifest.toml");
    fs::remove_file(&manifest_path).unwrap();

    let report = verify_run(&store, &result.run_id).unwrap();
    assert!(!report.passed());

    let manifest_check = find_check(&report, CheckKind::ManifestExists);
    assert_eq!(manifest_check.status, CheckStatus::Fail);
}

// ── Verify: corrupted artifact ──

#[test]
fn verify_detects_corrupted_artifact() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = sandboxed_job(&["echo", "tamper test"]);
    let policy = default_resolved_policy(Some(Duration::from_secs(30)));

    let result = runner.execute(&job, &policy, true, None).unwrap();

    // Tamper with the stdout blob.
    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let blob_path = cas.blob_path(&result.stdout_hash);
    // Make writable first (blobs are 0o444).
    let mut perms = fs::metadata(&blob_path).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o644);
    fs::set_permissions(&blob_path, perms).unwrap();
    fs::write(&blob_path, b"tampered content").unwrap();

    let report = verify_run(&store, &result.run_id).unwrap();
    assert!(!report.passed());

    let hash_check = find_check(&report, CheckKind::OutputArtifactHashes);
    assert_eq!(hash_check.status, CheckStatus::Fail);
}

// ── Verify: missing CAS blob ──

#[test]
fn verify_detects_missing_artifact() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = sandboxed_job(&["echo", "delete blob"]);
    let policy = default_resolved_policy(Some(Duration::from_secs(30)));

    let result = runner.execute(&job, &policy, true, None).unwrap();

    // Delete the stdout blob from CAS.
    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let blob_path = cas.blob_path(&result.stdout_hash);
    let mut perms = fs::metadata(&blob_path).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o644);
    fs::set_permissions(&blob_path, perms).unwrap();
    fs::remove_file(&blob_path).unwrap();

    let report = verify_run(&store, &result.run_id).unwrap();
    assert!(!report.passed());

    let exist_check = find_check(&report, CheckKind::OutputArtifactsExist);
    assert_eq!(exist_check.status, CheckStatus::Fail);
}

// ── Verify: trace checks skipped when no tracing ──

#[test]
fn verify_skips_trace_checks_when_untraced() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = sandboxed_job(&["echo", "no trace"]);
    let policy = default_resolved_policy(Some(Duration::from_secs(30)));

    let result = runner.execute(&job, &policy, true, None).unwrap();

    let report = verify_run(&store, &result.run_id).unwrap();
    assert!(report.passed());

    let trace_idx = find_check(&report, CheckKind::TraceIndexExists);
    assert_eq!(trace_idx.status, CheckStatus::Skip);
    let chain_check = find_check(&report, CheckKind::EventChainIntegrity);
    assert_eq!(chain_check.status, CheckStatus::Skip);
}

// ── Verify: VerifyReport::passed() and summary() ──

#[test]
fn verify_report_passed_returns_false_when_any_check_fails() {
    use oaie_core::verify::{CheckResult, VerifyReport};
    use oaie_core::run_id::RunId;

    let report = VerifyReport {
        run_id: RunId::new(),
        checks: vec![
            CheckResult {
                check: CheckKind::ManifestExists,
                status: CheckStatus::Pass,
                detail: None,
            },
            CheckResult {
                check: CheckKind::ManifestParseable,
                status: CheckStatus::Fail,
                detail: Some("corrupt".into()),
            },
            CheckResult {
                check: CheckKind::TraceIndexExists,
                status: CheckStatus::Skip,
                detail: None,
            },
        ],
    };

    assert!(!report.passed());
    assert!(report.summary().contains("1 passed"));
    assert!(report.summary().contains("1 failed"));
    assert!(report.summary().contains("1 skipped"));
}

#[test]
fn verify_report_passed_returns_true_when_all_pass_or_skip() {
    use oaie_core::verify::{CheckResult, VerifyReport};
    use oaie_core::run_id::RunId;

    let report = VerifyReport {
        run_id: RunId::new(),
        checks: vec![
            CheckResult {
                check: CheckKind::ManifestExists,
                status: CheckStatus::Pass,
                detail: None,
            },
            CheckResult {
                check: CheckKind::TraceIndexExists,
                status: CheckStatus::Skip,
                detail: None,
            },
        ],
    };

    assert!(report.passed());
}

// ── GC: basic tests ──

#[test]
fn gc_does_not_remove_referenced_blobs() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = sandboxed_job(&["echo", "gc test"]);
    let policy = default_resolved_policy(Some(Duration::from_secs(30)));

    runner.execute(&job, &policy, true, None).unwrap();

    // GC with min_age=0 should not remove anything (all blobs are referenced).
    let result = gc(&store, Duration::ZERO, false).unwrap();
    assert_eq!(result.blobs_removed, 0, "should not remove referenced blobs");
    assert!(result.blobs_retained > 0, "should retain some blobs");
}

#[test]
fn gc_removes_unreferenced_blobs() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let runner = Runner::new(store.clone()).unwrap();
    let job = sandboxed_job(&["echo", "gc remove test"]);
    let policy = default_resolved_policy(Some(Duration::from_secs(30)));

    let result = runner.execute(&job, &policy, true, None).unwrap();

    // Count blobs before delete.
    let blobs_before = cas.list_all().unwrap().len();
    assert!(blobs_before > 0);

    // Delete the run from DB (but leave CAS blobs).
    let db = OaieDb::open(&store.db_path).unwrap();
    db.delete_run(&result.run_id, &store.runs_dir).unwrap();

    // GC with min_age=0 should now remove orphaned blobs.
    let gc_result = gc(&store, Duration::ZERO, false).unwrap();
    assert!(
        gc_result.blobs_removed > 0,
        "should remove orphaned blobs, got blobs_removed=0"
    );

    // Verify blobs are actually gone.
    let blobs_after = cas.list_all().unwrap().len();
    assert!(
        blobs_after < blobs_before,
        "blobs should have been removed: before={blobs_before}, after={blobs_after}"
    );
}

#[test]
fn gc_dry_run_does_not_delete() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let runner = Runner::new(store.clone()).unwrap();
    let job = sandboxed_job(&["echo", "dry run test"]);
    let policy = default_resolved_policy(Some(Duration::from_secs(30)));

    let result = runner.execute(&job, &policy, true, None).unwrap();

    // Delete the run from DB.
    let db = OaieDb::open(&store.db_path).unwrap();
    db.delete_run(&result.run_id, &store.runs_dir).unwrap();

    let blobs_before = cas.list_all().unwrap().len();

    // Dry-run GC.
    let gc_result = gc(&store, Duration::ZERO, true).unwrap();
    assert!(gc_result.blobs_removed > 0, "dry run should report removals");

    // Blobs should still be there.
    let blobs_after = cas.list_all().unwrap().len();
    assert_eq!(
        blobs_before, blobs_after,
        "dry run should not delete blobs"
    );
}

#[test]
fn gc_respects_min_age() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let runner = Runner::new(store.clone()).unwrap();
    let job = sandboxed_job(&["echo", "age test"]);
    let policy = default_resolved_policy(Some(Duration::from_secs(30)));

    let result = runner.execute(&job, &policy, true, None).unwrap();

    // Delete the run from DB.
    let db = OaieDb::open(&store.db_path).unwrap();
    db.delete_run(&result.run_id, &store.runs_dir).unwrap();

    // GC with min_age=1 hour should NOT remove anything (blobs are seconds old).
    let gc_result = gc(&store, Duration::from_secs(3600), false).unwrap();
    assert_eq!(
        gc_result.blobs_removed, 0,
        "should not remove blobs newer than min_age"
    );

    // Blobs should still be there.
    let blobs_count = cas.list_all().unwrap().len();
    assert!(blobs_count > 0);
}

#[test]
fn gc_handles_empty_store() {
    let (store, _dir) = setup_store();

    let result = gc(&store, Duration::ZERO, false).unwrap();
    assert_eq!(result.blobs_scanned, 0);
    assert_eq!(result.blobs_removed, 0);
    assert_eq!(result.blobs_retained, 0);
}

// ── GC duration parsing ──

#[test]
fn parse_gc_duration_days() {
    let d = parse_gc_duration("7d").unwrap();
    assert_eq!(d, Duration::from_secs(7 * 86400));
}

#[test]
fn parse_gc_duration_hours() {
    let d = parse_gc_duration("12h").unwrap();
    assert_eq!(d, Duration::from_secs(12 * 3600));
}

#[test]
fn parse_gc_duration_minutes() {
    let d = parse_gc_duration("30m").unwrap();
    assert_eq!(d, Duration::from_secs(30 * 60));
}

// ── DB: list_all_runs and delete_run ──

#[test]
fn db_list_all_runs() {
    let (store, _dir) = setup_store();
    let db = OaieDb::open(&store.db_path).unwrap();

    // Initially empty.
    let runs = db.list_all_runs().unwrap();
    assert!(runs.is_empty());

    // Insert 3 runs.
    use oaie_tests::insert_test_run;
    insert_test_run(&db, &["echo", "1"], RunStatus::Completed);
    insert_test_run(&db, &["echo", "2"], RunStatus::Completed);
    insert_test_run(&db, &["echo", "3"], RunStatus::Completed);

    let runs = db.list_all_runs().unwrap();
    assert_eq!(runs.len(), 3);
}

#[test]
fn db_delete_run_removes_artifacts() {
    let (store, _dir) = setup_store();
    let db = OaieDb::open(&store.db_path).unwrap();

    let run_id = insert_test_run(&db, &["echo", "delete me"], RunStatus::Completed);

    // Insert an artifact for this run.
    db.insert_artifact(&oaie_db::ArtifactRecord {
        hash: "a".repeat(64),
        run_id: run_id.clone(),
        label: "stdout".into(),
        artifact_type: "stdout".into(),
        size: 42,
        created: chrono::Utc::now(),
    })
    .unwrap();

    // Create a fake run dir.
    let run_dir = store.runs_dir.join(run_id.full());
    fs::create_dir_all(&run_dir).unwrap();
    fs::write(run_dir.join("marker"), "test").unwrap();

    // Delete.
    db.delete_run(&run_id, &store.runs_dir).unwrap();

    // Run should be gone.
    assert!(db.get_run(&run_id).unwrap().is_none());

    // Artifacts should be gone.
    let artifacts = db.list_artifacts(&run_id).unwrap();
    assert!(artifacts.is_empty());

    // Run dir should be gone.
    assert!(!run_dir.exists());
}

// ── Chain verification with tampering ──

#[test]
fn verify_detects_trace_chain_tampering() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = traced_sandboxed_job(&["echo", "chain tamper"]);
    let policy = traced_policy();

    let result = runner.execute(&job, &policy, true, None).unwrap();

    // Verify passes initially.
    let report = verify_run(&store, &result.run_id).unwrap();
    assert!(report.passed());

    // Tamper with a trace chunk: find the trace index, get a chunk hash,
    // and overwrite the chunk blob.
    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let run_dir = store.runs_dir.join(result.run_id.full());
    let index_path = run_dir.join("trace_index.json");
    let index_str = fs::read_to_string(&index_path).unwrap();
    let index: oaie_observe::TraceIndex = serde_json::from_str(&index_str).unwrap();

    if let Some(chunk) = index.chunks.first() {
        let chunk_hash = Hash::from_hex(&chunk.hash).unwrap();
        let blob_path = cas.blob_path(&chunk_hash);
        // Make writable.
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&blob_path).unwrap().permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&blob_path, perms).unwrap();
        // Overwrite with garbage.
        fs::write(&blob_path, b"tampered trace chunk data").unwrap();
    }

    // Verify should now fail (chunk hash doesn't match, chain can't be read).
    let report = verify_run(&store, &result.run_id).unwrap();
    assert!(!report.passed());
}

// ── CheckKind display names ──

#[test]
fn check_kind_display_names() {
    assert_eq!(
        CheckKind::ManifestExists.display_name(),
        "Manifest exists"
    );
    assert_eq!(
        CheckKind::EventChainIntegrity.display_name(),
        "Event chain integrity"
    );
    assert_eq!(
        CheckKind::TraceChunkHashes.display_name(),
        "Trace chunk hashes match"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Corner-case tests
// ══════════════════════════════════════════════════════════════════════

// ── Verify: corrupt manifest TOML ──

#[test]
fn verify_fails_for_corrupted_manifest_toml() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = sandboxed_job(&["echo", "corrupt manifest"]);
    let policy = default_resolved_policy(Some(Duration::from_secs(30)));

    let result = runner.execute(&job, &policy, true, None).unwrap();

    // Overwrite manifest.toml with garbage (not valid TOML).
    let manifest_path = store
        .runs_dir
        .join(result.run_id.full())
        .join("manifest.toml");
    fs::write(&manifest_path, b"this is {{ not valid toml !@#$").unwrap();

    let report = verify_run(&store, &result.run_id).unwrap();
    assert!(!report.passed());

    // ManifestExists should pass, ManifestParseable should fail.
    let exists_check = find_check(&report, CheckKind::ManifestExists);
    assert_eq!(exists_check.status, CheckStatus::Pass);
    let parse_check = find_check(&report, CheckKind::ManifestParseable);
    assert_eq!(parse_check.status, CheckStatus::Fail);

    // Should bail early after ManifestParseable fails — only 2 checks total.
    assert_eq!(report.checks.len(), 2);
}

// ── Verify: trace index deleted from CAS ──

#[test]
fn verify_fails_for_missing_trace_index_in_cas() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = traced_sandboxed_job(&["echo", "trace index gone"]);
    let policy = traced_policy();

    let result = runner.execute(&job, &policy, true, None).unwrap();

    // Find the trace_index hash from the manifest and delete it from CAS.
    let run_dir = store.runs_dir.join(result.run_id.full());
    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);

    let index_path = run_dir.join("trace_index.json");
    let index_str = fs::read_to_string(&index_path).unwrap();
    let index: oaie_observe::TraceIndex = serde_json::from_str(&index_str).unwrap();

    // Delete the trace index blob from CAS using the manifest's trace_index_hash.
    let manifest = oaie_cas::store::read_manifest(&run_dir).unwrap();
    let trace = manifest.trace.as_ref().unwrap();
    let index_hash = Hash::from_hex(trace.trace_index_hash.as_ref().unwrap()).unwrap();
    let blob_path = cas.blob_path(&index_hash);
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(&blob_path).unwrap().permissions();
    perms.set_mode(0o644);
    fs::set_permissions(&blob_path, perms).unwrap();
    fs::remove_file(&blob_path).unwrap();

    let report = verify_run(&store, &result.run_id).unwrap();
    assert!(!report.passed());

    let trace_idx = find_check(&report, CheckKind::TraceIndexExists);
    assert_eq!(trace_idx.status, CheckStatus::Fail);

    // Downstream checks should be skipped since index is missing.
    let chunks_check = find_check(&report, CheckKind::TraceChunksExist);
    assert_eq!(chunks_check.status, CheckStatus::Skip);
    let chain_check = find_check(&report, CheckKind::EventChainIntegrity);
    assert_eq!(chain_check.status, CheckStatus::Skip);

    // But we should also verify that the index still exists on disk (run_dir copy)
    // and that we specifically failed on the CAS copy.
    assert!(index_path.exists(), "run dir trace_index.json should still exist");
    let _ = index; // used above
}

// ── Duration parsing edge cases ──

#[test]
fn parse_gc_duration_seconds() {
    let d = parse_gc_duration("60s").unwrap();
    assert_eq!(d, Duration::from_secs(60));
}

#[test]
fn parse_gc_duration_bare_number_defaults_to_days() {
    let d = parse_gc_duration("7").unwrap();
    assert_eq!(d, Duration::from_secs(7 * 86400));
}

#[test]
fn parse_gc_duration_zero() {
    let d = parse_gc_duration("0d").unwrap();
    assert_eq!(d, Duration::from_secs(0));
}

#[test]
fn parse_gc_duration_invalid_returns_error() {
    assert!(parse_gc_duration("abc").is_err());
    assert!(parse_gc_duration("").is_err());
    assert!(parse_gc_duration("12x").is_err());
}

// ── GC: arithmetic consistency ──

#[test]
fn gc_counts_are_consistent() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let policy = default_resolved_policy(Some(Duration::from_secs(30)));

    // Create two runs.
    runner
        .execute(&sandboxed_job(&["echo", "run1"]), &policy, true, None)
        .unwrap();
    let result2 = runner
        .execute(&sandboxed_job(&["echo", "run2"]), &policy, true, None)
        .unwrap();

    // Delete one run from DB to create orphaned blobs.
    let db = OaieDb::open(&store.db_path).unwrap();
    db.delete_run(&result2.run_id, &store.runs_dir).unwrap();

    // GC: scanned should equal retained + removed.
    let gc_result = gc(&store, Duration::ZERO, false).unwrap();
    assert_eq!(
        gc_result.blobs_scanned,
        gc_result.blobs_retained + gc_result.blobs_removed,
        "scanned ({}) != retained ({}) + removed ({})",
        gc_result.blobs_scanned,
        gc_result.blobs_retained,
        gc_result.blobs_removed,
    );
}

// ── DB: delete_run on nonexistent ID ──

#[test]
fn delete_run_nonexistent_returns_error() {
    let (store, _dir) = setup_store();
    let db = OaieDb::open(&store.db_path).unwrap();
    let fake_id = oaie_core::run_id::RunId::new();

    let err = db.delete_run(&fake_id, &store.runs_dir);
    assert!(err.is_err(), "delete of nonexistent run should error");
}

// ── Verify: all 12 checks present for traced run ──

#[test]
fn verify_report_has_all_12_checks_for_traced_run() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = traced_sandboxed_job(&["echo", "all checks"]);
    let policy = traced_policy();

    let result = runner.execute(&job, &policy, true, None).unwrap();
    let report = verify_run(&store, &result.run_id).unwrap();

    assert_eq!(
        report.checks.len(),
        12,
        "expected 12 checks, got {}",
        report.checks.len()
    );

    // Verify all check kinds appear exactly once.
    let kinds: Vec<CheckKind> = report.checks.iter().map(|c| c.check).collect();
    assert!(kinds.contains(&CheckKind::ManifestExists));
    assert!(kinds.contains(&CheckKind::ManifestParseable));
    assert!(kinds.contains(&CheckKind::InputArtifactsExist));
    assert!(kinds.contains(&CheckKind::OutputArtifactsExist));
    assert!(kinds.contains(&CheckKind::InputArtifactHashes));
    assert!(kinds.contains(&CheckKind::OutputArtifactHashes));
    assert!(kinds.contains(&CheckKind::TraceIndexExists));
    assert!(kinds.contains(&CheckKind::TraceChunksExist));
    assert!(kinds.contains(&CheckKind::TraceChunkHashes));
    assert!(kinds.contains(&CheckKind::EventChainIntegrity));
    assert!(kinds.contains(&CheckKind::EventChainTip));
    assert!(kinds.contains(&CheckKind::ManifestSignature));
}

// ── Verify: all checks for untraced run ──

#[test]
fn verify_report_has_all_12_checks_for_untraced_run() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = sandboxed_job(&["echo", "no trace checks"]);
    let policy = default_resolved_policy(Some(Duration::from_secs(30)));

    let result = runner.execute(&job, &policy, true, None).unwrap();
    let report = verify_run(&store, &result.run_id).unwrap();

    assert_eq!(
        report.checks.len(),
        12,
        "expected 12 checks even for untraced run, got {}",
        report.checks.len()
    );

    // All 5 trace checks should be Skip.
    for kind in [
        CheckKind::TraceIndexExists,
        CheckKind::TraceChunksExist,
        CheckKind::TraceChunkHashes,
        CheckKind::EventChainIntegrity,
        CheckKind::EventChainTip,
    ] {
        let check = find_check(&report, kind);
        assert_eq!(
            check.status,
            CheckStatus::Skip,
            "{kind:?} should be Skip for untraced run"
        );
    }
}

// ── GC: multiple runs, GC only removes orphaned blobs ──

#[test]
fn gc_only_removes_blobs_from_deleted_run() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let runner = Runner::new(store.clone()).unwrap();
    let policy = default_resolved_policy(Some(Duration::from_secs(30)));

    // Run 1: "echo aaa" and Run 2: "echo bbb".
    let r1 = runner
        .execute(&sandboxed_job(&["echo", "aaa"]), &policy, true, None)
        .unwrap();
    runner
        .execute(&sandboxed_job(&["echo", "bbb"]), &policy, true, None)
        .unwrap();

    let blobs_before = cas.list_all().unwrap().len();

    // Delete only run 1.
    let db = OaieDb::open(&store.db_path).unwrap();
    db.delete_run(&r1.run_id, &store.runs_dir).unwrap();

    let gc_result = gc(&store, Duration::ZERO, false).unwrap();

    // Some blobs removed (run 1's unique blobs), but run 2's still there.
    let blobs_after = cas.list_all().unwrap().len();
    assert!(blobs_after > 0, "run 2's blobs should still be present");
    assert!(blobs_after < blobs_before, "some blobs should be removed");
    assert!(gc_result.blobs_removed > 0);
    assert!(gc_result.blobs_retained > 0);

    // Verify run 2 still passes verification.
    let runs = db.list_all_runs().unwrap();
    assert_eq!(runs.len(), 1, "only run 2 should remain");
    let report = verify_run(&store, &runs[0].run_id).unwrap();
    assert!(
        report.passed(),
        "run 2 should still verify after GC: {:?}",
        report
            .checks
            .iter()
            .filter(|c| c.status == CheckStatus::Fail)
            .collect::<Vec<_>>()
    );
}

// ── Verify: summary format ──

#[test]
fn verify_report_summary_format() {
    use oaie_core::verify::{CheckResult, VerifyReport};

    let report = VerifyReport {
        run_id: oaie_core::run_id::RunId::new(),
        checks: vec![
            CheckResult {
                check: CheckKind::ManifestExists,
                status: CheckStatus::Pass,
                detail: None,
            },
            CheckResult {
                check: CheckKind::ManifestParseable,
                status: CheckStatus::Pass,
                detail: None,
            },
            CheckResult {
                check: CheckKind::OutputArtifactsExist,
                status: CheckStatus::Fail,
                detail: Some("1 missing".into()),
            },
            CheckResult {
                check: CheckKind::TraceIndexExists,
                status: CheckStatus::Skip,
                detail: None,
            },
            CheckResult {
                check: CheckKind::TraceChunksExist,
                status: CheckStatus::Skip,
                detail: None,
            },
        ],
    };

    assert_eq!(report.summary(), "2 passed, 1 failed, 2 skipped");
    assert!(!report.passed());
}

// ── Verify: empty checks list ──

#[test]
fn verify_report_empty_checks_passes() {
    use oaie_core::verify::VerifyReport;

    let report = VerifyReport {
        run_id: oaie_core::run_id::RunId::new(),
        checks: vec![],
    };

    // Empty report trivially passes (no failures).
    assert!(report.passed());
    assert_eq!(report.summary(), "0 passed, 0 failed, 0 skipped");
}
