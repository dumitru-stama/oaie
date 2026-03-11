//! Tests for `oaie doctor` structured probes and output scan limits.

use oaie_cas::store::CasStore;
use oaie_core::hash_algo::HashAlgorithm;
use oaie_cli::doctor::{
    probe_kernel_cves, probe_landlock_status, run_doctor, OverallStatus, ProbeStatus,
};
use oaie_db::OaieDb;
use oaie_tests::setup_store;

// ── Doctor probe tests ──

#[test]
fn doctor_healthy_system() {
    let (store, _dir) = setup_store();
    let report = run_doctor(Some(&store));

    // On a typical Linux test system, user_ns should be Available.
    let userns = report
        .probes
        .iter()
        .find(|p| p.name == "User namespaces")
        .unwrap();
    // Accept Available or Advisory — depends on test environment.
    assert!(
        userns.status == ProbeStatus::Available || userns.status == ProbeStatus::Advisory,
        "unexpected userns status: {:?}",
        userns.status
    );

    // With a valid store, CAS and SQLite should not be Broken.
    let cas = report
        .probes
        .iter()
        .find(|p| p.name == "CAS store")
        .unwrap();
    assert_eq!(cas.status, ProbeStatus::Available);

    let sqlite = report.probes.iter().find(|p| p.name == "SQLite").unwrap();
    assert_eq!(sqlite.status, ProbeStatus::Available);
}

#[test]
fn doctor_optional_missing_does_not_degrade() {
    let (store, _dir) = setup_store();
    let report = run_doctor(Some(&store));

    // eBPF and Firecracker are NotAvailable — should not affect overall status.
    let ebpf = report
        .probes
        .iter()
        .find(|p| p.name == "eBPF tracer")
        .unwrap();
    assert_eq!(ebpf.status, ProbeStatus::NotAvailable);

    let fc = report
        .probes
        .iter()
        .find(|p| p.name == "Firecracker")
        .unwrap();
    assert_eq!(fc.status, ProbeStatus::NotAvailable);

    // Overall should not be Broken just because of optional features.
    assert_ne!(report.overall, OverallStatus::Broken);
}

#[test]
fn doctor_broken_cas() {
    // Create a store but remove the CAS directory to simulate breakage.
    let (store, _dir) = setup_store();
    std::fs::remove_dir_all(&store.cas_dir).unwrap();

    let report = run_doctor(Some(&store));

    let cas = report
        .probes
        .iter()
        .find(|p| p.name == "CAS store")
        .unwrap();
    assert_eq!(cas.status, ProbeStatus::Broken);
    assert_eq!(report.overall, OverallStatus::Broken);
}

#[test]
fn doctor_broken_db() {
    // Create a store but corrupt the DB file.
    let (store, _dir) = setup_store();
    std::fs::write(&store.db_path, b"not a sqlite database").unwrap();

    let report = run_doctor(Some(&store));

    let sqlite = report.probes.iter().find(|p| p.name == "SQLite").unwrap();
    assert_eq!(sqlite.status, ProbeStatus::Broken);
}

#[test]
fn doctor_all_probes_present() {
    let (store, _dir) = setup_store();
    let report = run_doctor(Some(&store));
    assert_eq!(
        report.probes.len(),
        20,
        "expected exactly 20 probes, got {}",
        report.probes.len()
    );
}

#[test]
fn doctor_kernel_cve_check() {
    // Just verify it doesn't panic — the actual CVE list depends on kernel version.
    let caps = oaie_sandbox::probe::SystemCaps::detect();
    let probe = probe_kernel_cves(&caps);
    assert!(
        probe.status == ProbeStatus::Available || probe.status == ProbeStatus::Advisory
    );
}

#[test]
fn doctor_store_permissions_700() {
    let (store, _dir) = setup_store();
    // setup_store creates with default permissions; explicitly set 0o700.
    std::fs::set_permissions(
        &store.root,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();

    let report = run_doctor(Some(&store));
    let perms = report
        .probes
        .iter()
        .find(|p| p.name == "Store permissions")
        .unwrap();
    assert_eq!(perms.status, ProbeStatus::Available);
}

#[test]
fn doctor_store_permissions_755() {
    use std::os::unix::fs::PermissionsExt;
    let (store, _dir) = setup_store();
    std::fs::set_permissions(&store.root, PermissionsExt::from_mode(0o755)).unwrap();

    let report = run_doctor(Some(&store));
    let perms = report
        .probes
        .iter()
        .find(|p| p.name == "Store permissions")
        .unwrap();
    assert_eq!(perms.status, ProbeStatus::Advisory);
}

// ── Output scan limit tests ──

use oaie_cli::runner::collect_outputs_with_limits;
use oaie_core::store_config::{
    DEFAULT_MAX_OUTPUT_FILES, DEFAULT_MAX_OUTPUT_FILE_SIZE, DEFAULT_MAX_OUTPUT_TOTAL,
};
use std::io::Write;

#[test]
fn output_scan_file_count_limit() {
    let dir = tempfile::tempdir().unwrap();
    let out_dir = dir.path().join("out");
    std::fs::create_dir(&out_dir).unwrap();

    // Create 5 files, set limit to 3.
    for i in 0..5 {
        let path = out_dir.join(format!("file{i}.txt"));
        std::fs::write(&path, format!("content {i}")).unwrap();
    }

    let cas_dir = dir.path().join("cas");
    std::fs::create_dir(&cas_dir).unwrap();
    let cas = CasStore::new(cas_dir, HashAlgorithm::Blake3);

    let artifacts =
        collect_outputs_with_limits(&out_dir, &cas, 3, DEFAULT_MAX_OUTPUT_FILE_SIZE, DEFAULT_MAX_OUTPUT_TOTAL)
            .unwrap();
    assert_eq!(artifacts.len(), 3);
}

#[test]
fn output_scan_single_file_limit() {
    let dir = tempfile::tempdir().unwrap();
    let out_dir = dir.path().join("out");
    std::fs::create_dir(&out_dir).unwrap();

    // Create one small file and one that exceeds the per-file limit.
    std::fs::write(out_dir.join("small.txt"), "small").unwrap();

    let big_path = out_dir.join("big.bin");
    let mut f = std::fs::File::create(&big_path).unwrap();
    // Write just enough to exceed a 100-byte limit.
    f.write_all(&[0u8; 200]).unwrap();

    let cas_dir = dir.path().join("cas");
    std::fs::create_dir(&cas_dir).unwrap();
    let cas = CasStore::new(cas_dir, HashAlgorithm::Blake3);

    let artifacts =
        collect_outputs_with_limits(&out_dir, &cas, DEFAULT_MAX_OUTPUT_FILES, 100, DEFAULT_MAX_OUTPUT_TOTAL)
            .unwrap();
    // Only the small file should be collected.
    assert_eq!(artifacts.len(), 1);
    assert!(artifacts[0].label.contains("small.txt"));
}

#[test]
fn output_scan_total_bytes_limit() {
    let dir = tempfile::tempdir().unwrap();
    let out_dir = dir.path().join("out");
    std::fs::create_dir(&out_dir).unwrap();

    // Create 3 files of 100 bytes each, set total limit to 250 bytes.
    for i in 0..3 {
        let path = out_dir.join(format!("file{i}.txt"));
        std::fs::write(&path, [b'x'; 100]).unwrap();
    }

    let cas_dir = dir.path().join("cas");
    std::fs::create_dir(&cas_dir).unwrap();
    let cas = CasStore::new(cas_dir, HashAlgorithm::Blake3);

    let artifacts = collect_outputs_with_limits(
        &out_dir,
        &cas,
        DEFAULT_MAX_OUTPUT_FILES,
        DEFAULT_MAX_OUTPUT_FILE_SIZE,
        250,
    )
    .unwrap();
    // Should collect 2 files (200 bytes), third would push over 250.
    assert_eq!(artifacts.len(), 2);
}

// ── Landlock probe test ──

#[test]
fn landlock_probe_valid_status() {
    let probe = probe_landlock_status();
    // Must be either Available or NotAvailable — never Broken or Advisory.
    assert!(
        probe.status == ProbeStatus::Available || probe.status == ProbeStatus::NotAvailable,
        "unexpected landlock probe status: {:?}",
        probe.status
    );
}

// ── DB health tests ──

#[test]
fn db_check_health_valid() {
    // Use a file-based DB so WAL mode works (in-memory uses journal_mode=memory).
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.sqlite");
    let db = OaieDb::open(&db_path).unwrap();
    db.initialize().unwrap();

    for _ in 0..3 {
        oaie_tests::insert_test_run(&db, &["echo", "hello"], oaie_db::RunStatus::Completed);
    }

    let health = db.check_health().unwrap();
    assert_eq!(health.run_count, 3);
    assert!(health.wal_mode);
}

#[test]
fn db_check_health_empty() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.sqlite");
    let db = OaieDb::open(&db_path).unwrap();
    db.initialize().unwrap();

    let health = db.check_health().unwrap();
    assert_eq!(health.run_count, 0);
    assert!(health.wal_mode);
}

// ── Corner case tests ──

#[test]
fn doctor_no_store() {
    // Doctor should work before `oaie init` — store probes report Broken,
    // namespace/kernel probes still run.
    let report = run_doctor(None);

    // CAS, SQLite, and Store permissions should be Broken.
    let cas = report
        .probes
        .iter()
        .find(|p| p.name == "CAS store")
        .unwrap();
    assert_eq!(cas.status, ProbeStatus::Broken);

    let sqlite = report.probes.iter().find(|p| p.name == "SQLite").unwrap();
    assert_eq!(sqlite.status, ProbeStatus::Broken);

    let perms = report
        .probes
        .iter()
        .find(|p| p.name == "Store permissions")
        .unwrap();
    assert_eq!(perms.status, ProbeStatus::Broken);

    // Overall must be Broken when store probes are Broken.
    assert_eq!(report.overall, OverallStatus::Broken);

    // But namespace probes should still have run (not panic).
    assert_eq!(report.probes.len(), 20);
}

#[test]
fn output_scan_empty_directory() {
    // An empty output directory should return zero artifacts.
    let dir = tempfile::tempdir().unwrap();
    let out_dir = dir.path().join("out");
    std::fs::create_dir(&out_dir).unwrap();

    let cas_dir = dir.path().join("cas");
    std::fs::create_dir(&cas_dir).unwrap();
    let cas = CasStore::new(cas_dir, HashAlgorithm::Blake3);

    let artifacts = collect_outputs_with_limits(
        &out_dir,
        &cas,
        DEFAULT_MAX_OUTPUT_FILES,
        DEFAULT_MAX_OUTPUT_FILE_SIZE,
        DEFAULT_MAX_OUTPUT_TOTAL,
    )
    .unwrap();
    assert!(artifacts.is_empty());
}

#[test]
fn output_scan_nonexistent_directory() {
    // A nonexistent output directory should return zero artifacts (not error).
    let dir = tempfile::tempdir().unwrap();
    let out_dir = dir.path().join("does-not-exist");

    let cas_dir = dir.path().join("cas");
    std::fs::create_dir(&cas_dir).unwrap();
    let cas = CasStore::new(cas_dir, HashAlgorithm::Blake3);

    let artifacts = collect_outputs_with_limits(
        &out_dir,
        &cas,
        DEFAULT_MAX_OUTPUT_FILES,
        DEFAULT_MAX_OUTPUT_FILE_SIZE,
        DEFAULT_MAX_OUTPUT_TOTAL,
    )
    .unwrap();
    assert!(artifacts.is_empty());
}

#[test]
fn doctor_isolation_level_matches_userns() {
    // Isolation level should be "full" when user_ns is available, "none" otherwise.
    let (store, _dir) = setup_store();
    let report = run_doctor(Some(&store));

    let userns = report
        .probes
        .iter()
        .find(|p| p.name == "User namespaces")
        .unwrap();

    match userns.status {
        ProbeStatus::Available => assert!(
            report.isolation_level.starts_with("full"),
            "expected isolation level starting with 'full', got '{}'",
            report.isolation_level
        ),
        _ => assert_eq!(report.isolation_level, "none"),
    }
}
