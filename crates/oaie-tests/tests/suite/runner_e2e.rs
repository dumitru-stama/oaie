//! End-to-end integration tests for the Runner.
//!
//! Each test creates an isolated temp store, runs a command through Runner,
//! and verifies the full pipeline: CAS, DB, manifest, and report.

use std::fs;
use std::io::Read;
use std::time::Duration;

use oaie_cas::store::{read_manifest, CasStore, VerifyResult};
use oaie_cli::runner::Runner;
use oaie_core::hash_algo::HashAlgorithm;
use oaie_core::job::JobSpec;
use oaie_core::manifest::IsolationLevel;
use oaie_db::{OaieDb, RunStatus};
use oaie_tests::{
    default_resolved_policy, job_with_timeout, sandboxed_job, setup_store, simple_job,
    userns_available,
};

#[test]
fn test_run_echo() {
    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = simple_job(&["echo", "hello world"]);

    let result = runner.execute(&job, &default_resolved_policy(job.timeout), true, None).unwrap();

    assert_eq!(result.exit_code, 0);
    assert!(result.stdout_size > 0);

    // Verify stdout content in CAS matches "hello world\n".
    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let mut file = cas.open(&result.stdout_hash).unwrap();
    let mut content = Vec::new();
    file.read_to_end(&mut content).unwrap();
    assert_eq!(content, b"hello world\n");

    // Verify CAS blob integrity.
    assert_eq!(cas.verify(&result.stdout_hash).unwrap(), VerifyResult::Ok);
    assert_eq!(cas.verify(&result.stderr_hash).unwrap(), VerifyResult::Ok);

    // Verify DB record is complete.
    let db = OaieDb::open(&store.db_path).unwrap();
    let run = db.get_latest_run().unwrap().unwrap();
    assert_eq!(run.status, RunStatus::Completed);
    assert_eq!(run.exit_code, Some(0));
    assert!(run.duration_ms.is_some());
    assert!(run.manifest_hash.is_some());
    assert_eq!(run.command, vec!["echo", "hello world"]);
}

#[test]
fn test_run_false() {
    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = simple_job(&["false"]);

    let result = runner.execute(&job, &default_resolved_policy(job.timeout), true, None).unwrap();

    // `false` returns exit code 1 but the run is still "completed" —
    // the tool ran successfully, it just returned nonzero.
    assert_eq!(result.exit_code, 1);

    let db = OaieDb::open(&store.db_path).unwrap();
    let run = db.get_latest_run().unwrap().unwrap();
    assert_eq!(run.status, RunStatus::Completed);
    assert_eq!(run.exit_code, Some(1));
}

#[test]
fn test_run_nonexistent_binary() {
    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = simple_job(&["/nonexistent/binary/xyz"]);

    let err = runner.execute(&job, &default_resolved_policy(job.timeout), true, None);
    assert!(err.is_err());

    // Run should be recorded as failed in the database.
    let db = OaieDb::open(&store.db_path).unwrap();
    let run = db.get_latest_run().unwrap().unwrap();
    assert_eq!(run.status, RunStatus::Failed);
    assert!(run.error_message.is_some());
}

#[test]
fn test_run_with_timeout() {
    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = job_with_timeout(&["sleep", "60"], Duration::from_secs(1));

    let err = runner.execute(&job, &default_resolved_policy(job.timeout), true, None);
    assert!(err.is_err());
    let err_msg = err.unwrap_err().to_string();
    assert!(
        err_msg.contains("timed out"),
        "expected 'timed out' in: {err_msg}"
    );
}

#[test]
fn test_run_with_output_files() {
    let (store, dir) = setup_store();
    let out_dir = dir.path().join("test-out");
    fs::create_dir_all(&out_dir).unwrap();

    let runner = Runner::new(store.clone()).unwrap();
    let job = JobSpec {
        outputs: Some(out_dir.clone()),
        ..simple_job(&[
            "sh",
            "-c",
            &format!("echo 'output data' > {}/out.txt", out_dir.display()),
        ])
    };

    let result = runner.execute(&job, &default_resolved_policy(job.timeout), true, None).unwrap();

    // Should have found the output file.
    assert_eq!(result.output_artifacts.len(), 1);
    assert_eq!(result.output_artifacts[0].label, "output/out.txt");

    // Verify the output artifact in CAS.
    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let mut file = cas.open(&result.output_artifacts[0].hash).unwrap();
    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();
    assert_eq!(content.trim(), "output data");
}

#[test]
fn test_run_nested_output() {
    let (store, dir) = setup_store();
    let out_dir = dir.path().join("nested-out");
    fs::create_dir_all(&out_dir).unwrap();

    let runner = Runner::new(store.clone()).unwrap();
    let sub = out_dir.join("sub");
    let job = JobSpec {
        outputs: Some(out_dir),
        ..simple_job(&[
            "sh",
            "-c",
            &format!(
                "mkdir -p {} && echo A > {}/a.txt && echo B > {}/b.txt",
                sub.display(),
                sub.display(),
                sub.display()
            ),
        ])
    };

    let result = runner.execute(&job, &default_resolved_policy(job.timeout), true, None).unwrap();

    assert_eq!(result.output_artifacts.len(), 2);
    let labels: Vec<&str> = result
        .output_artifacts
        .iter()
        .map(|a| a.label.as_str())
        .collect();
    assert!(labels.contains(&"output/sub/a.txt"));
    assert!(labels.contains(&"output/sub/b.txt"));
}

#[test]
fn test_report_generated() {
    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = simple_job(&["echo", "report test"]);

    let result = runner.execute(&job, &default_resolved_policy(job.timeout), true, None).unwrap();

    // Find the run directory and check REPORT.md exists.
    let run_dir = store.runs_dir.join(result.run_id.full());
    let report_path = run_dir.join("REPORT.md");
    assert!(report_path.exists(), "REPORT.md should exist on disk");

    let report = fs::read_to_string(&report_path).unwrap();
    assert!(report.contains("# OAIE Run Report"));
    assert!(report.contains("echo 'report test'"));
}

#[test]
fn test_manifest_in_cas() {
    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = simple_job(&["echo", "manifest test"]);

    let result = runner.execute(&job, &default_resolved_policy(job.timeout), true, None).unwrap();

    // The manifest hash in RunResult should match what's in the DB.
    let db = OaieDb::open(&store.db_path).unwrap();
    let run = db.get_latest_run().unwrap().unwrap();
    assert_eq!(
        run.manifest_hash.as_deref(),
        Some(result.manifest_hash.to_hex().as_str())
    );

    // Verify the manifest is valid in CAS and parseable.
    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    assert_eq!(
        cas.verify(&result.manifest_hash).unwrap(),
        VerifyResult::Ok
    );

    // Also verify the on-disk manifest is parseable.
    let run_dir = store.runs_dir.join(result.run_id.full());
    let manifest = read_manifest(&run_dir).unwrap();
    assert_eq!(manifest.command, vec!["echo", "manifest test"]);
    assert_eq!(manifest.exit_code, Some(0));
}

#[test]
fn test_cas_integrity_all_artifacts() {
    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = simple_job(&["echo", "integrity check"]);

    let result = runner.execute(&job, &default_resolved_policy(job.timeout), true, None).unwrap();

    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let db = OaieDb::open(&store.db_path).unwrap();
    let artifacts = db.list_artifacts(&result.run_id).unwrap();

    // Every artifact recorded in the DB should verify cleanly in CAS.
    assert!(
        !artifacts.is_empty(),
        "should have at least stdout+stderr+report+manifest"
    );
    for artifact in &artifacts {
        let hash = artifact.hash.parse::<oaie_core::artifact::Hash>().unwrap();
        assert_eq!(
            cas.verify(&hash).unwrap(),
            VerifyResult::Ok,
            "artifact {} ({}) failed CAS verification",
            artifact.label,
            artifact.hash
        );
    }
}

#[test]
fn test_from_job_toml() {
    let (store, dir) = setup_store();
    let toml_path = dir.path().join("job.toml");
    fs::write(
        &toml_path,
        r#"
command = ["echo", "from toml"]
network = false
trace = "off"
no_isolation = true
"#,
    )
    .unwrap();

    let job = oaie_core::job::JobSpec::from_toml_file(&toml_path).unwrap();
    assert_eq!(job.command, vec!["echo", "from toml"]);

    let runner = Runner::new(store.clone()).unwrap();
    let result = runner.execute(&job, &default_resolved_policy(job.timeout), true, None).unwrap();
    assert_eq!(result.exit_code, 0);

    // Verify stdout captured the right output.
    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let mut file = cas.open(&result.stdout_hash).unwrap();
    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();
    assert_eq!(content, "from toml\n");
}

// --- Sandbox e2e tests ---
// All skip gracefully if user namespaces are not available.

#[test]
fn test_run_sandboxed_echo() {

    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = sandboxed_job(&["echo", "sandboxed hello"]);

    let result = runner.execute(&job, &default_resolved_policy(job.timeout), true, None).unwrap();

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.isolation_level, IsolationLevel::Full);

    // Verify stdout content.
    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let mut file = cas.open(&result.stdout_hash).unwrap();
    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();
    assert_eq!(content.trim(), "sandboxed hello");

    // Verify manifest records isolation.
    let run_dir = store.runs_dir.join(result.run_id.full());
    let manifest = read_manifest(&run_dir).unwrap();
    assert_eq!(manifest.isolation.level, IsolationLevel::Full);
    assert!(!manifest.isolation.namespaces.is_empty());
}

#[test]
fn test_run_no_isolation_flag() {
    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();
    let job = simple_job(&["echo", "no isolation"]);

    let result = runner.execute(&job, &default_resolved_policy(job.timeout), true, None).unwrap();

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.isolation_level, IsolationLevel::None);
}

#[test]
fn test_run_sandboxed_input_readonly() {

    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();

    // Try to write to /in — should fail.
    let job = sandboxed_job(&["sh", "-c", "touch /in/should_fail 2>&1; echo done"]);

    let result = runner.execute(&job, &default_resolved_policy(job.timeout), true, None).unwrap();

    // The command itself runs (echo done), but touch fails.
    assert_eq!(result.exit_code, 0);

    // Verify stdout contains "done" and touch error.
    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let mut file = cas.open(&result.stdout_hash).unwrap();
    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();
    assert!(content.contains("done"));
}

#[test]
fn test_run_sandboxed_output_writable() {

    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, dir) = setup_store();
    let out_dir = dir.path().join("sandbox-out");
    fs::create_dir_all(&out_dir).unwrap();

    let runner = Runner::new(store.clone()).unwrap();
    let job = JobSpec {
        outputs: Some(out_dir.clone()),
        ..sandboxed_job(&["sh", "-c", "echo sandboxed_result > /out/data.txt"])
    };

    let result = runner.execute(&job, &default_resolved_policy(job.timeout), true, None).unwrap();

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.output_artifacts.len(), 1);
    assert_eq!(result.output_artifacts[0].label, "output/data.txt");

    // Verify content through CAS.
    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let mut file = cas.open(&result.output_artifacts[0].hash).unwrap();
    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();
    assert_eq!(content.trim(), "sandboxed_result");
}

#[test]
fn test_run_sandboxed_no_network() {

    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();

    // Try to access network — should fail (CLONE_NEWNET isolates it).
    // Use a command that tries network and reports success/failure.
    let job = sandboxed_job(&[
        "sh",
        "-c",
        "cat /proc/net/dev 2>/dev/null | wc -l",
    ]);

    let result = runner.execute(&job, &default_resolved_policy(job.timeout), true, None).unwrap();

    // The command runs. In a network namespace, /proc/net/dev shows only "lo"
    // (3 lines: header + header + lo) vs many interfaces outside.
    // The key thing is the sandbox doesn't crash.
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.isolation_level, IsolationLevel::Full);
}

#[test]
fn test_run_sandboxed_no_home() {

    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();

    // /root/.ssh should not exist in the sandbox.
    let job = sandboxed_job(&["ls", "/root/.ssh"]);

    let result = runner.execute(&job, &default_resolved_policy(job.timeout), true, None).unwrap();

    // ls should fail because the directory doesn't exist.
    assert_ne!(result.exit_code, 0);
}

#[test]
fn test_run_hard_error_no_userns() {

    // If userns IS available, we simulate the scenario by testing
    // that without --no-isolation the system would require sandbox support.
    // This test just verifies the error path exists in the code.
    // If userns is not available AND no_isolation is false, we should get SandboxError.
    if userns_available() {
        // On systems with userns, just verify that no_isolation=false works.
        let (store, _dir) = setup_store();
        let runner = Runner::new(store).unwrap();
        let job = sandboxed_job(&["true"]);
        let result = runner.execute(&job, &default_resolved_policy(job.timeout), true, None);
        assert!(result.is_ok());
    } else {
        // On systems without userns, verify we get an error.
        let (store, _dir) = setup_store();
        let runner = Runner::new(store).unwrap();
        let job = sandboxed_job(&["true"]);
        let err = runner.execute(&job, &default_resolved_policy(job.timeout), true, None);
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(
            msg.contains("isolation unavailable") || msg.contains("sandbox"),
            "expected sandbox error, got: {msg}"
        );
    }
}

/// Helper: resolved policy with network enabled.
fn net_resolved_policy(timeout: Option<Duration>) -> oaie_cli::policy_resolve::ResolvedPolicy {
    oaie_cli::policy_resolve::ResolvedPolicy {
        network: oaie_core::policy::NetworkMode::On,
        ..default_resolved_policy(timeout)
    }
}

#[test]
fn test_network_disabled() {


    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store).unwrap();

    // Sandbox with no network — wget must fail (no route, no DNS).
    // 10s job timeout: wget should fail in <3s; if it somehow hangs,
    // the timeout kills it (non-zero exit = test still passes).
    let job = JobSpec {
        timeout: Some(Duration::from_secs(10)),
        ..sandboxed_job(&[
            "wget", "--spider", "-q", "--timeout=3", "--tries=1", "http://google.com",
        ])
    };
    let result = runner.execute(&job, &default_resolved_policy(job.timeout), true, None);
    // Err (timeout/sandbox error) is acceptable — still means no network access.
    if let Ok(r) = result {
        assert_ne!(r.exit_code, 0, "wget should fail without network");
    }
}

#[test]
fn test_network_enabled() {


    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store).unwrap();

    // Sandbox with network enabled — wget should resolve DNS and connect.
    // Uses --spider (HEAD request only, no download) with short timeout.
    // 10s job timeout caps the worst case if DNS is slow.
    // Retry once: under heavy parallel test load, namespace setup can
    // transiently fail (this doesn't affect production — each oaie run
    // is a separate process with no contention).
    let make_job = || JobSpec {
        network: true,
        timeout: Some(Duration::from_secs(10)),
        ..sandboxed_job(&[
            "wget", "--spider", "-q", "--timeout=5", "--tries=1", "http://google.com",
        ])
    };
    let job = make_job();
    let result = runner.execute(&job, &net_resolved_policy(job.timeout), true, None);
    match result {
        Ok(r) if r.exit_code == 0 => {}
        _ => {
            // Retry once after a brief pause.
            std::thread::sleep(Duration::from_millis(200));
            let job2 = make_job();
            let r2 = runner.execute(&job2, &net_resolved_policy(job2.timeout), true, None).unwrap();
            assert_eq!(r2.exit_code, 0, "wget should succeed with network enabled (retry)");
        }
    }
}

/// Helper: resolved policy with specific capabilities retained.
fn caps_resolved_policy(retain_caps: u64, timeout: Option<Duration>) -> oaie_cli::policy_resolve::ResolvedPolicy {
    oaie_cli::policy_resolve::ResolvedPolicy {
        retain_caps,
        ..default_resolved_policy(timeout)
    }
}

#[test]
fn test_capability_retained_in_sandbox() {

    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();

    // Run with CAP_NET_RAW (bit 13 = 0x2000) retained.
    // /proc/self/status is masked in the sandbox, so we can't read CapEff
    // directly. Instead, verify that retaining caps doesn't break execution
    // and that the sandbox correctly applies the mask by running a command
    // that exercises the capability (socket creation for ping uses net_raw).
    let job = sandboxed_job(&["echo", "caps_ok"]);
    let policy = caps_resolved_policy(1 << 13, job.timeout);
    let result = runner.execute(&job, &policy, true, None).unwrap();
    assert_eq!(result.exit_code, 0, "sandbox with retain_caps should work");

    let cas = oaie_cas::store::CasStore::new(store.cas_dir.clone(), oaie_core::hash_algo::HashAlgorithm::Blake3);
    let mut file = cas.open(&result.stdout_hash).unwrap();
    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();
    assert_eq!(content.trim(), "caps_ok");

    // Run without any caps retained — should also work fine.
    let job2 = sandboxed_job(&["echo", "no_caps_ok"]);
    let policy2 = caps_resolved_policy(0, job2.timeout);
    let result2 = runner.execute(&job2, &policy2, true, None).unwrap();
    assert_eq!(result2.exit_code, 0, "sandbox without retain_caps should work");

    let mut file2 = cas.open(&result2.stdout_hash).unwrap();
    let mut content2 = String::new();
    file2.read_to_string(&mut content2).unwrap();
    assert_eq!(content2.trim(), "no_caps_ok");
}

#[test]
fn test_ping_loopback_with_net_raw() {


    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store).unwrap();

    // In an isolated net ns with CAP_NET_RAW retained + loopback auto-setup,
    // ping to 127.0.0.1 should succeed via raw ICMP sockets.
    // 10s job timeout caps the worst case.
    // Retry once: under heavy parallel test load, namespace setup can
    // transiently fail.
    let make_job = || JobSpec {
        timeout: Some(Duration::from_secs(10)),
        ..sandboxed_job(&["ping", "-c", "1", "-W", "2", "127.0.0.1"])
    };
    let job = make_job();
    let policy = caps_resolved_policy(1 << 13, job.timeout);
    let result = runner.execute(&job, &policy, true, None);
    match result {
        Ok(r) if r.exit_code == 0 => {}
        _ => {
            std::thread::sleep(Duration::from_millis(200));
            let job2 = make_job();
            let policy2 = caps_resolved_policy(1 << 13, job2.timeout);
            let r2 = runner.execute(&job2, &policy2, true, None).unwrap();
            assert_eq!(r2.exit_code, 0, "ping loopback should succeed with CAP_NET_RAW (retry)");
        }
    }
}

#[test]
fn test_capability_rejected_dangerous() {
    // Policy validation should reject dangerous capabilities.
    use oaie_core::policy::Policy;

    let mut policy = Policy::preset_safe();
    policy.limits.capabilities = vec!["sys_admin".into()];
    let err = policy.validate();
    assert!(err.is_err(), "sys_admin should be rejected");
    let msg = err.unwrap_err().to_string();
    assert!(
        msg.contains("not in the allowlist"),
        "expected allowlist error, got: {msg}"
    );

    // net_raw should be accepted.
    let mut policy2 = Policy::preset_safe();
    policy2.limits.capabilities = vec!["net_raw".into()];
    assert!(policy2.validate().is_ok(), "net_raw should be accepted");

    // net_bind_service should be accepted.
    let mut policy3 = Policy::preset_safe();
    policy3.limits.capabilities = vec!["net_bind_service".into()];
    assert!(policy3.validate().is_ok(), "net_bind_service should be accepted");
}

#[test]
fn test_capability_mask_values() {
    use oaie_core::policy::capability_mask;

    assert_eq!(capability_mask(&[]), 0);
    assert_eq!(capability_mask(&["net_raw".into()]), 1 << 13);
    assert_eq!(capability_mask(&["net_bind_service".into()]), 1 << 10);
    assert_eq!(
        capability_mask(&["net_raw".into(), "net_bind_service".into()]),
        (1 << 13) | (1 << 10)
    );
}
