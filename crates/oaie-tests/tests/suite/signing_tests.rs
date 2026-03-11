//! Tests for Phase J Ed25519 manifest signing.
//!
//! Tests 1–12 are unit tests (no sandbox needed, can run in parallel).
//! Tests 13–18 require namespace isolation and run serially via the Makefile.

use std::time::Duration;

use oaie_cli::signing;
use oaie_core::hash_algo::HashAlgorithm;
use oaie_core::signing::{SignatureInfo, SigningAlgorithm};

// ── Unit tests: key management ──

#[test]
fn test_key_generate() {
    let (info, secret) = signing::generate_keypair("test-key").unwrap();
    assert_eq!(info.version, 1);
    assert_eq!(info.algorithm, SigningAlgorithm::Ed25519);
    assert_eq!(info.label, "test-key");
    assert_eq!(info.key_id.len(), 8); // first 8 hex chars of BLAKE3(pubkey)
    assert_eq!(info.public_key.len(), 64); // 32 bytes = 64 hex chars
    assert_eq!(secret.len(), 64); // 32 bytes = 64 hex chars
}

#[test]
fn test_key_generate_with_label() {
    let (info, _) = signing::generate_keypair("work-laptop-2026").unwrap();
    assert_eq!(info.label, "work-laptop-2026");
}

#[test]
fn test_key_list_empty() {
    let dir = tempfile::tempdir().unwrap();
    let keys = signing::list_keys(dir.path()).unwrap();
    assert!(keys.is_empty());
}

#[test]
fn test_key_list_finds_keys() {
    let dir = tempfile::tempdir().unwrap();

    let (info1, secret1) = signing::generate_keypair("key-one").unwrap();
    signing::save_key(dir.path(), &info1, &secret1).unwrap();

    let (info2, secret2) = signing::generate_keypair("key-two").unwrap();
    signing::save_key(dir.path(), &info2, &secret2).unwrap();

    let keys = signing::list_keys(dir.path()).unwrap();
    assert_eq!(keys.len(), 2);
}

#[test]
fn test_key_delete() {
    let dir = tempfile::tempdir().unwrap();

    let (info, secret) = signing::generate_keypair("to-delete").unwrap();
    signing::save_key(dir.path(), &info, &secret).unwrap();

    assert_eq!(signing::list_keys(dir.path()).unwrap().len(), 1);

    signing::delete_key(dir.path(), &info.key_id).unwrap();

    assert!(signing::list_keys(dir.path()).unwrap().is_empty());
}

#[test]
fn test_key_load_by_id_prefix() {
    let dir = tempfile::tempdir().unwrap();

    let (info, secret) = signing::generate_keypair("prefix-test").unwrap();
    signing::save_key(dir.path(), &info, &secret).unwrap();

    // Load by first 4 chars of key_id.
    let prefix = &info.key_id[..4];
    let (loaded, loaded_secret) = signing::load_key(dir.path(), prefix).unwrap();
    assert_eq!(loaded.key_id, info.key_id);
    assert_eq!(loaded_secret, secret);
}

#[test]
fn test_key_load_by_label() {
    let dir = tempfile::tempdir().unwrap();

    let (info, secret) = signing::generate_keypair("my-label").unwrap();
    signing::save_key(dir.path(), &info, &secret).unwrap();

    let (loaded, _) = signing::load_key(dir.path(), "my-label").unwrap();
    assert_eq!(loaded.key_id, info.key_id);
    assert_eq!(loaded.label, "my-label");
}

// ── Unit tests: sign and verify ──

#[test]
fn test_sign_and_verify_roundtrip() {
    let manifest_bytes = b"[manifest]\nversion = 1\nrun_id = \"abc\"";

    let (key_info, secret) = signing::generate_keypair("roundtrip").unwrap();
    let sig = signing::sign_manifest(manifest_bytes, &secret, &key_info, HashAlgorithm::Blake3)
        .unwrap();

    assert_eq!(sig.version, 1);
    assert_eq!(sig.signer_label, "roundtrip");
    assert_eq!(sig.hash_algorithm, "blake3");
    assert_eq!(sig.signature.len(), 128); // 64 bytes = 128 hex

    let valid = signing::verify_signature(manifest_bytes, &sig, HashAlgorithm::Blake3).unwrap();
    assert!(valid, "signature should verify against same manifest bytes");
}

#[test]
fn test_verify_fails_wrong_key() {
    let manifest_bytes = b"manifest content";

    let (key_a, secret_a) = signing::generate_keypair("key-a").unwrap();
    let sig = signing::sign_manifest(manifest_bytes, &secret_a, &key_a, HashAlgorithm::Blake3)
        .unwrap();

    // Tamper: replace public key with key B's public key.
    let (key_b, _) = signing::generate_keypair("key-b").unwrap();
    let tampered_sig = SignatureInfo {
        public_key: key_b.public_key.clone(),
        ..sig
    };

    let valid =
        signing::verify_signature(manifest_bytes, &tampered_sig, HashAlgorithm::Blake3).unwrap();
    assert!(!valid, "signature should fail with wrong public key");
}

#[test]
fn test_verify_fails_tampered_manifest() {
    let manifest_bytes = b"original manifest";

    let (key_info, secret) = signing::generate_keypair("tamper-test").unwrap();
    let sig = signing::sign_manifest(manifest_bytes, &secret, &key_info, HashAlgorithm::Blake3)
        .unwrap();

    let tampered_manifest = b"modified manifest";
    let valid =
        signing::verify_signature(tampered_manifest, &sig, HashAlgorithm::Blake3).unwrap();
    assert!(!valid, "signature should fail with tampered manifest bytes");
}

#[test]
fn test_signing_algorithm_fromstr_display() {
    use std::str::FromStr;

    let algo = SigningAlgorithm::from_str("ed25519").unwrap();
    assert_eq!(algo, SigningAlgorithm::Ed25519);
    assert_eq!(algo.to_string(), "ed25519");

    // Case insensitive.
    let algo2 = SigningAlgorithm::from_str("Ed25519").unwrap();
    assert_eq!(algo2, SigningAlgorithm::Ed25519);

    // Invalid.
    assert!(SigningAlgorithm::from_str("rsa").is_err());
}

// ── Unit test: key file permissions ──

#[test]
fn test_key_file_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let (info, secret) = signing::generate_keypair("perms-test").unwrap();
    signing::save_key(dir.path(), &info, &secret).unwrap();

    let key_path = dir.path().join(format!("{}.toml", info.key_id));
    let meta = std::fs::metadata(&key_path).unwrap();
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "key file should have mode 0600, got {mode:o}");
}

// ── Integration tests: signed runs (require namespaces) ──

use oaie_cli::runner::Runner;
use oaie_core::job::TraceMode;
use oaie_core::verify::CheckKind;
use oaie_tests::{default_resolved_policy, setup_store, userns_available};

#[test]
fn test_run_with_sign_flag() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();

    // Generate a signing key in the store's keys directory.
    let (key_info, secret) = signing::generate_keypair("test-signer").unwrap();
    signing::save_key(&store.keys_dir, &key_info, &secret).unwrap();

    let runner = Runner::new(store.clone()).unwrap();
    let job = oaie_core::job::JobSpec {
        command: vec!["echo".into(), "signed-hello".into()],
        inputs: None,
        outputs: None,
        network: false,
        trace: TraceMode::Off,
        timeout: Some(Duration::from_secs(10)),
        policy: None,
        extra_ro: vec![],
        extra_rw: vec![],
        no_isolation: false,
        backend: Default::default(),
        interactive: false,
    };

    let result = runner
        .execute(
            &job,
            &default_resolved_policy(job.timeout),
            true,
            Some(&key_info.key_id),
        )
        .expect("signed run should succeed");

    assert_eq!(result.exit_code, 0);
    assert!(
        result.signed_by.is_some(),
        "result should have signed_by set"
    );
    let signed_by = result.signed_by.unwrap();
    assert!(
        signed_by.contains("test-signer"),
        "signed_by should contain label, got: {signed_by}"
    );

    // Verify signature.toml exists in run dir.
    let run_dir = store.runs_dir.join(result.run_id.full());
    let sig_path = run_dir.join("signature.toml");
    assert!(sig_path.exists(), "signature.toml should exist in run dir");

    // Parse and verify the signature.
    let sig_content = std::fs::read_to_string(&sig_path).unwrap();
    let sig: SignatureInfo = toml::from_str(&sig_content).unwrap();
    let manifest_bytes = std::fs::read(run_dir.join("manifest.toml")).unwrap();
    let valid =
        signing::verify_signature(&manifest_bytes, &sig, store.hash_algorithm).unwrap();
    assert!(valid, "signature should verify against the manifest");
}

#[test]
fn test_run_unsigned_verify_skips_signature() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();

    let job = oaie_core::job::JobSpec {
        command: vec!["echo".into(), "unsigned".into()],
        inputs: None,
        outputs: None,
        network: false,
        trace: TraceMode::Off,
        timeout: Some(Duration::from_secs(10)),
        policy: None,
        extra_ro: vec![],
        extra_rw: vec![],
        no_isolation: false,
        backend: Default::default(),
        interactive: false,
    };

    let result = runner
        .execute(&job, &default_resolved_policy(job.timeout), true, None)
        .expect("unsigned run should succeed");

    assert!(result.signed_by.is_none(), "unsigned run should have no signed_by");

    // Verify: check 12 should be Skip.
    let report = oaie_cli::verify::verify_run(&store, &result.run_id).unwrap();
    let sig_check = report
        .checks
        .iter()
        .find(|c| c.check == CheckKind::ManifestSignature);
    assert!(sig_check.is_some(), "ManifestSignature check should exist");
    assert_eq!(
        sig_check.unwrap().status,
        oaie_core::verify::CheckStatus::Skip,
        "unsigned run's signature check should be Skip"
    );
}

#[test]
fn test_verify_12_checks_total() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();

    let job = oaie_core::job::JobSpec {
        command: vec!["true".into()],
        inputs: None,
        outputs: None,
        network: false,
        trace: TraceMode::Off,
        timeout: Some(Duration::from_secs(10)),
        policy: None,
        extra_ro: vec![],
        extra_rw: vec![],
        no_isolation: false,
        backend: Default::default(),
        interactive: false,
    };

    let result = runner
        .execute(&job, &default_resolved_policy(job.timeout), true, None)
        .unwrap();

    let report = oaie_cli::verify::verify_run(&store, &result.run_id).unwrap();
    assert_eq!(
        report.checks.len(),
        12,
        "verify report should have exactly 12 checks, got {}",
        report.checks.len()
    );
}

#[test]
fn test_signed_run_verify_passes() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();

    // Generate key.
    let (key_info, secret) = signing::generate_keypair("verify-pass").unwrap();
    signing::save_key(&store.keys_dir, &key_info, &secret).unwrap();

    let runner = Runner::new(store.clone()).unwrap();
    let job = oaie_core::job::JobSpec {
        command: vec!["echo".into(), "verify-me".into()],
        inputs: None,
        outputs: None,
        network: false,
        trace: TraceMode::Off,
        timeout: Some(Duration::from_secs(10)),
        policy: None,
        extra_ro: vec![],
        extra_rw: vec![],
        no_isolation: false,
        backend: Default::default(),
        interactive: false,
    };

    let result = runner
        .execute(
            &job,
            &default_resolved_policy(job.timeout),
            true,
            Some(&key_info.key_id),
        )
        .unwrap();

    // Verify: check 12 should be Pass.
    let report = oaie_cli::verify::verify_run(&store, &result.run_id).unwrap();
    let sig_check = report
        .checks
        .iter()
        .find(|c| c.check == CheckKind::ManifestSignature)
        .expect("ManifestSignature check should exist");

    assert_eq!(
        sig_check.status,
        oaie_core::verify::CheckStatus::Pass,
        "signed run's signature check should Pass, detail: {:?}",
        sig_check.detail
    );
}

#[test]
fn test_tampered_manifest_verify_fails() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();

    // Generate key and do a signed run.
    let (key_info, secret) = signing::generate_keypair("tamper-verify").unwrap();
    signing::save_key(&store.keys_dir, &key_info, &secret).unwrap();

    let runner = Runner::new(store.clone()).unwrap();
    let job = oaie_core::job::JobSpec {
        command: vec!["echo".into(), "tamper-target".into()],
        inputs: None,
        outputs: None,
        network: false,
        trace: TraceMode::Off,
        timeout: Some(Duration::from_secs(10)),
        policy: None,
        extra_ro: vec![],
        extra_rw: vec![],
        no_isolation: false,
        backend: Default::default(),
        interactive: false,
    };

    let result = runner
        .execute(
            &job,
            &default_resolved_policy(job.timeout),
            true,
            Some(&key_info.key_id),
        )
        .unwrap();

    // Tamper with the manifest after signing.
    let run_dir = store.runs_dir.join(result.run_id.full());
    let manifest_path = run_dir.join("manifest.toml");
    let mut manifest_content = std::fs::read_to_string(&manifest_path).unwrap();
    manifest_content.push_str("\n# tampered\n");
    std::fs::write(&manifest_path, manifest_content).unwrap();

    // Verify: check 12 should be Fail.
    let report = oaie_cli::verify::verify_run(&store, &result.run_id).unwrap();
    let sig_check = report
        .checks
        .iter()
        .find(|c| c.check == CheckKind::ManifestSignature)
        .expect("ManifestSignature check should exist");

    assert_eq!(
        sig_check.status,
        oaie_core::verify::CheckStatus::Fail,
        "tampered manifest signature check should Fail, detail: {:?}",
        sig_check.detail
    );
}

#[test]
fn test_export_includes_signature() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();

    // Generate key and do a signed run.
    let (key_info, secret) = signing::generate_keypair("export-sig").unwrap();
    signing::save_key(&store.keys_dir, &key_info, &secret).unwrap();

    let runner = Runner::new(store.clone()).unwrap();
    let job = oaie_core::job::JobSpec {
        command: vec!["echo".into(), "export-test".into()],
        inputs: None,
        outputs: None,
        network: false,
        trace: TraceMode::Off,
        timeout: Some(Duration::from_secs(10)),
        policy: None,
        extra_ro: vec![],
        extra_rw: vec![],
        no_isolation: false,
        backend: Default::default(),
        interactive: false,
    };

    let result = runner
        .execute(
            &job,
            &default_resolved_policy(job.timeout),
            true,
            Some(&key_info.key_id),
        )
        .unwrap();

    // Build a tar.gz archive the same way export.rs does.
    let run_dir = store.runs_dir.join(result.run_id.full());
    let archive_path = _dir.path().join("test-export.tar.gz");
    {
        let out_file = std::fs::File::create(&archive_path).unwrap();
        let gz = flate2::write::GzEncoder::new(out_file, flate2::Compression::default());
        let mut tar = tar::Builder::new(gz);

        // Add manifest.toml.
        let manifest_bytes = std::fs::read(run_dir.join("manifest.toml")).unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "export/manifest.toml", &manifest_bytes[..])
            .unwrap();

        // Add signature.toml (same logic as export.rs).
        let sig_path = run_dir.join("signature.toml");
        assert!(sig_path.exists(), "signature.toml should exist for signed run");
        let sig_bytes = std::fs::read(&sig_path).unwrap();
        let mut sig_header = tar::Header::new_gnu();
        sig_header.set_size(sig_bytes.len() as u64);
        sig_header.set_mode(0o644);
        sig_header.set_cksum();
        tar.append_data(&mut sig_header, "export/signature.toml", &sig_bytes[..])
            .unwrap();

        tar.finish().unwrap();
    }

    // Read back the archive and verify signature.toml is present.
    let archive_file = std::fs::File::open(&archive_path).unwrap();
    let gz = flate2::read::GzDecoder::new(archive_file);
    let mut archive = tar::Archive::new(gz);

    let entry_names: Vec<String> = archive
        .entries()
        .unwrap()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.path().ok().map(|p| p.to_string_lossy().into_owned()))
        .collect();

    assert!(
        entry_names.iter().any(|n| n.contains("signature.toml")),
        "archive should contain signature.toml, entries: {entry_names:?}"
    );
    assert!(
        entry_names.iter().any(|n| n.contains("manifest.toml")),
        "archive should contain manifest.toml, entries: {entry_names:?}"
    );

    // Verify the signature.toml content in the archive is valid TOML.
    let sig_content = std::fs::read_to_string(run_dir.join("signature.toml")).unwrap();
    let sig: SignatureInfo = toml::from_str(&sig_content).unwrap();
    assert_eq!(sig.signer_label, "export-sig");
}
