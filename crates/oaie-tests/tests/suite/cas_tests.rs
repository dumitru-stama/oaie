//! Tests extracted from oaie-cas: CAS store operations.

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;

use chrono::Utc;
use oaie_cas::store::{format_bytes, format_duration, read_manifest, VerifyResult};
use oaie_core::artifact::{ArtifactRef, ArtifactType, Hash};
use oaie_core::manifest::{IsolationInfo, IsolationLevel, Manifest};
use oaie_core::run_id::RunId;
use oaie_tests::temp_cas;

#[test]
fn store_bytes_and_verify() {
    let (cas, _dir) = temp_cas();
    let data = b"hello world";

    let (hash, size) = cas.store_bytes(data).unwrap();
    assert_eq!(size, 11);
    assert!(cas.exists(&hash));

    // Verify the hash matches a manual BLAKE3 computation.
    let expected = Hash::from_data(data);
    assert_eq!(hash, expected);

    // Re-read and compare.
    let mut file = cas.open(&hash).unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();
    assert_eq!(contents, data);
}

#[test]
fn store_file_from_disk() {
    let (cas, dir) = temp_cas();
    let file_path = dir.path().join("test.txt");
    fs::write(&file_path, b"file content").unwrap();

    let (hash, size) = cas.store_file(&file_path).unwrap();
    assert_eq!(size, 12);
    assert_eq!(hash, Hash::from_data(b"file content"));
}

#[test]
fn two_level_directory_layout() {
    let (cas, _dir) = temp_cas();
    let (hash, _) = cas.store_bytes(b"check layout").unwrap();

    let path = cas.blob_path(&hash);
    let hex = hash.to_hex();
    // Path should be: <root>/<hex[0..2]>/<hex[2..4]>/<hex>
    let l1 = &hex[..2];
    let l2 = &hex[2..4];
    assert!(path.to_string_lossy().contains(&format!("{l1}/{l2}/")));
    assert!(path.exists());
}

#[test]
fn deduplication() {
    let (cas, _dir) = temp_cas();
    let data = b"same content";

    let (hash1, _) = cas.store_bytes(data).unwrap();
    let (hash2, _) = cas.store_bytes(data).unwrap();
    assert_eq!(hash1, hash2);

    // Only one blob on disk.
    let blobs = cas.list_all().unwrap();
    assert_eq!(blobs.len(), 1);
}

#[test]
fn store_reader_streaming() {
    let (cas, _dir) = temp_cas();
    let data = b"streamed data";
    let mut cursor = std::io::Cursor::new(data.as_slice());

    let (hash, size) = cas.store_reader(&mut cursor).unwrap();
    assert_eq!(size, 13);
    assert_eq!(hash, Hash::from_data(data));
    assert!(cas.exists(&hash));
}

#[test]
fn verify_ok() {
    let (cas, _dir) = temp_cas();
    let (hash, _) = cas.store_bytes(b"verify me").unwrap();
    assert_eq!(cas.verify(&hash).unwrap(), VerifyResult::Ok);
}

#[test]
fn verify_missing() {
    let (cas, _dir) = temp_cas();
    let hash = Hash::from_data(b"not stored");
    assert_eq!(cas.verify(&hash).unwrap(), VerifyResult::Missing);
}

#[test]
fn verify_corrupted() {
    let (cas, _dir) = temp_cas();
    let (hash, _) = cas.store_bytes(b"original").unwrap();

    // Corrupt the blob by overwriting its content.
    let path = cas.blob_path(&hash);
    // Remove read-only protection first.
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o644);
    fs::set_permissions(&path, perms).unwrap();
    fs::write(&path, b"tampered").unwrap();

    match cas.verify(&hash).unwrap() {
        VerifyResult::Corrupted { expected, actual } => {
            assert_eq!(expected, hash);
            assert_ne!(actual, hash);
        }
        other => panic!("expected Corrupted, got {other:?}"),
    }
}

#[test]
fn store_empty_blob() {
    let (cas, _dir) = temp_cas();
    let (hash, size) = cas.store_bytes(b"").unwrap();
    assert_eq!(size, 0);
    assert!(cas.exists(&hash));
    assert_eq!(cas.verify(&hash).unwrap(), VerifyResult::Ok);
}

#[test]
fn list_all_counts() {
    let (cas, _dir) = temp_cas();
    cas.store_bytes(b"one").unwrap();
    cas.store_bytes(b"two").unwrap();
    cas.store_bytes(b"three").unwrap();
    cas.store_bytes(b"one").unwrap(); // Dedup.

    let blobs = cas.list_all().unwrap();
    assert_eq!(blobs.len(), 3);
}

#[test]
fn blobs_are_read_only() {
    let (cas, _dir) = temp_cas();
    let (hash, _) = cas.store_bytes(b"readonly").unwrap();
    let path = cas.blob_path(&hash);
    let perms = fs::metadata(&path).unwrap().permissions();
    assert_eq!(perms.mode() & 0o777, 0o444);
}

#[test]
fn cleanup_temps() {
    let (cas, dir) = temp_cas();
    // Create fake temp files using dir.path() (same as CAS root).
    fs::write(dir.path().join(".tmp-fake1"), b"junk").unwrap();
    fs::write(dir.path().join(".tmp-fake2"), b"junk").unwrap();

    // cleanup_temps_all() removes all temp files regardless of age.
    // (cleanup_temps() skips files newer than 1 hour — used at run start.)
    let cleaned = cas.cleanup_temps_all().unwrap();
    assert_eq!(cleaned, 2);
    assert!(!dir.path().join(".tmp-fake1").exists());
}

#[test]
fn blob_size_returns_correct_size() {
    let (cas, _dir) = temp_cas();
    let data = b"measure me";
    let (hash, _) = cas.store_bytes(data).unwrap();
    assert_eq!(cas.blob_size(&hash).unwrap(), 10);
}

#[test]
fn open_missing_blob_errors() {
    let (cas, _dir) = temp_cas();
    let hash = Hash::from_data(b"nonexistent");
    assert!(cas.open(&hash).is_err());
}

#[test]
fn write_and_read_manifest() {
    let (cas, dir) = temp_cas();
    let run_dir = dir.path().join("runs").join("testrun");
    fs::create_dir_all(&run_dir).unwrap();

    let manifest = Manifest {
        version: 1,
        hash_algorithm: "blake3".into(),
        run_id: RunId::new(),
        created: Utc::now(),
        command: vec!["echo".into(), "hello".into()],
        exit_code: Some(0),
        duration_ms: 42,
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
        artifacts: vec![ArtifactRef {
            hash: Hash::from_data(b"stdout data"),
            size: 11,
            label: "stdout".into(),
            artifact_type: ArtifactType::Stdout,
        }],
        policy: None,
        trace: None,
        resources: None,
    };

    let hash = cas.write_manifest(&manifest, &run_dir).unwrap();
    assert!(cas.exists(&hash));

    // Read it back.
    let read_back = read_manifest(&run_dir).unwrap();
    assert_eq!(read_back.command, manifest.command);
    assert_eq!(read_back.exit_code, Some(0));
    assert_eq!(read_back.artifacts.len(), 1);
}

#[test]
fn format_bytes_display() {
    assert_eq!(format_bytes(0), "0 B");
    assert_eq!(format_bytes(512), "512 B");
    assert_eq!(format_bytes(1024), "1.0 KB");
    assert_eq!(format_bytes(1536), "1.5 KB");
    assert_eq!(format_bytes(1048576), "1.0 MB");
    assert_eq!(format_bytes(1073741824), "1.0 GB");
}

#[test]
fn format_duration_display() {
    assert_eq!(format_duration(12), "12ms");
    assert_eq!(format_duration(999), "999ms");
    assert_eq!(format_duration(1847), "1.847s");
    assert_eq!(format_duration(65000), "1m5s");
}

#[test]
fn store_large_file_streaming() {
    // 10MB of deterministic data to exercise the streaming path
    // across multiple 64KB buffer iterations.
    let (cas, _dir) = temp_cas();
    let data: Vec<u8> = (0..10 * 1024 * 1024)
        .map(|i| (i % 251) as u8) // deterministic, non-trivial pattern
        .collect();

    let (hash, size) = cas.store_bytes(&data).unwrap();
    assert_eq!(size, 10 * 1024 * 1024);
    assert!(cas.exists(&hash));
    assert_eq!(cas.verify(&hash).unwrap(), VerifyResult::Ok);

    // Read back and verify content.
    let mut file = cas.open(&hash).unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();
    assert_eq!(contents.len(), data.len());
    assert_eq!(contents, data);
}

#[test]
fn list_all_with_many_blobs() {
    // 100 distinct blobs, verify list_all returns all of them.
    let (cas, _dir) = temp_cas();
    let mut expected_hashes = std::collections::HashSet::new();

    for i in 0u64..100 {
        let data = format!("blob number {i}");
        let (hash, _) = cas.store_bytes(data.as_bytes()).unwrap();
        expected_hashes.insert(hash.to_hex());
    }
    assert_eq!(expected_hashes.len(), 100);

    let all = cas.list_all().unwrap();
    assert_eq!(all.len(), 100);

    let listed_hashes: std::collections::HashSet<String> =
        all.iter().map(|(h, _)| h.to_hex()).collect();
    assert_eq!(listed_hashes, expected_hashes);
}
