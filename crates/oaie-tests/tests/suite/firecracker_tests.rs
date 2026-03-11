//! Tests for the Firecracker microVM backend.
//!
//! Unit tests (wire protocol, detection) run unconditionally.
//! Integration tests (VM boot) are gated on the `firecracker` feature
//! and the presence of /dev/kvm.

// ---- Wire protocol tests (no feature gate) ----

#[test]
fn wire_roundtrip_all_message_types() {
    use oaie_firecracker::wire::{self, Message};
    use std::collections::HashMap;
    use std::time::Duration;

    let messages = vec![
        Message::agent_ready(),
        Message::Shutdown,
        Message::Error {
            message: "something went wrong".into(),
        },
        Message::job_done(42, Duration::from_millis(1234)),
        Message::stdout_chunk(b"hello world"),
        Message::stderr_chunk(b"error output"),
        Message::RunJob {
            command: vec!["echo".into(), "hello".into()],
            env: HashMap::from([("KEY".into(), "val".into())]),
            timeout_secs: Some(30),
            trace: true,
        },
        Message::TraceEvent {
            event: r#"{"pid":123,"syscall":"openat"}"#.into(),
        },
    ];

    for msg in &messages {
        let encoded = wire::encode(msg).unwrap();
        let decoded = wire::decode(&mut &encoded[..]).unwrap().unwrap();
        assert_eq!(&decoded, msg);
    }
}

#[test]
fn wire_frame_too_large() {
    use oaie_firecracker::wire::{self, Message, MAX_FRAME_SIZE};

    let large = "x".repeat(MAX_FRAME_SIZE as usize + 1);
    let msg = Message::Error { message: large };
    assert!(wire::encode(&msg).is_err());
}

#[test]
fn wire_decode_oversized_length_prefix() {
    use oaie_firecracker::wire::{self, MAX_FRAME_SIZE};

    let len = (MAX_FRAME_SIZE + 1).to_be_bytes();
    assert!(wire::decode(&mut &len[..]).is_err());
}

#[test]
fn wire_decode_eof() {
    use oaie_firecracker::wire;

    let empty: &[u8] = &[];
    assert!(wire::decode(&mut &*empty).unwrap().is_none());
}

#[test]
fn wire_multiple_messages_on_stream() {
    use oaie_firecracker::wire::{self, Message};
    use std::time::Duration;

    let messages = vec![
        Message::agent_ready(),
        Message::stdout_chunk(b"data"),
        Message::job_done(0, Duration::from_secs(1)),
    ];

    let mut buf = Vec::new();
    for msg in &messages {
        wire::send(&mut buf, msg).unwrap();
    }

    let mut cursor = &buf[..];
    for expected in &messages {
        let got = wire::recv(&mut cursor).unwrap().unwrap();
        assert_eq!(&got, expected);
    }
    assert!(wire::recv(&mut cursor).unwrap().is_none());
}

#[test]
fn wire_base64_roundtrip() {
    use oaie_firecracker::wire;

    let cases: &[&[u8]] = &[
        b"",
        b"f",
        b"fo",
        b"foo",
        b"foobar",
        b"hello world",
        &[0, 1, 2, 255, 254, 253],
    ];
    for &data in cases {
        // Encode via stdout_chunk, then decode the base64 data.
        let msg = oaie_firecracker::wire::Message::stdout_chunk(data);
        if let oaie_firecracker::wire::Message::OutputChunk { data: b64, .. } = msg {
            let decoded = wire::base64_decode(&b64).unwrap();
            assert_eq!(decoded, data, "roundtrip failed for {:?}", data);
        }
    }
}

#[test]
fn wire_serde_tag_format() {
    use oaie_firecracker::wire::Message;

    let json = serde_json::to_string(&Message::Shutdown).unwrap();
    assert!(json.contains("\"type\":\"shutdown\""));

    let json = serde_json::to_string(&Message::agent_ready()).unwrap();
    assert!(json.contains("\"type\":\"agent_ready\""));
}

// ---- Detection tests (no feature gate, but results depend on system) ----

#[test]
fn detect_returns_struct() {
    let caps = oaie_firecracker::detect::detect();
    // Whether available or not, the struct should be well-formed.
    if caps.available {
        assert!(caps.firecracker_path.is_some());
        assert!(caps.kvm_available);
        assert!(caps.kernel_path.is_some());
        assert!(caps.rootfs_path.is_some());
        assert!(caps.guest_agent_path.is_some());
        assert!(caps.issues.is_empty());
    } else {
        assert!(!caps.issues.is_empty());
    }
}

#[test]
fn assets_dir_location() {
    let dir = oaie_firecracker::detect::assets_dir();
    let s = dir.to_str().unwrap();
    assert!(s.contains(".oaie/firecracker"), "got: {s}");
}

// ---- Image tests (require mkfs.ext4) ----

#[test]
fn image_create_input_from_dir() {
    use oaie_firecracker::image;
    use std::fs;

    let tmp = tempfile::tempdir().unwrap();
    let input_dir = tmp.path().join("input");
    fs::create_dir(&input_dir).unwrap();
    fs::write(input_dir.join("test.txt"), "hello").unwrap();

    let image_path = tmp.path().join("input.ext4");

    match image::create_input_image(&input_dir, &image_path) {
        Ok(()) => {
            assert!(image_path.exists());
            assert!(fs::metadata(&image_path).unwrap().len() >= 4 * 1024 * 1024);
        }
        Err(e) => {
            // mkfs.ext4 not available.
            let msg = e.to_string();
            assert!(
                msg.contains("mkfs.ext4") || msg.contains("No such file"),
                "unexpected: {msg}"
            );
        }
    }
}

#[test]
fn image_create_output() {
    use oaie_firecracker::image;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("out.ext4");

    match image::create_output_image(&path, 4) {
        Ok(()) => assert!(path.exists()),
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("mkfs.ext4") || msg.contains("No such file"),
                "unexpected: {msg}"
            );
        }
    }
}

// ---- VM boot test (requires firecracker feature + /dev/kvm) ----

#[cfg(feature = "firecracker")]
mod vm_tests {
    #[test]
    #[ignore] // Requires /dev/kvm and guest assets.
    fn vm_boot_echo() {
        use oaie_firecracker::detect;
        use oaie_firecracker::rootfs::FirecrackerAssets;
        use oaie_firecracker::vm::{FirecrackerVm, VmConfig};
        use std::collections::HashMap;

        let caps = detect::detect();
        if !caps.available {
            eprintln!("skipping: Firecracker prerequisites not met");
            return;
        }

        let assets = FirecrackerAssets::load().unwrap();

        let config = VmConfig {
            firecracker_path: caps.firecracker_path.unwrap(),
            kernel_path: assets.kernel,
            rootfs_path: assets.rootfs,
            vcpu_count: 1,
            mem_size_mib: 128,
            input_image: None,
            output_image: None,
        };

        let mut vm = FirecrackerVm::boot(&config).unwrap();

        let stdout_tmp = tempfile::NamedTempFile::new().unwrap();
        let stderr_tmp = tempfile::NamedTempFile::new().unwrap();

        let (exit_code, _duration) = vm
            .run_job(
                vec!["echo".into(), "hello from firecracker".into()],
                HashMap::new(),
                Some(std::time::Duration::from_secs(10)),
                false,
                stdout_tmp.path(),
                stderr_tmp.path(),
                true,
            )
            .unwrap();

        vm.shutdown().unwrap();

        assert_eq!(exit_code, 0);
        let stdout = std::fs::read_to_string(stdout_tmp.path()).unwrap();
        assert_eq!(stdout.trim(), "hello from firecracker");
    }
}
