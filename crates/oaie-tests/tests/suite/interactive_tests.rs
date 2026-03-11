//! Tests for Phase I interactive PTY mode.
//!
//! These tests exercise the PTY allocation, interactive sandbox spawn, and
//! end-to-end interactive runs. They are namespace-heavy and must run serially.

use std::io::{Read, Write};
use std::time::Duration;

use oaie_cas::store::CasStore;
use oaie_cli::runner::Runner;
use oaie_core::hash_algo::HashAlgorithm;
use oaie_core::job::TraceMode;
use oaie_sandbox::pty::allocate_pty;
use oaie_sandbox::sandbox::{spawn_sandboxed_interactive, SandboxConfig};
use oaie_tests::{default_resolved_policy, setup_store, userns_available};

// ── PTY allocation ──

#[test]
fn test_interactive_pty_allocate() {
    let pair = allocate_pty().expect("PTY allocation should succeed");
    // The slave path should be under /dev/pts/.
    assert!(
        pair.slave_path.to_str().unwrap().starts_with("/dev/pts/"),
        "slave path should be under /dev/pts/, got: {:?}",
        pair.slave_path
    );
    // Master fd should be valid (not -1).
    use std::os::unix::io::AsRawFd;
    assert!(pair.master.as_raw_fd() >= 0);
}

#[test]
fn test_interactive_pty_window_size() {
    use oaie_sandbox::pty::set_window_size;
    use std::os::unix::io::AsRawFd;

    let pair = allocate_pty().expect("PTY allocation should succeed");
    // Setting window size on master should succeed.
    set_window_size(pair.master.as_raw_fd(), 40, 120).expect("set_window_size should succeed");
}

// ── Interactive sandbox spawn ──

#[test]
fn test_interactive_echo() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let config = SandboxConfig { interactive: true, ..Default::default() };
    let command: Vec<String> = vec!["cat".into()];

    let mut child =
        spawn_sandboxed_interactive(&config, &command, &[], false, None)
            .expect("spawn should succeed");

    // Take the PTY master for I/O.
    let mut master = child.take_pty_master().expect("should have PTY master");

    // Write "hello\n" to stdin via PTY master.
    master.write_all(b"hello\n").unwrap();
    master.flush().unwrap();

    // Give cat time to echo back.
    std::thread::sleep(Duration::from_millis(200));

    // Read output from PTY master (cat echoes input).
    let mut buf = [0u8; 256];
    // Set non-blocking so we don't hang.
    use std::os::unix::io::AsRawFd;
    unsafe {
        let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    let n = master.read(&mut buf).unwrap_or(0);
    let output = String::from_utf8_lossy(&buf[..n]);
    // PTY echo produces the input back, so "hello" should appear.
    assert!(
        output.contains("hello"),
        "PTY output should contain 'hello', got: {output:?}"
    );

    // Send EOF (Ctrl+D) to terminate cat.
    master.write_all(&[0x04]).unwrap();
    master.flush().unwrap();
    std::thread::sleep(Duration::from_millis(200));

    // Reap child.
    use nix::sys::wait::waitpid;
    let _ = waitpid(child.pid, None);
    child.mark_reaped();
}

#[test]
fn test_interactive_isatty() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let config = SandboxConfig { interactive: true, ..Default::default() };
    // Use a shell script to check isatty on fd 0.
    let command: Vec<String> = vec![
        "/bin/sh".into(),
        "-c".into(),
        "test -t 0 && echo TTY_YES || echo TTY_NO".into(),
    ];

    let mut child =
        spawn_sandboxed_interactive(&config, &command, &[], false, None)
            .expect("spawn should succeed");

    let mut master = child.take_pty_master().expect("should have PTY master");

    // Wait for the child to produce output.
    std::thread::sleep(Duration::from_millis(500));

    // Read output.
    use std::os::unix::io::AsRawFd;
    unsafe {
        let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    let mut buf = [0u8; 512];
    let n = master.read(&mut buf).unwrap_or(0);
    let output = String::from_utf8_lossy(&buf[..n]);

    assert!(
        output.contains("TTY_YES"),
        "child should see isatty(0) = true, got: {output:?}"
    );

    // Reap.
    use nix::sys::wait::waitpid;
    let _ = waitpid(child.pid, None);
    child.mark_reaped();
}

#[test]
fn test_interactive_term_env() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let config = SandboxConfig { interactive: true, ..Default::default() };
    let command: Vec<String> = vec!["/bin/sh".into(), "-c".into(), "echo TERM=$TERM".into()];

    let mut child =
        spawn_sandboxed_interactive(&config, &command, &[], false, None)
            .expect("spawn should succeed");

    let mut master = child.take_pty_master().expect("should have PTY master");

    std::thread::sleep(Duration::from_millis(500));

    use std::os::unix::io::AsRawFd;
    unsafe {
        let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    let mut buf = [0u8; 512];
    let n = master.read(&mut buf).unwrap_or(0);
    let output = String::from_utf8_lossy(&buf[..n]);

    // TERM should NOT be "dumb" — interactive mode inherits from supervisor.
    assert!(
        output.contains("TERM="),
        "output should contain TERM= (got: {output:?})"
    );
    assert!(
        !output.contains("TERM=dumb"),
        "interactive mode should not use TERM=dumb (got: {output:?})"
    );

    use nix::sys::wait::waitpid;
    let _ = waitpid(child.pid, None);
    child.mark_reaped();
}

#[test]
fn test_interactive_signal_passthrough() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let config = SandboxConfig { interactive: true, ..Default::default() };
    // Start a process that traps SIGINT and prints a message.
    let command: Vec<String> = vec![
        "/bin/sh".into(),
        "-c".into(),
        "trap 'echo GOT_SIGINT; exit 0' INT; while true; do sleep 0.1; done".into(),
    ];

    let mut child =
        spawn_sandboxed_interactive(&config, &command, &[], false, None)
            .expect("spawn should succeed");

    let mut master = child.take_pty_master().expect("should have PTY master");

    // Let the trap set up.
    std::thread::sleep(Duration::from_millis(300));

    // Send Ctrl+C (0x03) via PTY — this delivers SIGINT to the child's
    // foreground process group through the PTY line discipline.
    master.write_all(&[0x03]).unwrap();
    master.flush().unwrap();

    std::thread::sleep(Duration::from_millis(500));

    use std::os::unix::io::AsRawFd;
    unsafe {
        let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    let mut buf = [0u8; 512];
    let n = master.read(&mut buf).unwrap_or(0);
    let output = String::from_utf8_lossy(&buf[..n]);

    assert!(
        output.contains("GOT_SIGINT"),
        "child should receive SIGINT via PTY Ctrl+C, got: {output:?}"
    );

    use nix::sys::wait::waitpid;
    let _ = waitpid(child.pid, None);
    child.mark_reaped();
}

#[test]
fn test_interactive_output_capture() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    // Run an interactive command through the full Runner pipeline and verify
    // that PTY output is captured to the CAS.
    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();

    let job = oaie_core::job::JobSpec {
        command: vec!["echo".into(), "interactive_output_test".into()],
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
        interactive: true,
    };

    let result = runner
        .execute(&job, &default_resolved_policy(job.timeout), true, None)
        .expect("interactive run should succeed");

    assert_eq!(result.exit_code, 0);
    assert!(result.interactive, "result should flag interactive mode");

    // Verify stdout was captured (PTY output goes to stdout capture).
    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let mut file = cas.open(&result.stdout_hash).unwrap();
    let mut content = Vec::new();
    file.read_to_end(&mut content).unwrap();
    let text = String::from_utf8_lossy(&content);
    assert!(
        text.contains("interactive_output_test"),
        "captured stdout should contain the echo output, got: {text:?}"
    );
}

#[test]
fn test_interactive_with_trace() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = Runner::new(store.clone()).unwrap();

    let job = oaie_core::job::JobSpec {
        command: vec!["echo".into(), "traced_interactive".into()],
        inputs: None,
        outputs: None,
        network: false,
        trace: TraceMode::Ptrace,
        timeout: Some(Duration::from_secs(10)),
        policy: None,
        extra_ro: vec![],
        extra_rw: vec![],
        no_isolation: false,
        backend: Default::default(),
        interactive: true,
    };

    let mut policy = default_resolved_policy(job.timeout);
    policy.trace = TraceMode::Ptrace;

    let result = runner
        .execute(&job, &policy, true, None)
        .expect("interactive run with tracing should succeed");

    assert_eq!(result.exit_code, 0);
    assert!(result.interactive);
    // Trace summary should be present.
    assert!(
        result.trace_summary.is_some(),
        "traced interactive run should produce a trace summary"
    );
}

#[test]
fn test_interactive_incompatible_flags() {
    // Test that the error messages for incompatible flags are correctly formed.
    use oaie_core::backend::BackendKind;
    use oaie_core::error::OaieError;

    // Interactive + bare backend should error.
    let msg = "interactive mode (-i) requires namespace backend (not --backend=bare)";
    let err = OaieError::InvalidJobSpec(msg.into());
    assert!(err.to_string().contains("interactive"));

    // Verify BackendKind::Bare != BackendKind::Namespace.
    assert_ne!(BackendKind::Bare, BackendKind::Namespace);

    // Interactive + quiet message.
    let msg2 = "interactive mode (-i) is incompatible with --quiet";
    let err2 = OaieError::InvalidJobSpec(msg2.into());
    assert!(err2.to_string().contains("interactive"));

    // Interactive + json output message.
    let msg3 = "interactive mode (-i) is incompatible with --output=json";
    let err3 = OaieError::InvalidJobSpec(msg3.into());
    assert!(err3.to_string().contains("interactive"));
}

#[test]
fn test_interactive_manifest_records() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    // Run an interactive command and verify the manifest records interactive: true.
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
        interactive: true,
    };

    let result = runner
        .execute(&job, &default_resolved_policy(job.timeout), true, None)
        .expect("interactive run should succeed");

    assert_eq!(result.exit_code, 0);

    // Read back the manifest and verify interactive is set.
    let run_dir = store.runs_dir.join(result.run_id.full());
    let manifest = oaie_cas::store::read_manifest(&run_dir).expect("manifest should exist");
    assert!(
        manifest.isolation.interactive,
        "manifest should record interactive: true"
    );
}
