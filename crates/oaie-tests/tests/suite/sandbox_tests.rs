//! Tests extracted from oaie-sandbox: probe, capability detection, and sandboxed execution.

use std::fs;

use oaie_core::manifest::IsolationLevel;
use oaie_sandbox::probe::{parse_kernel_version, SystemCaps};
use oaie_sandbox::sandbox::{spawn_sandboxed, SandboxConfig};
use oaie_tests::userns_available;

#[test]
fn detect_does_not_panic() {
    // Should complete without panicking regardless of system capabilities.
    let caps = SystemCaps::detect();
    // Kernel version should be nonzero on any real Linux system.
    assert!(caps.kernel_version.0 > 0, "kernel major should be > 0");
}

#[test]
fn isolation_level_mapping() {
    let full = SystemCaps {
        user_ns: true,
        max_user_ns: Some(65536),
        current_user_ns: None,
        kernel_version: (6, 8),
    };
    assert_eq!(full.isolation_level(), IsolationLevel::Full);

    let none = SystemCaps {
        user_ns: false,
        max_user_ns: Some(0),
        current_user_ns: None,
        kernel_version: (5, 4),
    };
    assert_eq!(none.isolation_level(), IsolationLevel::None);
}

#[test]
fn remediation_hint_none_when_capable() {
    let caps = SystemCaps {
        user_ns: true,
        max_user_ns: Some(65536),
        current_user_ns: None,
        kernel_version: (6, 8),
    };
    assert!(caps.remediation_hint().is_none());
}

#[test]
fn kernel_version_parsing() {
    assert_eq!(parse_kernel_version("6.8.0-101-generic").unwrap(), (6, 8));
    assert_eq!(parse_kernel_version("5.15.0").unwrap(), (5, 15));
    assert_eq!(
        parse_kernel_version("4.19.128-microsoft-standard").unwrap(),
        (4, 19)
    );
    assert!(parse_kernel_version("").is_err());
    assert!(parse_kernel_version("garbage").is_err());
}

// ---- sandbox execution tests ----
// All skip gracefully if user namespaces are not available.

#[test]
fn spawn_echo() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let in_dir = dir.path().join("in");
    let out_dir = dir.path().join("out");
    fs::create_dir_all(&in_dir).unwrap();
    fs::create_dir_all(&out_dir).unwrap();

    let config = SandboxConfig {
        input_dir: in_dir,
        output_dir: out_dir,
        ..Default::default()
    };

    let mut child = spawn_sandboxed(
        &config,
        &["echo".into(), "hello from sandbox".into()],
        &[],
        false,
        None,
    )
    .unwrap();

    // Read stdout.
    use std::io::Read;
    let mut stdout = child.take_stdout().unwrap();
    let mut buf = String::new();
    stdout.read_to_string(&mut buf).unwrap();
    assert_eq!(buf.trim(), "hello from sandbox");

    // Wait for child to exit.
    child.mark_reaped();
    let status = nix::sys::wait::waitpid(child.pid, None).unwrap();
    match status {
        nix::sys::wait::WaitStatus::Exited(_, code) => assert_eq!(code, 0),
        other => panic!("unexpected wait status: {other:?}"),
    }
}

#[test]
fn exit_code_preserved() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let in_dir = dir.path().join("in");
    let out_dir = dir.path().join("out");
    fs::create_dir_all(&in_dir).unwrap();
    fs::create_dir_all(&out_dir).unwrap();

    let config = SandboxConfig {
        input_dir: in_dir,
        output_dir: out_dir,
        ..Default::default()
    };

    let mut child = spawn_sandboxed(
        &config,
        &["sh".into(), "-c".into(), "exit 42".into()],
        &[],
        false,
        None,
    )
    .unwrap();

    // Must drain pipes before waitpid to avoid deadlock.
    drop(child.take_stdout());
    drop(child.take_stderr());

    child.mark_reaped();
    let status = nix::sys::wait::waitpid(child.pid, None).unwrap();
    match status {
        nix::sys::wait::WaitStatus::Exited(_, code) => assert_eq!(code, 42),
        other => panic!("unexpected wait status: {other:?}"),
    }
}

#[test]
fn env_sanitized() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let in_dir = dir.path().join("in");
    let out_dir = dir.path().join("out");
    fs::create_dir_all(&in_dir).unwrap();
    fs::create_dir_all(&out_dir).unwrap();

    let config = SandboxConfig {
        input_dir: in_dir,
        output_dir: out_dir,
        ..Default::default()
    };

    // Pass OAIE_TEST_VAR, check it's visible. Also verify HOME is /root.
    let mut child = spawn_sandboxed(
        &config,
        &["sh".into(), "-c".into(), "echo $HOME; echo $OAIE_TEST_VAR".into()],
        &[("OAIE_TEST_VAR".into(), "sandbox_works".into())],
        false,
        None,
    )
    .unwrap();

    use std::io::Read;
    let mut stdout = child.take_stdout().unwrap();
    let mut buf = String::new();
    stdout.read_to_string(&mut buf).unwrap();
    let lines: Vec<&str> = buf.trim().lines().collect();
    assert_eq!(lines[0], "/root");
    assert_eq!(lines[1], "sandbox_works");

    child.mark_reaped();
    let _ = nix::sys::wait::waitpid(child.pid, None);
}

#[test]
fn no_home_access() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let in_dir = dir.path().join("in");
    let out_dir = dir.path().join("out");
    fs::create_dir_all(&in_dir).unwrap();
    fs::create_dir_all(&out_dir).unwrap();

    let config = SandboxConfig {
        input_dir: in_dir,
        output_dir: out_dir,
        ..Default::default()
    };

    // Try to read ~/.ssh — should fail (no /home exists).
    let mut child = spawn_sandboxed(
        &config,
        &["ls".into(), "/root/.ssh".into()],
        &[],
        false,
        None,
    )
    .unwrap();

    drop(child.take_stdout());
    drop(child.take_stderr());

    child.mark_reaped();
    let status = nix::sys::wait::waitpid(child.pid, None).unwrap();
    match status {
        nix::sys::wait::WaitStatus::Exited(_, code) => {
            assert_ne!(code, 0, "ls /root/.ssh should fail");
        }
        other => panic!("unexpected wait status: {other:?}"),
    }
}

#[test]
fn output_writable() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let in_dir = dir.path().join("in");
    let out_dir = dir.path().join("out");
    fs::create_dir_all(&in_dir).unwrap();
    fs::create_dir_all(&out_dir).unwrap();

    let config = SandboxConfig {
        input_dir: in_dir,
        output_dir: out_dir.clone(),
        ..Default::default()
    };

    // Write a file to /out inside the sandbox.
    let mut child = spawn_sandboxed(
        &config,
        &["sh".into(), "-c".into(), "echo result > /out/test.txt".into()],
        &[],
        false,
        None,
    )
    .unwrap();

    drop(child.take_stdout());
    drop(child.take_stderr());

    child.mark_reaped();
    let status = nix::sys::wait::waitpid(child.pid, None).unwrap();
    match status {
        nix::sys::wait::WaitStatus::Exited(_, code) => assert_eq!(code, 0),
        other => panic!("unexpected wait status: {other:?}"),
    }

    // Verify the file exists on the host side.
    let content = fs::read_to_string(out_dir.join("test.txt")).unwrap();
    assert_eq!(content.trim(), "result");
}
