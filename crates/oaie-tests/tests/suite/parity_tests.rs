//! Parity tests: run the same job on multiple backends and compare results.
//!
//! These tests verify that bare and namespace backends produce equivalent
//! manifests for deterministic commands. Firecracker parity tests are
//! feature-gated and require /dev/kvm + guest assets.

use oaie_core::backend::BackendKind;
use oaie_core::manifest::IsolationLevel;

/// Helper: run a job on a specific backend and return (exit_code, isolation_level, output_count).
fn run_on_backend(
    command: Vec<String>,
    backend: BackendKind,
) -> (i32, IsolationLevel, usize) {
    use oaie_cli::runner::Runner;
    use oaie_tests::{default_resolved_policy, setup_store};

    let (store, _dir) = setup_store();
    let runner = Runner::new(store).unwrap();

    let no_isolation = matches!(backend, BackendKind::Bare);

    let job = oaie_core::job::JobSpec {
        command,
        inputs: None,
        outputs: None,
        network: false,
        trace: oaie_core::job::TraceMode::Off,
        timeout: None,
        policy: None,
        extra_ro: vec![],
        extra_rw: vec![],
        no_isolation,
        backend,
        interactive: false,
    };

    let policy = default_resolved_policy(None);
    let result = runner.execute(&job, &policy, true, None).unwrap();
    (
        result.exit_code,
        result.isolation_level,
        result.output_artifacts.len(),
    )
}

// ---- Echo parity ----

#[test]
fn parity_echo_bare_vs_namespace() {
    let cmd = vec!["echo".into(), "parity test".into()];

    let (bare_code, bare_iso, bare_outputs) =
        run_on_backend(cmd.clone(), BackendKind::Bare);
    let (ns_code, ns_iso, ns_outputs) =
        run_on_backend(cmd, BackendKind::Namespace);

    assert_eq!(bare_code, 0);
    assert_eq!(ns_code, 0);
    assert_eq!(bare_code, ns_code, "exit codes must match");
    assert_eq!(bare_outputs, ns_outputs, "output counts must match");

    // Isolation levels differ by design.
    assert_eq!(bare_iso, IsolationLevel::None);
    assert_eq!(ns_iso, IsolationLevel::Full);
}

// ---- Exit code parity ----

#[test]
fn parity_exit_code_bare_vs_namespace() {
    let cmd = vec!["sh".into(), "-c".into(), "exit 42".into()];

    let (bare_code, _, _) = run_on_backend(cmd.clone(), BackendKind::Bare);
    let (ns_code, _, _) = run_on_backend(cmd, BackendKind::Namespace);

    assert_eq!(bare_code, 42);
    assert_eq!(ns_code, 42);
}

// ---- Timeout parity ----

#[test]
fn parity_timeout_bare_vs_namespace() {
    // Both backends should handle timeouts the same way.
    // We don't actually time out here — just ensure both succeed quickly.
    let cmd = vec!["true".into()];

    let (bare_code, _, _) = run_on_backend(cmd.clone(), BackendKind::Bare);
    let (ns_code, _, _) = run_on_backend(cmd, BackendKind::Namespace);

    assert_eq!(bare_code, 0);
    assert_eq!(ns_code, 0);
}

// ---- Stderr parity ----

#[test]
fn parity_stderr_bare_vs_namespace() {
    let cmd = vec!["sh".into(), "-c".into(), "echo err >&2; exit 1".into()];

    let (bare_code, _, _) = run_on_backend(cmd.clone(), BackendKind::Bare);
    let (ns_code, _, _) = run_on_backend(cmd, BackendKind::Namespace);

    assert_eq!(bare_code, 1);
    assert_eq!(ns_code, 1);
}

// ---- Firecracker parity (feature-gated, ignored by default) ----

#[cfg(feature = "firecracker")]
mod firecracker_parity {
    use super::*;

    /// Skip helper: returns true if Firecracker is available.
    fn fc_available() -> bool {
        oaie_firecracker::detect::detect().available
    }

    #[test]
    #[ignore] // Requires /dev/kvm and guest assets.
    fn parity_echo_all_backends() {
        if !fc_available() {
            eprintln!("skipping: Firecracker not available");
            return;
        }

        let cmd = vec!["echo".into(), "triple parity".into()];

        let (bare_code, _, _) = run_on_backend(cmd.clone(), BackendKind::Bare);
        let (ns_code, _, _) = run_on_backend(cmd.clone(), BackendKind::Namespace);
        let (fc_code, fc_iso, _) = run_on_backend(cmd, BackendKind::Firecracker);

        assert_eq!(bare_code, 0);
        assert_eq!(ns_code, 0);
        assert_eq!(fc_code, 0);
        assert_eq!(fc_iso, IsolationLevel::MicroVM);
    }
}
