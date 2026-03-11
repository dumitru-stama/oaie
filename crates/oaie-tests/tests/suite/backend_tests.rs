//! Tests for the backend abstraction types and dispatch.

use std::str::FromStr;

use oaie_core::backend::BackendKind;
use oaie_core::manifest::{IsolationInfo, IsolationLevel};

// ---- BackendKind tests ----

#[test]
fn backend_kind_parse_display_roundtrip() {
    for kind in [
        BackendKind::Namespace,
        BackendKind::Bare,
        BackendKind::Firecracker,
    ] {
        let s = kind.to_string();
        let parsed = BackendKind::from_str(&s).unwrap();
        assert_eq!(kind, parsed);
    }
}

#[test]
fn backend_kind_parse_invalid() {
    assert!(BackendKind::from_str("docker").is_err());
    assert!(BackendKind::from_str("").is_err());
}

#[test]
fn backend_kind_default_is_namespace() {
    let default: BackendKind = Default::default();
    assert_eq!(default, BackendKind::Namespace);
}

#[test]
fn backend_kind_serde_roundtrip() {
    for kind in [
        BackendKind::Namespace,
        BackendKind::Bare,
        BackendKind::Firecracker,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let parsed: BackendKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, parsed);
    }
}

#[test]
fn backend_caps_namespace() {
    let caps = BackendKind::Namespace.caps();
    assert_eq!(caps.isolation_level, "namespace");
    assert!(caps.supports_trace_ptrace);
    assert!(caps.supports_trace_ebpf);
    assert!(caps.supports_cgroup);
}

#[test]
fn backend_caps_bare() {
    let caps = BackendKind::Bare.caps();
    assert_eq!(caps.isolation_level, "bare");
    assert!(!caps.supports_trace_ptrace);
    assert!(!caps.supports_cgroup);
}

#[test]
fn backend_caps_firecracker() {
    let caps = BackendKind::Firecracker.caps();
    assert_eq!(caps.isolation_level, "microvm");
    assert!(!caps.supports_trace_ptrace);
    assert!(!caps.supports_cgroup);
    assert!(!caps.needs_root);
}

// ---- MicroVM isolation level tests ----

#[test]
fn microvm_isolation_level_display_parse() {
    let level = IsolationLevel::MicroVM;
    let s = level.to_string();
    assert_eq!(s, "microvm");
    let parsed: IsolationLevel = s.parse().unwrap();
    assert_eq!(parsed, IsolationLevel::MicroVM);
}

#[test]
fn microvm_isolation_level_is_isolated() {
    assert!(IsolationLevel::Full.is_isolated());
    assert!(IsolationLevel::MicroVM.is_isolated());
    assert!(!IsolationLevel::None.is_isolated());
    assert!(!IsolationLevel::Partial.is_isolated());
}

#[test]
fn microvm_isolation_level_serde_roundtrip() {
    let level = IsolationLevel::MicroVM;
    let json = serde_json::to_string(&level).unwrap();
    assert_eq!(json, "\"microvm\"");
    let parsed: IsolationLevel = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, IsolationLevel::MicroVM);
}

// ---- IsolationInfo new fields tests ----

#[test]
fn isolation_info_new_fields_default_none() {
    let info = IsolationInfo {
        level: IsolationLevel::Full,
        namespaces: vec!["mount".into()],
        network: false,
        network_mode: "off".into(),
        landlock: true,
        cgroup: None,
        backend: None,
        firecracker_version: None,
        kernel: None,
        rootfs: None,
        trace_integrity: None,
        interactive: false,
    };

    // New fields are None by default.
    assert!(info.backend.is_none());
    assert!(info.firecracker_version.is_none());
    assert!(info.kernel.is_none());
    assert!(info.rootfs.is_none());
    assert!(info.trace_integrity.is_none());
}

#[test]
fn isolation_info_firecracker_fields_serialize() {
    let info = IsolationInfo {
        level: IsolationLevel::MicroVM,
        namespaces: vec![],
        network: false,
        network_mode: "off".into(),
        landlock: false,
        cgroup: None,
        backend: Some("firecracker".into()),
        firecracker_version: Some("1.10.0".into()),
        kernel: Some("vmlinux-5.10.225".into()),
        rootfs: Some("alpine-3.20.ext4".into()),
        trace_integrity: Some("reduced".into()),
        interactive: false,
    };

    let toml = toml::to_string(&info).unwrap();
    assert!(toml.contains("backend = \"firecracker\""));
    assert!(toml.contains("firecracker_version = \"1.10.0\""));
    assert!(toml.contains("kernel = \"vmlinux-5.10.225\""));
    assert!(toml.contains("rootfs = \"alpine-3.20.ext4\""));
    assert!(toml.contains("trace_integrity = \"reduced\""));

    // Deserialize back.
    let parsed: IsolationInfo = toml::from_str(&toml).unwrap();
    assert_eq!(parsed, info);
}

#[test]
fn isolation_info_none_fields_omitted_in_serialization() {
    let info = IsolationInfo {
        level: IsolationLevel::Full,
        namespaces: vec!["mount".into()],
        network: false,
        network_mode: "off".into(),
        landlock: true,
        cgroup: None,
        backend: None,
        firecracker_version: None,
        kernel: None,
        rootfs: None,
        trace_integrity: None,
        interactive: false,
    };

    let toml = toml::to_string(&info).unwrap();
    // None fields should be omitted entirely (skip_serializing_if).
    assert!(!toml.contains("backend"));
    assert!(!toml.contains("firecracker_version"));
    assert!(!toml.contains("kernel"));
    assert!(!toml.contains("rootfs"));
    assert!(!toml.contains("trace_integrity"));
}

#[test]
fn isolation_info_legacy_deserialize_without_new_fields() {
    // Legacy manifests don't have the new fields — they should deserialize fine.
    let toml_str = r#"
level = "full"
namespaces = ["mount", "pid"]
network = false
landlock = true
"#;
    let parsed: IsolationInfo = toml::from_str(toml_str).unwrap();
    assert_eq!(parsed.level, IsolationLevel::Full);
    assert!(parsed.backend.is_none());
    assert!(parsed.firecracker_version.is_none());
}

// ---- Firecracker backend error test ----

/// Without the `firecracker` feature, the backend should return an error about
/// the feature not being enabled. With the feature, it should fail because
/// Firecracker prerequisites are not met (no VM assets in test env).
#[test]
fn firecracker_backend_fails_gracefully() {
    use oaie_tests::setup_store;
    use oaie_cli::runner::Runner;

    let (store, _dir) = setup_store();
    let runner = Runner::new(store).unwrap();

    let job = oaie_core::job::JobSpec {
        command: vec!["echo".into(), "hello".into()],
        inputs: None,
        outputs: None,
        network: false,
        trace: oaie_core::job::TraceMode::Off,
        timeout: None,
        policy: None,
        extra_ro: vec![],
        extra_rw: vec![],
        no_isolation: true,
        backend: BackendKind::Firecracker,
        interactive: false,
    };

    let policy = oaie_tests::default_resolved_policy(None);
    let result = runner.execute(&job, &policy, true, None);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    // Either "feature" (not compiled) or "prerequisites" (compiled but no VM).
    assert!(
        err.contains("firecracker") || err.contains("Firecracker"),
        "expected firecracker-related error, got: {err}"
    );
}

// ---- Bare backend echo test ----

#[test]
fn bare_backend_echo() {
    use oaie_tests::setup_store;
    use oaie_cli::runner::Runner;

    let (store, _dir) = setup_store();
    let runner = Runner::new(store).unwrap();

    let job = oaie_core::job::JobSpec {
        command: vec!["echo".into(), "hello from bare".into()],
        inputs: None,
        outputs: None,
        network: false,
        trace: oaie_core::job::TraceMode::Off,
        timeout: None,
        policy: None,
        extra_ro: vec![],
        extra_rw: vec![],
        no_isolation: true,
        backend: BackendKind::Bare,
        interactive: false,
    };

    let policy = oaie_tests::default_resolved_policy(None);
    let result = runner.execute(&job, &policy, true, None).unwrap();
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.isolation_level, IsolationLevel::None);
}
