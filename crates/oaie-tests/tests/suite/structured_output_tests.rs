//! Tests for Phase G structured output, policy presets, and agent library.

use oaie_core::job::JobSpec;
use oaie_core::policy::Policy;

// ── StructuredRunResult serialization ──

#[test]
fn structured_result_roundtrip() {
    use oaie_core::structured_output::*;

    let result = StructuredRunResult {
        run_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
        exit_code: 0,
        duration_secs: 1.234,
        stdout: OutputRef {
            hash: "a".repeat(64),
            size_bytes: 6,
        },
        stderr: OutputRef {
            hash: "b".repeat(64),
            size_bytes: 0,
        },
        output_artifacts: vec![ArtifactEntry {
            name: "output/result.txt".into(),
            hash: "c".repeat(64),
            size_bytes: 42,
        }],
        manifest_hash: "d".repeat(64),
        isolation: IsolationSummary {
            level: "full".into(),
            backend: "namespace".into(),
            cgroup_enforced: true,
            network_mode: None,
            network_rules: None,
            interactive: false,
            signed_by: None,
        },
        resources: Some(ResourceSummary {
            memory_limit: Some("512M".into()),
            memory_peak: Some("128M".into()),
            cpu_user_ms: Some(100),
            cpu_system_ms: Some(50),
            pids_peak: Some(3),
        }),
        trace: Some(TraceSummaryOutput {
            files_read: 10,
            files_written: 2,
            net_connects: 0,
            net_denied: 0,
            processes_spawned: 1,
            suspicious_count: 0,
            total_events: 50,
        }),
        store_path: "/home/test/.oaie".into(),
    };

    let json = serde_json::to_string(&result).unwrap();
    let parsed: StructuredRunResult = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.exit_code, 0);
    assert_eq!(parsed.run_id, result.run_id);
    assert_eq!(parsed.output_artifacts.len(), 1);
    assert_eq!(parsed.output_artifacts[0].name, "output/result.txt");
    assert!(parsed.resources.is_some());
    assert!(parsed.trace.is_some());
}

#[test]
fn structured_result_minimal() {
    use oaie_core::structured_output::*;

    let result = StructuredRunResult {
        run_id: "test-id".into(),
        exit_code: 1,
        duration_secs: 0.5,
        stdout: OutputRef {
            hash: "a".repeat(64),
            size_bytes: 0,
        },
        stderr: OutputRef {
            hash: "b".repeat(64),
            size_bytes: 10,
        },
        output_artifacts: vec![],
        manifest_hash: "c".repeat(64),
        isolation: IsolationSummary {
            level: "none".into(),
            backend: "bare".into(),
            cgroup_enforced: false,
            network_mode: None,
            network_rules: None,
            interactive: false,
            signed_by: None,
        },
        resources: None,
        trace: None,
        store_path: "/tmp/.oaie".into(),
    };

    let json = serde_json::to_string(&result).unwrap();
    // resources and trace should be omitted from JSON when None
    assert!(!json.contains("\"resources\""));
    assert!(!json.contains("\"trace\""));
}

// ── Policy presets ──

#[test]
fn policy_from_name_known() {
    let names = ["safe", "net", "agent-safe", "agent-net", "agent-build", "agent-analyze"];
    for name in &names {
        let policy = Policy::from_name(name);
        assert!(policy.is_some(), "from_name should recognize '{name}'");
        let p = policy.unwrap();
        assert_eq!(p.name.as_deref(), Some(*name));
    }
}

#[test]
fn policy_from_name_unknown() {
    assert!(Policy::from_name("nonexistent").is_none());
    assert!(Policy::from_name("").is_none());
    assert!(Policy::from_name("safe.toml").is_none());
}

#[test]
fn policy_list_presets() {
    let presets = Policy::list_presets();
    assert_eq!(presets.len(), 13);
    let names: Vec<&str> = presets.iter().map(|(n, _)| *n).collect();
    assert!(names.contains(&"safe"));
    assert!(names.contains(&"agent-safe"));
    assert!(names.contains(&"agent-build"));
    assert!(names.contains(&"anthropic"));
    assert!(names.contains(&"openai"));
    assert!(names.contains(&"llm"));
    assert!(names.contains(&"contained-local"));
    assert!(names.contains(&"contained-cloud"));
    assert!(names.contains(&"contained-strict"));
    assert!(names.contains(&"contained-interactive"));
}

#[test]
fn agent_safe_preset_values() {
    let p = Policy::preset_agent_safe();
    assert!(!p.defaults.network.has_connectivity());
    assert_eq!(p.limits.max_memory, "256M");
    assert_eq!(p.limits.max_time, "2m");
    assert_eq!(p.limits.max_pids, 64);
    assert_eq!(p.limits.max_fsize, "256M");
    assert!(!p.limits.allow_memfd);
}

#[test]
fn agent_net_preset_values() {
    let p = Policy::preset_agent_net();
    assert!(p.defaults.network.has_connectivity());
    assert_eq!(p.limits.max_memory, "512M");
    assert_eq!(p.limits.max_time, "5m");
    assert_eq!(p.limits.max_pids, 64);
    assert_eq!(p.limits.max_fsize, "256M");
    assert!(!p.limits.allow_memfd);
}

#[test]
fn agent_build_preset_values() {
    let p = Policy::preset_agent_build();
    assert!(p.defaults.network.has_connectivity());
    assert_eq!(p.limits.max_memory, "2G");
    assert_eq!(p.limits.max_time, "10m");
    assert_eq!(p.limits.max_pids, 256);
    assert_eq!(p.limits.max_fsize, "1G");
    assert!(p.limits.allow_memfd);
}

#[test]
fn agent_analyze_preset_values() {
    let p = Policy::preset_agent_analyze();
    assert!(!p.defaults.network.has_connectivity());
    assert_eq!(p.limits.max_memory, "1G");
    assert_eq!(p.limits.max_time, "15m");
    assert_eq!(p.limits.max_pids, 128);
    assert_eq!(p.limits.max_fsize, "512M");
    assert!(p.limits.allow_memfd);
}

#[test]
fn policy_presets_validate() {
    for (name, _) in Policy::list_presets() {
        let policy = Policy::from_name(name).unwrap();
        assert!(policy.validate().is_ok(), "preset '{name}' should validate");
    }
}

#[test]
fn policy_to_toml_roundtrip() {
    let policy = Policy::preset_agent_safe();
    let toml_str = policy.to_toml_string().unwrap();

    // Should contain the policy name.
    assert!(toml_str.contains("agent-safe"), "TOML should contain the name");

    // Should parse back.
    let parsed: Policy = toml::from_str(&toml_str).unwrap();
    assert_eq!(parsed.name.as_deref(), Some("agent-safe"));
    assert_eq!(parsed.limits.max_memory, "256M");
}

// ── JobSpec JSON input ──

#[test]
fn job_spec_from_json_string() {
    let json = r#"{"command": ["/bin/echo", "hello"]}"#;
    let spec = JobSpec::from_string(json, "test").unwrap();
    assert_eq!(spec.command, vec!["/bin/echo", "hello"]);
    assert!(!spec.network);
}

#[test]
fn job_spec_from_toml_string() {
    let toml = r#"command = ["/bin/echo", "hello"]"#;
    let spec = JobSpec::from_string(toml, "test").unwrap();
    assert_eq!(spec.command, vec!["/bin/echo", "hello"]);
}

#[test]
fn job_spec_auto_detect_json() {
    // Leading whitespace + brace = JSON
    let json = r#"  {"command": ["/bin/echo"]}"#;
    let spec = JobSpec::from_string(json, "test").unwrap();
    assert_eq!(spec.command, vec!["/bin/echo"]);
}

#[test]
fn job_spec_auto_detect_toml() {
    // No leading brace = TOML
    let toml = "command = [\"/bin/echo\"]\n";
    let spec = JobSpec::from_string(toml, "test").unwrap();
    assert_eq!(spec.command, vec!["/bin/echo"]);
}

#[test]
fn job_spec_from_string_validates() {
    let json = r#"{"command": []}"#;
    let err = JobSpec::from_string(json, "test");
    assert!(err.is_err(), "empty command should fail validation");
}

// ── Agent library types ──

#[test]
fn verify_report_from_core() {
    use oaie_core::run_id::RunId;
    use oaie_core::verify::{CheckKind, CheckResult, CheckStatus};
    use oaie_agent::types::VerifyReport;

    let core_report = oaie_core::verify::VerifyReport {
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
                detail: Some("no tracing".into()),
            },
        ],
    };

    let report = VerifyReport::from(core_report);
    assert!(report.passed);
    assert_eq!(report.checks.len(), 2);
    assert_eq!(report.checks[0].status, "Pass");
    assert_eq!(report.checks[1].status, "Skip");

    // Should serialize to JSON.
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("ManifestExists"));
}
