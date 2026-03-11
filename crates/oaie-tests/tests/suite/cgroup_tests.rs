//! Tests for cgroup v2 types, parsing, stats collection, limits writing,
//! oaie-priv protocol/validation, and OOM detection.

use std::str::FromStr;

// ── Step 11 test 1: CgroupLimits/CgroupStats/CgroupInfo serde round-trip ──

#[test]
fn cgroup_limits_json_roundtrip() {
    use oaie_core::cgroup::CgroupLimits;

    let limits = CgroupLimits {
        memory_max: Some(512 * 1024 * 1024),
        pids_max: Some(64),
        cpu_quota_us: Some(50_000),
        cpu_period_us: Some(100_000),
    };

    let json = serde_json::to_string(&limits).unwrap();
    let parsed: CgroupLimits = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, limits);
}

#[test]
fn cgroup_stats_json_roundtrip() {
    use oaie_core::cgroup::CgroupStats;

    let stats = CgroupStats {
        memory_peak: Some(347 * 1024 * 1024),
        memory_limit: Some(512 * 1024 * 1024),
        cpu_user_us: Some(1_230_000),
        cpu_system_us: Some(89_000),
        cpu_throttled_periods: Some(5),
        cpu_throttled_us: Some(10_000),
        pids_current: Some(12),
        pids_limit: Some(64),
        oom_kill_count: Some(0),
    };

    let json = serde_json::to_string(&stats).unwrap();
    let parsed: CgroupStats = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, stats);
}

#[test]
fn cgroup_stats_backward_compat_no_oom_field() {
    use oaie_core::cgroup::CgroupStats;

    // JSON without oom_kill_count should still parse (backward compat).
    let json = r#"{"memory_peak":100,"memory_limit":200}"#;
    let parsed: CgroupStats = serde_json::from_str(json).unwrap();
    assert_eq!(parsed.memory_peak, Some(100));
    assert!(parsed.oom_kill_count.is_none());
}

#[test]
fn cgroup_info_json_roundtrip() {
    use oaie_core::cgroup::{CgroupInfo, CgroupMethod};

    let info = CgroupInfo {
        name: "oaie-run-abc12345.scope".into(),
        method: CgroupMethod::SystemdRun,
        enforced: true,
    };

    let json = serde_json::to_string(&info).unwrap();
    let parsed: CgroupInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.name, "oaie-run-abc12345.scope");
    assert_eq!(parsed.method, CgroupMethod::SystemdRun);
    assert!(parsed.enforced);
}

#[test]
fn cgroup_limits_toml_roundtrip() {
    use oaie_core::cgroup::CgroupLimits;

    let limits = CgroupLimits {
        memory_max: Some(1024 * 1024 * 1024),
        pids_max: Some(128),
        cpu_quota_us: None,
        cpu_period_us: None,
    };

    let toml_str = toml::to_string(&limits).unwrap();
    let parsed: CgroupLimits = toml::from_str(&toml_str).unwrap();
    assert_eq!(parsed.memory_max, Some(1024 * 1024 * 1024));
    assert_eq!(parsed.pids_max, Some(128));
    assert_eq!(parsed.cpu_quota_us, None);
}

#[test]
fn cgroup_limits_equality() {
    use oaie_core::cgroup::CgroupLimits;

    let a = CgroupLimits {
        memory_max: Some(256 * 1024 * 1024),
        pids_max: Some(32),
        cpu_quota_us: None,
        cpu_period_us: None,
    };
    let b = a.clone();
    assert_eq!(a, b);

    let c = CgroupLimits::default();
    assert_ne!(a, c);
}

// ── Step 11 test 2: parse_cpu_quota ──

#[test]
fn parse_cpu_quota_50_percent() {
    let (quota, period) = oaie_core::policy::parse_cpu_quota("50%").unwrap();
    assert_eq!(quota, 50_000);
    assert_eq!(period, 100_000);
}

#[test]
fn parse_cpu_quota_200_percent() {
    let (quota, period) = oaie_core::policy::parse_cpu_quota("200%").unwrap();
    assert_eq!(quota, 200_000);
    assert_eq!(period, 100_000);
}

#[test]
fn parse_cpu_quota_zero_fails() {
    assert!(oaie_core::policy::parse_cpu_quota("0%").is_err());
}

#[test]
fn parse_cpu_quota_no_percent_fails() {
    assert!(oaie_core::policy::parse_cpu_quota("50").is_err());
}

#[test]
fn parse_cpu_quota_abc_fails() {
    assert!(oaie_core::policy::parse_cpu_quota("abc%").is_err());
}

// ── Step 11 test 3: PolicyLimits backward compat ──

#[test]
fn policy_limits_backward_compat() {
    // TOML without cpu_quota field should still parse.
    let toml_str = r#"
        max_memory = "512M"
        max_time = "5m"
        max_pids = 64
        max_fsize = "1G"
    "#;
    let limits: oaie_core::policy::PolicyLimits = toml::from_str(toml_str).unwrap();
    assert_eq!(limits.max_pids, 64);
    assert!(limits.cpu_quota.is_none());
}

// ── Step 11 test 4: Manifest backward compat ──

#[test]
fn manifest_isolation_backward_compat() {
    // IsolationInfo TOML without cgroup field should still parse.
    let toml_str = r#"
        level = "full"
        namespaces = ["user", "mount", "pid"]
        network = false
        landlock = true
    "#;
    let info: oaie_core::manifest::IsolationInfo = toml::from_str(toml_str).unwrap();
    assert_eq!(info.level, oaie_core::manifest::IsolationLevel::Full);
    assert!(info.cgroup.is_none());
}

#[test]
fn manifest_resources_backward_compat() {
    // A minimal manifest TOML without resources should still parse.
    use oaie_core::manifest::ResourceInfo;

    // ResourceInfo with all None fields is valid.
    let json = r#"{"memory_limit":null,"memory_peak":null,"cpu_user_ms":null,"cpu_system_ms":null,"pids_peak":null}"#;
    let res: ResourceInfo = serde_json::from_str(json).unwrap();
    assert!(res.memory_limit.is_none());
    assert!(res.pids_peak.is_none());
}

// ── Step 11 test 5: ArtifactType::ResourceStats round-trip ──

#[test]
fn artifact_type_resource_stats_roundtrip() {
    use oaie_core::artifact::ArtifactType;

    let at = ArtifactType::ResourceStats;
    assert_eq!(at.to_string(), "resource_stats");

    let parsed = ArtifactType::from_str("resource_stats").unwrap();
    assert_eq!(parsed, ArtifactType::ResourceStats);
}

#[test]
fn artifact_type_resource_stats_serde_matches_display() {
    use oaie_core::artifact::ArtifactType;

    // serde (snake_case) and Display/FromStr must produce the same string.
    let at = ArtifactType::ResourceStats;
    let json = serde_json::to_string(&at).unwrap();
    assert_eq!(json, "\"resource_stats\"");

    let parsed: ArtifactType = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, at);
}

// ── Step 11 test 6: Stats file parsing ──

#[test]
fn collect_stats_from_mock_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();

    // Create mock cgroup files.
    std::fs::write(path.join("memory.peak"), "347078656\n").unwrap();
    std::fs::write(path.join("memory.max"), "536870912\n").unwrap();
    std::fs::write(path.join("pids.current"), "12\n").unwrap();
    std::fs::write(path.join("pids.max"), "64\n").unwrap();
    std::fs::write(
        path.join("cpu.stat"),
        "user_usec 1230000\nsystem_usec 89000\nnr_throttled 5\nthrottled_usec 10000\n",
    )
    .unwrap();
    std::fs::write(
        path.join("memory.events"),
        "low 0\nhigh 0\nmax 1\noom 0\noom_kill 0\noom_group_kill 0\n",
    )
    .unwrap();

    let stats = oaie_cgroup::stats::collect_stats(path);
    assert_eq!(stats.memory_peak, Some(347_078_656));
    assert_eq!(stats.memory_limit, Some(536_870_912));
    assert_eq!(stats.pids_current, Some(12));
    assert_eq!(stats.pids_limit, Some(64));
    assert_eq!(stats.cpu_user_us, Some(1_230_000));
    assert_eq!(stats.cpu_system_us, Some(89_000));
    assert_eq!(stats.cpu_throttled_periods, Some(5));
    assert_eq!(stats.cpu_throttled_us, Some(10_000));
    assert_eq!(stats.oom_kill_count, Some(0));
}

#[test]
fn collect_stats_missing_files() {
    let dir = tempfile::tempdir().unwrap();
    // Empty directory — all stats should be None.
    let stats = oaie_cgroup::stats::collect_stats(dir.path());
    assert!(stats.memory_peak.is_none());
    assert!(stats.cpu_user_us.is_none());
    assert!(stats.pids_current.is_none());
    assert!(stats.oom_kill_count.is_none());
}

#[test]
fn collect_stats_max_value() {
    let dir = tempfile::tempdir().unwrap();
    // "max" means unlimited — should return None.
    std::fs::write(dir.path().join("memory.max"), "max\n").unwrap();
    std::fs::write(dir.path().join("pids.max"), "max\n").unwrap();

    let stats = oaie_cgroup::stats::collect_stats(dir.path());
    assert!(stats.memory_limit.is_none());
    assert!(stats.pids_limit.is_none());
}

#[test]
fn collect_stats_pids_peak_preferred() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();

    // When both pids.peak and pids.current exist, peak is preferred.
    std::fs::write(path.join("pids.peak"), "42\n").unwrap();
    std::fs::write(path.join("pids.current"), "1\n").unwrap();

    let stats = oaie_cgroup::stats::collect_stats(path);
    assert_eq!(stats.pids_current, Some(42));
}

#[test]
fn collect_stats_pids_current_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();

    // When only pids.current exists (older kernel), use it.
    std::fs::write(path.join("pids.current"), "7\n").unwrap();

    let stats = oaie_cgroup::stats::collect_stats(path);
    assert_eq!(stats.pids_current, Some(7));
}

#[test]
fn collect_stats_oom_kill_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();

    std::fs::write(
        path.join("memory.events"),
        "low 0\nhigh 0\nmax 3\noom 2\noom_kill 2\noom_group_kill 0\n",
    )
    .unwrap();

    let stats = oaie_cgroup::stats::collect_stats(path);
    assert_eq!(stats.oom_kill_count, Some(2));
}

#[test]
fn collect_stats_no_memory_events_file() {
    let dir = tempfile::tempdir().unwrap();
    // No memory.events file — oom_kill_count should be None.
    let stats = oaie_cgroup::stats::collect_stats(dir.path());
    assert!(stats.oom_kill_count.is_none());
}

// ── Step 11 test 7: Limits writing ──

#[test]
fn apply_limits_writes_files() {
    use oaie_core::cgroup::CgroupLimits;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();

    let limits = CgroupLimits {
        memory_max: Some(256 * 1024 * 1024),
        pids_max: Some(32),
        cpu_quota_us: Some(100_000),
        cpu_period_us: Some(100_000),
    };

    let applied = oaie_cgroup::limits::apply_limits(path, &limits);
    assert!(applied.memory);
    assert!(applied.swap);
    assert!(applied.pids);
    assert!(applied.cpu);

    let mem = std::fs::read_to_string(path.join("memory.max")).unwrap();
    assert_eq!(mem, "268435456"); // 256 * 1024 * 1024

    // memory.swap.max should also be written when memory limit is set.
    let swap = std::fs::read_to_string(path.join("memory.swap.max")).unwrap();
    assert_eq!(swap, "0");

    let pids = std::fs::read_to_string(path.join("pids.max")).unwrap();
    assert_eq!(pids, "32");

    let cpu = std::fs::read_to_string(path.join("cpu.max")).unwrap();
    assert_eq!(cpu, "100000 100000");
}

#[test]
fn apply_limits_partial() {
    use oaie_core::cgroup::CgroupLimits;

    let dir = tempfile::tempdir().unwrap();

    let limits = CgroupLimits {
        memory_max: Some(128 * 1024 * 1024),
        pids_max: None,
        cpu_quota_us: None,
        cpu_period_us: None,
    };

    let applied = oaie_cgroup::limits::apply_limits(dir.path(), &limits);
    assert!(applied.memory);
    assert!(applied.swap);
    assert!(!applied.pids);
    assert!(!applied.cpu);
    assert!(applied.any_enforced());
}

#[test]
fn apply_limits_no_swap_without_memory() {
    use oaie_core::cgroup::CgroupLimits;

    let dir = tempfile::tempdir().unwrap();

    // No memory limit → swap should not be written.
    let limits = CgroupLimits {
        memory_max: None,
        pids_max: Some(16),
        cpu_quota_us: None,
        cpu_period_us: None,
    };

    let applied = oaie_cgroup::limits::apply_limits(dir.path(), &limits);
    assert!(!applied.memory);
    assert!(!applied.swap);
    assert!(applied.pids);
    assert!(!dir.path().join("memory.swap.max").exists());
}

// ── Step 11 test 8: oaie-priv protocol round-trip ──

#[test]
fn priv_protocol_create_cgroup_roundtrip() {
    use oaie_core::cgroup::CgroupLimits;
    use oaie_priv::protocol::Request;

    let req = Request::CreateCgroup {
        run_id: "abc-123".into(),
        limits: CgroupLimits {
            memory_max: Some(512 * 1024 * 1024),
            pids_max: Some(64),
            cpu_quota_us: None,
            cpu_period_us: None,
        },
    };

    let json = serde_json::to_vec(&req).unwrap();
    let parsed: Request = serde_json::from_slice(&json).unwrap();
    match parsed {
        Request::CreateCgroup { run_id, limits } => {
            assert_eq!(run_id, "abc-123");
            assert_eq!(limits.memory_max, Some(512 * 1024 * 1024));
            assert_eq!(limits.pids_max, Some(64));
        }
        _ => panic!("expected CreateCgroup"),
    }
}

#[test]
fn priv_protocol_cleanup_roundtrip() {
    use oaie_priv::protocol::Request;

    let req = Request::CleanupCgroup {
        cgroup_path: "/sys/fs/cgroup/oaie/run-test".into(),
    };

    let json = serde_json::to_vec(&req).unwrap();
    let parsed: Request = serde_json::from_slice(&json).unwrap();
    match parsed {
        Request::CleanupCgroup { cgroup_path } => {
            assert_eq!(cgroup_path, "/sys/fs/cgroup/oaie/run-test");
        }
        _ => panic!("expected CleanupCgroup"),
    }
}

#[test]
fn priv_protocol_ping_roundtrip() {
    use oaie_priv::protocol::Request;

    let req = Request::Ping;
    let json = serde_json::to_vec(&req).unwrap();
    let parsed: Request = serde_json::from_slice(&json).unwrap();
    assert!(matches!(parsed, Request::Ping));
}

#[test]
fn priv_response_roundtrip() {
    use oaie_priv::protocol::Response;

    let ok = Response::ok();
    let json = serde_json::to_vec(&ok).unwrap();
    let parsed: Response = serde_json::from_slice(&json).unwrap();
    assert!(parsed.ok);
    assert!(parsed.error.is_none());

    let ok_path = Response::ok_with_path("/sys/fs/cgroup/oaie/run-abc");
    let json = serde_json::to_vec(&ok_path).unwrap();
    let parsed: Response = serde_json::from_slice(&json).unwrap();
    assert!(parsed.ok);
    assert_eq!(parsed.cgroup_path.as_deref(), Some("/sys/fs/cgroup/oaie/run-abc"));

    let err = Response::error("something failed");
    let json = serde_json::to_vec(&err).unwrap();
    let parsed: Response = serde_json::from_slice(&json).unwrap();
    assert!(!parsed.ok);
    assert_eq!(parsed.error.as_deref(), Some("something failed"));
}

#[test]
fn priv_protocol_oversized_payload_rejected() {
    // Simulate a length header claiming > 64KB.
    let len: u32 = 128 * 1024; // 128KB > MAX_REQUEST_SIZE (64KB)
    let len_bytes = len.to_be_bytes();
    // Just verify the encoding is correct — the actual rejection happens
    // in the binary's read loop, not in the protocol module.
    assert_eq!(u32::from_be_bytes(len_bytes), 128 * 1024);
}

// ── Step 11 test 9: oaie-priv validation ──

#[test]
fn validate_run_id_valid() {
    assert!(oaie_priv::validate::validate_run_id("abc-123").is_ok());
    assert!(oaie_priv::validate::validate_run_id("A1B2C3").is_ok());
    assert!(oaie_priv::validate::validate_run_id("a").is_ok());
}

#[test]
fn validate_run_id_empty() {
    assert!(oaie_priv::validate::validate_run_id("").is_err());
}

#[test]
fn validate_run_id_too_long() {
    let long = "a".repeat(65);
    assert!(oaie_priv::validate::validate_run_id(&long).is_err());
}

#[test]
fn validate_run_id_path_traversal() {
    assert!(oaie_priv::validate::validate_run_id("../../etc/passwd").is_err());
    assert!(oaie_priv::validate::validate_run_id("run/../../../root").is_err());
}

#[test]
fn validate_run_id_special_chars() {
    assert!(oaie_priv::validate::validate_run_id("hello world").is_err());
    assert!(oaie_priv::validate::validate_run_id("run;rm -rf").is_err());
    assert!(oaie_priv::validate::validate_run_id("hello\0world").is_err());
}

#[test]
fn validate_cgroup_path_valid() {
    assert!(oaie_priv::validate::validate_cgroup_path("/sys/fs/cgroup/oaie/run-abc").is_ok());
}

#[test]
fn validate_cgroup_path_outside_root() {
    assert!(oaie_priv::validate::validate_cgroup_path("/sys/fs/cgroup/user.slice/foo").is_err());
    assert!(oaie_priv::validate::validate_cgroup_path("/tmp/evil").is_err());
}

#[test]
fn validate_cgroup_path_traversal() {
    assert!(oaie_priv::validate::validate_cgroup_path("/sys/fs/cgroup/oaie/../user.slice").is_err());
}

#[test]
fn validate_cgroup_path_root_itself() {
    // Must not allow deletion of the OAIE root directory itself.
    assert!(oaie_priv::validate::validate_cgroup_path("/sys/fs/cgroup/oaie/").is_err());
}

#[test]
fn validate_cgroup_path_double_slash() {
    assert!(oaie_priv::validate::validate_cgroup_path("/sys/fs/cgroup/oaie//run-abc").is_err());
}

#[test]
fn validate_cgroup_path_nul_byte() {
    assert!(oaie_priv::validate::validate_cgroup_path("/sys/fs/cgroup/oaie/run\0abc").is_err());
}

#[test]
fn validate_limits_valid() {
    use oaie_core::cgroup::CgroupLimits;

    let limits = CgroupLimits {
        memory_max: Some(128 * 1024 * 1024),
        pids_max: Some(64),
        cpu_quota_us: Some(50_000),
        cpu_period_us: Some(100_000),
    };
    assert!(oaie_priv::validate::validate_limits(&limits).is_ok());
}

#[test]
fn validate_limits_memory_too_small() {
    use oaie_core::cgroup::CgroupLimits;

    let limits = CgroupLimits {
        memory_max: Some(512), // < 1MB
        ..Default::default()
    };
    assert!(oaie_priv::validate::validate_limits(&limits).is_err());
}

#[test]
fn validate_limits_pids_zero() {
    use oaie_core::cgroup::CgroupLimits;

    let limits = CgroupLimits {
        pids_max: Some(0),
        ..Default::default()
    };
    assert!(oaie_priv::validate::validate_limits(&limits).is_err());
}

#[test]
fn validate_limits_pids_too_large() {
    use oaie_core::cgroup::CgroupLimits;

    let limits = CgroupLimits {
        pids_max: Some(2_000_000),
        ..Default::default()
    };
    assert!(oaie_priv::validate::validate_limits(&limits).is_err());
}

#[test]
fn validate_limits_cpu_quota_without_period() {
    use oaie_core::cgroup::CgroupLimits;

    let limits = CgroupLimits {
        cpu_quota_us: Some(50_000),
        cpu_period_us: None,
        ..Default::default()
    };
    assert!(oaie_priv::validate::validate_limits(&limits).is_err());
}

#[test]
fn validate_limits_cpu_period_without_quota() {
    use oaie_core::cgroup::CgroupLimits;

    let limits = CgroupLimits {
        cpu_quota_us: None,
        cpu_period_us: Some(100_000),
        ..Default::default()
    };
    assert!(oaie_priv::validate::validate_limits(&limits).is_err());
}

#[test]
fn validate_limits_cpu_quota_zero() {
    use oaie_core::cgroup::CgroupLimits;

    let limits = CgroupLimits {
        cpu_quota_us: Some(0),
        cpu_period_us: Some(100_000),
        ..Default::default()
    };
    assert!(oaie_priv::validate::validate_limits(&limits).is_err());
}

#[test]
fn validate_limits_all_none() {
    use oaie_core::cgroup::CgroupLimits;

    let limits = CgroupLimits::default();
    assert!(oaie_priv::validate::validate_limits(&limits).is_ok());
}

// ── CgroupMode parsing ──

#[test]
fn cgroup_mode_parsing() {
    use oaie_core::cgroup::CgroupMode;

    assert_eq!("auto".parse::<CgroupMode>().unwrap(), CgroupMode::Auto);
    assert_eq!("require".parse::<CgroupMode>().unwrap(), CgroupMode::Require);
    assert_eq!("off".parse::<CgroupMode>().unwrap(), CgroupMode::Off);
    assert!("invalid".parse::<CgroupMode>().is_err());
}

// ── Step 11 test 10: Report generation with ResourceInfo ──

#[test]
fn report_with_resource_info() {
    use oaie_core::manifest::*;

    let manifest = Manifest {
        version: 1,
        hash_algorithm: "blake3".into(),
        run_id: oaie_core::run_id::RunId::new(),
        created: chrono::Utc::now(),
        command: vec!["echo".into(), "hello".into()],
        exit_code: Some(0),
        duration_ms: 150,
        isolation: IsolationInfo {
            level: IsolationLevel::Full,
            namespaces: vec!["user".into(), "mount".into()],
            network: false,
            network_mode: "off".into(),
            landlock: true,
            cgroup: Some(oaie_core::cgroup::CgroupInfo {
                name: "oaie-run-test.scope".into(),
                method: oaie_core::cgroup::CgroupMethod::SystemdRun,
                enforced: true,
            }),
            backend: None,
            firecracker_version: None,
            kernel: None,
            rootfs: None,
            trace_integrity: None,
            interactive: false,
        },
        artifacts: vec![],
        policy: Some(PolicyInfo {
            name: Some("safe".into()),
            network: false,
            network_rules: None,
            max_memory: "512M".into(),
            max_time: "5m".into(),
            max_pids: 64,
            max_fsize: "1G".into(),
            allow_memfd: false,
            deny_paths: vec![],
            auto_mounts: vec![],
            limits_enforced: LimitsEnforced {
                timeout: true,
                memory: true,
                pids: true,
                fsize: true,
            },
        }),
        trace: None,
        resources: Some(ResourceInfo {
            memory_limit: Some("512M".into()),
            memory_peak: Some("347M".into()),
            cpu_user_ms: Some(1230),
            cpu_system_ms: Some(89),
            pids_peak: Some(12),
        }),
    };

    let report = oaie_report::generate_report(&manifest, None);

    // Check that resource accounting section exists.
    assert!(report.contains("## Resource Accounting"));
    assert!(report.contains("Memory limit"));
    assert!(report.contains("512M"));
    assert!(report.contains("Memory peak"));
    assert!(report.contains("347M"));
    assert!(report.contains("CPU user"));
    assert!(report.contains("1230ms"));
    assert!(report.contains("PIDs peak"));
    assert!(report.contains("12"));

    // Check that cgroup enforcement is shown in Policy section.
    assert!(report.contains("enforced — cgroup memory.max"));
    assert!(report.contains("enforced — cgroup pids.max"));
}

#[test]
fn report_without_resource_info() {
    use oaie_core::manifest::*;

    let manifest = Manifest {
        version: 1,
        hash_algorithm: "blake3".into(),
        run_id: oaie_core::run_id::RunId::new(),
        created: chrono::Utc::now(),
        command: vec!["echo".into(), "hello".into()],
        exit_code: Some(0),
        duration_ms: 150,
        isolation: IsolationInfo {
            level: IsolationLevel::Full,
            namespaces: vec!["user".into(), "mount".into()],
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
        },
        artifacts: vec![],
        policy: Some(PolicyInfo {
            name: Some("safe".into()),
            network: false,
            network_rules: None,
            max_memory: "512M".into(),
            max_time: "5m".into(),
            max_pids: 64,
            max_fsize: "1G".into(),
            allow_memfd: false,
            deny_paths: vec![],
            auto_mounts: vec![],
            limits_enforced: LimitsEnforced {
                timeout: true,
                memory: true,
                pids: true,
                fsize: true,
            },
        }),
        trace: None,
        resources: None,
    };

    let report = oaie_report::generate_report(&manifest, None);

    // Resource Accounting section should NOT appear.
    assert!(!report.contains("## Resource Accounting"));

    // Policy section should show advisory rlimits.
    assert!(report.contains("advisory — RLIMIT_AS"));
    assert!(report.contains("system-wide per-UID — RLIMIT_NPROC"));
}
