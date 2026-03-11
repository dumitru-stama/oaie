//! Backward compatibility tests — ensure v0.2 patterns still work with v0.3 code.
//!
//! All tests are parallel-safe (no namespace spawning).

use std::time::Duration;

use oaie_core::policy::Policy;
use oaie_core::session::{SessionBudget, SessionConfig};
use oaie_db::OaieDb;
use oaie_tests::{default_resolved_policy, setup_store, userns_available};

// ── Test 1: v0.2 manifest fields ──

#[test]
fn test_v02_manifest_parses_without_session_fields() {
    // A manifest TOML from v0.2 has no session-related fields.
    // Verify it still parses via the Manifest struct (session fields are optional).
    let toml_str = r#"
version = 1
hash_algorithm = "blake3"
run_id = "019d0000-0000-7000-0000-000000000001"
created = "2026-01-01T00:00:00Z"
command = ["echo", "hello"]
exit_code = 0
duration_ms = 42

[isolation]
level = "full"
namespaces = ["user", "mount", "pid", "net"]
network = false
interactive = false

[[artifacts]]
label = "stdout"
hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
size = 6
artifact_type = "stdout"
"#;
    let manifest: oaie_core::manifest::Manifest = toml::from_str(toml_str).unwrap();
    assert_eq!(manifest.exit_code, Some(0));
    assert_eq!(manifest.command, vec!["echo", "hello"]);
    // Trace section is optional — should be None for v0.2 manifests.
    assert!(manifest.trace.is_none());
}

// ── Test 2: v0.2 policy boolean network ──

#[test]
fn test_v02_policy_bool_network_backward_compat() {
    // v0.2 policies use `[defaults] network = false/true`.
    // v0.3 uses NetworkMode enum but maintains backward compat via serde.
    let toml_no_net = r#"
[defaults]
network = false

[mounts]
deny = []

[limits]
max_memory = "512M"
max_time = "5m"
max_pids = 64
max_fsize = "1G"
"#;
    let policy: Policy = toml::from_str(toml_no_net).unwrap();
    assert!(!policy.defaults.network.has_connectivity());

    // Explicit network = true should parse.
    let toml_net = r#"
[defaults]
network = true

[mounts]
deny = []

[limits]
max_memory = "512M"
max_time = "5m"
max_pids = 64
max_fsize = "1G"
"#;
    let policy: Policy = toml::from_str(toml_net).unwrap();
    assert!(policy.defaults.network.has_connectivity());
}

// ── Test 3: v0.2 policy presets ──

#[test]
fn test_v02_policy_presets_still_work() {
    // preset_safe and preset_net should still produce valid policies.
    let safe = Policy::preset_safe();
    assert!(!safe.defaults.network.has_connectivity());

    let net = Policy::preset_net();
    assert!(net.defaults.network.has_connectivity());

    // Both should serialize/deserialize via TOML roundtrip.
    let safe_toml = toml::to_string(&safe).unwrap();
    let safe_parsed: Policy = toml::from_str(&safe_toml).unwrap();
    assert!(!safe_parsed.defaults.network.has_connectivity());
}

// ── Test 4: v0.2 run mode unaffected ──

#[test]
fn test_v02_run_mode_works_with_v03_codebase() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let runner = oaie_cli::runner::Runner::new(store).unwrap();
    let job = oaie_tests::sandboxed_job(&["echo", "v02-compat"]);
    let policy = default_resolved_policy(Some(Duration::from_secs(30)));

    // Standard run (non-session) should work unchanged.
    let result = runner.execute(&job, &policy, true, None).unwrap();
    assert_eq!(result.exit_code, 0);
}

// ── Test 5: missing network_mode field defaults ──

#[test]
fn test_v02_manifest_without_network_mode_field() {
    // v0.2 manifests may not have the network_mode field in isolation.
    let toml_str = r#"
version = 1
hash_algorithm = "blake3"
run_id = "019d0000-0000-7000-0000-000000000002"
created = "2026-01-01T00:00:00Z"
command = ["echo", "test"]
exit_code = 0
duration_ms = 10

[isolation]
level = "full"
namespaces = ["user", "mount", "pid", "net"]
network = false
interactive = false

[[artifacts]]
label = "stdout"
hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
size = 5
artifact_type = "stdout"
"#;
    let manifest: oaie_core::manifest::Manifest = toml::from_str(toml_str).unwrap();
    assert!(!manifest.isolation.network);
    // network_mode defaults to "off" for pre-Phase H manifests.
    assert_eq!(manifest.isolation.network_mode, "off");
}

// ── Test 6: fresh DB auto-migration ──

#[test]
fn test_v02_db_schema_auto_migration() {
    // A fresh DB should auto-migrate and have the sessions table.
    let db = OaieDb::open_in_memory().unwrap();
    db.initialize().unwrap();

    // sessions table should exist (v0.3 schema).
    let sessions = db.list_sessions(10).unwrap();
    assert!(sessions.is_empty()); // No sessions, but table exists.

    // SessionBudget with new field should roundtrip through JSON.
    let budget = SessionBudget::default();
    assert_eq!(budget.max_agent_output_rate, 0);
    let json = serde_json::to_string(&budget).unwrap();
    let parsed: SessionBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.max_tool_calls, 50);
    assert_eq!(parsed.max_agent_output_rate, 0);

    // SessionConfig with new max_concurrent_tools field should roundtrip.
    let config = SessionConfig::default();
    assert_eq!(config.max_concurrent_tools, 1);
    let json = serde_json::to_string(&config).unwrap();
    let parsed: SessionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.max_concurrent_tools, 1);
}
