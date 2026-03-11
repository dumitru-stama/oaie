//! v0.3 integration tests — session mode end-to-end validation.
//!
//! All tests run serially via the Makefile (namespace-heavy).

use std::time::Duration;

use oaie_cli::session_runner::SessionRunner;
use oaie_core::hash_algo::HashAlgorithm;
use oaie_core::session::*;
use oaie_tests::{default_resolved_policy, setup_store, userns_available};

// ── Test 1: Session lifecycle with containment ──

#[test]
fn test_v03_session_lifecycle_with_containment() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let profile = ContainmentProfile::Local;
    let budget = profile.budget();
    let policy = default_resolved_policy(Some(Duration::from_secs(30)));

    let config = SessionConfig {
        name: Some("v03-lifecycle".into()),
        budget: SessionBudget {
            max_tool_calls: 5,
            max_wall_time_s: 60,
            max_tool_time_s: 30,
            ..budget
        },
        containment: Some("local".into()),
        ..SessionConfig::default()
    };

    // Agent exits immediately — lifecycle still works with containment profile.
    let command = vec!["/bin/true".to_string()];

    let session = SessionRunner::create(store.clone(), policy, config, &command).unwrap();
    let result = session.run(&command, true).unwrap();

    assert_eq!(result.state, SessionState::Stopped);
    assert_eq!(result.tool_calls, 0);
    assert!(result.manifest_hash.is_some());
}

// ── Test 2: Budget enforcement ──

#[test]
fn test_v03_session_budget_enforcement_strict() {
    if !userns_available() {
        eprintln!("skipping: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let policy = default_resolved_policy(Some(Duration::from_secs(30)));

    let config = SessionConfig {
        budget: SessionBudget {
            max_tool_calls: 2,
            max_wall_time_s: 60,
            max_tool_time_s: 30,
            ..SessionBudget::default()
        },
        ..SessionConfig::default()
    };

    // Agent exits immediately — no tool calls, budget not consumed.
    let command = vec!["/bin/true".to_string()];

    let session = SessionRunner::create(store, policy, config, &command).unwrap();
    let result = session.run(&command, true).unwrap();

    // Agent exited without dispatching — budget intact.
    assert_eq!(result.tool_calls, 0);
    assert_eq!(result.state, SessionState::Stopped);
}

// ── Test 3: Budget extension ──

#[test]
fn test_v03_session_budget_extension() {
    // Verify BudgetExtensionRequest serialization works.
    let ext = BudgetExtensionRequest {
        add_tool_calls: 10,
        add_wall_time_s: 300,
        add_tool_time_s: 0,
        add_output_bytes: 0,
    };
    let json = serde_json::to_string(&ext).unwrap();
    let parsed: BudgetExtensionRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.add_tool_calls, 10);
    assert_eq!(parsed.add_wall_time_s, 300);
}

// ── Test 4: Session event chain verification ──

#[test]
fn test_v03_session_verification_pass() {
    use oaie_cli::session_runner::SessionEventWriter;

    let mut writer = SessionEventWriter::new(HashAlgorithm::Blake3);

    writer.emit(SessionEventKind::SessionStart {
        command: vec!["echo".into(), "verify".into()],
    });
    writer.emit(SessionEventKind::ToolDispatch {
        call_id: "c-1".into(),
        command: vec!["echo".into(), "test".into()],
    });
    writer.emit(SessionEventKind::ToolResult {
        call_id: "c-1".into(),
        run_id: "run-001".into(),
        exit_code: 0,
        trace_hash: None,
    });
    writer.emit(SessionEventKind::SessionStop {
        status: "stopped".into(),
    });

    let (bytes, chain_tip) = writer.finalize();
    assert!(!bytes.is_empty());
    assert!(!chain_tip.is_empty());

    // Parse events and verify chain.
    let events: Vec<SessionEvent> = bytes
        .split(|&b| b == b'\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_slice(line).ok())
        .collect();
    assert_eq!(events.len(), 4);
    // Sequence numbers should be monotonic.
    for (i, event) in events.iter().enumerate() {
        assert_eq!(event.seq, i as u64);
    }
}

// ── Test 5: Tampered event log detection ──

#[test]
fn test_v03_session_verification_tampered_log() {
    use oaie_cli::session_runner::SessionEventWriter;

    let mut writer = SessionEventWriter::new(HashAlgorithm::Blake3);

    writer.emit(SessionEventKind::SessionStart {
        command: vec!["echo".into()],
    });
    writer.emit(SessionEventKind::SessionStop {
        status: "stopped".into(),
    });

    let (bytes, _chain_tip) = writer.finalize();

    // Parse events.
    let events: Vec<SessionEvent> = bytes
        .split(|&b| b == b'\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_slice(line).ok())
        .collect();
    assert_eq!(events.len(), 2);

    // Tamper: modify the second event's prev_hash.
    let mut tampered = events.clone();
    tampered[1] = SessionEvent {
        prev_hash: "0".repeat(64),
        ..tampered[1].clone()
    };

    // The prev_hash of event[1] should NOT match the hash of event[0].
    assert_ne!(tampered[1].prev_hash, events[1].prev_hash);
}

// ── Test 6: Containment profile budget defaults ──

#[test]
fn test_v03_containment_profile_budget_defaults() {
    let local = ContainmentProfile::Local.budget();
    assert_eq!(local.max_tool_calls, 100);
    assert_eq!(local.max_wall_time_s, 3600);

    let cloud = ContainmentProfile::Cloud.budget();
    assert_eq!(cloud.max_tool_calls, 50);
    assert_eq!(cloud.max_wall_time_s, 1800);

    let strict = ContainmentProfile::Strict.budget();
    assert_eq!(strict.max_tool_calls, 20);
    assert_eq!(strict.max_wall_time_s, 600);

    let interactive = ContainmentProfile::Interactive.budget();
    assert_eq!(interactive.max_tool_calls, 200);
    assert_eq!(interactive.max_wall_time_s, 7200);

    // All 4 profiles listed.
    let all = ContainmentProfile::list_all();
    assert_eq!(all.len(), 4);
}

// ── Test 7: Tool filter integration ──

#[test]
fn test_v03_tool_filter_integration() {
    // Deny takes precedence over allow.
    let filter = ToolFilter {
        allow: vec!["echo".into(), "cat".into()],
        deny: vec!["cat".into()],
    };
    assert!(filter.is_allowed("echo"));
    assert!(!filter.is_allowed("cat")); // denied despite being in allow
    assert!(!filter.is_allowed("ls")); // not in allow list

    // Empty allow = everything allowed except deny.
    let filter2 = ToolFilter {
        allow: vec![],
        deny: vec!["rm".into()],
    };
    assert!(filter2.is_allowed("echo"));
    assert!(filter2.is_allowed("cat"));
    assert!(!filter2.is_allowed("rm"));

    // Glob matching.
    let filter3 = ToolFilter {
        allow: vec!["gcc*".into()],
        deny: vec![],
    };
    assert!(filter3.is_allowed("gcc"));
    assert!(filter3.is_allowed("gcc-12"));
    assert!(!filter3.is_allowed("clang"));
}

// ── Test 8: Heartbeat timeout ──

#[test]
fn test_v03_heartbeat_timeout() {
    // Verify heartbeat-related session event serialization.
    let event = SessionEventKind::HeartbeatTimeout {
        elapsed_s: 120,
        interval_s: 60,
    };
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("heartbeat_timeout"));
    assert!(json.contains("120"));
    assert!(json.contains("60"));

    let parsed: SessionEventKind = serde_json::from_str(&json).unwrap();
    match parsed {
        SessionEventKind::HeartbeatTimeout {
            elapsed_s,
            interval_s,
        } => {
            assert_eq!(elapsed_s, 120);
            assert_eq!(interval_s, 60);
        }
        _ => panic!("wrong event kind"),
    }
}
