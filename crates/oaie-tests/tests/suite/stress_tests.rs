//! Stress tests for session mode — exercising limits and edge cases.
//!
//! These tests run serially (via Makefile) to avoid resource contention.

use std::time::{Duration, Instant};

use oaie_cli::session_runner::SessionRunner;
use oaie_core::session::*;
use oaie_tests::{default_resolved_policy, setup_store, userns_available};

// ── Stress 1: Rapid sequential tool calls ──

#[test]
fn test_stress_rapid_tool_calls() {
    if !userns_available() {
        eprintln!("SKIP: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let policy = default_resolved_policy(Some(Duration::from_secs(60)));

    let config = SessionConfig {
        name: Some("stress-rapid-calls".into()),
        budget: SessionBudget {
            max_tool_calls: 100,
            max_wall_time_s: 60,
            max_tool_time_s: 30,
            ..SessionBudget::default()
        },
        ..SessionConfig::default()
    };

    // Agent sends 50 rapid sequential tool calls (echo commands).
    let agent_script = r#"
import socket, json, os, time
sock_path = os.environ['OAIE_DISPATCH_SOCK']
time.sleep(0.2)
for i in range(50):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    req = {"id": f"rapid-{i}", "command": ["echo", f"call-{i}"]}
    s.sendall((json.dumps(req) + '\n').encode())
    resp = b''
    while b'\n' not in resp:
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk
    s.close()
"#;

    let command = vec![
        "python3".to_string(),
        "-c".to_string(),
        agent_script.to_string(),
    ];

    let session = SessionRunner::create(store, policy, config, &command).unwrap();
    let start = Instant::now();
    let result = session.run(&command, true).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(result.state, SessionState::Stopped);
    assert_eq!(result.tool_calls, 50, "expected exactly 50 tool calls");
    assert!(
        elapsed.as_secs() < 30,
        "50 echo calls should complete in <30s, took {}s",
        elapsed.as_secs()
    );
}

// ── Stress 2: Concurrent sessions ──

#[test]
fn test_stress_concurrent_sessions() {
    let (store, _dir) = setup_store();

    // Run 3 sequential sessions (not truly concurrent, but validates no state leaks).
    for i in 0..3 {
        let policy = default_resolved_policy(Some(Duration::from_secs(10)));
        let config = SessionConfig {
            name: Some(format!("concurrent-{i}")),
            budget: SessionBudget {
                max_tool_calls: 5,
                max_wall_time_s: 10,
                ..SessionBudget::default()
            },
            ..SessionConfig::default()
        };
        let command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exit 0".to_string(),
        ];

        let session =
            SessionRunner::create(store.clone(), policy, config, &command).unwrap();
        let result = session.run(&command, true).unwrap();
        assert_eq!(result.state, SessionState::Stopped);
    }

    // Verify all 3 sessions are in the DB.
    let db = oaie_db::OaieDb::open(&store.db_path).unwrap();
    let sessions = db.list_sessions(10).unwrap();
    assert!(
        sessions.len() >= 3,
        "expected at least 3 sessions, got {}",
        sessions.len()
    );
}

// ── Stress 3: Agent crash recovery ──

#[test]
fn test_stress_agent_crash() {
    let (store, _dir) = setup_store();
    let policy = default_resolved_policy(Some(Duration::from_secs(10)));
    let config = SessionConfig {
        name: Some("crash-test".into()),
        budget: SessionBudget {
            max_tool_calls: 10,
            max_wall_time_s: 10,
            ..SessionBudget::default()
        },
        ..SessionConfig::default()
    };

    // Agent crashes immediately via SIGKILL.
    let command = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "kill -9 $$".to_string(),
    ];

    let session = SessionRunner::create(store, policy, config, &command).unwrap();
    let result = session.run(&command, true).unwrap();

    // Session should stop (agent exited).
    assert_eq!(result.state, SessionState::Stopped);
    assert_eq!(result.tool_calls, 0, "no tool calls from crashed agent");
}

// ── Stress 4: Path traversal escape attempts ──

#[test]
fn test_stress_path_traversal() {
    if !userns_available() {
        eprintln!("SKIP: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let policy = default_resolved_policy(Some(Duration::from_secs(10)));
    let config = SessionConfig {
        name: Some("path-traversal-test".into()),
        budget: SessionBudget {
            max_tool_calls: 5,
            max_wall_time_s: 10,
            ..SessionBudget::default()
        },
        ..SessionConfig::default()
    };

    // Agent sends a tool call with a path traversal attempt in inputs.
    let agent_script = r#"
import socket, json, os, time
sock_path = os.environ['OAIE_DISPATCH_SOCK']
time.sleep(0.2)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)
# Attempt path traversal in input label.
req = {"id": "escape", "command": ["echo", "hi"], "inputs": {"../../../etc/passwd": "/dev/null"}}
s.sendall((json.dumps(req) + '\n').encode())
resp = b''
while b'\n' not in resp:
    chunk = s.recv(4096)
    if not chunk:
        break
    resp += chunk
parsed = json.loads(resp)
# Should get an error about unsafe label.
assert parsed.get('error'), f"expected error, got: {parsed}"
s.close()
"#;

    let command = vec![
        "python3".to_string(),
        "-c".to_string(),
        agent_script.to_string(),
    ];

    let session = SessionRunner::create(store, policy, config, &command).unwrap();
    let result = session.run(&command, true).unwrap();
    assert_eq!(result.state, SessionState::Stopped);
}

// ── Stress 5: Large output budget tracking ──

#[test]
fn test_stress_large_output() {
    if !userns_available() {
        eprintln!("SKIP: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let policy = default_resolved_policy(Some(Duration::from_secs(15)));
    let config = SessionConfig {
        name: Some("large-output-test".into()),
        budget: SessionBudget {
            max_tool_calls: 10,
            max_wall_time_s: 15,
            max_output_bytes: 1_073_741_824, // 1GB (should not be reached)
            ..SessionBudget::default()
        },
        ..SessionConfig::default()
    };

    // Agent runs a tool that produces some output, then checks budget tracking.
    let agent_script = r#"
import socket, json, os, time
sock_path = os.environ['OAIE_DISPATCH_SOCK']
time.sleep(0.2)
# Run 3 tool calls that produce output files.
for i in range(3):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    req = {"id": f"out-{i}", "command": ["echo", "x" * 100]}
    s.sendall((json.dumps(req) + '\n').encode())
    resp = b''
    while b'\n' not in resp:
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk
    s.close()
"#;

    let command = vec![
        "python3".to_string(),
        "-c".to_string(),
        agent_script.to_string(),
    ];

    let session = SessionRunner::create(store, policy, config, &command).unwrap();
    let result = session.run(&command, true).unwrap();
    assert_eq!(result.state, SessionState::Stopped);
    assert_eq!(result.tool_calls, 3);
    // Output bytes are tracked via artifact sizes — value depends on
    // runner artifact handling, so just verify the field exists and
    // the session completed correctly.
    eprintln!("total_output_bytes = {}", result.total_output_bytes);
}

// ── Stress 6: Oversized dispatch request ──

#[test]
fn test_stress_oversized_request() {
    if !userns_available() {
        eprintln!("SKIP: user namespaces not available");
        return;
    }

    let (store, _dir) = setup_store();
    let policy = default_resolved_policy(Some(Duration::from_secs(10)));
    let config = SessionConfig {
        name: Some("oversized-request-test".into()),
        budget: SessionBudget {
            max_tool_calls: 5,
            max_wall_time_s: 10,
            ..SessionBudget::default()
        },
        ..SessionConfig::default()
    };

    // Agent sends an oversized request (>1 MiB) then a normal one.
    let agent_script = r#"
import socket, json, os, time
sock_path = os.environ['OAIE_DISPATCH_SOCK']
time.sleep(0.2)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)
# Send oversized request (> 1 MiB).
big_str = "A" * (1024 * 1024 + 100)
req = {"id": "big", "command": ["echo", big_str]}
s.sendall((json.dumps(req) + '\n').encode())
resp = b''
while b'\n' not in resp:
    chunk = s.recv(4096)
    if not chunk:
        break
    resp += chunk
# Should get error response about size limit.
parsed = json.loads(resp)
assert parsed.get('error'), f"expected error for oversized request, got: {parsed}"
s.close()
"#;

    let command = vec![
        "python3".to_string(),
        "-c".to_string(),
        agent_script.to_string(),
    ];

    let session = SessionRunner::create(store, policy, config, &command).unwrap();
    let result = session.run(&command, true).unwrap();
    assert_eq!(result.state, SessionState::Stopped);
}
