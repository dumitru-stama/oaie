//! MCP tool handlers — dispatch `tools/call` requests to `OaieClient` methods.

use std::str::FromStr;

use serde_json::Value;

use oaie_agent::OaieClient;
use oaie_core::backend::BackendKind;
use oaie_core::job::{self, JobSpec};

use crate::jsonrpc::{self, Response};

/// Dispatch a `tools/call` request to the appropriate handler.
pub fn handle_tool_call(
    id: Option<Value>,
    tool_name: &str,
    arguments: &Value,
    store_path: &str,
) -> Response {
    match tool_name {
        "oaie_run" => handle_run(id, arguments, store_path),
        "oaie_verify" => handle_verify(id, arguments, store_path),
        "oaie_read_output" => handle_read_output(id, arguments, store_path),
        "oaie_session_run" => handle_session_run(id, arguments, store_path),
        "oaie_session_status" => handle_session_status(id, arguments, store_path),
        "oaie_session_stop" => handle_session_stop(id, arguments, store_path),
        _ => Response::err(
            id,
            jsonrpc::METHOD_NOT_FOUND,
            format!("unknown tool: {tool_name}"),
        ),
    }
}

/// Handle `oaie_run` — execute a command in the sandbox.
fn handle_run(id: Option<Value>, args: &Value, store_path: &str) -> Response {
    let command = match args.get("command").and_then(|v| v.as_array()) {
        Some(arr) => {
            let mut cmd = Vec::new();
            for item in arr {
                match item.as_str() {
                    Some(s) => cmd.push(s.to_string()),
                    None => {
                        return Response::err(
                            id,
                            jsonrpc::INVALID_PARAMS,
                            "command array must contain strings",
                        );
                    }
                }
            }
            if cmd.is_empty() {
                return Response::err(
                    id,
                    jsonrpc::INVALID_PARAMS,
                    "command array must not be empty",
                );
            }
            cmd
        }
        None => {
            return Response::err(
                id,
                jsonrpc::INVALID_PARAMS,
                "missing required parameter: command",
            );
        }
    };

    let policy_name = args
        .get("policy")
        .and_then(|v| v.as_str())
        .unwrap_or("agent-safe");

    let backend = match args.get("backend").and_then(|v| v.as_str()) {
        Some(b) => match BackendKind::from_str(b) {
            Ok(bk) => bk,
            Err(e) => return Response::err(id, jsonrpc::INVALID_PARAMS, e.to_string()),
        },
        None => BackendKind::Namespace,
    };

    let network = args
        .get("network")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let timeout = match args.get("timeout").and_then(|v| v.as_str()) {
        Some(t) => match job::parse_timeout(t) {
            Ok(d) => Some(d),
            Err(e) => return Response::err(id, jsonrpc::INVALID_PARAMS, e.to_string()),
        },
        None => None,
    };

    let no_isolation = backend == BackendKind::Bare;

    let job = JobSpec {
        command,
        inputs: None,
        outputs: None,
        network,
        trace: Default::default(),
        timeout,
        policy: None,
        extra_ro: vec![],
        extra_rw: vec![],
        no_isolation,
        backend,
        interactive: false,
    };

    let client = OaieClient::new(store_path).policy(policy_name);

    match client.run_job(&job) {
        Ok(result) => {
            let content = serde_json::to_value(&result).unwrap_or(Value::Null);
            Response::ok(
                id,
                serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string_pretty(&content).unwrap_or_default()
                    }]
                }),
            )
        }
        Err(e) => Response::err(id, jsonrpc::INTERNAL_ERROR, e.to_string()),
    }
}

/// Handle `oaie_verify` — verify a run's integrity.
fn handle_verify(id: Option<Value>, args: &Value, store_path: &str) -> Response {
    let run_id = match args.get("run_id").and_then(|v| v.as_str()) {
        Some(r) => r,
        None => {
            return Response::err(
                id,
                jsonrpc::INVALID_PARAMS,
                "missing required parameter: run_id",
            );
        }
    };

    let client = OaieClient::new(store_path);

    match client.verify(run_id) {
        Ok(report) => {
            let content = serde_json::to_value(&report).unwrap_or(Value::Null);
            Response::ok(
                id,
                serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string_pretty(&content).unwrap_or_default()
                    }]
                }),
            )
        }
        Err(e) => Response::err(id, jsonrpc::INTERNAL_ERROR, e.to_string()),
    }
}

/// Handle `oaie_read_output` — read an artifact's content.
fn handle_read_output(id: Option<Value>, args: &Value, store_path: &str) -> Response {
    let run_id = match args.get("run_id").and_then(|v| v.as_str()) {
        Some(r) => r,
        None => {
            return Response::err(
                id,
                jsonrpc::INVALID_PARAMS,
                "missing required parameter: run_id",
            );
        }
    };

    let artifact_name = match args.get("artifact_name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => {
            return Response::err(
                id,
                jsonrpc::INVALID_PARAMS,
                "missing required parameter: artifact_name",
            );
        }
    };

    let client = OaieClient::new(store_path);

    match client.read_output(run_id, artifact_name) {
        Ok(bytes) => {
            use serde_json::json;
            // Try to return as text if valid UTF-8, otherwise base64-encode.
            if let Ok(text) = std::str::from_utf8(&bytes) {
                Response::ok(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": text
                        }]
                    }),
                )
            } else {
                let encoded = base64_encode(&bytes);
                Response::ok(
                    id,
                    json!({
                        "content": [{
                            "type": "resource",
                            "resource": {
                                "uri": format!("oaie://{run_id}/{artifact_name}"),
                                "mimeType": "application/octet-stream",
                                "blob": encoded
                            }
                        }]
                    }),
                )
            }
        }
        Err(e) => Response::err(id, jsonrpc::INTERNAL_ERROR, e.to_string()),
    }
}

// ── MCP Session tools (P.1) ──

/// Handle `oaie_session_run` — start a session with an agent command.
///
/// Returns the session ID immediately. The session runs synchronously in this
/// handler (MCP calls are expected to be on separate threads/connections).
fn handle_session_run(id: Option<Value>, args: &Value, store_path: &str) -> Response {
    let command = match args.get("command").and_then(|v| v.as_array()) {
        Some(arr) => {
            let mut cmd = Vec::new();
            for item in arr {
                match item.as_str() {
                    Some(s) => cmd.push(s),
                    None => {
                        return Response::err(
                            id,
                            jsonrpc::INVALID_PARAMS,
                            "command array must contain strings",
                        );
                    }
                }
            }
            if cmd.is_empty() {
                return Response::err(
                    id,
                    jsonrpc::INVALID_PARAMS,
                    "command array must not be empty",
                );
            }
            cmd
        }
        None => {
            return Response::err(
                id,
                jsonrpc::INVALID_PARAMS,
                "missing required parameter: command",
            );
        }
    };

    let policy_name = args.get("policy").and_then(|v| v.as_str());

    let budget = if let Some(budget_obj) = args.get("budget") {
        let max_tool_calls = budget_obj
            .get("max_tool_calls")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .unwrap_or(50);
        let max_wall_time_s = budget_obj
            .get("max_wall_time_s")
            .and_then(|v| v.as_u64())
            .unwrap_or(1800);
        let max_tool_time_s = budget_obj
            .get("max_tool_time_s")
            .and_then(|v| v.as_u64())
            .unwrap_or(600);
        Some(oaie_core::session::SessionBudget {
            max_tool_calls,
            max_wall_time_s,
            max_tool_time_s,
            ..oaie_core::session::SessionBudget::default()
        })
    } else {
        None
    };

    let client = OaieClient::new(store_path);
    match client.session_run(&command, budget, policy_name) {
        Ok(session_id) => Response::ok(
            id,
            serde_json::json!({
                "content": [{
                    "type": "text",
                    "text": serde_json::json!({
                        "session_id": session_id,
                        "status": "completed"
                    }).to_string()
                }]
            }),
        ),
        Err(e) => Response::err(id, jsonrpc::INTERNAL_ERROR, e.to_string()),
    }
}

/// Handle `oaie_session_status` — query session state and budget.
fn handle_session_status(id: Option<Value>, args: &Value, store_path: &str) -> Response {
    let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return Response::err(
                id,
                jsonrpc::INVALID_PARAMS,
                "missing required parameter: session_id",
            );
        }
    };

    let client = OaieClient::new(store_path);
    match client.session_status(session_id) {
        Ok(info) => {
            let content = serde_json::to_value(&info).unwrap_or(Value::Null);
            Response::ok(
                id,
                serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string_pretty(&content).unwrap_or_default()
                    }]
                }),
            )
        }
        Err(e) => Response::err(id, jsonrpc::INTERNAL_ERROR, e.to_string()),
    }
}

/// Handle `oaie_session_stop` — stop a running session.
fn handle_session_stop(id: Option<Value>, args: &Value, store_path: &str) -> Response {
    let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return Response::err(
                id,
                jsonrpc::INVALID_PARAMS,
                "missing required parameter: session_id",
            );
        }
    };

    let client = OaieClient::new(store_path);
    match client.session_stop(session_id) {
        Ok(()) => Response::ok(
            id,
            serde_json::json!({
                "content": [{
                    "type": "text",
                    "text": serde_json::json!({
                        "session_id": session_id,
                        "status": "stopped"
                    }).to_string()
                }]
            }),
        ),
        Err(e) => Response::err(id, jsonrpc::INTERNAL_ERROR, e.to_string()),
    }
}

/// Minimal base64 encoder (RFC 4648, with padding).
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}
