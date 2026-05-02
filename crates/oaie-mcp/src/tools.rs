//! MCP tool handlers — dispatch `tools/call` requests to `OaieClient` methods.

use std::collections::HashSet;
use std::str::FromStr;

use serde_json::Value;

use oaie_agent::OaieClient;
use oaie_core::backend::BackendKind;
use oaie_core::job::{self, JobSpec};

use crate::jsonrpc::{self, Response};

/// Per-connection state: which run_ids THIS MCP server process created.
///
/// The store at `~/.oaie` is shared between this MCP server and the
/// operator's CLI (`oaie run`, `oaie session run`). `handle_run` already
/// restricts the MCP caller to a hardened policy subset
/// (MCP_ALLOWED_POLICIES, no Bare backend, network=false hardcoded) —
/// the MCP stdin caller is treated as less trusted than the operator.
/// `handle_read_output` and `handle_verify` need an equivalent gate:
/// without one, any run_id the LLM supplies hits the shared DB and
/// returns the operator's blob (build output, API tokens on stderr,
/// etc.). The "last" alias and prefix queries are particularly
/// dangerous since they have no origin filter at the store layer.
///
/// This set tracks run_ids that `handle_run` inserted on success.
/// `handle_read_output` and `handle_verify` check membership before
/// touching the DB. The "last" alias is rejected outright; explicit
/// run_ids that aren't in the set get a clear "not created by this MCP
/// connection" error.
///
/// MCP-over-stdio is one process per connection, so this set is
/// per-connection without extra plumbing — `&mut` from the request loop,
/// no Mutex (single-threaded), no persistence. A new MCP connection
/// shouldn't inherit a previous one's runs any more than it should
/// inherit the operator's.
///
/// Sessions are a separate axis: there is no MCP tool that creates a
/// session (sessions are operator-CLI only), so the MCP caller has no
/// session it could legitimately stop. `oaie_session_stop` is therefore
/// not exposed via MCP at all — see the dispatch below.
/// `oaie_session_status` is read-only and stays available.
#[derive(Default)]
pub struct McpState {
    /// run_ids returned by handle_run on this connection. Membership
    /// gates handle_read_output and handle_verify. HashSet not Vec —
    /// the "is this run_id one of ours" check is the hot path,
    /// connections can be long-lived (an agent might do hundreds of
    /// runs), and the IDs are 36-char UUID strings.
    pub created_runs: HashSet<String>,
}

/// Dispatch a `tools/call` request to the appropriate handler.
///
/// `state` is per-connection — main.rs holds it across the request loop.
pub fn handle_tool_call(id: Option<Value>, tool_name: &str, arguments: &Value, store_path: &str, state: &mut McpState) -> Response {
    match tool_name {
        "oaie_run" => handle_run(id, arguments, store_path, state),
        "oaie_verify" => handle_verify(id, arguments, store_path, state),
        "oaie_read_output" => handle_read_output(id, arguments, store_path, state),
        "oaie_session_status" => handle_session_status(id, arguments, store_path),
        // No MCP tool creates sessions, so the MCP caller has no session
        // it could legitimately stop. Return METHOD_NOT_FOUND (rather
        // than a softer "not permitted") so spec-compliant clients see
        // the tool as nonexistent and don't retry. Operators still have
        // `oaie session stop` on the CLI.
        "oaie_session_stop" => Response::err(
            id,
            jsonrpc::METHOD_NOT_FOUND,
            "oaie_session_stop is not available via MCP. Sessions are \
             operator-CLI-managed; the MCP caller has no session it \
             could have started. Use `oaie session stop` on the host.",
        ),
        _ => Response::err(id, jsonrpc::METHOD_NOT_FOUND, format!("unknown tool: {tool_name}")),
    }
}

/// Membership check shared by handle_read_output and handle_verify.
/// Returns Ok(()) if `run_id` was created by this connection's
/// handle_run; Err(Response) with the right error otherwise.
///
/// "last" is rejected outright — it's `ORDER BY created DESC LIMIT 1`
/// in the DB with no origin filter, so it's "the operator's most
/// recent run" by definition. There's no safe way to alias it.
///
/// Prefix matching (the LLM passes the first 8 chars of a UUID) goes
/// through the same set check: if "01ab2c3d" isn't in the set, it
/// doesn't matter that "01ab2c3d-4e5f-..." might be a valid run in the
/// DB — it's not THIS connection's run. The store's prefix-expansion
/// path never gets called, so its ambiguous-match leak (returns prefix+4
/// of every match) never fires. The MCP caller has to use exact run_ids
/// — which it has, because handle_run returned them.
fn check_run_origin(id: &Option<Value>, run_id: &str, state: &McpState) -> Result<(), Box<Response>> {
    if run_id == "last" {
        return Err(Box::new(Response::err(
            id.clone(),
            jsonrpc::INVALID_PARAMS,
            "run_id='last' is not available via MCP — it resolves to the \
             store's most recent run regardless of origin, which is the \
             operator's CLI run, not yours. Use the explicit run_id that \
             oaie_run returned.",
        )));
    }
    if !state.created_runs.contains(run_id) {
        return Err(Box::new(Response::err(
            id.clone(),
            jsonrpc::INVALID_PARAMS,
            format!(
                "run_id {run_id:?} was not created by this MCP connection. \
                 oaie_read_output and oaie_verify only accept run_ids that \
                 a previous oaie_run on THIS connection returned. The store \
                 is shared with the operator's CLI; reading their runs is \
                 the leak this gate exists to close."
            ),
        )));
    }
    Ok(())
}

/// Handle `oaie_run` — execute a command in the sandbox.
fn handle_run(id: Option<Value>, args: &Value, store_path: &str, state: &mut McpState) -> Response {
    let command = match args.get("command").and_then(|v| v.as_array()) {
        Some(arr) => {
            let mut cmd = Vec::new();
            for item in arr {
                match item.as_str() {
                    Some(s) => cmd.push(s.to_string()),
                    None => {
                        return Response::err(id, jsonrpc::INVALID_PARAMS, "command array must contain strings");
                    }
                }
            }
            if cmd.is_empty() {
                return Response::err(id, jsonrpc::INVALID_PARAMS, "command array must not be empty");
            }
            cmd
        }
        None => {
            return Response::err(id, jsonrpc::INVALID_PARAMS, "missing required parameter: command");
        }
    };

    let policy_name = args.get("policy").and_then(|v| v.as_str()).unwrap_or("agent-safe");
    // MCP-specific allowlist: only the agent-* presets are permitted from an
    // untrusted caller. Policy::from_name() accepts a wider set (net, llm,
    // contained-*, ...) intended for the operator-driven CLI, not this
    // boundary.
    const MCP_ALLOWED_POLICIES: &[&str] = &["agent-safe", "agent-net", "agent-build", "agent-analyze"];
    if !MCP_ALLOWED_POLICIES.contains(&policy_name) {
        return Response::err(id, jsonrpc::INVALID_PARAMS, format!("policy must be one of {MCP_ALLOWED_POLICIES:?}, got: {policy_name:?}"));
    }

    let backend = match args.get("backend").and_then(|v| v.as_str()) {
        Some(b) => match BackendKind::from_str(b) {
            Ok(BackendKind::Bare) => {
                return Response::err(id, jsonrpc::INVALID_PARAMS, "backend 'bare' is not permitted via MCP");
            }
            Ok(bk) => bk,
            Err(e) => return Response::err(id, jsonrpc::INVALID_PARAMS, e.to_string()),
        },
        None => BackendKind::Namespace,
    };

    // Network mode comes from the policy preset, not AI-agent JSON.
    let network = false;

    let timeout = match args.get("timeout").and_then(|v| v.as_str()) {
        Some(t) => match job::parse_timeout(t) {
            Ok(d) => Some(d),
            Err(e) => return Response::err(id, jsonrpc::INVALID_PARAMS, e.to_string()),
        },
        None => None,
    };

    // MCP never disables isolation; BackendKind::Bare is rejected above.
    let no_isolation = false;

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
            // Record the run_id so handle_read_output / handle_verify
            // accept it. This is the ONLY insert path — runs the
            // operator started via CLI are never in this set, which is
            // the point. Cloned because StructuredRunResult.run_id is
            // owned by `result` and we're about to serialize+drop it.
            state.created_runs.insert(result.run_id.clone());
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
fn handle_verify(id: Option<Value>, args: &Value, store_path: &str, state: &McpState) -> Response {
    let run_id = match args.get("run_id").and_then(|v| v.as_str()) {
        Some(r) => r,
        None => {
            return Response::err(id, jsonrpc::INVALID_PARAMS, "missing required parameter: run_id");
        }
    };

    // Same origin gate as handle_read_output. verify() reads the
    // manifest + artifact blobs — same shared-store leak as
    // read_output, just structured instead of raw. The verify report
    // includes artifact hashes, sizes, and the full isolation block
    // (which kernel, which namespaces, which policy) — all of which
    // describe an operator-CLI run if the run_id wasn't ours.
    if let Err(resp) = check_run_origin(&id, run_id, state) {
        return *resp;
    }

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
fn handle_read_output(id: Option<Value>, args: &Value, store_path: &str, state: &McpState) -> Response {
    let run_id = match args.get("run_id").and_then(|v| v.as_str()) {
        Some(r) => r,
        None => {
            return Response::err(id, jsonrpc::INVALID_PARAMS, "missing required parameter: run_id");
        }
    };

    // The whole reason McpState exists. See its doc comment for the
    // attack chain — short version: `{"run_id":"last","artifact_name":
    // "stderr"}` reads the operator's most recent CLI run's stderr,
    // which on a build run is API tokens. This gate fires BEFORE the
    // DB query so client.read_output's prefix-expansion (which leaks
    // partial UUIDs in the ambiguous-match error) never sees a run_id
    // that isn't ours.
    if let Err(resp) = check_run_origin(&id, run_id, state) {
        return *resp;
    }

    let artifact_name = match args.get("artifact_name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => {
            return Response::err(id, jsonrpc::INVALID_PARAMS, "missing required parameter: artifact_name");
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
#[allow(dead_code)]
fn handle_session_run(id: Option<Value>, args: &Value, store_path: &str) -> Response {
    let command = match args.get("command").and_then(|v| v.as_array()) {
        Some(arr) => {
            let mut cmd = Vec::new();
            for item in arr {
                match item.as_str() {
                    Some(s) => cmd.push(s),
                    None => {
                        return Response::err(id, jsonrpc::INVALID_PARAMS, "command array must contain strings");
                    }
                }
            }
            if cmd.is_empty() {
                return Response::err(id, jsonrpc::INVALID_PARAMS, "command array must not be empty");
            }
            cmd
        }
        None => {
            return Response::err(id, jsonrpc::INVALID_PARAMS, "missing required parameter: command");
        }
    };

    let policy_name = args.get("policy").and_then(|v| v.as_str());

    let budget = if let Some(budget_obj) = args.get("budget") {
        let max_tool_calls = budget_obj.get("max_tool_calls").and_then(|v| v.as_u64()).map(|v| v as u32).unwrap_or(50);
        let max_wall_time_s = budget_obj.get("max_wall_time_s").and_then(|v| v.as_u64()).unwrap_or(1800);
        let max_tool_time_s = budget_obj.get("max_tool_time_s").and_then(|v| v.as_u64()).unwrap_or(600);
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
            return Response::err(id, jsonrpc::INVALID_PARAMS, "missing required parameter: session_id");
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
