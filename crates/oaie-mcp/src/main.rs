//! OAIE MCP Server — JSON-RPC 2.0 over stdin/stdout.
//!
//! Implements the Model Context Protocol (MCP) for AI agent integration.
//! Three tools: `oaie_run`, `oaie_verify`, `oaie_read_output`.
//!
//! Usage: `oaie-mcp` (reads JSON-RPC from stdin, writes responses to stdout)
//!
//! The store path is resolved from `OAIE_HOME` or defaults to `~/.oaie`.

use std::io::{self, BufRead, Read, Write};

use serde_json::Value;

use oaie_mcp::jsonrpc::{self, Request, Response};
use oaie_mcp::tools;

/// Maximum line length accepted from stdin (1 MiB).  Prevents a malicious
/// or buggy client from sending an unbounded JSON line and exhausting memory.
const MAX_LINE_BYTES: usize = 1024 * 1024;

fn main() {
    // Resolve store path from environment (same logic as oaie CLI).
    let store_path = resolve_store_path();

    // Per-connection authorization state. MCP-over-stdio is one process
    // per client connection (the client spawns this binary, talks to
    // its stdin); when stdin closes, this process exits and the state
    // dies with it. So `&mut` through the loop is per-connection
    // without any explicit connection tracking. See McpState's doc
    // comment for what this gates (read_output/verify run_id origin).
    let mut state = tools::McpState::default();

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout_lock = stdout.lock();

    // Wrap stdin in a Take adapter so read_line is bounded BEFORE allocation.
    // BufReader over Take ensures the internal buffer never exceeds the limit.
    let limited = stdin.lock().take((MAX_LINE_BYTES + 1) as u64);
    let mut reader = io::BufReader::new(limited);
    let mut buf = String::new();

    loop {
        buf.clear();
        // Reset the Take limit for each line — the adapter counts bytes read.
        reader.get_mut().set_limit((MAX_LINE_BYTES + 1) as u64);

        match reader.read_line(&mut buf) {
            Ok(0) => break, // EOF
            Ok(n) if n > MAX_LINE_BYTES => {
                // Drain remaining bytes of this oversized line so the next
                // read_line starts at a fresh line boundary.  The Take limit
                // is exhausted at this point, so we must reset it before
                // draining.  Use read_line through BufReader (not get_mut)
                // so any data already in BufReader's internal buffer is also
                // consumed.
                buf.clear();
                loop {
                    // Keep the Take cap in place while draining so each chunk
                    // is bounded; never call read_line with the limit lifted.
                    reader.get_mut().set_limit((MAX_LINE_BYTES + 1) as u64);
                    match reader.read_line(&mut buf) {
                        Ok(0) | Err(_) => break,
                        // Found the line terminator — remainder consumed.
                        Ok(_) if buf.ends_with('\n') => break,
                        // Still more data without newline — keep draining.
                        Ok(_) => { buf.clear(); continue; }
                    }
                }
                let resp = Response::err(
                    None,
                    -32700,
                    format!("request too large ({n} bytes, max {MAX_LINE_BYTES})"),
                );
                if !write_response(&mut stdout_lock, &resp) {
                    break;
                }
                continue;
            }
            Ok(_) => {}
            Err(_) => break,
        }

        let line = buf.trim();
        if line.is_empty() {
            continue;
        }

        let request: Request = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response::err(
                    None,
                    -32700, // Parse error
                    format!("invalid JSON: {e}"),
                );
                if !write_response(&mut stdout_lock, &resp) {
                    break;
                }
                continue;
            }
        };

        // Validate JSON-RPC version per spec.
        if request.jsonrpc != "2.0" {
            let resp = Response::err(
                request.id.clone(),
                -32600, // Invalid Request
                format!("unsupported jsonrpc version: {:?}", request.jsonrpc),
            );
            if !write_response(&mut stdout_lock, &resp) {
                break;
            }
            continue;
        }

        let response = handle_request(&request, &store_path, &mut state);

        // Notifications (no id) don't get a response.
        if let Some(resp) = response {
            if !write_response(&mut stdout_lock, &resp) {
                break;
            }
        }
    }
}

/// Handle a single JSON-RPC request and return the response (if any).
///
/// Returns `None` for notifications (requests without an id).
fn handle_request(
    req: &Request,
    store_path: &str,
    state: &mut tools::McpState,
) -> Option<Response> {
    match req.method.as_str() {
        "initialize" => Some(Response::ok(
            req.id.clone(),
            jsonrpc::initialize_result(),
        )),

        "notifications/initialized" => {
            // Notification — no response.
            None
        }

        "tools/list" => Some(Response::ok(req.id.clone(), jsonrpc::tools_list())),

        "tools/call" => {
            let tool_name = req
                .params
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let arguments = req
                .params
                .get("arguments")
                .cloned()
                .unwrap_or(Value::Object(serde_json::Map::new()));

            Some(tools::handle_tool_call(
                req.id.clone(),
                tool_name,
                &arguments,
                store_path,
                state,
            ))
        }

        _ => {
            if req.id.is_some() {
                Some(Response::err(
                    req.id.clone(),
                    jsonrpc::METHOD_NOT_FOUND,
                    format!("unknown method: {}", req.method),
                ))
            } else {
                // Unknown notification — ignore per JSON-RPC spec.
                None
            }
        }
    }
}

/// Write a JSON-RPC response as a single line to stdout.
///
/// Returns `false` if the write fails (broken pipe), signalling the main
/// loop to exit cleanly instead of spinning on a dead stdout.
fn write_response(out: &mut impl Write, resp: &Response) -> bool {
    let json = match serde_json::to_string(resp) {
        Ok(j) => j,
        Err(_) => return true, // serialization error — skip, don't kill server
    };
    if writeln!(out, "{json}").is_err() || out.flush().is_err() {
        return false; // broken pipe — caller should exit
    }
    true
}

/// Resolve the OAIE store path from environment.
fn resolve_store_path() -> String {
    if let Ok(path) = std::env::var("OAIE_HOME") {
        return path;
    }
    if let Ok(home) = std::env::var("HOME") {
        return format!("{home}/.oaie");
    }
    // Fallback — will fail at runtime when the store is opened.
    ".oaie".into()
}
