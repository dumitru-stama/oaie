//! Minimal JSON-RPC 2.0 handler for the MCP protocol.
//!
//! Hand-rolled (~200 lines) — no external MCP SDK dependency. Handles:
//! - `initialize` → server capabilities
//! - `notifications/initialized` → ack (no response)
//! - `tools/list` → tool schemas
//! - `tools/call` → dispatch to tool handlers

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A JSON-RPC 2.0 request.
#[derive(Debug, Deserialize)]
pub struct Request {
    /// Protocol version marker — always "2.0". Deserialized for validation,
    /// not directly read by application code.
    #[allow(dead_code)]
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// A JSON-RPC 2.0 response.
#[derive(Debug, Serialize)]
pub struct Response {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Serialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl Response {
    /// Construct a success response.
    pub fn ok(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Construct an error response.
    pub fn err(id: Option<Value>, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

/// Standard JSON-RPC error codes.
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;

/// MCP server info returned in the initialize response.
pub fn initialize_result() -> Value {
    serde_json::json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": "oaie-mcp",
            "version": env!("CARGO_PKG_VERSION")
        }
    })
}

/// Tool schemas for the `tools/list` response.
pub fn tools_list() -> Value {
    serde_json::json!({
        "tools": [
            {
                "name": "oaie_run",
                "description": "Run a command in an isolated, observed sandbox. Returns structured results including exit code, duration, artifact hashes, and optional trace summary.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Command and arguments to execute"
                        },
                        "policy": {
                            "type": "string",
                            "description": "Policy preset name (agent-safe, agent-net, agent-build, agent-analyze) or path to policy TOML file. Default: agent-safe"
                        },
                        "backend": {
                            "type": "string",
                            "enum": ["namespace", "bare", "firecracker"],
                            "description": "Execution backend. Default: namespace"
                        },
                        "timeout": {
                            "type": "string",
                            "description": "Timeout (e.g. '30s', '5m'). Overrides policy default"
                        },
                        "network": {
                            "type": "boolean",
                            "description": "Allow network access. Default: false"
                        }
                    },
                    "required": ["command"]
                }
            },
            {
                "name": "oaie_verify",
                "description": "Verify the integrity of a previous run's artifacts and hash chain.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "run_id": {
                            "type": "string",
                            "description": "Run ID, short prefix, or 'last'"
                        }
                    },
                    "required": ["run_id"]
                }
            },
            {
                "name": "oaie_read_output",
                "description": "Read an output artifact from a previous run. Returns base64-encoded content.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "run_id": {
                            "type": "string",
                            "description": "Run ID, short prefix, or 'last'"
                        },
                        "artifact_name": {
                            "type": "string",
                            "description": "Artifact label: stdout, stderr, output/file.txt, etc."
                        }
                    },
                    "required": ["run_id", "artifact_name"]
                }
            }
        ]
    })
}
