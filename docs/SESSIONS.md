# OAIE Session Mode

Session mode provides persistent agent sandboxes with tool dispatch. An agent
process runs inside a long-lived environment and dispatches tool calls to the
OAIE supervisor over a Unix domain socket. Each tool call becomes a standard
OAIE run with its own sandbox, manifest, and database record.

## Lifecycle States

Sessions follow a deterministic state machine:

```
                  ┌──────────┐
                  │ Starting │
                  └────┬─────┘
                       │  agent process launched
                       v
                  ┌──────────┐
            ┌─────│ Running  │─────┐
            │     └────┬─────┘     │
            │          │           │
     wall timeout   stop cmd   budget limit
            │          │           │
            v          v           v
     ┌───────────┐ ┌─────────┐ ┌──────────────────┐
     │ TimedOut   │ │Stopping │ │ BudgetExhausted  │
     └───────────┘ └────┬────┘ └──────────────────┘
                        │
                   agent exits
                        │
                        v
                   ┌─────────┐
                   │ Stopped │
                   └─────────┘
```

- **Starting**: Sandbox and dispatch socket are being created.
- **Running**: Agent process is live. Dispatch loop accepts tool calls.
- **Stopping**: SIGTERM sent to agent. Waiting for graceful exit.
- **Stopped**: Agent exited normally or was stopped via `oaie session stop`.
- **TimedOut**: Wall-clock time exceeded `max_wall_time_s`.
- **BudgetExhausted**: One or more budget limits reached.

## Quick Start

```bash
# Initialize an OAIE store (one-time)
oaie init ~/.oaie

# Run an agent in a session with the "local" containment profile
oaie session run --contained=local -- python3 my_agent.py

# Run with explicit budget overrides
oaie session run \
  --budget-tool-calls=200 \
  --budget-wall-time=2h \
  -- ./my_agent

# Run with cloud profile and LLM provider metadata
oaie session run --contained=cloud --llm=anthropic -- ./claude_agent

# Interactive session with human-in-the-loop approval
oaie session run --contained=interactive --require-approval -- ./agent.sh

# Agent sandboxed alongside its tools
oaie session run --contained=cloud --sandbox-agent --llm=openai -- ./gpt_agent
```

## Dispatch Protocol

The agent communicates with the OAIE supervisor through a Unix domain socket
using JSON newline-delimited messages.

### Environment Variables

The session runner injects three environment variables into the agent process:

| Variable | Description | Example |
|---|---|---|
| `OAIE_DISPATCH_SOCK` | Path to the Unix domain socket | `/tmp/oaie-session-xyz/dispatch.sock` |
| `OAIE_SESSION_ID` | UUIDv7 session identifier | `019cb6a3-1234-7abc-...` |
| `OAIE_ARTIFACTS_DIR` | Shared directory for tool outputs | `/tmp/oaie-session-xyz/artifacts/` |

### Request Format

```json
{
  "id": "call-001",
  "command": ["grep", "-r", "TODO", "/in/src/"],
  "inputs": {"data": "/artifacts/input.txt"},
  "timeout_s": 30
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Unique call identifier (assigned by the agent) |
| `command` | string[] | yes | Command argv to execute |
| `inputs` | map<string,string> | no | Input artifacts: label to path (path traversal rejected) |
| `timeout_s` | u64 | no | Per-call timeout override (capped by session budget) |

### Response Format

```json
{
  "id": "call-001",
  "run_id": "019cb6a3-5678-7def-...",
  "exit_code": 0,
  "outputs": [
    {"path": "stdout.txt", "hash": "ab3f...", "size": 1024}
  ],
  "duration_ms": 234,
  "error": null
}
```

| Field | Type | Description |
|---|---|---|
| `id` | string | Matches the request `id` |
| `run_id` | string | OAIE run ID for this tool call |
| `exit_code` | i32 | Tool process exit code |
| `outputs` | OutputEntry[] | Artifacts produced (path, hash, size) |
| `duration_ms` | u64 | Wall-clock duration of the tool call |
| `error` | string? | Error message if dispatch was rejected |

### Wire Message Envelope (Sandboxed Agent)

When the agent runs in sandbox mode (`--sandbox-agent`), all communication uses
the `WireMessage` envelope for typed I/O mediation:

```json
{"msg_type": "dispatch_request", "id": "call-001", "command": ["echo", "hi"], ...}
{"msg_type": "dispatch_response", "id": "call-001", "exit_code": 0, ...}
{"msg_type": "agent_output", "channel": "stdout", "text": "Thinking...\n"}
{"msg_type": "user_input", "text": "yes\n"}
```

## Budget System

Every session has a `SessionBudget` that limits resource consumption.

| Field | Type | Default | Description |
|---|---|---|---|
| `max_tool_calls` | u32 | 50 | Maximum number of dispatched tool calls |
| `max_wall_time_s` | u64 | 1800 (30m) | Maximum session wall-clock time |
| `max_tool_time_s` | u64 | 600 (10m) | Maximum cumulative tool execution time |
| `max_output_bytes` | u64 | 1 GiB | Maximum cumulative output bytes |
| `max_network_bytes` | u64 | 0 (unlimited) | Maximum cumulative network bytes (nftables) |

### Budget Warnings and Exhaustion

At **80% usage** of any budget field, a `BudgetWarning` event is emitted to the
session event log. When any limit is reached, the dispatch is rejected, a
`BudgetExhausted` event is recorded, and the session transitions to the
`BudgetExhausted` state.

### Mid-Session Budget Extension

A budget-exhausted session can be revived via `oaie session extend`:

```bash
# Add 50 more tool calls and 30 minutes of wall time
oaie session extend <session-id> --add-tool-calls=50 --add-wall-time=30m
```

The extension is communicated via file signaling (`budget_extension.json` in the
session directory). A `BudgetExtension` event records the old and new limits.

## Heartbeat

The heartbeat mechanism detects agent crashes or hangs. When
`heartbeat_interval_s` is set (non-zero), the supervisor monitors the time
since the last dispatch activity. If the interval elapses with no tool calls,
a `HeartbeatTimeout` event is recorded and the session is stopped.

```bash
oaie session run --heartbeat=60 -- ./agent  # 60s heartbeat interval
```

## Event Log

Every session produces a hash-chained NDJSON event log stored in CAS. Each
event links to the previous via a `prev_hash` field, creating a tamper-evident
chain identical in structure to trace event chains.

### Event Types

| Event | Description |
|---|---|
| `SessionStart` | Session started (includes agent command) |
| `SessionStop` | Session stopped (includes final state) |
| `ToolDispatch` | Tool call dispatched (call_id, command) |
| `ToolResult` | Tool call completed (run_id, exit_code, trace_hash) |
| `BudgetWarning` | 80% of a budget limit reached |
| `BudgetExhausted` | Budget limit hit |
| `BudgetExtension` | Budget extended mid-session |
| `HeartbeatTimeout` | No activity within heartbeat interval |
| `ResourceSnapshot` | Periodic usage snapshot (every 30s) |
| `ToolDenied` | Tool call blocked by filter |
| `AgentOutput` | Agent stdout/stderr chunk (sandboxed mode) |
| `ApprovalRequired` | Tool call awaited human approval |

### Event Structure

```json
{
  "seq": 0,
  "timestamp": "2026-03-04T10:15:30Z",
  "kind": {"type": "session_start", "command": ["python3", "agent.py"]},
  "prev_hash": "genesis:blake3:session"
}
```

## Session Manifest

Each session produces a `session_manifest.toml` in the session directory,
stored in CAS alongside the event log. The manifest records:

- Session ID, state, and timestamps
- Budget configuration and final usage
- Containment profile and LLM provider metadata
- Event log hash and chain tip for verification
- Complete call history with run IDs

## CLI Commands

| Command | Description |
|---|---|
| `oaie session run` | Start a new session with an agent command |
| `oaie session list` | List all sessions (with state, tool calls, timestamps) |
| `oaie session status <id>` | Show detailed status of a session |
| `oaie session stop <id>` | Gracefully stop a running session |
| `oaie session inspect <id>` | Show session manifest and call history |
| `oaie session log <id>` | View raw event log (with `--type` filter) |
| `oaie session extend <id>` | Extend budget of a running/exhausted session |
| `oaie session attach <id>` | nsenter into a sandboxed session's namespace |
| `oaie session profiles` | List available containment profiles |

### Filtering Session Logs

```bash
# Show only tool dispatch and result events
oaie session log <id> --type=tool_dispatch,tool_result

# Show budget-related events
oaie session log <id> --type=budget_warning,budget_exhausted,budget_extension
```

## MCP Integration

The OAIE MCP server exposes session tools via JSON-RPC 2.0:

| MCP Tool | Description |
|---|---|
| `oaie_session_run` | Start a new session (returns session ID) |
| `oaie_session_status` | Query session state and usage |
| `oaie_session_stop` | Stop a running session |

These complement the existing `oaie_run`, `oaie_verify`, and `oaie_read_output`
tools, allowing AI agents to manage sessions through the MCP protocol.

## SessionClient Library

The `oaie-agent` crate provides `SessionClient` for agents running inside
sessions. It reads connection details from environment variables and provides
a typed Rust API for the dispatch protocol.

```rust
use oaie_agent::SessionClient;

// Create client from env vars (OAIE_DISPATCH_SOCK, OAIE_SESSION_ID, OAIE_ARTIFACTS_DIR)
let client = SessionClient::from_env()?;

// Simple tool dispatch
let response = client.dispatch("grep", &["-r", "TODO", "/in/src/"])?;
assert_eq!(response.exit_code, 0);

// Dispatch with input artifacts
let mut inputs = std::collections::HashMap::new();
inputs.insert("data".into(), "/artifacts/input.txt".into());
let response = client.dispatch_with_inputs("python3", &["process.py"], inputs)?;

// Access session metadata
println!("Session: {}", client.session_id());
println!("Artifacts: {}", client.artifacts_dir().display());
```

### OaieClient Session Methods

The `OaieClient` also provides session management from the host side:

```rust
use oaie_agent::OaieClient;

let client = OaieClient::new("/home/user/.oaie");

// Start a session (returns session ID)
// let session_id = client.session_run(&["python3", "agent.py"], config)?;

// Check session status
// let status = client.session_status(&session_id)?;

// Stop a session
// client.session_stop(&session_id)?;
```
