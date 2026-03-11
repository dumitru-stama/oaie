# OAIE Containment Profiles

Containment profiles bundle a per-tool sandbox policy with a session-level
resource budget into a single `--contained=<profile>` flag. They provide
ergonomic defaults for common agent deployment scenarios.

## Overview

When running a session, the containment profile determines:

1. **Session budget** -- how many tool calls, how much time, and how many bytes
   the session as a whole may consume.
2. **Per-tool sandbox policy** -- memory, time, PID, and network limits for each
   individual tool execution within the session.
3. **Agent network access** -- whether the agent process itself can reach the
   network (relevant when `--sandbox-agent` is used).

Tools never get network access under any containment profile. The agent process
handles LLM API calls directly, either on the host (default) or through
narrowed allowlists (when sandboxed).

## Profile Comparison Table

### Session-Level Budget

| Field | `local` | `cloud` | `strict` | `interactive` |
|---|---|---|---|---|
| **max_tool_calls** | 100 | 50 | 20 | 200 |
| **max_wall_time_s** | 3600 (1h) | 1800 (30m) | 600 (10m) | 7200 (2h) |
| **max_tool_time_s** | 1800 (30m) | 600 (10m) | 300 (5m) | 3600 (1h) |
| **max_output_bytes** | 2 GiB | 1 GiB | 256 MiB | 2 GiB |
| **Use case** | Local LLM agents | Cloud API agents | Minimal trust | Human-in-the-loop |

### Per-Tool Sandbox Policy

| Field | `local` | `cloud` | `strict` | `interactive` |
|---|---|---|---|---|
| **Policy preset** | contained-local | contained-cloud | contained-strict | contained-interactive |
| **Network** | Off | Off | Off | Off |
| **max_memory** | 1G | 512M | 128M | 1G |
| **max_time** | 10m | 5m | 1m | 10m |
| **max_pids** | 128 | 64 | 32 | 128 |
| **max_fsize** | 1G | 256M | 256M | 1G |
| **allow_memfd** | yes | no | no | yes |

### Agent Network (with --sandbox-agent)

| Profile | Agent network | Narrowed by --llm | Description |
|---|---|---|---|
| `local` | Off | n/a | Agent calls local LLM, no network needed |
| `cloud` | On | Yes (per provider) | Agent calls cloud API |
| `strict` | Off | n/a | No network for anything |
| `interactive` | On | Yes (per provider) | Agent calls cloud API |

## Choosing a Profile

### local

For agents powered by local LLMs (ollama, llama.cpp, vLLM). The agent process
runs on the host and calls the local inference server directly. Tools run
without network access. Generous budget accommodates iterative local model
behavior (local models tend to need more tool calls).

```bash
oaie session run --contained=local -- python3 local_agent.py
```

### cloud

For agents calling cloud LLM APIs (Claude, GPT, Gemini). Moderate budget
suitable for cloud models that are typically more efficient per call. Tools
run without network; the agent handles API calls on the host.

```bash
oaie session run --contained=cloud --llm=anthropic -- ./claude_agent
```

### strict

Maximum restriction for untrusted or experimental agents. Tight per-tool
limits (128M memory, 1 minute timeout, 32 PIDs) and small session budget
(20 calls, 10 minutes). Use when you want to minimize blast radius.

```bash
oaie session run --contained=strict -- ./untrusted_agent
```

### interactive

For human-in-the-loop sessions where an operator is actively monitoring.
Generous budget (200 calls, 2 hours) because the human provides oversight.
Pairs well with `--require-approval` for explicit tool-call gating.

```bash
oaie session run --contained=interactive --require-approval -- ./agent
```

## Agent Containment

By default, the agent process runs directly on the host. Only tool calls
are sandboxed. The `--sandbox-agent` flag places the agent itself inside a
namespace sandbox with mediated I/O.

```bash
# Agent runs on host (default) -- tools sandboxed
oaie session run --contained=cloud -- ./agent

# Agent AND tools sandboxed
oaie session run --contained=cloud --sandbox-agent --llm=openai -- ./agent
```

When `--sandbox-agent` is active:

- The agent runs inside a namespace sandbox (user ns, mount ns, PID ns)
- The dispatch socket is bind-mounted into the sandbox
- The artifacts directory is bind-mounted read-write
- Agent I/O is mediated through the `WireMessage` envelope
- Network access for the agent is controlled by the profile's
  `agent_network_mode()` (Off for local/strict, On for cloud/interactive)

### Per-Provider Network Narrowing

When `--llm=<provider>` is specified alongside `--sandbox-agent`, the agent's
network is narrowed to only that provider's API endpoint:

| Provider | Allowed endpoint |
|---|---|
| `anthropic` | `api.anthropic.com:443/tcp` |
| `openai` | `api.openai.com:443/tcp` |
| `google` | `generativelanguage.googleapis.com:443/tcp` |
| `local` | No network (agent calls local LLM) |
| `custom` | Profile default (no narrowing) |

```bash
# Agent can ONLY reach api.anthropic.com:443
oaie session run --contained=cloud --sandbox-agent --llm=anthropic -- ./agent
```

## Tool Containment

Each dispatched tool call runs in its own isolated sandbox with the profile's
per-tool policy. The sandbox provides:

- Namespace isolation (user, mount, PID, IPC, UTS, optionally net)
- seccomp BPF syscall filtering
- Landlock filesystem restrictions
- Cgroup v2 resource limits (when available)
- Capability dropping (all caps dropped by default)

## Approval Gates

The `--require-approval` flag gates every tool call behind human approval.
The supervisor pauses dispatch, displays the command, and waits for the
operator to approve or deny.

```bash
oaie session run --contained=cloud --require-approval -- ./agent
```

Each approval decision is recorded as an `ApprovalRequired` event in the
session event log with the `approved` boolean field.

## Tool Filtering

Fine-grained control over which tools the agent may dispatch:

```bash
# Only allow specific tools
oaie session run --allow-tools='gcc,make,python3' -- ./build_agent

# Block dangerous tools (deny takes precedence over allow)
oaie session run --deny-tools='rm,curl,wget' -- ./agent

# Deny network for specific tools (others follow profile default)
oaie session run --deny-net-tools='curl,wget' --contained=cloud -- ./agent
```

Tool patterns support simple glob matching on the command basename:

| Pattern | Matches |
|---|---|
| `gcc` | Exact match: `gcc` |
| `python*` | `python3`, `python3.11`, `python` |
| `*` | Everything |

Deny always takes precedence over allow. If the allow list is non-empty, only
matching commands are permitted. An empty allow list permits everything not
denied.

## Budget Overrides

Individual budget fields can be overridden on top of a containment profile:

```bash
# Use cloud profile but extend wall time to 1 hour
oaie session run --contained=cloud --budget-wall-time=1h -- ./agent

# Use strict profile but allow 50 tool calls instead of 20
oaie session run --contained=strict --budget-tool-calls=50 -- ./agent
```

The `--contained` flag is mutually exclusive with `--policy` (which specifies
a custom per-tool policy file). Use one or the other.

## LLM Provider Metadata

The `--llm` flag records which LLM provider the agent uses. This metadata
appears in the session manifest and database, and also drives per-provider
network narrowing when `--sandbox-agent` is active.

```bash
oaie session run --contained=cloud --llm=anthropic -- ./agent
oaie session run --contained=local --llm=local -- ./ollama_agent
oaie session run --contained=cloud --llm=custom -- ./custom_agent
```

Valid provider values: `anthropic`, `openai`, `google`, `local`, `custom`.
