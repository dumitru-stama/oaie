# OAIE Tracing and Verification

OAIE provides tamper-evident tracing of sandboxed executions via hash-chained
event logs stored in content-addressable storage (CAS). Two trace backends
are available (ptrace and eBPF), and session mode extends the same hash-chain
model to the session event log.

## Tracing Overview

| Mode | Mechanism | Overhead | Fidelity | Requirements |
|---|---|---|---|---|
| **Off** (default) | No tracing | 0% | None | None |
| **Ptrace** | `PTRACE_SYSCALL` | ~30-50% | Full | Linux 5.13+ |
| **eBPF** | Tracepoint programs | <5% | Reduced (no argv) | `CAP_BPF`+`CAP_PERFMON`, cgroup isolation |

### Selecting a Trace Mode

```bash
# No tracing (default)
oaie run -- ./tool

# ptrace tracing (full fidelity, higher overhead)
oaie run --trace=ptrace -- ./tool

# eBPF tracing (low overhead, requires oaie-priv)
oaie run --trace=ebpf -- ./tool

# Auto-select: eBPF if available, otherwise ptrace
oaie run --trace=auto -- ./tool
```

### Ptrace

The ptrace tracer intercepts every syscall entry and exit via `PTRACE_SYSCALL`.
It captures:

- Process exec events (with full argv from `/proc/<pid>/cmdline`)
- Process exit events (with exit code)
- File open/stat operations (path read from process memory)
- Network connect calls (with sockaddr parsing)
- Fork/clone/clone3 events (process tree tracking)
- Security-relevant syscalls (socket with AF inspection, prctl, ioctl)

The tracer runs on the host, outside the sandbox trust boundary, ensuring full
trace integrity. A compromised tool cannot tamper with its own trace.

### eBPF

The eBPF tracer uses four tracepoint programs sharing a BPF ring buffer:

- `tracepoint/sched/sched_process_exec` -- process execution
- `tracepoint/sched/sched_process_exit` -- process exit
- `tracepoint/syscalls/sys_enter_openat` -- file access
- `tracepoint/syscalls/sys_enter_connect` -- network connections

BPF programs are loaded by `oaie-priv` (requires `CAP_BPF` + `CAP_PERFMON`)
and FDs are passed to the unprivileged consumer via `SCM_RIGHTS`. Programs
filter by cgroup ID, so cgroup isolation must be active.

**Pre-loading guarantee**: BPF programs are loaded and the cgroup filter is
set BEFORE the child process spawns. The kernel ring buffer accumulates events
until the consumer thread starts polling, so no early events are missed.

**Known limitations**: No argv capture, no syscall return values, no stat/dns/
security events. These are inherent to the tracepoint-based approach.

## CAS-Based Traces

Trace events are written as NDJSON (newline-delimited JSON) with hash chains
for tamper evidence. The `ChunkedEventWriter` handles chunking and CAS storage.

### Hash Chains

Each event contains a `prev_hash` field linking it to the previous event.
The first event links to a genesis hash derived from the hash algorithm:

```
genesis_hash = BLAKE3("oaie:genesis:blake3")   # or SHA-256 equivalent
event[0].prev_hash = genesis_hash
event[N].prev_hash = HASH(json_bytes(event[N-1]))
```

To verify, recompute each hash and confirm it matches the next event's
`prev_hash`. The chain tip (hash of the final event) is recorded in the
trace index and manifest.

### ChunkedEventWriter

Events are buffered and rotated into CAS chunks at 1 MiB boundaries:

```
ChunkedEventWriter
  ├── chunk_0.ndjson  →  CAS: ab3f.../
  ├── chunk_1.ndjson  →  CAS: cd89.../
  └── trace_index.json → CAS: ef01.../

trace_index.json:
{
  "chunks": [
    {"hash": "ab3f...", "event_count": 1024},
    {"hash": "cd89...", "event_count": 512}
  ],
  "chain_tip": "4a7b...",
  "total_events": 1536
}
```

## Event Types

Each trace event has a type, timestamp, PID, and type-specific detail:

| Event Type | Detail Fields | Description |
|---|---|---|
| `exec` | path, argv, cwd | Process executed a new binary |
| `exit` | code | Process exited |
| `open` | path, flags | File opened (via `openat`) |
| `stat` | path | File stat'd |
| `connect` | addr, port, protocol | Network connection attempt |
| `dns_query` | domain, query_type | DNS lookup |
| `socket` | domain, type, protocol | Socket created (AF inspection) |
| `clone` | child_pid, flags | Process forked/cloned |
| `security` | syscall, detail | Security-relevant syscall detected |

## Session Event Log

Session mode uses the same hash-chain model for its event log. Session events
are distinct from trace events -- they record supervisor-level actions rather
than syscall-level observations.

The session event chain uses a separate genesis string:

```
genesis_hash = BLAKE3("oaie:genesis:blake3:session")
```

Session events are written to an NDJSON file in the session directory, then
stored in CAS upon session completion. The chain tip is recorded in
`session_manifest.toml`.

### Linking Traces to Sessions

`ToolResult` session events include an optional `trace_hash` field containing
the chain tip of the individual tool call's trace. This creates a two-level
verification chain:

```
Session Event Log
  └── ToolResult { call_id, run_id, trace_hash }
        └── links to → Tool Run Trace (trace_index.json)
              └── Event hash chain (per-syscall)
```

## Verification

The `oaie verify` command performs comprehensive integrity checks on runs
and sessions.

### Run Verification

```bash
oaie verify <run-id>
```

### Session Verification

```bash
oaie verify --session <session-id>
```

Session verification is recursive: it checks the session-level integrity,
then verifies every individual tool call run.

### All 19 CheckKind Variants

| # | CheckKind | Scope | Description |
|---|---|---|---|
| 1 | `ManifestExists` | Run | manifest.toml exists in run directory |
| 2 | `ManifestParseable` | Run | manifest.toml is valid TOML |
| 3 | `InputArtifactsExist` | Run | All input artifacts present in CAS |
| 4 | `OutputArtifactsExist` | Run | All output artifacts present in CAS |
| 5 | `InputArtifactHashes` | Run | Input content hashes match CAS filenames |
| 6 | `OutputArtifactHashes` | Run | Output content hashes match CAS filenames |
| 7 | `TraceIndexExists` | Run | trace_index.json exists in CAS |
| 8 | `TraceChunksExist` | Run | All chunks listed in index exist in CAS |
| 9 | `TraceChunkHashes` | Run | Chunk content hashes match CAS filenames |
| 10 | `EventChainIntegrity` | Run | Hash chain intact across all chunks |
| 11 | `EventChainTip` | Run | Chain tip matches trace index claim |
| 12 | `ManifestSignature` | Run | Ed25519 signature verification |
| 13 | `SessionManifestExists` | Session | session_manifest.toml exists |
| 14 | `SessionManifestParseable` | Session | session_manifest.toml is valid TOML |
| 15 | `SessionEventLogExists` | Session | Event log exists in CAS |
| 16 | `SessionEventLogHash` | Session | Event log hash matches manifest claim |
| 17 | `SessionEventChainIntegrity` | Session | Event hash chain intact |
| 18 | `SessionEventChainTip` | Session | Chain tip matches manifest claim |
| 19 | `SessionRunsVerified` | Session | All tool call runs pass verification |

### Check Status Values

| Status | Meaning |
|---|---|
| `Pass` | Data is intact and correct |
| `Fail` | Data is missing, corrupted, or inconsistent |
| `Skip` | Check not applicable (e.g. trace checks when tracing was off) |

## SessionVerifyReport

Session verification produces a `SessionVerifyReport` containing:

- **Session-level checks** (7 checks: #13-#19)
- **Nested run reports** (checks #1-#12 for each tool call)

```bash
$ oaie verify --session 019cb6a3-1234-7abc-...

Session 019cb6a3-1234-7abc-...
  [PASS] Session manifest exists
  [PASS] Session manifest parseable
  [PASS] Session event log in CAS
  [PASS] Session event log hash matches
  [PASS] Session event chain integrity
  [PASS] Session event chain tip matches
  [PASS] Session runs verified (12/12 runs pass)

Summary: 7 passed, 0 failed, 0 skipped; 12/12 runs verified
```

The `passed()` method returns true only if all session checks AND all nested
run checks pass (or are skipped). A single failure at any level fails the
entire session verification.

## Hash Algorithm

The hash algorithm is set at store initialization and used consistently for
all hash chains (trace events, session events, CAS storage):

```bash
oaie init ~/.oaie              # Default: BLAKE3
oaie init ~/.oaie --sha256     # SHA-256
```

Both algorithms produce 32-byte digests. The `StreamingHasher` enum in
`oaie-core` wraps both algorithms behind a common interface. The genesis
hash string includes the algorithm name to prevent cross-algorithm collisions.
