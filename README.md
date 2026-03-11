# OAIE — Observed & Attested Isolated Execution

**Run any command in a sandbox. Record what happened. Prove it.**

No daemons. No root. No Docker. Just `oaie run ./tool`.

```
 +-----------+       +------------------+       +------------------+
 |  You run  | ----> |  OAIE isolates,  | ----> | Verifiable report|
 |  a command|       |  observes, and   |       | with signed      |
 |           |       |  records it      |       | manifest + CAS   |
 +-----------+       +------------------+       +------------------+
                       |                          |
                       | 6 namespaces             | BLAKE3 hash chain
                       | seccomp BPF              | Ed25519 signatures
                       | cgroups + rlimits        | content-addressed
                       | (or Firecracker VM)      |   artifact store
```

### At a Glance

| | |
|---|---|
| **What** | Safe execution wrapper with built-in provenance |
| **Isolation** | Linux namespaces + seccomp + Landlock + cgroups, or Firecracker microVM (KVM) |
| **Observation** | ptrace or eBPF syscall tracing, out-of-band (tool can't tamper with its own trace) |
| **Attestation** | Content-addressed storage (BLAKE3/SHA-256), Ed25519 signed manifests |
| **Defaults** | No network, 512 MB memory, 64 processes, 5 min timeout — zero config needed |
| **Requirements** | Linux 5.10+, user namespaces, unprivileged user (no root) |
| **Tests** | 668 tests across 16 crates |

---

## Install

```bash
cargo install --path crates/oaie-cli
oaie init
oaie doctor   # check system readiness
```

## Quick Start

```bash
# Sandboxed compilation (no network, no access to ~/.ssh, ~/.aws, etc.)
oaie run -- gcc -o hello hello.c

# With network
oaie run --net on -- curl https://example.com -o page.html

# With syscall tracing
oaie run --trace ptrace -- ./suspicious_binary

# With hardware-level isolation (Firecracker microVM)
oaie run --backend firecracker -- ./untrusted_binary

# Verify integrity of any run
oaie verify <run-id>
```

## How It Works

```
 YOUR COMMAND
      |
      v
 +----+----+    +------------+    +-----------+
 | ISOLATE |    |  OBSERVE   |    |  ATTEST   |
 +---------+    +------------+    +-----------+
 | 6 Linux |    | ptrace or  |    | All output|
 | name-   |    | eBPF       |    | content-  |
 | spaces  |    | syscall    |    | addressed |
 |         |    | tracing    |    | (BLAKE3)  |
 | seccomp |    |            |    |           |
 | BPF     |    | Records:   |    | Signed    |
 | (69-71  |    | file I/O,  |    | manifest  |
 | blocked)|    | network,   |    | (Ed25519) |
 |         |    | processes, |    |           |
 | cgroups |    | security   |    | Stored in |
 | + rlimits|   | events     |    | CAS with  |
 |         |    |            |    | hash chain|
 | Landlock|    | Out-of-band|    |           |
 | caps=0  |    | (untamper- |    | oaie      |
 |         |    |  able)     |    |  verify   |
 +---------+    +------------+    +-----------+
```

---

## Execution Backends

| Backend | Isolation | Startup | Use Case |
|---------|-----------|---------|----------|
| `namespace` (default) | OS-level (namespaces + seccomp + Landlock) | ~15 ms | General use, best tracing fidelity |
| `firecracker` | Hardware-level (KVM hypervisor) | ~800 ms | Maximum isolation for untrusted code |

> **Note:** The Firecracker backend is **experimental**. Syscall trace collection
> and network namespace setup inside the guest are not yet implemented. The backend
> returns explicit errors for these operations. The namespace backend is
> fully production-ready.

```bash
oaie run --backend namespace  -- ./tool    # default
oaie run --backend firecracker -- ./tool   # hardware isolation (experimental)
```

---

## Security Model

> **For managers:** Think of this as a building with multiple locked doors.
> An attacker must break through ALL layers to escape — not just one.

OAIE uses defense-in-depth: multiple independent layers that an attacker must
break through simultaneously.

### Namespace Sandbox (6 layers)

```
+--[Layer 6]---------------------------------------+
| Landlock filesystem restrictions (kernel 5.13+)  |
+--[Layer 5]---------------------------------------+
| Seccomp BPF: 69-71 syscalls blocked/killed       |
|   KILL tier: io_uring, bpf, kexec, unshare, ...  |
|   ERRNO tier: mount, ptrace, reboot, keyctl, ... |
|   Arg inspection: clone, socket, prctl, ioctl    |
+--[Layer 4]---------------------------------------+
| All capabilities dropped (0 of 41 retained)     |
|   Allowlist: only CAP_NET_RAW, CAP_NET_BIND_SVC |
+--[Layer 3]---------------------------------------+
| Cgroup v2: hard memory, PID, and CPU caps        |
|   memory.max, memory.swap.max=0, pids.max,      |
|   cpu.max (kernel-enforced, cannot be bypassed)  |
+--[Layer 2]---------------------------------------+
| rlimits: memory, CPU time, file size, processes, |
|   open files, locked memory, stack, core dumps   |
+--[Layer 1]---------------------------------------+
| 6 Linux namespaces                               |
|   user, mount, PID, IPC, UTS, net (+ cgroup)    |
+--------------------------------------------------+
```

### Firecracker MicroVM (4 layers)

```
+--[Layer 4]---------------------------------------+
| Guest seccomp: tool cannot access AF_VSOCK       |
|   (prevents bypassing guest agent)               |
+--[Layer 3]---------------------------------------+
| Separate Linux kernel (no shared syscall table)  |
+--[Layer 2]---------------------------------------+
| Firecracker VMM (minimal device model, <50K LoC) |
+--[Layer 1]---------------------------------------+
| KVM hypervisor (hardware CPU isolation)          |
|   1 vCPU, 128 MB RAM, no network device          |
+--------------------------------------------------+
```

### Resource Limits

| Resource | Default | Enforcement |
|----------|---------|-------------|
| Memory (virtual address space) | 512 MB | rlimit + cgroup |
| Wall-clock timeout | 5 min (max 7 days) | Supervisor |
| CPU time | 2x wall timeout (min 60s) | rlimit |
| Processes/threads | 64 | rlimit + cgroup |
| Max file size | 1 GB | rlimit |
| Open file descriptors | 1024 / 4096 | rlimit |
| Locked memory | 64 MB | rlimit |
| Core dumps | Disabled | rlimit |
| Stack size | 8 MB / 16 MB | rlimit |
| Output files per run | 10,000 | Supervisor |
| Single output file | 256 MB | Supervisor |
| Total output | 1 GB | Supervisor |

### Filesystem Isolation

| Path | Access | Contents |
|------|--------|----------|
| `/` | tmpfs | Empty root (pivot_root, old root unmounted) |
| `/in` | Read-only | Input directory |
| `/out` | Read-write | Output directory |
| `/usr`, `/lib` | Read-only | System libraries |
| `/proc` | Masked | `/proc/net`, `*/tty`, `*/smaps*`, `self/attr/*`, `self/io`, `oom_adj` hidden |
| `/dev` | Minimal | null, zero, random, urandom, console, pts only |
| `/etc` | Synthetic | passwd + shadow entries only |

24 credential paths are **always denied** (never mounted even if requested):
`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.azure`, `~/.docker`, `~/.kube`,
`~/.config/gcloud`, `~/.git-credentials`, `~/.npmrc`, `~/.vault-token`, and more.

### Network Isolation

| Mode | Flag | Behavior |
|------|------|----------|
| Off (default) | `--net off` | Separate network namespace, loopback only |
| On | `--net on` | Host network shared, no restrictions |
| Allowlist | `--net allow:host:port` | Isolated NS + veth + nftables + DNS proxy |
| Preset | `--net preset:anthropic` | Pre-configured allowlist (anthropic, openai, llm) |

Allowlist mode provides: DNS pre-resolution on host, nftables rule enforcement,
TLS SNI extraction for domain-level filtering, and a DNS proxy at 127.0.0.53.

### Environment Sanitization

All dangerous environment variables are blocked: `LD_*`, `GIT_*`, `PYTHONPATH`,
`NODE_OPTIONS`, `JAVA_TOOL_OPTIONS`, `CLASSPATH`, `BASH_ENV`, `OPENSSL_CONF`,
and 25+ others. A clean `PATH`, `HOME`, `LANG`, and `TERM` are set.

---

## Session Mode

Host long-running AI agents in managed sessions with tool dispatch. Each tool
call becomes a standard OAIE run with its own sandbox, manifest, and DB record.

```bash
# Run an agent with local containment profile
oaie session run --contained=local -- python3 agent.py

# Run with the agent itself sandboxed (tools + agent both isolated)
oaie session run --contained=cloud --sandbox-agent -- python3 agent.py

# Run with approval gates (user confirms each tool call)
oaie session run --require-approval -- python3 agent.py

# List active sessions
oaie session list

# Verify full session integrity (manifest + all tool calls + event chain)
oaie verify --session <session-id>
```

### Session Budgets

| Budget | Default | Purpose |
|--------|---------|---------|
| Max tool calls | 50 | Limits total dispatched tool invocations |
| Max wall time | 30 min | Total session duration |
| Max tool time | 10 min | Cumulative tool execution time |
| Max output | 1 GB | Cumulative output across all tools |
| Max network bytes | Unlimited | Network transfer cap (with nftables tracking) |
| Agent output rate | Unlimited | Per-second stdout/stderr rate limit |

See [SESSIONS.md](docs/SESSIONS.md) and [CONTAINMENT.md](docs/CONTAINMENT.md) for the full guide.

---

## Policy Presets

Built-in presets cover common use cases. Custom policies via TOML files.

| Preset | Memory | Timeout | PIDs | Network | JIT | Use Case |
|--------|--------|---------|------|---------|-----|----------|
| `safe` (default) | 512 MB | 5 min | 64 | Off | No | General sandboxed execution |
| `net` | 512 MB | 5 min | 64 | On | No | Commands needing network |
| `agent-safe` | 256 MB | 2 min | 64 | Off | No | AI agent tool calls |
| `agent-net` | 512 MB | 5 min | 64 | On | No | AI tools with network |
| `agent-build` | 2 GB | 10 min | 256 | On | Yes | Build tasks (cargo, npm) |
| `agent-analyze` | 1 GB | 15 min | 128 | Off | Yes | Analysis tasks |
| `contained-local` | 1 GB | 10 min | 128 | Off | Yes | Local LLM agent sessions |
| `contained-cloud` | 512 MB | 5 min | 64 | Off | No | Cloud LLM agent sessions |
| `contained-strict` | 128 MB | 1 min | 32 | Off | No | Maximum restriction |
| `contained-interactive` | 1 GB | 10 min | 128 | Off | Yes | Human-in-the-loop sessions |

"JIT" = allow `memfd_create`/`execveat` (needed by Java, Node.js, .NET runtimes).

```bash
oaie policy list              # list all presets
oaie policy show agent-build  # show preset details
oaie run --policy=agent-build -- npm install  # use a preset
oaie run --policy=my_policy.toml -- ./tool    # use a custom TOML policy
```

---

## Commands

| Command | Description |
|---------|-------------|
| `oaie init` | Initialize the OAIE store (~/.oaie) |
| `oaie run` | Execute a command in isolation |
| `oaie check` | Validate a job against policy (dry run) |
| `oaie inspect` | View run artifacts, trace data, CAS stats |
| `oaie verify` | Verify integrity of a run or session |
| `oaie replay` | Replay a run and compare outputs |
| `oaie diff` | Compare two runs side-by-side |
| `oaie list` | List past runs |
| `oaie report` | Print stored REPORT.md |
| `oaie export` | Package a run as a self-contained .tar.gz |
| `oaie clean` | Remove old runs (`--auto` for 7-day default) |
| `oaie doctor` | Check system readiness (20 probes) |
| `oaie key` | Manage Ed25519 signing keys |
| `oaie policy` | List/show built-in policy presets |
| `oaie cas` | Interact with the content-addressed store |
| `oaie completions` | Generate shell completions |
| `oaie session run` | Host an agent in a managed session |
| `oaie session list/status/stop` | Session lifecycle management |
| `oaie session attach` | Shell into a running sandboxed session |
| `oaie session log` | View session event log |
| `oaie session extend` | Extend budgets for a running session |
| `oaie session profiles` | List containment profiles |

## Tracing

| Mode | Flag | Overhead | Fidelity | Requirements |
|------|------|----------|----------|-------------- |
| Off (default) | `--trace off` | None | No syscall data | None |
| ptrace | `--trace ptrace` | ~20-40% | Full (argv, return values) | None |
| eBPF | `--trace ebpf` | <5% | Reduced (no argv) | `oaie-priv` + cgroups |

Both modes produce BLAKE3/SHA-256 hash-chained NDJSON event logs stored in CAS.
Events tracked: execve, openat, connect, stat, fork/clone, exit, and
security-relevant syscalls.

---

## Trust Model

- **Defense-in-depth, not a single boundary.** Multiple independent layers
  (namespaces, seccomp, Landlock, rlimits, cgroups, capabilities) make escape
  progressively harder. Firecracker adds KVM hardware isolation on top.

- **Tamper-evident observation.** The observation layer runs out-of-band in the
  supervisor. A sandboxed process cannot influence its own trace. Hash chains
  make silent modification detectable.

- **Content-addressed integrity.** All artifacts are identified by their
  BLAKE3/SHA-256 hash. Corruption or tampering is detected by `oaie verify`.

- **Cryptographic attestation.** Ed25519 manifest signing provides
  non-repudiation. Keys managed via `oaie key generate/list/export`.

- **Honest reporting.** OAIE reports what isolation was actually applied — if
  cgroups were unavailable, if Landlock was not supported, if a capability was
  retained. No silent degradation.

---

## Architecture

16-crate workspace:

```
oaie-cli          CLI entry point, runner, session runner, policy resolution
oaie-core         Types, config, errors (no heavy deps)
oaie-cas          Content-addressed blob store (BLAKE3/SHA-256)
oaie-db           SQLite index (WAL mode)
oaie-sandbox      Namespace isolation, seccomp BPF, Landlock, PTY
oaie-observe      ptrace tracer, eBPF tracer, event model, hash chain
oaie-report       REPORT.md generation
oaie-cgroup       Cgroup v2 detection, scope management, stats
oaie-netpol       Network policy: DNS resolution, nftables, DNS proxy, SNI
oaie-agent        Library interface for agent integrations
oaie-mcp          MCP server (JSON-RPC 2.0 over stdin/stdout)
oaie-priv         Privileged helper (cgroup management, BPF loading)
oaie-firecracker  Firecracker microVM backend (feature-gated)
oaie-guest        Guest agent for microVMs (static musl binary)
oaie-bpf-common   Shared BPF/userspace types
oaie-tests        Consolidated test suite (668 tests)
```

## MCP Integration

OAIE includes an MCP server for AI agent frameworks:

```bash
# Start MCP server (JSON-RPC 2.0 over stdin/stdout)
oaie-mcp

# Tools: oaie_run, oaie_verify, oaie_read_output,
#         oaie_session_run, oaie_session_status, oaie_session_stop
```

The `oaie-agent` crate provides a typed Rust client (`OaieClient`) for
programmatic access to all functionality.

## Documentation

| Guide | Content |
|-------|---------|
| [SECURITY.md](docs/SECURITY.md) | Full security model, attack surface, threat analysis |
| [SESSIONS.md](docs/SESSIONS.md) | Session mode lifecycle, dispatch protocol, budgets |
| [CONTAINMENT.md](docs/CONTAINMENT.md) | Containment profiles, agent sandboxing |
| [NETWORK.md](docs/NETWORK.md) | Network modes, allowlists, nftables, DNS proxy |
| [TRACING.md](docs/TRACING.md) | Trace modes, hash chains, verification |
| [BACKENDS.md](docs/BACKENDS.md) | Execution backends (namespace, Firecracker) |
| [SECURITY_DIAGRAMS.md](docs/SECURITY_DIAGRAMS.md) | Visual security model diagrams |
| [FEATURES.md](docs/FEATURES.md) | Complete CLI flag reference |
| [DESIGN.md](docs/DESIGN.md) | Architecture, design rationale, goals |
| [CHANGELOG.md](docs/CHANGELOG.md) | Version history and release notes |
| [VALIDATION_GUIDE.md](docs/VALIDATION_GUIDE.md) | Step-by-step feature testing procedures |

## Build

```bash
cd code_v03
make                     # build + clippy + test (668 tests)
make build-firecracker   # build with Firecracker backend
make build-mcp           # build MCP server
make check-all           # all clippy + test variants
```

## License

MIT
