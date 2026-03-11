# OAIE Feature Reference

## CLI Commands

### `oaie run` — Execute a command in an isolated sandbox

The primary command. Runs an arbitrary command inside a Linux namespace sandbox
with configurable isolation, resource limits, and observation.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--spec` | | `PathBuf` | | TOML/JSON job spec file (`-` for stdin) |
| `--in` | | `PathBuf` | cwd | Input directory (read-only inside sandbox) |
| `--out` | `-o` | `PathBuf` | `./oaie-out/<run_id>` | Output directory |
| `--ro` | | `Vec<String>` | | Additional read-only bind mounts |
| `--rw` | | `Vec<String>` | | Additional read-write bind mounts |
| `--net` | | `String` | `off` | Network mode: `on`, `off`, `allow:host:port`, `preset:name` |
| `--trace` | | `String` | `off` | Trace backend: `off`, `ptrace`, `ebpf` |
| `--notrace` | | `bool` | | Disable tracing (overrides `--trace`) |
| `--timeout` | | `u64` | 5m | Maximum wall-clock seconds |
| `--policy` | | `String` | | Policy file path or named preset |
| `--no-isolation` | | `bool` | | Skip namespace isolation |
| `--no-auto-mount` | | `bool` | | Disable automatic bind-mount inference |
| `--quiet` | `-q` | `bool` | | Suppress output |
| `--cgroup` | | `String` | `auto` | Cgroup mode: `auto`, `on`, `off` |
| `--backend` | | `String` | `namespace` | Backend: `namespace`, `firecracker` |
| `--interactive` | `-i` | `bool` | | Interactive PTY mode |
| `--sign` | | `bool` | | Sign manifest with Ed25519 key |
| `--verbose` | `-v` | count | | `-v` policy summary, `-vv` full sandbox spec |
| `--output` | | `OutputFormat` | `human` | Output format: `human`, `json` |

Environment set inside sandbox: `OAIE_RUN_ID`, `OAIE_OUT=/out`.

### `oaie inspect` — Inspect a completed run

| Arg/Flag | Description |
|----------|-------------|
| `run_id` (positional) | Run UUID or `"last"` |
| `--trace-full` | Dump raw NDJSON trace events |
| `--trace-stats` | Show trace statistics only |

Default mode shows: metadata, network policy, observation summary (files
read/written, access denied, network), suspicious activity, process tree,
CAS store statistics, directory grouping.

### `oaie replay` — Replay a run and compare outputs

| Arg/Flag | Description |
|----------|-------------|
| `run_id` (positional) | Run UUID |
| `--diff` | Show hash details for mismatched outputs |

Re-executes the command from a stored manifest in a new sandbox, then compares
output artifact hashes between original and replay.

### `oaie export` — Export a run as a portable archive

| Arg/Flag | Short | Default | Description |
|----------|-------|---------|-------------|
| `run_id` (positional) | | | Run UUID |
| `--output` | `-o` | `oaie-<short_id>.tar.gz` | Output archive path |

Archive contains: `manifest.toml`, `signature.toml` (if present), `REPORT.md`,
`blobs/` (streamed from CAS), trace blobs, `artifacts.json` index.

### `oaie clean` — Remove old runs and unreferenced blobs

| Flag | Default | Description |
|------|---------|-------------|
| `--older-than` | | Delete runs older than duration (`7d`, `12h`, `30m`) |
| `--min-age` | `7d` | Minimum age before orphaned blobs removed |
| `--dry-run` | | Show what would be removed |
| `--auto` | | Automatic cleanup (defaults `--older-than` to `7d`) |

### `oaie key` — Ed25519 signing key management

| Subcommand | Args/Flags | Description |
|------------|------------|-------------|
| `generate` | `--label` (default: `"default"`) | Generate new Ed25519 keypair |
| `list` | | Show all keys: ID, label, algorithm, public key prefix |
| `delete` | `key_id` | Delete by ID prefix or label |
| `export` | `key_id`, `--public` | Export keypair (or public key only) |

Key ID = first 8 hex chars of `BLAKE3(public_key_bytes)`. Keys stored at
`<store>/keys/<key_id>.toml` with `0o600` permissions. Secret keys zeroized
via `zeroize` crate.

### `oaie session` — Persistent agent sandbox sessions

| Subcommand | Description |
|------------|-------------|
| `run` | Create and run a session (see flags below) |
| `list` | List sessions (`--limit`, default 20) |
| `status` | Query session state |
| `stop` | Send SIGTERM to running session |
| `inspect` | Budget, resource usage, tool call table |
| `log` | Event log (`--type all/tool_call/budget/io`, `--json`) |
| `extend` | Add budget (`--add-tool-calls`, `--add-wall-time`, etc.) |
| `attach` | Enter session namespaces via `nsenter` |
| `profiles` | List/show containment profiles |

**`session run` flags:**

| Flag | Type | Description |
|------|------|-------------|
| `--policy` | `String` | Policy file or preset |
| `--contained` | `String` | Containment profile (mutually exclusive with `--policy`) |
| `--llm` | `String` | LLM provider: `anthropic`, `openai`, `google`, `local`, `custom` |
| `--net` | `String` | Network mode |
| `--timeout` | `u64` | Max wall-clock seconds |
| `--name` | `String` | Session name |
| `--budget-tools` | `u32` | Max tool calls |
| `--budget-wall` | `u64` | Max wall time (seconds) |
| `--budget-tool-time` | `u64` | Max cumulative tool time (seconds) |
| `--heartbeat` | `u64` | Heartbeat interval (0=disabled) |
| `--allow-tools` | `Vec<String>` | Tool allow-list (glob patterns) |
| `--deny-tools` | `Vec<String>` | Tool deny-list (glob patterns) |
| `--deny-net-tools` | `Vec<String>` | Tools denied network access |
| `--max-agent-output` | `u64` | Max agent output bytes (0=unlimited) |
| `--max-agent-rate` | `u64` | Max agent output rate (bytes/sec) |
| `--require-approval` | `bool` | Require human approval for tool calls |
| `--sandbox-agent` | `bool` | Run agent itself in sandbox |
| `--interactive` | `-i` | Interactive mode |

### `oaie init` — Initialize the OAIE store

| Flag | Description |
|------|-------------|
| `--path` | Store directory path |
| `--sha256` | Use SHA-256 instead of BLAKE3 for CAS |
| `--pgsql` | PostgreSQL connection URL |

### `oaie verify` — Verify run integrity

| Arg/Flag | Description |
|----------|-------------|
| `run_id` (optional) | Run UUID (required unless `--all`) |
| `--all` | Verify every run in the store |
| `--format` | Output: `text`, `json` |
| `--strict` | Exit non-zero on any failure (for CI) |

**12 run checks:** ManifestExists, ManifestParseable, InputArtifactsExist,
OutputArtifactsExist, InputArtifactHashes, OutputArtifactHashes,
TraceIndexExists, TraceChunksExist, TraceChunkHashes, EventChainIntegrity,
EventChainTip, ManifestSignature.

**7 session checks:** SessionManifestExists, SessionManifestParseable,
SessionEventLogExists, SessionEventLogHash, SessionEventChainIntegrity,
SessionEventChainTip, SessionRunsVerified.

### `oaie list` — List stored runs

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--limit` | `-n` | 20 | Max runs |
| `--all` | | | Show all |
| `--json` | | | JSON output |
| `--search` | `-s` | | Command substring filter |

### `oaie cat` — Output a run artifact to stdout

Takes `run_id` and `artifact` label. Writes raw CAS blob to stdout.

### `oaie cas` — Content-Addressed Store operations

| Subcommand | Description |
|------------|-------------|
| `add` | Store a file, print hash and size |
| `verify` | Check blob exists and content matches hash |

### `oaie report` — View or regenerate a run report

Takes `run_id`. `--regenerate` rebuilds from manifest + trace events.

### `oaie diff` — Compare two runs

Takes `run_a` and `run_b`. `--trace` includes observed file/network access diff.
Compares metadata, exit codes, duration, isolation, artifact hashes.

### `oaie check` — Pre-flight validation of a job spec

Takes TOML spec file. `--policy` validates against specific policy. Checks
network rules, timeout constraints, command existence, input paths.

### `oaie doctor` — Run diagnostic probes

20 probes with color-coded results (green/yellow/red):

1. User namespaces
2. Mount namespace
3. PID namespace
4. Net namespace
5. ptrace scope
6. CAS store (exists and writable)
7. SQLite (database accessible)
8. Kernel CVEs (known problematic versions)
9. Store permissions
10. Landlock (LSM availability)
11. Cgroup v2 (hierarchy and delegation)
12. eBPF tracer (BPF syscall availability)
13. Firecracker (binary, `/dev/kvm`, assets)
14. Ping group range
15. Namespace headroom (max user namespaces)
16. oaie-priv helper
17. nftables (`nft` binary and permissions)
18. IP forwarding
19. nsenter (binary availability)
20. Signing key

### `oaie policy` — Policy preset management

| Subcommand | Description |
|------------|-------------|
| `list` | Show all named presets |
| `show` | Print preset as TOML |

### `oaie firecracker` — MicroVM management (feature-gated)

| Subcommand | Description |
|------------|-------------|
| `init` | Install kernel, rootfs, guest agent |
| `check` | Verify prerequisites |
| `boot-test` | Boot test VM, run echo, verify roundtrip |

### `oaie completions` — Generate shell completions

---

## Sandbox Isolation

### Linux Namespaces

7 namespaces created via `clone()`:

| Namespace | Purpose |
|-----------|---------|
| `CLONE_NEWUSER` | UID 0 inside maps to caller's UID outside |
| `CLONE_NEWNS` | Independent mount tree; `pivot_root` replaces `/` |
| `CLONE_NEWPID` | Child is PID 1 inside |
| `CLONE_NEWIPC` | Isolates System V IPC, POSIX message queues |
| `CLONE_NEWUTS` | Independent hostname/domainname |
| `CLONE_NEWCGROUP` | Isolates cgroup view |
| `CLONE_NEWNET` | Network isolation (conditional: only for `Off`/`Allowlist`) |

### Filesystem Isolation

**Root filesystem:** tmpfs (64m), read-only after pivot. Writable areas:
`/out`, `/tmp` (64m), `/root` (16m).

**Mount layout:**

| Path | Type | Flags |
|------|------|-------|
| `/in` | bind from host | RO, nodev, nosuid, noexec |
| `/out` | bind from host | RW, nodev, nosuid, noexec |
| `/tmp` | tmpfs 64m | nosuid, nodev, noexec |
| `/root` | tmpfs 16m | nosuid, nodev, noexec |
| `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin` | bind from host | RO, nodev, nosuid (executable) |
| `/proc` | procfs | nosuid, nodev, noexec, heavily masked |
| `/dev` | 4 nodes only | null, zero, random, urandom |
| `/mnt/ro{i}` | extra RO mounts | nodev, nosuid, noexec |
| `/mnt/rw{i}` | extra RW mounts | nodev, nosuid, noexec |

**Generated `/etc`:** passwd (root + nobody), group (root + nogroup),
nsswitch.conf (files only), resolv.conf (depends on network mode).

### /proc Masking

**Top-level files masked with /dev/null (16):** kallsyms, kcore, keys,
sysrq-trigger, timer_list, interrupts, softirqs, modules, kpagecount,
kpageflags, kpagecgroup, sched_debug, kmsg, version, cpuinfo, meminfo.

**`/proc/self` and `/proc/1` entries masked (26):** pagemap, oom_score_adj,
oom_adj, timerslack_ns, mem, mountinfo, mounts, environ, maps, smaps,
smaps_rollup, numa_maps, status, syscall, stack, wchan, autogroup, uid_map,
gid_map, setgroups, fdinfo, limits, cgroup, ns, attr, io.

**Directories masked with RO tmpfs (9):** sys, sysvipc, bus, irq, acpi, scsi,
fs, net, tty.

### Seccomp BPF

**Architecture:** x86_64 and aarch64. 32-bit compat killed by arch check.

**KILL tier (14 syscalls on x86_64):** io_uring_setup, io_uring_enter,
io_uring_register, userfaultfd, kexec_load, kexec_file_load, init_module,
finit_module, create_module, bpf, unshare, clone3, modify_ldt, iopl, ioperm.

**ERRNO tier (55+ syscalls):** ptrace, perf_event_open, mount, mount_setattr,
pivot_root, keyctl, add_key, request_key, kcmp, pidfd_send_signal, pidfd_getfd,
pidfd_open, process_vm_readv, process_vm_writev, process_madvise, fsopen,
fsconfig, fsmount, move_mount, open_tree, fspick, umount2, setns,
delete_module, reboot, swapon, swapoff, acct, quotactl, quotactl_fd,
clock_adjtime, clock_settime, settimeofday, adjtimex, sethostname,
setdomainname, personality, remap_file_pages, landlock_create_ruleset,
landlock_add_rule, landlock_restrict_self, open_by_handle_at,
name_to_handle_at, memfd_secret, seccomp, mknod, mknodat, chroot,
fanotify_init, move_pages, migrate_pages, lookup_dcookie, syslog, statmount,
listmount. When `allow_memfd=false`: adds memfd_create, execveat.

**Argument inspection:**
- `clone()`: CLONE_NEW* flags blocked via `CLONE_NEW_MASK` (0x7E020080)
- `socket()`: 11 blocked address families (AF_NETLINK, AF_PACKET, AF_CAN,
  AF_TIPC, AF_BLUETOOTH, AF_ALG, AF_NFC, AF_VSOCK, AF_KCM, AF_QIPCRTR, AF_XDP)
- `prctl()`: 6 blocked operations (PR_SET_DUMPABLE, PR_SET_SECCOMP,
  PR_SET_SECUREBITS, PR_SET_MM, PR_CAP_AMBIENT, PR_SET_PTRACER)
- `ioctl()`: 2 blocked commands (TIOCSTI, TIOCLINUX)

### Resource Limits (rlimits)

| Resource | Soft | Hard | Configurable |
|----------|------|------|-------------|
| NOFILE | 1024 | 4096 | No |
| MEMLOCK | 64M | 64M | No |
| CORE | 0 | 0 | No |
| NPROC | 64 | 128 | Yes (`max_pids`) |
| FSIZE | 1G | 1G | Yes (`max_fsize`) |
| AS | 4G | 8G | Yes (`max_memory`) |
| MSGQUEUE | 0 | 0 | No |
| CPU | 600s | 600s | Yes (`max_cpu_time`) |
| STACK | 8M | 16M | No |

### Capability Management

All capabilities dropped via raw `capset()` v3 syscall. Ambient capabilities
cleared first. Inheritable set zeroed. Optional retention of `CAP_NET_RAW`
(for ping) and `CAP_NET_BIND_SERVICE` (for privileged ports) via policy.

### Landlock LSM

Defense-in-depth filesystem access control. Supports ABI v1-v3. Deny-by-default:
only explicitly allowed paths are accessible. `/out`, `/tmp`, `/root` get
RW (no execute). System dirs get RO+execute. `/in` gets RO.

### Environment Sanitization

**Base environment (always set):**
- `PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin`
- `HOME=/root`
- `TERM=dumb` (or supervisor's TERM in interactive mode)
- `LANG=C.UTF-8`

**Blocked prefixes:** `LD_*`, `GIT_*`

**Blocked keys (24):** GCONV_PATH, TMPDIR, BASH_ENV, ENV, IFS, CDPATH,
HOSTALIASES, LOCALDOMAIN, RESOLV_HOST_CONF, PYTHONPATH, PYTHONSTARTUP,
PYTHONHOME, RUBYLIB, RUBYOPT, PERL5LIB, PERL5OPT, PERLLIB, CLASSPATH,
NODE_OPTIONS, JAVA_TOOL_OPTIONS, _JAVA_OPTIONS, JDK_JAVA_OPTIONS,
MAVEN_OPTS, GRADLE_OPTS, GLIBC_TUNABLES, DOTNET_STARTUP_HOOKS,
OPENSSL_CONF, OPENSSL_ENGINES.

### Child Process Setup Order

1. Mount namespace setup (pivot_root, all masking)
2. Loopback setup (ioctl before cap drop)
3. `setsid()` (detach from controlling terminal)
4. Stdin/stdout/stderr redirect (pipes or PTY)
5. `PR_SET_NO_NEW_PRIVS` (required before Landlock/seccomp)
6. Landlock application
7. `close_range_above(3)` (close all fds >= 3)
8. `PR_SET_DUMPABLE=0` (prevent ptrace, skip when tracing)
9. ptrace handshake (when tracing)
10. `personality(0)` (reset, disable READ_IMPLIES_EXEC)
11. `set_rlimits()`
12. `set_caps()` (capability drop)
13. `install_seccomp_filter()`
14. Clean environment build
15. `execvpe()` (replace process image)

---

## Network Isolation

### Three Modes

| Mode | CLONE_NEWNET | resolv.conf | Connectivity |
|------|-------------|-------------|-------------|
| `Off` | Yes | No nameservers | Loopback only |
| `On` | No | Copies host's | Full host network |
| `Allowlist` | Yes | `127.0.0.53` | Filtered via nftables + DNS proxy |

### nftables Rule Generation

- Table `inet oaie_filter` (dual-stack IPv4+IPv6)
- Default policy: **drop** (deny-all baseline)
- Rules: stateful tracking, loopback allow, per-endpoint accept with byte
  counters, DNS proxy rules
- Applied inside network namespace via `nsenter`
- Dynamic rule insertion for newly resolved IPs
- Byte counter reading for network budget enforcement

---

## Policy System

### Resource Limits

| Field | Default | Description |
|-------|---------|-------------|
| `max_memory` | 512M | RLIMIT_AS + cgroup memory.max |
| `max_time` | 5m | Wall-clock timeout |
| `max_pids` | 64 | RLIMIT_NPROC + cgroup pids.max |
| `max_fsize` | 1G | RLIMIT_FSIZE |
| `allow_memfd` | false | Allow memfd_create/execveat (for JIT) |
| `capabilities` | [] | Retained caps (net_raw, net_bind_service) |
| `cpu_quota` | None | cgroup cpu.max ("50%", "200%") |

### Credential Deny Paths (always enforced)

~/.ssh, ~/.gnupg, ~/.aws, ~/.azure, ~/.config/gcloud, ~/.docker, ~/.kube,
~/.npmrc, ~/.pypirc, ~/.netrc, ~/.git-credentials, ~/.config/git/credentials,
~/.local/share/keyrings, ~/.password-store, ~/.config/gh,
~/.cargo/credentials.toml, ~/.cargo/credentials, ~/.config/op,
~/.vault-token, ~/.terraform.d/credentials.tfrc.json, ~/.config/helm,
~/.config/doctl, ~/.config/heroku, ~/.config/stripe, /var/run/secrets.

### 13 Named Presets

| Name | Network | Memory | Time | PIDs | memfd |
|------|---------|--------|------|------|-------|
| `safe` | Off | 512M | 5m | 64 | No |
| `net` | On | 512M | 5m | 64 | No |
| `agent-safe` | Off | 256M | 2m | 64 | No |
| `agent-net` | On | 512M | 5m | 64 | No |
| `agent-build` | On | 2G | 10m | 256 | Yes |
| `agent-analyze` | Off | 1G | 15m | 128 | Yes |
| `anthropic` | Allowlist | 512M | 5m | 64 | No |
| `openai` | Allowlist | 512M | 5m | 64 | No |
| `llm` | Allowlist | 512M | 5m | 64 | No |
| `contained-local` | Off | 1G | 10m | 128 | Yes |
| `contained-cloud` | Off | 512M | 5m | 64 | No |
| `contained-strict` | Off | 128M | 1m | 32 | No |
| `contained-interactive` | Off | 1G | 10m | 128 | Yes |

---

## Session Mode

### Containment Profiles

| Profile | Tool Calls | Wall Time | Tool Time | Output | Memory | PIDs |
|---------|-----------|-----------|-----------|--------|--------|------|
| `Local` | 100 | 1h | 30m | 2 GiB | 1G | 128 |
| `Cloud` | 50 | 30m | 10m | 1 GiB | 512M | 64 |
| `Strict` | 20 | 10m | 5m | 256 MiB | 128M | 32 |
| `Interactive` | 200 | 2h | 1h | 2 GiB | 1G | 128 |

### Budget Resources

| Budget | Default | Description |
|--------|---------|-------------|
| `max_tool_calls` | 50 | Max tool dispatches |
| `max_wall_time_s` | 1800 | Total session wall time |
| `max_tool_time_s` | 600 | Cumulative tool execution time |
| `max_output_bytes` | 1 GiB | Cumulative output bytes |
| `max_network_bytes` | unlimited | Cumulative network bytes |
| `max_agent_output_rate` | unlimited | Per-second agent output rate |

### Wire Protocol

JSON newline-delimited over Unix domain socket (`dispatch.sock`).

**Messages:** DispatchRequest, DispatchResponse, AgentOutput, UserInput.

### Event Log

Hash-chained NDJSON stored in CAS. 12 event kinds: SessionStart, SessionStop,
ToolDispatch, ToolResult, BudgetWarning, BudgetExhausted, BudgetExtension,
HeartbeatTimeout, ResourceSnapshot, ToolDenied, AgentOutput, ApprovalRequired.

### Tool Filtering

- Allow-list: glob patterns, command must match one
- Deny-list: glob patterns, always takes precedence
- Per-tool network denial: specific tools denied network access

---

## Content-Addressed Store (CAS)

- 2-level directory layout: `cas/ab/cd/abcdef01...`
- Hash algorithms: BLAKE3 (default, fast) or SHA-256 (FIPS)
- Chosen at `oaie init`, immutable after
- Atomic writes (temp + fsync + rename)
- Deduplication by content hash

### Artifact Types

Stdout, Stderr, Output, Trace, Report, Manifest, ResourceStats, Signature.

---

## Observation / Tracing

### Trace Modes

| Mode | Description |
|------|-------------|
| `Off` | No tracing |
| `Ptrace` | ptrace-based syscall interception |
| `eBPF` | Kernel-level BPF observation (feature-gated) |
| `Auto` | Best available (eBPF > ptrace) |

### Hash Chain

Events stored as NDJSON with hash-chained integrity. Each event includes
`prev_hash` linking to the previous event. Chain tip stored in manifest
for verification.

---

## Cgroup v2 Integration

### Modes

| Mode | Description |
|------|-------------|
| `Auto` | Use if available, fall back gracefully |
| `Require` | Fail without cgroups |
| `Off` | Rlimits only |

### Enforced Limits

| Limit | cgroup file | Description |
|-------|-------------|-------------|
| `memory_max` | `memory.max` | Hard memory limit |
| `pids_max` | `pids.max` | Process count limit |
| `cpu_quota_us` | `cpu.max` | CPU quota |

### Post-Run Stats

Memory peak, CPU user/system, throttled periods, PIDs current, OOM kill count.

Scope creation via `systemd-run --user --scope` or `oaie-priv` helper.

---

## Interactive PTY Mode

- PTY allocation via `posix_openpt` with `O_CLOEXEC`
- Only the specific slave file bind-mounted (no `/dev/ptmx`)
- Raw mode on supervisor terminal with RAII cleanup
- SIGWINCH forwarding for terminal resize
- TERM inherited from supervisor (sanitized: ASCII alphanumeric + `-_.`, max 64 chars)
- I/O threads: stdin->PTY and PTY->stdout+capture (tee pattern)
- Emergency exit: 3 rapid Ctrl+C presses within 2 seconds force-kills the child
  (hint printed after first press; first two forwarded normally)
- Slave-closed detection via `poll()` POLLHUP on PTY master (not zero-length write)

---

## Ed25519 Signing

- Keypair generation with `ed25519-dalek`
- Manifest signing: hash manifest bytes, sign with secret key
- Signature sidecar: `signature.toml` with public key, manifest hash, signature
- Key ID: first 8 hex chars of `BLAKE3(public_key_bytes)`
- Secret key zeroization via `zeroize` crate
- Key lookup by ID prefix or exact label

---

## Database Backends

### SQLite (default)

- WAL journal mode, foreign keys enabled, 5s busy timeout
- Schema version 4 with migration system
- Atomic transactions for run completion + artifact insertion

### PostgreSQL

- `postgresql://` connection URL
- Credential redaction in error messages
- `ADD COLUMN IF NOT EXISTS` migrations
- Same schema as SQLite

### Schema (4 tables)

- `runs`: run_id, created, command, exit_code, duration, isolation, status, manifest_hash
- `artifacts`: hash, run_id, label, artifact_type, size, created
- `sessions`: session_id, name, created, stopped, status, command, policy, budget_json, containment, llm_provider
- `session_calls`: call_id, session_id, run_id, seq, command, created, duration_ms, exit_code

---

## Agent Integration Library

### OaieClient

- `run(command)` — execute command with defaults
- `run_job(job_spec)` — full control execution
- `verify(run_id)` — verify run integrity
- `read_output(run_id, label)` — read artifact bytes
- `session_run(command, budget, policy)` — create and run session
- `session_status(session_id)` — query session state
- `session_stop(session_id)` — stop running session

### SessionClient

For agents running inside an OAIE session. Communicates via Unix domain socket.
Constructed from `OAIE_DISPATCH_SOCK`, `OAIE_SESSION_ID`, `OAIE_ARTIFACTS_DIR`
environment variables.

---

## MCP Server (Model Context Protocol)

6 tools exposed via JSON-RPC 2.0 over stdin/stdout:

| Tool | Description |
|------|-------------|
| `oaie_run` | Execute command in sandbox |
| `oaie_verify` | Verify run integrity |
| `oaie_read_output` | Read artifact (text or base64 binary) |
| `oaie_session_run` | Start agent session |
| `oaie_session_status` | Query session state |
| `oaie_session_stop` | Stop running session |

---

## Report Generation

Markdown `REPORT.md` with sections: summary table, network policy, artifacts,
output files, policy details, resource accounting, observed accesses (files
read/written, access denied, suspicious activity, DNS queries, network activity,
process tree), verification commands.

Markdown injection prevention: pipe/backslash/backtick escaping, newline
stripping, Unicode bidi override removal, process tree depth capping at 64.

---

## Auto-Mount Detection

Scans command arguments for existing file paths. Element 0 (executable) mounted
RO, arguments mounted RW. Files mount their parent directory. Skips flags,
system paths, deny-listed paths. Deduplicates and canonicalizes.

---

## Probe / Capability Detection

Cached per-process via `OnceLock`. Tests user namespace support with actual
`clone()` (not just sysctl reads). Container detection via `/.dockerenv`,
`/run/.containerenv`, cgroup patterns. Namespace headroom warning at 80%.

---

## Structured Output

`--output=json` produces `StructuredRunResult` with: run_id, exit_code, duration,
stdout/stderr refs, output artifacts, manifest hash, isolation summary, resource
stats, trace summary, store path.

Session equivalent: `StructuredSessionResult` with tool call results.

---

## Environment Variables

| Variable | Context | Description |
|----------|---------|-------------|
| `OAIE_RUN_ID` | Inside sandbox | UUID of current run |
| `OAIE_OUT` | Inside sandbox | Always `/out` |
| `OAIE_HOME` | Host | Store location override |
| `OAIE_LOG` | Host | Log level: error, warn, info, debug |
| `OAIE_NO_SIGNAL_HANDLERS` | Host/test | Skip signal handler installation |
| `NO_COLOR` | Host | Suppress colored output and banner |
| `OAIE_DISPATCH_SOCK` | Inside session | Dispatch socket path |
| `OAIE_SESSION_ID` | Inside session | Session identifier |
| `OAIE_ARTIFACTS_DIR` | Inside session | Artifacts directory path |

---

## Feature Gates

| Feature | Description |
|---------|-------------|
| `ebpf` | eBPF tracer (<5% overhead vs ptrace) |
| `firecracker` | Firecracker microVM backend (KVM isolation) |

---

## Execution Backends

| Backend | Isolation | Tracing | Cgroups | Root Required |
|---------|-----------|---------|---------|---------------|
| `namespace` | Linux namespaces | ptrace, eBPF | Yes | No |
| `bare` | None | No | No | No |
| `firecracker` | KVM microVM | No | No | No (KVM group) |

---

## Build and Test

- `make` — build + clippy + test (default target)
- `make test` — multi-phase: parallel unit tests, then serial integration tests
- `make release` — release build
- Serial test categories: adversarial, sandbox, parity, trace, verify, signing,
  interactive, session, stress, v03_integration, backward_compat, runner_e2e
- 668 tests total
