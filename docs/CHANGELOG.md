# Changelog

## v0.2.0 (2026-05-02)

### Security fixes

- **Signature verification trust anchor**: `verify_signature` now returns `VerifyOutcome` (`Trusted` / `UntrustedKey` / `BadSignature` / `NoTrustStore`) instead of `bool`. The previous bool conflated "no trust store configured" with "trusted" — both returned `true`, letting self-attesting signatures pass verification. Pass status now requires the signing public key to be in `SigningConfig.trusted_public_keys`; an empty trust list yields `Skip`, and an unknown key yields `Fail`.
- **Network policy IPC hardening**: `SetupNetns` no longer accepts a caller-supplied `nft_script: String`. The unprivileged client sends a typed `Vec<NetAllowRule>` (resolved IPs or canonical CIDR + port + protocol enum), and `oaie-priv` reconstructs the nft batch on the privileged side. New explicit validation in `oaie-priv/src/validate.rs`: protocol must be `tcp`/`udp`, port nonzero, exactly one of `addrs`/`cidr` set, CIDR fully parsed (not charset-only), `MAX_ALLOW_RULES = 256`, `MAX_ADDRS_PER_RULE = 64`, plus interface-name and subnet validators.
- **MCP `oaie_session_stop` removed**: Sessions are operator-CLI-managed; the MCP caller has no session it could legitimately stop. The handler now returns `METHOD_NOT_FOUND` so spec-compliant clients see the tool as nonexistent. Operators continue to use `oaie session stop` on the host.
- **Interactive bind-mount validation**: `oaie run -i` now rejects `--bind-ro/--bind-rw/--bind-exec` paths under `/proc`, `/sys`, `/dev`, `/boot`, `/root`, `/etc`, `/var/run` (with carve-outs for `/etc/ssl`, `/etc/ca-certificates`, `/etc/alternatives`, `/etc/java*`, `/etc/ld.so*`, `/etc/localtime`, `/etc/timezone`). Previously these flags were silently dropped.
- **CgroupMode::Require enforced in interactive backend**: When the policy demands cgroup isolation, interactive mode now fails closed if neither `systemd-run` nor `oaie-priv` can create the scope. Previously `-i` could fall through to rlimits-only.

### Features

- **Identity-path bind mounts**: New `--bind-ro <PATH>`, `--bind-rw <PATH>`, `--bind-exec <PATH>` flags on `oaie run`. Mount a host path at the SAME path inside the sandbox (bwrap-style), distinct from `--ro`/`--rw` which map to `/mnt/ro{i}` / `/mnt/rw{i}`. Use when the command literally references host paths (pre-built JSON envelopes with absolute paths, `sh -c 'executor < /host/scratch/input.json'`). `--bind-ro` is NOEXEC; `--bind-exec` drops NOEXEC for the narrow case of an external executor binary; `--bind-rw` cannot be combined with exec.
- **Policy-configurable `max_files`**: New `[limits].max_files` field (RLIMIT_NOFILE soft; hard = 4× soft). Default 1024. Preset values: `agent-build` and `agent-analyze` raise to 4096 (rustc/cargo, JVM-style classpaths), `contained-strict` lowers to 256.

### Preset adjustments

- `agent-safe`: `max_memory` 256M → 1G (RLIMIT_AS headroom for pthread/library mmaps). `max_pids` 64 → 512. The kuid-keyed RLIMIT_NPROC counter is shared across the operator's process tree, so the limit must clear the operator's working set plus a job's thread burst while staying a fork-bomb defense.
- `agent-net`: `max_pids` 64 → 256.
- `agent-analyze`: `max_memory` 1G → 12G, `max_time` 15m → 45m (sized for JVM-style analysis workloads).

### Notes

- Version number is `0.2.0` (down from the prior `0.3.x` working numbers in this changelog) — the `0.3.x` entries below describe an earlier development line that was not part of the released sequence.

## v0.3.9 (2026-03-04)

### Features — Phase Q: Gap Fixes & Documentation

- **SO_PEERCRED on dispatch socket**: Verify connecting process PID matches spawned agent PID via `getsockopt(SO_PEERCRED)`. Rejects connections from unexpected processes with a warning.
- **Concurrent tool call semaphore**: `max_concurrent_tools` field on `SessionConfig` (default 1). Defense-in-depth: rejects tool dispatch if active tools already at limit.
- **Agent output rate limiting**: `max_agent_output_rate` budget field (bytes/sec, 0 = unlimited). Tee threads track per-second byte windows and kill agent on sustained flood.
- **Per-tool workspace merging**: After each tool execution, output artifacts are copied into a shared `workspace/` directory in the session dir. Later tools overwrite on name conflict.
- **`oaie session profiles`**: List all containment profiles or show detail for a specific profile (`--show <name>`).
- **`oaie clean --auto`**: Automatic cleanup with sensible defaults (removes runs older than 7 days).
- **CAS store stats in inspect**: `oaie inspect` shows CAS object count and total size, warns if > 1 GiB.
- **Documentation**: SESSIONS.md, CONTAINMENT.md, NETWORK.md, TRACING.md, SECURITY.md — comprehensive guides covering session mode, containment profiles, network policy, tracing/verification, and security model.
- **Example agents**: 3 new Python agent scripts in `examples/sessions/` — local RE agent, cloud build agent, interactive agent with approval handling.
- **Backward compatibility tests**: 6 tests validating v0.2 manifests/policies parse correctly with v0.3 code.
- **v0.3 integration tests**: 8 tests covering session lifecycle, budget enforcement, event chain verification, containment profiles, tool filtering, and heartbeat timeout.
- **Tests**: 14 new tests, 668 total.

## v0.3.8 (2026-03-04)

### Features — Phase P: Integration & Release

- **MCP session tools**: `oaie_session_run`, `oaie_session_status`, `oaie_session_stop` — manage sessions via MCP JSON-RPC protocol. Follow existing `handle_run()` pattern.
- **`SessionClient` library**: Typed Rust client for agents running inside OAIE sessions. `from_env()` reads dispatch socket path, session ID, and artifacts directory from environment. `dispatch()` and `dispatch_with_inputs()` send tool calls via Unix socket.
- **`OaieClient` session methods**: `session_run()`, `session_status()`, `session_stop()` for programmatic session management from external code.
- **Stress tests**: 6 stress tests exercising rapid sequential tool calls (50×), concurrent sessions (3×), agent crash recovery, path traversal rejection, output tracking, and oversized request handling.
- **Tests**: 6 new stress tests, 654 total.

## v0.3.7 (2026-03-04)

### Features — Phase O: Full Agent Containment

- **`--sandbox-agent` flag**: Run the agent process itself inside a namespace sandbox. Moves from "tools sandboxed, agent trusted" to "everything sandboxed." `AgentProcess` enum abstracts host (`std::process::Child`) and sandboxed (`nix::unistd::Pid`) agent processes.
- **Sandboxed agent spawning**: Uses `spawn_sandboxed()` with `SessionMount` to bind-mount dispatch socket (`/oaie/dispatch.sock`) and artifacts directory (`/oaie/artifacts`) into the agent sandbox.
- **Mediated I/O**: `WireMessage` envelope type supports `DispatchRequest`, `DispatchResponse`, `AgentOutput`, and `UserInput`. Backward compatible with legacy messages.
- **Approval gates**: `--require-approval` flag prompts user before each tool execution. `ApprovalPolicy`, `ApprovalRequired`, and `ApprovalResult` event types.
- **`oaie session attach`**: Shell into a running sandboxed session via `nsenter`. Requires `AgentSandboxMode::Sandboxed`.
- **Agent network by containment profile**: `ContainmentProfile::agent_network_mode()` and `agent_network_for_provider()` control agent network access. Cloud/Interactive → On, Local/Strict → Off. Provider narrowing for anthropic/openai/google endpoints.
- **Tests**: 8 new tests, 647 total.

## v0.3.6 (2026-03-04)

### Features — Phase N: Advanced Budget & Policy

- **`max_network_bytes` budget**: Network transfer tracking via nftables byte counters. Counter clause in accept rules, `read_byte_counters()` for accumulation.
- **Tool allowlist/denylist**: `--allow-tools` and `--deny-tools` CLI flags. `ToolFilter` with glob matching on command basename. Deny takes precedence.
- **Per-tool network denial**: `--deny-net-tools` flag forces `NetworkMode::Off` for matching commands while other tools retain network access.
- **`max_agent_output_bytes` budget**: Limits agent stdout/stderr via counting tee threads. Agent killed when limit exceeded.
- **Tests**: 10 new tests, 639 total.

## v0.3.5 (2026-03-04)

### Features — Phase M: Session Extensions

- **`oaie session log <id>`**: Raw event log viewer with `--type` filter (all/tool_call/budget/io).
- **`oaie session extend <id>`**: Mid-session budget extension via file-based signaling. Can revive `BudgetExhausted` sessions. `--add-tools`, `--add-wall`, `--add-output` flags.
- **Recursive session verification**: `oaie verify --session <id>` verifies event chain integrity AND all nested run chains. 7 new `CheckKind` variants.
- **Heartbeat mechanism**: `--heartbeat=<seconds>` watchdog timer. Sessions transition to `HeartbeatTimeout` when no activity received within interval.
- **Input artifact support**: `DispatchRequest.inputs` now functional. Files validated, copied to session directory, and passed as `job.inputs` to sandboxed tool calls.
- **trace_hash in ToolResult events**: Links session events to per-run trace chains.
- **Resource stats snapshots**: Periodic `ResourceSnapshot` events every 30 seconds with budget usage timeline.
- **Tests**: 16 new tests, 586 total.

## v0.3.4 (2026-03-04)

### Features — Phase L: Containment Policy Profiles

- **`--contained` flag on `oaie session run`**: Select a pre-built containment profile that bundles per-tool sandbox policy and session-level resource budget into a single ergonomic flag. Four profiles available: `local`, `cloud`, `strict`, `interactive`.
- **Profile: `local`**: For local LLM agents (ollama, llama.cpp, vLLM). Generous per-tool limits (1G memory, 10m timeout, 128 PIDs, memfd allowed). Session budget: 100 tool calls, 1h wall time, 30m tool time, 2GB output.
- **Profile: `cloud`**: For cloud LLM agents (Claude, GPT). Moderate per-tool limits (512M memory, 5m timeout, 64 PIDs). Session budget: 50 tool calls, 30m wall time, 10m tool time, 1GB output.
- **Profile: `strict`**: Maximum restriction. Tight per-tool limits (128M memory, 1m timeout, 32 PIDs). Session budget: 20 tool calls, 10m wall time, 5m tool time, 256MB output.
- **Profile: `interactive`**: Human-in-the-loop. Generous budget (200 tool calls, 2h wall time, 1h tool time, 2GB output) with same per-tool limits as `local`.
- **`--llm` metadata flag**: Records LLM provider (`anthropic`, `openai`, `google`, `local`, `custom`) in session DB and manifest. Informational only — does not affect per-tool network (tools don't call LLM APIs; the unsandboxed agent does).
- **Mutual exclusivity**: `--contained` and `--policy` cannot be combined (error). Individual `--budget-*` flags override profile defaults. `--net` overrides per-tool network.
- **4 new policy presets**: `contained-local`, `contained-cloud`, `contained-strict`, `contained-interactive` — available via `oaie policy list/show` and `--policy=<name>`.
- **DB schema v4**: `containment` and `llm_provider` nullable TEXT columns on `sessions` table. Auto-migrated on first access.
- **Session manifest**: Optional `[session.agent]` section with `containment` and `llm_provider` fields.
- **Display**: `oaie session list` shows CONTAINED column. `oaie session status/inspect` show Containment and LLM provider fields.
- **Structured output**: `StructuredSessionResult.containment` and `StructuredSessionResult.llm_provider` fields.
- **Integration examples**: `examples/sessions/` (3 shell scripts + Python agent) and `examples/policies/` (2 TOML files).
- **Tests**: 10 new containment tests, 567 total.

## v0.3.3 (2026-03-04)

### Features — Phase K: Session Mode (Persistent Agent Sandboxes)

- **`oaie session run`**: Host a long-running agent process in a managed session. The agent communicates tool calls via a Unix domain socket (`dispatch.sock`), and each tool call becomes a standard OAIE run with its own sandbox, manifest, and DB record.
- **Wire protocol**: JSON newline-delimited over Unix socket. Agent sends `DispatchRequest` (command, inputs, timeout), supervisor returns `DispatchResponse` (run_id, exit_code, outputs, duration, error).
- **Resource budgets**: `--budget-tools`, `--budget-wall`, `--budget-tool-time` flags enforce hard limits. 80% warning events emitted before exhaustion. Budget-exhausted sessions reject further tool calls.
- **`oaie session list`**: List active and recent sessions with status, call count, and creation time.
- **`oaie session status <id>`**: Show session state and budget consumption (used / max).
- **`oaie session stop <id>`**: Gracefully stop a running session.
- **`oaie session inspect <id>`**: Detailed session report with all tool calls, budget usage, and manifest hash.
- **Hash-chained event log**: Session events (start, stop, tool dispatch/result, budget warnings) stored as NDJSON in CAS with BLAKE3/SHA-256 hash chain for tamper evidence.
- **Session manifest**: `session_manifest.toml` stored in session directory and CAS with full call history, budget config, stats, and event chain tip.
- **DB schema v3**: `sessions` and `session_calls` tables with FK references to `runs`. Schema auto-migrated on first access.
- **`SessionMount`**: New sandbox mount type for bind-mounting sockets and directories into namespaces (prepared for future full-sandbox agent mode).
- **Structured output**: `StructuredSessionResult` and `StructuredCallResult` types in `oaie-core` for machine-readable session output.
- **Tests**: 15 new session tests (7 unit/DB + 8 integration), 557 total.

## v0.3.2 (2026-03-04)

### Features — Phase J: Remote Attestation (Ed25519 Manifest Signing)

- **Ed25519 signing keys**: `oaie key generate [--label <name>]` creates Ed25519 keypairs stored at `<store>/keys/<key_id>.toml` with 0o600 permissions. Key ID is first 8 hex chars of BLAKE3(public_key).
- **`oaie key list/delete/export`**: Full key lifecycle management. `export --public` outputs public key only for sharing.
- **`--sign` flag on `oaie run`**: Signs the manifest after execution. Sidecar `signature.toml` stored alongside `manifest.toml` — avoids circular hash dependency.
- **Config default key**: `[signing].default_key` in `config.toml` auto-signs all runs without `--sign`.
- **Verification check #12 (ManifestSignature)**: `oaie verify` now checks 12 integrity properties. Pass (valid signature), Skip (unsigned run), or Fail (tampered manifest / invalid signature).
- **Inspect**: Shows "Signed by: <label> (<pubkey_short>..)" for signed runs.
- **Export**: Archives include `signature.toml` when present.
- **Doctor probe #20**: "Signing key" reports key count and default configuration status.
- **Structured output**: `IsolationSummary.signed_by` field in JSON output.
- **New types**: `SigningAlgorithm`, `SignatureInfo`, `KeyInfo` in `oaie-core/src/signing.rs` (pure data, no crypto deps). `ArtifactType::Signature` variant.
- **Crypto**: `ed25519-dalek` + `rand` for signing operations in `oaie-cli/src/signing.rs`.
- **Tests**: 18 new signing tests (12 unit + 6 integration), 542 total.

## v0.3.1 (2026-03-04)

### Features — Phase I: Interactive PTY Mode

- **`-i` / `--interactive` flag**: Allocates a pseudoterminal for the sandboxed process, enabling full terminal app support (vim, nano, htop, less, top) inside the sandbox while maintaining all isolation guarantees.
- **PTY allocation** (`oaie-sandbox/src/pty.rs`): Raw libc PTY allocation via `posix_openpt()`, `grantpt()`, `unlockpt()`, `ptsname_r()`. Window size control via `TIOCSWINSZ` ioctl.
- **Terminal raw mode** (`oaie-sandbox/src/terminal.rs`): `RawModeGuard` RAII guard saves/restores terminal state. `enter_raw_mode()` disables echo and canonical mode for pass-through.
- **Interactive sandbox spawn** (`spawn_sandboxed_interactive()`): Same namespace/seccomp/Landlock isolation as `spawn_sandboxed()`, but allocates a PTY pair. Child gets controlling terminal via `setsid()` + `TIOCSCTTY`. `TERM` env var inherited from supervisor.
- **Interactive backend** (`oaie-cli/src/backend_interactive.rs`): Two I/O threads (stdin→PTY master, PTY master→stdout+capture). SIGWINCH forwarding via `AtomicU64` counter pattern. PTY output captured to CAS for the manifest.
- **Manifest and report**: `IsolationInfo.interactive` and `IsolationSummary.interactive` fields. "Interactive: yes (PTY)" shown in report, inspect, and CLI summary.
- **Incompatibility checks**: `-i` errors with `--quiet`, `--output=json`, `--backend=bare`, `--backend=firecracker`.
- **Security**: PTY slave is a new terminal device in the child's session. TIOCSTI on the slave pushes into the master's read buffer — supervisor reads as data, never executes. Same model as `docker run -it`.

## v0.1.5 (2026-03-01)

### Features — Concurrency Hardening (500 concurrent sandbox instances)

- **Ptrace signalfd**: Replaced 100μs busy-wait in `PtraceTracer::run()` with `signalfd(SIGCHLD)` + `poll()`. Each traced sandbox no longer burns a full CPU core when idle.
- **Runner signalfd**: Applied same `signalfd` + `poll()` pattern to the non-traced `waitpid` polling loops in `spawn_sandboxed_and_capture()`.
- **Signal counter**: Replaced global `AtomicBool` with monotonic `AtomicU64` counter + `Once` for handler installation. Concurrent runners no longer interfere — each captures a baseline and checks if the counter advanced.
- **DB batch transactions**: Added `complete_run_with_artifacts()` that commits run completion + all artifact inserts in a single `BEGIN IMMEDIATE` transaction. Reduces SQLite lock acquisitions from N+2 to 2 per run.
- **Probe caching**: `SystemCaps::detect()` now caches results in `OnceLock`. Avoids 500 redundant `clone(CLONE_NEWUSER)` + `waitpid` probes at startup.
- **RLIMIT_NPROC default 64**: Lowered from 128 to 64. 500 sandboxes × 64 = 32K processes, well under typical system limits. Tools needing more already specify `max_pids` in policy.
- **CAS temp cleanup with age filter**: `cleanup_temps()` now skips files newer than 1 hour (concurrent writers). `cleanup_temps_all()` (no filter) for `oaie init`. Both called from `Runner::new()`.
- **Stale sandbox dir cleanup**: `Runner::new()` scans `/tmp` for `oaie-root-*` directories older than 5 minutes and removes empty ones.
- **Namespace headroom warning**: New `current_user_ns` field in `SystemCaps` (from `/proc/sys/user/nr_user_namespaces`, kernel 6.7+). Warning logged and doctor probe #14 reports Degraded when usage exceeds 80%.
- **Enriched clone() errors**: `clone()` failure messages now include hints for ENOSPC (namespace exhaustion) and EPERM (AppArmor/SELinux).
- **Doctor probe #14**: Namespace headroom (current/max with percentage, degraded if >80%).

## v0.1.4 (2026-03-01)

### Features

- **Selective capability retention**: Policy-driven `capabilities` field in `[limits]` allows retaining specific Linux capabilities inside the sandbox. Only two safe capabilities are allowed: `net_raw` (CAP_NET_RAW for ICMP ping) and `net_bind_service` (CAP_NET_BIND_SERVICE for binding privileged ports). All other capabilities are rejected during validation.
- **`capability_mask()` helper**: Converts capability names to a 64-bit bitmask for the kernel capset API.
- **`set_caps()` replaces `drop_all_caps()`**: The sandbox now selectively retains capabilities instead of unconditionally zeroing all sets. Inheritable set stays zero so caps don't survive execve chains.
- **Selective prctl arg inspection**: `SYS_prctl` removed from the blanket ERRNO tier. A seccomp BPF argument-inspection block now allows safe prctl operations (PR_CAPBSET_READ, PR_SET_KEEPCAPS, PR_SET_NAME, etc.) while blocking 6 dangerous operations: PR_SET_DUMPABLE, PR_SET_SECCOMP, PR_SET_SECUREBITS, PR_SET_MM, PR_CAP_AMBIENT, PR_SET_PTRACER.
- **Automatic loopback setup**: When running in an isolated network namespace (`--net` omitted), the sandbox brings up the `lo` interface via ioctl before dropping capabilities. This allows `ping 127.0.0.1` with CAP_NET_RAW in the isolated namespace.
- **Doctor probe for `ping_group_range`**: New probe #13 checks the `net.ipv4.ping_group_range` sysctl. Reports Degraded with remediation hint when the range doesn't cover sandbox GID 65534 (needed for `ping` with `--net`).
- **`ping.toml` example policy**: Demonstrates CAP_NET_RAW retention for ICMP ping with network enabled.

### Notes

- **Ping with `--net` requires host sysctl**: When sharing the host network namespace, unprivileged ICMP sockets require `net.ipv4.ping_group_range` to include the sandbox GID (65534). Run `sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"` to enable. This only allows DGRAM ICMP echo requests — not SOCK_RAW.
- **Ping without `--net` works with CAP_NET_RAW**: In the isolated network namespace, the sandbox owns the namespace so CAP_NET_RAW is sufficient for `ping 127.0.0.1`.

## v0.1.3 (2026-03-01)

### Features

- **SHA-256 support**: `oaie init --sha256` selects SHA-256 for CAS, event chains, and verification. Algorithm is set at init and immutable. Both algorithms produce 32-byte digests.
- **`config.toml`**: store-level configuration persisted at `<store_root>/config.toml`. Contains `store_path`, `hash_algorithm`, artifact limits (`max_output_files`, `max_output_file_size`, `max_output_total`), and default timeouts (`default_timeout`, `max_timeout`).
- **Configurable artifact limits**: output collection limits are now configurable via `config.toml` instead of hardcoded constants.
- **Configurable timeouts**: site-wide `default_timeout` and `max_timeout` in `config.toml`. Default timeout used when no `--timeout` flag; max timeout clamps all runs.
- **Store path in config**: `store_path` records the canonical store root. On re-init, existing config's path is authoritative.
- **Legacy store migration**: stores without `config.toml` auto-migrate on first `open()` — BLAKE3 defaults are written.
- 283 tests, clippy clean

## v0.1.0 (2026-02-28)

Initial release.

### Features

- **Namespace isolation**: user, mount, PID, net, IPC, UTS, cgroup namespaces
- **Seccomp BPF**: 14 KILL-tier + 51 ERRNO-tier syscalls, multi-arch (x86_64/aarch64/riscv64)
- **Landlock**: filesystem restriction defense-in-depth (kernel 5.13+)
- **ptrace tracer**: syscall-level observation with process tree tracking
- **BLAKE3 hash chain**: tamper-evident event stream with chunked CAS storage
- **Content-addressed store**: all artifacts stored by BLAKE3 hash, two-level prefix dirs
- **Policy system**: TOML-based policies with safe/net presets, auto-mount detection
- **10 CLI commands**: init, run, check, inspect, verify, replay, gc, doctor, cas, completions
- **Structured doctor**: 12 diagnostic probes with remediation hints
- **Verify engine**: manifest, artifact, trace chain integrity checks (text/JSON output)
- **Replay**: reconstruct job from manifest, compare output hashes
- **GC**: mark-and-sweep with min-age protection and dry-run
- **Shell completions**: bash, zsh, fish, PowerShell
- **271 tests**, clippy clean

### Known Limitations

- eBPF tracer not yet implemented (ptrace only, v0.2)
- `io_uring` submissions bypass ptrace observation (detected and flagged)
- No interactive/PTY mode yet
- No remote attestation or signature verification
- Single-machine only (no distributed execution)
