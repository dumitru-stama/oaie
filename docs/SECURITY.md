# OAIE Security Model

OAIE is a security tool. Its purpose is to run untrusted commands inside
observable, verifiable sandboxes. This document describes the trust boundaries,
attack surface, defense layers, and known limitations.

## Trust Boundary Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          Host Kernel                                     │
│                                                                          │
│  ┌───────────────────────────────────────────────────────────────────┐   │
│  │  OAIE Supervisor (trusted)                                        │   │
│  │                                                                   │   │
│  │  ┌───────────┐  ┌───────────┐  ┌──────────┐  ┌───────────────┐  │   │
│  │  │  Runner   │  │  Tracer   │  │   CAS    │  │  Session      │  │   │
│  │  │           │  │(ptrace/   │  │  Store   │  │  Runner       │  │   │
│  │  │           │  │ eBPF)     │  │          │  │               │  │   │
│  │  └─────┬─────┘  └──────────┘  └──────────┘  └───────┬───────┘  │   │
│  │        │                                             │          │   │
│  │  ══════╪═══════════ TRUST BOUNDARY ══════════════════╪══════    │   │
│  │        │                                             │          │   │
│  │  ┌─────┴──────────────────────────────┐  ┌──────────┴───────┐  │   │
│  │  │  Namespace Sandbox                 │  │  Agent Sandbox   │  │   │
│  │  │  ┌──────────┐  ┌──────────────┐   │  │  (--sandbox-     │  │   │
│  │  │  │  Tool    │  │ seccomp BPF  │   │  │   agent)         │  │   │
│  │  │  │  Process │  │ Landlock     │   │  │  ┌────────────┐  │  │   │
│  │  │  │  (PID 1) │  │ cgroup v2    │   │  │  │  Agent     │  │   │
│  │  │  └──────────┘  └──────────────┘   │  │  │  Process   │  │   │
│  │  └────────────────────────────────────┘  │  └────────────┘  │  │   │
│  │                                          └──────────────────┘  │   │
│  └───────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  Firecracker MicroVM (optional)                                  │    │
│  │  ┌──────────────────────────────┐                                │    │
│  │  │  Guest Kernel                │                                │    │
│  │  │  ┌────────────────────────┐  │                                │    │
│  │  │  │  Tool Process          │  │                                │    │
│  │  │  └────────────────────────┘  │                                │    │
│  │  └──────────────────────────────┘                                │    │
│  └──────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────┘
```

The supervisor, tracer, CAS store, and session runner all run above the trust
boundary with full host access. Tool processes (and optionally agent processes)
run below the trust boundary inside sandboxes.

## Attack Surface Table

| Attack Vector | Mitigation | Residual Risk |
|---|---|---|
| **Syscall exploitation** | seccomp BPF: 14 KILL + 55 ERRNO syscalls | Allowed syscalls could have kernel bugs |
| **Filesystem escape** | User ns + mount ns + pivot_root + Landlock | Kernel mount namespace bugs |
| **Network escape** | Network ns + nftables + DNS proxy | Host kernel network stack bugs |
| **Capability abuse** | All caps dropped (only net_raw/net_bind_service retained if policy allows) | Retained caps have limited scope |
| **Resource exhaustion** | Cgroup v2 limits + rlimits + session budget | cgroups require kernel support |
| **Process tree escape** | PID namespace isolation | PID ns kernel bugs |
| **Signal injection** | IPC namespace + PID namespace | n/a |
| **Terminal injection** | TIOCSTI/TIOCLINUX blocked via ioctl seccomp inspection | Other ioctl attacks unknown |
| **Credential theft** | 24 default deny paths (SSH, GPG, cloud, etc.) + Landlock | Custom credential locations |
| **Fileless execution** | `memfd_create`/`execveat` blocked by default (EPERM via seccomp) | Allowed when `allow_memfd = true` |
| **Trace tampering** | Hash-chained NDJSON in CAS, tracer runs outside sandbox | eBPF inside VM has reduced integrity |
| **Manifest tampering** | Ed25519 signing, CAS content-addressing | Key management is user's responsibility |
| **Agent crash/hang** | Heartbeat mechanism, wall-clock timeout | Agent could consume resources silently |
| **Dispatch socket abuse** | 1 MiB request size cap, max_concurrent_tools=1 | Agent controls dispatch rate |
| **Path traversal** | Input path validation rejects `..` components | n/a |
| **DNS-based escape** | Pre-resolution on host, DNS proxy filtering, TLS SNI verification | DNS rebinding within TTL |
| **Fork bomb** | RLIMIT_NPROC (default 64) + cgroup pids.max | System-level PID exhaustion unlikely |

## Sandbox Layers

OAIE employs 8 independent defense layers. Each layer is designed to function
even if other layers are compromised (defense-in-depth).

### 1. User Namespace

`CLONE_NEWUSER` creates a new user namespace where the process runs as UID/GID
65534 (nobody). UID/GID maps are written by the parent before the child starts
executing. No `setuid` binaries work inside the namespace.

### 2. Mount Namespace

`CLONE_NEWNS` with `pivot_root` creates a minimal filesystem:

- tmpfs root with selective bind mounts
- `/in` (read-only input directory)
- `/out` (read-write output directory)
- `/proc` with dangerous paths masked (oom_score_adj, oom_adj, attr, io, net, tty, smaps)
- Minimal `/dev` (null, zero, urandom, random)
- System directories read-only (/usr, /lib, /lib64, /bin, /sbin)
- Credential paths denied by default (24 paths: SSH, GPG, AWS, GCloud, Docker, Kube, etc.)

### 3. PID Namespace

`CLONE_NEWPID` gives the tool its own process ID space. The tool runs as PID 1
inside its namespace. It cannot see or signal any host processes. Zombie cleanup
is handled by the supervisor.

### 4. Network Namespace

`CLONE_NEWNET` creates a completely isolated network stack. Three sub-modes:

- **Off**: Empty namespace, only loopback (auto-configured).
- **Allowlist**: veth pair with nftables filtering and DNS proxy.
- **On**: No network namespace (shares host network).

### 5. Seccomp BPF

A BPF program loaded via `seccomp(SECCOMP_SET_MODE_FILTER)` filters syscalls
in two tiers:

- **KILL tier (14 syscalls)**: Immediately terminates the process. Includes
  `kexec_load`, `init_module`, `finit_module`, `delete_module`, `reboot`,
  `swapon`, `swapoff`, `mount`, `umount2`, `pivot_root`, `ptrace`,
  `process_vm_readv`, `process_vm_writev`, `userfaultfd`.

- **ERRNO tier (55+ syscalls)**: Returns EPERM. Includes `unshare`, `setns`,
  `clone3` (with namespace flags), `memfd_create`, `execveat` (unless
  `allow_memfd`), `fspick`, `move_mount`, `open_tree`, `syslog`,
  `statmount`, `listmount`, and more.

- **Argument inspection**: `socket()` blocks 11 address families
  (AF_PACKET, AF_ALG, AF_VSOCK, AF_XDP, AF_BLUETOOTH, AF_NETLINK, AF_CAN,
  AF_TIPC, AF_NFC, AF_KCM, AF_QIPCRTR). `prctl()` blocks 6 dangerous
  operations. `ioctl()` blocks TIOCSTI and TIOCLINUX.

### 6. Landlock

Landlock LSM (ABI v1-v3, kernel 5.13+) provides filesystem restrictions as a
second layer on top of mount namespace isolation. Even if a mount namespace bug
allows escape, Landlock independently restricts filesystem access.

### 7. Cgroup v2

Per-run cgroup scopes provide kernel-enforced resource limits:

| Limit | Controller | Default |
|---|---|---|
| `memory.max` | memory | From policy `max_memory` |
| `pids.max` | pids | From policy `max_pids` |
| `cpu.max` | cpu | From policy `cpu_quota` (if set) |

Cgroup scopes are created via `systemd-run --user --scope` (preferred) or the
`oaie-priv` helper. The child PID is assigned to the cgroup between UID/GID
map writes and the sync pipe release, ensuring the child is in the cgroup
before it starts executing.

### 8. Capability Drop

All Linux capabilities are dropped by default. Only two may be retained via
policy allowlist:

- `CAP_NET_RAW` (bit 13): ICMP ping and raw sockets
- `CAP_NET_BIND_SERVICE` (bit 10): Bind ports below 1024

All other capabilities are rejected during policy validation.

## Signing and Attestation

OAIE supports Ed25519 manifest signing for remote attestation.

### Key Management

```bash
# Generate a signing key
oaie key generate --label "work-laptop"

# List keys
oaie key list

# Export public key (for verifiers)
oaie key export <key-id>

# Delete a key
oaie key delete <key-id>
```

Keys are stored as TOML files under `<store>/keys/<key-id>.toml` with 0o600
permissions. The key ID is the first 8 hex characters of `BLAKE3(public_key_bytes)`.

### Sidecar Design

Signatures are stored in a `signature.toml` sidecar alongside the manifest,
not embedded in the manifest itself. This avoids a circular dependency (the
manifest hash would change if it contained its own signature).

```
run-dir/
  manifest.toml       ← the signed data
  signature.toml      ← Ed25519 signature + public key + metadata
```

### Signature Contents

```toml
version = 1
algorithm = "ed25519"
public_key = "3b6a27bc..."   # 32 bytes, hex
signer_label = "work-laptop"
hash_algorithm = "blake3"
manifest_hash = "7d3f8a..."  # HASH(manifest.toml bytes)
signature = "9e2b4c..."      # Ed25519(manifest_hash_bytes), 64 bytes hex
signed_at = "2026-03-04T10:15:30Z"
```

### Signing a Run

```bash
# Sign with default key (configured in config.toml)
oaie run --sign -- ./tool

# Sign with a specific key
oaie run --sign=<key-id> -- ./tool
```

### Verifying a Signature

```bash
oaie verify <run-id>
# CheckKind::ManifestSignature verifies Ed25519(manifest_hash)
```

Verification check #12 (`ManifestSignature`) reads the sidecar, recomputes the
manifest hash, and verifies the Ed25519 signature against the embedded public
key. The check is skipped if no signature sidecar exists.

## Budget as DoS Prevention

Session budgets serve as a defense against denial-of-service attacks from
runaway or malicious agents:

| Budget Field | DoS Prevention |
|---|---|
| `max_tool_calls` | Prevents unbounded command spawning |
| `max_wall_time_s` | Prevents indefinite session occupation |
| `max_tool_time_s` | Prevents single slow tools from consuming all time |
| `max_output_bytes` | Prevents disk filling via tool outputs |
| `max_network_bytes` | Prevents bandwidth abuse (nftables counters) |
| `max_agent_output_bytes` | Prevents agent stdout/stderr flooding |

All limits emit warnings at 80% usage (via `BudgetWarning` events) and hard-
stop at 100%. The wall-clock timeout is enforced independently of tool execution
via the session runner's main loop.

## Known Limitations

1. **Shared kernel**: The namespace sandbox shares the host kernel. A kernel
   exploit in an allowed syscall could escape all user-space defenses. Use the
   Firecracker backend for kernel-level isolation against this threat.

2. **eBPF trace integrity in VMs**: When using eBPF tracing inside a Firecracker
   VM, the trace is produced inside the VM trust boundary (`trace_integrity =
   "reduced"`). A compromised tool could theoretically interfere with tracing.

3. **No MAC (SELinux/AppArmor) integration**: OAIE does not configure SELinux
   or AppArmor profiles. It relies on its own Landlock + seccomp layers.

4. **DNS rebinding**: In allowlist mode, DNS resolution happens before the
   sandbox starts. A time-of-check/time-of-use gap exists if DNS records
   change between resolution and tool execution.

5. **Credential path coverage**: The 24 default deny paths cover common
   credential locations. Custom applications storing secrets in non-standard
   paths require explicit deny rules in the policy.

6. **Seccomp architecture**: BPF filters are architecture-specific. OAIE
   generates filters for x86_64 and aarch64. Other architectures are not
   supported.

7. **`oaie-priv` privileges**: The privileged helper requires `CAP_SYS_ADMIN`
   for cgroup creation and `CAP_BPF` + `CAP_PERFMON` for eBPF. These are
   powerful capabilities that expand the attack surface of the helper binary.
   The helper is minimal (<500 lines) with audit logging to mitigate this risk.

8. **Agent dispatch rate**: The session runner caps concurrent tool calls
   (default: 1) but does not rate-limit dispatch requests. A malicious agent
   could send rapid requests within budget limits.
