# OAIE Execution Backends

OAIE supports three execution backends, each providing different isolation
guarantees. Choose based on your threat model and performance requirements.

## Comparison

| Feature | Bare | Namespace | Firecracker |
|---|---|---|---|
| **Isolation level** | None | Full (kernel-level) | MicroVM (hardware-level) |
| **Mechanism** | Process only | Linux namespaces + seccomp + Landlock | Firecracker KVM microVM |
| **Kernel boundary** | Shared | Shared | Separate kernel |
| **Syscall filtering** | No | seccomp BPF (14 KILL + 55 ERRNO) | Guest kernel + optional seccomp |
| **Filesystem isolation** | Working dir only | pivot_root + bind mounts | Separate rootfs image |
| **Network isolation** | Host network | Network namespace (blocked by default) | No network (VM-level) |
| **Resource limits** | Advisory (rlimits) | Cgroup v2 enforced | VM memory/vCPU limits |
| **Trace support** | No | ptrace + eBPF (full fidelity) | ptrace (reduced fidelity) |
| **Root required** | No | No (user namespaces) | No (needs /dev/kvm access) |
| **Startup overhead** | ~1ms | ~15ms | ~800ms |
| **Use case** | Trusted tools, debugging | Default production use | Untrusted tools, kernel exploit protection |

## Usage

```bash
# Default: namespace isolation (recommended)
oaie run -- /path/to/tool args...

# Bare: no isolation
oaie run --backend=bare -- /path/to/tool args...

# Firecracker: microVM isolation (requires setup)
oaie run --backend=firecracker -- /path/to/tool args...
```

## When to Use Which

### Bare (`--backend=bare`)

Use when:
- Running trusted, well-known tools (compilers, linters)
- Debugging sandbox issues
- The tool requires capabilities that sandboxing removes

Trade-offs:
- No protection against malicious or buggy tools
- No syscall filtering, no filesystem isolation
- Environment sanitized (env vars cleared) but no other protection

### Namespace (default, `--backend=namespace`)

Use when:
- Running untrusted or semi-trusted tools
- You need full-fidelity tracing (ptrace or eBPF)
- Production builds and CI/CD pipelines

Trade-offs:
- Strong isolation via kernel namespaces + seccomp + Landlock
- Same kernel as host — a kernel exploit could escape
- ~15ms startup overhead (negligible for most tools)
- Requires Linux 5.13+ with user namespaces enabled

### Firecracker (`--backend=firecracker`)

Use when:
- Running completely untrusted tools (downloaded binaries, CTF challenges)
- Kernel-level isolation is required (defense against kernel exploits)
- You need maximum isolation and accept reduced trace fidelity

Trade-offs:
- Hardware-enforced isolation via KVM — separate kernel and rootfs
- ~800ms fixed startup overhead (VM boot)
- Trace fidelity is "reduced" — ptrace runs inside the VM trust boundary
- Requires Firecracker binary, /dev/kvm, and guest assets
- Tool must be a static binary or available in the Alpine rootfs

## Trust Boundaries

```
┌─────────────────────────────────────────────┐
│                  Host Kernel                 │
│  ┌───────────────────────────────────────┐  │
│  │         OAIE Supervisor               │  │
│  │  ┌─────────────┐ ┌─────────────────┐ │  │
│  │  │  Namespace   │ │   Firecracker   │ │  │
│  │  │  Sandbox     │ │   MicroVM       │ │  │
│  │  │  ┌─────────┐ │ │  ┌───────────┐  │ │  │
│  │  │  │  Tool   │ │ │  │Guest Kern.│  │ │  │
│  │  │  │         │ │ │  │ ┌───────┐ │  │ │  │
│  │  │  │         │ │ │  │ │ Tool  │ │  │ │  │
│  │  │  └─────────┘ │ │  │ └───────┘ │  │ │  │
│  │  └─────────────┘ │  │ └───────────┘  │ │  │
│  │                   │  └─────────────────┘ │  │
│  └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

**Namespace**: Tool shares the host kernel. seccomp + namespaces prevent
most escape vectors, but a kernel vulnerability could be exploited.

**Firecracker**: Tool runs inside a separate kernel (guest). Even if the
tool exploits a kernel vulnerability, it only compromises the guest kernel.
The Firecracker VMM provides a minimal attack surface to the host.

## Trace Integrity

| Backend | Trace integrity | Explanation |
|---|---|---|
| Namespace | `full` | ptrace/eBPF run on the host, outside the sandbox |
| Firecracker | `reduced` | ptrace runs inside the VM (guest agent traces the tool) |

"Reduced" integrity means the trace is produced inside the VM trust
boundary. A compromised tool could theoretically interfere with the
tracing process inside the VM. The manifest records this honestly via
`trace_integrity = "reduced"`.

## Prerequisites

### Namespace (default)
- Linux kernel 5.13+ (for Landlock ABI v1+)
- User namespaces enabled (`sysctl kernel.unprivileged_userns_clone=1`)
- Check: `oaie doctor`

### Firecracker
- Firecracker binary (v1.0+)
- `/dev/kvm` accessible (KVM support, user in `kvm` group)
- Guest assets in `~/.oaie/firecracker/`:
  - `vmlinux` — uncompressed Linux kernel image
  - `rootfs.ext4` — minimal Alpine Linux root filesystem with oaie-guest
  - `oaie-guest` — static musl binary of the guest agent
- Setup: `oaie firecracker init --kernel <path> --rootfs <path> --guest <path>`
- Check: `oaie firecracker check`

## Performance

Measured on AMD Ryzen 9 7950X, Linux 6.8, NVMe SSD:

| Backend | `echo hello` | `gcc -c hello.c` | Notes |
|---|---|---|---|
| Bare | 2ms | 45ms | No isolation overhead |
| Namespace | 17ms | 60ms | +15ms sandbox setup |
| Firecracker | 820ms | 880ms | +800ms VM boot |

The Firecracker overhead is fixed (VM boot) — it's amortized for longer-running
tools but significant for sub-second operations.
