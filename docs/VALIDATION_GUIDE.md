# OAIE Validation Guide — Step-by-Step Feature Testing

This document provides a complete, step-by-step procedure to validate every
feature of OAIE. Tests are organized by functional area, from basic to
advanced. Each test has prerequisites, exact commands, and expected outcomes.

**Convention:**
- `$` = run on host
- `EXPECT:` = what you should see
- `VERIFY:` = how to confirm correctness
- **Requires:** at the top of each section lists what must be installed first

---

## Table of Contents

0.  [Component Installation Guide](#0-component-installation-guide)
1.  [Prerequisites & Environment Setup](#1-prerequisites--environment-setup)
2.  [Store Initialization & Configuration](#2-store-initialization--configuration)
3.  [Basic Command Execution](#3-basic-command-execution)
4.  [Output & Artifact Collection](#4-output--artifact-collection)
5.  [Namespace Sandbox Isolation](#5-namespace-sandbox-isolation)
6.  [Seccomp BPF Enforcement](#6-seccomp-bpf-enforcement)
7.  [Resource Limits (rlimits)](#7-resource-limits-rlimits)
8.  [Cgroup v2 Enforcement](#8-cgroup-v2-enforcement)
9.  [Capability Dropping & Retention](#9-capability-dropping--retention)
10. [Filesystem Isolation & Credential Denial](#10-filesystem-isolation--credential-denial)
11. [Environment Sanitization](#11-environment-sanitization)
12. [Network Isolation](#12-network-isolation)
13. [Network Allowlist Mode](#13-network-allowlist-mode)
14. [Ptrace Tracing](#14-ptrace-tracing)
15. [eBPF Tracing](#15-ebpf-tracing)
16. [Firecracker MicroVM Backend](#16-firecracker-microvm-backend)
17. [Interactive PTY Mode](#17-interactive-pty-mode)
18. [Ed25519 Signing & Attestation](#18-ed25519-signing--attestation)
19. [Verification & Integrity Checks](#19-verification--integrity-checks)
20. [Content-Addressed Store (CAS)](#20-content-addressed-store-cas)
21. [Database & Run Management](#21-database--run-management)
22. [Policy System](#22-policy-system)
23. [Session Mode — Basic](#23-session-mode--basic)
24. [Session Mode — Budgets](#24-session-mode--budgets)
25. [Session Mode — Containment Profiles](#25-session-mode--containment-profiles)
26. [Session Mode — Tool Filtering](#26-session-mode--tool-filtering)
27. [Session Mode — Agent Sandboxing](#27-session-mode--agent-sandboxing)
28. [Session Mode — Approval Gates](#28-session-mode--approval-gates)
29. [Session Mode — Budget Extension](#29-session-mode--budget-extension)
30. [Session Mode — Heartbeat & Crash Recovery](#30-session-mode--heartbeat--crash-recovery)
31. [MCP Server Integration](#31-mcp-server-integration)
32. [Agent Library (oaie-agent)](#32-agent-library-oaie-agent)
33. [Report Generation](#33-report-generation)
34. [Replay & Diff](#34-replay--diff)
35. [Export & Archival](#35-export--archival)
36. [Cleanup & Garbage Collection](#36-cleanup--garbage-collection)
37. [Doctor Diagnostics](#37-doctor-diagnostics)
38. [Structured JSON Output](#38-structured-json-output)
39. [Concurrency & Stress Testing](#39-concurrency--stress-testing)
40. [Backward Compatibility](#40-backward-compatibility)
41. [Automated Test Suite](#41-automated-test-suite)

---

## 0. Component Installation Guide

OAIE has several optional components. Not everything is needed for every
feature. This section explains how to install each component, and the feature
sections below list which components they need.

### 0.A — OAIE CLI (core — needed for everything)

```bash
$ cd path/to/oaie

# Build all workspace crates
$ cargo build --workspace --release

# Install the CLI to ~/.cargo/bin
$ cargo install --path crates/oaie-cli

# Initialize the store
$ oaie init

# Verify
$ oaie doctor
$ oaie --version
```

**System requirements:**
- Linux kernel 5.10+
- User namespaces enabled: `cat /proc/sys/kernel/unprivileged_userns_clone` must be `1`
  - If `0`: `sudo sysctl -w kernel.unprivileged_userns_clone=1`
- Rust toolchain (for building)
- gcc (for compiling C test programs in the seccomp tests)

### 0.B — oaie-priv (privileged helper — needed for cgroups and eBPF)

The `oaie-priv` helper is a small binary that runs with elevated capabilities.
It manages cgroup scopes and loads eBPF programs on behalf of unprivileged users.

```bash
# Build
$ cargo build -p oaie-priv --release
# OR with eBPF support:
$ cargo build -p oaie-priv --release --features ebpf

# Install to system path
$ sudo mkdir -p /usr/lib/oaie
$ sudo cp target/release/oaie-priv /usr/lib/oaie/
$ sudo chown root:root /usr/lib/oaie/oaie-priv
$ sudo chmod 755 /usr/lib/oaie/oaie-priv

# Set capabilities — pick one:

# For cgroups only:
$ sudo setcap cap_sys_admin=ep /usr/lib/oaie/oaie-priv

# For cgroups + eBPF:
$ sudo setcap cap_sys_admin,cap_bpf,cap_perfmon=ep /usr/lib/oaie/oaie-priv

# Verify
$ getcap /usr/lib/oaie/oaie-priv
# Expected: /usr/lib/oaie/oaie-priv cap_bpf,cap_perfmon,cap_sys_admin=ep

$ oaie doctor 2>&1 | grep -E "oaie-priv|Cgroup|eBPF"
```

**Note:** If your system uses systemd with user sessions (most desktop Linux),
cgroups work without oaie-priv via `systemd-run --user --scope`. The doctor
probe will tell you which method is available. oaie-priv is needed only when
systemd user sessions are not available, or for eBPF tracing.

**Audit log:** oaie-priv logs all actions to `/var/log/oaie-priv.log`. Create
it if it doesn't exist: `sudo touch /var/log/oaie-priv.log && sudo chmod 644 /var/log/oaie-priv.log`

### 0.C — eBPF BPF programs (needed for eBPF tracing)

eBPF tracing requires compiled BPF programs and the oaie-priv helper with
BPF capabilities.

```bash
# System packages needed
$ sudo apt install clang bpftool libbpf-dev   # Debian/Ubuntu
# OR
$ sudo dnf install clang bpftool libbpf-devel  # Fedora

# Compile BPF programs
$ cd path/to/oaie
$ make -C bpf

# Verify output
$ ls bpf/oaie_tracer.bpf.o
# Should exist. This gets embedded into oaie-priv at build time via include_bytes!

# Rebuild oaie-priv with eBPF support (after compiling BPF programs)
$ cargo build -p oaie-priv --release --features ebpf
$ sudo cp target/release/oaie-priv /usr/lib/oaie/
$ sudo setcap cap_sys_admin,cap_bpf,cap_perfmon=ep /usr/lib/oaie/oaie-priv

# Verify
$ oaie doctor 2>&1 | grep eBPF
```

**Kernel requirements:**
- Kernel 5.8+ (BPF ring buffer support)
- BTF enabled: `ls /sys/kernel/btf/vmlinux` must exist
  - Kernel must be built with `CONFIG_DEBUG_INFO_BTF=y`

### 0.D — Firecracker (needed for microVM backend)

Firecracker provides hardware-level isolation via KVM.

```bash
# 1. Install Firecracker binary
#    Download from https://github.com/firecracker-microvm/firecracker/releases
#    Place at one of these paths (searched in order):
#      $HOME/tools/firecracker
#      /usr/local/bin/firecracker
#      /usr/bin/firecracker
$ mkdir -p ~/tools
$ cp firecracker-v*-x86_64 ~/tools/firecracker
$ chmod +x ~/tools/firecracker

# 2. Ensure /dev/kvm access
$ ls -la /dev/kvm
# If permission denied, add yourself to the kvm group:
$ sudo usermod -a -G kvm $USER
# Then log out and log back in for group change to take effect

# 3. Build the guest agent (static musl binary — runs as PID 1 inside VM)
$ rustup target add x86_64-unknown-linux-musl   # one-time setup
$ cd path/to/oaie
$ make build-guest
# Produces: target/x86_64-unknown-linux-musl/release/oaie-guest

# 4. Build OAIE with Firecracker feature
$ make build-firecracker

# 5. You need a kernel image (vmlinux) and a root filesystem (rootfs.ext4).
#    These are typically built from the Firecracker getting-started guide.
#    Then initialize assets:
$ oaie firecracker init \
    --kernel /path/to/vmlinux \
    --rootfs /path/to/rootfs.ext4 \
    --guest target/x86_64-unknown-linux-musl/release/oaie-guest
# Assets are copied to ~/.oaie/firecracker/

# 6. Verify
$ oaie firecracker check
$ oaie firecracker boot-test   # boots a VM, runs echo, verifies roundtrip
$ oaie doctor 2>&1 | grep Firecracker
```

### 0.E — Network allowlist tools (needed for --net allow:... mode)

Network allowlist mode creates a filtered network namespace with nftables rules.

```bash
# Install required system packages
$ sudo apt install nftables util-linux iproute2   # Debian/Ubuntu
# OR
$ sudo dnf install nftables util-linux iproute    # Fedora

# Enable IP forwarding (required for NAT between namespaces)
$ sudo sysctl -w net.ipv4.ip_forward=1
# Make persistent:
$ echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-oaie.conf

# Optional: enable ping in sandbox (for CAP_NET_RAW)
$ sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"

# Verify
$ nft --version
$ nsenter --version
$ cat /proc/sys/net/ipv4/ip_forward   # must be 1

$ oaie doctor 2>&1 | grep -E "nftables|forwarding|nsenter"
```

### 0.F — MCP server (needed for AI agent framework integration)

```bash
$ cd path/to/oaie
$ make build-mcp
# Produces: target/debug/oaie-mcp (or target/release/oaie-mcp with --release)

# Verify
$ echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' \
  | timeout 5 oaie-mcp 2>/dev/null | head -1
# Should return JSON with server capabilities
```

### 0.G — Python 3 (needed for session mode agent tests)

Most session mode tests use small Python scripts as test agents.

```bash
$ python3 --version
# Any Python 3.7+ works. No pip packages needed — only stdlib (socket, json, os).
```

---

### Dependency Matrix — What Each Feature Section Needs

| Section | Feature | Required Components |
|---------|---------|---------------------|
| 2 | Store init | A |
| 3 | Basic execution | A |
| 4 | Output collection | A |
| 5 | Namespace isolation | A |
| 6 | Seccomp BPF | A, gcc |
| 7 | rlimits | A |
| 8 | Cgroup v2 | A, B (or systemd user session) |
| 9 | Capabilities | A |
| 10 | Filesystem isolation | A |
| 11 | Environment sanitization | A |
| 12 | Network isolation | A |
| 13 | Network allowlist | A, E, internet access |
| 14 | Ptrace tracing | A |
| 15 | eBPF tracing | A, B (with eBPF caps), C |
| 16 | Firecracker VM | A, D |
| 17 | Interactive PTY | A |
| 18 | Ed25519 signing | A |
| 19 | Verification | A |
| 20 | CAS | A |
| 21 | DB & run management | A |
| 22 | Policy system | A |
| 23-30 | Session mode | A, G |
| 31 | MCP server | A, F |
| 32 | Agent library | A |
| 33-35 | Report, replay, export | A |
| 36 | Cleanup | A |
| 37 | Doctor | A (shows status of B, C, D, E) |
| 38 | JSON output | A |
| 39 | Stress testing | A, G |
| 40-41 | Compat & test suite | A |

**Legend:** A = OAIE CLI, B = oaie-priv, C = eBPF BPF programs, D = Firecracker,
E = nftables + nsenter + IP forwarding, F = MCP server, G = Python 3

---

## 1. Prerequisites & Environment Setup

**Requires: A (OAIE CLI)**

### 1.1 Build the project

```bash
$ cd path/to/oaie
$ make
```

EXPECT: Build succeeds, clippy clean, 668 tests pass.

### 1.2 Verify kernel requirements

```bash
$ uname -r
```

EXPECT: 5.10 or higher.

```bash
$ cat /proc/sys/kernel/unprivileged_userns_clone
```

EXPECT: `1` (user namespaces enabled).

### 1.3 Check PATH

```bash
$ which oaie
```

If not found, add to PATH:

```bash
$ export PATH="$PWD/target/release:$PATH"
```

### 1.4 Create a clean test workspace

```bash
$ export OAIE_TEST_DIR=$(mktemp -d /tmp/oaie-validation-XXXXXX)
$ cd $OAIE_TEST_DIR
$ mkdir -p input output
$ echo '#include <stdio.h>' > input/hello.c
$ echo 'int main() { printf("hello\\n"); return 0; }' >> input/hello.c
$ echo "test data" > input/data.txt
```

---

## 2. Store Initialization & Configuration

**Requires: A (OAIE CLI)**

### 2.1 Initialize with BLAKE3 (default)

```bash
$ export OAIE_HOME=$OAIE_TEST_DIR/store-blake3
$ oaie init
```

EXPECT: `OAIE: Store initialized at ...`
VERIFY:
```bash
$ cat $OAIE_HOME/config.toml
```
Should show `hash_algorithm = "blake3"`, `version = 1`.

### 2.2 Initialize with SHA-256

```bash
$ export OAIE_HOME=$OAIE_TEST_DIR/store-sha256
$ oaie init --sha256
```

VERIFY:
```bash
$ cat $OAIE_HOME/config.toml | grep hash_algorithm
```
EXPECT: `hash_algorithm = "sha256"`

### 2.3 Re-init with different algorithm is rejected

```bash
$ oaie init --sha256   # already BLAKE3
```

EXPECT: Error about algorithm mismatch.

### 2.4 Re-init same algorithm is idempotent

```bash
$ export OAIE_HOME=$OAIE_TEST_DIR/store-blake3
$ oaie init
```

EXPECT: Success (no error).

### 2.5 Custom store path

```bash
$ oaie init --path $OAIE_TEST_DIR/custom-store
```

EXPECT: Store created at the specified path.

### 2.6 Switch back to BLAKE3 store for remaining tests

```bash
$ export OAIE_HOME=$OAIE_TEST_DIR/store-blake3
```

---

## 3. Basic Command Execution

**Requires: A (OAIE CLI)**

### 3.1 Simple echo

```bash
$ oaie run -- echo "hello world"
```

EXPECT: `hello world` on stdout. OAIE banner on stderr. Exit code 0.

### 3.2 Non-zero exit code

```bash
$ oaie run -- false
$ echo $?
```

EXPECT: Exit code 1 (propagated from `false`).

### 3.3 Nonexistent binary

```bash
$ oaie run -- /usr/bin/nonexistent_binary_12345
```

EXPECT: Error recorded, non-zero exit.

### 3.4 Timeout enforcement

```bash
$ oaie run --timeout 2s -- sleep 60
```

EXPECT: Killed after ~2 seconds. OAIE reports timeout.

### 3.5 Quiet mode

```bash
$ oaie run -q -- echo "quiet test" 2>/dev/null
```

EXPECT: Only `quiet test` on stdout. No OAIE banner.

### 3.6 Verbose mode

```bash
$ oaie run -v -- echo "verbose"
```

EXPECT: Policy summary printed before execution.

```bash
$ oaie run -vv -- echo "very verbose"
```

EXPECT: Full sandbox specification printed.

### 3.7 From job spec file

```bash
$ cat > $OAIE_TEST_DIR/job.toml <<'EOF'
[job]
command = ["echo", "from spec"]
timeout = "30s"
EOF
$ oaie run --spec $OAIE_TEST_DIR/job.toml
```

EXPECT: `from spec` on stdout.

### 3.8 Job spec from stdin

```bash
$ echo '{"command": ["echo", "from stdin"], "timeout": "30s"}' | oaie run --spec -
```

EXPECT: `from stdin` on stdout.

### 3.9 Custom input directory

```bash
$ oaie run --in $OAIE_TEST_DIR/input -- ls /in/
```

EXPECT: Lists `hello.c` and `data.txt`.

### 3.10 Custom output directory

```bash
$ oaie run --out $OAIE_TEST_DIR/my-output -- sh -c 'echo result > /out/result.txt'
$ cat $OAIE_TEST_DIR/my-output/result.txt
```

EXPECT: `result`.

---

## 4. Output & Artifact Collection

**Requires: A (OAIE CLI)**

### 4.1 Stdout and stderr captured

```bash
$ oaie run -- sh -c 'echo stdout-data; echo stderr-data >&2'
$ oaie inspect last
```

EXPECT: Inspect shows both stdout and stderr artifacts with correct hashes.

### 4.2 Output files collected

```bash
$ oaie run -- sh -c 'echo A > /out/a.txt; echo B > /out/b.txt; mkdir -p /out/sub; echo C > /out/sub/c.txt'
$ oaie inspect last
```

EXPECT: 3 output artifacts listed (a.txt, b.txt, sub/c.txt).

### 4.3 Large output file (within limits)

```bash
$ oaie run -- sh -c 'dd if=/dev/zero of=/out/big.bin bs=1M count=10 2>/dev/null'
$ oaie inspect last
```

EXPECT: Artifact `big.bin` listed, size ~10 MB.

### 4.4 Output file exceeding single-file limit

```bash
$ oaie run -- sh -c 'dd if=/dev/zero of=/out/huge.bin bs=1M count=300 2>/dev/null'
```

EXPECT: File truncated or run completes but artifact exceeds 256 MB limit warning.
VERIFY: `oaie inspect last` shows artifact size capped or warning.

### 4.5 Read artifact content

```bash
$ oaie run -- sh -c 'echo "artifact content" > /out/test.txt'
$ oaie cat last stdout
$ oaie cat last output/test.txt
```

EXPECT: `artifact content` from the second command.

---

## 5. Namespace Sandbox Isolation

**Requires: A (OAIE CLI)**

### 5.1 PID namespace — PID 1 inside sandbox

```bash
$ oaie run -- sh -c 'echo $$'
```

EXPECT: A small PID number (typically 1 or 2), not the host PID.

### 5.2 User namespace — UID mapping

```bash
$ oaie run -- id
```

EXPECT: `uid=0(root) gid=0(root)` — mapped UID, no actual root privileges.

### 5.3 Mount namespace — isolated root

```bash
$ oaie run -- ls /
```

EXPECT: Minimal root: `in`, `out`, `usr`, `lib`, `lib64`, `bin`, `sbin`, `proc`, `sys`, `dev`, `etc`, `tmp`, `root`.

### 5.4 IPC namespace — isolated shared memory

```bash
$ oaie run -- sh -c 'ipcs -m 2>&1 || echo "ipcs not available"'
```

EXPECT: No shared memory segments from host visible (empty list or command not available).

### 5.5 UTS namespace — separate hostname

```bash
$ oaie run -- hostname
```

EXPECT: Different from host hostname (or empty/default).

### 5.6 Cgroup namespace — isolated view

```bash
$ oaie run -- cat /proc/self/cgroup
```

EXPECT: Shows cgroup path relative to sandbox root, not host path.

### 5.7 Network namespace — no connectivity

```bash
$ oaie run -- sh -c 'cat /proc/net/tcp 2>/dev/null; echo exit=$?'
```

EXPECT: Empty or masked.

### 5.8 Cannot see host processes

```bash
$ oaie run -- ps aux 2>/dev/null || oaie run -- ls /proc/
```

EXPECT: Only sandbox processes visible (PID 1 and its children).

### 5.9 No access to host root filesystem

```bash
$ oaie run -- sh -c 'ls /home 2>&1; echo exit=$?'
```

EXPECT: Error or empty (home not mounted).

---

## 6. Seccomp BPF Enforcement

**Requires: A (OAIE CLI), gcc (to compile C test programs)**

### 6.1 KILL tier — io_uring blocked

```bash
$ cat > $OAIE_TEST_DIR/input/uring_test.c <<'EOF'
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
int main() {
    long ret = syscall(SYS_io_uring_setup, 32, NULL);
    printf("io_uring_setup returned: %ld\n", ret);
    return 0;
}
EOF
$ gcc -o $OAIE_TEST_DIR/input/uring_test $OAIE_TEST_DIR/input/uring_test.c
$ oaie run --in $OAIE_TEST_DIR/input -- /in/uring_test
```

EXPECT: Process killed (SIGSYS) — does NOT print "io_uring_setup returned".

### 6.2 ERRNO tier — mount blocked

```bash
$ oaie run -- sh -c 'mount -t tmpfs none /tmp 2>&1; echo exit=$?'
```

EXPECT: `mount: permission denied` or `EPERM`. Process continues (not killed).

### 6.3 ERRNO tier — ptrace blocked

```bash
$ oaie run -- sh -c 'strace echo test 2>&1; echo exit=$?'
```

EXPECT: `EPERM` from ptrace, strace fails.

### 6.4 memfd_create blocked by default

```bash
$ cat > $OAIE_TEST_DIR/input/memfd_test.c <<'EOF'
#define _GNU_SOURCE
#include <sys/mman.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
int main() {
    int fd = memfd_create("test", 0);
    if (fd < 0) { printf("memfd_create blocked: %s\n", strerror(errno)); return 1; }
    printf("memfd_create succeeded: fd=%d\n", fd);
    return 0;
}
EOF
$ gcc -o $OAIE_TEST_DIR/input/memfd_test $OAIE_TEST_DIR/input/memfd_test.c
$ oaie run --in $OAIE_TEST_DIR/input -- /in/memfd_test
```

EXPECT: `memfd_create blocked: Operation not permitted`

### 6.5 memfd_create allowed with policy

```bash
$ oaie run --policy agent-build --in $OAIE_TEST_DIR/input -- /in/memfd_test
```

EXPECT: `memfd_create succeeded` (agent-build has allow_memfd=true).

### 6.6 Socket AF_PACKET blocked

```bash
$ cat > $OAIE_TEST_DIR/input/raw_sock.c <<'EOF'
#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
int main() {
    int fd = socket(AF_PACKET, SOCK_RAW, 0);
    if (fd < 0) { printf("AF_PACKET blocked: %s\n", strerror(errno)); return 1; }
    printf("AF_PACKET succeeded: fd=%d\n", fd);
    return 0;
}
EOF
$ gcc -o $OAIE_TEST_DIR/input/raw_sock $OAIE_TEST_DIR/input/raw_sock.c
$ oaie run --in $OAIE_TEST_DIR/input -- /in/raw_sock
```

EXPECT: `AF_PACKET blocked: Operation not permitted`

### 6.7 ioctl TIOCSTI blocked

```bash
$ cat > $OAIE_TEST_DIR/input/tiocsti_test.c <<'EOF'
#include <sys/ioctl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
int main() {
    char c = 'x';
    int ret = ioctl(0, 0x5412, &c);  /* TIOCSTI */
    if (ret < 0) { printf("TIOCSTI blocked: %s\n", strerror(errno)); return 1; }
    printf("TIOCSTI succeeded\n");
    return 0;
}
EOF
$ gcc -o $OAIE_TEST_DIR/input/tiocsti_test $OAIE_TEST_DIR/input/tiocsti_test.c
$ oaie run --in $OAIE_TEST_DIR/input -- /in/tiocsti_test
```

EXPECT: `TIOCSTI blocked: Operation not permitted`

---

## 7. Resource Limits (rlimits)

**Requires: A (OAIE CLI)**

### 7.1 Fork bomb protection (RLIMIT_NPROC)

```bash
$ oaie run --timeout 5s -- sh -c ':(){ :|:& };:'
```

EXPECT: Fork bomb contained. Process eventually killed by timeout or NPROC limit.
The system should NOT become unresponsive.

### 7.2 Memory limit (RLIMIT_AS)

```bash
$ oaie run -- sh -c 'python3 -c "x = bytearray(600_000_000)" 2>&1; echo exit=$?'
```

EXPECT: MemoryError or killed (default 512 MB).

### 7.3 Memory with higher policy

```bash
$ oaie run --policy agent-build -- sh -c 'python3 -c "x = bytearray(1_500_000_000); print(len(x))" 2>&1'
```

EXPECT: Succeeds (agent-build allows 2 GB).

### 7.4 File size limit (RLIMIT_FSIZE)

```bash
$ oaie run -- sh -c 'dd if=/dev/zero of=/out/big bs=1M count=2000 2>&1; echo exit=$?'
```

EXPECT: Write fails after reaching 1 GB (default RLIMIT_FSIZE).

### 7.5 Open file limit (RLIMIT_NOFILE)

```bash
$ oaie run -- sh -c 'ulimit -n'
```

EXPECT: `1024` (soft limit).

### 7.6 Core dumps disabled

```bash
$ oaie run -- sh -c 'ulimit -c'
```

EXPECT: `0`

### 7.7 CPU time limit

```bash
$ oaie run --timeout 5s -- sh -c 'ulimit -t'
```

EXPECT: A value >= 10 (2x timeout = 10s, min 60s) — shows the rlimit CPU time.

---

## 8. Cgroup v2 Enforcement

**Requires: A (OAIE CLI), B (oaie-priv with CAP_SYS_ADMIN) or systemd user session**

### 8.1 Check cgroup availability

```bash
$ oaie doctor 2>&1 | grep -i cgroup
```

EXPECT: Shows whether cgroup v2 is available and which method (systemd-run or oaie-priv).

### 8.2 Run with cgroup=auto (default)

```bash
$ oaie run -- sh -c 'cat /proc/self/cgroup; echo ---; cat /sys/fs/cgroup/memory.max 2>/dev/null || echo "no cgroup memory"'
```

VERIFY: If cgroups available, should show a scope path. If not, falls back to rlimits only.

### 8.3 Run with cgroup=require

```bash
$ oaie run --cgroup require -- echo "cgroup required"
```

EXPECT: If cgroups not available, ERROR. If available, succeeds.

### 8.4 Run with cgroup=off

```bash
$ oaie run --cgroup off -- echo "no cgroup"
```

EXPECT: Succeeds, uses only rlimits (no cgroup scope created).

### 8.5 Memory cgroup enforcement (OOM kill)

```bash
$ oaie run --cgroup require --policy contained-strict -- sh -c 'python3 -c "x = bytearray(200_000_000)" 2>&1; echo exit=$?'
```

EXPECT: OOM killed (contained-strict = 128 MB).
VERIFY: `oaie inspect last` shows resource stats with OOM indicator if cgroup active.

### 8.6 PID cgroup enforcement

```bash
$ oaie run --cgroup require --policy contained-strict --timeout 5s -- sh -c 'for i in $(seq 1 50); do sleep 60 & done; wait'
```

EXPECT: Fork fails after 32 PIDs (contained-strict).

---

## 9. Capability Dropping & Retention

**Requires: A (OAIE CLI)**

### 9.1 All capabilities dropped by default

```bash
$ oaie run -- sh -c 'cat /proc/self/status | grep Cap'
```

EXPECT: `CapEff: 0000000000000000` (all zeroes).

### 9.2 Ping fails without CAP_NET_RAW

```bash
$ oaie run -- ping -c 1 127.0.0.1
```

EXPECT: Fails (no CAP_NET_RAW, no network).

### 9.3 Ping succeeds with CAP_NET_RAW via custom policy

```bash
$ cat > $OAIE_TEST_DIR/ping_policy.toml <<'EOF'
[limits]
capabilities = ["net_raw"]
EOF
$ oaie run --policy $OAIE_TEST_DIR/ping_policy.toml -- ping -c 1 127.0.0.1
```

EXPECT: Ping succeeds on loopback (CAP_NET_RAW retained, loopback auto-setup).

### 9.4 Dangerous capabilities rejected

```bash
$ cat > $OAIE_TEST_DIR/bad_policy.toml <<'EOF'
[limits]
capabilities = ["sys_admin"]
EOF
$ oaie run --policy $OAIE_TEST_DIR/bad_policy.toml -- echo test
```

EXPECT: Error: capability 'sys_admin' not in allowlist.

---

## 10. Filesystem Isolation & Credential Denial

**Requires: A (OAIE CLI)**

### 10.1 Input directory is read-only

```bash
$ oaie run --in $OAIE_TEST_DIR/input -- sh -c 'echo hack > /in/hello.c 2>&1; echo exit=$?'
```

EXPECT: `Read-only file system`. Exit 1.

### 10.2 Output directory is writable

```bash
$ oaie run -- sh -c 'echo ok > /out/test.txt; cat /out/test.txt'
```

EXPECT: `ok`

### 10.3 /proc masking — sensitive paths hidden

```bash
$ oaie run -- sh -c 'cat /proc/net/tcp 2>&1; echo "---"; cat /proc/self/io 2>&1'
```

EXPECT: Both masked (Permission denied or empty).

### 10.4 Minimal /dev

```bash
$ oaie run -- ls /dev/
```

EXPECT: Only `null`, `zero`, `random`, `urandom`, `console`, `pts/`, `ptmx` (and possibly `fd`, `stdin`, `stdout`, `stderr` symlinks).

### 10.5 SSH keys never accessible

```bash
$ oaie run --rw ~/.ssh -- sh -c 'ls /root/.ssh 2>&1; echo exit=$?'
```

EXPECT: ~/.ssh is in the deny list — mount rejected or path not visible.

### 10.6 AWS credentials never accessible

```bash
$ oaie run --rw ~/.aws -- sh -c 'ls /root/.aws 2>&1; echo exit=$?'
```

EXPECT: Denied.

### 10.7 All 24 credential paths denied

Test a sampling:
```bash
$ for path in ~/.gnupg ~/.docker ~/.kube ~/.npmrc ~/.git-credentials ~/.vault-token; do
    echo "--- Testing $path ---"
    oaie run --rw $path -- echo "should not see this" 2>&1 | head -2
  done
```

EXPECT: Each one denied or not mounted.

### 10.8 Extra RO mount

```bash
$ mkdir -p $OAIE_TEST_DIR/extra-data
$ echo "extra" > $OAIE_TEST_DIR/extra-data/file.txt
$ oaie run --ro $OAIE_TEST_DIR/extra-data -- cat /extra-data/file.txt 2>/dev/null || \
  oaie run --ro $OAIE_TEST_DIR/extra-data -- sh -c 'find / -name file.txt 2>/dev/null'
```

EXPECT: File accessible read-only inside sandbox.

### 10.9 Extra RW mount

```bash
$ mkdir -p $OAIE_TEST_DIR/rw-data
$ oaie run --rw $OAIE_TEST_DIR/rw-data -- sh -c 'echo written > /rw-data/out.txt 2>/dev/null || find / -writable -name rw-data 2>/dev/null'
```

EXPECT: File writable inside sandbox.

---

## 11. Environment Sanitization

**Requires: A (OAIE CLI)**

### 11.1 Dangerous vars stripped

```bash
$ LD_PRELOAD=/tmp/evil.so PYTHONPATH=/tmp NODE_OPTIONS="--max-old-space-size=1" \
  oaie run -- env
```

EXPECT: Output does NOT contain `LD_PRELOAD`, `PYTHONPATH`, or `NODE_OPTIONS`.

### 11.2 PATH is clean

```bash
$ oaie run -- sh -c 'echo $PATH'
```

EXPECT: `/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin`

### 11.3 HOME set to /root

```bash
$ oaie run -- sh -c 'echo $HOME'
```

EXPECT: `/root`

### 11.4 LANG set to C.UTF-8

```bash
$ oaie run -- sh -c 'echo $LANG'
```

EXPECT: `C.UTF-8`

### 11.5 OAIE_RUN_ID and OAIE_OUT set

```bash
$ oaie run -- sh -c 'echo "run=$OAIE_RUN_ID out=$OAIE_OUT"'
```

EXPECT: `run=<uuid> out=/out`

### 11.6 GIT_* vars stripped

```bash
$ GIT_AUTHOR_NAME=evil GIT_TOKEN=secret oaie run -- env | grep GIT
```

EXPECT: No GIT_ variables in output.

---

## 12. Network Isolation

**Requires: A (OAIE CLI)**

### 12.1 No network by default

```bash
$ oaie run -- sh -c 'curl http://example.com 2>&1 || wget http://example.com 2>&1 || echo "no network"'
```

EXPECT: Connection fails. `no network` printed.

### 12.2 Loopback works

```bash
$ oaie run -- sh -c 'python3 -c "
import socket
s = socket.socket()
s.bind((\"127.0.0.1\", 12345))
s.listen(1)
print(\"loopback works\")
s.close()
"'
```

EXPECT: `loopback works`

### 12.3 Network enabled with --net on

```bash
$ oaie run --net on -- sh -c 'curl -s -o /dev/null -w "%{http_code}" http://example.com'
```

EXPECT: `200` [REQUIRES NETWORK]

### 12.4 --net flag without value defaults to on

```bash
$ oaie run --net -- sh -c 'curl -s -o /dev/null -w "%{http_code}" http://example.com'
```

EXPECT: `200` [REQUIRES NETWORK]

---

## 13. Network Allowlist Mode

**Requires: A (OAIE CLI), E (nftables + nsenter + IP forwarding), internet access**

### 13.1 Check prerequisites

```bash
$ oaie doctor 2>&1 | grep -E "nftables|forwarding|nsenter"
```

EXPECT: All green/yellow for network policy features.

### 13.2 Allowlist specific host

```bash
$ oaie run --net 'allow:example.com:443' -- \
  sh -c 'curl -s https://example.com > /dev/null && echo "allowed"'
```

EXPECT: `allowed`

### 13.3 Non-allowed host rejected

```bash
$ oaie run --net 'allow:example.com:443' -- \
  sh -c 'curl -s --connect-timeout 3 https://httpbin.org 2>&1; echo exit=$?'
```

EXPECT: Connection refused or timeout.

### 13.4 Network preset — anthropic

```bash
$ oaie run --net preset:anthropic -- \
  sh -c 'curl -s -o /dev/null -w "%{http_code}" https://api.anthropic.com/v1/messages'
```

EXPECT: `401` (unauthorized, but connection succeeds — proves allowlist works).

### 13.5 Network preset — llm (multi-provider)

```bash
$ oaie run --net preset:llm -- \
  sh -c 'curl -s -o /dev/null -w "%{http_code}" https://api.openai.com/v1/models && echo ok'
```

EXPECT: HTTP response (connection succeeds).

---

## 14. Ptrace Tracing

**Requires: A (OAIE CLI)**

### 14.1 Basic traced run

```bash
$ oaie run --trace ptrace -- echo "traced"
```

EXPECT: `traced` on stdout. Run completes normally.

### 14.2 Trace captures exec events

```bash
$ oaie run --trace ptrace -- echo "hello"
$ oaie inspect last --trace-stats
```

EXPECT: Trace stats show at least 1 exec event, 1 exit event.

### 14.3 Trace captures file access

```bash
$ oaie run --trace ptrace --in $OAIE_TEST_DIR/input -- cat /in/data.txt
$ oaie inspect last --trace-stats
```

EXPECT: File access events for `/in/data.txt`.

### 14.4 Full trace dump

```bash
$ oaie run --trace ptrace -- echo "test"
$ oaie inspect last --trace-full 2>&1 | head -20
```

EXPECT: NDJSON events with `event_type`, `pid`, `detail` fields.

### 14.5 Trace with multiple processes

```bash
$ oaie run --trace ptrace -- sh -c 'echo parent; (echo child)'
$ oaie inspect last --trace-stats
```

EXPECT: Events for both parent and child processes (fork/clone tracked).

### 14.6 Trace hash chain integrity

```bash
$ oaie run --trace ptrace -- echo "chain test"
$ oaie verify last
```

EXPECT: `EventChainIntegrity: Pass`, `EventChainTip: Pass`.

### 14.7 --notrace overrides --trace

```bash
$ oaie run --trace ptrace --notrace -- echo "not traced"
$ oaie inspect last
```

EXPECT: No trace data in artifacts.

---

## 15. eBPF Tracing

**Requires: A (OAIE CLI), B (oaie-priv with CAP_SYS_ADMIN + CAP_BPF + CAP_PERFMON), C (compiled BPF programs)**

### 15.1 Check eBPF availability

```bash
$ oaie doctor 2>&1 | grep -i ebpf
```

EXPECT: Shows eBPF tracer status.

### 15.2 Run with eBPF trace

```bash
$ oaie run --trace ebpf --cgroup require -- echo "ebpf traced"
```

EXPECT: Succeeds if eBPF available. Trace events captured.

### 15.3 eBPF trace captures exec

```bash
$ oaie run --trace ebpf --cgroup require -- echo "test"
$ oaie inspect last --trace-stats
```

EXPECT: Exec event count >= 1.

### 15.4 --trace auto selects eBPF when available

```bash
$ oaie run --trace auto --cgroup require -- echo "auto trace"
$ oaie inspect last --trace-stats
```

EXPECT: Uses eBPF if available, ptrace otherwise.

---

## 16. Firecracker MicroVM Backend

**Requires: A (OAIE CLI built with `--features firecracker`), D (Firecracker binary + /dev/kvm + guest assets)**

### 16.1 Check Firecracker availability

```bash
$ oaie doctor 2>&1 | grep -i firecracker
```

EXPECT: Shows Firecracker binary status and /dev/kvm availability.

### 16.2 Initialize Firecracker assets

```bash
$ oaie firecracker check
```

EXPECT: Shows status of kernel, rootfs, guest agent.

### 16.3 Boot test

```bash
$ oaie firecracker boot-test
```

EXPECT: VM boots, runs echo, returns result. Shows boot time.

### 16.4 Run command in Firecracker

```bash
$ oaie run --backend firecracker -- echo "hello from VM"
```

EXPECT: `hello from VM`. Takes ~800ms+ (VM boot overhead).

### 16.5 No network in Firecracker

```bash
$ oaie run --backend firecracker -- sh -c 'curl http://example.com 2>&1 || echo "no network in VM"'
```

EXPECT: No network (no virtio-net device attached).

### 16.6 Output file collection from VM

```bash
$ oaie run --backend firecracker -- sh -c 'echo "vm output" > /out/result.txt'
$ oaie cat last output/result.txt
```

EXPECT: `vm output`

### 16.7 Verify Firecracker run

```bash
$ oaie run --backend firecracker -- echo "verify me"
$ oaie verify last
```

EXPECT: All checks pass. Manifest shows `backend: firecracker`.

### 16.8 Inspect shows Firecracker metadata

```bash
$ oaie inspect last
```

EXPECT: Shows `fc_version`, `kernel`, `rootfs` in isolation info.

---

## 17. Interactive PTY Mode

**Requires: A (OAIE CLI)**

### 17.1 Basic interactive session

```bash
$ echo "echo interactive-works" | oaie run -i -- /bin/sh
```

EXPECT: `interactive-works` (command sent through PTY).

### 17.2 isatty returns true

```bash
$ echo 'python3 -c "import sys; print(sys.stdout.isatty())"' | oaie run -i -- /bin/sh
```

EXPECT: `True` (PTY allocated).

### 17.3 TERM environment set

```bash
$ echo 'echo $TERM' | oaie run -i -- /bin/sh
```

EXPECT: A terminal type (not `dumb` — inherits supervisor's TERM in interactive mode).

### 17.4 Incompatible flag combinations

```bash
$ oaie run -i --output json -- echo test 2>&1
```

EXPECT: Error about incompatible flags (-i with --output=json).

```bash
$ oaie run -i -q -- echo test 2>&1
```

EXPECT: Error about incompatible flags (-i with --quiet).

### 17.5 Manifest records interactive mode

```bash
$ echo exit | oaie run -i -- /bin/sh
$ oaie inspect last
```

EXPECT: `interactive: true` in isolation info.

### 17.6 Full terminal app (manual)

```bash
$ oaie run -i -- vim /out/test.txt
```

Type `:q!` to exit.
EXPECT: vim renders correctly, responds to keystrokes, exits cleanly.

---

## 18. Ed25519 Signing & Attestation

**Requires: A (OAIE CLI)**

### 18.1 Generate a signing key

```bash
$ oaie key generate --label "test-key"
```

EXPECT: Key ID displayed (8 hex chars), stored at `<store>/keys/<id>.toml`.

### 18.2 List keys

```bash
$ oaie key list
```

EXPECT: Shows the key with ID, label, algorithm (Ed25519), creation date.

### 18.3 Sign a run

```bash
$ oaie run --sign -- echo "signed run"
```

EXPECT: Run completes. Signature recorded.

### 18.4 Verify signed run

```bash
$ oaie verify last
```

EXPECT: `ManifestSignature: Pass` (12th check).

### 18.5 Unsigned run — signature check skipped

```bash
$ oaie run -- echo "unsigned"
$ oaie verify last
```

EXPECT: `ManifestSignature: Skip` (no signature present).

### 18.6 Export public key

```bash
$ KEY_ID=$(oaie key list 2>&1 | grep -oP '[a-f0-9]{8}' | head -1)
$ oaie key export $KEY_ID --public
```

EXPECT: Public key in base64 format.

### 18.7 Delete key

```bash
$ oaie key delete $KEY_ID
```

EXPECT: Key removed. `oaie key list` shows empty.

### 18.8 Default signing key in config

```bash
$ oaie key generate --label "auto-sign"
```

Manually add to config.toml:
```bash
$ cat >> $OAIE_HOME/config.toml <<EOF

[signing]
default_key = "auto-sign"
EOF
```

```bash
$ oaie run -- echo "auto-signed"
$ oaie verify last
```

EXPECT: `ManifestSignature: Pass` (automatically signed via config).

---

## 19. Verification & Integrity Checks

**Requires: A (OAIE CLI)**

### 19.1 Verify a good run (all 12 checks)

```bash
$ oaie run --trace ptrace --sign -- echo "verify all"
$ oaie verify last
```

EXPECT: 12 checks, all Pass:
1. ManifestExists
2. ManifestParseable
3. InputArtifactsExist
4. OutputArtifactsExist
5. InputArtifactHashes
6. OutputArtifactHashes
7. TraceIndexExists
8. TraceChunksExist
9. TraceChunkHashes
10. EventChainIntegrity
11. EventChainTip
12. ManifestSignature

### 19.2 Verify untraced run

```bash
$ oaie run -- echo "no trace"
$ oaie verify last
```

EXPECT: Trace checks (7-11) show Skip. Others Pass.

### 19.3 Detect corrupted artifact

```bash
$ oaie run -- sh -c 'echo "original" > /out/file.txt'
$ RUN_ID=$(oaie list --json 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['run_id'])" 2>/dev/null || oaie list -n 1 2>&1 | grep -oP '[0-9a-f-]{36}' | head -1)
```

Manually corrupt a CAS blob (find the hash, modify 1 byte), then:
```bash
$ oaie verify $RUN_ID
```

EXPECT: Hash mismatch detected — check fails.

### 19.4 Verify all runs

```bash
$ oaie verify --all
```

EXPECT: All runs verified with summary.

### 19.5 Strict mode (CI)

```bash
$ oaie run -- echo "strict verify"
$ oaie verify last --strict
$ echo $?
```

EXPECT: Exit code 0 (all pass). With a corrupted run: exit code non-zero.

### 19.6 JSON format

```bash
$ oaie verify last --format json
```

EXPECT: JSON output with checks array, each having kind/status/detail.

---

## 20. Content-Addressed Store (CAS)

**Requires: A (OAIE CLI)**

### 20.1 Add a file to CAS

```bash
$ echo "cas test data" > /tmp/cas_test.txt
$ oaie cas add /tmp/cas_test.txt
```

EXPECT: Prints hash (64 hex chars) and size.

### 20.2 Verify a CAS blob

```bash
$ HASH=$(oaie cas add /tmp/cas_test.txt 2>&1 | grep -oP '[a-f0-9]{64}')
$ oaie cas verify $HASH
```

EXPECT: `Ok` — blob exists and matches.

### 20.3 Verify nonexistent blob

```bash
$ oaie cas verify 0000000000000000000000000000000000000000000000000000000000000000
```

EXPECT: `Missing`

### 20.4 Deduplication

```bash
$ echo "dedup test" > /tmp/dedup1.txt
$ cp /tmp/dedup1.txt /tmp/dedup2.txt
$ HASH1=$(oaie cas add /tmp/dedup1.txt 2>&1 | grep -oP '[a-f0-9]{64}')
$ HASH2=$(oaie cas add /tmp/dedup2.txt 2>&1 | grep -oP '[a-f0-9]{64}')
$ echo "hash1=$HASH1 hash2=$HASH2"
```

EXPECT: Same hash (content-addressed deduplication).

### 20.5 CAS stats in inspect

```bash
$ oaie inspect last
```

EXPECT: CAS store stats section showing object count and total size.

---

## 21. Database & Run Management

**Requires: A (OAIE CLI)**

### 21.1 List runs

```bash
$ oaie list
```

EXPECT: Table of recent runs with ID, status, command, exit code, duration.

### 21.2 List with limit

```bash
$ oaie list -n 5
```

EXPECT: At most 5 runs.

### 21.3 List all

```bash
$ oaie list --all
```

EXPECT: All runs in store.

### 21.4 Search runs

```bash
$ oaie list -s "echo"
```

EXPECT: Only runs with "echo" in command.

### 21.5 List as JSON

```bash
$ oaie list --json
```

EXPECT: Valid JSON array.

### 21.6 Inspect by ID prefix

```bash
$ RUN_PREFIX=$(oaie list -n 1 2>&1 | grep -oP '[0-9a-f-]{8}' | head -1)
$ oaie inspect $RUN_PREFIX
```

EXPECT: Resolves prefix to full run, shows details.

### 21.7 Inspect "last"

```bash
$ oaie inspect last
```

EXPECT: Shows most recent run.

---

## 22. Policy System

**Requires: A (OAIE CLI)**

### 22.1 List all presets

```bash
$ oaie policy list
```

EXPECT: 13 presets listed (safe, net, agent-safe, agent-net, agent-build,
agent-analyze, anthropic, openai, llm, contained-local, contained-cloud,
contained-strict, contained-interactive).

### 22.2 Show preset details

```bash
$ oaie policy show safe
$ oaie policy show agent-build
$ oaie policy show contained-strict
```

EXPECT: Full TOML output for each preset with limits, network mode, etc.

### 22.3 Use named preset

```bash
$ oaie run --policy agent-safe -- echo "agent-safe policy"
$ oaie inspect last
```

EXPECT: Policy name shown as "agent-safe" in metadata.

### 22.4 Custom TOML policy

```bash
$ cat > $OAIE_TEST_DIR/custom.toml <<'EOF'
name = "custom-test"

[defaults]
network = false

[limits]
max_memory = "256M"
max_time = "30s"
max_pids = 16
max_fsize = "100M"
EOF
$ oaie run --policy $OAIE_TEST_DIR/custom.toml -- echo "custom policy"
```

EXPECT: Succeeds with custom limits applied.

### 22.5 Policy validation — bad capability

```bash
$ cat > $OAIE_TEST_DIR/bad.toml <<'EOF'
[limits]
capabilities = ["sys_ptrace"]
EOF
$ oaie run --policy $OAIE_TEST_DIR/bad.toml -- echo test
```

EXPECT: Error: capability not in allowlist.

### 22.6 Policy validation — zero PIDs

```bash
$ cat > $OAIE_TEST_DIR/zero.toml <<'EOF'
[limits]
max_pids = 0
EOF
$ oaie run --policy $OAIE_TEST_DIR/zero.toml -- echo test
```

EXPECT: Error: max_pids must be > 0.

### 22.7 Check command (dry run)

```bash
$ cat > $OAIE_TEST_DIR/check_job.toml <<'EOF'
[job]
command = ["echo", "check"]
timeout = "30s"
EOF
$ oaie check $OAIE_TEST_DIR/check_job.toml
```

EXPECT: Validation passes without executing.

### 22.8 Check with policy violation

```bash
$ cat > $OAIE_TEST_DIR/net_job.toml <<'EOF'
[job]
command = ["curl", "http://example.com"]
timeout = "30s"
network = true
EOF
$ oaie check $OAIE_TEST_DIR/net_job.toml --policy $OAIE_TEST_DIR/custom.toml
```

EXPECT: Warning about network access vs policy.

---

## 23. Session Mode — Basic

**Requires: A (OAIE CLI), G (Python 3)**

### 23.1 Create a simple agent script

```bash
$ cat > $OAIE_TEST_DIR/input/agent.py <<'PYEOF'
import os, socket, json, sys

sock_path = os.environ["OAIE_DISPATCH_SOCK"]
session_id = os.environ.get("OAIE_SESSION_ID", "unknown")
print(f"Agent started, session={session_id}", flush=True)

# Dispatch a tool call
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(sock_path)

request = json.dumps({
    "command": ["echo", "tool-output"],
    "timeout": "10s"
}) + "\n"
sock.sendall(request.encode())

# Read response
data = b""
while b"\n" not in data:
    chunk = sock.recv(4096)
    if not chunk:
        break
    data += chunk

response = json.loads(data.decode().strip())
print(f"Tool result: exit_code={response.get('exit_code')}", flush=True)
sock.close()
print("Agent done", flush=True)
PYEOF
```

### 23.2 Run a basic session

```bash
$ oaie session run --in $OAIE_TEST_DIR/input --timeout 30s -- python3 /in/agent.py
```

EXPECT: Agent starts, dispatches tool call, receives result, exits.

### 23.3 List sessions

```bash
$ oaie session list
```

EXPECT: Shows the session with ID, status (stopped), tool calls count.

### 23.4 Session status

```bash
$ SESSION_ID=$(oaie session list -n 1 2>&1 | grep -oP '[0-9a-f-]{36}' | head -1)
$ oaie session status $SESSION_ID
```

EXPECT: Session details with budget usage.

### 23.5 Session inspect

```bash
$ oaie session inspect $SESSION_ID
```

EXPECT: Full session report with tool call table.

### 23.6 Session event log

```bash
$ oaie session log $SESSION_ID
```

EXPECT: Event log entries (SessionStart, ToolDispatch, ToolResult, SessionStop).

### 23.7 Filter event log by type

```bash
$ oaie session log $SESSION_ID --type tool_call
```

EXPECT: Only ToolDispatch and ToolResult events.

---

## 24. Session Mode — Budgets

**Requires: A (OAIE CLI), G (Python 3)**

### 24.1 Agent that makes many tool calls

```bash
$ cat > $OAIE_TEST_DIR/input/multi_agent.py <<'PYEOF'
import os, socket, json, sys

sock_path = os.environ["OAIE_DISPATCH_SOCK"]

for i in range(10):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sock_path)
    request = json.dumps({"command": ["echo", f"call-{i}"], "timeout": "5s"}) + "\n"
    sock.sendall(request.encode())
    data = b""
    while b"\n" not in data:
        chunk = sock.recv(4096)
        if not chunk: break
        data += chunk
    response = json.loads(data.decode().strip())
    print(f"Call {i}: exit={response.get('exit_code')}", flush=True)
    sock.close()

print("Agent completed all calls", flush=True)
PYEOF
```

### 24.2 Tool call budget enforced

```bash
$ oaie session run --budget-tools 3 --in $OAIE_TEST_DIR/input --timeout 30s -- python3 /in/multi_agent.py
```

EXPECT: First 3 calls succeed, then session stops with BudgetExhausted.

### 24.3 Wall time budget enforced

```bash
$ cat > $OAIE_TEST_DIR/input/slow_agent.py <<'PYEOF'
import os, socket, json, time

sock_path = os.environ["OAIE_DISPATCH_SOCK"]
print("Starting slow agent", flush=True)
time.sleep(2)

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(sock_path)
request = json.dumps({"command": ["sleep", "30"], "timeout": "30s"}) + "\n"
sock.sendall(request.encode())
data = b""
while b"\n" not in data:
    chunk = sock.recv(4096)
    if not chunk: break
    data += chunk
print("Done", flush=True)
sock.close()
PYEOF
$ oaie session run --budget-wall 5 --in $OAIE_TEST_DIR/input --timeout 30s -- python3 /in/slow_agent.py
```

EXPECT: Session killed after ~5 seconds wall time.

### 24.4 Status shows budget consumption

```bash
$ oaie session status $(oaie session list -n 1 2>&1 | grep -oP '[0-9a-f-]{36}' | head -1)
```

EXPECT: Shows used/max for each budget dimension.

---

## 25. Session Mode — Containment Profiles

**Requires: A (OAIE CLI), G (Python 3)**

### 25.1 List profiles

```bash
$ oaie session profiles
```

EXPECT: 4 profiles listed: local, cloud, strict, interactive.

### 25.2 Show profile details

```bash
$ oaie session profiles --show local
$ oaie session profiles --show strict
```

EXPECT: Budget defaults, policy preset, agent network mode for each.

### 25.3 Run with contained=local

```bash
$ oaie session run --contained=local --in $OAIE_TEST_DIR/input --timeout 30s -- python3 /in/agent.py
```

EXPECT: Uses contained-local policy (1G memory, 128 PIDs, no network).

### 25.4 Run with contained=strict

```bash
$ oaie session run --contained=strict --in $OAIE_TEST_DIR/input --timeout 30s -- python3 /in/agent.py
```

EXPECT: Uses contained-strict policy (128M memory, 32 PIDs).

### 25.5 Contained + policy is mutually exclusive

```bash
$ oaie session run --contained=local --policy safe -- echo test
```

EXPECT: Error about mutually exclusive flags.

### 25.6 Budget override with containment

```bash
$ oaie session run --contained=strict --budget-tools 5 --in $OAIE_TEST_DIR/input --timeout 30s -- python3 /in/agent.py
```

EXPECT: Uses strict policy but with 5 tool calls (overridden).

### 25.7 LLM provider metadata

```bash
$ oaie session run --contained=cloud --llm anthropic --in $OAIE_TEST_DIR/input --timeout 30s -- python3 /in/agent.py
$ oaie session inspect $(oaie session list -n 1 2>&1 | grep -oP '[0-9a-f-]{36}' | head -1)
```

EXPECT: `llm_provider: anthropic` in session metadata.

---

## 26. Session Mode — Tool Filtering

**Requires: A (OAIE CLI), G (Python 3)**

### 26.1 Allow-list

```bash
$ oaie session run --allow-tools "echo" --in $OAIE_TEST_DIR/input --timeout 30s -- python3 /in/agent.py
```

EXPECT: Tool calls to `echo` succeed.

### 26.2 Deny-list

Create an agent that calls `ls`:
```bash
$ cat > $OAIE_TEST_DIR/input/ls_agent.py <<'PYEOF'
import os, socket, json
sock_path = os.environ["OAIE_DISPATCH_SOCK"]
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(sock_path)
request = json.dumps({"command": ["ls", "/"], "timeout": "5s"}) + "\n"
sock.sendall(request.encode())
data = b""
while b"\n" not in data:
    chunk = sock.recv(4096)
    if not chunk: break
    data += chunk
response = json.loads(data.decode().strip())
print(f"Result: {response}", flush=True)
sock.close()
PYEOF
$ oaie session run --deny-tools "ls" --in $OAIE_TEST_DIR/input --timeout 30s -- python3 /in/ls_agent.py
```

EXPECT: Tool call to `ls` rejected (ToolDenied event).

### 26.3 Deny takes precedence over allow

```bash
$ oaie session run --allow-tools "*" --deny-tools "ls" --in $OAIE_TEST_DIR/input --timeout 30s -- python3 /in/ls_agent.py
```

EXPECT: `ls` still denied even though `*` is in allow list.

---

## 27. Session Mode — Agent Sandboxing

**Requires: A (OAIE CLI), G (Python 3)**

### 27.1 Sandbox the agent itself

```bash
$ oaie session run --sandbox-agent --contained=local --in $OAIE_TEST_DIR/input --timeout 30s -- python3 /in/agent.py
```

EXPECT: Agent runs inside namespace sandbox. Tool calls dispatched through sandbox.

### 27.2 Verify agent can't access host filesystem

```bash
$ cat > $OAIE_TEST_DIR/input/probe_agent.py <<'PYEOF'
import os
print(f"HOME={os.environ.get('HOME', 'unset')}", flush=True)
try:
    files = os.listdir("/home")
    print(f"/home: {files}", flush=True)
except Exception as e:
    print(f"/home: {e}", flush=True)
PYEOF
$ oaie session run --sandbox-agent --contained=local --in $OAIE_TEST_DIR/input --timeout 30s -- python3 /in/probe_agent.py
```

EXPECT: Agent cannot list /home — sandboxed filesystem.

### 27.3 Attach to sandboxed session (manual)

Start a long-running session, then in another terminal:
```bash
$ oaie session attach <session-id>
```

EXPECT: Shell opened inside agent's namespaces. `exit` to leave.

---

## 28. Session Mode — Approval Gates

**Requires: A (OAIE CLI), G (Python 3)**

### 28.1 Approval mode (manual/interactive)

```bash
$ oaie session run --require-approval --in $OAIE_TEST_DIR/input --timeout 60s -- python3 /in/agent.py
```

EXPECT: When agent dispatches a tool call, OAIE prompts for approval.
Type `y` to approve. Tool runs. Agent receives result.

### 28.2 Deny a tool call

Same setup — type `n` when prompted.
EXPECT: Tool call rejected, agent receives denial response.

---

## 29. Session Mode — Budget Extension

**Requires: A (OAIE CLI), G (Python 3)**

### 29.1 Extend budget of running session

Start a session with low budget:
```bash
$ oaie session run --budget-tools 2 --in $OAIE_TEST_DIR/input --timeout 60s -- python3 /in/multi_agent.py &
$ sleep 3
$ SESSION_ID=$(oaie session list -n 1 2>&1 | grep -oP '[0-9a-f-]{36}' | head -1)
$ oaie session extend $SESSION_ID --add-tool-calls 10
```

EXPECT: Session budget extended. Agent can make more calls.

### 29.2 Extend exhausted session

After budget exhausted:
```bash
$ oaie session extend $SESSION_ID --add-tool-calls 5
```

EXPECT: Session revived from budget_exhausted state.

---

## 30. Session Mode — Heartbeat & Crash Recovery

**Requires: A (OAIE CLI), G (Python 3)**

### 30.1 Heartbeat timeout

```bash
$ cat > $OAIE_TEST_DIR/input/hang_agent.py <<'PYEOF'
import time
print("Agent started, now hanging...", flush=True)
time.sleep(300)
PYEOF
$ oaie session run --heartbeat 3 --in $OAIE_TEST_DIR/input --timeout 30s -- python3 /in/hang_agent.py
```

EXPECT: After ~3 seconds without dispatch activity, heartbeat timeout triggers.
Session terminates.

### 30.2 Agent crash recovery

```bash
$ cat > $OAIE_TEST_DIR/input/crash_agent.py <<'PYEOF'
import os, socket, json
sock_path = os.environ["OAIE_DISPATCH_SOCK"]
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(sock_path)
request = json.dumps({"command": ["echo", "before-crash"], "timeout": "5s"}) + "\n"
sock.sendall(request.encode())
data = b""
while b"\n" not in data:
    chunk = sock.recv(4096)
    if not chunk: break
    data += chunk
sock.close()
print("Now crashing...", flush=True)
os._exit(42)
PYEOF
$ oaie session run --in $OAIE_TEST_DIR/input --timeout 30s -- python3 /in/crash_agent.py
```

EXPECT: Session detects agent crash, records it, transitions to stopped.
VERIFY: `oaie session status <id>` shows stopped with agent exit code.

---

## 31. MCP Server Integration

**Requires: A (OAIE CLI), F (oaie-mcp binary)**

### 31.1 Build MCP server

```bash
$ cd path/to/oaie
$ make build-mcp
```

### 31.2 Initialize protocol

```bash
$ echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | timeout 5 oaie-mcp 2>/dev/null | head -1
```

EXPECT: JSON response with server info and capabilities.

### 31.3 List tools

```bash
$ (echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'; echo '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}') | timeout 5 oaie-mcp 2>/dev/null
```

EXPECT: JSON listing 6 tools: oaie_run, oaie_verify, oaie_read_output,
oaie_session_run, oaie_session_status, oaie_session_stop.

### 31.4 Execute run via MCP

```bash
$ (echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'; echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"oaie_run","arguments":{"command":["echo","mcp-test"]}}}') | timeout 10 oaie-mcp 2>/dev/null
```

EXPECT: JSON response with run result containing stdout "mcp-test".

---

## 32. Agent Library (oaie-agent)

**Requires: A (OAIE CLI), G (Python 3)**

### 32.1 SessionClient environment variables

Inside a running session, verify:
```bash
$ cat > $OAIE_TEST_DIR/input/env_agent.py <<'PYEOF'
import os
for var in ["OAIE_DISPATCH_SOCK", "OAIE_SESSION_ID", "OAIE_ARTIFACTS_DIR"]:
    print(f"{var}={os.environ.get(var, 'MISSING')}", flush=True)
PYEOF
$ oaie session run --in $OAIE_TEST_DIR/input --timeout 30s -- python3 /in/env_agent.py
```

EXPECT: All three environment variables set with valid values.

---

## 33. Report Generation

**Requires: A (OAIE CLI)**

### 33.1 Report for a basic run

```bash
$ oaie run -- echo "report test"
$ oaie report last
```

EXPECT: Markdown report with sections: Summary, Artifacts, Policy, Isolation.

### 33.2 Report for traced run

```bash
$ oaie run --trace ptrace -- echo "traced report"
$ oaie report last
```

EXPECT: Report includes Observed Accesses section with file/network events.

### 33.3 Report for signed run

```bash
$ oaie key generate --label report-test 2>/dev/null
$ oaie run --sign --trace ptrace -- echo "signed report"
$ oaie report last
```

EXPECT: Report includes Signature section.

---

## 34. Replay & Diff

**Requires: A (OAIE CLI)**

### 34.1 Replay a run

```bash
$ oaie run -- echo "replay me"
$ oaie replay last
```

EXPECT: Re-executes the same command. Shows comparison (match/mismatch).

### 34.2 Replay with diff

```bash
$ oaie replay last --diff
```

EXPECT: Hash details for any mismatched outputs.

### 34.3 Diff two runs

```bash
$ oaie run -- echo "run A"
$ RUN_A=$(oaie list -n 1 2>&1 | grep -oP '[0-9a-f-]{36}' | head -1)
$ oaie run -- echo "run B"
$ RUN_B=$(oaie list -n 1 2>&1 | grep -oP '[0-9a-f-]{36}' | head -1)
$ oaie diff $RUN_A $RUN_B
```

EXPECT: Side-by-side comparison showing differences.

### 34.4 Diff with trace comparison

```bash
$ oaie run --trace ptrace -- echo "trace A"
$ RUN_A=$(oaie list -n 1 2>&1 | grep -oP '[0-9a-f-]{36}' | head -1)
$ oaie run --trace ptrace -- echo "trace B"
$ RUN_B=$(oaie list -n 1 2>&1 | grep -oP '[0-9a-f-]{36}' | head -1)
$ oaie diff $RUN_A $RUN_B --trace
```

EXPECT: Also compares observed file/network accesses.

### 34.5 Diff using "last" shorthand

```bash
$ oaie run -- echo "first"
$ oaie run -- echo "second"
$ oaie diff last last
```

EXPECT: Shows comparison of the most recent run with itself (identical).

---

## 35. Export & Archival

**Requires: A (OAIE CLI)**

### 35.1 Export a run

```bash
$ oaie run --trace ptrace --sign -- echo "export me"
$ oaie export last
```

EXPECT: Creates `oaie-<short_id>.tar.gz` in current directory.

### 35.2 Export with custom path

```bash
$ oaie export last -o $OAIE_TEST_DIR/my-export.tar.gz
```

EXPECT: Archive at specified path.

### 35.3 Verify archive contents

```bash
$ tar tzf $OAIE_TEST_DIR/my-export.tar.gz | head -20
```

EXPECT: Contains `manifest.toml`, `signature.toml`, `REPORT.md`, `blobs/`, etc.

### 35.4 Archive is self-contained

```bash
$ mkdir /tmp/verify-export && cd /tmp/verify-export
$ tar xzf $OAIE_TEST_DIR/my-export.tar.gz
$ ls
```

EXPECT: All files needed for verification present.

---

## 36. Cleanup & Garbage Collection

**Requires: A (OAIE CLI)**

### 36.1 Dry run

```bash
$ oaie clean --dry-run --older-than 0s
```

EXPECT: Shows what would be removed without removing anything.

### 36.2 Clean old runs

```bash
$ oaie clean --older-than 0s
```

EXPECT: Removes all runs. `oaie list` shows empty.

### 36.3 Auto clean (7-day default)

```bash
$ oaie clean --auto
```

EXPECT: Removes runs older than 7 days.

### 36.4 Blob cleanup respects min age

```bash
$ oaie clean --older-than 0s --min-age 1h
```

EXPECT: Orphaned blobs younger than 1 hour are kept.

### 36.5 Verify store is clean

```bash
$ oaie list
```

EXPECT: Empty or only recent runs.

---

## 37. Doctor Diagnostics

**Requires: A (OAIE CLI) — shows status of all other components (B, C, D, E)**

### 37.1 Run full diagnostics

```bash
$ oaie doctor
```

EXPECT: 20 probes with color-coded results. Summary of isolation level,
trace backends, and storage stats.

### 37.2 Check each probe category

Review output for:
- User namespaces (green = available)
- Mount namespace
- PID namespace
- Net namespace
- ptrace scope
- CAS store health
- SQLite health
- Kernel CVEs
- Store permissions
- Landlock LSM
- Cgroup v2
- eBPF tracer
- Firecracker
- Ping group range
- Namespace headroom
- oaie-priv helper
- nftables
- IP forwarding
- nsenter
- Signing key

### 37.3 Interpret degraded probes

If any probe is yellow/red, follow the remediation hints provided.

---

## 38. Structured JSON Output

**Requires: A (OAIE CLI)**

### 38.1 JSON run output

```bash
$ oaie run --output json -- echo "json output"
```

EXPECT: StructuredRunResult as JSON on stdout. No banner.

### 38.2 Parse JSON output

```bash
$ oaie run --output json -- echo "parse me" 2>/dev/null | python3 -c "
import json, sys
result = json.load(sys.stdin)
print(f'exit_code={result[\"exit_code\"]}')
print(f'run_id={result[\"run_id\"]}')
"
```

EXPECT: Parsed fields from structured output.

### 38.3 JSON output preserves exit code

```bash
$ oaie run --output json -- false 2>/dev/null | python3 -c "
import json, sys
result = json.load(sys.stdin)
print(f'exit_code={result[\"exit_code\"]}')
"
```

EXPECT: `exit_code=1`

### 38.4 JSON verify output

```bash
$ oaie run -- echo "verify json"
$ oaie verify last --format json 2>/dev/null | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin), indent=2))"
```

EXPECT: Pretty-printed JSON with checks array.

---

## 39. Concurrency & Stress Testing

**Requires: A (OAIE CLI), G (Python 3 for session stress tests)**

### 39.1 Parallel runs

```bash
$ for i in $(seq 1 10); do
    oaie run -- echo "parallel-$i" &
  done
  wait
```

EXPECT: All 10 runs complete without errors.

### 39.2 Verify all parallel runs

```bash
$ oaie verify --all
```

EXPECT: All pass.

### 39.3 Rapid session tool calls

```bash
$ cat > $OAIE_TEST_DIR/input/rapid_agent.py <<'PYEOF'
import os, socket, json

sock_path = os.environ["OAIE_DISPATCH_SOCK"]
for i in range(20):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sock_path)
    request = json.dumps({"command": ["echo", f"rapid-{i}"], "timeout": "5s"}) + "\n"
    sock.sendall(request.encode())
    data = b""
    while b"\n" not in data:
        chunk = sock.recv(4096)
        if not chunk: break
        data += chunk
    sock.close()
print("All rapid calls done", flush=True)
PYEOF
$ oaie session run --budget-tools 50 --in $OAIE_TEST_DIR/input --timeout 60s -- python3 /in/rapid_agent.py
```

EXPECT: All 20 calls succeed sequentially.

### 39.4 Concurrent sessions

```bash
$ for i in $(seq 1 3); do
    oaie session run --budget-tools 5 --in $OAIE_TEST_DIR/input --timeout 30s -- python3 /in/agent.py &
  done
  wait
```

EXPECT: All 3 sessions complete independently.

---

## 40. Backward Compatibility

**Requires: A (OAIE CLI)**

### 40.1 Store without config.toml (legacy)

```bash
$ mkdir -p /tmp/legacy-store/cas /tmp/legacy-store/runs
$ sqlite3 /tmp/legacy-store/db.sqlite "CREATE TABLE IF NOT EXISTS schema_version(version INTEGER);"
$ OAIE_HOME=/tmp/legacy-store oaie list 2>&1
```

EXPECT: Handles gracefully — creates config.toml with defaults.

### 40.2 Run automated backward compatibility tests

```bash
$ cd path/to/oaie
$ cargo test --package oaie-tests backward_compat -- --test-threads=1
```

EXPECT: 6 tests pass.

---

## 41. Automated Test Suite

**Requires: A (OAIE CLI). Feature-gated tests also need B, C, D, E, F.**

### 41.1 Full test suite

```bash
$ cd path/to/oaie
$ timeout 300 make test
```

EXPECT: 668 tests pass. Zero failures.

### 41.2 Test categories breakdown

```bash
# Parallel unit tests (fast)
$ cargo test --package oaie-tests -- --test-threads=$(nproc) 2>&1 | tail -5

# Serial runner_e2e tests
$ cargo test --package oaie-tests runner_e2e -- --test-threads=1 2>&1 | tail -5

# Signing tests
$ cargo test --package oaie-tests signing -- --test-threads=1 2>&1 | tail -5

# Interactive tests
$ cargo test --package oaie-tests interactive -- --test-threads=1 2>&1 | tail -5

# Session tests
$ cargo test --package oaie-tests session -- --test-threads=1 2>&1 | tail -5

# Stress tests
$ cargo test --package oaie-tests stress -- --test-threads=1 2>&1 | tail -5

# v0.3 integration tests
$ cargo test --package oaie-tests v03_integration -- --test-threads=1 2>&1 | tail -5

# Backward compatibility tests
$ cargo test --package oaie-tests backward_compat -- --test-threads=1 2>&1 | tail -5
```

### 41.3 Feature-gated tests

```bash
# eBPF tests (requires oaie-priv + cgroups)
$ make test-ebpf

# Firecracker tests (requires /dev/kvm + assets)
$ make test-firecracker

# MCP server tests
$ make test-mcp

# Network policy tests
$ make test-netpol
```

### 41.4 Clippy (all variants)

```bash
$ make check-all
```

EXPECT: Zero warnings across all feature combinations.

---

## Validation Checklist Summary

| Area | Tests | Manual | Status |
|------|-------|--------|--------|
| Store init (BLAKE3 + SHA-256) | Sec 2 | 6 steps | |
| Basic execution | Sec 3 | 10 steps | |
| Output collection | Sec 4 | 5 steps | |
| Namespace isolation | Sec 5 | 9 steps | |
| Seccomp BPF | Sec 6 | 7 steps | |
| Resource limits (rlimits) | Sec 7 | 7 steps | |
| Cgroup v2 | Sec 8 | 6 steps | |
| Capabilities | Sec 9 | 4 steps | |
| Filesystem isolation | Sec 10 | 9 steps | |
| Environment sanitization | Sec 11 | 6 steps | |
| Network isolation | Sec 12 | 4 steps | |
| Network allowlist | Sec 13 | 5 steps | |
| Ptrace tracing | Sec 14 | 7 steps | |
| eBPF tracing | Sec 15 | 4 steps | |
| Firecracker VM | Sec 16 | 8 steps | |
| Interactive PTY | Sec 17 | 6 steps | |
| Ed25519 signing | Sec 18 | 8 steps | |
| Verification | Sec 19 | 6 steps | |
| CAS | Sec 20 | 5 steps | |
| DB & run management | Sec 21 | 7 steps | |
| Policy system | Sec 22 | 8 steps | |
| Session basic | Sec 23 | 7 steps | |
| Session budgets | Sec 24 | 4 steps | |
| Session containment | Sec 25 | 7 steps | |
| Session tool filtering | Sec 26 | 3 steps | |
| Session agent sandbox | Sec 27 | 3 steps | |
| Session approval gates | Sec 28 | 2 steps | |
| Session budget extension | Sec 29 | 2 steps | |
| Session heartbeat/crash | Sec 30 | 2 steps | |
| MCP server | Sec 31 | 4 steps | |
| Agent library | Sec 32 | 1 step | |
| Report generation | Sec 33 | 3 steps | |
| Replay & diff | Sec 34 | 5 steps | |
| Export | Sec 35 | 4 steps | |
| Cleanup & GC | Sec 36 | 5 steps | |
| Doctor diagnostics | Sec 37 | 3 steps | |
| Structured JSON output | Sec 38 | 4 steps | |
| Concurrency & stress | Sec 39 | 4 steps | |
| Backward compatibility | Sec 40 | 2 steps | |
| Automated test suite | Sec 41 | 4 steps | |
| **Total** | | **~200 steps** | |
