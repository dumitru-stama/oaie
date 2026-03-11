# OAIE Security Model Diagrams

## 1. Namespace Sandbox Execution

```
 HOST SYSTEM
 ===========================================================================

   User runs: oaie run --policy=safe -- ./my_program input.bin

                          |
                          v
                 +------------------+
                 |   OAIE Supervisor |  (unprivileged user process)
                 |   - timeout mgr   |
                 |   - output scan   |
                 |   - ptrace/eBPF   |
                 +--------+---------+
                          |
                          | clone() with namespace flags
                          |
 =========================|=====================================================
  ISOLATION BOUNDARY      |  (everything below is sandboxed)
 =========================|=====================================================
                          v
 +-----------------------------------------------------------------------+
 | SANDBOXED PROCESS  (UID 0 mapped to real user — no actual privileges) |
 +-----------------------------------------------------------------------+
 |                                                                       |
 |  6 LINUX NAMESPACES                                                   |
 |  +-----------------------------------------------------------------+  |
 |  | User NS    — UID 0 inside = real user outside (no root power)   |  |
 |  | Mount NS   — private mount tree, pivot_root to tmpfs            |  |
 |  | PID NS     — process 1 inside, invisible to host processes      |  |
 |  | IPC NS     — isolated shared memory, semaphores, msg queues     |  |
 |  | UTS NS     — separate hostname                                  |  |
 |  | Cgroup NS  — isolated cgroup view                               |  |
 |  | Net NS     — loopback only (no network unless policy allows)    |  |
 |  +-----------------------------------------------------------------+  |
 |                                                                       |
 |  SECCOMP BPF FILTER  (syscall firewall — kernel-enforced)             |
 |  +-----------------------------------------------------------------+  |
 |  | KILL (instant process death):                                   |  |
 |  |   io_uring_*, userfaultfd, kexec_*, init/finit/create_module,  |  |
 |  |   bpf, unshare, clone3, modify_ldt, iopl, ioperm   (14 total)  |  |
 |  +-----------------------------------------------------------------+  |
 |  | BLOCK with EPERM (return error, don't kill):                    |  |
 |  |   ptrace, mount, pivot_root, reboot, swapon/off, keyctl,       |  |
 |  |   perf_event_open, setns, chroot, syslog, seccomp,             |  |
 |  |   process_vm_read/write, pidfd_*, landlock_*, mknod,           |  |
 |  |   memfd_create* (*unless allow_memfd=true)        (55-57 total) |  |
 |  +-----------------------------------------------------------------+  |
 |  | ARGUMENT INSPECTION (allow syscall, block dangerous args):      |  |
 |  |   clone()  — kill if CLONE_NEW* namespace flags present         |  |
 |  |   socket() — block 11 address families:                         |  |
 |  |              AF_NETLINK, AF_PACKET, AF_CAN, AF_BLUETOOTH,       |  |
 |  |              AF_ALG, AF_VSOCK, AF_XDP, AF_NFC, ...              |  |
 |  |   prctl()  — block 6 ops: SET_DUMPABLE, SET_SECCOMP,           |  |
 |  |              SET_SECUREBITS, SET_MM, CAP_AMBIENT, SET_PTRACER   |  |
 |  |   ioctl()  — block TIOCSTI (keystroke inject),                  |  |
 |  |              TIOCLINUX (console manipulation)                    |  |
 |  +-----------------------------------------------------------------+  |
 |                                                                       |
 |  FILESYSTEM (minimal, isolated)                                       |
 |  +-----------------------------------------------------------------+  |
 |  | /           tmpfs root (pivot_root, old root unmounted)         |  |
 |  | /in         input directory (READ-ONLY bind mount)              |  |
 |  | /out        output directory (read-write bind mount)            |  |
 |  | /usr,/lib   system libraries (READ-ONLY)                       |  |
 |  | /proc       mounted with sensitive paths MASKED:                |  |
 |  |               /proc/net, /proc/*/tty, /proc/*/smaps*,          |  |
 |  |               /proc/self/attr/*, /proc/self/io, oom_adj        |  |
 |  | /sys        READ-ONLY                                          |  |
 |  | /dev        minimal: null, zero, random, urandom, console, pts |  |
 |  | /etc        synthetic: passwd + shadow only                     |  |
 |  +-----------------------------------------------------------------+  |
 |  | DENIED PATHS (never mounted, even if requested):                |  |
 |  |   ~/.ssh, ~/.gnupg, ~/.aws, ~/.azure, ~/.config/gcloud,        |  |
 |  |   ~/.docker, ~/.kube, ~/.npmrc, ~/.pypirc, ~/.netrc,           |  |
 |  |   ~/.git-credentials, ~/.password-store, ~/.vault-token,       |  |
 |  |   ~/.cargo/credentials*, ~/.config/gh, ~/.config/op, ...       |  |
 |  |                                             (24 credential paths)|  |
 |  +-----------------------------------------------------------------+  |
 |  | LANDLOCK (defense-in-depth filesystem restriction, kernel 5.13+)|  |
 |  +-----------------------------------------------------------------+  |
 |                                                                       |
 |  CAPABILITIES: ALL DROPPED                                            |
 |  +--------------------------------------------------+                 |
 |  | Effective = Permitted = 0 (no caps by default)   |                 |
 |  | Inheritable = 0 (no leak through execve)         |                 |
 |  | Policy may retain: CAP_NET_RAW, CAP_NET_BIND_SVC |                 |
 |  | (only 2 caps in allowlist — all others rejected)  |                 |
 |  +--------------------------------------------------+                 |
 |                                                                       |
 |  ENVIRONMENT: SANITIZED                                               |
 |  +--------------------------------------------------+                 |
 |  | Blocked: LD_*, GIT_*, PYTHONPATH, NODE_OPTIONS,  |                 |
 |  |   JAVA_TOOL_OPTIONS, CLASSPATH, RUBYLIB,         |                 |
 |  |   GCONV_PATH, BASH_ENV, IFS, OPENSSL_CONF, ...  |                 |
 |  | Set: PATH=/usr/local/bin:..., HOME=/root,        |                 |
 |  |   LANG=C.UTF-8, TERM=dumb                       |                 |
 |  +--------------------------------------------------+                 |
 |                                                                       |
 +-----------------------------------------------------------------------+


  RESOURCE LIMITS  (enforced by kernel — process cannot bypass)
  =====================================================================

  LAYER 1: RLIMITS (per-process, always active)
  +------------------------------------------------------------------+
  |  Resource          |  Default          |  Purpose                 |
  |--------------------+-------------------+--------------------------|
  |  Memory (AS)       |  512 MB soft      |  Virtual address space   |
  |                    |  (up to 8 GB)     |                          |
  |  CPU time          |  2x wall timeout  |  Prevents CPU spinning   |
  |                    |  (min 60s)        |  that evades timeout     |
  |  Processes (NPROC) |  64 soft/128 hard |  Fork bomb protection    |
  |  File size (FSIZE) |  1 GB             |  Disk fill protection    |
  |  Open files        |  1024/4096        |  FD exhaustion           |
  |  Locked memory     |  64 MB            |  mlock DoS prevention    |
  |  Core dumps        |  0 (disabled)     |  Prevent data leaks      |
  |  Message queues    |  0 (disabled)     |  POSIX MQ disabled       |
  |  Stack size        |  8 MB / 16 MB     |  Stack-smash defense     |
  +------------------------------------------------------------------+

  LAYER 2: CGROUP v2 (per-run scope, kernel-enforced, optional)
  +------------------------------------------------------------------+
  |  memory.max     =  policy max_memory  |  Hard OOM kill           |
  |  memory.swap.max = 0                  |  No swap (can't hide     |
  |                                       |  memory pressure)        |
  |  pids.max       =  policy max_pids    |  Hard fork bomb limit    |
  |  cpu.max        =  quota/period       |  CPU throttling          |
  |                    (e.g. 50%=50ms/100ms)                         |
  +------------------------------------------------------------------+

  LAYER 3: SUPERVISOR ENFORCEMENT (wall-clock, output limits)
  +------------------------------------------------------------------+
  |  Wall-clock timeout  =  5 min default (max 7 days)               |
  |  Max output files    =  10,000                                   |
  |  Max single file     =  256 MB                                   |
  |  Max total output    =  1 GB                                     |
  +------------------------------------------------------------------+


  NETWORK ISOLATION
  =====================================================================

  +-------------------+  +--------------------------+  +------------------+
  |    mode: Off      |  |    mode: Allowlist       |  |    mode: On      |
  |  (default)        |  |                          |  |                  |
  |  New net NS       |  |  New net NS              |  |  Host network    |
  |  Loopback only    |  |  veth pair + NAT         |  |  shared as-is    |
  |  No connectivity  |  |  nftables rules          |  |  No restrictions |
  |                   |  |  DNS proxy (127.0.0.53)  |  |                  |
  |                   |  |  TLS SNI inspection      |  |                  |
  |                   |  |  Per-host:port allowlist  |  |                  |
  +-------------------+  +--------------------------+  +------------------+
```


## 2. Firecracker MicroVM Execution

```
 HOST SYSTEM
 ===========================================================================

   User runs: oaie run --backend=firecracker -- ./my_program input.bin

                         |
                         v
                +------------------+
                |   OAIE Supervisor |  (unprivileged user process)
                |   - timeout mgr   |
                |   - output collect |
                +--------+---------+
                         |
                         | Spawns Firecracker process
                         | Configures via REST API (Unix socket)
                         |
                         v
               +---------------------+
               |  Firecracker VMM    |   (Virtual Machine Monitor)
               |  - KVM hypervisor   |   Hardware-enforced isolation
               |  - /dev/kvm         |
               +----------+----------+
                          |
 =========================|=============================================
  HARDWARE ISOLATION      |  KVM boundary — separate address space,
  BOUNDARY (CPU-enforced) |  separate kernel, no shared memory
 =========================|=============================================
                          |
                          v
 +-----------------------------------------------------------------------+
 | GUEST MICROVM                                                         |
 +-----------------------------------------------------------------------+
 |                                                                       |
 |  HARDWARE RESOURCES                                                   |
 |  +-----------------------------------------------------------------+  |
 |  | vCPUs       :  1 (default)                                      |  |
 |  | RAM         :  128 MB (default)                                 |  |
 |  | Network     :  NONE (no virtio-net device attached)             |  |
 |  | Storage     :  3 virtio-blk devices only:                       |  |
 |  |   /dev/vda  :  rootfs (read-only, minimal Linux)                |  |
 |  |   /dev/vdb  :  input image (read-only ext4)                     |  |
 |  |   /dev/vdc  :  output image (read-write ext4, 32 MB)           |  |
 |  +-----------------------------------------------------------------+  |
 |                                                                       |
 |  GUEST AGENT (oaie-guest, PID 1 — static musl binary)                |
 |  +-----------------------------------------------------------------+  |
 |  | - Boots as init (PID 1), no systemd, no shell                   |  |
 |  | - Communicates with host via AF_VSOCK (CID 3)                   |  |
 |  | - Receives job spec, runs tool process                          |  |
 |  | - Collects output files, sends results back                     |  |
 |  | - Guest seccomp blocks AF_VSOCK on TOOL process                 |  |
 |  |   (tool cannot talk to host, only agent can)                    |  |
 |  +-----------------------------------------------------------------+  |
 |                                                                       |
 |  KERNEL: Minimal Linux                                                |
 |  +-----------------------------------------------------------------+  |
 |  | Boot args: console=ttyS0 reboot=k panic=1 pci=off              |  |
 |  |            init=/oaie-guest                                     |  |
 |  | panic=1  : reboot on kernel panic (VM terminates)               |  |
 |  | pci=off  : no PCI bus (reduced attack surface)                  |  |
 |  +-----------------------------------------------------------------+  |
 |                                                                       |
 +-----------------------------------------------------------------------+


  VM LIFECYCLE TIMEOUTS
  =====================================================================

  +-------------------------------------------------------------------+
  | Phase                    | Timeout  | On failure                   |
  |--------------------------+----------+------------------------------|
  | VM boot (API socket)     |   5 sec  | Abort, kill process          |
  | Guest agent ready        |  30 sec  | Abort, kill process          |
  | Job execution            |  policy  | Guest notified, then kill    |
  |  (effective timeout)     | +10 sec  | (+10s margin for I/O)        |
  | Vsock read (per message) |  60 sec  | Connection error             |
  | Graceful shutdown        |   5 sec  | SIGKILL fallback             |
  +-------------------------------------------------------------------+


  COMMUNICATION PROTOCOL
  =====================================================================

  +-------------+        AF_VSOCK (CID 3)        +-------------+
  |    Host     | <=============================> |    Guest    |
  |  Supervisor |   Length-prefixed JSON messages  |    Agent    |
  +-------------+                                 +-------------+
       |                                                |
       | 1. Send JobSpec ---------------------------->  |
       |                                                | 2. Run tool
       |                                                |    process
       | 3. <------------- Receive ToolResult --------- |
       |    (exit code, stdout/stderr, output files)    |
       |                                                |
       | 4. Shutdown command ----------------------->   |
       |                                                |


  HOST-SIDE SAFETY (output extraction)
  =====================================================================

  +-------------------------------------------------------------------+
  | Output image (ext4) extracted on HOST after VM exits               |
  | Path traversal prevention:                                         |
  |   - Reject: "..", "/", "\", leading ".", NUL bytes                |
  |   - Defense-in-depth allowlist validation                          |
  +-------------------------------------------------------------------+
```


## 3. Side-by-Side Comparison

```
  +============================+========================+========================+
  |        RESOURCE            |   NAMESPACE SANDBOX    |   FIRECRACKER VM       |
  +============================+========================+========================+
  | Isolation mechanism        | Linux namespaces       | KVM hypervisor         |
  |                            | (OS-level)             | (hardware-level)       |
  +----------------------------+------------------------+------------------------+
  | Kernel                     | SHARED with host       | SEPARATE guest kernel  |
  +----------------------------+------------------------+------------------------+
  | Memory limit               | rlimit + cgroup        | VM RAM: 128 MB        |
  |                            | (512 MB default)       | (hard, cannot grow)    |
  +----------------------------+------------------------+------------------------+
  | CPU limit                  | rlimit + cgroup quota  | 1 vCPU (hard limit)    |
  +----------------------------+------------------------+------------------------+
  | Process limit              | rlimit + cgroup        | Within VM RAM          |
  |                            | (64 PIDs default)      | (self-limiting)        |
  +----------------------------+------------------------+------------------------+
  | Network                    | New net NS (none)      | No virtio-net device   |
  |                            | or veth + nftables     | (physically impossible)|
  +----------------------------+------------------------+------------------------+
  | Filesystem                 | tmpfs + bind mounts    | ext4 images            |
  |                            | read-only where needed | vda=RO, vdc=RW 32MB   |
  +----------------------------+------------------------+------------------------+
  | Syscall filtering          | Seccomp BPF            | Not needed (separate   |
  |                            | (69-71 blocked)        | kernel, no host calls) |
  +----------------------------+------------------------+------------------------+
  | Tracing support            | ptrace or eBPF         | Guest-side ptrace      |
  |                            | (full fidelity)        | (reduced integrity)    |
  +----------------------------+------------------------+------------------------+
  | Startup overhead           | ~15 ms                 | ~800 ms                |
  +----------------------------+------------------------+------------------------+
  | Credential protection      | 24 paths denied        | No host FS visible     |
  +----------------------------+------------------------+------------------------+
  | Capabilities               | All dropped            | N/A (separate kernel)  |
  +----------------------------+------------------------+------------------------+
  | Environment sanitized      | Yes (30+ vars blocked) | Clean (guest agent)    |
  +----------------------------+------------------------+------------------------+
  | Escape difficulty          | Requires kernel vuln   | Requires KVM + FC vuln |
  |                            | (1 boundary)           | (2 boundaries)         |
  +============================+========================+========================+
```


## 4. Defense-in-Depth Layers (Both Backends)

```
   For managers: Think of this as a building with multiple locked doors.
   An attacker must break through ALL layers to escape — not just one.

   NAMESPACE SANDBOX                          FIRECRACKER VM
   (6 layers deep)                            (4 layers deep)

   +--[Layer 6]---------------------------+
   | Landlock filesystem restrictions     |
   +--[Layer 5]---------------------------+   +--[Layer 4]------------------+
   | Seccomp BPF: 69-71 syscalls blocked  |   | Guest seccomp on tool      |
   +--[Layer 4]---------------------------+   |  (blocks AF_VSOCK escape)  |
   | All capabilities dropped             |   +--[Layer 3]------------------+
   +--[Layer 3]---------------------------+   | Separate Linux kernel      |
   | Cgroup v2: hard memory/PID/CPU caps  |   |  (no shared syscall table) |
   +--[Layer 2]---------------------------+   +--[Layer 2]------------------+
   | rlimits: memory, CPU time, files,    |   | Firecracker VMM            |
   | processes, stack, core dumps          |   |  (minimal device model,    |
   +--[Layer 1]---------------------------+   |   <50K lines of code)      |
   | 6 Linux namespaces                   |   +--[Layer 1]------------------+
   | (user, mount, PID, IPC, UTS, net)    |   | KVM hypervisor             |
   +--------------------------------------+   |  (hardware CPU isolation)  |
                                              +----------------------------+

   SHARED PROTECTIONS (both backends):
   +--------------------------------------------------------------+
   | - Wall-clock timeout (5 min default, max 7 days)             |
   | - Output size caps (10K files, 256 MB/file, 1 GB total)      |
   | - Credential path deny list (24 sensitive paths)              |
   | - Environment variable sanitization                           |
   | - Path traversal rejection on output extraction               |
   | - Supervisor-enforced session budgets (50 calls, 30 min,     |
   |   10 min tool time, 1 GB output)                              |
   +--------------------------------------------------------------+
```


## 5. Policy Presets Quick Reference

```
  +---------------------+--------+--------+------+---------+--------+---------+
  |  Preset             | Memory | Time   | PIDs | Network | Memfd  | Use For |
  +---------------------+--------+--------+------+---------+--------+---------+
  | safe (default)      | 512 MB | 5 min  |   64 | OFF     | no     | General |
  | net                 | 512 MB | 5 min  |   64 | ON      | no     | Network |
  | agent-safe          | 256 MB | 2 min  |   64 | OFF     | no     | AI tool |
  | agent-net           | 512 MB | 5 min  |   64 | ON      | no     | AI+net  |
  | agent-build         |   2 GB | 10 min |  256 | ON      | yes    | Builds  |
  | agent-analyze       |   1 GB | 15 min |  128 | OFF     | yes    | Analyze |
  | contained-local     |   1 GB | 10 min |  128 | OFF     | yes    | Local AI|
  | contained-cloud     | 512 MB | 5 min  |   64 | OFF     | no     | Cloud AI|
  | contained-strict    | 128 MB | 1 min  |   32 | OFF     | no     | Minimal |
  | contained-interactv |   1 GB | 10 min |  128 | OFF     | yes    | Human+AI|
  +---------------------+--------+--------+------+---------+--------+---------+

  "Memfd" = allow memfd_create/execveat (needed for JIT: Java, Node, .NET)
```
