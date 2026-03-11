# OAIE — Observed & Attested Isolated Execution

> *OAIE v0.1 targets developers who run untrusted tools, scripts, or build steps and want proof of what happened.*

## What OAIE Is

OAIE is a safe execution wrapper with built-in provenance.

You ask OAIE to run something. OAIE:

- Runs it inside strict isolation (or refuses to run)
- Enforces explicit capability boundaries
- Records artifacts content-addressed
- Observes what actually happened (out-of-band, untamperable by the tool)
- Produces a truthful, verifiable report

OAIE is **not** a container runtime, a workflow engine, a CI platform, or an AI chatbot.

OAIE is a calm, strict execution supervisor that makes `./tool` safer and accountable.

## Core Design Principle

```
sudo apt install oaie
oaie run ./tool
```

No services. No daemons. No setuid helpers. No root required.

**OAIE should feel like a safer `./tool`.**

Everything beyond this default path is an optional power-up. eBPF, Firecracker, cgroup accounting — all opt-in. The core product works as an unprivileged user from a single package install.

## Architecture: Three Planes

### 1. Execution Plane — where the tool runs

- Linux user namespaces (mount, PID, net, IPC, UTS, cgroup) — no root needed
- `/in` mounted read-only, `/out` mounted read-write
- No implicit network access
- **Five-layer sandbox defense (v0.1):**
  1. **Namespaces** — mount, PID, net, IPC, UTS, cgroup isolation via `clone()`
  2. **Capability dropping** — `capset()` clears all caps after mount setup + `PR_CAP_AMBIENT_CLEAR_ALL` (prevents re-mount /proc, FUSE, nested namespaces, cap inheritance across execve)
  3. **Two-tier seccomp deny-list** — blocks ~37 syscalls on x86_64 (~33 on asm-generic). Tier 1 (KILL_PROCESS, 13/9 syscalls): io_uring, userfaultfd, bpf, kexec, init_module, unshare, modify_ldt, iopl, ioperm — process terminated immediately. Tier 2 (ERRNO, 24 syscalls): mount, pivot_root, umount2, fsopen/fsconfig/fsmount/move_mount/open_tree (new mount API), memfd_create, execveat, perf_event_open, keyctl/add_key/request_key, kcmp, pidfd_send_signal, setns, delete_module, reboot, swapon/swapoff, acct, quotactl, clock_adjtime
  4. **Landlock LSM** (Linux 5.13+) — VFS-layer filesystem restrictions that survive namespace escape; graceful fallback on older kernels
  5. **rlimits** — RLIMIT_NPROC (fork bomb), RLIMIT_FSIZE (disk exhaustion), RLIMIT_AS (OOM), RLIMIT_NOFILE (FD exhaustion), RLIMIT_MEMLOCK, RLIMIT_MSGQUEUE=0, RLIMIT_CORE=0
- Resource limits: rlimit-level always enforced (Tier 1), cgroup-level applied when available (Tier 2, honestly reported)
- Hard error when namespaces are unavailable (explicit `--no-isolation` required to proceed)

### 2. Supervisor Plane — where OAIE lives

- Captures stdout/stderr
- Captures resource stats
- Captures ptrace events (execve, openat, connect)
- Stores observability out-of-band (tool cannot tamper with this)
- Writes to CAS and SQLite
- Generates manifest and REPORT.md

**This is OAIE's strongest differentiator.** The tool cannot influence its own observation record. Untamperable by the sandboxed process, not by a machine owner with root. OAIE provides tamper evidence within its trust boundary (supervisor vs tool), not absolute tamper proof against a privileged operator.

### 3. Artifact Plane — immutable storage

- Content-addressed artifacts (BLAKE3)
- Manifest per run
- Trace artifacts
- Hash-chained event logs
- Replay verification (with honest nondeterminism documentation)

## Two-Tier Capability Model

### Tier 1 — Default: safe isolation + provenance + tracing, no root

`oaie run ./tool` works as a normal user. Always.

| Capability | Method | Needs root? |
|---|---|---|
| Isolation | User namespaces (mount + PID + net) | No |
| Observability | ptrace (parent traces own child) | No |
| Provenance | CAS + manifest + hash-chain | No |
| Reporting | REPORT.md + `oaie inspect` | No |

If user namespaces are disabled (some enterprise distros), OAIE **refuses to run** and tells the user exactly how to fix it. The user must explicitly pass `--no-isolation` to run without sandboxing. A security tool must never silently degrade.

The main `oaie` binary is **never** setuid. This is non-negotiable.

### Tier 2 — Enhanced tracing pack: adds eBPF where supported, may require admin enablement

Ships as separate optional packages. Only for users who want them and understand them:

| Capability | Method | Package | Needs? |
|---|---|---|---|
| eBPF tracing | Kernel tracepoints filtered by cgroup | `oaie-ebpf` | `CAP_BPF` or root |
| Cgroup isolation | Dedicated cgroup per run | `oaie-ebpf` | Usually root |
| Firecracker backend | MicroVM execution | `oaie-firecracker` | root + KVM |

eBPF and Firecracker are separate optional packages (`oaie-ebpf` and `oaie-firecracker` respectively). They can be installed independently of each other. Privileged components are **never** bundled into the core `oaie` binary.

```
$ oaie run --trace=ebpf ./tool

OAIE: eBPF tracing requires elevated privileges on this system.
OAIE: Falling back to strace tracing. (use --no-fallback to error)
```

No one is forced into extra setup.

## Isolation Enforcement (No Silent Fallback)

When you run `oaie run ./tool`, OAIE probes capabilities and enforces isolation:

| Level | Isolation | Behavior | Report says |
|---|---|---|---|
| Full | userns + mountns + pidns + netns | All sandboxing active | `Isolation: full` |
| None (explicit) | `--no-isolation` passed | **User explicitly accepted the risk.** Hashes outputs, records manifest, captures stdout/stderr, optional ptrace | `Isolation: none` + warning |
| None (implicit) | No namespaces, no flag | **Hard error.** OAIE refuses to run. Prints remediation hint + `--no-isolation` instructions | N/A (run does not proceed) |

**A security tool must never silently degrade.** If the user thinks they're isolated but aren't, OAIE has made things *worse* by providing false confidence. The cost of one extra flag is nothing compared to the cost of a false sense of security.

OAIE always produces a manifest and report when it runs. But it only runs when the isolation contract is clear.

**When isolation is unavailable, OAIE errors with a clear, actionable message:**

```
$ oaie run -- ./untrusted_tool

Error: Namespace isolation is not available on this system.
User namespaces disabled on this system.
To enable: sudo sysctl -w kernel.unprivileged_userns_clone=1
(persistent: add kernel.unprivileged_userns_clone=1 to /etc/sysctl.d/99-oaie.conf)

To run without isolation (recording only):
  oaie run --no-isolation -- <command>

WARNING: Without isolation, the tool has full access to your system.
```

**When `--no-isolation` is explicitly passed:**

```
$ oaie run --no-isolation -- ./untrusted_tool

OAIE: WARNING: Running WITHOUT isolation (--no-isolation). The tool has full access to your system.
OAIE: Running: ./untrusted_tool
...
```

**Inside a container (no nested namespaces):**

```
$ oaie run -- ./tool

Error: Namespace isolation is not available on this system.
Running inside a container — nested user namespaces are not supported.

To run without isolation (recording only):
  oaie run --no-isolation -- <command>
```

**Tracing fallback is separate** — `--trace=ebpf` falls back to ptrace with a note (use `--no-fallback` to error). This is acceptable because tracing is *observability*, not a *security boundary*. Isolation fallback is NOT acceptable because isolation IS the security boundary.

---

## Sandbox Security Model

This section documents every escape vector the sandbox protects against, organized by attack class, and what legitimate functionality is affected. The goal is full transparency — a security auditor should be able to read this section and understand exactly what OAIE does and does not defend against.

### Escape vectors: blocked or mitigated

#### 1. Filesystem escape

| Vector | Attack | Defense | Week |
|---|---|---|---|
| Read host files (`~/.ssh`, `/etc/shadow`) | Tool reads sensitive host files | Mount namespace: only `/in`, `/out`, `/usr`, `/lib`, `/bin`, `/etc` (synthetic) are visible. `pivot_root` + unmount old root. | 4 |
| Write to host filesystem | Tool writes outside `/out` | Mount namespace: all mounts except `/out` are read-only. `/out` has MS_NODEV \| MS_NOSUID. | 4 |
| Symlink escape from `/out` | Tool creates symlink in `/out` pointing to host path; OAIE follows it during output scanning | `openat2(RESOLVE_NO_SYMLINKS \| RESOLVE_BENEATH)` for output ingestion. Symlinks in `/out` are rejected. | 4 |
| Remount `/in` read-write | Tool calls `mount -o remount,rw /in` | Capabilities dropped (no CAP_SYS_ADMIN) + `mount` in seccomp ERRNO list. | 4 |
| Mount fresh `/proc` (unmasked) | Tool mounts `proc` filesystem to undo `/proc` masking | Capabilities dropped + `mount` in seccomp ERRNO + `fsopen`/`fsmount` in seccomp ERRNO. | 4 |
| Unmount `/proc` masks | Tool calls `umount2("/proc/sys", MNT_DETACH)` | `umount2` in seccomp ERRNO list. | 4 |
| New mount API bypass | Tool uses `fsopen` → `fsconfig` → `fsmount` → `move_mount` instead of `mount()` | All five new mount API syscalls in seccomp ERRNO list. | 4 |
| Device node creation in `/out` | Tool creates `/out/evil_device` via `mknod` | MS_NODEV on `/out` mount. Capabilities dropped (no CAP_MKNOD for real devices). | 4 |
| Setuid binary exploitation | Tool executes setuid binary from bind-mounted `/usr` | `PR_SET_NO_NEW_PRIVS` blocks setuid. MS_NOSUID on all system library mounts. User namespace ignores real setuid. | 4 |

#### 2. /proc information disclosure and escape

| Vector | Attack | Defense | Week |
|---|---|---|---|
| `/proc/self/mem` code patching | Write to own executable pages to patch out seccomp filter | Masked with `/dev/null`. Tool cannot open `/proc/self/mem`. | 4 |
| `/proc/kallsyms` KASLR bypass | Read kernel symbol addresses to defeat ASLR | Masked with `/dev/null`. | 4 |
| `/proc/kcore` memory read | Read physical memory | Masked with `/dev/null`. | 4 |
| `/proc/keys` keyring disclosure | Read kernel keyring contents | Masked with `/dev/null`. | 4 |
| `/proc/sysrq-trigger` system reboot | Write to trigger kernel SysRq handler | Masked with `/dev/null`. | 4 |
| `/proc/sys` kernel tuning | Write to change kernel parameters | Mounted as read-only empty tmpfs. | 4 |
| `/proc/sys/kernel/core_pattern` escape | Write pipe handler that executes as root on crash | `/proc/sys` mounted as RO tmpfs. | 4 |
| `/proc/self/pagemap` Rowhammer | Read physical page frame numbers for targeted bit flips | Masked with `/dev/null`. | 4 |
| `/proc/self/oom_score_adj` OOM evasion | Write -1000 to become OOM-immune, then exhaust host memory | Masked with `/dev/null`. | 4 |
| `/proc/self/exe` host path leak | Read symlink to discover host filesystem layout | Masked with `/dev/null`. | 4 |
| `/proc/self/timerslack_ns` timing precision | Write 0 for maximum timer resolution in side-channel attacks | Masked with `/dev/null`. | 4 |
| `/proc/timer_list` timing side-channel | Read host-wide scheduling patterns and timer state | Masked with `/dev/null`. | 4 |
| `/proc/interrupts` timing side-channel | Read interrupt rates for cache probing | Masked with `/dev/null`. | 4 |
| `/proc/softirqs` timing side-channel | Read softirq statistics for timing attacks | Masked with `/dev/null`. | 4 |
| `/proc/<host_pid>/root` traversal | Traverse other process's root to escape mount namespace | PID namespace: `/proc` only shows sandbox PIDs. No host PIDs visible. | 4 |
| `/proc/self/cgroup` host info leak | Read host cgroup path to learn UID, session, systemd slice | CLONE_NEWCGROUP: `/proc/self/cgroup` shows `/` as root. | 4 |

#### 3. Namespace and capability escape

| Vector | Attack | Defense | Week |
|---|---|---|---|
| Nested user namespace (`unshare`) | `unshare(CLONE_NEWUSER)` → regain caps → mount fresh /proc → escape | `unshare` in seccomp KILL list. | 4 |
| Nested user namespace (`clone`) | `clone(CLONE_NEWUSER)` — same effect, cannot block clone | Seccomp blocks steps 2-4 of chain (mount, fsopen, fsmount). Ptrace detects the attempt as `nested_userns_via_clone`. | 4, 7 |
| Nested user namespace (`clone3`) | `clone3` with `CLONE_NEWUSER` in `clone_args` struct | Same seccomp + ptrace detection as clone. | 4, 7 |
| Join host namespace (`setns`) | `setns(fd, nstype)` to re-enter host namespace via leaked FD | `setns` in seccomp ERRNO list. `close_range` + PID namespace prevent obtaining host namespace FDs. | 4 |
| Capability re-acquisition after `capset` | Tool exploits that `capset()` errors are silently ignored | 8 cap-requiring syscalls added to seccomp ERRNO as safety net (delete_module, reboot, swapon/swapoff, acct, quotactl, clock_adjtime, setns). | 4 |
| Ambient capability inheritance | Capabilities survive execve via ambient set | `PR_CAP_AMBIENT_CLEAR_ALL` after `capset()`. | 4 |
| `pivot_root` filesystem manipulation | Tool changes its filesystem root | `pivot_root` in seccomp ERRNO list. | 4 |

#### 4. Kernel exploitation primitives

| Vector | Attack | Defense | Week |
|---|---|---|---|
| `io_uring` kernel bugs | CVE-2023-2598, CVE-2022-29582, CVE-2023-21400 | `io_uring_setup/enter/register` in seccomp KILL list. | 4 |
| `userfaultfd` TOCTOU enabler | Pause kernel during `copy_from_user()` for reliable race conditions | `userfaultfd` in seccomp KILL list. | 4 |
| `bpf` verifier bugs | CVE-2021-3490, CVE-2022-23222 — eBPF verifier bypass | `bpf` in seccomp KILL list. | 4 |
| `perf_event_open` Spectre | Cache timing, branch prediction side-channels. CVE-2022-1729. | `perf_event_open` in seccomp ERRNO list. | 4 |
| `modify_ldt` LDT corruption | CVE-2017-1000112 class — custom code segments for kernel memory corruption | `modify_ldt` in seccomp KILL list (x86_64 only). | 4 |
| `iopl`/`ioperm` I/O ports | Direct hardware I/O port access | Both in seccomp KILL list (x86_64 only). | 4 |
| Kernel module loading | `init_module`/`finit_module` — load arbitrary kernel code | Both in seccomp KILL list. `delete_module` in ERRNO list. | 4 |
| Kernel replacement | `kexec_load`/`kexec_file_load` — replace running kernel | Both in seccomp KILL list. | 4 |
| `keyctl` refcount overflow | CVE-2016-0728, CVE-2020-7053 — kernel keyring bugs | `keyctl`/`add_key`/`request_key` in seccomp ERRNO list. | 4 |
| Dirty Pipe (`vmsplice`) | CVE-2022-0847 — overwrite read-only file page cache | `vmsplice` flagged in ptrace with `SPLICE_F_GIFT` inspection. | 7 |
| Spectre mitigation tampering | `prctl(PR_SET_SPECULATION_CTRL, *, PR_SPEC_ENABLE)` re-enables SSB | Detected by ptrace, flagged in trace. | 7 |

#### 5. Process and signal escape

| Vector | Attack | Defense | Week |
|---|---|---|---|
| Fork bomb | `:(){ :\|:& };:` exhausts PID table | `RLIMIT_NPROC` (128/256). PID namespace. Cgroups (week 11). | 4 |
| Signal supervisor | `kill(supervisor_pid, SIGKILL)` | PID namespace: tool cannot see or signal host PIDs. | 4 |
| `pidfd_send_signal` cross-namespace | Signal host process via pidfd obtained before namespace creation | `pidfd_send_signal` in seccomp ERRNO list. PID namespace prevents obtaining external pidfds. | 4 |
| `clone3(CLONE_INTO_CGROUP)` cgroup escape | Place child in less-restricted cgroup | Detected by ptrace. `/sys/fs/cgroup` not mounted. | 7 |
| `prctl(PR_SET_CHILD_SUBREAPER)` | Intercept orphaned child processes from tracing infrastructure | Detected by ptrace. | 7 |
| `prctl(PR_SET_MM)` | Modify memory map metadata to confuse introspection | Detected by ptrace. | 7 |
| ASLR/NX bypass via `personality()` | `personality(ADDR_NO_RANDOMIZE \| READ_IMPLIES_EXEC)` | `personality(0)` called in sandbox setup. Detected by ptrace if called again. | 4, 7 |
| Anti-debugging via `ptrace(TRACEME)` | Child calls TRACEME before OAIE attaches | `PTRACE_O_TRACECLONE` auto-attaches. TRACEME detected by ptrace. | 7 |

#### 6. Network escape

| Vector | Attack | Defense | Week |
|---|---|---|---|
| TCP/UDP network access | Exfiltrate data over the network | CLONE_NEWNET: empty network namespace (no interfaces). | 4 |
| `AF_VSOCK` hypervisor bypass | Communicate with VM host regardless of net namespace | Detected by ptrace (`socket_af_vsock`). Only relevant on VMs with virtio-vsock. | 7 |
| `AF_BLUETOOTH` bypass | Communicate with nearby Bluetooth devices | Detected by ptrace (`socket_af_bluetooth`). Requires CONFIG_BT + adapter. | 7 |
| `AF_XDP` raw packets | Raw packet access via XDP eBPF sockets | Detected by ptrace (`socket_af_xdp`). Requires CAP_NET_ADMIN (dropped). | 7 |
| `AF_ALG` kernel crypto | Direct kernel crypto API — CVE-2023-6176, CVE-2024-0775 | Detected by ptrace (`socket_af_alg`). | 7 |
| `AF_PACKET` raw sockets | Raw packet capture/injection | Detected by ptrace (`socket_af_packet`). Requires CAP_NET_RAW (dropped). | 7 |
| `SOCK_RAW` | Raw socket creation | Detected by ptrace (`socket_sock_raw`). | 7 |
| `AF_NETLINK` host info leak | Probe routing tables, firewall rules, interface config | Detected in sockaddr parser. Net namespace limits visible interfaces. | 7 |

#### 7. Terminal injection

| Vector | Attack | Defense | Week |
|---|---|---|---|
| `TIOCSTI` keystroke injection (non-interactive) | CVE-2017-5226 — push keystrokes into supervisor's terminal via ioctl on inherited stdin | `setsid()` (sufficient on kernel 6.2+) + stdin redirected to `/dev/null` (required on kernels 5.13–6.1 where TIOCSTI works on any terminal FD regardless of controlling terminal). | 4 |
| `TIOCSTI` keystroke injection (interactive mode) | Push keystrokes via ioctl on the PTY slave FD | The slave PTY is a **new terminal device**, not the supervisor's terminal. `setsid()` makes the child the session leader of the PTY session. TIOCSTI on the slave pushes characters into the master's read buffer — the supervisor's copy loop reads them as display data, does NOT execute them as shell commands. The user's actual terminal is never exposed. This is the same model Docker uses with `docker run -it`. | 4 |
| `TIOCLINUX` console injection | CVE-2017-5226 — inject via virtual console selection paste | `setsid()` + no `/dev/tty` or `/dev/console` in sandbox + `close_range()` + stdin redirected to `/dev/null` (or PTY slave in interactive mode). | 4 |

#### 8. File descriptor and IPC escape

| Vector | Attack | Defense | Week |
|---|---|---|---|
| Inherited supervisor FDs | Read CAS, SQLite, pipe FDs inherited from supervisor | `close_range(3, MAX)` in child. All supervisor FDs opened with `O_CLOEXEC`. | 4 |
| `pidfd_getfd` FD theft | Duplicate FDs from supervisor via pidfd | `pidfd_getfd` detected by ptrace. PID namespace prevents obtaining supervisor pidfd. | 7 |
| `kcmp` FD probing | Probe whether FDs point to same file as supervisor's | `kcmp` in seccomp ERRNO list. Detected by ptrace with target PID enrichment. | 4, 7 |
| SysV IPC cross-sandbox | Shared memory, message queues, semaphores | CLONE_NEWIPC isolates SysV IPC. | 4 |
| POSIX mqueue memory exhaustion | Create many mqueues to consume kernel memory | `RLIMIT_MSGQUEUE = 0`. | 4 |
| Kernel keyring cross-sandbox IPC | Store data in session keyring that persists after sandbox exits | `keyctl`/`add_key`/`request_key` in seccomp ERRNO list. | 4 |

#### 9. Resource exhaustion (DoS)

| Vector | Attack | Defense | Week |
|---|---|---|---|
| Memory exhaustion (OOM-kill) | `mmap(MAP_ANONYMOUS, 128GB)` triggers OOM-killer for host processes | `RLIMIT_AS` (4GB soft / 8GB hard). | 4 |
| File descriptor exhaustion | Open 65536+ FDs, exhaust system-wide FD table | `RLIMIT_NOFILE` (1024/4096). | 4 |
| Memory locking exhaustion | `mlock()` pins all physical RAM | `RLIMIT_MEMLOCK` (64MB). | 4 |
| Disk exhaustion via `/out` | Write multi-GB files filling host disk | `RLIMIT_FSIZE` (1GB). | 4 |
| tmpfs exhaustion | Fill `/tmp` to exhaust RAM | tmpfs `size=64m` limit. | 4 |
| Core dump data leak | Trigger crash → core dump writes secrets to systemd-coredump | `PR_SET_DUMPABLE=0` + `RLIMIT_CORE=0`. | 4 |

#### 10. Observation evasion

| Vector | Attack | Defense | Week |
|---|---|---|---|
| `io_uring` ptrace bypass | Perform file/network I/O invisible to ptrace | `io_uring` blocked by seccomp (KILL). If it reaches ptrace, hard WARNING that trace is incomplete. | 4, 7 |
| `seccomp(SECCOMP_SET_MODE_FILTER)` | Install own BPF filter to suppress syscalls before ptrace sees them | `seccomp()` syscall detected by ptrace. Tool's filter cannot remove OAIE's (seccomp is append-only). | 7 |
| `prctl(PR_SET_SECCOMP)` | Alternative seccomp installation path | Detected by ptrace as seccomp alias. | 7 |
| Fileless execution | `memfd_create` + `execveat(AT_EMPTY_PATH)` — no file on disk for CAS to hash | Both in seccomp ERRNO. Ptrace correlates memfd_create → execveat and flags as `fileless_exec_detected`. | 4, 7 |
| `prctl(PR_SET_PTRACER)` | Override Yama LSM ptracer restrictions | Detected by ptrace. | 7 |

#### 11. Information disclosure

| Vector | Attack | Defense | Week |
|---|---|---|---|
| Environment variables leak host paths | Tool reads `$HOME`, `$OAIE_STORE`, etc. | Environment sanitized: only `PATH`, `HOME=/root`, `TERM=dumb`, `LANG=C.UTF-8`. | 4 |
| Hostname leaks host identity | `gethostname()` reveals host | CLONE_NEWUTS: UTS namespace isolation. | 4 |
| `/proc/self/exe` leaks host path | `readlink("/proc/self/exe")` reveals install location | Masked with `/dev/null`. | 4 |
| Timer precision for side-channels | `prctl(PR_SET_TIMERSLACK, 0)` or rdtsc/rdtscp for high-precision timing | timerslack_ns masked + prctl(29) detected by ptrace (week 7). **rdtsc cannot be blocked at process level** — requires VM isolation (Firecracker). | 4, 7 |

### Not blocked (and why)

These are things the sandbox deliberately does NOT block because they would break legitimate tools without meaningful security benefit:

| Syscall/feature | Why not blocked | Who needs it |
|---|---|---|
| `read`, `write`, `open`, `close`, `stat` | Core POSIX. Blocking = nothing works. | Everything |
| `mmap`, `mprotect(PROT_EXEC)` | Needed for JIT compilation, dynamic linking | JVM, Node.js, Python, V8, any runtime |
| `fork`, `clone`, `clone3` | Needed for process creation and threading | Any multi-process or multi-threaded tool |
| `execve` | Needed to run programs | Everything |
| `socket`, `connect`, `sendto`, `recvfrom` | Needed when `--net` is passed. In no-net mode, net namespace blocks them. | `curl`, `wget`, package managers |
| `ioctl` | Used by virtually every program (terminal I/O, etc.). Attack surface controlled by minimal `/dev`. | Everything |
| `ptrace` | Tool can only ptrace its own children (PID namespace + OAIE already tracing). Blocking breaks debuggers. | GDB, strace, lldb |
| `kill`, `tgkill` | PID namespace limits targets to sandbox processes. | Any signal-using program |
| `clock_gettime` | Every program needs timekeeping. | Everything |
| `madvise` | Memory optimization hints. `MADV_MERGEABLE` (KSM) is a theoretical side-channel but KSM is off by default and `/proc/sys` is masked. | mmap-heavy tools |
| `mincore` | Legitimate mmap I/O optimization. Side-channel fixed in kernel 5.0+. | Database engines, file processing |
| `prctl` (most options) | Only suspicious options are detected (SET_CHILD_SUBREAPER, SET_MM, SET_SECCOMP, SET_PTRACER, SET_SPECULATION_CTRL). | Various |
| `/proc/self/maps` | Shows tool's own memory layout, not host. ASLR active. | Debuggers, profilers, crash handlers |
| `/proc/self/status` | Shows TracerPid (tool can detect it's traced). Documented — tool can't escape regardless. | Anti-debug checks (harmless in sandbox) |
| Landlock (tool installing) | Landlock is restrictive-only — tool can restrict itself further but cannot expand access. | Security-conscious tools |
| seccomp (tool installing) | Seccomp is append-only — tool can add restrictions but cannot remove OAIE's filter. | Chrome, Firefox, any sandboxed runtime |

### App compatibility impact

The sandbox is designed to be invisible to well-behaved tools. Here is what might actually be noticed:

#### Works without any flags

`cat`, `grep`, `sed`, `awk`, `find`, `ls`, `diff`, `sort`, `head`, `tail`, `wc`, `jq`, `python3`, `python3 -c "..."`, `node -e "..."`, `ruby -e "..."`, `perl -e "..."`, `gcc`, `g++`, `clang`, `rustc`, `go build`, `make`, `cmake`, `ninja`, `cargo build` (read-only deps), `rizin`, `radare2`, `objdump`, `readelf`, `strings`, `file`, `hexdump`, `xxd`, `sha256sum`, `base64`, `tar` (extract to `/out`), `gzip`/`gunzip`, `xz`, `zstd`, `sqlite3` (on files in `/in` or `/out`), non-interactive tools with file arguments auto-mounted

#### Works with `-i` flag (interactive mode)

`vim`, `nano`, `less`, `more`, `top`, `htop`, `tmux` (single session), any ncurses/readline/terminal app. Full PTY: `isatty(0)` returns true, TERM inherited from supervisor, signal delivery works (Ctrl-C → SIGINT via PTY line discipline).

#### Works with `--net` flag

`curl`, `wget`, `pip install`, `npm install`, `cargo fetch`, `apt download`, `git clone`, DNS resolution, any tool that makes network connections

#### Works with policy overrides (week 5)

| Situation | Override | Example tools |
|---|---|---|
| Tool needs > 4GB virtual memory | `rlimit_as = "16GB"` | Large dataset processors, some compilers on huge codebases |
| Tool probes `memfd_create` | `allow_memfd = true` | Some JIT runtimes that prefer memfd over temp files (rare — most fall back gracefully) |
| Tool needs writable scratch space with exec | `extra_rw = ["/scratch"]` | Build systems that compile and run in temp dirs |
| Tool needs specific host paths | `extra_ro = ["/opt/toolchain"]` | Cross-compilers, vendor SDKs |
| Tool needs `/proc/self/mem` | `allow_proc_self_mem = true` | Extremely rare — debuggers use ptrace, JITs use mmap |
| Tool needs to create files next to input (e.g. `.bak`, `.orig`) | `--rw /path/to/dir` (explicit RW on parent dir) | Build tools that produce outputs next to inputs |
| Tool needs file argument auto-mount disabled | `auto_mount = false` or `--no-auto-mount` | When strict mount control is needed |

#### Does not work (by design)

| What breaks | Why | This is intentional because... |
|---|---|---|
| `mount` / `umount` | Seccomp blocks it | A sandboxed tool should never mount filesystems |
| `unshare` (create namespaces) | Seccomp KILL | A sandboxed tool should never create nested namespaces |
| `perf record` / `perf stat` | `perf_event_open` blocked | Side-channel attack surface; profiling tools are not sandbox targets |
| Writing outside `/out` | Read-only mounts | The entire point of sandboxing |
| Accessing `~/.ssh`, `~/.aws`, `~/.gnupg` | Not mounted | The entire point of sandboxing |
| Docker-in-sandbox | `unshare` blocked, no cgroups | Container runtimes need kernel-level access the sandbox denies |
| `strace` / `gdb` inside sandbox on sandbox processes | OAIE already tracing; only one tracer per process | Debugging inside the sandbox requires `--no-isolation` |
| FUSE filesystems | `mount`/`fsopen` blocked, no `/dev/fuse` | Userspace filesystems are a mount-namespace escape |
| io_uring async I/O | Seccomp KILL | Bypasses ptrace observation entirely |

#### What ERRNO-tier syscalls look like to tools

The ERRNO tier returns `EPERM` — the same error tools get when running as an unprivileged user outside a sandbox. Well-written tools already handle this:

```
$ oaie run -- python3 -c "import os; os.memfd_create('test')"
# Python gets OSError: [Errno 1] Operation not permitted
# Same as running without CAP_SYS_ADMIN on a restricted system

$ oaie run -- sh -c "mount -t proc proc /proc"
# mount: permission denied (same as any non-root user)
```

The tool doesn't know it's in a sandbox — it just thinks it's running as an unprivileged user on a system that doesn't grant those capabilities. This is exactly what makes the deny-list approach robust: tools already have fallback paths for these errors because they encounter them on hardened systems and containers.

---

## Default Behavior

```
oaie run ./weird_tool
```

What happens:

- `/in` = current directory (read-only)
- `/out` = `./oaie-out/<run_id>/` (read-write)
- Network disabled by default (`--no-net`)
- Tight resource limits applied
- stdout/stderr captured
- Outputs hashed and stored in CAS
- REPORT.md generated
- File paths in arguments auto-detected and mounted transparently

Then:

```
oaie inspect last
```

Shows:

- **Reachable** inputs (what the sandbox allowed access to)
- **Observed** accesses (what the tool actually touched, if traced)
- Outputs produced with hashes
- Any network attempts
- Process tree (if traced)
- Exit code and resource usage

The distinction between *reachable* and *observed* is central to OAIE's report model. Most tools conflate these. OAIE does not.

### Interactive mode and transparent file access

```bash
# Edit a file interactively
oaie run -i -- vim ~/documents/draft.txt
# OAIE: Auto-mounting /home/user/documents/ (read-only)
# OAIE: Auto-mounting /home/user/documents/draft.txt (read-write, file-level)
# vim opens with full terminal support, saves work in-place

# Run a tool on a specific file (non-interactive)
oaie run -- /opt/tools/analyzer ~/samples/binary.elf
# OAIE: Auto-mounting /opt/tools/ (read-only) — executable
# OAIE: Auto-mounting /home/user/samples/ (read-only)
# OAIE: Auto-mounting /home/user/samples/binary.elf (read-write, file-level)

# Disable auto-mount for strict control
oaie run --no-auto-mount --ro /data -- grep pattern /data/file.txt
```

**Auto-mount**: OAIE scans command arguments for existing file paths and mounts them with minimal privilege. Parent directories are bind-mounted **read-only** (giving the tool visibility for tab completion, relative path resolution, etc.), then the specific file argument is bind-mounted **read-write** on top. This means the tool can only write to the exact files the user specified — not create new files, not modify neighbors. Editors that attempt atomic save (write temp → rename) will fail the rename and fall back to in-place truncate+write, which works because the file itself is RW. Editor scratch files (`.swp`, `~` backups) go to sandbox-local `/tmp` instead of the original directory.

**Interactive mode** (`-i`): Allocates a PTY so terminal apps (vim, nano, less, top, htop) work inside the sandbox. The sandbox still provides full isolation — the PTY is a new terminal device, not the supervisor's terminal.

**Design principle**: "If somebody is invoking OAIE with a specific file as parameter, I assume they know what they're doing. It's on host anyways so they can do anything anyways." The sandbox protects the user FROM the tool, not the tool FROM the user. Explicit file arguments should be transparently available.

## UX Philosophy

```
oaie run job.toml
oaie run -- ./tool --flag
oaie run -i -- vim /path/to/file
oaie inspect <run_id>
oaie inspect last
oaie replay <run_id>
oaie verify <run_id>
```

No 20 flags. No hidden defaults. No hype. Everything explicit.

Presets for common cases:

- `--safe` (default): no net, RO in, RW out, tight limits
- `--net`: explicitly allow network
- `-i` / `--interactive`: allocate PTY for terminal apps (vim, nano, less)
- `--no-auto-mount`: disable automatic file path detection and mounting
- `--in <path>` / `--out <path>` / `--ro <path>` / `--rw <path>`: mount control
- `--trace=strace`: enable syscall observation (friendly name, implemented via ptrace internally)
- `--trace=ptrace`: explicit/advanced alias for strace mode
- `--trace=ebpf`: enable kernel-level observation (Tier 2, optional power-up)
- `--trace=auto`: use best available backend (eBPF if available, falls back to ptrace)

## Mascot

The sheep is calm, neutral, slightly warm. Not silly, not aggressive.

It communicates: *"You are safe. I am watching."*

It does not define technical credibility. Architecture does. But it gives the project memorability.

---

## 10-Week Development Plan (v0.1)

### Phase 0: Identity (Week 1)

#### Week 1 — Repo skeleton + CLI + identity

**Goal:** OAIE feels real and consistent from day one.

**Deliverables:**
- Cargo workspace with crates:
  - `oaie-cli` — command dispatch, output formatting
  - `oaie-core` — run model, config parsing, job.toml schema
  - `oaie-cas` — content-addressed store
  - `oaie-db` — SQLite index (WAL mode)
  - `oaie-sandbox` — Linux namespace isolation
  - `oaie-observe` — ptrace tracer, event stream
  - `oaie-report` — REPORT.md and manifest generation
- CLI commands stubbed: `run`, `inspect`, `replay`, `verify`
- Directory layout established:
  ```
  ~/.oaie/
    runs/
    cas/
    db.sqlite
  ```
- `oaie init` creates the store
- Mascot SVG placeholder included
- `oaie.run` static page updated

**Milestone:** `oaie run --help` reads clean and memorable. `oaie init` creates the local store.

---

### Phase A: Safe Execution + Provenance (Weeks 2–5)

**Goal:** `oaie run ./tool` works end-to-end with isolation and produces honest, verifiable reports.

#### Week 2 — CAS + run directory model

**Goal:** Everything OAIE produces is a content-addressed artifact.

**Deliverables:**
- CAS store implementation (BLAKE3, `cas/<2-char prefix>/<hash>`)
- Deduplication on store
- Run directory structure:
  ```
  runs/<run_id>/
    manifest.toml
    REPORT.md
    events.log
  ```
- SQLite index for runs and artifacts
- `oaie cas add <file>` and `oaie cas verify <hash>`

**Milestone:** `oaie inspect <run_id>` prints stored metadata and artifact hashes.

#### Week 3 — Runner (no isolation) + outputs hashed

**Goal:** Run, capture, store, report — the full loop without sandboxing.

**Deliverables:**
- Execute command from CLI args or `job.toml`
- Capture stdout/stderr as CAS artifacts
- Enumerate `/out` outputs, hash and store each
- Produce `manifest.toml` linking all artifacts
- Generate `REPORT.md` ("what ran, what was produced, exit code")
- `oaie inspect last` shorthand

**Milestone:** `oaie run -- echo hello` works end-to-end. Manifest, report, and CAS artifacts are all correct.

#### Week 4 — Namespace isolation

**Goal:** "Run untrusted tool safely" becomes true.

**Deliverables:**
- User namespace creation (no root)
- Mount namespace with private propagation:
  - `/in` bound read-only from specified input path
  - `/out` bound read-write to run output directory
  - Minimal `/proc` (enough for common tools)
  - No access to `~/.ssh`, `~/.gnupg`, `~/.config`, etc.
- PID namespace (tool sees only its own process tree)
- Network namespace with no interfaces (default `--no-net`)
- Interactive mode (`-i`): PTY allocation for terminal apps (vim, nano, less)
  - Slave PTY as stdin/stdout/stderr in child (full terminal emulation)
  - Supervisor bidirectional copy loop with raw mode
  - TIOCSTI-safe: slave PTY is isolated from supervisor's terminal
  - Output tee: live display + capture file for manifest
- Auto-mount: transparent file path detection from command arguments
  - Parent directory mounted read-only (visibility for tab completion, relative paths)
  - Specific file argument bind-mounted read-write on top (minimal write surface)
  - Executables and their directories mounted read-only
  - Editors fall back from atomic save to in-place write; scratch files go to sandbox `/tmp`
  - /proc, /sys, /dev paths never auto-mounted
- Capability probing: detect what namespaces are available on this kernel/distro
- Pre-flight check: if user namespaces disabled, hard error with remediation hint (require `--no-isolation` to proceed)
- Report includes isolation level achieved and reachable input list

**Milestone:** Demo: a tool cannot read `~/.ssh`, cannot access the network. `oaie run -i -- vim /tmp/file.txt` opens vim with full terminal support. `oaie inspect` shows isolation level as `full`.

**Known risks:** Mount propagation edge cases, `/proc` handling for tools that need `/proc/self`, kernel version differences (5.x vs 6.x). Budget overflow time here.

#### Week 5 — Policy layer + ergonomic presets

**Goal:** Make it easy to do the right thing.

**Deliverables:**
- `policy.toml` file format:
  ```toml
  [defaults]
  network = false
  auto_mount = true
  max_memory = "512M"
  max_time = "5m"
  max_pids = 64

  [mounts]
  ro = ["/in"]
  rw = ["/out"]
  deny = ["~/.ssh", "~/.gnupg", "~/.aws"]
  ```
- Deny-by-default enforcement: anything not explicitly allowed is blocked
- `oaie check job.toml` validates job against policy before running
- CLI presets:
  - `--safe` (default): no net, RO in, RW out, tight limits
  - `--net`: explicitly enable network
  - `-i` / `--interactive`: allocate PTY for terminal apps
  - `--no-auto-mount`: disable automatic file path detection
  - `--in <path>` / `--out <path>` / `--ro <path>` / `--rw <path>`
- Auto-mount integration: `detect_file_args()` scans command arguments, `auto_mount_paths()` adds parent dirs as RO + specific files as RW
- Auto-mount entries recorded in manifest for audit trail (distinguishes directory RO mounts from file-level RW mounts)
- Sensible defaults that work without writing any policy file

**Milestone:** `oaie run --safe -- ./sketch_tool` feels frictionless. `oaie run --net -- curl example.com` requires explicit opt-in. `oaie run -i -- vim /path/to/file` works transparently.

---

### Phase B: Observability (Weeks 6–8)

**Goal:** Out-of-band ptrace tracing as a first-class, untamperable artifact. This is the shipped observability for v0.1. No privileged components.

**Key principle:** OAIE writes the observation record. The tool cannot.

#### Week 6 — Observe pipeline + event format

**Goal:** Observability becomes a structured, storable artifact.

**Deliverables:**
- OAIE event stream format (compact, stable, versioned):
  ```
  {ts, event_type, pid, detail, hash_prev}
  ```
- Event types: `process_exec`, `file_open`, `file_stat`, `net_connect`, `exit`
- Storage as CAS artifact (not in `/out` — tool-inaccessible)
- `oaie inspect` shows two columns:
  - **Reachable:** what the sandbox allowed access to
  - **Observed:** what the tool actually touched (if tracing enabled)
- Clear messaging when tracing is off: "Observation not enabled for this run"

**Milestone:** The concept "OAIE observed this, the tool cannot dispute it" is visible in the inspect output.

#### Week 7 — ptrace tracer

**Goal:** strace-like visibility without relying on tool cooperation.

**Deliverables:**
- `--trace=strace` flag (user-facing name; `--trace=ptrace` accepted as alias)
- Parent-traces-child architecture (no root needed)
- Captured syscalls:
  - `execve` — full process tree reconstruction
  - `openat` / `statx` — file access paths (best-effort)
  - `connect` — network attempt targets
- Fork/clone following via `PTRACE_O_TRACECLONE` / `PTRACE_O_TRACEFORK` / `PTRACE_O_TRACEVFORK`
- Multi-threaded target handling via `PTRACE_O_TRACECLONE`
- Trace stored as CAS artifact, linked in manifest
- REPORT.md includes "Observed Access Summary" section (careful wording — "observed" not "all")

**Milestone:** `oaie run --trace=strace -- ./tool` produces a useful observed summary showing process tree, files accessed, and network attempts.

**Known risks:** ptrace overhead on syscall-heavy workloads (10-100x on hot paths). Document this honestly. Multi-threaded targets need careful `waitpid` loop handling. See "Known Limitations and Trust Boundaries" section for full details on ptrace best-effort semantics.

#### Week 8 — Trace summarizer + volume handling

**Goal:** Make tracing output readable, not a wall of syscalls.

**Deliverables:**
- Chunked trace storage for large traces (CAS chunks + index artifact)
- Summarizer that produces:
  - Top opened paths (grouped by directory)
  - Write attempts
  - Network connect targets
  - Process tree (parent → child relationships)
- `oaie inspect <run_id>` shows clean summary by default
- `oaie inspect <run_id> --trace-full` for raw trace
- Summary included in REPORT.md

**Milestone:** A run that produces 50K syscall events shows a readable one-page summary in `oaie inspect`.

---

### Phase C: Integrity + Release (Weeks 9–10)

**Goal:** Verification, polish, and honest v0.1 release.

#### Week 9 — Verify + replay + tamper-evident chain

**Goal:** "You can trust your own logs didn't get edited."

**Deliverables:**
- Hash-chained event log (each event includes hash of previous)
- `oaie verify <run_id>` checks:
  - All referenced artifacts exist in CAS
  - Hash-chain integrity (no gaps, no edits)
  - Manifest consistency (listed hashes match stored blobs)
  - Reports pass/fail per check
- `oaie replay <run_id>` re-runs the job and compares output hashes
  - Clear documentation of what can be nondeterministic (timestamps, ASLR, thread scheduling)
  - Reports: "3/5 outputs match, 2 differ (expected for this tool type)"
- `oaie gc` — garbage collect unreferenced CAS blobs older than N days

**Milestone:** `oaie verify <run_id>` gives a clear, honest pass/fail. `oaie replay` works and is transparent about nondeterminism.

**Trust model note:** Hash-chain provides tamper *evidence* for local logs. It does not provide tamper *proof* against a malicious operator who controls the machine. The design is honest about this boundary. Third-party witnessing or remote attestation are post-v0.1 concerns.

#### Week 10 — Polish + v0.1 release

**Goal:** Ship it.

**Deliverables:**
- `oaie doctor` command — capability detection and system diagnosis:
  ```
  $ oaie doctor

  OAIE v0.1.0 — system check

  User namespaces:  ✓ available
  Mount namespace:  ✓ available
  PID namespace:    ✓ available
  Net namespace:    ✓ available
  ptrace:           ✓ available (no restrictions)
  CAS store:        ✓ ~/.oaie/cas (2.3 GB, 847 artifacts)
  SQLite:           ✓ ~/.oaie/db.sqlite (WAL mode)
  eBPF:             – not available (install oaie-ebpf for enhanced tracing)
  Firecracker:      – not available (install oaie-firecracker for VM backend)

  Isolation level:  full
  Trace backends:   strace (ptrace)
  Ready to run.
  ```
  - Warns about restricted environments (Docker, WSL, hardened kernels)
  - Prints actionable fix for each degraded capability
  - Exit code 0 if basic functionality works, nonzero if critically broken
- Edge case hardening:
  - Tools that ignore signals
  - Tools that fill `/out` with garbage
  - Tools that fork-bomb (PID limit enforcement)
  - Symlink attacks in mount setup
- Error messages reviewed for clarity
- `oaie --version` and update check
- Example `job.toml` files for common use cases:
  - Run downloaded binary safely
  - Run build script with network
  - Run test suite in isolation
- Minimal docs (README, man page, `oaie help <command>`)
- GitHub public repository
- `oaie.run` website updated with terminal demo
- Announcement post

**Milestone:** `sudo apt install oaie && oaie run ./tool` works. v0.1 is tagged and released.

---

## 15-Week Development Plan (v0.2) — Power-Ups

v0.2 begins after v0.1 ships and has real users. Every feature in v0.2 is optional — the `apt install oaie && oaie run ./tool` path from v0.1 remains untouched and unprivileged. v0.2 adds capabilities for users who explicitly opt in.

**New crates introduced in v0.2:**
- `oaie-cgroup` — cgroup v2 creation, limits, stats collection
- `oaie-priv` — tiny privileged helper binary (pipe IPC)
- `oaie-ebpf` — eBPF programs and userspace loader
- `oaie-firecracker` — microVM backend
- `oaie-agent` — agent runtime adapter and SDK

**Dependency chain:**

```
Cgroups ──→ Privileged Helper ──→ eBPF
                                    │
Backend Abstraction ──→ Firecracker │
                                    │
              Agent Runtime (needs all of the above stable)
```

---

### Phase D: Cgroup Isolation + Privileged Helper (Weeks 11–13)

**Goal:** Hard resource limits per run and a secure privilege escalation path that never touches the main binary.

#### Week 11 — Cgroup v2 per-run isolation

**Goal:** Every run gets its own cgroup with enforced resource limits.

**Deliverables:**
- Cgroup v2 detection and validation (fail clearly on cgroups v1-only systems)
- Two creation paths:
  - **Unprivileged (preferred):** Use `systemd-run --user --scope` to obtain a user-owned cgroup on systemd systems. No root needed. This is the happy path for most modern distros.
  - **Privileged fallback:** Direct cgroup hierarchy write via `oaie-priv` helper (week 12) for non-systemd systems or when user cgroups are unavailable.
- Resource limits applied per run:
  - `memory.max` — hard memory ceiling
  - `pids.max` — fork bomb protection
  - `cpu.max` — CPU time quota (period-based)
- Out-of-band stats collection after run completes:
  - `memory.peak` — high water mark
  - `cpu.stat` — user/system time consumed
  - `pids.current` — peak concurrent processes
- Stats stored as CAS artifact, linked in manifest
- Cgroup cleanup on run exit (including crash/signal paths)
- Report includes `Resource Accounting` section when cgroup data available
- `policy.toml` extended:
  ```toml
  [limits]
  memory = "512M"
  pids = 64
  cpu_quota = "50%"      # 50% of one core
  ```

**Milestone:** `oaie run --cgroup -- ./hungry_tool` enforces a 512M memory limit. Tool gets OOM-killed if it exceeds it. Report shows peak memory usage.

**Known risks:** systemd-run behavior varies across distro versions. Some container environments (Docker, LXC) restrict nested cgroup creation. Detect and report clearly.

#### Week 12 — Privileged helper (`oaie-priv`)

**Goal:** A secure, auditable privilege boundary that does exactly three things and nothing else.

**Deliverables:**
- `oaie-priv` binary — separate from main `oaie`, installed to `/usr/lib/oaie/oaie-priv`
- Responsibilities (exhaustive list):
  1. Create cgroup in system hierarchy (when systemd-run path unavailable)
  2. Attach eBPF programs to tracepoints (week 14)
  3. Configure cgroup-level network filtering (future)
- **Nothing else.** No file access, no artifact writes, no report generation.
- Communication: stdin/stdout pipe protocol with length-prefixed JSON messages
  ```
  OAIE main ──pipe──→ oaie-priv
     │                    │
     │  {action: "create_cgroup", run_id: "...", limits: {...}}
     │                    │
     │  {ok: true, cgroup_path: "/sys/fs/cgroup/oaie/run-..."}
     │←──────────────────│
  ```
- Privilege model:
  - **Option A (preferred):** `setcap cap_bpf,cap_sys_admin=ep oaie-priv` — no setuid, minimal caps
  - **Option B:** User runs `sudo oaie-priv` explicitly — OAIE detects and uses it
  - **Never:** setuid root on the main `oaie` binary
- Helper drops all capabilities after setup phase completes
- Helper validates all inputs (run ID format, limit ranges, cgroup paths) before acting
- Audit log: helper writes its own log to a fixed path (`/var/log/oaie-priv.log`) with timestamp, caller UID, action, result
- Unit tests for every message type, including malformed input rejection

**Milestone:** `oaie-priv` is a <500 line binary that passes a security review. It creates cgroups via pipe request and nothing else. Main `oaie` binary remains fully unprivileged.

**Design note:** The helper is intentionally small enough to audit by hand. If you can't read the whole thing in 20 minutes, it's too big.

#### Week 13 — Integration + graceful detection

**Goal:** Cgroup support is seamlessly integrated but never forced.

**Deliverables:**
- `oaie doctor` extended with cgroup detection:
  ```
  Cgroups:          ✓ available (systemd-run --user)
  eBPF:             – not available (install oaie-ebpf for enhanced tracing)
  Trace backends:   strace (ptrace)
  ```
- `oaie run` automatically uses cgroups when available; logs a note and records `cgroup_enforced = false` in the manifest when unavailable (resource limits become advisory)
- `oaie run --cgroup=require` fails if cgroups unavailable (for CI pipelines that need guarantees)
- `oaie run --cgroup=off` explicitly disables
- **Distinction from namespace isolation:** Cgroups are resource limits (fork bomb / OOM protection), not the security boundary. Silent degradation from "enforced limits" to "advisory limits" is acceptable because it does not create false confidence about isolation. The report is honest about what's enforced.
- Manifest `isolation` section extended:
  ```toml
  [isolation]
  level = "full"
  namespaces = ["mount", "pid", "net", "user"]
  cgroup = "oaie-run-a1b2c3"
  cgroup_method = "systemd-run"   # or "oaie-priv"

  [resources]
  memory_limit = "512M"
  memory_peak = "347M"
  cpu_user_ms = 1230
  cpu_system_ms = 89
  pids_peak = 12
  ```

**Milestone:** `oaie doctor` gives a clear picture of what this system supports. Cgroups work end-to-end with both systemd and helper paths.

---

### Phase E: eBPF Tracing (Weeks 14–17)

**Goal:** High-performance kernel-level tracing that's faster than ptrace, harder to evade, and produces the same event model. Ships as an optional feature — never required.

#### Week 14 — eBPF programs (kernel side)

**Goal:** Write the BPF programs that capture the events OAIE cares about.

**Deliverables:**
- BPF framework choice: [Aya](https://aya-rs.dev/) (pure Rust, no libbpf-sys dependency, compiles BPF programs as part of cargo build)
- Three BPF programs, each attached to a tracepoint:
  - **`oaie_exec`** — `tracepoint/sched/sched_process_exec`
    - Captures: pid, ppid, comm, filename
    - Filtered by cgroup ID (only events from the run's cgroup)
  - **`oaie_open`** — `tracepoint/syscalls/sys_enter_openat`
    - Captures: pid, flags, filename (read from userspace pointer via `bpf_probe_read_user_str`)
    - Filtered by cgroup ID
  - **`oaie_connect`** — `tracepoint/syscalls/sys_enter_connect`
    - Captures: pid, address family, destination IP/port
    - Filtered by cgroup ID
- BPF ring buffer for event delivery to userspace (preferred over perf buffer — lower overhead, no per-CPU allocation)
- Event struct shared between BPF and userspace:
  ```rust
  #[repr(C)]
  struct OaieEvent {
      event_type: u32,    // EXEC=1, OPEN=2, CONNECT=3
      pid: u32,
      ppid: u32,
      ts_ns: u64,
      cgroup_id: u64,
      payload: [u8; 256], // filename or address
  }
  ```
- BPF programs tested individually via `bpf_prog_test_run` where possible

**Milestone:** BPF programs compile, load on a 6.x kernel, and produce events when a test process runs inside a cgroup.

**Known risks:** Aya's BPF verifier compatibility across kernel versions. `bpf_probe_read_user_str` can fail on short-lived processes. Ring buffer overflow under heavy syscall load — need a drop counter.

#### Week 15 — Userspace loader + event pipeline

**Goal:** eBPF events flow through the same pipeline as ptrace events.

**Deliverables:**
- Userspace BPF loader in `oaie-ebpf` crate:
  - Loads programs via `oaie-priv` helper (helper does the privileged `bpf()` syscall, passes FDs back via SCM_RIGHTS over Unix socket)
  - Alternative: helper attaches programs and OAIE reads the ring buffer (simpler, ring buffer FD passed back)
- Ring buffer consumer thread:
  - Reads `OaieEvent` structs
  - Converts to the same `{ts, event_type, pid, detail, hash_prev}` event format used by ptrace
  - Feeds into the existing observe pipeline (CAS storage, summarizer, report)
- `--trace=ebpf` flag activates this path
- Automatic fallback:
  ```
  if --trace=ebpf requested:
      if oaie-priv available and has caps:
          if cgroup available:
              use eBPF path
          else:
              warn "eBPF requires cgroup scoping"
              fall back to strace
      else:
          warn "eBPF requires oaie-priv with CAP_BPF"
          fall back to strace (unless --no-fallback)
  ```
- `oaie inspect` output identical regardless of trace backend (ptrace vs eBPF)
- Manifest records which trace backend was used:
  ```toml
  [trace]
  backend = "ebpf"     # or "ptrace" or "none"
  events = 12847
  dropped = 0
  ```

**Milestone:** `oaie run --trace=ebpf -- ./tool` produces the same report structure as `--trace=strace`, but runs with <5% overhead instead of 10-100x.

#### Week 16 — eBPF hardening + cross-kernel testing

**Goal:** eBPF tracing works reliably across real-world kernels and workloads.

**Deliverables:**
- Test matrix:
  - Ubuntu 22.04 (kernel 5.15) — oldest supported LTS
  - Ubuntu 24.04 (kernel 6.8) — current LTS
  - Debian 12 (kernel 6.1)
  - Fedora 40+ (kernel 6.x)
- Edge case handling:
  - Short-lived processes (fork + exec + exit before BPF event delivered)
  - High-frequency syscall workloads (ring buffer overflow → drop counter, not crash)
  - Processes that `unshare()` themselves (should still be tracked via cgroup)
  - `execve` of scripts (capture interpreter, not just script path)
- Ring buffer sizing: adaptive based on `--trace-buffer=<size>` or auto-detect
- BPF program pinning: programs pinned to `/sys/fs/bpf/oaie/<run_id>/` for debuggability, cleaned up on run exit
- Performance benchmarks: measure overhead vs strace (ptrace) on a standardized workload (compile a small C project), document in `TRACING.md`
- `oaie inspect <run_id> --trace-stats` shows:
  - Events captured
  - Events dropped (ring buffer overflow)
  - Trace backend and kernel version
  - Overhead estimate

**Milestone:** eBPF tracing passes the full test matrix. Performance documented honestly. Drop counter is zero on normal workloads.

#### Week 17 — Packaging + `--trace=auto`

**Goal:** Users get the best available tracing without thinking about it.

**Deliverables:**
- `--trace=auto` (new default when tracing is enabled):
  - Probes for eBPF capability → uses it if available
  - Falls back to ptrace if not
  - Reports which backend was selected and why
- Packaging:
  - `oaie` package: main binary, no privileged components (same as v0.1)
  - `oaie-ebpf` package: `oaie-priv` binary + BPF programs + postinst that runs `setcap`
  - `apt install oaie-ebpf` upgrades tracing capability, nothing else changes
- Cargo feature flag: `oaie-cli` built with `features = ["ebpf"]` includes eBPF loader in the main binary; without it, eBPF is a runtime-detected optional component
- `oaie doctor` updated to show trace backends:
  ```
  Trace backends:
    strace (ptrace):  ✓ available (no privileges needed)
    eBPF:             ✓ available (oaie-priv detected, CAP_BPF confirmed)
    default:          ebpf
  ```
- Documentation: `TRACING.md` covers strace (ptrace) vs eBPF tradeoffs, when to use each, known limitations

**Milestone:** `apt install oaie oaie-ebpf` gives full capability. `apt install oaie` alone still works perfectly. `--trace=auto` picks the best option.

---

### Phase F: Firecracker Backend (Weeks 18–21)

**Goal:** MicroVM-level isolation for workloads that need stronger boundaries than namespaces. Same UX, same manifest, same report format. The user changes one flag and gets hardware-enforced isolation.

#### Week 18 — Backend trait abstraction

**Goal:** Refactor the execution path so namespace isolation is one backend, not the only path.

**Deliverables:**
- `IsolationBackend` trait:
  ```rust
  /// The trait methods are synchronous. Backends that need async internally
  /// (e.g. Firecracker VM boot) spawn tasks and block within their implementation.
  pub trait IsolationBackend: Send + Sync {
      /// Human-readable name for reports
      fn name(&self) -> &str;

      /// What this backend provides
      fn capabilities(&self) -> BackendCaps;

      /// Prepare the execution environment
      fn prepare(&self, spec: &RunSpec) -> Result<PreparedEnv>;

      /// Execute the tool inside the prepared environment
      fn execute(
          &self,
          env: &PreparedEnv,
          observe: Option<&dyn Observer>,
      ) -> Result<RunResult>;

      /// Retrieve outputs from the environment
      fn collect_outputs(&self, env: &PreparedEnv) -> Result<Vec<OutputArtifact>>;

      /// Tear down the environment
      fn cleanup(&self, env: &PreparedEnv) -> Result<()>;
  }

  pub struct BackendCaps {
      pub isolation_level: IsolationLevel,  // None, Namespace, MicroVM  (v0.2 renames/expands the v0.1 IsolationLevel to these three variants)
      pub supports_trace_ptrace: bool,
      pub supports_trace_ebpf: bool,
      pub supports_cgroup: bool,
      pub needs_root: bool,
  }
  ```
- Refactor existing namespace code into `NamespaceBackend` implementing the trait
- Refactor existing `--no-isolation` path into `BareBackend` (only reachable via explicit `--no-isolation` or `--backend=bare`)
- Runner dispatches through the trait — all existing tests pass with zero behavior change
- `--backend=namespace` (default), `--backend=bare`, `--backend=firecracker` (week 20)

**Milestone:** All v0.1 functionality works identically through the `IsolationBackend` trait. Zero user-visible changes. This is a pure refactor week.

**Design note:** The trait is intentionally simple. Prepare, execute, collect, cleanup. No lifecycle hooks, no plugin system, no middleware. If a backend needs something special, it handles it internally.

#### Week 19 — Firecracker VM management

**Goal:** Boot and manage Firecracker microVMs from OAIE.

**Deliverables:**
- Firecracker binary management:
  - Detect installed `firecracker` binary
  - Validate version compatibility (Firecracker 1.x API)
  - Check `/dev/kvm` availability
- Minimal guest rootfs:
  - Alpine-based root filesystem (~30MB)
  - Contains: busybox, /bin/sh, basic /usr, /lib
  - Read-only base image, overlayfs for /out
  - `oaie firecracker init-rootfs` generates/downloads it
- VM boot sequence:
  - Configure via Firecracker REST API (unix socket)
  - Kernel: vmlinux (minimal config, ~5MB)
  - Single vCPU, configurable memory (default 256M)
  - Boot to init script in <1 second (Firecracker's strength)
  - `/in` passed via virtio-fs (read-only) or block device snapshot
  - `/out` via virtio-fs (read-write) or tmpfs + retrieval
- Guest agent (`oaie-guest`):
  - Minimal static binary included in rootfs
  - Runs as init (PID 1) or started by init
  - Receives job spec via MMDS (Firecracker metadata service) or virtio-vsock
  - Executes tool, captures stdout/stderr
  - Writes exit code and output manifest to MMDS/vsock on completion
- VM shutdown: clean halt after job completes, force kill after timeout
- `oaie doctor` detects Firecracker availability:
  ```
  Backends:
    namespace:    ✓ available
    firecracker:  ✓ available (firecracker 1.7.0, /dev/kvm ok)
  ```

**Milestone:** A Firecracker VM boots, runs `/bin/echo hello` inside it, and returns stdout to OAIE. Under 2 seconds total.

**Known risks:** Firecracker API surface is well-documented but the guest agent + vsock communication is the fiddly part. virtio-fs support varies across Firecracker versions. Budget extra time here.

#### Week 20 — Firecracker end-to-end + outputs

**Goal:** `oaie run --backend=firecracker -- ./tool` works exactly like the namespace path.

**Deliverables:**
- `/in` mounting: tool binary + input files available read-only inside VM
- `/out` retrieval: after VM exits, OAIE extracts outputs from VM filesystem
- Stdout/stderr capture: streamed via vsock during execution, stored as CAS artifacts
- Resource limits: enforced at VM level (vCPU count, memory size)
- Observability inside VM:
  - **strace (ptrace):** Guest agent can ptrace the tool (same parent-traces-child model)
  - **eBPF:** Not available inside VM (eBPF is host-side only). If requested, trace the VM's cgroup from the host instead.
  - Trace artifacts produced same format regardless of where tracing runs
- Network isolation: Firecracker VM has no network by default. `--net` creates a TAP device with masquerade NAT.
- Manifest records backend:
  ```toml
  [isolation]
  level = "microvm"
  backend = "firecracker"
  firecracker_version = "1.7.0"
  kernel = "vmlinux-5.15"
  rootfs = "alpine-3.19-minimal"
  ```
- `oaie inspect` output indistinguishable from namespace runs (same sections, same format)

**Milestone:** `oaie run --backend=firecracker --trace=strace -- ./tool` produces identical report structure to `oaie run --trace=strace -- ./tool`. User can switch backends with one flag.

#### Week 21 — Backend parity testing + packaging

**Goal:** Prove that the provenance model is backend-independent.

**Deliverables:**
- Parity test suite: run the same set of jobs on all three backends and verify:
  - Manifest structure identical (modulo backend-specific fields)
  - CAS artifacts have same hashes for deterministic tools
  - Report sections present and formatted identically
  - `oaie verify` works on runs from any backend
  - `oaie replay` works (re-runs on same backend by default, `--backend=X` to cross-check)
- Edge cases tested:
  - Tool that tries to escape (reads /proc, tries network, fork bomb)
  - Tool that produces large outputs (multi-GB /out)
  - Tool that hangs (timeout enforcement across backends)
  - Tool that crashes (signal handling, core dump capture)
- Packaging:
  - `oaie-firecracker` package: guest rootfs + kernel + Firecracker config templates
  - Depends on `firecracker` package (system-provided or Firecracker's own releases)
  - `apt install oaie-firecracker` enables the backend, nothing else changes
- `oaie.run` website updated with backend comparison table
- `BACKENDS.md` documentation: when to use which backend, tradeoffs

**Milestone:** A single job.toml runs identically on namespace, Firecracker, and bare backends. `oaie verify` passes on all three. Backend swap does not alter the provenance model.

---

### Phase G: Agent Runtime Adapter (Weeks 22–25)

**Goal:** Let LLM agents and automated systems use OAIE as their tool execution layer. Every tool call runs in isolation, every result is observed and attested. The agent sees structured output, not raw reports.

**Prerequisite:** This phase assumes v0.1 is in use by human developers and v0.2's eBPF + Firecracker are stable. Do not start this until the core tool is trusted.

#### Week 22 — Structured output + job spec generation

**Goal:** OAIE speaks JSON, not just REPORT.md.

**Deliverables:**
- `oaie run --output=json` returns structured result:
  ```json
  {
    "run_id": "a1b2c3d4",
    "exit_code": 0,
    "isolation_level": "full",
    "trace_backend": "ebpf",
    "duration_ms": 1847,
    "outputs": [
      {"path": "result.txt", "hash": "blake3:abc...", "size": 4096}
    ],
    "observed": {
      "files_read": ["/in/input.bin", "/lib/x86_64-linux-gnu/libc.so.6"],
      "files_written": ["/out/result.txt"],
      "net_attempts": [],
      "process_tree": [
        {"pid": 1, "comm": "tool", "children": []}
      ]
    },
    "resources": {
      "memory_peak": "47M",
      "cpu_user_ms": 312,
      "cpu_system_ms": 45
    },
    "verification": {
      "chain_valid": true,
      "artifacts_intact": true
    }
  }
  ```
- `oaie run --output=json` writes report artifacts as usual but prints JSON to stdout
- Job spec can be passed as JSON (not just TOML):
  ```json
  {
    "command": ["./analyzer", "--input", "/in/sample.bin"],
    "inputs": {"sample.bin": "/path/to/sample.bin"},
    "policy": "safe",
    "trace": "auto",
    "timeout": "5m"
  }
  ```
- `oaie run --spec=job.json` accepts JSON job specs
- `oaie run --spec=-` reads job spec from stdin (for piping from agent)

**Milestone:** An LLM agent can generate a JSON job spec, pipe it to `oaie run --spec=- --output=json`, and parse the structured result. No human-readable formatting needed.

#### Week 23 — Policy templates for agent-safe mode

**Goal:** Pre-built policies that make it safe to let an LLM agent execute tools.

**Deliverables:**
- Built-in policy templates:
  - **`agent-safe`** — Maximum restriction. No network, tight memory (256M), short timeout (60s), PID limit 32, no access to home directory, no access to /etc. The "I don't trust this tool at all" policy.
  - **`agent-net`** — Like agent-safe but allows outbound network (for tools that need to fetch data). Logs all connect attempts.
  - **`agent-build`** — For build/compile tools. More memory (2G), longer timeout (10m), read access to common build dependencies (/usr/include, /usr/lib). No network.
  - **`agent-analyze`** — For analysis tools (RE, static analysis). Read-only access to /in, no network, moderate resources. Maps naturally to reverse-claw style tool execution.
- Policy templates installed to `/usr/share/oaie/policies/`
- `oaie run --policy=agent-safe -- ./tool` applies template
- Policy stacking: `--policy=agent-safe --rw /extra/path` applies template then overrides specific fields
- Policy introspection: `oaie policy show agent-safe` prints what the policy allows/denies
- Agent can request policy by name in job spec:
  ```json
  {"policy": "agent-analyze", "command": ["./decompiler", "/in/sample"]}
  ```

**Milestone:** Four battle-tested policy templates that an agent framework can reference by name. A new agent integration takes <10 lines of glue code to use OAIE.

#### Week 24 — Library interface (`liboaie`)

**Goal:** Agents can embed OAIE as a Rust library, not just shell out to a CLI.

**Deliverables:**
- `oaie-agent` crate — public Rust API:
  ```rust
  use oaie_agent::{OaieClient, JobSpec, Policy, RunResult};

  let client = OaieClient::new()?;  // uses ~/.oaie store

  let result: RunResult = client.run(JobSpec {
      command: vec!["./tool".into(), "/in/sample".into()],
      inputs: vec![("/in/sample", Path::new("/path/to/sample"))],
      policy: Policy::builtin("agent-safe"),
      trace: TraceMode::Auto,
      timeout: Duration::from_secs(60),
      output_format: OutputFormat::Structured,
  }).await?;

  println!("exit: {}", result.exit_code);
  println!("files read: {:?}", result.observed.files_read);
  println!("outputs: {:?}", result.outputs);
  ```
- `RunResult` struct mirrors the JSON output format (serde-compatible)
- Library handles all isolation, tracing, CAS storage internally
- Async API (tokio) — runs can be launched concurrently
- Concurrent run safety: each run gets its own cgroup, own CAS subdirectory, no shared mutable state
- Error types: `OaieError::IsolationUnavailable`, `OaieError::PolicyViolation`, `OaieError::Timeout`, `OaieError::ToolFailed { exit_code, stderr }`
- Python bindings (PyO3) — stretch goal, scaffolded but not required for v0.2:
  ```python
  from oaie import Client, JobSpec

  client = Client()
  result = client.run(JobSpec(
      command=["./tool", "/in/sample"],
      policy="agent-safe",
  ))
  ```

**Milestone:** A Rust agent framework can `use oaie_agent` and run tools in isolation with three function calls. No subprocess spawning, no output parsing.

#### Week 25 — Integration patterns + v0.2 release

**Goal:** Ship v0.2 with documentation showing how agents use OAIE.

**Deliverables:**
- Integration examples:
  - **MCP server:** `oaie-mcp` — an MCP tool server that exposes `oaie_run` as a tool. Any MCP-compatible agent (Claude Code, etc.) can call it. Tool description includes policy options. Returns structured JSON.
    ```json
    {
      "name": "oaie_run",
      "description": "Run a tool in isolated execution with observation",
      "parameters": {
        "command": {"type": "array", "items": {"type": "string"}},
        "policy": {"type": "string", "enum": ["agent-safe", "agent-net", "agent-build", "agent-analyze"]},
        "inputs": {"type": "object"},
        "trace": {"type": "string", "default": "auto"}
      }
    }
    ```
  - **CLI pipeline:** `agent-output | oaie run --spec=- --output=json | agent-input` — OAIE as a Unix pipe component
  - **Reverse-claw integration sketch:** How `reverse-claw` could use `liboaie` instead of raw bwrap for tool execution (not implemented — just documented as a proof of concept)
- Security documentation:
  - Threat model: what OAIE protects against (tool escaping sandbox, tool lying about its behavior, accidental damage)
  - What OAIE does NOT protect against (malicious operator, kernel exploits, hardware attacks)
  - Policy authoring guide: how to write custom policies for your agent's specific tools
- v0.2 release:
  - Packages: `oaie` (core), `oaie-ebpf` (enhanced tracing), `oaie-firecracker` (VM backend), `oaie-agent` (library + MCP server)
  - GitHub release with changelog
  - `oaie.run` updated with v0.2 capabilities
  - Announcement post

**Milestone:** v0.2 ships. The full stack works: `apt install oaie oaie-ebpf` for human developers, `oaie-agent` crate for agent frameworks, `oaie-mcp` for MCP-compatible agents. Every execution is isolated, observed, and attested.

---

## 11-Week Development Plan (v0.3) — Agent Containment

> *v0.3 targets teams running AI agents that need verifiable boundaries: the agent itself is constrained, not just the tools it calls.*

v0.3 changes OAIE's role. In v0.1 and v0.2, OAIE wraps individual tool executions. In v0.3, OAIE wraps the agent — the entire reasoning loop, its tool calls, its network access, its interaction with the user. The agent runs inside OAIE. Everything it does is observed from the supervisor plane it cannot reach.

**The shift:**

```
v0.1:  human → oaie run ./tool
v0.2:  agent → oaie run --output=json ./tool     (agent calls tools through OAIE)
v0.3:  human → oaie session --policy=contained    (agent itself runs inside OAIE)
           └→ agent runs inside session
               ├→ calls LLM API (selective network)
               ├→ runs tools (nested OAIE isolation)
               ├→ talks to user (mediated channel)
               └→ everything observed, budgeted, attested
```

**New crates introduced in v0.3:**
- `oaie-netpol` — network policy engine (nftables generation, DNS proxy, SNI filtering)
- `oaie-session` — session lifecycle, tool dispatch, mediated I/O, budgets

**Prerequisite:** v0.2 must be stable and in use. Session mode builds on namespace isolation, cgroup limits, eBPF tracing, the backend trait, and the structured JSON I/O from the agent runtime.

---

### Phase H: Selective Network Control (Weeks 26–28)

**Goal:** Move beyond network=on/off to fine-grained control. An agent can reach `api.anthropic.com:443` and nothing else. This is the single most important prerequisite for constraining agents that need cloud LLM access.

#### Week 26 — Network policy engine

**Goal:** OAIE can enforce "allow these endpoints, deny everything else."

**Deliverables:**
- Network policy specification in `policy.toml`:
  ```toml
  [network]
  mode = "allowlist"    # "off" | "on" | "allowlist"

  [[network.allow]]
  host = "api.anthropic.com"
  port = 443
  protocol = "tcp"

  [[network.allow]]
  host = "api.openai.com"
  port = 443
  protocol = "tcp"

  # Everything else is denied. No implicit defaults.
  ```
- Enforcement via nftables rules generated per-run:
  - OAIE creates a dedicated nftables chain for the run's network namespace
  - Default policy: DROP
  - Allow rules added for each `[[network.allow]]` entry
  - Rules reference resolved IP addresses (DNS resolution happens outside the sandbox, see week 27)
  - Chain torn down on run exit
- IP-level enforcement (no DNS yet — host names resolved to IPs by OAIE before run starts):
  - `oaie run --policy=agent-cloud -- ./agent` resolves `api.anthropic.com` → IPs, creates allow rules for those IPs on port 443
  - If DNS changes mid-run, the allow rules use the resolved IPs — conservative but correct
- `oaie inspect` network section extended:
  ```
  Network policy: allowlist
    Allowed:
      api.anthropic.com:443  (resolved: 104.18.32.7, 104.18.33.7)
    Observed:
      104.18.32.7:443  ✓ allowed (3 connections)
      93.184.216.34:80 ✗ denied  (1 attempt, blocked)
  ```
- Fallback for systems without nftables: eBPF socket filter on the cgroup (requires `oaie-priv`). If neither is available, OAIE refuses to run in allowlist mode rather than silently allowing everything.

**Milestone:** `oaie run --net=allow:api.anthropic.com:443 -- ./agent` works. The agent can reach the LLM API. Everything else is blocked and logged.

**Known risks:** IP resolution caching vs CDN rotation. Some APIs use many IPs (CloudFront, etc.). May need CIDR range support. Document limitations honestly.

#### Week 27 — DNS-aware filtering

**Goal:** Agents resolve DNS inside the sandbox, but only for allowed domains.

**Deliverables:**
- `oaie-dns-proxy` — tiny DNS forwarder that runs inside the network namespace:
  - Listens on 127.0.0.53:53 (same as systemd-resolved)
  - Receives DNS queries from the sandboxed process
  - Checks query domain against the allowlist:
    - Allowed domain → forwards to real resolver, returns real answer, logs the resolution
    - Denied domain → returns NXDOMAIN, logs the attempt
  - All resolutions logged as OAIE events (`dns_resolve` event type)
- `/etc/resolv.conf` inside sandbox points to the proxy
- Proxy runs in the supervisor plane (tool can't tamper with it)
- TLS SNI validation (defense in depth):
  - For HTTPS allowlist entries, eBPF or ptrace observes the `connect()` target
  - If the IP doesn't match known resolutions for the allowed domain, flag it in the report
  - This catches hardcoded IPs or DNS rebinding attempts
- Policy shorthand:
  ```toml
  # Allow any host on port 443 (trust the DNS proxy to filter)
  [[network.allow]]
  host = "*.anthropic.com"
  port = 443

  # Allow a specific IP range (for private APIs)
  [[network.allow]]
  cidr = "10.0.0.0/8"
  port = 443
  ```
- `oaie inspect` shows DNS activity:
  ```
  DNS queries observed:
    api.anthropic.com    → 104.18.32.7  (allowed)
    evil.example.com     → NXDOMAIN     (denied by policy)
  ```

**Milestone:** An agent inside OAIE resolves DNS normally for allowed domains. Queries for non-allowed domains get NXDOMAIN. Every DNS query is logged as an OAIE event.

#### Week 28 — Network policy integration + hardening

**Goal:** Network filtering is robust, tested, and integrated with existing policy and reporting infrastructure.

**Deliverables:**
- Built-in network policy presets:
  - **`net-off`** — No network (existing v0.1 default)
  - **`net-anthropic`** — Allow `api.anthropic.com:443` only
  - **`net-openai`** — Allow `api.openai.com:443` only
  - **`net-llm`** — Allow common LLM API endpoints (Anthropic, OpenAI, Google AI)
  - **`net-custom`** — User-defined allowlist
- `oaie policy show net-anthropic` prints full allowlist
- Edge case testing:
  - Tool that tries DNS rebinding (resolve allowed domain, connect to different IP)
  - Tool that tries direct IP connection bypassing DNS
  - Tool that sends UDP (default: blocked)
  - Tool that tries to access the DNS proxy itself (proxy binds only to loopback inside namespace)
  - Long-running connections (WebSocket to LLM streaming endpoints — must stay open)
  - Connection pooling / keep-alive (common in HTTP clients)
- Performance: DNS proxy adds <1ms latency per query. nftables rules evaluated in kernel — zero per-packet userspace overhead.
- Integration with eBPF tracing: `oaie_connect` BPF program now annotates events with allow/deny status based on policy
- Report `Network` section is now the most detailed part of the report for allowlist runs

**Milestone:** Network allowlisting works reliably for real LLM agent workloads. WebSocket streaming to API endpoints works. DNS rebinding and IP bypass attempts are caught and logged. All network presets battle-tested.

---

### Phase I: Session Mode (Weeks 29–33)

**Goal:** OAIE can host an entire agent session — a long-running, interactive, multi-step execution where the agent thinks, calls tools, interacts with the user, and produces results, all inside a single observed sandbox.

This is the core of v0.3. Everything before this was prerequisites.

#### Week 29 — Session lifecycle

**Goal:** `oaie session` creates a persistent, observed execution environment.

**Deliverables:**
- `oaie session start` command:
  ```bash
  # Start a contained agent session
  oaie session start \
    --policy=agent-contained \
    --net=allow:api.anthropic.com:443 \
    --timeout=30m \
    --name="analysis-run-42"
  ```
  - Creates namespace sandbox (or Firecracker VM) that stays alive
  - Returns session ID
  - Session state stored in `~/.oaie/sessions/<session_id>/`
  - Tracing begins immediately (captures everything from session start)
- Session control commands:
  - `oaie session list` — show active sessions
  - `oaie session attach <id>` — get a shell inside the session (for debugging)
  - `oaie session stop <id>` — graceful shutdown (tool gets SIGTERM, then SIGKILL after grace period)
  - `oaie session status <id>` — show resource usage, tool call count, elapsed time
- Session state machine:
  ```
  starting → running → stopping → stopped
                 ↓
              timed_out
                 ↓
              budget_exhausted
  ```
- Session manifest (extends run manifest):
  ```toml
  [session]
  id = "sess-a1b2c3"
  name = "analysis-run-42"
  started = "2026-03-15T10:30:00Z"
  stopped = "2026-03-15T10:47:23Z"
  status = "stopped"       # stopped | timed_out | budget_exhausted
  policy = "agent-contained"
  network_mode = "allowlist"

  [session.stats]
  tool_calls = 14
  wall_time_s = 1043
  total_tool_time_s = 287
  ```
- Heartbeat: session process sends periodic heartbeat to supervisor. If heartbeat stops (agent crashed), supervisor logs it and keeps trace artifacts intact.

**Milestone:** `oaie session start` creates a persistent sandbox. `oaie session status` shows it running. `oaie session stop` tears it down cleanly. Trace artifacts cover the full session lifetime.

#### Week 30 — Tool dispatch protocol

**Goal:** An agent running inside an OAIE session can request tool executions that are each individually isolated and observed.

**Deliverables:**
- **Tool dispatch socket:** Unix socket at `<session_dir>/dispatch.sock`, exposed to the sandbox via `OAIE_DISPATCH_SOCK` env var
  - Agent sends tool call requests as JSON:
    ```json
    {
      "id": "call-001",
      "command": ["./decompiler", "/in/sample.bin"],
      "inputs": {"sample.bin": "/session/artifacts/sample.bin"},
      "policy": "agent-analyze",
      "timeout": "60s"
    }
    ```
  - OAIE supervisor receives request, validates against session policy, executes tool in **nested isolation** (new namespace/cgroup inside the session), returns result:
    ```json
    {
      "id": "call-001",
      "run_id": "run-x7y8z9",
      "exit_code": 0,
      "outputs": [
        {"path": "decompiled.json", "hash": "blake3:abc...", "size": 48210}
      ],
      "observed": {
        "files_read": ["/in/sample.bin"],
        "files_written": ["/out/decompiled.json"],
        "net_attempts": []
      },
      "duration_ms": 3400
    }
    ```
- **Nested isolation:** Each tool call gets its own:
  - Namespace (nested inside session namespace) or cgroup scope
  - Trace (individual run trace, linked to parent session)
  - CAS artifacts (stored in session's CAS subdirectory)
  - The tool cannot access other tools' outputs unless explicitly passed as inputs
- **Tool output handoff:** After a tool run completes, its `/out` contents are available to the agent at `/session/artifacts/<run_id>/`. The agent can reference these as inputs to subsequent tool calls.
- **Dispatch validation:** The supervisor validates every tool call against the session policy:
  - Is this command allowed? (allowlist of tool binaries)
  - Are the inputs within the session's accessible scope?
  - Has the tool call budget been exceeded?
  - If validation fails: return error JSON, log the rejection, do not execute
- `liboaie` session client: Rust API for agents to use the dispatch socket:
  ```rust
  use oaie_session::SessionClient;

  let client = SessionClient::default().await?;  // reads OAIE_DISPATCH_SOCK env var

  let result = client.call_tool(ToolCall {
      command: vec!["./decompiler", "/in/sample.bin"],
      inputs: vec![("sample.bin", artifact_path)],
      policy: "agent-analyze",
      timeout: Duration::from_secs(60),
  }).await?;
  ```

**Milestone:** An agent inside an OAIE session sends a tool call request over the dispatch socket. OAIE executes the tool in nested isolation, returns structured results. The agent can chain tool calls, passing outputs from one as inputs to the next.

#### Week 31 — Mediated I/O

**Goal:** All communication between the agent and the outside world passes through OAIE's supervisor plane, is logged, and can be controlled.

**Deliverables:**
- **Three I/O channels,** all mediated by the supervisor:

  1. **Agent → User (output):** Agent produces messages for the user (progress, questions, results). These pass through the supervisor which logs them as `agent_output` events and forwards to the user's terminal / API caller.
     ```
     Agent process → /run/oaie/user.sock → Supervisor → User terminal
     ```

  2. **User → Agent (input):** User sends responses (answers to questions, approvals, cancellations). Supervisor logs as `user_input` events and forwards into the session.
     ```
     User terminal → Supervisor → /run/oaie/user.sock → Agent process
     ```

  3. **Agent → LLM API (network):** Already handled by Phase H's selective network policy. All network traffic is observed and logged.

- **I/O logging format:**
  ```json
  {"ts": 1710499200, "type": "agent_output", "channel": "user", "content": "Found 3 suspicious functions. Analyzing..."}
  {"ts": 1710499205, "type": "tool_call", "id": "call-003", "command": ["./decompiler", "/in/func_0x4010"]}
  {"ts": 1710499210, "type": "tool_result", "id": "call-003", "exit_code": 0, "duration_ms": 4800}
  {"ts": 1710499215, "type": "agent_output", "channel": "user", "content": "Analysis complete. See report."}
  ```
- **I/O policies:**
  ```toml
  [io]
  # Agent can write to user channel (always allowed, but logged)
  user_output = true

  # Agent can read user input (for interactive agents)
  user_input = true

  # Rate limit: max messages per minute to prevent spam
  user_output_rate = 60

  # Max message size (prevent dumping large blobs to user)
  max_message_size = "64K"
  ```
- **CLI for interactive sessions:**
  ```bash
  # Start session and attach interactively
  oaie session run --interactive --policy=agent-contained -- ./my_agent

  # Agent output appears in terminal, user can type responses
  # Ctrl+C sends graceful stop signal
  # All interaction logged in session trace
  ```
- **Non-interactive mode** (for automated pipelines):
  ```bash
  # Start session, agent runs to completion, output captured
  oaie session run --policy=agent-contained --output=json -- ./my_agent < input.json
  ```

**Milestone:** An interactive agent session shows agent output in real-time, accepts user input, and logs every message in both directions. `oaie session inspect` shows the full conversation with timestamps.

#### Week 32 — Session budgets

**Goal:** Hard limits on what an agent can do within a session — not just resources, but actions.

**Deliverables:**
- Budget dimensions:
  | Budget | What it limits | Default | Enforcement |
  |---|---|---|---|
  | `max_tool_calls` | Total tool executions in the session | 50 | Supervisor rejects dispatch requests after limit |
  | `max_wall_time` | Total session duration | 30m | Supervisor sends SIGTERM, then SIGKILL |
  | `max_tool_time` | Cumulative time spent in tool calls | 10m | Supervisor kills current tool, rejects further calls |
  | `max_output_bytes` | Total bytes written to /out across all tool calls | 1G | Tool calls that would exceed are rejected |
  | `max_network_bytes` | Total bytes transferred over network | 100M | Connection killed when exceeded |
  | `max_agent_output` | Total bytes of agent→user messages | 10M | Messages truncated after limit |

- Budget specification in policy:
  ```toml
  [budget]
  max_tool_calls = 50
  max_wall_time = "30m"
  max_tool_time = "10m"
  max_output_bytes = "1G"
  max_network_bytes = "100M"
  ```
- Budget exhaustion behavior:
  - When any budget is exhausted, the agent receives a clear error:
    ```json
    {"error": "budget_exhausted", "budget": "max_tool_calls", "used": 50, "limit": 50}
    ```
  - Session continues running (agent can produce final output, save state) but no new tool calls are dispatched
  - If `max_wall_time` is exceeded, session stops entirely (graceful shutdown)
  - All budget events logged: `budget_warning` at 80%, `budget_exhausted` at 100%
- `oaie session status` shows budget consumption:
  ```
  Session: sess-a1b2c3 (running, 12m elapsed)
  Budget:
    Tool calls:     23/50     (46%)
    Wall time:      12m/30m   (40%)
    Tool time:      4m12s/10m (42%)
    Output:         47M/1G    (5%)
    Network:        12M/100M  (12%)
  ```
- Budget can be extended mid-session:
  ```bash
  oaie session extend sess-a1b2c3 --max_tool_calls=100
  ```
  - Extension logged as a supervisor event with timestamp and old/new values
  - Requires explicit user action — agent cannot extend its own budget

**Milestone:** An agent hits its tool call budget, gets a clear error, and can gracefully wrap up. `oaie session status` shows real-time budget consumption. Budget extension works and is audited.

#### Week 33 — Session audit trail

**Goal:** A complete, hash-chained, verifiable record of everything that happened in an agent session.

**Deliverables:**
- **Session trace:** Single hash-chained event log covering the entire session:
  - Session start/stop events
  - Every tool dispatch request and result
  - Every agent↔user I/O message
  - Every DNS query and network connection
  - Every budget warning and exhaustion
  - Resource stats snapshots (periodic, every 30s)
- **Nested trace linking:** Each tool call within the session produces its own run trace (from v0.1/v0.2). The session trace references each nested run by `run_id` and trace hash:
  ```json
  {"ts": 1710499205, "type": "tool_call_start", "call_id": "call-003", "run_id": "run-x7y8z9"}
  {"ts": 1710499210, "type": "tool_call_end", "call_id": "call-003", "run_id": "run-x7y8z9", "trace_hash": "blake3:def..."}
  ```
  - `oaie verify <session_id>` verifies the session chain AND all nested run chains recursively
- **Session report:**
  ```
  SESSION REPORT: sess-a1b2c3
  ══════════════════════════════════════

  Agent:         ./my_analysis_agent
  Policy:        agent-contained
  Network:       allowlist (api.anthropic.com:443)
  Duration:      17m 23s
  Status:        completed (agent exited 0)

  ── Budget Usage ──────────────────────
  Tool calls:     14/50     (28%)
  Wall time:      17m/30m   (58%)
  Network:        8.2M/100M (8%)

  ── Tool Calls ────────────────────────
  #01  ./strings /in/sample.bin         0.3s  exit:0  [run-a1b2c3]
  #02  ./decompiler /in/sample.bin      4.8s  exit:0  [run-d4e5f6]
  #03  ./decompiler /in/func_0x4010     3.2s  exit:0  [run-g7h8i9]
  ...
  #14  ./report_gen /session/artifacts  1.1s  exit:0  [run-z1y2x3]

  ── Network Activity ──────────────────
  api.anthropic.com:443  12 connections  8.2MB transferred
  (no denied attempts)

  ── Agent I/O ─────────────────────────
  Agent messages to user:  23  (4.7KB)
  User messages to agent:   3  (0.2KB)

  ── Integrity ─────────────────────────
  Session chain:  238 events, hash: blake3:abc...
  Nested runs:    14/14 chains verified
  Verification:   PASS
  ```
- **CAS storage:** Session trace stored as CAS artifact. Session report stored as CAS artifact. All nested run artifacts already in CAS from v0.2.
- **oaie session inspect <id>** shows the session report
- **oaie session log <id>** shows the raw event log (scrollable, filterable by event type)
- **oaie session log <id> --type=io** shows only agent↔user messages (conversation replay)

**Milestone:** `oaie session inspect` shows a complete, readable audit of an agent session. `oaie verify <session_id>` recursively verifies the entire session including all nested tool runs. The full chain is tamper-evident.

---

### Phase J: Agent Containment Policies + Release (Weeks 34–36)

**Goal:** Pre-built containment profiles, real-world integration examples, and the v0.3 release.

#### Week 34 — Containment policy profiles

**Goal:** "How do I contain my agent?" has a one-line answer for common cases.

**Deliverables:**
- Built-in session policies (installed to `/usr/share/oaie/policies/sessions/`):

  - **`contained-local`** — For agents using local LLMs (ollama, llama.cpp, vLLM):
    ```toml
    [network]
    mode = "off"              # No network at all — LLM runs locally

    [budget]
    max_tool_calls = 100
    max_wall_time = "1h"
    max_output_bytes = "2G"

    [tools]
    allow = ["*"]             # Any tool in /in can be executed
    deny_network_per_tool = true   # Even if session had network, tools don't
    ```

  - **`contained-cloud`** — For agents calling cloud LLM APIs:
    ```toml
    [network]
    mode = "allowlist"

    [[network.allow]]         # Populated at runtime from --llm-provider flag
    host = "${LLM_API_HOST}"
    port = 443

    [budget]
    max_tool_calls = 50
    max_wall_time = "30m"
    max_network_bytes = "100M"

    [io]
    user_input = true         # Agent can ask user questions
    user_output_rate = 30
    ```

  - **`contained-strict`** — Maximum paranoia:
    ```toml
    [network]
    mode = "off"

    [budget]
    max_tool_calls = 20
    max_wall_time = "10m"
    max_tool_time = "5m"
    max_output_bytes = "256M"

    [tools]
    allow = ["/in/approved/*"]   # Only pre-approved tools
    ```

  - **`contained-interactive`** — For human-in-the-loop agent workflows:
    ```toml
    [network]
    mode = "allowlist"        # Network available for LLM API

    [budget]
    max_tool_calls = 200      # More generous — human is watching
    max_wall_time = "2h"

    [io]
    user_input = true
    require_approval = ["tool_call"]  # Agent must ask before each tool call
    ```
    When `require_approval` is set, the supervisor intercepts tool call requests and prompts the user:
    ```
    OAIE: Agent wants to run: ./decompiler /in/sample.bin
    OAIE: Policy: agent-analyze | Timeout: 60s
    OAIE: [A]pprove / [D]eny / [A]pprove all / [S]top session?
    ```

- Convenience flags:
  ```bash
  # Local LLM agent, contained
  oaie session run --contained=local -- ./my_agent

  # Cloud agent calling Anthropic API
  oaie session run --contained=cloud --llm=anthropic -- ./my_agent

  # Interactive mode with human approval
  oaie session run --contained=interactive --llm=anthropic -- ./my_agent
  ```

**Milestone:** `oaie session run --contained=cloud --llm=anthropic -- ./agent` is a single command that contains an agent with sensible defaults. No policy file authoring needed for common cases.

#### Week 35 — Integration examples + testing

**Goal:** Prove that agent containment works with real agent frameworks.

**Deliverables:**
- **Example 1: Local LLM reverse-engineering agent**
  - Ollama running locally, agent loop in Python
  - Agent analyzes a binary: calls strings, decompiler, disassembler
  - Runs inside `oaie session --contained=local`
  - Session report shows full analysis chain
  - Zero network access — everything local

- **Example 2: Cloud-backed coding agent**
  - Agent calls Claude API for reasoning
  - Executes build/test commands as tools
  - Runs inside `oaie session --contained=cloud --llm=anthropic`
  - Network restricted to Anthropic API
  - Session report shows API calls alongside tool executions

- **Example 3: Human-in-the-loop analysis**
  - Interactive session with approval gates
  - Human reviews and approves each tool call
  - Full conversation captured in session trace
  - `oaie session log <id> --type=io` replays the human-agent interaction

- **MCP integration update:** `oaie-mcp` server extended with session support:
  ```json
  {
    "name": "oaie_session_run",
    "description": "Run an agent in a contained OAIE session",
    "parameters": {
      "agent_command": {"type": "array"},
      "containment": {"type": "string", "enum": ["local", "cloud", "strict", "interactive"]},
      "llm_provider": {"type": "string"},
      "budget": {"type": "object"}
    }
  }
  ```

- **Stress testing:**
  - Agent that makes 1000 rapid tool calls (budget enforcement under load)
  - Agent that tries to escape (read outside sandbox, access dispatch socket internals, forge tool results)
  - Agent that crashes mid-session (trace and artifacts preserved)
  - Agent that tries to exhaust network budget (connection killed cleanly)
  - Concurrent sessions (10 simultaneous contained agents — resource isolation verified)

**Milestone:** Three real-world agent containment examples work end-to-end. Escape attempts are caught and logged. Concurrent sessions don't interfere with each other.

#### Week 36 — v0.3 release

**Goal:** Ship agent containment.

**Deliverables:**
- Documentation:
  - `SESSIONS.md` — session mode concepts, lifecycle, dispatch protocol
  - `CONTAINMENT.md` — agent containment guide, policy profiles, threat model
  - `NETWORK.md` — selective network control, DNS proxy, allowlisting
  - Updated `TRACING.md` — session trace + nested run trace structure
  - Threat model update: what agent containment protects against (agent exceeding boundaries, agent lying about tool results, unintended data access), what it doesn't protect against (compromised LLM provider, kernel exploits, side channels)
- Packages:
  - `oaie` — core (unchanged from v0.1)
  - `oaie-ebpf` — enhanced tracing (unchanged from v0.2)
  - `oaie-firecracker` — VM backend (unchanged from v0.2)
  - `oaie-agent` — library + MCP server (extended with session support)
  - `oaie-session` — session mode + network policy (**new in v0.3**)
- GitHub release with changelog
- `oaie.run` updated:
  - New section: "Agent Containment"
  - Session mode terminal demo
  - Policy profile comparison table
- Announcement post: "OAIE v0.3: Run AI Agents With Proof of What They Did"

**Milestone:** v0.3 ships. `oaie session run --contained=cloud --llm=anthropic -- ./agent` contains an AI agent with selective network access, budget enforcement, nested tool isolation, mediated I/O, and a complete verifiable audit trail. Every action the agent took is observed from a plane it could not reach.

---

## Full Timeline Summary

| Weeks | Phase | What ships | Release |
|---|---|---|---|
| 1 | Phase 0 — Identity | Repo skeleton, CLI stubs, `oaie init` | |
| 2–5 | Phase A — Safe Execution | CAS, runner, namespace isolation, policy layer | |
| 6–8 | Phase B — Observability | Event format, ptrace tracer, trace summarizer | |
| 9–10 | Phase C — Integrity + Release | Verify, replay, hash-chain | **v0.1** |
| 11–13 | Phase D — Cgroups + Priv Helper | Cgroup per run, `oaie-priv`, capability detection | |
| 14–17 | Phase E — eBPF | BPF programs, userspace loader, cross-kernel testing, packaging | |
| 18–21 | Phase F — Firecracker | Backend trait, VM management, end-to-end, parity testing | |
| 22–25 | Phase G — Agent Runtime | JSON I/O, policy templates, `liboaie`, MCP server | **v0.2** |
| 26–28 | Phase H — Network Control | Selective network allowlisting, DNS proxy, SNI filtering | |
| 29–33 | Phase I — Session Mode | Session lifecycle, tool dispatch, mediated I/O, budgets, audit | |
| 34–36 | Phase J — Containment + Release | Policy profiles, integration examples, stress testing | **v0.3** |

**Total: 36 weeks.**

- **v0.1 (week 10):** A safe execution wrapper for humans. `apt install oaie && oaie run ./tool`.
- **v0.2 (week 25):** Infrastructure for agents. eBPF, Firecracker, `liboaie`, MCP server.
- **v0.3 (week 36):** Agent containment. The agent itself runs inside OAIE. Everything it does is observed, budgeted, and attested.

---

## What OAIE Promises

- Isolated execution (enforced by default, honestly reported when overridden via `--no-isolation`)
- Explicit capabilities (deny-by-default)
- Out-of-band observability (tool cannot tamper with its own record)
- Tamper-evident local logs (hash-chained)
- Replay verification where applicable (with honest nondeterminism docs)

## What OAIE Does Not Promise

- Deterministic execution (too many sources of nondeterminism to guarantee)
- Protection against a malicious operator (local trust model)
- Kernel-level security guarantees without Tier 2 components
- Magic

That honesty is what makes people trust OAIE.

---

## Cross-Cutting Concerns

These topics span multiple phases and need consistent handling throughout.

### Upgrade Path and Backwards Compatibility

OAIE will ship three major versions (v0.1, v0.2, v0.3) over 36 weeks. Users upgrade. Their data must survive.

**Manifest versioning:**
- Every manifest has `version = 1` (v0.1), `version = 2` (v0.2), `version = 3` (v0.3)
- New fields use `#[serde(skip_serializing_if = "Option::is_none")]` — old versions ignore them
- `oaie verify` from v0.2 can verify v0.1 manifests (new fields simply absent)
- `oaie verify` from v0.1 can verify v0.2 manifests (unknown fields ignored by TOML parser)
- Manifest version is checked on read; if `version > supported`, warn but don't fail

**CAS store:**
- Content-addressed by BLAKE3 hash — format never changes
- v0.1 and v0.3 CAS stores are identical in layout
- No migration needed

**SQLite schema:**
- Schema version tracked in `pragma user_version`
- Migrations run automatically on startup: `if user_version < CURRENT_VERSION { apply_migrations() }`
- Migrations are forward-only SQL files in `migrations/` directory
- v0.2 adds columns with `ALTER TABLE ... ADD COLUMN ... DEFAULT NULL`
- Never drop columns or tables (old data preserved)

**Event format:**
- NDJSON lines are self-describing (each event has all fields)
- New event types added in v0.2/v0.3 are ignored by older `oaie inspect` versions
- The hash chain is version-independent (hashes serialized JSON bytes regardless of content)

**Testing:** Each release week (10, 25, 36) includes a backwards compatibility test:
- Parse v0.1 manifests with v0.2 code
- Verify v0.1 CAS blobs with v0.2 verifier
- Run v0.2 `oaie inspect` on v0.1 runs

### Concurrent Runs

Multiple `oaie run` invocations can happen simultaneously (e.g., parallel build steps, multiple terminals).

**SQLite:**
- WAL mode (set at init time) allows concurrent readers with a single writer
- Write transactions are short (INSERT run record, INSERT artifacts) — contention is minimal
- If two writes collide, SQLite returns `SQLITE_BUSY`; retry with exponential backoff (3 attempts, 50ms/100ms/200ms)
- `busy_timeout` pragma set to 5000ms as a safety net

**CAS store:**
- Content-addressed writes are inherently conflict-free: same content = same hash = same file
- Atomic write pattern (temp → fsync → rename) means two processes writing the same blob both succeed; second rename is a no-op
- No locking needed

**Run directories:**
- Run IDs are UUIDv7 (time-ordered, globally unique) — no collisions
- Each run writes to `~/.oaie/runs/<run_id>/` — completely independent paths

**Sessions:**
- Session IDs are also unique
- Each session has its own directory, dispatch socket, and cgroup — no shared state

### Signal Handling in the Supervisor

When the user sends Ctrl+C (SIGINT) during a traced run, OAIE must clean up reliably. This is a defined sequence, not a panic path.

**Signal handler registration (at startup):**
```
SIGINT, SIGTERM → set atomic flag SHUTDOWN_REQUESTED = true
```

**Cleanup sequence (checked in the main loop and after waitpid):**
1. **Stop the ptrace loop:** Set `tracer_active = false`. The ptrace loop checks this on each iteration and breaks cleanly, flushing buffered events.
2. **Kill the sandboxed process tree:** Send SIGTERM to the sandboxed child PID (which is PID 1 in its PID namespace — killing PID 1 kills all processes in the namespace). Wait 3 seconds. If still alive, SIGKILL.
3. **Flush partial trace data:** The EventWriter/ChunkedEventWriter flushes its buffer to disk. If the run produced events, they are stored in CAS (even if incomplete). The trace index records `complete = false`.
4. **Write a partial manifest:** The manifest is generated with `status = "interrupted"` and `exit_code = null`. Artifacts collected so far are recorded. The manifest is stored in CAS.
5. **Clean up cgroup (if active):** Kill remaining processes in the cgroup. Remove the cgroup directory.
6. **Clean up namespace:** Unmount any remaining bind mounts. The PID namespace cleanup (step 2) handles most of this — when PID 1 dies, the namespace is torn down automatically.
7. **Update database:** Mark the run as `interrupted` in SQLite.
8. **Print summary:** `"OAIE: Run <id> interrupted. Partial results saved. oaie inspect <id>"`

**Key invariant:** OAIE never leaves orphaned processes or cgroups. If the supervisor is killed with SIGKILL (unrecoverable), the `oaie doctor` command detects stale cgroups and offers cleanup.

### Operational Logging

OAIE records tamper-evident logs for tools. It also needs defined logging for itself.

**Structured logging via `tracing` crate:**
- Default: `WARN` level to stderr (user sees errors and warnings)
- `OAIE_LOG=debug`: Full debug output to stderr
- `OAIE_LOG_FILE=~/.oaie/oaie.log`: Append structured logs to file (for bug reports)

**What gets logged:**
- Namespace creation/failure (INFO/ERROR)
- Cgroup creation/failure (INFO/WARN)
- Ptrace loop start/stop/error (DEBUG/ERROR)
- CAS write/dedup events (DEBUG)
- Policy resolution (DEBUG)
- Pre-flight check results (INFO)

**What does NOT get logged by OAIE itself:**
- Tool stdout/stderr (captured to files, not mixed with OAIE logs)
- Trace events (stored in CAS, not in operational logs)

**Operational logs are NOT tamper-evident.** They are for debugging OAIE itself, not for provenance. The hash-chained event logs are the tamper-evident record.

### Platform Scope: Linux (x86_64, aarch64, rv64gc)

**Supported architectures:**
- **x86_64** — primary development target
- **aarch64** — ARM 64-bit (server, embedded, Apple Silicon Linux VMs)
- **rv64gc** — RISC-V 64-bit (emerging server/embedded)

All three share the same Rust codebase with `#[cfg(target_arch)]` for:
- Seccomp BPF filter: AUDIT_ARCH validation + per-arch syscall number tables (x86_64 legacy table vs asm-generic shared by aarch64/rv64gc). x86_64 has 3 extra KILL entries (modify_ldt, iopl, ioperm) that don't exist on asm-generic.
- Ptrace tracer: `SyscallRegs` abstraction (register layout differs), `PTRACE_GETREGSET` on aarch64/rv64gc (PTRACE_GETREGS unavailable)
- Syscall table: arch-conditional constants with unified post-5.0 numbers (io_uring, pidfd_*, new mount API, landlock)

**Architecture-independent layers (no `#[cfg]` needed):**
- CAS, manifests, policies, SQLite, event format, hash chain
- eBPF (tracepoints abstract register layout)
- Landlock (syscall numbers unified post-5.13)

**Explicitly out of scope:**
- macOS — no user namespaces, no ptrace-based syscall tracing, no cgroups
- Windows — entirely different process model

**Minimum kernel version:** 4.18 (user namespaces stable, ptrace reliable). Recommended: 5.8+ (eBPF ring buffer support for Phase E).

### CI Environments

Many CI systems (GitHub Actions, GitLab CI, Jenkins) run jobs in containers where user namespaces are unavailable. Since CI is a primary use case for "safe build steps," this deserves explicit guidance.

**CI without namespaces — provenance mode:**
```yaml
# GitHub Actions example
- run: oaie run --no-isolation -- make build
```

In this mode, OAIE provides:
- Content-addressed artifact storage (CAS)
- Manifest with full hashes of inputs and outputs
- Stdout/stderr capture
- REPORT.md with timing and artifact list
- Optional ptrace tracing (usually available in CI containers)

OAIE does NOT provide:
- Filesystem isolation (the build runs with full access)
- Network isolation (no namespace)
- The manifest records `isolation: none`

**CI with namespaces — full isolation:**

Some CI systems support user namespaces:
- **GitHub Actions (ubuntu-latest):** User namespaces enabled by default since Ubuntu 22.04
- **GitLab CI (Docker executor):** Add `--security-opt seccomp=unconfined` or use Kubernetes with `hostUsers: false`
- **Kubernetes 1.25+:** Enable `UserNamespacesSupport` feature gate

```yaml
# Kubernetes pod spec for full isolation
spec:
  hostUsers: false  # Enable user namespaces in pod
  containers:
  - name: build
    command: ["oaie", "run", "--", "make", "build"]
```

**`oaie doctor` in CI:** Run `oaie doctor` as a setup step to verify capabilities. Parse the JSON output (`oaie doctor --output=json`) to fail the pipeline early if required capabilities are missing.

**Recommended CI pattern:**
```yaml
steps:
  - name: Check OAIE capabilities
    run: |
      oaie doctor
      # If namespaces unavailable but you want provenance only:
      # oaie run --no-isolation -- make build
      # If namespaces required:
      # oaie run -- make build  (will fail if unavailable)
```

### Known Limitations and Trust Boundaries

Honest documentation of what OAIE cannot guarantee and where boundaries are advisory.

**Hardware timing instructions are the fundamental limit of process-level isolation:**
- On x86_64, `rdtsc` / `rdtscp` read the CPU Time Stamp Counter directly as a ring-3 instruction — not a syscall. Seccomp cannot block it. Ptrace cannot intercept it. It provides ~nanosecond precision timing.
- On aarch64, `mrs x0, cntvct_el0` reads the virtual counter at EL0. Same situation — userspace instruction, not interceptable.
- On rv64gc, `rdtime` reads the timer CSR. Same situation.
- This enables cache timing attacks (Flush+Reload, Prime+Probe), Spectre-class side-channels, and covert channels between cooperating processes (one inside sandbox, one outside). The `/proc/self/timerslack_ns` masking and `prctl(PR_SET_TIMERSLACK)` detection (week 7) address timer-based channels, but rdtsc bypasses all kernel timing controls entirely.
- **This is not a bug — it is a fundamental architectural limitation of process-level sandboxing.** Docker, Bubblewrap, Chromium, Flatpak — none of them can block rdtsc. The only mitigation is VM isolation: Firecracker/KVM can trap rdtsc via `VMX_TSC_OFFSET` (x86_64) or trap `cntvct_el0` via hypervisor configuration (aarch64). This is the primary technical reason the Firecracker backend (Phase F) exists as a tier above namespace isolation.

**ptrace observability is best-effort:**
- `openat` / `statx` capture is best-effort: a tool can use raw syscalls or `io_uring` to bypass ptrace interception. ptrace cannot observe `io_uring` submissions.
- Multithreaded targets with high syscall rates may see events delivered out of order (the ptrace loop processes one event at a time per `waitpid`).
- Short-lived child processes may exit before ptrace can attach (`PTRACE_O_TRACEFORK` mitigates but does not eliminate the race).
- REPORT.md wording must say "observed" (not "all") to reflect this honestly.

**Cgroup limits are advisory when managed via systemd-run:**
- When OAIE uses `systemd-run --user` (Tier 1, no root), cgroup limits are advisory: the user can kill the cgroup manager, and a tool that spawns a process outside the cgroup tree (e.g., via `nsenter` before cgroup attachment) is not constrained.
- With dedicated cgroups via `oaie-priv` (Tier 2), limits are enforced by the kernel. The manifest records which tier was used.

**CAP_SYS_ADMIN vs CAP_BPF scope:**
- `oaie-priv` needs `CAP_BPF` + `CAP_PERFMON` for BPF loading, and `CAP_SYS_ADMIN` only for cgroup creation in the unified hierarchy. The postinst script sets file capabilities via `setcap`.
- `CAP_SYS_ADMIN` is broad. OAIE mitigates this by: (1) `oaie-priv` is a separate binary with <500 lines, auditable in 20 minutes; (2) it only processes three message types; (3) it validates all inputs and logs all actions.

**Garbage collection race condition:**
- `oaie gc` (which prunes old runs from CAS) can race with a concurrent `oaie run` that is writing artifacts. A CAS blob could be deleted between being written and being referenced in the manifest.
- Mitigation: `oaie gc` only prunes runs older than a configurable age (default 7 days). Active runs (status != "completed") are never pruned. The SQLite `busy_timeout` prevents concurrent write conflicts.

**Dispatch socket trust boundary (v0.3 sessions):**
- The dispatch socket (`session_dir/dispatch.sock`) is the interface between the sandboxed agent and OAIE. The agent sends tool call requests; OAIE validates and executes them.
- The socket is NOT bind-mounted into the sandbox. Instead, OAIE exposes it via the `OAIE_DISPATCH_SOCK` environment variable pointing to a path accessible from inside the sandbox's mount namespace.
- A malicious agent can send malformed requests — OAIE must validate all fields (command, arguments, timeout) against the session policy before execution. The dispatch handler treats all input as untrusted.

**Network inheritance in nested tool calls:**
- When a session tool call spawns a nested sandbox, the nested sandbox inherits the session's network namespace by default. This means a tool call with `--net` inside a session with network access has the same network rules as the session.
- Per-tool network deny (`deny_network_per_tool` in session policy) is enforced by NOT passing `--net` to the nested sandbox, regardless of the session's own network state. This is a deny-override, not an allow-override.
