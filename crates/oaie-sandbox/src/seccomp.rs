//! Seccomp BPF syscall filter for sandboxed processes.
//!
//! Two-tier filter:
//! - **KILL tier**: Syscalls that could escape the sandbox or destabilize
//!   the kernel (io_uring, kexec, bpf, unshare, etc.) → SECCOMP_RET_KILL_PROCESS.
//! - **ERRNO tier**: Syscalls that are dangerous but where EPERM is a safe
//!   response (mount, perf_event_open, memfd_create, etc.) → SECCOMP_RET_ERRNO(EPERM).
//! - **Default**: SECCOMP_RET_ALLOW.
//!
//! The filter first checks AUDIT_ARCH to block 32-bit compat syscalls (which
//! have different syscall numbers and could bypass the filter).

use oaie_core::error::{OaieError, Result};

/// BPF instruction: matches Linux's `struct sock_filter` (4 fields, 8 bytes).
#[repr(C)]
pub struct BpfInsn {
    /// Instruction opcode (LD, JMP, RET, etc. combined with width/mode).
    code: u16,
    /// Jump-true offset (number of instructions to skip on match).
    jt: u8,
    /// Jump-false offset (number of instructions to skip on no match).
    jf: u8,
    /// Operand: immediate value, memory offset, or syscall number.
    k: u32,
}

/// BPF program header: matches Linux's `struct sock_fprog`.
#[repr(C)]
struct BpfProg {
    /// Number of instructions in the filter.
    len: u16,
    /// Pointer to the first `BpfInsn` in the instruction array.
    filter: *const BpfInsn,
}

// BPF instruction opcodes.
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;
const BPF_ALU: u16 = 0x04;
const BPF_AND: u16 = 0x50;

// Seccomp return values.
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

// seccomp_data field offsets.
const SECCOMP_DATA_NR: u32 = 0; // offsetof(struct seccomp_data, nr)
const SECCOMP_DATA_ARCH: u32 = 4; // offsetof(struct seccomp_data, arch)
                                  // Low 32 bits of args[0] on little-endian (offset 16 in seccomp_data).
const SECCOMP_DATA_ARGS_0_LO: u32 = 16;
// Low 32 bits of args[1] — used for ioctl command number inspection.
const SECCOMP_DATA_ARGS_1_LO: u32 = 24;

/// Combined mask of all CLONE_NEW* namespace flags.
///
/// CLONE_NEWTIME(0x00000080) | CLONE_NEWNS(0x00020000) | CLONE_NEWCGROUP(0x02000000) |
/// CLONE_NEWUTS(0x04000000) | CLONE_NEWIPC(0x08000000) | CLONE_NEWUSER(0x10000000) |
/// CLONE_NEWPID(0x20000000) | CLONE_NEWNET(0x40000000)
pub const CLONE_NEW_MASK: u32 = 0x7E02_0080;

// Dangerous socket address families blocked via socket() argument inspection.
// These trigger kernel module autoloading and/or expose kernel attack surface.
//
// AF_NETLINK is in this list CONDITIONALLY, controlled by `in_host_netns`.
// Under NetworkMode::On `needs_netns()` returns false, so the workload
// shares the HOST netns and AF_NETLINK would give it `ip route`/`ip addr`
// on the host. When `in_host_netns` is true the filter appends AF_NETLINK
// to the block list — the workload asked for host network so it can
// connect() out, but doesn't get to enumerate host interfaces/routes via
// netlink. When false (Off/Allowlist → CLONE_NEWNET),
// AF_NETLINK stays allowed so getifaddrs()/getaddrinfo(AI_ADDRCONFIG) keep
// working inside the empty/provisioned netns where they're harmless.
const AF_NETLINK: u32 = 16;
const AF_PACKET: u32 = 17; // Raw packet sockets — CVE-2025-38617 (af_packet race).
const AF_CAN: u32 = 29; // Controller Area Network — triggers can.ko autoload.
const AF_TIPC: u32 = 30; // Transparent IPC — CVE-2021-43267.
const AF_BLUETOOTH: u32 = 31; // Physical network bypass — triggers bt module autoload.
const AF_ALG: u32 = 38; // Kernel crypto API — CVE-2023-6176, CVE-2024-0775,
                        // CVE-2026-31431 ("Copy Fail": algif_aead + splice
                        // page-cache write to setuid binaries).
const AF_NFC: u32 = 39; // Near Field Communication — triggers nfc.ko autoload.
const AF_VSOCK: u32 = 40; // Hypervisor communication — bypasses net namespace on VMs.
const AF_KCM: u32 = 41; // Kernel Connection Multiplexer — triggers kcm.ko autoload.
const AF_QIPCRTR: u32 = 42; // Qualcomm IPC Router — triggers qrtr.ko autoload.
const AF_XDP: u32 = 44; // eBPF packet processing sockets.

/// Dangerous socket address families blocked via socket() argument inspection.
/// Defined once so the BPF offset calculation and the JEQ loop use the same array.
pub const BLOCKED_SOCKET_AFS: [u32; 10] = [AF_PACKET, AF_CAN, AF_TIPC, AF_BLUETOOTH, AF_ALG, AF_NFC, AF_VSOCK, AF_KCM, AF_QIPCRTR, AF_XDP];

/// Number of blocked socket address families — derived from the array.
pub const BLOCKED_SOCKET_AF_COUNT: usize = BLOCKED_SOCKET_AFS.len();

// Dangerous prctl sub-operations blocked via argument inspection.
// Safe operations like PR_CAPBSET_READ (23), PR_SET_KEEPCAPS (8),
// PR_SET_NAME (15), PR_CAPBSET_DROP (24), and all PR_GET_* are allowed.
const PR_SET_DUMPABLE: u32 = 4; // Re-enable ptrace attachment + core dumps.
const PR_SET_SECCOMP: u32 = 22; // Alternative seccomp installation path.
const PR_SET_SECUREBITS: u32 = 28; // Modify capability securebits.
const PR_SET_MM: u32 = 35; // Modify /proc/self/exe and memory layout.
const PR_CAP_AMBIENT: u32 = 47; // Ambient capability manipulation.
const PR_SET_PTRACER: u32 = 0x5961_6d61; // Yama LSM: allow specific pid to ptrace.

/// Dangerous prctl sub-operations blocked via argument inspection.
///
/// `prctl()` is a multiplexer — the first argument selects the operation.
/// Most operations are harmless (name, keepcaps, bounding set queries), but
/// a few can undermine sandbox isolation. We block those and allow the rest,
/// so programs like `ping` (which calls `PR_CAPBSET_READ` and `PR_SET_KEEPCAPS`)
/// work without issue.
pub const BLOCKED_PRCTL_OPS: [u32; 6] = [PR_SET_DUMPABLE, PR_SET_SECCOMP, PR_SET_SECUREBITS, PR_SET_MM, PR_CAP_AMBIENT, PR_SET_PTRACER];

/// Number of blocked prctl operations — derived from the array.
pub const BLOCKED_PRCTL_OPS_COUNT: usize = BLOCKED_PRCTL_OPS.len();

// Dangerous ioctl commands blocked via argument inspection on args[1].
// ioctl(fd, request, ...) — request is the command number in args[1].
const TIOCSTI: u32 = 0x5412; // Inject keystrokes into terminal (deprecated in 6.2).
const TIOCLINUX: u32 = 0x541C; // Virtual console selection/paste.

/// Dangerous ioctl commands blocked via argument inspection.
///
/// `ioctl()` is a massive multiplexer — the second argument (request) selects
/// the operation. Most commands are harmless (TCGETS for terminal queries,
/// FIONREAD for buffer sizes), but a few can escape sandbox isolation:
/// - `TIOCSTI` injects keystrokes into a controlling terminal
/// - `TIOCLINUX` manipulates virtual console selection
pub const BLOCKED_IOCTL_CMDS: [u32; 2] = [TIOCSTI, TIOCLINUX];

/// Number of blocked ioctl commands — derived from the array.
pub const BLOCKED_IOCTL_CMD_COUNT: usize = BLOCKED_IOCTL_CMDS.len();

// New mount info syscalls (kernel 6.8+) — not yet in libc for x86_64/aarch64.
// These bypass /proc masking to retrieve mount namespace information.
const SYS_STATMOUNT: i64 = 457;
const SYS_LISTMOUNT: i64 = 458;

/// EPERM errno value packed into seccomp return.
const ERRNO_EPERM: u32 = SECCOMP_RET_ERRNO | 1; // EPERM = 1

/// ENOSYS for clone3. glibc 2.35+ uses clone3 for pthread_create; its flags
/// live in a struct at arg[0] which BPF can't deref, so we can't distinguish
/// "create thread" from "create namespace" the way we can with clone(flags).
/// Returning ENOSYS makes glibc fall back to clone() — which DOES have arg
/// inspection below that kills on CLONE_NEW*. Verified: EPERM does NOT
/// trigger the fallback (glibc treats it as "denied", not "unavailable"),
/// so the generic ERRNO tier won't work here.
const ERRNO_ENOSYS: u32 = SECCOMP_RET_ERRNO | 38; // ENOSYS = 38

/// Construct a BPF statement (non-jump) instruction.
fn bpf_stmt(code: u16, k: u32) -> BpfInsn {
    BpfInsn { code, jt: 0, jf: 0, k }
}

/// Construct a BPF conditional jump instruction with true/false offsets.
fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> BpfInsn {
    BpfInsn { code, jt, jf, k }
}

/// Install the seccomp BPF filter on the calling thread.
///
/// Must be called after `PR_SET_NO_NEW_PRIVS` is set. Returns `Ok(true)` on
/// success, or `Err` if installation fails (e.g. seccomp not available).
///
/// When `allow_memfd` is true, `memfd_create()` and `execveat()` are removed
/// from the ERRNO tier — needed for JIT compilers and language runtimes.
pub(crate) fn install_seccomp_filter(allow_memfd: bool, in_host_netns: bool) -> Result<bool> {
    let filter = build_filter(allow_memfd, in_host_netns)?;
    let len: u16 = filter.len().try_into().map_err(|_| OaieError::SandboxError(format!("seccomp filter too large: {} instructions (max {})", filter.len(), u16::MAX)))?;
    let prog = BpfProg { len, filter: filter.as_ptr() };

    // SECCOMP_SET_MODE_FILTER = 1, SECCOMP_FILTER_FLAG_TSYNC = 1.
    // TSYNC synchronizes the filter across all threads. The child is
    // single-threaded at this point, but TSYNC is a zero-cost safety net
    // against future changes that might introduce threading before exec.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            1i32,                             // SECCOMP_SET_MODE_FILTER
            1i32,                             // SECCOMP_FILTER_FLAG_TSYNC
            &prog as *const BpfProg as usize, // args
        )
    };

    if ret == 0 {
        Ok(true)
    } else {
        let err = std::io::Error::last_os_error();
        Err(OaieError::SandboxError(format!("seccomp filter installation failed: {err}")))
    }
}

/// Build the BPF filter program.
///
/// The filter has three sections plus argument inspection for clone, socket,
/// prctl, and ioctl:
/// 1. Architecture check (kills 32-bit compat syscalls)
/// 2. Kill tier — unconditional KILL for dangerous syscalls
/// 3. Errno tier — returns EPERM for blocked-but-safe syscalls
/// 4. Clone argument inspection — kills `clone()` only if CLONE_NEW* flags are
///    set; plain `fork()`/`clone()` without namespace flags is allowed
/// 5. Socket argument inspection — returns EPERM for dangerous address families
///    (AF_NETLINK, AF_PACKET, AF_CAN, AF_TIPC, AF_BLUETOOTH, AF_ALG, AF_NFC,
///    AF_VSOCK, AF_KCM, AF_QIPCRTR, AF_XDP) that expose kernel attack surface
///    or trigger module autoloading; normal sockets are allowed
/// 6. Prctl argument inspection — returns EPERM for dangerous sub-operations
///    (PR_SET_DUMPABLE, PR_SET_SECCOMP, PR_SET_MM, etc.); safe operations like
///    PR_CAPBSET_READ, PR_SET_KEEPCAPS, and PR_SET_NAME are allowed
/// 7. Ioctl argument inspection — returns EPERM for dangerous ioctl commands
///    (TIOCSTI keystroke injection, TIOCLINUX console manipulation); normal
///    ioctls like TCGETS, FIONREAD are allowed
///
/// `SYS_clone` needs argument inspection because glibc uses it for `fork()`.
/// Simply killing all `clone()` calls would break shell pipes, subprocesses, etc.
///
/// `SYS_socket` needs argument inspection because `socket(AF_INET, ...)` is
/// legitimate, but `socket(AF_ALG, ...)` triggers kernel crypto module loading
/// and exposes the algif_* family (CVE-2023-6176, CVE-2024-0775,
/// CVE-2026-31431 "Copy Fail") and `socket(AF_VSOCK, ...)` can bypass
/// network namespace isolation on VMs.
///
/// `SYS_prctl` needs argument inspection because it's a multiplexer: most
/// operations are harmless (name, keepcaps, bounding set queries) but a few
/// can undermine sandbox isolation (re-enable ptrace, install seccomp filters,
/// modify /proc/self/exe, manipulate ambient capabilities).
///
/// `SYS_ioctl` needs argument inspection because it's the single largest
/// unfiltered syscall surface. The command number is in args[1] (not args[0]).
/// TIOCSTI (0x5412) can inject keystrokes into a terminal; TIOCLINUX (0x541C)
/// can manipulate virtual console selection. Both are blocked with EPERM.
///
/// When `allow_memfd` is true, `memfd_create()` and `execveat()` are excluded
/// from the ERRNO tier so JIT compilers and language runtimes can function.
pub fn build_filter(allow_memfd: bool, in_host_netns: bool) -> Result<Vec<BpfInsn>> {
    let kill_syscalls = kill_tier_syscalls();
    let errno_syscalls = errno_tier_syscalls(allow_memfd);

    // Socket AF block list is mode-dependent (see AF_NETLINK comment above).
    // Built as a Vec so n_sock_af reflects the actual count and the offset
    // arithmetic below stays correct without compile-time gymnastics.
    let mut blocked_afs: Vec<u32> = BLOCKED_SOCKET_AFS.to_vec();
    if in_host_netns {
        blocked_afs.push(AF_NETLINK);
    }

    let n_kill = kill_syscalls.len();
    let n_errno = errno_syscalls.len();
    let n_sock_af = blocked_afs.len();
    let n_prctl = BLOCKED_PRCTL_OPS_COUNT;
    let n_ioctl = BLOCKED_IOCTL_CMD_COUNT;

    // Program structure (Ns = n_sock_af, Np = n_prctl, Ni = n_ioctl):
    //   [0]     Load arch
    //   [1]     Check arch → kill_ret if wrong
    //   [2]     Load syscall nr
    //   [3]     JGE 0x40000000 → kill_ret (x32 ABI gate — see below)
    //   [4..4+n_kill-1]              Kill tier JEQs → kill_ret
    //   [4+n_kill..4+n_kill+n_errno-1]  Errno tier JEQs → errno_ret
    //   [C+0]   JEQ SYS_clone3 → fall through to ENOSYS, else skip
    //   [C+1]   RET ENOSYS (glibc retries with clone())
    //   [C+2]   JEQ SYS_clone → clone_check
    //   [C+3]   JEQ SYS_socket → socket_check
    //   [C+4]   JEQ SYS_socketpair → socket_check
    //   [C+5]   JEQ SYS_prctl → prctl_check
    //   [C+6]   JEQ SYS_ioctl → ioctl_check
    //   [C+7]   RET ALLOW (default — no match)
    //   --- clone argument inspection (5 insns) ---
    //   [C+8]   Load args[0] low 32 bits (clone flags)
    //   [C+9]   AND with CLONE_NEW_MASK
    //   [C+10]  JEQ 0 → clone_allow (jt=1), else fall through
    //   [C+11]  RET KILL_PROCESS (namespace flags in clone)
    //   [C+12]  RET ALLOW (clone without namespace flags)
    //   --- socket argument inspection (2+Ns insns) ---
    //   [C+13]              Load args[0] (address family)
    //   [C+14..C+13+Ns]     JEQ AF_xxx → errno_ret
    //   [C+14+Ns]           RET ALLOW (normal socket)
    //   --- prctl argument inspection (2+Np insns) ---
    //   [C+15+Ns]              Load args[0] (prctl operation)
    //   [C+16+Ns..C+15+Ns+Np]  JEQ PR_xxx → errno_ret
    //   [C+16+Ns+Np]           RET ALLOW (safe prctl)
    //   --- ioctl argument inspection (2+Ni insns) ---
    //   [C+17+Ns+Np]              Load args[1] (ioctl command)
    //   [C+18+Ns+Np..C+17+Ns+Np+Ni]  JEQ TIOC_xxx → errno_ret
    //   [C+18+Ns+Np+Ni]              RET ALLOW (safe ioctl)
    //   --- return targets ---
    //   [C+19+Ns+Np+Ni]  RET KILL_PROCESS (kill tier + arch mismatch target)
    //   [C+20+Ns+Np+Ni]  RET ERRNO(EPERM) (errno tier + socket/prctl/ioctl target)
    //
    //   where C = 4 + n_kill + n_errno (the four-instruction prefix is
    //   arch-load + arch JEQ + nr-load + x32 gate at [3])
    //
    //   If you insert anything in the body, recompute from insns.len() at
    //   the point of insertion rather than trusting these labels — jump
    //   OFFSETS are relative so they survive shifts, but absolute indices
    //   in this comment do not.

    let c = 4 + n_kill + n_errno;
    // 2 (clone3→ENOSYS) + 6 (dispatch incl. socketpair) + 5 (clone) + 2+Ns (socket) + 2+Np (prctl) + 2+Ni (ioctl) + 2 (returns)
    let total = c + 21 + n_sock_af + n_prctl + n_ioctl;
    let mut insns = Vec::with_capacity(total);

    // BPF jump offsets are u8 — guard against overflow if syscall lists grow.
    // Worst-case offset is total-2 (from instruction 1 to last instruction).
    if total > 257 {
        return Err(OaieError::SandboxError(format!("seccomp filter too large ({total} instructions, max 257 for u8 jump offsets)")));
    }

    let kill_ret_idx = c + 19 + n_sock_af + n_prctl + n_ioctl;
    let errno_ret_idx = c + 20 + n_sock_af + n_prctl + n_ioctl;

    // [0] Load architecture.
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH));

    // [1] Check architecture — kill if wrong.
    let arch = native_audit_arch();
    let jf_arch = (kill_ret_idx - 2) as u8;
    insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, arch, 0, jf_arch));

    // [2] Load syscall number.
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR));

    // [3] x32 ABI gate. On x86_64 kernels with CONFIG_X86_X32_ABI=y, x32
    // syscalls share AUDIT_ARCH_X86_64 (so the arch JEQ at [1] passes) but
    // carry __X32_SYSCALL_BIT (0x40000000) in nr. The tier JEQs below
    // compare against raw libc::SYS_* — x32's mount = 0x400000a5 ≠ 165 →
    // every JEQ falls through → default ALLOW. Without this gate the entire
    // filter is bypassable by setting bit 30 in nr. The gate is a
    // no-op on aarch64/rv64gc (nr never ≥ 0x40000000 there), so it's
    // unconditional rather than #[cfg]'d to keep the offset arithmetic
    // arch-independent.
    let jt_x32 = (kill_ret_idx - 3 - 1) as u8;
    insns.push(bpf_jump(BPF_JMP | BPF_JGE | BPF_K, 0x4000_0000, jt_x32, 0));

    // [4..4+n_kill-1] Kill tier: each syscall gets a JEQ → kill_ret.
    for (i, &nr) in kill_syscalls.iter().enumerate() {
        let cur_idx = 4 + i;
        let jt = (kill_ret_idx - cur_idx - 1) as u8;
        insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr as u32, jt, 0));
    }

    // [4+n_kill..4+n_kill+n_errno-1] Errno tier.
    for (i, &nr) in errno_syscalls.iter().enumerate() {
        let cur_idx = 4 + n_kill + i;
        let jt = (errno_ret_idx - cur_idx - 1) as u8;
        insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr as u32, jt, 0));
    }

    // [C+0] clone3 → ENOSYS. Inserted before the dispatch chain so the
    // dispatch JEQs' relative jt offsets (which target blocks that also
    // shifted by +2) stay arithmetically unchanged. Only kill_ret_idx and
    // errno_ret_idx (absolute targets used by the tier JEQs above) needed +2.
    // jt=0 falls through to the inline ENOSYS; jf=1 skips over it into the
    // dispatch chain.
    insns.push(bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_clone3 as u32,
        0, // jt: fall through → ENOSYS
        1, // jf: skip ENOSYS → clone dispatch
    ));
    // [C+1] RET ENOSYS — glibc sees "not implemented", retries with clone().
    insns.push(bpf_stmt(BPF_RET | BPF_K, ERRNO_ENOSYS));

    // [C+2] JEQ SYS_clone → clone_check at C+8 (skip 5), else fall through.
    insns.push(bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_clone as u32,
        5, // jt: skip socket_jeq + socketpair_jeq + prctl_jeq + ioctl_jeq + ALLOW
        0, // jf: fall through
    ));

    // [C+3] JEQ SYS_socket → socket_check at C+13 (skip 9), else fall through.
    insns.push(bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_socket as u32,
        9, // jt: skip socketpair_jeq + prctl_jeq + ioctl_jeq + ALLOW + clone block (5) → C+13
        0, // jf: fall through to C+4
    ));

    // [C+4] JEQ SYS_socketpair → socket_check at C+13 (skip 8). socketpair's
    // args[0] is also the address family (same ABI as socket), so the same
    // arg-inspection block applies. Without this JEQ, socketpair(AF_ALG,…)
    // falls through to ALLOW with args never inspected — both syscalls reach
    // __sock_create() → pf->create(), so BLOCKED_SOCKET_AFS was guarding one
    // of two doors
    insns.push(bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_socketpair as u32,
        8, // jt: skip prctl_jeq + ioctl_jeq + ALLOW + clone block (5) → C+13
        0, // jf: fall through to C+5
    ));

    // [C+5] JEQ SYS_prctl → prctl_check at C+15+Ns (skip 9+Ns), else fall through.
    let prctl_check_offset = (9 + n_sock_af) as u8;
    insns.push(bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_prctl as u32,
        prctl_check_offset, // jt: skip ioctl_jeq + ALLOW + clone(5) + socket(2+Ns) → C+14+Ns
        0,                  // jf: fall through to C+5
    ));

    // [C+5] JEQ SYS_ioctl → ioctl_check at C+16+Ns+Np (skip 10+Ns+Np).
    let ioctl_check_offset = (10 + n_sock_af + n_prctl) as u8;
    insns.push(bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_ioctl as u32,
        ioctl_check_offset, // jt: skip ALLOW + clone(5) + socket(2+Ns) + prctl(2+Np) → C+16+Ns+Np
        0,                  // jf: fall through to C+6
    ));

    // [C+6] Default ALLOW — syscall not in any tier, not clone/socket/prctl/ioctl.
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    // --- Clone argument inspection block (C+7..C+11) ---

    // [C+7] Load clone flags (args[0], low 32 bits on little-endian).
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARGS_0_LO));

    // [C+8] AND with CLONE_NEW_MASK — isolate namespace flag bits.
    insns.push(bpf_stmt(BPF_ALU | BPF_AND | BPF_K, CLONE_NEW_MASK));

    // [C+9] JEQ 0 → safe fork (skip 1 to clone_allow at C+11), else → KILL.
    insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0));

    // [C+10] KILL — clone() with namespace flags.
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // [C+11] ALLOW — clone() without namespace flags (plain fork).
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    // --- Socket argument inspection block (C+12..C+13+Ns) ---

    // [C+12] Load socket domain (args[0], low 32 bits — address family).
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARGS_0_LO));

    // [C+13..C+12+Ns] JEQ for each blocked address family → errno_ret.
    // cur_idx computed from insns.len() would be cleaner but this matches
    // the pattern in the tier loops above; keeping it consistent.
    for (i, &af) in blocked_afs.iter().enumerate() {
        let cur_idx = c + 14 + i;
        let jt = (errno_ret_idx - cur_idx - 1) as u8;
        insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, af, jt, 0));
    }

    // [C+13+Ns] ALLOW — socket with normal address family.
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    // --- Prctl argument inspection block (C+14+Ns..C+15+Ns+Np) ---
    // Blocks dangerous sub-operations while allowing safe ones (PR_CAPBSET_READ,
    // PR_SET_KEEPCAPS, PR_SET_NAME, etc.) that programs like ping need.

    // [C+14+Ns] Load prctl operation (args[0], low 32 bits).
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARGS_0_LO));

    // [C+15+Ns..C+14+Ns+Np] JEQ for each dangerous prctl op → errno_ret.
    for (i, &op) in BLOCKED_PRCTL_OPS.iter().enumerate() {
        let cur_idx = c + 16 + n_sock_af + i;
        let jt = (errno_ret_idx - cur_idx - 1) as u8;
        insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, op, jt, 0));
    }

    // [C+13+Ns+Np] ALLOW — safe prctl operation.
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    // --- Ioctl argument inspection block (C+14+Ns+Np..C+15+Ns+Np+Ni) ---
    // Blocks dangerous ioctl commands (TIOCSTI, TIOCLINUX) while allowing
    // normal terminal queries and I/O control operations.

    // [C+14+Ns+Np] Load ioctl command (args[1], low 32 bits).
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARGS_1_LO));

    // [C+15+Ns+Np..C+14+Ns+Np+Ni] JEQ for each blocked ioctl cmd → errno_ret.
    for (i, &cmd) in BLOCKED_IOCTL_CMDS.iter().enumerate() {
        let cur_idx = c + 18 + n_sock_af + n_prctl + i;
        let jt = (errno_ret_idx - cur_idx - 1) as u8;
        insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, cmd, jt, 0));
    }

    // [C+15+Ns+Np+Ni] ALLOW — safe ioctl command.
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    // --- Return targets ---

    // [C+16+Ns+Np+Ni] KILL_PROCESS — arch mismatch + kill tier target.
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // [C+17+Ns+Np+Ni] ERRNO(EPERM) — errno tier + socket/prctl/ioctl blocked ops target.
    insns.push(bpf_stmt(BPF_RET | BPF_K, ERRNO_EPERM));

    if insns.len() != total {
        return Err(OaieError::SandboxError(format!("seccomp filter size mismatch: expected {total}, got {}", insns.len())));
    }

    Ok(insns)
}

// --- Architecture-specific syscall number tables ---

/// AUDIT_ARCH value for the native architecture.
fn native_audit_arch() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        // AUDIT_ARCH_X86_64 = 0xC000003E
        0xC000_003E
    }
    #[cfg(target_arch = "aarch64")]
    {
        // AUDIT_ARCH_AARCH64 = 0xC00000B7
        0xC000_00B7
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        compile_error!("seccomp: unsupported architecture");
    }
}

/// Kill-tier syscalls with human-readable names for display.
pub fn kill_tier_named() -> Vec<(&'static str, i64)> {
    #[cfg(target_arch = "x86_64")]
    {
        vec![
            ("io_uring_setup", libc::SYS_io_uring_setup),
            ("io_uring_enter", libc::SYS_io_uring_enter),
            ("io_uring_register", libc::SYS_io_uring_register),
            ("userfaultfd", libc::SYS_userfaultfd),
            ("kexec_load", libc::SYS_kexec_load),
            ("kexec_file_load", libc::SYS_kexec_file_load),
            ("init_module", libc::SYS_init_module),
            ("finit_module", libc::SYS_finit_module),
            #[allow(deprecated)]
            ("create_module", libc::SYS_create_module),
            ("bpf", libc::SYS_bpf),
            ("unshare", libc::SYS_unshare),
            // clone3 handled separately — ENOSYS forces glibc's clone() fallback
            // so the arg-inspectable path carries the namespace-flag check.
            ("modify_ldt", libc::SYS_modify_ldt),
            ("iopl", libc::SYS_iopl),
            ("ioperm", libc::SYS_ioperm),
        ]
    }
    #[cfg(target_arch = "aarch64")]
    {
        vec![
            ("io_uring_setup", libc::SYS_io_uring_setup),
            ("io_uring_enter", libc::SYS_io_uring_enter),
            ("io_uring_register", libc::SYS_io_uring_register),
            ("userfaultfd", libc::SYS_userfaultfd),
            ("kexec_load", libc::SYS_kexec_load),
            ("kexec_file_load", libc::SYS_kexec_file_load),
            ("init_module", libc::SYS_init_module),
            ("finit_module", libc::SYS_finit_module),
            ("bpf", libc::SYS_bpf),
            ("unshare", libc::SYS_unshare),
            // clone3 handled separately — ENOSYS forces glibc's clone() fallback
            // so the arg-inspectable path carries the namespace-flag check.
        ]
    }
}

/// Syscalls in the KILL tier — sandbox escape vectors.
///
/// io_uring bypasses seccomp entirely (it submits syscalls from kernel context).
/// kexec/init_module/create_module load arbitrary kernel code.
/// bpf can install programs that bypass security.
/// unshare/clone3 could create nested namespaces to escape.
///
/// Note: `SYS_clone` is NOT in this list because glibc uses it for `fork()`.
/// Instead, `clone()` gets BPF argument inspection in `build_filter()` —
/// calls with `CLONE_NEW*` flags are killed, plain fork() is allowed.
pub fn kill_tier_syscalls() -> Vec<i64> {
    kill_tier_named().into_iter().map(|(_, nr)| nr).collect()
}

/// Errno-tier syscalls with human-readable names for display.
pub fn errno_tier_named(allow_memfd: bool) -> Vec<(&'static str, i64)> {
    #[cfg(target_arch = "x86_64")]
    {
        let mut syscalls = vec![
            ("ptrace", libc::SYS_ptrace),
            ("perf_event_open", libc::SYS_perf_event_open),
            ("mount", libc::SYS_mount),
            ("mount_setattr", libc::SYS_mount_setattr),
            ("pivot_root", libc::SYS_pivot_root),
            ("keyctl", libc::SYS_keyctl),
            ("add_key", libc::SYS_add_key),
            ("request_key", libc::SYS_request_key),
            ("kcmp", libc::SYS_kcmp),
            ("pidfd_send_signal", libc::SYS_pidfd_send_signal),
            ("pidfd_getfd", libc::SYS_pidfd_getfd),
            ("process_vm_readv", libc::SYS_process_vm_readv),
            ("process_vm_writev", libc::SYS_process_vm_writev),
            ("fsopen", libc::SYS_fsopen),
            ("fsconfig", libc::SYS_fsconfig),
            ("fsmount", libc::SYS_fsmount),
            ("move_mount", libc::SYS_move_mount),
            ("open_tree", libc::SYS_open_tree),
            ("fspick", libc::SYS_fspick),
            ("umount2", libc::SYS_umount2),
            ("setns", libc::SYS_setns),
            ("delete_module", libc::SYS_delete_module),
            ("reboot", libc::SYS_reboot),
            ("swapon", libc::SYS_swapon),
            ("swapoff", libc::SYS_swapoff),
            ("acct", libc::SYS_acct),
            ("quotactl", libc::SYS_quotactl),
            ("clock_adjtime", libc::SYS_clock_adjtime),
            ("clock_settime", libc::SYS_clock_settime),
            ("settimeofday", libc::SYS_settimeofday),
            ("adjtimex", libc::SYS_adjtimex),
            ("sethostname", libc::SYS_sethostname),
            ("setdomainname", libc::SYS_setdomainname),
            ("personality", libc::SYS_personality),
            ("remap_file_pages", libc::SYS_remap_file_pages),
            ("landlock_create_ruleset", libc::SYS_landlock_create_ruleset),
            ("landlock_add_rule", libc::SYS_landlock_add_rule),
            ("landlock_restrict_self", libc::SYS_landlock_restrict_self),
            ("open_by_handle_at", libc::SYS_open_by_handle_at),
            ("name_to_handle_at", libc::SYS_name_to_handle_at),
            ("pidfd_open", libc::SYS_pidfd_open),
            ("process_madvise", libc::SYS_process_madvise),
            ("memfd_secret", libc::SYS_memfd_secret),
            ("quotactl_fd", libc::SYS_quotactl_fd),
            ("seccomp", libc::SYS_seccomp),
            ("mknod", libc::SYS_mknod),
            ("mknodat", libc::SYS_mknodat),
            ("chroot", libc::SYS_chroot),
            ("fanotify_init", libc::SYS_fanotify_init),
            ("move_pages", libc::SYS_move_pages),
            ("migrate_pages", libc::SYS_migrate_pages),
            ("lookup_dcookie", libc::SYS_lookup_dcookie),
            ("syslog", libc::SYS_syslog),
            ("statmount", SYS_STATMOUNT),
            ("listmount", SYS_LISTMOUNT),
        ];
        if !allow_memfd {
            syscalls.push(("memfd_create", libc::SYS_memfd_create));
            syscalls.push(("execveat", libc::SYS_execveat));
        }
        syscalls
    }
    #[cfg(target_arch = "aarch64")]
    {
        let mut syscalls = vec![
            ("ptrace", libc::SYS_ptrace),
            ("perf_event_open", libc::SYS_perf_event_open),
            ("mount", libc::SYS_mount),
            ("mount_setattr", libc::SYS_mount_setattr),
            ("pivot_root", libc::SYS_pivot_root),
            ("keyctl", libc::SYS_keyctl),
            ("add_key", libc::SYS_add_key),
            ("request_key", libc::SYS_request_key),
            ("kcmp", libc::SYS_kcmp),
            ("pidfd_send_signal", libc::SYS_pidfd_send_signal),
            ("pidfd_getfd", libc::SYS_pidfd_getfd),
            ("process_vm_readv", libc::SYS_process_vm_readv),
            ("process_vm_writev", libc::SYS_process_vm_writev),
            ("fsopen", libc::SYS_fsopen),
            ("fsconfig", libc::SYS_fsconfig),
            ("fsmount", libc::SYS_fsmount),
            ("move_mount", libc::SYS_move_mount),
            ("open_tree", libc::SYS_open_tree),
            ("fspick", libc::SYS_fspick),
            ("umount2", libc::SYS_umount2),
            ("setns", libc::SYS_setns),
            ("delete_module", libc::SYS_delete_module),
            ("reboot", libc::SYS_reboot),
            ("swapon", libc::SYS_swapon),
            ("swapoff", libc::SYS_swapoff),
            ("acct", libc::SYS_acct),
            ("quotactl", libc::SYS_quotactl),
            ("clock_adjtime", libc::SYS_clock_adjtime),
            ("clock_settime", libc::SYS_clock_settime),
            ("settimeofday", libc::SYS_settimeofday),
            ("adjtimex", libc::SYS_adjtimex),
            ("sethostname", libc::SYS_sethostname),
            ("setdomainname", libc::SYS_setdomainname),
            ("personality", libc::SYS_personality),
            ("remap_file_pages", libc::SYS_remap_file_pages),
            ("landlock_create_ruleset", libc::SYS_landlock_create_ruleset),
            ("landlock_add_rule", libc::SYS_landlock_add_rule),
            ("landlock_restrict_self", libc::SYS_landlock_restrict_self),
            ("open_by_handle_at", libc::SYS_open_by_handle_at),
            ("name_to_handle_at", libc::SYS_name_to_handle_at),
            ("pidfd_open", libc::SYS_pidfd_open),
            ("process_madvise", libc::SYS_process_madvise),
            ("memfd_secret", libc::SYS_memfd_secret),
            ("quotactl_fd", libc::SYS_quotactl_fd),
            ("seccomp", libc::SYS_seccomp),
            ("mknodat", libc::SYS_mknodat),
            ("chroot", libc::SYS_chroot),
            ("fanotify_init", libc::SYS_fanotify_init),
            ("move_pages", libc::SYS_move_pages),
            ("migrate_pages", libc::SYS_migrate_pages),
            ("lookup_dcookie", libc::SYS_lookup_dcookie),
            ("syslog", libc::SYS_syslog),
            ("statmount", SYS_STATMOUNT),
            ("listmount", SYS_LISTMOUNT),
        ];
        if !allow_memfd {
            syscalls.push(("memfd_create", libc::SYS_memfd_create));
            syscalls.push(("execveat", libc::SYS_execveat));
        }
        syscalls
    }
}

/// Syscalls in the ERRNO(EPERM) tier — dangerous but EPERM is safe.
///
/// ptrace could manipulate sibling processes.
/// mount_setattr can change mount properties (new mount API).
/// pidfd_getfd can steal file descriptors from other processes.
/// process_vm_readv/writev can read/write other processes' memory.
///
/// When `allow_memfd` is true, `memfd_create` and `execveat` are excluded.
/// These are needed by JIT compilers and language runtimes (Java, Node.js, .NET)
/// that use fileless execution via anonymous memory-backed file descriptors.
pub fn errno_tier_syscalls(allow_memfd: bool) -> Vec<i64> {
    errno_tier_named(allow_memfd).into_iter().map(|(_, nr)| nr).collect()
}

/// Human-readable name for a blocked socket address family.
pub fn af_name(af: u32) -> &'static str {
    match af {
        AF_PACKET => "AF_PACKET",
        AF_CAN => "AF_CAN",
        AF_TIPC => "AF_TIPC",
        AF_BLUETOOTH => "AF_BLUETOOTH",
        AF_ALG => "AF_ALG",
        AF_NFC => "AF_NFC",
        AF_VSOCK => "AF_VSOCK",
        AF_KCM => "AF_KCM",
        AF_QIPCRTR => "AF_QIPCRTR",
        AF_XDP => "AF_XDP",
        _ => "AF_?",
    }
}

/// Human-readable name for a blocked prctl operation.
pub fn prctl_op_name(op: u32) -> &'static str {
    match op {
        PR_SET_DUMPABLE => "PR_SET_DUMPABLE",
        PR_SET_SECCOMP => "PR_SET_SECCOMP",
        PR_SET_SECUREBITS => "PR_SET_SECUREBITS",
        PR_SET_MM => "PR_SET_MM",
        PR_CAP_AMBIENT => "PR_CAP_AMBIENT",
        PR_SET_PTRACER => "PR_SET_PTRACER",
        _ => "PR_?",
    }
}

/// Human-readable name for a blocked ioctl command.
pub fn ioctl_cmd_name(cmd: u32) -> &'static str {
    match cmd {
        TIOCSTI => "TIOCSTI",
        TIOCLINUX => "TIOCLINUX",
        _ => "IOCTL_?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The offset arithmetic in build_filter() is hand-rolled (every JEQ
    // computes `target_idx - cur_idx - 1`); inserting an instruction
    // without rebasing `c` and the tier `cur_idx` formulas silently
    // produces a filter where some jumps land one slot short of their
    // intended RET. The runtime `insns.len() != total` check at the end
    // of build_filter() catches a SIZE mismatch, but not a jump that's
    // in-bounds-but-wrong. This test asserts:
    //   - both parameter combinations build (size check passes)
    //   - the two trailing return targets are RET KILL / RET ERRNO at
    //     the indices the tier loops aim at
    //   - no jt/jf offset lands past the end (catches an over-shoot
    //     from a stale `cur_idx` after a prefix insertion)
    // It does NOT simulate the BPF — that would need a full interpreter.
    // It catches the class of mistake any future prefix-instruction
    // insertion is most likely to make.
    #[test]
    fn filter_structure_invariants() {
        for &(allow_memfd, in_host_netns) in &[(false, false), (true, false), (false, true), (true, true)] {
            let f = build_filter(allow_memfd, in_host_netns).unwrap_or_else(|e| panic!("build({allow_memfd},{in_host_netns}): {e}"));
            let len = f.len();
            // Trailing return targets — every tier JEQ's jt aims here.
            assert_eq!(f[len - 2].code, BPF_RET | BPF_K, "kill_ret not RET");
            assert_eq!(f[len - 2].k, SECCOMP_RET_KILL_PROCESS, "kill_ret wrong k");
            assert_eq!(f[len - 1].code, BPF_RET | BPF_K, "errno_ret not RET");
            assert_eq!(f[len - 1].k, ERRNO_EPERM, "errno_ret wrong k");
            // x32 gate is at [3], one past the nr load. Its jt must land
            // exactly on kill_ret (len-2).
            assert_eq!(f[3].code, BPF_JMP | BPF_JGE | BPF_K, "x32 gate missing at [3]");
            assert_eq!(3 + 1 + f[3].jt as usize, len - 2, "x32 gate jt doesn't reach kill_ret");
            // No jump offset overshoots the program.
            for (pc, insn) in f.iter().enumerate() {
                if insn.code & 0x07 == BPF_JMP {
                    let jt = insn.jt as usize;
                    let jf = insn.jf as usize;
                    assert!(pc + 1 + jt < len, "jt overshoot at [{pc}] (jt={jt}, len={len})");
                    assert!(pc + 1 + jf < len, "jf overshoot at [{pc}] (jf={jf}, len={len})");
                }
            }
            // in_host_netns must change the filter (AF_NETLINK appended →
            // one more JEQ in the socket block → len differs by exactly 1).
        }
        let off = build_filter(false, false).unwrap().len();
        let on = build_filter(false, true).unwrap().len();
        assert_eq!(on, off + 1, "in_host_netns should add exactly one AF JEQ");
    }
}
