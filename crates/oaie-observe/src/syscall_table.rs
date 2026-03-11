//! Multi-architecture syscall number table.
//!
//! x86_64 has its own legacy table; aarch64 and rv64gc share the
//! asm-generic table (same numbers). Post-5.0 syscalls were assigned
//! after the asm-generic unification and share the same numbers everywhere.
//!
//! NOTE: fork/vfork do NOT exist on asm-generic. aarch64/rv64gc use clone
//! for all process creation. We use `u64::MAX` as a sentinel so
//! `is_security_relevant()` never matches on these arches for those syscalls.

// ── x86_64 syscall numbers (from asm/unistd_64.h) ──
#[cfg(target_arch = "x86_64")]
mod arch {
    pub const SYS_READ: u64 = 0;
    pub const SYS_WRITE: u64 = 1;
    pub const SYS_OPEN: u64 = 2;
    pub const SYS_CLOSE: u64 = 3;
    pub const SYS_STAT: u64 = 4;
    pub const SYS_FSTAT: u64 = 5;
    pub const SYS_LSTAT: u64 = 6;
    pub const SYS_SENDTO: u64 = 44;
    pub const SYS_SOCKET: u64 = 41;
    pub const SYS_CONNECT: u64 = 42;
    pub const SYS_CLONE: u64 = 56;
    pub const SYS_FORK: u64 = 57;
    pub const SYS_VFORK: u64 = 58;
    pub const SYS_EXECVE: u64 = 59;
    pub const SYS_PRCTL: u64 = 157;
    pub const SYS_MOUNT: u64 = 165;
    pub const SYS_UMOUNT2: u64 = 166;
    pub const SYS_OPENAT: u64 = 257;
    pub const SYS_UNSHARE: u64 = 272;
    pub const SYS_SPLICE: u64 = 275;
    pub const SYS_TEE: u64 = 276;
    pub const SYS_VMSPLICE: u64 = 278;
    pub const SYS_PERF_EVENT_OPEN: u64 = 298;
    pub const SYS_PROCESS_VM_READV: u64 = 310;
    pub const SYS_PROCESS_VM_WRITEV: u64 = 311;
    pub const SYS_KCMP: u64 = 312;
    pub const SYS_FINIT_MODULE: u64 = 313;
    pub const SYS_SECCOMP: u64 = 317;
    pub const SYS_MEMFD_CREATE: u64 = 319;
    pub const SYS_KEXEC_FILE_LOAD: u64 = 320;
    pub const SYS_BPF: u64 = 321;
    pub const SYS_EXECVEAT: u64 = 322;
    pub const SYS_USERFAULTFD: u64 = 323;
    pub const SYS_NEWFSTATAT: u64 = 262;
    pub const SYS_STATX: u64 = 332;
    pub const SYS_PTRACE: u64 = 101;
    pub const SYS_PERSONALITY: u64 = 135;
    pub const SYS_INIT_MODULE: u64 = 175;
    pub const SYS_DELETE_MODULE: u64 = 176;
    pub const SYS_KEXEC_LOAD: u64 = 246;
    pub const SYS_ADD_KEY: u64 = 248;
    pub const SYS_REQUEST_KEY: u64 = 249;
    pub const SYS_KEYCTL: u64 = 250;
    pub const SYS_PIVOT_ROOT: u64 = 155;
    pub const SYS_CHROOT: u64 = 161;
    pub const SYS_SWAPON: u64 = 167;
    pub const SYS_SWAPOFF: u64 = 168;
}

// ── asm-generic syscall numbers (aarch64 + rv64gc) ──
// Source: include/uapi/asm-generic/unistd.h (kernel 6.8+)
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
mod arch {
    pub const SYS_READ: u64 = 63;
    pub const SYS_WRITE: u64 = 64;
    pub const SYS_OPEN: u64 = u64::MAX; // not available, use openat
    pub const SYS_CLOSE: u64 = 57;
    pub const SYS_STAT: u64 = u64::MAX; // not available, use fstatat
    pub const SYS_FSTAT: u64 = 80;
    pub const SYS_LSTAT: u64 = u64::MAX; // not available, use fstatat
    pub const SYS_SENDTO: u64 = 206;
    pub const SYS_SOCKET: u64 = 198;
    pub const SYS_CONNECT: u64 = 203;
    pub const SYS_CLONE: u64 = 220;
    pub const SYS_FORK: u64 = u64::MAX; // not available, use clone
    pub const SYS_VFORK: u64 = u64::MAX; // not available, use clone
    pub const SYS_EXECVE: u64 = 221;
    pub const SYS_PRCTL: u64 = 167;
    pub const SYS_MOUNT: u64 = 40;
    pub const SYS_UMOUNT2: u64 = 39;
    pub const SYS_OPENAT: u64 = 56;
    pub const SYS_UNSHARE: u64 = 97;
    pub const SYS_SPLICE: u64 = 76;
    pub const SYS_TEE: u64 = 77;
    pub const SYS_VMSPLICE: u64 = 75;
    pub const SYS_PERF_EVENT_OPEN: u64 = 241;
    pub const SYS_PROCESS_VM_READV: u64 = 270;
    pub const SYS_PROCESS_VM_WRITEV: u64 = 271;
    pub const SYS_KCMP: u64 = 272;
    pub const SYS_FINIT_MODULE: u64 = 273;
    pub const SYS_SECCOMP: u64 = 277;
    pub const SYS_MEMFD_CREATE: u64 = 279;
    pub const SYS_BPF: u64 = 280;
    pub const SYS_EXECVEAT: u64 = 281;
    pub const SYS_USERFAULTFD: u64 = 282;
    pub const SYS_NEWFSTATAT: u64 = 79;
    pub const SYS_STATX: u64 = 291;
    pub const SYS_KEXEC_FILE_LOAD: u64 = 294;
    pub const SYS_PTRACE: u64 = 117;
    pub const SYS_PERSONALITY: u64 = 92;
    pub const SYS_INIT_MODULE: u64 = 105;
    pub const SYS_DELETE_MODULE: u64 = 106;
    pub const SYS_KEXEC_LOAD: u64 = u64::MAX; // not available on asm-generic
    pub const SYS_ADD_KEY: u64 = 217;
    pub const SYS_REQUEST_KEY: u64 = 218;
    pub const SYS_KEYCTL: u64 = 219;
    pub const SYS_PIVOT_ROOT: u64 = 41;
    pub const SYS_CHROOT: u64 = 51;
    pub const SYS_SWAPON: u64 = 224;
    pub const SYS_SWAPOFF: u64 = 225;
}

pub use arch::*;

// ── Unified syscall numbers (same across all architectures) ──
// Post-5.0 syscalls were assigned after the asm-generic unification.
pub const SYS_CLONE3: u64 = 435;
pub const SYS_IO_URING_SETUP: u64 = 425;
pub const SYS_IO_URING_ENTER: u64 = 426;
pub const SYS_IO_URING_REGISTER: u64 = 427;
pub const SYS_FSOPEN: u64 = 430;
pub const SYS_FSCONFIG: u64 = 431;
pub const SYS_FSMOUNT: u64 = 432;
pub const SYS_MOVE_MOUNT: u64 = 429;
pub const SYS_OPEN_TREE: u64 = 428;
pub const SYS_PIDFD_GETFD: u64 = 438;
pub const SYS_PIDFD_OPEN: u64 = 434;
pub const SYS_PIDFD_SEND_SIGNAL: u64 = 424;

/// Map a syscall number to its name. Returns "unknown" for unrecognized numbers.
///
/// On aarch64/rv64gc, several constants are `u64::MAX` sentinels (fork, vfork,
/// open, stat, lstat, kexec_load don't exist on asm-generic), so their match
/// arms are unreachable — but keeping them makes the table complete for x86_64.
#[allow(unreachable_patterns)]
pub fn syscall_name(nr: u64) -> &'static str {
    match nr {
        SYS_OPENAT => "openat",
        SYS_EXECVE => "execve",
        SYS_CONNECT => "connect",
        SYS_SENDTO => "sendto",
        SYS_NEWFSTATAT => "newfstatat",
        SYS_STATX => "statx",
        SYS_CLONE => "clone",
        SYS_FORK => "fork",
        SYS_VFORK => "vfork",
        SYS_CLONE3 => "clone3",
        SYS_SOCKET => "socket",
        SYS_MOUNT => "mount",
        SYS_UMOUNT2 => "umount2",
        SYS_UNSHARE => "unshare",
        SYS_PTRACE => "ptrace",
        SYS_MEMFD_CREATE => "memfd_create",
        SYS_EXECVEAT => "execveat",
        SYS_PROCESS_VM_READV => "process_vm_readv",
        SYS_PROCESS_VM_WRITEV => "process_vm_writev",
        SYS_USERFAULTFD => "userfaultfd",
        SYS_IO_URING_SETUP => "io_uring_setup",
        SYS_IO_URING_ENTER => "io_uring_enter",
        SYS_IO_URING_REGISTER => "io_uring_register",
        SYS_PERSONALITY => "personality",
        SYS_PERF_EVENT_OPEN => "perf_event_open",
        SYS_BPF => "bpf",
        SYS_SECCOMP => "seccomp",
        SYS_FSOPEN => "fsopen",
        SYS_FSCONFIG => "fsconfig",
        SYS_FSMOUNT => "fsmount",
        SYS_MOVE_MOUNT => "move_mount",
        SYS_OPEN_TREE => "open_tree",
        SYS_PIDFD_GETFD => "pidfd_getfd",
        SYS_PIDFD_OPEN => "pidfd_open",
        SYS_PIDFD_SEND_SIGNAL => "pidfd_send_signal",
        SYS_KEYCTL => "keyctl",
        SYS_ADD_KEY => "add_key",
        SYS_REQUEST_KEY => "request_key",
        SYS_INIT_MODULE => "init_module",
        SYS_FINIT_MODULE => "finit_module",
        SYS_DELETE_MODULE => "delete_module",
        SYS_KEXEC_LOAD => "kexec_load",
        SYS_KEXEC_FILE_LOAD => "kexec_file_load",
        SYS_SPLICE => "splice",
        SYS_TEE => "tee",
        SYS_VMSPLICE => "vmsplice",
        SYS_KCMP => "kcmp",
        SYS_PRCTL => "prctl",
        SYS_PIVOT_ROOT => "pivot_root",
        SYS_CHROOT => "chroot",
        SYS_SWAPON => "swapon",
        SYS_SWAPOFF => "swapoff",
        _ => "unknown",
    }
}

/// Returns true if this syscall is security-relevant and should be flagged
/// in the trace even when full argument extraction is not implemented.
///
/// See week 7 plan for detailed rationale on each syscall.
#[allow(unreachable_patterns)]
pub fn is_security_relevant(nr: u64) -> bool {
    matches!(
        nr,
        SYS_MOUNT
            | SYS_UMOUNT2
            | SYS_UNSHARE
            | SYS_PTRACE
            | SYS_MEMFD_CREATE
            | SYS_EXECVEAT
            | SYS_PROCESS_VM_READV
            | SYS_PROCESS_VM_WRITEV
            | SYS_USERFAULTFD
            | SYS_IO_URING_SETUP
            | SYS_IO_URING_ENTER
            | SYS_IO_URING_REGISTER
            | SYS_PERSONALITY
            | SYS_PERF_EVENT_OPEN
            | SYS_BPF
            | SYS_SECCOMP
            | SYS_FSOPEN
            | SYS_FSCONFIG
            | SYS_FSMOUNT
            | SYS_MOVE_MOUNT
            | SYS_OPEN_TREE
            | SYS_PIDFD_GETFD
            | SYS_PIDFD_OPEN
            | SYS_PIDFD_SEND_SIGNAL
            | SYS_KEYCTL
            | SYS_ADD_KEY
            | SYS_REQUEST_KEY
            | SYS_INIT_MODULE
            | SYS_FINIT_MODULE
            | SYS_DELETE_MODULE
            | SYS_KEXEC_LOAD
            | SYS_KEXEC_FILE_LOAD
            | SYS_VMSPLICE
            | SYS_KCMP
            | SYS_CLONE
            | SYS_CLONE3
            | SYS_PIVOT_ROOT
            | SYS_CHROOT
            | SYS_SWAPON
            | SYS_SWAPOFF
    )
}
