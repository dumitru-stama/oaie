//! Ptrace-based syscall tracer.
//!
//! Traces a child process and all its descendants, capturing syscall events
//! (file open, exec, connect, stat) and security-relevant syscall attempts.
//! Events are written to the provided [`EventWriter`] as they happen.
//!
//! ## Integration
//!
//! The child must call `ptrace::traceme()` + `raise(SIGSTOP)` before exec.
//! The parent creates a `PtraceTracer` and calls `run()`, which takes over
//! the waitpid loop and returns the root process's exit code.
//!
//! ## Inherent TOCTOU limitation
//!
//! Ptrace sees syscall arguments **after** the kernel has begun processing
//! the syscall. By the time we read file paths from the child's memory, the
//! child (or another thread) could have modified them. This means the paths
//! and addresses we record are **best-effort observations**, not cryptographic
//! guarantees of what the kernel actually accessed. This is an inherent
//! limitation of ptrace-based tracing; eBPF-based tracing (v0.2) will
//! capture arguments at the kernel boundary.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;

use crate::chunked_writer::ChunkedEventWriter;
use crate::event::{EventDetail, EventType, OaieEvent};
use crate::memory::{self, SockAddrInfo};
use crate::syscall_table::*;

/// Block SIGCHLD and create a signalfd for it.
///
/// Returns `Some(fd)` on success, `None` if any step fails (in which case
/// the tracer falls back to a short sleep). The signalfd is non-blocking
/// and close-on-exec.
fn setup_signalfd() -> Option<libc::c_int> {
    unsafe {
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGCHLD);

        // Block SIGCHLD so it goes to the signalfd instead of being delivered.
        let mut old_mask: libc::sigset_t = std::mem::zeroed();
        if libc::pthread_sigmask(libc::SIG_BLOCK, &mask, &mut old_mask) != 0 {
            return None;
        }

        let fd = libc::signalfd(-1, &mask, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC);
        if fd < 0 {
            // Restore old signal mask on failure.
            libc::pthread_sigmask(libc::SIG_SETMASK, &old_mask, std::ptr::null_mut());
            return None;
        }

        Some(fd)
    }
}

/// Clean up signalfd: close the fd and unblock SIGCHLD on this thread.
/// Called on both normal and error exit paths to prevent fd leaks
/// and ensure SIGCHLD is not permanently blocked on the thread.
fn cleanup_signalfd(sigchld_fd: Option<libc::c_int>) {
    if let Some(fd) = sigchld_fd {
        unsafe {
            libc::close(fd);
            let mut mask: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGCHLD);
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &mask, std::ptr::null_mut());
        }
    }
}

/// Wait for SIGCHLD via signalfd+poll, or sleep briefly if signalfd is unavailable.
///
/// `timeout_ms` is the maximum time to wait in milliseconds. When a SIGCHLD
/// arrives (possibly coalesced), the function drains the signalfd and returns
/// so the caller can sweep all PIDs with WNOHANG.
fn wait_for_sigchld(sigchld_fd: Option<libc::c_int>, timeout_ms: libc::c_int) {
    let Some(fd) = sigchld_fd else {
        // Fallback: short sleep when signalfd is not available.
        std::thread::sleep(std::time::Duration::from_micros(100));
        return;
    };

    unsafe {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };

        libc::poll(&mut pfd, 1, timeout_ms);

        // Drain all pending signals (SIGCHLD may be coalesced).
        if pfd.revents & libc::POLLIN != 0 {
            let mut buf = [0u8; std::mem::size_of::<libc::signalfd_siginfo>()];
            loop {
                let n = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
                if n <= 0 {
                    break;
                }
            }
        }
    }
}

/// Architecture-abstracted syscall register access.
///
/// Provides uniform `syscall_nr`, `args[0..6]`, and `ret_val` across
/// x86_64, aarch64, and rv64gc.
pub struct SyscallRegs {
    /// The syscall number (from orig_rax on x86_64, x8 on aarch64, a7 on rv64gc).
    pub syscall_nr: u64,
    /// Syscall arguments: arg0..arg5.
    pub args: [u64; 6],
    /// Return value (rax on x86_64, x0 on aarch64, a0 on rv64gc).
    pub ret_val: i64,
}

/// Read registers from a traced process, abstracting architecture differences.
fn get_regs(pid: Pid) -> Result<SyscallRegs, nix::errno::Errno> {
    #[cfg(target_arch = "x86_64")]
    {
        let regs = ptrace::getregs(pid)?;
        Ok(SyscallRegs {
            syscall_nr: regs.orig_rax,
            args: [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9],
            ret_val: regs.rax as i64,
        })
    }

    // aarch64/rv64gc: PTRACE_GETREGS not available, use PTRACE_GETREGSET.
    #[cfg(target_arch = "aarch64")]
    {
        use std::mem;
        // libc doesn't expose `user_pt_regs` for aarch64; define it manually.
        // Layout matches kernel's `struct user_pt_regs` (arch/arm64/include/uapi/asm/ptrace.h):
        // 31 general-purpose registers (x0–x30), then sp, pc, pstate.
        #[repr(C)]
        struct UserPtRegs {
            regs: [u64; 31],
            sp: u64,
            pc: u64,
            pstate: u64,
        }
        let mut regs: UserPtRegs = unsafe { mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: &mut regs as *mut _ as *mut _,
            iov_len: mem::size_of_val(&regs),
        };
        let ret = unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGSET,
                pid.as_raw(),
                libc::NT_PRSTATUS,
                &mut iov as *mut _,
            )
        };
        if ret < 0 {
            return Err(nix::errno::Errno::last());
        }
        Ok(SyscallRegs {
            syscall_nr: regs.regs[8],
            args: [
                regs.regs[0],
                regs.regs[1],
                regs.regs[2],
                regs.regs[3],
                regs.regs[4],
                regs.regs[5],
            ],
            ret_val: regs.regs[0] as i64,
        })
    }

    #[cfg(target_arch = "riscv64")]
    {
        let regs = ptrace::getregs(pid)?;
        Ok(SyscallRegs {
            syscall_nr: regs.a7 as u64,
            args: [
                regs.a0 as u64,
                regs.a1 as u64,
                regs.a2 as u64,
                regs.a3 as u64,
                regs.a4 as u64,
                regs.a5 as u64,
            ],
            ret_val: regs.a0 as i64,
        })
    }
}

/// Per-PID syscall entry/exit state.
///
/// Ptrace delivers two stops per syscall: one at entry, one at exit.
/// We capture arguments at entry and the return value at exit.
struct SyscallState {
    /// True if we're expecting a syscall entry, false if expecting exit.
    in_entry: bool,
    /// The syscall number captured at entry.
    syscall_nr: u64,
    /// Arguments captured at entry (before kernel modifies them).
    args: [u64; 6],
}

/// Pending openat call — path and flags captured at entry, result at exit.
struct PendingOpen {
    path: String,
    flags: u32,
}

/// Pending statx call — path captured at entry, result at exit.
struct PendingStatx {
    path: String,
}

/// Pending connect call — socket address captured at entry, result at exit.
struct PendingConnect {
    addr_info: SockAddrInfo,
}

/// Pending sendto call — DNS query name captured at entry when dest is port 53.
struct PendingSendto {
    /// Parsed domain name from the DNS query payload.
    dns_name: String,
    /// DNS server address string (e.g. "8.8.8.8:53").
    server: String,
}

/// Pending execve call — filename and argv captured at entry, emitted on success
/// (PTRACE_EVENT_EXEC) rather than at entry time.
struct PendingExec {
    filename: String,
    argv: Vec<String>,
}

/// Ptrace-based syscall tracer for a sandboxed child process.
///
/// Owns the [`ChunkedEventWriter`] and runs the trace loop until all traced
/// processes exit. Returns the root process's exit code.
pub struct PtraceTracer {
    /// The root child PID (the tool's main process).
    root_pid: Pid,
    /// All currently traced PIDs (root + children from fork/clone).
    traced_pids: HashSet<i32>,
    /// Event writer — where we send observation events (CAS-chunked).
    writer: ChunkedEventWriter,
    /// Monotonic start time for relative timestamp calculation.
    start: Instant,
    /// Deadline after which the tracer kills all traced processes and returns.
    /// Derived from the effective timeout passed at construction.
    deadline: Option<Instant>,
    /// Per-PID syscall entry/exit tracking.
    syscall_states: HashMap<i32, SyscallState>,
    /// Parent-child PID mapping for process tree reconstruction.
    parent_map: HashMap<i32, i32>,
    /// Pending openat calls: path+flags at entry, waiting for exit.
    pending_opens: HashMap<i32, PendingOpen>,
    /// Pending statx calls: path at entry, waiting for exit.
    pending_statxs: HashMap<i32, PendingStatx>,
    /// Pending connect calls: address at entry, waiting for exit.
    pending_connects: HashMap<i32, PendingConnect>,
    /// Pending execve calls: filename+argv at entry, emitted on PTRACE_EVENT_EXEC.
    pending_execs: HashMap<i32, PendingExec>,
    /// Pending sendto calls to UDP port 53: DNS name at entry, emitted on exit.
    pending_sendtos: HashMap<i32, PendingSendto>,
    /// PIDs that have called memfd_create (for fileless exec detection).
    memfd_pids: HashSet<i32>,
    /// Number of events that failed to write (silent drops).
    dropped_events: u64,
    /// True if io_uring_setup was detected (trace has blind spots).
    pub io_uring_detected: bool,
}

impl PtraceTracer {
    /// Create a new tracer for the given root PID.
    ///
    /// The child should already be stopped (via SIGSTOP after traceme).
    /// Call `run()` to enter the trace loop.
    pub fn new(root_pid: Pid, writer: ChunkedEventWriter, timeout: Option<std::time::Duration>) -> Self {
        let mut traced_pids = HashSet::new();
        traced_pids.insert(root_pid.as_raw());
        let deadline = timeout.map(|d| Instant::now() + d);
        Self {
            root_pid,
            traced_pids,
            writer,
            start: Instant::now(),
            deadline,
            syscall_states: HashMap::new(),
            parent_map: HashMap::new(),
            pending_opens: HashMap::new(),
            pending_statxs: HashMap::new(),
            pending_connects: HashMap::new(),
            pending_execs: HashMap::new(),
            pending_sendtos: HashMap::new(),
            memfd_pids: HashSet::new(),
            dropped_events: 0,
            io_uring_detected: false,
        }
    }

    /// Write an event, incrementing the drop counter on failure.
    fn try_write(&mut self, event: OaieEvent) {
        if self.writer.write_event(event).is_err() {
            self.dropped_events += 1;
        }
    }

    /// Main trace loop. Runs until all traced processes exit.
    ///
    /// Returns `(exit_code, writer, io_uring_detected)`. The `io_uring_detected`
    /// flag is true if `io_uring_setup` was observed — indicating the trace
    /// has blind spots (io_uring operations are invisible to ptrace).
    pub fn run(mut self) -> Result<(i32, ChunkedEventWriter, bool), TracerError> {
        // Wait for the initial SIGSTOP from the child (raised after traceme).
        match waitpid(self.root_pid, Some(WaitPidFlag::__WALL)) {
            Ok(WaitStatus::Stopped(_, Signal::SIGSTOP)) => {}
            Ok(WaitStatus::Stopped(_, Signal::SIGTRAP)) => {}
            Ok(other) => {
                return Err(TracerError::Unexpected(format!(
                    "expected initial SIGSTOP, got {other:?}"
                )));
            }
            Err(e) => return Err(TracerError::Nix(e)),
        }

        // Set ptrace options on the root process.
        self.setup_ptrace_options(self.root_pid)?;

        // Resume the child to the next syscall stop.
        ptrace::syscall(self.root_pid, None).map_err(TracerError::Nix)?;

        let mut last_exit_code = 0;

        // Block SIGCHLD in this thread and create a signalfd for it.
        // This replaces the 100us busy-wait: instead of spinning, we
        // poll() on the signalfd and wake only when a child event occurs.
        // Falls back to 100us sleep if signalfd setup fails.
        let sigchld_fd = setup_signalfd();

        // Use per-PID waitpid with WNOHANG to avoid stealing exit statuses
        // of unrelated child processes (critical for correctness when multiple
        // tracers or tests run concurrently in the same process).
        loop {
            let pids: Vec<i32> = self.traced_pids.iter().copied().collect();
            let mut got_event = false;

            for &raw_pid in &pids {
                let pid = Pid::from_raw(raw_pid);
                let status = match waitpid(pid, Some(WaitPidFlag::__WALL | WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::StillAlive) => continue,
                    Ok(status) => status,
                    Err(nix::errno::Errno::ECHILD) => {
                        self.traced_pids.remove(&raw_pid);
                        continue;
                    }
                    Err(e) => {
                        // Clean up signalfd before returning to prevent fd leak
                        // and ensure SIGCHLD is unblocked for this thread.
                        cleanup_signalfd(sigchld_fd);
                        return Err(TracerError::Nix(e));
                    }
                };

                got_event = true;
                match status {
                    WaitStatus::PtraceSyscall(pid) => {
                        self.handle_syscall(pid);
                        // Resume to the next syscall stop.
                        if let Err(nix::errno::Errno::ESRCH) = ptrace::syscall(pid, None) {
                            self.traced_pids.remove(&pid.as_raw());
                        }
                    }
                    WaitStatus::PtraceEvent(pid, _signal, event) => {
                        self.handle_ptrace_event(pid, event);
                        if let Err(nix::errno::Errno::ESRCH) = ptrace::syscall(pid, None) {
                            self.traced_pids.remove(&pid.as_raw());
                        }
                    }
                    WaitStatus::Exited(pid, code) => {
                        self.handle_exit(pid, code, None);
                        self.traced_pids.remove(&pid.as_raw());
                        if pid == self.root_pid {
                            last_exit_code = code;
                        }
                    }
                    WaitStatus::Signaled(pid, signal, _core) => {
                        let code = 128 + signal as i32;
                        self.handle_exit(pid, code, Some(signal as i32));
                        self.traced_pids.remove(&pid.as_raw());
                        if pid == self.root_pid {
                            last_exit_code = code;
                        }
                    }
                    WaitStatus::Stopped(pid, signal) => {
                        if signal == Signal::SIGSTOP
                            && !self.traced_pids.contains(&pid.as_raw())
                        {
                            self.traced_pids.insert(pid.as_raw());
                            let _ = self.setup_ptrace_options(pid);
                            if let Err(nix::errno::Errno::ESRCH) = ptrace::syscall(pid, None) {
                                self.traced_pids.remove(&pid.as_raw());
                            }
                        } else {
                            // Deliver the signal to the process.
                            if let Err(nix::errno::Errno::ESRCH) =
                                ptrace::syscall(pid, Some(signal))
                            {
                                self.traced_pids.remove(&pid.as_raw());
                            }
                        }
                    }
                    _ => {}
                }
            }

            if self.traced_pids.is_empty() {
                break;
            }

            // Check deadline — kill all traced processes if timeout exceeded.
            if let Some(deadline) = self.deadline {
                if Instant::now() >= deadline {
                    let pids_to_kill: Vec<i32> = self.traced_pids.iter().copied().collect();
                    for &raw_pid in &pids_to_kill {
                        let _ = nix::sys::signal::kill(Pid::from_raw(raw_pid), Signal::SIGKILL);
                    }
                    // Reap all killed processes and emit ProcessExit events.
                    for &raw_pid in &pids_to_kill {
                        let pid = Pid::from_raw(raw_pid);
                        let code = match waitpid(pid, None) {
                            Ok(WaitStatus::Exited(_, c)) => c,
                            Ok(WaitStatus::Signaled(_, sig, _)) => 128 + sig as i32,
                            _ => -1,
                        };
                        self.handle_exit(pid, code, Some(libc::SIGKILL));
                        if pid == self.root_pid {
                            last_exit_code = code;
                        }
                    }
                    self.traced_pids.clear();
                    break;
                }
            }

            if !got_event {
                // Wait for SIGCHLD via signalfd+poll instead of busy-waiting.
                // Timeout: min(100ms, deadline_remaining) so we still check
                // the deadline even if no child event fires.
                let timeout_ms = if let Some(deadline) = self.deadline {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    // Clamp to [1, 100] to avoid busy-polling on sub-ms remainders.
                    remaining.as_millis().clamp(1, 100) as libc::c_int
                } else {
                    100 // 100ms default poll timeout
                };
                wait_for_sigchld(sigchld_fd, timeout_ms);
            }
        }

        // Clean up signalfd and unblock SIGCHLD on this thread.
        cleanup_signalfd(sigchld_fd);

        Ok((last_exit_code, self.writer, self.io_uring_detected))
    }

    /// Set ptrace options: follow forks/clones, mark syscalls, kill on tracer death.
    fn setup_ptrace_options(&self, pid: Pid) -> Result<(), TracerError> {
        ptrace::setoptions(
            pid,
            ptrace::Options::PTRACE_O_TRACESYSGOOD
                | ptrace::Options::PTRACE_O_TRACEFORK
                | ptrace::Options::PTRACE_O_TRACEVFORK
                | ptrace::Options::PTRACE_O_TRACECLONE
                | ptrace::Options::PTRACE_O_TRACEEXEC
                | ptrace::Options::PTRACE_O_EXITKILL,
        )
        .map_err(TracerError::Nix)
    }

    /// Nanoseconds elapsed since tracer creation.
    fn elapsed_ns(&self) -> u64 {
        self.start.elapsed().as_nanos() as u64
    }

    /// Look up parent PID for a traced process.
    fn get_ppid(&self, pid: Pid) -> u32 {
        self.parent_map
            .get(&pid.as_raw())
            .copied()
            .unwrap_or(0) as u32
    }

    /// Number of events that failed to write during the trace.
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    /// Handle a syscall stop (entry or exit) for a traced PID.
    fn handle_syscall(&mut self, pid: Pid) {
        let sregs = match get_regs(pid) {
            Ok(r) => r,
            Err(nix::errno::Errno::ESRCH) => {
                // Process already gone before we could read registers.
                oaie_core::log_debug!("PID {} gone before register read", pid);
                return;
            }
            Err(e) => {
                oaie_core::log_debug!("getregs failed for PID {}: {e}", pid);
                // Flip the entry/exit state so we don't permanently desync.
                // Without this, all subsequent syscalls for this PID would have
                // swapped entry/exit handling.
                if let Some(state) = self.syscall_states.get_mut(&pid.as_raw()) {
                    state.in_entry = !state.in_entry;
                }
                return;
            }
        };

        let state = self
            .syscall_states
            .entry(pid.as_raw())
            .or_insert(SyscallState {
                in_entry: true,
                syscall_nr: 0,
                args: [0; 6],
            });

        if state.in_entry {
            // Syscall entry: capture number and arguments.
            state.syscall_nr = sregs.syscall_nr;
            state.args = sregs.args;
            state.in_entry = false;

            // Handle argument reading for interesting syscalls at entry
            // (before the kernel modifies them).
            let nr = state.syscall_nr;
            let args = state.args;
            // Allow unreachable_patterns: on aarch64, SYS_OPEN/SYS_STAT/SYS_LSTAT
            // are u64::MAX sentinels (those syscalls don't exist), so their arms
            // are unreachable — but keeping them makes x86_64 behavior explicit.
            #[allow(unreachable_patterns)]
            match nr {
                SYS_OPENAT => self.on_openat_entry(pid, &args),
                // Legacy open(pathname, flags, mode) — x86_64 only (u64::MAX on aarch64/rv64gc).
                SYS_OPEN => self.on_open_entry(pid, &args),
                SYS_EXECVE => self.on_execve_entry(pid, &args),
                SYS_CONNECT => self.on_connect_entry(pid, &args),
                // statx/newfstatat: pathname at args[1].
                SYS_STATX | SYS_NEWFSTATAT => self.on_statx_entry(pid, &args),
                // Legacy stat/lstat — x86_64 only (u64::MAX on aarch64/rv64gc).
                SYS_STAT | SYS_LSTAT => self.on_stat_entry(pid, &args),
                SYS_SENDTO => self.on_sendto_entry(pid, &args),
                SYS_SOCKET => self.check_dangerous_socket(pid, &args),
                SYS_PRCTL => self.check_prctl_subcmds(pid, &args),
                _ => {}
            }

            // Security-relevant syscalls get flagged immediately.
            if is_security_relevant(nr) {
                self.on_security_relevant(pid, nr, &args);
            }
        } else {
            // Syscall exit: capture return value.
            let ret = sregs.ret_val;
            let nr = state.syscall_nr;
            state.in_entry = true;

            #[allow(unreachable_patterns)]
            match nr {
                SYS_OPENAT | SYS_OPEN => self.on_openat_exit(pid, ret),
                SYS_CONNECT => self.on_connect_exit(pid, ret),
                SYS_SENDTO => self.on_sendto_exit(pid, ret),
                SYS_STATX | SYS_NEWFSTATAT | SYS_STAT | SYS_LSTAT => self.on_statx_exit(pid, ret),
                _ => {}
            }
        }
    }

    // ── Syscall entry handlers ──

    fn on_openat_entry(&mut self, pid: Pid, args: &[u64; 6]) {
        // openat(dirfd, pathname, flags, mode)
        let path = memory::read_string(pid, args[1], 4096);
        let flags = args[2] as u32;
        self.pending_opens
            .insert(pid.as_raw(), PendingOpen { path, flags });
    }

    fn on_open_entry(&mut self, pid: Pid, args: &[u64; 6]) {
        // Legacy open(pathname, flags, mode) — x86_64 only.
        let path = memory::read_string(pid, args[0], 4096);
        let flags = args[1] as u32;
        self.pending_opens
            .insert(pid.as_raw(), PendingOpen { path, flags });
    }

    fn on_openat_exit(&mut self, pid: Pid, ret: i64) {
        if let Some(pending) = self.pending_opens.remove(&pid.as_raw()) {
            let result = if ret >= 0 { 0 } else { (-ret) as i32 };
            self.try_write(OaieEvent {
                ts_ns: self.elapsed_ns(),
                event_type: EventType::FileOpen,
                pid: pid.as_raw() as u32,
                ppid: None,
                detail: EventDetail::FileAccess {
                    path: pending.path,
                    flags: pending.flags,
                    result,
                },
                hash_prev: String::new(),
            });
        }
    }

    fn on_execve_entry(&mut self, pid: Pid, args: &[u64; 6]) {
        // execve(filename, argv, envp) — read args at entry (before kernel
        // overwrites the address space), but defer the event until
        // PTRACE_EVENT_EXEC confirms the execve succeeded.
        let filename = memory::read_string(pid, args[0], 4096);
        let argv = memory::read_string_array(pid, args[1], 32);
        self.pending_execs.insert(
            pid.as_raw(),
            PendingExec { filename, argv },
        );
    }

    fn on_connect_entry(&mut self, pid: Pid, args: &[u64; 6]) {
        // connect(sockfd, addr, addrlen)
        let addr_info = memory::read_sockaddr(pid, args[1], args[2] as usize);
        self.pending_connects
            .insert(pid.as_raw(), PendingConnect { addr_info });
    }

    fn on_connect_exit(&mut self, pid: Pid, ret: i64) {
        if let Some(pending) = self.pending_connects.remove(&pid.as_raw()) {
            // EINPROGRESS (115) is returned for non-blocking sockets and means
            // the connection is in progress, not failed. Treat it as success.
            let result = if ret == 0 || ret == -115 { 0 } else { (-ret) as i32 };
            self.try_write(OaieEvent {
                ts_ns: self.elapsed_ns(),
                event_type: EventType::NetConnect,
                pid: pid.as_raw() as u32,
                ppid: None,
                detail: EventDetail::NetConnect {
                    family: pending.addr_info.family,
                    address: pending.addr_info.display,
                    result,
                },
                hash_prev: String::new(),
            });
        }
    }

    fn on_sendto_entry(&mut self, pid: Pid, args: &[u64; 6]) {
        // sendto(sockfd, buf, len, flags, dest_addr, addrlen)
        // Only interested in UDP sends to port 53 (DNS queries).
        let dest_addr_ptr = args[4];
        let addrlen = args[5] as usize;
        if dest_addr_ptr == 0 || addrlen == 0 {
            return; // No destination address (connected socket sendto).
        }

        let addr_info = memory::read_sockaddr(pid, dest_addr_ptr, addrlen);

        // Check if this is a send to port 53 (DNS).
        let is_dns = (addr_info.family == "AF_INET" || addr_info.family == "AF_INET6")
            && addr_info.display.ends_with(":53");

        if !is_dns {
            return;
        }

        // Read the DNS payload and parse the query name.
        let buf_ptr = args[1];
        let buf_len = args[2] as usize;
        let payload = memory::read_bytes(pid, buf_ptr, buf_len.min(512));

        if let Some(name) = memory::parse_dns_query_name(&payload) {
            self.pending_sendtos.insert(
                pid.as_raw(),
                PendingSendto {
                    dns_name: name,
                    server: addr_info.display,
                },
            );
        }
    }

    fn on_sendto_exit(&mut self, pid: Pid, ret: i64) {
        if let Some(pending) = self.pending_sendtos.remove(&pid.as_raw()) {
            let result = if ret >= 0 { 0 } else { (-ret) as i32 };
            self.try_write(OaieEvent {
                ts_ns: self.elapsed_ns(),
                event_type: EventType::DnsQuery,
                pid: pid.as_raw() as u32,
                ppid: None,
                detail: EventDetail::DnsQuery {
                    name: pending.dns_name,
                    server: pending.server,
                    result,
                },
                hash_prev: String::new(),
            });
        }
    }

    fn on_statx_entry(&mut self, pid: Pid, args: &[u64; 6]) {
        // statx(dirfd, pathname, flags, mask, statxbuf)
        let path = memory::read_string(pid, args[1], 4096);
        self.pending_statxs
            .insert(pid.as_raw(), PendingStatx { path });
    }

    fn on_stat_entry(&mut self, pid: Pid, args: &[u64; 6]) {
        // Legacy stat/lstat(pathname, statbuf) — x86_64 only.
        let path = memory::read_string(pid, args[0], 4096);
        self.pending_statxs
            .insert(pid.as_raw(), PendingStatx { path });
    }

    fn on_statx_exit(&mut self, pid: Pid, ret: i64) {
        if let Some(pending) = self.pending_statxs.remove(&pid.as_raw()) {
            let result = if ret == 0 { 0 } else { (-ret) as i32 };
            self.try_write(OaieEvent {
                ts_ns: self.elapsed_ns(),
                event_type: EventType::FileStat,
                pid: pid.as_raw() as u32,
                ppid: None,
                detail: EventDetail::FileStat {
                    path: pending.path,
                    result,
                },
                hash_prev: String::new(),
            });
        }
    }

    // ── Security-relevant syscall handling ──

    fn on_security_relevant(&mut self, pid: Pid, nr: u64, args: &[u64; 6]) {
        let name = syscall_name(nr);

        // io_uring detection: kill the process because all I/O through the
        // submission queue is invisible to ptrace, creating blind spots.
        // The seccomp layer also blocks this syscall, but if it somehow gets
        // through, killing here is the defense-in-depth backstop.
        if nr == SYS_IO_URING_SETUP {
            self.io_uring_detected = true;
            let _ = nix::sys::signal::kill(pid, Signal::SIGKILL);
        }

        // Fileless exec detection: memfd_create → execveat(AT_EMPTY_PATH).
        if nr == SYS_MEMFD_CREATE {
            self.memfd_pids.insert(pid.as_raw());
        }
        if nr == SYS_EXECVEAT {
            let flags = args[4] as u32;
            let is_empty_path = flags & libc::AT_EMPTY_PATH as u32 != 0;
            if is_empty_path && self.memfd_pids.contains(&pid.as_raw()) {
                self.try_write(OaieEvent {
                    ts_ns: self.elapsed_ns(),
                    event_type: EventType::SecurityRelevant,
                    pid: pid.as_raw() as u32,
                    ppid: Some(self.get_ppid(pid)),
                    detail: EventDetail::SecurityRelevant {
                        syscall: "fileless_exec_detected".into(),
                        syscall_nr: nr,
                    },
                    hash_prev: String::new(),
                });
            }
        }

        // Nested namespace detection: unshare(CLONE_NEWUSER).
        if nr == SYS_UNSHARE {
            let flags = args[0];
            if flags & libc::CLONE_NEWUSER as u64 != 0 {
                self.try_write(OaieEvent {
                    ts_ns: self.elapsed_ns(),
                    event_type: EventType::SecurityRelevant,
                    pid: pid.as_raw() as u32,
                    ppid: Some(self.get_ppid(pid)),
                    detail: EventDetail::SecurityRelevant {
                        syscall: "nested_userns_attempt".into(),
                        syscall_nr: nr,
                    },
                    hash_prev: String::new(),
                });
                return; // Don't also emit the generic unshare event.
            }
        }

        // clone(CLONE_NEWUSER) — same as unshare but via clone.
        // Regular clone() calls (thread creation, fork) are not security-relevant
        // and would produce excessive event noise, so we return early for all
        // SYS_CLONE calls — only emitting an event if CLONE_NEWUSER is set.
        if nr == SYS_CLONE {
            let flags = args[0];
            if flags & libc::CLONE_NEWUSER as u64 != 0 {
                self.try_write(OaieEvent {
                    ts_ns: self.elapsed_ns(),
                    event_type: EventType::SecurityRelevant,
                    pid: pid.as_raw() as u32,
                    ppid: Some(self.get_ppid(pid)),
                    detail: EventDetail::SecurityRelevant {
                        syscall: "nested_userns_via_clone".into(),
                        syscall_nr: nr,
                    },
                    hash_prev: String::new(),
                });
            }
            // Always return — normal clone/fork/thread creation is not
            // security-relevant and should not emit a generic event.
            return;
        }

        // clone3(CLONE_NEWUSER or CLONE_INTO_CGROUP) — read flags from clone_args struct.
        if nr == SYS_CLONE3 {
            let clone_args_ptr = args[0];
            if let Ok(flags_word) = ptrace::read(pid, clone_args_ptr as *mut _) {
                let flags = flags_word as u64;
                const CLONE_INTO_CGROUP: u64 = 0x200000000;
                if flags & CLONE_INTO_CGROUP != 0 {
                    self.try_write(OaieEvent {
                        ts_ns: self.elapsed_ns(),
                        event_type: EventType::SecurityRelevant,
                        pid: pid.as_raw() as u32,
                        ppid: Some(self.get_ppid(pid)),
                        detail: EventDetail::SecurityRelevant {
                            syscall: "clone3_into_cgroup".into(),
                            syscall_nr: nr,
                        },
                        hash_prev: String::new(),
                    });
                }
                if flags & libc::CLONE_NEWUSER as u64 != 0 {
                    self.try_write(OaieEvent {
                        ts_ns: self.elapsed_ns(),
                        event_type: EventType::SecurityRelevant,
                        pid: pid.as_raw() as u32,
                        ppid: Some(self.get_ppid(pid)),
                        detail: EventDetail::SecurityRelevant {
                            syscall: "nested_userns_via_clone3".into(),
                            syscall_nr: nr,
                        },
                        hash_prev: String::new(),
                    });
                }
                // Don't return — still emit the generic clone3 event if it was
                // flagged for other reasons.
            }
        }

        // ── Enriched security detections ──

        // ptrace(PTRACE_TRACEME) — anti-debugging / tracer interference.
        if nr == SYS_PTRACE && args[0] == 0 {
            self.try_write(OaieEvent {
                ts_ns: self.elapsed_ns(),
                event_type: EventType::SecurityRelevant,
                pid: pid.as_raw() as u32,
                ppid: Some(self.get_ppid(pid)),
                detail: EventDetail::SecurityRelevant {
                    syscall: "ptrace_traceme".into(),
                    syscall_nr: nr,
                },
                hash_prev: String::new(),
            });
        }

        // userfaultfd: check UFFD_USER_MODE_ONLY (bit 1). Without it, kernel
        // page faults can be handled — the dangerous mode for kernel exploits.
        if nr == SYS_USERFAULTFD {
            const UFFD_USER_MODE_ONLY: u64 = 1;
            let severity = if args[0] & UFFD_USER_MODE_ONLY == 0 {
                "userfaultfd_kernel_mode"
            } else {
                "userfaultfd_user_mode"
            };
            self.try_write(OaieEvent {
                ts_ns: self.elapsed_ns(),
                event_type: EventType::SecurityRelevant,
                pid: pid.as_raw() as u32,
                ppid: Some(self.get_ppid(pid)),
                detail: EventDetail::SecurityRelevant {
                    syscall: severity.into(),
                    syscall_nr: nr,
                },
                hash_prev: String::new(),
            });
            return; // Don't also emit the generic event (would duplicate).
        }

        // process_vm_readv/writev: emit target PID from arg0.
        if nr == SYS_PROCESS_VM_READV || nr == SYS_PROCESS_VM_WRITEV {
            let target_pid = args[0] as u32;
            let op = if nr == SYS_PROCESS_VM_READV {
                "process_vm_readv"
            } else {
                "process_vm_writev"
            };
            self.try_write(OaieEvent {
                ts_ns: self.elapsed_ns(),
                event_type: EventType::SecurityRelevant,
                pid: pid.as_raw() as u32,
                ppid: Some(self.get_ppid(pid)),
                detail: EventDetail::SecurityRelevant {
                    syscall: format!("{op}_target_pid_{target_pid}"),
                    syscall_nr: nr,
                },
                hash_prev: String::new(),
            });
            return; // Don't also emit the generic event (would duplicate).
        }

        // vmsplice(fd, iov, nr_segs, flags): check SPLICE_F_GIFT (bit 3, value 8) — Dirty Pipe class.
        if nr == SYS_VMSPLICE {
            const SPLICE_F_GIFT: u64 = 8;
            if args[3] & SPLICE_F_GIFT != 0 {
                self.try_write(OaieEvent {
                    ts_ns: self.elapsed_ns(),
                    event_type: EventType::SecurityRelevant,
                    pid: pid.as_raw() as u32,
                    ppid: Some(self.get_ppid(pid)),
                    detail: EventDetail::SecurityRelevant {
                        syscall: "vmsplice_splice_f_gift".into(),
                        syscall_nr: nr,
                    },
                    hash_prev: String::new(),
                });
                return; // Don't also emit the generic event (would duplicate).
            }
            // Non-GIFT vmsplice falls through to the generic event below.
        }

        // pidfd_send_signal: read signal number from arg1.
        if nr == SYS_PIDFD_SEND_SIGNAL {
            let signal = args[1] as u32;
            self.try_write(OaieEvent {
                ts_ns: self.elapsed_ns(),
                event_type: EventType::SecurityRelevant,
                pid: pid.as_raw() as u32,
                ppid: Some(self.get_ppid(pid)),
                detail: EventDetail::SecurityRelevant {
                    syscall: format!("pidfd_send_signal_{signal}"),
                    syscall_nr: nr,
                },
                hash_prev: String::new(),
            });
            return; // Don't also emit the generic event (would duplicate).
        }

        // kcmp: read target PID (arg0) and resource type (arg2).
        if nr == SYS_KCMP {
            let target_pid = args[0] as u32;
            let resource_type = args[2] as u32;
            self.try_write(OaieEvent {
                ts_ns: self.elapsed_ns(),
                event_type: EventType::SecurityRelevant,
                pid: pid.as_raw() as u32,
                ppid: Some(self.get_ppid(pid)),
                detail: EventDetail::SecurityRelevant {
                    syscall: format!("kcmp_target_{target_pid}_type_{resource_type}"),
                    syscall_nr: nr,
                },
                hash_prev: String::new(),
            });
            return; // Don't also emit the generic event (would duplicate).
        }

        // Emit generic security-relevant event (only for syscalls not already
        // handled by the enriched detections above).
        self.try_write(OaieEvent {
            ts_ns: self.elapsed_ns(),
            event_type: EventType::SecurityRelevant,
            pid: pid.as_raw() as u32,
            ppid: Some(self.get_ppid(pid)),
            detail: EventDetail::SecurityRelevant {
                syscall: name.into(),
                syscall_nr: nr,
            },
            hash_prev: String::new(),
        });
    }

    /// Check for suspicious prctl subcommands.
    fn check_prctl_subcmds(&mut self, pid: Pid, args: &[u64; 6]) {
        let option = args[0] as i32;
        let syscall_label = match option {
            // PR_SET_PDEATHSIG with signal 0 — harmless (disable parent death signal).
            0 => None,
            // PR_SET_SECCOMP (22) — alternative seccomp installation path.
            22 => Some("seccomp"),
            // PR_SET_MM (35) — modify process memory map metadata.
            35 => Some("prctl_set_mm"),
            // PR_SET_CHILD_SUBREAPER (36) — intercept orphaned descendants.
            36 => Some("prctl_set_child_subreaper"),
            // PR_SET_TIMERSLACK (29) with value 0 — max timer resolution.
            29 => {
                if args[1] == 0 {
                    Some("prctl_set_timerslack_zero")
                } else {
                    None
                }
            }
            // PR_CAP_AMBIENT (47) — ambient capability manipulation.
            // arg2=2 (PR_CAP_AMBIENT_RAISE) is the dangerous subcommand.
            47 => {
                if args[1] == 2 {
                    Some("prctl_cap_ambient_raise")
                } else {
                    None
                }
            }
            // PR_SET_SPECULATION_CTRL (53) with PR_SPEC_ENABLE (1).
            53 => {
                if args[2] == 1 {
                    // PR_SPEC_ENABLE
                    Some(if args[1] == 0 {
                        "prctl_enable_speculation_ssb"
                    } else {
                        "prctl_enable_speculation_indirect_branch"
                    })
                } else {
                    None
                }
            }
            _ => None,
        };

        // PR_SET_PTRACER (0x59616d61) — Yama ptracer override.
        let label = if option == 0x59616d61u32 as i32 {
            Some("prctl_set_ptracer")
        } else {
            syscall_label
        };

        if let Some(name) = label {
            self.try_write(OaieEvent {
                ts_ns: self.elapsed_ns(),
                event_type: EventType::SecurityRelevant,
                pid: pid.as_raw() as u32,
                ppid: Some(self.get_ppid(pid)),
                detail: EventDetail::SecurityRelevant {
                    syscall: name.into(),
                    syscall_nr: SYS_PRCTL,
                },
                hash_prev: String::new(),
            });
        }
    }

    /// Check for dangerous socket types (AF_PACKET, AF_VSOCK, etc.).
    fn check_dangerous_socket(&mut self, pid: Pid, args: &[u64; 6]) {
        let domain = args[0] as i32;
        let sock_type = args[1] as i32;

        const AF_PACKET: i32 = 17;
        const AF_BLUETOOTH: i32 = 31;
        const AF_ALG: i32 = 38;
        const AF_VSOCK: i32 = 40;
        const AF_XDP: i32 = 44;
        const SOCK_RAW: i32 = 3;

        let warning = match domain {
            AF_VSOCK => Some("socket_af_vsock"),
            AF_BLUETOOTH => Some("socket_af_bluetooth"),
            AF_ALG => Some("socket_af_alg"),
            AF_XDP => Some("socket_af_xdp"),
            AF_PACKET => Some("socket_af_packet"),
            // Mask off SOCK_NONBLOCK/SOCK_CLOEXEC flags to get the base type.
            _ if (sock_type & 0xF) == SOCK_RAW => Some("socket_sock_raw"),
            _ => None,
        };

        if let Some(name) = warning {
            self.try_write(OaieEvent {
                ts_ns: self.elapsed_ns(),
                event_type: EventType::SecurityRelevant,
                pid: pid.as_raw() as u32,
                ppid: Some(self.get_ppid(pid)),
                detail: EventDetail::SecurityRelevant {
                    syscall: name.into(),
                    syscall_nr: SYS_SOCKET,
                },
                hash_prev: String::new(),
            });
        }
    }

    // ── Fork/clone/exec event handling ──

    /// Handle PTRACE_EVENT_FORK/VFORK/CLONE/EXEC.
    fn handle_ptrace_event(&mut self, pid: Pid, event: i32) {
        match event {
            // PTRACE_EVENT_FORK (1), PTRACE_EVENT_VFORK (2), PTRACE_EVENT_CLONE (3)
            1..=3 => {
                // Get the new child PID.
                if let Ok(new_pid_raw) = ptrace::getevent(pid) {
                    // Validate the PID fits in i32 (kernel default pid_max is 2^22,
                    // but configurable up to 2^22 on 64-bit — safely within i32).
                    if new_pid_raw < 0 || new_pid_raw > i32::MAX as i64 {
                        eprintln!(
                            "oaie: ptrace getevent returned out-of-range PID: {new_pid_raw}"
                        );
                        return;
                    }
                    let new_pid = new_pid_raw as i32;
                    self.traced_pids.insert(new_pid);
                    self.parent_map.insert(new_pid, pid.as_raw());
                    self.syscall_states.insert(
                        new_pid,
                        SyscallState {
                            in_entry: true,
                            syscall_nr: 0,
                            args: [0; 6],
                        },
                    );
                }
            }
            // PTRACE_EVENT_EXEC (4) — process called execve successfully.
            // Emit the ProcessExec event now that we know it succeeded.
            4 => {
                let raw = pid.as_raw();
                let ppid = self.get_ppid(pid);
                // When a non-leader thread calls execve, the kernel rewrites its
                // TID to the thread-group leader's PID. Try the reported PID first,
                // then fall back to searching all pending_execs entries for this
                // process's children.
                let pending_opt = self.pending_execs.remove(&raw).or_else(|| {
                    // The TID was rewritten to the thread-group leader's PID.
                    // Find the pending exec from a thread in the same group by
                    // matching ppid, instead of picking an arbitrary entry.
                    let target_ppid = ppid as i32;
                    let key = self.pending_execs.keys().copied().find(|&k| {
                        self.parent_map.get(&k).copied().unwrap_or(-1) == target_ppid
                    }).or_else(|| {
                        // Last resort: any pending exec (preserves old behavior).
                        self.pending_execs.keys().copied().next()
                    });
                    key.and_then(|k| self.pending_execs.remove(&k))
                });
                if let Some(pending) = pending_opt {
                    self.try_write(OaieEvent {
                        ts_ns: self.elapsed_ns(),
                        event_type: EventType::ProcessExec,
                        pid: raw as u32,
                        ppid: Some(ppid),
                        detail: EventDetail::Exec {
                            filename: pending.filename,
                            argv: pending.argv,
                        },
                        hash_prev: String::new(),
                    });
                }
            }
            _ => {}
        }
    }

    /// Handle process exit (either normal exit or signal death).
    fn handle_exit(&mut self, pid: Pid, code: i32, signal: Option<i32>) {
        let ppid = self.get_ppid(pid);

        self.try_write(OaieEvent {
            ts_ns: self.elapsed_ns(),
            event_type: EventType::ProcessExit,
            pid: pid.as_raw() as u32,
            ppid: Some(ppid),
            detail: EventDetail::Exit {
                exit_code: code,
                signal,
            },
            hash_prev: String::new(),
        });

        // Clean up per-PID state.
        let raw = pid.as_raw();
        self.syscall_states.remove(&raw);
        self.parent_map.remove(&raw);
        self.pending_opens.remove(&raw);
        self.pending_statxs.remove(&raw);
        self.pending_connects.remove(&raw);
        self.pending_execs.remove(&raw);
        self.pending_sendtos.remove(&raw);
        self.memfd_pids.remove(&raw);
    }
}

/// Called in the child process before exec to enable tracing.
///
/// Tells the kernel "my parent wants to trace me", then raises SIGSTOP
/// so the parent can set ptrace options before the child execs.
pub fn child_traceme() -> Result<(), nix::errno::Errno> {
    ptrace::traceme()?;
    nix::sys::signal::raise(Signal::SIGSTOP)?;
    Ok(())
}

/// Errors that can occur during tracing.
#[derive(Debug)]
pub enum TracerError {
    /// A nix/ptrace/waitpid error.
    Nix(nix::errno::Errno),
    /// An unexpected state in the trace loop.
    Unexpected(String),
    /// An I/O error (e.g. writing events).
    Io(std::io::Error),
}

impl std::fmt::Display for TracerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TracerError::Nix(e) => write!(f, "ptrace error: {e}"),
            TracerError::Unexpected(msg) => write!(f, "unexpected tracer state: {msg}"),
            TracerError::Io(e) => write!(f, "tracer I/O error: {e}"),
        }
    }
}

impl std::error::Error for TracerError {}

impl From<std::io::Error> for TracerError {
    fn from(e: std::io::Error) -> Self {
        TracerError::Io(e)
    }
}
