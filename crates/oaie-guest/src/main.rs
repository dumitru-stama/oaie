//! oaie-guest: init process (PID 1) for the Firecracker microVM.
//!
//! This binary runs as the VM's init process. Boot sequence:
//! 1. Mount /proc, /dev, /tmp, /in (if /dev/vdb present), /out (/dev/vdc or tmpfs)
//! 2. Connect to host via AF_VSOCK (CID=2, port=1024)
//! 3. Send AgentReady
//! 4. Receive RunJob, fork+exec tool with captured stdout/stderr
//! 5. Stream OutputChunk messages for stdout/stderr
//! 6. Send JobDone with exit code
//! 7. Receive Shutdown, halt VM
//!
//! Security measures applied before exec'ing the tool:
//! - Seccomp BPF filter blocking AF_VSOCK socket creation (EACCES)
//! - /dev/vsock removed from filesystem (defense in depth)
//! - RLIMIT_FSIZE (1 GiB) and RLIMIT_NPROC (64) set
//! - Dangerous environment variables filtered (LD_*, BASH_ENV, etc.)
//! - stdout/stderr capped at 64 MiB to prevent memory exhaustion
//!
//! Built as a static musl binary: `cargo build -p oaie-guest --target x86_64-unknown-linux-musl --release`

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// We reuse the wire protocol types directly via serde_json, to keep
// the guest binary minimal. Same framing as oaie-firecracker/src/wire.rs.

/// Maximum frame size: 16 MiB.
const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

/// Chunk size for streaming output (64 KiB).
const OUTPUT_CHUNK_SIZE: usize = 64 * 1024;

/// AF_VSOCK address family constant.
const AF_VSOCK: i32 = 40;

/// Host CID for vsock connections.
const HOST_CID: u32 = 2;

/// Port the host listens on.
const HOST_PORT: u32 = 1024;

fn main() {
    // We're PID 1 — no panic handler, just print and halt on error.
    if let Err(e) = run() {
        eprintln!("oaie-guest: fatal: {e}");
        // As init, we need to halt the machine.
        unsafe {
            libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
        }
    }
}

fn run() -> io::Result<()> {
    eprintln!("oaie-guest: starting (PID {})", std::process::id());

    // Mount essential filesystems.
    mount_filesystems()?;

    // SECURITY: harden PID 1 against FD theft from the (later) child.
    // PR_SET_DUMPABLE=0 blocks ptrace/pidfd_getfd from same-UID processes;
    // combined with the UID drop in pre_exec (which removes CAP_SYS_PTRACE),
    // this prevents the tool from stealing the connected vsock FD.
    // chmod/chown so the dropped-UID tool can still write its work dirs.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        libc::chmod(c"/tmp".as_ptr(), 0o1777);
        libc::chown(c"/out".as_ptr(), 65534, 65534);
    }

    // Connect to host via vsock.
    let mut stream = vsock_connect(HOST_CID, HOST_PORT)?;
    eprintln!("oaie-guest: connected to host via vsock");

    // Send AgentReady.
    send_message(
        &mut stream,
        &serde_json::json!({
            "type": "agent_ready",
            "version": env!("CARGO_PKG_VERSION"),
        }),
    )?;

    // Main loop: receive commands.
    let mut job_completed = false;
    loop {
        let msg = match recv_message(&mut stream)? {
            Some(msg) => msg,
            None => {
                eprintln!("oaie-guest: host disconnected");
                break;
            }
        };

        let msg_type = msg
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        match msg_type {
            "run_job" => {
                if job_completed {
                    // Only one job per VM lifetime — reject subsequent jobs.
                    send_message(
                        &mut stream,
                        &serde_json::json!({
                            "type": "error",
                            "message": "only one job per VM instance is allowed",
                        }),
                    )?;
                    continue;
                }
                handle_run_job(&mut stream, &msg)?;
                job_completed = true;
            }
            "shutdown" => {
                eprintln!("oaie-guest: shutdown requested");
                break;
            }
            other => {
                eprintln!("oaie-guest: unknown message type: {other}");
                send_message(
                    &mut stream,
                    &serde_json::json!({
                        "type": "error",
                        "message": format!("unknown message type: {other}"),
                    }),
                )?;
            }
        }
    }

    // Halt the VM.
    eprintln!("oaie-guest: halting");
    unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
    }

    Ok(())
}

/// Mount essential filesystems for the VM environment.
fn mount_filesystems() -> io::Result<()> {
    use std::ffi::CString;

    let mounts: &[(&str, &str, &str, u64)] = &[
        ("/proc", "proc", "proc", 0),
        ("/dev", "devtmpfs", "devtmpfs", 0),
        ("/tmp", "tmpfs", "tmpfs", 0),
        // SECURITY: mount /sys read-only — writable sysfs is not needed
        // inside the VM and could allow kernel parameter manipulation.
        ("/sys", "sysfs", "sysfs", libc::MS_RDONLY),
    ];

    for (target, fstype, source, flags) in mounts {
        // Ensure mount point exists.
        let _ = std::fs::create_dir_all(target);

        let c_source = CString::new(*source).unwrap();
        let c_target = CString::new(*target).unwrap();
        let c_fstype = CString::new(*fstype).unwrap();

        let ret = unsafe {
            libc::mount(
                c_source.as_ptr(),
                c_target.as_ptr(),
                c_fstype.as_ptr(),
                *flags,
                std::ptr::null(),
            )
        };

        if ret != 0 {
            let err = io::Error::last_os_error();
            // Don't fail on already-mounted.
            if err.raw_os_error() != Some(libc::EBUSY) {
                return Err(io::Error::other(format!("mount {target} failed: {err}")));
            }
        }
    }

    // Mount /dev/vdb as /in if the device exists (input directory).
    let _ = std::fs::create_dir_all("/in");
    if std::path::Path::new("/dev/vdb").exists() {
        let c_source = CString::new("/dev/vdb").unwrap();
        let c_target = CString::new("/in").unwrap();
        let c_fstype = CString::new("ext4").unwrap();

        let ret = unsafe {
            libc::mount(
                c_source.as_ptr(),
                c_target.as_ptr(),
                c_fstype.as_ptr(),
                libc::MS_RDONLY,
                std::ptr::null(),
            )
        };

        if ret != 0 {
            eprintln!(
                "oaie-guest: warning: mount /in failed: {}",
                io::Error::last_os_error()
            );
        } else {
            eprintln!("oaie-guest: mounted /dev/vdb at /in (read-only)");
        }
    }

    // Mount /dev/vdc as /out if the device exists (output directory).
    let _ = std::fs::create_dir_all("/out");
    if std::path::Path::new("/dev/vdc").exists() {
        let c_source = CString::new("/dev/vdc").unwrap();
        let c_target = CString::new("/out").unwrap();
        let c_fstype = CString::new("ext4").unwrap();

        let ret = unsafe {
            libc::mount(
                c_source.as_ptr(),
                c_target.as_ptr(),
                c_fstype.as_ptr(),
                0, // read-write
                std::ptr::null(),
            )
        };

        if ret != 0 {
            eprintln!(
                "oaie-guest: warning: mount /out failed: {}",
                io::Error::last_os_error()
            );
            // Fall back to tmpfs for /out.
            let c_source = CString::new("tmpfs").unwrap();
            let c_target = CString::new("/out").unwrap();
            let c_fstype = CString::new("tmpfs").unwrap();
            unsafe {
                libc::mount(
                    c_source.as_ptr(),
                    c_target.as_ptr(),
                    c_fstype.as_ptr(),
                    0,
                    std::ptr::null(),
                );
            }
        } else {
            eprintln!("oaie-guest: mounted /dev/vdc at /out (read-write)");
        }
    } else {
        // No output device — use tmpfs.
        let c_source = CString::new("tmpfs").unwrap();
        let c_target = CString::new("/out").unwrap();
        let c_fstype = CString::new("tmpfs").unwrap();
        unsafe {
            libc::mount(
                c_source.as_ptr(),
                c_target.as_ptr(),
                c_fstype.as_ptr(),
                0,
                std::ptr::null(),
            );
        }
    }

    Ok(())
}

/// Connect to the host via AF_VSOCK.
///
/// SECURITY: Socket is created with SOCK_CLOEXEC to prevent the connected
/// vsock FD from leaking to the tool process via fork+exec. Without this,
/// the tool could use the inherited FD to communicate with the host directly,
/// bypassing the guest agent protocol and seccomp filter (which only blocks
/// new socket() calls, not inherited FDs).
fn vsock_connect(cid: u32, port: u32) -> io::Result<UnixStream> {
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = AF_VSOCK as libc::sa_family_t;
    addr.svm_cid = cid;
    addr.svm_port = port;

    // Connect with retries (host listener may not be ready yet).
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        // Create a fresh socket on each attempt. POSIX leaves the FD in an
        // unspecified state after a failed connect(), so reusing it is UB.
        // SOCK_CLOEXEC prevents this FD from leaking to the tool process.
        let fd = unsafe {
            libc::socket(AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0)
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let ret = unsafe {
            libc::connect(
                fd,
                &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        };

        if ret == 0 {
            use std::os::unix::io::FromRawFd;
            let stream = unsafe { UnixStream::from_raw_fd(fd) };
            return Ok(stream);
        }

        let err = io::Error::last_os_error();
        // Close the failed socket before retrying.
        unsafe { libc::close(fd) };

        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("vsock connect to CID={cid} port={port} timed out: {err}"),
            ));
        }

        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Handle a RunJob message: fork+exec the command, stream output.
fn handle_run_job(stream: &mut UnixStream, msg: &serde_json::Value) -> io::Result<()> {
    let command: Vec<String> = msg
        .get("command")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    if command.is_empty() {
        send_message(
            stream,
            &serde_json::json!({
                "type": "error",
                "message": "empty command",
            }),
        )?;
        return Ok(());
    }

    let env: HashMap<String, String> = msg
        .get("env")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let timeout_secs: Option<u64> = msg
        .get("timeout_secs")
        .and_then(|v| v.as_u64());

    eprintln!("oaie-guest: running: {:?}", command);

    let start = Instant::now();

    // Build command.
    let mut cmd = Command::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
    }

    // Set working directory to /in if it has files, otherwise /tmp.
    if std::fs::read_dir("/in").map(|mut d| d.next().is_some()).unwrap_or(false) {
        cmd.current_dir("/in");
    } else {
        cmd.current_dir("/tmp");
    }

    // Environment: start clean, set safe defaults, filter host-supplied vars.
    cmd.env_clear();
    cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin");
    cmd.env("HOME", "/tmp");
    cmd.env("TERM", "dumb");
    cmd.env("LANG", "C.UTF-8");
    cmd.env("OAIE_OUT", "/out");
    // SECURITY: filter dangerous environment variables from host-supplied set.
    // These could alter dynamic linker behavior or shell initialization.
    const BLOCKED_ENV_PREFIXES: &[&str] = &[
        "LD_", "BASH_FUNC_", "BASH_ENV", "ENV",
    ];
    for (k, v) in &env {
        if BLOCKED_ENV_PREFIXES.iter().any(|p| k.starts_with(p)) {
            eprintln!("oaie-guest: rejecting dangerous env var: {k}");
            continue;
        }
        cmd.env(k, v);
    }

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // SECURITY: install seccomp filter and rlimits on the child process
    // before it execs. We use pre_exec (unsafe) to set these in the
    // forked child before exec.
    unsafe {
        cmd.pre_exec(|| {
            // 1. Hide /dev/vsock by removing it (defense in depth).
            let _ = std::fs::remove_file("/dev/vsock");

            // 2. Set resource limits (check return values).
            // RLIMIT_FSIZE: 1 GiB max file size.
            let fsize_limit = libc::rlimit {
                rlim_cur: 1024 * 1024 * 1024,
                rlim_max: 1024 * 1024 * 1024,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &fsize_limit) != 0 {
                return Err(io::Error::other("failed to set RLIMIT_FSIZE"));
            }

            // RLIMIT_NPROC: 64 max processes.
            let nproc_limit = libc::rlimit {
                rlim_cur: 64,
                rlim_max: 64,
            };
            if libc::setrlimit(libc::RLIMIT_NPROC, &nproc_limit) != 0 {
                return Err(io::Error::other("failed to set RLIMIT_NPROC"));
            }

            // 3. SECURITY: drop to unprivileged UID. This is the primary
            // defense — without root, the tool loses CAP_SYS_PTRACE (so
            // PR_SET_DUMPABLE=0 on PID 1 actually blocks pidfd_getfd/ptrace),
            // CAP_MKNOD (so it cannot recreate /dev/vsock), and CAP_NET_ADMIN.
            // Order: clear supplementary groups, then GID, then UID (last,
            // since dropping UID drops CAP_SETGID).
            if libc::setgroups(0, std::ptr::null()) != 0 {
                return Err(io::Error::other("failed to clear supplementary groups"));
            }
            if libc::setresgid(65534, 65534, 65534) != 0 {
                return Err(io::Error::other("failed to setresgid(nobody)"));
            }
            if libc::setresuid(65534, 65534, 65534) != 0 {
                return Err(io::Error::other("failed to setresuid(nobody)"));
            }

            // 4. Install seccomp filter blocking AF_VSOCK socket creation.
            // This prevents the tool from creating vsock sockets to talk
            // to the host directly, bypassing the guest agent.
            // SECURITY: seccomp failure is fatal — without this filter, the
            // tool process could create vsock sockets and bypass the agent.
            if let Err(e) = install_seccomp_vsock_filter() {
                return Err(io::Error::other(
                    format!("seccomp filter install failed: {e}"),
                ));
            }

            Ok(())
        });
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            send_message(
                stream,
                &serde_json::json!({
                    "type": "error",
                    "message": format!("spawn failed: {e}"),
                }),
            )?;
            return Ok(());
        }
    };

    // Read stdout and stderr in separate threads, collect after process exits.
    // We can't send from two threads to the same stream simultaneously
    // (framing would be corrupted). Capped at 64 MiB each to prevent a
    // malicious tool from exhausting VM memory.
    const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;

    let child_stdout = child.stdout.take().unwrap();
    let child_stderr = child.stderr.take().unwrap();

    let stdout_handle = std::thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        child_stdout.take(MAX_OUTPUT_BYTES).read_to_end(&mut buf)?;
        Ok(buf)
    });

    let stderr_handle = std::thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        child_stderr.take(MAX_OUTPUT_BYTES).read_to_end(&mut buf)?;
        Ok(buf)
    });

    // Wait for the child with optional timeout.
    let exit_code = if let Some(timeout) = timeout_secs {
        let deadline = Instant::now() + Duration::from_secs(timeout);
        loop {
            match child.try_wait()? {
                Some(status) => break status.code().unwrap_or(-1),
                None if Instant::now() >= deadline => {
                    let _ = unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
                    let _ = child.wait();
                    break -1;
                }
                None => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    } else {
        let status = child.wait()?;
        status.code().unwrap_or(-1)
    };

    let duration = start.elapsed();

    // Collect output.
    let stdout_data = stdout_handle.join().unwrap_or_else(|_| Ok(Vec::new())).unwrap_or_default();
    let stderr_data = stderr_handle.join().unwrap_or_else(|_| Ok(Vec::new())).unwrap_or_default();

    // Send output chunks.
    for chunk in stdout_data.chunks(OUTPUT_CHUNK_SIZE) {
        send_message(
            stream,
            &serde_json::json!({
                "type": "output_chunk",
                "stream": "stdout",
                "data": base64_encode(chunk),
            }),
        )?;
    }

    for chunk in stderr_data.chunks(OUTPUT_CHUNK_SIZE) {
        send_message(
            stream,
            &serde_json::json!({
                "type": "output_chunk",
                "stream": "stderr",
                "data": base64_encode(chunk),
            }),
        )?;
    }

    // Send JobDone.
    send_message(
        stream,
        &serde_json::json!({
            "type": "job_done",
            "exit_code": exit_code,
            "duration_ms": duration.as_millis().min(u64::MAX as u128) as u64,
        }),
    )?;

    eprintln!(
        "oaie-guest: job finished, exit_code={}, duration={:.1}s",
        exit_code,
        duration.as_secs_f64()
    );

    Ok(())
}

// ---- Wire protocol helpers (minimal, no external deps) ----

fn send_message(stream: &mut UnixStream, msg: &serde_json::Value) -> io::Result<()> {
    let json = serde_json::to_vec(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if json.len() > MAX_FRAME_SIZE as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {} > {MAX_FRAME_SIZE}", json.len()),
        ));
    }
    let len = json.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&json)?;
    stream.flush()
}

fn recv_message(stream: &mut UnixStream) -> io::Result<Option<serde_json::Value>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {len}"),
        ));
    }

    let mut payload = vec![0u8; len as usize];
    stream.read_exact(&mut payload)?;

    let msg: serde_json::Value = serde_json::from_slice(&payload)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(msg))
}

/// Install a seccomp BPF filter that blocks AF_VSOCK socket creation.
///
/// This prevents the tool process from creating vsock sockets to communicate
/// with the host directly, bypassing the guest agent protocol. The filter
/// only blocks `socket()` calls where the first argument (domain) is AF_VSOCK (40).
/// All other syscalls pass through — the VM kernel provides isolation for
/// everything else.
fn install_seccomp_vsock_filter() -> io::Result<()> {
    const AUDIT_ARCH_X86_64: u32 = 0xC000003E;

    #[repr(C)]
    struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const SockFilter,
    }

    // BPF instruction building blocks.
    const BPF_LD_W_ABS: u16 = 0x20;  // BPF_LD | BPF_W | BPF_ABS
    const BPF_JMP_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const BPF_JMP_JGE_K: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
    const BPF_RET_K: u16 = 0x06;     // BPF_RET | BPF_K

    const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

    // seccomp_data offsets (struct seccomp_data { int nr; __u32 arch; ... __u64 args[6]; }).
    const OFF_ARCH: u32 = 4;
    const OFF_NR: u32 = 0;
    const OFF_ARGS_0: u32 = 16; // low 32 bits of args[0]

    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

    // x86_64 syscall numbers.
    const SYS_SOCKET: u32 = 41;
    const SYS_PTRACE: u32 = 101;
    const SYS_IO_URING_SETUP: u32 = 425;
    const SYS_IO_URING_ENTER: u32 = 426;
    const SYS_IO_URING_REGISTER: u32 = 427;
    const SYS_PIDFD_OPEN: u32 = 434;
    const SYS_PIDFD_GETFD: u32 = 438;
    const AF_VSOCK: u32 = 40;
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;

    // BPF program: 16 instructions.
    //
    // [0]  Load arch
    // [1]  arch != x86_64 → KILL [14]   (fail-closed: blocks i386 socketcall)
    // [2]  Load syscall nr
    // [3]  nr >= 0x40000000 → KILL [14] (x32 ABI shares AUDIT_ARCH_X86_64;
    //                                    without this, nr|__X32_SYSCALL_BIT
    //                                    bypasses every JEQ below)
    // [4]  io_uring_setup    → ERRNO [13]  (IORING_OP_SOCKET bypass, kernel ≥5.19)
    // [5]  io_uring_enter    → ERRNO [13]
    // [6]  io_uring_register → ERRNO [13]
    // [7]  pidfd_open        → ERRNO [13]  (FD theft from PID 1)
    // [8]  pidfd_getfd       → ERRNO [13]
    // [9]  ptrace            → ERRNO [13]  (PTRACE_ATTACH PID 1)
    // [10] socket? else → ALLOW [15]
    // [11] Load arg0 (domain)
    // [12] arg0 == AF_VSOCK → ERRNO [13], else → ALLOW [15]
    // [13] RET ERRNO(EACCES)
    // [14] RET KILL_PROCESS
    // [15] RET ALLOW
    let filter: [SockFilter; 16] = [
        SockFilter { code: BPF_LD_W_ABS,  jt: 0, jf: 0,  k: OFF_ARCH },
        SockFilter { code: BPF_JMP_JEQ_K, jt: 0, jf: 12, k: AUDIT_ARCH_X86_64 },
        SockFilter { code: BPF_LD_W_ABS,  jt: 0, jf: 0,  k: OFF_NR },
        SockFilter { code: BPF_JMP_JGE_K, jt: 10, jf: 0, k: X32_SYSCALL_BIT },
        SockFilter { code: BPF_JMP_JEQ_K, jt: 8, jf: 0,  k: SYS_IO_URING_SETUP },
        SockFilter { code: BPF_JMP_JEQ_K, jt: 7, jf: 0,  k: SYS_IO_URING_ENTER },
        SockFilter { code: BPF_JMP_JEQ_K, jt: 6, jf: 0,  k: SYS_IO_URING_REGISTER },
        SockFilter { code: BPF_JMP_JEQ_K, jt: 5, jf: 0,  k: SYS_PIDFD_OPEN },
        SockFilter { code: BPF_JMP_JEQ_K, jt: 4, jf: 0,  k: SYS_PIDFD_GETFD },
        SockFilter { code: BPF_JMP_JEQ_K, jt: 3, jf: 0,  k: SYS_PTRACE },
        SockFilter { code: BPF_JMP_JEQ_K, jt: 0, jf: 4,  k: SYS_SOCKET },
        SockFilter { code: BPF_LD_W_ABS,  jt: 0, jf: 0,  k: OFF_ARGS_0 },
        SockFilter { code: BPF_JMP_JEQ_K, jt: 0, jf: 2,  k: AF_VSOCK },
        SockFilter { code: BPF_RET_K,     jt: 0, jf: 0,  k: SECCOMP_RET_ERRNO | (libc::EACCES as u32) },
        SockFilter { code: BPF_RET_K,     jt: 0, jf: 0,  k: SECCOMP_RET_KILL_PROCESS },
        SockFilter { code: BPF_RET_K,     jt: 0, jf: 0,  k: SECCOMP_RET_ALLOW },
    ];

    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    unsafe {
        // Required before seccomp.
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

        // SECCOMP_MODE_FILTER = 2.
        let ret = libc::prctl(
            libc::PR_SET_SECCOMP,
            2,
            &prog as *const SockFprog as libc::c_ulong,
            0,
            0,
        );
        if ret != 0 {
            return Err(io::Error::other(format!(
                "seccomp filter install failed: {}",
                io::Error::last_os_error()
            )));
        }
    }

    Ok(())
}

/// Base64 encoding (same as wire.rs, duplicated to keep guest binary minimal).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}
