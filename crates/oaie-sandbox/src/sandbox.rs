//! Sandbox orchestrator: creates namespaced child processes.
//!
//! `spawn_sandboxed()` uses `clone()` with user/mount/PID/IPC/UTS/net namespaces
//! to create an isolated child process. The child sets up its own root filesystem,
//! drops capabilities, installs seccomp filters, then execs the requested command.
//!
//! The parent writes UID/GID maps and returns pipe handles for stdout/stderr
//! so the Runner can feed them into its existing tee-thread pipeline.

use std::ffi::CString;
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::io::RawFd;
use std::path::PathBuf;

use nix::fcntl::OFlag;
use nix::sched::CloneFlags;
use nix::sys::signal::Signal;
use nix::unistd::{self, Pid};
use oaie_core::error::{OaieError, Result};
use oaie_core::policy::NetworkMode;

use crate::mounts;
use crate::pty;
use crate::seccomp;

/// Environment variable prefixes blocked from entering the sandbox.
pub const ENV_BLOCKED_PREFIXES: &[&str] = &["LD_", "GIT_"];

/// Specific environment variable names blocked from entering the sandbox.
///
/// These are variables that can inject code, override library paths, or
/// manipulate runtime behavior in ways that could compromise sandbox isolation.
pub const ENV_BLOCKED_KEYS: &[&str] = &[
    "GCONV_PATH", "TMPDIR", "BASH_ENV", "ENV", "IFS", "CDPATH",
    "HOSTALIASES", "LOCALDOMAIN", "RESOLV_HOST_CONF",
    "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME",
    "RUBYLIB", "RUBYOPT", "PERL5LIB", "PERL5OPT", "PERLLIB",
    "CLASSPATH", "NODE_OPTIONS",
    "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
    "MAVEN_OPTS", "GRADLE_OPTS",
    "GLIBC_TUNABLES", "DOTNET_STARTUP_HOOKS",
    "OPENSSL_CONF", "OPENSSL_ENGINES",
];

/// Base environment variables always set inside the sandbox.
pub const BASE_ENV: &[(&str, &str)] = &[
    ("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"),
    ("HOME", "/root"),
    ("TERM", "dumb"),
    ("LANG", "C.UTF-8"),
];

/// Check whether an env var key is blocked by prefix or name.
fn is_env_blocked(key: &str) -> bool {
    ENV_BLOCKED_PREFIXES.iter().any(|p| key.starts_with(p))
        || ENV_BLOCKED_KEYS.contains(&key)
}

/// A named bind mount for session mode (dispatch socket, artifacts directory).
#[derive(Clone, Debug)]
pub struct SessionMount {
    /// Host-side path to the file or directory to mount.
    pub source: PathBuf,
    /// Path inside the sandbox where this will appear.
    pub target: String,
    /// If true, the mount is read-write; otherwise read-only.
    pub writable: bool,
}

/// Configuration for a sandboxed execution.
#[derive(Clone, Debug)]
pub struct SandboxConfig {
    /// Host directory mounted read-only at `/in` inside the sandbox.
    pub input_dir: PathBuf,
    /// Host directory mounted read-write at `/out` inside the sandbox.
    pub output_dir: PathBuf,
    /// Additional host paths mounted read-only.
    pub extra_ro: Vec<PathBuf>,
    /// Additional host paths mounted read-write.
    pub extra_rw: Vec<PathBuf>,
    /// Network access mode (default: Off → CLONE_NEWNET isolates network).
    /// `On` shares host network, `Allowlist` creates isolated ns with filtered access.
    pub network: NetworkMode,
    /// Mount /proc inside the sandbox (default: true).
    pub proc_mount: bool,
    /// Override RLIMIT_NPROC soft limit. None → use default (64).
    pub max_pids: Option<u32>,
    /// Override RLIMIT_AS in bytes. None → use default (4G soft / 8G hard).
    pub max_memory: Option<u64>,
    /// Override RLIMIT_FSIZE in bytes. None → use default (1G).
    pub max_fsize: Option<u64>,
    /// Allow `memfd_create()` and `execveat()` syscalls through the seccomp filter.
    /// Needed for JIT compilers and language runtimes (Java, Node.js, .NET).
    pub allow_memfd: bool,
    /// Bitmask of Linux capabilities to retain instead of dropping (0 = drop all).
    /// Only safe capabilities are allowed: CAP_NET_RAW (bit 13) for ICMP ping
    /// and CAP_NET_BIND_SERVICE (bit 10) for binding privileged ports.
    pub retain_caps: u64,
    /// CPU time limit in seconds (RLIMIT_CPU). Defaults to 600s.
    /// Should be set to 2× the effective wall-clock timeout so CPU-intensive
    /// tools aren't killed before their wall-clock deadline.
    pub max_cpu_time: Option<u64>,
    /// Interactive PTY mode — when true, the child gets a PTY for terminal I/O.
    pub interactive: bool,
    /// Host-side PTY slave path (e.g. "/dev/pts/3") to bind-mount into the
    /// sandbox. Set internally by `spawn_sandboxed_interactive()` — callers
    /// should not set this. Only the specific slave file is mounted, not the
    /// entire `/dev/pts` directory.
    pub pty_slave_path: Option<PathBuf>,
    /// Extra named bind mounts for session mode (dispatch socket, artifacts dir).
    /// Applied after extra_rw mounts, before pivot_root.
    pub session_mounts: Vec<SessionMount>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            input_dir: PathBuf::from("."),
            output_dir: PathBuf::from("."),
            extra_ro: vec![],
            extra_rw: vec![],
            network: NetworkMode::Off,
            proc_mount: true,
            max_pids: None,
            max_memory: None,
            max_fsize: None,
            allow_memfd: false,
            retain_caps: 0,
            max_cpu_time: None,
            interactive: false,
            pty_slave_path: None,
            session_mounts: vec![],
        }
    }
}

/// A sandboxed child process with pipe handles for I/O capture.
///
/// The Runner reads from `stdout`/`stderr` pipes and uses `waitpid(pid)`
/// instead of `child.try_wait()` since this is a raw PID from `clone()`.
///
/// Implements `Drop` to kill and reap the child process if the caller drops
/// this without calling `waitpid` (e.g. due to panic or early return). This
/// prevents zombie processes and namespace resource leaks.
pub struct SandboxedChild {
    /// PID of the sandboxed process (PID 1 inside its PID namespace).
    pub pid: Pid,
    /// True once the caller has waited on the child (prevents double-wait in Drop).
    pub reaped: bool,
    /// Read end of the stdout pipe (child writes to the other end via dup2).
    /// Wrapped in Option so it can be taken without moving out of the Drop type.
    pub stdout: Option<std::fs::File>,
    /// Read end of the stderr pipe (child writes to the other end via dup2).
    /// Wrapped in Option so it can be taken without moving out of the Drop type.
    pub stderr: Option<std::fs::File>,
}

impl SandboxedChild {
    /// Take ownership of the stdout pipe, leaving `None` in its place.
    pub fn take_stdout(&mut self) -> Option<std::fs::File> {
        self.stdout.take()
    }

    /// Take ownership of the stderr pipe, leaving `None` in its place.
    pub fn take_stderr(&mut self) -> Option<std::fs::File> {
        self.stderr.take()
    }

    /// Mark the child as reaped (caller has already called waitpid).
    pub fn mark_reaped(&mut self) {
        self.reaped = true;
    }
}

impl Drop for SandboxedChild {
    fn drop(&mut self) {
        if !self.reaped {
            // Best-effort cleanup: kill and reap to prevent zombie + namespace leak.
            let _ = nix::sys::signal::kill(self.pid, Signal::SIGKILL);
            let _ = nix::sys::wait::waitpid(self.pid, None);
        }
    }
}

/// Spawn a command inside a fully isolated Linux namespace sandbox.
///
/// Creates pipe pairs for stdout/stderr, clones into new namespaces,
/// sets up UID/GID mapping, and returns handles for the parent to read.
///
/// # Arguments
/// * `config` — Sandbox configuration (input/output dirs, network, etc.)
/// * `command` — Command and arguments to execute (e.g. `["gcc", "-o", "hello", "hello.c"]`)
/// * `env_vars` — Additional environment variables for the child (on top of the clean base set)
/// * `trace_enabled` — If true, the child calls `ptrace::traceme()` + SIGSTOP
///   before exec so the parent can attach a ptrace tracer. This also skips
///   `PR_SET_DUMPABLE=0` (which would prevent ptrace attachment after exec).
/// * `post_map_hook` — Optional closure called in the parent after UID/GID maps
///   are written but before the child is released from the sync pipe. Used to
///   assign the child PID to a cgroup scope before it starts executing.
pub fn spawn_sandboxed(
    config: &SandboxConfig,
    command: &[String],
    env_vars: &[(String, String)],
    trace_enabled: bool,
    post_map_hook: Option<Box<dyn FnOnce(Pid) -> Result<()>>>,
) -> Result<SandboxedChild> {
    if command.is_empty() {
        return Err(OaieError::SandboxError("empty command".into()));
    }

    // 1. Create pipe pairs: stdout, stderr, sync.
    // All pipes use O_CLOEXEC so they don't leak into the exec'd process.
    let (stdout_read, stdout_write) = pipe_cloexec()?;
    let (stderr_read, stderr_write) = pipe_cloexec()?;
    let (sync_read, sync_write) = pipe_cloexec()?;

    // 2. Build clone flags.
    let mut clone_flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWIPC
        | CloneFlags::CLONE_NEWUTS
        | CloneFlags::CLONE_NEWCGROUP;

    if config.network.needs_netns() {
        clone_flags |= CloneFlags::CLONE_NEWNET;
    }

    // 3. Allocate 1 MiB stack for the child.
    let mut stack = vec![0u8; 1024 * 1024];

    // Capture values for the child closure.
    let config = config.clone();
    let command = command.to_vec();
    let env_vars = env_vars.to_vec();

    let stdout_write_fd = stdout_write.as_raw_fd();
    let stderr_write_fd = stderr_write.as_raw_fd();
    let sync_read_fd = sync_read.as_raw_fd();
    let sync_write_fd = sync_write.as_raw_fd();
    let stdout_read_fd = stdout_read.as_raw_fd();
    let stderr_read_fd = stderr_read.as_raw_fd();

    // 4. clone() into new namespaces.
    let child_fn = move || -> isize {
        // Close parent-side pipe ends in the child.
        unsafe {
            libc::close(stdout_read_fd);
            libc::close(stderr_read_fd);
            libc::close(sync_write_fd);
        }

        // Block on sync pipe — wait for parent to write UID/GID maps.
        let mut sync_buf = [0u8; 1];
        let n = unsafe {
            libc::read(sync_read_fd, sync_buf.as_mut_ptr() as *mut libc::c_void, 1)
        };
        unsafe { libc::close(sync_read_fd); }

        if n != 1 {
            write_err(stderr_write_fd, "sync pipe read failed");
            return 127;
        }

        // Set up the mount namespace (new rootfs, /in, /out, etc.).
        // Use UUID to avoid collisions — getpid() always returns 1 inside
        // the new PID namespace (CLONE_NEWPID), so it can't distinguish
        // concurrent sandbox instances.
        let root_path = format!("/tmp/oaie-root-{}", uuid::Uuid::now_v7().simple());
        if let Err(e) = mounts::setup_mounts(&config, &root_path) {
            // Best-effort cleanup: detach any partial mounts, then remove the
            // empty directory. umount2 with MNT_DETACH propagates to submounts
            // inside our namespace — it won't affect the host.
            if let Ok(c_path) = std::ffi::CString::new(root_path.as_bytes()) {
                let ret = unsafe { libc::umount2(c_path.as_ptr(), libc::MNT_DETACH) };
                if ret != 0 {
                    write_err(stderr_write_fd, &format!(
                        "mount cleanup: umount2 failed: errno {}",
                        unsafe { *libc::__errno_location() }
                    ));
                }
            }
            if let Err(rm_err) = std::fs::remove_dir(&root_path) {
                // Non-fatal: the directory will be cleaned up at next startup.
                write_err(stderr_write_fd, &format!(
                    "mount cleanup: remove_dir failed (will be cleaned at next run): {rm_err}"
                ));
            }
            write_err(stderr_write_fd, &format!("mount setup failed: {e}"));
            return 127;
        }

        // Bring up loopback interface in isolated network namespaces.
        // Without this, the loopback is down and ping/localhost connections fail.
        // Must run before cap drop — requires CAP_NET_ADMIN in the namespace.
        // Skipped when sharing host network (NetworkMode::On, no CLONE_NEWNET).
        if config.network.needs_netns() {
            setup_loopback();
        }

        // Create a new session (detach from controlling terminal).
        if unsafe { libc::setsid() } < 0 {
            write_err(stderr_write_fd, "setsid failed");
            return 127;
        }

        // Redirect stdin from /dev/null so the child doesn't inherit the
        // parent's terminal fd. Best-effort: /dev/null may be inaccessible
        // inside the sandbox due to MS_NODEV on the bind mount. If it fails,
        // close stdin instead (fd 0 → no reads possible).
        let dev_null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if dev_null >= 0 {
            if unsafe { libc::dup2(dev_null, 0) } < 0 {
                write_err(stderr_write_fd, "dup2 stdin failed");
                return 127;
            }
            unsafe { libc::close(dev_null); }
        } else {
            // /dev/null unavailable — close stdin as fallback.
            unsafe { libc::close(0); }
        }

        // dup2 stdout and stderr to our pipe write ends.
        // First, clear O_CLOEXEC on the write ends so they survive exec.
        if !clear_cloexec(stdout_write_fd) || !clear_cloexec(stderr_write_fd) {
            write_err(stderr_write_fd, "fcntl F_SETFD failed");
            return 127;
        }

        if unsafe { libc::dup2(stdout_write_fd, 1) } < 0 {
            write_err(stderr_write_fd, "dup2 stdout failed");
            return 127;
        }
        if unsafe { libc::dup2(stderr_write_fd, 2) } < 0 {
            // stderr_write_fd is still the original pipe fd here.
            write_err(stderr_write_fd, "dup2 stderr failed");
            return 127;
        }

        // PR_SET_NO_NEW_PRIVS — required before both Landlock and seccomp.
        // Must be set before landlock_restrict_self() and seccomp install.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            write_err(stderr_write_fd, "PR_SET_NO_NEW_PRIVS failed — aborting");
            return 127;
        }

        // Apply Landlock filesystem restrictions (defense-in-depth on top of
        // namespace + seccomp isolation). Must be after NO_NEW_PRIVS and after
        // pivot_root, before close_range (opens/closes fds internally).
        // Silently skipped on kernels < 5.13 that lack Landlock support.
        match crate::landlock::apply_landlock(config.extra_ro.len(), config.extra_rw.len()) {
            Ok(_applied) => {}
            Err(e) => {
                // Landlock returning Err (not Ok(false) for unsupported kernel)
                // means it IS available but application failed — this is abnormal
                // and may indicate a compromised state. Abort the sandbox.
                write_err(stderr_write_fd, &format!("landlock failed — aborting: {e}"));
                return 127;
            }
        }

        // Close all file descriptors >= 3 (including the original pipe write fds).
        close_range_above(3);

        // PR_SET_DUMPABLE=0 — prevent ptrace attachment and core dumps.
        // Skip when tracing is enabled: ptrace requires the process to be dumpable,
        // and the parent tracer needs to read registers/memory after exec.
        if !trace_enabled {
            unsafe {
                libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            }
        }

        // If tracing is enabled, call ptrace::traceme() before seccomp
        // (seccomp blocks the ptrace syscall). Then raise SIGSTOP so the
        // parent can set ptrace options before we exec.
        if trace_enabled {
            if unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) } < 0 {
                write_err(2, "ptrace::traceme failed");
                return 127;
            }
            unsafe { libc::raise(libc::SIGSTOP); }
        }

        // Reset personality — disable READ_IMPLIES_EXEC and other dangerous
        // personality flags.  PER_LINUX (0x0000) is the safe default.
        // personality(0) would merely *read* the current value; we must
        // pass PER_LINUX to actually clear dangerous flags.
        const PER_LINUX: libc::c_ulong = 0x0000;
        if unsafe { libc::personality(PER_LINUX) } == -1 {
            write_err(2, "personality(PER_LINUX) failed");
            return 127;
        }

        // Set resource limits (policy-driven when overrides are present).
        set_rlimits(&config);

        // Set capabilities — retain only the policy-approved subset (usually none).
        // Fatal if it fails because seccomp ERRNO tier relies on dangerous
        // capabilities being absent (e.g. open_by_handle_at needs CAP_DAC_READ_SEARCH).
        if !set_caps(config.retain_caps) {
            write_err(2, "capset failed — aborting");
            return 127;
        }

        // Install seccomp filter.
        if let Err(e) = seccomp::install_seccomp_filter(config.allow_memfd) {
            let msg = format!("seccomp install failed: {e}");
            // stderr is already dup2'd, so just write directly.
            let _ = unsafe {
                libc::write(
                    2,
                    msg.as_ptr() as *const libc::c_void,
                    msg.len(),
                )
            };
            return 127;
        }

        // Build clean environment using C string literals (no NUL bytes possible).
        let mut env: Vec<CString> = BASE_ENV
            .iter()
            .map(|(k, v)| CString::new(format!("{k}={v}")).unwrap())
            .collect();
        for (key, val) in &env_vars {
            // Reject env var keys that are empty, contain '=' (which would
            // let an attacker override PATH/LD_PRELOAD by embedding a key
            // like "PATH=/evil"), or contain NUL bytes.
            if key.is_empty()
                || key.contains('=')
                || key.contains('\0')
                || key.contains('\n')
                || val.contains('\0')
                || val.contains('\n')
            {
                write_err(2, "invalid env var: contains forbidden character");
                return 127;
            }
            // Reject env var keys that could compromise sandbox isolation.
            if is_env_blocked(key) {
                write_err(2, &format!("rejected dangerous env var: {key}"));
                return 127;
            }
            // Safe to unwrap: we just verified no NUL bytes above.
            env.push(CString::new(format!("{key}={val}")).unwrap());
        }

        // Build argv — NUL bytes in arguments are a programming error.
        let argv: Vec<CString> = match command
            .iter()
            .map(|s| CString::new(s.as_str()))
            .collect::<std::result::Result<Vec<_>, _>>()
        {
            Ok(v) => v,
            Err(_) => {
                let _ = unsafe {
                    libc::write(
                        2,
                        b"command contains NUL byte\n".as_ptr() as *const libc::c_void,
                        26,
                    )
                };
                return 127;
            }
        };

        if argv.is_empty() {
            return 127;
        }

        // execvpe: search PATH for the command.
        let argv_ptrs: Vec<*const libc::c_char> = argv
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        let env_ptrs: Vec<*const libc::c_char> = env
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        unsafe {
            libc::execvpe(argv_ptrs[0], argv_ptrs.as_ptr(), env_ptrs.as_ptr());
        }

        // If execvpe returns, it failed — report the errno.
        let errno = unsafe { *libc::__errno_location() };
        let msg = format!("exec failed (errno {errno}): {}\n", command[0]);
        let _ = unsafe {
            libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len())
        };
        127
    };

    let pid = unsafe {
        nix::sched::clone(
            Box::new(child_fn),
            &mut stack,
            clone_flags,
            Some(Signal::SIGCHLD as i32),
        )
    }
    .map_err(|e| {
        let hint = match e {
            nix::errno::Errno::ENOSPC | nix::errno::Errno::ENOMEM => {
                ". Likely cause: user namespace limit exhausted. \
                 Check: cat /proc/sys/user/max_user_namespaces; \
                 increase with: sudo sysctl -w user.max_user_namespaces=131072"
            }
            nix::errno::Errno::EPERM => {
                ". Likely cause: LSM (AppArmor/SELinux) blocking unprivileged userns. \
                 On Ubuntu 24.04+: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"
            }
            _ => "",
        };
        OaieError::SandboxError(format!("clone() failed: {e}{hint}"))
    })?;

    // 5. Parent side: close child-side pipe ends.
    drop(stdout_write);
    drop(stderr_write);
    drop(sync_read);

    // 6. Write UID/GID maps for the child.
    // If any step fails, kill the child and waitpid to prevent zombies.
    let uid = unistd::getuid();
    let gid = unistd::getgid();

    let mut post_map_hook = post_map_hook;
    let mut parent_setup = || -> Result<()> {
        write_uid_map(pid, uid.as_raw())?;
        write_setgroups_deny(pid)?;
        write_gid_map(pid, gid.as_raw())?;

        // Cgroup assignment hook: parent assigns child PID to cgroup
        // before releasing child from sync pipe.
        if let Some(hook) = post_map_hook.take() {
            hook(pid)?;
        }

        // 7. Signal the child that maps (and cgroup) are ready.
        let sync_fd = sync_write.as_raw_fd();
        let written = unsafe { libc::write(sync_fd, [1u8].as_ptr() as *const libc::c_void, 1) };
        if written != 1 {
            return Err(OaieError::SandboxError("failed to signal child via sync pipe".into()));
        }
        Ok(())
    };

    if let Err(e) = parent_setup() {
        // Kill the child and reap to avoid zombie.
        let _ = nix::sys::signal::kill(pid, Signal::SIGKILL);
        let _ = nix::sys::wait::waitpid(pid, None);
        drop(sync_write);
        return Err(e);
    }
    drop(sync_write);

    // 8. Return the sandboxed child with read ends of the pipes.
    // into_raw_fd() consumes the OwnedFd without closing, then File takes ownership.
    let stdout_file = unsafe { std::fs::File::from_raw_fd(OwnedFd::into_raw_fd(stdout_read)) };
    let stderr_file = unsafe { std::fs::File::from_raw_fd(OwnedFd::into_raw_fd(stderr_read)) };

    Ok(SandboxedChild {
        pid,
        reaped: false,
        stdout: Some(stdout_file),
        stderr: Some(stderr_file),
    })
}

/// A sandboxed child process with a PTY master for interactive I/O.
///
/// The PTY master is bidirectional: reading returns child output, writing
/// sends input to the child. stdout and stderr are both routed through the
/// PTY (merged into a single stream, as with a real terminal).
///
/// Implements `Drop` to kill and reap the child process if not already reaped.
pub struct InteractiveChild {
    /// PID of the sandboxed process.
    pub pid: Pid,
    /// True once the caller has waited on the child.
    pub reaped: bool,
    /// Bidirectional PTY master — read=child output, write=child input.
    /// Wrapped in Option so it can be taken without moving out of the Drop type.
    pub pty_master: Option<std::fs::File>,
}

impl InteractiveChild {
    /// Take ownership of the PTY master, leaving `None` in its place.
    pub fn take_pty_master(&mut self) -> Option<std::fs::File> {
        self.pty_master.take()
    }

    /// Mark the child as reaped (caller has already called waitpid).
    pub fn mark_reaped(&mut self) {
        self.reaped = true;
    }
}

impl Drop for InteractiveChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = nix::sys::signal::kill(self.pid, Signal::SIGKILL);
            let _ = nix::sys::wait::waitpid(self.pid, None);
        }
    }
}

/// Spawn a command inside a namespace sandbox with a pseudoterminal.
///
/// Like [`spawn_sandboxed()`] but allocates a PTY pair instead of pipes.
/// The child gets a controlling terminal, enabling full terminal app support
/// (vim, htop, less, etc.) inside the sandbox. `isatty()` returns true for
/// all three standard fds.
///
/// # Security model
///
/// The PTY slave is a NEW terminal device inside the child's session — the
/// supervisor's actual terminal is never exposed. TIOCSTI on the slave pushes
/// characters into the master's read buffer (supervisor reads as data, never
/// executes). Same model as `docker run -it`.
///
/// # Arguments
/// Same as [`spawn_sandboxed()`], plus the child inherits the supervisor's
/// `TERM` environment variable (not hardcoded "dumb").
pub fn spawn_sandboxed_interactive(
    config: &SandboxConfig,
    command: &[String],
    env_vars: &[(String, String)],
    trace_enabled: bool,
    post_map_hook: Option<Box<dyn FnOnce(Pid) -> Result<()>>>,
) -> Result<InteractiveChild> {
    if command.is_empty() {
        return Err(OaieError::SandboxError("empty command".into()));
    }

    // Allocate PTY pair before clone — master stays with parent.
    let pty_pair = pty::allocate_pty()?;
    let slave_path_str = pty_pair.slave_path.to_string_lossy().to_string();

    // Sync pipe for UID/GID map coordination (same as non-interactive).
    let (sync_read, sync_write) = pipe_cloexec()?;

    // Build clone flags (identical to non-interactive).
    let mut clone_flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWIPC
        | CloneFlags::CLONE_NEWUTS
        | CloneFlags::CLONE_NEWCGROUP;

    if config.network.needs_netns() {
        clone_flags |= CloneFlags::CLONE_NEWNET;
    }

    let mut stack = vec![0u8; 1024 * 1024];

    let mut config = config.clone();
    // Inject the specific slave path — setup_mounts() will bind-mount only this
    // file (not the entire /dev/pts directory) to minimize attack surface.
    config.pty_slave_path = Some(pty_pair.slave_path.clone());
    let command = command.to_vec();
    let env_vars = env_vars.to_vec();

    // Inherit TERM from supervisor (not "dumb" — terminal apps need this).
    // Sanitize: only allow safe ASCII chars, cap at 64 chars.
    let supervisor_term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
    let supervisor_term = if supervisor_term.len() <= 64
        && !supervisor_term.is_empty()
        && supervisor_term
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        supervisor_term
    } else {
        "xterm-256color".into()
    };

    let sync_read_fd = sync_read.as_raw_fd();
    let sync_write_fd = sync_write.as_raw_fd();
    let master_fd = pty_pair.master.as_raw_fd();

    let child_fn = move || -> isize {
        // Close parent-side fds in the child.
        unsafe {
            libc::close(sync_write_fd);
            libc::close(master_fd);
        }

        // Block on sync pipe — wait for parent UID/GID maps.
        let mut sync_buf = [0u8; 1];
        let n = unsafe {
            libc::read(sync_read_fd, sync_buf.as_mut_ptr() as *mut libc::c_void, 1)
        };
        unsafe { libc::close(sync_read_fd); }

        if n != 1 {
            write_err(2, "sync pipe read failed");
            return 127;
        }

        // Set up mount namespace (same as non-interactive).
        let root_path = format!("/tmp/oaie-root-{}", uuid::Uuid::now_v7().simple());
        if let Err(e) = mounts::setup_mounts(&config, &root_path) {
            if let Ok(c_path) = std::ffi::CString::new(root_path.as_bytes()) {
                unsafe { libc::umount2(c_path.as_ptr(), libc::MNT_DETACH); }
            }
            if let Err(rm_err) = std::fs::remove_dir(&root_path) {
                write_err(2, &format!(
                    "mount cleanup: remove_dir failed: {rm_err}"
                ));
            }
            write_err(2, &format!("mount setup failed: {e}"));
            return 127;
        }

        // Bring up loopback in isolated net namespace.
        if config.network.needs_netns() {
            setup_loopback();
        }

        // Create new session — required so TIOCSCTTY can set controlling terminal.
        if unsafe { libc::setsid() } < 0 {
            write_err(2, "setsid failed");
            return 127;
        }

        // Open the PTY slave device as the child's terminal.
        // The slave path is on the host's devpts — setup_mounts() bind-mounts
        // only this specific slave file (not the whole /dev/pts directory) when
        // config.pty_slave_path is set.
        let slave_cstr = match CString::new(slave_path_str.as_bytes()) {
            Ok(s) => s,
            Err(_) => {
                write_err(2, "invalid slave path");
                return 127;
            }
        };

        let slave_fd = unsafe {
            libc::open(slave_cstr.as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC)
        };
        if slave_fd < 0 {
            let errno = unsafe { *libc::__errno_location() };
            write_err(2, &format!("open pty slave failed: errno {errno}"));
            return 127;
        }

        // Set the slave as controlling terminal for this session.
        // TIOCSCTTY arg=0: steal the terminal (safe — we're in our own session).
        if unsafe { libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) } < 0 {
            let errno = unsafe { *libc::__errno_location() };
            write_err(2, &format!("TIOCSCTTY failed: errno {errno}"));
            unsafe { libc::close(slave_fd); }
            return 127;
        }

        // dup2 slave to stdin/stdout/stderr.
        if unsafe { libc::dup2(slave_fd, 0) } < 0
            || unsafe { libc::dup2(slave_fd, 1) } < 0
            || unsafe { libc::dup2(slave_fd, 2) } < 0
        {
            // Write error to fd 2 (stderr) — it may or may not have been
            // overwritten by dup2 yet depending on which call failed.
            write_err(2, "dup2 pty slave failed");
            return 127;
        }

        // Close the original slave fd (now duplicated to 0/1/2).
        if slave_fd > 2 {
            unsafe { libc::close(slave_fd); }
        }

        // PR_SET_NO_NEW_PRIVS — required before Landlock and seccomp.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            write_err(2, "PR_SET_NO_NEW_PRIVS failed");
            return 127;
        }

        // Apply Landlock filesystem restrictions.
        match crate::landlock::apply_landlock(config.extra_ro.len(), config.extra_rw.len()) {
            Ok(_) => {}
            Err(e) => {
                write_err(2, &format!("landlock failed: {e}"));
                return 127;
            }
        }

        // Close all fds >= 3.
        close_range_above(3);

        // PR_SET_DUMPABLE — skip when tracing.
        if !trace_enabled {
            unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0); }
        }

        // ptrace handshake if tracing.
        if trace_enabled {
            if unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) } < 0 {
                write_err(2, "ptrace::traceme failed");
                return 127;
            }
            unsafe { libc::raise(libc::SIGSTOP); }
        }

        // Reset personality — PER_LINUX (0x0000) clears READ_IMPLIES_EXEC etc.
        const PER_LINUX: libc::c_ulong = 0x0000;
        if unsafe { libc::personality(PER_LINUX) } == -1 {
            write_err(2, "personality(PER_LINUX) failed");
            return 127;
        }

        // Set rlimits.
        set_rlimits(&config);

        // Set capabilities.
        if !set_caps(config.retain_caps) {
            write_err(2, "capset failed");
            return 127;
        }

        // Install seccomp filter.
        if let Err(e) = seccomp::install_seccomp_filter(config.allow_memfd) {
            let msg = format!("seccomp install failed: {e}");
            let _ = unsafe {
                libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len())
            };
            return 127;
        }

        // Build clean environment — same as non-interactive, except TERM
        // inherits from supervisor (terminal apps need correct termcap).
        let mut env: Vec<CString> = BASE_ENV
            .iter()
            .map(|(k, v)| {
                // Override TERM with supervisor's terminal type for interactive mode.
                if *k == "TERM" {
                    CString::new(format!("TERM={supervisor_term}")).unwrap()
                } else {
                    CString::new(format!("{k}={v}")).unwrap()
                }
            })
            .collect();
        for (key, val) in &env_vars {
            if key.is_empty()
                || key.contains('=')
                || key.contains('\0')
                || key.contains('\n')
                || val.contains('\0')
                || val.contains('\n')
            {
                write_err(2, "invalid env var: contains forbidden character");
                return 127;
            }
            if is_env_blocked(key) {
                write_err(2, &format!("rejected dangerous env var: {key}"));
                return 127;
            }
            env.push(CString::new(format!("{key}={val}")).unwrap());
        }

        // Build argv.
        let argv: Vec<CString> = match command
            .iter()
            .map(|s| CString::new(s.as_str()))
            .collect::<std::result::Result<Vec<_>, _>>()
        {
            Ok(v) => v,
            Err(_) => {
                let _ = unsafe {
                    libc::write(2, b"command contains NUL byte\n".as_ptr() as *const libc::c_void, 26)
                };
                return 127;
            }
        };

        if argv.is_empty() {
            return 127;
        }

        let argv_ptrs: Vec<*const libc::c_char> = argv
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        let env_ptrs: Vec<*const libc::c_char> = env
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        unsafe {
            libc::execvpe(argv_ptrs[0], argv_ptrs.as_ptr(), env_ptrs.as_ptr());
        }

        let errno = unsafe { *libc::__errno_location() };
        let msg = format!("exec failed (errno {errno}): {}\n", command[0]);
        let _ = unsafe {
            libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len())
        };
        127
    };

    let pid = unsafe {
        nix::sched::clone(
            Box::new(child_fn),
            &mut stack,
            clone_flags,
            Some(Signal::SIGCHLD as i32),
        )
    }
    .map_err(|e| {
        let hint = match e {
            nix::errno::Errno::ENOSPC | nix::errno::Errno::ENOMEM => {
                ". Likely cause: user namespace limit exhausted. \
                 Check: cat /proc/sys/user/max_user_namespaces; \
                 increase with: sudo sysctl -w user.max_user_namespaces=131072"
            }
            nix::errno::Errno::EPERM => {
                ". Likely cause: LSM (AppArmor/SELinux) blocking unprivileged userns. \
                 On Ubuntu 24.04+: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"
            }
            _ => "",
        };
        OaieError::SandboxError(format!("clone() failed: {e}{hint}"))
    })?;

    // Parent side: close child-side fds.
    drop(sync_read);

    // Write UID/GID maps.
    let uid = unistd::getuid();
    let gid = unistd::getgid();

    let mut post_map_hook = post_map_hook;
    let mut parent_setup = || -> Result<()> {
        write_uid_map(pid, uid.as_raw())?;
        write_setgroups_deny(pid)?;
        write_gid_map(pid, gid.as_raw())?;

        if let Some(hook) = post_map_hook.take() {
            hook(pid)?;
        }

        let sync_fd = sync_write.as_raw_fd();
        let written = unsafe { libc::write(sync_fd, [1u8].as_ptr() as *const libc::c_void, 1) };
        if written != 1 {
            return Err(OaieError::SandboxError("failed to signal child via sync pipe".into()));
        }
        Ok(())
    };

    if let Err(e) = parent_setup() {
        let _ = nix::sys::signal::kill(pid, Signal::SIGKILL);
        let _ = nix::sys::wait::waitpid(pid, None);
        drop(sync_write);
        return Err(e);
    }
    drop(sync_write);

    // Convert PTY master OwnedFd to File for the caller.
    let pty_master = unsafe {
        std::fs::File::from_raw_fd(OwnedFd::into_raw_fd(pty_pair.master))
    };

    Ok(InteractiveChild {
        pid,
        reaped: false,
        pty_master: Some(pty_master),
    })
}

/// Create a pipe pair with O_CLOEXEC set on both ends.
fn pipe_cloexec() -> Result<(OwnedFd, OwnedFd)> {
    let (read, write) = nix::unistd::pipe2(OFlag::O_CLOEXEC)
        .map_err(|e| OaieError::SandboxError(format!("pipe2: {e}")))?;
    Ok((read, write))
}

/// Write the UID map for a child process: map UID 0 inside → our UID outside.
fn write_uid_map(pid: Pid, uid: u32) -> Result<()> {
    let path = format!("/proc/{pid}/uid_map");
    let content = format!("0 {uid} 1\n");
    fs::write(&path, &content)
        .map_err(|e| OaieError::SandboxError(format!("write uid_map: {e}")))
}

/// Write "deny" to setgroups before writing the GID map.
///
/// Required by the kernel when an unprivileged process creates a user namespace —
/// without this, writing gid_map fails with EPERM.
fn write_setgroups_deny(pid: Pid) -> Result<()> {
    let path = format!("/proc/{pid}/setgroups");
    fs::write(&path, "deny")
        .map_err(|e| OaieError::SandboxError(format!("write setgroups deny: {e}")))
}

/// Write the GID map for a child process: map GID 0 inside → our GID outside.
fn write_gid_map(pid: Pid, gid: u32) -> Result<()> {
    let path = format!("/proc/{pid}/gid_map");
    let content = format!("0 {gid} 1\n");
    fs::write(&path, &content)
        .map_err(|e| OaieError::SandboxError(format!("write gid_map: {e}")))
}

/// Write an error message to a raw file descriptor (best-effort, ignores errors).
fn write_err(fd: RawFd, msg: &str) {
    let bytes = msg.as_bytes();
    // SAFETY: fd is a valid open file descriptor from pipe2(), bytes is a valid slice.
    unsafe {
        libc::write(fd, bytes.as_ptr() as *const libc::c_void, bytes.len());
    }
}

/// Bring up the loopback (`lo`) interface in an isolated network namespace.
///
/// A new network namespace starts with loopback down. Without bringing it up,
/// even `ping 127.0.0.1` fails with "Network is unreachable". Uses a raw
/// `SIOCGIFFLAGS`/`SIOCSIFFLAGS` ioctl — no external commands needed.
///
/// Best-effort: failures are silently ignored because the sandbox still works
/// without loopback (just no localhost connectivity). Must be called before
/// capabilities are dropped since `SIOCSIFFLAGS` requires `CAP_NET_ADMIN`.
fn setup_loopback() {
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if sock < 0 {
            return;
        }

        // struct ifreq with ifr_name = "lo\0" (16-byte name field).
        #[repr(C)]
        struct Ifreq {
            ifr_name: [u8; 16],
            // Union of ifr_flags (i16) and padding. We only use the flags field.
            ifr_flags: i16,
            _pad: [u8; 22],
        }

        let mut ifr: Ifreq = std::mem::zeroed();
        ifr.ifr_name[0] = b'l';
        ifr.ifr_name[1] = b'o';

        // SIOCGIFFLAGS = 0x8913
        if libc::ioctl(sock, 0x8913, &mut ifr) == 0 {
            ifr.ifr_flags |= libc::IFF_UP as i16;
            // SIOCSIFFLAGS = 0x8914
            libc::ioctl(sock, 0x8914, &ifr);
        }

        libc::close(sock);
    }
}

/// Clear the O_CLOEXEC flag on a file descriptor so it survives exec.
/// Returns `true` on success. On failure, writes the errno to stderr
/// for post-mortem debugging.
fn clear_cloexec(fd: RawFd) -> bool {
    // SAFETY: fd is a valid open file descriptor from pipe2().
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags < 0 {
            let errno = *libc::__errno_location();
            write_err(2, &format!("fcntl F_GETFD fd={fd} failed: errno {errno}"));
            return false;
        }
        if libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) != 0 {
            let errno = *libc::__errno_location();
            write_err(2, &format!("fcntl F_SETFD fd={fd} failed: errno {errno}"));
            return false;
        }
        true
    }
}

/// Close all file descriptors from `from` upward.
///
/// Uses the `close_range` syscall if available (Linux 5.9+), falls back to
/// iterating through /proc/self/fd.
fn close_range_above(from: RawFd) {
    // Try close_range(3) syscall first (available since Linux 5.9).
    let ret = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            from as libc::c_uint,
            libc::c_uint::MAX,
            0u32, // no flags
        )
    };
    if ret == 0 {
        return;
    }

    // Fallback: iterate /proc/self/fd.
    match std::fs::read_dir("/proc/self/fd") {
        Ok(entries) => {
            let fds: Vec<RawFd> = entries
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse().ok()))
                .filter(|&fd| fd >= from)
                .collect();
            for fd in fds {
                unsafe { libc::close(fd); }
            }
        }
        Err(ref e) => {
            // Neither close_range nor /proc/self/fd is available.
            // Best effort: close up to the system's RLIMIT_NOFILE limit.
            // This is a degraded path — leaked FDs are a minor info leak
            // but not a critical sandbox escape.
            write_err(2, &format!(
                "close_range: /proc/self/fd unavailable ({e}), using RLIMIT_NOFILE fallback"
            ));
            let mut rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            let max_fd = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } == 0 {
                rlim.rlim_cur as RawFd
            } else {
                1024
            };
            for fd in from..max_fd {
                unsafe { libc::close(fd); }
            }
        }
    }
}

/// Set restrictive resource limits for the sandboxed process.
///
/// Policy-driven overrides: `config.max_pids`, `config.max_memory`, and
/// `config.max_fsize` replace the defaults when present. Other limits
/// (open files, locked memory, core dumps, message queues) are always
/// hardcoded — they're not user-facing knobs.
///
/// Limits are best-effort (failures ignored) since seccomp + namespaces
/// are the primary isolation mechanisms. Rlimits provide defense-in-depth.
fn set_rlimits(config: &SandboxConfig) {
    let nproc_soft = config.max_pids.map(u64::from).unwrap_or(64);
    let nproc_hard = nproc_soft.saturating_mul(2);

    let fsize = config.max_fsize.unwrap_or(1024 * 1024 * 1024);

    let as_soft = config.max_memory.unwrap_or(4 * 1024 * 1024 * 1024);
    let as_hard = as_soft.saturating_mul(2);

    let limits: &[(libc::__rlimit_resource_t, u64, u64)] = &[
        // Open files: 1024 soft / 4096 hard — enough for most tools.
        (libc::RLIMIT_NOFILE, 1024, 4096),
        // Locked memory: 64 MiB — prevents mlock-based DoS.
        (libc::RLIMIT_MEMLOCK, 64 * 1024 * 1024, 64 * 1024 * 1024),
        // Core dumps: disabled — no sensitive data leaks via cores.
        (libc::RLIMIT_CORE, 0, 0),
        // Processes: policy-driven (default 64/128).
        (libc::RLIMIT_NPROC, nproc_soft, nproc_hard),
        // File size: policy-driven (default 1 GiB).
        (libc::RLIMIT_FSIZE, fsize, fsize),
        // Address space: policy-driven (default 4G/8G).
        (libc::RLIMIT_AS, as_soft, as_hard),
        // POSIX message queues: disabled — not needed.
        (libc::RLIMIT_MSGQUEUE, 0, 0),
        // CPU time: 2x the wall-clock timeout (or 600s default) as defense-in-depth.
        // The primary timeout mechanism is in the runner/tracer; this is a backstop
        // against CPU spinning that evades wall-clock detection.
        (libc::RLIMIT_CPU, config.max_cpu_time.unwrap_or(600), config.max_cpu_time.unwrap_or(600)),
        // Stack size: 8 MiB (matches default on most distros). Defense-in-depth
        // against stack-smashing exploits that grow the stack to consume memory.
        (libc::RLIMIT_STACK, 8 * 1024 * 1024, 16 * 1024 * 1024),
    ];

    let mut fail_count = 0usize;
    for &(resource, soft, hard) in limits {
        let rlim = libc::rlimit {
            rlim_cur: soft,
            rlim_max: hard,
        };
        let ret = unsafe { libc::setrlimit(resource, &rlim) };
        if ret != 0 {
            fail_count += 1;
            let errno = unsafe { *libc::__errno_location() };
            let _ = unsafe {
                let msg = format!("setrlimit({resource}) failed: errno {errno}\n");
                libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len())
            };
        }
    }

    // If ALL rlimits failed, something is seriously wrong (e.g. seccomp_data
    // race, broken kernel). Abort to avoid running completely uncontained.
    if fail_count == limits.len() {
        let _ = unsafe {
            let msg = b"OAIE: all rlimits failed, aborting sandbox\n";
            libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len())
        };
        unsafe { libc::_exit(126) };
    }
}

/// Set Linux capabilities to only retain the specified subset, dropping all others.
///
/// `retain_mask` is a bitmask of capability bits to keep in the effective and
/// permitted sets. Typically 0 (drop everything). Only CAP_NET_RAW (bit 13)
/// and CAP_NET_BIND_SERVICE (bit 10) are safe to retain — the policy layer
/// validates this. The inheritable set is always zeroed so retained caps don't
/// survive execve chains into grandchildren.
///
/// Returns `true` on success, `false` if capset fails.
fn set_caps(retain_mask: u64) -> bool {
    // Clear ambient capabilities first — these bypass the inheritable check
    // and would let retained caps leak into child processes via execve().
    let ret = unsafe {
        libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
    };
    if ret != 0 {
        return false;
    }

    // We use raw capset() since we don't want to pull in the caps crate.
    /// Linux capability header for capset(2). Matches `struct __user_cap_header_struct`.
    #[repr(C)]
    struct CapHeader {
        /// Capability version (we use _LINUX_CAPABILITY_VERSION_3 = 0x20080522).
        version: u32,
        /// Target process (0 = current process).
        pid: i32,
    }

    /// Linux capability data for capset(2). Matches `struct __user_cap_data_struct`.
    /// Version 3 uses two of these structs (low 32 + high 32 capability bits).
    #[repr(C)]
    struct CapData {
        /// Capabilities the thread can actually use right now.
        effective: u32,
        /// Capabilities the thread is allowed to have (superset of effective).
        permitted: u32,
        /// Capabilities preserved across execve (always 0 to prevent leak).
        inheritable: u32,
    }

    // Split 64-bit mask into low/high 32-bit halves for the v3 capset API.
    let low = (retain_mask & 0xFFFF_FFFF) as u32;
    let high = ((retain_mask >> 32) & 0xFFFF_FFFF) as u32;

    // _LINUX_CAPABILITY_VERSION_3 = 0x20080522, uses 2 CapData structs.
    let header = CapHeader {
        version: 0x2008_0522,
        pid: 0, // current process
    };
    let data = [
        CapData {
            effective: low,
            permitted: low,
            inheritable: 0,
        },
        CapData {
            effective: high,
            permitted: high,
            inheritable: 0,
        },
    ];

    // SAFETY: capset() with a valid v3 header and correctly-sized data array.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &header as *const CapHeader,
            data.as_ptr(),
        )
    };
    ret == 0
}
