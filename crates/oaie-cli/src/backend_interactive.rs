//! Interactive (PTY) execution backend.
//!
//! Spawns commands inside a namespace sandbox with a pseudoterminal,
//! enabling full terminal app support (vim, htop, less, etc.). The
//! supervisor's terminal is put into raw mode and all I/O is forwarded
//! through the PTY master.
//!
//! Output is captured to a file (tee'd from the PTY stream) so the
//! run is still fully recorded. Since the PTY merges stdout and stderr
//! into a single stream, the stderr capture file will be empty.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use oaie_core::cgroup::{CgroupInfo, CgroupLimits, CgroupMode};
use oaie_core::error::{OaieError, Result};
use oaie_core::job::{JobSpec, TraceMode};
use oaie_core::manifest::ResourceInfo;
use oaie_core::policy::{self, NetworkMode};
use oaie_core::run_dir::RunDir;
use oaie_core::run_id::RunId;
use oaie_observe::{ChunkedEventWriter, PtraceTracer};
use oaie_sandbox::sandbox::SandboxConfig;

use crate::backend_namespace::SandboxedResult;
use crate::policy_resolve::ResolvedPolicy;
use crate::runner::{install_signal_handlers, signal_received_since};

/// Monotonic counter incremented by the SIGWINCH handler.
/// The I/O thread checks this to detect terminal resize events.
static SIGWINCH_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Set by the input thread when 3 rapid Ctrl+C presses are detected.
/// Checked by the main thread's waitpid loop to force-kill the child.
static FORCE_KILL_REQUESTED: AtomicBool = AtomicBool::new(false);

/// SIGWINCH handler — only uses async-signal-safe operations.
extern "C" fn sigwinch_handler(_sig: libc::c_int) {
    SIGWINCH_COUNTER.fetch_add(1, Ordering::SeqCst);
}

/// RAII guard that restores the previous SIGWINCH handler on drop.
struct SigwinchGuard {
    old_action: nix::sys::signal::SigAction,
}

impl Drop for SigwinchGuard {
    fn drop(&mut self) {
        // Best-effort restore — nothing useful to do if this fails.
        let _ = unsafe {
            nix::sys::signal::sigaction(
                nix::sys::signal::Signal::SIGWINCH,
                &self.old_action,
            )
        };
    }
}

/// Spawn a command interactively inside a namespace sandbox with PTY support.
///
/// The supervisor's terminal is put into raw mode, keystrokes are forwarded
/// to the PTY master, and PTY output is tee'd to both the terminal and a
/// capture file. SIGWINCH is forwarded so terminal resizes propagate.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_interactive_and_capture(
    job: &JobSpec,
    policy: &ResolvedPolicy,
    run_dir: &RunDir,
    out_dir: &Path,
    run_id: &RunId,
    effective_timeout: Option<Duration>,
    event_writer: Option<ChunkedEventWriter>,
    resolved_trace: &TraceMode,
) -> Result<SandboxedResult> {
    FORCE_KILL_REQUESTED.store(false, Ordering::SeqCst);
    // Reset stale resize events from previous sessions so the input thread
    // doesn't deliver a spurious SIGWINCH to the new child.
    SIGWINCH_COUNTER.store(0, Ordering::SeqCst);

    if job.command.is_empty() {
        return Err(OaieError::InvalidJobSpec("empty command".into()));
    }

    // ── Path resolution (same as backend_namespace) ──

    let input_dir = match &job.inputs {
        Some(p) => p.clone(),
        None => std::env::current_dir()?,
    };
    let input_dir = std::fs::canonicalize(&input_dir)?;
    let out_dir_canon = std::fs::canonicalize(out_dir)?;

    let canonicalize_extra =
        |paths: &[std::path::PathBuf], label: &str| -> Result<Vec<std::path::PathBuf>> {
            let denied = ["/proc", "/sys", "/dev", "/boot", "/root", "/etc", "/var/run"];
            paths
                .iter()
                .map(|p| {
                    let canon = std::fs::canonicalize(p)?;
                    for prefix in &denied {
                        if canon.starts_with(prefix) {
                            return Err(OaieError::SandboxError(format!(
                                "refusing to mount {label} path {}: sensitive path",
                                canon.display()
                            )));
                        }
                    }
                    Ok(canon)
                })
                .collect()
        };

    let extra_ro = canonicalize_extra(&policy.ro_mounts, "--ro")?;
    let extra_rw = canonicalize_extra(&policy.rw_mounts, "--rw")?;

    // ── Build sandbox config ──

    let cpu_time_limit = effective_timeout.map(|t| t.as_secs().saturating_mul(2).max(60));
    let config = SandboxConfig {
        input_dir,
        output_dir: out_dir_canon,
        extra_ro,
        extra_rw,
        network: policy.network.clone(),
        proc_mount: true,
        max_pids: Some(policy.max_pids),
        max_memory: Some(policy.max_memory),
        max_fsize: Some(policy.max_fsize),
        allow_memfd: policy.allow_memfd,
        retain_caps: policy.retain_caps,
        max_cpu_time: cpu_time_limit,
        interactive: true,
        pty_slave_path: None, // Set internally by spawn_sandboxed_interactive.
        session_mounts: vec![],
    };

    let env_vars = vec![
        ("OAIE_RUN_ID".into(), run_id.full()),
        ("OAIE_OUT".into(), "/out".into()),
    ];

    // ── Cgroup scope creation (same as backend_namespace) ──

    let mut cgroup_scope: Option<oaie_cgroup::scope::CgroupScope> = None;
    let mut cgroup_limits_applied = oaie_cgroup::limits::LimitsApplied::default();

    if policy.cgroup_mode != CgroupMode::Off {
        let caps = oaie_cgroup::detect::detect();
        if caps.systemd_run {
            match oaie_cgroup::scope::CgroupScope::create_systemd(run_id) {
                Ok(scope) => {
                    let limits = CgroupLimits {
                        memory_max: Some(policy.max_memory),
                        pids_max: Some(policy.max_pids),
                        cpu_quota_us: policy.cpu_quota.map(|(q, _)| q),
                        cpu_period_us: policy.cpu_quota.map(|(_, p)| p),
                    };
                    cgroup_limits_applied =
                        oaie_cgroup::limits::apply_limits(&scope.path, &limits);
                    cgroup_scope = Some(scope);
                }
                Err(e) => {
                    if policy.cgroup_mode == CgroupMode::Require {
                        return Err(e);
                    }
                    oaie_core::log_warn!(
                        "cgroup scope creation failed (falling back to rlimits): {e}"
                    );
                }
            }
        } else if caps.oaie_priv {
            let limits = CgroupLimits {
                memory_max: Some(policy.max_memory),
                pids_max: Some(policy.max_pids),
                cpu_quota_us: policy.cpu_quota.map(|(q, _)| q),
                cpu_period_us: policy.cpu_quota.map(|(_, p)| p),
            };
            match oaie_cgroup::scope::CgroupScope::create_via_priv(run_id, &limits) {
                Ok(scope) => {
                    cgroup_limits_applied = oaie_cgroup::limits::LimitsApplied {
                        memory: limits.memory_max.is_some(),
                        swap: limits.memory_max.is_some(),
                        pids: limits.pids_max.is_some(),
                        cpu: limits.cpu_quota_us.is_some(),
                    };
                    cgroup_scope = Some(scope);
                }
                Err(e) => {
                    if policy.cgroup_mode == CgroupMode::Require {
                        return Err(e);
                    }
                    oaie_core::log_warn!(
                        "oaie-priv cgroup creation failed (falling back to rlimits): {e}"
                    );
                }
            }
        } else if policy.cgroup_mode == CgroupMode::Require {
            return Err(OaieError::SandboxError(
                "cgroup isolation required but no creation method available".into(),
            ));
        }
    }

    // ── Post-map hook (cgroup + netpol) ──

    let cgroup_enforced = cgroup_limits_applied.any_enforced();
    let netpol_rules = if let NetworkMode::Allowlist(ref rules) = policy.network {
        Some(rules.clone())
    } else {
        None
    };
    let run_id_short = run_id.short();

    use std::sync::{Arc, Mutex};
    let netpol_handle: Arc<Mutex<Option<oaie_netpol::enforcer::NetworkEnforcement>>> =
        Arc::new(Mutex::new(None));
    let netpol_handle_clone = Arc::clone(&netpol_handle);

    let cgroup_procs_path = cgroup_scope.as_ref().map(|s| s.path.join("cgroup.procs"));

    let post_map_hook: Option<Box<dyn FnOnce(nix::unistd::Pid) -> Result<()>>> = {
        let has_cgroup = cgroup_procs_path.is_some();
        let has_netpol = netpol_rules.is_some();

        if has_cgroup || has_netpol {
            Some(Box::new(move |pid: nix::unistd::Pid| {
                if let Some(ref procs_path) = cgroup_procs_path {
                    std::fs::write(procs_path, format!("{}\n", pid.as_raw())).map_err(|e| {
                        OaieError::SandboxError(format!(
                            "failed to assign PID {} to cgroup: {e}",
                            pid
                        ))
                    })?;
                }
                if let Some(ref rules) = netpol_rules {
                    let enforcement = oaie_netpol::enforcer::enforce_allowlist(
                        pid,
                        rules,
                        &run_id_short,
                    )?;
                    *netpol_handle_clone.lock().unwrap() = Some(enforcement);
                }
                Ok(())
            }))
        } else {
            None
        }
    };

    // ── Spawn interactive child ──

    let use_ptrace = event_writer.is_some() && !matches!(resolved_trace, TraceMode::Ebpf);
    let mut child = oaie_sandbox::sandbox::spawn_sandboxed_interactive(
        &config,
        &job.command,
        &env_vars,
        use_ptrace,
        post_map_hook,
    )?;
    let pid = child.pid;

    // Kill cgroup holder now that sandbox PID is in the cgroup.
    if let Some(ref mut scope) = cgroup_scope {
        scope.assign_pid(pid.as_raw()).ok();
    }

    // Take ownership of the PTY master. Keep `child` alive (not mark_reaped)
    // so its Drop will kill+wait the child if we return early due to error.
    // On success paths (after waitpid), the child is already reaped so the
    // double kill+wait in Drop is harmless (ESRCH/ECHILD, both ignored).
    let pty_master = child.take_pty_master().ok_or_else(|| {
        OaieError::SandboxError("sandbox child PTY master already taken".into())
    })?;

    // ── Signal handling ──

    let signal_baseline = install_signal_handlers();

    // Install SIGWINCH handler for terminal resize forwarding.
    // No SA_RESTART: read() returns EINTR on resize, letting the input thread
    // immediately check the counter and forward the new window size.
    let sigwinch_baseline = SIGWINCH_COUNTER.load(Ordering::SeqCst);
    let _sigwinch_guard = {
        use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
        let action = SigAction::new(
            SigHandler::Handler(sigwinch_handler),
            SaFlags::empty(),
            SigSet::empty(),
        );
        let old = unsafe { sigaction(Signal::SIGWINCH, &action) }
            .map_err(|e| OaieError::SandboxError(format!("sigaction SIGWINCH: {e}")))?;
        SigwinchGuard { old_action: old }
    };

    // ── Set up PTY I/O ──

    // Enter raw mode on the supervisor's terminal (skip if stdin isn't a TTY,
    // e.g. when running under test harness or piped input).
    let stdin_is_tty = unsafe { libc::isatty(0) } == 1;
    let _raw_guard = if stdin_is_tty {
        Some(oaie_sandbox::terminal::enter_raw_mode(0)?)
    } else {
        None
    };

    // Copy initial window size to PTY master.
    let (rows, cols) = oaie_sandbox::terminal::get_window_size(0);
    let master_fd = pty_master.as_raw_fd();
    let _ = oaie_sandbox::pty::set_window_size(master_fd, rows, cols);

    // Create capture file for stdout (PTY output includes both stdout+stderr).
    let stdout_capture = File::create(run_dir.stdout_path())?;
    // Create empty stderr capture (PTY merges both streams).
    File::create(run_dir.stderr_path())?;

    // Re-sample start time.
    let start = Instant::now();

    // Clone the PTY master fd for the I/O threads.
    let master_for_output = pty_master.try_clone()?;
    let master_for_input = pty_master.try_clone()?;

    // Track SIGWINCH baseline in the input thread.
    let sigwinch_baseline_for_input = sigwinch_baseline;
    // Use the input thread's clone fd for SIGWINCH (not the original pty_master —
    // the original is kept alive by the main thread, but the input thread should
    // use its own clone's fd since it controls that clone's lifetime).
    let master_fd_for_winch = master_for_input.as_raw_fd();

    // Keep pty_master alive for the main thread's SIGWINCH forwarding fallback.
    // When the child exits, the slave closes — reads on any master clone return
    // EIO, which naturally terminates the output thread.
    let master_fd_for_main = pty_master.as_raw_fd();
    let mut main_last_winch = sigwinch_baseline;

    // ── Spawn I/O threads ──

    // Input thread: supervisor stdin → PTY master.
    // Uses poll() on stdin with a short timeout so we don't block forever
    // after the child exits — without poll, stdin.read() would hang until
    // the user presses a key, leaving the terminal in raw mode.
    let input_handle = std::thread::spawn(move || -> Result<()> {
        let mut master = master_for_input;
        let mut buf = [0u8; 4096];
        let mut last_winch = sigwinch_baseline_for_input;

        // Track rapid Ctrl+C presses (3 within 2 seconds → force-kill).
        let mut ctrl_c_times: Vec<Instant> = Vec::new();
        let ctrl_c_window = Duration::from_secs(2);

        loop {
            // Check for SIGWINCH — forward terminal size changes.
            let current_winch = SIGWINCH_COUNTER.load(Ordering::Acquire);
            if current_winch > last_winch {
                last_winch = current_winch;
                let (rows, cols) = oaie_sandbox::terminal::get_window_size(0);
                let _ = oaie_sandbox::pty::set_window_size(master_fd_for_winch, rows, cols);
            }

            // Poll stdin for readability AND the PTY master for hangup with a
            // 100ms timeout. POLLHUP on the master means the slave closed (child
            // exited). We must poll the master explicitly because zero-length
            // writes (the previous approach) are short-circuited by tty_write()
            // and never return EIO.
            let mut pfds = [
                libc::pollfd {
                    fd: libc::STDIN_FILENO,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: master_fd_for_winch,
                    events: 0, // POLLHUP/POLLERR are always reported
                    revents: 0,
                },
            ];
            let poll_ret = unsafe { libc::poll(pfds.as_mut_ptr(), 2, 100) };
            if poll_ret < 0 {
                // EINTR from signal — loop back to check SIGWINCH counter.
                continue;
            }
            // PTY slave closed — child exited.
            if pfds[1].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                break;
            }
            if poll_ret == 0 {
                continue; // Timeout, no events on either fd.
            }

            // stdin is readable (or POLLHUP/POLLERR) — read it.
            let n = {
                let mut stdin = io::stdin();
                match stdin.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            };

            // Detect rapid Ctrl+C (byte 0x03) for emergency exit.
            // First two presses are forwarded normally; on the 3rd the flag is
            // set and the main thread's waitpid loop kills the child.
            let mut force_kill = false;
            for &byte in &buf[..n] {
                if byte == 0x03 {
                    let now = Instant::now();
                    ctrl_c_times.retain(|t| now.duration_since(*t) < ctrl_c_window);
                    ctrl_c_times.push(now);

                    if ctrl_c_times.len() == 1 {
                        let _ = io::stderr().write_all(
                            b"\r\n[press Ctrl+C 2 more times to force-exit]\r\n",
                        );
                    }
                    if ctrl_c_times.len() >= 3 {
                        FORCE_KILL_REQUESTED.store(true, Ordering::SeqCst);
                        force_kill = true;
                        break;
                    }
                }
            }
            if force_kill {
                break;
            }

            if master.write_all(&buf[..n]).is_err() {
                break; // PTY closed (child exited).
            }
        }
        Ok(())
    });

    // Output thread: PTY master → supervisor stdout + capture file.
    let output_handle = std::thread::spawn(move || -> Result<()> {
        let mut master = master_for_output;
        let mut capture = stdout_capture;
        let mut stdout = io::stdout();
        let mut buf = [0u8; 8192];

        loop {
            let n = match master.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(ref e) if e.raw_os_error() == Some(libc::EIO) => {
                    // EIO on PTY master means the slave was closed (child exited).
                    break;
                }
                Err(e) => return Err(e.into()),
            };

            capture.write_all(&buf[..n])?;
            // Ignore terminal write errors.
            let _ = stdout.write_all(&buf[..n]);
            let _ = stdout.flush();
        }
        capture.sync_all()?;
        Ok(())
    });

    // ── Helper closures (same pattern as backend_namespace) ──

    let collect_cgroup_result =
        |scope: &Option<oaie_cgroup::scope::CgroupScope>| -> (Option<CgroupInfo>, Option<ResourceInfo>) {
            let scope = match scope {
                Some(ref s) => s,
                None => return (None, None),
            };

            let stats = oaie_cgroup::stats::collect_stats(&scope.path);

            let cgroup_info = CgroupInfo {
                name: scope
                    .unit_name
                    .clone()
                    .unwrap_or_else(|| scope.path.display().to_string()),
                method: scope.method.clone(),
                enforced: cgroup_enforced,
            };

            let resources = ResourceInfo {
                memory_limit: stats.memory_limit.map(policy::format_size_human),
                memory_peak: stats.memory_peak.map(policy::format_size_human),
                cpu_user_ms: stats.cpu_user_us.map(|us| us / 1000),
                cpu_system_ms: stats.cpu_system_us.map(|us| us / 1000),
                pids_peak: stats.pids_current,
            };

            (Some(cgroup_info), Some(resources))
        };

    let build_result =
        |exit_code: i32,
         duration: Duration,
         writer: Option<ChunkedEventWriter>,
         dropped_events: u64|
         -> SandboxedResult {
            let (cgroup_info, resources) = collect_cgroup_result(&cgroup_scope);
            let network_enforcement = netpol_handle.lock().unwrap().take();
            if let Some(ref ne) = network_enforcement {
                let _ = oaie_netpol::enforcer::cleanup(ne);
            }

            SandboxedResult {
                exit_code,
                duration,
                event_writer: writer,
                cgroup_info,
                resources,
                cgroup_enforced,
                dropped_events,
                network_enforcement,
            }
        };

    // ── Ptrace traced execution path ──
    if let Some(writer) = event_writer {
        let tracer = PtraceTracer::new(pid, writer, effective_timeout);
        match tracer.run() {
            Ok((exit_code, writer, _io_uring)) => {
                let _ = input_handle.join();
                let _ = output_handle.join();
                return Ok(build_result(exit_code, start.elapsed(), Some(writer), 0));
            }
            Err(e) => {
                let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
                let _ = nix::sys::wait::waitpid(pid, None);
                let _ = input_handle.join();
                let _ = output_handle.join();
                return Err(OaieError::SandboxError(format!("ptrace tracer: {e}")));
            }
        }
    }

    // ── Normal (non-traced) execution path ──

    use nix::sys::signal;
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};

    if let Some(timeout) = effective_timeout {
        let deadline = Instant::now() + timeout;
        loop {
            match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(_, code)) => {
                    let _ = input_handle.join();
                    let _ = output_handle.join();
                    return Ok(build_result(code, start.elapsed(), None, 0));
                }
                Ok(WaitStatus::Signaled(_, sig, _)) => {
                    let _ = input_handle.join();
                    let _ = output_handle.join();
                    return Ok(build_result(-(sig as i32), start.elapsed(), None, 0));
                }
                Ok(WaitStatus::StillAlive) => {}
                Ok(_) => {}
                Err(nix::errno::Errno::ECHILD) => {
                    let _ = input_handle.join();
                    let _ = output_handle.join();
                    return Ok(build_result(-1, start.elapsed(), None, 0));
                }
                Err(e) => {
                    let _ = input_handle.join();
                    let _ = output_handle.join();
                    return Err(OaieError::SandboxError(format!("waitpid: {e}")));
                }
            }

            if Instant::now() >= deadline
                || signal_received_since(signal_baseline)
                || FORCE_KILL_REQUESTED.load(Ordering::Acquire)
            {
                let _ = signal::kill(pid, signal::Signal::SIGKILL);
                let _ = waitpid(pid, None);
                let _ = input_handle.join();
                let _ = output_handle.join();
                if signal_received_since(signal_baseline)
                    || FORCE_KILL_REQUESTED.load(Ordering::Acquire)
                {
                    return Ok(build_result(-1, start.elapsed(), None, 0));
                }
                return Err(OaieError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("command timed out after {:.1}s", timeout.as_secs_f64()),
                )));
            }

            // Fallback SIGWINCH forwarding — in case the signal was delivered
            // to the main thread instead of the input thread.
            let w = SIGWINCH_COUNTER.load(Ordering::Acquire);
            if w > main_last_winch {
                main_last_winch = w;
                let (rows, cols) = oaie_sandbox::terminal::get_window_size(0);
                let _ = oaie_sandbox::pty::set_window_size(master_fd_for_main, rows, cols);
            }

            std::thread::sleep(Duration::from_millis(1));
        }
    } else {
        // No timeout — wait with signal awareness.
        loop {
            match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(_, code)) => {
                    let _ = input_handle.join();
                    let _ = output_handle.join();
                    return Ok(build_result(code, start.elapsed(), None, 0));
                }
                Ok(WaitStatus::Signaled(_, sig, _)) => {
                    let _ = input_handle.join();
                    let _ = output_handle.join();
                    return Ok(build_result(-(sig as i32), start.elapsed(), None, 0));
                }
                Ok(WaitStatus::StillAlive) => {}
                Ok(_) => {}
                Err(nix::errno::Errno::ECHILD) => {
                    let _ = input_handle.join();
                    let _ = output_handle.join();
                    return Ok(build_result(-1, start.elapsed(), None, 0));
                }
                Err(e) => {
                    let _ = input_handle.join();
                    let _ = output_handle.join();
                    return Err(OaieError::SandboxError(format!("waitpid: {e}")));
                }
            }

            if signal_received_since(signal_baseline)
                || FORCE_KILL_REQUESTED.load(Ordering::Acquire)
            {
                let _ = signal::kill(pid, signal::Signal::SIGTERM);
                let kill_deadline = Instant::now() + Duration::from_secs(3);
                loop {
                    match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                        Ok(WaitStatus::StillAlive) if Instant::now() < kill_deadline => {
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        Ok(WaitStatus::Exited(_, code)) => {
                            let _ = input_handle.join();
                            let _ = output_handle.join();
                            return Ok(build_result(code, start.elapsed(), None, 0));
                        }
                        _ => {
                            let _ = signal::kill(pid, signal::Signal::SIGKILL);
                            let _ = waitpid(pid, None);
                            let _ = input_handle.join();
                            let _ = output_handle.join();
                            return Ok(build_result(-1, start.elapsed(), None, 0));
                        }
                    }
                }
            }

            // Fallback SIGWINCH forwarding (same as timeout loop above).
            let w = SIGWINCH_COUNTER.load(Ordering::Acquire);
            if w > main_last_winch {
                main_last_winch = w;
                let (rows, cols) = oaie_sandbox::terminal::get_window_size(0);
                let _ = oaie_sandbox::pty::set_window_size(master_fd_for_main, rows, cols);
            }

            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
