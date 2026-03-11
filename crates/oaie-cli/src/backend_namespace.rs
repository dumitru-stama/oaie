//! Namespace isolation backend.
//!
//! Executes commands inside Linux namespace sandboxes with optional ptrace
//! or eBPF tracing. This module contains the sandbox lifecycle management:
//! namespace setup, cgroup scope creation, BPF pre-loading, tee threads,
//! waitpid loops, and signal handling.
//!
//! Extracted from `runner.rs` (Step 6 of Phase F plan) to keep backend-specific
//! logic separate from the backend-agnostic execution pipeline.

use std::fs::File;
use std::io;
use std::path::Path;
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

use crate::policy_resolve::ResolvedPolicy;
use crate::runner::{
    check_tee_thread, install_signal_handlers, signal_received_since, tee_to_file_and_terminal,
    tee_to_file_only,
};

/// Result of the sandboxed execution phase, including cgroup accounting.
pub(crate) struct SandboxedResult {
    pub exit_code: i32,
    pub duration: Duration,
    pub event_writer: Option<ChunkedEventWriter>,
    /// Cgroup resource info for the manifest.
    pub cgroup_info: Option<CgroupInfo>,
    /// Resource accounting from cgroup stats.
    pub resources: Option<ResourceInfo>,
    /// Whether cgroup limits were enforced.
    pub cgroup_enforced: bool,
    /// Number of events dropped by the eBPF ring buffer (0 for ptrace).
    pub dropped_events: u64,
    /// Network enforcement state for cleanup (allowlist mode only).
    /// Currently consumed by build_result for cleanup; will be surfaced
    /// to runner for report/inspect integration in later phases.
    #[allow(dead_code)]
    pub network_enforcement: Option<oaie_netpol::enforcer::NetworkEnforcement>,
}

/// Spawn the command inside a namespace sandbox, tee stdout/stderr to files
/// (and optionally terminal), wait with optional timeout, handle signals.
///
/// When `event_writer` is Some (tracing enabled), the child calls
/// `ptrace::traceme()` before exec and we run the PtraceTracer loop
/// instead of the normal polling waitpid.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_sandboxed_and_capture(
    job: &JobSpec,
    policy: &ResolvedPolicy,
    run_dir: &RunDir,
    out_dir: &Path,
    run_id: &RunId,
    effective_timeout: Option<Duration>,
    quiet: bool,
    event_writer: Option<ChunkedEventWriter>,
    resolved_trace: &TraceMode,
) -> Result<SandboxedResult> {
    if job.command.is_empty() {
        return Err(OaieError::InvalidJobSpec("empty command".into()));
    }

    // Resolve the input directory (default: cwd).
    let input_dir = match &job.inputs {
        Some(p) => p.clone(),
        None => std::env::current_dir()?,
    };

    // Canonicalize both dirs so bind mounts work.
    let input_dir = std::fs::canonicalize(&input_dir)?;
    let out_dir_canon = std::fs::canonicalize(out_dir)?;

    // Canonicalize extra mount paths and reject sensitive system targets.
    // These are non-overridable system-level checks — policy deny validation
    // happens inside resolve_policy() using the same policy load.
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

    // Build sandbox config from resolved policy.
    // CPU time backstop: 2× the wall-clock timeout so CPU-intensive tools
    // aren't killed by RLIMIT_CPU before their wall-clock deadline.
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
        interactive: false,
        pty_slave_path: None,
        session_mounts: vec![],
    };

    let env_vars = vec![
        ("OAIE_RUN_ID".into(), run_id.full()),
        ("OAIE_OUT".into(), "/out".into()),
    ];

    // ── Cgroup scope creation ──
    // Try to create a cgroup scope for per-run resource isolation.
    // The scope is created before spawning so we can assign the child PID
    // via the post_map_hook before it starts executing.
    let mut cgroup_scope: Option<oaie_cgroup::scope::CgroupScope> = None;
    let mut cgroup_limits_applied = oaie_cgroup::limits::LimitsApplied::default();

    if policy.cgroup_mode != CgroupMode::Off {
        let caps = oaie_cgroup::detect::detect();
        if caps.systemd_run {
            match oaie_cgroup::scope::CgroupScope::create_systemd(run_id) {
                Ok(scope) => {
                    // Build and apply cgroup limits.
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
                    // Limits are applied by oaie-priv during creation.
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
                "cgroup isolation required but no creation method available \
                 (neither systemd-run nor oaie-priv found). \
                 Use --cgroup=auto or --cgroup=off to proceed without cgroups."
                    .into(),
            ));
        }
    }

    // ── Pre-load eBPF programs before spawning child ──
    // BPF must be attached to tracepoints BEFORE the child execs so events
    // are captured from the very start. Events accumulate in the kernel
    // ring buffer until the consumer thread starts polling.
    #[cfg(feature = "ebpf")]
    let ebpf_bpf_fds: Option<oaie_cgroup::bpf_client::BpfFds> = {
        if matches!(resolved_trace, TraceMode::Ebpf) {
            if let Some(ref scope) = cgroup_scope {
                let cgroup_id = oaie_cgroup::bpf_client::cgroup_id_from_path(&scope.path)?;
                Some(oaie_cgroup::bpf_client::load_bpf(cgroup_id, 1_048_576)?)
            } else {
                None
            }
        } else {
            None
        }
    };

    // Build the post_map_hook to assign the child PID to the cgroup scope
    // and enforce network allowlist rules (if applicable).
    let cgroup_enforced = cgroup_limits_applied.any_enforced();

    // Pre-resolve DNS for allowlist rules on the host side before spawning.
    let netpol_rules = if let NetworkMode::Allowlist(ref rules) = policy.network {
        Some(rules.clone())
    } else {
        None
    };
    let run_id_short = run_id.short();

    // Shared cell to pass the NetworkEnforcement handle out of the hook closure.
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
                // Step 1: Assign to cgroup (if available).
                if let Some(ref procs_path) = cgroup_procs_path {
                    std::fs::write(procs_path, format!("{}\n", pid.as_raw())).map_err(|e| {
                        OaieError::SandboxError(format!(
                            "failed to assign PID {} to cgroup: {e}",
                            pid
                        ))
                    })?;
                }

                // Step 2: Enforce network allowlist (if applicable).
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

    // eBPF tracing doesn't use ptrace — the child runs freely while
    // BPF programs observe from the kernel. Only ptrace needs trace_enabled=true.
    let use_ptrace = event_writer.is_some() && !matches!(resolved_trace, TraceMode::Ebpf);
    let mut child = oaie_sandbox::sandbox::spawn_sandboxed(
        &config,
        &job.command,
        &env_vars,
        use_ptrace,
        post_map_hook,
    )?;
    let pid = child.pid;

    // Kill the holder process now that the sandbox PID is in the cgroup.
    // The scope stays alive because the sandbox PID keeps it populated.
    // This avoids leaving an unnecessary sleep process running throughout
    // the sandbox execution and speeds up scope cleanup on Drop.
    if let Some(ref mut scope) = cgroup_scope {
        scope.assign_pid(pid.as_raw()).ok(); // PID already written by hook; this kills the holder.
    }

    // Take ownership of pipes and mark the child as reaped: from here on,
    // all wait/kill logic uses the raw `pid` and the function handles
    // process lifecycle on all return paths (including error/timeout/signal).
    let child_stdout = child.take_stdout().ok_or_else(|| {
        OaieError::SandboxError("sandbox child stdout already taken".into())
    })?;
    let child_stderr = child.take_stderr().ok_or_else(|| {
        OaieError::SandboxError("sandbox child stderr already taken".into())
    })?;
    child.mark_reaped(); // This function manages kill+wait; Drop should not double-wait.

    // Set up signal handling: catch SIGINT and SIGTERM.
    let signal_baseline = install_signal_handlers();

    // Spawn tee threads for stdout and stderr.
    let stdout_file = File::create(run_dir.stdout_path())?;
    let stderr_file = File::create(run_dir.stderr_path())?;

    let stdout_handle = if quiet {
        std::thread::spawn(move || tee_to_file_only(child_stdout, stdout_file))
    } else {
        std::thread::spawn(move || {
            tee_to_file_and_terminal(child_stdout, stdout_file, io::stdout())
        })
    };

    let stderr_handle = if quiet {
        std::thread::spawn(move || tee_to_file_only(child_stderr, stderr_file))
    } else {
        std::thread::spawn(move || {
            tee_to_file_and_terminal(child_stderr, stderr_file, io::stderr())
        })
    };

    // Re-sample start time now that the child is spawned and tee threads are
    // running. This excludes sandbox setup (namespace, mounts, exec) from the
    // reported duration, giving an accurate wall-clock of the actual command.
    let start = Instant::now();

    // Helper to collect cgroup stats and build cgroup info for the manifest.
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

    // Helper to build a SandboxedResult from exit code, duration, and optional writer.
    let build_result =
        |exit_code: i32,
         duration: Duration,
         writer: Option<ChunkedEventWriter>,
         dropped_events: u64|
         -> SandboxedResult {
            let (cgroup_info, resources) = collect_cgroup_result(&cgroup_scope);

            // Extract the network enforcement handle for cleanup by the caller.
            let network_enforcement = netpol_handle.lock().unwrap().take();

            // Best-effort cleanup of network policy resources.
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

    // ── eBPF traced execution path ──
    // BPF programs were pre-loaded before spawn (above). The consumer thread
    // polls the ring buffer while the normal waitpid loop handles lifecycle.
    #[cfg(feature = "ebpf")]
    if matches!(resolved_trace, TraceMode::Ebpf) {
        if let Some(writer) = event_writer {
            let bpf_fds = ebpf_bpf_fds.ok_or_else(|| {
                OaieError::SandboxError("eBPF tracing requires cgroup isolation".into())
            })?;
            return run_with_ebpf_tracing(
                pid,
                writer,
                bpf_fds,
                effective_timeout,
                signal_baseline,
                stdout_handle,
                stderr_handle,
                start,
                build_result,
            );
        }
    }

    // ── Ptrace traced execution path: PtraceTracer takes over the wait loop ──
    if let Some(writer) = event_writer {
        let tracer = PtraceTracer::new(pid, writer, effective_timeout);
        match tracer.run() {
            Ok((exit_code, writer, _io_uring)) => {
                check_tee_thread(stdout_handle, "stdout")?;
                check_tee_thread(stderr_handle, "stderr")?;
                return Ok(build_result(exit_code, start.elapsed(), Some(writer), 0));
            }
            Err(e) => {
                // Kill any remaining traced processes.
                let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
                let _ = nix::sys::wait::waitpid(pid, None);
                let _ = stdout_handle.join();
                let _ = stderr_handle.join();
                return Err(OaieError::SandboxError(format!("ptrace tracer: {e}")));
            }
        }
    }

    // ── Normal (non-traced) execution path: poll with sleep(1ms) ──
    //
    // NOTE: signalfd was tried here but is fundamentally broken in
    // multi-threaded environments (like cargo test). pthread_sigmask only
    // blocks SIGCHLD on the calling thread; other threads can still receive
    // it, so the signalfd never wakes up. The 1ms sleep is fine — the
    // real CPU burner was the ptrace tracer's 100μs loop (fixed via
    // signalfd there, in a dedicated single-threaded context).
    use nix::sys::signal;
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};

    if let Some(timeout) = effective_timeout {
        let deadline = Instant::now() + timeout;
        loop {
            match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(_, code)) => {
                    check_tee_thread(stdout_handle, "stdout")?;
                    check_tee_thread(stderr_handle, "stderr")?;
                    return Ok(build_result(code, start.elapsed(), None, 0));
                }
                Ok(WaitStatus::Signaled(_, sig, _)) => {
                    check_tee_thread(stdout_handle, "stdout")?;
                    check_tee_thread(stderr_handle, "stderr")?;
                    return Ok(build_result(-(sig as i32), start.elapsed(), None, 0));
                }
                Ok(WaitStatus::StillAlive) => {}
                Ok(_) => {} // other states, keep waiting
                Err(nix::errno::Errno::ECHILD) => {
                    check_tee_thread(stdout_handle, "stdout")?;
                    check_tee_thread(stderr_handle, "stderr")?;
                    return Ok(build_result(-1, start.elapsed(), None, 0));
                }
                Err(e) => {
                    return Err(OaieError::SandboxError(format!("waitpid: {e}")));
                }
            }

            if Instant::now() >= deadline || signal_received_since(signal_baseline) {
                let _ = signal::kill(pid, signal::Signal::SIGKILL);
                let _ = waitpid(pid, None);
                // Timeout/interrupt path: best-effort tee cleanup.
                let _ = stdout_handle.join();
                let _ = stderr_handle.join();
                if signal_received_since(signal_baseline) {
                    return Ok(build_result(-1, start.elapsed(), None, 0));
                }
                return Err(OaieError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("command timed out after {:.1}s", timeout.as_secs_f64()),
                )));
            }

            std::thread::sleep(Duration::from_millis(1));
        }
    } else {
        // No timeout — wait with signal awareness.
        loop {
            match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(_, code)) => {
                    check_tee_thread(stdout_handle, "stdout")?;
                    check_tee_thread(stderr_handle, "stderr")?;
                    return Ok(build_result(code, start.elapsed(), None, 0));
                }
                Ok(WaitStatus::Signaled(_, sig, _)) => {
                    check_tee_thread(stdout_handle, "stdout")?;
                    check_tee_thread(stderr_handle, "stderr")?;
                    return Ok(build_result(-(sig as i32), start.elapsed(), None, 0));
                }
                Ok(WaitStatus::StillAlive) => {}
                Ok(_) => {}
                Err(nix::errno::Errno::ECHILD) => {
                    check_tee_thread(stdout_handle, "stdout")?;
                    check_tee_thread(stderr_handle, "stderr")?;
                    return Ok(build_result(-1, start.elapsed(), None, 0));
                }
                Err(e) => {
                    return Err(OaieError::SandboxError(format!("waitpid: {e}")));
                }
            }

            if signal_received_since(signal_baseline) {
                let _ = signal::kill(pid, signal::Signal::SIGTERM);
                let kill_deadline = Instant::now() + Duration::from_secs(3);
                loop {
                    match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                        Ok(WaitStatus::StillAlive) if Instant::now() < kill_deadline => {
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        Ok(WaitStatus::Exited(_, code)) => {
                            // Interrupt path: best-effort tee cleanup.
                            let _ = stdout_handle.join();
                            let _ = stderr_handle.join();
                            return Ok(build_result(code, start.elapsed(), None, 0));
                        }
                        _ => {
                            let _ = signal::kill(pid, signal::Signal::SIGKILL);
                            let _ = waitpid(pid, None);
                            // Kill path: best-effort tee cleanup.
                            let _ = stdout_handle.join();
                            let _ = stderr_handle.join();
                            return Ok(build_result(-1, start.elapsed(), None, 0));
                        }
                    }
                }
            }

            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// eBPF tracing execution path.
///
/// BPF programs are already loaded and attached (pre-loaded before spawn to
/// eliminate the race where early events were missed). This function creates
/// the consumer thread, runs the waitpid loop, then stops the consumer and
/// collects results.
#[cfg(feature = "ebpf")]
#[allow(clippy::too_many_arguments)]
fn run_with_ebpf_tracing(
    pid: nix::unistd::Pid,
    writer: ChunkedEventWriter,
    mut bpf_fds: oaie_cgroup::bpf_client::BpfFds,
    effective_timeout: Option<Duration>,
    signal_baseline: u64,
    stdout_handle: std::thread::JoinHandle<Result<()>>,
    stderr_handle: std::thread::JoinHandle<Result<()>>,
    start: Instant,
    build_result: impl FnOnce(i32, Duration, Option<ChunkedEventWriter>, u64) -> SandboxedResult,
) -> Result<SandboxedResult> {
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};

    // Create the eBPF tracer and spawn the consumer thread.
    let tracer = oaie_observe::EbpfTracer::new(
        bpf_fds.ring_buffer_fd,
        bpf_fds.link_fds.clone(),
        writer,
    );
    let stop_handle = tracer.stop_handle();
    let consumer_thread = std::thread::spawn(move || tracer.run());

    // Normal waitpid loop with timeout and signal awareness.
    let exit_code;
    if let Some(timeout) = effective_timeout {
        let deadline = Instant::now() + timeout;
        loop {
            match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(_, code)) => {
                    exit_code = code;
                    break;
                }
                Ok(WaitStatus::Signaled(_, sig, _)) => {
                    exit_code = -(sig as i32);
                    break;
                }
                Ok(WaitStatus::StillAlive) => {}
                Ok(_) => {}
                Err(nix::errno::Errno::ECHILD) => {
                    exit_code = -1;
                    break;
                }
                Err(e) => {
                    stop_handle.store(true, std::sync::atomic::Ordering::Relaxed);
                    let _ = consumer_thread.join();
                    let _ = oaie_cgroup::bpf_client::unload_bpf(&mut bpf_fds);
                    return Err(OaieError::SandboxError(format!("waitpid: {e}")));
                }
            }

            if Instant::now() >= deadline || signal_received_since(signal_baseline) {
                // Graceful shutdown: SIGTERM first, then SIGKILL after 3s grace.
                exit_code = graceful_kill_ebpf(pid);
                break;
            }

            std::thread::sleep(Duration::from_millis(1));
        }
    } else {
        loop {
            match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(_, code)) => {
                    exit_code = code;
                    break;
                }
                Ok(WaitStatus::Signaled(_, sig, _)) => {
                    exit_code = -(sig as i32);
                    break;
                }
                Ok(WaitStatus::StillAlive) => {}
                Ok(_) => {}
                Err(nix::errno::Errno::ECHILD) => {
                    exit_code = -1;
                    break;
                }
                Err(e) => {
                    stop_handle.store(true, std::sync::atomic::Ordering::Relaxed);
                    let _ = consumer_thread.join();
                    let _ = oaie_cgroup::bpf_client::unload_bpf(&mut bpf_fds);
                    return Err(OaieError::SandboxError(format!("waitpid: {e}")));
                }
            }

            if signal_received_since(signal_baseline) {
                // Graceful shutdown: SIGTERM first, then SIGKILL after 3s grace.
                exit_code = graceful_kill_ebpf(pid);
                break;
            }

            std::thread::sleep(Duration::from_millis(1));
        }
    }

    // Stop the eBPF consumer thread and collect results.
    stop_handle.store(true, std::sync::atomic::Ordering::Relaxed);

    let (writer, dropped) = consumer_thread
        .join()
        .map_err(|_| OaieError::SandboxError("eBPF consumer thread panicked".into()))?
        .map_err(|e| OaieError::SandboxError(format!("eBPF tracer: {e}")))?;

    // Unload BPF programs.
    let _ = oaie_cgroup::bpf_client::unload_bpf(&mut bpf_fds);

    // Collect tee threads.
    check_tee_thread(stdout_handle, "stdout")?;
    check_tee_thread(stderr_handle, "stderr")?;

    Ok(build_result(exit_code, start.elapsed(), Some(writer), dropped))
}

/// Graceful process termination for the eBPF path: send SIGTERM first, wait
/// up to 3 seconds for exit, then escalate to SIGKILL. Returns the exit code.
#[cfg(feature = "ebpf")]
fn graceful_kill_ebpf(pid: nix::unistd::Pid) -> i32 {
    use nix::sys::signal;
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};

    let _ = signal::kill(pid, signal::Signal::SIGTERM);
    let kill_deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, code)) => return code,
            Ok(WaitStatus::Signaled(_, sig, _)) => return -(sig as i32),
            Ok(WaitStatus::StillAlive) if Instant::now() < kill_deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            _ => {
                // Grace period expired or unexpected status — force kill.
                let _ = signal::kill(pid, signal::Signal::SIGKILL);
                let _ = waitpid(pid, None);
                return -1;
            }
        }
    }
}
