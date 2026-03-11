//! Bare execution backend: runs the command directly without isolation.
//!
//! Used when `--no-isolation` is passed or `--backend=bare`. No namespace
//! sandboxing, no seccomp, no Landlock. Only basic environment sanitization.

use std::fs::File;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use oaie_core::error::{OaieError, Result};
use oaie_core::job::JobSpec;
use oaie_core::run_dir::RunDir;
use oaie_core::run_id::RunId;

use crate::runner::{
    check_tee_thread, install_signal_handlers, signal_received_since, tee_to_file_and_terminal,
    tee_to_file_only, wait_with_timeout, WaitOutcome,
};

/// Execute a command without isolation, capturing stdout/stderr to files.
///
/// Returns `(exit_code, duration)`. The caller handles CAS storage,
/// manifest generation, and DB indexing.
pub fn execute_bare(
    job: &JobSpec,
    run_dir: &RunDir,
    out_dir: &Path,
    run_id: &RunId,
    effective_timeout: Option<Duration>,
    quiet: bool,
) -> Result<(i32, Duration)> {
    if job.command.is_empty() {
        return Err(OaieError::InvalidJobSpec("empty command".into()));
    }

    let mut cmd = Command::new(&job.command[0]);
    if job.command.len() > 1 {
        cmd.args(&job.command[1..]);
    }

    // Set working directory to input path if specified.
    if let Some(ref input_dir) = job.inputs {
        cmd.current_dir(input_dir);
    }

    // Clear inherited environment to prevent leaking secrets, credentials,
    // or other sensitive vars into the unsandboxed child process.
    // Only pass through a minimal safe set needed for basic tool operation.
    cmd.env_clear();
    cmd.env(
        "PATH",
        std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()),
    );
    cmd.env(
        "HOME",
        std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()),
    );
    cmd.env(
        "TERM",
        std::env::var("TERM").unwrap_or_else(|_| "dumb".into()),
    );
    cmd.env(
        "LANG",
        std::env::var("LANG").unwrap_or_else(|_| "C.UTF-8".into()),
    );

    // Set environment variables so the tool knows about OAIE.
    cmd.env("OAIE_RUN_ID", run_id.full());
    cmd.env("OAIE_OUT", out_dir.display().to_string());

    // Pipe stdout/stderr so we can tee to files.
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn()?;

    // Set up signal handling: catch SIGINT and SIGTERM and forward to child.
    let signal_baseline = install_signal_handlers();

    // Spawn tee threads for stdout and stderr.
    let stdout_file = File::create(run_dir.stdout_path())?;
    let stderr_file = File::create(run_dir.stderr_path())?;

    let child_stdout = child.stdout.take().ok_or_else(|| {
        OaieError::Io(io::Error::other(
            "stdout pipe missing after Stdio::piped()",
        ))
    })?;
    let child_stderr = child.stderr.take().ok_or_else(|| {
        OaieError::Io(io::Error::other(
            "stderr pipe missing after Stdio::piped()",
        ))
    })?;

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

    // Re-sample start time now that the child is spawned, for accurate duration.
    let start = Instant::now();

    // Wait with optional timeout.
    let exit_status = if let Some(timeout) = effective_timeout {
        match wait_with_timeout(&mut child, timeout, signal_baseline)? {
            WaitOutcome::Exited(status) => status,
            WaitOutcome::TimedOut => {
                // Timeout — kill the process.
                let _ = child.kill();
                let _ = child.wait();
                // Wait for tee threads to finish.
                let _ = stdout_handle.join();
                let _ = stderr_handle.join();
                return Err(OaieError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("command timed out after {}s", timeout.as_secs()),
                )));
            }
            WaitOutcome::Interrupted => {
                // Signal received: forward to child, wait up to 3s, then kill.
                // On Unix, the child's process group already gets SIGINT from
                // the terminal, so we just wait.
                let deadline = Instant::now() + Duration::from_secs(3);
                loop {
                    match child.try_wait()? {
                        Some(status) => {
                            let _ = stdout_handle.join();
                            let _ = stderr_handle.join();
                            let duration = start.elapsed();
                            let exit_code = status.code().unwrap_or(-1);
                            return Ok((exit_code, duration));
                        }
                        None if Instant::now() >= deadline => {
                            let _ = child.kill();
                            let _ = child.wait();
                            let _ = stdout_handle.join();
                            let _ = stderr_handle.join();
                            let duration = start.elapsed();
                            return Ok((-1, duration));
                        }
                        None => std::thread::sleep(Duration::from_millis(50)),
                    }
                }
            }
        }
    } else {
        // No timeout — wait with signal awareness.
        loop {
            match child.try_wait()? {
                Some(status) => break status,
                None => {
                    if signal_received_since(signal_baseline) {
                        let deadline = Instant::now() + Duration::from_secs(3);
                        loop {
                            match child.try_wait()? {
                                Some(status) => {
                                    let _ = stdout_handle.join();
                                    let _ = stderr_handle.join();
                                    let duration = start.elapsed();
                                    let exit_code = status.code().unwrap_or(-1);
                                    return Ok((exit_code, duration));
                                }
                                None if Instant::now() >= deadline => {
                                    let _ = child.kill();
                                    let _ = child.wait();
                                    let _ = stdout_handle.join();
                                    let _ = stderr_handle.join();
                                    let duration = start.elapsed();
                                    return Ok((-1, duration));
                                }
                                None => std::thread::sleep(Duration::from_millis(50)),
                            }
                        }
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
    };

    // Wait for tee threads to finish. Panics are hard errors (truncated
    // artifact); I/O errors are logged but tolerated (broken pipe etc).
    check_tee_thread(stdout_handle, "stdout")?;
    check_tee_thread(stderr_handle, "stderr")?;

    let duration = start.elapsed();
    // Unix convention: signal-killed processes exit with 128 + signal number.
    let exit_code = exit_status.code().unwrap_or_else(|| {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            exit_status.signal().map_or(-1, |s| 128 + s)
        }
        #[cfg(not(unix))]
        {
            -1
        }
    });

    Ok((exit_code, duration))
}
