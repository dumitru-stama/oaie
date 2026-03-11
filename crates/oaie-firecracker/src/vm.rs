//! Firecracker VM lifecycle management.
//!
//! `FirecrackerVm` encapsulates the entire lifecycle of a Firecracker microVM:
//! boot, job execution, and shutdown. The VM process is force-killed on Drop
//! if not cleanly shut down.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use oaie_core::error::{OaieError, Result};

use crate::api::{BootSource, Drive, FirecrackerApi, MachineConfig, VsockConfig};
use crate::vsock::{VsockHost, GUEST_PORT};
use crate::wire::Message;

/// Configuration for booting a Firecracker VM.
#[derive(Clone, Debug)]
pub struct VmConfig {
    /// Path to the Firecracker binary.
    pub firecracker_path: PathBuf,
    /// Path to the kernel image (vmlinux).
    pub kernel_path: PathBuf,
    /// Path to the root filesystem image (ext4).
    pub rootfs_path: PathBuf,
    /// Number of vCPUs (default: 1).
    pub vcpu_count: u32,
    /// Memory size in MiB (default: 128).
    pub mem_size_mib: u32,
    /// Optional ext4 image to mount as /dev/vdb (input directory).
    pub input_image: Option<PathBuf>,
    /// Optional ext4 image to mount as /dev/vdc (output directory).
    pub output_image: Option<PathBuf>,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            firecracker_path: PathBuf::from("/usr/bin/firecracker"),
            kernel_path: PathBuf::new(),
            rootfs_path: PathBuf::new(),
            vcpu_count: 1,
            mem_size_mib: 128,
            input_image: None,
            output_image: None,
        }
    }
}

/// A running Firecracker microVM instance.
pub struct FirecrackerVm {
    /// The Firecracker child process.
    child: Child,
    /// API client for the VM.
    _api: FirecrackerApi,
    /// Vsock communication channel with the guest agent.
    vsock: crate::vsock::VsockStream,
    /// Working directory containing API socket, vsock socket, etc.
    work_dir: PathBuf,
    /// Whether the VM has been cleanly shut down.
    shutdown: bool,
}

impl FirecrackerVm {
    /// Boot a Firecracker VM with the given configuration.
    ///
    /// This:
    /// 1. Creates a temporary working directory for sockets
    /// 2. Spawns the Firecracker process
    /// 3. Configures the VM via the REST API (kernel, drives, vsock)
    /// 4. Starts the VM
    /// 5. Waits for the guest agent to connect and send `AgentReady`
    ///
    /// Returns a `FirecrackerVm` ready to execute jobs.
    pub fn boot(config: &VmConfig) -> Result<Self> {
        // Create working directory for this VM instance.
        let work_dir = tempfile::Builder::new()
            .prefix("oaie-fc-")
            .tempdir()
            .map_err(OaieError::Io)?;
        // Persist the tempdir — we manage cleanup ourselves in shutdown()/Drop.
        let work_path = work_dir.keep();

        let api_socket = work_path.join("api.sock");
        let vsock_uds = work_path.join("vsock.sock");

        // Pre-create the vsock listener before starting Firecracker.
        let vsock_host = VsockHost::new(&vsock_uds, GUEST_PORT)?;

        // Spawn Firecracker process.
        let mut child = Command::new(&config.firecracker_path)
            .arg("--api-sock")
            .arg(&api_socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            // Redirect stderr to null — Firecracker's stderr is not useful
            // and piping without draining could cause a deadlock if the pipe
            // buffer fills.
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                OaieError::Io(io::Error::new(
                    e.kind(),
                    format!(
                        "failed to spawn Firecracker at {}: {}",
                        config.firecracker_path.display(),
                        e
                    ),
                ))
            })?;

        // Guard: if anything below fails, kill the child and clean up.
        // Without this, a failed boot leaks an orphan Firecracker process.
        let configure_result = (|| -> Result<(FirecrackerApi, crate::vsock::VsockStream)> {
            // Wait for the API socket to appear, checking for early exit.
            let api_deadline = Instant::now() + Duration::from_secs(5);
            while !api_socket.exists() {
                // Check if Firecracker already exited (crash, missing libs, etc.).
                if let Some(status) = child.try_wait().map_err(OaieError::Io)? {
                    return Err(OaieError::Io(io::Error::other(
                        format!("Firecracker exited with {status} before API socket appeared"),
                    )));
                }
                if Instant::now() >= api_deadline {
                    return Err(OaieError::Io(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Firecracker API socket did not appear within 5s",
                    )));
                }
                std::thread::sleep(Duration::from_millis(50));
            }

            // Configure the VM via the REST API.
            let api = FirecrackerApi::new(&api_socket)?;

        // Boot source: kernel + init args.
        let boot_args = "console=ttyS0 reboot=k panic=1 pci=off init=/oaie-guest".to_string();
        api.set_boot_source(&BootSource {
            kernel_image_path: config.kernel_path.display().to_string(),
            boot_args: Some(boot_args),
            initrd_path: None,
        })?;

        // Machine config.
        api.set_machine_config(&MachineConfig {
            vcpu_count: config.vcpu_count,
            mem_size_mib: config.mem_size_mib,
        })?;

        // Root filesystem drive.
        api.set_drive(&Drive {
            drive_id: "rootfs".to_string(),
            path_on_host: config.rootfs_path.display().to_string(),
            is_root_device: true,
            is_read_only: true,
        })?;

        // Optional input drive (/dev/vdb).
        if let Some(ref input_img) = config.input_image {
            api.set_drive(&Drive {
                drive_id: "input".to_string(),
                path_on_host: input_img.display().to_string(),
                is_root_device: false,
                is_read_only: true,
            })?;
        }

        // Optional output drive (/dev/vdc).
        if let Some(ref output_img) = config.output_image {
            api.set_drive(&Drive {
                drive_id: "output".to_string(),
                path_on_host: output_img.display().to_string(),
                is_root_device: false,
                is_read_only: false,
            })?;
        }

        // Vsock device — guest CID 3 (0=hypervisor, 1=reserved, 2=host).
        api.set_vsock(&VsockConfig {
            guest_cid: 3,
            uds_path: vsock_uds.display().to_string(),
        })?;

        // Start the VM.
        api.instance_start()?;

        // Wait for the guest agent to connect via vsock.
        let mut vsock_stream =
            vsock_host.accept(Duration::from_secs(30)).map_err(|e| {
                OaieError::Io(io::Error::new(
                    e.kind(),
                    format!("guest agent did not connect: {e}"),
                ))
            })?;

        // Wait for AgentReady message.
        match vsock_stream.recv()? {
            Some(Message::AgentReady { version }) => {
                eprintln!("OAIE: guest agent v{version} ready");
            }
            Some(other) => {
                return Err(OaieError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("expected AgentReady, got: {other:?}"),
                )));
            }
            None => {
                return Err(OaieError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "guest agent disconnected before AgentReady",
                )));
            }
        }

            Ok((api, vsock_stream))
        })(); // End of configure_result closure.

        // If configuration failed, kill the child and clean up.
        match configure_result {
            Ok((api, vsock_stream)) => Ok(Self {
                child,
                _api: api,
                vsock: vsock_stream,
                work_dir: work_path,
                shutdown: false,
            }),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = std::fs::remove_dir_all(&work_path);
                Err(e)
            }
        }
    }

    /// Run a job inside the VM.
    ///
    /// Sends a `RunJob` message to the guest agent and collects output
    /// chunks until `JobDone` is received. Stdout and stderr are written
    /// to the specified files.
    ///
    /// Returns `(exit_code, duration)`.
    #[allow(clippy::too_many_arguments)]
    pub fn run_job(
        &mut self,
        command: Vec<String>,
        env: std::collections::HashMap<String, String>,
        timeout: Option<Duration>,
        trace: bool,
        stdout_path: &Path,
        stderr_path: &Path,
        quiet: bool,
    ) -> Result<(i32, Duration)> {
        use std::fs::File;
        use std::io::Write;

        let msg = Message::run_job(command, env, timeout, trace);
        self.vsock
            .send(&msg)
            .map_err(|e| OaieError::Io(io::Error::new(e.kind(), format!("send RunJob: {e}"))))?;

        let mut stdout_file = File::create(stdout_path)?;
        let mut stderr_file = File::create(stderr_path)?;

        // Set a generous read timeout for the overall job (saturating to avoid overflow).
        let job_timeout = timeout
            .map(|t| t.saturating_add(Duration::from_secs(10)))
            .unwrap_or(Duration::from_secs(3600));

        let start = Instant::now();

        loop {
            if start.elapsed() > job_timeout {
                return Err(OaieError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "job timed out waiting for guest response",
                )));
            }

            match self.vsock.recv_timeout(Duration::from_secs(60))? {
                Some(Message::OutputChunk { stream, data }) => {
                    let bytes = crate::wire::base64_decode(&data)?;
                    match stream.as_str() {
                        "stdout" => {
                            stdout_file.write_all(&bytes)?;
                            if !quiet {
                                std::io::stdout().write_all(&bytes)?;
                            }
                        }
                        "stderr" => {
                            stderr_file.write_all(&bytes)?;
                            if !quiet {
                                std::io::stderr().write_all(&bytes)?;
                            }
                        }
                        _ => {} // Ignore unknown streams.
                    }
                }
                Some(Message::TraceEvent { event: _event }) => {
                    // TODO (Step 24): Write trace events to ChunkedEventWriter.
                }
                Some(Message::JobDone {
                    exit_code,
                    duration_ms,
                }) => {
                    return Ok((exit_code, Duration::from_millis(duration_ms)));
                }
                Some(Message::Error { message }) => {
                    return Err(OaieError::Io(io::Error::other(
                        format!("guest agent error: {message}"),
                    )));
                }
                Some(other) => {
                    return Err(OaieError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected message during job: {other:?}"),
                    )));
                }
                None => {
                    return Err(OaieError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "guest agent disconnected during job execution",
                    )));
                }
            }
        }
    }

    /// Gracefully shut down the VM.
    ///
    /// Sends a `Shutdown` message to the guest agent, then waits for the
    /// Firecracker process to exit. If it doesn't exit within 5 seconds,
    /// kills it.
    pub fn shutdown(&mut self) -> Result<()> {
        if self.shutdown {
            return Ok(());
        }

        // Tell the guest agent to halt.
        let _ = self.vsock.send(&Message::Shutdown);
        let _ = self.vsock.shutdown();

        // Wait for the Firecracker process to exit.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match self.child.try_wait()? {
                Some(_status) => {
                    self.shutdown = true;
                    self.cleanup();
                    return Ok(());
                }
                None if Instant::now() >= deadline => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    self.shutdown = true;
                    self.cleanup();
                    return Ok(());
                }
                None => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    }

    /// Clean up working directory.
    fn cleanup(&self) {
        let _ = fs::remove_dir_all(&self.work_dir);
    }

    /// Get the working directory path (for debugging).
    pub fn work_dir(&self) -> &Path {
        &self.work_dir
    }
}

impl Drop for FirecrackerVm {
    fn drop(&mut self) {
        if !self.shutdown {
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.cleanup();
        }
    }
}
