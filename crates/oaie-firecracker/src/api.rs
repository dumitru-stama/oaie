//! Firecracker REST API client.
//!
//! Firecracker exposes an HTTP/1.1 API over a Unix domain socket for VM
//! configuration and lifecycle management. This module wraps that API
//! using hyper with a Unix socket connector.
//!
//! All public methods are synchronous — they create a single-threaded
//! tokio runtime internally. This is the only async code in the project.

use std::path::{Path, PathBuf};

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::Request;
use serde::{Deserialize, Serialize};

use oaie_core::error::{OaieError, Result};

/// Firecracker API client communicating over a Unix domain socket.
pub struct FirecrackerApi {
    /// Path to the Firecracker API socket.
    socket_path: PathBuf,
    /// Tokio runtime for async HTTP requests.
    rt: tokio::runtime::Runtime,
}

/// Boot source configuration.
#[derive(Debug, Serialize)]
pub struct BootSource {
    /// Path to the kernel image.
    pub kernel_image_path: String,
    /// Kernel boot arguments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_args: Option<String>,
    /// Path to the initrd image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initrd_path: Option<String>,
}

/// Drive (block device) configuration.
#[derive(Debug, Serialize)]
pub struct Drive {
    /// Unique drive ID.
    pub drive_id: String,
    /// Path to the host-side image file.
    pub path_on_host: String,
    /// Whether the drive is the root device.
    pub is_root_device: bool,
    /// Whether the drive is read-only.
    pub is_read_only: bool,
}

/// Machine configuration (vCPU count, memory).
#[derive(Debug, Serialize)]
pub struct MachineConfig {
    /// Number of vCPUs.
    pub vcpu_count: u32,
    /// Memory size in MiB.
    pub mem_size_mib: u32,
}

/// Vsock device configuration.
#[derive(Debug, Serialize)]
pub struct VsockConfig {
    /// Guest CID (must be ≥ 3; 0, 1, 2 are reserved).
    pub guest_cid: u32,
    /// Path to the host-side Unix domain socket for vsock proxy.
    pub uds_path: String,
}

/// Instance action (e.g., start the VM).
#[derive(Debug, Serialize)]
struct InstanceAction {
    action_type: String,
}

/// Response body from Firecracker API (for error reporting).
#[derive(Debug, Deserialize)]
struct ApiError {
    fault_message: Option<String>,
}

impl FirecrackerApi {
    /// Create a new API client for the given Firecracker socket path.
    ///
    /// Creates a single-threaded tokio runtime for async HTTP operations.
    pub fn new(socket_path: &Path) -> Result<Self> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(OaieError::Io)?;

        Ok(Self {
            socket_path: socket_path.to_path_buf(),
            rt,
        })
    }

    /// Configure the boot source (kernel image and boot arguments).
    pub fn set_boot_source(&self, boot: &BootSource) -> Result<()> {
        self.put("/boot-source", boot)
    }

    /// Add or update a drive (block device).
    pub fn set_drive(&self, drive: &Drive) -> Result<()> {
        self.put(&format!("/drives/{}", drive.drive_id), drive)
    }

    /// Configure machine resources (vCPU count, memory).
    pub fn set_machine_config(&self, config: &MachineConfig) -> Result<()> {
        self.put("/machine-config", config)
    }

    /// Configure the vsock device.
    pub fn set_vsock(&self, vsock: &VsockConfig) -> Result<()> {
        self.put("/vsock", vsock)
    }

    /// Start the VM instance.
    pub fn instance_start(&self) -> Result<()> {
        let action = InstanceAction {
            action_type: "InstanceStart".to_string(),
        };
        self.put("/actions", &action)
    }

    /// Send Ctrl+Alt+Del to trigger a graceful shutdown.
    pub fn send_ctrl_alt_del(&self) -> Result<()> {
        let action = InstanceAction {
            action_type: "SendCtrlAltDel".to_string(),
        };
        self.put("/actions", &action)
    }

    /// Internal: perform a PUT request to the Firecracker API.
    fn put<T: Serialize>(&self, path: &str, body: &T) -> Result<()> {
        let json = serde_json::to_vec(body)
            .map_err(|e| OaieError::InvalidJobSpec(format!("JSON serialization: {e}")))?;

        let socket_path = self.socket_path.clone();
        let path = path.to_string();

        self.rt.block_on(async {
            // Wrap the entire request in a 30-second timeout to prevent
            // indefinite hangs if Firecracker stops responding.
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                async {
                    let stream = tokio::net::UnixStream::connect(&socket_path)
                        .await
                        .map_err(OaieError::Io)?;

                    let io = hyper_util::rt::TokioIo::new(stream);

                    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
                        .await
                        .map_err(|e| OaieError::Io(io_err(&e)))?;

                    // Spawn connection driver.
                    tokio::spawn(async move {
                        let _ = conn.await;
                    });

                    let req = Request::builder()
                        .method("PUT")
                        .uri(&path)
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .body(Full::new(Bytes::from(json)))
                        .map_err(|e| OaieError::Io(io_err(&e)))?;

                    sender
                        .send_request(req)
                        .await
                        .map_err(|e| OaieError::Io(io_err(&e)))
                },
            )
            .await;

            let resp = match result {
                Ok(r) => r?,
                Err(_elapsed) => {
                    return Err(OaieError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("Firecracker API request {path} timed out after 30s"),
                    )));
                }
            };

            let status = resp.status();
            if !status.is_success() {
                // Limit error body to 64 KiB to prevent a misbehaving
                // Firecracker from sending unbounded error responses.
                // Limited enforces the cap during streaming; collect() will
                // return an error if the body exceeds the limit, instead of
                // buffering the whole thing first.
                let body_bytes = Limited::new(resp.into_body(), 65536)
                    .collect()
                    .await
                    .map_err(|e| OaieError::Io(io_err(&e)))?
                    .to_bytes();

                let detail = if let Ok(api_err) = serde_json::from_slice::<ApiError>(&body_bytes) {
                    api_err
                        .fault_message
                        .unwrap_or_else(|| String::from_utf8_lossy(&body_bytes).to_string())
                } else {
                    String::from_utf8_lossy(&body_bytes).to_string()
                };

                return Err(OaieError::Io(std::io::Error::other(
                    format!("Firecracker API {path} returned {status}: {detail}"),
                )));
            }

            Ok(())
        })
    }
}

/// Convert any Display-able error into io::Error.
fn io_err(e: &dyn std::fmt::Display) -> std::io::Error {
    std::io::Error::other(e.to_string())
}
