//! IPC client for the `oaie-priv` privileged helper binary.
//!
//! Uses a length-prefixed JSON protocol over a Unix domain socket.
//! The helper is expected to be at `/usr/lib/oaie/oaie-priv` with
//! appropriate capabilities set via `setcap`.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use oaie_core::cgroup::{CgroupLimits, CgroupMethod};
use oaie_core::error::{OaieError, Result};
use oaie_core::run_id::RunId;

use crate::scope::CgroupScope;

/// Socket path for the oaie-priv helper.
const PRIV_SOCKET: &str = "/run/oaie/oaie-priv.sock";

/// Maximum response size (64 KB) to prevent DoS from a rogue helper.
const MAX_RESPONSE_SIZE: u32 = 64 * 1024;

/// Request sent to the oaie-priv helper.
#[derive(serde::Serialize)]
#[serde(tag = "action")]
enum Request {
    #[serde(rename = "create_cgroup")]
    CreateCgroup {
        run_id: String,
        limits: CgroupLimits,
    },
    #[serde(rename = "cleanup_cgroup")]
    CleanupCgroup {
        cgroup_path: String,
    },
    #[serde(rename = "ping")]
    Ping,
}

/// Response from the oaie-priv helper.
#[derive(serde::Deserialize)]
struct Response {
    ok: bool,
    #[serde(default)]
    cgroup_path: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// Send a request and receive a response over the priv socket.
fn rpc(request: &Request) -> Result<Response> {
    let mut stream = UnixStream::connect(PRIV_SOCKET).map_err(|e| {
        OaieError::SandboxError(format!("cannot connect to oaie-priv at {PRIV_SOCKET}: {e}"))
    })?;

    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .ok();

    // Send: 4-byte BE length + JSON payload.
    let payload = serde_json::to_vec(request).map_err(|e| {
        OaieError::SandboxError(format!("failed to serialize priv request: {e}"))
    })?;
    let len = payload.len() as u32;
    stream.write_all(&len.to_be_bytes()).map_err(|e| {
        OaieError::SandboxError(format!("failed to write to oaie-priv: {e}"))
    })?;
    stream.write_all(&payload).map_err(|e| {
        OaieError::SandboxError(format!("failed to write payload to oaie-priv: {e}"))
    })?;

    // Receive: 4-byte BE length + JSON payload.
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| {
        OaieError::SandboxError(format!("failed to read response length from oaie-priv: {e}"))
    })?;
    let resp_len = u32::from_be_bytes(len_buf);
    if resp_len > MAX_RESPONSE_SIZE {
        return Err(OaieError::SandboxError(format!(
            "oaie-priv response too large: {resp_len} bytes (max {MAX_RESPONSE_SIZE})"
        )));
    }

    let mut resp_buf = vec![0u8; resp_len as usize];
    stream.read_exact(&mut resp_buf).map_err(|e| {
        OaieError::SandboxError(format!("failed to read response from oaie-priv: {e}"))
    })?;

    serde_json::from_slice(&resp_buf).map_err(|e| {
        OaieError::SandboxError(format!("invalid response from oaie-priv: {e}"))
    })
}

/// Create a cgroup scope via the oaie-priv helper.
pub fn create_cgroup(run_id: &RunId, limits: &CgroupLimits) -> Result<CgroupScope> {
    let resp = rpc(&Request::CreateCgroup {
        run_id: run_id.full(),
        limits: limits.clone(),
    })?;

    if !resp.ok {
        return Err(OaieError::SandboxError(format!(
            "oaie-priv create_cgroup failed: {}",
            resp.error.unwrap_or_else(|| "unknown error".into())
        )));
    }

    let cgroup_path = resp.cgroup_path.ok_or_else(|| {
        OaieError::SandboxError("oaie-priv returned ok but no cgroup_path".into())
    })?;

    Ok(CgroupScope {
        path: PathBuf::from(&cgroup_path),
        unit_name: None,
        method: CgroupMethod::OaiePriv,
        cleanup: true,
        holder: None,
    })
}

/// Clean up a cgroup scope via the oaie-priv helper.
pub fn cleanup_cgroup(path: &std::path::Path) -> Result<()> {
    let resp = rpc(&Request::CleanupCgroup {
        cgroup_path: path.display().to_string(),
    })?;

    if !resp.ok {
        return Err(OaieError::SandboxError(format!(
            "oaie-priv cleanup failed: {}",
            resp.error.unwrap_or_else(|| "unknown error".into())
        )));
    }

    Ok(())
}

/// Ping the oaie-priv helper to check if it's running.
pub fn ping() -> Result<bool> {
    match rpc(&Request::Ping) {
        Ok(resp) => Ok(resp.ok),
        Err(_) => Ok(false),
    }
}
