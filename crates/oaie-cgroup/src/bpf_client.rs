//! BPF loading client — communicates with oaie-priv to load eBPF programs.
//!
//! The client sends a `LoadBpf` request with the cgroup ID, receives the
//! ring buffer and link FDs via SCM_RIGHTS, and keeps the socket alive
//! until `unload_bpf()` is called.

use std::io::Read;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use oaie_core::error::{OaieError, Result};

/// Socket path for the oaie-priv helper.
const PRIV_SOCKET: &str = "/run/oaie/oaie-priv.sock";

/// Maximum response size from oaie-priv.
const MAX_RESPONSE_SIZE: usize = 64 * 1024;

/// Maximum number of FDs we expect from BPF loading.
/// 1 ring buffer + 4 tracepoint links = 5.
const MAX_BPF_FDS: usize = 8;

/// File descriptors received from oaie-priv after BPF loading.
///
/// The ring buffer FD is used by the EbpfTracer to poll events.
/// Link FDs keep the tracepoint probes attached. The stream is kept
/// alive for the unload request.
///
/// Implements `Drop` to close BPF FDs if dropped without calling
/// `unload_bpf()` (e.g. on error paths or panics).
pub struct BpfFds {
    /// Ring buffer map file descriptor for polling events.
    /// Set to -1 after close to prevent double-close.
    pub ring_buffer_fd: RawFd,
    /// Tracepoint link file descriptors (kept alive to maintain attachment).
    /// Each is set to -1 after close.
    pub link_fds: Vec<RawFd>,
    /// Socket connection to oaie-priv (kept alive for unload).
    pub stream: UnixStream,
}

impl Drop for BpfFds {
    fn drop(&mut self) {
        // Safety net: close any FDs that weren't closed by unload_bpf().
        close_bpf_fds(self);
    }
}

/// Close all BPF file descriptors in a `BpfFds`, invalidating them to -1.
fn close_bpf_fds(fds: &mut BpfFds) {
    if fds.ring_buffer_fd >= 0 {
        unsafe { libc::close(fds.ring_buffer_fd); }
        fds.ring_buffer_fd = -1;
    }
    for fd in &mut fds.link_fds {
        if *fd >= 0 {
            unsafe { libc::close(*fd); }
            *fd = -1;
        }
    }
}

/// Close a list of raw FDs (used for error path cleanup).
fn close_raw_fds(fds: &[RawFd]) {
    for &fd in fds {
        if fd >= 0 {
            unsafe { libc::close(fd); }
        }
    }
}

/// Get the cgroup ID from a cgroup filesystem path.
///
/// On cgroup v2, the inode number of the cgroup directory equals the
/// cgroup ID returned by `bpf_get_current_cgroup_id()` in BPF programs.
pub fn cgroup_id_from_path(path: &Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).map_err(|e| {
        OaieError::SandboxError(format!(
            "cannot stat cgroup path {}: {e}",
            path.display()
        ))
    })?;
    Ok(meta.ino())
}

/// Request oaie-priv to load BPF programs and return the FDs.
///
/// Sends a `LoadBpf` request, receives the response with FDs via SCM_RIGHTS.
/// The returned `BpfFds` keeps the socket alive — call `unload_bpf()` when done.
pub fn load_bpf(cgroup_id: u64, ring_buf_size: u32) -> Result<BpfFds> {
    let stream = UnixStream::connect(PRIV_SOCKET).map_err(|e| {
        OaieError::SandboxError(format!("cannot connect to oaie-priv at {PRIV_SOCKET}: {e}"))
    })?;

    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .ok();

    // Send LoadBpf request using length-prefixed JSON.
    let request = serde_json::json!({
        "action": "load_bpf",
        "cgroup_id": cgroup_id,
        "ring_buffer_size": ring_buf_size,
    });
    let payload = serde_json::to_vec(&request).map_err(|e| {
        OaieError::SandboxError(format!("failed to serialize LoadBpf request: {e}"))
    })?;
    crate::fd_passing::send_request(&stream, &payload).map_err(|e| {
        OaieError::SandboxError(format!("failed to send LoadBpf to oaie-priv: {e}"))
    })?;

    // Receive response with FDs via SCM_RIGHTS.
    let (resp_bytes, fds) =
        crate::fd_passing::recv_response_with_fds(&stream, MAX_RESPONSE_SIZE, MAX_BPF_FDS)
            .map_err(|e| {
                OaieError::SandboxError(format!("failed to receive BPF FDs from oaie-priv: {e}"))
            })?;

    // Parse the JSON response. On any error, close received FDs first.
    let resp: serde_json::Value = match serde_json::from_slice(&resp_bytes) {
        Ok(v) => v,
        Err(e) => {
            close_raw_fds(&fds);
            return Err(OaieError::SandboxError(format!(
                "invalid response from oaie-priv: {e}"
            )));
        }
    };

    if resp.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        close_raw_fds(&fds);
        let err = resp
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        return Err(OaieError::SandboxError(format!(
            "oaie-priv load_bpf failed: {err}"
        )));
    }

    let expected_fds = resp
        .get("bpf_fd_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    if fds.len() < expected_fds || fds.is_empty() {
        close_raw_fds(&fds);
        return Err(OaieError::SandboxError(format!(
            "oaie-priv returned {expected_fds} expected FDs but only {} received",
            fds.len()
        )));
    }

    // First FD is the ring buffer, rest are link FDs.
    let ring_buffer_fd = fds[0];
    let link_fds = fds[1..].to_vec();

    Ok(BpfFds {
        ring_buffer_fd,
        link_fds,
        stream,
    })
}

/// Request oaie-priv to unload BPF programs and close handles.
///
/// Sends an `UnloadBpf` request on the same socket used for `load_bpf`.
/// After this call, the ring buffer and link FDs are no longer valid.
pub fn unload_bpf(fds: &mut BpfFds) -> Result<()> {
    let request = serde_json::json!({
        "action": "unload_bpf",
    });
    let payload = serde_json::to_vec(&request).map_err(|e| {
        OaieError::SandboxError(format!("failed to serialize UnloadBpf request: {e}"))
    })?;
    crate::fd_passing::send_request(&fds.stream, &payload).map_err(|e| {
        OaieError::SandboxError(format!("failed to send UnloadBpf to oaie-priv: {e}"))
    })?;

    // Read the response (best-effort — the important thing is that we sent the unload).
    let mut len_buf = [0u8; 4];
    if fds.stream.read_exact(&mut len_buf).is_ok() {
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        if resp_len <= MAX_RESPONSE_SIZE {
            let mut resp_buf = vec![0u8; resp_len];
            let _ = fds.stream.read_exact(&mut resp_buf);
        }
    }

    // Close FDs on our side, invalidating them to prevent double-close.
    close_bpf_fds(fds);

    Ok(())
}
