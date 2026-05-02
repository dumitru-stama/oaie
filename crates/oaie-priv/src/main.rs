//! oaie-priv — privileged helper for cgroup v2 scope management.
//!
//! Designed to run with `cap_sys_admin=ep` capability (via setcap).
//! Accepts a single connection on a Unix socket, validates the request,
//! performs the cgroup operation, responds, and exits. Single-shot design
//! minimizes the window of elevated privilege.
//!
//! This binary is intentionally minimal (under 500 lines total) to
//! minimize the attack surface of the privileged component.

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;

// Re-use library modules.
use oaie_priv::audit;
use oaie_priv::cgroup;
use oaie_priv::protocol;
use oaie_priv::validate;

const SOCKET_PATH: &str = "/run/oaie/oaie-priv.sock";

/// Maximum request size (64 KB) to prevent resource exhaustion.
const MAX_REQUEST_SIZE: u32 = 64 * 1024;

/// Socket read timeout in seconds. Prevents a connected client from holding
/// the helper indefinitely.
const READ_TIMEOUT_SECS: u64 = 5;

fn main() {
    // Set restrictive umask before creating any files/directories.
    // The socket will be created with 0o600 permissions.
    unsafe { libc::umask(0o077); }

    // Ensure the socket directory exists.
    if let Err(e) = std::fs::create_dir_all("/run/oaie") {
        eprintln!("oaie-priv: failed to create /run/oaie: {e}");
        std::process::exit(1);
    }

    // Remove stale socket file.
    let _ = std::fs::remove_file(SOCKET_PATH);

    let listener = match UnixListener::bind(SOCKET_PATH) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("oaie-priv: failed to bind {SOCKET_PATH}: {e}");
            std::process::exit(1);
        }
    };

    // Verify socket permissions were set correctly (umask should handle this,
    // but belt-and-suspenders for a privileged binary).
    if let Err(e) = std::fs::set_permissions(
        SOCKET_PATH,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    ) {
        eprintln!("oaie-priv: failed to set socket permissions: {e}");
        // Clean up the socket before exiting.
        let _ = std::fs::remove_file(SOCKET_PATH);
        std::process::exit(1);
    }

    // Accept exactly one connection (single-shot design).
    let mut stream = match listener.accept() {
        Ok((s, _addr)) => s,
        Err(e) => {
            eprintln!("oaie-priv: accept error: {e}");
            let _ = std::fs::remove_file(SOCKET_PATH);
            std::process::exit(1);
        }
    };

    // Set read timeout to prevent a slow/malicious client from holding
    // the privileged process indefinitely.
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(READ_TIMEOUT_SECS)));

    // Get caller identity via SO_PEERCRED (kernel-verified, cannot be forged).
    let cred = match get_peer_cred(&stream) {
        Some(c) => c,
        None => {
            let _ = send_error(&mut stream, "authentication failed");
            let _ = std::fs::remove_file(SOCKET_PATH);
            std::process::exit(1);
        }
    };
    let caller_uid = Some(cred.uid);
    let caller_pid = Some(cred.pid as u32);

    // Read request: 4-byte BE length + JSON payload.
    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).is_err() {
        let _ = std::fs::remove_file(SOCKET_PATH);
        std::process::exit(1);
    }
    let req_len = u32::from_be_bytes(len_buf);
    if req_len > MAX_REQUEST_SIZE {
        let _ = send_error(&mut stream, "request too large");
        let _ = std::fs::remove_file(SOCKET_PATH);
        std::process::exit(1);
    }

    let mut req_buf = vec![0u8; req_len as usize];
    if stream.read_exact(&mut req_buf).is_err() {
        let _ = std::fs::remove_file(SOCKET_PATH);
        std::process::exit(1);
    }

    let request: protocol::Request = match serde_json::from_slice(&req_buf) {
        Ok(r) => r,
        Err(_) => {
            // Generic error — don't leak parse details to client.
            let _ = send_error(&mut stream, "invalid request");
            let _ = std::fs::remove_file(SOCKET_PATH);
            std::process::exit(1);
        }
    };

    // Handle LoadBpf specially: two-phase flow where we stay alive
    // until UnloadBpf or socket close.
    #[cfg(feature = "ebpf")]
    if let protocol::Request::LoadBpf { cgroup_id, ring_buffer_size } = &request {
        handle_load_bpf(&mut stream, *cgroup_id, *ring_buffer_size, caller_uid, caller_pid);
        let _ = std::fs::remove_file(SOCKET_PATH);
        return;
    }

    let response = handle_request(&request, caller_uid, caller_pid, cred.uid);

    // Send response.
    if let Ok(payload) = serde_json::to_vec(&response) {
        let len = payload.len() as u32;
        let _ = stream.write_all(&len.to_be_bytes());
        let _ = stream.write_all(&payload);
    }

    // Clean up socket and exit. Single-shot: we're done.
    let _ = std::fs::remove_file(SOCKET_PATH);
}

fn handle_request(
    request: &protocol::Request,
    caller_uid: Option<u32>,
    caller_pid: Option<u32>,
    peer_uid: u32,
) -> protocol::Response {
    match request {
        protocol::Request::CreateCgroup { run_id, limits } => {
            if let Err(e) = validate::validate_run_id(run_id) {
                audit::log_action(caller_uid, caller_pid, "create_cgroup", &format!("rejected: {e}"));
                return protocol::Response::error("invalid run ID");
            }
            if let Err(e) = validate::validate_limits(limits) {
                audit::log_action(caller_uid, caller_pid, "create_cgroup", &format!("rejected: {e}"));
                return protocol::Response::error("invalid limits");
            }

            match cgroup::create_cgroup(run_id, limits, peer_uid) {
                Ok(path) => {
                    audit::log_action(caller_uid, caller_pid, "create_cgroup", &format!("ok: {path}"));
                    protocol::Response::ok_with_path(&path)
                }
                Err(e) => {
                    audit::log_action(caller_uid, caller_pid, "create_cgroup", &format!("failed: {e}"));
                    // Generic error to client — details logged to audit file.
                    protocol::Response::error("cgroup creation failed")
                }
            }
        }

        protocol::Request::CleanupCgroup { cgroup_path } => {
            if let Err(e) = validate::validate_cgroup_path(cgroup_path) {
                audit::log_action(caller_uid, caller_pid, "cleanup_cgroup", &format!("rejected: {e}"));
                return protocol::Response::error("invalid cgroup path");
            }

            match cgroup::cleanup_cgroup(std::path::Path::new(cgroup_path), peer_uid) {
                Ok(()) => {
                    audit::log_action(caller_uid, caller_pid, "cleanup_cgroup", "ok");
                    protocol::Response::ok()
                }
                Err(e) => {
                    audit::log_action(caller_uid, caller_pid, "cleanup_cgroup", &format!("failed: {e}"));
                    protocol::Response::error("cgroup cleanup failed")
                }
            }
        }

        protocol::Request::Ping => {
            protocol::Response::ok()
        }

        // LoadBpf is handled before handle_request() in the two-phase flow.
        // If we somehow reach here, return an error.
        protocol::Request::LoadBpf { .. } => {
            #[cfg(not(feature = "ebpf"))]
            {
                audit::log_action(caller_uid, caller_pid, "load_bpf", "rejected: ebpf feature not enabled");
                protocol::Response::error("eBPF support not compiled in")
            }
            #[cfg(feature = "ebpf")]
            {
                audit::log_action(caller_uid, caller_pid, "load_bpf", "rejected: internal dispatch error");
                protocol::Response::error("internal error")
            }
        }

        protocol::Request::UnloadBpf => {
            // UnloadBpf outside of a two-phase session is a no-op.
            protocol::Response::ok()
        }

        protocol::Request::SetupNetns { sandbox_pid, run_id_short, allow_rules } => {
            if *sandbox_pid == 0 {
                audit::log_action(caller_uid, caller_pid, "setup_netns", "rejected: sandbox_pid is 0");
                return protocol::Response::error("invalid sandbox_pid");
            }
            if let Err(e) = validate::validate_run_id(run_id_short) {
                audit::log_action(caller_uid, caller_pid, "setup_netns", &format!("rejected: {e}"));
                return protocol::Response::error("invalid run_id_short");
            }
            if allow_rules.len() > validate::MAX_ALLOW_RULES {
                audit::log_action(
                    caller_uid,
                    caller_pid,
                    "setup_netns",
                    &format!("rejected: {} rules exceeds max {}", allow_rules.len(), validate::MAX_ALLOW_RULES),
                );
                return protocol::Response::error("too many allow rules");
            }
            for (i, rule) in allow_rules.iter().enumerate() {
                if let Err(e) = validate::validate_allow_rule(rule) {
                    audit::log_action(
                        caller_uid,
                        caller_pid,
                        "setup_netns",
                        &format!("rejected: rule[{i}]: {e}"),
                    );
                    return protocol::Response::error("invalid allow rule");
                }
            }
            audit::log_action(
                caller_uid,
                caller_pid,
                "setup_netns",
                &format!("pid={sandbox_pid} run={run_id_short} rules={}", allow_rules.len()),
            );
            // TODO: implement veth pair + NAT + nftables setup. Generate
            // the nft script HERE from `allow_rules` (see oaie-netpol's
            // generate_nft_script for the template). Never accept a
            // pre-built script from the caller — that would be an
            // arbitrary-command channel into CAP_NET_ADMIN.
            protocol::Response::error("setup_netns not yet implemented")
        }

        protocol::Request::CleanupNetns { host_iface, nat_subnet, host_default_iface } => {
            if let Err(e) = validate::validate_iface_name(host_iface)
                .and_then(|_| validate::validate_iface_name(host_default_iface))
                .and_then(|_| validate::validate_subnet(nat_subnet))
            {
                audit::log_action(caller_uid, caller_pid, "cleanup_netns", &format!("rejected: {e}"));
                return protocol::Response::error("invalid netns parameters");
            }
            audit::log_action(
                caller_uid,
                caller_pid,
                "cleanup_netns",
                &format!("iface={host_iface} subnet={nat_subnet} default={host_default_iface}"),
            );
            // TODO: implement host-side netns cleanup.
            protocol::Response::error("cleanup_netns not yet implemented")
        }
    }
}

/// Handle a LoadBpf request: two-phase flow.
///
/// 1. Validate, load BPF programs, attach to tracepoints.
/// 2. Send response with ring buffer + link FDs via SCM_RIGHTS.
/// 3. Wait for UnloadBpf or socket close.
/// 4. Drop BPF handles (detaches probes, closes FDs).
#[cfg(feature = "ebpf")]
fn handle_load_bpf(
    stream: &mut std::os::unix::net::UnixStream,
    cgroup_id: u64,
    ring_buffer_size: u32,
    caller_uid: Option<u32>,
    caller_pid: Option<u32>,
) {
    // Validate ring buffer size.
    if let Err(e) = validate::validate_ring_buffer_size(ring_buffer_size) {
        audit::log_action(caller_uid, caller_pid, "load_bpf", &format!("rejected: {e}"));
        // Send error via sendmsg (no length prefix) to match the client's
        // recv_response_with_fds which uses recvmsg, not length-prefixed read.
        let resp = protocol::Response::error("invalid ring buffer size");
        if let Ok(payload) = serde_json::to_vec(&resp) {
            let _ = oaie_priv::fd_passing::send_response_with_fds(stream, &payload, &[]);
        }
        return;
    }

    // Validate cgroup_id: reject the wildcard (0 = "trace everything" in the
    // BPF program's cgroup_match()) and verify the caller owns the target
    // cgroup under /sys/fs/cgroup/oaie (cgroup.procs was chowned to the
    // creator's UID by create_cgroup).
    let authorized = caller_uid.map_or(false, |uid| {
        cgroup_id != 0
            && std::fs::read_dir("/sys/fs/cgroup/oaie")
                .into_iter()
                .flatten()
                .flatten()
                .any(|entry| {
                    use std::os::unix::fs::MetadataExt;
                    entry.metadata().ok().map(|m| m.ino()) == Some(cgroup_id)
                        && std::fs::metadata(entry.path().join("cgroup.procs"))
                            .ok()
                            .map(|m| m.uid())
                            == Some(uid)
                })
    });
    if !authorized {
        audit::log_action(caller_uid, caller_pid, "load_bpf", &format!("rejected: unauthorized cgroup_id={cgroup_id}"));
        let resp = protocol::Response::error("unauthorized cgroup");
        if let Ok(payload) = serde_json::to_vec(&resp) {
            let _ = oaie_priv::fd_passing::send_response_with_fds(stream, &payload, &[]);
        }
        return;
    }

    audit::log_action(
        caller_uid,
        caller_pid,
        "load_bpf",
        &format!("loading: cgroup_id={cgroup_id}, ring_buf={ring_buffer_size}"),
    );

    // Load and attach BPF programs.
    let handles = match oaie_priv::bpf::load_and_attach(cgroup_id, ring_buffer_size) {
        Ok(h) => h,
        Err(e) => {
            audit::log_action(caller_uid, caller_pid, "load_bpf", &format!("failed: {e}"));
            // Send error via sendmsg (no length prefix) to match the client's
            // recv_response_with_fds which uses recvmsg, not length-prefixed read.
            let resp = protocol::Response::error("BPF loading failed");
            if let Ok(payload) = serde_json::to_vec(&resp) {
                let _ = oaie_priv::fd_passing::send_response_with_fds(stream, &payload, &[]);
            }
            return;
        }
    };

    // Build response with FD count.
    let fd_count = 1 + handles.link_fds.len() as u32; // ring_buf + links
    let response = protocol::Response::ok_with_fds(fd_count);

    // Collect all FDs to pass: ring buffer first, then link FDs.
    let mut fds = vec![handles.ring_buffer_fd];
    fds.extend_from_slice(&handles.link_fds);

    // Send response with FDs via SCM_RIGHTS.
    let payload = match serde_json::to_vec(&response) {
        Ok(p) => p,
        Err(e) => {
            audit::log_action(caller_uid, caller_pid, "load_bpf", &format!("serialize error: {e}"));
            return;
        }
    };

    if let Err(e) = oaie_priv::fd_passing::send_response_with_fds(stream, &payload, &fds) {
        audit::log_action(caller_uid, caller_pid, "load_bpf", &format!("fd_pass error: {e}"));
        return;
    }

    audit::log_action(caller_uid, caller_pid, "load_bpf", &format!("ok: {fd_count} fds sent"));

    // Phase 2: Wait for UnloadBpf or socket close.
    // The BPF programs stay attached as long as `handles` is alive.
    // Remove the longer read timeout for the wait phase.
    // 60-second timeout for the wait phase.  If the client crashes without
    // sending UnloadBpf or closing the socket, we don't want to hold
    // elevated capabilities for too long.  The typical OAIE run has a
    // max timeout of ~600s, but BPF program attachment needs much less.
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(60)));

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut len_buf = [0u8; 4];
    loop {
        if std::time::Instant::now() >= deadline {
            audit::log_action(caller_uid, caller_pid, "unload_bpf", "deadline exceeded");
            break;
        }
        match stream.read_exact(&mut len_buf) {
            Ok(()) => {
                let req_len = u32::from_be_bytes(len_buf);
                if req_len > MAX_REQUEST_SIZE {
                    break;
                }
                let mut req_buf = vec![0u8; req_len as usize];
                if stream.read_exact(&mut req_buf).is_err() {
                    break;
                }
                if let Ok(req) = serde_json::from_slice::<protocol::Request>(&req_buf) {
                    if matches!(req, protocol::Request::UnloadBpf) {
                        audit::log_action(caller_uid, caller_pid, "unload_bpf", "ok");
                        // Send ok response.
                        let resp = protocol::Response::ok();
                        if let Ok(payload) = serde_json::to_vec(&resp) {
                            let len = payload.len() as u32;
                            let _ = stream.write_all(&len.to_be_bytes());
                            let _ = stream.write_all(&payload);
                        }
                        break;
                    }
                }
            }
            Err(_) => {
                // Socket closed by client — clean up.
                audit::log_action(caller_uid, caller_pid, "unload_bpf", "socket closed");
                break;
            }
        }
    }

    // handles dropped here → BPF programs detached, FDs closed.
}

fn send_error(stream: &mut std::os::unix::net::UnixStream, msg: &str) -> std::io::Result<()> {
    let resp = protocol::Response::error(msg);
    let payload = serde_json::to_vec(&resp).unwrap_or_default();
    let len = payload.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&payload)
}

/// Get peer credentials from a Unix socket via SO_PEERCRED.
///
/// Returns the kernel-verified `ucred` struct containing UID, GID, and PID
/// of the connected peer. This cannot be forged by the client.
fn get_peer_cred(stream: &std::os::unix::net::UnixStream) -> Option<libc::ucred> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret == 0 { Some(cred) } else { None }
}
