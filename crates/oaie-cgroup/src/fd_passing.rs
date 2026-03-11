//! SCM_RIGHTS file descriptor passing — client side.
//!
//! Mirror of `oaie-priv/src/fd_passing.rs` for the unprivileged client.
//! Receives file descriptors sent by oaie-priv after BPF program loading.

use std::io;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;

/// Receive a response payload with file descriptors via SCM_RIGHTS.
///
/// Returns the payload bytes and a vector of received file descriptors.
/// `max_size` limits the payload buffer. `max_fds` limits the FD count.
pub fn recv_response_with_fds(
    stream: &UnixStream,
    max_size: usize,
    max_fds: usize,
) -> io::Result<(Vec<u8>, Vec<RawFd>)> {
    use std::os::unix::io::AsRawFd;

    let mut buf = vec![0u8; max_size];
    let iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let fd_bytes = max_fds * std::mem::size_of::<RawFd>();
    let cmsg_space = unsafe { libc::CMSG_SPACE(fd_bytes as u32) } as usize;
    let mut cmsg_buf = vec![0u64; cmsg_space.div_ceil(8)]; // u64 for alignment

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space;

    let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    if n == 0 {
        return Err(io::Error::other("connection closed by peer"));
    }

    // Check if ancillary data was truncated (FDs silently dropped by kernel).
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::other(
            "ancillary data truncated (MSG_CTRUNC) — FDs may have been lost",
        ));
    }

    buf.truncate(n as usize);

    // Parse ancillary data for SCM_RIGHTS.
    let mut fds = Vec::new();
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        unsafe {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data_ptr = libc::CMSG_DATA(cmsg);
                let data_len = (*cmsg).cmsg_len - libc::CMSG_LEN(0) as usize;
                let fd_count = data_len / std::mem::size_of::<RawFd>();
                for i in 0..fd_count {
                    let fd_ptr = data_ptr.add(i * std::mem::size_of::<RawFd>()) as *const RawFd;
                    fds.push(std::ptr::read_unaligned(fd_ptr));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    Ok((buf, fds))
}

/// Send a request payload over a Unix stream (no FDs attached).
///
/// Used by the BPF client to send LoadBpf/UnloadBpf requests.
pub fn send_request(stream: &UnixStream, request_bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;

    // Use standard length-prefixed framing (same as priv_client).
    let len = request_bytes.len() as u32;
    let mut stream = stream;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(request_bytes)?;
    Ok(())
}
