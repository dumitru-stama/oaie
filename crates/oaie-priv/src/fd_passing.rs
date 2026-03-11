//! SCM_RIGHTS file descriptor passing over Unix sockets.
//!
//! Used by the BPF loading flow: oaie-priv loads BPF programs (which requires
//! elevated capabilities), then passes the ring buffer and link file descriptors
//! to the unprivileged client via SCM_RIGHTS ancillary messages.

use std::io;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;

/// Aligned buffer for cmsg data. `cmsghdr` requires alignment to
/// `size_of::<usize>()` (8 bytes on x86_64).
#[repr(C, align(8))]
struct CmsgBuf {
    data: [u8; 256],
}

/// Send a response payload with file descriptors via SCM_RIGHTS.
///
/// The response bytes are sent as the regular payload. File descriptors are
/// attached as ancillary data using SOL_SOCKET/SCM_RIGHTS.
pub fn send_response_with_fds(
    stream: &UnixStream,
    response_bytes: &[u8],
    fds: &[RawFd],
) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    // Build the iovec for the payload.
    let iov = libc::iovec {
        iov_base: response_bytes.as_ptr() as *mut libc::c_void,
        iov_len: response_bytes.len(),
    };

    // Calculate cmsg buffer size for SCM_RIGHTS.
    let fd_bytes = std::mem::size_of_val(fds);
    let cmsg_space = unsafe { libc::CMSG_SPACE(fd_bytes as u32) } as usize;
    assert!(cmsg_space <= 256, "too many FDs for cmsg buffer");
    let mut cmsg_buf = CmsgBuf { data: [0u8; 256] };

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.data.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space;

    // Fill the cmsg header and copy FDs.
    let cmsg: *mut libc::cmsghdr = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(io::Error::other("CMSG_FIRSTHDR returned null"));
    }
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(fd_bytes as u32) as usize;

        let data_ptr = libc::CMSG_DATA(cmsg);
        std::ptr::copy_nonoverlapping(
            fds.as_ptr() as *const u8,
            data_ptr,
            fd_bytes,
        );
    }

    let ret = unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // Check for short write (unlikely on Unix domain sockets with small
    // payloads, but correctness requires it).
    if (ret as usize) != response_bytes.len() {
        return Err(io::Error::other(format!(
            "short sendmsg: sent {} of {} bytes",
            ret, response_bytes.len()
        )));
    }

    Ok(())
}

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
