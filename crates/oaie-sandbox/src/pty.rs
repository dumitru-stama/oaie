//! Pseudoterminal (PTY) allocation for interactive sandbox mode.
//!
//! Uses raw libc calls (no new dependencies) to allocate a PTY pair.
//! The master fd stays with the supervisor; the child opens the slave
//! path and uses it as its controlling terminal.

use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

use oaie_core::error::{OaieError, Result};

/// A PTY master/slave pair.
///
/// The master fd is kept by the parent process for bidirectional I/O:
/// writes go to the child's stdin, reads come from the child's stdout/stderr.
/// The slave path (e.g. `/dev/pts/3`) is opened by the child after fork.
pub struct PtyPair {
    /// Master side — parent reads output and writes input through this fd.
    pub master: OwnedFd,
    /// Filesystem path to the slave device (e.g. `/dev/pts/3`).
    /// The child opens this path and dup2's it to stdin/stdout/stderr.
    pub slave_path: PathBuf,
}

/// Allocate a new pseudoterminal pair.
///
/// Uses POSIX `posix_openpt()` → `grantpt()` → `unlockpt()` → `ptsname_r()`
/// sequence. The master fd has `O_RDWR | O_NOCTTY | O_CLOEXEC` set.
pub fn allocate_pty() -> Result<PtyPair> {
    unsafe {
        // Open the master side of the PTY.
        let master_fd = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        if master_fd < 0 {
            let errno = *libc::__errno_location();
            return Err(OaieError::SandboxError(format!(
                "posix_openpt failed: errno {errno}"
            )));
        }

        // Grant access to the slave side (changes owner/permissions).
        if libc::grantpt(master_fd) != 0 {
            let errno = *libc::__errno_location();
            libc::close(master_fd);
            return Err(OaieError::SandboxError(format!(
                "grantpt failed: errno {errno}"
            )));
        }

        // Unlock the slave side so it can be opened.
        if libc::unlockpt(master_fd) != 0 {
            let errno = *libc::__errno_location();
            libc::close(master_fd);
            return Err(OaieError::SandboxError(format!(
                "unlockpt failed: errno {errno}"
            )));
        }

        // Get the slave device path via ptsname_r (thread-safe).
        let mut buf = [0u8; 256];
        if libc::ptsname_r(master_fd, buf.as_mut_ptr() as *mut libc::c_char, buf.len()) != 0 {
            let errno = *libc::__errno_location();
            libc::close(master_fd);
            return Err(OaieError::SandboxError(format!(
                "ptsname_r failed: errno {errno}"
            )));
        }

        // Find the NUL terminator and convert to PathBuf.
        let nul_pos = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let slave_path = PathBuf::from(
            std::str::from_utf8(&buf[..nul_pos])
                .map_err(|_| OaieError::SandboxError("ptsname_r returned invalid UTF-8".into()))?,
        );

        Ok(PtyPair {
            master: OwnedFd::from_raw_fd(master_fd),
            slave_path,
        })
    }
}

/// Set the terminal window size on a PTY master fd.
///
/// The PTY line discipline automatically delivers `SIGWINCH` to the child's
/// foreground process group when the window size changes.
pub fn set_window_size(fd: RawFd, rows: u16, cols: u16) -> Result<()> {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    // TIOCSWINSZ = 0x5414
    let ret = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) };
    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(OaieError::SandboxError(format!(
            "TIOCSWINSZ failed: errno {errno}"
        )));
    }

    Ok(())
}
