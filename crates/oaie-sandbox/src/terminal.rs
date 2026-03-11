//! Terminal state management for interactive sandbox mode.
//!
//! Provides raw mode entry/exit and window size queries using raw libc
//! calls (no new dependencies). `RawModeGuard` restores the original
//! terminal state on drop — critical for cleanup on panic/signal.

use std::os::unix::io::RawFd;

use oaie_core::error::{OaieError, Result};

/// RAII guard that restores the terminal to its original state on drop.
///
/// Created by [`enter_raw_mode()`]. When dropped (including on panic),
/// restores the saved termios settings so the user's terminal isn't
/// left in an unusable state.
pub struct RawModeGuard {
    fd: RawFd,
    original: libc::termios,
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        // Best-effort restore — nothing useful to do if this fails.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original);
        }
    }
}

/// Put the terminal into raw mode for direct character-by-character I/O.
///
/// Disables canonical mode, echo, signal generation, and output processing
/// so keystrokes are forwarded verbatim to the PTY master. The returned
/// guard restores the original settings when dropped.
///
/// # Arguments
/// * `fd` — File descriptor of the terminal (typically 0 for stdin).
pub fn enter_raw_mode(fd: RawFd) -> Result<RawModeGuard> {
    let mut original: libc::termios = unsafe { std::mem::zeroed() };

    if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(OaieError::SandboxError(format!(
            "tcgetattr failed: errno {errno}"
        )));
    }

    let mut raw = original;

    // cfmakeraw equivalent — disable everything that would process input
    // or output before we see it.
    //
    // Input flags: no break interrupt, no CR-to-NL, no parity check,
    // no strip 8th bit, no XON/XOFF flow control.
    raw.c_iflag &= !(libc::BRKINT
        | libc::ICRNL
        | libc::INPCK
        | libc::ISTRIP
        | libc::IXON
        | libc::IXOFF
        | libc::IGNBRK
        | libc::IGNCR
        | libc::INLCR
        | libc::PARMRK);

    // Output flags: no output processing.
    raw.c_oflag &= !libc::OPOST;

    // Control flags: 8-bit characters.
    raw.c_cflag &= !(libc::CSIZE | libc::PARENB);
    raw.c_cflag |= libc::CS8;

    // Local flags: no echo, no canonical mode, no signal generation,
    // no extended input processing.
    raw.c_lflag &= !(libc::ECHO | libc::ICANON | libc::IEXTEN | libc::ISIG);

    // Control characters: read returns immediately with whatever is available.
    raw.c_cc[libc::VMIN] = 1; // At least 1 byte
    raw.c_cc[libc::VTIME] = 0; // No timeout

    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw) } != 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(OaieError::SandboxError(format!(
            "tcsetattr (raw mode) failed: errno {errno}"
        )));
    }

    Ok(RawModeGuard { fd, original })
}

/// Query the terminal window size (rows, columns).
///
/// Returns `(rows, cols)` from `TIOCGWINSZ`. Falls back to `(24, 80)`
/// if the ioctl fails (e.g. stdin is not a terminal).
pub fn get_window_size(fd: RawFd) -> (u16, u16) {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };

    // TIOCGWINSZ = 0x5413
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_row > 0 && ws.ws_col > 0
    {
        (ws.ws_row, ws.ws_col)
    } else {
        // Sensible defaults when not connected to a real terminal.
        (24, 80)
    }
}
