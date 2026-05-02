//! Host-side vsock communication with the Firecracker VM.
//!
//! Firecracker proxies AF_VSOCK connections from the guest to a Unix domain
//! socket on the host. The host creates a listener on the UDS path, and when
//! the guest connects via AF_VSOCK (CID=2, port=1024), Firecracker connects
//! to `{uds_path}_{port}` on the host side.
//!
//! This module provides:
//! - `VsockHost`: listens for the guest agent connection
//! - `VsockStream`: framed send/recv over the established connection

use std::io;
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::wire::{self, Message};

/// Default vsock port the guest agent connects on.
pub const GUEST_PORT: u32 = 1024;

/// Host-side vsock listener. Waits for the guest agent to connect.
pub struct VsockHost {
    /// Path to the Firecracker vsock UDS (without port suffix).
    uds_path: PathBuf,
    /// The port number used for the listen socket path suffix.
    port: u32,
    /// The actual listener (on `{uds_path}_{port}`).
    listener: UnixListener,
}

impl VsockHost {
    /// Create a new vsock host listener.
    ///
    /// The `uds_path` is the vsock UDS path configured in Firecracker's
    /// vsock device. Firecracker creates `{uds_path}_{port}` when the guest
    /// connects on that port.
    ///
    /// This pre-creates the listener socket at `{uds_path}_{port}` so that
    /// when Firecracker proxies the guest connection, it finds a listener.
    pub fn new(uds_path: &Path, port: u32) -> io::Result<Self> {
        let listen_path = format!("{}_{}", uds_path.display(), port);
        let listen_path = PathBuf::from(&listen_path);

        // Remove stale socket if present.
        let _ = std::fs::remove_file(&listen_path);

        let listener = UnixListener::bind(&listen_path)?;
        // Non-blocking so we can implement timeouts.
        listener.set_nonblocking(true)?;

        Ok(Self {
            uds_path: uds_path.to_path_buf(),
            port,
            listener,
        })
    }

    /// Wait for the guest agent to connect, with a timeout.
    ///
    /// Returns a `VsockStream` for framed communication once the guest
    /// connects and sends `AgentReady`.
    pub fn accept(&self, timeout: Duration) -> io::Result<VsockStream> {
        let deadline = Instant::now() + timeout;

        loop {
            match self.listener.accept() {
                Ok((stream, _addr)) => {
                    stream.set_nonblocking(false)?;
                    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
                    return Ok(VsockStream { stream });
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "timed out waiting for guest agent connection",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Path to the vsock UDS (without port suffix).
    pub fn uds_path(&self) -> &Path {
        &self.uds_path
    }
}

impl Drop for VsockHost {
    fn drop(&mut self) {
        // Clean up the listener socket using the stored port.
        let listen_path = format!("{}_{}", self.uds_path.display(), self.port);
        let _ = std::fs::remove_file(&listen_path);
    }
}

/// Reader wrapper that enforces an absolute deadline across an entire
/// framed read. SO_RCVTIMEO alone is a per-`read()` inactivity timer, so a
/// peer that trickles >=1 byte per window could otherwise hold `read_exact`
/// indefinitely inside `wire::decode`.
struct DeadlineReader<'a> {
    inner: &'a mut UnixStream,
    deadline: Instant,
}

impl io::Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "frame read deadline exceeded",
            ));
        }
        io::Read::read(&mut *self.inner, buf)
    }
}

/// Framed communication channel over a vsock connection.
///
/// Uses the wire protocol's length-prefixed JSON framing.
pub struct VsockStream {
    stream: UnixStream,
}

impl VsockStream {
    /// Send a message to the peer.
    pub fn send(&mut self, msg: &Message) -> io::Result<()> {
        wire::send(&mut self.stream, msg)
    }

    /// Receive a message from the peer.
    ///
    /// Returns `None` at EOF (peer disconnected).
    pub fn recv(&mut self) -> io::Result<Option<Message>> {
        wire::recv(&mut self.stream)
    }

    /// Receive a message with a custom read timeout.
    ///
    /// `timeout` is enforced as an absolute deadline for the whole frame
    /// (header + payload), not just a per-`read()` inactivity timer.
    pub fn recv_timeout(&mut self, timeout: Duration) -> io::Result<Option<Message>> {
        self.stream.set_read_timeout(Some(timeout))?;
        let mut reader = DeadlineReader {
            inner: &mut self.stream,
            deadline: Instant::now() + timeout,
        };
        let result = wire::recv(&mut reader);
        // Restore default timeout (ignore error — worst case is wrong timeout on next call).
        let _ = self.stream.set_read_timeout(Some(Duration::from_secs(30)));
        result
    }

    /// Shut down the stream.
    pub fn shutdown(&self) -> io::Result<()> {
        self.stream.shutdown(Shutdown::Both)
    }

    /// Get a reference to the underlying Unix stream (for advanced use).
    pub fn inner(&self) -> &UnixStream {
        &self.stream
    }
}
