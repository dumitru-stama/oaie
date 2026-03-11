//! Wire protocol for host ↔ guest communication over AF_VSOCK.
//!
//! Uses length-prefixed JSON framing (same pattern as oaie-priv):
//! - 4-byte big-endian length prefix
//! - JSON payload
//! - Maximum frame size: 16 MiB
//!
//! The `Message` enum defines the protocol. The host sends `RunJob` and
//! `Shutdown`; the guest sends `AgentReady`, `OutputChunk`, `JobDone`,
//! and `Error`.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Maximum frame size: 16 MiB. Protects against malicious/corrupt frames
/// exhausting memory.
pub const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

/// Messages exchanged between host and guest agent over the vsock channel.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    /// Guest → Host: agent is ready to receive commands.
    AgentReady {
        /// Guest agent version string.
        version: String,
    },

    /// Host → Guest: run a command inside the VM.
    RunJob {
        /// Command and arguments (argv).
        command: Vec<String>,
        /// Environment variables to set.
        #[serde(default)]
        env: HashMap<String, String>,
        /// Optional timeout in seconds.
        #[serde(default)]
        timeout_secs: Option<u64>,
        /// Whether to enable ptrace on the child.
        #[serde(default)]
        trace: bool,
    },

    /// Guest → Host: chunk of stdout or stderr output.
    OutputChunk {
        /// Which stream: "stdout" or "stderr".
        stream: String,
        /// Base64-encoded output data.
        data: String,
    },

    /// Guest → Host: a trace event captured by ptrace inside the VM.
    TraceEvent {
        /// JSON-serialized trace event.
        event: String,
    },

    /// Guest → Host: the command finished.
    JobDone {
        /// Process exit code.
        exit_code: i32,
        /// Wall-clock duration in milliseconds.
        duration_ms: u64,
    },

    /// Host → Guest: shut down the VM.
    Shutdown,

    /// Either direction: an error occurred.
    Error {
        /// Human-readable error message.
        message: String,
    },
}

/// Encode a message as a length-prefixed JSON frame.
pub fn encode(msg: &Message) -> io::Result<Vec<u8>> {
    let json = serde_json::to_vec(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Check size as usize first before truncating to u32, otherwise a
    // payload > 4 GiB would silently wrap and pass the size check.
    if json.len() > MAX_FRAME_SIZE as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {} bytes (max {})", json.len(), MAX_FRAME_SIZE),
        ));
    }
    let len = json.len() as u32;

    let mut buf = Vec::with_capacity(4 + json.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&json);
    Ok(buf)
}

/// Read a single length-prefixed JSON frame from a reader.
///
/// Returns `None` at EOF (zero-length read on the length prefix).
pub fn decode<R: Read>(reader: &mut R) -> io::Result<Option<Message>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {} bytes (max {})", len, MAX_FRAME_SIZE),
        ));
    }

    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload)?;

    let msg: Message = serde_json::from_slice(&payload)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(msg))
}

/// Write a message to a writer, flushing after.
pub fn send<W: Write>(writer: &mut W, msg: &Message) -> io::Result<()> {
    let frame = encode(msg)?;
    writer.write_all(&frame)?;
    writer.flush()
}

/// Convenience: read a message with a deadline.
///
/// This is a blocking read — for async use, wrap in tokio::task::spawn_blocking
/// or use the vsock module's async interface.
pub fn recv<R: Read>(reader: &mut R) -> io::Result<Option<Message>> {
    decode(reader)
}

impl Message {
    /// Create an AgentReady message with the current version.
    pub fn agent_ready() -> Self {
        Message::AgentReady {
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Create a simple RunJob message.
    pub fn run_job(
        command: Vec<String>,
        env: HashMap<String, String>,
        timeout: Option<Duration>,
        trace: bool,
    ) -> Self {
        Message::RunJob {
            command,
            env,
            timeout_secs: timeout.map(|d| d.as_secs()),
            trace,
        }
    }

    /// Create a JobDone message.
    pub fn job_done(exit_code: i32, duration: Duration) -> Self {
        Message::JobDone {
            exit_code,
            duration_ms: duration.as_millis().min(u64::MAX as u128) as u64,
        }
    }

    /// Create an OutputChunk for stdout.
    pub fn stdout_chunk(data: &[u8]) -> Self {
        Message::OutputChunk {
            stream: "stdout".to_string(),
            data: base64_encode(data),
        }
    }

    /// Create an OutputChunk for stderr.
    pub fn stderr_chunk(data: &[u8]) -> Self {
        Message::OutputChunk {
            stream: "stderr".to_string(),
            data: base64_encode(data),
        }
    }
}

/// Simple base64 encoding (no external dependency for minimal guest binary).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Simple base64 decoding.
pub fn base64_decode(s: &str) -> io::Result<Vec<u8>> {
    fn val(c: u8) -> io::Result<u32> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid base64 byte: {}", c),
            )),
        }
    }

    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let chunks = bytes.chunks(4);

    for chunk in chunks {
        if chunk.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "base64 input not a multiple of 4",
            ));
        }

        let pad = chunk.iter().filter(|&&b| b == b'=').count();

        let a = val(chunk[0])?;
        let b = val(chunk[1])?;
        let c = if chunk[2] != b'=' { val(chunk[2])? } else { 0 };
        let d = if chunk[3] != b'=' { val(chunk[3])? } else { 0 };

        let triple = (a << 18) | (b << 12) | (c << 6) | d;

        out.push((triple >> 16) as u8);
        if pad < 2 {
            out.push((triple >> 8) as u8);
        }
        if pad < 1 {
            out.push(triple as u8);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let messages = vec![
            Message::agent_ready(),
            Message::Shutdown,
            Message::Error {
                message: "test error".to_string(),
            },
            Message::job_done(42, Duration::from_millis(1234)),
            Message::stdout_chunk(b"hello world"),
            Message::stderr_chunk(b"error output"),
            Message::RunJob {
                command: vec!["echo".into(), "hello".into()],
                env: HashMap::from([("FOO".into(), "bar".into())]),
                timeout_secs: Some(30),
                trace: false,
            },
        ];

        for msg in &messages {
            let encoded = encode(msg).unwrap();
            let decoded = decode(&mut &encoded[..]).unwrap().unwrap();
            assert_eq!(&decoded, msg);
        }
    }

    #[test]
    fn frame_too_large() {
        // Try to encode a message with > MAX_FRAME_SIZE payload.
        let large_data = "x".repeat(MAX_FRAME_SIZE as usize + 1);
        let msg = Message::Error { message: large_data };
        assert!(encode(&msg).is_err());
    }

    #[test]
    fn decode_oversized_length() {
        // Fabricate a frame header claiming > MAX_FRAME_SIZE.
        let len = (MAX_FRAME_SIZE + 1).to_be_bytes();
        let result = decode(&mut &len[..]);
        assert!(result.is_err());
    }

    #[test]
    fn decode_eof() {
        let empty: &[u8] = &[];
        let result = decode(&mut &*empty).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn base64_roundtrip() {
        let cases: &[&[u8]] = &[
            b"",
            b"f",
            b"fo",
            b"foo",
            b"foobar",
            b"hello world",
            &[0, 1, 2, 255, 254, 253],
        ];
        for &data in cases {
            let encoded = base64_encode(data);
            let decoded = base64_decode(&encoded).unwrap();
            assert_eq!(decoded, data, "roundtrip failed for {:?}", data);
        }
    }

    #[test]
    fn multiple_messages_on_stream() {
        let messages = vec![
            Message::agent_ready(),
            Message::stdout_chunk(b"line 1\n"),
            Message::stderr_chunk(b"err\n"),
            Message::job_done(0, Duration::from_secs(1)),
        ];

        // Write all messages to a buffer.
        let mut buf = Vec::new();
        for msg in &messages {
            send(&mut buf, msg).unwrap();
        }

        // Read them back.
        let mut cursor = &buf[..];
        for expected in &messages {
            let got = recv(&mut cursor).unwrap().unwrap();
            assert_eq!(&got, expected);
        }
        // Should be EOF now.
        assert!(recv(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn serde_tag_format() {
        // Verify the JSON tag format is correct.
        let msg = Message::Shutdown;
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"shutdown\""), "got: {json}");

        let msg = Message::agent_ready();
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"agent_ready\""), "got: {json}");
    }
}
