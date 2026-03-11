//! Linux namespace isolation for OAIE runs.
//!
//! Uses mount, PID, network, and user namespaces to create a sandboxed
//! execution environment. The child process sees a minimal root filesystem
//! with read-only input, read-write output, and no access to the host.
//!
//! Entry point: [`sandbox::spawn_sandboxed()`] creates a new namespace and
//! returns pipe handles for stdout/stderr capture.

pub mod landlock;
pub mod probe;
pub mod pty;
pub mod sandbox;
pub mod terminal;
pub mod mounts;
pub mod seccomp;
