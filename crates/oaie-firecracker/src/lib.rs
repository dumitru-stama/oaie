//! Firecracker microVM backend for OAIE.
//!
//! Provides VM-level isolation by running tool commands inside a Firecracker
//! microVM with a separate kernel and rootfs. Communication between host and
//! guest uses AF_VSOCK (proxied by Firecracker to a Unix domain socket).

pub mod api;
pub mod detect;
pub mod image;
pub mod rootfs;
pub mod vm;
pub mod vsock;
pub mod wire;
