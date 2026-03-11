//! Cgroup v2 per-run isolation for OAIE sandboxes.
//!
//! Provides detection, scope creation, limit application, stats collection,
//! and cleanup for cgroup v2 scopes. Supports two creation methods:
//! - `systemd-run --user --scope` (preferred, no extra privileges)
//! - `oaie-priv` privileged helper (for systems without systemd user session)

pub mod bpf_client;
pub mod cleanup;
pub mod detect;
pub mod ebpf_detect;
pub mod fd_passing;
pub mod limits;
pub mod priv_client;
pub mod scope;
pub mod stats;
