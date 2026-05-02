//! Length-prefixed JSON protocol for oaie-priv IPC.
//!
//! Wire format: 4-byte big-endian length prefix + JSON payload.
//! Both request and response use the same framing.

use std::net::IpAddr;

use oaie_core::cgroup::CgroupLimits;
use serde::{Deserialize, Serialize};

/// One entry in the netns egress allowlist. The privileged helper
/// reconstructs the nft script from these typed fields — the unprivileged
/// caller never holds raw nft command text.
/// Mirrors the fields `oaie_netpol::nftables::generate_nft_script` actually
/// reads from `ResolvedAllowRule`, using std-only types so oaie-priv's
/// dependency surface stays minimal.
#[derive(Debug, Serialize, Deserialize)]
pub struct NetAllowRule {
    /// Resolved IP addresses (one rule emitted per address).
    /// Empty if `cidr` is set.
    #[serde(default)]
    pub addrs: Vec<IpAddr>,
    /// CIDR network in canonical text form, e.g. "10.0.0.0/24" or
    /// "2001:db8::/32". Mutually exclusive with `addrs`.
    #[serde(default)]
    pub cidr: Option<String>,
    /// Destination port (1..=65535, validated as nonzero).
    pub port: u16,
    /// Transport protocol: exactly "tcp" or "udp".
    pub protocol: String,
}

/// Request sent from the oaie-cgroup client to the oaie-priv helper.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum Request {
    /// Create a cgroup scope for a run with the given limits.
    #[serde(rename = "create_cgroup")]
    CreateCgroup { run_id: String, limits: CgroupLimits },
    /// Clean up (remove) a cgroup scope at the given path.
    #[serde(rename = "cleanup_cgroup")]
    CleanupCgroup { cgroup_path: String },
    /// Load BPF programs, attach to tracepoints, and return FDs.
    /// This starts a two-phase flow: oaie-priv stays alive until
    /// `UnloadBpf` is received or the socket is closed.
    #[serde(rename = "load_bpf")]
    LoadBpf {
        /// Cgroup ID to filter events on (from `stat(cgroup_path).st_ino`).
        cgroup_id: u64,
        /// Ring buffer size in bytes (must be power of 2, 256KB..4MB).
        ring_buffer_size: u32,
    },
    /// Unload BPF programs and close all handles. Sent on the same
    /// socket that received `LoadBpf`.
    #[serde(rename = "unload_bpf")]
    UnloadBpf,
    /// Health check — responds with ok=true.
    #[serde(rename = "ping")]
    Ping,
    /// Set up network namespace for allowlist mode: veth pair + NAT + nftables.
    /// The nft script is generated *here*, on the privileged side, from
    /// validated `allow_rules` — never accepted as caller-supplied text.
    #[serde(rename = "setup_netns")]
    SetupNetns { sandbox_pid: u32, run_id_short: String, allow_rules: Vec<NetAllowRule> },
    /// Clean up network namespace host-side resources.
    #[serde(rename = "cleanup_netns")]
    CleanupNetns { host_iface: String, nat_subnet: String, host_default_iface: String },
}

/// Response sent from the oaie-priv helper back to the client.
#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    /// Whether the operation succeeded.
    pub ok: bool,
    /// Cgroup filesystem path (only for successful create_cgroup).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup_path: Option<String>,
    /// Error message (only for failed operations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Number of BPF file descriptors attached via SCM_RIGHTS
    /// (only for successful load_bpf). First FD is the ring buffer,
    /// remaining FDs are tracepoint link handles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bpf_fd_count: Option<u32>,
}

impl Response {
    /// Successful response with no additional data.
    pub fn ok() -> Self {
        Self {
            ok: true,
            cgroup_path: None,
            error: None,
            bpf_fd_count: None,
        }
    }

    /// Successful create_cgroup response with the cgroup path.
    pub fn ok_with_path(path: &str) -> Self {
        Self {
            ok: true,
            cgroup_path: Some(path.into()),
            error: None,
            bpf_fd_count: None,
        }
    }

    /// Successful load_bpf response with FD count.
    pub fn ok_with_fds(fd_count: u32) -> Self {
        Self {
            ok: true,
            cgroup_path: None,
            error: None,
            bpf_fd_count: Some(fd_count),
        }
    }

    /// Error response with a message.
    pub fn error(msg: &str) -> Self {
        Self {
            ok: false,
            cgroup_path: None,
            error: Some(msg.into()),
            bpf_fd_count: None,
        }
    }
}
