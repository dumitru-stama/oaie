//! Backend abstraction for OAIE execution engines.
//!
//! Defines `BackendKind` (enum dispatch, not trait objects) and supporting
//! types used by the runner to select between namespace isolation, bare
//! execution, and Firecracker microVM backends.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::OaieError;

/// Which execution backend to use for this run.
///
/// Enum dispatch — the runner matches on this value to select the execution
/// path. Avoids trait-object lifetime complexity with `ChunkedEventWriter`
/// ownership transfer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    /// Linux namespace isolation (user, mount, pid, net, ipc, uts, cgroup).
    /// Shares the host kernel — strongest isolation available without a VM.
    #[default]
    Namespace,
    /// No isolation — run the command directly on the host.
    Bare,
    /// Firecracker microVM — hardware-enforced (KVM) isolation with a
    /// separate kernel and rootfs. Strongest isolation tier.
    Firecracker,
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Namespace => write!(f, "namespace"),
            Self::Bare => write!(f, "bare"),
            Self::Firecracker => write!(f, "firecracker"),
        }
    }
}

impl FromStr for BackendKind {
    type Err = OaieError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "namespace" => Ok(Self::Namespace),
            "bare" => Ok(Self::Bare),
            "firecracker" => Ok(Self::Firecracker),
            _ => Err(OaieError::InvalidJobSpec(format!(
                "unknown backend: {s} (expected: namespace, bare, firecracker)"
            ))),
        }
    }
}

/// Capabilities and characteristics of a backend.
///
/// Used by the runner to decide which features are available for a given
/// backend selection (e.g. whether ptrace tracing works, whether cgroups
/// are meaningful).
#[derive(Clone, Debug)]
pub struct BackendCaps {
    /// Human-readable isolation tier: "namespace", "bare", "microvm".
    pub isolation_level: &'static str,
    /// Whether ptrace-based syscall tracing is supported.
    pub supports_trace_ptrace: bool,
    /// Whether eBPF-based tracing is supported.
    pub supports_trace_ebpf: bool,
    /// Whether host-side cgroup isolation is meaningful.
    pub supports_cgroup: bool,
    /// Whether the backend requires root or elevated privileges.
    pub needs_root: bool,
}

impl BackendKind {
    /// Return the capabilities for this backend kind.
    pub fn caps(&self) -> BackendCaps {
        match self {
            Self::Namespace => BackendCaps {
                isolation_level: "namespace",
                supports_trace_ptrace: true,
                supports_trace_ebpf: true,
                supports_cgroup: true,
                needs_root: false,
            },
            Self::Bare => BackendCaps {
                isolation_level: "bare",
                supports_trace_ptrace: false,
                supports_trace_ebpf: false,
                supports_cgroup: false,
                needs_root: false,
            },
            Self::Firecracker => BackendCaps {
                isolation_level: "microvm",
                supports_trace_ptrace: false,
                supports_trace_ebpf: false,
                supports_cgroup: false,
                needs_root: false, // KVM group membership, not root
            },
        }
    }
}
