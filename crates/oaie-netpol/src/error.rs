//! Network policy error types.

use std::fmt;

/// Errors that can occur during network policy enforcement.
#[derive(Debug)]
pub enum NetpolError {
    /// DNS resolution failed for a hostname.
    DnsResolution { host: String, reason: String },
    /// Invalid CIDR notation in an allow rule.
    InvalidCidr { cidr: String, reason: String },
    /// Failed to set up veth pair.
    VethSetup(String),
    /// Failed to apply nftables rules.
    NftablesApply(String),
    /// nftables binary not found on the system.
    NftablesNotFound,
    /// nsenter binary not found on the system.
    NsenterNotFound,
    /// Failed to set up NAT.
    NatSetup(String),
    /// IP forwarding not enabled.
    IpForwardDisabled,
    /// General I/O error.
    Io(std::io::Error),
}

impl fmt::Display for NetpolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DnsResolution { host, reason } => {
                write!(f, "DNS resolution failed for '{host}': {reason}")
            }
            Self::InvalidCidr { cidr, reason } => {
                write!(f, "invalid CIDR '{cidr}': {reason}")
            }
            Self::VethSetup(msg) => write!(f, "veth setup failed: {msg}"),
            Self::NftablesApply(msg) => write!(f, "nftables apply failed: {msg}"),
            Self::NftablesNotFound => write!(f, "nftables (nft) not found in PATH"),
            Self::NsenterNotFound => write!(f, "nsenter not found in PATH"),
            Self::NatSetup(msg) => write!(f, "NAT setup failed: {msg}"),
            Self::IpForwardDisabled => write!(f, "net.ipv4.ip_forward is not enabled"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for NetpolError {}

impl From<std::io::Error> for NetpolError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Convert NetpolError to OaieError for integration with the broader error type.
impl From<NetpolError> for oaie_core::error::OaieError {
    fn from(e: NetpolError) -> Self {
        oaie_core::error::OaieError::SandboxError(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, NetpolError>;
