//! Network policy enforcement for OAIE sandboxes.
//!
//! Provides allowlist-mode networking: an isolated network namespace with
//! outbound connectivity filtered by nftables rules so only specified
//! endpoints are reachable.
//!
//! Architecture:
//! - **resolve**: Pre-resolve hostnames to IPs on the host before sandbox start.
//! - **nftables**: Generate and apply nftables rules inside the sandbox netns.
//! - **veth**: Create veth pair + NAT for outbound connectivity from isolated ns.
//! - **enforcer**: Top-level orchestration combining all the above.
//!
//! Follows the same pattern as `oaie-cgroup`: depends on `oaie-core` only,
//! integrated by `oaie-cli`.

pub mod dns_proxy;
pub mod dns_wire;
pub mod domain;
pub mod enforcer;
pub mod error;
pub mod nftables;
pub mod resolve;
pub mod sni;
pub mod veth;
