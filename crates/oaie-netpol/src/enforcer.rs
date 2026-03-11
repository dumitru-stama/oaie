//! Top-level network policy orchestration.
//!
//! Combines DNS pre-resolution, veth pair setup, and nftables rule application
//! into a single entry point called from the sandbox runner's `post_map_hook`.

use nix::unistd::Pid;

use oaie_core::policy::AllowRule;

use crate::error::{NetpolError, Result};
use crate::nftables;
use crate::resolve::{self, ResolvedAllowRule};
use crate::veth::{self, VethSetup};

/// State handle for active network enforcement.
///
/// Holds references needed for cleanup and for adding dynamic rules
/// (e.g., from the DNS proxy when resolving wildcard domains).
pub struct NetworkEnforcement {
    /// veth pair setup (if created). None when running via oaie-priv.
    pub veth: Option<VethSetup>,
    /// Resolved allowlist rules used for enforcement.
    pub resolved_rules: Vec<ResolvedAllowRule>,
    /// PID of the sandbox child (for dynamic rule updates).
    pub sandbox_pid: u32,
}

/// Enforce an allowlist network policy for a sandbox child.
///
/// Called from `post_map_hook` — the parent side, while the child is
/// blocked on the sync pipe (after UID/GID maps but before exec).
///
/// Steps:
/// 1. Pre-resolve all hostnames to IP addresses (on the host).
/// 2. Set up veth pair + NAT for outbound connectivity.
/// 3. Apply nftables rules inside the sandbox namespace.
///
/// The child will be unblocked after this returns, with network
/// filtering already in place.
pub fn enforce_allowlist(
    pid: Pid,
    rules: &[AllowRule],
    run_id_short: &str,
) -> Result<NetworkEnforcement> {
    let raw_pid = pid.as_raw() as u32;

    // Step 1: Pre-resolve hostnames.
    log::info!(
        "enforcing network allowlist ({} rules) for pid {}",
        rules.len(),
        raw_pid
    );
    let resolved = resolve::resolve_rules(rules)?;

    // Step 2: Set up veth + NAT.
    let veth = match veth::setup_veth(raw_pid, run_id_short) {
        Ok(v) => Some(v),
        Err(e) => {
            log::error!("veth setup failed: {e} — sandbox will have no outbound connectivity");
            return Err(e);
        }
    };

    // Step 3: Generate and apply nftables rules.
    let script = nftables::generate_nft_script(&resolved);
    if let Err(e) = nftables::apply_in_netns(raw_pid, &script) {
        // Cleanup veth on nftables failure to avoid a sandbox with
        // unrestricted connectivity.
        if let Some(ref v) = veth {
            let _ = veth::cleanup_veth(v);
        }
        return Err(e);
    }

    log::info!(
        "network allowlist enforced for pid {} ({} rules, {} resolved IPs)",
        raw_pid,
        rules.len(),
        resolved.iter().map(|r| r.addrs.len()).sum::<usize>()
    );

    Ok(NetworkEnforcement {
        veth,
        resolved_rules: resolved,
        sandbox_pid: raw_pid,
    })
}

/// Clean up network enforcement after the sandbox exits.
///
/// Best-effort: when the namespace is destroyed, all its interfaces and
/// nftables rules vanish automatically. This cleans up the host-side
/// veth interface and iptables masquerade rule.
pub fn cleanup(enforcement: &NetworkEnforcement) -> Result<()> {
    // nftables cleanup is best-effort (namespace may already be gone).
    let _ = nftables::cleanup_in_netns(enforcement.sandbox_pid);

    // veth cleanup removes host-side interface + NAT rule.
    if let Some(ref v) = enforcement.veth {
        let _ = veth::cleanup_veth(v);
    }

    Ok(())
}

/// Add a dynamic nftables rule for a newly-resolved IP.
///
/// Used by the DNS proxy when resolving wildcard domains that produce
/// new IP addresses at runtime.
pub fn add_dynamic_endpoint(
    enforcement: &NetworkEnforcement,
    addr: std::net::IpAddr,
    port: u16,
    protocol: &str,
) -> std::result::Result<(), NetpolError> {
    nftables::add_dynamic_rule(enforcement.sandbox_pid, addr, port, protocol)
}
