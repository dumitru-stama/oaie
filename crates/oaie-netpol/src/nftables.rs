//! nftables rule generation and application for network allowlists.
//!
//! Generates nft batch scripts from resolved allow rules and applies them
//! inside a network namespace via `nsenter`. The script creates:
//! - A table `inet oaie_filter` with a chain `output` (default policy: drop)
//! - Rules for established/related connections (stateful)
//! - Rules for loopback traffic
//! - Per-endpoint accept rules for each allowed IP:port/protocol

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

use crate::error::{NetpolError, Result};
use crate::resolve::ResolvedAllowRule;

/// Name of the nftables table used inside the sandbox namespace.
const TABLE_NAME: &str = "oaie_filter";

/// Return true if `addr` is a non-global address (loopback / RFC1918 /
/// link-local / CGNAT 100.64/10 / multicast / unspecified, or an IPv4-mapped
/// IPv6 form of any of those) that must never be opened in the sandbox's
/// egress firewall. DNS-rebinding guard shared by BOTH the static pre-resolve
/// path (`generate_nft_script`) and the dynamic path (`add_dynamic_rule`).
fn is_non_global(addr: &IpAddr) -> bool {
    fn v4(a: &Ipv4Addr) -> bool {
        a.is_loopback() || a.is_private() || a.is_link_local() || a.is_unspecified() || a.is_broadcast() || a.is_multicast() || (a.octets()[0] == 100 && (a.octets()[1] & 0xc0) == 64)
        // 100.64.0.0/10 (RFC 6598)
    }
    match addr {
        IpAddr::V4(a) => v4(a),
        IpAddr::V6(a) => {
            let s = a.segments();
            // NAT64 well-known prefix 64:ff9b::/96 (RFC 6052) embeds an IPv4
            // address in the low 32 bits — judge as v4, same as ::ffff:0:0/96.
            // The original v6 arm tested only segments[0] which is 0x0064 here
            // (passes all the >=0xfc00 checks), so 64:ff9b::10.0.0.1 slipped
            // through as "global".
            if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
                return v4(&Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8));
            }
            match a.to_ipv4_mapped() {
                Some(mapped) => v4(&mapped), // ::ffff:0:0/96 — judge as v4
                None => {
                    a.is_loopback() || a.is_unspecified() || a.is_multicast()
                    || (s[0] & 0xfe00) == 0xfc00  // unique-local fc00::/7
                    || (s[0] & 0xffc0) == 0xfe80
                } // link-local fe80::/10
            }
        }
    }
}

/// Generate an nft batch script for a set of resolved allow rules.
///
/// The script creates a table with a single output chain that drops
/// everything except explicitly allowed destinations.
pub fn generate_nft_script(rules: &[ResolvedAllowRule]) -> String {
    let mut lines = Vec::new();

    // Create table and output chain with default drop policy.
    lines.push(format!("add table inet {TABLE_NAME}"));
    lines.push(format!("add chain inet {TABLE_NAME} output {{ type filter hook output priority 0; policy drop; }}"));

    // Allow established/related connections (stateful tracking).
    lines.push(format!("add rule inet {TABLE_NAME} output ct state established,related accept"));

    // Allow all loopback traffic (needed for DNS proxy on 127.0.0.53).
    lines.push(format!("add rule inet {TABLE_NAME} output oifname \"lo\" accept"));

    // Per-rule accept entries with byte counters for budget tracking (N.1).
    for rule in rules {
        // Defense-in-depth: re-validate protocol at the nft generation layer
        // to prevent injection even if upstream validation is bypassed.
        let proto = match rule.protocol.as_str() {
            "tcp" => "tcp",
            "udp" => "udp",
            other => {
                log::error!("nft script generation: invalid protocol '{other}', skipping rule");
                continue;
            }
        };
        // Port 0 is invalid for tcp/udp rules.
        if rule.port == 0 {
            log::error!("nft script generation: port 0 is invalid, skipping rule");
            continue;
        }
        if let Some(ref net) = rule.cidr {
            // CIDR rule — match the entire network range.
            let family = if net.addr().is_ipv4() { "ip" } else { "ip6" };
            lines.push(format!("add rule inet {TABLE_NAME} output {family} daddr {net} {proto} dport {} counter accept", rule.port));
        } else {
            // Host rule — one entry per resolved IP address.
            for addr in &rule.addrs {
                if is_non_global(addr) {
                    log::warn!("nft: skipping non-global resolved address {addr} (DNS rebinding guard)");
                    continue;
                }
                let family = if addr.is_ipv4() { "ip" } else { "ip6" };
                lines.push(format!("add rule inet {TABLE_NAME} output {family} daddr {addr} {proto} dport {} counter accept", rule.port));
            }
        }
    }

    // Allow DNS to the local proxy (UDP + TCP port 53 on loopback).
    // Already covered by the loopback rule above, but be explicit.
    lines.push(format!("add rule inet {TABLE_NAME} output ip daddr 127.0.0.53 udp dport 53 accept"));
    lines.push(format!("add rule inet {TABLE_NAME} output ip daddr 127.0.0.53 tcp dport 53 accept"));

    lines.join("\n") + "\n"
}

/// Apply nftables rules inside a network namespace via nsenter.
///
/// The script is piped to `nft -f -` via stdin of nsenter.
/// Requires `nsenter` and `nft` to be available on the host.
///
/// Takes a `BorrowedFd` on the netns, NOT a pid. The path
/// `/proc/self/fd/{fd}` resolves to the netns the open fd pins,
/// regardless of what `/proc/{pid}/ns/net` resolves to NOW. This
/// matters for the DNS proxy: the sandbox can exit, get reaped, and
/// its PID get reused by an unrelated process — all during one
/// in-flight forward_query (up to 10s upstream-DNS wait). nsenter
/// against `/proc/{reused_pid}/ns/net` enters the WRONG netns and
/// installs the rule there. `enforcer::cleanup` documents the same
/// hazard for the cleanup path ("by the time cleanup() runs, waitpid()
/// has already reaped the child, so the PID may have been reused");
/// the proxy_loop sibling has a wider window.
/// (LoadBpf cgroup_id TOCTOU): hold the fd until after the act.
pub fn apply_in_netns(netns_fd: std::os::fd::BorrowedFd<'_>, script: &str) -> Result<()> {
    // Verify nft is available.
    check_nft_available()?;

    // /proc/self/fd/N is a magic symlink to whatever fd N opened. nsenter
    // resolves it; the open fd pins the netns past PID reuse.
    let net_ns = format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&netns_fd));
    let output = Command::new("nsenter")
        .args(["--net", &net_ns, "--", "nft", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                NetpolError::NsenterNotFound
            } else {
                NetpolError::NftablesApply(format!("failed to spawn nsenter: {e}"))
            }
        })
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(script.as_bytes())?;
            }
            drop(child.stdin.take());
            child.wait_with_output().map_err(|e| NetpolError::NftablesApply(e.to_string()))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NetpolError::NftablesApply(format!("nft exited with {}: {}", output.status, stderr.trim())));
    }

    log::info!("applied nftables rules in netns (fd {})", std::os::fd::AsRawFd::as_raw_fd(&netns_fd));
    Ok(())
}

/// Add a single dynamic rule to an existing nftables table.
///
/// Used by the DNS proxy to add newly resolved IPs for wildcard domains.
/// Takes a netns fd — see `apply_in_netns` doc for the PID-reuse rationale.
pub fn add_dynamic_rule(netns_fd: std::os::fd::BorrowedFd<'_>, addr: IpAddr, port: u16, protocol: &str) -> Result<()> {
    // Re-validate protocol to prevent malformed nft scripts.
    if protocol != "tcp" && protocol != "udp" {
        return Err(NetpolError::NftablesApply(format!("invalid protocol '{protocol}': must be 'tcp' or 'udp'")));
    }
    // Reject non-global addresses: DNS responses for wildcard domains can
    // return loopback/private/link-local IPs (DNS rebinding) — never open
    // firewall holes to those. Filter at the sink so all callers are covered.
    if is_non_global(&addr) {
        return Err(NetpolError::NftablesApply(format!("refusing dynamic rule for non-global address {addr}")));
    }
    let family = if addr.is_ipv4() { "ip" } else { "ip6" };
    let script = format!("add rule inet {TABLE_NAME} output {family} daddr {addr} {protocol} dport {port} accept\n");
    apply_in_netns(netns_fd, &script)
}

/// Read cumulative byte counter from the nftables table inside a namespace.
///
/// Parses `nft list table inet oaie_filter` output and sums all byte counters.
/// Returns `None` if nftables is not available or parsing fails.
/// Takes a netns fd — see `apply_in_netns` doc for the PID-reuse rationale.
pub fn read_byte_counters(netns_fd: std::os::fd::BorrowedFd<'_>) -> Option<u64> {
    let net_ns = format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&netns_fd));
    let output = match Command::new("nsenter")
        .args(["--net", &net_ns, "--", "nft", "list", "table", "inet", TABLE_NAME])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return None,
    };

    let text = String::from_utf8_lossy(&output.stdout);
    Some(parse_byte_counters(&text))
}

/// Parse byte counters from `nft list table` output.
///
/// Looks for `counter packets N bytes N` patterns and sums all byte values.
fn parse_byte_counters(nft_output: &str) -> u64 {
    let mut total: u64 = 0;
    for line in nft_output.lines() {
        // Pattern: "counter packets <N> bytes <N>"
        if let Some(pos) = line.find("bytes ") {
            let after = &line[pos + 6..];
            // Take digits until non-digit.
            let num_str: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(n) = num_str.parse::<u64>() {
                total = total.saturating_add(n);
            }
        }
    }
    total
}

/// Tear down the nftables table inside a namespace (best-effort).
///
/// Called during cleanup. Errors are logged but not propagated since
/// the namespace will be destroyed anyway. Takes a netns fd — see
/// `apply_in_netns` doc for the PID-reuse rationale. `enforcer::cleanup`
/// deliberately avoids calling this and instead lets the netns destroy
/// itself when the last process exits.
pub fn cleanup_in_netns(netns_fd: std::os::fd::BorrowedFd<'_>) -> Result<()> {
    let net_ns = format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&netns_fd));
    let script = format!("delete table inet {TABLE_NAME}\n");

    let output = Command::new("nsenter")
        .args(["--net", &net_ns, "--", "nft", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(script.as_bytes());
            }
            drop(child.stdin.take());
            child.wait_with_output()
        });

    match output {
        Ok(o) if o.status.success() => {
            log::debug!("cleaned up nftables in netns (fd {})", std::os::fd::AsRawFd::as_raw_fd(&netns_fd));
        }
        Ok(o) => {
            log::warn!("nftables cleanup failed (netns fd {}): {}", std::os::fd::AsRawFd::as_raw_fd(&netns_fd), String::from_utf8_lossy(&o.stderr).trim());
        }
        Err(e) => {
            log::warn!("nftables cleanup spawn failed (netns fd {}): {e}", std::os::fd::AsRawFd::as_raw_fd(&netns_fd));
        }
    }

    Ok(())
}

/// Check that nft binary is available in PATH.
fn check_nft_available() -> Result<()> {
    match Command::new("nft").arg("--version").output() {
        Ok(o) if o.status.success() => Ok(()),
        Ok(_) => Err(NetpolError::NftablesNotFound),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(NetpolError::NftablesNotFound),
        Err(e) => Err(NetpolError::NftablesApply(format!("failed to check nft: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::ResolvedAllowRule;

    #[test]
    fn script_generation_basic() {
        let rules = vec![ResolvedAllowRule {
            hostname: Some("api.example.com".into()),
            addrs: vec!["1.2.3.4".parse().unwrap()],
            cidr: None,
            port: 443,
            protocol: "tcp".into(),
        }];

        let script = generate_nft_script(&rules);
        assert!(script.contains("add table inet oaie_filter"));
        assert!(script.contains("policy drop"));
        assert!(script.contains("ct state established,related accept"));
        assert!(script.contains("oifname \"lo\" accept"));
        assert!(script.contains("ip daddr 1.2.3.4 tcp dport 443 counter accept"));
    }

    #[test]
    fn script_generation_ipv6() {
        let rules = vec![ResolvedAllowRule {
            hostname: Some("example.com".into()),
            addrs: vec!["2001:db8::1".parse().unwrap()],
            cidr: None,
            port: 443,
            protocol: "tcp".into(),
        }];

        let script = generate_nft_script(&rules);
        assert!(script.contains("ip6 daddr 2001:db8::1 tcp dport 443 counter accept"));
    }

    #[test]
    fn script_generation_cidr() {
        let rules = vec![ResolvedAllowRule {
            hostname: None,
            addrs: vec!["10.0.0.0".parse().unwrap()],
            cidr: Some("10.0.0.0/24".parse().unwrap()),
            port: 80,
            protocol: "tcp".into(),
        }];

        let script = generate_nft_script(&rules);
        assert!(script.contains("ip daddr 10.0.0.0/24 tcp dport 80 counter accept"));
    }

    #[test]
    fn script_generation_multiple_addrs() {
        let rules = vec![ResolvedAllowRule {
            hostname: Some("multi.example.com".into()),
            addrs: vec!["1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap()],
            cidr: None,
            port: 443,
            protocol: "tcp".into(),
        }];

        let script = generate_nft_script(&rules);
        assert!(script.contains("ip daddr 1.2.3.4 tcp dport 443 counter accept"));
        assert!(script.contains("ip daddr 5.6.7.8 tcp dport 443 counter accept"));
    }

    #[test]
    fn script_has_dns_proxy_rules() {
        let rules = vec![];
        let script = generate_nft_script(&rules);
        assert!(script.contains("ip daddr 127.0.0.53 udp dport 53 accept"));
        assert!(script.contains("ip daddr 127.0.0.53 tcp dport 53 accept"));
    }

    #[test]
    fn parse_byte_counters_basic() {
        let nft_output = r#"table inet oaie_filter {
    chain output {
        type filter hook output priority filter; policy drop;
        ct state established,related accept
        oifname "lo" accept
        ip daddr 1.2.3.4 tcp dport 443 counter packets 10 bytes 5000 accept
        ip daddr 5.6.7.8 tcp dport 443 counter packets 3 bytes 1500 accept
    }
}"#;
        assert_eq!(super::parse_byte_counters(nft_output), 6500);
    }

    #[test]
    fn parse_byte_counters_empty() {
        assert_eq!(super::parse_byte_counters(""), 0);
        assert_eq!(super::parse_byte_counters("no counters here"), 0);
    }

    #[test]
    fn parse_byte_counters_zero() {
        let nft_output = "ip daddr 1.2.3.4 tcp dport 443 counter packets 0 bytes 0 accept";
        assert_eq!(super::parse_byte_counters(nft_output), 0);
    }
}
