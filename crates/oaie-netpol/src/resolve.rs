//! DNS pre-resolution for network allowlist rules.
//!
//! Resolves hostnames to concrete IP addresses on the HOST side before
//! enforcement. This ensures nftables rules use real IPs. CIDR rules
//! pass through without DNS lookup.
//!
//! Resolution is fail-closed: if any hostname fails to resolve, the entire
//! operation fails. This prevents accidental allowlist bypass.

use std::net::{IpAddr, ToSocketAddrs};

use ipnet::IpNet;

use oaie_core::policy::AllowRule;

use crate::error::{NetpolError, Result};

/// A resolved version of [`AllowRule`] with concrete IP addresses.
#[derive(Clone, Debug)]
pub struct ResolvedAllowRule {
    /// Original hostname, if this rule came from a `host` field.
    pub hostname: Option<String>,
    /// Resolved IP addresses (A + AAAA records) or parsed CIDR range.
    pub addrs: Vec<IpAddr>,
    /// CIDR network, if this rule came from a `cidr` field.
    pub cidr: Option<IpNet>,
    /// Destination port.
    pub port: u16,
    /// Transport protocol ("tcp" or "udp").
    pub protocol: String,
}

/// Resolve a list of [`AllowRule`]s to concrete IP addresses.
///
/// Called on the HOST (outside sandbox) before enforcement.
/// Fails if any hostname cannot be resolved (fail-closed).
pub fn resolve_rules(rules: &[AllowRule]) -> Result<Vec<ResolvedAllowRule>> {
    let mut resolved = Vec::with_capacity(rules.len());

    for rule in rules {
        resolved.push(resolve_one(rule)?);
    }

    Ok(resolved)
}

/// Resolve a single allow rule.
fn resolve_one(rule: &AllowRule) -> Result<ResolvedAllowRule> {
    if let Some(ref host) = rule.host {
        // DNS resolution — resolve both A and AAAA records.
        let sock_addr = format!("{}:{}", host, rule.port);
        let addrs: Vec<IpAddr> = sock_addr
            .to_socket_addrs()
            .map_err(|e| NetpolError::DnsResolution {
                host: host.clone(),
                reason: e.to_string(),
            })?
            .map(|sa| sa.ip())
            .collect();

        if addrs.is_empty() {
            return Err(NetpolError::DnsResolution {
                host: host.clone(),
                reason: "no addresses returned".into(),
            });
        }

        log::info!(
            "resolved {} -> {} address(es): {}",
            host,
            addrs.len(),
            addrs
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );

        Ok(ResolvedAllowRule {
            hostname: Some(host.clone()),
            addrs,
            cidr: None,
            port: rule.port,
            protocol: rule.protocol.clone(),
        })
    } else if let Some(ref cidr) = rule.cidr {
        // CIDR — parse and expand to representative addresses for nftables.
        let net: IpNet = cidr.parse().map_err(|e: ipnet::AddrParseError| {
            NetpolError::InvalidCidr {
                cidr: cidr.clone(),
                reason: e.to_string(),
            }
        })?;

        Ok(ResolvedAllowRule {
            hostname: None,
            addrs: vec![net.addr()],
            cidr: Some(net),
            port: rule.port,
            protocol: rule.protocol.clone(),
        })
    } else {
        // Should not happen if AllowRule::validate() was called, but be safe.
        Err(NetpolError::DnsResolution {
            host: "(none)".into(),
            reason: "allow rule has neither host nor cidr".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_cidr_rule() {
        let rule = AllowRule {
            host: None,
            cidr: Some("10.0.0.0/24".into()),
            port: 443,
            protocol: "tcp".into(),
        };
        let resolved = resolve_rules(&[rule]).unwrap();
        assert_eq!(resolved.len(), 1);
        assert!(resolved[0].cidr.is_some());
        assert_eq!(resolved[0].port, 443);
    }

    #[test]
    fn resolve_invalid_cidr_fails() {
        let rule = AllowRule {
            host: None,
            cidr: Some("not-a-cidr".into()),
            port: 443,
            protocol: "tcp".into(),
        };
        assert!(resolve_rules(&[rule]).is_err());
    }

    #[test]
    fn resolve_localhost() {
        let rule = AllowRule {
            host: Some("localhost".into()),
            cidr: None,
            port: 80,
            protocol: "tcp".into(),
        };
        let resolved = resolve_rules(&[rule]).unwrap();
        assert_eq!(resolved.len(), 1);
        assert!(!resolved[0].addrs.is_empty());
        assert_eq!(resolved[0].hostname.as_deref(), Some("localhost"));
    }

    #[test]
    fn resolve_no_host_no_cidr_fails() {
        let rule = AllowRule {
            host: None,
            cidr: None,
            port: 443,
            protocol: "tcp".into(),
        };
        assert!(resolve_rules(&[rule]).is_err());
    }
}
