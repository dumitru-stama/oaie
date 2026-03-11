//! Tests for the network policy system (Phase H).
//!
//! Covers NetworkMode serde, AllowRule validation, DNS resolution, nftables
//! script generation, domain matching, DNS wire format, CLI --net flag parsing,
//! backward compatibility, and preset resolution.

use oaie_core::policy::{self, AllowRule, NetworkMode, Policy};

// ── NetworkMode serde ──

#[test]
fn network_mode_serde_bool_true() {
    // Backward compat: `network = true` in TOML → NetworkMode::On
    let toml_str = r#"
name = "test"
[defaults]
network = true
trace = "off"
[mounts]
deny = []
[limits]
max_memory = "512M"
max_time = "5m"
max_pids = 64
max_fsize = "1G"
allow_memfd = false
"#;
    let policy: Policy = toml::from_str(toml_str).unwrap();
    assert_eq!(policy.defaults.network, NetworkMode::On);
}

#[test]
fn network_mode_serde_bool_false() {
    // Backward compat: `network = false` in TOML → NetworkMode::Off
    let toml_str = r#"
name = "test"
[defaults]
network = false
trace = "off"
[mounts]
deny = []
[limits]
max_memory = "512M"
max_time = "5m"
max_pids = 64
max_fsize = "1G"
allow_memfd = false
"#;
    let policy: Policy = toml::from_str(toml_str).unwrap();
    assert_eq!(policy.defaults.network, NetworkMode::Off);
}

#[test]
fn network_mode_serde_string_on() {
    let toml_str = r#"
name = "test"
[defaults]
network = "on"
trace = "off"
[mounts]
deny = []
[limits]
max_memory = "512M"
max_time = "5m"
max_pids = 64
max_fsize = "1G"
allow_memfd = false
"#;
    let policy: Policy = toml::from_str(toml_str).unwrap();
    assert_eq!(policy.defaults.network, NetworkMode::On);
}

#[test]
fn network_mode_serde_string_off() {
    let toml_str = r#"
name = "test"
[defaults]
network = "off"
trace = "off"
[mounts]
deny = []
[limits]
max_memory = "512M"
max_time = "5m"
max_pids = 64
max_fsize = "1G"
allow_memfd = false
"#;
    let policy: Policy = toml::from_str(toml_str).unwrap();
    assert_eq!(policy.defaults.network, NetworkMode::Off);
}

#[test]
fn network_mode_serde_toml_table_allowlist() {
    // Table form: [defaults.network] with mode = "allowlist" and [[defaults.network.allow]]
    let toml_str = r#"
name = "test"
[defaults]
trace = "off"

[defaults.network]
mode = "allowlist"

[[defaults.network.allow]]
host = "api.anthropic.com"
port = 443
protocol = "tcp"

[[defaults.network.allow]]
host = "api.openai.com"
port = 443

[mounts]
deny = []
[limits]
max_memory = "512M"
max_time = "5m"
max_pids = 64
max_fsize = "1G"
allow_memfd = false
"#;
    let policy: Policy = toml::from_str(toml_str).unwrap();
    match &policy.defaults.network {
        NetworkMode::Allowlist(rules) => {
            assert_eq!(rules.len(), 2);
            assert_eq!(rules[0].host.as_deref(), Some("api.anthropic.com"));
            assert_eq!(rules[0].port, 443);
            assert_eq!(rules[1].host.as_deref(), Some("api.openai.com"));
        }
        other => panic!("expected Allowlist, got {other:?}"),
    }
}

#[test]
fn network_mode_serde_toml_table_rejects_allow_with_wrong_mode() {
    // mode = "on" with allow rules should error.
    let toml_str = r#"
name = "test"
[defaults]
trace = "off"

[defaults.network]
mode = "on"

[[defaults.network.allow]]
host = "api.anthropic.com"
port = 443

[mounts]
deny = []
[limits]
max_memory = "512M"
max_time = "5m"
max_pids = 64
max_fsize = "1G"
allow_memfd = false
"#;
    let result: Result<Policy, _> = toml::from_str(toml_str);
    assert!(result.is_err(), "mode='on' with allow rules should be rejected");
}

#[test]
fn parse_net_flag_cidr_no_protocol() {
    // CIDR without explicit protocol should default to tcp.
    let mode = policy::parse_net_flag("allow:10.0.0.0/24:443").unwrap();
    match mode {
        NetworkMode::Allowlist(rules) => {
            assert_eq!(rules.len(), 1);
            assert_eq!(rules[0].cidr.as_deref(), Some("10.0.0.0/24"));
            assert_eq!(rules[0].port, 443);
            assert_eq!(rules[0].protocol, "tcp");
        }
        other => panic!("expected Allowlist, got {other:?}"),
    }
}

#[test]
fn parse_net_flag_cidr_with_protocol() {
    let mode = policy::parse_net_flag("allow:10.0.0.0/24:53/udp").unwrap();
    match mode {
        NetworkMode::Allowlist(rules) => {
            assert_eq!(rules[0].cidr.as_deref(), Some("10.0.0.0/24"));
            assert_eq!(rules[0].port, 53);
            assert_eq!(rules[0].protocol, "udp");
        }
        other => panic!("expected Allowlist, got {other:?}"),
    }
}

// ── AllowRule validation ──

#[test]
fn allow_rule_valid_host() {
    let rule = AllowRule {
        host: Some("api.anthropic.com".into()),
        cidr: None,
        port: 443,
        protocol: "tcp".into(),
    };
    assert!(rule.validate().is_ok());
}

#[test]
fn allow_rule_valid_cidr() {
    let rule = AllowRule {
        host: None,
        cidr: Some("10.0.0.0/24".into()),
        port: 80,
        protocol: "tcp".into(),
    };
    assert!(rule.validate().is_ok());
}

#[test]
fn allow_rule_both_host_and_cidr_rejected() {
    let rule = AllowRule {
        host: Some("example.com".into()),
        cidr: Some("10.0.0.0/24".into()),
        port: 443,
        protocol: "tcp".into(),
    };
    assert!(rule.validate().is_err());
}

#[test]
fn allow_rule_neither_host_nor_cidr_rejected() {
    let rule = AllowRule {
        host: None,
        cidr: None,
        port: 443,
        protocol: "tcp".into(),
    };
    assert!(rule.validate().is_err());
}

#[test]
fn allow_rule_invalid_protocol_rejected() {
    let rule = AllowRule {
        host: Some("example.com".into()),
        cidr: None,
        port: 443,
        protocol: "sctp".into(),
    };
    assert!(rule.validate().is_err());
}

#[test]
fn allow_rule_zero_port_rejected() {
    let rule = AllowRule {
        host: Some("example.com".into()),
        cidr: None,
        port: 0,
        protocol: "tcp".into(),
    };
    assert!(rule.validate().is_err());
}

// ── NetworkMode methods ──

#[test]
fn network_mode_needs_netns() {
    assert!(NetworkMode::Off.needs_netns());
    assert!(!NetworkMode::On.needs_netns());
    assert!(NetworkMode::Allowlist(vec![]).needs_netns());
}

#[test]
fn network_mode_has_connectivity() {
    assert!(!NetworkMode::Off.has_connectivity());
    assert!(NetworkMode::On.has_connectivity());
    assert!(NetworkMode::Allowlist(vec![]).has_connectivity());
}

#[test]
fn network_mode_is_on() {
    assert!(!NetworkMode::Off.is_on());
    assert!(NetworkMode::On.is_on());
    assert!(!NetworkMode::Allowlist(vec![]).is_on());
}

// ── DNS pre-resolution ──

#[test]
fn resolve_cidr_rule() {
    let rule = AllowRule {
        host: None,
        cidr: Some("192.168.1.0/24".into()),
        port: 443,
        protocol: "tcp".into(),
    };
    let resolved = oaie_netpol::resolve::resolve_rules(&[rule]).unwrap();
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
    assert!(oaie_netpol::resolve::resolve_rules(&[rule]).is_err());
}

#[test]
fn resolve_localhost_host() {
    let rule = AllowRule {
        host: Some("localhost".into()),
        cidr: None,
        port: 80,
        protocol: "tcp".into(),
    };
    let resolved = oaie_netpol::resolve::resolve_rules(&[rule]).unwrap();
    assert!(!resolved[0].addrs.is_empty());
}

// ── nftables script generation ──

#[test]
fn nftables_script_basic_structure() {
    let rules = vec![oaie_netpol::resolve::ResolvedAllowRule {
        hostname: Some("api.example.com".into()),
        addrs: vec!["1.2.3.4".parse().unwrap()],
        cidr: None,
        port: 443,
        protocol: "tcp".into(),
    }];

    let script = oaie_netpol::nftables::generate_nft_script(&rules);
    assert!(script.contains("add table inet oaie_filter"));
    assert!(script.contains("policy drop"));
    assert!(script.contains("ct state established,related accept"));
    assert!(script.contains("oifname \"lo\" accept"));
    assert!(script.contains("ip daddr 1.2.3.4 tcp dport 443 counter accept"));
    assert!(script.contains("ip daddr 127.0.0.53 udp dport 53 accept"));
}

#[test]
fn nftables_script_ipv6() {
    let rules = vec![oaie_netpol::resolve::ResolvedAllowRule {
        hostname: None,
        addrs: vec!["2001:db8::1".parse().unwrap()],
        cidr: None,
        port: 443,
        protocol: "tcp".into(),
    }];

    let script = oaie_netpol::nftables::generate_nft_script(&rules);
    assert!(script.contains("ip6 daddr 2001:db8::1 tcp dport 443 counter accept"));
}

#[test]
fn nftables_script_cidr() {
    let rules = vec![oaie_netpol::resolve::ResolvedAllowRule {
        hostname: None,
        addrs: vec!["10.0.0.0".parse().unwrap()],
        cidr: Some("10.0.0.0/24".parse().unwrap()),
        port: 80,
        protocol: "tcp".into(),
    }];

    let script = oaie_netpol::nftables::generate_nft_script(&rules);
    assert!(script.contains("ip daddr 10.0.0.0/24 tcp dport 80 counter accept"));
}

// ── Domain pattern matching ──

#[test]
fn domain_exact_match() {
    let p = oaie_netpol::domain::DomainPattern::parse("api.anthropic.com");
    assert!(p.matches("api.anthropic.com"));
    assert!(p.matches("API.ANTHROPIC.COM"));
    assert!(!p.matches("cdn.anthropic.com"));
}

#[test]
fn domain_wildcard_match() {
    let p = oaie_netpol::domain::DomainPattern::parse("*.anthropic.com");
    assert!(p.matches("api.anthropic.com"));
    assert!(p.matches("cdn.anthropic.com"));
    assert!(!p.matches("anthropic.com"));
    assert!(!p.matches("evil-anthropic.com"));
}

#[test]
fn domain_matches_any() {
    let patterns = vec![
        oaie_netpol::domain::DomainPattern::parse("api.anthropic.com"),
        oaie_netpol::domain::DomainPattern::parse("*.openai.com"),
    ];
    assert!(oaie_netpol::domain::matches_any("api.anthropic.com", &patterns));
    assert!(oaie_netpol::domain::matches_any("api.openai.com", &patterns));
    assert!(!oaie_netpol::domain::matches_any("evil.example.com", &patterns));
}

// ── DNS wire format ──

#[test]
fn dns_wire_extract_query() {
    // Build a minimal A query for "example.com".
    let mut pkt = vec![
        0x12, 0x34, 0x01, 0x00, // ID + flags
        0x00, 0x01, 0x00, 0x00, // QDCOUNT=1
        0x00, 0x00, 0x00, 0x00, // NSCOUNT=0, ARCOUNT=0
    ];
    // "example" label
    pkt.push(7);
    pkt.extend_from_slice(b"example");
    // "com" label
    pkt.push(3);
    pkt.extend_from_slice(b"com");
    pkt.push(0); // root
    pkt.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
    pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

    let (name, qtype) = oaie_netpol::dns_wire::extract_query_name(&pkt).unwrap();
    assert_eq!(name, "example.com");
    assert_eq!(qtype, 1); // A record
}

#[test]
fn dns_wire_build_nxdomain() {
    let mut query = vec![
        0x12, 0x34, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    query.push(4);
    query.extend_from_slice(b"evil");
    query.push(3);
    query.extend_from_slice(b"com");
    query.push(0);
    query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

    let response = oaie_netpol::dns_wire::build_nxdomain(&query).unwrap();
    // QR bit set
    assert!(response[2] & 0x80 != 0);
    // RCODE = 3 (NXDOMAIN)
    assert_eq!(response[3] & 0x0F, 3);
}

#[test]
fn dns_wire_too_short() {
    assert!(oaie_netpol::dns_wire::extract_query_name(&[0; 5]).is_none());
}

// ── TLS SNI extraction ──

#[test]
fn sni_extraction_basic() {
    // Build a minimal TLS ClientHello with SNI.
    let hello = build_test_client_hello("api.anthropic.com");
    let sni = oaie_netpol::sni::extract_sni(&hello);
    assert_eq!(sni.as_deref(), Some("api.anthropic.com"));
}

#[test]
fn sni_extraction_not_tls() {
    assert!(oaie_netpol::sni::extract_sni(&[0x17, 0x03, 0x01, 0x00, 0x05]).is_none());
}

#[test]
fn sni_validate_against_patterns() {
    let patterns = vec![oaie_netpol::domain::DomainPattern::parse("*.anthropic.com")];
    assert!(oaie_netpol::sni::validate_sni("api.anthropic.com", &patterns));
    assert!(!oaie_netpol::sni::validate_sni("evil.example.com", &patterns));
}

// ── CLI --net flag parsing ──

#[test]
fn parse_net_flag_on() {
    let mode = policy::parse_net_flag("on").unwrap();
    assert_eq!(mode, NetworkMode::On);
}

#[test]
fn parse_net_flag_off() {
    let mode = policy::parse_net_flag("off").unwrap();
    assert_eq!(mode, NetworkMode::Off);
}

#[test]
fn parse_net_flag_allow_single() {
    let mode = policy::parse_net_flag("allow:api.anthropic.com:443").unwrap();
    if let NetworkMode::Allowlist(rules) = mode {
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].host.as_deref(), Some("api.anthropic.com"));
        assert_eq!(rules[0].port, 443);
    } else {
        panic!("expected Allowlist");
    }
}

#[test]
fn parse_net_flag_allow_multiple() {
    let mode = policy::parse_net_flag("allow:api.anthropic.com:443,api.openai.com:443").unwrap();
    if let NetworkMode::Allowlist(rules) = mode {
        assert_eq!(rules.len(), 2);
    } else {
        panic!("expected Allowlist");
    }
}

#[test]
fn parse_net_flag_preset_anthropic() {
    let mode = policy::parse_net_flag("preset:anthropic").unwrap();
    if let NetworkMode::Allowlist(rules) = mode {
        assert!(rules.iter().any(|r| r.host.as_deref() == Some("api.anthropic.com")));
    } else {
        panic!("expected Allowlist");
    }
}

#[test]
fn parse_net_flag_invalid() {
    assert!(policy::parse_net_flag("garbage").is_err());
}

// ── Preset resolution ──

#[test]
fn preset_anthropic_is_allowlist() {
    let p = Policy::preset_anthropic();
    if let NetworkMode::Allowlist(ref rules) = p.defaults.network {
        assert!(rules.iter().any(|r| r.host.as_deref() == Some("api.anthropic.com")));
        assert!(rules.iter().any(|r| r.port == 443));
    } else {
        panic!("expected Allowlist mode");
    }
}

#[test]
fn preset_openai_is_allowlist() {
    let p = Policy::preset_openai();
    if let NetworkMode::Allowlist(ref rules) = p.defaults.network {
        assert!(rules.iter().any(|r| r.host.as_deref() == Some("api.openai.com")));
    } else {
        panic!("expected Allowlist mode");
    }
}

#[test]
fn preset_llm_includes_multiple_providers() {
    let p = Policy::preset_llm();
    if let NetworkMode::Allowlist(ref rules) = p.defaults.network {
        let hosts: Vec<&str> = rules.iter().filter_map(|r| r.host.as_deref()).collect();
        assert!(hosts.contains(&"api.anthropic.com"));
        assert!(hosts.contains(&"api.openai.com"));
        assert!(hosts.contains(&"generativelanguage.googleapis.com"));
    } else {
        panic!("expected Allowlist mode");
    }
}

#[test]
fn preset_from_name_anthropic() {
    let p = Policy::from_name("anthropic");
    assert!(p.is_some());
}

#[test]
fn preset_from_name_llm() {
    let p = Policy::from_name("llm");
    assert!(p.is_some());
}

// ── Backward compatibility ──

#[test]
fn safe_preset_still_works() {
    let p = Policy::preset_safe();
    assert_eq!(p.defaults.network, NetworkMode::Off);
}

#[test]
fn net_preset_still_works() {
    let p = Policy::preset_net();
    assert_eq!(p.defaults.network, NetworkMode::On);
}

// ── Test helper ──

/// Build a minimal TLS 1.2 ClientHello with SNI for testing.
fn build_test_client_hello(hostname: &str) -> Vec<u8> {
    let hostname_bytes = hostname.as_bytes();

    // SNI extension data.
    let mut sni_ext = Vec::new();
    let sni_list_len = 3 + hostname_bytes.len();
    sni_ext.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    sni_ext.push(0); // host name type
    sni_ext.extend_from_slice(&(hostname_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(hostname_bytes);

    // Extensions block.
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0u16.to_be_bytes()); // extension type: SNI
    extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext);

    // ClientHello body.
    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    hello.extend_from_slice(&[0u8; 32]); // random
    hello.push(0); // session ID len
    hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x2F]); // cipher suites
    hello.extend_from_slice(&[0x01, 0x00]); // compression
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);

    // Handshake header.
    let mut handshake = Vec::new();
    handshake.push(1); // ClientHello
    let len = hello.len();
    handshake.push((len >> 16) as u8);
    handshake.push((len >> 8) as u8);
    handshake.push(len as u8);
    handshake.extend_from_slice(&hello);

    // TLS record.
    let mut record = Vec::new();
    record.push(22); // handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record layer
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}
