//! Input validation for oaie-priv requests.
//!
//! All inputs from the unprivileged client are validated before any
//! privileged operations are performed.

use oaie_core::cgroup::CgroupLimits;

/// Minimum ring buffer size: 256 KB.
const MIN_RING_BUF_SIZE: u32 = 256 * 1024;

/// Maximum ring buffer size: 4 MB.
const MAX_RING_BUF_SIZE: u32 = 4 * 1024 * 1024;

/// Validate a ring buffer size for BPF loading.
///
/// Must be a power of 2, between 256KB and 4MB inclusive.
/// The kernel requires ring buffer sizes to be powers of 2.
pub fn validate_ring_buffer_size(size: u32) -> Result<(), String> {
    if size == 0 || (size & (size - 1)) != 0 {
        return Err(format!("ring_buffer_size must be a power of 2, got {size}"));
    }
    if size < MIN_RING_BUF_SIZE {
        return Err(format!(
            "ring_buffer_size must be >= {MIN_RING_BUF_SIZE} (256KB), got {size}"
        ));
    }
    if size > MAX_RING_BUF_SIZE {
        return Err(format!(
            "ring_buffer_size must be <= {MAX_RING_BUF_SIZE} (4MB), got {size}"
        ));
    }
    Ok(())
}

/// Validate a run ID: alphanumeric + hyphens only, 1–64 characters.
///
/// Prevents path traversal and command injection via crafted run IDs.
pub fn validate_run_id(run_id: &str) -> Result<(), String> {
    if run_id.is_empty() || run_id.len() > 64 {
        return Err(format!(
            "run_id must be 1–64 characters, got {}",
            run_id.len()
        ));
    }

    if !run_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err("run_id contains invalid characters (only alphanumeric and hyphens allowed)".into());
    }

    Ok(())
}

/// Validate a cgroup path: must start with `/sys/fs/cgroup/oaie/` and contain no `..`.
///
/// Prevents arbitrary filesystem access via path traversal.
/// Also requires minimum depth (at least one component after the prefix)
/// to prevent deletion of the OAIE root cgroup directory itself.
pub fn validate_cgroup_path(path: &str) -> Result<(), String> {
    if !path.starts_with("/sys/fs/cgroup/oaie/") {
        return Err(format!(
            "cgroup_path must start with /sys/fs/cgroup/oaie/, got: {path}"
        ));
    }

    if path.contains("..") {
        return Err("cgroup_path contains path traversal (..)".into());
    }

    // Reject empty components (double slashes), NUL bytes.
    if path.contains('\0') || path.contains("//") {
        return Err("cgroup_path contains invalid characters".into());
    }

    // Require at least one path component after the prefix to prevent
    // deletion of the OAIE root cgroup directory itself.
    let suffix = &path["/sys/fs/cgroup/oaie/".len()..];
    let suffix = suffix.trim_end_matches('/');
    if suffix.is_empty() {
        return Err("cgroup_path must reference a scope under /sys/fs/cgroup/oaie/".into());
    }

    Ok(())
}

/// Validate cgroup limits: check ranges are sane.
///
/// Prevents resource exhaustion from unreasonable values.
/// Also validates coupling: cpu_quota_us and cpu_period_us must be set together.
pub fn validate_limits(limits: &CgroupLimits) -> Result<(), String> {
    if let Some(mem) = limits.memory_max {
        if mem < 1024 * 1024 {
            return Err(format!(
                "memory_max must be >= 1MB, got {mem} bytes"
            ));
        }
    }

    if let Some(pids) = limits.pids_max {
        if pids == 0 || pids > 1_000_000 {
            return Err(format!(
                "pids_max must be 1–1000000, got {pids}"
            ));
        }
    }

    if let Some(quota) = limits.cpu_quota_us {
        if quota == 0 {
            return Err("cpu_quota_us must be > 0".into());
        }
    }

    if let Some(period) = limits.cpu_period_us {
        if period == 0 || period > 1_000_000 {
            return Err(format!(
                "cpu_period_us must be 1–1000000, got {period}"
            ));
        }
    }

    // CPU quota and period must be set together — one without the other
    // means the cpu.max write is silently skipped, which is misleading.
    match (limits.cpu_quota_us, limits.cpu_period_us) {
        (Some(_), None) => return Err("cpu_quota_us set without cpu_period_us".into()),
        (None, Some(_)) => return Err("cpu_period_us set without cpu_quota_us".into()),
        _ => {}
    }

    Ok(())
}

/// Validate a Linux network interface name: 1–15 chars (IFNAMSIZ-1),
/// alphanumeric / `-` / `_` / `.` only.
pub fn validate_iface_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 15 {
        return Err(format!("interface name must be 1–15 characters, got {}", name.len()));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err("interface name contains invalid characters".into());
    }
    Ok(())
}

/// Validate an IPv4 CIDR subnet: digits / `.` / `/` only, 1–18 chars.
pub fn validate_subnet(subnet: &str) -> Result<(), String> {
    if subnet.is_empty() || subnet.len() > 18 {
        return Err(format!("subnet must be 1–18 characters, got {}", subnet.len()));
    }
    if !subnet.chars().all(|c| c.is_ascii_digit() || c == '.' || c == '/') {
        return Err("subnet contains invalid characters".into());
    }
    Ok(())
}

/// Maximum entries in a SetupNetns allowlist. The 64KB MAX_REQUEST_SIZE
/// caps the JSON already, but an explicit count makes the bound visible
/// at the validation layer.
pub const MAX_ALLOW_RULES: usize = 256;

/// Maximum addresses per rule (one nft line emitted per address).
const MAX_ADDRS_PER_RULE: usize = 64;

/// Validate a single netns allow-rule. Structural checks only — these
/// fields are interpolated into nft commands on the privileged side, so
/// every variable component must be a closed-form value (IpAddr is parsed
/// by serde, port is u16, protocol is enum-checked, CIDR is parsed here).
pub fn validate_allow_rule(rule: &crate::protocol::NetAllowRule) -> Result<(), String> {
    // Protocol: closed set. The nft generator interpolates this string
    // directly into "add rule ... {proto} dport ..." so it must be one of
    // exactly two literals.
    match rule.protocol.as_str() {
        "tcp" | "udp" => {}
        other => return Err(format!("protocol must be 'tcp' or 'udp', got '{other}'")),
    }

    // Port 0 is reserved/invalid for tcp/udp dport matching.
    if rule.port == 0 {
        return Err("port must be nonzero".into());
    }

    // Exactly one of (addrs, cidr) must carry data.
    match (&rule.cidr, rule.addrs.is_empty()) {
        (Some(_), false) => {
            return Err("cidr and addrs are mutually exclusive".into());
        }
        (None, true) => {
            return Err("rule must have either addrs or cidr".into());
        }
        _ => {}
    }

    if rule.addrs.len() > MAX_ADDRS_PER_RULE {
        return Err(format!(
            "rule has {} addrs, max {MAX_ADDRS_PER_RULE}",
            rule.addrs.len()
        ));
    }

    // CIDR: parse fully (not charset-only — "999.999.999.999/99" passes a
    // charset check). The Display impl that the nft generator uses comes
    // from this same parsed form, so what we validate is what we emit.
    if let Some(ref cidr) = rule.cidr {
        let (addr_part, prefix_part) = cidr
            .split_once('/')
            .ok_or_else(|| format!("cidr '{cidr}' missing '/'"))?;
        let addr: std::net::IpAddr = addr_part
            .parse()
            .map_err(|_| format!("cidr '{cidr}' has invalid address"))?;
        let prefix: u8 = prefix_part
            .parse()
            .map_err(|_| format!("cidr '{cidr}' has invalid prefix"))?;
        let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max_prefix {
            return Err(format!(
                "cidr '{cidr}' prefix {prefix} exceeds max {max_prefix}"
            ));
        }
    }

    // addrs: IpAddr was parsed by serde from the JSON wire form, so it's
    // already structurally valid. The nft generator uses IpAddr's Display
    // (canonical form, no injection vector). Nothing further to check.

    Ok(())
}
