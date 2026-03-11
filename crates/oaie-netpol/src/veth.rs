//! veth pair and NAT setup for allowlist networking.
//!
//! Creates a virtual ethernet pair connecting the sandbox network namespace
//! to the host, with NAT (masquerade) for outbound connectivity. The sandbox
//! gets a private IP (10.200.X.2) and a default route through the host side
//! (10.200.X.1).
//!
//! Requires `CAP_NET_ADMIN` (or oaie-priv helper).

use std::process::Command;

use crate::error::{NetpolError, Result};

/// State for a configured veth pair + NAT setup.
#[derive(Clone, Debug)]
pub struct VethSetup {
    /// Host-side interface name (e.g. "oaie-h-a1b2c3d4").
    pub host_iface: String,
    /// Sandbox-side interface name (always "eth0" inside the namespace).
    pub sandbox_iface: String,
    /// Host-side IP address (e.g. 10.200.X.1).
    pub host_ip: String,
    /// Sandbox-side IP address (e.g. 10.200.X.2).
    pub sandbox_ip: String,
    /// Subnet in CIDR notation (e.g. "10.200.X.0/30").
    pub subnet: String,
    /// The host's default outbound interface (for masquerade).
    pub host_default_iface: String,
}

/// Set up a veth pair + NAT for allowlist networking.
///
/// Creates the pair, moves one end into the sandbox namespace, configures
/// IP addresses, routing, and masquerade. The sandbox PID's network
/// namespace must already exist (child spawned with `CLONE_NEWNET`).
///
/// # Arguments
/// * `pid` - PID of the sandbox child process (for namespace reference).
/// * `run_id_short` - Short run ID for generating unique interface names.
pub fn setup_veth(pid: u32, run_id_short: &str) -> Result<VethSetup> {
    // Check ip forwarding is enabled.
    check_ip_forward()?;

    // Generate unique interface names from run ID.
    let suffix = &run_id_short[..std::cmp::min(8, run_id_short.len())];
    let host_iface = format!("oaie-h-{suffix}");
    let peer_iface = format!("oaie-p-{suffix}");

    // Pick a /30 subnet: use last 2 bytes of run_id as subnet index.
    let idx = u16::from_str_radix(&suffix[..std::cmp::min(4, suffix.len())], 16).unwrap_or(0);
    // Map to 10.200.X.Y with X = high byte, Y base = low byte * 4, avoiding 0.
    let x = ((idx >> 8) as u8).wrapping_add(1);
    let y_base = ((idx & 0xFF) as u8) & 0xFC; // Align to /30 boundary.
    let host_ip = format!("10.200.{x}.{}", y_base.wrapping_add(1));
    let sandbox_ip = format!("10.200.{x}.{}", y_base.wrapping_add(2));
    let subnet = format!("10.200.{x}.{y_base}/30");

    // Detect the host's default outbound interface.
    let host_default_iface = detect_default_iface()?;

    // Step 1: Create veth pair.
    run_cmd(
        "ip",
        &[
            "link", "add", &host_iface, "type", "veth", "peer", "name", &peer_iface,
        ],
        "create veth pair",
    )?;

    // Step 2: Move peer end into sandbox namespace.
    let pid_str = pid.to_string();
    if let Err(e) = run_cmd(
        "ip",
        &["link", "set", &peer_iface, "netns", &pid_str],
        "move veth to sandbox ns",
    ) {
        // Cleanup host side on failure.
        let _ = run_cmd("ip", &["link", "delete", &host_iface], "cleanup host veth");
        return Err(e);
    }

    // Step 3: Configure host side.
    let host_cidr = format!("{host_ip}/30");
    run_cmd(
        "ip",
        &["addr", "add", &host_cidr, "dev", &host_iface],
        "assign host IP",
    )?;
    run_cmd(
        "ip",
        &["link", "set", &host_iface, "up"],
        "bring up host veth",
    )?;

    // Step 4: Configure sandbox side (via nsenter).
    let net_ns = format!("/proc/{pid}/ns/net");
    let sandbox_cidr = format!("{sandbox_ip}/30");

    // Rename the peer interface to eth0 inside the namespace.
    run_nsenter_cmd(
        &net_ns,
        &["ip", "link", "set", &peer_iface, "name", "eth0"],
        "rename peer to eth0",
    )?;
    run_nsenter_cmd(
        &net_ns,
        &["ip", "addr", "add", &sandbox_cidr, "dev", "eth0"],
        "assign sandbox IP",
    )?;
    run_nsenter_cmd(
        &net_ns,
        &["ip", "link", "set", "eth0", "up"],
        "bring up sandbox eth0",
    )?;
    run_nsenter_cmd(
        &net_ns,
        &["ip", "link", "set", "lo", "up"],
        "bring up sandbox loopback",
    )?;
    run_nsenter_cmd(
        &net_ns,
        &["ip", "route", "add", "default", "via", &host_ip],
        "add sandbox default route",
    )?;

    // Step 5: Set up masquerade NAT on host.
    run_cmd(
        "iptables",
        &[
            "-t", "nat", "-A", "POSTROUTING", "-s", &subnet, "-o",
            &host_default_iface, "-j", "MASQUERADE",
        ],
        "add NAT masquerade",
    )?;

    log::info!(
        "veth setup complete: {} ({}) <-> eth0 ({}) in ns of pid {}",
        host_iface,
        host_ip,
        sandbox_ip,
        pid
    );

    Ok(VethSetup {
        host_iface,
        sandbox_iface: "eth0".into(),
        host_ip,
        sandbox_ip,
        subnet,
        host_default_iface,
    })
}

/// Clean up host-side veth interface and NAT rule.
///
/// Best-effort: when the sandbox namespace exits, its interfaces vanish
/// automatically. This cleans up the host side and iptables rule.
pub fn cleanup_veth(setup: &VethSetup) -> Result<()> {
    // Remove the iptables masquerade rule.
    let _ = run_cmd(
        "iptables",
        &[
            "-t", "nat", "-D", "POSTROUTING", "-s", &setup.subnet, "-o",
            &setup.host_default_iface, "-j", "MASQUERADE",
        ],
        "remove NAT masquerade",
    );

    // Delete host-side veth (also removes the peer).
    let _ = run_cmd(
        "ip",
        &["link", "delete", &setup.host_iface],
        "delete host veth",
    );

    log::debug!("cleaned up veth {}", setup.host_iface);
    Ok(())
}

/// Check that IPv4 forwarding is enabled.
fn check_ip_forward() -> Result<()> {
    let val = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .map_err(NetpolError::Io)?;
    if val.trim() != "1" {
        return Err(NetpolError::IpForwardDisabled);
    }
    Ok(())
}

/// Detect the host's default outbound network interface.
fn detect_default_iface() -> Result<String> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .map_err(|e| NetpolError::VethSetup(format!("failed to run 'ip route': {e}")))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Parse: "default via X.X.X.X dev <iface> ..."
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(idx) = parts.iter().position(|&p| p == "dev") {
            if let Some(iface) = parts.get(idx + 1) {
                return Ok((*iface).to_string());
            }
        }
    }

    Err(NetpolError::VethSetup(
        "could not detect default network interface".into(),
    ))
}

/// Run a command, returning an error with context on failure.
fn run_cmd(program: &str, args: &[&str], context: &str) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| NetpolError::VethSetup(format!("{context}: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NetpolError::VethSetup(format!(
            "{context}: {} exited with {}: {}",
            program,
            output.status,
            stderr.trim()
        )));
    }
    Ok(())
}

/// Run a command inside a network namespace via nsenter.
fn run_nsenter_cmd(net_ns: &str, cmd: &[&str], context: &str) -> Result<()> {
    let mut args = vec!["--net", net_ns, "--"];
    args.extend_from_slice(cmd);

    let output = Command::new("nsenter")
        .args(&args)
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                NetpolError::NsenterNotFound
            } else {
                NetpolError::VethSetup(format!("{context}: nsenter failed: {e}"))
            }
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NetpolError::VethSetup(format!(
            "{context}: nsenter exited with {}: {}",
            output.status,
            stderr.trim()
        )));
    }
    Ok(())
}
