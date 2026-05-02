//! DNS proxy thread for network allowlist filtering.
//!
//! Runs in the parent process, bound to `127.0.0.53:53` inside the sandbox's
//! network namespace. Forwards allowed queries to the host's upstream DNS
//! resolver and returns NXDOMAIN for blocked domains.
//!
//! The proxy is unkillable by the sandbox (different PID namespace) and
//! runs until signaled to stop via the [`DnsProxyHandle`].

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::dns_wire;
use crate::domain::DomainPattern;
use crate::nftables;

/// Handle for controlling the DNS proxy from the parent.
pub struct DnsProxyHandle {
    /// Signal to stop the proxy loop.
    stop: Arc<AtomicBool>,
    /// Join handle for the proxy thread.
    thread: Option<JoinHandle<Vec<DnsEvent>>>,
}

/// Record of a DNS query processed by the proxy.
#[derive(Clone, Debug)]
pub struct DnsEvent {
    /// Queried domain name.
    pub domain: String,
    /// DNS query type as string ("A", "AAAA", etc.).
    pub query_type: String,
    /// Whether the query was forwarded (allowed) or blocked.
    pub allowed: bool,
    /// Resolved IP addresses (empty if blocked).
    pub resolved_addrs: Vec<IpAddr>,
}

/// DNS proxy configuration.
pub struct DnsProxyConfig {
    /// Domain patterns from the allowlist rules.
    pub allowed_domains: Vec<DomainPattern>,
    /// Sandbox PID. Carried for logging only — every operation that
    /// needs to enter the sandbox netns takes an open fd on
    /// `/proc/{sandbox_pid}/ns/net`, NOT this integer. See the
    /// PID-reuse comment at `nftables::apply_in_netns`.
    pub sandbox_pid: u32,
    /// Ports associated with each allowed host for dynamic nftables updates.
    /// Maps domain patterns to (port, protocol) pairs.
    pub domain_ports: Vec<(DomainPattern, u16, String)>,
    /// Upstream DNS server address (host resolver).
    pub upstream: SocketAddr,
}

impl DnsProxyHandle {
    /// Signal the proxy to stop and wait for it to finish.
    ///
    /// Returns the list of DNS events recorded during the proxy's lifetime.
    pub fn stop(mut self) -> Vec<DnsEvent> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap_or_default()
        } else {
            vec![]
        }
    }

    /// Check if the proxy thread is still running.
    pub fn is_running(&self) -> bool {
        self.thread.as_ref().map(|t| !t.is_finished()).unwrap_or(false)
    }
}

impl Drop for DnsProxyHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Don't join in drop — the thread will exit on its own when
        // it sees the stop flag on its next poll iteration.
    }
}

/// Start the DNS proxy thread.
///
/// The proxy binds to `127.0.0.53:53` inside the sandbox's network namespace
/// via `setns()`, then switches back to the host namespace for upstream
/// resolution. The proxy runs until the stop flag is set.
///
/// # Arguments
/// * `sandbox_netns_fd` - File descriptor for the sandbox's network namespace
///   (opened from `/proc/<pid>/ns/net`).
/// * `config` - Proxy configuration with allowed domains and ports.
///
/// Returns a handle to stop the proxy and collect DNS event logs.
pub fn start_dns_proxy(sandbox_netns_path: &str, config: DnsProxyConfig) -> Result<DnsProxyHandle, crate::error::NetpolError> {
    // Open the sandbox netns fd TWICE: once for the bind thread (consumed
    // by setns and dropped on join), once for proxy_loop's lifetime. The
    // proxy_loop holds an open netns fd so the netns survives sandbox-PID
    // reuse during an in-flight forward_query (upstream DNS can take up to
    // 10s, longer than the sandbox's lifetime in some cases). See the
    // long comment at nftables::apply_in_netns for the full rationale.
    let open_netns = || std::fs::File::open(sandbox_netns_path).map_err(|e| crate::error::NetpolError::VethSetup(format!("failed to open sandbox netns {sandbox_netns_path}: {e}")));
    let sandbox_ns_fd = open_netns()?;
    let proxy_ns_fd = open_netns()?;

    // Bind the UDP socket inside the sandbox namespace using a dedicated
    // short-lived thread. This avoids a TOCTOU race where the calling
    // thread's netns is temporarily changed (any other code on the same
    // thread that does network I/O between setns calls would use the
    // wrong namespace).
    let listen_sock = std::thread::Builder::new()
        .name("oaie-dns-bind".into())
        .spawn(move || -> std::result::Result<UdpSocket, crate::error::NetpolError> {
            use std::os::fd::AsFd;

            // Enter sandbox netns (only affects this thread).
            nix::sched::setns(sandbox_ns_fd.as_fd(), nix::sched::CloneFlags::CLONE_NEWNET).map_err(|e| crate::error::NetpolError::VethSetup(format!("setns to sandbox failed: {e}")))?;

            let bind_addr: SocketAddr = "127.0.0.53:53".parse().unwrap();
            let sock = UdpSocket::bind(bind_addr).map_err(|e| crate::error::NetpolError::VethSetup(format!("failed to bind DNS proxy to {bind_addr}: {e}")))?;

            // Thread exits here; its netns state is discarded with the thread.
            Ok(sock)
        })
        .map_err(|e| crate::error::NetpolError::VethSetup(format!("failed to spawn DNS bind thread: {e}")))?
        .join()
        .map_err(|_| crate::error::NetpolError::VethSetup("DNS bind thread panicked".into()))??;

    // Set socket timeout for polling.
    listen_sock.set_read_timeout(Some(Duration::from_millis(100))).map_err(crate::error::NetpolError::Io)?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);

    let thread = std::thread::Builder::new()
        .name("oaie-dns-proxy".into())
        .spawn(move || proxy_loop(listen_sock, proxy_ns_fd, config, stop_clone))
        .map_err(|e| crate::error::NetpolError::VethSetup(format!("failed to spawn DNS proxy thread: {e}")))?;

    Ok(DnsProxyHandle { stop, thread: Some(thread) })
}

/// Maximum number of DNS events to retain. Prevents unbounded memory growth
/// if the sandbox floods DNS queries.
const MAX_DNS_EVENTS: usize = 10_000;

/// Maximum number of distinct dynamic nftables rules to install. Bounds
/// kernel-ruleset growth and host-side fork+exec when the sandbox floods
/// queries for an allowed wildcard domain.
const MAX_DYNAMIC_RULES: usize = 4096;

/// Main proxy loop: receive queries, filter, forward or reject.
///
/// `netns_fd` is held open for the loop's lifetime. Every
/// `add_dynamic_rule` call uses `netns_fd.as_fd()` — nsenter resolves
/// `/proc/self/fd/{fd}` to the pinned netns regardless of whether
/// `config.sandbox_pid` has been reaped and reused.
fn proxy_loop(listen_sock: UdpSocket, netns_fd: std::fs::File, config: DnsProxyConfig, stop: Arc<AtomicBool>) -> Vec<DnsEvent> {
    use std::os::fd::AsFd;
    let mut events = Vec::new();
    let mut added_rules: HashSet<(IpAddr, u16, String)> = HashSet::new();
    let mut buf = [0u8; 4096]; // DNS UDP max practical size.

    // Create an upstream socket on the host side for forwarding.
    let upstream_sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            log::error!("DNS proxy: failed to create upstream socket: {e}");
            return events;
        }
    };
    // Connect the socket so the kernel filters inbound datagrams by 4-tuple.
    // Without this, any host on the LAN can inject forged DNS responses to
    // the ephemeral port (recv_from accepts from any source).
    if let Err(e) = upstream_sock.connect(config.upstream) {
        log::error!("DNS proxy: failed to connect upstream socket: {e}");
        return events;
    }
    let _ = upstream_sock.set_read_timeout(Some(Duration::from_secs(2)));

    while !stop.load(Ordering::Relaxed) {
        // Receive a query from the sandbox.
        let (n, src) = match listen_sock.recv_from(&mut buf) {
            Ok(r) => r,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => {
                log::warn!("DNS proxy recv error: {e}");
                continue;
            }
        };

        let query = &buf[..n];

        // Parse the query to extract the domain name.
        let (domain, qtype) = match dns_wire::extract_query_name(query) {
            Some(r) => r,
            None => {
                log::debug!("DNS proxy: malformed query from {src}");
                continue;
            }
        };

        let qtype_str = match qtype {
            1 => "A",
            28 => "AAAA",
            _ => "OTHER",
        }
        .to_string();

        // Check if the domain is in the allowlist.
        if crate::domain::matches_any(&domain, &config.allowed_domains) {
            // Allowed: forward to upstream resolver (on host network).
            match forward_query(&upstream_sock, query, config.upstream) {
                Ok(response) => {
                    // Extract resolved addresses for audit and dynamic rules.
                    // Pass &domain so extract_response_addrs can drop RRs
                    // whose owner-name doesn't match what we asked. See
                    // the function's doc for the gratuitous-RR attack.
                    let addrs = dns_wire::extract_response_addrs(&response, &domain);

                    // Add dynamic nftables rules for newly resolved IPs.
                    for addr in &addrs {
                        for (pat, port, proto) in &config.domain_ports {
                            if pat.matches(&domain) {
                                let key = (*addr, *port, proto.clone());
                                if added_rules.contains(&key) || added_rules.len() >= MAX_DYNAMIC_RULES {
                                    continue;
                                }
                                added_rules.insert(key);
                                if let Err(e) = nftables::add_dynamic_rule(netns_fd.as_fd(), *addr, *port, proto) {
                                    log::warn!("DNS proxy: failed to add dynamic rule for {addr}:{port}: {e}");
                                }
                            }
                        }
                    }

                    if events.len() < MAX_DNS_EVENTS {
                        events.push(DnsEvent {
                            domain: domain.clone(),
                            query_type: qtype_str,
                            allowed: true,
                            resolved_addrs: addrs,
                        });
                    }

                    // Send response back to the sandbox.
                    let _ = listen_sock.send_to(&response, src);
                }
                Err(e) => {
                    log::warn!("DNS proxy: upstream forward failed for {domain}: {e}");
                    // Return SERVFAIL on upstream error (not NXDOMAIN, to avoid
                    // negative caching — the domain exists, we just can't reach it).
                    if let Some(servfail) = dns_wire::build_servfail(query) {
                        let _ = listen_sock.send_to(&servfail, src);
                    }
                    if events.len() < MAX_DNS_EVENTS {
                        events.push(DnsEvent {
                            domain,
                            query_type: qtype_str,
                            allowed: true,
                            resolved_addrs: vec![],
                        });
                    }
                }
            }
        } else {
            // Blocked: return NXDOMAIN.
            log::debug!("DNS proxy: blocking query for {domain}");
            if let Some(nxdomain) = dns_wire::build_nxdomain(query) {
                let _ = listen_sock.send_to(&nxdomain, src);
            }
            if events.len() < MAX_DNS_EVENTS {
                events.push(DnsEvent {
                    domain,
                    query_type: qtype_str,
                    allowed: false,
                    resolved_addrs: vec![],
                });
            }
        }
    }

    events
}

/// Forward a DNS query to the upstream resolver on the host network.
///
/// Verifies that the response's transaction ID matches the query's to prevent
/// cross-query response mixups when multiple queries are in flight.
fn forward_query(upstream_sock: &UdpSocket, query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>, std::io::Error> {
    if query.len() < 2 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "query too short for transaction ID"));
    }
    let txn_id = [query[0], query[1]];
    // Locate the end of the question section (header + qname + qtype + qclass)
    // so the response can be verified to answer the SAME question (RFC 5452 §9.1).
    let question_end = {
        let mut p = 12;
        while p < query.len() {
            let l = query[p] as usize;
            if l == 0 {
                p += 1;
                break;
            }
            if p + 1 + l > query.len() {
                p = query.len();
                break;
            }
            p += 1 + l;
        }
        (p + 4).min(query.len())
    };

    upstream_sock.send_to(query, upstream)?;

    let mut buf = [0u8; 4096];
    // Retry if we get responses with mismatched transaction IDs (stale
    // responses from previous queries).  The upstream socket has a 2-second
    // read timeout, so worst case is 5 × 2s = 10s before giving up.
    for attempt in 0..5 {
        match upstream_sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if n >= question_end && buf[0] == txn_id[0] && buf[1] == txn_id[1] && (buf[2] & 0x80) != 0 && buf[12..question_end] == query[12..question_end] {
                    return Ok(buf[..n].to_vec());
                }
                log::debug!(
                    "DNS proxy: discarding response with mismatched txn ID \
                     (attempt {}/5, got {:02x}{:02x}, want {:02x}{:02x})",
                    attempt + 1,
                    buf[0],
                    buf[1],
                    txn_id[0],
                    txn_id[1]
                );
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                // Socket read timeout — no more responses waiting.
                break;
            }
            Err(e) => return Err(e),
        }
    }

    Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "no matching DNS response after retries"))
}

/// Detect the system's upstream DNS resolver from /etc/resolv.conf.
pub fn detect_upstream_resolver() -> SocketAddr {
    if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in contents.lines() {
            let line = line.trim();
            if let Some(addr_str) = line.strip_prefix("nameserver ") {
                let addr_str = addr_str.trim();
                // The upstream socket lives in the HOST netns (proxy_loop never
                // calls setns()), so host-loopback resolvers like 127.0.0.53
                // (systemd-resolved) are valid upstreams — do NOT skip them.
                if let Ok(addr) = addr_str.parse::<IpAddr>() {
                    return SocketAddr::new(addr, 53);
                }
            }
        }
    }

    // Fallback to Google's public DNS.
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)), 53)
}
