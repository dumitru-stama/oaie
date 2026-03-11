//! Read data from a traced process's memory via ptrace.
//!
//! All reads are best-effort: if the target memory is unmapped or the process
//! has exited, we return what we could read rather than erroring out.

use nix::sys::ptrace;
use nix::unistd::Pid;

/// Maximum length for strings read from traced processes (4 KiB).
const MAX_STRING_LEN: usize = 4096;

/// Maximum number of argv entries to read from an execve call.
const MAX_ARGV_ENTRIES: usize = 32;

/// Read a null-terminated string from the traced process's memory.
///
/// Best-effort: returns what we can read, truncated at `max_len`.
/// Returns an empty string if `addr` is 0 (NULL pointer).
pub fn read_string(pid: Pid, addr: u64, max_len: usize) -> String {
    if addr == 0 {
        return String::new();
    }

    let cap = max_len.min(MAX_STRING_LEN);
    let mut result = Vec::with_capacity(cap);
    let mut offset = 0u64;

    loop {
        if result.len() >= cap {
            result.truncate(cap);
            break;
        }

        // Read one word (8 bytes on 64-bit) at a time via PTRACE_PEEKDATA.
        let word = match ptrace::read(pid, (addr + offset) as *mut _) {
            Ok(w) => w as u64,
            Err(_) => break, // Process memory not accessible
        };

        let bytes = word.to_ne_bytes();
        for &b in &bytes {
            if b == 0 {
                return String::from_utf8_lossy(&result).into_owned();
            }
            result.push(b);
            if result.len() >= cap {
                break;
            }
        }

        offset = offset.saturating_add(8);
    }

    String::from_utf8_lossy(&result).into_owned()
}

/// Read a null-terminated array of string pointers (e.g. argv from execve).
///
/// Reads up to `max_entries` pointers, then reads each string.
/// Returns an empty vec on any error.
pub fn read_string_array(pid: Pid, array_addr: u64, max_entries: usize) -> Vec<String> {
    if array_addr == 0 {
        return vec![];
    }

    let limit = max_entries.min(MAX_ARGV_ENTRIES);
    let mut result = Vec::new();
    let mut offset = 0u64;

    for _ in 0..limit {
        // Read the pointer value (8 bytes on 64-bit).
        let ptr = match ptrace::read(pid, (array_addr + offset) as *mut _) {
            Ok(p) => p as u64,
            Err(_) => break,
        };

        if ptr == 0 {
            break; // NULL terminator in the pointer array
        }

        result.push(read_string(pid, ptr, MAX_STRING_LEN));
        offset = offset.saturating_add(8);
    }

    result
}

/// Parsed socket address information from a connect() call.
#[derive(Debug, Clone)]
pub struct SockAddrInfo {
    /// Address family name: "AF_INET", "AF_INET6", "AF_UNIX", "AF_NETLINK", etc.
    pub family: String,
    /// Human-readable address: "1.2.3.4:80", "/var/run/sock", "netlink_protocol=0".
    pub display: String,
}

/// Read raw bytes from the traced process's memory.
///
/// Reads up to `len` bytes from `addr` in the tracee's address space.
/// Best-effort: returns what we can read (may be shorter than `len`).
pub fn read_bytes(pid: Pid, addr: u64, len: usize) -> Vec<u8> {
    if addr == 0 || len == 0 {
        return vec![];
    }
    let cap = len.min(512); // Cap reads for safety.
    let mut result = Vec::with_capacity(cap);
    let mut offset = 0u64;

    while result.len() < cap {
        let word = match ptrace::read(pid, (addr + offset) as *mut _) {
            Ok(w) => w as u64,
            Err(_) => break,
        };
        let bytes = word.to_ne_bytes();
        for &b in &bytes {
            if result.len() >= cap {
                break;
            }
            result.push(b);
        }
        offset = offset.saturating_add(8);
    }
    result.truncate(cap);
    result
}

/// Parse a domain name from a DNS query wire-format payload.
///
/// DNS queries have a 12-byte header, then the question section with
/// length-prefixed labels: `\x03www\x06google\x03com\x00`.
/// Returns `None` if the payload is too short or malformed.
pub fn parse_dns_query_name(payload: &[u8]) -> Option<String> {
    // DNS header is 12 bytes minimum.
    if payload.len() < 13 {
        return None;
    }

    // Check QDCOUNT >= 1 (bytes 4-5, big-endian).
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }

    // Parse the first question's QNAME starting at offset 12.
    let mut pos = 12;
    let mut labels = Vec::new();

    loop {
        if pos >= payload.len() {
            return None;
        }
        let label_len = payload[pos] as usize;
        if label_len == 0 {
            break; // Root label terminator.
        }
        // Pointer compression (0xC0 prefix) — unlikely in queries, bail out.
        if label_len >= 0xC0 {
            return None;
        }
        // Sanity: labels max 63 bytes per RFC 1035.
        if label_len > 63 {
            return None;
        }
        pos += 1;
        if pos + label_len > payload.len() {
            return None;
        }
        let label = &payload[pos..pos + label_len];
        // Best-effort UTF-8: DNS labels are case-insensitive ASCII in practice.
        labels.push(String::from_utf8_lossy(label).to_lowercase());
        pos += label_len;

        // Safety: cap total name length at 253 chars (RFC 1035 max).
        let total: usize = labels.iter().map(|l| l.len() + 1).sum();
        if total > 253 {
            return None;
        }
    }

    if labels.is_empty() {
        return None;
    }

    Some(labels.join("."))
}

/// Read and parse a sockaddr structure from the traced process's memory.
///
/// Handles AF_INET (IPv4), AF_INET6, AF_UNIX, and AF_NETLINK.
/// Returns a generic fallback for unrecognized families.
/// `len` is the kernel-reported address length used to bound reads (especially
/// for AF_UNIX path length).
pub fn read_sockaddr(pid: Pid, addr: u64, len: usize) -> SockAddrInfo {
    // Minimum sockaddr is 2 bytes (sa_family only).
    if len < 2 {
        return SockAddrInfo {
            family: "unknown".into(),
            display: "(too short)".into(),
        };
    }
    // Read the first 8 bytes which contain sa_family + first data fields.
    let family_word = match ptrace::read(pid, addr as *mut _) {
        Ok(w) => w as u64,
        Err(_) => {
            return SockAddrInfo {
                family: "unknown".into(),
                display: "(unreadable)".into(),
            };
        }
    };

    // sa_family is the first 2 bytes (little-endian on all supported arches).
    let family = (family_word & 0xFFFF) as u16;

    match family {
        2 => {
            // AF_INET: struct sockaddr_in { family(2) + port(2) + addr(4) }
            // port and addr are in network byte order within the struct.
            let port = ((family_word >> 16) & 0xFFFF) as u16;
            let port = u16::from_be(port);
            let addr_bytes = ((family_word >> 32) & 0xFFFFFFFF) as u32;
            let ip = std::net::Ipv4Addr::from(u32::from_be(addr_bytes));
            SockAddrInfo {
                family: "AF_INET".into(),
                display: format!("{ip}:{port}"),
            }
        }
        10 => {
            // AF_INET6: struct sockaddr_in6 {
            //   family(2) + port(2) + flowinfo(4) + addr(16) + scope_id(4)
            // }
            // Port is at offset 2 (network byte order), address at offset 8.
            let port = ((family_word >> 16) & 0xFFFF) as u16;
            let port = u16::from_be(port);

            // Read the 16-byte IPv6 address starting at offset 8.
            let mut addr_bytes = [0u8; 16];
            let mut ok = true;
            for word_idx in 0..2 {
                let offset = 8 + word_idx * 8;
                match ptrace::read(pid, (addr + offset as u64) as *mut _) {
                    Ok(w) => {
                        let bytes = (w as u64).to_ne_bytes();
                        let start = word_idx * 8;
                        addr_bytes[start..start + 8].copy_from_slice(&bytes);
                    }
                    Err(_) => { ok = false; break; }
                }
            }

            if ok {
                let ip = std::net::Ipv6Addr::from(addr_bytes);
                SockAddrInfo {
                    family: "AF_INET6".into(),
                    display: format!("[{ip}]:{port}"),
                }
            } else {
                SockAddrInfo {
                    family: "AF_INET6".into(),
                    display: format!("(IPv6):{port}"),
                }
            }
        }
        1 => {
            // AF_UNIX: path starts at offset 2 in sockaddr_un.
            // Use addrlen to bound the path read (path_len = len - 2, max 108).
            let path_len = len.saturating_sub(2).min(108);
            // Abstract sockets have a NUL byte at offset 2 followed by the name;
            // read_string would return empty. Detect this and read past the NUL.
            let first_byte = match ptrace::read(pid, (addr + 2) as *mut _) {
                Ok(w) => w as u8,
                Err(_) => 0,
            };
            let path = if first_byte == 0 {
                // Abstract socket: name starts after the leading NUL byte.
                let name = read_string(pid, addr + 3, path_len.saturating_sub(1));
                if name.is_empty() {
                    "(abstract)".to_string()
                } else {
                    format!("@{name}")
                }
            } else {
                read_string(pid, addr + 2, path_len)
            };
            SockAddrInfo {
                family: "AF_UNIX".into(),
                display: path,
            }
        }
        16 => {
            // AF_NETLINK: kernel interface probing.
            // nl_pid is at offset 4 in sockaddr_nl (after family(2) + pad(2)).
            // The protocol is specified in the socket() call, not the address.
            let nl_pid = ((family_word >> 32) & 0xFFFFFFFF) as u32;
            SockAddrInfo {
                family: "AF_NETLINK".into(),
                display: format!("nl_pid={nl_pid}"),
            }
        }
        _ => SockAddrInfo {
            family: format!("AF_{family}"),
            display: "(unknown)".into(),
        },
    }
}
