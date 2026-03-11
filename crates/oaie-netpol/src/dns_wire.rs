//! Minimal DNS wire format parsing.
//!
//! Implements just enough DNS packet parsing for the proxy:
//! - Extract query name and type from a DNS query packet.
//! - Build an NXDOMAIN response from a query packet.
//! - Extract A/AAAA addresses from a DNS response.
//!
//! No external DNS library dependency — the wire format for simple
//! queries/responses is straightforward (RFC 1035).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// DNS header size in bytes.
const HEADER_SIZE: usize = 12;

/// DNS record types.
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;

/// DNS response codes.
const RCODE_SERVFAIL: u8 = 2;
const RCODE_NXDOMAIN: u8 = 3;

/// Extract the query domain name and query type from a DNS query packet.
///
/// Returns `(domain, qtype)` where qtype is the numeric DNS type (1=A, 28=AAAA).
/// Returns `None` if the packet is malformed or too short.
pub fn extract_query_name(packet: &[u8]) -> Option<(String, u16)> {
    if packet.len() < HEADER_SIZE + 5 {
        return None; // Too short for header + minimal question
    }

    // Parse the question section (starts at byte 12).
    let mut pos = HEADER_SIZE;
    let mut labels = Vec::new();

    loop {
        if pos >= packet.len() {
            return None;
        }
        let len = packet[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        // Pointer compression in queries is rare but check anyway.
        if len & 0xC0 == 0xC0 {
            return None; // Don't handle compression in queries.
        }
        if len > 63 || pos + 1 + len > packet.len() {
            return None; // Label too long or truncated.
        }
        labels.push(
            std::str::from_utf8(&packet[pos + 1..pos + 1 + len])
                .ok()?
                .to_string(),
        );
        pos += 1 + len;
    }

    // Read QTYPE (2 bytes) after the name.
    if pos + 2 > packet.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);

    let domain = labels.join(".");
    Some((domain, qtype))
}

/// Build an NXDOMAIN response from a query packet.
///
/// Mirrors the query's ID and question section, sets QR=1, RA=1, RCODE=3.
pub fn build_nxdomain(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < HEADER_SIZE {
        return None;
    }

    let mut response = query.to_vec();

    // Set QR=1 (response), keep opcode, set RA=1.
    response[2] = (query[2] & 0x78) | 0x80; // QR=1, preserve opcode
    response[3] = 0x80 | RCODE_NXDOMAIN; // RA=1, RCODE=NXDOMAIN

    // ANCOUNT=0, NSCOUNT=0, ARCOUNT=0 (keep QDCOUNT as-is).
    response[6..8].copy_from_slice(&[0, 0]); // ANCOUNT
    response[8..10].copy_from_slice(&[0, 0]); // NSCOUNT
    response[10..12].copy_from_slice(&[0, 0]); // ARCOUNT

    Some(response)
}

/// Build a SERVFAIL response from a query packet.
///
/// Used when the upstream DNS resolver fails — tells the client to retry later
/// instead of NXDOMAIN which would get negative-cached.
pub fn build_servfail(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < HEADER_SIZE {
        return None;
    }

    let mut response = query.to_vec();

    // Set QR=1 (response), keep opcode, set RA=1.
    response[2] = (query[2] & 0x78) | 0x80;
    response[3] = 0x80 | RCODE_SERVFAIL; // RA=1, RCODE=SERVFAIL

    // ANCOUNT=0, NSCOUNT=0, ARCOUNT=0.
    response[6..8].copy_from_slice(&[0, 0]);
    response[8..10].copy_from_slice(&[0, 0]);
    response[10..12].copy_from_slice(&[0, 0]);

    Some(response)
}

/// Extract A and AAAA addresses from a DNS response packet.
///
/// Parses the answer section and returns all IP addresses found.
pub fn extract_response_addrs(response: &[u8]) -> Vec<IpAddr> {
    let mut addrs = Vec::new();

    if response.len() < HEADER_SIZE {
        return addrs;
    }

    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    if ancount == 0 {
        return addrs;
    }

    // Skip past the question section.
    let mut pos = HEADER_SIZE;

    // Skip QDCOUNT questions.
    let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
    for _ in 0..qdcount {
        match skip_name_checked(response, pos) {
            Some(p) => pos = p,
            None => return addrs,
        }
        pos += 4; // QTYPE + QCLASS
        if pos > response.len() {
            return addrs;
        }
    }

    // Parse answer records.
    for _ in 0..ancount {
        if pos >= response.len() {
            break;
        }

        // Skip the name (may use compression pointers).
        let new_pos = match skip_name_checked(response, pos) {
            Some(p) => p,
            None => break,
        };
        pos = new_pos;

        // Read TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) = 10 bytes.
        if pos + 10 > response.len() {
            break;
        }
        let rtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > response.len() {
            break;
        }

        match rtype {
            TYPE_A if rdlength == 4 => {
                let addr = Ipv4Addr::new(
                    response[pos],
                    response[pos + 1],
                    response[pos + 2],
                    response[pos + 3],
                );
                addrs.push(IpAddr::V4(addr));
            }
            TYPE_AAAA if rdlength == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&response[pos..pos + 16]);
                addrs.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }

        pos += rdlength;
    }

    addrs
}

/// Skip a DNS name with bounds checking (handles compression pointers).
///
/// The 128-iteration cap is well above the DNS limit of 127 labels per name
/// (max name = 253 bytes, min label = 1 byte + length byte = 2 bytes).
/// Each iteration advances `pos` or returns, so the loop terminates.
fn skip_name_checked(packet: &[u8], mut pos: usize) -> Option<usize> {
    // 128 = max labels per DNS name (RFC 1035: max 253 octets, min 2 per label).
    for _ in 0..128 {
        if pos >= packet.len() {
            return None;
        }
        let len = packet[pos] as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer: 2 bytes, then done.
            return Some(pos + 2);
        }
        if len > 63 {
            return None;
        }
        pos += 1 + len;
    }
    None // Too many labels.
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS query for testing.
    fn build_test_query(domain: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Header: ID=0x1234, flags=0x0100 (standard query, RD=1),
        // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        pkt.extend_from_slice(&[0x12, 0x34, 0x01, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // Question: encode domain name as labels.
        for label in domain.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0); // Root label.

        // QTYPE + QCLASS=IN(1)
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01]);

        pkt
    }

    /// Build a DNS response with A records for testing.
    fn build_test_response(domain: &str, addrs: &[Ipv4Addr]) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Header: ID=0x1234, flags=0x8180 (response, RD=1, RA=1),
        // QDCOUNT=1, ANCOUNT=N
        pkt.extend_from_slice(&[0x12, 0x34, 0x81, 0x80]);
        pkt.extend_from_slice(&[0x00, 0x01]);
        pkt.extend_from_slice(&(addrs.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // Question section.
        let question_start = pkt.len();
        for label in domain.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        pkt.extend_from_slice(&TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01]);

        // Answer records.
        for addr in addrs {
            // Name: compression pointer to question.
            pkt.push(0xC0);
            pkt.push(question_start as u8);
            // TYPE=A, CLASS=IN, TTL=300, RDLENGTH=4
            pkt.extend_from_slice(&TYPE_A.to_be_bytes());
            pkt.extend_from_slice(&[0x00, 0x01]); // CLASS
            pkt.extend_from_slice(&300u32.to_be_bytes()); // TTL
            pkt.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
            pkt.extend_from_slice(&addr.octets());
        }

        pkt
    }

    #[test]
    fn extract_query_name_a_record() {
        let pkt = build_test_query("api.anthropic.com", TYPE_A);
        let (name, qtype) = extract_query_name(&pkt).unwrap();
        assert_eq!(name, "api.anthropic.com");
        assert_eq!(qtype, TYPE_A);
    }

    #[test]
    fn extract_query_name_aaaa() {
        let pkt = build_test_query("example.com", TYPE_AAAA);
        let (name, qtype) = extract_query_name(&pkt).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(qtype, TYPE_AAAA);
    }

    #[test]
    fn extract_query_too_short() {
        assert!(extract_query_name(&[0; 10]).is_none());
    }

    #[test]
    fn build_nxdomain_response() {
        let query = build_test_query("evil.example.com", TYPE_A);
        let response = build_nxdomain(&query).unwrap();

        // Check QR=1 (response bit).
        assert!(response[2] & 0x80 != 0);
        // Check RCODE=3 (NXDOMAIN).
        assert_eq!(response[3] & 0x0F, RCODE_NXDOMAIN);
        // Check ANCOUNT=0.
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    }

    #[test]
    fn extract_addrs_from_response() {
        let ip1 = Ipv4Addr::new(104, 18, 32, 7);
        let ip2 = Ipv4Addr::new(104, 18, 33, 7);
        let response = build_test_response("api.anthropic.com", &[ip1, ip2]);

        let addrs = extract_response_addrs(&response);
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], IpAddr::V4(ip1));
        assert_eq!(addrs[1], IpAddr::V4(ip2));
    }

    #[test]
    fn extract_addrs_empty_response() {
        let response = build_test_response("example.com", &[]);
        let addrs = extract_response_addrs(&response);
        assert!(addrs.is_empty());
    }

    #[test]
    fn extract_addrs_truncated() {
        let addrs = extract_response_addrs(&[0; 8]);
        assert!(addrs.is_empty());
    }

    #[test]
    fn extract_aaaa_addrs() {
        // Build a response with an AAAA record manually.
        let domain = "example.com";
        let mut pkt = Vec::new();

        // Header: ID, flags=response, QDCOUNT=1, ANCOUNT=1.
        pkt.extend_from_slice(&[0x12, 0x34, 0x81, 0x80]);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // Question.
        let question_start = pkt.len();
        for label in domain.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        pkt.extend_from_slice(&TYPE_AAAA.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01]);

        // Answer: AAAA record.
        pkt.push(0xC0);
        pkt.push(question_start as u8);
        pkt.extend_from_slice(&TYPE_AAAA.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01]); // CLASS
        pkt.extend_from_slice(&300u32.to_be_bytes()); // TTL
        pkt.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH
        let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        pkt.extend_from_slice(&ipv6.octets());

        let addrs = extract_response_addrs(&pkt);
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], IpAddr::V6(ipv6));
    }

    #[test]
    fn build_servfail_response() {
        let query = build_test_query("example.com", TYPE_A);
        let response = build_servfail(&query).unwrap();
        assert!(response[2] & 0x80 != 0); // QR=1
        assert_eq!(response[3] & 0x0F, RCODE_SERVFAIL);
    }
}
