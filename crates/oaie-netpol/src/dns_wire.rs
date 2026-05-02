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
        labels.push(std::str::from_utf8(&packet[pos + 1..pos + 1 + len]).ok()?.to_string());
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

/// Extract A and AAAA addresses from a DNS response packet, **filtered
/// to RRs whose owner-name matches the question domain**.
///
/// The owner-name filter constrains the answer section:
/// A malicious upstream resolver (or a successful spoofer past the
/// connect()/txn-id/question-section guards in dns_proxy.rs) can
/// stuff gratuitous RRs into the answer section:
///
/// ```text
///   ;; QUESTION: allowed.example.com IN A      ← echoed → forward_query passes
///   ;; ANSWER:   allowed.example.com IN A 93.184.216.34
///   ;;           victim.org          IN A 198.51.100.7   ← gratuitous
/// ```
///
/// Without the filter, both IPs reach `add_dynamic_rule` and the
/// firewall opens to 198.51.100.7 — an IP the operator never named.
/// `is_non_global` blocks RFC1918/loopback/CGNAT but passes all global
/// unicast, so any public IP could be injected.
///
/// The question-section bytewise check in `dns_proxy::proxy_loop`
/// (RFC 5452 §9.1) proves the responder echoed the question. It does
/// NOT constrain answer-section RR owner-names — that's this function's
/// job.
///
/// CNAME chains: a recursive resolver that chases CNAMEs and returns
/// the A under the *canonical* name (rather than the query name) will
/// have those RRs dropped here. Fail-closed: the workload's connect
/// fails, no allowlist hole opens. Most resolvers return the A under
/// the original qname (with the CNAME RR alongside), so this catches
/// the common case. Full CNAME-following would parse TYPE_CNAME RRs
/// and build a name → canonical chain — overkill for a [LATENT] guard
/// (start_dns_proxy has 0 production callers today).
pub fn extract_response_addrs(response: &[u8], question_domain: &str) -> Vec<IpAddr> {
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

        // Decode (not skip) the owner name so we can compare it.
        // Compression pointers are followed; resume position is past
        // the pointer in THIS stream, not where it chased to.
        let (rr_owner, new_pos) = match decode_name(response, pos) {
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

        // RFC 1035 §2.3.3: name comparisons are case-insensitive.
        // The question-section bytewise check in dns_proxy is exact-match
        // on raw bytes, but the resolver echoes our query so the case
        // already matches. Here we compare against that same string, so
        // eq_ignore_ascii_case is the most permissive correct comparison
        // (a resolver that 0x20-randomizes answer-section owner names —
        // unusual but legal — still passes).
        let owner_matches = rr_owner.eq_ignore_ascii_case(question_domain);

        match rtype {
            TYPE_A if rdlength == 4 && owner_matches => {
                let addr = Ipv4Addr::new(response[pos], response[pos + 1], response[pos + 2], response[pos + 3]);
                addrs.push(IpAddr::V4(addr));
            }
            TYPE_AAAA if rdlength == 16 && owner_matches => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&response[pos..pos + 16]);
                addrs.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            // Owner mismatch, or non-A/AAAA type (CNAME, NS, ...): skip.
            // The RR is well-formed (we parsed past it cleanly) but its
            // address — if any — does NOT answer the question we asked.
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

/// Decode a DNS name into a String, following compression pointers.
///
/// Returns `(decoded_name, position_after_name_in_original_stream)`.
/// The returned position is where the answer-section parser should
/// continue — when a compression pointer is encountered, that's
/// `pointer_pos + 2` (right after the 2-byte pointer), NOT where the
/// pointer chased to.
///
/// Differs from `extract_query_name`'s inline decoder in two ways:
/// (1) follows compression pointers (queries rarely use them; answers
/// commonly do — `api.example.com IN A` answer typically has the owner
/// name as a single 0xC00C pointer back to the question), and
/// (2) takes an arbitrary start position (questions always start at
/// HEADER_SIZE).
///
/// Compression-loop defense: a malformed packet can have pointer A → B
/// → A. The `jumps` counter caps total pointer follows at 16 (RFC 1035
/// names are ≤255 octets so ≤127 labels; but a pointer can jump
/// mid-name, and well-formed names need at most a handful of jumps —
/// 16 is well above legitimate use). Distinct from the 128-label cap,
/// which bounds the OTHER axis (a name with 200 inline labels and zero
/// pointers).
fn decode_name(packet: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    // The position in the ORIGINAL stream (before any pointer jump) where
    // the caller should resume. Set on first pointer encounter; if no
    // pointer, set when we hit the terminator.
    let mut resume_at: Option<usize> = None;
    let mut jumps = 0u8;

    for _ in 0..128 {
        if pos >= packet.len() {
            return None;
        }
        let len = packet[pos] as usize;
        if len == 0 {
            // Terminator. If we never jumped, resume right after it.
            let resume = resume_at.unwrap_or(pos + 1);
            return Some((labels.join("."), resume));
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer: top two bits set, lower 14 bits are
            // the offset from the start of the packet. RFC 1035 §4.1.4.
            if pos + 1 >= packet.len() {
                return None;
            }
            jumps += 1;
            if jumps > 16 {
                return None; // Pointer loop or pathological chaining.
            }
            // Lock in the resume position on the FIRST jump only — that's
            // where the caller's stream continues. Subsequent jumps are
            // inside the chased name.
            if resume_at.is_none() {
                resume_at = Some(pos + 2);
            }
            let target = ((len & 0x3F) << 8) | (packet[pos + 1] as usize);
            // Backward-only check: a pointer at offset N must target < N.
            // RFC 1035 doesn't strictly require this but every real
            // encoder does it (the pointed-to name has to already exist
            // when the pointer is written). A forward pointer is either
            // a parser bug or a crafted packet.
            if target >= pos {
                return None;
            }
            pos = target;
            continue;
        }
        if len > 63 {
            // 0x40-0xBF: extended label types (RFC 2671 EDNS) or reserved.
            // We don't handle them; bail.
            return None;
        }
        if pos + 1 + len > packet.len() {
            return None;
        }
        // RFC 1035 §3.1: labels are octet strings, no charset constraint.
        // We accept ASCII only (UTF-8 here is bytes-as-codepoints since
        // each label byte is <128 by the len<=63 check... no wait, that's
        // the LENGTH, not the bytes). For an allowlist comparison we want
        // the same encoding extract_query_name uses, which is from_utf8.
        // Non-UTF-8 label bytes (rare in real DNS, but a malformed packet
        // could have them) → reject the whole name. Fail-closed: the RR
        // gets skipped, no firewall hole opens.
        let label = std::str::from_utf8(&packet[pos + 1..pos + 1 + len]).ok()?;
        labels.push(label.to_string());
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

        // build_test_response uses a compression pointer (0xC0 + offset)
        // for the answer RR owner name, so this exercises decode_name's
        // pointer-following.
        let addrs = extract_response_addrs(&response, "api.anthropic.com");
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], IpAddr::V4(ip1));
        assert_eq!(addrs[1], IpAddr::V4(ip2));
    }

    #[test]
    fn extract_addrs_owner_mismatch_drops_rr() {
        // The fix this test pins: a response whose answer-section RR
        // owner-name does NOT match the question domain must NOT
        // contribute its IPs. build_test_response's answer pointer
        // chases to "api.anthropic.com" — when we tell extract that
        // we asked about "different.org", every RR is gratuitous.
        let ip = Ipv4Addr::new(198, 51, 100, 7);
        let response = build_test_response("api.anthropic.com", &[ip]);
        let addrs = extract_response_addrs(&response, "different.org");
        assert!(addrs.is_empty(), "RR owner mismatch should drop the address; got {:?}", addrs);
    }

    #[test]
    fn extract_addrs_case_insensitive_owner_match() {
        // RFC 1035 §2.3.3: name comparisons are case-insensitive.
        // A resolver that 0x20-randomizes (RFC draft-vixie-dnsext-dns0x20)
        // returns mixed-case owner names — must still match.
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        let response = build_test_response("Example.COM", &[ip]);
        let addrs = extract_response_addrs(&response, "example.com");
        assert_eq!(addrs.len(), 1);
    }

    #[test]
    fn extract_addrs_empty_response() {
        let response = build_test_response("example.com", &[]);
        let addrs = extract_response_addrs(&response, "example.com");
        assert!(addrs.is_empty());
    }

    #[test]
    fn extract_addrs_truncated() {
        let addrs = extract_response_addrs(&[0; 8], "x");
        assert!(addrs.is_empty());
    }

    #[test]
    fn decode_name_rejects_pointer_loop() {
        // A → B → A: pointer at offset 12 jumps to 14, which jumps back
        // to 12. Without the jump cap this spins forever.
        let mut pkt = vec![0u8; 20];
        pkt[12] = 0xC0;
        pkt[13] = 14; // pointer → 14
        pkt[14] = 0xC0;
        pkt[15] = 12; // pointer → 12
                      // Backward-only check catches the second pointer (14 → 12 < 14
                      // is OK; 12 → 14 > 12 fails). Either way: None, no spin.
        assert!(decode_name(&pkt, 12).is_none());
    }

    #[test]
    fn decode_name_rejects_forward_pointer() {
        // Pointer at offset 12 → offset 50 (past itself). RFC doesn't
        // strictly forbid this but every real encoder writes backward
        // pointers (the target has to exist when you write the pointer).
        // Forward = crafted or buggy.
        let mut pkt = vec![0u8; 60];
        pkt[12] = 0xC0;
        pkt[13] = 50;
        pkt[50] = 0; // valid terminator at the target
        assert!(decode_name(&pkt, 12).is_none());
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

        let addrs = extract_response_addrs(&pkt, domain);
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
