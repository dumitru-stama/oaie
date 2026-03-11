//! TLS SNI (Server Name Indication) extraction and validation.
//!
//! Post-hoc analysis tool — extracts the hostname from a TLS ClientHello
//! and validates it against the allowed domain patterns. Used in report
//! generation to detect potential DNS rebinding or policy violations.
//!
//! This does NOT perform real-time blocking. The nftables rules enforce
//! IP-level filtering; SNI is for audit trail verification.

use crate::domain::DomainPattern;

/// TLS record types and handshake constants.
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 22;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 1;
const TLS_EXTENSION_SNI: u16 = 0;
const SNI_HOST_NAME_TYPE: u8 = 0;

/// Extract the SNI hostname from TLS ClientHello data.
///
/// Parses just enough of the TLS record to find the SNI extension.
/// Returns `None` if the data is not a TLS ClientHello or has no SNI.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    // TLS record header: content_type(1) + version(2) + length(2) = 5 bytes.
    if data.len() < 5 {
        return None;
    }
    if data[0] != TLS_CONTENT_TYPE_HANDSHAKE {
        return None;
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return None;
    }

    let handshake = &data[5..5 + record_len];

    // Handshake header: type(1) + length(3).
    if handshake.len() < 4 {
        return None;
    }
    if handshake[0] != TLS_HANDSHAKE_CLIENT_HELLO {
        return None;
    }

    let hs_len = ((handshake[1] as usize) << 16)
        | ((handshake[2] as usize) << 8)
        | (handshake[3] as usize);
    if handshake.len() < 4 + hs_len {
        return None;
    }

    let hello = &handshake[4..4 + hs_len];

    // ClientHello: version(2) + random(32) = 34 bytes minimum.
    if hello.len() < 34 {
        return None;
    }
    let mut pos = 34;

    // Session ID (length-prefixed).
    if pos >= hello.len() {
        return None;
    }
    let session_id_len = hello[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites (2-byte length prefix).
    if pos + 2 > hello.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    // Compression methods (1-byte length prefix).
    if pos >= hello.len() {
        return None;
    }
    let comp_len = hello[pos] as usize;
    pos += 1 + comp_len;

    // Extensions (2-byte length prefix).
    if pos + 2 > hello.len() {
        return None; // No extensions.
    }
    let ext_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_len;
    if ext_end > hello.len() {
        return None;
    }

    // Walk extensions looking for SNI (type 0).
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_data_len > ext_end {
            return None;
        }

        if ext_type == TLS_EXTENSION_SNI {
            return parse_sni_extension(&hello[pos..pos + ext_data_len]);
        }

        pos += ext_data_len;
    }

    None
}

/// Parse the SNI extension data to extract the hostname.
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    // SNI extension: list_length(2) + entries.
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return None;
    }

    let mut pos = 2;
    let end = 2 + list_len;

    while pos + 3 <= end {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;

        if pos + name_len > end {
            return None;
        }

        if name_type == SNI_HOST_NAME_TYPE {
            return std::str::from_utf8(&data[pos..pos + name_len])
                .ok()
                .map(|s| s.to_string());
        }

        pos += name_len;
    }

    None
}

/// Validate an SNI hostname against allowed domain patterns.
///
/// Returns true if the SNI matches any allowed pattern.
pub fn validate_sni(sni: &str, allowed: &[DomainPattern]) -> bool {
    crate::domain::matches_any(sni, allowed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS ClientHello with SNI for testing.
    fn build_client_hello_with_sni(hostname: &str) -> Vec<u8> {
        let mut pkt = Vec::new();

        // SNI extension data.
        let hostname_bytes = hostname.as_bytes();
        let sni_name_entry_len = 3 + hostname_bytes.len(); // type(1) + len(2) + name
        let sni_list_len = sni_name_entry_len;
        let _sni_ext_data_len = 2 + sni_list_len; // list_len(2) + entries

        // Extensions block.
        let ext_type = TLS_EXTENSION_SNI.to_be_bytes();
        let ext_data = {
            let mut d = Vec::new();
            d.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
            d.push(SNI_HOST_NAME_TYPE);
            d.extend_from_slice(&(hostname_bytes.len() as u16).to_be_bytes());
            d.extend_from_slice(hostname_bytes);
            d
        };
        let extensions_block = {
            let mut e = Vec::new();
            e.extend_from_slice(&ext_type);
            e.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
            e.extend_from_slice(&ext_data);
            e
        };

        // ClientHello body.
        let mut hello_body = Vec::new();
        hello_body.extend_from_slice(&[0x03, 0x03]); // Version: TLS 1.2
        hello_body.extend_from_slice(&[0u8; 32]); // Random
        hello_body.push(0); // Session ID length: 0
        hello_body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2F]); // Cipher suites: 1 suite
        hello_body.extend_from_slice(&[0x01, 0x00]); // Compression: null
        hello_body.extend_from_slice(&(extensions_block.len() as u16).to_be_bytes());
        hello_body.extend_from_slice(&extensions_block);

        // Handshake header.
        let mut handshake = Vec::new();
        handshake.push(TLS_HANDSHAKE_CLIENT_HELLO);
        let hs_len = hello_body.len();
        handshake.push((hs_len >> 16) as u8);
        handshake.push((hs_len >> 8) as u8);
        handshake.push(hs_len as u8);
        handshake.extend_from_slice(&hello_body);

        // TLS record header.
        pkt.push(TLS_CONTENT_TYPE_HANDSHAKE);
        pkt.extend_from_slice(&[0x03, 0x01]); // Version: TLS 1.0 (record layer)
        pkt.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&handshake);

        pkt
    }

    #[test]
    fn extract_sni_basic() {
        let hello = build_client_hello_with_sni("api.anthropic.com");
        let sni = extract_sni(&hello);
        assert_eq!(sni.as_deref(), Some("api.anthropic.com"));
    }

    #[test]
    fn extract_sni_long_hostname() {
        let hello = build_client_hello_with_sni("very.long.subdomain.example.com");
        let sni = extract_sni(&hello);
        assert_eq!(sni.as_deref(), Some("very.long.subdomain.example.com"));
    }

    #[test]
    fn extract_sni_not_tls() {
        assert!(extract_sni(&[0x17, 0x03, 0x01, 0x00, 0x05]).is_none()); // Application data
        assert!(extract_sni(&[0; 3]).is_none()); // Too short
    }

    #[test]
    fn validate_sni_allowed() {
        let patterns = vec![DomainPattern::parse("api.anthropic.com")];
        assert!(validate_sni("api.anthropic.com", &patterns));
        assert!(!validate_sni("evil.example.com", &patterns));
    }

    #[test]
    fn validate_sni_wildcard() {
        let patterns = vec![DomainPattern::parse("*.anthropic.com")];
        assert!(validate_sni("api.anthropic.com", &patterns));
        assert!(!validate_sni("anthropic.com", &patterns));
    }
}
