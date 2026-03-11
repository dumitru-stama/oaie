//! Domain pattern matching for DNS allowlist filtering.
//!
//! Supports exact domain matching and wildcard patterns (e.g. `*.anthropic.com`).
//! Used by the DNS proxy to decide whether to forward or block queries.

/// A pattern for matching DNS domain names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DomainPattern {
    /// Exact match: "api.anthropic.com" matches only "api.anthropic.com".
    Exact(String),
    /// Wildcard suffix: "*.anthropic.com" matches "api.anthropic.com"
    /// and "cdn.anthropic.com" but NOT "anthropic.com" itself.
    /// Stores the suffix with a leading dot pre-computed (e.g. ".anthropic.com")
    /// to avoid allocation on every `matches()` call in the DNS proxy hot path.
    Wildcard(String),
}

impl DomainPattern {
    /// Parse a domain pattern string.
    ///
    /// Patterns starting with `*.` are treated as wildcards.
    /// Everything else is an exact match.
    pub fn parse(s: &str) -> Self {
        let lower = s.to_ascii_lowercase();
        if let Some(suffix) = lower.strip_prefix("*.") {
            // Store with leading dot for O(1) suffix matching without allocation.
            DomainPattern::Wildcard(format!(".{suffix}"))
        } else {
            DomainPattern::Exact(lower)
        }
    }

    /// Check if a query domain matches this pattern.
    ///
    /// Matching is case-insensitive.
    pub fn matches(&self, query: &str) -> bool {
        let query_lower = query.to_ascii_lowercase();
        match self {
            DomainPattern::Exact(domain) => query_lower == *domain,
            DomainPattern::Wildcard(dot_suffix) => {
                // dot_suffix is ".example.com" (pre-computed with leading dot).
                // "*.example.com" matches "sub.example.com" but not "example.com".
                query_lower.ends_with(dot_suffix.as_str())
            }
        }
    }

    /// Get the base domain (without wildcard prefix or leading dot).
    pub fn base_domain(&self) -> &str {
        match self {
            DomainPattern::Exact(d) => d,
            // Strip the leading dot from stored ".example.com" → "example.com".
            DomainPattern::Wildcard(d) => &d[1..],
        }
    }
}

/// Check if a query domain matches any pattern in the allowlist.
pub fn matches_any(query: &str, patterns: &[DomainPattern]) -> bool {
    patterns.iter().any(|p| p.matches(query))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        let p = DomainPattern::parse("api.anthropic.com");
        assert!(p.matches("api.anthropic.com"));
        assert!(p.matches("API.ANTHROPIC.COM")); // case insensitive
        assert!(!p.matches("cdn.anthropic.com"));
        assert!(!p.matches("anthropic.com"));
    }

    #[test]
    fn wildcard_match() {
        let p = DomainPattern::parse("*.anthropic.com");
        assert!(p.matches("api.anthropic.com"));
        assert!(p.matches("cdn.anthropic.com"));
        assert!(p.matches("deep.sub.anthropic.com"));
        assert!(!p.matches("anthropic.com")); // wildcard does NOT match bare domain
        assert!(!p.matches("evil-anthropic.com")); // not a subdomain
    }

    #[test]
    fn case_insensitive_pattern() {
        let p = DomainPattern::parse("*.EXAMPLE.COM");
        assert!(p.matches("sub.example.com"));
    }

    #[test]
    fn matches_any_works() {
        let patterns = vec![
            DomainPattern::parse("api.anthropic.com"),
            DomainPattern::parse("*.openai.com"),
        ];
        assert!(matches_any("api.anthropic.com", &patterns));
        assert!(matches_any("api.openai.com", &patterns));
        assert!(!matches_any("evil.example.com", &patterns));
    }

    #[test]
    fn base_domain() {
        assert_eq!(DomainPattern::parse("api.example.com").base_domain(), "api.example.com");
        assert_eq!(DomainPattern::parse("*.example.com").base_domain(), "example.com");
    }

    #[test]
    fn parse_variants() {
        assert!(matches!(DomainPattern::parse("example.com"), DomainPattern::Exact(_)));
        assert!(matches!(DomainPattern::parse("*.example.com"), DomainPattern::Wildcard(_)));
        // Single * is treated as exact (unusual but handled)
        assert!(matches!(DomainPattern::parse("*"), DomainPattern::Exact(_)));
    }
}
