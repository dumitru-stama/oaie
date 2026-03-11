//! Run identifiers based on UUIDv7.
//!
//! UUIDv7 is time-ordered, so run IDs sort chronologically as strings.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// UUIDv7 — time-ordered, sortable, unique.
/// Display format: first 8 hex chars for human use ("a1b2c3d4"),
/// full UUID stored internally.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RunId(uuid::Uuid);

impl RunId {
    /// Generate a new time-ordered UUIDv7 run identifier.
    pub fn new() -> Self {
        Self(uuid::Uuid::now_v7())
    }

    /// Returns the full UUID.
    pub fn as_uuid(&self) -> &uuid::Uuid {
        &self.0
    }

    /// Returns the full UUID as a hyphenated string.
    pub fn full(&self) -> String {
        self.0.to_string()
    }

    /// Returns the short 8-char hex prefix for human display.
    pub fn short(&self) -> String {
        // UUIDv7 simple (no hyphens) hex, take first 8 chars.
        self.0.simple().to_string()[..8].to_string()
    }

    /// Check if this RunId's hex representation starts with the given prefix.
    pub fn matches_prefix(&self, prefix: &str) -> bool {
        self.0.simple().to_string().starts_with(prefix)
    }
}

impl Default for RunId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Short form for human display.
        let hex = self.0.simple().to_string();
        write!(f, "{}", &hex[..8])
    }
}

impl FromStr for RunId {
    type Err = crate::error::OaieError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try parsing as a full UUID first (with or without hyphens).
        if let Ok(uuid) = uuid::Uuid::parse_str(s) {
            return Ok(Self(uuid));
        }
        // Short prefixes can't be resolved to a specific RunId without a database
        // lookup, so we reject them here. Callers that want prefix matching should
        // use RunId::matches_prefix() against known IDs.
        Err(crate::error::OaieError::InvalidRunId(s.to_string()))
    }
}

impl Serialize for RunId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RunId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let uuid = uuid::Uuid::parse_str(&s).map_err(serde::de::Error::custom)?;
        Ok(Self(uuid))
    }
}
