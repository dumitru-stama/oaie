//! Serializable types for the agent API.
//!
//! Re-exports `StructuredRunResult` from oaie-core and provides a
//! serializable `VerifyReport` for JSON consumption.

use serde::{Deserialize, Serialize};

/// Serializable verification report for programmatic consumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    /// Run ID that was verified.
    pub run_id: String,
    /// Whether all checks passed (no failures).
    pub passed: bool,
    /// Summary string like "8 passed, 0 failed, 3 skipped".
    pub summary: String,
    /// Individual check results.
    pub checks: Vec<VerifyCheck>,
}

/// A single verification check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyCheck {
    /// What was checked (e.g. "ManifestExists").
    pub check: String,
    /// Status: "Pass", "Fail", or "Skip".
    pub status: String,
    /// Human-readable detail (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Convert an oaie-core `VerifyReport` into a serializable `VerifyReport`.
impl From<oaie_core::verify::VerifyReport> for VerifyReport {
    fn from(r: oaie_core::verify::VerifyReport) -> Self {
        Self {
            run_id: r.run_id.full(),
            passed: r.passed(),
            summary: r.summary(),
            checks: r
                .checks
                .iter()
                .map(|c| VerifyCheck {
                    check: format!("{:?}", c.check),
                    status: format!("{:?}", c.status),
                    detail: c.detail.clone(),
                })
                .collect(),
        }
    }
}
