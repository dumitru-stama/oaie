//! Verification result types for run integrity checks.
//!
//! The types live here in oaie-core so any crate can reference them.
//! The actual verification logic lives in oaie-cli (needs CAS + DB access).

use std::fmt;

/// The result of verifying a single run.
#[derive(Debug)]
pub struct VerifyReport {
    /// The run that was verified.
    pub run_id: crate::run_id::RunId,
    /// Individual check results.
    pub checks: Vec<CheckResult>,
}

/// Result of a single verification check.
#[derive(Debug)]
pub struct CheckResult {
    /// What was checked.
    pub check: CheckKind,
    /// Whether it passed, failed, or was skipped.
    pub status: CheckStatus,
    /// Human-readable detail (e.g. "3 artifacts verified" or "1 missing: ab3f").
    pub detail: Option<String>,
}

/// The kinds of checks performed during run verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckKind {
    /// manifest.toml exists in the run directory.
    ManifestExists,
    /// manifest.toml is valid TOML and deserializes correctly.
    ManifestParseable,
    /// All input artifacts referenced by the manifest exist in CAS.
    InputArtifactsExist,
    /// All output artifacts referenced by the manifest exist in CAS.
    OutputArtifactsExist,
    /// Input artifact content hashes match their CAS filenames.
    InputArtifactHashes,
    /// Output artifact content hashes match their CAS filenames.
    OutputArtifactHashes,
    /// The trace index (trace_index.json) exists in CAS.
    TraceIndexExists,
    /// All trace chunks listed in the index exist in CAS.
    TraceChunksExist,
    /// Trace chunk content hashes match their CAS filenames.
    TraceChunkHashes,
    /// The event hash chain is intact across all chunks.
    EventChainIntegrity,
    /// The chain tip matches what the trace index claims.
    EventChainTip,
    /// Ed25519 manifest signature verification.
    ManifestSignature,

    // ── Session verification checks ──

    /// session_manifest.toml exists in the session directory.
    SessionManifestExists,
    /// session_manifest.toml is valid TOML and parseable.
    SessionManifestParseable,
    /// Session event log exists in CAS.
    SessionEventLogExists,
    /// Session event log content hash matches the manifest claim.
    SessionEventLogHash,
    /// Session event hash chain is intact (all events link correctly).
    SessionEventChainIntegrity,
    /// Session event chain tip matches the manifest claim.
    SessionEventChainTip,
    /// All runs referenced by session calls pass verification.
    SessionRunsVerified,
}

/// The result of verifying a session (recursive: includes nested run checks).
#[derive(Debug)]
pub struct SessionVerifyReport {
    /// The session that was verified.
    pub session_id: String,
    /// Session-level check results.
    pub checks: Vec<CheckResult>,
    /// Nested run verification reports for each session call.
    pub run_reports: Vec<VerifyReport>,
}

impl SessionVerifyReport {
    /// True if all session checks and all nested run checks passed (or were skipped).
    pub fn passed(&self) -> bool {
        self.checks
            .iter()
            .all(|c| matches!(c.status, CheckStatus::Pass | CheckStatus::Skip))
            && self.run_reports.iter().all(|r| r.passed())
    }

    /// Human-readable summary.
    pub fn summary(&self) -> String {
        let pass = self.checks.iter().filter(|c| c.status == CheckStatus::Pass).count();
        let fail = self.checks.iter().filter(|c| c.status == CheckStatus::Fail).count();
        let skip = self.checks.iter().filter(|c| c.status == CheckStatus::Skip).count();
        let run_pass = self.run_reports.iter().filter(|r| r.passed()).count();
        let run_total = self.run_reports.len();
        format!(
            "{pass} passed, {fail} failed, {skip} skipped; {run_pass}/{run_total} runs verified"
        )
    }
}

/// Status of a single verification check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    /// Check passed — data is intact.
    Pass,
    /// Check failed — data is missing, corrupted, or inconsistent.
    Fail,
    /// Check was skipped (e.g. trace checks when no tracing was used).
    Skip,
}

impl VerifyReport {
    /// True if all checks passed (or were skipped). No failures.
    pub fn passed(&self) -> bool {
        self.checks
            .iter()
            .all(|c| matches!(c.status, CheckStatus::Pass | CheckStatus::Skip))
    }

    /// Human-readable summary like "8 passed, 1 failed, 2 skipped".
    pub fn summary(&self) -> String {
        let pass = self
            .checks
            .iter()
            .filter(|c| c.status == CheckStatus::Pass)
            .count();
        let fail = self
            .checks
            .iter()
            .filter(|c| c.status == CheckStatus::Fail)
            .count();
        let skip = self
            .checks
            .iter()
            .filter(|c| c.status == CheckStatus::Skip)
            .count();
        format!("{pass} passed, {fail} failed, {skip} skipped")
    }
}

impl CheckKind {
    /// Human-readable name for display in verify output.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::ManifestExists => "Manifest exists",
            Self::ManifestParseable => "Manifest parseable",
            Self::InputArtifactsExist => "Input artifacts in CAS",
            Self::OutputArtifactsExist => "Output artifacts in CAS",
            Self::InputArtifactHashes => "Input artifact hashes match",
            Self::OutputArtifactHashes => "Output artifact hashes match",
            Self::TraceIndexExists => "Trace index in CAS",
            Self::TraceChunksExist => "Trace chunks in CAS",
            Self::TraceChunkHashes => "Trace chunk hashes match",
            Self::EventChainIntegrity => "Event chain integrity",
            Self::EventChainTip => "Event chain tip matches index",
            Self::ManifestSignature => "Manifest signature",
            Self::SessionManifestExists => "Session manifest exists",
            Self::SessionManifestParseable => "Session manifest parseable",
            Self::SessionEventLogExists => "Session event log in CAS",
            Self::SessionEventLogHash => "Session event log hash matches",
            Self::SessionEventChainIntegrity => "Session event chain integrity",
            Self::SessionEventChainTip => "Session event chain tip matches",
            Self::SessionRunsVerified => "Session runs verified",
        }
    }
}

impl fmt::Display for CheckKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

impl fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "Pass"),
            Self::Fail => write!(f, "Fail"),
            Self::Skip => write!(f, "Skip"),
        }
    }
}
