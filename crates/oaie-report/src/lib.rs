//! Report and manifest generation for OAIE runs.
//!
//! Generates REPORT.md after each run with a human-readable summary.

pub mod report;

pub use report::generate_report;
