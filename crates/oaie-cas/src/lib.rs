//! Content-addressed store for OAIE artifacts.
//!
//! Stores blobs keyed by their content hash. Deduplicates automatically.
//! Uses atomic rename (temp file -> fsync -> rename) for crash safety.
//! Supports BLAKE3 (default) and SHA-256 via `HashAlgorithm`.

pub mod store;

pub use store::{CasStore, VerifyResult};
