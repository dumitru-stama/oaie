//! The `oaie cas` subcommand — interact with the content-addressed store directly.
//!
//! Provides `add` (store a file and print its hash) and `verify` (check a blob
//! exists and its content matches the expected hash).

use std::path::PathBuf;

use clap::Subcommand;

use oaie_cas::store::{format_bytes, CasStore, VerifyResult};
use oaie_core::artifact::Hash;

use oaie_core::error::Result;

use super::load_store;
use crate::output;

/// Interact with the content-addressed store directly.
#[derive(Subcommand, Debug)]
pub enum CasCmd {
    /// Add a file to the content-addressed store
    Add {
        /// Path to the file to add
        path: PathBuf,
    },
    /// Verify a hash exists and matches its stored content
    Verify {
        /// BLAKE3 hash (64-char hex) to verify
        hash: String,
    },
}

impl CasCmd {
    /// Add a file to the CAS or verify an existing blob's integrity.
    pub fn execute(&self) -> Result<()> {
        match self {
            CasCmd::Add { path } => {
                let store = load_store()?;
                let cas = CasStore::new(store.cas_dir, store.hash_algorithm);

                let (hash, size) = cas.store_file(path)?;

                output::info(&format!("Stored: {}", path.display()));
                output::field("Hash", &hash.to_hex());
                output::field("Size", &format_bytes(size));
            }
            CasCmd::Verify { hash } => {
                let store = load_store()?;
                let cas = CasStore::new(store.cas_dir, store.hash_algorithm);
                let hash = Hash::from_hex(hash)?;

                match cas.verify(&hash)? {
                    VerifyResult::Ok => {
                        output::info("Verification passed.");
                        output::field("Hash", &hash.to_hex());
                        output::field("Size", &format_bytes(cas.blob_size(&hash)?));
                    }
                    VerifyResult::Missing => {
                        output::error(&format!("Blob not found: {}", hash.short()));
                        std::process::exit(1);
                    }
                    VerifyResult::Corrupted { expected, actual } => {
                        output::error("Blob corrupted!");
                        output::field("Expected", &expected.to_hex());
                        output::field("Actual", &actual.to_hex());
                        std::process::exit(1);
                    }
                }
            }
        }
        Ok(())
    }
}
