//! CLI subcommand implementations.
//!
//! Each subcommand gets its own module with a Clap `Args` or `Subcommand`
//! struct and an `execute()` method that drives the operation.

pub mod cas;
pub mod cat;
pub mod check;
pub mod clean;
pub mod diff;
pub mod doctor;
pub mod export;
pub mod firecracker;
pub mod init;
pub mod inspect;
pub mod key;
pub mod list;
pub mod policy;
pub mod replay;
pub mod report;
pub mod run;
pub mod session;
pub mod verify;

use oaie_core::config::OaieStore;
use oaie_core::error::{OaieError, Result};

/// Load the OAIE store from default or env-configured path.
/// Reads `config.toml` to set the hash algorithm. Returns error if not initialized.
pub fn load_store() -> Result<OaieStore> {
    let mut store = OaieStore::from_env()?;
    if !store.is_initialized() {
        return Err(OaieError::StoreNotInitialized);
    }
    store.open()?;
    Ok(store)
}
