//! The `oaie init` subcommand — initialize the store directory and database.

use std::path::PathBuf;

use clap::Args;

use crate::output;
use oaie_core::config::OaieStore;
use oaie_core::error::{OaieError, Result};
use oaie_core::hash_algo::HashAlgorithm;
use oaie_core::store_config::{DatabaseConfig, StoreConfig};

/// Initialize the OAIE store (directory structure + database).
#[derive(Args, Debug)]
pub struct InitCmd {
    /// Custom store path (default: ~/.oaie)
    #[arg(long)]
    pub path: Option<PathBuf>,

    /// Use SHA-256 instead of BLAKE3 for content hashing
    #[arg(long)]
    pub sha256: bool,

    /// Use PostgreSQL instead of SQLite (provide connection URL).
    ///
    /// Example: postgresql://user:password@localhost:5432/oaie
    #[arg(long)]
    pub pgsql: Option<String>,
}

impl InitCmd {
    /// Create the store directory structure and initialize the database.
    ///
    /// If a `config.toml` already exists at the resolved location, its
    /// `store_path` is authoritative — init operates there instead of the
    /// default/CLI path. This lets users move the store by editing `config.toml`
    /// and re-running `oaie init`.
    pub fn execute(&self) -> Result<()> {
        let algo = if self.sha256 {
            HashAlgorithm::Sha256
        } else {
            HashAlgorithm::Blake3
        };

        let db_config = match &self.pgsql {
            Some(url) => DatabaseConfig::Postgresql { url: url.clone() },
            None => DatabaseConfig::default(),
        };

        let mut store = match &self.path {
            Some(p) => OaieStore::from_root(p.clone()),
            None => OaieStore::from_env()?,
        };

        // If a config.toml exists, read it and follow its store_path.
        if let Some(existing) = StoreConfig::load(&store.root)? {
            if existing.hash_algorithm != algo {
                return Err(OaieError::Other(format!(
                    "store already initialized with {} — cannot switch to {}",
                    existing.hash_algorithm,
                    algo,
                )));
            }

            // Preserve the existing database configuration on re-init,
            // unless --pgsql was explicitly passed to switch backends.
            if self.pgsql.is_none() {
                store.database = existing.database.clone();
            } else {
                store.database = db_config.clone();
            }

            // If the config records a different store_path, redirect there.
            if !existing.store_path.as_os_str().is_empty()
                && existing.store_path != store.root
            {
                output::info(&format!(
                    "Config points to {} — initializing there",
                    existing.store_path.display()
                ));
                let db = store.database.clone();
                store = OaieStore::from_root(existing.store_path.clone());
                store.database = db;
            }

            if store.is_initialized() {
                output::info(&format!(
                    "Store already initialized at {}",
                    store.root.display()
                ));
                return Ok(());
            }
        } else {
            // Fresh init — use the CLI-selected database config.
            store.database = db_config;
        }

        // Canonicalize the store root for config.toml.
        // Use the raw path if canonicalize fails (dir may not exist yet).
        let canonical_root = std::fs::canonicalize(&store.root)
            .unwrap_or_else(|_| store.root.clone());

        // Create directory structure.
        store.ensure_dirs()?;

        // Write config.toml with the chosen algorithm, store path, and database config.
        let cfg = StoreConfig {
            version: 1,
            store_path: canonical_root,
            hash_algorithm: algo,
            database: store.database.clone(),
            ..StoreConfig::default()
        };
        cfg.write(&store.root)?;

        // Open and initialize the database using the configured backend.
        let db = oaie_db::OaieDb::from_config(&store.database, &store.root)?;
        db.initialize()?;

        output::info(&format!("Store initialized at {}", store.root.display()));
        output::field("Hash algorithm", &algo.to_string());
        output::field("CAS directory", &store.cas_dir.display().to_string());
        output::field("Runs directory", &store.runs_dir.display().to_string());
        output::field("Database", &store.database.to_string());

        Ok(())
    }
}
