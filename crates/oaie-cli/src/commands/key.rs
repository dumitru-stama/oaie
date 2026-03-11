//! The `oaie key` subcommand group — manage signing keys for manifest attestation.

use clap::{Args, Subcommand};

use oaie_core::error::Result;

use super::load_store;
use crate::output;

/// Manage signing keys for manifest attestation.
#[derive(Subcommand, Debug)]
pub enum KeyCmd {
    /// Generate a new Ed25519 signing key
    Generate(KeyGenerateCmd),
    /// List all signing keys
    List(KeyListCmd),
    /// Delete a signing key
    Delete(KeyDeleteCmd),
    /// Export a key (full or public-only)
    Export(KeyExportCmd),
}

impl KeyCmd {
    pub fn execute(&self) -> Result<()> {
        match self {
            Self::Generate(cmd) => cmd.execute(),
            Self::List(cmd) => cmd.execute(),
            Self::Delete(cmd) => cmd.execute(),
            Self::Export(cmd) => cmd.execute(),
        }
    }
}

/// Generate a new Ed25519 signing key.
#[derive(Args, Debug)]
pub struct KeyGenerateCmd {
    /// Human-readable label for the key (e.g. "work-laptop", "ci-server").
    #[arg(long, default_value = "default")]
    pub label: String,
}

impl KeyGenerateCmd {
    pub fn execute(&self) -> Result<()> {
        let store = load_store()?;
        let (info, secret) = oaie_cli::signing::generate_keypair(&self.label)?;
        oaie_cli::signing::save_key(&store.keys_dir, &info, &secret)?;

        output::info("Generated Ed25519 signing key");
        output::field("Key ID", &info.key_id);
        output::field("Label", &info.label);
        output::field("Public key", &format!("{}...", &info.public_key[..16]));
        output::field("Stored at", &store.keys_dir.join(format!("{}.toml", info.key_id)).display().to_string());

        Ok(())
    }
}

/// List all signing keys.
#[derive(Args, Debug)]
pub struct KeyListCmd;

impl KeyListCmd {
    pub fn execute(&self) -> Result<()> {
        let store = load_store()?;
        let keys = oaie_cli::signing::list_keys(&store.keys_dir)?;

        if keys.is_empty() {
            output::info("No signing keys found. Generate one with: oaie key generate --label <name>");
            return Ok(());
        }

        output::header("Signing Keys");
        for key in &keys {
            let pub_short = if key.public_key.len() >= 12 {
                &key.public_key[..12]
            } else {
                &key.public_key
            };
            output::field(
                &format!("{} ({})", key.key_id, key.label),
                &format!("{} pub:{}..  created:{}", key.algorithm, pub_short, &key.created[..10]),
            );
        }

        // Show default key hint if none configured.
        let has_default = store.signing.as_ref().and_then(|s| s.default_key.as_ref()).is_some();
        if !has_default && !keys.is_empty() {
            println!();
            output::info("Tip: set a default key in config.toml [signing] section, or use --sign <key>");
        }

        Ok(())
    }
}

/// Delete a signing key.
#[derive(Args, Debug)]
pub struct KeyDeleteCmd {
    /// Key ID prefix or label to delete.
    pub key_id: String,
}

impl KeyDeleteCmd {
    pub fn execute(&self) -> Result<()> {
        let store = load_store()?;

        // Verify key exists before deleting.
        let (info, _) = oaie_cli::signing::load_key(&store.keys_dir, &self.key_id)?;

        oaie_cli::signing::delete_key(&store.keys_dir, &self.key_id)?;
        output::info(&format!("Deleted signing key {} ({})", info.key_id, info.label));

        Ok(())
    }
}

/// Export a key's TOML representation.
#[derive(Args, Debug)]
pub struct KeyExportCmd {
    /// Key ID prefix or label to export.
    pub key_id: String,

    /// Export only the public key (safe to share).
    #[arg(long)]
    pub public: bool,
}

impl KeyExportCmd {
    pub fn execute(&self) -> Result<()> {
        let store = load_store()?;
        let (info, secret) = oaie_cli::signing::load_key(&store.keys_dir, &self.key_id)?;

        if self.public {
            // Public-only export: safe to share.
            let public_toml = toml::to_string_pretty(&info)
                .map_err(|e| oaie_core::error::OaieError::Io(std::io::Error::other(e)))?;
            println!("{public_toml}");
        } else {
            // Full export including secret key. Warn the user.
            output::warn("Exporting FULL key including secret key material.");
            output::warn("Keep this output secure — anyone with the secret key can sign manifests.");
            println!();

            #[derive(serde::Serialize)]
            struct FullExport {
                version: u32,
                algorithm: oaie_core::signing::SigningAlgorithm,
                label: String,
                key_id: String,
                created: String,
                public_key: String,
                secret_key: String,
            }

            let full = FullExport {
                version: info.version,
                algorithm: info.algorithm,
                label: info.label,
                key_id: info.key_id,
                created: info.created,
                public_key: info.public_key,
                secret_key: secret,
            };

            let toml_str = toml::to_string_pretty(&full)
                .map_err(|e| oaie_core::error::OaieError::Io(std::io::Error::other(e)))?;
            println!("{toml_str}");
        }

        Ok(())
    }
}
