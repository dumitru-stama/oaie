//! The `oaie policy` subcommand — inspect named policy presets.
//!
//! `oaie policy list` shows all available presets with one-line descriptions.
//! `oaie policy show <name>` prints a preset's full configuration as TOML.

use clap::Subcommand;

use oaie_core::error::{OaieError, Result};
use oaie_core::policy::Policy;

/// Inspect named policy presets.
#[derive(Subcommand, Debug)]
pub enum PolicyCmd {
    /// List all available named policy presets
    List,

    /// Show a preset's full configuration as TOML
    Show {
        /// Preset name (e.g. "agent-safe", "net")
        name: String,
    },
}

impl PolicyCmd {
    pub fn execute(&self) -> Result<()> {
        match self {
            Self::List => {
                println!("Available policy presets:\n");
                for (name, description) in Policy::list_presets() {
                    println!("  {name:<16}{description}");
                }
                println!();
                println!("Usage: oaie run --policy=<name> -- <command>");
                Ok(())
            }
            Self::Show { name } => {
                let policy = Policy::from_name(name).ok_or_else(|| {
                    OaieError::InvalidJobSpec(format!(
                        "unknown policy preset: {name}\nRun 'oaie policy list' to see available presets"
                    ))
                })?;
                let toml_str = policy.to_toml_string()?;
                print!("{toml_str}");
                Ok(())
            }
        }
    }
}
