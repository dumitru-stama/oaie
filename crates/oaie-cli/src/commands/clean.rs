//! The `oaie clean` subcommand — prune old runs and remove unreferenced blobs.

use clap::Args;

use oaie_core::error::Result;

use super::load_store;
use crate::output;
use oaie_cli::clean::{clean, humanize_bytes, parse_duration};

/// Remove old runs and unreferenced blobs from the store.
#[derive(Args, Debug)]
pub struct CleanCmd {
    /// Delete runs older than this threshold.
    /// Format: "7d", "12h", "30m". Omit to only sweep orphaned blobs.
    #[arg(long)]
    pub older_than: Option<String>,

    /// Minimum age before an orphaned blob can be removed.
    /// Format: "7d", "12h", "30m". Default: "7d".
    #[arg(long, default_value = "7d")]
    pub min_age: String,

    /// Show what would be removed without removing anything.
    #[arg(long)]
    pub dry_run: bool,

    /// Automatic cleanup: remove runs older than 7 days.
    #[arg(long)]
    pub auto: bool,
}

impl CleanCmd {
    pub fn execute(&self) -> Result<()> {
        let store = load_store()?;
        let min_age = parse_duration(&self.min_age)?;
        // --auto defaults to "7d" if --older-than is not specified.
        let older_than_str = if self.auto && self.older_than.is_none() {
            Some("7d")
        } else {
            self.older_than.as_deref()
        };
        let older_than = older_than_str.map(parse_duration).transpose()?;

        println!();
        if self.dry_run {
            output::info("clean dry run");
        } else {
            output::info("cleaning store");
        }
        println!();

        let result = clean(&store, older_than, min_age, self.dry_run)?;

        // Prune summary.
        if let Some(ref prune) = result.prune {
            output::header("Runs");
            if self.dry_run {
                println!("  Would delete: {} runs", prune.runs_deleted);
            } else {
                println!("  Deleted:  {} runs", prune.runs_deleted);
            }
            println!("  Retained: {} runs", prune.runs_retained);
            println!();
        }

        // Sweep summary.
        output::header("Blobs");
        println!("  Scanned:  {} blobs", result.sweep.blobs_scanned);
        println!("  Retained: {} blobs", result.sweep.blobs_retained);
        if self.dry_run {
            println!(
                "  Would remove: {} blobs ({})",
                result.sweep.blobs_removed,
                humanize_bytes(result.sweep.bytes_freed)
            );
        } else {
            println!(
                "  Removed:  {} blobs ({})",
                result.sweep.blobs_removed,
                humanize_bytes(result.sweep.bytes_freed)
            );
        }
        println!();

        Ok(())
    }
}
