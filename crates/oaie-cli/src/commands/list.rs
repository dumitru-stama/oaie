//! The `oaie list` subcommand — tabular listing of past runs.
//!
//! Shows run ID (short), status, exit code, duration, and command.
//! Supports `--limit`, `--all`, `--json`, and `--grep` flags.

use clap::Args;

use oaie_cas::store::format_duration;
use oaie_db::OaieDb;

use oaie_core::error::Result;

use super::load_store;
use crate::output;

/// List past runs with their status and metadata.
#[derive(Args, Debug)]
pub struct ListCmd {
    /// Maximum number of runs to show (default 20).
    #[arg(short, long, default_value_t = 20)]
    pub limit: usize,

    /// Show all runs (ignores --limit).
    #[arg(long)]
    pub all: bool,

    /// Output as JSON array for scripting.
    #[arg(long)]
    pub json: bool,

    /// Filter runs whose command contains this substring (case-insensitive).
    #[arg(short, long)]
    pub search: Option<String>,
}

/// Collapse a command string to a single line, truncating at `max_len` with "…".
/// Replaces newlines and runs of whitespace with a single space.
fn truncate_command(cmd: &str, max_len: usize) -> String {
    // Collapse all whitespace (including newlines) into single spaces.
    let oneline: String = cmd.split_whitespace().collect::<Vec<_>>().join(" ");
    if oneline.len() <= max_len {
        oneline
    } else {
        // Cut at max_len - 1 to leave room for the ellipsis character.
        let mut end = max_len - 1;
        // Avoid splitting a multi-byte character.
        while end > 0 && !oneline.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}\u{2026}", &oneline[..end])
    }
}

impl ListCmd {
    pub fn execute(&self) -> Result<()> {
        let store = load_store()?;
        let db = OaieDb::open(&store.db_path)?;

        let mut runs = if self.all {
            db.list_all_runs()?
        } else {
            db.list_runs(self.limit)?
        };

        // Apply search filter if specified (case-insensitive substring match).
        if let Some(ref pattern) = self.search {
            let pattern_lower = pattern.to_lowercase();
            runs.retain(|r| {
                let cmd = output::shell_join(&r.command).to_lowercase();
                cmd.contains(&pattern_lower)
            });
        }

        if self.json {
            self.print_json(&runs)?;
        } else {
            self.print_table(&runs);
        }

        Ok(())
    }

    /// Print runs as a JSON array to stdout.
    fn print_json(&self, runs: &[oaie_db::RunRecord]) -> Result<()> {
        let entries: Vec<serde_json::Value> = runs
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.run_id.full(),
                    "status": r.status.as_str(),
                    "exit_code": r.exit_code,
                    "duration_ms": r.duration_ms,
                    "command": r.command,
                    "created": r.created.to_rfc3339(),
                    "isolation": r.isolation,
                })
            })
            .collect();
        let json = serde_json::to_string_pretty(&entries)
            .map_err(|e| oaie_core::error::OaieError::Other(format!("JSON serialization failed: {e}")))?;
        println!("{json}");
        Ok(())
    }

    /// Print runs as an aligned table to stdout.
    fn print_table(&self, runs: &[oaie_db::RunRecord]) {
        if runs.is_empty() {
            output::info("no runs found");
            return;
        }

        output::header("Runs");
        println!(
            "  {:<10}{:<12}{:<6}{:<12}Command",
            "ID", "Status", "Exit", "Duration"
        );

        for r in runs {
            let id = r.run_id.short();
            let status = r.status.as_str();

            let exit = match r.exit_code {
                Some(code) => code.to_string(),
                None => "\u{2014}".into(), // em dash
            };

            let duration = match r.duration_ms {
                Some(ms) => format_duration(ms.max(0) as u64),
                None => "\u{2014}".into(),
            };

            let cmd = truncate_command(&output::shell_join(&r.command), 60);

            println!("  {:<10}{:<12}{:<6}{:<12}{}", id, status, exit, duration, cmd);
        }
    }
}
