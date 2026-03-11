//! The `oaie verify` subcommand — verify a run's artifact integrity and hash chain.
//!
//! Checks every artifact the manifest claims to exist, verifies CAS hashes,
//! and validates the tamper-evident event chain if tracing was enabled.

use clap::{Args, ValueEnum};
use serde::Serialize;

use oaie_core::error::{OaieError, Result};
use oaie_core::verify::CheckStatus;
use oaie_db::OaieDb;

use super::load_store;
use crate::output;

// verify_run lives in the oaie_cli library crate.
use oaie_cli::verify::verify_run;

/// Verify the integrity of a run's artifacts against their manifest.
#[derive(Args, Debug)]
pub struct VerifyCmd {
    /// Run ID, short prefix, or "last". Required unless --all is used.
    #[arg(required_unless_present = "all")]
    pub run_id: Option<String>,

    /// Verify ALL runs in the store.
    #[arg(long)]
    pub all: bool,

    /// Output format: text (human-readable) or json (machine-readable).
    #[arg(long, default_value = "text")]
    pub format: VerifyFormat,

    /// Exit with non-zero status if any check fails (for CI/scripting).
    #[arg(long)]
    pub strict: bool,
}

/// Output format for verify results.
#[derive(Clone, Debug, ValueEnum)]
pub enum VerifyFormat {
    Text,
    Json,
}

impl VerifyCmd {
    /// Run verification for a single run or all runs.
    pub fn execute(&self) -> Result<()> {
        let store = load_store()?;

        if self.all {
            return self.execute_all(&store);
        }

        let db = OaieDb::open(&store.db_path)?;
        let run_id_str = self.run_id.as_deref().unwrap_or("last");

        let run = if run_id_str == "last" {
            db.get_latest_run()?
                .ok_or_else(|| OaieError::Other("no runs found".into()))?
        } else {
            db.get_run_by_prefix(run_id_str)?
        };

        let report = verify_run(&store, &run.run_id)?;

        match self.format {
            VerifyFormat::Text => print_verify_text(&report),
            VerifyFormat::Json => print_verify_json(&report)?,
        }

        if self.strict && !report.passed() {
            std::process::exit(1);
        }

        Ok(())
    }

    /// Verify all runs in the store.
    fn execute_all(&self, store: &oaie_core::config::OaieStore) -> Result<()> {
        let db = OaieDb::open(&store.db_path)?;
        let runs = db.list_all_runs()?;

        if runs.is_empty() {
            output::info("no runs found");
            return Ok(());
        }

        println!();
        output::info(&format!("verifying {} runs", runs.len()));
        println!();

        let mut total_pass = 0;
        let mut total_fail = 0;

        for run_meta in &runs {
            let report = verify_run(store, &run_meta.run_id)?;
            if report.passed() {
                total_pass += 1;
                println!(
                    "  {} {} -- {}",
                    pass_icon(),
                    run_meta.run_id.short(),
                    report.summary()
                );
            } else {
                total_fail += 1;
                println!(
                    "  {} {} -- {}",
                    fail_icon(),
                    run_meta.run_id.short(),
                    report.summary()
                );
            }
        }

        println!();
        output::info(&format!(
            "{total_pass} passed, {total_fail} failed out of {} runs",
            runs.len()
        ));
        println!();

        if self.strict && total_fail > 0 {
            std::process::exit(1);
        }

        Ok(())
    }
}

/// Print verify report in human-readable text.
fn print_verify_text(report: &oaie_core::verify::VerifyReport) {
    println!();
    output::info(&format!("verify {}", report.run_id.short()));
    println!();

    for check in &report.checks {
        let icon = match check.status {
            CheckStatus::Pass => pass_icon(),
            CheckStatus::Fail => fail_icon(),
            CheckStatus::Skip => skip_icon(),
        };
        match &check.detail {
            Some(d) => println!("  {} {} -- {}", icon, check.check.display_name(), d),
            None => println!("  {} {}", icon, check.check.display_name()),
        }
    }

    println!();
    if report.passed() {
        output::info(&format!("verify passed ({})", report.summary()));
    } else {
        output::info(&format!("verify FAILED ({})", report.summary()));
    }
    println!();
}

/// Print verify report as JSON.
fn print_verify_json(report: &oaie_core::verify::VerifyReport) -> Result<()> {
    #[derive(Serialize)]
    struct JsonReport {
        run_id: String,
        passed: bool,
        summary: String,
        checks: Vec<JsonCheck>,
    }

    #[derive(Serialize)]
    struct JsonCheck {
        check: String,
        status: String,
        detail: Option<String>,
    }

    let json = JsonReport {
        run_id: report.run_id.full(),
        passed: report.passed(),
        summary: report.summary(),
        checks: report
            .checks
            .iter()
            .map(|c| JsonCheck {
                check: format!("{:?}", c.check),
                status: format!("{:?}", c.status),
                detail: c.detail.clone(),
            })
            .collect(),
    };

    let output = serde_json::to_string_pretty(&json)
        .map_err(|e| OaieError::Io(std::io::Error::other(e)))?;
    println!("{output}");
    Ok(())
}

fn pass_icon() -> &'static str {
    if std::env::var_os("NO_COLOR").is_some() {
        "[PASS]"
    } else {
        "\u{2713}" // checkmark
    }
}

fn fail_icon() -> &'static str {
    if std::env::var_os("NO_COLOR").is_some() {
        "[FAIL]"
    } else {
        "\u{2717}" // cross mark
    }
}

fn skip_icon() -> &'static str {
    if std::env::var_os("NO_COLOR").is_some() {
        "[SKIP]"
    } else {
        "\u{2013}" // en dash
    }
}
