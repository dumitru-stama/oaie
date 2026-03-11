//! The `oaie doctor` subcommand — CLI entry point for structured diagnostics.
//!
//! Types and probe logic live in `oaie_cli::doctor` (the library module) so
//! integration tests can call `run_doctor()` directly. This module handles
//! only the CLI command and formatted output.

use clap::Args;

use oaie_core::config::OaieStore;

use oaie_core::error::Result;

use crate::output;

// Re-export the library types so `commands::doctor::*` still works in main.rs.
pub use oaie_cli::doctor::{
    run_doctor, DoctorReport, OverallStatus, Probe, ProbeStatus,
};

/// Check system requirements and OAIE installation health.
#[derive(Args, Debug)]
pub struct DoctorCmd {}

impl DoctorCmd {
    /// Run all probes and print a formatted diagnostic report.
    pub fn execute(&self) -> Result<()> {
        let store = OaieStore::from_env().ok().filter(|s| s.is_initialized());

        let report = run_doctor(store.as_ref());
        print_report(&report);

        if report.overall == OverallStatus::Broken {
            std::process::exit(1);
        }

        Ok(())
    }
}

/// Width of the left panel (ASCII logo + tagline + version).
const LEFT_WIDTH: usize = 35;

/// The ASCII art logo lines and left-panel text, returned as a Vec of strings.
/// Each string is padded/truncated to exactly `LEFT_WIDTH` characters.
fn left_panel(report: &DoctorReport) -> Vec<String> {
    let mut lines: Vec<String> = Vec::with_capacity(12);

    // ASCII art logo.
    lines.push(r#"  ___    _    ___ _____"#.into());
    lines.push(r#" / _ \  / \  |_ _| ____|"#.into());
    lines.push(r#"| | | |/ _ \  | ||  _|"#.into());
    lines.push(r#"| |_| / ___ \ | || |___"#.into());
    lines.push(r#" \___/_/   \_\___|_____|"#.into());
    lines.push(" https://oaie.run".into());
    lines.push(String::new());
    lines.push(" Observed & Attested".into());
    lines.push(" Isolated Execution".into());
    lines.push(format!(" v{}", report.version));

    // Pad each line to LEFT_WIDTH.
    for line in &mut lines {
        if line.len() < LEFT_WIDTH {
            line.push_str(&" ".repeat(LEFT_WIDTH - line.len()));
        }
    }
    lines
}

/// Format a single probe line for the right panel, with color.
fn format_probe(probe: &Probe) -> String {
    let (icon, colorize): (&str, fn(&str) -> String) = match probe.status {
        ProbeStatus::Available => ("\u{2713}", output::green),      // ✓ green
        ProbeStatus::Advisory => ("\u{26A0}", output::yellow),      // ⚠ yellow
        ProbeStatus::NotAvailable => ("\u{2013}", output::yellow),  // – yellow
        ProbeStatus::Broken => ("\u{2717}", output::red),           // ✗ red
    };

    let status_str = match probe.status {
        ProbeStatus::Available => "available",
        ProbeStatus::Advisory => "note",
        ProbeStatus::NotAvailable => "not available",
        ProbeStatus::Broken => "BROKEN",
    };

    let colored_icon = colorize(icon);
    let colored_status = colorize(status_str);

    if let Some(ref detail) = probe.detail {
        format!("{colored_icon} {:<22} {colored_status}  ({detail})", probe.name)
    } else {
        format!("{colored_icon} {:<22} {colored_status}", probe.name)
    }
}

/// Print the doctor report in split-screen layout:
/// left panel = ASCII logo + tagline, right panel = diagnostics.
fn print_report(report: &DoctorReport) {
    if output::is_quiet() {
        return;
    }

    let left = left_panel(report);
    let left_pad: String = std::iter::repeat_n(' ', LEFT_WIDTH).collect();

    // Build right-panel lines.
    let mut right: Vec<String> = Vec::new();

    for probe in &report.probes {
        right.push(format_probe(probe));

        if let Some(ref remediation) = probe.remediation {
            if probe.status == ProbeStatus::Advisory || probe.status == ProbeStatus::Broken {
                let colorize: fn(&str) -> String = if probe.status == ProbeStatus::Broken {
                    output::red
                } else {
                    output::yellow
                };
                for line in remediation.lines() {
                    right.push(format!("  {}", colorize(line)));
                }
            }
        }
    }

    right.push(String::new());
    right.push(format!("Isolation:      {}", report.isolation_level));
    right.push(format!(
        "Trace backends: {}",
        if report.trace_backends.is_empty() {
            "none".into()
        } else {
            report.trace_backends.join(", ")
        }
    ));

    if let Some(ref s) = report.storage {
        let span = if s.span_days == 0 {
            "today".to_string()
        } else {
            format!("{} days", s.span_days)
        };
        right.push(format!(
            "Storage:        {} runs over {}, {}",
            s.run_count,
            span,
            oaie_cas::store::format_bytes(s.store_bytes),
        ));
    }

    // Print both panels side by side.
    let max_lines = std::cmp::max(left.len(), right.len());
    println!();
    for i in 0..max_lines {
        let l = if i < left.len() { &left[i] } else { &left_pad };
        let r = if i < right.len() {
            right[i].as_str()
        } else {
            ""
        };
        println!("{l} {r}");
    }

    // Separator and overall status — printed at column 0.
    // Strip ANSI escapes when measuring line widths so colors don't inflate the count.
    let max_right = right.iter()
        .map(|l| strip_ansi_len(l))
        .max()
        .unwrap_or(60);
    let separator_width = (LEFT_WIDTH + 1 + max_right).min(100);
    let separator = output::grey(&"\u{2500}".repeat(separator_width));
    println!("{separator}");
    let overall_str = match report.overall {
        OverallStatus::Ready | OverallStatus::Advisory => {
            output::green("Sandboxing active and working, tracing off by default")
        }
        OverallStatus::Broken => {
            output::red("BROKEN — sandboxing unavailable")
        }
    };
    println!("{overall_str}");
    println!();

    // Status message on stderr.
    if report.overall == OverallStatus::Broken {
        output::error("System cannot run sandboxed execution. Fix broken probes above.");
    }
}

/// Visible length of a string after stripping ANSI escape sequences.
fn strip_ansi_len(s: &str) -> usize {
    let mut len = 0;
    let mut in_escape = false;
    for c in s.chars() {
        if in_escape {
            if c == 'm' {
                in_escape = false;
            }
        } else if c == '\x1b' {
            in_escape = true;
        } else {
            len += 1;
        }
    }
    len
}
