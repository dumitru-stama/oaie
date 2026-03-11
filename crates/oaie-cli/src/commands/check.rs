//! The `oaie check` subcommand — pre-flight validation of a job spec against a policy.
//!
//! Validates that a job can run successfully under the given policy before
//! actually executing it. Reports clear pass/fail with specific issues.

use std::path::PathBuf;

use clap::Args;

use oaie_core::job::JobSpec;
use oaie_core::policy::{self, Policy};

use oaie_core::error::{OaieError, Result};

use crate::output;

/// Validate a job spec against a policy without running it.
#[derive(Args, Debug)]
pub struct CheckCmd {
    /// Job spec file (TOML) to validate.
    pub spec: PathBuf,

    /// Policy file to check against (default: safe preset).
    #[arg(long)]
    pub policy: Option<PathBuf>,
}

impl CheckCmd {
    /// Run pre-flight checks and report issues.
    pub fn execute(&self) -> Result<()> {
        // Load job spec.
        let job = JobSpec::from_toml_file(&self.spec)?;

        // Load policy.
        let pol = if let Some(ref policy_path) = self.policy {
            Policy::from_file(policy_path)?
        } else {
            Policy::preset_safe()
        };

        let policy_name = pol.name.as_deref().unwrap_or("(unnamed)");
        output::info(&format!(
            "Checking {} against policy '{}'",
            self.spec.display(),
            policy_name,
        ));

        let mut issues: Vec<String> = Vec::new();

        // Check 1: Network access.
        if job.network && !pol.defaults.network.has_connectivity() {
            issues.push(
                "job requests network access but policy denies it".into(),
            );
        }

        // Check 2: Timeout vs policy max_time.
        if let Some(ref timeout) = job.timeout {
            let max_time = policy::parse_duration_policy(&pol.limits.max_time)?;
            if *timeout > max_time {
                issues.push(format!(
                    "job timeout ({:.0}s) exceeds policy max_time ({})",
                    timeout.as_secs_f64(),
                    pol.limits.max_time,
                ));
            }
        }

        // Check 3: Command exists (best-effort via which).
        if let Some(cmd) = job.command.first() {
            if !cmd.contains('/') {
                // Not an absolute path — check PATH.
                let found = std::env::var("PATH")
                    .unwrap_or_default()
                    .split(':')
                    .any(|dir| {
                        let p = std::path::Path::new(dir).join(cmd);
                        p.exists() && p.is_file()
                    });
                if !found {
                    issues.push(format!("command '{cmd}' not found in PATH"));
                }
            } else if !std::path::Path::new(cmd).exists() {
                issues.push(format!("command '{}' does not exist", cmd));
            }
        }

        // Check 4: Input path exists.
        if let Some(ref input) = job.inputs {
            if !input.exists() {
                issues.push(format!(
                    "input path does not exist: {}",
                    input.display()
                ));
            }
        }

        // Report results.
        if issues.is_empty() {
            output::info("All checks passed.");
            Ok(())
        } else {
            for (i, issue) in issues.iter().enumerate() {
                output::warn(&format!("[{}] {}", i + 1, issue));
            }
            Err(OaieError::Other(format!(
                "{} issue(s) found — job may fail under this policy",
                issues.len()
            )))
        }
    }
}
