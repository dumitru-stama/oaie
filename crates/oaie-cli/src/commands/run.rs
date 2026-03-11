//! The `oaie run` subcommand — execute a tool in an isolated, observed environment.
//!
//! Builds a `JobSpec` from either a TOML spec file (`--spec`) or CLI flags,
//! resolves the policy (from file, preset, or defaults), and delegates to the
//! Runner engine for sandboxed execution, artifact collection, and manifest generation.

use std::path::PathBuf;
use std::str::FromStr;

use clap::{Args, ValueEnum};

use oaie_cas::store::{format_bytes, format_duration};
use oaie_cli::policy_resolve::{self, PolicyInput};
use oaie_cli::runner::{Runner, RunResult};
use oaie_core::backend::BackendKind;
use oaie_core::job::{self, JobSpec, TraceMode};
use oaie_core::manifest::IsolationLevel;

use oaie_core::error::{OaieError, Result};
use oaie_core::policy::{format_duration_human, format_size_human, NetworkMode};

/// Output format for `oaie run`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable summary (default).
    Human,
    /// Machine-readable JSON (StructuredRunResult).
    Json,
}

use super::load_store;
use crate::output;

/// Execute a command in an isolated, observed environment.
#[derive(Args, Debug)]
pub struct RunCmd {
    /// Job spec file (TOML)
    #[arg(long)]
    pub spec: Option<PathBuf>,

    /// Input directory (default: current directory, mounted read-only)
    #[arg(long = "in")]
    pub input: Option<PathBuf>,

    /// Output directory (default: ./oaie-out/<run_id>)
    #[arg(long, short = 'o')]
    pub out: Option<PathBuf>,

    /// Additional read-only mount
    #[arg(long)]
    pub ro: Vec<PathBuf>,

    /// Additional read-write mount
    #[arg(long)]
    pub rw: Vec<PathBuf>,

    /// Network mode: on, off, allow:host:port, preset:name (default: off)
    ///
    /// Without a value, `--net` enables full network access (backward compat).
    /// Explicit forms: `--net=off`, `--net=on`,
    /// `--net=allow:api.anthropic.com:443`,
    /// `--net=allow:host1:443,host2:443`,
    /// `--net=preset:anthropic`.
    #[arg(long, value_name = "MODE", num_args = 0..=1, default_missing_value = "on")]
    pub net: Option<String>,

    /// Trace mode: auto, strace, ptrace, ebpf, off
    #[arg(long, default_value = "off")]
    pub trace: String,

    /// Disable syscall tracing entirely
    #[arg(long)]
    pub notrace: bool,

    /// Timeout for the run (e.g. "30s", "5m")
    #[arg(long)]
    pub timeout: Option<String>,

    /// Path to a TOML policy file constraining resource limits and mount rules.
    #[arg(long)]
    pub policy: Option<PathBuf>,

    /// Skip namespace isolation (run without sandboxing)
    #[arg(long)]
    pub no_isolation: bool,

    /// Disable automatic file path detection and mounting
    #[arg(long)]
    pub no_auto_mount: bool,

    /// Suppress tool output (only show OAIE summary)
    #[arg(long, short = 'q')]
    pub quiet: bool,

    /// Cgroup isolation mode: auto (use if available), require (fail if unavailable), off
    #[arg(long, default_value = "auto")]
    pub cgroup: String,

    /// Execution backend: namespace (default), bare, firecracker
    #[arg(long, default_value = "namespace")]
    pub backend: String,

    /// Interactive mode: allocate a PTY for terminal app support (vim, htop, less)
    #[arg(short = 'i', long)]
    pub interactive: bool,

    /// Sign the manifest with a signing key (key ID prefix or label).
    /// If omitted, uses default_key from config.toml [signing] section (if set).
    #[arg(long)]
    pub sign: Option<String>,

    /// Verbosity: -v shows policy summary, -vv shows full sandbox spec.
    #[arg(long, short = 'v', action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Output format: human (default) or json (machine-readable structured output)
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub output: OutputFormat,

    /// Command to run (after --)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

impl RunCmd {
    /// Build a JobSpec, resolve policy, run the command, and print the summary.
    pub fn execute(&self) -> Result<i32> {
        let json_output = self.output == OutputFormat::Json;

        let store = load_store()?;
        let store_path = store.root.display().to_string();

        // Build JobSpec from --spec file or CLI args.
        let job = self.build_job_spec()?;

        // Parse --net flag into NetworkMode (if specified).
        let net_mode = match &self.net {
            Some(val) => Some(oaie_core::policy::parse_net_flag(val)?),
            None => None,
        };

        // Resolve policy: merge policy file + CLI flags + auto-mount detection.
        let policy_input = PolicyInput {
            policy_path: self.policy.as_ref(),
            net: net_mode.clone(),
            timeout: self.timeout.as_deref(),
            ro: &self.ro,
            rw: &self.rw,
            no_auto_mount: self.no_auto_mount,
            command: &self.command,
            input: self.input.as_ref(),
            out: self.out.as_ref(),
            store_default_timeout: Some(&store.timeouts.default_timeout),
            store_max_timeout: Some(&store.timeouts.max_timeout),
            cgroup: &self.cgroup,
        };
        let resolved = policy_resolve::resolve_policy(&policy_input)?;

        // Validate interactive mode incompatibilities.
        // Use job.interactive (not self.interactive) so validation also applies
        // when interactive mode is set via --spec TOML/JSON, not just the -i flag.
        if job.interactive {
            if self.quiet {
                return Err(OaieError::InvalidJobSpec(
                    "interactive mode (-i) is incompatible with --quiet".into(),
                ));
            }
            if json_output {
                return Err(OaieError::InvalidJobSpec(
                    "interactive mode (-i) is incompatible with --output=json".into(),
                ));
            }
            if job.backend == BackendKind::Bare {
                return Err(OaieError::InvalidJobSpec(
                    "interactive mode (-i) requires namespace backend (not --backend=bare)".into(),
                ));
            }
            if job.backend == BackendKind::Firecracker {
                return Err(OaieError::InvalidJobSpec(
                    "interactive mode (-i) is not supported with --backend=firecracker".into(),
                ));
            }
            if job.no_isolation {
                return Err(OaieError::InvalidJobSpec(
                    "interactive mode (-i) requires namespace isolation (not --no-isolation)".into(),
                ));
            }
            if self.trace == "ebpf" {
                return Err(OaieError::InvalidJobSpec(
                    "interactive mode (-i) is not yet supported with --trace=ebpf".into(),
                ));
            }
        }

        // In JSON mode, suppress all OAIE chrome — only JSON goes to stdout.
        let effective_quiet = self.quiet || json_output;

        if !effective_quiet && self.no_isolation {
            output::warn("Running without namespace isolation (--no-isolation)");
        }

        let policy_label = resolved.name.as_deref().unwrap_or("custom");
        if !effective_quiet {
            output::info(&format!(
                "Running: {} (policy: {})",
                output::shell_join(&job.command),
                policy_label,
            ));
        }

        if self.verbose >= 1 && !effective_quiet {
            self.print_resource_summary(&job, &resolved);
            output::separator();
        }
        if self.verbose >= 2 && !effective_quiet {
            // Sandbox spec is only meaningful when namespace isolation is active.
            if job.no_isolation || job.backend == BackendKind::Bare {
                output::warn("-vv: sandbox spec not shown (no namespace isolation)");
            } else {
                self.print_sandbox_spec(&resolved);
            }
            output::separator();
        }

        // Resolve signing key: explicit --sign flag, or default_key from store config.
        let sign_key: Option<String> = self.sign.clone().or_else(|| {
            store.signing.as_ref().and_then(|s| s.default_key.clone())
        });

        let runner = Runner::new(store)?;
        let result = runner.execute(&job, &resolved, effective_quiet, sign_key.as_deref())?;

        if json_output {
            let structured = result.to_structured(&job.backend, &store_path);
            serde_json::to_writer_pretty(std::io::stdout(), &structured)
                .map_err(|e| OaieError::Io(std::io::Error::other(e)))?;
            println!();
        } else {
            self.print_human_summary(&result, policy_label);
        }

        Ok(result.exit_code)
    }

    /// Build a JobSpec from `--spec` file or CLI arguments.
    fn build_job_spec(&self) -> Result<JobSpec> {
        if let Some(ref spec_path) = self.spec {
            let spec_str = spec_path.to_string_lossy();
            if spec_str == "-" {
                // Read from stdin, auto-detect JSON vs TOML.
                return JobSpec::from_stdin();
            }
            JobSpec::from_toml_file(spec_path)
        } else if !self.command.is_empty() {
            let timeout = match &self.timeout {
                Some(t) => Some(job::parse_timeout(t)?),
                None => None,
            };
            let trace = if self.notrace {
                TraceMode::Off
            } else {
                TraceMode::from_str(&self.trace)?
            };

            let backend = BackendKind::from_str(&self.backend)?;
            let no_isolation = self.no_isolation || backend == BackendKind::Bare;

            Ok(JobSpec {
                command: self.command.clone(),
                inputs: self.input.clone(),
                outputs: self.out.clone(),
                network: self.net.as_deref().is_some_and(|v| v != "off" && v != "false"),
                trace,
                timeout,
                policy: self.policy.clone(),
                extra_ro: self.ro.clone(),
                extra_rw: self.rw.clone(),
                no_isolation,
                backend,
                interactive: self.interactive,
            })
        } else {
            Err(OaieError::InvalidJobSpec(
                "specify a command (-- cmd) or a job spec (--spec file.toml)".into(),
            ))
        }
    }

    /// Print resource restrictions before execution starts (for `--verbose`).
    ///
    /// Shows isolation level, backend, network mode, trace mode, cgroup mode,
    /// resource limits, filesystem mounts, and network allowlist rules.
    fn print_resource_summary(&self, job: &JobSpec, resolved: &policy_resolve::ResolvedPolicy) {
        // --- Isolation & modes ---
        output::header("Resource Restrictions");

        let isolation = if job.no_isolation {
            "None (no sandbox)"
        } else {
            match job.backend {
                BackendKind::Namespace => "Full (namespace)",
                BackendKind::Bare => "None (bare)",
                BackendKind::Firecracker => "Full (Firecracker microVM)",
            }
        };
        output::field("Isolation", isolation);
        output::field("Backend", &format!("{}", job.backend));
        output::field(
            "Network",
            match &resolved.network {
                NetworkMode::Off => "off",
                NetworkMode::On => "on",
                NetworkMode::Allowlist(_) => "allowlist",
            },
        );
        output::field("Trace", &format!("{}", job.trace));
        output::field("Cgroup", &resolved.cgroup_mode.to_string());

        // --- Resource limits ---
        output::header("Limits");
        output::field("Memory", &format_size_human(resolved.max_memory));
        let wall_time = resolved.timeout.unwrap_or(resolved.max_time);
        output::field("Wall time", &format_duration_human(wall_time));
        output::field("Max PIDs", &resolved.max_pids.to_string());
        output::field("File size", &format_size_human(resolved.max_fsize));
        output::field("memfd", if resolved.allow_memfd { "yes" } else { "no" });

        // Decode capability bitmask into human-readable names.
        let caps = if resolved.retain_caps == 0 {
            "none".to_string()
        } else {
            let mut names = Vec::new();
            if resolved.retain_caps & (1 << 10) != 0 {
                names.push("net_bind_service");
            }
            if resolved.retain_caps & (1 << 13) != 0 {
                names.push("net_raw");
            }
            names.join(", ")
        };
        output::field("Caps", &caps);

        if let Some((quota, period)) = resolved.cpu_quota {
            let pct = quota * 100 / period;
            output::field("CPU quota", &format!("{pct}%"));
        }

        // --- Filesystem ---
        output::header("Filesystem");
        output::field(
            "Input",
            &format!("{} (read-only)", resolved.input_dir.display()),
        );
        if let Some(ref out) = resolved.output_dir {
            output::field("Output", &format!("{} (read-write)", out.display()));
        } else {
            output::field("Output", "<auto> (read-write)");
        }

        for p in &resolved.ro_mounts {
            output::field("RO", &p.display().to_string());
        }
        for p in &resolved.rw_mounts {
            output::field("RW", &p.display().to_string());
        }

        // Auto-mounted paths (from executable/argument detection).
        for entry in &resolved.auto_mounts {
            let mode_label = entry.mode.to_uppercase();
            output::field(
                &format!("Auto ({mode_label})"),
                &format!("{} (from: {})", entry.mount_dir.display(), entry.source),
            );
        }

        // Denied paths.
        if !resolved.deny_paths.is_empty() {
            let denied: Vec<String> = resolved
                .deny_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect();
            output::field("Denied", &denied.join(", "));
        }

        // --- Network rules (only for allowlist mode) ---
        if let NetworkMode::Allowlist(ref rules) = resolved.network {
            output::header("Network Rules");
            for rule in rules {
                let target = rule
                    .host
                    .as_deref()
                    .or(rule.cidr.as_deref())
                    .unwrap_or("?");
                output::field(
                    "Allow",
                    &format!("{}:{}/{}", target, rule.port, rule.protocol),
                );
            }
        }
    }

    /// Print full sandbox specification (`-vv`).
    ///
    /// Shows all hardcoded sandbox internals — seccomp rules, /proc masking,
    /// env blocklist, rlimits, mounts, namespaces, capabilities — directly
    /// from the same constants used at runtime (single source of truth).
    fn print_sandbox_spec(&self, resolved: &policy_resolve::ResolvedPolicy) {
        use oaie_sandbox::mounts;
        use oaie_sandbox::sandbox;
        use oaie_sandbox::seccomp;

        // --- Seccomp: KILL tier ---
        let kill = seccomp::kill_tier_named();
        output::header(&format!("Seccomp: KILL ({} syscalls)", kill.len()));
        let names: Vec<&str> = kill.iter().map(|(n, _)| *n).collect();
        output::field("Syscalls", &names.join(", "));

        // --- Seccomp: ERRNO tier ---
        let errno = seccomp::errno_tier_named(resolved.allow_memfd);
        output::header(&format!("Seccomp: ERRNO ({} syscalls)", errno.len()));
        let names: Vec<&str> = errno.iter().map(|(n, _)| *n).collect();
        output::field("Syscalls", &names.join(", "));

        // --- Seccomp: Arg Inspection ---
        output::header("Seccomp: Arg Inspection");
        // socket() blocked AFs
        let af_list: Vec<String> = seccomp::BLOCKED_SOCKET_AFS
            .iter()
            .map(|&af| format!("{} ({})", seccomp::af_name(af), af))
            .collect();
        output::field(
            "socket()",
            &format!("{} blocked AFs: {}", seccomp::BLOCKED_SOCKET_AFS.len(), af_list.join(", ")),
        );
        // prctl() blocked ops
        let prctl_list: Vec<String> = seccomp::BLOCKED_PRCTL_OPS
            .iter()
            .map(|&op| format!("{} ({})", seccomp::prctl_op_name(op), op))
            .collect();
        output::field(
            "prctl()",
            &format!("{} blocked ops: {}", seccomp::BLOCKED_PRCTL_OPS.len(), prctl_list.join(", ")),
        );
        // ioctl() blocked cmds
        let ioctl_list: Vec<String> = seccomp::BLOCKED_IOCTL_CMDS
            .iter()
            .map(|&cmd| format!("{} ({:#06x})", seccomp::ioctl_cmd_name(cmd), cmd))
            .collect();
        output::field(
            "ioctl()",
            &format!("{} blocked cmds: {}", seccomp::BLOCKED_IOCTL_CMDS.len(), ioctl_list.join(", ")),
        );
        // clone() namespace flags
        output::field(
            "clone()",
            &format!("namespace flags blocked (CLONE_NEW_MASK: {:#010x})", seccomp::CLONE_NEW_MASK),
        );

        // --- Rlimits ---
        output::header("Rlimits (soft / hard)");
        output::field("NOFILE", "1024 / 4096");
        output::field("MEMLOCK", "64M / 64M");
        output::field("CORE", "0 / 0");

        // Policy-driven rlimits
        let nproc_soft = resolved.max_pids;
        let nproc_hard = (nproc_soft as u64).saturating_mul(2);
        output::field(
            "NPROC",
            &format!("{nproc_soft} / {nproc_hard}  (from policy)"),
        );
        output::field(
            "FSIZE",
            &format!("{} / {}  (from policy)", format_size_human(resolved.max_fsize), format_size_human(resolved.max_fsize)),
        );
        output::field(
            "AS",
            &format!(
                "{} / {}  (from policy)",
                format_size_human(resolved.max_memory),
                format_size_human(resolved.max_memory.saturating_mul(2)),
            ),
        );
        output::field("MSGQUEUE", "0 / 0");

        // CPU time: 2x wall-clock timeout, min 60s
        let wall_time = resolved.timeout.unwrap_or(resolved.max_time);
        let cpu_secs = (wall_time.as_secs().saturating_mul(2)).max(60);
        output::field("CPU", &format!("{cpu_secs}s / {cpu_secs}s"));
        output::field("STACK", "8M / 16M");

        // --- Mounts ---
        output::header("Mounts");
        output::field("/", "tmpfs (64m, RO after pivot)");
        output::field("/in", "bind RO (nodev, nosuid, noexec)");
        output::field("/out", "bind RW (nodev, nosuid, noexec)");
        output::field("/tmp", "tmpfs (64m, nosuid, nodev, noexec)");
        output::field("/root", "tmpfs (16m, nosuid, nodev, noexec)");
        for dir in mounts::SYSTEM_RO_DIRS {
            output::field(dir, "bind RO (nodev, nosuid)");
        }
        output::field("/proc", "procfs (nosuid, nodev, noexec, masked)");
        output::field(
            "/dev",
            &format!("{} nodes: {}", mounts::DEV_NODES.len(), mounts::DEV_NODES.join(", ")),
        );

        // --- /proc Masked ---
        output::header("/proc Masked");
        output::field(
            "Top-level",
            &format!("{} ({} entries)", mounts::PROC_MASK_ENTRIES.join(", "), mounts::PROC_MASK_ENTRIES.len()),
        );
        output::field(
            "/proc/self",
            &format!("{} ({} entries)", mounts::PROC_SELF_MASK_ENTRIES.join(", "), mounts::PROC_SELF_MASK_ENTRIES.len()),
        );
        output::field("/proc/1", "(mirrors /proc/self)");
        output::field(
            "Directories",
            &mounts::PROC_DIR_MASK.join(", "),
        );

        // --- /etc (generated) ---
        output::header("/etc (generated)");
        output::field("passwd", "root (UID 0), nobody (UID 65534)");
        output::field("group", "root (GID 0), nogroup (GID 65534)");
        output::field("nsswitch", "files only");
        let resolv = match &resolved.network {
            NetworkMode::Off => "no nameservers (isolated)",
            NetworkMode::On => "copy from host",
            NetworkMode::Allowlist(_) => "127.0.0.53 (DNS proxy)",
        };
        output::field("resolv.conf", resolv);

        // --- Environment ---
        output::header("Environment");
        for (k, v) in sandbox::BASE_ENV {
            output::field("Set", &format!("{k}={v}"));
        }
        let mut blocked: Vec<String> = sandbox::ENV_BLOCKED_PREFIXES
            .iter()
            .map(|p| format!("{p}*"))
            .collect();
        for k in sandbox::ENV_BLOCKED_KEYS {
            blocked.push(k.to_string());
        }
        output::field(
            "Blocked",
            &format!("{} ({} entries)", blocked.join(", "), blocked.len()),
        );

        // --- Namespaces ---
        output::header("Namespaces");
        let mut ns = vec!["user", "mount", "PID", "IPC", "UTS", "cgroup"];
        if resolved.network != NetworkMode::On {
            ns.push("network");
        }
        output::field("Active", &ns.join(", "));

        // --- Capabilities ---
        output::header("Capabilities");
        let caps = if resolved.retain_caps == 0 {
            "none".to_string()
        } else {
            let mut names = Vec::new();
            if resolved.retain_caps & (1 << 10) != 0 {
                names.push("net_bind_service");
            }
            if resolved.retain_caps & (1 << 13) != 0 {
                names.push("net_raw");
            }
            names.join(", ")
        };
        output::field("Retained", &caps);
        output::field("All others", "dropped via capset(v3)");
    }

    /// Print human-readable summary of a completed run.
    fn print_human_summary(&self, result: &RunResult, policy_label: &str) {
        // Ensure the child's stdout didn't leave us mid-line.
        if !self.quiet {
            eprintln!();
        }

        output::info(&format!("Run {} completed.", result.run_id.short()));
        output::field("Policy", policy_label);
        let iso_note = match result.isolation_level {
            IsolationLevel::None => " (no sandbox)",
            IsolationLevel::MicroVM => " (Firecracker microVM)",
            _ => "",
        };
        output::field("Isolation", &format!("{}{}", result.isolation_level, iso_note));
        if result.interactive {
            output::field("Interactive", "yes (PTY)");
        }
        if let Some(ref signer) = result.signed_by {
            output::field("Signed by", signer);
        }
        output::field("Exit code", &result.exit_code.to_string());
        output::field(
            "Duration",
            &format_duration(result.duration.as_millis().min(u64::MAX as u128) as u64),
        );
        output::field(
            "Stdout",
            &format!(
                "{}.. ({})",
                result.stdout_hash.short(),
                format_bytes(result.stdout_size)
            ),
        );
        output::field(
            "Stderr",
            &format!(
                "{}.. ({})",
                result.stderr_hash.short(),
                format_bytes(result.stderr_size)
            ),
        );

        if !result.output_artifacts.is_empty() {
            output::field(
                "Outputs",
                &format!("{} file(s)", result.output_artifacts.len()),
            );
            for a in &result.output_artifacts {
                output::field(
                    &format!("  {}", a.label),
                    &format!("{}.. ({})", a.hash.short(), format_bytes(a.size)),
                );
            }
        }

        if result.cgroup_enforced {
            output::field("Cgroup", "enforced");
        }

        if let Some(ref res) = result.resources {
            if let Some(ref peak) = res.memory_peak {
                let limit_str = res.memory_limit.as_deref().unwrap_or("?");
                output::field("Memory", &format!("{peak} / {limit_str}"));
            }
            if let (Some(user_ms), Some(sys_ms)) = (res.cpu_user_ms, res.cpu_system_ms) {
                output::field("CPU", &format!("{user_ms}ms user, {sys_ms}ms sys"));
            }
            if let Some(pids) = res.pids_peak {
                output::field("PIDs peak", &pids.to_string());
            }
        }

        output::info(&format!(
            "Inspect: oaie inspect {}",
            result.run_id.full()
        ));
    }
}

