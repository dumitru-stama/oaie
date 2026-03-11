//! Policy resolution: merges policy file + CLI flags + auto-mount detection
//! into a final [`ResolvedPolicy`] that drives the sandbox.
//!
//! Lives in oaie-cli (not oaie-core) because it depends on oaie-sandbox's
//! `SandboxConfig`. Putting it in oaie-core would create a dependency cycle.
//!
//! Uses [`PolicyInput`] instead of `RunCmd` directly so the lib crate doesn't
//! depend on the binary's clap types.

use std::path::PathBuf;
use std::time::Duration;

use oaie_core::auto_mount::{self, AutoMountEntry};
use oaie_core::cgroup::CgroupMode;
use oaie_core::error::{OaieError, Result};
use oaie_core::job::TraceMode;
use oaie_core::policy::{self, NetworkMode, Policy};
use oaie_sandbox::sandbox::SandboxConfig;

/// Extracted CLI fields needed for policy resolution.
///
/// Constructed from `RunCmd` in the binary; keeps clap types out of the lib.
pub struct PolicyInput<'a> {
    pub policy_path: Option<&'a PathBuf>,
    /// CLI `--net` override. `None` means not specified (defer to policy).
    pub net: Option<NetworkMode>,
    pub timeout: Option<&'a str>,
    pub ro: &'a [PathBuf],
    pub rw: &'a [PathBuf],
    pub no_auto_mount: bool,
    pub command: &'a [String],
    pub input: Option<&'a PathBuf>,
    pub out: Option<&'a PathBuf>,
    /// Store-level default timeout (from `config.toml`). Used when no CLI
    /// `--timeout` is given, overriding the policy preset's default.
    pub store_default_timeout: Option<&'a str>,
    /// Store-level maximum timeout (from `config.toml`). The effective timeout
    /// is clamped to this value regardless of CLI or policy settings.
    pub store_max_timeout: Option<&'a str>,
    /// Cgroup mode from CLI `--cgroup` flag ("auto", "require", "off").
    pub cgroup: &'a str,
}

/// Fully resolved policy: all values are concrete (no defaults, no "inherit").
/// Ready to be converted to a `SandboxConfig` and fed to the runner.
#[derive(Clone, Debug)]
pub struct ResolvedPolicy {
    /// Policy name (from preset or file).
    pub name: Option<String>,
    /// Network access mode (Off, On, or Allowlist with rules).
    pub network: NetworkMode,
    /// Effective timeout (from CLI or policy, whichever is set).
    pub timeout: Option<Duration>,
    /// Trace mode.
    pub trace: TraceMode,
    /// Input directory.
    pub input_dir: PathBuf,
    /// Output directory override.
    pub output_dir: Option<PathBuf>,
    /// Read-only mount paths (policy + CLI + auto-mount RO).
    pub ro_mounts: Vec<PathBuf>,
    /// Read-write mount paths (policy + CLI + auto-mount RW).
    pub rw_mounts: Vec<PathBuf>,
    /// Paths denied from mounting.
    pub deny_paths: Vec<PathBuf>,
    /// Maximum address space in bytes.
    pub max_memory: u64,
    /// Maximum wall-clock time.
    pub max_time: Duration,
    /// Maximum processes (RLIMIT_NPROC soft limit).
    pub max_pids: u32,
    /// Maximum file size in bytes (RLIMIT_FSIZE).
    pub max_fsize: u64,
    /// Allow `memfd_create()`/`execveat()` through the seccomp filter.
    pub allow_memfd: bool,
    /// Bitmask of Linux capabilities to retain (0 = drop all). Only safe
    /// capabilities (CAP_NET_RAW, CAP_NET_BIND_SERVICE) are allowed; the
    /// policy validation rejects anything else.
    pub retain_caps: u64,
    /// Auto-mounted entries (for audit trail in manifest).
    pub auto_mounts: Vec<AutoMountEntry>,
    /// CPU quota from policy, parsed into (quota_us, period_us).
    /// Only effective when cgroup isolation is active.
    pub cpu_quota: Option<(u64, u64)>,
    /// Cgroup isolation mode (auto/require/off).
    pub cgroup_mode: CgroupMode,
}

/// Resolve a complete policy from CLI flags, policy file, and auto-mount detection.
///
/// Priority order:
/// 1. Load base policy: `--policy` file → `Policy::from_file()`,
///    or `--net` → `preset_net()`, else `preset_safe()`
/// 2. CLI `--net` overrides `defaults.network`
/// 3. CLI `--timeout` overrides `limits.max_time`
/// 4. CLI `--ro`/`--rw` append to policy mounts (tilde-expanded)
/// 5. Auto-mount detection (unless `--no-auto-mount` or `auto_mount = false`)
/// 6. Expand tilde on deny paths
/// 7. Parse size/duration limits
pub fn resolve_policy(input: &PolicyInput<'_>) -> Result<ResolvedPolicy> {
    // 1. Load base policy.
    //
    // When --policy=<value> has no path separator and no file extension,
    // treat it as a named preset (e.g. "agent-safe", "net"). If the name
    // isn't recognized, fall through to file-based loading.
    let base = if let Some(policy_path) = input.policy_path {
        let path_str = policy_path.to_string_lossy();
        let is_named_preset = !path_str.contains(std::path::MAIN_SEPARATOR)
            && !path_str.contains('/')
            && !path_str.contains('.');
        if is_named_preset {
            if let Some(preset) = Policy::from_name(&path_str) {
                preset
            } else {
                // Not a known preset — try as file path (existing behavior).
                Policy::from_file(policy_path)?
            }
        } else {
            Policy::from_file(policy_path)?
        }
    } else if let Some(ref net_mode) = input.net {
        // --net specified without --policy: use the appropriate base preset.
        match net_mode {
            NetworkMode::On => Policy::preset_net(),
            _ => Policy::preset_safe(),
        }
    } else {
        Policy::preset_safe()
    };

    // 2. CLI --net overrides policy's network mode.
    let network = if let Some(ref net_mode) = input.net {
        net_mode.clone()
    } else {
        base.defaults.network.clone()
    };

    // 3. Parse policy limits.
    let max_memory = policy::parse_size(&base.limits.max_memory)?;
    let max_time = policy::parse_duration_policy(&base.limits.max_time)?;
    let max_pids = base.limits.max_pids;
    let max_fsize = policy::parse_size(&base.limits.max_fsize)?;

    // CLI --timeout overrides policy max_time.
    // Store default_timeout overrides the preset's default (used when no
    // explicit policy file and no CLI --timeout).
    let timeout = if let Some(t) = input.timeout {
        Some(oaie_core::job::parse_timeout(t)?)
    } else if input.policy_path.is_none() {
        // No explicit policy — use store default timeout if configured.
        if let Some(dt) = input.store_default_timeout {
            Some(policy::parse_duration_policy(dt)?)
        } else {
            Some(max_time)
        }
    } else {
        Some(max_time)
    };

    // Clamp to store max_timeout if configured.
    let timeout = if let (Some(t), Some(mt)) = (timeout, input.store_max_timeout) {
        let max = policy::parse_duration_policy(mt)?;
        Some(t.min(max))
    } else {
        timeout
    };

    // 4. Collect mounts from policy + CLI, tilde-expanded.
    let mut ro_mounts: Vec<PathBuf> = base
        .mounts
        .ro
        .iter()
        .map(|p| policy::expand_tilde(p))
        .collect();
    for p in input.ro {
        ro_mounts.push(p.clone());
    }

    let mut rw_mounts: Vec<PathBuf> = base
        .mounts
        .rw
        .iter()
        .map(|p| policy::expand_tilde(p))
        .collect();
    for p in input.rw {
        rw_mounts.push(p.clone());
    }

    // 6. Expand tilde on deny paths.
    let deny_paths: Vec<PathBuf> = base
        .mounts
        .deny
        .iter()
        .map(|p| policy::expand_tilde(p))
        .collect();

    // Validate explicit mounts against deny paths (before auto-mount).
    // Done here (not after resolve_policy returns) to avoid re-reading the
    // policy file, which would create a TOCTOU window.
    {
        let explicit_paths: Vec<PathBuf> = input.ro.iter()
            .chain(input.rw.iter())
            .cloned()
            .chain(base.mounts.ro.iter().map(|p| policy::expand_tilde(p)))
            .chain(base.mounts.rw.iter().map(|p| policy::expand_tilde(p)))
            .collect();
        for mount_path in &explicit_paths {
            for deny in &deny_paths {
                if mount_path.starts_with(deny) || deny.starts_with(mount_path) {
                    return Err(OaieError::PolicyViolation(format!(
                        "mount path {} would expose denied path {}",
                        mount_path.display(),
                        deny.display()
                    )));
                }
            }
        }
    }

    // 5. Auto-mount detection.
    let auto_mount_enabled = !input.no_auto_mount
        && base.defaults.auto_mount.unwrap_or(true);

    let auto_mounts = if auto_mount_enabled && !input.command.is_empty() {
        let (exec_paths, arg_paths) = auto_mount::detect_file_args(input.command);
        auto_mount::auto_mount_paths(
            &exec_paths,
            &arg_paths,
            &ro_mounts,
            &rw_mounts,
            &deny_paths,
        )
    } else {
        vec![]
    };

    // Add auto-mounted paths to the appropriate mount lists.
    for entry in &auto_mounts {
        match entry.mode.as_str() {
            "ro" => ro_mounts.push(entry.mount_dir.clone()),
            "rw" => rw_mounts.push(entry.mount_dir.clone()),
            _ => {}
        }
    }

    // Parse trace mode from policy (CLI --trace is handled in run.rs on JobSpec).
    let trace = match base.defaults.trace.parse::<TraceMode>() {
        Ok(mode) => mode,
        Err(_) => {
            oaie_core::log_warn!(
                "unrecognized trace mode '{}' in policy, defaulting to 'off'",
                base.defaults.trace
            );
            TraceMode::Off
        }
    };

    let input_dir = input
        .input
        .cloned()
        .unwrap_or_else(|| PathBuf::from("."));

    // Parse CPU quota from policy (if present).
    let cpu_quota = match &base.limits.cpu_quota {
        Some(q) => Some(policy::parse_cpu_quota(q)?),
        None => None,
    };

    // Parse cgroup mode from CLI flag.
    let cgroup_mode: CgroupMode = input.cgroup.parse()?;

    Ok(ResolvedPolicy {
        name: base.name,
        network,
        timeout,
        trace,
        input_dir,
        output_dir: input.out.cloned(),
        ro_mounts,
        rw_mounts,
        deny_paths,
        max_memory,
        max_time,
        max_pids,
        max_fsize,
        allow_memfd: base.limits.allow_memfd,
        retain_caps: policy::capability_mask(&base.limits.capabilities),
        auto_mounts,
        cpu_quota,
        cgroup_mode,
    })
}

impl ResolvedPolicy {
    /// Convert the resolved policy into a `SandboxConfig` for `spawn_sandboxed()`.
    pub fn to_sandbox_config(&self, output_dir: &std::path::Path) -> SandboxConfig {
        SandboxConfig {
            input_dir: self.input_dir.clone(),
            output_dir: output_dir.to_path_buf(),
            extra_ro: self.ro_mounts.clone(),
            extra_rw: self.rw_mounts.clone(),
            network: self.network.clone(),
            proc_mount: true,
            max_pids: Some(self.max_pids),
            max_memory: Some(self.max_memory),
            max_fsize: Some(self.max_fsize),
            allow_memfd: self.allow_memfd,
            retain_caps: self.retain_caps,
            max_cpu_time: None, // Set by runner from effective timeout.
            interactive: false, // Set by backend, not policy.
            pty_slave_path: None,
            session_mounts: vec![],
        }
    }
}
