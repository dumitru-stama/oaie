//! Policy data model: deny-by-default resource constraints for sandboxed execution.
//!
//! A [`Policy`] can come from a TOML file (`--policy`) or a built-in preset
//! (`safe`, `net`). It describes network access, mount rules, credential
//! protection, and resource limits. The CLI's `policy_resolve` module merges
//! policy + CLI flags into a final `ResolvedPolicy` that drives the sandbox.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize};

use crate::error::{OaieError, Result};

/// A policy constraining what a sandboxed process may access.
///
/// Loaded from a TOML file or constructed via [`Policy::preset_safe()`] /
/// [`Policy::preset_net()`]. Fields use `#[serde(default)]` so minimal
/// TOML files work (missing fields get safe defaults).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    /// Human-readable name (e.g. "safe", "build"). Shown in summaries.
    #[serde(default)]
    pub name: Option<String>,
    /// Default behavioral switches (network, trace, auto-mount).
    #[serde(default)]
    pub defaults: PolicyDefaults,
    /// Mount rules: extra RO/RW paths and denied credential paths.
    #[serde(default)]
    pub mounts: PolicyMounts,
    /// Resource limits (memory, time, PIDs, file size).
    #[serde(default)]
    pub limits: PolicyLimits,
}

/// Network access mode for the sandbox.
///
/// Controls whether and how the sandboxed process can reach the network:
/// - `Off`: full network isolation via `CLONE_NEWNET` (default)
/// - `On`: share host network unrestricted
/// - `Allowlist`: isolated namespace with veth pair + nftables rules allowing
///   only specific endpoints
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum NetworkMode {
    /// No network access — `CLONE_NEWNET` creates an isolated namespace.
    #[default]
    Off,
    /// Full host network access — no `CLONE_NEWNET`.
    On,
    /// Isolated namespace with allowlisted endpoints via nftables.
    Allowlist(Vec<AllowRule>),
}

impl NetworkMode {
    /// Whether this mode requires creating a new network namespace.
    ///
    /// True for `Off` (no connectivity) and `Allowlist` (filtered connectivity).
    /// False for `On` (shares host network).
    pub fn needs_netns(&self) -> bool {
        matches!(self, NetworkMode::Off | NetworkMode::Allowlist(_))
    }

    /// Whether this mode provides any outbound connectivity.
    ///
    /// True for `On` (unrestricted) and `Allowlist` (filtered).
    /// False for `Off` (no connectivity).
    pub fn has_connectivity(&self) -> bool {
        matches!(self, NetworkMode::On | NetworkMode::Allowlist(_))
    }

    /// Whether this mode allows full unrestricted network access (backward compat).
    pub fn is_on(&self) -> bool {
        matches!(self, NetworkMode::On)
    }
}


impl Serialize for NetworkMode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match self {
            NetworkMode::Off => serializer.serialize_bool(false),
            NetworkMode::On => serializer.serialize_bool(true),
            NetworkMode::Allowlist(rules) => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("mode", "allowlist")?;
                map.serialize_entry("allow", rules)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for NetworkMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        use serde::de;

        struct NetworkModeVisitor;

        impl<'de> de::Visitor<'de> for NetworkModeVisitor {
            type Value = NetworkMode;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a boolean, string, or table with mode + allow rules")
            }

            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<NetworkMode, E> {
                Ok(if v { NetworkMode::On } else { NetworkMode::Off })
            }

            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<NetworkMode, E> {
                match v {
                    "off" | "false" => Ok(NetworkMode::Off),
                    "on" | "true" => Ok(NetworkMode::On),
                    "allowlist" => Ok(NetworkMode::Allowlist(vec![])),
                    _ => Err(de::Error::unknown_variant(v, &["off", "on", "allowlist"])),
                }
            }

            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> std::result::Result<NetworkMode, A::Error> {
                let mut mode: Option<String> = None;
                let mut allow: Option<Vec<AllowRule>> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "mode" => mode = Some(map.next_value()?),
                        "allow" => allow = Some(map.next_value()?),
                        _ => { let _: toml::Value = map.next_value()?; }
                    }
                }

                match mode.as_deref() {
                    Some("allowlist") => {
                        Ok(NetworkMode::Allowlist(allow.unwrap_or_default()))
                    }
                    Some("on") | Some("true") => {
                        if allow.is_some() {
                            return Err(de::Error::custom(
                                "network mode is 'on' but 'allow' rules are present; \
                                 did you mean mode = \"allowlist\"?"
                            ));
                        }
                        Ok(NetworkMode::On)
                    }
                    Some("off") | Some("false") => {
                        if allow.is_some() {
                            return Err(de::Error::custom(
                                "network mode is 'off' but 'allow' rules are present; \
                                 did you mean mode = \"allowlist\"?"
                            ));
                        }
                        Ok(NetworkMode::Off)
                    }
                    Some(other) => Err(de::Error::unknown_variant(other, &["off", "on", "allowlist"])),
                    None => Err(de::Error::missing_field("mode")),
                }
            }
        }

        deserializer.deserialize_any(NetworkModeVisitor)
    }
}

/// A single allowlist rule specifying a permitted network endpoint.
///
/// Rules are mutually exclusive: specify either `host` (resolved to IPs via DNS)
/// or `cidr` (direct IP range), never both.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowRule {
    /// DNS hostname to resolve (e.g. "api.anthropic.com"). Mutually exclusive with `cidr`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// CIDR notation IP range (e.g. "104.18.0.0/16"). Mutually exclusive with `host`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    /// Destination port number (e.g. 443).
    pub port: u16,
    /// Transport protocol: "tcp" (default) or "udp".
    #[serde(default = "default_tcp")]
    pub protocol: String,
}

fn default_tcp() -> String {
    "tcp".into()
}

impl AllowRule {
    /// Validate this rule for internal consistency.
    ///
    /// Checks: exactly one of host/cidr is set, port > 0, protocol is tcp/udp.
    pub fn validate(&self) -> Result<()> {
        match (&self.host, &self.cidr) {
            (Some(h), Some(_)) if !h.is_empty() => {
                return Err(OaieError::InvalidJobSpec(
                    "allow rule has both 'host' and 'cidr' — use one or the other".into(),
                ));
            }
            (Some(h), None) if h.is_empty() => {
                return Err(OaieError::InvalidJobSpec(
                    "allow rule 'host' must not be empty".into(),
                ));
            }
            (None, Some(c)) if c.is_empty() => {
                return Err(OaieError::InvalidJobSpec(
                    "allow rule 'cidr' must not be empty".into(),
                ));
            }
            (Some(_), Some(_)) => {
                return Err(OaieError::InvalidJobSpec(
                    "allow rule has both 'host' and 'cidr' — use one or the other".into(),
                ));
            }
            (None, None) => {
                return Err(OaieError::InvalidJobSpec(
                    "allow rule needs either 'host' or 'cidr'".into(),
                ));
            }
            _ => {}
        }

        if self.port == 0 {
            return Err(OaieError::InvalidJobSpec(
                "allow rule port must be > 0".into(),
            ));
        }

        match self.protocol.as_str() {
            "tcp" | "udp" => {}
            other => {
                return Err(OaieError::InvalidJobSpec(format!(
                    "allow rule protocol must be 'tcp' or 'udp', got '{other}'"
                )));
            }
        }

        Ok(())
    }
}

/// Default behavioral switches for the sandbox.
///
/// Uses a custom deserializer for `network` to handle backward-compatible
/// TOML: `network = true` → On, `network = false` → Off, `[network]` table
/// with `mode = "allowlist"` and `[[network.allow]]` rules → Allowlist.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyDefaults {
    /// Network access mode (default: Off — CLONE_NEWNET isolates network).
    #[serde(default)]
    pub network: NetworkMode,
    /// Trace mode (default: "off"). Same values as `TraceMode`.
    #[serde(default = "default_trace")]
    pub trace: String,
    /// Enable auto-mount detection for file arguments.
    /// None is treated as true (opt-out, not opt-in).
    #[serde(default)]
    pub auto_mount: Option<bool>,
}

impl Default for PolicyDefaults {
    fn default() -> Self {
        Self {
            network: NetworkMode::Off,
            trace: "off".into(),
            auto_mount: None,
        }
    }
}

fn default_trace() -> String {
    "off".into()
}

/// Mount rules: extra paths to expose and credential paths to deny.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyMounts {
    /// Extra read-only paths (tilde-expandable, e.g. "~/data").
    #[serde(default)]
    pub ro: Vec<String>,
    /// Extra read-write paths (tilde-expandable).
    #[serde(default)]
    pub rw: Vec<String>,
    /// Denied paths — blocked from mounting even if requested.
    /// Default: credential paths (SSH keys, GPG, cloud configs, etc.).
    #[serde(default = "default_deny_paths")]
    pub deny: Vec<String>,
}

impl Default for PolicyMounts {
    fn default() -> Self {
        Self {
            ro: vec![],
            rw: vec![],
            deny: default_deny_paths(),
        }
    }
}

/// Resource limits for the sandboxed process.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyLimits {
    /// Maximum address space (RLIMIT_AS). Human-readable: "512M", "2G".
    #[serde(default = "default_max_memory")]
    pub max_memory: String,
    /// Maximum wall-clock time. Human-readable: "5m", "1h", "30s".
    #[serde(default = "default_max_time")]
    pub max_time: String,
    /// Maximum number of processes (RLIMIT_NPROC soft limit).
    #[serde(default = "default_max_pids")]
    pub max_pids: u32,
    /// Maximum file size (RLIMIT_FSIZE). Human-readable: "1G", "256M".
    #[serde(default = "default_max_fsize")]
    pub max_fsize: String,
    /// Allow `memfd_create()` and `execveat()` syscalls (default: false).
    ///
    /// Needed for JIT compilers and language runtimes that use fileless
    /// execution (e.g. Java, Node.js JIT, .NET). When false, these syscalls
    /// return EPERM via the seccomp filter.
    #[serde(default)]
    pub allow_memfd: bool,
    /// Linux capabilities to retain inside the sandbox (default: none).
    ///
    /// Only safe capabilities are allowed: "net_raw" (CAP_NET_RAW, bit 13)
    /// for ICMP ping and raw sockets, and "net_bind_service" (CAP_NET_BIND_SERVICE,
    /// bit 10) for binding privileged ports. All other capabilities are rejected
    /// during validation.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// CPU quota as a percentage string (e.g. "50%", "200%").
    ///
    /// Translated to cgroup v2 `cpu.max` values: "50%" → quota=50000, period=100000.
    /// Values above 100% allow multi-core usage (e.g. "200%" = 2 full cores).
    /// Only effective when cgroup isolation is active; ignored with rlimits-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_quota: Option<String>,
}

impl Default for PolicyLimits {
    fn default() -> Self {
        Self {
            max_memory: default_max_memory(),
            max_time: default_max_time(),
            max_pids: default_max_pids(),
            max_fsize: default_max_fsize(),
            allow_memfd: false,
            capabilities: vec![],
            cpu_quota: None,
        }
    }
}

fn default_max_memory() -> String { "512M".into() }
fn default_max_time() -> String { "5m".into() }
fn default_max_pids() -> u32 { 64 }
fn default_max_fsize() -> String { "1G".into() }

impl Policy {
    /// Load a policy from a TOML file, validate it, and return.
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            OaieError::InvalidJobSpec(format!(
                "failed to read policy {}: {e}",
                path.display()
            ))
        })?;
        let mut policy: Policy = toml::from_str(&content).map_err(|e| {
            OaieError::InvalidJobSpec(format!(
                "failed to parse policy {}: {e}",
                path.display()
            ))
        })?;
        // Merge default credential deny paths — a policy.toml with `deny = []`
        // must not silently remove SSH/GPG/cloud credential protection.
        policy.enforce_default_deny_paths();
        policy.validate()?;
        Ok(policy)
    }

    /// Validate that all policy fields are internally consistent.
    ///
    /// Checks: limits parse correctly (including non-zero for memory/fsize),
    /// deny paths don't conflict with required system mounts, `~user` syntax
    /// is rejected, max_pids > 0, and allowlist rules are valid.
    pub fn validate(&self) -> Result<()> {
        // Validate network allowlist rules if present.
        if let NetworkMode::Allowlist(ref rules) = self.defaults.network {
            for rule in rules {
                rule.validate()?;
            }
        }

        // Limits must parse and be non-zero.
        let mem = parse_size(&self.limits.max_memory)?;
        let fsize = parse_size(&self.limits.max_fsize)?;
        parse_duration_policy(&self.limits.max_time)?;

        if mem == 0 {
            return Err(OaieError::InvalidJobSpec(
                "max_memory must be > 0".into(),
            ));
        }
        if fsize == 0 {
            return Err(OaieError::InvalidJobSpec(
                "max_fsize must be > 0".into(),
            ));
        }

        if self.limits.max_pids == 0 {
            return Err(OaieError::InvalidJobSpec(
                "max_pids must be > 0".into(),
            ));
        }

        // Validate cpu_quota if present.
        if let Some(ref quota) = self.limits.cpu_quota {
            parse_cpu_quota(quota)?;
        }

        // Validate capabilities against the allowlist.
        const ALLOWED_CAPS: &[&str] = &["net_raw", "net_bind_service"];
        for cap in &self.limits.capabilities {
            if !ALLOWED_CAPS.contains(&cap.as_str()) {
                return Err(OaieError::InvalidJobSpec(format!(
                    "capability '{}' is not in the allowlist (allowed: {})",
                    cap,
                    ALLOWED_CAPS.join(", ")
                )));
            }
        }

        // Validate tilde paths and deny paths against system directories.
        for path_str in self.mounts.ro.iter().chain(self.mounts.rw.iter()).chain(self.mounts.deny.iter()) {
            validate_tilde_path(path_str)?;
        }
        let system_dirs = ["/usr", "/lib", "/lib64", "/bin", "/sbin"];
        for deny in &self.mounts.deny {
            let expanded = expand_tilde(deny);
            for sys in &system_dirs {
                if expanded == PathBuf::from(sys) || expanded.starts_with(sys) {
                    return Err(OaieError::InvalidJobSpec(format!(
                        "deny path {deny} conflicts with required system mount {sys}"
                    )));
                }
            }
        }

        Ok(())
    }

    /// Ensure the default credential deny paths are always present.
    ///
    /// Called after deserialization to merge `default_deny_paths()` into any
    /// user-provided deny list. This prevents a malicious policy.toml with
    /// `deny = []` from silently removing credential protection.
    pub fn enforce_default_deny_paths(&mut self) {
        let defaults = default_deny_paths();
        for d in &defaults {
            if !self.mounts.deny.contains(d) {
                self.mounts.deny.push(d.clone());
            }
        }
    }

    /// The default deny-by-default policy: no network, 512M, 5m, 64 PIDs.
    pub fn preset_safe() -> Self {
        Self {
            name: Some("safe".into()),
            defaults: PolicyDefaults::default(),
            mounts: PolicyMounts::default(),
            limits: PolicyLimits::default(),
        }
    }

    /// Same as `safe` but with network access enabled.
    pub fn preset_net() -> Self {
        Self {
            name: Some("net".into()),
            defaults: PolicyDefaults {
                network: NetworkMode::On,
                ..PolicyDefaults::default()
            },
            mounts: PolicyMounts::default(),
            limits: PolicyLimits::default(),
        }
    }

    /// Alias for [`Policy::preset_safe()`].
    pub fn default_policy() -> Self {
        Self::preset_safe()
    }

    /// Serialize this policy as a pretty-printed TOML string.
    pub fn to_toml_string(&self) -> Result<String> {
        toml::to_string_pretty(self)
            .map_err(|e| OaieError::Other(format!("failed to serialize policy: {e}")))
    }

    /// Look up a named policy preset by name.
    ///
    /// Returns `None` if the name is not recognized. This is the dispatcher
    /// used by `--policy=agent-safe` (no extension, no path separator) to
    /// select built-in presets without requiring a TOML file.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "safe" => Some(Self::preset_safe()),
            "net" => Some(Self::preset_net()),
            "agent-safe" => Some(Self::preset_agent_safe()),
            "agent-net" => Some(Self::preset_agent_net()),
            "agent-build" => Some(Self::preset_agent_build()),
            "agent-analyze" => Some(Self::preset_agent_analyze()),
            "anthropic" => Some(Self::preset_anthropic()),
            "openai" => Some(Self::preset_openai()),
            "llm" => Some(Self::preset_llm()),
            "contained-local" => Some(Self::preset_contained_local()),
            "contained-cloud" => Some(Self::preset_contained_cloud()),
            "contained-strict" => Some(Self::preset_contained_strict()),
            "contained-interactive" => Some(Self::preset_contained_interactive()),
            _ => None,
        }
    }

    /// List all available named presets with descriptions.
    pub fn list_presets() -> Vec<(&'static str, &'static str)> {
        vec![
            ("safe", "No network, 512M memory, 5m timeout, 64 PIDs"),
            ("net", "Network allowed, 512M memory, 5m timeout, 64 PIDs"),
            ("agent-safe", "Agent: no network, 256M memory, 2m timeout, 64 PIDs"),
            ("agent-net", "Agent: network allowed, 512M memory, 5m timeout, 64 PIDs"),
            ("agent-build", "Agent: network, 2G memory, 10m timeout, 256 PIDs, memfd"),
            ("agent-analyze", "Agent: no network, 1G memory, 15m timeout, 128 PIDs, memfd"),
            ("anthropic", "Allowlist: api.anthropic.com:443 only"),
            ("openai", "Allowlist: api.openai.com:443 only"),
            ("llm", "Allowlist: anthropic + openai + Google generativelanguage API"),
            ("contained-local", "Contained: local LLM, no network, 1G/10m/128 PIDs, memfd"),
            ("contained-cloud", "Contained: cloud LLM, no network, 512M/5m/64 PIDs"),
            ("contained-strict", "Contained: strict, no network, 128M/1m/32 PIDs"),
            ("contained-interactive", "Contained: interactive, no network, 1G/10m/128 PIDs, memfd"),
        ]
    }

    /// Agent preset: no network, tight limits. For running untrusted
    /// commands from AI agents where safety is paramount.
    pub fn preset_agent_safe() -> Self {
        Self {
            name: Some("agent-safe".into()),
            defaults: PolicyDefaults::default(),
            mounts: PolicyMounts::default(),
            limits: PolicyLimits {
                max_memory: "256M".into(),
                max_time: "2m".into(),
                max_pids: 64,
                max_fsize: "256M".into(),
                allow_memfd: false,
                capabilities: vec![],
                cpu_quota: None,
            },
        }
    }

    /// Agent preset: network allowed, moderate limits. For agent tasks
    /// that need outbound connectivity (API calls, downloads).
    pub fn preset_agent_net() -> Self {
        Self {
            name: Some("agent-net".into()),
            defaults: PolicyDefaults {
                network: NetworkMode::On,
                ..PolicyDefaults::default()
            },
            mounts: PolicyMounts::default(),
            limits: PolicyLimits {
                max_memory: "512M".into(),
                max_time: "5m".into(),
                max_pids: 64,
                max_fsize: "256M".into(),
                allow_memfd: false,
                capabilities: vec![],
                cpu_quota: None,
            },
        }
    }

    /// Agent preset: network + generous limits for build tasks.
    /// Allows memfd for JIT runtimes (Java, Node.js, .NET).
    pub fn preset_agent_build() -> Self {
        Self {
            name: Some("agent-build".into()),
            defaults: PolicyDefaults {
                network: NetworkMode::On,
                ..PolicyDefaults::default()
            },
            mounts: PolicyMounts::default(),
            limits: PolicyLimits {
                max_memory: "2G".into(),
                max_time: "10m".into(),
                max_pids: 256,
                max_fsize: "1G".into(),
                allow_memfd: true,
                capabilities: vec![],
                cpu_quota: None,
            },
        }
    }

    /// Agent preset: no network, generous time/memory for analysis tasks.
    /// Allows memfd for runtimes that need fileless execution.
    pub fn preset_agent_analyze() -> Self {
        Self {
            name: Some("agent-analyze".into()),
            defaults: PolicyDefaults::default(),
            mounts: PolicyMounts::default(),
            limits: PolicyLimits {
                max_memory: "1G".into(),
                max_time: "15m".into(),
                max_pids: 128,
                max_fsize: "512M".into(),
                allow_memfd: true,
                capabilities: vec![],
                cpu_quota: None,
            },
        }
    }

    /// Network preset: allowlist Anthropic API only.
    pub fn preset_anthropic() -> Self {
        Self {
            name: Some("anthropic".into()),
            defaults: PolicyDefaults {
                network: NetworkMode::Allowlist(vec![AllowRule {
                    host: Some("api.anthropic.com".into()),
                    cidr: None,
                    port: 443,
                    protocol: "tcp".into(),
                }]),
                ..PolicyDefaults::default()
            },
            mounts: PolicyMounts::default(),
            limits: PolicyLimits::default(),
        }
    }

    /// Network preset: allowlist OpenAI API only.
    pub fn preset_openai() -> Self {
        Self {
            name: Some("openai".into()),
            defaults: PolicyDefaults {
                network: NetworkMode::Allowlist(vec![AllowRule {
                    host: Some("api.openai.com".into()),
                    cidr: None,
                    port: 443,
                    protocol: "tcp".into(),
                }]),
                ..PolicyDefaults::default()
            },
            mounts: PolicyMounts::default(),
            limits: PolicyLimits::default(),
        }
    }

    /// Network preset: allowlist major LLM APIs (Anthropic + OpenAI + Google).
    pub fn preset_llm() -> Self {
        Self {
            name: Some("llm".into()),
            defaults: PolicyDefaults {
                network: NetworkMode::Allowlist(vec![
                    AllowRule {
                        host: Some("api.anthropic.com".into()),
                        cidr: None,
                        port: 443,
                        protocol: "tcp".into(),
                    },
                    AllowRule {
                        host: Some("api.openai.com".into()),
                        cidr: None,
                        port: 443,
                        protocol: "tcp".into(),
                    },
                    AllowRule {
                        host: Some("generativelanguage.googleapis.com".into()),
                        cidr: None,
                        port: 443,
                        protocol: "tcp".into(),
                    },
                ]),
                ..PolicyDefaults::default()
            },
            mounts: PolicyMounts::default(),
            limits: PolicyLimits::default(),
        }
    }

    // ── Containment profile presets (Phase L) ──
    //
    // Per-tool sandbox policies used by `--contained=<profile>`. All have
    // network Off because tools don't call LLM APIs — the unsandboxed
    // agent process handles that directly on the host.

    /// Contained-local: generous limits for local LLM agents.
    /// No network, 1G memory, 10m timeout, 128 PIDs, memfd enabled.
    pub fn preset_contained_local() -> Self {
        Self {
            name: Some("contained-local".into()),
            defaults: PolicyDefaults::default(), // network Off
            mounts: PolicyMounts::default(),
            limits: PolicyLimits {
                max_memory: "1G".into(),
                max_time: "10m".into(),
                max_pids: 128,
                max_fsize: "1G".into(),
                allow_memfd: true,
                capabilities: vec![],
                cpu_quota: None,
            },
        }
    }

    /// Contained-cloud: moderate limits for cloud LLM agents.
    /// No network, 512M memory, 5m timeout, 64 PIDs.
    pub fn preset_contained_cloud() -> Self {
        Self {
            name: Some("contained-cloud".into()),
            defaults: PolicyDefaults::default(), // network Off
            mounts: PolicyMounts::default(),
            limits: PolicyLimits::default(), // 512M, 5m, 64 PIDs
        }
    }

    /// Contained-strict: maximum restriction.
    /// No network, 128M memory, 1m timeout, 32 PIDs.
    pub fn preset_contained_strict() -> Self {
        Self {
            name: Some("contained-strict".into()),
            defaults: PolicyDefaults::default(), // network Off
            mounts: PolicyMounts::default(),
            limits: PolicyLimits {
                max_memory: "128M".into(),
                max_time: "1m".into(),
                max_pids: 32,
                max_fsize: "256M".into(),
                allow_memfd: false,
                capabilities: vec![],
                cpu_quota: None,
            },
        }
    }

    /// Contained-interactive: generous limits for human-in-the-loop sessions.
    /// No network, 1G memory, 10m timeout, 128 PIDs, memfd enabled.
    pub fn preset_contained_interactive() -> Self {
        Self {
            name: Some("contained-interactive".into()),
            defaults: PolicyDefaults::default(), // network Off
            mounts: PolicyMounts::default(),
            limits: PolicyLimits {
                max_memory: "1G".into(),
                max_time: "10m".into(),
                max_pids: 128,
                max_fsize: "1G".into(),
                allow_memfd: true,
                capabilities: vec![],
                cpu_quota: None,
            },
        }
    }
}

/// Credential and secret paths that are denied by default.
///
/// These paths contain SSH keys, GPG keyrings, cloud credentials, package
/// registry tokens, password stores, and Kubernetes secrets. A sandboxed
/// process should never need access to these.
pub fn default_deny_paths() -> Vec<String> {
    vec![
        "~/.ssh".into(),
        "~/.gnupg".into(),
        "~/.aws".into(),
        "~/.azure".into(),
        "~/.config/gcloud".into(),
        "~/.docker".into(),
        "~/.kube".into(),
        "~/.npmrc".into(),
        "~/.pypirc".into(),
        "~/.netrc".into(),
        "~/.git-credentials".into(),
        "~/.config/git/credentials".into(),
        "~/.local/share/keyrings".into(),
        "~/.password-store".into(),
        "~/.config/gh".into(),
        "~/.cargo/credentials.toml".into(),
        "~/.cargo/credentials".into(),
        "~/.config/op".into(),
        "~/.vault-token".into(),
        "~/.terraform.d/credentials.tfrc.json".into(),
        "~/.config/helm".into(),
        "~/.config/doctl".into(),
        "~/.config/heroku".into(),
        "~/.config/stripe".into(),
        "/var/run/secrets".into(),
    ]
}

/// Expand `~` at the start of a path to `$HOME`.
///
/// Uses `std::env::var("HOME")` — no `dirs` crate needed. Returns the
/// path unchanged if it doesn't start with `~` or `HOME` is not set.
///
/// Note: `~user` syntax (e.g. `~bob/data`) is intentionally not supported
/// and is rejected with an error. OAIE runs as a single user and policy
/// files shouldn't reference other users' home directories.
pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    } else if path == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home);
        }
    }
    PathBuf::from(path)
}

/// Validate that a path does not use unsupported `~user` syntax.
///
/// Returns `Ok(())` if the path is valid, or an error if it starts with `~`
/// followed by a username (e.g. `~root/.ssh`). Bare `~` and `~/path` are fine.
pub fn validate_tilde_path(path: &str) -> Result<()> {
    if path.starts_with('~') && path != "~" && !path.starts_with("~/") {
        return Err(OaieError::InvalidJobSpec(format!(
            "~user syntax is not supported: {path}"
        )));
    }
    Ok(())
}

/// Parse a human-readable size string into bytes.
///
/// Supports suffixes: K (kibibytes), M (mebibytes), G (gibibytes),
/// or no suffix (raw bytes). Case-insensitive suffixes.
///
/// # Examples
/// - `"512M"` → 536_870_912
/// - `"2G"` → 2_147_483_648
/// - `"1024K"` → 1_048_576
/// - `"1024"` → 1024
pub fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        return Err(OaieError::InvalidJobSpec("empty size string".into()));
    }

    let (num_str, multiplier) = if let Some(num) = s.strip_suffix('G').or_else(|| s.strip_suffix('g')) {
        (num, 1024u64 * 1024 * 1024)
    } else if let Some(num) = s.strip_suffix('M').or_else(|| s.strip_suffix('m')) {
        (num, 1024u64 * 1024)
    } else if let Some(num) = s.strip_suffix('K').or_else(|| s.strip_suffix('k')) {
        (num, 1024u64)
    } else {
        (s, 1u64)
    };

    let value: u64 = num_str
        .trim()
        .parse()
        .map_err(|_| OaieError::InvalidJobSpec(format!("invalid size: {s}")))?;

    value
        .checked_mul(multiplier)
        .ok_or_else(|| OaieError::InvalidJobSpec(format!("size overflow: {s}")))
}

/// Parse a human-readable duration string for policy limits.
///
/// Supports: "30s", "5m", "1h", "7d", "1h30m", or compound forms.
/// Zero durations are rejected.
pub fn parse_duration_policy(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return Err(OaieError::InvalidJobSpec("empty duration string".into()));
    }

    let mut total_secs: u64 = 0;
    let mut current_num = String::new();
    let mut had_unit = false;

    for c in s.chars() {
        if c.is_ascii_digit() {
            current_num.push(c);
        } else {
            if current_num.is_empty() {
                return Err(OaieError::InvalidJobSpec(format!(
                    "invalid duration: {s}"
                )));
            }
            let val: u64 = current_num
                .parse()
                .map_err(|_| OaieError::InvalidJobSpec(format!("invalid duration: {s}")))?;
            current_num.clear();

            let multiplied = match c {
                'd' | 'D' => val.checked_mul(86400),
                'h' | 'H' => val.checked_mul(3600),
                'm' | 'M' => val.checked_mul(60),
                's' | 'S' => Some(val),
                _ => {
                    return Err(OaieError::InvalidJobSpec(format!(
                        "invalid duration unit '{c}' in: {s}"
                    )));
                }
            };
            let multiplied = multiplied.ok_or_else(|| {
                OaieError::InvalidJobSpec(format!("duration overflow: {s}"))
            })?;
            total_secs = total_secs.checked_add(multiplied).ok_or_else(|| {
                OaieError::InvalidJobSpec(format!("duration overflow: {s}"))
            })?;
            had_unit = true;
        }
    }

    // Trailing number without suffix: treat as seconds.
    if !current_num.is_empty() {
        let val: u64 = current_num
            .parse()
            .map_err(|_| OaieError::InvalidJobSpec(format!("invalid duration: {s}")))?;
        if had_unit {
            // e.g. "5m30" — trailing digits without unit after a unit was used.
            return Err(OaieError::InvalidJobSpec(format!(
                "invalid duration (trailing digits without unit): {s}"
            )));
        }
        total_secs = total_secs.checked_add(val).ok_or_else(|| {
            OaieError::InvalidJobSpec(format!("duration overflow: {s}"))
        })?;
    }

    if total_secs == 0 {
        return Err(OaieError::InvalidJobSpec(format!(
            "duration must be > 0: {s}"
        )));
    }

    Ok(Duration::from_secs(total_secs))
}

/// Format bytes as a human-readable size string (e.g. "512M", "2G").
///
/// Picks the largest clean unit. Falls back to bytes for non-round values.
pub fn format_size_human(bytes: u64) -> String {
    if bytes == 0 {
        return "0".into();
    }
    if bytes.is_multiple_of(1024 * 1024 * 1024) {
        format!("{}G", bytes / (1024 * 1024 * 1024))
    } else if bytes.is_multiple_of(1024 * 1024) {
        format!("{}M", bytes / (1024 * 1024))
    } else if bytes.is_multiple_of(1024) {
        format!("{}K", bytes / 1024)
    } else {
        bytes.to_string()
    }
}

/// Convert capability names to a bitmask of Linux capability bits.
///
/// Only the two allowlisted capabilities are recognized:
/// - `"net_raw"` → CAP_NET_RAW (bit 13): raw sockets for ICMP ping
/// - `"net_bind_service"` → CAP_NET_BIND_SERVICE (bit 10): bind ports < 1024
///
/// Unknown names are silently ignored (validation rejects them earlier).
pub fn capability_mask(caps: &[String]) -> u64 {
    let mut mask: u64 = 0;
    for cap in caps {
        match cap.as_str() {
            "net_raw" => mask |= 1 << 13,
            "net_bind_service" => mask |= 1 << 10,
            _ => {} // validated earlier
        }
    }
    mask
}

/// Parse a CPU quota percentage string into cgroup v2 `cpu.max` values.
///
/// Returns `(quota_us, period_us)` where period is always 100000 (100ms).
/// - `"50%"` → `(50000, 100000)` — 50% of one CPU
/// - `"200%"` → `(200000, 100000)` — 2 full CPUs
/// - `"0%"` → error (must be > 0)
/// - `"abc"` → error (not a valid percentage)
pub fn parse_cpu_quota(s: &str) -> Result<(u64, u64)> {
    let s = s.trim();
    let num_str = s.strip_suffix('%').ok_or_else(|| {
        OaieError::InvalidJobSpec(format!("cpu_quota must end with '%': {s}"))
    })?;

    let pct: u64 = num_str.trim().parse().map_err(|_| {
        OaieError::InvalidJobSpec(format!("invalid cpu_quota percentage: {s}"))
    })?;

    if pct == 0 {
        return Err(OaieError::InvalidJobSpec(
            "cpu_quota must be > 0%".into(),
        ));
    }

    let period: u64 = 100_000; // 100ms in microseconds
    let quota = pct.checked_mul(1000).ok_or_else(|| {
        OaieError::InvalidJobSpec(format!("cpu_quota overflow: {s}"))
    })?;

    Ok((quota, period))
}

/// Parse a `--net` flag value into a `NetworkMode`.
///
/// Supported forms:
/// - `"on"` / `"true"` → `On`
/// - `"off"` / `"false"` → `Off`
/// - `"allow:host:port"` → `Allowlist` with a single rule
/// - `"allow:host:port,host2:port2"` → `Allowlist` with multiple rules
/// - `"preset:anthropic"` → preset lookup
pub fn parse_net_flag(value: &str) -> Result<NetworkMode> {
    match value {
        "on" | "true" => Ok(NetworkMode::On),
        "off" | "false" => Ok(NetworkMode::Off),
        _ if value.starts_with("allow:") => {
            let rules_str = &value["allow:".len()..];
            let mut rules = Vec::new();
            for entry in rules_str.split(',') {
                let entry = entry.trim();
                if entry.is_empty() {
                    continue;
                }
                // Parse "host:port" or "host:port/proto".
                // Use rfind('/') but only treat it as a protocol separator if
                // the part after it is a known protocol name. This avoids
                // confusing CIDR slashes (e.g. "10.0.0.0/24:443") with proto.
                let (addr_part, proto) = match entry.rfind('/') {
                    Some(slash_pos) => {
                        let after = &entry[slash_pos + 1..];
                        if after == "tcp" || after == "udp" {
                            (&entry[..slash_pos], after)
                        } else {
                            (entry, "tcp")
                        }
                    }
                    None => (entry, "tcp"),
                };
                // Split host/CIDR from port.  IPv6 addresses use bracket
                // notation: [::1]:443 or [2001:db8::1]:443/tcp.
                let (host_or_cidr, port) = if addr_part.starts_with('[') {
                    // Bracketed IPv6: find matching ']' then expect ':port'.
                    let bracket_end = addr_part.find(']').ok_or_else(|| {
                        OaieError::InvalidJobSpec(format!(
                            "unclosed bracket in IPv6 allow rule: '{entry}'"
                        ))
                    })?;
                    let inner = &addr_part[1..bracket_end];
                    let rest = &addr_part[bracket_end + 1..];
                    let port_str = rest.strip_prefix(':').ok_or_else(|| {
                        OaieError::InvalidJobSpec(format!(
                            "expected ':port' after ']' in allow rule: '{entry}'"
                        ))
                    })?;
                    let port: u16 = port_str.parse().map_err(|_| {
                        OaieError::InvalidJobSpec(format!(
                            "invalid port in allow rule: '{entry}'"
                        ))
                    })?;
                    (inner, port)
                } else {
                    // IPv4 / hostname / CIDR: last colon separates port.
                    let colon_pos = addr_part.rfind(':').ok_or_else(|| {
                        OaieError::InvalidJobSpec(format!(
                            "allow rule must be 'host:port' or 'cidr:port', got '{entry}'"
                        ))
                    })?;
                    let port: u16 = addr_part[colon_pos + 1..].parse().map_err(|_| {
                        OaieError::InvalidJobSpec(format!(
                            "invalid port in allow rule: '{entry}'"
                        ))
                    })?;
                    (&addr_part[..colon_pos], port)
                };

                // Distinguish host vs CIDR: CIDR contains '/'.
                let (host, cidr) = if host_or_cidr.contains('/') {
                    (None, Some(host_or_cidr.to_string()))
                } else {
                    (Some(host_or_cidr.to_string()), None)
                };

                let rule = AllowRule {
                    host,
                    cidr,
                    port,
                    protocol: proto.to_string(),
                };
                rule.validate()?;
                rules.push(rule);
            }
            if rules.is_empty() {
                return Err(OaieError::InvalidJobSpec(
                    "allow: requires at least one rule".into(),
                ));
            }
            Ok(NetworkMode::Allowlist(rules))
        }
        _ if value.starts_with("preset:") => {
            let preset_name = &value["preset:".len()..];
            match Policy::from_name(preset_name) {
                Some(policy) => Ok(policy.defaults.network),
                None => Err(OaieError::InvalidJobSpec(format!(
                    "unknown network preset: '{preset_name}'"
                ))),
            }
        }
        _ => Err(OaieError::InvalidJobSpec(format!(
            "unknown --net value: '{value}'. Use on, off, allow:host:port, or preset:name"
        ))),
    }
}

/// Format a duration as a human-readable string (e.g. "5m", "1h30m").
pub fn format_duration_human(d: Duration) -> String {
    let secs = d.as_secs();
    if secs == 0 {
        return "0s".into();
    }
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;

    let mut out = String::new();
    if h > 0 {
        out.push_str(&format!("{h}h"));
    }
    if m > 0 {
        out.push_str(&format!("{m}m"));
    }
    if s > 0 {
        out.push_str(&format!("{s}s"));
    }
    out
}
