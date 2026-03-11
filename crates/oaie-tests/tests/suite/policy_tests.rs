//! Tests for the policy layer: parsing, validation, presets, auto-mount, and enforcement.

use std::time::Duration;

use oaie_core::auto_mount;
use oaie_core::policy::{
    self, default_deny_paths, expand_tilde, parse_duration_policy, parse_size, Policy,
};

// ---- parse_size ----

#[test]
fn parse_size_megabytes() {
    assert_eq!(parse_size("512M").unwrap(), 536_870_912);
}

#[test]
fn parse_size_gigabytes() {
    assert_eq!(parse_size("2G").unwrap(), 2_147_483_648);
}

#[test]
fn parse_size_kilobytes() {
    assert_eq!(parse_size("1024K").unwrap(), 1_048_576);
}

#[test]
fn parse_size_raw_bytes() {
    assert_eq!(parse_size("1024").unwrap(), 1024);
}

#[test]
fn parse_size_lowercase() {
    assert_eq!(parse_size("512m").unwrap(), 536_870_912);
    assert_eq!(parse_size("2g").unwrap(), 2_147_483_648);
    assert_eq!(parse_size("1024k").unwrap(), 1_048_576);
}

#[test]
fn parse_size_invalid_alpha() {
    assert!(parse_size("abc").is_err());
}

#[test]
fn parse_size_empty() {
    assert!(parse_size("").is_err());
}

// ---- parse_duration_policy ----

#[test]
fn parse_duration_5m() {
    assert_eq!(parse_duration_policy("5m").unwrap(), Duration::from_secs(300));
}

#[test]
fn parse_duration_1h() {
    assert_eq!(parse_duration_policy("1h").unwrap(), Duration::from_secs(3600));
}

#[test]
fn parse_duration_30s() {
    assert_eq!(parse_duration_policy("30s").unwrap(), Duration::from_secs(30));
}

#[test]
fn parse_duration_compound() {
    assert_eq!(parse_duration_policy("1h30m").unwrap(), Duration::from_secs(5400));
}

#[test]
fn parse_duration_invalid_unit() {
    assert!(parse_duration_policy("5x").is_err());
}

#[test]
fn parse_duration_zero() {
    assert!(parse_duration_policy("0s").is_err());
}

#[test]
fn parse_duration_empty() {
    assert!(parse_duration_policy("").is_err());
}

// ---- expand_tilde ----

#[test]
fn expand_tilde_ssh() {
    let home = std::env::var("HOME").unwrap();
    let expanded = expand_tilde("~/.ssh");
    assert_eq!(expanded, std::path::PathBuf::from(format!("{home}/.ssh")));
}

#[test]
fn expand_tilde_absolute_unchanged() {
    let expanded = expand_tilde("/var/run/secrets");
    assert_eq!(expanded, std::path::PathBuf::from("/var/run/secrets"));
}

#[test]
fn expand_tilde_bare() {
    let home = std::env::var("HOME").unwrap();
    let expanded = expand_tilde("~");
    assert_eq!(expanded, std::path::PathBuf::from(home));
}

// ---- Policy from TOML ----

#[test]
fn policy_from_toml_full() {
    let toml = r#"
name = "custom"

[defaults]
network = true
trace = "strace"
auto_mount = false

[mounts]
ro = ["~/data"]
rw = ["/tmp/scratch"]
deny = ["~/.ssh", "~/.aws"]

[limits]
max_memory = "2G"
max_time = "10m"
max_pids = 128
max_fsize = "256M"
"#;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), toml).unwrap();
    let policy = Policy::from_file(tmp.path()).unwrap();

    assert_eq!(policy.name.as_deref(), Some("custom"));
    assert!(policy.defaults.network.has_connectivity());
    assert_eq!(policy.defaults.trace, "strace");
    assert_eq!(policy.defaults.auto_mount, Some(false));
    assert_eq!(policy.mounts.ro, vec!["~/data"]);
    assert_eq!(policy.mounts.rw, vec!["/tmp/scratch"]);
    // The deny list includes the 2 user-specified paths plus default_deny_paths().
    assert!(policy.mounts.deny.contains(&"~/.ssh".to_string()));
    assert!(policy.mounts.deny.contains(&"~/.aws".to_string()));
    assert!(policy.mounts.deny.len() >= 2);
    assert_eq!(policy.limits.max_memory, "2G");
    assert_eq!(policy.limits.max_time, "10m");
    assert_eq!(policy.limits.max_pids, 128);
    assert_eq!(policy.limits.max_fsize, "256M");
}

#[test]
fn policy_from_toml_minimal() {
    // Empty file should parse with all defaults.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), "").unwrap();
    let policy = Policy::from_file(tmp.path()).unwrap();

    assert!(policy.name.is_none());
    assert!(!policy.defaults.network.has_connectivity());
    assert_eq!(policy.limits.max_memory, "512M");
    assert_eq!(policy.limits.max_time, "5m");
    assert_eq!(policy.limits.max_pids, 64);
    assert_eq!(policy.limits.max_fsize, "1G");
    // Should have default deny paths.
    assert!(!policy.mounts.deny.is_empty());
}

// ---- Policy validation ----

#[test]
fn validate_deny_usr() {
    let mut policy = Policy::preset_safe();
    policy.mounts.deny.push("/usr".into());
    assert!(policy.validate().is_err());
}

#[test]
fn validate_deny_bin() {
    let mut policy = Policy::preset_safe();
    policy.mounts.deny.push("/bin".into());
    assert!(policy.validate().is_err());
}

#[test]
fn validate_max_pids_zero() {
    let mut policy = Policy::preset_safe();
    policy.limits.max_pids = 0;
    assert!(policy.validate().is_err());
}

#[test]
fn validate_invalid_size() {
    let mut policy = Policy::preset_safe();
    policy.limits.max_memory = "nope".into();
    assert!(policy.validate().is_err());
}

// ---- Presets ----

#[test]
fn preset_safe_properties() {
    let p = Policy::preset_safe();
    assert_eq!(p.name.as_deref(), Some("safe"));
    assert!(!p.defaults.network.has_connectivity());
    assert_eq!(parse_size(&p.limits.max_memory).unwrap(), 512 * 1024 * 1024);
    assert_eq!(parse_duration_policy(&p.limits.max_time).unwrap(), Duration::from_secs(300));
    assert_eq!(p.limits.max_pids, 64);
    assert!(!p.limits.allow_memfd);
}

#[test]
fn preset_net_properties() {
    let p = Policy::preset_net();
    assert_eq!(p.name.as_deref(), Some("net"));
    assert!(p.defaults.network.has_connectivity());
    // Same limits as safe.
    assert_eq!(p.limits.max_pids, 64);
}

#[test]
fn default_deny_includes_ssh() {
    let deny = default_deny_paths();
    assert!(deny.contains(&"~/.ssh".to_string()));
}

#[test]
fn default_deny_includes_aws() {
    let deny = default_deny_paths();
    assert!(deny.contains(&"~/.aws".to_string()));
}

// ---- allow_memfd ----

#[test]
fn allow_memfd_default_false() {
    let p = Policy::preset_safe();
    assert!(!p.limits.allow_memfd);
    let p = Policy::preset_net();
    assert!(!p.limits.allow_memfd);
}

#[test]
fn allow_memfd_from_toml() {
    let toml = r#"
[limits]
allow_memfd = true
"#;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), toml).unwrap();
    let policy = Policy::from_file(tmp.path()).unwrap();
    assert!(policy.limits.allow_memfd);
}

#[test]
fn allow_memfd_missing_defaults_false() {
    // Empty TOML — allow_memfd should default to false.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), "").unwrap();
    let policy = Policy::from_file(tmp.path()).unwrap();
    assert!(!policy.limits.allow_memfd);
}

// ---- Auto-mount detection ----

#[test]
fn detect_file_args_flags_skipped() {
    let cmd: Vec<String> = vec![
        "ls".into(), "-la".into(), "--color".into(), "/tmp".into(),
    ];
    let (exec_paths, arg_paths) = auto_mount::detect_file_args(&cmd);
    // ls is found via PATH, not as a file arg
    assert!(exec_paths.is_empty() || exec_paths.iter().all(|p| p.exists()));
    // Flags should be skipped, /tmp should be detected
    assert!(!arg_paths.iter().any(|p| p.to_str() == Some("-la")));
    assert!(!arg_paths.iter().any(|p| p.to_str() == Some("--color")));
    assert!(arg_paths.iter().any(|p| p.to_str() == Some("/tmp")));
}

#[test]
fn detect_file_args_system_paths_skipped() {
    let cmd: Vec<String> = vec!["cat".into(), "/proc/cpuinfo".into()];
    let (_, arg_paths) = auto_mount::detect_file_args(&cmd);
    assert!(!arg_paths.iter().any(|p| p.starts_with("/proc")));
}

#[test]
fn auto_mount_dedup() {
    use std::path::PathBuf;

    // Create two files in the same temp dir.
    let dir = tempfile::tempdir().unwrap();
    let f1 = dir.path().join("a.txt");
    let f2 = dir.path().join("b.txt");
    std::fs::write(&f1, "a").unwrap();
    std::fs::write(&f2, "b").unwrap();

    let entries = auto_mount::auto_mount_paths(
        &[],
        &[f1, f2],
        &[],
        &[],
        &[],
    );
    // Both files are in the same parent dir — should get a single mount.
    let mount_dirs: Vec<&PathBuf> = entries.iter().map(|e| &e.mount_dir).collect();
    assert_eq!(mount_dirs.len(), 1);
    assert_eq!(mount_dirs[0], dir.path());
}

#[test]
fn is_under_system_dirs() {
    use std::path::Path;
    assert!(auto_mount::is_under_system_dirs(Path::new("/usr/bin/gcc")));
    assert!(auto_mount::is_under_system_dirs(Path::new("/bin/sh")));
    assert!(!auto_mount::is_under_system_dirs(Path::new("/home/user/file")));
    assert!(!auto_mount::is_under_system_dirs(Path::new("/tmp/data")));
}

// ---- format_size_human / format_duration_human ----

#[test]
fn format_size_roundtrip() {
    assert_eq!(policy::format_size_human(512 * 1024 * 1024), "512M");
    assert_eq!(policy::format_size_human(2 * 1024 * 1024 * 1024), "2G");
    assert_eq!(policy::format_size_human(1024), "1K");
    assert_eq!(policy::format_size_human(0), "0");
}

#[test]
fn format_duration_roundtrip() {
    assert_eq!(policy::format_duration_human(Duration::from_secs(300)), "5m");
    assert_eq!(policy::format_duration_human(Duration::from_secs(3600)), "1h");
    assert_eq!(policy::format_duration_human(Duration::from_secs(5400)), "1h30m");
    assert_eq!(policy::format_duration_human(Duration::from_secs(90)), "1m30s");
}
