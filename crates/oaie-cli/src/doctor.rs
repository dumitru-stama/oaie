//! Doctor diagnostic types and probe logic.
//!
//! This module is part of the library crate so integration tests can call
//! `run_doctor()` directly. The CLI formatting lives in `commands/doctor.rs`.

use std::os::unix::fs::MetadataExt;

use oaie_core::config::OaieStore;
use oaie_db::OaieDb;
use oaie_sandbox::probe::SystemCaps;

// ── Public types ──

/// Status of a single diagnostic probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeStatus {
    /// Capability is present and working.
    Available,
    /// Capability works but has a non-critical recommendation.
    Advisory,
    /// Capability is not available on this system (optional feature).
    NotAvailable,
    /// Capability is required but broken — blocks execution.
    Broken,
}

/// A single diagnostic probe result.
#[derive(Clone, Debug)]
pub struct Probe {
    /// Short name of the probe (e.g. "User namespaces").
    pub name: &'static str,
    /// Status of the probe.
    pub status: ProbeStatus,
    /// Optional detail message (e.g. kernel version, blob count).
    pub detail: Option<String>,
    /// Optional remediation hint for Advisory/Broken probes.
    pub remediation: Option<String>,
}

/// Overall system status based on all probes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OverallStatus {
    /// All core probes available, system is ready.
    Ready,
    /// All core probes work; some have non-critical advisories.
    Advisory,
    /// One or more required probes are broken — execution will fail.
    Broken,
}

/// Storage summary statistics for the doctor report.
#[derive(Clone, Debug, Default)]
pub struct StorageSummary {
    /// Total number of runs in the database.
    pub run_count: u64,
    /// Number of days between the oldest and newest run (0 if <=1 run).
    pub span_days: u64,
    /// Total size of the store directory (CAS + runs + DB) in bytes.
    pub store_bytes: u64,
}

/// The complete doctor report.
#[derive(Clone, Debug)]
pub struct DoctorReport {
    /// OAIE version string.
    pub version: String,
    /// All probe results.
    pub probes: Vec<Probe>,
    /// Determined isolation level: "full", "partial", or "none".
    pub isolation_level: String,
    /// Available trace backends.
    pub trace_backends: Vec<String>,
    /// Overall system status.
    pub overall: OverallStatus,
    /// Storage summary, `None` if the store is not initialized.
    pub storage: Option<StorageSummary>,
}

// ── Public entry point (testable) ──

/// Run all diagnostic probes and build a doctor report.
///
/// `store` is `None` if the OAIE store is not initialized (init not run).
/// Namespace and kernel probes still run; store probes report Broken with
/// a "run oaie init" hint.
pub fn run_doctor(store: Option<&OaieStore>) -> DoctorReport {
    let caps = SystemCaps::detect();
    let mut probes = Vec::with_capacity(20);

    // 1–4. Namespace probes (all derive from user_ns).
    let (userns_probe, _userns_detail) = probe_user_namespaces(&caps);
    probes.push(userns_probe);
    probes.push(probe_mount_namespace(&caps));
    probes.push(probe_pid_namespace(&caps));
    probes.push(probe_net_namespace(&caps));

    // 5. ptrace scope.
    probes.push(probe_ptrace());

    // 6–7. Store probes (require initialized store).
    probes.push(probe_cas_store(store));
    probes.push(probe_sqlite(store));

    // 8. Kernel CVE check.
    probes.push(probe_kernel_cves(&caps));

    // 9. Store permissions.
    probes.push(probe_store_permissions(store));

    // 10. Landlock.
    probes.push(probe_landlock_status());

    // 11. Cgroup v2 availability.
    probes.push(probe_cgroup_v2());

    // 12. eBPF tracer.
    probes.push(probe_ebpf_tracer());

    // 13. Firecracker microVM.
    probes.push(probe_firecracker());

    // 14. Ping group range (needed for unprivileged ICMP with CAP_NET_RAW in sandbox).
    probes.push(probe_ping_group_range());

    // 15. Namespace headroom (current vs max, advisory if >80%).
    probes.push(probe_namespace_headroom(&caps));

    // 16. oaie-priv helper.
    probes.push(probe_oaie_priv());

    // 17. nftables availability (needed for network allowlist).
    probes.push(probe_nftables());

    // 18. IP forwarding (needed for network allowlist veth+NAT).
    probes.push(probe_ip_forward());

    // 19. nsenter availability (needed for nftables in sandbox netns).
    probes.push(probe_nsenter());

    // 20. Signing key availability.
    probes.push(probe_signing_keys(store));

    let isolation_level = determine_isolation_level(&probes);
    let overall = determine_overall_status(&probes);

    // Trace backends: ptrace is always available if user_ns works.
    let mut trace_backends = vec![];
    if caps.user_ns {
        trace_backends.push("ptrace".into());
    }
    if probes.iter().any(|p| p.name == "eBPF tracer" && p.status == ProbeStatus::Available) {
        trace_backends.push("ebpf".into());
    }

    let storage = store.and_then(compute_storage_summary);

    DoctorReport {
        version: env!("CARGO_PKG_VERSION").into(),
        probes,
        isolation_level,
        trace_backends,
        overall,
        storage,
    }
}

// ── Individual probes ──

fn probe_user_namespaces(caps: &SystemCaps) -> (Probe, Option<String>) {
    if caps.user_ns {
        let detail = caps
            .max_user_ns
            .map(|max| format!("max_user_namespaces={max}"));
        (
            Probe {
                name: "User namespaces",
                status: ProbeStatus::Available,
                detail,
                remediation: None,
            },
            None,
        )
    } else {
        let detail = diagnose_userns_failure();
        let remediation = userns_remediation(&detail);
        let d = detail.clone();
        (
            Probe {
                name: "User namespaces",
                status: ProbeStatus::Advisory,
                detail: Some(detail),
                remediation: Some(remediation),
            },
            Some(d),
        )
    }
}

fn probe_mount_namespace(caps: &SystemCaps) -> Probe {
    Probe {
        name: "Mount namespace",
        status: if caps.user_ns {
            ProbeStatus::Available
        } else {
            ProbeStatus::Advisory
        },
        detail: None,
        remediation: if caps.user_ns {
            None
        } else {
            Some("requires user namespaces".into())
        },
    }
}

fn probe_pid_namespace(caps: &SystemCaps) -> Probe {
    Probe {
        name: "PID namespace",
        status: if caps.user_ns {
            ProbeStatus::Available
        } else {
            ProbeStatus::Advisory
        },
        detail: None,
        remediation: if caps.user_ns {
            None
        } else {
            Some("requires user namespaces".into())
        },
    }
}

fn probe_net_namespace(caps: &SystemCaps) -> Probe {
    Probe {
        name: "Net namespace",
        status: if caps.user_ns {
            ProbeStatus::Available
        } else {
            ProbeStatus::Advisory
        },
        detail: None,
        remediation: if caps.user_ns {
            None
        } else {
            Some("requires user namespaces".into())
        },
    }
}

fn probe_ptrace() -> Probe {
    match std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
        Ok(val) => {
            let scope: u32 = val.trim().parse().unwrap_or(99);
            match scope {
                0 | 1 => Probe {
                    name: "ptrace",
                    status: ProbeStatus::Available,
                    detail: Some(format!("yama scope={scope}")),
                    remediation: None,
                },
                _ => Probe {
                    name: "ptrace",
                    status: ProbeStatus::Advisory,
                    detail: Some(format!("yama scope={scope}")),
                    remediation: Some(
                        "trace mode may not work. Set scope to 0 or 1:\n  \
                         sudo sysctl -w kernel.yama.ptrace_scope=1"
                            .into(),
                    ),
                },
            }
        }
        Err(_) => Probe {
            name: "ptrace",
            status: ProbeStatus::Available,
            detail: Some("yama not present (ptrace unrestricted)".into()),
            remediation: None,
        },
    }
}

fn probe_cas_store(store: Option<&OaieStore>) -> Probe {
    let Some(store) = store else {
        return Probe {
            name: "CAS store",
            status: ProbeStatus::Broken,
            detail: Some("store not initialized".into()),
            remediation: Some("run: oaie init".into()),
        };
    };

    if !store.cas_dir.exists() {
        return Probe {
            name: "CAS store",
            status: ProbeStatus::Broken,
            detail: Some("cas directory missing".into()),
            remediation: Some("run: oaie init".into()),
        };
    }

    let mut blob_count: u64 = 0;
    let mut total_size: u64 = 0;
    for entry in crate::walk::walk_dir(&store.cas_dir).into_iter().flatten() {
        if entry.is_file() {
            blob_count += 1;
            total_size += entry.metadata().len();
        }
    }

    let size_human = format_bytes(total_size);
    Probe {
        name: "CAS store",
        status: ProbeStatus::Available,
        detail: Some(format!("{blob_count} blobs, {size_human}")),
        remediation: None,
    }
}

fn probe_sqlite(store: Option<&OaieStore>) -> Probe {
    let Some(store) = store else {
        return Probe {
            name: "SQLite",
            status: ProbeStatus::Broken,
            detail: Some("store not initialized".into()),
            remediation: Some("run: oaie init".into()),
        };
    };

    match OaieDb::open(&store.db_path) {
        Ok(db) => {
            if let Err(e) = db.initialize() {
                return Probe {
                    name: "SQLite",
                    status: ProbeStatus::Broken,
                    detail: Some(format!("initialize failed: {e}")),
                    remediation: Some("database may be corrupt".into()),
                };
            }
            match db.check_health() {
                Ok(health) => Probe {
                    name: "SQLite",
                    status: ProbeStatus::Available,
                    detail: Some(format!(
                        "{} runs, WAL={}",
                        health.run_count,
                        if health.wal_mode { "yes" } else { "no" }
                    )),
                    remediation: None,
                },
                Err(e) => Probe {
                    name: "SQLite",
                    status: ProbeStatus::Broken,
                    detail: Some(format!("health check failed: {e}")),
                    remediation: None,
                },
            }
        }
        Err(e) => Probe {
            name: "SQLite",
            status: ProbeStatus::Broken,
            detail: Some(format!("cannot open: {e}")),
            remediation: Some("database may be corrupt or locked".into()),
        },
    }
}

/// Probe for known kernel CVEs affecting namespace isolation.
pub fn probe_kernel_cves(caps: &SystemCaps) -> Probe {
    let (major, minor) = caps.kernel_version;
    let mut cves = Vec::new();

    let patch = read_kernel_patch().unwrap_or(0);

    if (major, minor) < (4, 8) || (major == 4 && minor == 8 && patch < 3) {
        cves.push("CVE-2016-5195 (Dirty COW)");
    }
    if (major == 5 && (8..=15).contains(&minor))
        || (major == 5 && minor == 16 && patch < 11)
    {
        cves.push("CVE-2022-0847 (Dirty Pipe)");
    }
    if (major, minor) < (6, 2) {
        cves.push("CVE-2023-0386 (OverlayFS)");
    }
    if (major, minor) < (5, 16) || (major == 5 && minor == 16 && patch < 2) {
        cves.push("CVE-2022-0185 (fsconfig)");
    }
    if (major, minor) < (5, 17) {
        cves.push("CVE-2022-0492 (cgroup escape)");
    }

    if cves.is_empty() {
        Probe {
            name: "Kernel CVEs",
            status: ProbeStatus::Available,
            detail: Some(format!("kernel {major}.{minor}.{patch} — no known CVEs")),
            remediation: None,
        }
    } else {
        Probe {
            name: "Kernel CVEs",
            status: ProbeStatus::Advisory,
            detail: Some(format!(
                "kernel {major}.{minor}.{patch} — {} known CVE(s): {}",
                cves.len(),
                cves.join(", ")
            )),
            remediation: Some("upgrade kernel to latest stable".into()),
        }
    }
}

fn probe_store_permissions(store: Option<&OaieStore>) -> Probe {
    let Some(store) = store else {
        return Probe {
            name: "Store permissions",
            status: ProbeStatus::Broken,
            detail: Some("store not initialized".into()),
            remediation: Some("run: oaie init".into()),
        };
    };

    match std::fs::metadata(&store.root) {
        Ok(meta) => {
            let mode = meta.mode() & 0o777;
            if mode == 0o700 {
                Probe {
                    name: "Store permissions",
                    status: ProbeStatus::Available,
                    detail: Some(format!("0o{mode:03o}")),
                    remediation: None,
                }
            } else {
                Probe {
                    name: "Store permissions",
                    status: ProbeStatus::Advisory,
                    detail: Some(format!("0o{mode:03o} (expected 0o700)")),
                    remediation: Some(format!("chmod 700 {}", store.root.display())),
                }
            }
        }
        Err(e) => Probe {
            name: "Store permissions",
            status: ProbeStatus::Broken,
            detail: Some(format!("cannot stat: {e}")),
            remediation: None,
        },
    }
}

/// Probe Landlock LSM availability.
pub fn probe_landlock_status() -> Probe {
    if oaie_sandbox::landlock::probe_landlock() {
        Probe {
            name: "Landlock",
            status: ProbeStatus::Available,
            detail: Some("filesystem restriction active".into()),
            remediation: None,
        }
    } else {
        Probe {
            name: "Landlock",
            status: ProbeStatus::NotAvailable,
            detail: Some("kernel < 5.13 or Landlock disabled".into()),
            remediation: None,
        }
    }
}

/// Probe `net.ipv4.ping_group_range` sysctl.
///
/// When running with `--net` (sharing the host network namespace), unprivileged
/// ICMP sockets require the process GID to fall within the kernel's
/// `ping_group_range`.  Inside a user namespace, the sandbox maps the user's
/// GID to 65534 (nobody).  If the sysctl range doesn't include 65534 (or is
/// set to "1 0" meaning "nobody"), `ping` will fail even with CAP_NET_RAW
/// retained.
///
/// This does NOT affect isolated-net-namespace runs (`--net` omitted) where
/// the sandbox owns the network namespace and CAP_NET_RAW is sufficient.
pub fn probe_ping_group_range() -> Probe {
    match std::fs::read_to_string("/proc/sys/net/ipv4/ping_group_range") {
        Ok(val) => {
            let parts: Vec<&str> = val.split_whitespace().collect();
            if parts.len() != 2 {
                return Probe {
                    name: "Ping group range",
                    status: ProbeStatus::Advisory,
                    detail: Some(format!("unexpected format: {}", val.trim())),
                    remediation: Some(
                        "expected two integers in /proc/sys/net/ipv4/ping_group_range".into(),
                    ),
                };
            }

            let lo: i64 = parts[0].parse().unwrap_or(-1);
            let hi: i64 = parts[1].parse().unwrap_or(-1);

            if lo == 1 && hi == 0 {
                // "1 0" is the kernel default meaning "nobody can use DGRAM ICMP".
                Probe {
                    name: "Ping group range",
                    status: ProbeStatus::Advisory,
                    detail: Some("disabled (1 0)".into()),
                    remediation: Some(
                        "sandboxed `ping` with --net will fail. To enable:\n  \
                         sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"\n  \
                         This only allows DGRAM ICMP echo (not raw sockets)."
                            .into(),
                    ),
                }
            } else if lo <= 0 && hi >= 65534 {
                // Range includes GID 0 (host) and 65534 (sandbox nobody).
                Probe {
                    name: "Ping group range",
                    status: ProbeStatus::Available,
                    detail: Some(format!("{lo} {hi}")),
                    remediation: None,
                }
            } else {
                // Some range exists but may not cover sandbox GID 65534.
                Probe {
                    name: "Ping group range",
                    status: ProbeStatus::Advisory,
                    detail: Some(format!("{lo} {hi} — may not cover sandbox GID 65534")),
                    remediation: Some(
                        "sandboxed `ping` with --net may fail. To widen the range:\n  \
                         sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\""
                            .into(),
                    ),
                }
            }
        }
        Err(_) => Probe {
            name: "Ping group range",
            status: ProbeStatus::NotAvailable,
            detail: Some("sysctl not found (non-Linux or /proc not mounted)".into()),
            remediation: None,
        },
    }
}

/// Probe namespace usage headroom: current vs max user namespaces.
///
/// Advisory if usage exceeds 80% — at that point, concurrent sandbox
/// launches risk ENOSPC failures. NotAvailable on kernels that don't
/// expose `/proc/sys/user/nr_user_namespaces` (pre-6.7).
fn probe_namespace_headroom(caps: &SystemCaps) -> Probe {
    match (caps.current_user_ns, caps.max_user_ns) {
        (Some(current), Some(max)) if max > 0 => {
            let usage_pct = (current as f64 / max as f64) * 100.0;
            if usage_pct > 80.0 {
                Probe {
                    name: "Namespace headroom",
                    status: ProbeStatus::Advisory,
                    detail: Some(format!("{current}/{max} ({usage_pct:.0}%)")),
                    remediation: Some(format!(
                        "namespace usage high. Increase with:\n  \
                         sudo sysctl -w user.max_user_namespaces={}",
                        max * 2
                    )),
                }
            } else {
                Probe {
                    name: "Namespace headroom",
                    status: ProbeStatus::Available,
                    detail: Some(format!("{current}/{max} ({usage_pct:.0}%)")),
                    remediation: None,
                }
            }
        }
        (_, Some(max)) => Probe {
            name: "Namespace headroom",
            status: ProbeStatus::Available,
            detail: Some(format!("max={max}, current usage unknown (kernel < 6.7)")),
            remediation: None,
        },
        _ => Probe {
            name: "Namespace headroom",
            status: ProbeStatus::NotAvailable,
            detail: Some("max_user_namespaces not readable".into()),
            remediation: None,
        },
    }
}

/// Probe cgroup v2 availability and creation methods.
///
/// Checks for unified cgroup v2 hierarchy and whether scopes can be created
/// via systemd-run or oaie-priv.
fn probe_cgroup_v2() -> Probe {
    let caps = oaie_cgroup::detect::detect();

    if !caps.unified_v2 {
        return Probe {
            name: "Cgroup v2",
            status: ProbeStatus::NotAvailable,
            detail: Some("cgroup v2 unified hierarchy not mounted".into()),
            remediation: Some(
                "cgroup v2 required for per-run resource isolation. \
                 Check: mount -t cgroup2 | grep -q cgroup2"
                    .into(),
            ),
        };
    }

    let method = if caps.systemd_run {
        "systemd-run"
    } else if caps.oaie_priv {
        "oaie-priv"
    } else {
        return Probe {
            name: "Cgroup v2",
            status: ProbeStatus::Advisory,
            detail: Some(format!(
                "v2 available, controllers: [{}], but no creation method",
                caps.controllers.join(", ")
            )),
            remediation: Some(
                "resource limits will use advisory rlimits only. \
                 For cgroup isolation, ensure systemd user session is running \
                 or install oaie-priv helper."
                    .into(),
            ),
        };
    };

    // Check that required controllers are available.
    let required = ["memory", "pids"];
    let missing: Vec<_> = required
        .iter()
        .filter(|c| !caps.controllers.iter().any(|have| have == **c))
        .collect();

    if !missing.is_empty() {
        return Probe {
            name: "Cgroup v2",
            status: ProbeStatus::Advisory,
            detail: Some(format!(
                "method: {method}, controllers: [{}], missing required: [{}]",
                caps.controllers.join(", "),
                missing.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", ")
            )),
            remediation: Some(format!(
                "enable missing controllers: {}",
                missing.iter().map(|c| format!("+{c}")).collect::<Vec<_>>().join(" ")
            )),
        };
    }

    Probe {
        name: "Cgroup v2",
        status: ProbeStatus::Available,
        detail: Some(format!(
            "method: {method}, controllers: [{}]",
            caps.controllers.join(", ")
        )),
        remediation: None,
    }
}

/// Probe oaie-priv privileged helper availability.
fn probe_oaie_priv() -> Probe {
    let priv_path = std::path::Path::new("/usr/lib/oaie/oaie-priv");
    if !priv_path.exists() {
        return Probe {
            name: "oaie-priv helper",
            status: ProbeStatus::NotAvailable,
            detail: Some("not installed at /usr/lib/oaie/oaie-priv".into()),
            remediation: Some(
                "optional: install oaie-priv for cgroup isolation without systemd. \
                 After installation: sudo setcap cap_sys_admin=ep /usr/lib/oaie/oaie-priv"
                    .into(),
            ),
        };
    }

    match oaie_cgroup::priv_client::ping() {
        Ok(true) => Probe {
            name: "oaie-priv helper",
            status: ProbeStatus::Available,
            detail: Some("installed and responding".into()),
            remediation: None,
        },
        Ok(false) | Err(_) => Probe {
            name: "oaie-priv helper",
            status: ProbeStatus::Advisory,
            detail: Some("installed but not responding".into()),
            remediation: Some(
                "start the oaie-priv service or check socket at /run/oaie/oaie-priv.sock"
                    .into(),
            ),
        },
    }
}

/// Probe eBPF tracer availability.
///
/// Checks kernel version (>= 5.8 for ring buffer), BTF availability,
/// and oaie-priv capabilities. All prerequisites must be met for eBPF tracing.
fn probe_ebpf_tracer() -> Probe {
    let caps = oaie_cgroup::ebpf_detect::detect_ebpf();

    if caps.available {
        return Probe {
            name: "eBPF tracer",
            status: ProbeStatus::Available,
            detail: Some("kernel 5.8+, BTF present, oaie-priv has CAP_BPF".into()),
            remediation: None,
        };
    }

    // Build a list of missing prerequisites.
    let mut missing = Vec::new();
    if !caps.kernel_supports_ringbuf {
        missing.push("kernel < 5.8 (no ring buffer)");
    }
    if !caps.btf_available {
        missing.push("BTF not available (/sys/kernel/btf/vmlinux missing)");
    }
    if !caps.priv_has_bpf_caps {
        missing.push("oaie-priv lacks CAP_BPF/CAP_PERFMON");
    }

    Probe {
        name: "eBPF tracer",
        status: ProbeStatus::NotAvailable,
        detail: Some(format!("missing: {}", missing.join(", "))),
        remediation: Some(
            "for eBPF tracing: kernel >= 5.8, BTF enabled, and \
             sudo setcap cap_sys_admin,cap_bpf,cap_perfmon=ep /usr/lib/oaie/oaie-priv"
                .into(),
        ),
    }
}

/// Probe Firecracker microVM prerequisites: binary, /dev/kvm, guest assets.
fn probe_firecracker() -> Probe {
    let mut issues = Vec::new();

    // Check for firecracker binary.
    let mut fc_search: Vec<std::path::PathBuf> = vec![
        "/usr/local/bin/firecracker".into(),
        "/usr/bin/firecracker".into(),
    ];
    // Also check $HOME/tools/firecracker (common developer setup).
    if let Ok(home) = std::env::var("HOME") {
        fc_search.insert(0, std::path::PathBuf::from(home).join("tools/firecracker"));
    }
    let fc_found = fc_search.iter().any(|p| p.exists()) || which_exists("firecracker");

    if !fc_found {
        issues.push("firecracker binary not found");
    }

    // Check /dev/kvm.
    let kvm_ok = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok();
    if !kvm_ok {
        issues.push("/dev/kvm not accessible");
    }

    // Check guest assets.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let assets_dir = std::path::PathBuf::from(&home).join(".oaie/firecracker");
    let kernel_ok = assets_dir.join("vmlinux").exists();
    let rootfs_ok = assets_dir.join("rootfs.ext4").exists();
    let guest_ok = assets_dir.join("oaie-guest").exists();

    if !kernel_ok {
        issues.push("kernel image missing (~/.oaie/firecracker/vmlinux)");
    }
    if !rootfs_ok {
        issues.push("rootfs missing (~/.oaie/firecracker/rootfs.ext4)");
    }
    if !guest_ok {
        issues.push("guest agent missing (~/.oaie/firecracker/oaie-guest)");
    }

    if issues.is_empty() {
        Probe {
            name: "Firecracker",
            status: ProbeStatus::Available,
            detail: Some("binary, /dev/kvm, and guest assets present".into()),
            remediation: None,
        }
    } else {
        Probe {
            name: "Firecracker",
            status: ProbeStatus::NotAvailable,
            detail: Some(format!("missing: {}", issues.join(", "))),
            remediation: Some(
                "install Firecracker, ensure /dev/kvm access, run `oaie firecracker init`"
                    .into(),
            ),
        }
    }
}

/// Check if an executable is on PATH.
fn which_exists(name: &str) -> bool {
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            let candidate = std::path::Path::new(dir).join(name);
            if candidate.exists() {
                return true;
            }
        }
    }
    false
}

/// Probe nftables availability (needed for `--net=allow:...` network allowlist mode).
fn probe_nftables() -> Probe {
    match std::process::Command::new("nft").arg("--version").output() {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            let ver_str = version.trim().to_string();
            Probe {
                name: "nftables",
                status: ProbeStatus::Available,
                detail: Some(ver_str),
                remediation: None,
            }
        }
        _ => Probe {
            name: "nftables",
            status: ProbeStatus::NotAvailable,
            detail: Some("nft binary not found".into()),
            remediation: Some(
                "network allowlist (--net=allow:...) requires nftables. \
                 Install: sudo apt install nftables"
                    .into(),
            ),
        },
    }
}

/// Probe IPv4 forwarding (needed for network allowlist veth+NAT mode).
fn probe_ip_forward() -> Probe {
    match std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward") {
        Ok(val) if val.trim() == "1" => Probe {
            name: "IP forwarding",
            status: ProbeStatus::Available,
            detail: Some("net.ipv4.ip_forward=1".into()),
            remediation: None,
        },
        Ok(_) => Probe {
            name: "IP forwarding",
            status: ProbeStatus::Advisory,
            detail: Some("net.ipv4.ip_forward=0".into()),
            remediation: Some(
                "network allowlist requires IP forwarding. Enable:\n  \
                 sudo sysctl -w net.ipv4.ip_forward=1"
                    .into(),
            ),
        },
        Err(_) => Probe {
            name: "IP forwarding",
            status: ProbeStatus::NotAvailable,
            detail: Some("sysctl not readable".into()),
            remediation: None,
        },
    }
}

/// Probe nsenter availability (needed for applying nftables inside sandbox netns).
fn probe_nsenter() -> Probe {
    match std::process::Command::new("nsenter").arg("--version").output() {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            let ver_str = version.trim().to_string();
            Probe {
                name: "nsenter",
                status: ProbeStatus::Available,
                detail: Some(ver_str),
                remediation: None,
            }
        }
        _ => Probe {
            name: "nsenter",
            status: ProbeStatus::NotAvailable,
            detail: Some("nsenter binary not found".into()),
            remediation: Some(
                "network allowlist (--net=allow:...) requires nsenter. \
                 Install: sudo apt install util-linux"
                    .into(),
            ),
        },
    }
}

/// Probe #20: Signing key availability.
fn probe_signing_keys(store: Option<&OaieStore>) -> Probe {
    let Some(store) = store else {
        return Probe {
            name: "Signing key",
            status: ProbeStatus::NotAvailable,
            detail: Some("Store not initialized".into()),
            remediation: Some("Run `oaie init` first".into()),
        };
    };

    let keys = crate::signing::list_keys(&store.keys_dir).unwrap_or_default();
    let has_default = store
        .signing
        .as_ref()
        .and_then(|s| s.default_key.as_ref())
        .is_some();

    match (keys.len(), has_default) {
        (0, _) => Probe {
            name: "Signing key",
            status: ProbeStatus::NotAvailable,
            detail: Some("No signing keys".into()),
            remediation: Some(
                "Generate a key with `oaie key generate --label <name>`".into(),
            ),
        },
        (n, true) => Probe {
            name: "Signing key",
            status: ProbeStatus::Available,
            detail: Some(format!("{n} key(s), default configured")),
            remediation: None,
        },
        (n, false) => Probe {
            name: "Signing key",
            status: ProbeStatus::Advisory,
            detail: Some(format!("{n} key(s), no default")),
            remediation: Some(
                "Use `--sign <key>` or set [signing].default_key in config.toml".into(),
            ),
        },
    }
}

// ── Diagnostic helpers ──

fn diagnose_userns_failure() -> String {
    if oaie_sandbox::probe::is_inside_container() {
        return "running inside a container (Docker/Podman/LXC)".into();
    }

    if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        if release.contains("Microsoft") && !release.contains("microsoft-standard") {
            return "WSL1 detected (no namespace support)".into();
        }
    }

    if let Ok(val) = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        if val.trim() == "0" {
            return "unprivileged_userns_clone=0".into();
        }
    }

    if let Ok(val) =
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    {
        if val.trim() == "1" {
            return "AppArmor restricts unprivileged user namespaces".into();
        }
    }

    if let Ok(val) = std::fs::read_to_string("/proc/sys/user/max_user_namespaces") {
        if val.trim() == "0" {
            return "max_user_namespaces=0".into();
        }
    }

    "unknown cause — check kernel config and LSM settings".into()
}

fn userns_remediation(detail: &str) -> String {
    if detail.contains("container") {
        "run the container with --privileged or --security-opt seccomp=unconfined".into()
    } else if detail.contains("WSL1") {
        "upgrade to WSL2: wsl --set-version <distro> 2".into()
    } else if detail.contains("unprivileged_userns_clone") {
        "sudo sysctl -w kernel.unprivileged_userns_clone=1".into()
    } else if detail.contains("AppArmor") {
        "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0".into()
    } else if detail.contains("max_user_namespaces=0") {
        "sudo sysctl -w user.max_user_namespaces=65536".into()
    } else {
        "check kernel config: CONFIG_USER_NS=y, no LSM restrictions".into()
    }
}

fn determine_isolation_level(probes: &[Probe]) -> String {
    // All namespace probes (mount, PID, net) derive from user_ns — if user_ns
    // is Available then all namespaces are Available ("full"), otherwise none
    // are ("none"). There is no "partial" state in the current probe design.
    let userns_ok = probes
        .iter()
        .any(|p| p.name == "User namespaces" && p.status == ProbeStatus::Available);

    let cgroup_ok = probes
        .iter()
        .any(|p| p.name == "Cgroup v2" && p.status == ProbeStatus::Available);

    if userns_ok {
        if cgroup_ok {
            "full (cgroup v2 enforced)".into()
        } else {
            "full".into()
        }
    } else {
        "none".into()
    }
}

/// Determine overall status: Broken if any Broken, Advisory if core probes have notes.
pub fn determine_overall_status(probes: &[Probe]) -> OverallStatus {
    if probes.iter().any(|p| p.status == ProbeStatus::Broken) {
        return OverallStatus::Broken;
    }

    let core_advisory = probes.iter().any(|p| {
        p.status == ProbeStatus::Advisory
            && (p.name == "User namespaces"
                || p.name == "ptrace"
                || p.name == "Kernel CVEs"
                || p.name == "Store permissions")
    });

    if core_advisory {
        OverallStatus::Advisory
    } else {
        OverallStatus::Ready
    }
}

/// Compute storage summary: run count, date span, and total store size.
fn compute_storage_summary(store: &OaieStore) -> Option<StorageSummary> {
    let db = OaieDb::open(&store.db_path).ok()?;
    let runs = db.list_all_runs().ok()?;

    let run_count = runs.len() as u64;

    // Date span: difference between oldest and newest run.
    let span_days = if runs.len() >= 2 {
        // list_all_runs returns most recent first.
        let newest = &runs[0].created;
        let oldest = &runs[runs.len() - 1].created;
        (*newest - *oldest).num_days().unsigned_abs()
    } else {
        0
    };

    // Total store directory size (walk everything under store root).
    let mut store_bytes: u64 = 0;
    for entry in crate::walk::walk_dir(&store.root).into_iter().flatten() {
        if entry.is_file() {
            store_bytes += entry.metadata().len();
        }
    }

    Some(StorageSummary {
        run_count,
        span_days,
        store_bytes,
    })
}

fn read_kernel_patch() -> Option<u32> {
    let info = nix::sys::utsname::uname().ok()?;
    let release = info.release().to_string_lossy();
    let mut parts = release.split('.');
    let _major = parts.next()?;
    let _minor = parts.next()?;
    let patch_str = parts.next()?;
    patch_str
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .and_then(|s| s.parse().ok())
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!(
            "{:.2} GiB",
            bytes as f64 / (1024.0 * 1024.0 * 1024.0)
        )
    }
}
