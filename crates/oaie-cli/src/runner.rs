//! Execution engine: spawns a command, captures output, hashes everything,
//! builds a manifest and report, stores in CAS, and indexes in the DB.
//!
//! Lives in oaie-cli (not oaie-core) because it depends on both oaie-cas
//! and oaie-db, and oaie-core must stay lightweight.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Once;
use std::time::{Duration, Instant};

/// Monotonic signal counter incremented by SIGINT/SIGTERM handler.
/// Each runner captures a baseline at start and checks if the counter has
/// advanced — concurrent runners don't interfere because each compares
/// against its own baseline.
static SIGNAL_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Ensures signal handlers are installed exactly once per process.
static SIGNAL_INIT: Once = Once::new();

/// Signal handler that increments the global signal counter.
/// Only uses async-signal-safe operations (atomic fetch_add).
extern "C" fn signal_handler(_sig: libc::c_int) {
    SIGNAL_COUNTER.fetch_add(1, Ordering::SeqCst);
}

/// Install SIGINT and SIGTERM handlers (once per process) and return the
/// current signal counter value as a baseline. Callers check
/// `signal_received_since(baseline)` to detect signals targeted at their run.
///
/// Set `OAIE_NO_SIGNAL_HANDLERS=1` to skip installation — used by the test
/// harness to avoid overriding the default SIGINT handler (which would make
/// the test binary immune to Ctrl+C).
pub fn install_signal_handlers() -> u64 {
    SIGNAL_INIT.call_once(|| {
        // Allow tests to skip signal handler installation to preserve the
        // test harness's default Ctrl+C behavior.
        if std::env::var_os("OAIE_NO_SIGNAL_HANDLERS").is_some() {
            return;
        }

        use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};

        let action = SigAction::new(
            SigHandler::Handler(signal_handler),
            SaFlags::SA_RESTART,
            SigSet::empty(),
        );

        // SAFETY: signal_handler only performs an atomic fetch_add, which is
        // async-signal-safe. sigaction is the POSIX-specified API for
        // installing signal handlers.
        if unsafe { sigaction(Signal::SIGINT, &action) }.is_err() {
            oaie_core::log_warn!("could not register SIGINT handler");
        }
        if unsafe { sigaction(Signal::SIGTERM, &action) }.is_err() {
            oaie_core::log_warn!("could not register SIGTERM handler");
        }
    });

    SIGNAL_COUNTER.load(Ordering::SeqCst)
}

/// Check whether any signal was received after `baseline` was captured.
/// Uses `Acquire` ordering to pair with the `SeqCst` store in the signal
/// handler — `Relaxed` would be incorrect on weakly-ordered architectures
/// (ARM, RISC-V) where the load could observe a stale value.
pub fn signal_received_since(baseline: u64) -> bool {
    SIGNAL_COUNTER.load(Ordering::Acquire) > baseline
}

use chrono::Utc;

use oaie_cas::store::CasStore;
use oaie_core::artifact::{ArtifactRef, ArtifactType, Hash};
use oaie_core::config::OaieStore;
use oaie_core::error::{OaieError, Result};
use oaie_core::job::{JobSpec, TraceMode};
use oaie_core::manifest::{
    IsolationInfo, IsolationLevel, LimitsEnforced, Manifest, PolicyInfo, TraceInfo,
};
use oaie_core::policy;
use oaie_core::run_dir::RunDir;
use oaie_core::run_id::RunId;
use oaie_db::{ArtifactRecord, OaieDb, RunRecord, RunStatus};
use oaie_observe::{
    ChunkedEventWriter, EventDetail, EventType, OaieEvent, StreamingSummarizer, TraceSummary,
};
use oaie_sandbox::probe::SystemCaps;

use crate::policy_resolve::ResolvedPolicy;

/// Map a TraceMode to the backend name used in manifests and event logs.
fn trace_backend_name(mode: &TraceMode) -> &'static str {
    match mode {
        TraceMode::Off => "none",
        TraceMode::Strace | TraceMode::Ptrace => "ptrace",
        TraceMode::Ebpf => "ebpf",
        TraceMode::Auto => "ptrace", // Fallback — Auto should be resolved before reaching here.
    }
}

/// Resolve `TraceMode::Auto` to a concrete backend based on system capabilities.
///
/// eBPF requires cgroup isolation (for per-run filtering). If cgroups are
/// unavailable or eBPF prerequisites aren't met, falls back to ptrace.
fn resolve_trace_mode(mode: TraceMode, cgroup_available: bool) -> TraceMode {
    match mode {
        TraceMode::Auto => {
            if cgroup_available && oaie_cgroup::ebpf_detect::detect_ebpf().available {
                TraceMode::Ebpf
            } else {
                TraceMode::Ptrace
            }
        }
        TraceMode::Ebpf if !cgroup_available => {
            oaie_core::log_warn!(
                "eBPF tracing requires cgroup isolation; falling back to ptrace"
            );
            TraceMode::Ptrace
        }
        other => other,
    }
}

/// Execution engine: orchestrates the full run pipeline.
///
/// Owns the CAS store and DB connection. Created once per `oaie run` invocation.
pub struct Runner {
    /// Store paths — used for resolving run directories, sandbox setup, etc.
    store: OaieStore,
    /// Content-addressed blob store for hashing and storing artifacts.
    cas: CasStore,
    /// SQLite index for run metadata and artifact records.
    db: OaieDb,
}

/// Result of a completed run (tool executed, even if exit code was nonzero).
#[derive(Debug)]
pub struct RunResult {
    /// Unique identifier for this run.
    pub run_id: RunId,
    /// Process exit code (-1 if killed by signal).
    pub exit_code: i32,
    /// Wall-clock duration of the run.
    pub duration: Duration,
    /// BLAKE3 hash of captured stdout.
    pub stdout_hash: Hash,
    /// Size of captured stdout in bytes.
    pub stdout_size: u64,
    /// BLAKE3 hash of captured stderr.
    pub stderr_hash: Hash,
    /// Size of captured stderr in bytes.
    pub stderr_size: u64,
    /// Output files collected from the output directory.
    pub output_artifacts: Vec<ArtifactRef>,
    /// BLAKE3 hash of the manifest stored in CAS.
    pub manifest_hash: Hash,
    /// What isolation level was applied to this run.
    pub isolation_level: IsolationLevel,
    /// Resource accounting from cgroup v2 (if active).
    pub resources: Option<oaie_core::manifest::ResourceInfo>,
    /// Whether cgroup limits were enforced for this run.
    pub cgroup_enforced: bool,
    /// Trace summary (present when tracing was enabled).
    pub trace_summary: Option<TraceSummary>,
    /// Network mode used for this run (for structured output).
    pub network_mode: oaie_core::policy::NetworkMode,
    /// Whether interactive PTY mode was used.
    pub interactive: bool,
    /// Signer label if the manifest was signed (e.g. "work-laptop (a1b2c3d4..)").
    pub signed_by: Option<String>,
}

impl Runner {
    /// Create a new Runner, opening the CAS and DB from the store.
    ///
    /// Performs lightweight startup cleanup:
    /// - Removes stale CAS temp files (>1 hour old) from crashed writes.
    /// - Removes empty stale sandbox dirs from `/tmp` (>5 min old).
    pub fn new(store: OaieStore) -> Result<Self> {
        let cas = CasStore::new(store.cas_dir.clone(), store.hash_algorithm);
        let db = OaieDb::open(&store.db_path)?;

        // Best-effort cleanup of stale temp files from crashed writes.
        let _ = cas.cleanup_temps();

        // Best-effort cleanup of stale sandbox mount-point directories.
        cleanup_stale_sandbox_dirs();

        Ok(Self { store, cas, db })
    }

    /// Execute a job: spawn, capture, hash, manifest, report, DB index.
    ///
    /// `policy`: resolved policy with concrete limits, mounts, and deny paths.
    /// `quiet`: if true, suppress tool output to terminal (still captured to file).
    /// `sign_key`: optional key ID/label for Ed25519 manifest signing.
    pub fn execute(&self, job: &JobSpec, policy: &ResolvedPolicy, quiet: bool, sign_key: Option<&str>) -> Result<RunResult> {
        let run_id = RunId::new();
        let run_dir = RunDir::create(&self.store.runs_dir, &run_id)?;
        let out_dir = prepare_output_dir(job, &run_id)?;

        // 0. Determine isolation level based on backend choice.
        //
        // BackendKind is the primary dispatch key:
        //   Bare       → no isolation
        //   Namespace  → full namespace isolation (requires user namespaces)
        //   Firecracker → microVM isolation (requires /dev/kvm + assets)
        let (isolation_level, namespaces) = match job.backend {
            oaie_core::backend::BackendKind::Bare => {
                (IsolationLevel::None, vec![])
            }
            oaie_core::backend::BackendKind::Firecracker => {
                // Firecracker provides its own isolation — no host namespaces needed.
                (IsolationLevel::MicroVM, vec![])
            }
            oaie_core::backend::BackendKind::Namespace => {
                if job.no_isolation {
                    (IsolationLevel::None, vec![])
                } else {
                    let caps = SystemCaps::detect();
                    if let Some(warning) = caps.namespace_headroom_warning() {
                        oaie_core::log_warn!("{warning}");
                    }
                    match caps.isolation_level() {
                        IsolationLevel::Full => {
                            let mut ns = vec![
                                "user".into(), "mount".into(), "pid".into(),
                                "ipc".into(), "uts".into(), "cgroup".into(),
                            ];
                            if policy.network.needs_netns() {
                                ns.push("net".into());
                            }
                            (IsolationLevel::Full, ns)
                        }
                        _ => {
                            let hint = caps.remediation_hint().unwrap_or_default();
                            return Err(OaieError::SandboxError(format!(
                                "namespace isolation unavailable on this system. \
                                 Use --no-isolation to run without sandboxing, \
                                 or --backend=bare for no isolation.\n{hint}"
                            )));
                        }
                    }
                }
            }
        };

        // 1. Record run start in database.
        self.db.insert_run(&RunRecord {
            run_id: run_id.clone(),
            created: Utc::now(),
            command: job.command.clone(),
            exit_code: None,
            duration_ms: None,
            isolation: isolation_level.to_string(),
            status: RunStatus::Running,
            manifest_hash: None,
            error_message: None,
        })?;

        // Effective timeout: CLI/policy timeout, falling back to policy max_time.
        let effective_timeout = policy.timeout.or(Some(policy.max_time));

        // 1b. Create chunked event writer if tracing is enabled.
        // Resolve Auto → Ebpf/Ptrace based on cgroup availability.
        let cgroup_caps = oaie_cgroup::detect::detect();
        let cgroup_available = cgroup_caps.systemd_run || cgroup_caps.oaie_priv;
        let resolved_trace = resolve_trace_mode(job.trace.clone(), cgroup_available);
        let backend_name = trace_backend_name(&resolved_trace);
        let mut event_writer = if resolved_trace != TraceMode::Off {
            let writer = ChunkedEventWriter::new(
                &run_dir.path,
                self.cas.clone(),
                &run_id.full(),
                backend_name,
                self.store.hash_algorithm,
            )?;
            Some(writer)
        } else {
            None
        };

        // Write RunStart event before execution.
        if let Some(ref mut writer) = event_writer {
            writer.write_event(OaieEvent {
                ts_ns: 0,
                event_type: EventType::RunStart,
                pid: 0,
                ppid: None,
                detail: EventDetail::RunLifecycle {
                    status: "started".into(),
                    command: Some(job.command.clone()),
                    exit_code: None,
                },
                hash_prev: String::new(),
            })?;
        }

        // 2. Execute the command — dispatched by backend and isolation level.
        // When tracing is enabled and sandboxed, the event writer is passed to
        // the PtraceTracer (or EbpfTracer) which owns it during the trace loop.
        // It's returned after the child exits so we can write RunEnd and finalize.
        //
        // Firecracker metadata, populated when the firecracker backend runs.
        #[allow(unused_mut)]
        let mut fc_version: Option<String> = None;
        #[allow(unused_mut)]
        let mut fc_kernel: Option<String> = None;
        #[allow(unused_mut)]
        let mut fc_rootfs: Option<String> = None;

        let (exit_code, duration, mut event_writer, cgroup_info, run_resources, cgroup_enforced, dropped_events) =
            match job.backend {
                oaie_core::backend::BackendKind::Namespace => {
                    // Namespace backend (default): full sandbox with namespaces + seccomp.
                    // Also used when --no-isolation demotes to bare-like behavior
                    // (isolation_level will be None, but spawn_sandboxed_and_capture
                    // handles that internally).
                    if isolation_level == IsolationLevel::Full && job.interactive {
                        // Interactive PTY mode — dispatch to the interactive backend.
                        match crate::backend_interactive::spawn_interactive_and_capture(job, policy, &run_dir, &out_dir, &run_id, effective_timeout, event_writer, &resolved_trace) {
                            Ok(sr) => (sr.exit_code, sr.duration, sr.event_writer, sr.cgroup_info, sr.resources, sr.cgroup_enforced, sr.dropped_events),
                            Err(e) => {
                                self.db.fail_run(&run_id, &e.to_string())?;
                                return Err(e);
                            }
                        }
                    } else if isolation_level == IsolationLevel::Full {
                        match crate::backend_namespace::spawn_sandboxed_and_capture(job, policy, &run_dir, &out_dir, &run_id, effective_timeout, quiet, event_writer, &resolved_trace) {
                            Ok(sr) => (sr.exit_code, sr.duration, sr.event_writer, sr.cgroup_info, sr.resources, sr.cgroup_enforced, sr.dropped_events),
                            Err(e) => {
                                self.db.fail_run(&run_id, &e.to_string())?;
                                return Err(e);
                            }
                        }
                    } else if job.interactive {
                        // Defense-in-depth: interactive mode requires Full isolation.
                        // CLI validation should have caught this, but reject here too
                        // in case the job comes via --spec or the agent API.
                        self.db.fail_run(&run_id, "interactive mode requires namespace isolation")?;
                        return Err(OaieError::InvalidJobSpec(
                            "interactive mode requires namespace isolation (not --no-isolation)".into(),
                        ));
                    } else {
                        // --no-isolation with namespace backend falls through to bare.
                        match crate::backend_bare::execute_bare(job, &run_dir, &out_dir, &run_id, effective_timeout, quiet) {
                            Ok((code, dur)) => (code, dur, event_writer, None, None, false, 0),
                            Err(e) => {
                                self.db.fail_run(&run_id, &e.to_string())?;
                                return Err(e);
                            }
                        }
                    }
                }
                oaie_core::backend::BackendKind::Firecracker => {
                    #[cfg(feature = "firecracker")]
                    {
                        match crate::backend_firecracker::execute_firecracker(job, &run_dir, &out_dir, &run_id, effective_timeout, quiet) {
                            Ok(fr) => {
                                fc_version = fr.firecracker_version;
                                fc_kernel = fr.kernel_name;
                                fc_rootfs = fr.rootfs_name;
                                (fr.exit_code, fr.duration, event_writer, None, fr.resources, false, 0)
                            }
                            Err(e) => {
                                self.db.fail_run(&run_id, &e.to_string())?;
                                return Err(e);
                            }
                        }
                    }
                    #[cfg(not(feature = "firecracker"))]
                    {
                        self.db.fail_run(&run_id, "firecracker backend not available (feature not enabled)")?;
                        return Err(OaieError::Other(
                            "oaie was built without the 'firecracker' feature; rebuild with --features firecracker".into(),
                        ));
                    }
                }
                oaie_core::backend::BackendKind::Bare => {
                    match crate::backend_bare::execute_bare(job, &run_dir, &out_dir, &run_id, effective_timeout, quiet) {
                        Ok((code, dur)) => (code, dur, event_writer, None, None, false, 0),
                        Err(e) => {
                            self.db.fail_run(&run_id, &e.to_string())?;
                            return Err(e);
                        }
                    }
                }
            };

        // 3–11. Post-execution steps: if any fail, mark the run as failed
        // so it doesn't stay in "Running" status forever.
        let post_exec_result: Result<RunResult> = (|| {
        // 3. Store stdout/stderr in CAS.
        let (stdout_hash, stdout_size) = self.cas.store_file(&run_dir.stdout_path())?;
        let (stderr_hash, stderr_size) = self.cas.store_file(&run_dir.stderr_path())?;

        // 4. Collect and hash output files (using store-configured limits).
        let output_artifacts = collect_outputs_with_limits(
            &out_dir,
            &self.cas,
            self.store.limits.max_output_files,
            self.store.limits.max_output_file_size,
            self.store.limits.max_output_total,
        )?;

        // 4b. Finalize event writer: write RunEnd, store chunks in CAS, build summary.
        let trace_result = if let Some(mut writer) = event_writer.take() {
            writer.write_event(OaieEvent {
                ts_ns: 0,
                event_type: EventType::RunEnd,
                pid: 0,
                ppid: None,
                detail: EventDetail::RunLifecycle {
                    status: if exit_code == 0 {
                        "completed".into()
                    } else {
                        "failed".into()
                    },
                    command: None,
                    exit_code: Some(exit_code),
                },
                hash_prev: String::new(),
            })?;
            let trace_index = writer.finalize(&run_id.full(), backend_name)?;

            // Store trace_index.json in CAS.
            let index_path = run_dir.path.join("trace_index.json");
            let (index_hash, index_size) = self.cas.store_file(&index_path)?;

            // Build TraceSummary by reading events back from CAS chunks.
            let summary = {
                let mut summarizer = StreamingSummarizer::new();
                let events = ChunkedEventWriter::read_events_from_index(&self.cas, &trace_index)?;
                for event in &events {
                    summarizer.ingest(event);
                }
                summarizer.finish()
            };

            Some((
                TraceInfo {
                    backend: backend_name.into(),
                    event_count: trace_index.total_events,
                    chain_tip: trace_index.chain_tip.clone(),
                    dropped: dropped_events,
                    chunks: trace_index.total_chunks,
                    trace_index_hash: Some(index_hash.to_hex()),
                },
                ArtifactRef {
                    hash: index_hash,
                    size: index_size,
                    label: "trace_index.json".into(),
                    artifact_type: ArtifactType::Trace,
                },
                summary,
            ))
        } else {
            None
        };

        // 4c. Performance note for high-event-count traced runs.
        if let Some((ref ti, _, _)) = trace_result {
            if ti.event_count > 1000 && duration > Duration::from_secs(1) {
                eprintln!(
                    "OAIE: Trace: {} events in {:.1}s. ptrace adds overhead on syscall-heavy workloads.",
                    ti.event_count,
                    duration.as_secs_f64()
                );
            }
        }

        // 5. Build preliminary artifact list (stdout + stderr + outputs).
        let mut artifacts = vec![
            ArtifactRef {
                hash: stdout_hash.clone(),
                size: stdout_size,
                label: "stdout".into(),
                artifact_type: ArtifactType::Stdout,
            },
            ArtifactRef {
                hash: stderr_hash.clone(),
                size: stderr_size,
                label: "stderr".into(),
                artifact_type: ArtifactType::Stderr,
            },
        ];
        artifacts.extend(output_artifacts.clone());

        // Add trace index artifact if tracing was enabled.
        if let Some((_, ref trace_artifact, _)) = trace_result {
            artifacts.push(trace_artifact.clone());
        }

        // 6. Build preliminary manifest (for report generation).
        let created = Utc::now();

        // Build network_rules for manifest when in allowlist mode.
        let network_rules = if let oaie_core::policy::NetworkMode::Allowlist(ref rules) = policy.network {
            Some(rules.iter().map(|r| oaie_core::manifest::AllowRuleSerialized {
                target: r.host.clone().or_else(|| r.cidr.clone()).unwrap_or_default(),
                port: r.port,
                protocol: r.protocol.clone(),
            }).collect())
        } else {
            None
        };

        let network_mode_str = match &policy.network {
            oaie_core::policy::NetworkMode::Off => "off",
            oaie_core::policy::NetworkMode::On => "on",
            oaie_core::policy::NetworkMode::Allowlist(_) => "allowlist",
        };

        let policy_info = PolicyInfo {
            name: policy.name.clone(),
            network: policy.network.has_connectivity(),
            network_rules,
            max_memory: policy::format_size_human(policy.max_memory),
            max_time: policy::format_duration_human(policy.max_time),
            max_pids: policy.max_pids,
            max_fsize: policy::format_size_human(policy.max_fsize),
            allow_memfd: policy.allow_memfd,
            deny_paths: policy
                .deny_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            auto_mounts: policy.auto_mounts.clone(),
            limits_enforced: LimitsEnforced {
                timeout: true,
                memory: true,
                pids: true,
                fsize: true,
            },
        };

        let preliminary_manifest = Manifest {
            version: 1,
            hash_algorithm: self.store.hash_algorithm.to_string(),
            run_id: run_id.clone(),
            created,
            command: job.command.clone(),
            exit_code: Some(exit_code),
            duration_ms: duration.as_millis().min(u64::MAX as u128) as u64,
            isolation: IsolationInfo {
                level: isolation_level.clone(),
                namespaces: namespaces.clone(),
                network: policy.network.has_connectivity(),
                network_mode: network_mode_str.into(),
                landlock: oaie_sandbox::landlock::probe_landlock(),
                cgroup: cgroup_info.clone(),
                backend: Some(job.backend.to_string()),
                firecracker_version: fc_version.clone(),
                kernel: fc_kernel.clone(),
                rootfs: fc_rootfs.clone(),
                trace_integrity: if job.backend == oaie_core::backend::BackendKind::Firecracker {
                    Some("reduced".into())
                } else {
                    None
                },
                interactive: job.interactive,
            },
            artifacts: artifacts.clone(),
            policy: Some(policy_info),
            trace: trace_result.as_ref().map(|(ti, _, _)| ti.clone()),
            resources: run_resources.clone(),
        };

        // 7. Generate REPORT.md and store it.
        let trace_summary_ref = trace_result.as_ref().map(|(_, _, s)| s);
        let report_content = oaie_report::generate_report(&preliminary_manifest, trace_summary_ref);
        fs::write(run_dir.report_path(), &report_content)?;
        let (report_hash, report_size) = self.cas.store_bytes(report_content.as_bytes())?;

        // Add report artifact to the list.
        artifacts.push(ArtifactRef {
            hash: report_hash,
            size: report_size,
            label: "report".into(),
            artifact_type: ArtifactType::Report,
        });

        // 8. Rebuild final manifest with report included.
        let final_manifest = Manifest {
            artifacts: artifacts.clone(),
            ..preliminary_manifest
        };

        // 9. Write manifest to run dir and CAS.
        let manifest_hash = self
            .cas
            .write_manifest(&final_manifest, &run_dir.path)?;

        // 9a. Sign the manifest if a signing key was specified.
        let signed_by = if let Some(key_ref) = sign_key {
            let manifest_bytes = std::fs::read(run_dir.path.join("manifest.toml"))?;
            let (key_info, mut secret_hex) = crate::signing::load_key(&self.store.keys_dir, key_ref)?;
            let sig_info = crate::signing::sign_manifest(
                &manifest_bytes,
                &secret_hex,
                &key_info,
                self.store.hash_algorithm,
            )?;
            // Zeroize secret key material as soon as signing completes.
            zeroize::Zeroize::zeroize(&mut secret_hex);

            // Write signature.toml to run dir.
            let sig_toml = toml::to_string_pretty(&sig_info)
                .map_err(|e| OaieError::Io(io::Error::other(e)))?;
            let sig_path = run_dir.signature_path();
            fs::write(&sig_path, &sig_toml)?;

            // Store signature.toml in CAS and add as artifact.
            let (sig_hash, sig_size) = self.cas.store_bytes(sig_toml.as_bytes())?;
            artifacts.push(ArtifactRef {
                hash: sig_hash,
                size: sig_size,
                label: "signature".into(),
                artifact_type: ArtifactType::Signature,
            });

            let label = format!("{} ({}..)", key_info.label, &key_info.key_id);
            Some(label)
        } else {
            None
        };

        // 10+11. Build artifact records and commit everything in one transaction.
        let mut artifact_records: Vec<ArtifactRecord> = artifacts
            .iter()
            .map(|a| ArtifactRecord {
                hash: a.hash.to_hex(),
                run_id: run_id.clone(),
                label: a.label.clone(),
                artifact_type: a.artifact_type.to_string(),
                size: a.size.min(i64::MAX as u64) as i64,
                created,
            })
            .collect();

        // Also record the manifest itself as an artifact.
        artifact_records.push(ArtifactRecord {
            hash: manifest_hash.to_hex(),
            run_id: run_id.clone(),
            label: "manifest".into(),
            artifact_type: ArtifactType::Manifest.to_string(),
            size: self.cas.blob_size(&manifest_hash)?.min(i64::MAX as u64) as i64,
            created,
        });

        self.db.complete_run_with_artifacts(
            &run_id,
            exit_code,
            duration.as_millis().min(i64::MAX as u128) as i64,
            &manifest_hash.to_hex(),
            &artifact_records,
        )?;

        // Extract the trace summary for the RunResult (owned clone).
        let run_trace_summary = trace_result.map(|(_, _, s)| s);

        Ok(RunResult {
            run_id: run_id.clone(),
            exit_code,
            duration,
            stdout_hash,
            stdout_size,
            stderr_hash,
            stderr_size,
            output_artifacts,
            manifest_hash,
            isolation_level,
            resources: run_resources,
            cgroup_enforced,
            trace_summary: run_trace_summary,
            network_mode: policy.network.clone(),
            interactive: job.interactive,
            signed_by,
        })
        })(); // end post-exec closure

        match post_exec_result {
            Ok(result) => Ok(result),
            Err(e) => {
                // Mark run as failed so it doesn't stay in "Running" status.
                let _ = self.db.fail_run(&run_id, &format!("post-execution error: {e}"));
                Err(e)
            }
        }
    }
}

/// Prepare the output directory for a run.
///
/// Auto-generated output dirs use the short run-ID prefix (`oaie-out/<short>`).
/// If that already exists (e.g. from a previous run with a nearby timestamp),
/// falls back to the full UUID to avoid mixing artifacts from different runs.
fn prepare_output_dir(job: &JobSpec, run_id: &RunId) -> Result<PathBuf> {
    let out_dir = match &job.outputs {
        Some(path) => path.clone(),
        None => {
            let short_dir = PathBuf::from("oaie-out").join(run_id.short());
            if short_dir.exists() {
                // Short-ID collision — use the full UUID to avoid mixing artifacts.
                PathBuf::from("oaie-out").join(run_id.full())
            } else {
                short_dir
            }
        }
    };

    if out_dir.exists() {
        if !out_dir.is_dir() {
            return Err(OaieError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "output path exists but is not a directory: {}",
                    out_dir.display()
                ),
            )));
        }
    } else {
        fs::create_dir_all(&out_dir)?;
    }

    Ok(out_dir)
}

/// Outcome of waiting for a child process with timeout and signal awareness.
pub enum WaitOutcome {
    /// Child exited normally (or was killed by a signal), with an exit status.
    Exited(std::process::ExitStatus),
    /// The wall-clock timeout expired before the child exited.
    TimedOut,
    /// A SIGINT/SIGTERM was received before the child exited.
    Interrupted,
}

/// Poll-based wait with timeout and signal awareness.
/// Returns `WaitOutcome` distinguishing between normal exit, timeout, and
/// signal interruption so callers can handle each case appropriately.
pub fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
    signal_baseline: u64,
) -> Result<WaitOutcome> {
    let deadline = Instant::now() + timeout;

    loop {
        match child.try_wait()? {
            Some(status) => return Ok(WaitOutcome::Exited(status)),
            None => {
                if signal_received_since(signal_baseline) {
                    return Ok(WaitOutcome::Interrupted);
                }
                if Instant::now() >= deadline {
                    return Ok(WaitOutcome::TimedOut);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

/// Check tee thread join results. Panics are hard errors (indicate a bug
/// that could produce truncated artifacts). I/O errors are logged but
/// tolerated (e.g. broken pipe on the terminal side of stderr).
pub fn check_tee_thread(
    handle: std::thread::JoinHandle<Result<()>>,
    label: &str,
) -> Result<()> {
    match handle.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            // I/O error in the tee thread (e.g. broken pipe on terminal).
            // Log but don't fail — the file side may still be complete.
            oaie_core::log_warn!("{label} tee thread I/O error: {e}");
            Ok(())
        }
        Err(_panic) => {
            // Thread panicked — artifact file is likely truncated.
            Err(OaieError::Other(format!("{label} capture thread panicked")))
        }
    }
}

/// Copy bytes from input to both a file and the terminal.
pub fn tee_to_file_and_terminal(
    mut input: impl Read,
    mut file: File,
    mut terminal: impl Write,
) -> Result<()> {
    let mut buf = [0u8; 8192];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])?;
        // Ignore terminal write errors (e.g. broken pipe).
        let _ = terminal.write_all(&buf[..n]);
    }
    file.sync_all()?;
    Ok(())
}

/// Copy bytes from input to a file only (quiet mode).
pub fn tee_to_file_only(mut input: impl Read, mut file: File) -> Result<()> {
    let mut buf = [0u8; 8192];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])?;
    }
    file.sync_all()?;
    Ok(())
}

/// Remove stale `oaie-root-*` directories from `/tmp` that were left behind
/// by sandbox instances that crashed or were killed before cleanup. Only
/// removes directories older than 5 minutes (to avoid racing with sandboxes
/// still starting up) and only empty dirs (`remove_dir` fails on non-empty).
fn cleanup_stale_sandbox_dirs() {
    let Ok(entries) = fs::read_dir("/tmp") else {
        return;
    };
    let now = std::time::SystemTime::now();
    let min_age = Duration::from_secs(300); // 5 minutes

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with("oaie-root-") {
            continue;
        }
        // Skip directories newer than min_age.
        if let Ok(meta) = entry.metadata() {
            if let Ok(modified) = meta.modified() {
                if now.duration_since(modified).unwrap_or_default() < min_age {
                    continue;
                }
            }
        }
        // remove_dir only succeeds on empty directories — safe even if
        // something is still mounted (non-empty dir will fail with ENOTEMPTY).
        let _ = fs::remove_dir(entry.path());
    }
}

/// Collect output files with configurable limits. Skips files that exceed
/// individual size limits and stops collecting when file count or total
/// bytes limits are reached.
pub fn collect_outputs_with_limits(
    out_dir: &Path,
    cas: &CasStore,
    max_files: u64,
    max_single: u64,
    max_total: u64,
) -> Result<Vec<ArtifactRef>> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut artifacts = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut file_count: u64 = 0;

    if !out_dir.exists() {
        return Ok(artifacts);
    }

    for entry in crate::walk::walk_dir_sorted(out_dir) {
        let entry = entry?;
        if !entry.is_file() {
            continue;
        }

        // Check file count limit.
        if file_count >= max_files {
            oaie_core::log_warn!(
                "output file count limit reached ({max_files}), skipping remaining files"
            );
            break;
        }

        let path = entry.path();

        // Open with O_NOFOLLOW to prevent symlink TOCTOU: if the file was
        // replaced with a symlink between walkdir's stat and this open,
        // the open fails with ELOOP instead of following the symlink.
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;

        // Double-check via fstat that the opened fd points to a regular file.
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            oaie_core::log_warn!(
                "skipping {}: not a regular file after open",
                path.display()
            );
            continue;
        }

        // Check single file size limit.
        let file_size = metadata.len();
        if file_size > max_single {
            oaie_core::log_warn!(
                "skipping {}: size {} exceeds single-file limit {}",
                path.display(),
                file_size,
                max_single
            );
            continue;
        }

        // Check total bytes limit.
        if total_bytes.saturating_add(file_size) > max_total {
            oaie_core::log_warn!(
                "output total bytes limit reached ({max_total}), skipping {}",
                path.display()
            );
            break;
        }

        let relative = path
            .strip_prefix(out_dir)
            .map_err(|e| OaieError::Io(io::Error::other(e.to_string())))?;
        let label = format!("output/{}", relative.display());

        // Validate label against path traversal from malicious sandbox output.
        ArtifactRef::validate_label(&label)?;

        let (hash, size) = cas.store_reader(&mut file)?;

        total_bytes += size;
        file_count += 1;

        artifacts.push(ArtifactRef {
            hash,
            size,
            label,
            artifact_type: ArtifactType::Output,
        });
    }

    Ok(artifacts)
}

// ── Structured output conversion ──

use oaie_core::backend::BackendKind;
use oaie_core::structured_output::{
    ArtifactEntry, IsolationSummary, NetworkRuleSummary, OutputRef, ResourceSummary,
    StructuredRunResult, TraceSummaryOutput,
};

impl RunResult {
    /// Convert this `RunResult` into a [`StructuredRunResult`] for JSON serialization.
    ///
    /// Shared by the CLI `--output=json` path and the `oaie-agent` library crate
    /// to guarantee identical structured output from both.
    pub fn to_structured(&self, backend: &BackendKind, store_path: &str) -> StructuredRunResult {
        let trace = self.trace_summary.as_ref().map(|ts| TraceSummaryOutput {
            files_read: ts.unique_files_read,
            files_written: ts.unique_files_written,
            net_connects: ts.net_connects.len() as u64,
            net_denied: ts.net_denied.len() as u64,
            processes_spawned: ts.total_exec_events,
            suspicious_count: ts.suspicious_activity.len() as u64,
            total_events: ts.total_events,
        });

        let resources = self.resources.as_ref().map(|r| ResourceSummary {
            memory_limit: r.memory_limit.clone(),
            memory_peak: r.memory_peak.clone(),
            cpu_user_ms: r.cpu_user_ms,
            cpu_system_ms: r.cpu_system_ms,
            pids_peak: r.pids_peak,
        });

        StructuredRunResult {
            run_id: self.run_id.full(),
            exit_code: self.exit_code,
            duration_secs: self.duration.as_secs_f64(),
            stdout: OutputRef {
                hash: self.stdout_hash.to_hex(),
                size_bytes: self.stdout_size,
            },
            stderr: OutputRef {
                hash: self.stderr_hash.to_hex(),
                size_bytes: self.stderr_size,
            },
            output_artifacts: self
                .output_artifacts
                .iter()
                .map(|a| ArtifactEntry {
                    name: a.label.clone(),
                    hash: a.hash.to_hex(),
                    size_bytes: a.size,
                })
                .collect(),
            manifest_hash: self.manifest_hash.to_hex(),
            isolation: IsolationSummary {
                level: self.isolation_level.to_string(),
                backend: backend.to_string(),
                cgroup_enforced: self.cgroup_enforced,
                network_mode: Some(match &self.network_mode {
                    oaie_core::policy::NetworkMode::Off => "off",
                    oaie_core::policy::NetworkMode::On => "on",
                    oaie_core::policy::NetworkMode::Allowlist(_) => "allowlist",
                }.to_string()),
                network_rules: if let oaie_core::policy::NetworkMode::Allowlist(ref rules) = self.network_mode {
                    Some(rules.iter().map(|r| NetworkRuleSummary {
                        target: r.host.clone().or_else(|| r.cidr.clone()).unwrap_or_default(),
                        port: r.port,
                        protocol: r.protocol.clone(),
                    }).collect())
                } else {
                    None
                },
                interactive: self.interactive,
                signed_by: self.signed_by.clone(),
            },
            resources,
            trace,
            store_path: store_path.to_string(),
        }
    }
}
