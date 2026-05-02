//! Run verification engine: checks manifest, artifacts, trace, and hash chain.
//!
//! Lives in oaie-cli (not oaie-core) because it needs access to both
//! oaie-cas (CAS verification) and oaie-observe (chain verification).

use oaie_cas::store::{read_manifest, CasStore, VerifyResult};
use oaie_core::artifact::{ArtifactRef, ArtifactType, Hash};
use oaie_core::config::OaieStore;
use oaie_core::error::Result;
use oaie_core::hash_algo::{HashAlgorithm, StreamingHasher};
use oaie_core::manifest::TraceInfo;
use oaie_core::run_id::RunId;
use oaie_core::session::SessionEvent;
use oaie_core::verify::{CheckKind, CheckResult, CheckStatus, SessionVerifyReport, VerifyReport};
use oaie_db::OaieDb;
use oaie_observe::{verify_chain, ChainVerifyResult, ChunkedEventWriter, TraceIndex};

/// Verify the integrity of a completed run.
///
/// Checks manifest existence and validity, artifact existence and hash integrity,
/// trace chunk integrity, and event chain continuity. Returns a detailed report
/// with pass/fail/skip for each check.
pub fn verify_run(store: &OaieStore, run_id: &RunId) -> Result<VerifyReport> {
    let cas = CasStore::new(store.cas_dir.clone(), store.hash_algorithm);
    let mut checks = Vec::new();

    // Check 1: Manifest exists.
    let run_dir = store.runs_dir.join(run_id.full());
    let manifest_path = run_dir.join("manifest.toml");
    if !manifest_path.exists() {
        checks.push(CheckResult {
            check: CheckKind::ManifestExists,
            status: CheckStatus::Fail,
            detail: Some("manifest.toml not found in run directory".into()),
        });
        return Ok(VerifyReport {
            run_id: run_id.clone(),
            checks,
        });
    }
    checks.push(CheckResult {
        check: CheckKind::ManifestExists,
        status: CheckStatus::Pass,
        detail: None,
    });

    // Check 2: Manifest is valid TOML and parseable.
    let manifest = match read_manifest(&run_dir) {
        Ok(m) => {
            checks.push(CheckResult {
                check: CheckKind::ManifestParseable,
                status: CheckStatus::Pass,
                detail: None,
            });
            m
        }
        Err(e) => {
            checks.push(CheckResult {
                check: CheckKind::ManifestParseable,
                status: CheckStatus::Fail,
                detail: Some(format!("Failed to parse: {e}")),
            });
            return Ok(VerifyReport {
                run_id: run_id.clone(),
                checks,
            });
        }
    };

    // Partition artifacts: trace artifacts are checked separately, everything
    // else is "output" (stdout, stderr, output files, report, manifest).
    // OAIE doesn't store input files as artifacts — they live on disk at the
    // user's path. So input checks are skipped.
    let non_trace: Vec<&ArtifactRef> = manifest
        .artifacts
        .iter()
        .filter(|a| a.artifact_type != ArtifactType::Trace)
        .collect();

    // Check 3: Input artifacts — OAIE doesn't store inputs in CAS, skip.
    checks.push(CheckResult {
        check: CheckKind::InputArtifactsExist,
        status: CheckStatus::Skip,
        detail: Some("Inputs are not stored in CAS".into()),
    });

    // Check 4: Output artifacts exist in CAS.
    verify_artifact_existence(&cas, &non_trace, CheckKind::OutputArtifactsExist, &mut checks);

    // Check 5: Input artifact hashes — skip (same reason).
    checks.push(CheckResult {
        check: CheckKind::InputArtifactHashes,
        status: CheckStatus::Skip,
        detail: None,
    });

    // Check 6: Output artifact hashes match.
    verify_artifact_hashes(&cas, &non_trace, CheckKind::OutputArtifactHashes, &mut checks);

    // Check 7-11: Trace integrity (if tracing was enabled).
    if let Some(ref trace_info) = manifest.trace {
        verify_trace_artifacts(&cas, trace_info, store.hash_algorithm, &mut checks);
    } else {
        // Skip all trace checks.
        for kind in [
            CheckKind::TraceIndexExists,
            CheckKind::TraceChunksExist,
            CheckKind::TraceChunkHashes,
            CheckKind::EventChainIntegrity,
            CheckKind::EventChainTip,
        ] {
            checks.push(CheckResult {
                check: kind,
                status: CheckStatus::Skip,
                detail: if kind == CheckKind::TraceIndexExists {
                    Some("Run had no tracing enabled".into())
                } else {
                    None
                },
            });
        }
    }

    // Check 12: Manifest signature.
    // The trusted-key list is the trust anchor: without it, the only
    // public key verify_signature() can see is the one inside
    // signature.toml — i.e., the file under verification. Empty list
    // → Skip (not Pass). See SigningConfig.trusted_public_keys doc.
    let trusted_keys: &[String] = store
        .signing
        .as_ref()
        .map(|s| s.trusted_public_keys.as_slice())
        .unwrap_or(&[]);
    let sig_path = run_dir.join("signature.toml");
    if sig_path.exists() {
        verify_manifest_signature(
            &sig_path,
            &manifest_path,
            store.hash_algorithm,
            trusted_keys,
            &mut checks,
        );
    } else {
        checks.push(CheckResult {
            check: CheckKind::ManifestSignature,
            status: CheckStatus::Skip,
            detail: Some("No signature.toml (unsigned run)".into()),
        });
    }

    Ok(VerifyReport {
        run_id: run_id.clone(),
        checks,
    })
}

/// Check that all artifacts in a list exist in CAS.
fn verify_artifact_existence(
    cas: &CasStore,
    artifacts: &[&ArtifactRef],
    kind: CheckKind,
    checks: &mut Vec<CheckResult>,
) {
    if artifacts.is_empty() {
        checks.push(CheckResult {
            check: kind,
            status: CheckStatus::Pass,
            detail: Some("0 artifacts (none expected)".into()),
        });
        return;
    }

    let mut missing = Vec::new();
    for artifact in artifacts {
        if !cas.exists(&artifact.hash) {
            missing.push(artifact.hash.short());
        }
    }

    if missing.is_empty() {
        checks.push(CheckResult {
            check: kind,
            status: CheckStatus::Pass,
            detail: Some(format!("{} artifacts verified", artifacts.len())),
        });
    } else {
        checks.push(CheckResult {
            check: kind,
            status: CheckStatus::Fail,
            detail: Some(format!(
                "{} missing: {}",
                missing.len(),
                missing.join(", ")
            )),
        });
    }
}

/// Re-hash all artifacts and verify they match their expected hashes.
fn verify_artifact_hashes(
    cas: &CasStore,
    artifacts: &[&ArtifactRef],
    kind: CheckKind,
    checks: &mut Vec<CheckResult>,
) {
    if artifacts.is_empty() {
        checks.push(CheckResult {
            check: kind,
            status: CheckStatus::Pass,
            detail: None,
        });
        return;
    }

    let mut corrupted = Vec::new();
    for artifact in artifacts {
        match cas.verify(&artifact.hash) {
            Ok(VerifyResult::Ok) => {}
            Ok(VerifyResult::Corrupted { expected, actual }) => {
                corrupted.push(format!(
                    "{}: expected {}, got {}",
                    artifact.hash.short(),
                    expected.short(),
                    actual.short()
                ));
            }
            Ok(VerifyResult::Missing) => {
                // Already caught by existence check.
            }
            Err(e) => {
                corrupted.push(format!("{}: read error: {e}", artifact.hash.short()));
            }
        }
    }

    if corrupted.is_empty() {
        checks.push(CheckResult {
            check: kind,
            status: CheckStatus::Pass,
            detail: None,
        });
    } else {
        checks.push(CheckResult {
            check: kind,
            status: CheckStatus::Fail,
            detail: Some(corrupted.join("; ")),
        });
    }
}

/// Verify trace index, chunks, and event chain.
fn verify_trace_artifacts(
    cas: &CasStore,
    trace: &TraceInfo,
    algo: HashAlgorithm,
    checks: &mut Vec<CheckResult>,
) {
    // Check 7: Trace index exists in CAS.
    let index_hash_str = match &trace.trace_index_hash {
        Some(h) => h.clone(),
        None => {
            checks.push(CheckResult {
                check: CheckKind::TraceIndexExists,
                status: CheckStatus::Skip,
                detail: Some("No trace index hash in manifest (legacy run)".into()),
            });
            // Can't verify chunks or chain without the index.
            for kind in [
                CheckKind::TraceChunksExist,
                CheckKind::TraceChunkHashes,
                CheckKind::EventChainIntegrity,
                CheckKind::EventChainTip,
            ] {
                checks.push(CheckResult {
                    check: kind,
                    status: CheckStatus::Skip,
                    detail: None,
                });
            }
            return;
        }
    };

    let index_hash = match Hash::from_hex(&index_hash_str) {
        Ok(h) => h,
        Err(_) => {
            checks.push(CheckResult {
                check: CheckKind::TraceIndexExists,
                status: CheckStatus::Fail,
                detail: Some(format!("Invalid trace index hash: {index_hash_str}")),
            });
            skip_remaining_trace_checks(checks);
            return;
        }
    };

    if !cas.exists(&index_hash) {
        checks.push(CheckResult {
            check: CheckKind::TraceIndexExists,
            status: CheckStatus::Fail,
            detail: Some(format!(
                "Trace index {} not found in CAS",
                index_hash.short()
            )),
        });
        skip_remaining_trace_checks(checks);
        return;
    }
    checks.push(CheckResult {
        check: CheckKind::TraceIndexExists,
        status: CheckStatus::Pass,
        detail: None,
    });

    // Read and parse the trace index.
    let index_path = cas.blob_path(&index_hash);
    let index_bytes = match std::fs::read(&index_path) {
        Ok(b) => b,
        Err(e) => {
            checks.push(CheckResult {
                check: CheckKind::TraceChunksExist,
                status: CheckStatus::Fail,
                detail: Some(format!("Cannot read trace index: {e}")),
            });
            skip_chain_checks(checks);
            return;
        }
    };

    let index: TraceIndex = match serde_json::from_slice(&index_bytes) {
        Ok(i) => i,
        Err(e) => {
            checks.push(CheckResult {
                check: CheckKind::TraceChunksExist,
                status: CheckStatus::Fail,
                detail: Some(format!("Trace index is invalid JSON: {e}")),
            });
            skip_chain_checks(checks);
            return;
        }
    };

    // Check 8: All chunks exist in CAS.
    let mut missing_chunks = Vec::new();
    for chunk in &index.chunks {
        let hash = match Hash::from_hex(&chunk.hash) {
            Ok(h) => h,
            Err(_) => {
                missing_chunks.push(format!("chunk_{:03} (invalid hash)", chunk.index));
                continue;
            }
        };
        if !cas.exists(&hash) {
            missing_chunks.push(format!("chunk_{:03}", chunk.index));
        }
    }

    if missing_chunks.is_empty() {
        checks.push(CheckResult {
            check: CheckKind::TraceChunksExist,
            status: CheckStatus::Pass,
            detail: Some(format!("{} chunks present", index.chunks.len())),
        });
    } else {
        checks.push(CheckResult {
            check: CheckKind::TraceChunksExist,
            status: CheckStatus::Fail,
            detail: Some(format!(
                "{} missing: {}",
                missing_chunks.len(),
                missing_chunks.join(", ")
            )),
        });
    }

    // Check 9: All chunk hashes are correct.
    let mut corrupted_chunks = Vec::new();
    for chunk in &index.chunks {
        if let Ok(hash) = Hash::from_hex(&chunk.hash) {
            match cas.verify(&hash) {
                Ok(VerifyResult::Ok) => {}
                Ok(VerifyResult::Corrupted { .. }) => {
                    corrupted_chunks.push(format!("chunk_{:03}", chunk.index));
                }
                _ => {} // Missing already caught above.
            }
        }
    }

    if corrupted_chunks.is_empty() {
        checks.push(CheckResult {
            check: CheckKind::TraceChunkHashes,
            status: CheckStatus::Pass,
            detail: None,
        });
    } else {
        checks.push(CheckResult {
            check: CheckKind::TraceChunkHashes,
            status: CheckStatus::Fail,
            detail: Some(format!("{} corrupted", corrupted_chunks.join(", "))),
        });
    }

    // Check 10-11: Event chain integrity and tip verification.
    verify_event_chain_from_index(cas, &index, trace, algo, checks);
}

/// Verify the event hash chain across all chunks.
fn verify_event_chain_from_index(
    cas: &CasStore,
    index: &TraceIndex,
    trace: &TraceInfo,
    algo: HashAlgorithm,
    checks: &mut Vec<CheckResult>,
) {
    // Read all events from CAS chunks.
    let events = match ChunkedEventWriter::read_events_from_index(cas, index) {
        Ok(e) => e,
        Err(e) => {
            checks.push(CheckResult {
                check: CheckKind::EventChainIntegrity,
                status: CheckStatus::Fail,
                detail: Some(format!("Failed to read events from CAS: {e}")),
            });
            checks.push(CheckResult {
                check: CheckKind::EventChainTip,
                status: CheckStatus::Skip,
                detail: None,
            });
            return;
        }
    };

    // Verify the chain.
    let result = verify_chain(&events, &index.genesis_hash, algo);

    match result {
        ChainVerifyResult::Valid {
            events: count,
            tip_hash,
        } => {
            checks.push(CheckResult {
                check: CheckKind::EventChainIntegrity,
                status: CheckStatus::Pass,
                detail: Some(format!("{count} events verified")),
            });

            // Check tip matches what the manifest claims.
            if tip_hash == trace.chain_tip {
                checks.push(CheckResult {
                    check: CheckKind::EventChainTip,
                    status: CheckStatus::Pass,
                    detail: None,
                });
            } else {
                checks.push(CheckResult {
                    check: CheckKind::EventChainTip,
                    status: CheckStatus::Fail,
                    detail: Some(format!(
                        "chain tip {} does not match manifest claim {}",
                        &tip_hash[..12.min(tip_hash.len())],
                        &trace.chain_tip[..12.min(trace.chain_tip.len())]
                    )),
                });
            }
        }
        ChainVerifyResult::Broken {
            event_index,
            expected,
            found,
        } => {
            checks.push(CheckResult {
                check: CheckKind::EventChainIntegrity,
                status: CheckStatus::Fail,
                detail: Some(format!(
                    "chain broken at event {event_index}: expected {}, found {}",
                    &expected[..12.min(expected.len())],
                    &found[..12.min(found.len())]
                )),
            });
            checks.push(CheckResult {
                check: CheckKind::EventChainTip,
                status: CheckStatus::Skip,
                detail: Some("Chain broken, tip not verifiable".into()),
            });
        }
        ChainVerifyResult::Empty => {
            checks.push(CheckResult {
                check: CheckKind::EventChainIntegrity,
                status: CheckStatus::Skip,
                detail: Some("No events in trace".into()),
            });
            checks.push(CheckResult {
                check: CheckKind::EventChainTip,
                status: CheckStatus::Skip,
                detail: None,
            });
        }
    }
}

/// Skip remaining trace checks after an early failure.
fn skip_remaining_trace_checks(checks: &mut Vec<CheckResult>) {
    for kind in [
        CheckKind::TraceChunksExist,
        CheckKind::TraceChunkHashes,
        CheckKind::EventChainIntegrity,
        CheckKind::EventChainTip,
    ] {
        checks.push(CheckResult {
            check: kind,
            status: CheckStatus::Skip,
            detail: None,
        });
    }
}

/// Skip chain checks (EventChainIntegrity and EventChainTip).
fn skip_chain_checks(checks: &mut Vec<CheckResult>) {
    for kind in [CheckKind::EventChainIntegrity, CheckKind::EventChainTip] {
        checks.push(CheckResult {
            check: kind,
            status: CheckStatus::Skip,
            detail: None,
        });
    }
}

/// Verify the integrity of a completed session (M.3).
///
/// Checks session manifest, event log hash, event chain integrity, and
/// recursively verifies all runs referenced by session tool calls.
pub fn verify_session(store: &OaieStore, session_id: &str) -> Result<SessionVerifyReport> {
    let cas = CasStore::new(store.cas_dir.clone(), store.hash_algorithm);
    let db = OaieDb::open(&store.db_path)?;
    let mut checks = Vec::new();

    // Check 1: Session manifest exists.
    let session_dir = store.root.join("sessions").join(session_id);
    let manifest_path = session_dir.join("session_manifest.toml");
    if !manifest_path.exists() {
        checks.push(CheckResult {
            check: CheckKind::SessionManifestExists,
            status: CheckStatus::Fail,
            detail: Some("session_manifest.toml not found".into()),
        });
        return Ok(SessionVerifyReport {
            session_id: session_id.to_string(),
            checks,
            run_reports: vec![],
        });
    }
    checks.push(CheckResult {
        check: CheckKind::SessionManifestExists,
        status: CheckStatus::Pass,
        detail: None,
    });

    // Check 2: Session manifest is valid TOML.
    let manifest_content = match std::fs::read_to_string(&manifest_path) {
        Ok(c) => c,
        Err(e) => {
            checks.push(CheckResult {
                check: CheckKind::SessionManifestParseable,
                status: CheckStatus::Fail,
                detail: Some(format!("read error: {e}")),
            });
            return Ok(SessionVerifyReport {
                session_id: session_id.to_string(),
                checks,
                run_reports: vec![],
            });
        }
    };
    let manifest: toml::Value = match manifest_content.parse() {
        Ok(v) => {
            checks.push(CheckResult {
                check: CheckKind::SessionManifestParseable,
                status: CheckStatus::Pass,
                detail: None,
            });
            v
        }
        Err(e) => {
            checks.push(CheckResult {
                check: CheckKind::SessionManifestParseable,
                status: CheckStatus::Fail,
                detail: Some(format!("parse error: {e}")),
            });
            return Ok(SessionVerifyReport {
                session_id: session_id.to_string(),
                checks,
                run_reports: vec![],
            });
        }
    };

    // Extract trace section from manifest.
    let trace_section = manifest
        .get("session")
        .and_then(|s| s.get("trace"));

    let event_log_hash_str = trace_section
        .and_then(|t| t.get("event_log_hash"))
        .and_then(|v| v.as_str());
    let chain_tip_str = trace_section
        .and_then(|t| t.get("chain_tip"))
        .and_then(|v| v.as_str());

    // Check 3: Event log exists in CAS.
    let event_log_hash = match event_log_hash_str {
        Some(full) => {
            let hex = full.split(':').nth(1).unwrap_or(full);
            match Hash::from_hex(hex) {
                Ok(h) if cas.exists(&h) => {
                    checks.push(CheckResult {
                        check: CheckKind::SessionEventLogExists,
                        status: CheckStatus::Pass,
                        detail: None,
                    });
                    Some(h)
                }
                Ok(_) => {
                    checks.push(CheckResult {
                        check: CheckKind::SessionEventLogExists,
                        status: CheckStatus::Fail,
                        detail: Some("event log blob not found in CAS".into()),
                    });
                    None
                }
                Err(_) => {
                    checks.push(CheckResult {
                        check: CheckKind::SessionEventLogExists,
                        status: CheckStatus::Fail,
                        detail: Some("invalid event log hash".into()),
                    });
                    None
                }
            }
        }
        None => {
            checks.push(CheckResult {
                check: CheckKind::SessionEventLogExists,
                status: CheckStatus::Skip,
                detail: Some("no event_log_hash in manifest".into()),
            });
            None
        }
    };

    // Check 4: Event log hash matches content.
    if let Some(ref hash) = event_log_hash {
        match cas.verify(hash) {
            Ok(VerifyResult::Ok) => {
                checks.push(CheckResult {
                    check: CheckKind::SessionEventLogHash,
                    status: CheckStatus::Pass,
                    detail: None,
                });
            }
            Ok(VerifyResult::Corrupted { .. }) => {
                checks.push(CheckResult {
                    check: CheckKind::SessionEventLogHash,
                    status: CheckStatus::Fail,
                    detail: Some("event log content hash mismatch".into()),
                });
            }
            _ => {
                checks.push(CheckResult {
                    check: CheckKind::SessionEventLogHash,
                    status: CheckStatus::Fail,
                    detail: Some("event log read error".into()),
                });
            }
        }
    } else {
        checks.push(CheckResult {
            check: CheckKind::SessionEventLogHash,
            status: CheckStatus::Skip,
            detail: None,
        });
    }

    // Check 5-6: Event chain integrity and tip.
    if let Some(ref hash) = event_log_hash {
        let blob_path = cas.blob_path(hash);
        if let Ok(ndjson) = std::fs::read_to_string(&blob_path) {
            let events: Vec<SessionEvent> = ndjson
                .lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();

            if events.is_empty() {
                checks.push(CheckResult {
                    check: CheckKind::SessionEventChainIntegrity,
                    status: CheckStatus::Skip,
                    detail: Some("no events in log".into()),
                });
                checks.push(CheckResult {
                    check: CheckKind::SessionEventChainTip,
                    status: CheckStatus::Skip,
                    detail: None,
                });
            } else {
                // Re-hash the chain to verify integrity.
                let genesis = format!("oaie-session-genesis-{}", store.hash_algorithm);
                let genesis_hash = hash_bytes(store.hash_algorithm, genesis.as_bytes());

                let mut expected_prev = genesis_hash;
                let mut chain_ok = true;
                let mut break_idx = 0;

                for (i, event) in events.iter().enumerate() {
                    if event.prev_hash != expected_prev {
                        chain_ok = false;
                        break_idx = i;
                        break;
                    }
                    // Hash this event to get the next expected prev.
                    let event_json = serde_json::to_string(event).unwrap_or_default();
                    expected_prev = hash_bytes(store.hash_algorithm, event_json.as_bytes());
                }

                if chain_ok {
                    checks.push(CheckResult {
                        check: CheckKind::SessionEventChainIntegrity,
                        status: CheckStatus::Pass,
                        detail: Some(format!("{} events verified", events.len())),
                    });

                    // Check tip matches manifest claim.
                    if let Some(tip_str) = chain_tip_str {
                        let tip_hex = tip_str.split(':').nth(1).unwrap_or(tip_str);
                        if expected_prev == tip_hex {
                            checks.push(CheckResult {
                                check: CheckKind::SessionEventChainTip,
                                status: CheckStatus::Pass,
                                detail: None,
                            });
                        } else {
                            checks.push(CheckResult {
                                check: CheckKind::SessionEventChainTip,
                                status: CheckStatus::Fail,
                                detail: Some(format!(
                                    "computed tip {} != manifest {}",
                                    &expected_prev[..12.min(expected_prev.len())],
                                    &tip_hex[..12.min(tip_hex.len())]
                                )),
                            });
                        }
                    } else {
                        checks.push(CheckResult {
                            check: CheckKind::SessionEventChainTip,
                            status: CheckStatus::Skip,
                            detail: Some("no chain_tip in manifest".into()),
                        });
                    }
                } else {
                    checks.push(CheckResult {
                        check: CheckKind::SessionEventChainIntegrity,
                        status: CheckStatus::Fail,
                        detail: Some(format!("chain broken at event {break_idx}")),
                    });
                    checks.push(CheckResult {
                        check: CheckKind::SessionEventChainTip,
                        status: CheckStatus::Skip,
                        detail: Some("chain broken".into()),
                    });
                }
            }
        } else {
            checks.push(CheckResult {
                check: CheckKind::SessionEventChainIntegrity,
                status: CheckStatus::Fail,
                detail: Some("could not read event log".into()),
            });
            checks.push(CheckResult {
                check: CheckKind::SessionEventChainTip,
                status: CheckStatus::Skip,
                detail: None,
            });
        }
    } else {
        checks.push(CheckResult {
            check: CheckKind::SessionEventChainIntegrity,
            status: CheckStatus::Skip,
            detail: None,
        });
        checks.push(CheckResult {
            check: CheckKind::SessionEventChainTip,
            status: CheckStatus::Skip,
            detail: None,
        });
    }

    // Check 7: Verify all nested runs.
    let calls = db.list_session_calls(session_id).unwrap_or_default();
    let mut run_reports = Vec::new();
    let mut runs_ok = true;

    for call in &calls {
        if let Ok(run_id) = call.run_id.parse::<RunId>() {
            match verify_run(store, &run_id) {
                Ok(report) => {
                    if !report.passed() {
                        runs_ok = false;
                    }
                    run_reports.push(report);
                }
                Err(_) => {
                    runs_ok = false;
                    run_reports.push(VerifyReport {
                        run_id,
                        checks: vec![CheckResult {
                            check: CheckKind::ManifestExists,
                            status: CheckStatus::Fail,
                            detail: Some("run verification failed".into()),
                        }],
                    });
                }
            }
        }
    }

    if calls.is_empty() {
        checks.push(CheckResult {
            check: CheckKind::SessionRunsVerified,
            status: CheckStatus::Skip,
            detail: Some("no tool calls in session".into()),
        });
    } else if runs_ok {
        checks.push(CheckResult {
            check: CheckKind::SessionRunsVerified,
            status: CheckStatus::Pass,
            detail: Some(format!("{} runs verified", run_reports.len())),
        });
    } else {
        let failed = run_reports.iter().filter(|r| !r.passed()).count();
        checks.push(CheckResult {
            check: CheckKind::SessionRunsVerified,
            status: CheckStatus::Fail,
            detail: Some(format!("{failed} runs failed verification")),
        });
    }

    Ok(SessionVerifyReport {
        session_id: session_id.to_string(),
        checks,
        run_reports,
    })
}

/// Hash bytes using the store's configured algorithm.
fn hash_bytes(algo: HashAlgorithm, data: &[u8]) -> String {
    let mut hasher = StreamingHasher::new(algo);
    hasher.update(data);
    hasher.finalize().to_hex()
}

/// Verify the manifest signature from a sidecar `signature.toml`.
///
/// 1. Read manifest.toml raw bytes → hash with store's algorithm.
/// 2. Parse signature.toml → `SignatureInfo`.
/// 3. Check computed hash matches claimed manifest_hash.
/// 4. Verify Ed25519 signature.
/// 5. Check `sig.public_key` is in `trusted_keys` — the trust anchor.
///    Step 5 is what makes this verification mean something: steps 3-4
///    only prove that SOME key signed it, and that key came from inside
///    the file we're verifying.
fn verify_manifest_signature(
    sig_path: &std::path::Path,
    manifest_path: &std::path::Path,
    hash_algo: HashAlgorithm,
    trusted_keys: &[String],
    checks: &mut Vec<CheckResult>,
) {
    // Read signature.toml.
    let sig_content = match std::fs::read_to_string(sig_path) {
        Ok(c) => c,
        Err(e) => {
            checks.push(CheckResult {
                check: CheckKind::ManifestSignature,
                status: CheckStatus::Fail,
                detail: Some(format!("Failed to read signature.toml: {e}")),
            });
            return;
        }
    };

    let sig: oaie_core::signing::SignatureInfo = match toml::from_str(&sig_content) {
        Ok(s) => s,
        Err(e) => {
            checks.push(CheckResult {
                check: CheckKind::ManifestSignature,
                status: CheckStatus::Fail,
                detail: Some(format!("Failed to parse signature.toml: {e}")),
            });
            return;
        }
    };

    // Read manifest bytes.
    let manifest_bytes = match std::fs::read(manifest_path) {
        Ok(b) => b,
        Err(e) => {
            checks.push(CheckResult {
                check: CheckKind::ManifestSignature,
                status: CheckStatus::Fail,
                detail: Some(format!("Failed to read manifest for signature check: {e}")),
            });
            return;
        }
    };

    // Verify the signature against the trust list.
    use crate::signing::VerifyOutcome;
    let pub_short = if sig.public_key.len() >= 12 {
        &sig.public_key[..12]
    } else {
        &sig.public_key
    };
    match crate::signing::verify_signature(&manifest_bytes, &sig, hash_algo, trusted_keys) {
        Ok(VerifyOutcome::Trusted) => {
            checks.push(CheckResult {
                check: CheckKind::ManifestSignature,
                status: CheckStatus::Pass,
                detail: Some(format!(
                    "Signed by {} ({pub_short}.., in trusted_public_keys)",
                    sig.signer_label
                )),
            });
        }
        Ok(VerifyOutcome::UntrustedKey) => {
            // Signature is cryptographically valid but the key isn't
            // in our trust store. This is exactly the self-attesting-
            // signature attack: anyone can generate a key, sign a
            // manifest, and embed both in signature.toml. The math
            // checks out; the trust does not. Fail, not Skip — the
            // signer made a positive claim of authenticity, and that
            // claim is unverified.
            checks.push(CheckResult {
                check: CheckKind::ManifestSignature,
                status: CheckStatus::Fail,
                detail: Some(format!(
                    "Signature valid but public key {pub_short}.. NOT in \
                     trusted_public_keys (signer claims '{}'). Add the key \
                     to config.toml [signing].trusted_public_keys if you \
                     trust this signer — or this is a self-attesting forge.",
                    sig.signer_label
                )),
            });
        }
        Ok(VerifyOutcome::NoTrustStore) => {
            // Signature is cryptographically valid but we have no
            // trust list to check against. Skip, not Pass: the operator
            // must opt in to trust by populating the list.
            checks.push(CheckResult {
                check: CheckKind::ManifestSignature,
                status: CheckStatus::Skip,
                detail: Some(format!(
                    "Signature cryptographically valid (signer claims '{}', \
                     key {pub_short}..) but config.toml has no \
                     [signing].trusted_public_keys — cannot establish trust. \
                     The signature could be self-attesting.",
                    sig.signer_label
                )),
            });
        }
        Ok(VerifyOutcome::BadSignature) => {
            checks.push(CheckResult {
                check: CheckKind::ManifestSignature,
                status: CheckStatus::Fail,
                detail: Some("Signature invalid (manifest hash mismatch or bad signature)".into()),
            });
        }
        Err(e) => {
            checks.push(CheckResult {
                check: CheckKind::ManifestSignature,
                status: CheckStatus::Fail,
                detail: Some(format!("Signature verification error: {e}")),
            });
        }
    }
}
