//! The `oaie replay` subcommand — re-run a previous execution and compare outputs.
//!
//! Reconstructs the JobSpec from a stored manifest, re-executes with the same
//! isolation and policy settings, then compares output artifact hashes.

use std::collections::HashMap;
use std::time::Duration;

use clap::Args;

use oaie_cas::store::{format_duration, read_manifest};
use oaie_core::artifact::{ArtifactRef, ArtifactType, Hash};
use oaie_core::job::{JobSpec, TraceMode};
use oaie_core::manifest::Manifest;
use oaie_db::OaieDb;

use oaie_core::error::{OaieError, Result};

use super::load_store;
use crate::output;
use oaie_cli::runner::Runner;

/// Replay a previous run with the same inputs and isolation settings.
#[derive(Args, Debug)]
pub struct ReplayCmd {
    /// Run ID to replay (or prefix, or "last").
    pub run_id: String,

    /// Show hash details for mismatched outputs.
    #[arg(long)]
    pub diff: bool,
}

/// Comparison between an original and a replayed output artifact.
struct OutputMatch {
    /// Artifact label (e.g. "output/result.txt").
    path: String,
    /// Hash of the original output.
    original_hash: Hash,
    /// Hash of the replay output, if the file was produced.
    replay_hash: Option<Hash>,
    /// Whether the hashes match.
    matches: bool,
}

impl ReplayCmd {
    /// Re-execute a stored run and compare outputs.
    pub fn execute(&self) -> Result<()> {
        let store = load_store()?;
        let db = OaieDb::open(&store.db_path)?;

        // Resolve run ID.
        let run = if self.run_id == "last" {
            db.get_latest_run()?.ok_or_else(|| OaieError::Other("no runs found".into()))?
        } else {
            db.get_run_by_prefix(&self.run_id)?
        };

        // Load the original manifest.
        let run_dir = store.runs_dir.join(run.run_id.full());
        let manifest = read_manifest(&run_dir)?;

        // Gate replay on signature trust. replay_policy() below builds
        // a ResolvedPolicy from manifest fields WITHOUT going through
        // Policy::validate() — parse_size().unwrap_or(default) silently
        // swallows bad values, max_pids is taken raw, AllowRule is built
        // with no .validate() call. A self-attesting signature (the bug
        // verify_signature's trust gate exists to fix) plus this
        // unvalidated reconstruction = sandbox config from an untrusted
        // manifest. So: refuse to replay unless the manifest verifies
        // against a TRUSTED key. NoTrustStore (operator hasn't set up
        // trusted_public_keys) is also a refusal — replay is a "load
        // policy from disk" operation and we want explicit opt-in.
        let sig_path = run_dir.join("signature.toml");
        let trusted_keys: &[String] = store.signing.as_ref().map(|s| s.trusted_public_keys.as_slice()).unwrap_or(&[]);
        gate_replay_on_signature(&run_dir, &sig_path, store.hash_algorithm, trusted_keys)?;

        println!();
        output::info(&format!("replaying run {}", run.run_id.short()));
        println!();

        // Reconstruct a JobSpec from the manifest.
        // Replay does NOT trace — we're comparing outputs, not traces.
        // The original input directory is not stored in the manifest, so we
        // use the current directory as default (same as normal run).
        let job = JobSpec {
            command: manifest.command.clone(),
            inputs: None,
            outputs: None,
            network: manifest.isolation.network,
            trace: TraceMode::Off,
            timeout: None,
            policy: None,
            extra_ro: vec![],
            extra_rw: vec![],
            no_isolation: !manifest.isolation.level.is_isolated(),
            backend: Default::default(),
            interactive: false,
        };

        // Build a policy from the manifest's policy info.
        let policy = replay_policy(&manifest);

        // Warn the user about inherent replay limitations.
        output::warn(
            "replay does not restore the original input directory or mount points; \
                       results may differ if the run depended on specific paths",
        );

        // Execute the replay run.
        let runner = Runner::new(store.clone())?;
        let replay_result = runner.execute(&job, &policy, true, None)?;

        // Load the replay manifest.
        let replay_run_dir = store.runs_dir.join(replay_result.run_id.full());
        let replay_manifest = read_manifest(&replay_run_dir)?;

        // Compare output artifacts.
        let comparisons = compare_outputs(&manifest, &replay_manifest);
        print_replay_result(&run.run_id, &replay_result.run_id, &comparisons, manifest.duration_ms, replay_result.duration.as_millis().min(u64::MAX as u128) as u64, self.diff);

        Ok(())
    }
}

/// Build a ResolvedPolicy from the manifest's policy info for replay.
fn replay_policy(manifest: &Manifest) -> oaie_cli::policy_resolve::ResolvedPolicy {
    use oaie_core::policy;

    // Start from the safe preset, then override with what the manifest recorded.
    let safe = policy::Policy::preset_safe();
    let deny_paths = safe.mounts.deny.iter().map(|p| policy::expand_tilde(p)).collect();

    let (network, max_memory, max_time, max_pids, max_fsize, allow_memfd) = if let Some(ref pi) = manifest.policy {
        // Reconstruct NetworkMode from manifest, preserving allowlist rules.
        let net_mode = if manifest.isolation.network_mode == "allowlist" {
            // Rebuild AllowRule vec from serialized rules in the manifest.
            let rules = pi
                .network_rules
                .as_ref()
                .map(|serialized| {
                    serialized
                        .iter()
                        .map(|r| {
                            let is_cidr = r.target.contains('/');
                            policy::AllowRule {
                                host: if is_cidr { None } else { Some(r.target.clone()) },
                                cidr: if is_cidr { Some(r.target.clone()) } else { None },
                                port: r.port,
                                protocol: r.protocol.clone(),
                            }
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            policy::NetworkMode::Allowlist(rules)
        } else if pi.network {
            policy::NetworkMode::On
        } else {
            policy::NetworkMode::Off
        };
        (
            net_mode,
            policy::parse_size(&pi.max_memory).unwrap_or(512 * 1024 * 1024),
            policy::parse_duration_policy(&pi.max_time).unwrap_or(Duration::from_secs(300)),
            pi.max_pids,
            policy::parse_size(&pi.max_fsize).unwrap_or(1024 * 1024 * 1024),
            pi.allow_memfd,
        )
    } else {
        (policy::NetworkMode::Off, 512 * 1024 * 1024, Duration::from_secs(300), 64, 1024 * 1024 * 1024, false)
    };

    oaie_cli::policy_resolve::ResolvedPolicy {
        name: manifest.policy.as_ref().and_then(|p| p.name.clone()),
        network,
        timeout: Some(max_time),
        trace: TraceMode::Off,
        input_dir: std::path::PathBuf::from("."),
        output_dir: None,
        ro_mounts: vec![],
        rw_mounts: vec![],
        bind_mounts: vec![],
        deny_paths,
        max_memory,
        max_time,
        max_pids,
        max_fsize,
        // Manifest doesn't carry max_files, so replays use the historical
        // NOFILE limit to reproduce the original run faithfully.
        max_files: 1024,
        allow_memfd,
        retain_caps: 0,
        auto_mounts: vec![],
        cpu_quota: None,
        cgroup_mode: oaie_core::cgroup::CgroupMode::Off,
    }
}

/// Refuse replay unless the manifest's signature verifies against a
/// key in `trusted_public_keys`. Replay reconstructs a policy from
/// manifest fields without going through Policy::validate(); a
/// self-attesting signature is the only thing that would otherwise
/// stop a forged manifest from feeding the sandbox.
fn gate_replay_on_signature(run_dir: &std::path::Path, sig_path: &std::path::Path, hash_algo: oaie_core::hash_algo::HashAlgorithm, trusted_keys: &[String]) -> oaie_core::error::Result<()> {
    use oaie_cli::signing::VerifyOutcome;

    if !sig_path.exists() {
        return Err(OaieError::Other(format!(
            "replay refused: {} has no signature.toml. Replay reconstructs \
             sandbox policy from the manifest without re-validating it; an \
             unsigned manifest is untrusted input. Sign the run or replay \
             a different one.",
            run_dir.display()
        )));
    }
    if trusted_keys.is_empty() {
        return Err(OaieError::Other(
            "replay refused: config.toml has no [signing].trusted_public_keys. \
             Replay reconstructs sandbox policy from the manifest, so the \
             manifest's signature must verify against a TRUSTED key — a \
             cryptographically-valid signature against a key from inside the \
             file under verification proves nothing. Populate \
             trusted_public_keys with `oaie key list --json | jq '.[].public_key'` \
             for keys you generated locally."
                .into(),
        ));
    }

    let sig_content = std::fs::read_to_string(sig_path).map_err(|e| OaieError::Other(format!("read {}: {e}", sig_path.display())))?;
    let sig: oaie_core::signing::SignatureInfo = toml::from_str(&sig_content).map_err(|e| OaieError::Other(format!("parse signature.toml: {e}")))?;
    let manifest_path = run_dir.join("manifest.toml");
    let manifest_bytes = std::fs::read(&manifest_path).map_err(|e| OaieError::Other(format!("read manifest for sig check: {e}")))?;

    match oaie_cli::signing::verify_signature(&manifest_bytes, &sig, hash_algo, trusted_keys)? {
        VerifyOutcome::Trusted => Ok(()),
        VerifyOutcome::UntrustedKey => Err(OaieError::Other(format!(
            "replay refused: signature is cryptographically valid but the \
             public key ({}.., signer claims '{}') is NOT in \
             config.toml [signing].trusted_public_keys. This is exactly \
             the self-attesting-signature shape — anyone can generate a \
             key, sign any manifest, and embed both in signature.toml. \
             Add the key to trusted_public_keys IF you trust this signer.",
            &sig.public_key[..sig.public_key.len().min(12)],
            sig.signer_label
        ))),
        VerifyOutcome::BadSignature => Err(OaieError::Other(
            "replay refused: signature invalid (manifest hash mismatch \
             or Ed25519 verify failed). Manifest may be tampered."
                .into(),
        )),
        // Already handled above by the trusted_keys.is_empty() check,
        // but exhaustive match.
        VerifyOutcome::NoTrustStore => Err(OaieError::Other("replay refused: no trust store".into())),
    }
}

/// Compare output artifacts between original and replay manifests.
fn compare_outputs(original: &Manifest, replay: &Manifest) -> Vec<OutputMatch> {
    let mut comparisons = Vec::new();

    let orig_outputs: Vec<&ArtifactRef> = original.artifacts.iter().filter(|a| a.artifact_type == ArtifactType::Output).collect();
    let replay_outputs: Vec<&ArtifactRef> = replay.artifacts.iter().filter(|a| a.artifact_type == ArtifactType::Output).collect();

    // Build a map of replay outputs by label.
    let replay_map: HashMap<&str, &ArtifactRef> = replay_outputs.iter().map(|a| (a.label.as_str(), *a)).collect();

    // Check original outputs against replay.
    for orig in &orig_outputs {
        match replay_map.get(orig.label.as_str()) {
            Some(replay_artifact) => {
                comparisons.push(OutputMatch {
                    path: orig.label.clone(),
                    original_hash: orig.hash.clone(),
                    replay_hash: Some(replay_artifact.hash.clone()),
                    matches: orig.hash == replay_artifact.hash,
                });
            }
            None => {
                comparisons.push(OutputMatch {
                    path: orig.label.clone(),
                    original_hash: orig.hash.clone(),
                    replay_hash: None,
                    matches: false,
                });
            }
        }
    }

    // Check for new files in replay that weren't in original.
    for replay_artifact in &replay_outputs {
        if !orig_outputs.iter().any(|a| a.label == replay_artifact.label) {
            comparisons.push(OutputMatch {
                path: format!("{} (new in replay)", replay_artifact.label),
                original_hash: Hash::from_data(b""),
                replay_hash: Some(replay_artifact.hash.clone()),
                matches: false,
            });
        }
    }

    // Also compare stdout and stderr hashes.
    let orig_stdout = original.artifacts.iter().find(|a| a.artifact_type == ArtifactType::Stdout);
    let replay_stdout = replay.artifacts.iter().find(|a| a.artifact_type == ArtifactType::Stdout);
    if let (Some(o), Some(r)) = (orig_stdout, replay_stdout) {
        comparisons.push(OutputMatch {
            path: "stdout".into(),
            original_hash: o.hash.clone(),
            replay_hash: Some(r.hash.clone()),
            matches: o.hash == r.hash,
        });
    }

    comparisons
}

/// Print replay comparison results.
fn print_replay_result(original_id: &oaie_core::run_id::RunId, replay_id: &oaie_core::run_id::RunId, comparisons: &[OutputMatch], orig_ms: u64, replay_ms: u64, show_diff: bool) {
    let total = comparisons.len();
    let matching = comparisons.iter().filter(|m| m.matches).count();
    let differing = total - matching;

    output::info(&format!("replay results (original {} -> replay {})", original_id.short(), replay_id.short()));
    println!();

    for m in comparisons {
        if m.matches {
            println!("  {} {} -- identical", output::pass_icon(), m.path);
        } else if m.replay_hash.is_none() {
            println!("  {} {} -- missing in replay (was in original)", output::skip_icon(), m.path);
        } else {
            println!("  {} {} -- differs", output::fail_icon(), m.path);
            if show_diff {
                println!("      original: {}", m.original_hash.short());
                if let Some(ref rh) = m.replay_hash {
                    println!("      replay:   {}", rh.short());
                }
            }
        }
    }

    println!();
    println!("  {} outputs compared: {} identical, {} differ", total, matching, differing);
    println!("  Timing: original {}, replay {}", format_duration(orig_ms), format_duration(replay_ms));

    if differing > 0 {
        println!();
        output::info("Note: output differences are common and expected.");
        eprintln!("      Many tools produce nondeterministic output (timestamps, PIDs, ASLR).");
        eprintln!("      See 'oaie help replay' for known nondeterminism sources.");
    }
    println!();
}
