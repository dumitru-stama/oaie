//! REPORT.md generation from a run manifest and optional trace summary.
//!
//! Pure function: takes a [`Manifest`] and optional [`TraceSummary`],
//! returns formatted Markdown. No side effects, no filesystem access.
//! The caller writes the result.

use oaie_core::artifact::ArtifactType;
use oaie_core::manifest::Manifest;
use oaie_observe::TraceSummary;

/// Generate a Markdown report from a completed run manifest.
///
/// When `summary` is `Some`, renders rich observation sections (files read/written,
/// network activity, process tree, suspicious activity). When `None`, shows
/// basic trace metadata or "Tracing not enabled".
pub fn generate_report(manifest: &Manifest, summary: Option<&TraceSummary>) -> String {
    let mut r = String::with_capacity(4096);

    r.push_str("# OAIE Run Report\n\n");

    // Summary table.
    r.push_str("## Summary\n\n");
    r.push_str("| Field | Value |\n");
    r.push_str("|---|---|\n");
    r.push_str(&format!("| Run ID | `{}` |\n", md_escape(&manifest.run_id.full())));
    r.push_str(&format!("| Created | {} |\n", manifest.created.to_rfc3339()));
    r.push_str(&format!("| Command | `{}` |\n", md_escape(&shell_join(&manifest.command))));

    match manifest.exit_code {
        Some(code) => r.push_str(&format!("| Exit code | {} |\n", code)),
        None => r.push_str("| Exit code | (none — killed or still running) |\n"),
    }

    r.push_str(&format!(
        "| Duration | {} |\n",
        format_duration_human(manifest.duration_ms)
    ));
    r.push_str(&format!(
        "| Isolation | {} |\n",
        md_escape(&manifest.isolation.level.to_string())
    ));
    if manifest.isolation.interactive {
        r.push_str("| Interactive | yes (PTY) |\n");
    }
    r.push_str(&format!(
        "| Network | {} |\n",
        if manifest.isolation.network {
            "allowed"
        } else {
            "blocked"
        }
    ));

    // Firecracker-specific fields.
    if let Some(ref backend) = manifest.isolation.backend {
        r.push_str(&format!("| Backend | {} |\n", md_escape(backend)));
    }
    if let Some(ref ver) = manifest.isolation.firecracker_version {
        r.push_str(&format!("| Firecracker | v{} |\n", md_escape(ver)));
    }
    if let Some(ref kernel) = manifest.isolation.kernel {
        r.push_str(&format!("| Kernel | `{}` |\n", md_escape(kernel)));
    }
    if let Some(ref rootfs) = manifest.isolation.rootfs {
        r.push_str(&format!("| Rootfs | `{}` |\n", md_escape(rootfs)));
    }
    if let Some(ref integrity) = manifest.isolation.trace_integrity {
        r.push_str(&format!("| Trace integrity | {} |\n", md_escape(integrity)));
    }

    r.push('\n');

    // Network policy section (only for allowlist mode).
    if manifest.isolation.network_mode == "allowlist" {
        r.push_str("## Network Policy\n\n");
        r.push_str("| Setting | Value |\n");
        r.push_str("|---|---|\n");
        r.push_str("| Mode | allowlist |\n");
        if let Some(ref pol) = manifest.policy {
            if let Some(ref rules) = pol.network_rules {
                for rule in rules {
                    r.push_str(&format!(
                        "| Allow | `{}:{}/{}` |\n",
                        md_escape(&rule.target),
                        rule.port,
                        md_escape(&rule.protocol),
                    ));
                }
            }
        }
        r.push('\n');
    }

    // Artifacts table.
    if !manifest.artifacts.is_empty() {
        r.push_str("## Artifacts\n\n");
        r.push_str("| Label | Type | Hash | Size |\n");
        r.push_str("|---|---|---|---|\n");
        for a in &manifest.artifacts {
            r.push_str(&format!(
                "| `{}` | {} | `{}` | {} |\n",
                md_escape(&a.label),
                a.artifact_type,
                a.hash.short(),
                format_size_human(a.size),
            ));
        }
        r.push('\n');
    }

    // Output files subsection.
    let outputs: Vec<_> = manifest
        .artifacts
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::Output)
        .collect();
    if !outputs.is_empty() {
        r.push_str("## Output Files\n\n");
        for a in &outputs {
            r.push_str(&format!(
                "- `{}` — {} (`{}`)\n",
                md_escape(&a.label),
                format_size_human(a.size),
                a.hash.short(),
            ));
        }
        r.push('\n');
    }

    // Policy section.
    if let Some(ref policy) = manifest.policy {
        r.push_str("## Policy\n\n");
        r.push_str("| Setting | Value |\n");
        r.push_str("|---|---|\n");
        if let Some(ref name) = policy.name {
            r.push_str(&format!("| Name | `{}` |\n", md_escape(name)));
        }
        r.push_str(&format!(
            "| Network | {} |\n",
            if policy.network { "allowed" } else { "blocked" }
        ));
        // Show enforcement mechanism: cgroup (hard) or rlimit (advisory).
        let cgroup_active = manifest.isolation.cgroup.as_ref().is_some_and(|c| c.enforced);
        if cgroup_active {
            r.push_str(&format!(
                "| Max memory | {} (enforced — cgroup memory.max) |\n",
                md_escape(&policy.max_memory)
            ));
        } else {
            r.push_str(&format!(
                "| Max memory | {} (advisory — RLIMIT_AS) |\n",
                md_escape(&policy.max_memory)
            ));
        }
        r.push_str(&format!("| Max time | {} |\n", md_escape(&policy.max_time)));
        if cgroup_active {
            r.push_str(&format!(
                "| Max PIDs | {} (enforced — cgroup pids.max) |\n",
                policy.max_pids
            ));
        } else {
            r.push_str(&format!(
                "| Max PIDs | {} (system-wide per-UID — RLIMIT_NPROC) |\n",
                policy.max_pids
            ));
        }
        r.push_str(&format!(
            "| Max file size | {} (RLIMIT_FSIZE) |\n",
            md_escape(&policy.max_fsize)
        ));

        if policy.allow_memfd {
            r.push_str("| memfd/execveat | allowed |\n");
        }

        if !policy.deny_paths.is_empty() {
            r.push_str(&format!(
                "| Denied paths | {} |\n",
                policy.deny_paths.len()
            ));
        }

        if !policy.auto_mounts.is_empty() {
            r.push_str(&format!(
                "| Auto-mounts | {} |\n",
                policy.auto_mounts.len()
            ));
        }
        r.push('\n');
    }

    // Resource Accounting section (when cgroup isolation was active).
    if let Some(ref res) = manifest.resources {
        r.push_str("## Resource Accounting\n\n");
        r.push_str("| Metric | Value |\n");
        r.push_str("|---|---|\n");
        if let Some(ref limit) = res.memory_limit {
            r.push_str(&format!("| Memory limit | {} |\n", md_escape(limit)));
        }
        if let Some(ref peak) = res.memory_peak {
            r.push_str(&format!("| Memory peak | {} |\n", md_escape(peak)));
        }
        if let Some(user_ms) = res.cpu_user_ms {
            r.push_str(&format!("| CPU user | {}ms |\n", user_ms));
        }
        if let Some(sys_ms) = res.cpu_system_ms {
            r.push_str(&format!("| CPU system | {}ms |\n", sys_ms));
        }
        if let Some(pids) = res.pids_peak {
            r.push_str(&format!("| PIDs peak | {} |\n", pids));
        }
        r.push('\n');
    }

    // Observation section.
    render_observation_section(&mut r, manifest, summary);

    // Verification section.
    r.push_str("## Verification\n\n");
    r.push_str("```bash\n");
    r.push_str(&format!("oaie verify {}\n", manifest.run_id.short()));
    r.push_str(&format!("oaie inspect {}\n", manifest.run_id.short()));
    r.push_str("```\n");

    if manifest.trace.is_none() {
        r.push_str("\n> **Tip:** Re-run with `--trace=ptrace` to observe file accesses,\n");
        r.push_str("> network connections, and process activity.\n");
    }

    r
}

/// Render the observation/trace section of the report.
fn render_observation_section(r: &mut String, manifest: &Manifest, summary: Option<&TraceSummary>) {
    r.push_str("## Observed Accesses\n\n");

    let trace = match &manifest.trace {
        Some(t) => t,
        None => {
            r.push_str("_Tracing not enabled. Use `--trace=strace` to observe access._\n\n");
            return;
        }
    };

    r.push_str(&format!(
        "_Traced via {} — {} events captured._\n\n",
        md_escape(&trace.backend), trace.event_count
    ));
    r.push_str(&format!(
        "Chain tip: `{}`\n",
        md_escape(if trace.chain_tip.len() >= 12 {
            // Use .get() to safely handle non-ASCII (avoids panic on non-char boundary).
            trace.chain_tip.get(..12).unwrap_or(&trace.chain_tip)
        } else {
            &trace.chain_tip
        })
    ));
    if trace.dropped > 0 {
        r.push_str(&format!("Events dropped: {}\n", trace.dropped));
    }
    if trace.chunks > 1 {
        r.push_str(&format!("Chunks: {}\n", trace.chunks));
    }
    r.push('\n');

    // Rich sections from TraceSummary.
    let summary = match summary {
        Some(s) => s,
        None => return,
    };

    // Files Read.
    if !summary.files_read.is_empty() {
        r.push_str("### Files Read\n\n");
        r.push_str("| Path | Category | Accesses |\n");
        r.push_str("|---|---|---|\n");
        for entry in summary.files_read.iter().take(30) {
            r.push_str(&format!(
                "| `{}` | `{}` | {} |\n",
                md_escape(&entry.path), md_escape(&entry.category.to_string()), entry.count
            ));
        }
        if summary.files_read.len() > 30 {
            r.push_str(&format!(
                "\n_...and {} more files._\n",
                summary.files_read.len() - 30
            ));
        }
        r.push('\n');
    }

    // Files Written.
    if !summary.files_written.is_empty() {
        r.push_str("### Files Written\n\n");
        for entry in &summary.files_written {
            r.push_str(&format!("- `{}` ({} accesses)\n", md_escape(&entry.path), entry.count));
        }
        r.push('\n');
    }

    // Access Denied.
    if !summary.file_access_denied.is_empty() {
        r.push_str("### Access Denied\n\n");
        for entry in &summary.file_access_denied {
            r.push_str(&format!(
                "- `{}` ({} attempts)\n",
                md_escape(&entry.path), entry.count
            ));
        }
        r.push('\n');
    }

    // Suspicious Activity.
    if !summary.suspicious_activity.is_empty() {
        r.push_str("### Suspicious Activity\n\n");
        r.push_str("| PID | Category | Detail | Count |\n");
        r.push_str("|---|---|---|---|\n");
        for entry in &summary.suspicious_activity {
            r.push_str(&format!(
                "| {} | `{}` | `{}` | {} |\n",
                entry.pid, md_escape(&entry.category.to_string()), md_escape(&entry.detail), entry.count
            ));
        }
        r.push('\n');
    }

    // DNS Queries.
    if !summary.dns_queries.is_empty() {
        r.push_str("### DNS Queries\n\n");
        r.push_str("| Domain | Server | Count |\n");
        r.push_str("|---|---|---|\n");
        for entry in &summary.dns_queries {
            r.push_str(&format!(
                "| `{}` | `{}` | {} |\n",
                md_escape(&entry.name), md_escape(&entry.server), entry.count
            ));
        }
        r.push('\n');
    }

    // Network Activity.
    r.push_str("### Network Activity\n\n");
    if summary.net_connects.is_empty() && summary.net_denied.is_empty() {
        r.push_str("No network connections.\n\n");
    } else {
        r.push_str("| Address | Status | Count |\n");
        r.push_str("|---|---|---|\n");
        for entry in &summary.net_connects {
            r.push_str(&format!(
                "| `{}` | connected | {} |\n",
                md_escape(&entry.address), entry.count
            ));
        }
        for entry in &summary.net_denied {
            r.push_str(&format!(
                "| `{}` | denied | {} |\n",
                md_escape(&entry.address), entry.count
            ));
        }
        r.push('\n');
    }

    // Process Tree.
    if !summary.process_tree.is_empty() {
        r.push_str("### Process Tree\n\n");
        r.push_str("```\n");
        for proc in &summary.process_tree {
            // Cap indent depth to prevent excessively wide output from
            // malicious process trees (e.g. 10000-deep fork chains).
            let capped_depth = proc.depth.min(64);
            let indent = "  ".repeat(capped_depth);
            let exit_str = match proc.exit_code {
                Some(0) => String::new(),
                Some(code) => format!(" (exit {code})"),
                None => " (running)".to_string(),
            };
            // Sanitize command to prevent closing the code fence (``` injection)
            // and newline injection (which could close the fence and inject Markdown).
            let safe_cmd = proc.command.replace('`', "'").replace(['\n', '\r'], " ");
            r.push_str(&format!(
                "{indent}[{}] {}{}\n",
                proc.pid, safe_cmd, exit_str
            ));
        }
        r.push_str("```\n\n");
    }
}

/// Escape characters in user-supplied strings for safe Markdown rendering.
///
/// Without this, a malicious filename like `foo|bar` could break table formatting
/// or inject extra cells. Also escapes backslash (Markdown escape char) and
/// backtick (which would break inline code spans).
/// Escape characters in user-supplied strings for safe Markdown rendering.
///
/// Pipe (|) breaks table formatting. Backslash and backtick are Markdown
/// escape/code chars. Underscores and asterisks are not escaped because all
/// user strings are rendered inside backtick inline code spans (`path`)
/// where emphasis is not interpreted.
///
/// Also strips Unicode bidirectional override characters (U+202A–U+202E,
/// U+2066–U+2069) which can reorder displayed text to mislead report readers
/// (e.g. making a malicious path look like a benign one).
pub fn md_escape(s: &str) -> String {
    // Strip newlines first — a newline inside a table cell breaks the row
    // and could inject arbitrary Markdown below the table.
    s.replace(['\n', '\r'], " ")
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('`', "\\`")
        // Strip Unicode bidi override characters that could mislead readers.
        .replace([
            '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}',
            '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        ], "")
}

/// Join command parts into a shell-safe string for display.
///
/// Uses POSIX single-quoting for safety. Parts containing shell metacharacters
/// (`$`, `` ` ``, `|`, `\`, etc.) are wrapped in single quotes.
pub fn shell_join(parts: &[String]) -> String {
    parts
        .iter()
        .map(|p| shell_quote(p))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Shell-quote a single argument for safe display.
pub fn shell_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_./=+:@".contains(c))
    {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Format milliseconds as human-readable duration.
fn format_duration_human(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.3}s", ms as f64 / 1000.0)
    } else {
        let secs = ms / 1000;
        let mins = secs / 60;
        let rem = secs % 60;
        format!("{mins}m{rem}s")
    }
}

/// Format bytes as human-readable size.
fn format_size_human(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
