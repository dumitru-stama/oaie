//! All OAIE output goes through these functions for consistent formatting.
//! Prefix: "OAIE:" so messages are distinguishable from tool output.
//! Respects NO_COLOR env var (<https://no-color.org/>).
//! Respects `--quiet` via a global flag: when set, all OAIE chrome is suppressed
//! and only the sandboxed command's own stdout/stderr passes through.

use std::env;
use std::sync::atomic::{AtomicBool, Ordering};

/// Global quiet flag — when true, all output functions become no-ops.
static QUIET: AtomicBool = AtomicBool::new(false);

/// Enable quiet mode (called from main before command dispatch).
pub fn set_quiet(q: bool) {
    QUIET.store(q, Ordering::Relaxed);
}

pub fn is_quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

fn no_color() -> bool {
    env::var_os("NO_COLOR").is_some()
}

/// Print the OAIE ASCII banner: logo on the left, name + version on the right.
/// Output goes to stderr so it doesn't interfere with piped data on stdout.
pub fn banner() {
    if is_quiet() {
        return;
    }
    let version = env!("CARGO_PKG_VERSION");
    eprintln!(
        r#"  ___    _    ___ _____
 / _ \  / \  |_ _| ____|   OAIE v{version}
| | | |/ _ \  | ||  _|     Observed & Attested
| |_| / ___ \ | || |___    Isolated Execution
 \___/_/   \_\___|_____|"#
    );
    eprintln!();
}

/// Standard info message: "OAIE: message"
pub fn info(msg: &str) {
    if is_quiet() {
        return;
    }
    eprintln!("OAIE: {msg}");
}

/// Warning: "OAIE: \u{26a0} message" (warning sign is the only emoji, used sparingly).
pub fn warn(msg: &str) {
    if is_quiet() {
        return;
    }
    if no_color() {
        eprintln!("OAIE: Warning: {msg}");
    } else {
        eprintln!("OAIE: \u{26a0} {msg}");
    }
}

/// Error: "OAIE: Error: message"
///
/// Always printed regardless of `--quiet` — a silent `exit(1)` is undebuggable.
/// Errors are exceptional; suppressing them makes scripted usage impossible.
pub fn error(msg: &str) {
    eprintln!("OAIE: Error: {msg}");
}

/// Section header, printed to stdout.
pub fn header(title: &str) {
    if is_quiet() {
        return;
    }
    println!("=== {title} ===");
}

/// Key-value pair: "  Key:  value" (aligned with colon after key).
pub fn field(key: &str, value: &str) {
    if is_quiet() {
        return;
    }
    // Pad key+colon to 16 chars for alignment.
    let label = format!("{key}:");
    println!("  {label:<16}{value}");
}

/// Visual separator line between output sections.
pub fn separator() {
    if is_quiet() {
        return;
    }
    println!("{}", "-".repeat(60));
}

/// Join command parts into a shell-safe string for display.
///
/// Uses POSIX single-quoting: wraps any part containing shell metacharacters
/// in single quotes, and escapes embedded single quotes as `'\''`.
/// Parts that are purely alphanumeric/path-safe are left unquoted.
pub fn shell_join(parts: &[String]) -> String {
    parts
        .iter()
        .map(|p| shell_quote(p))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Pass icon: checkmark or "[PASS]" when NO_COLOR is set.
pub fn pass_icon() -> &'static str {
    if no_color() {
        "[PASS]"
    } else {
        "\u{2713}"
    }
}

/// Fail icon: cross mark or "[FAIL]" when NO_COLOR is set.
pub fn fail_icon() -> &'static str {
    if no_color() {
        "[FAIL]"
    } else {
        "\u{2717}"
    }
}

/// Skip/missing icon: en-dash or "[SKIP]" when NO_COLOR is set.
pub fn skip_icon() -> &'static str {
    if no_color() {
        "[SKIP]"
    } else {
        "\u{2013}"
    }
}

// ── ANSI color helpers ──

/// Wrap text in red (ANSI 31). No-op when NO_COLOR is set.
pub fn red(text: &str) -> String {
    if no_color() {
        text.to_string()
    } else {
        format!("\x1b[31m{text}\x1b[0m")
    }
}

/// Wrap text in yellow (ANSI 33). No-op when NO_COLOR is set.
pub fn yellow(text: &str) -> String {
    if no_color() {
        text.to_string()
    } else {
        format!("\x1b[33m{text}\x1b[0m")
    }
}

/// Wrap text in grey/dim (ANSI 90). No-op when NO_COLOR is set.
pub fn grey(text: &str) -> String {
    if no_color() {
        text.to_string()
    } else {
        format!("\x1b[90m{text}\x1b[0m")
    }
}

/// Wrap text in green (ANSI 32). No-op when NO_COLOR is set.
pub fn green(text: &str) -> String {
    if no_color() {
        text.to_string()
    } else {
        format!("\x1b[32m{text}\x1b[0m")
    }
}

/// Shell-quote a single argument for safe display.
///
/// Returns the argument unquoted if it contains only safe characters
/// (alphanumeric, `-`, `_`, `.`, `/`, `=`, `+`, `:`). Otherwise wraps
/// in single quotes with embedded single quotes escaped as `'\''`.
fn shell_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    // Safe chars: no quoting needed.
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_./=+:@".contains(c))
    {
        return s.to_string();
    }
    // POSIX single-quote: only single quotes need special handling.
    format!("'{}'", s.replace('\'', "'\\''"))
}
