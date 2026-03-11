//! Tests extracted from oaie-report: REPORT.md generation.

use chrono::Utc;
use oaie_core::artifact::{ArtifactRef, ArtifactType, Hash};
use oaie_core::manifest::{IsolationInfo, IsolationLevel, Manifest};
use oaie_core::run_id::RunId;
use oaie_report::generate_report;
use oaie_report::report::{md_escape, shell_join, shell_quote};

fn sample_manifest(exit_code: Option<i32>, artifacts: Vec<ArtifactRef>) -> Manifest {
    Manifest {
        version: 1,
        hash_algorithm: "blake3".into(),
        run_id: RunId::new(),
        created: Utc::now(),
        command: vec!["echo".into(), "hello world".into()],
        exit_code,
        duration_ms: 1234,
        isolation: IsolationInfo {
            level: IsolationLevel::None,
            namespaces: vec![],
            network: false,
            network_mode: "off".into(),
            landlock: false,
            cgroup: None,
            backend: None,
            firecracker_version: None,
            kernel: None,
            rootfs: None,
            trace_integrity: None,
            interactive: false,
        },
        artifacts,
        policy: None,
        trace: None,
        resources: None,
    }
}

#[test]
fn report_has_header_and_command() {
    let report = generate_report(&sample_manifest(Some(0), vec![]), None);
    assert!(report.contains("# OAIE Run Report"));
    assert!(report.contains("echo 'hello world'"));
    assert!(report.contains("Exit code | 0"));
}

#[test]
fn report_with_artifacts() {
    let artifacts = vec![
        ArtifactRef {
            hash: Hash::from_data(b"stdout data"),
            size: 11,
            label: "stdout".into(),
            artifact_type: ArtifactType::Stdout,
        },
        ArtifactRef {
            hash: Hash::from_data(b"stderr data"),
            size: 0,
            label: "stderr".into(),
            artifact_type: ArtifactType::Stderr,
        },
    ];
    let report = generate_report(&sample_manifest(Some(0), artifacts), None);
    assert!(report.contains("## Artifacts"));
    assert!(report.contains("stdout"));
    assert!(report.contains("stderr"));
}

#[test]
fn report_nonzero_exit() {
    let report = generate_report(&sample_manifest(Some(1), vec![]), None);
    assert!(report.contains("Exit code | 1"));
}

#[test]
fn report_none_exit_code() {
    let report = generate_report(&sample_manifest(None, vec![]), None);
    assert!(report.contains("(none"));
}

#[test]
fn report_with_output_files() {
    let artifacts = vec![ArtifactRef {
        hash: Hash::from_data(b"output"),
        size: 42,
        label: "output/result.txt".into(),
        artifact_type: ArtifactType::Output,
    }];
    let report = generate_report(&sample_manifest(Some(0), artifacts), None);
    assert!(report.contains("## Output Files"));
    assert!(report.contains("output/result.txt"));
}

#[test]
fn report_has_verification_section() {
    let report = generate_report(&sample_manifest(Some(0), vec![]), None);
    assert!(report.contains("## Verification"));
    assert!(report.contains("oaie verify"));
    assert!(report.contains("oaie inspect"));
}

// ── M13: md_escape tests ──

#[test]
fn md_escape_pipes() {
    assert_eq!(md_escape("foo|bar"), "foo\\|bar");
    assert_eq!(md_escape("a|b|c"), "a\\|b\\|c");
}

#[test]
fn md_escape_backticks() {
    assert_eq!(md_escape("foo`bar"), "foo\\`bar");
    assert_eq!(md_escape("`code`"), "\\`code\\`");
}

#[test]
fn md_escape_backslash() {
    assert_eq!(md_escape("foo\\bar"), "foo\\\\bar");
}

#[test]
fn md_escape_newlines() {
    assert_eq!(md_escape("line1\nline2"), "line1 line2");
    assert_eq!(md_escape("line1\r\nline2"), "line1  line2");
    assert_eq!(md_escape("a\nb\nc"), "a b c");
}

#[test]
fn md_escape_unicode_bidi() {
    // LRE, RLE, PDF, LRO, RLO
    let bidi = "safe\u{202A}evil\u{202B}text\u{202C}here\u{202D}test\u{202E}end";
    let escaped = md_escape(bidi);
    assert!(!escaped.contains('\u{202A}'));
    assert!(!escaped.contains('\u{202B}'));
    assert!(!escaped.contains('\u{202C}'));
    assert!(!escaped.contains('\u{202D}'));
    assert!(!escaped.contains('\u{202E}'));
    assert_eq!(escaped, "safeeviltextheretestend");

    // LRI, RLI, FSI, PDI
    let bidi2 = "a\u{2066}b\u{2067}c\u{2068}d\u{2069}e";
    let escaped2 = md_escape(bidi2);
    assert_eq!(escaped2, "abcde");
}

#[test]
fn md_escape_combined() {
    assert_eq!(md_escape("a|b`c\\d\ne"), "a\\|b\\`c\\\\d e");
}

#[test]
fn md_escape_empty_and_safe() {
    assert_eq!(md_escape(""), "");
    assert_eq!(md_escape("hello world"), "hello world");
    assert_eq!(md_escape("path/to/file.txt"), "path/to/file.txt");
}

// ── M14: shell_quote and shell_join tests ──

#[test]
fn shell_quote_empty() {
    assert_eq!(shell_quote(""), "''");
}

#[test]
fn shell_quote_safe_strings() {
    assert_eq!(shell_quote("hello"), "hello");
    assert_eq!(shell_quote("/usr/bin/echo"), "/usr/bin/echo");
    assert_eq!(shell_quote("file.txt"), "file.txt");
    assert_eq!(shell_quote("key=value"), "key=value");
    assert_eq!(shell_quote("a-b_c.d"), "a-b_c.d");
    assert_eq!(shell_quote("+opt"), "+opt");
    assert_eq!(shell_quote("user@host"), "user@host");
    assert_eq!(shell_quote(":port"), ":port");
}

#[test]
fn shell_quote_metacharacters() {
    assert_eq!(shell_quote("hello world"), "'hello world'");
    assert_eq!(shell_quote("$HOME"), "'$HOME'");
    assert_eq!(shell_quote("foo;bar"), "'foo;bar'");
    assert_eq!(shell_quote("a&b"), "'a&b'");
    assert_eq!(shell_quote("a|b"), "'a|b'");
    assert_eq!(shell_quote("a>b"), "'a>b'");
    assert_eq!(shell_quote("a<b"), "'a<b'");
    assert_eq!(shell_quote("a*b"), "'a*b'");
    assert_eq!(shell_quote("a?b"), "'a?b'");
    assert_eq!(shell_quote("a(b)"), "'a(b)'");
}

#[test]
fn shell_quote_single_quotes() {
    assert_eq!(shell_quote("it's"), "'it'\\''s'");
    assert_eq!(shell_quote("'"), "''\\'''");
}

#[test]
fn shell_join_basic() {
    let parts: Vec<String> = vec!["echo".into(), "hello".into()];
    assert_eq!(shell_join(&parts), "echo hello");
}

#[test]
fn shell_join_with_spaces() {
    let parts: Vec<String> = vec!["echo".into(), "hello world".into()];
    assert_eq!(shell_join(&parts), "echo 'hello world'");
}

#[test]
fn shell_join_with_empty() {
    let parts: Vec<String> = vec!["cmd".into(), "".into(), "arg".into()];
    assert_eq!(shell_join(&parts), "cmd '' arg");
}

#[test]
fn shell_join_empty_parts() {
    let parts: Vec<String> = vec![];
    assert_eq!(shell_join(&parts), "");
}
