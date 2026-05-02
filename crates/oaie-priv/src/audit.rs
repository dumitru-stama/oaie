//! Lightweight audit logging for oaie-priv operations.
//!
//! Writes to `/var/log/oaie-priv.log` on a best-effort basis.
//! Errors are silently ignored — audit logging must not block operations.

use std::io::Write;

/// Log file path for audit trail.
const AUDIT_LOG: &str = "/var/log/oaie-priv.log";

/// Log a privileged action with caller identity and result.
///
/// Format: `YYYY-MM-DD HH:MM:SS uid=N pid=N action result`
/// Uses `libc::time` + `gmtime_r` for timestamps to avoid pulling in chrono.
pub fn log_action(
    caller_uid: Option<u32>,
    caller_pid: Option<u32>,
    action: &str,
    result: &str,
) {
    let timestamp = format_timestamp();
    let uid_str = caller_uid.map_or("?".into(), |u| u.to_string());
    let pid_str = caller_pid.map_or("?".into(), |p| p.to_string());

    // Strip line terminators so caller-supplied text cannot forge audit entries.
    let result = result.replace(['\n', '\r'], " ");
    let line = format!("{timestamp} uid={uid_str} pid={pid_str} {action} {result}\n");

    // Best-effort append — ignore all errors.
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(AUDIT_LOG)
    {
        let _ = file.write_all(line.as_bytes());
    }
}

/// Format a UTC timestamp without pulling in the chrono crate.
///
/// Uses `libc::time()` + `libc::gmtime_r()` for a minimal implementation.
fn format_timestamp() -> String {
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::gmtime_r(&now, &mut tm);

        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
        )
    }
}
