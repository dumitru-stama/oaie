//! Minimal logging macros for OAIE.
//!
//! Replaces the `tracing` crate with simple `eprintln!`-based macros gated
//! by a global log level. Respects the `OAIE_LOG` environment variable
//! (values: `error`, `warn`, `info`, `debug`; default: `warn`).
//!
//! The log level is set once at process startup via [`init()`].

use std::sync::atomic::{AtomicU8, Ordering};

/// Numeric log levels (lower = more severe).
const LEVEL_ERROR: u8 = 1;
const LEVEL_WARN: u8 = 2;
const LEVEL_INFO: u8 = 3;
const LEVEL_DEBUG: u8 = 4;

/// Global log level, set once at startup by [`init()`].
static LOG_LEVEL: AtomicU8 = AtomicU8::new(LEVEL_WARN);

/// Initialize the log level from the `OAIE_LOG` environment variable.
///
/// Call once early in `main()`. If the env var is absent or unrecognized,
/// defaults to `warn`. Safe to call multiple times (last write wins).
pub fn init() {
    let level = match std::env::var("OAIE_LOG").as_deref() {
        Ok("error") => LEVEL_ERROR,
        Ok("warn") => LEVEL_WARN,
        Ok("info") => LEVEL_INFO,
        Ok("debug") => LEVEL_DEBUG,
        _ => LEVEL_WARN,
    };
    LOG_LEVEL.store(level, Ordering::Relaxed);
}

/// Returns true if messages at the given level should be emitted.
#[doc(hidden)]
pub fn enabled(level: u8) -> bool {
    level <= LOG_LEVEL.load(Ordering::Relaxed)
}

/// Log level constants exposed for the macros.
#[doc(hidden)]
pub mod level {
    pub const ERROR: u8 = super::LEVEL_ERROR;
    pub const WARN: u8 = super::LEVEL_WARN;
    #[allow(dead_code)]
    pub const INFO: u8 = super::LEVEL_INFO;
    pub const DEBUG: u8 = super::LEVEL_DEBUG;
}

/// Log an error message to stderr.
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::log::level::ERROR) {
            eprintln!("oaie: error: {}", format_args!($($arg)*));
        }
    };
}

/// Log a warning message to stderr.
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::log::level::WARN) {
            eprintln!("oaie: warn: {}", format_args!($($arg)*));
        }
    };
}

/// Log a debug message to stderr.
#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::log::level::DEBUG) {
            eprintln!("oaie: debug: {}", format_args!($($arg)*));
        }
    };
}
