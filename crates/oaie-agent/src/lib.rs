//! Library interface for calling OAIE from Rust agents and tools.
//!
//! Provides [`OaieClient`], a synchronous builder for running commands inside
//! OAIE's sandbox and getting structured results back. Designed for AI agent
//! integration — same security guarantees as the CLI, but callable from code.
//!
//! # Example
//!
//! ```no_run
//! use oaie_agent::OaieClient;
//!
//! let result = OaieClient::new("/home/user/.oaie")
//!     .policy("agent-safe")
//!     .run(&["echo", "hello"])
//!     .unwrap();
//!
//! assert_eq!(result.exit_code, 0);
//! ```

pub mod client;
pub mod types;

pub use client::{OaieClient, SessionClient, SessionStatusInfo};
pub use oaie_core::structured_output::StructuredRunResult;
pub use types::VerifyReport;
