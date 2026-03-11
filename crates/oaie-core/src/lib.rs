//! Core types, configuration, and error definitions for OAIE.
//!
//! This crate is imported by every other OAIE crate and deliberately has
//! no heavy dependencies (no rusqlite, no nix). Only pure-Rust crates
//! like blake3, chrono, serde, and uuid are allowed here.

pub mod artifact;
pub mod auto_mount;
pub mod backend;
pub mod cgroup;
pub mod config;
pub mod error;
pub mod hash_algo;
pub mod job;
pub mod log;
pub mod manifest;
pub mod policy;
pub mod run_dir;
pub mod run_id;
pub mod session;
pub mod signing;
pub mod store_config;
pub mod structured_output;
pub mod verify;
