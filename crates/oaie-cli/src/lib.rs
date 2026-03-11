//! OAIE CLI library: exposes the Runner, policy resolution, and doctor
//! diagnostics for integration tests.

pub mod backend_bare;
pub mod backend_firecracker;
pub mod backend_interactive;
pub mod backend_namespace;
pub mod clean;
pub mod doctor;
pub mod policy_resolve;
pub mod runner;
pub mod session_runner;
pub mod signing;
pub mod verify;
pub mod walk;
