//! oaie-priv library — exposes protocol and validation types for testing.
//!
//! The binary (`main.rs`) imports these modules via `use oaie_priv::*`.
//! Test code in `oaie-tests` can also import them to verify protocol
//! serialization, validation logic, and edge cases.

pub mod audit;
pub mod cgroup;
pub mod fd_passing;
pub mod protocol;
pub mod validate;

#[cfg(feature = "ebpf")]
pub mod bpf;
