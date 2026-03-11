//! Tamper-evident hash chain for observation events.
//!
//! Every event includes the hash of the previous event's serialized bytes.
//! The first event links to a deterministic genesis hash. If anyone edits,
//! deletes, inserts, or reorders an event, `verify_chain()` detects it.
//!
//! Supports both BLAKE3 and SHA-256 — the algorithm is chosen at store init.

use oaie_core::artifact::Hash;
use oaie_core::hash_algo::HashAlgorithm;

use crate::event::OaieEvent;

/// The genesis string — hashed to produce the "zero block" of the chain.
/// Never change this: it would break verification of all existing BLAKE3 traces.
const CHAIN_GENESIS_BLAKE3: &str = "OAIE_CHAIN_GENESIS";

/// Distinct genesis string for SHA-256 chains so they can't accidentally cross.
const CHAIN_GENESIS_SHA256: &str = "OAIE_CHAIN_GENESIS_SHA256";

/// Compute the deterministic genesis hash for the given algorithm.
pub fn genesis_hash(algo: HashAlgorithm) -> String {
    let genesis_str = match algo {
        HashAlgorithm::Blake3 => CHAIN_GENESIS_BLAKE3,
        HashAlgorithm::Sha256 => CHAIN_GENESIS_SHA256,
    };
    Hash::compute(algo, genesis_str.as_bytes()).to_hex()
}

/// Builds a hash chain over events as they are appended.
///
/// Used by [`EventWriter`](crate::writer::EventWriter) during a run.
/// After each `append()`, `tip_hash()` reflects the latest chain state.
pub struct EventChain {
    /// Hash of the most recently appended event (or genesis for empty chain).
    prev_hash: String,
    /// Which algorithm to use for hashing events.
    algo: HashAlgorithm,
}

impl EventChain {
    /// Create a new chain starting from the genesis hash.
    pub fn new(algo: HashAlgorithm) -> Self {
        Self {
            prev_hash: genesis_hash(algo),
            algo,
        }
    }

    /// Finalize an event: set its `hash_prev` field and compute the new chain tip.
    ///
    /// Returns the serialized event bytes (exactly what should be written to the log).
    /// The caller must write these bytes, not re-serialize the event, because
    /// chain verification depends on byte-exact matching.
    ///
    /// # Chain integrity contract
    ///
    /// This method advances the chain tip **before** the caller writes the bytes.
    /// If the write fails, the caller **must** call [`restore_tip()`](Self::restore_tip)
    /// with the previously saved tip to roll back. Failing to do so permanently
    /// desyncs the chain — subsequent events will reference a hash that was
    /// never written to the log.
    pub fn append(&mut self, event: &mut OaieEvent) -> Vec<u8> {
        event.hash_prev = self.prev_hash.clone();

        let serialized =
            serde_json::to_vec(event).expect("OaieEvent serialization cannot fail");

        let event_hash = Hash::compute(self.algo, &serialized);
        self.prev_hash = event_hash.to_hex();

        serialized
    }

    /// Current chain tip hash — written into the manifest after finalization.
    pub fn tip_hash(&self) -> &str {
        &self.prev_hash
    }

    /// Restore the chain tip to a previously saved value.
    ///
    /// Used by writers to roll back the chain state when a write fails after
    /// `append()` has already advanced the tip. Without this, a failed write
    /// would permanently desync the chain.
    pub fn restore_tip(&mut self, prev_hash: String) {
        self.prev_hash = prev_hash;
    }
}

/// Result of chain verification.
#[derive(Debug, PartialEq)]
pub enum ChainVerifyResult {
    /// The chain is intact. All events link correctly.
    Valid {
        /// Number of events verified.
        events: usize,
        /// Hash of the final event (the chain tip).
        tip_hash: String,
    },
    /// The chain is broken at a specific event.
    Broken {
        /// Zero-based index of the first broken event.
        event_index: usize,
        /// The hash_prev we expected (computed from the prior event).
        expected: String,
        /// The hash_prev we found in the event.
        found: String,
    },
    /// The event stream was empty (no events to verify).
    Empty,
}

/// Verify a chain of events against a genesis hash using the specified algorithm.
///
/// Re-serializes each event and checks that every `hash_prev` matches
/// the hash of the previous event's serialized bytes.
///
/// # Serialization stability
///
/// Chain verification depends on **byte-exact** reproducibility of event
/// serialization. Both `append()` and `verify_chain()` use `serde_json::to_vec`
/// (compact JSON, no pretty-printing, deterministic field order from struct
/// derive order). Changing the serialization format (e.g. switching to
/// `serde_json::to_string_pretty`, reordering `OaieEvent` fields, or upgrading
/// serde_json to a version with different float formatting) will break
/// verification of all existing chains.
pub fn verify_chain(events: &[OaieEvent], genesis: &str, algo: HashAlgorithm) -> ChainVerifyResult {
    if events.is_empty() {
        return ChainVerifyResult::Empty;
    }

    let mut expected_prev = genesis.to_string();

    for (i, event) in events.iter().enumerate() {
        if event.hash_prev != expected_prev {
            return ChainVerifyResult::Broken {
                event_index: i,
                expected: expected_prev,
                found: event.hash_prev.clone(),
            };
        }

        // Compute this event's hash to derive the next expected_prev.
        let serialized =
            serde_json::to_vec(event).expect("OaieEvent serialization cannot fail");
        let event_hash = Hash::compute(algo, &serialized);
        expected_prev = event_hash.to_hex();
    }

    ChainVerifyResult::Valid {
        events: events.len(),
        tip_hash: expected_prev,
    }
}
