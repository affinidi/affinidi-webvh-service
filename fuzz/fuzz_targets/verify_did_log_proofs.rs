#![no_main]
//! Fuzz the semantic verifier `did_ops::verify_did_log_proofs` (raw bytes).
//!
//! Seeded with the committed valid multi-entry chains under
//! `corpus/verify_did_log_proofs/`, so libfuzzer's mutations explore the
//! SCID / entry-hash chain walk, parameter transitions, and proof gate rather
//! than bouncing off the JSON parser. Must never panic.

use libfuzzer_sys::fuzz_target;
use did_hosting_common::did_ops::verify_did_log_proofs;

fuzz_target!(|data: &str| {
    let _ = verify_did_log_proofs(data);
});
