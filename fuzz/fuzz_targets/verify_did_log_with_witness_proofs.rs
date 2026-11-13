#![no_main]
//! Fuzz the verifiers that read a `did.jsonl` log together with its
//! `did-witness.json` proofs: `verify_did_log_and_witness_proofs` (a host
//! serving a log it did not author), `verify_did_log_for_publish` (a publish
//! with a not-yet-witnessed tail) and `servable_did_log` (what resolution
//! serves).
//!
//! Input layout: one byte for the published-entry count, then the log, then
//! optionally a NUL byte and the witness-proof file. Must never panic, and
//! `servable_did_log` must never return more entries than the log holds.

use did_hosting_common::did_ops::{
    servable_did_log, verify_did_log_and_witness_proofs, verify_did_log_for_publish,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&published, rest)) = data.split_first() else {
        return;
    };
    let Ok(rest) = std::str::from_utf8(rest) else {
        return;
    };
    let (log, witness) = match rest.split_once('\0') {
        Some((log, witness)) => (log, Some(witness)),
        None => (rest, None),
    };

    let _ = verify_did_log_and_witness_proofs(log, witness);
    let _ = verify_did_log_for_publish(log, witness, usize::from(published));
    if let Some(servable) = servable_did_log(log, witness) {
        let entries = |s: &str| s.lines().filter(|l| !l.trim().is_empty()).count();
        assert!(
            entries(&servable) <= entries(log),
            "servable_did_log returned more entries than the log holds"
        );
    }
});
