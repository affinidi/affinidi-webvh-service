#![no_main]
//! Structure-aware fuzz of `did_ops::verify_did_log_proofs`.
//!
//! Instead of mutating bytes, this generates a `Vec<LogEntry>` straight from
//! the fuzzer (plausible parameters and entry shapes, deliberately broken
//! linkage) via didwebvh-rs's `arbitrary` feature, serializes each entry to a
//! JSONL line, and feeds the result to the real verifier. This reaches the
//! chain-walk logic far more often than byte mutation, which almost never
//! produces input that survives `LogEntry` deserialization. Must never panic.

use libfuzzer_sys::fuzz_target;
use did_hosting_common::did_ops::verify_did_log_proofs;
use didwebvh_rs::log_entry::LogEntry;

fuzz_target!(|entries: Vec<LogEntry>| {
    let mut lines = Vec::with_capacity(entries.len());
    for entry in &entries {
        match serde_json::to_string(entry) {
            Ok(line) => lines.push(line),
            Err(_) => return,
        }
    }
    let jsonl = lines.join("\n");
    let _ = verify_did_log_proofs(&jsonl);
});
