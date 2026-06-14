#![no_main]
//! Fuzz the structural validator `did_ops::validate_did_jsonl`.
//!
//! Raw-bytes target: exercises per-line `LogEntry::deserialize_string`, the
//! blank-line handling, and the "latest entry must encode a did:webvh id"
//! gate. Any input must yield `Ok`/`Err` — never a panic.

use libfuzzer_sys::fuzz_target;
use did_hosting_common::did_ops::validate_did_jsonl;

fuzz_target!(|data: &str| {
    let _ = validate_did_jsonl(data);
});
