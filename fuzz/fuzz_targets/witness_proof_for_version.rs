#![no_main]
//! Fuzz `did_ops::verify_witness_proof_for_version`, the check on a witness
//! proof accepted from the wire (`webvh/witness/publish`).
//!
//! Input layout: the first line is the `versionId`, the second the proof as
//! JSON, and the rest the `did.jsonl` log. Built with `--features
//! server-core`. Must never panic.

use did_hosting_common::did_ops::verify_witness_proof_for_version;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let mut parts = data.splitn(3, '\n');
    let (Some(version_id), Some(proof), Some(log)) = (parts.next(), parts.next(), parts.next())
    else {
        return;
    };
    let Ok(proof) = serde_json::from_str::<serde_json::Value>(proof) else {
        return;
    };
    let _ = verify_witness_proof_for_version(log, version_id, &proof);
});
