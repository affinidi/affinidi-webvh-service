#![no_main]
//! Fuzz `did_ops::verify_log_for_witnessing`, the check a witness runs on a
//! requester-supplied log before it signs.
//!
//! Input layout: the first line is the requested `versionId`, the second the
//! witness DID, and the rest the `did.jsonl` log. The seeds pair the committed
//! chains with their own last `versionId` and declared witness, so mutation
//! starts from logs the function accepts and explores the chain walk, the
//! deactivation index and the witness-list lookup. Must never panic, and an
//! accepted log must report the requested `versionId` as its last.

use did_hosting_common::did_ops::verify_log_for_witnessing;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let mut parts = data.splitn(3, '\n');
    let (Some(version_id), Some(witness_did), Some(log)) =
        (parts.next(), parts.next(), parts.next())
    else {
        return;
    };
    if let Ok(witnessed) = verify_log_for_witnessing(log, version_id, witness_did) {
        assert_eq!(
            witnessed.version_ids.last().map(String::as_str),
            Some(version_id),
            "an accepted log's last versionId is the one requested"
        );
    }
});
