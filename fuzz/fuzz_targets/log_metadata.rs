#![no_main]
//! Fuzz the unverified `did.jsonl` readers the services run for indexing and
//! display: `extract_did_id`, `extract_service_types`, `extract_agent_names`,
//! `extract_log_metadata`, `extract_did_web_document` and
//! `parse_log_entries`. Must never panic.

use did_hosting_common::did_ops::{
    extract_agent_names, extract_did_id, extract_did_web_document, extract_log_metadata,
    extract_service_types, parse_log_entries,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let did = extract_did_id(data);
    let _ = extract_service_types(data);
    let _ = extract_agent_names(data, "fuzz.example.com");
    let _ = extract_log_metadata(data);
    let _ = parse_log_entries(data);
    if let Some(did) = did {
        let _ = extract_did_web_document(data, &did.replacen("did:webvh:", "did:web:", 1));
    }
});
