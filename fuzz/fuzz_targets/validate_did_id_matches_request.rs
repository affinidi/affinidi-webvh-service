#![no_main]
//! Fuzz the host/path impersonation guard
//! `did_ops::validate_did_id_matches_request`.
//!
//! Structure-aware over a `(did_id, request_path, server_base_url)` triple:
//! exercises `WebVHURL::parse_did_url`, the `server_base_url` + path URL
//! composition, and the domain/port/path comparison. Hostile inputs (bogus
//! DIDs, path traversal, odd URL schemes) must produce `Ok`/`Err`, never a
//! panic.

use libfuzzer_sys::fuzz_target;
use did_hosting_common::did_ops::validate_did_id_matches_request;

fuzz_target!(|input: (String, String, String)| {
    let (did_id, request_path, server_base_url) = input;
    let _ = validate_did_id_matches_request(&did_id, &request_path, &server_base_url);
});
