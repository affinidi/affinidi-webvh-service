#![no_main]
//! Fuzz the URL-path validators every DID route runs on its path parameter:
//! `validate_mnemonic` (did:web / did:webvh) and `validate_webs_mnemonic`
//! (did:webs, trailing AID). Built with `--features server-core`. Must never
//! panic.

use did_hosting_common::server::mnemonic::{validate_mnemonic, validate_webs_mnemonic};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = validate_mnemonic(data);
    let _ = validate_webs_mnemonic(data);
});
