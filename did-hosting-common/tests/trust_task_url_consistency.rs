// Feature-gated on `server-core` because the daemon-side
// `did_hosting_tasks` module is itself gated there. A method-only
// build doesn't need (or have) these constants; the test compiles
// to a no-op so `cargo test --workspace` works regardless of which
// feature subset CI picked.
#![cfg(feature = "server-core")]

//! T51: cross-crate Trust-Task URL parity.
//!
//! Asserts that every `TASK_*` URL exposed by
//! `did-hosting-client::trust_tasks` matches the same-named const
//! in `did-hosting-common::did_hosting_tasks` byte-for-byte.
//!
//! Why this matters: the daemon's `TrustTaskRouter` (T8b) does
//! exact-string matching. A drift between client and daemon
//! constants — even a stray space or a `1.0` → `1.1` bump — would
//! cause the daemon to 415 every request from a client built
//! against the stale value, with the test suite cheerfully green
//! because neither side's unit tests cross the boundary. This
//! integration test is the boundary check.
//!
//! Add new `TASK_*` consts to both crates AND to the matching
//! pairs list below. The test loops over the pairs; if a future
//! contributor adds a const to one side and forgets the other,
//! the boundary stays unbroken — they just have to update this
//! list.

use did_hosting_client::trust_tasks as client_tasks;
use did_hosting_common::did_hosting_tasks as daemon_tasks;

/// Every (daemon, client) URL pair that must match byte-for-byte.
///
/// Daemon side is a `LazyLock<TrustTask>` (`.as_str()` to compare).
/// Client side is a `&'static str`. Names match across the two
/// crates by convention; the test would catch a renamed-on-one-side
/// regression because the pair entry would no longer compile.
fn parity_pairs() -> Vec<(&'static str, String, &'static str)> {
    vec![
        // Auth
        (
            "TASK_AUTH_AUTHENTICATE_0_1",
            daemon_tasks::TASK_AUTH_AUTHENTICATE_0_1
                .as_str()
                .to_string(),
            client_tasks::TASK_AUTH_AUTHENTICATE_0_1,
        ),
        (
            "TASK_AUTH_CHALLENGE_0_1",
            daemon_tasks::TASK_AUTH_CHALLENGE_0_1.as_str().to_string(),
            client_tasks::TASK_AUTH_CHALLENGE_0_1,
        ),
        (
            "TASK_AUTH_REFRESH_0_1",
            daemon_tasks::TASK_AUTH_REFRESH_0_1.as_str().to_string(),
            client_tasks::TASK_AUTH_REFRESH_0_1,
        ),
        // DID lifecycle (v0.1 client surface)
        (
            "TASK_DID_CHECK_NAME_1_0",
            daemon_tasks::TASK_DID_CHECK_NAME_1_0.as_str().to_string(),
            client_tasks::TASK_DID_CHECK_NAME_1_0,
        ),
        (
            "TASK_DID_REQUEST_1_0",
            daemon_tasks::TASK_DID_REQUEST_1_0.as_str().to_string(),
            client_tasks::TASK_DID_REQUEST_1_0,
        ),
        (
            "TASK_DID_REGISTER_1_0",
            daemon_tasks::TASK_DID_REGISTER_1_0.as_str().to_string(),
            client_tasks::TASK_DID_REGISTER_1_0,
        ),
        (
            "TASK_DID_PUBLISH_1_0",
            daemon_tasks::TASK_DID_PUBLISH_1_0.as_str().to_string(),
            client_tasks::TASK_DID_PUBLISH_1_0,
        ),
        (
            "TASK_DID_DELETE_1_0",
            daemon_tasks::TASK_DID_DELETE_1_0.as_str().to_string(),
            client_tasks::TASK_DID_DELETE_1_0,
        ),
    ]
}

#[test]
fn every_client_task_matches_daemon_byte_for_byte() {
    let pairs = parity_pairs();
    assert!(
        !pairs.is_empty(),
        "parity_pairs is empty — at least the auth/lifecycle pairs must be present"
    );

    let mut mismatches = Vec::new();
    for (name, daemon, client) in &pairs {
        if daemon != client {
            mismatches.push(format!(
                "{name} drift:\n  daemon: {daemon}\n  client: {client}"
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "Trust-Task URL drift between client and daemon — fix both sides to match:\n\n{}",
        mismatches.join("\n\n")
    );
}

/// Pin that the parity_pairs list is exhaustive at the time of
/// writing: we expect at least the auth (3) + DID lifecycle (5) =
/// 8 entries. A future expansion of the client surface should
/// raise this number AND add the new pair to the list.
#[test]
fn parity_pairs_list_covers_v01_surface() {
    let pairs = parity_pairs();
    assert!(
        pairs.len() >= 8,
        "v0.1 client surface is at least 8 Trust-Task URLs (3 auth + 5 lifecycle); \
         got {}. If the surface grew, extend `parity_pairs`.",
        pairs.len()
    );
}
