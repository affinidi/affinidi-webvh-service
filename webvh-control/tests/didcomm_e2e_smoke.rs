//! End-to-end DIDComm smoke test against an embedded mediator.
//!
//! Foundation test for the deferred dispatcher coverage. Spawns an
//! `affinidi-messaging-test-mediator` (default `MemoryStore` backend, no
//! Redis required), provisions two named users via `TestEnvironment`,
//! and asserts the basics:
//!
//! - the mediator binds to a free `127.0.0.1` port and reports a
//!   `did:peer:2.*` identifier;
//! - distinct users get distinct DIDs and Ed25519 + X25519 secrets;
//! - graceful shutdown completes without hanging.
//!
//! This test exists as the proof point that `messaging-test-mediator`
//! integrates with our build. The full webvh-control DIDComm dispatcher
//! tests (sending `MSG_AUTHENTICATE` / `MSG_DID_REQUEST` / etc. from a
//! simulated tenant DID through the mediator and asserting the
//! handlers respond correctly) build on top of this foundation in a
//! separate test file — see `tasks/plan.md` for the roadmap.

use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator};

/// Spawn + shutdown without panicking. Catches any startup-path
/// regression in the mediator fixture itself before more elaborate
/// dispatcher tests run.
#[tokio::test]
async fn test_mediator_spawn_and_shutdown() {
    let mediator = TestMediator::spawn()
        .await
        .expect("test mediator should spawn against in-memory backend");

    assert_eq!(mediator.endpoint().scheme(), "http");
    assert!(
        mediator.did().starts_with("did:peer:2."),
        "mediator DID must be a did:peer:2.*; got: {}",
        mediator.did()
    );
    assert!(mediator.bound_addr().port() > 0, "ephemeral port assigned");

    mediator.shutdown();
    mediator
        .join()
        .await
        .expect("mediator must shut down cleanly");
}

/// `TestEnvironment::add_user` mints fresh `did:peer` identities for
/// simulated tenants. Both users get Ed25519 + X25519 secret material
/// so they can sign DIDComm envelopes and exchange encrypted messages
/// through the mediator. This is the building block the dispatcher
/// tests use to feed signed `MSG_*` messages into webvh-control's
/// router.
#[tokio::test]
async fn test_environment_provisions_distinct_users() {
    let env = TestEnvironment::spawn().await.expect("env spawn");

    let alice = env.add_user("Alice").await.expect("provision Alice");
    let bob = env.add_user("Bob").await.expect("provision Bob");

    assert!(alice.did.starts_with("did:peer:2."));
    assert!(bob.did.starts_with("did:peer:2."));
    assert_ne!(alice.did, bob.did, "users must have distinct DIDs");
    assert_ne!(
        alice.did,
        env.mediator.did(),
        "users and mediator must have distinct DIDs"
    );
    // Each user carries a signing key + key-agreement key.
    assert_eq!(alice.secrets.len(), 2);
    assert_eq!(bob.secrets.len(), 2);

    env.shutdown().await.expect("env shutdown");
}
