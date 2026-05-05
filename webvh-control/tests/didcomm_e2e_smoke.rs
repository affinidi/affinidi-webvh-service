//! End-to-end DIDComm smoke test against an embedded mediator.
//!
//! Foundation test for the deferred dispatcher coverage. Spawns an
//! `affinidi-messaging-test-mediator` (default `MemoryStore` backend, no
//! Redis required), provisions two named users, and asserts the basics:
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
//!
//! Uses 0.2's `TestMediator::with_users` helper for the multi-user
//! case — drops the ATM-bound `TestEnvironment` indirection that earlier
//! revisions needed (the dispatcher tests don't round-trip via the SDK,
//! so an ATM client is dead weight here).

use affinidi_messaging_test_mediator::TestMediator;

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

/// `TestMediator::with_users` mints fresh `did:peer` identities for
/// simulated tenants. Both users get Ed25519 + X25519 secret material
/// so they can sign DIDComm envelopes and exchange encrypted messages
/// through the mediator. This is the building block the dispatcher
/// tests use to feed signed `MSG_*` messages into webvh-control's
/// router.
#[tokio::test]
async fn with_users_provisions_distinct_local_accounts() {
    let (mediator, users) = TestMediator::with_users(["Alice", "Bob"])
        .await
        .expect("spawn + register users");

    assert_eq!(users.len(), 2, "one user per alias");
    let alice = &users[0];
    let bob = &users[1];

    assert_eq!(alice.alias, "Alice");
    assert_eq!(bob.alias, "Bob");
    assert!(alice.did.starts_with("did:peer:2."));
    assert!(bob.did.starts_with("did:peer:2."));
    assert_ne!(alice.did, bob.did, "users must have distinct DIDs");
    assert_ne!(
        alice.did,
        mediator.did(),
        "users and mediator must have distinct DIDs"
    );
    // Each user carries a signing key + key-agreement key.
    assert_eq!(alice.secrets.len(), 2);
    assert_eq!(bob.secrets.len(), 2);

    mediator.shutdown();
    mediator.join().await.expect("clean shutdown");
}

/// `TestMediatorHandle::add_user` is the post-spawn counterpart — useful
/// for tests that need to introduce a participant after the mediator
/// is already running (e.g. simulating a late-joining tenant). Pins
/// the same wire-shape contract so we notice if 0.x ever changes the
/// returned secrets layout.
#[tokio::test]
async fn add_user_post_spawn_returns_registered_local_account() {
    let mediator = TestMediator::spawn().await.expect("spawn");

    let charlie = mediator.add_user("Charlie").await.expect("add user");

    assert_eq!(charlie.alias, "Charlie");
    assert!(charlie.did.starts_with("did:peer:2."));
    assert_eq!(charlie.secrets.len(), 2);
    assert_ne!(charlie.did, mediator.did());

    mediator.shutdown();
    mediator.join().await.expect("clean shutdown");
}
