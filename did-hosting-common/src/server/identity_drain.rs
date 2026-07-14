//! Draining an **old mediator** after the service's DID document has moved to a
//! new one.
//!
//! # The problem
//!
//! A mediator change is the one rotation that key overlap alone cannot cover.
//! Peers holding a cached DID document keep delivering to the *old* mediator,
//! where the messages queue up. Our listener is now connected to the *new*
//! mediator and will never see them. Holding the old key does not help: the
//! messages are not addressed to the wrong key, they are sitting at the wrong
//! address.
//!
//! So for as long as the retiring generation is live, we must stay connected to
//! its mediator too.
//!
//! # Why a second `DIDCommService`, and not an HTTP poll
//!
//! The obvious-looking alternative is a websocket-free `ATM` polling
//! `fetch_messages` over REST — the SDK supports it (`send_message` falls back to
//! HTTP when no websocket is attached, and `profile_add(&p, false)` keeps it that
//! way). It can fetch. It can unpack. It can even dispatch, because `Router`
//! implements the public `DIDCommHandler` trait and `HandlerContext` has public
//! fields.
//!
//! What it **cannot** do is reply. A handler returns a `DIDCommResponse`, and
//! `DIDCommResponse::into_message` is `pub(crate)` — there is no public way to
//! turn one into a sendable `Message`. A drain that received requests and
//! silently dropped every response would quietly break `MSG_DID_REQUEST`,
//! `MSG_AUTHENTICATE` and every other request/response protocol. Worse than not
//! draining at all, because it would look like it was working.
//!
//! A second `DIDCommService` sidesteps that entirely: it is the real listener,
//! with the real router and the real response path. It is safe because the
//! duplicate-DID guard is **per-service-instance** (a stack-local map inside
//! `start_inner`), and the mediator's own duplicate eviction is keyed by DID hash
//! **within one mediator** — so the same DID on two *different* mediators is no
//! conflict at either end. Auth tokens are cached under a composite
//! `(profile_did, mediator_did)` key, so the two connections do not tread on each
//! other.
//!
//! The cost is a second TDK stack (DID resolver, secrets resolver, auth task,
//! HTTP client) for the length of the drain window. That is bounded by the grace
//! period and is the price of not losing mail.
//!
//! # Lifetime
//!
//! A drain lives exactly as long as its generation. It is started when a rotation
//! changes the mediator, and on boot for any live retired generation whose
//! mediator differs from the current one (a restart mid-window must not abandon
//! the old queue). It stops when the generation leaves the live set — whether by
//! reaching its expiry or by an operator pulling the kill switch.

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_didcomm_service::{
    DIDCommServiceConfig, ListenerConfig, Protocols, RestartPolicy, RetryConfig,
};
use affinidi_tdk_common::profiles::TDKProfile;
use tracing::{info, warn};

use super::identity::{IdentityGeneration, ServiceIdentity};

/// How often a drain checks whether its generation is still live.
///
/// The generation is the drain's shutdown signal, and the two things that end it
/// — the expiry sweep and the operator kill switch — both act on the live set.
/// Polling it keeps the drain's lifetime honest without a second channel to keep
/// in sync.
const LIVENESS_POLL: Duration = Duration::from_secs(15);

/// Whether this generation needs a drain: it is retired, and its mediator is not
/// the one the live listener is already connected to.
///
/// A generation that merely rotated *keys* on the same mediator needs nothing
/// here — its old key-agreement secret is already in the main listener's profile,
/// which is what makes that case free.
pub fn needs_drain(identity: &ServiceIdentity, generation: &IdentityGeneration) -> bool {
    generation.retired_at.is_some()
        && generation.mediator_did.is_some()
        && generation.mediator_did != identity.current().mediator_did
}

/// Every live generation that still needs its old mediator drained.
///
/// Called on boot: a restart part-way through a drain window must reconnect to
/// the old mediator, or the queue sitting there is abandoned.
pub fn generations_needing_drain(identity: &ServiceIdentity) -> Vec<IdentityGeneration> {
    identity
        .generations()
        .into_iter()
        .filter(|g| needs_drain(identity, g))
        .collect()
}

/// Build the listener config for a drain: our DID, the **old** mediator, and the
/// key material of every live generation.
///
/// All live secrets rather than just this generation's, deliberately. The drain
/// should decrypt whatever turns up at the old mediator, and a peer with a
/// half-stale view could plausibly have the new key and the old mediator. The
/// extra secrets cost one map entry each.
///
/// The listener `id` is generation-scoped so it can never collide with the main
/// listener's, and reads clearly in a log line.
pub fn drain_listener_config(
    alias: &str,
    identity: &ServiceIdentity,
    generation: &IdentityGeneration,
) -> Option<ListenerConfig> {
    let mediator = generation.mediator_did.as_deref()?;

    let profile = TDKProfile::new(
        &format!("{alias}-drain-{}", generation.id),
        &identity.did,
        Some(mediator),
        identity.secrets(),
    );

    // The transports this generation was *serving* when it was current — not the
    // union. A peer still talking to the old mediator is a peer with the old
    // document, so it will use what that document advertised.
    let protocols = match (generation.protocols.didcomm, generation.protocols.tsp) {
        (true, true) => Protocols::BOTH,
        (false, true) => Protocols::TSP_ONLY,
        _ => Protocols::DIDCOMM_ONLY,
    };

    Some(ListenerConfig {
        id: format!("{alias}-drain-{}", generation.id),
        profile,
        restart_policy: RestartPolicy::Always {
            backoff: RetryConfig::default(),
        },
        auto_delete: true,
        protocols,
        ..Default::default()
    })
}

/// Wrap a drain listener config into a one-listener service config.
pub fn drain_service_config(listener: ListenerConfig) -> DIDCommServiceConfig {
    DIDCommServiceConfig {
        listeners: vec![listener],
    }
}

/// Block until the generation stops being live — its expiry elapsed, or an
/// operator retired it early.
///
/// The caller cancels its `DIDCommService` when this returns.
pub async fn wait_until_generation_retires(identity: Arc<ServiceIdentity>, generation_id: u64) {
    let mut timer = tokio::time::interval(LIVENESS_POLL);
    timer.tick().await; // intervals fire immediately

    loop {
        timer.tick().await;
        if !identity.generations().iter().any(|g| g.id == generation_id) {
            info!(
                generation = generation_id,
                "retired generation is no longer live — stopping its mediator drain"
            );
            return;
        }
    }
}

/// Log the one failure mode an operator has to fix by hand.
///
/// (See tests below for the predicates that decide whether any of this runs.)
///
/// The old mediator will refuse the connection if our DID is no longer registered
/// with it (its inbox-fetch path rejects a non-local DID outright). There is
/// nothing the service can do about that, and silently retrying forever would
/// hide it — so say plainly what is being lost.
pub fn warn_drain_failed(generation: &IdentityGeneration, error: &str) {
    warn!(
        generation = generation.id,
        mediator = ?generation.mediator_did,
        "could not connect to the old mediator to drain it: {error}. \
         Messages queued there by peers holding a stale DID document will not be \
         delivered. If the DID has been deregistered from that mediator, this \
         cannot be recovered."
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::identity::ProtocolSet;

    const DID: &str = "did:webvh:example:alpha";
    const MEDIATOR_A: &str = "did:web:mediator-a.example";
    const MEDIATOR_B: &str = "did:web:mediator-b.example";

    fn generation(id: u64, mediator: Option<&str>, retired: bool) -> IdentityGeneration {
        IdentityGeneration {
            id,
            did: DID.into(),
            signing_kid: format!("{DID}#z6Mk{id}"),
            ka_kid: format!("{DID}#z6LS{id}"),
            mediator_did: mediator.map(str::to_string),
            protocols: ProtocolSet {
                didcomm: true,
                tsp: false,
            },
            created_at: 100,
            retired_at: retired.then_some(200),
            expires_at: retired.then_some(4_000),
        }
    }

    #[tokio::test]
    async fn a_same_mediator_key_rotation_needs_no_drain() {
        // The common case, and the one that must stay free. The old key is
        // already in the main listener's profile, so nothing is stranded and a
        // second mediator connection would be pure waste.
        let current = generation(1, Some(MEDIATOR_A), false);
        let retired = generation(0, Some(MEDIATOR_A), true);
        let identity = ServiceIdentity::for_test(DID, vec![current, retired.clone()]).await;

        assert!(!needs_drain(&identity, &retired));
        assert!(generations_needing_drain(&identity).is_empty());
    }

    #[tokio::test]
    async fn a_mediator_change_needs_a_drain() {
        // The case the whole module exists for: peers with a stale document are
        // still delivering to mediator A, and nothing else will collect them.
        let current = generation(1, Some(MEDIATOR_B), false);
        let retired = generation(0, Some(MEDIATOR_A), true);
        let identity = ServiceIdentity::for_test(DID, vec![current, retired.clone()]).await;

        assert!(needs_drain(&identity, &retired));

        let needing = generations_needing_drain(&identity);
        assert_eq!(needing.len(), 1);
        assert_eq!(
            needing[0].id, 0,
            "the retired generation, on the old mediator"
        );
    }

    #[tokio::test]
    async fn the_current_generation_is_never_drained() {
        // It is not stranded — it is the one the live listener is connected to.
        // Draining it would mean two connections to the same mediator for the
        // same DID, which that mediator would evict.
        let current = generation(1, Some(MEDIATOR_B), false);
        let identity = ServiceIdentity::for_test(DID, vec![current.clone()]).await;

        assert!(!needs_drain(&identity, &current));
        assert!(generations_needing_drain(&identity).is_empty());
    }

    #[tokio::test]
    async fn a_generation_with_no_mediator_is_not_drained() {
        // An HTTP-only deployment has nothing to connect to.
        let current = generation(1, Some(MEDIATOR_B), false);
        let retired = generation(0, None, true);
        let identity = ServiceIdentity::for_test(DID, vec![current, retired.clone()]).await;

        assert!(!needs_drain(&identity, &retired));
        assert!(drain_listener_config("control", &identity, &retired).is_none());
    }

    #[tokio::test]
    async fn the_drain_listener_points_at_the_old_mediator() {
        // The load-bearing assertion. The profile's mediator — not our DID
        // document — is what the SDK resolves the REST/WS endpoint from, so
        // pointing it at the retired generation's mediator is precisely what
        // makes the drain reach the *old* queue rather than the new one.
        let current = generation(1, Some(MEDIATOR_B), false);
        let retired = generation(0, Some(MEDIATOR_A), true);
        let identity = ServiceIdentity::for_test(DID, vec![current, retired.clone()]).await;

        let listener = drain_listener_config("control", &identity, &retired).expect("drain config");

        assert_eq!(listener.profile.mediator.as_deref(), Some(MEDIATOR_A));
        assert_eq!(listener.profile.did, DID);
        assert_eq!(
            listener.id, "control-drain-0",
            "generation-scoped so it can never collide with the main listener"
        );
    }
}
