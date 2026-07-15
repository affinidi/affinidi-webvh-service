//! Rotation of the witness's *own* DID identity.
//!
//! The witness hosts no DIDs — it has no `dids` keyspace and no publish path —
//! so unlike the server and the control plane it has **no publish hook**. Its
//! own DID is published by whichever service hosts it, in another process.
//!
//! That leaves the periodic sweep as the only trigger: it expires generations
//! whose grace period has elapsed, and re-resolves our document to notice a
//! rotation that happened elsewhere. A rotation therefore takes effect within
//! one sweep interval rather than immediately, which is the right trade for a
//! service that cannot observe its own DID being published.

use std::time::Duration;

use affinidi_messaging_didcomm_service::{
    DIDCommService, ListenerConfig, Protocols, RestartPolicy, RetryConfig,
};
use did_hosting_common::server::didcomm_profile::build_tdk_profile_for_identity;
use did_hosting_common::server::identity::{
    self, DEFAULT_RELOAD_INTERVAL, DEFAULT_SWEEP_INTERVAL, IdentityGeneration, ReloadOutcome,
};
use did_hosting_common::server::identity_drain;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::error::AppError;
use crate::messaging;
use crate::secret_store::create_secret_store;
use crate::server::AppState;

/// Must match the listener id `server::start_didcomm_service` registers.
const LISTENER_ID: &str = "witness";

/// How long the expiry sweep waits between passes (local, cheap).
pub const SWEEP_INTERVAL: Duration = DEFAULT_SWEEP_INTERVAL;

/// How long between DID-document re-resolves (network).
pub const RELOAD_INTERVAL: Duration = DEFAULT_RELOAD_INTERVAL;

/// Re-resolve our DID document, rotate if it changed, and rebuild the listener.
pub async fn reload_now(state: &AppState) -> Result<(), AppError> {
    let Some(identity) = state.identity.as_ref() else {
        return Ok(());
    };

    let secret_store = create_secret_store(&state.config)?;

    let outcome = identity::reload_service_identity(
        identity,
        &state.store,
        secret_store.as_ref(),
        state.config.mediator_did.as_deref(),
        // The witness carries no TSP listener of its own — TSP rides the
        // control plane's mediator socket.
        identity::ProtocolSet {
            didcomm: state.config.features.didcomm,
            tsp: false,
        },
        state.config.identity.rotation_grace_secs(),
    )
    .await?;

    match outcome {
        ReloadOutcome::Unchanged => debug!("witness identity unchanged"),
        ReloadOutcome::MetadataUpdated { generation } => {
            // Not a rotation — protocols/mediator changed but the keys did not.
            // Rebuild the listener so a transport change takes effect.
            info!(
                generation,
                "witness identity metadata updated (no key rotation) — rebuilding listener"
            );
            rebuild_listener(state).await?;
        }
        ReloadOutcome::Established { generation } => {
            // Not a rotation — the first real look at our own DID document, now
            // that we are serving it. The listener (if any) was built on guessed
            // kids, so it has to be rebuilt on the real ones.
            info!(
                generation,
                "service identity established — rebuilding listener"
            );
            rebuild_listener(state).await?;
        }
        ReloadOutcome::RotatedWithoutOverlap { generation, ka_kid } => {
            // Loud on purpose: the operator asked for a rotation and got one, but
            // without the grace window they are almost certainly expecting.
            error!(
                generation,
                ka_kid = %ka_kid,
                "identity rotated WITHOUT a grace period — the new key-agreement key reuses the \
                 same verification-method id, and a kid identifies exactly one key, so messages \
                 already encrypted to the previous key CANNOT be decrypted. Peers holding a stale \
                 DID document cannot reach this service until their cache expires. Rotate onto a \
                 NEW fragment for a seamless cutover."
            );
            rebuild_listener(state).await?;
        }
        ReloadOutcome::Unresolvable => {
            warn!("could not resolve our own DID document — identity left as-is");
        }
        ReloadOutcome::Refused { reason } => {
            error!(
                "REFUSED to rotate the witness identity: {reason}. The published DID document and \
                 the secret store disagree — the witness is still using the previous key. Write \
                 the new key to the secret store, then publish the DID."
            );
        }
        ReloadOutcome::Rotated {
            new_generation,
            retired_generation,
            expires_at,
        } => {
            info!(
                new_generation,
                retired_generation, expires_at, "witness identity rotated — rebuilding listener"
            );
            // Order matters: rebuild first (re-pointing the main listener at the
            // new mediator), then drain — otherwise two connections would pull
            // the same queue, and the mediator evicts a duplicate DID.
            rebuild_listener(state).await?;

            if let Some(retired) = identity
                .generations()
                .into_iter()
                .find(|g| g.id == retired_generation)
            {
                spawn_mediator_drain(state, retired);
            }
        }
    }

    Ok(())
}

/// Rebuild the DIDComm listener against the current live set.
///
/// Necessary because the framework re-seeds its secrets resolver from
/// `ListenerConfig.profile.secrets()` on every reconnect — a secret that is not
/// in the profile vector vanishes the moment the socket drops.
async fn rebuild_listener(state: &AppState) -> Result<(), AppError> {
    let Some(svc) = state.didcomm_service.get() else {
        debug!("no messaging service running — nothing to rebuild");
        return Ok(());
    };
    let Some(identity) = state.identity.as_ref() else {
        return Ok(());
    };
    let Some(mediator_did) = identity.mediator_did() else {
        return Ok(());
    };

    let profile =
        build_tdk_profile_for_identity(LISTENER_ID, identity, Some(&mediator_did)).await?;

    let transports = identity.protocols();
    let protocols = match (transports.didcomm, transports.tsp) {
        (true, true) => Protocols::BOTH,
        (false, true) => Protocols::TSP_ONLY,
        _ => Protocols::DIDCOMM_ONLY,
    };

    // Remove-then-add: the mediator allows one connection per DID, and the
    // framework rejects a second listener for a DID it already holds.
    if let Err(e) = svc.remove_listener(LISTENER_ID).await {
        warn!("failed to remove the old listener: {e}");
    }

    svc.add_listener(ListenerConfig {
        id: LISTENER_ID.into(),
        profile,
        restart_policy: RestartPolicy::Always {
            backoff: RetryConfig::default(),
        },
        auto_delete: true,
        protocols,
        ..Default::default()
    })
    .await
    .map_err(|e| AppError::Internal(format!("failed to restart the DIDComm listener: {e}")))?;

    info!("DIDComm listener rebuilt on the new identity");
    Ok(())
}

/// Start draining an old mediator, if this generation left one behind.
///
/// See `did_hosting_common::server::identity_drain` for why this is a second
/// `DIDCommService` and not an HTTP poll: the poll can fetch and dispatch, but it
/// cannot *reply*, so it would silently break every request/response protocol.
///
/// Only a mediator change strands a queue. A key rotation on the same mediator
/// short-circuits here and costs nothing.
pub fn spawn_mediator_drain(state: &AppState, generation: IdentityGeneration) {
    let Some(identity) = state.identity.clone() else {
        return;
    };
    if !identity_drain::needs_drain(&identity, &generation) {
        return;
    }
    let Some(listener) = identity_drain::drain_listener_config("witness", &identity, &generation)
    else {
        return;
    };

    let router = match messaging::build_witness_router(state.clone()) {
        Ok(r) => r,
        Err(e) => {
            identity_drain::warn_drain_failed(&generation, &e.to_string());
            return;
        }
    };

    let mediator = generation.mediator_did.clone().unwrap_or_default();
    let generation_id = generation.id;

    tokio::spawn(async move {
        info!(
            generation = generation_id,
            mediator = %mediator,
            "connecting to the old mediator to drain messages from peers with a stale DID document"
        );

        let shutdown = CancellationToken::new();
        let config = identity_drain::drain_service_config(listener);

        // The witness carries no TSP listener of its own — TSP rides the control
        // plane's mediator socket — so there is no `start_with_tsp` arm here.
        let svc = match DIDCommService::start(config, router, shutdown.clone()).await {
            Ok(svc) => svc,
            Err(e) => {
                identity_drain::warn_drain_failed(&generation, &e.to_string());
                return;
            }
        };

        identity_drain::wait_until_generation_retires(identity, generation_id).await;

        shutdown.cancel();
        svc.shutdown().await;
        info!(
            generation = generation_id,
            mediator = %mediator,
            "old-mediator drain stopped"
        );
    });
}

/// Restart any drains a previous process had running.
///
/// A restart part-way through a drain window must reconnect to the old mediator,
/// or the queue sitting there is abandoned for good.
pub fn resume_mediator_drains(state: &AppState) {
    let Some(identity) = state.identity.as_ref() else {
        return;
    };
    for generation in identity_drain::generations_needing_drain(identity) {
        spawn_mediator_drain(state, generation);
    }
}

/// Expire generations past their grace period — and any retired out of band, by
/// the offline CLI or another process sharing the store.
///
/// Local only: no DID resolution.
pub async fn expire_due(state: &AppState) {
    let Some(identity) = state.identity.as_ref() else {
        return;
    };

    let secret_store = match create_secret_store(&state.config) {
        Ok(s) => s,
        Err(e) => {
            warn!("identity sweep: could not open the secret store: {e}");
            return;
        }
    };

    let reaped = identity::run_sweep_once(identity, &state.store, secret_store.as_ref()).await;
    if reaped > 0
        && let Err(e) = rebuild_listener(state).await
    {
        error!("failed to rebuild the listener after expiring {reaped} generation(s): {e}");
    }
}

/// The two periodic jobs, on deliberately different cadences.
///
/// **Expiry** is local and runs every 60s. **Reload** re-resolves our DID
/// document over the network every 5 minutes — and unlike the server and the
/// control plane, for the witness this is not a backstop but its *only* trigger,
/// since it hosts no DIDs and never sees its own being published. A rotation
/// therefore reaches the witness within 5 minutes, which is far inside the
/// default 1-hour grace period.
pub async fn run_identity_sweep_loop(state: AppState, mut shutdown: watch::Receiver<bool>) {
    let mut expiry = tokio::time::interval(SWEEP_INTERVAL);
    let mut reload = tokio::time::interval(RELOAD_INTERVAL);
    expiry.tick().await;
    reload.tick().await;

    loop {
        tokio::select! {
            _ = expiry.tick() => expire_due(&state).await,
            _ = reload.tick() => {
                if let Err(e) = reload_now(&state).await {
                    debug!("identity reload failed: {e}");
                }
            }
            _ = shutdown.changed() => break,
        }
    }
}
