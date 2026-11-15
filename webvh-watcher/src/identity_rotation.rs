//! Rotation of the watcher's *own* DID identity.
//!
//! The watcher is in the witness's position: its own DID is published by
//! whichever service hosts it, in another process, so it has **no publish
//! hook**. (It does mirror DIDs from its sources, but a mirrored DID's
//! mnemonic alone does not say it is ours — the same path can exist on many
//! domains — and the sweep below covers the case anyway.)
//!
//! That leaves the periodic sweep as the only trigger: it expires generations
//! whose grace period has elapsed, and re-resolves our document to notice a
//! rotation that happened elsewhere. A rotation therefore takes effect within
//! one reload interval rather than immediately. Without it the watcher would
//! keep signing replies with a key its document no longer carries, sources
//! would reject every reply, and every sync would look unacknowledged until a
//! restart.

use std::time::Duration;

use affinidi_messaging_didcomm_service::DIDCommService;
use did_hosting_common::server::didcomm_profile::rebuild_own_listener;
use did_hosting_common::server::identity::{
    self, DEFAULT_RELOAD_INTERVAL, DEFAULT_SWEEP_INTERVAL, IdentityGeneration, ReloadOutcome,
};
use did_hosting_common::server::identity_drain;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::error::AppError;
use crate::secret_store::create_secret_store;
use crate::server::AppState;

/// The listener id the watcher registers its DID under, at boot
/// (`server::start_messaging_service`) and on every rebuild.
pub(crate) const LISTENER_ID: &str = "watcher";

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
        // The same set the watcher loads its identity with at boot.
        identity::ProtocolSet {
            didcomm: state.config.features.didcomm,
            tsp: state.config.features.tsp,
        },
        state.config.identity.rotation_grace_secs(),
    )
    .await?;

    match outcome {
        ReloadOutcome::Unchanged => debug!("watcher identity unchanged"),
        ReloadOutcome::MetadataUpdated { generation } => {
            // Not a rotation — protocols/mediator changed but the keys did not.
            info!(
                generation,
                "watcher identity metadata updated (no key rotation) — rebuilding listener"
            );
            rebuild_listener(state).await?;
        }
        ReloadOutcome::Established { generation } => {
            // The first real look at our own DID document: the listener (if
            // any) was built on guessed kids, so rebuild it on the real ones.
            info!(
                generation,
                "service identity established — rebuilding listener"
            );
            rebuild_listener(state).await?;
        }
        ReloadOutcome::RotatedWithoutOverlap { generation, ka_kid } => {
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
                "REFUSED to rotate the watcher identity: {reason}. The published DID document and \
                 the secret store disagree — the watcher is still using the previous key. Write \
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
                retired_generation, expires_at, "watcher identity rotated — rebuilding listener"
            );
            // Rebuild first (re-pointing the main listener at the new mediator),
            // then drain — otherwise two connections would pull the same queue,
            // and the mediator evicts a duplicate DID.
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

/// Rebuild the listener against the current live set — through the same
/// builder boot uses, so it keeps the transports our DID document advertises
/// and the persistent TSP relationship store.
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

    rebuild_own_listener(svc, LISTENER_ID, identity, &mediator_did, &state.store).await?;
    Ok(())
}

/// Start draining an old mediator, if this generation left one behind.
///
/// See `did_hosting_common::server::identity_drain` for why this is a second
/// `DIDCommService` and not an HTTP poll. Only a mediator change strands a
/// queue; a key rotation on the same mediator short-circuits here.
pub fn spawn_mediator_drain(state: &AppState, generation: IdentityGeneration) {
    let Some(identity) = state.identity.clone() else {
        return;
    };
    if !identity_drain::needs_drain(&identity, &generation) {
        return;
    }
    let Some(listener) = identity_drain::drain_listener_config(LISTENER_ID, &identity, &generation)
    else {
        return;
    };

    let router = match crate::messaging::build_watcher_router(state.clone()) {
        Ok(r) => r,
        Err(e) => {
            identity_drain::warn_drain_failed(&generation, &e.to_string());
            return;
        }
    };

    let mediator = generation.mediator_did.clone().unwrap_or_default();
    let generation_id = generation.id;
    let tsp_state = state.clone();

    tokio::spawn(async move {
        info!(
            generation = generation_id,
            mediator = %mediator,
            "connecting to the old mediator to drain messages from peers with a stale DID document"
        );

        let shutdown = CancellationToken::new();
        let config = identity_drain::drain_service_config(listener);

        let svc = match if generation.protocols.tsp {
            DIDCommService::start_with_tsp(
                config,
                router,
                crate::tsp::WatcherTspHandler::new(tsp_state),
                shutdown.clone(),
            )
            .await
        } else {
            DIDCommService::start(config, router, shutdown.clone()).await
        } {
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
/// A restart part-way through a drain window must reconnect to the old
/// mediator, or the queue sitting there is abandoned for good.
pub fn resume_mediator_drains(state: &AppState) {
    let Some(identity) = state.identity.as_ref() else {
        return;
    };
    for generation in identity_drain::generations_needing_drain(identity) {
        spawn_mediator_drain(state, generation);
    }
}

/// Expire generations past their grace period — and any retired out of band,
/// by the offline CLI or another process sharing the store.
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
/// document over the network every 5 minutes — and, as for the witness, it is
/// the watcher's *only* trigger, since it never sees its own DID being
/// published. A rotation therefore reaches the watcher within 5 minutes, far
/// inside the default 1-hour grace period.
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
