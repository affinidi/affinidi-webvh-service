//! Rotation of the server's *own* DID identity.
//!
//! The mirror of `did_hosting_control::identity_rotation`. Same model, two
//! differences that follow from what a server is:
//!
//! - Its listener id is `server`, not `control`.
//! - Its own DID can change through **two** paths, not one: a direct publish
//!   (`did_ops::publish_did`), or a sync update pushed from a control plane
//!   (`MSG_SYNC_UPDATE` → `apply_single_update`). Both funnel into
//!   [`on_did_published`].
//!
//! In **daemon mode this module is inert**, and deliberately so: the embedded
//! server runs no DIDComm listener of its own (CLAUDE.md — the control plane's
//! listener handles the full protocol on the authoritative store), so its
//! `didcomm_service` slot is never filled and `rebuild_listener` no-ops. The
//! daemon's control plane owns the rotation. Nothing here needs to be
//! conditionally skipped; the no-op falls out.

use std::time::Duration;

use affinidi_messaging_didcomm_service::{
    DIDCommService, ListenerConfig, Protocols, RestartPolicy, RetryConfig,
};
use did_hosting_common::server::didcomm_profile::build_tdk_profile_for_identity;
use did_hosting_common::server::identity::{
    self, DEFAULT_RELOAD_INTERVAL, DEFAULT_SWEEP_INTERVAL, IdentityGeneration, ReloadOutcome,
    mnemonic_from_did,
};
use did_hosting_common::server::identity_drain;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::error::AppError;
use crate::messaging;
use crate::secret_store::create_secret_store;
use crate::server::AppState;

/// Must match the listener id `server::start_didcomm_service` registers, or the
/// rebuild would try to add a *second* listener for the same DID and the
/// framework would reject it as a duplicate.
const LISTENER_ID: &str = "server";

/// How long the expiry sweep waits between passes (local, cheap).
pub const SWEEP_INTERVAL: Duration = DEFAULT_SWEEP_INTERVAL;

/// How long between DID-document re-resolves (network).
pub const RELOAD_INTERVAL: Duration = DEFAULT_RELOAD_INTERVAL;

/// Called after any DID's content changes — whether published directly or
/// applied from a control-plane sync. Rotates the identity if the DID was ours.
///
/// Cheap on the hot path: the mnemonic comparison rejects every other DID
/// without touching the network.
pub async fn on_did_published(state: &AppState, mnemonic: &str) {
    let Some(server_did) = state.config.server_did.as_deref() else {
        return;
    };
    let Some(ours) = mnemonic_from_did(server_did) else {
        return;
    };
    if ours != mnemonic {
        return;
    }

    info!(
        mnemonic,
        "our own DID changed — checking for an identity rotation"
    );
    if let Err(e) = reload_now(state).await {
        error!("identity reload failed: {e}");
    }
}

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
        identity::ProtocolSet {
            didcomm: state.config.features.didcomm,
            tsp: state.config.features.tsp,
        },
        state.config.identity.rotation_grace_secs(),
    )
    .await?;

    match outcome {
        ReloadOutcome::Unchanged => debug!("service identity unchanged"),
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
            // Loud on purpose: the published document now advertises a key this
            // process does not hold, so peers who have seen it cannot reach us.
            error!(
                "REFUSED to rotate the service identity: {reason}. The published DID document and \
                 the secret store disagree — the service is still using the previous key. Write \
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
                retired_generation, expires_at, "service identity rotated — rebuilding listener"
            );
            rebuild_listener(state).await?;

            // If the rotation moved us to a different mediator, peers holding a
            // stale DID document are still delivering to the old one. Stay
            // connected to it until the generation expires, or that queue is
            // stranded.
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
/// `ListenerConfig.profile.secrets()` on every reconnect: a secret that is not
/// in the profile vector vanishes the moment the socket drops, however
/// carefully we inserted it into the shared resolver.
///
/// A no-op in daemon mode, where the embedded server never starts a listener.
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

    // Union across live generations — a generation retiring out of DIDComm
    // while the current identity is TSP-only still has peers delivering DIDComm
    // to it until it expires.
    let transports = identity.protocols();
    let protocols = match (transports.didcomm, transports.tsp) {
        (true, true) => Protocols::BOTH,
        (false, true) => Protocols::TSP_ONLY,
        _ => Protocols::DIDCOMM_ONLY,
    };

    // Remove-then-add: the mediator allows one connection per DID, and the
    // framework rejects a second listener for a DID it already holds. The brief
    // gap is safe — inbound messages queue at the mediator and are delivered on
    // reconnect.
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

    info!(
        didcomm = transports.didcomm,
        tsp = transports.tsp,
        "DIDComm listener rebuilt on the new identity"
    );
    Ok(())
}

/// Start draining an old mediator, if this generation left one behind.
///
/// See `did_hosting_common::server::identity_drain` for why this is a second
/// `DIDCommService` and not an HTTP poll: the poll can fetch and dispatch, but
/// it cannot *reply* — `DIDCommResponse::into_message` is `pub(crate)` — so it
/// would silently break every request/response protocol.
///
/// A key rotation on the same mediator needs nothing here. Only a mediator change
/// strands a queue.
pub fn spawn_mediator_drain(state: &AppState, generation: IdentityGeneration) {
    let Some(identity) = state.identity.clone() else {
        return;
    };
    if !identity_drain::needs_drain(&identity, &generation) {
        return;
    }
    let Some(listener) = identity_drain::drain_listener_config("server", &identity, &generation)
    else {
        return;
    };

    let router = match messaging::build_server_router(state.clone()) {
        Ok(r) => r,
        Err(e) => {
            identity_drain::warn_drain_failed(&generation, &e.to_string());
            return;
        }
    };

    let tsp_enabled = generation.protocols.tsp;
    let drain_state = state.clone();
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

        let svc = if tsp_enabled {
            DIDCommService::start_with_tsp(
                config,
                router,
                crate::tsp::ServerTspHandler::new(drain_state),
                shutdown.clone(),
            )
            .await
        } else {
            DIDCommService::start(config, router, shutdown.clone()).await
        };

        let svc = match svc {
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

/// Expire generations past their grace period — and any that were retired out of
/// band, by the offline CLI or another process sharing the store.
///
/// Local only: no DID resolution. Rebuilds the listener when the live set
/// actually shrank.
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
    if reaped > 0 {
        // The live set shrank, so the profile must lose the expired secrets —
        // otherwise the next reconnect would re-seed them from the stale vector
        // and the retired key would come back from the dead.
        if let Err(e) = rebuild_listener(state).await {
            error!("failed to rebuild the listener after expiring {reaped} generation(s): {e}");
        }
    }
}

/// The two periodic jobs, on deliberately different cadences.
///
/// **Expiry** is local, so it runs every 60s and retires promptly. **Reload**
/// re-resolves our DID document over the network and is only a *backstop* — the
/// publish and sync hooks already catch a rotation the instant it happens — so
/// it runs every 5 minutes rather than burning ~1,400 self-resolves a day on a
/// check that almost never has anything to say.
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
                    debug!("identity backstop reload failed: {e}");
                }
            }
            _ = shutdown.changed() => break,
        }
    }
}

/// Expire one generation immediately, regardless of its grace period.
///
/// The compromise response. Messages still addressed to the old key stop
/// decrypting at once — that is the point.
pub async fn retire_generation_now(state: &AppState, generation_id: u64) -> Result<(), AppError> {
    let Some(identity) = state.identity.as_ref() else {
        return Err(AppError::Config("no service identity loaded".into()));
    };
    let secret_store = create_secret_store(&state.config)?;

    identity::retire_generation_now(identity, &state.store, secret_store.as_ref(), generation_id)
        .await?;

    rebuild_listener(state).await?;

    warn!(
        generation_id,
        "identity generation retired immediately — messages still addressed to its \
         key-agreement key will no longer decrypt"
    );
    Ok(())
}
