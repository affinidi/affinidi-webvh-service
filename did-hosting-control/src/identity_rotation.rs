//! Rotation of the control plane's *own* DID identity.
//!
//! Three entry points, all of which end in the same place — the live set in
//! [`ServiceIdentity`] changes, so the listener's profile has to be rebuilt:
//!
//! - [`on_did_published`] — the trigger. Fires from the publish path on every
//!   publish of a DID, and does real work only when the DID is ours.
//! - [`run_identity_sweep_loop`] — the reaper. Drops generations whose grace
//!   period has elapsed.
//! - [`reload_now`] — the periodic backstop, for identity changes that never
//!   went through our publish path (an out-of-band update, or one applied while
//!   the process was down).
//!
//! The listener is rebuilt in place with `remove_listener` / `add_listener`,
//! which take `&self`. The `DIDCommService` itself is never replaced — only the
//! one listener it holds for our DID — so the `OnceLock` in `AppState` stays
//! sound and no other state has to be re-threaded.

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

/// The listener id the control plane registers its DID under. Must match
/// `server::start_didcomm_service`, or the rebuild would add a second listener
/// for the same DID and the framework would reject it as a duplicate.
const LISTENER_ID: &str = "control";

/// Called after any DID is published. Rotates the service identity if the DID
/// that changed was our own.
///
/// Cheap and safe on the hot path: the mnemonic comparison rejects the
/// overwhelming majority of publishes without touching the network, and a
/// publish of our own DID that did not change the identity resolves the
/// document once and no-ops.
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
        "our own DID was published — checking for a rotation"
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

    // Reconstructed rather than held in `AppState`: no binary retains a
    // `SecretStore` past startup, and a rotation is rare enough that building
    // one here is free next to the DID resolution it is about to do.
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
            // Loud on purpose. The service is still running on the old identity
            // while its published document advertises a key it cannot use, so
            // peers who have seen the new document cannot reach it.
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
            // Order matters: rebuild first, drain second.
            //
            // `rebuild_listener` re-points the main listener at the *new*
            // mediator. Only once it has let go of the old one is it safe to
            // attach the drain there — otherwise two connections would be
            // pulling the same queue (the live listener's websocket and its
            // periodic offline sync, racing the drain), and the same DID twice
            // on one mediator is exactly what that mediator evicts.
            rebuild_listener(state).await?;

            // If the rotation moved us to a different mediator, peers holding a
            // stale DID document are still delivering to the old one. Stay
            // connected to it until the generation expires, or that queue is
            // stranded. A same-mediator key rotation short-circuits inside
            // `spawn_mediator_drain` and costs nothing.
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
/// in the profile vector vanishes the moment the socket drops, no matter that
/// we inserted it into the shared resolver.
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

    // Union across live generations: a generation retiring out of DIDComm while
    // the current identity is TSP-only still has peers delivering DIDComm to it
    // until it expires.
    let transports = identity.protocols();
    let protocols = match (transports.didcomm, transports.tsp) {
        (true, true) => Protocols::BOTH,
        (false, true) => Protocols::TSP_ONLY,
        _ => Protocols::DIDCOMM_ONLY,
    };

    // Remove-then-add, not add-then-remove: the mediator allows exactly one
    // connection per DID, and the framework rejects a second listener for a DID
    // it already holds. There is a brief window with no listener; inbound
    // messages queue at the mediator and are delivered on reconnect.
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

/// The two periodic jobs, on deliberately different cadences.
///
/// **Expiry** is local — it compares timestamps and reads the store — so it runs
/// every 60s and retires generations promptly.
///
/// **Reload** re-resolves our DID document over the network. It is only a
/// *backstop* here (the publish hook already catches a rotation the instant it
/// happens), so running it as often as the expiry sweep would mean ~1,400
/// pointless self-resolves a day. It runs every 5 minutes instead — far inside
/// any sane grace period.
pub async fn run_identity_sweep_loop(state: AppState, mut shutdown: watch::Receiver<bool>) {
    let mut expiry = tokio::time::interval(DEFAULT_SWEEP_INTERVAL);
    let mut reload = tokio::time::interval(DEFAULT_RELOAD_INTERVAL);
    // Intervals fire immediately; skip that first tick.
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

/// Start draining an old mediator, if this generation left one behind.
///
/// A key rotation on the same mediator needs nothing here — the old secret is
/// already in the main listener's profile. Only a *mediator change* strands a
/// queue, and only then does a second connection earn its keep.
///
/// Spawned detached. The task ends when the generation leaves the live set, so
/// it needs no handle: the expiry sweep and the kill switch both act on the live
/// set, and the drain simply notices.
pub fn spawn_mediator_drain(state: &AppState, generation: IdentityGeneration) {
    let Some(identity) = state.identity.clone() else {
        return;
    };
    if !identity_drain::needs_drain(&identity, &generation) {
        return;
    }
    let Some(listener) = identity_drain::drain_listener_config("control", &identity, &generation)
    else {
        return;
    };

    let router = match messaging::build_control_router(state.clone()) {
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

        // The drain's own service — a *separate* `DIDCommService` instance. Safe
        // because the duplicate-DID guard is per-instance and the mediator's own
        // eviction is per-mediator, so the same DID on two different mediators
        // conflicts at neither end. See `identity_drain` for why an HTTP poll
        // cannot be used instead (it cannot send responses).
        let shutdown = CancellationToken::new();
        let config = identity_drain::drain_service_config(listener);

        let svc = if tsp_enabled {
            DIDCommService::start_with_tsp(
                config,
                router,
                crate::tsp::WebvhTspHandler::new(drain_state),
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

        // Runs until the generation expires or an operator retires it early.
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
/// Called once, after the main listener is up. A restart part-way through a
/// drain window must reconnect to the old mediator, or the queue sitting there is
/// abandoned for good — which is the whole reason the generation is persisted.
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
/// Local only. Rebuilds the listener when the live set actually shrank.
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
        // and the key would come back from the dead.
        if let Err(e) = rebuild_listener(state).await {
            error!("failed to rebuild the listener after expiring {reaped} generation(s): {e}");
        }
    }
}

/// Expire one generation immediately, regardless of its grace period.
///
/// The compromise response. Messages still addressed to the old key stop
/// decrypting at once — that is the point, and the caller is expected to have
/// meant it.
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

/// How long the expiry sweep waits between passes (local, cheap). Re-exported so
/// the daemon's unified storage task runs on the same cadence.
pub const SWEEP_INTERVAL: Duration = DEFAULT_SWEEP_INTERVAL;

/// How long between DID-document re-resolves (network). Five times slower than
/// the expiry sweep — see [`run_identity_sweep_loop`].
pub const RELOAD_INTERVAL: Duration = DEFAULT_RELOAD_INTERVAL;
