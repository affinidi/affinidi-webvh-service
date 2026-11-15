//! Stats collection and sync to control plane.
//!
//! Hot-path operations (`record_resolve`, `record_update`) accumulate in the
//! in-memory `StatsCollector`. A periodic sync task drains the per-DID deltas
//! and pushes them to the control plane, which holds the authoritative totals.
//!
//! Stats are **not** persisted to disk on the server. On restart the counters
//! start at zero and deltas are additive on the control plane, so there is no
//! double-counting.

pub use did_hosting_common::server::stats_collector::{StatsAggregate, StatsCollector};

use affinidi_messaging_didcomm_service::DIDCommService;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, warn};

/// Monotonic sequence counter for stats sync idempotency.
static SYNC_SEQ: AtomicU64 = AtomicU64::new(0);

/// Push per-DID stat deltas to the control plane over the messaging transport.
///
/// The binding (TSP or DIDComm) follows the control plane's DID document;
/// there is no HTTPS side channel to the control plane.
///
/// Sent as a signed `.../server/stats-sync/0.1` trust task: the control plane
/// credits the deltas to the server whose DID signed the document, so an
/// unsigned push — the bare-message form this replaced — is refused there.
pub async fn sync_to_control_messaging(
    svc: &DIDCommService,
    state: &crate::server::AppState,
    server_did: &str,
    control_did: &str,
    collector: &StatsCollector,
) {
    use did_hosting_common::didcomm_types::MSG_STATS_SYNC;
    use did_hosting_common::server::didcomm_profile::TransportFallback;
    use did_hosting_common::server::trust_tasks::send::{
        Peers, build_signed_request, send_trust_task,
    };

    // Resolve the signer before draining, so a node that cannot sign keeps
    // its deltas for a later tick instead of discarding them.
    let Some(identity) = state.identity.as_deref() else {
        debug!("stats sync skipped: service identity not loaded, cannot sign");
        return;
    };
    let signer = match did_hosting_common::server::trust_tasks::identity_signing_secret(
        identity, server_did,
    ) {
        Ok(s) => s,
        Err(e) => {
            debug!(error = %e, "stats sync skipped: no signing key");
            return;
        }
    };

    let mut deltas = collector.drain_for_sync();
    if deltas.is_empty() {
        return;
    }
    // The control plane refuses an oversized sync; send what fits and keep
    // the rest (a backlog after an outage) for the next tick.
    let max = did_hosting_common::server::stats_collector::MAX_STATS_SYNC_DELTAS;
    if deltas.len() > max {
        collector.requeue_deltas(deltas.split_off(max));
    }

    let seq = SYNC_SEQ.fetch_add(1, Ordering::Relaxed);

    // The pinned `server/stats-sync/0.1` shape: `seq` and each entry's
    // latest-event times travel in our `ext` namespace.
    use did_hosting_common::server::trust_tasks::infra;
    let body = match infra::stats_sync_body(&infra::instance_id_for(server_did), seq, &deltas) {
        Ok(body) => body,
        Err(e) => {
            // Only an entry the schema refuses (an empty path) gets here, and
            // no tick would ever send it: dropped, not requeued.
            warn!(error = %e, dropped = deltas.len(), "stats sync: deltas do not fit server/stats-sync/0.1; dropped");
            return;
        }
    };

    let fallback = TransportFallback::from_config(
        state.config.mediator_did.as_deref(),
        state.config.features.tsp,
    );
    let sent =
        match build_signed_request(MSG_STATS_SYNC, server_did, control_did, body, &signer).await {
            Ok(doc) => send_trust_task(
                svc,
                "server",
                server_did,
                control_did,
                &doc,
                &fallback,
                Peers::new(
                    state.did_resolver.as_ref(),
                    state.trust_tasks_verifier.as_deref(),
                ),
            )
            .await
            .map(|_| ()),
            Err(e) => Err(e),
        };
    if let Err(e) = sent {
        // Keep the deltas for the next tick. A send that failed after the
        // control plane accepted it is counted twice; one that is dropped is
        // lost for good, which is the worse error for a counter.
        let dropped = collector.requeue_deltas(deltas);
        debug!(error = %e, dropped, "failed to sync stats to control plane (trust task); deltas requeued");
    }
}
