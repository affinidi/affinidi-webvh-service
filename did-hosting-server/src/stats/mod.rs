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

/// Push per-DID stat deltas to the control plane via HTTP.
///
/// Drains the collector's accumulated deltas. If nothing changed since the
/// last sync, the HTTP POST is skipped entirely (zero cost when idle).
/// Each payload includes a monotonic sequence number so the control plane
/// can detect replayed or out-of-order payloads.
pub async fn sync_to_control(
    http: &reqwest::Client,
    control_url: &str,
    server_did: &str,
    collector: &StatsCollector,
) {
    let deltas = collector.drain_for_sync();
    if deltas.is_empty() {
        return; // Nothing changed — skip the POST
    }

    let seq = SYNC_SEQ.fetch_add(1, Ordering::Relaxed);

    let payload = did_hosting_common::StatsSyncPayload {
        server_did: server_did.to_string(),
        seq,
        did_deltas: deltas,
    };

    let url = format!("{control_url}/api/control/stats");
    match http.post(&url).json(&payload).send().await {
        Ok(_) => {
            #[cfg(feature = "metrics")]
            did_hosting_common::server::metrics::inc_stats_sync();
        }
        Err(e) => {
            warn!(error = %e, url = %url, "failed to sync stats to control plane");
        }
    }
}

/// Push per-DID stat deltas to the control plane via DIDComm.
///
/// Same semantics as `sync_to_control` but routes through the mediator
/// instead of requiring direct HTTP access to the control plane.
pub async fn sync_to_control_didcomm(
    svc: &DIDCommService,
    server_did: &str,
    control_did: &str,
    collector: &StatsCollector,
) {
    use affinidi_messaging_didcomm::Message;
    use did_hosting_common::didcomm_types::MSG_STATS_SYNC;
    use serde_json::json;

    let deltas = collector.drain_for_sync();
    if deltas.is_empty() {
        return;
    }

    let seq = SYNC_SEQ.fetch_add(1, Ordering::Relaxed);

    let did_deltas: Vec<_> = deltas
        .iter()
        .map(|d| {
            json!({
                "mnemonic": d.mnemonic,
                "resolve_delta": d.resolve_delta,
                "update_delta": d.update_delta,
                "last_resolved_at": d.last_resolved_at,
                "last_updated_at": d.last_updated_at,
            })
        })
        .collect();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        MSG_STATS_SYNC.to_string(),
        json!({
            "server_did": server_did,
            "seq": seq,
            "did_deltas": did_deltas,
        }),
    )
    .from(server_did.to_string())
    .to(control_did.to_string())
    .created_time(now)
    .finalize();

    if let Err(e) = svc.send_message("server", msg, control_did).await {
        debug!(error = %e, "failed to sync stats to control plane via DIDComm");
    }
}
