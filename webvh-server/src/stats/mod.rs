//! Stats collection and sync to control plane.
//!
//! Hot-path operations (`record_resolve`, `record_update`) accumulate in the
//! in-memory `StatsCollector`. A periodic sync task drains the per-DID deltas
//! and pushes them to the control plane, which holds the authoritative totals.
//!
//! Stats are **not** persisted to disk on the server. On restart the counters
//! start at zero and deltas are additive on the control plane, so there is no
//! double-counting.

pub use affinidi_webvh_common::server::stats_collector::{StatsAggregate, StatsCollector};

use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

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

    let payload = affinidi_webvh_common::StatsSyncPayload {
        server_did: server_did.to_string(),
        seq,
        did_deltas: deltas,
    };

    let url = format!("{control_url}/api/control/stats");
    match http.post(&url).json(&payload).send().await {
        Ok(_) => {
            #[cfg(feature = "metrics")]
            affinidi_webvh_common::server::metrics::inc_stats_sync();
        }
        Err(e) => {
            warn!(error = %e, url = %url, "failed to sync stats to control plane");
        }
    }
}
