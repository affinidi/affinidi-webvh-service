//! Stats sync endpoint — receives per-DID deltas from webvh-server instances.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;

use affinidi_webvh_common::StatsSyncPayload;
use tracing::debug;

use crate::server::AppState;

/// POST /api/control/stats — receive per-DID deltas from a server instance.
///
/// No authentication required — servers self-identify by their DID in the payload.
/// Deltas are merged into the in-memory collector (fast, no I/O). A separate
/// flush timer on the storage thread writes dirty per-DID stats to the store.
pub async fn receive_stats(
    State(state): State<AppState>,
    Json(payload): Json<StatsSyncPayload>,
) -> StatusCode {
    let delta_count = payload.did_deltas.len();

    for delta in &payload.did_deltas {
        // Update in-memory per-DID deltas (will be flushed to store periodically)
        state.stats_collector.record_deltas(
            &delta.mnemonic,
            delta.resolve_delta,
            delta.update_delta,
            delta.last_resolved_at,
            delta.last_updated_at,
        );
    }

    debug!(
        server_did = %payload.server_did,
        delta_count,
        "received stats sync"
    );

    StatusCode::NO_CONTENT
}
