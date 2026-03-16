//! Stats sync endpoint — receives aggregate stats pushed by webvh-server instances.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;

use affinidi_webvh_common::StatsSyncPayload;
use tracing::debug;

use crate::server::AppState;

/// POST /api/control/stats — receive stats from a server instance.
///
/// No authentication required — servers self-identify by their DID in the payload.
/// This is intentional: stats are non-sensitive aggregate counters, and requiring
/// auth would add complexity to the sync hot path.
pub async fn receive_stats(
    State(state): State<AppState>,
    Json(payload): Json<StatsSyncPayload>,
) -> StatusCode {
    debug!(
        server_did = %payload.server_did,
        total_dids = payload.total_dids,
        total_resolves = payload.total_resolves,
        total_updates = payload.total_updates,
        "received stats sync"
    );

    if let Ok(mut map) = state.server_stats.write() {
        map.insert(payload.server_did.clone(), payload);
    }

    StatusCode::NO_CONTENT
}
