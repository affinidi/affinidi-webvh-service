//! Stats sync endpoint — receives per-DID deltas from webvh-server instances.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;

use affinidi_webvh_common::StatsSyncPayload;
use affinidi_webvh_common::server::acl;
use tracing::{debug, warn};

use crate::server::AppState;

/// POST /api/control/stats — receive per-DID deltas from a server instance.
///
/// Validates that `server_did` belongs to a registered service account (ACL
/// lookup, O(1)). Deltas are merged into the in-memory collector.
pub async fn receive_stats(
    State(state): State<AppState>,
    Json(payload): Json<StatsSyncPayload>,
) -> StatusCode {
    // Validate the server DID is in the ACL (any role — service, admin, or owner)
    match acl::get_acl_entry(&state.acl_ks, &payload.server_did).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            warn!(server_did = %payload.server_did, "stats sync rejected: DID not in ACL");
            return StatusCode::FORBIDDEN;
        }
        Err(e) => {
            warn!(error = %e, "stats sync: ACL lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    }

    let delta_count = payload.did_deltas.len();

    for delta in &payload.did_deltas {
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
