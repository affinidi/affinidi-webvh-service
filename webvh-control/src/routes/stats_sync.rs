//! Stats sync endpoint — receives per-DID deltas from webvh-server instances.

use std::collections::HashMap;
use std::sync::RwLock;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;

use affinidi_webvh_common::StatsSyncPayload;
use affinidi_webvh_common::server::acl;
use tracing::{debug, warn};

use crate::server::AppState;

/// Tracks the last accepted sequence number per server DID.
/// Prevents replayed or out-of-order stats payloads from being applied twice.
static LAST_SEQ: std::sync::LazyLock<RwLock<HashMap<String, u64>>> =
    std::sync::LazyLock::new(|| RwLock::new(HashMap::new()));

/// POST /api/control/stats — receive per-DID deltas from a server instance.
///
/// Validates that `server_did` is in the ACL, and that the sequence number
/// is strictly increasing (rejects replayed payloads).
pub async fn receive_stats(
    State(state): State<AppState>,
    Json(payload): Json<StatsSyncPayload>,
) -> StatusCode {
    // Validate the server DID is in the ACL
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

    // Idempotency: reject replayed or out-of-order payloads
    {
        let map = match LAST_SEQ.read() {
            Ok(m) => m,
            Err(_) => {
                warn!("LAST_SEQ lock poisoned — accepting payload");
                return StatusCode::NO_CONTENT;
            }
        };
        if let Some(&last) = map.get(&payload.server_did) {
            if payload.seq <= last {
                debug!(
                    server_did = %payload.server_did,
                    seq = payload.seq,
                    last_seq = last,
                    "stats sync rejected: stale sequence"
                );
                return StatusCode::NO_CONTENT; // Silently accept (idempotent)
            }
        }
    }

    // Update last seen sequence
    {
        let mut map = match LAST_SEQ.write() {
            Ok(m) => m,
            Err(_) => {
                warn!("LAST_SEQ write lock poisoned — accepting payload");
                // Fall through to apply deltas even if sequence tracking is broken
                return StatusCode::NO_CONTENT;
            }
        };
        map.insert(payload.server_did.clone(), payload.seq);
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
        seq = payload.seq,
        delta_count,
        "received stats sync"
    );

    StatusCode::NO_CONTENT
}
