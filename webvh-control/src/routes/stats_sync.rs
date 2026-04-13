//! Stats sync endpoint — receives per-DID deltas from webvh-server instances.
//!
//! All I/O is deferred to the periodic flush cycle. This handler only updates
//! in-memory counters (nanosecond cost per delta).

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
static LAST_SEQ: std::sync::LazyLock<RwLock<HashMap<String, u64>>> =
    std::sync::LazyLock::new(|| RwLock::new(HashMap::new()));

/// Check and update the idempotency sequence for a server.
///
/// Returns `true` if the payload should be accepted (new seq), or `false`
/// if it's stale/replayed. Shared by both REST and DIDComm stats ingestion.
pub fn accept_seq(server_did: &str, seq: u64) -> bool {
    // seq=0 means server restart — always accept
    if seq > 0 {
        if let Ok(map) = LAST_SEQ.read()
            && let Some(&last) = map.get(server_did)
            && seq <= last
        {
            return false;
        }
    }

    if let Ok(mut map) = LAST_SEQ.write() {
        map.insert(server_did.to_string(), seq);
    }
    true
}

/// POST /api/control/stats — receive per-DID deltas from a server instance.
///
/// Validates ACL, checks sequence for idempotency, then records deltas into
/// the in-memory collector. Zero I/O — everything is flushed to store by
/// the periodic flush cycle in the storage thread.
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

    // Idempotency: reject replayed payloads
    if !accept_seq(&payload.server_did, payload.seq) {
        debug!(
            server_did = %payload.server_did,
            seq = payload.seq,
            "stats sync: stale sequence (skipped)"
        );
        return StatusCode::NO_CONTENT;
    }

    // Record deltas into in-memory collector (no I/O)
    for delta in &payload.did_deltas {
        state.stats_collector.record_deltas(
            &delta.mnemonic,
            delta.resolve_delta,
            delta.update_delta,
            delta.last_resolved_at,
            delta.last_updated_at,
        );
    }

    #[cfg(feature = "metrics")]
    affinidi_webvh_common::server::metrics::inc_stats_sync();

    debug!(
        server_did = %payload.server_did,
        seq = payload.seq,
        delta_count = payload.did_deltas.len(),
        "stats sync accepted"
    );

    StatusCode::NO_CONTENT
}
