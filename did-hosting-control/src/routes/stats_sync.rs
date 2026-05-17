//! Stats sync endpoint — receives per-DID deltas from did-hosting-server instances.
//!
//! All I/O is deferred to the periodic flush cycle. This handler only updates
//! in-memory counters (nanosecond cost per delta).

use std::collections::HashMap;
use std::sync::RwLock;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;

use did_hosting_common::StatsSyncPayload;
use did_hosting_common::server::acl;
use did_hosting_common::server::auth::ServiceAuth;
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
    if seq > 0
        && let Ok(map) = LAST_SEQ.read()
        && let Some(&last) = map.get(server_did)
        && seq <= last
    {
        return false;
    }

    if let Ok(mut map) = LAST_SEQ.write() {
        map.insert(server_did.to_string(), seq);
    }
    true
}

/// POST /api/control/stats — receive per-DID deltas from a server instance.
///
/// Requires the Service-role JWT issued to the registered server, and rejects
/// payloads whose `server_did` does not match the authenticated caller. The
/// Service role is a separate role from Admin/Owner; only servers that have
/// completed registration receive a Service JWT.
///
/// Validates ACL, checks sequence for idempotency, then records deltas into
/// the in-memory collector. Zero I/O — everything is flushed to store by
/// the periodic flush cycle in the storage thread.
pub async fn receive_stats(
    auth: ServiceAuth,
    State(state): State<AppState>,
    Json(payload): Json<StatsSyncPayload>,
) -> StatusCode {
    // Bind the payload to the JWT-authenticated server. Without this check,
    // any holder of a Service-role JWT could falsify counters for any server.
    if auth.0.did != payload.server_did {
        warn!(
            authenticated = %auth.0.did,
            claimed = %payload.server_did,
            "stats sync rejected: payload server_did does not match authenticated DID",
        );
        return StatusCode::FORBIDDEN;
    }

    // Belt-and-braces: re-check ACL membership at request time so a yanked
    // ACL entry takes effect immediately even if the JWT hasn't expired.
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
    did_hosting_common::server::metrics::inc_stats_sync();

    debug!(
        server_did = %payload.server_did,
        seq = payload.seq,
        delta_count = payload.did_deltas.len(),
        "stats sync accepted"
    );

    StatusCode::NO_CONTENT
}
