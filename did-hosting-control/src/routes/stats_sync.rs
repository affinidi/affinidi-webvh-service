//! Stats sync endpoint — receives per-DID deltas from did-hosting-server instances.
//!
//! All I/O is deferred to the periodic flush cycle. This handler only updates
//! in-memory counters (nanosecond cost per delta).

use std::collections::HashMap;
use std::sync::RwLock;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;

use did_hosting_common::server::acl;
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

/// `POST /api/control/stats` — a server's signed stats-sync document.
///
/// The body is a `.../server/stats-sync/0.1` Trust Task document. It is
/// applied only when signed by its issuer (an `authentication` key), addressed
/// to this control plane and fresh (`verify_sender_bound`), not a replay, and
/// the issuer holds the `Service` role — the same checks, and the same core
/// (`do_stats_sync`), as the messaging path. There is no bearer token: the
/// document's own proof is the authentication.
pub async fn receive_stats(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> (StatusCode, Json<serde_json::Value>) {
    use did_hosting_common::didcomm_types::MSG_STATS_SYNC;
    use did_hosting_common::server::trust_tasks::verify_sender_bound;
    use serde_json::json;

    let refuse = |status: StatusCode, reason: &str| (status, Json(json!({ "error": reason })));
    let doc: trust_tasks_rs::TrustTask<serde_json::Value> = match serde_json::from_slice(&body) {
        Ok(d) => d,
        Err(_) => return refuse(StatusCode::BAD_REQUEST, "body is not a Trust Task document"),
    };
    if doc.type_uri.to_string() != MSG_STATS_SYNC {
        return refuse(StatusCode::BAD_REQUEST, "expected a stats-sync document");
    }
    let (Some(my_vid), Some(verifier)) = (
        state.config.server_did.as_deref(),
        state.trust_tasks_verifier.as_deref(),
    ) else {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "control plane cannot verify documents",
        );
    };
    // Cheap pre-filter before any signature work.
    let Some(issuer) = doc.issuer.clone() else {
        return refuse(StatusCode::BAD_REQUEST, "document names no issuer");
    };
    if !matches!(
        acl::get_acl_entry(&state.acl_ks, &issuer).await,
        Ok(Some(_))
    ) {
        warn!(%issuer, "stats sync rejected: DID not in ACL");
        return refuse(StatusCode::FORBIDDEN, "not permitted");
    }
    let signer = match verify_sender_bound(&doc, None, None, my_vid, verifier).await {
        Ok(s) => s,
        Err(e) => {
            warn!(%issuer, error = %e, "stats sync rejected: document not bound to its signer");
            return refuse(StatusCode::FORBIDDEN, "document proof invalid");
        }
    };
    if state.replay_cache.check(&signer, &doc.id).is_err() {
        return refuse(StatusCode::CONFLICT, "replayed document");
    }
    match crate::messaging::do_stats_sync(&state, &signer, &doc.payload).await {
        Ok(ack) => {
            debug!(%signer, "stats sync accepted (HTTPS)");
            (StatusCode::OK, Json(ack))
        }
        Err(rej) => (
            StatusCode::FORBIDDEN,
            Json(json!({ "code": rej.code, "comment": rej.comment })),
        ),
    }
}
