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
            // seq=0 means server restarted — accept and reset tracking
            if payload.seq > 0 && payload.seq <= last {
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

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let bucket_epoch = now / 300 * 300; // 5-minute bucket

    for delta in &payload.did_deltas {
        state.stats_collector.record_deltas(
            &delta.mnemonic,
            delta.resolve_delta,
            delta.update_delta,
            delta.last_resolved_at,
            delta.last_updated_at,
        );

        // Record time-series buckets (per-DID + global)
        if delta.resolve_delta > 0 || delta.update_delta > 0 {
            let _ = record_ts_bucket(
                &state.stats_ks,
                &delta.mnemonic,
                bucket_epoch,
                delta.resolve_delta,
                delta.update_delta,
            )
            .await;
            let _ = record_ts_bucket(
                &state.stats_ks,
                "_all",
                bucket_epoch,
                delta.resolve_delta,
                delta.update_delta,
            )
            .await;
        }
    }

    #[cfg(feature = "metrics")]
    affinidi_webvh_common::server::metrics::inc_stats_sync();

    debug!(
        server_did = %payload.server_did,
        seq = payload.seq,
        delta_count,
        "received stats sync"
    );

    StatusCode::NO_CONTENT
}

/// Record resolve/update deltas into a 5-minute time-series bucket.
async fn record_ts_bucket(
    stats_ks: &affinidi_webvh_common::server::store::KeyspaceHandle,
    mnemonic: &str,
    epoch: u64,
    resolves: u64,
    updates: u64,
) -> Result<(), affinidi_webvh_common::server::error::AppError> {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Default)]
    struct BucketData {
        r: u64,
        u: u64,
    }

    let key = format!("ts:{mnemonic}:{epoch:010}");
    let mut bucket: BucketData = stats_ks.get(key.as_str()).await?.unwrap_or_default();
    bucket.r += resolves;
    bucket.u += updates;
    stats_ks.insert(key, &bucket).await
}
