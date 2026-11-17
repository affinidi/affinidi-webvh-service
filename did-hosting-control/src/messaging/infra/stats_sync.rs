//! `server/stats-sync`: an edge's signed stats deltas, merged into the
//! control plane's collector.

use super::*;

// ---------------------------------------------------------------------------
// Stats sync (server → control plane)
// ---------------------------------------------------------------------------

/// Tracks the last accepted sequence number per server DID.
pub(in crate::messaging) static LAST_SEQ: std::sync::LazyLock<
    std::sync::RwLock<std::collections::HashMap<String, u64>>,
> = std::sync::LazyLock::new(|| std::sync::RwLock::new(std::collections::HashMap::new()));

/// Check and update the idempotency sequence for a server.
///
/// Returns `true` if the payload should be accepted (new seq), or `false`
/// if it's stale/replayed.
pub(in crate::messaging) fn accept_seq(server_did: &str, seq: u64) -> bool {
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

/// Transport-agnostic core of stats sync, for the `.../server/stats-sync/0.1`
/// trust task over DIDComm **or** TSP.
///
/// `signer` is the document's proven issuer (see
/// [`dispatch_trust_task_doc`]), never a transport's report. Returns the ack
/// body — `accepted`, or `skipped` for a stale sequence — or a rejection when
/// the signer is not a Service.
pub(crate) async fn do_stats_sync(
    state: &AppState,
    signer: &str,
    body: &Value,
) -> Result<Value, InfraRejection> {
    use did_hosting_common::server::trust_tasks::infra;

    // Require Service role. An Owner-role DID must not be able to write per-DID
    // stats deltas: doing so would let any tenant tamper with another
    // server's resolved/update counters.
    let service = is_service(state, signer).await.map_err(|e| {
        warn!(did = signer, error = %e, "stats sync deferred: ACL lookup failed");
        InfraRejection::lookup_failed(&e)
    })?;
    if !service {
        warn!(did = signer, "stats sync rejected: Service role required");
        return Err(InfraRejection::not_authorised("service role required"));
    }

    // The body is typed and closed (R3.2): a member this service does not
    // read is refused rather than silently dropped. The pinned
    // `server/stats-sync/0.1` shape, or for one release the shape edges
    // sent before #449 (`infra::read_stats_sync`).
    let body = infra::read_stats_sync(body).map_err(|e| {
        warn!(did = signer, error = %e, "stats sync rejected: malformed payload");
        InfraRejection::malformed(format!("not a stats-sync payload this service reads: {e}"))
    })?;

    // Bind the payload to the proven signer. The sender keys the replay
    // window, so accepting a foreign one would let one server advance — and
    // so suppress — another's.
    if let Err(claimed) = body.identity.check(signer) {
        warn!(
            did = signer,
            claimed, "stats sync rejected: instanceId/server_did does not name the signer"
        );
        return Err(InfraRejection::SenderMismatch {
            claimed,
            signer: signer.to_string(),
        });
    }
    let server_did = signer;
    let instance_id = infra::instance_id_for(signer);
    let ack = |accepted: u64, skipped: Option<&str>| {
        infra::stats_sync_ack(&instance_id, accepted, skipped).map_err(|e| {
            InfraRejection::Failed(Box::new(trust_tasks_rs::RejectReason::TaskFailed {
                reason: e,
                details: None,
            }))
        })
    };

    // Ordering: a sync without `seq` is not ordered (its document id is still
    // replay-checked by the proof gate).
    if let Some(seq) = body.seq
        && !accept_seq(server_did, seq)
    {
        debug!(server_did, seq, "stats sync: stale sequence");
        return ack(0, Some("stale_seq"));
    }
    let seq = body.seq;

    let deltas = body.deltas.as_slice();
    if deltas.len() > did_hosting_common::server::stats_collector::MAX_STATS_SYNC_DELTAS {
        warn!(
            did = signer,
            count = deltas.len(),
            "stats sync rejected: too many deltas"
        );
        return Err(InfraRejection::TooLarge {
            message: "too many deltas in one sync".into(),
            limit: did_hosting_common::server::stats_collector::MAX_STATS_SYNC_DELTAS,
        });
    }
    let mut invalid = 0usize;
    let mut invalid_sample: Vec<String> = Vec::new();
    // Lookups left for paths outside the current grammar (see below).
    let mut lookups_left = MAX_HOSTED_LOOKUPS_PER_SYNC;
    for d in deltas {
        let mnemonic = d.mnemonic.as_str();
        // The path keys `stats:` and `ts:` rows: only a hosted-path shape is
        // accepted, and never the server-wide series name. A path stored
        // before the current path rules is accepted if it is hosted here;
        // that costs a read, so only a few are looked up per sync.
        // A count one edge could not have seen in one sync interval is not
        // a count: it is refused with the delta rather than added.
        let mut accepted = d.resolve_delta <= MAX_SYNCED_COUNT
            && d.update_delta <= MAX_SYNCED_COUNT
            && is_stats_mnemonic(mnemonic);
        if !accepted
            && d.resolve_delta <= MAX_SYNCED_COUNT
            && d.update_delta <= MAX_SYNCED_COUNT
            && lookups_left > 0
            && is_key_safe_stats_path(mnemonic)
        {
            lookups_left -= 1;
            accepted = state
                .dids_ks
                .contains_key(did_hosting_common::did_ops::did_key(mnemonic))
                .await
                .unwrap_or(false);
        }
        if !accepted {
            invalid += 1;
            if invalid_sample.len() < 5 {
                invalid_sample.push(mnemonic.chars().take(64).collect());
            }
            continue;
        }
        state.stats_collector.record_deltas(
            mnemonic,
            d.resolve_delta,
            d.update_delta,
            d.last_resolved_at,
            d.last_updated_at,
        );
    }

    if invalid > 0 {
        warn!(
            server_did,
            invalid,
            sample = ?invalid_sample,
            "stats sync: skipped deltas whose path is not a hosted DID path"
        );
    }
    debug!(
        server_did,
        ?seq,
        delta_count = deltas.len(),
        "stats sync accepted"
    );

    ack((deltas.len() - invalid) as u64, None)
}

/// The largest resolve or update count one delta may carry: far above what
/// one edge serves one DID between two syncs, far below what could wrap a
/// running total.
pub(in crate::messaging) const MAX_SYNCED_COUNT: u64 = 1_000_000_000;

/// Most odd-shaped stats-sync paths one sync may have looked up in the
/// store to see whether they are hosted here.
pub(in crate::messaging) const MAX_HOSTED_LOOKUPS_PER_SYNC: usize = 100;

/// Whether a path outside the current path grammar could still key a stats
/// row safely: non-empty, bounded, never the server-wide series name, and
/// without the `:` that separates a `ts:` key's path from its epoch.
pub(in crate::messaging) fn is_key_safe_stats_path(mnemonic: &str) -> bool {
    use did_hosting_common::server::stats_collector::ALL_SERIES;

    !mnemonic.is_empty()
        && mnemonic.len() <= 255
        && mnemonic != ALL_SERIES
        && !mnemonic.contains(':')
        && !mnemonic.chars().any(char::is_control)
}

/// Whether a stats-sync delta's path can key a stats row: a hosted path's
/// shape (`did:webs` slots end in a case-sensitive AID), never the
/// server-wide series name.
pub(in crate::messaging) fn is_stats_mnemonic(mnemonic: &str) -> bool {
    use did_hosting_common::server::mnemonic::{validate_mnemonic, validate_webs_mnemonic};
    use did_hosting_common::server::stats_collector::ALL_SERIES;

    mnemonic != ALL_SERIES
        && (validate_mnemonic(mnemonic).is_ok() || validate_webs_mnemonic(mnemonic).is_ok())
}
