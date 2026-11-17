//! Rolling a did:webvh log back to an earlier version ([`rollback_did_to`]).

use did_hosting_common::did_ops::{
    self, DidRecord, LogMetadata, agent_name_key, content_log_key, content_witness_key, did_key,
};
use did_hosting_common::server::error::ValidationKind;
use tracing::info;

use crate::auth::AuthClaims;
use crate::server::AppState;
use did_hosting_common::server::error::AppError;

use super::agent_names::reconcile_agent_names;
use super::{
    check_did_host_safety, extract_did_id, extract_log_metadata, extract_service_types,
    get_authorized_record, invalidate_cached_content, stage_index, validate_slot_mnemonic,
};

/// Discard every log entry after `target_version` (1-based), or — with no
/// target — the newest entry alone. Returns the updated record, the log's
/// metadata and how many entries were removed. A target outside
/// `1..=versionCount` is refused; the current version removes nothing.
pub async fn rollback_did_to(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    target_version: Option<u64>,
) -> Result<(DidRecord, Option<LogMetadata>, u64), AppError> {
    use crate::auth::session::now_epoch;

    validate_slot_mnemonic(&state.dids_ks, mnemonic).await?;
    // Held from the record and log reads through the commit: a publish
    // landing in between would otherwise be overwritten by a truncation of
    // the log as it stood before it.
    let _path_guard = state.path_locks.guard(mnemonic).await;
    let mut record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    // Rollback truncates a did:webvh log by line, so it applies to did:webvh
    // alone (an empty method is a slot from before methods were recorded,
    // which is did:webvh). Any other method's content is not one entry per
    // line: a did:web did.json may be pretty-printed, and cutting it by line
    // leaves invalid JSON; a did:webs key event stream is only ever extended
    // by its controller (a publish may not rewind it either, see
    // `Webs::verify_continuation`).
    if !record.method.is_empty() && record.method != "webvh" {
        return Err(AppError::invalid(format!(
            "a did:{} slot cannot be rolled back: rollback removes did:webvh log \
             entries, and this method's content is not a did:webvh log",
            record.method
        )));
    }

    // Re-check DomainScope at time-of-use (SEC-4045 W7).
    if let Some(did_id) = record.did_id.as_deref() {
        check_did_host_safety(state, auth, did_id).await?;
    }

    let bytes = state
        .dids_ks
        .get_raw(content_log_key(mnemonic))
        .await?
        .ok_or_else(|| AppError::NotFound("no log content for this DID".into()))?;

    let content = String::from_utf8(bytes)
        .map_err(|e| AppError::Internal(format!("invalid log bytes: {e}")))?;

    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    let keep = match target_version {
        None => {
            if lines.len() < 2 {
                return Err(AppError::invalid(
                    "cannot rollback: DID log must have at least 2 entries",
                ));
            }
            lines.len() - 1
        }
        Some(target) => {
            if target < 1 || target as usize > lines.len() {
                return Err(AppError::validation(
                    ValidationKind::InvalidTargetVersion,
                    format!(
                        "invalid target version {target}: the log holds {} entries",
                        lines.len()
                    ),
                ));
            }
            target as usize
        }
    };
    let removed = (lines.len() - keep) as u64;
    if removed == 0 {
        let metadata = Some(extract_log_metadata(&content));
        return Ok((record, metadata, 0));
    }

    let truncated_lines = &lines[..keep];
    let truncated = truncated_lines.join("\n");

    let new_did_id = extract_did_id(&truncated);
    let new_size = truncated.len() as u64;

    record.version_count = truncated_lines.len() as u64;
    record.did_id = new_did_id;
    record.content_size = new_size;
    record.updated_at = now_epoch();
    // Rolling back can retract a service — if the dropped entry was the
    // one that added `TSPTransport`, the badge must go with it.
    record.services = extract_service_types(&truncated);

    // The rolled-back document is now the signed document of record, so the
    // agent-name registry follows it exactly as on a publish: names it claims
    // are served, names it no longer claims are released, parked names stay
    // parked. The same preconditions apply — a rollback to an entry claiming a
    // name another DID now holds (or a reserved one) is refused, so a rollback
    // never moves a name between DIDs.
    let domain = if !record.domain.is_empty() {
        record.domain.clone()
    } else {
        record
            .did_id
            .as_deref()
            .and_then(|d| did_hosting_common::server::domain::extract_did_host(d).ok())
            .unwrap_or_default()
    };
    let claims = did_ops::extract_agent_names(&truncated, &domain);
    let now = record.updated_at;
    let (claimed, released, name_locks) =
        reconcile_agent_names(state, &mut record, mnemonic, &claims, &domain, now).await?;

    let mut batch = state.store.batch();
    batch.insert_raw(
        &state.dids_ks,
        content_log_key(mnemonic),
        truncated.as_bytes().to_vec(),
    );
    batch.insert(&state.dids_ks, did_key(mnemonic), &record)?;
    batch.remove(&state.dids_ks, content_witness_key(mnemonic));
    for name in &claimed {
        batch.insert_raw(
            &state.dids_ks,
            agent_name_key(&domain, name),
            mnemonic.as_bytes().to_vec(),
        );
    }
    let previous: Option<DidRecord> = state.dids_ks.get(did_key(mnemonic)).await?;
    for name in &released {
        batch.remove(&state.dids_ks, agent_name_key(&domain, name));
    }
    let sync = crate::server_push::stage_did_sync(
        state,
        &mut batch,
        mnemonic,
        crate::server_push::DidChange::Published { log: &truncated },
    )
    .await;
    let usage = stage_index(state, &mut batch, previous.as_ref(), Some(&record)).await?;
    batch.commit().await?;
    sync.finish(state).await;
    drop(name_locks);
    drop(usage);
    invalidate_cached_content(state, mnemonic);

    let log_metadata = Some(extract_log_metadata(&truncated));

    info!(
        did = %auth.did,
        mnemonic = %mnemonic,
        remaining = truncated_lines.len(),
        removed,
        "DID log rolled back on control plane"
    );

    Ok((record, log_metadata, removed))
}
