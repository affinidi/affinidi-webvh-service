//! The watcher's Trust Task listener: one dispatch for every transport.
//!
//! TSP frames ([`crate::tsp`]), DIDComm trust-task envelopes
//! ([`crate::messaging`]) and `POST /api/trust-tasks`
//! ([`crate::routes::trust_tasks`]) all land in [`dispatch_inbound_document`].
//! The watcher is a replica: it applies `webvh/sync/update/0.2`,
//! `webvh/sync/delete/0.2` and `webvh/sync/batch/0.1` from its configured
//! sources (`sync.source_dids`) and from no one else.
//!
//! ## Every sync is a document its source signed
//!
//! - The document must verify ([`verify_sender_bound`]): an in-band `issuer`,
//!   a `proofPurpose: authentication` proof by one of its `authentication`
//!   keys, `recipient` = this watcher, a fresh `issuedAt`, and a transport
//!   sender that agrees with the proof. One that does not verify gets **no
//!   reply at all** — a signed refusal would settle a sync its source never
//!   sent (HTTPS answers `403` with an unsigned, detail-free body).
//! - A verified document whose issuer is not a configured source is refused
//!   with the task's signed `notAuthorized`, and **nothing is recorded** for
//!   it: the replay cache only ever holds a source's documents, so a stranger
//!   minting DIDs cannot fill it and defer a real sync.
//! - A replay of a document already applied gets no reply.
//!
//! Every reply to a verified document is signed by the watcher.

// The task handlers return the framework's `ErrorPayload`, which is upstream
// and over `result_large_err`'s threshold; see the same allow, and why, on
// `did_hosting_common::server::trust_tasks::handlers`.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use serde_json::{Value, json};
use tracing::{debug, info, warn};
use trust_tasks_rs::specs::webvh::sync::{
    batch::v0_1 as sync_batch, delete::v0_2 as sync_delete, update::v0_2 as sync_update,
};
use trust_tasks_rs::{DeclaredErrorCode, ErrorPayload, RejectReason, TrustTask};

use did_hosting_common::didcomm_types::{MSG_SYNC_BATCH, MSG_SYNC_DELETE, MSG_SYNC_UPDATE};
use did_hosting_common::server::replay::ReplayError;
use did_hosting_common::server::trust_tasks::{
    TransportBoundVerifier, identity_signing_secret, sign_document, verify_sender_bound,
};

use crate::server::AppState;
use crate::watcher_ops::{self, SyncApplied, SyncEntry, SyncRefusal};

/// The transport a document arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Tsp,
    Didcomm,
    Https,
}

/// The sync tasks the watcher applies.
pub const SYNC_TASKS: &[&str] = &[MSG_SYNC_UPDATE, MSG_SYNC_DELETE, MSG_SYNC_BATCH];

/// Build the proof verifier the watcher checks syncs with: the workspace's one
/// construction, over this watcher's DID resolver.
pub fn build_verifier(
    did_resolver: Option<&affinidi_did_resolver_cache_sdk::DIDCacheClient>,
) -> Option<Arc<TransportBoundVerifier>> {
    did_hosting_common::server::trust_tasks::build_verifier(did_resolver)
}

/// The `notAuthorized` code each sync task declares.
fn not_authorized(type_uri: &str) -> Option<DeclaredErrorCode> {
    Some(match type_uri {
        MSG_SYNC_UPDATE => sync_update::error_codes::NOT_AUTHORIZED,
        MSG_SYNC_DELETE => sync_delete::error_codes::NOT_AUTHORIZED,
        MSG_SYNC_BATCH => sync_batch::error_codes::NOT_AUTHORIZED,
        _ => return None,
    })
}

/// Verify, authorise and apply one inbound Trust Task document. Returns the
/// signed reply, or `None` when nothing is to be sent back.
pub async fn dispatch_inbound_document(
    state: &AppState,
    via: Via,
    sender: Option<&str>,
    doc: TrustTask<Value>,
) -> Option<Value> {
    let type_uri = doc.type_uri.to_string();
    // An error is somebody's account of a failure, never a request.
    if type_uri.contains("/trust-task-error/") {
        return None;
    }
    let Some(my_did) = state.config.server_did.as_deref() else {
        warn!(%type_uri, "trust task dropped: this watcher has no configured DID");
        return None;
    };
    let Some(verifier) = state.trust_tasks_verifier.clone() else {
        warn!(%type_uri, "trust task dropped: no DID resolver configured to verify it");
        return None;
    };

    let principal = match verify_sender_bound(&doc, None, sender, my_did, &verifier).await {
        Ok(p) => p,
        Err(e) => {
            warn!(
                ?via,
                sender = sender.unwrap_or("unknown"),
                %type_uri,
                error = %e,
                "trust task not answered: it does not verify"
            );
            return None;
        }
    };

    // Authorise before remembering: see the module docs.
    let reply_id = || format!("urn:uuid:{}", uuid::Uuid::new_v4());
    if !state.config.sync.source_dids.contains(&principal) {
        warn!(issuer = %principal, %type_uri, "sync refused: the issuer is not a configured source");
        let message = format!("{principal} is not a source of this watcher");
        let payload = match not_authorized(&type_uri) {
            Some(code) => ErrorPayload::from(code).with_message(message),
            None => RejectReason::PermissionDenied { reason: message }.into(),
        };
        return seal(
            state,
            my_did,
            &principal,
            error_value(doc.reject_with(reply_id(), payload)),
        )
        .await;
    }

    match state.replay_cache.check(&principal, &doc.id) {
        Ok(()) => {}
        Err(ReplayError::Duplicate) => {
            warn!(issuer = %principal, doc_id = %doc.id, "sync not answered: replay");
            return None;
        }
        Err(ReplayError::Full) => {
            let refusal =
                doc.reject_with(reply_id(), RejectReason::Unavailable { retry_after: None });
            return seal(state, my_did, &principal, error_value(refusal)).await;
        }
    }

    let result = match type_uri.as_str() {
        MSG_SYNC_UPDATE => sync_update_task(state, &principal, &doc).await,
        MSG_SYNC_DELETE => sync_delete_task(state, &principal, &doc).await,
        MSG_SYNC_BATCH => sync_batch_task(state, &principal, &doc).await,
        other => Err(RejectReason::UnsupportedType {
            type_uri: other.to_string(),
        }
        .into()),
    };
    let reply = match result {
        Ok(payload) => doc.respond_with(reply_id(), payload),
        Err(e) => error_value(doc.reject_with(reply_id(), e)),
    };
    seal(state, my_did, &principal, reply).await
}

/// An error document as the untyped reply shape the transports carry.
fn error_value(err: trust_tasks_rs::ErrorResponse) -> TrustTask<Value> {
    let value = serde_json::to_value(&err).expect("error document serialises");
    serde_json::from_value(value).expect("error document re-reads as a TrustTask")
}

/// Stamp a reply from this watcher to `requester` and sign it. A reply the
/// watcher cannot sign is not sent: its source refuses unsigned answers.
async fn seal(
    state: &AppState,
    my_did: &str,
    requester: &str,
    mut reply: TrustTask<Value>,
) -> Option<Value> {
    let identity = state.identity.as_deref()?;
    let secret = match identity_signing_secret(identity, my_did) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "cannot sign trust-task reply");
            return None;
        }
    };
    reply.issuer = Some(my_did.to_string());
    reply.recipient = Some(requester.to_string());
    reply.issued_at = Some(chrono::Utc::now());
    reply.proof = None;
    match sign_document(&reply, &secret).await {
        Ok(signed) => serde_json::to_value(&signed).ok(),
        Err(e) => {
            warn!(error = %e, "cannot sign trust-task reply");
            None
        }
    }
}

fn internal(e: impl std::fmt::Display) -> ErrorPayload {
    RejectReason::InternalError {
        reason: e.to_string(),
    }
    .into()
}

/// Read a request payload into its generated type. The schemas are closed, so
/// a member they do not define — 0.1's snake_case among them — is refused.
fn payload<P: serde::de::DeserializeOwned>(doc: &TrustTask<Value>) -> Result<P, ErrorPayload> {
    serde_json::from_value(doc.payload.clone()).map_err(|e| {
        RejectReason::MalformedRequest {
            reason: format!("the payload does not fit its schema: {e}"),
        }
        .into()
    })
}

/// A reply payload through its generated response type.
fn reply<R: serde::Serialize + serde::de::DeserializeOwned>(
    body: Value,
) -> Result<Value, ErrorPayload> {
    let typed: R = serde_json::from_value(body).map_err(internal)?;
    serde_json::to_value(typed).map_err(internal)
}

fn status_str(status: SyncApplied) -> &'static str {
    match status {
        SyncApplied::Applied => "applied",
        SyncApplied::Unchanged => "unchanged",
    }
}

/// A refusal under the code `sync/update/0.2` declares for it. A transient
/// failure is retryable, so the source keeps the sync queued.
fn refusal_payload(refusal: SyncRefusal) -> ErrorPayload {
    match refusal {
        SyncRefusal::InvalidLog(reason) => {
            ErrorPayload::from(sync_update::error_codes::INVALID_LOG)
                .with_message("the log does not verify")
                .with_details(json!({ "reason": reason }))
        }
        SyncRefusal::HistoryRewrite(m) => {
            ErrorPayload::from(sync_update::error_codes::HISTORY_REWRITE).with_message(m)
        }
        SyncRefusal::Deactivated(m) => {
            ErrorPayload::from(sync_update::error_codes::DEACTIVATED).with_message(m)
        }
        SyncRefusal::Transient(reason) => {
            warn!(%reason, "sync not applied (transient); the source will re-send it");
            RejectReason::InternalError { reason }.into()
        }
    }
}

fn refusal_code(refusal: &SyncRefusal) -> Option<&'static str> {
    match refusal {
        SyncRefusal::InvalidLog(_) => Some(sync_update::error_codes::INVALID_LOG.code),
        SyncRefusal::HistoryRewrite(_) => Some(sync_update::error_codes::HISTORY_REWRITE.code),
        SyncRefusal::Deactivated(_) => Some(sync_update::error_codes::DEACTIVATED.code),
        SyncRefusal::Transient(_) => None,
    }
}

fn entry(
    mnemonic: String,
    did_id: String,
    log_content: String,
    witness_content: Option<String>,
    version_count: u64,
    disabled: bool,
) -> SyncEntry {
    SyncEntry {
        mnemonic,
        did_id,
        log_content,
        witness_content,
        version_count,
        disabled,
    }
}

/// `webvh/sync/update/0.2`.
async fn sync_update_task(
    state: &AppState,
    source: &str,
    doc: &TrustTask<Value>,
) -> Result<Value, ErrorPayload> {
    let u: sync_update::Payload = payload(doc)?;
    let e = entry(
        u.mnemonic.to_string(),
        u.did_id.to_string(),
        u.log_content.to_string(),
        u.witness_content.map(|w| w.to_string()),
        u.version_count.get(),
        u.disabled,
    );
    let status = watcher_ops::apply_sync(&state.store, &state.dids_ks, source, &e)
        .await
        .map_err(refusal_payload)?;
    info!(source, mnemonic = %e.mnemonic, ?status, "sync update applied");
    reply::<sync_update::Response>(json!({ "mnemonic": e.mnemonic, "status": status_str(status) }))
}

/// `webvh/sync/batch/0.1`: one outcome per entry. A refused entry is reported
/// with its code and the rest still apply; an entry the watcher could not
/// apply just now makes the whole batch retryable.
async fn sync_batch_task(
    state: &AppState,
    source: &str,
    doc: &TrustTask<Value>,
) -> Result<Value, ErrorPayload> {
    let b: sync_batch::Payload = payload(doc)?;
    let mut results = Vec::with_capacity(b.updates.len());
    let mut transient: Option<String> = None;
    for u in b.updates {
        let e = entry(
            u.mnemonic.to_string(),
            u.did_id.to_string(),
            u.log_content.to_string(),
            u.witness_content.map(|w| w.to_string()),
            u.version_count.get(),
            u.disabled,
        );
        match watcher_ops::apply_sync(&state.store, &state.dids_ks, source, &e).await {
            Ok(status) => {
                results.push(json!({ "mnemonic": e.mnemonic, "status": status_str(status) }))
            }
            Err(refusal) => match refusal_code(&refusal) {
                Some(code) => {
                    warn!(mnemonic = %e.mnemonic, ?refusal, "sync-batch: entry refused");
                    results
                        .push(json!({ "mnemonic": e.mnemonic, "status": "refused", "code": code }));
                }
                None => {
                    transient.get_or_insert(format!("{refusal:?}"));
                }
            },
        }
    }
    if let Some(reason) = transient {
        return Err(RejectReason::InternalError {
            reason: format!("a sync-batch entry could not be applied just now: {reason}"),
        }
        .into());
    }
    debug!(source, count = results.len(), "sync batch applied");
    reply::<sync_batch::Response>(json!({ "results": results }))
}

/// `webvh/sync/delete/0.2`: stop mirroring the slot. The high-water mark stays.
async fn sync_delete_task(
    state: &AppState,
    source: &str,
    doc: &TrustTask<Value>,
) -> Result<Value, ErrorPayload> {
    let d: sync_delete::Payload = payload(doc)?;
    let mnemonic = d.mnemonic.as_str();
    did_hosting_common::server::mnemonic::validate_mnemonic(mnemonic).map_err(|e| {
        ErrorPayload::from(RejectReason::MalformedRequest {
            reason: format!("mnemonic: {e}"),
        })
    })?;
    let held = watcher_ops::delete_record(&state.store, &state.dids_ks, mnemonic)
        .await
        .map_err(internal)?;
    info!(source, mnemonic, held, "sync delete applied");
    reply::<sync_delete::Response>(json!({
        "mnemonic": mnemonic,
        "status": if held { "deleted" } else { "absent" },
    }))
}
