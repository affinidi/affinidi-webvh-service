//! The witness's Trust Task listener: one dispatch for every transport.
//!
//! TSP frames ([`crate::tsp`]), DIDComm trust-task envelopes
//! ([`crate::messaging`]) and `POST /api/trust-tasks`
//! ([`crate::routes::trust_tasks`]) all land in [`dispatch_inbound_document`],
//! so a request is verified, authorised and answered identically whichever
//! transport carried it. The witness serves:
//!
//! - `webvh/witness/key/create|list|delete/0.1` — administer witness identities;
//! - `webvh/witness/sign/0.1` — witness one log entry, after verifying the log;
//! - `acl/grant|revoke|change-role|show|list/0.1` — the witness's own ACL.
//!
//! ## Every request is a document its issuer signed
//!
//! A request is acted on only when its own proof establishes who sent it
//! ([`verify_sender_bound`]): an in-band `issuer`, a `proofPurpose:
//! authentication` proof by one of the issuer's `authentication` keys,
//! `recipient` = this witness, and a fresh `issuedAt`. The transport's sender
//! is only required to agree with the proof.
//!
//! - A document that does not verify gets **no reply at all** — not even an
//!   unsigned refusal on the messaging transports (HTTPS answers `403` with a
//!   detail-free, unsigned body, which settles nothing).
//! - A verified document whose issuer the witness does not authorise is
//!   answered with a signed `permissionDenied`, and **nothing is recorded** for
//!   it — the replay cache only ever holds documents from authorised issuers,
//!   so a stranger minting DIDs cannot fill it and defer a real request.
//! - A replay of a document already acted on gets no reply.
//!
//! Every reply to a verified document is signed by the witness.

// The task handlers return the framework's `ErrorPayload`, which is upstream
// and over `result_large_err`'s threshold; see the same allow, and why, on
// `did_hosting_common::server::trust_tasks::handlers`.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use serde_json::{Value, json};
use tracing::{info, warn};
use trust_tasks_rs::specs::acl::{change_role, grant, list, revoke, show};
use trust_tasks_rs::specs::webvh::witness::{
    key::{create::v0_1 as key_create, delete::v0_1 as key_delete, list::v0_1 as key_list},
    sign::v0_1 as sign,
};
use trust_tasks_rs::{ErrorPayload, Payload, ProofPolicy, RejectReason, TrustTask};

use did_hosting_common::did_ops::{WitnessLogRefusal, verify_log_for_witnessing};
use did_hosting_common::server::acl::Role;
use did_hosting_common::server::replay::ReplayError;
use did_hosting_common::server::trust_tasks::{
    DispatchOutcome, TransportBoundVerifier, TrustTaskContext, TspTransportHandler,
    dispatch_inbound, identity_signing_secret, sign_document, verify_sender_bound,
};

use crate::server::AppState;
use crate::witness_ops::{self, WitnessRecord};

/// The transport a document arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Tsp,
    Didcomm,
    Https,
}

/// The witness's own tasks.
pub const WITNESS_TASKS: &[&str] = &[
    key_create::Payload::TYPE_URI,
    key_list::Payload::TYPE_URI,
    key_delete::Payload::TYPE_URI,
    sign::Payload::TYPE_URI,
];

/// The shared ACL family, served on the witness's own ACL.
pub const ACL_TASKS: &[&str] = &[
    grant::v0_1::Payload::TYPE_URI,
    revoke::v0_1::Payload::TYPE_URI,
    change_role::v0_1::Payload::TYPE_URI,
    show::v0_1::Payload::TYPE_URI,
    list::v0_1::Payload::TYPE_URI,
];

/// Build the proof verifier the witness checks requests with: the workspace's
/// one construction, over this witness's DID resolver.
pub fn build_verifier(
    did_resolver: Option<&affinidi_did_resolver_cache_sdk::DIDCacheClient>,
) -> Option<Arc<TransportBoundVerifier>> {
    did_hosting_common::server::trust_tasks::build_verifier(did_resolver)
}

/// Whether `role` authorises `type_uri`: a witness-admin task
/// ([`WITNESS_TASKS`]) requires [`Role::Admin`]; every other task (the shared
/// ACL family, and anything unsupported) requires only some ACL entry. Used
/// both for the cheap pre-check against a claimed issuer and the real check
/// against the proven one, so the two can never drift apart.
fn task_authorised(type_uri: &str, role: Option<Role>) -> bool {
    if WITNESS_TASKS.contains(&type_uri) {
        role == Some(Role::Admin)
    } else {
        role.is_some()
    }
}

/// Verify, authorise and answer one inbound Trust Task document. Returns the
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
        warn!(%type_uri, "trust task dropped: this witness has no configured DID");
        return None;
    };
    let Some(verifier) = state.trust_tasks_verifier.clone() else {
        warn!(%type_uri, "trust task dropped: no DID resolver configured to verify it");
        return None;
    };

    // Cheap pre-check, before any DID resolution: verifying a proof means
    // resolving its issuer's DID, an outbound fetch, while an ACL lookup is a
    // local store read. A claimed issuer this witness would refuse anyway —
    // absent from the ACL, or lacking the role a witness-admin task requires
    // — is refused right here, with no reply and no resolution attempted.
    // This is the same "no reply to unverified" refusal an invalid proof
    // gets, not a weaker one: only a claimed issuer the ACL would actually
    // authorise goes on to have its proof checked.
    let claimed_role = match doc.issuer.as_deref() {
        Some(issuer) => crate::acl::check_acl(&state.acl_ks, issuer).await.ok(),
        None => None,
    };
    if !task_authorised(&type_uri, claimed_role) {
        warn!(
            issuer = doc.issuer.as_deref().unwrap_or("unknown"),
            %type_uri,
            "trust task dropped: claimed issuer is not authorised; refusing before DID resolution"
        );
        return None;
    }

    let principal = match verify_sender_bound(&doc, None, sender, my_did, &verifier).await {
        Ok(p) => p,
        Err(e) => {
            warn!(
                sender = sender.unwrap_or("unknown"),
                %type_uri,
                error = %e,
                "trust task not answered: it does not verify"
            );
            return None;
        }
    };

    // Authorise before remembering: see the module docs. Re-checked here
    // (rather than trusting the pre-check above) because the pre-check ran
    // against the claimed, unverified issuer — this is the ACL's answer for
    // the *proven* one, which is what a reply may safely attribute the
    // refusal to.
    let reply_id = || format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let role = crate::acl::check_acl(&state.acl_ks, &principal).await.ok();
    let authorised = task_authorised(&type_uri, role);
    if !authorised {
        warn!(issuer = %principal, %type_uri, "trust task refused: the issuer is not authorised");
        let refusal = doc.reject_with(
            reply_id(),
            RejectReason::PermissionDenied {
                reason: format!("{principal} is not authorised on this witness"),
            },
        );
        return seal(state, my_did, &principal, error_value(refusal)).await;
    }

    match state.replay_cache.check(&principal, &doc.id) {
        Ok(()) => {}
        Err(ReplayError::Duplicate) => {
            warn!(issuer = %principal, doc_id = %doc.id, "trust task not answered: replay");
            return None;
        }
        Err(ReplayError::Full) => {
            let refusal =
                doc.reject_with(reply_id(), RejectReason::Unavailable { retry_after: None });
            return seal(state, my_did, &principal, error_value(refusal)).await;
        }
    }

    let reply = if WITNESS_TASKS.contains(&type_uri.as_str()) {
        let result = match type_uri.as_str() {
            t if t == key_create::Payload::TYPE_URI => key_create_task(state, &doc).await,
            t if t == key_list::Payload::TYPE_URI => key_list_task(state, &doc).await,
            t if t == key_delete::Payload::TYPE_URI => key_delete_task(state, &doc).await,
            _ => sign_task(state, &principal, &doc).await,
        };
        match result {
            Ok(payload) => doc.respond_with(reply_id(), payload),
            Err(e) => error_value(doc.reject_with(reply_id(), e)),
        }
    } else if ACL_TASKS.contains(&type_uri.as_str()) {
        let ctx = TrustTaskContext {
            acl_ks: &state.acl_ks,
            acl_locks: &state.acl_locks,
            my_vid: my_did,
        };
        // The proof was verified above, on the document as it arrived.
        let policy = ProofPolicy::<TransportBoundVerifier>::AcceptUnverified;
        let outcome = match via {
            Via::Tsp => {
                let t = TspTransportHandler::new(my_did.to_string(), principal.clone());
                dispatch_inbound(&ctx, &t, policy, doc).await
            }
            Via::Didcomm => {
                let t =
                    trust_tasks_didcomm::DidcommHandler::new(my_did.to_string(), principal.clone());
                dispatch_inbound(&ctx, &t, policy, doc).await
            }
            Via::Https => {
                let t = trust_tasks_https::HttpsHandler::new(
                    my_did.to_string(),
                    Some(principal.clone()),
                );
                dispatch_inbound(&ctx, &t, policy, doc).await
            }
        };
        match outcome {
            DispatchOutcome::Handled(reply) => reply,
            DispatchOutcome::Rejected(err) => error_value(err),
            DispatchOutcome::Suppressed => return None,
        }
    } else {
        error_value(doc.reject_with(
            reply_id(),
            RejectReason::UnsupportedType {
                type_uri: type_uri.clone(),
            },
        ))
    };
    seal(state, my_did, &principal, reply).await
}

/// An error document as the untyped reply shape the transports carry.
fn error_value(err: trust_tasks_rs::ErrorResponse) -> TrustTask<Value> {
    let value = serde_json::to_value(&err).expect("error document serialises");
    serde_json::from_value(value).expect("error document re-reads as a TrustTask")
}

/// Stamp a reply from this witness to `requester` and sign it. A reply the
/// witness cannot sign is not sent: the requester refuses unsigned answers.
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

/// Read a request payload into its generated type. The schemas are closed, so
/// a member they do not define is refused rather than ignored.
fn payload<P: serde::de::DeserializeOwned>(doc: &TrustTask<Value>) -> Result<P, ErrorPayload> {
    serde_json::from_value(doc.payload.clone()).map_err(|e| {
        RejectReason::MalformedRequest {
            reason: format!("the payload does not fit its schema: {e}"),
        }
        .into()
    })
}

/// A reply payload through its generated response type, so it leaves only in
/// the shape its schema allows.
fn reply<R: serde::Serialize + serde::de::DeserializeOwned>(
    body: Value,
) -> Result<Value, ErrorPayload> {
    let typed: R = serde_json::from_value(body).map_err(internal)?;
    serde_json::to_value(typed).map_err(internal)
}

fn invalid_log(reason: String) -> ErrorPayload {
    ErrorPayload::from(sign::error_codes::INVALID_LOG)
        .with_message("the log does not verify")
        .with_details(json!({ "reason": reason }))
}

fn internal(e: impl std::fmt::Display) -> ErrorPayload {
    RejectReason::InternalError {
        reason: e.to_string(),
    }
    .into()
}

fn rfc3339(secs: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A witness identity as `webvh/_shared/0.1/witness-key` describes it: no key
/// material.
fn witness_key(record: &WitnessRecord) -> Value {
    let mut key = json!({
        "witnessId": record.witness_id,
        "did": record.did,
        "createdAt": rfc3339(record.created_at),
        "proofsSigned": record.proofs_signed,
    });
    if let Some(label) = record.label.as_deref().filter(|l| !l.is_empty()) {
        key["label"] = json!(label);
    }
    key
}

/// `webvh/witness/key/create/0.1`.
async fn key_create_task(state: &AppState, doc: &TrustTask<Value>) -> Result<Value, ErrorPayload> {
    let p: key_create::Payload = payload(doc)?;
    let record = witness_ops::create_witness(&state.witnesses_ks, p.label.map(|l| l.to_string()))
        .await
        .map_err(internal)?;
    info!(audit = true, witness_id = %record.witness_id, did = %record.did, "witness identity created");
    reply::<key_create::Response>(json!({ "key": witness_key(&record) }))
}

/// `webvh/witness/key/list/0.1`.
async fn key_list_task(state: &AppState, doc: &TrustTask<Value>) -> Result<Value, ErrorPayload> {
    let _: key_list::Payload = payload(doc)?;
    let mut records = witness_ops::list_witnesses(&state.witnesses_ks)
        .await
        .map_err(internal)?;
    records.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.witness_id.cmp(&b.witness_id))
    });
    let keys: Vec<Value> = records.iter().map(witness_key).collect();
    reply::<key_list::Response>(json!({ "keys": keys }))
}

/// `webvh/witness/key/delete/0.1`.
async fn key_delete_task(state: &AppState, doc: &TrustTask<Value>) -> Result<Value, ErrorPayload> {
    let p: key_delete::Payload = payload(doc)?;
    let witness_id = p.witness_id.as_str();
    if witness_ops::get_witness(&state.witnesses_ks, witness_id)
        .await
        .map_err(internal)?
        .is_none()
    {
        return Err(ErrorPayload::from(key_delete::error_codes::NOT_FOUND)
            .with_message(format!("no witness identity {witness_id}")));
    }
    witness_ops::delete_witness(&state.witnesses_ks, witness_id)
        .await
        .map_err(internal)?;
    info!(audit = true, witness_id, "witness identity deleted");
    reply::<key_delete::Response>(json!({
        "witnessId": witness_id,
        "deletedAt": rfc3339(did_hosting_common::server::auth::session::now_epoch()),
    }))
}

/// `webvh/witness/sign/0.1`: the witness signs only an entry it has verified —
/// the log's chain up to the entry, that the entry is the last, that no
/// entry before it already deactivated the DID (the deactivating entry
/// itself is signed like any other), that the entry's witness parameter
/// names this witness identity, and that the log extends the furthest entry
/// this identity has already witnessed for the DID.
async fn sign_task(
    state: &AppState,
    requester: &str,
    doc: &TrustTask<Value>,
) -> Result<Value, ErrorPayload> {
    let p: sign::Payload = payload(doc)?;
    let witness_id = p.witness_id.as_str();
    let version_id = p.version_id.as_str();
    let Some(record) = witness_ops::get_witness(&state.witnesses_ks, witness_id)
        .await
        .map_err(internal)?
    else {
        return Err(ErrorPayload::from(sign::error_codes::NOT_FOUND)
            .with_message(format!("no witness identity {witness_id}")));
    };

    let witnessed = match verify_log_for_witnessing(&p.log_content, version_id, &record.did) {
        Ok(w) => w,
        Err(refusal) => {
            warn!(
                requester,
                witness_id,
                version_id,
                ?refusal,
                "witness sign refused"
            );
            return Err(match refusal {
                WitnessLogRefusal::InvalidLog(reason) => invalid_log(reason),
                WitnessLogRefusal::VersionNotLast { last } => {
                    ErrorPayload::from(sign::error_codes::VERSION_NOT_LAST).with_message(format!(
                        "{version_id} is not the last entry of the log ({last} is)"
                    ))
                }
                WitnessLogRefusal::Deactivated => {
                    ErrorPayload::from(sign::error_codes::DEACTIVATED).with_message(
                        "versionId is after the DID's deactivating entry; nothing is witnessed \
                         once a DID is deactivated",
                    )
                }
                WitnessLogRefusal::NotListed => ErrorPayload::from(sign::error_codes::NOT_LISTED)
                    .with_message(format!(
                        "the entry's witness parameter does not name {}",
                        record.did
                    )),
            });
        }
    };

    // The log must extend what this witness identity has already witnessed for
    // the DID: a witness proof on entry N vouches for every entry before it, so
    // witnessing a fork — or an older entry than one already witnessed — would
    // put this identity's name behind two histories of one DID. The check, the
    // signature and the record are one step under `sign_lock`.
    let _guard = state.sign_lock.lock().await;
    let version_number = witnessed.version_ids.len() as u64;
    let mark = witness_ops::get_witnessed_mark(&state.witnesses_ks, witness_id, &witnessed.scid)
        .await
        .map_err(internal)?;
    if let Some(mark) = mark.as_ref() {
        let extends = version_number >= mark.version_number
            && usize::try_from(mark.version_number)
                .ok()
                .and_then(|n| n.checked_sub(1))
                .and_then(|i| witnessed.version_ids.get(i))
                == Some(&mark.version_id);
        if !extends {
            warn!(
                requester,
                witness_id,
                version_id,
                witnessed = %mark.version_id,
                "witness sign refused: the log does not extend what this witness has witnessed"
            );
            return Err(invalid_log(format!(
                "the log does not extend {}, which this witness identity has already witnessed \
                 for this DID",
                mark.version_id
            )));
        }
    }

    let (version_id, proof) = witness_ops::sign_witness_proof(
        &state.witnesses_ks,
        state.signer.as_ref(),
        witness_id,
        version_id,
    )
    .await
    .map_err(internal)?;
    if mark
        .as_ref()
        .is_none_or(|m| version_number > m.version_number)
    {
        witness_ops::set_witnessed_mark(
            &state.witnesses_ks,
            witness_id,
            &witnessed.scid,
            &witness_ops::WitnessedMark {
                version_number,
                version_id: version_id.clone(),
            },
        )
        .await
        .map_err(internal)?;
    }
    drop(_guard);
    let did = did_hosting_common::did_ops::extract_did_id(&p.log_content).unwrap_or_default();
    info!(
        audit = true,
        requester,
        witness_id,
        did = %did,
        version_id = %version_id,
        "witness proof signed"
    );
    reply::<sign::Response>(json!({
        "witnessId": witness_id,
        "versionId": version_id,
        "proof": serde_json::to_value(&proof).map_err(internal)?,
    }))
}
