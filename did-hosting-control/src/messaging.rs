//! DIDComm messaging for the control plane.
//!
//! **Inbound:** Uses the `affinidi-messaging-didcomm-service` framework for
//! mediator connection, message dispatch, and response handling. Handles
//! the full VTA provisioning protocol (did/request, did/publish, etc.)
//! as well as sync acknowledgements from servers.
//!
//! **Outbound:** Sync push messages are sent via `server_push.rs` using the
//! shared `DIDCommService` — no separate ATM connection needed.

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommServiceError, Extension, HandlerContext, MESSAGE_PICKUP_STATUS_TYPE,
    MessagePolicy, MiddlewareResult, Next, Router, TRUST_PING_TYPE, handler_fn, ignore_handler,
    middleware_fn, trust_ping_handler,
};
use did_hosting_common::did_ops::did_key;
use did_hosting_common::didcomm_types::*;
use did_hosting_common::server::problem_report::log_problem_report;
use serde_json::{Value, json};
use tracing::{debug, info, warn};

use crate::acl::check_acl;
use crate::auth::AuthClaims;
use crate::did_ops;
use crate::error::AppError;
use crate::server::AppState;
use crate::server_push;

// ---------------------------------------------------------------------------
// Inbound router (framework-managed)
// ---------------------------------------------------------------------------

/// Build the DIDComm router for the control plane's inbound messages.
///
/// Handles the full VTA provisioning protocol (authenticate, did/request,
/// did/publish, etc.) as well as sync acknowledgements from servers.
pub fn build_control_router(state: AppState) -> Result<Router, DIDCommServiceError> {
    Ok(Router::new()
        .extension(state)
        // Standard DIDComm
        .route(TRUST_PING_TYPE, handler_fn(trust_ping_handler))?
        .route(MESSAGE_PICKUP_STATUS_TYPE, handler_fn(ignore_handler))?
        // Every DID-management, auth and infrastructure operation arrives as a
        // signed Trust Task document in the trust-task envelope below; the
        // bare-message routes that used to sit here authorised on the
        // transport's report of the sender alone and have been removed. A peer
        // still sending one gets `handle_fallback`'s problem report naming the
        // type, not a silent timeout.
        // Wallet consent decision (RP→wallet task-consent protocol).
        // The matching outbound `task-consent/request/0.1` is sent by
        // the REST endpoint `POST /api/task-consent/request`.
        .route(
            did_hosting_common::did_hosting_tasks::TASK_CONSENT_DECISION_0_1.as_str(),
            handler_fn(handle_consent_decision),
        )?
        // Trust Tasks envelope (v0.7.0+) — routes the five `acl/*`
        // ops and `trust-task-discovery` through the same handlers
        // the HTTPS transport hits at `POST /api/trust-tasks`.
        .route(
            trust_tasks_didcomm::ENVELOPE_TYPE,
            handler_fn(handle_trust_tasks_envelope),
        )?
        .fallback(handler_fn(handle_fallback))
        .layer(
            MessagePolicy::new()
                .require_encrypted(true)
                .require_sender_did(true),
        )
        .layer(middleware_fn(filtered_request_logging)))
}

/// Request logging middleware that silences noisy health/stats messages.
async fn filtered_request_logging(
    ctx: HandlerContext,
    message: Message,
    meta: affinidi_messaging_didcomm::UnpackMetadata,
    next: Next,
) -> MiddlewareResult {
    const QUIET: &[&str] = &[
        MSG_HEALTH_PING,
        MSG_HEALTH_PONG,
        MSG_STATS_SYNC,
        MSG_STATS_ACK,
        MESSAGE_PICKUP_STATUS_TYPE,
    ];

    let msg_type = message.typ.clone();
    let result = next.run(ctx, message, meta).await;

    if !QUIET.iter().any(|t| msg_type == *t) {
        let status = match &result {
            Ok(Some(_)) => "ok(response)",
            Ok(None) => "ok(empty)",
            Err(_) => "error",
        };
        info!(message_type = %msg_type, status, "DIDComm request processed");
    }

    result
}

// ---------------------------------------------------------------------------
// VTA provisioning handlers
// ---------------------------------------------------------------------------

/// Extract `(challenge, payloadDigest, approved)` from a
/// `task-consent/decision/0.1` payload, or `None` when a required member
/// is absent or `decision` is not one of the spec's two values.
///
/// A device **MUST NOT** synthesise an approval, and neither may we:
/// anything that is not literally `approve` is *not* an approval, and
/// anything that is not literally `deny` is not a signed refusal either
/// — an unknown third value is a decision this executor cannot read, so
/// it resolves nothing and the parked request times out.
fn parse_decision_payload(payload: &Value) -> Option<(&str, &str, bool)> {
    let challenge = payload.get("challenge").and_then(Value::as_str)?;
    let digest = payload.get("payloadDigest").and_then(Value::as_str)?;
    let approved = match payload.get("decision").and_then(Value::as_str)? {
        "approve" => true,
        "deny" => false,
        _ => return None,
    };
    Some((challenge, digest, approved))
}

/// Inbound `task-consent/decision/0.1` from a wallet.
///
/// The decision's Data Integrity proof — not the transport session — is
/// the authorization (per the task-consent spec), so it is **required**
/// and verified before anything else. The decision is only honoured when
/// the proof's `verificationMethod` DID, the in-band `issuer` (required) and
/// the transport's reported sender all name the holder the request was
/// addressed to; the reported sender alone establishes nothing. We correlate by `challenge`, require
/// the echoed `payloadDigest` to match the one we sent (the binding
/// between what the human approved and what the parked admin call
/// proceeds with), and resolve the parked REST request with the user's
/// decision. A `#response` acknowledgement is returned per the spec.
async fn handle_consent_decision(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = require_sender(&ctx)?;
    match run_consent_decision(&state, sender, &message).await? {
        Some((response_type, response_body)) => Ok(Some(
            DIDCommResponse::new(response_type, response_body).thid(message.id.clone()),
        )),
        None => Ok(None),
    }
}

/// Compute the wire-level `(response_type, response_body)` for an inbound
/// `task-consent/decision/0.1`, or `None` when the decision must be
/// ignored (every refusal deliberately resolves nothing — see the stage
/// comments below). Extracted from [`handle_consent_decision`] so the
/// full signed round trip is testable without an `ATM`-backed
/// [`HandlerContext`] — the same pattern as `run_authenticate` /
/// `run_trust_tasks_envelope`.
async fn run_consent_decision(
    state: &AppState,
    sender: &str,
    message: &Message,
) -> Result<Option<(String, Value)>, DIDCommServiceError> {
    use did_hosting_common::did_hosting_tasks::{
        TASK_CONSENT_DECISION_0_1, TASK_CONSENT_DECISION_RESPONSE_0_1,
    };
    use trust_tasks_rs::ProofVerifier;

    // ── 1. The body must be a Trust Task document of the decision type.
    let doc: trust_tasks_rs::TrustTask<Value> = match serde_json::from_value(message.body.clone()) {
        Ok(d) => d,
        Err(e) => {
            warn!(
                sender = sender,
                error = %e,
                "task-consent decision is not a Trust Task document — ignoring"
            );
            return Ok(None);
        }
    };
    if doc.type_uri.to_string() != TASK_CONSENT_DECISION_0_1.as_str() {
        warn!(
            sender = sender,
            doc_type = %doc.type_uri,
            "task-consent decision body type does not match the message type — ignoring"
        );
        return Ok(None);
    }

    // ── 2. The proof is mandatory: it — not the authcrypt session that
    //       carried the message — is the authorization.
    let Some(proof) = doc.proof.as_ref() else {
        warn!(
            sender = sender,
            "task-consent decision carries no proof — ignoring"
        );
        return Ok(None);
    };
    // The proven signer must be the reported sender (and so, below, the
    // addressed holder). `TransportBoundVerifier` additionally requires an
    // in-band `issuer` and enforces `verificationMethod` DID == `issuer`.
    let proof_did = proof
        .verification_method
        .split_once('#')
        .map(|(d, _)| d)
        .unwrap_or(proof.verification_method.as_str());
    if proof_did != sender {
        warn!(
            sender = sender,
            proof_did = %proof_did,
            "task-consent decision proof verificationMethod DID does not match the sender — ignoring"
        );
        return Ok(None);
    }
    if doc.issuer.as_deref() != Some(sender) {
        warn!(
            sender = sender,
            issuer = ?doc.issuer,
            "task-consent decision issuer is absent or does not match the sender — ignoring"
        );
        return Ok(None);
    }
    // Audience binding: a decision signed for another executor must not
    // resolve a pending consent here.
    if let (Some(recipient), Some(control_did)) =
        (doc.recipient.as_deref(), state.config.server_did.as_deref())
        && recipient != control_did
    {
        warn!(
            sender = sender,
            recipient = %recipient,
            "task-consent decision recipient is not this control plane — ignoring"
        );
        return Ok(None);
    }
    let Some(verifier) = state.trust_tasks_verifier.as_deref() else {
        warn!("trust-tasks proof verifier not configured — cannot accept consent decisions");
        return Ok(None);
    };
    if let Err(e) = verifier.verify(&doc).await {
        warn!(
            sender = sender,
            error = %e,
            "task-consent decision proof failed verification — ignoring"
        );
        return Ok(None);
    }

    // ── 3. Typed payload fields, validated BEFORE the pending entry is
    //       consumed so a malformed decision cannot destroy it.
    let Some((challenge, digest, approved)) = parse_decision_payload(&doc.payload) else {
        warn!(
            sender = sender,
            "task-consent decision missing challenge/payloadDigest or \
             carrying an unknown decision — ignoring"
        );
        return Ok(None);
    };

    // ── 4. Match the pending entry and remove it under ONE lock, so two
    //       decisions for the same challenge can't both fire the sender —
    //       and so a decision that fails the holder/digest checks leaves
    //       the legitimate pending entry in place rather than consuming
    //       it. The proven sender must equal the holder DID the request
    //       was addressed to, and the echoed digest must be the one we
    //       sent (the binding between what the human approved and what
    //       the parked admin call proceeds with).
    let pending = {
        let mut map = state.pending_confirms.lock().await;
        match map.get(challenge) {
            None => {
                // Stale, duplicate, lapsed, or already-resolved challenge.
                warn!(
                    sender = sender,
                    "task-consent decision for unknown challenge — ignoring"
                );
                return Ok(None);
            }
            Some(p) if p.holder_did != sender => {
                warn!(
                    sender = sender,
                    expected = %p.holder_did,
                    "task-consent decision sender does not match addressed holder DID — rejecting"
                );
                return Ok(None);
            }
            Some(p) if p.expected_digest != digest => {
                warn!(
                    sender = sender,
                    "task-consent decision payloadDigest does not match the pending request \
                     — rejecting"
                );
                return Ok(None);
            }
            Some(_) => map
                .remove(challenge)
                .expect("checked present under the same lock"),
        }
    };

    info!(sender = sender, approved, "task-consent decision received");
    // Receiver may have already timed out and dropped — ignore the error.
    let _ = pending.tx.send(approved);

    // Spec `#response` acknowledgement: minApprovals is 1, so an approve
    // is immediately `granted` and a deny is `denied`.
    let ack = json!({
        "status": if approved { "granted" } else { "denied" },
        "payloadDigest": digest,
        "approvals": if approved { 1 } else { 0 },
    });
    Ok(Some((
        TASK_CONSENT_DECISION_RESPONSE_0_1.as_str().to_string(),
        ack,
    )))
}

// ---------------------------------------------------------------------------
// DID operation dispatch
// ---------------------------------------------------------------------------

/// Project a stored [`DidRecord`] into the canonical `DidRecord` wire
/// shape used by the `did-management/did/*` Trust Task family
/// (camelCase keys, RFC3339 timestamps).
///
/// `did_url` is the resolvable location of the DID log document; it is
/// stable from the initial reservation (`versionCount: 0`) and lets the
/// owner know where to publish and where resolvers will fetch. `didId`
/// is only meaningful once a log entry exists, so it is emitted solely
/// when `versionCount > 0`.
pub(crate) fn spec_did_record_json(
    record: &did_hosting_common::did_ops::DidRecord,
    did_url: &str,
) -> Value {
    let rfc3339 = |secs: u64| {
        chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
            .unwrap_or_default()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    };
    let mut rec = serde_json::Map::new();
    rec.insert("mnemonic".into(), json!(record.mnemonic));
    rec.insert("owner".into(), json!(record.owner));
    rec.insert("createdAt".into(), json!(rfc3339(record.created_at)));
    rec.insert("updatedAt".into(), json!(rfc3339(record.updated_at)));
    rec.insert("versionCount".into(), json!(record.version_count));
    rec.insert("method".into(), json!(record.method));
    rec.insert("disabled".into(), json!(record.disabled));
    rec.insert("didUrl".into(), json!(did_url));
    if !record.domain.is_empty() {
        rec.insert("domain".into(), json!(record.domain));
    }
    if let Some(did_id) = record.did_id.as_ref().filter(|_| record.version_count > 0) {
        rec.insert("didId".into(), json!(did_id));
    }
    // The agent-name registry, so the four `agent-name/*` verbs are
    // self-describing: without it a client has to follow every `set` or
    // `disable` with an authenticated `GET /api/dids/{mnemonic}` just to learn
    // what its own call did. A *parked* name is invisible in the DID document
    // by design, so the response is the only place the caller can see it.
    //
    // Emitted only when non-empty, matching `domain`/`didId` above: a DID with
    // no names produces a byte-identical response to before, which keeps this
    // additive for the `did-management/did/*` family that shares this shape.
    if !record.agent_names.is_empty() {
        rec.insert("agentNames".into(), json!(record.agent_names));
    }
    Value::Object(rec)
}

/// Transport-agnostic dispatch table for the DID-management `MSG_*` Type URIs.
///
/// Reached only through [`bridge_did_management`], after
/// [`dispatch_trust_task_doc`] has verified the document's proof and ACL'd its
/// signer into `auth`. It reads only `msg.typ` and `msg.body`, so it has no view
/// of — and places no trust in — any transport.
pub async fn dispatch_did_op(
    auth: &AuthClaims,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), AppError> {
    // Phase 3 end-state: did-hosting accepts canonical Trust-Task
    // spec URIs only. The MSG_* constants in `didcomm_types` hold the
    // canonical spec URI values, so the dispatcher matches `msg.typ`
    // directly without the historical `to_legacy` translation step.
    // Unrecognised types fall through to the default arm (which emits
    // a protocol error code).
    match msg.typ.as_str() {
        MSG_DID_REQUEST => {
            // `did-management/did/check-name/0.1`. Two modes share this
            // task (see the spec): an availability *probe* (`reserve`
            // false/absent) that never mutates state, and a *reserve*
            // (`reserve: true`) that atomically claims a slot. Reserve
            // additionally supports *auto-assign*: when `path` is
            // omitted the host generates a fresh server-side mnemonic.
            let path = msg.body.get("path").and_then(|v| v.as_str());
            let reserve = msg
                .body
                .get("reserve")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let force = msg
                .body
                .get("force")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            // Probe mode is read-only and MUST name a path — a path-less
            // request is only meaningful as an auto-assign reservation.
            if !reserve {
                let path = path.ok_or_else(|| {
                    AppError::Validation(
                        "check-name without `reserve: true` requires a `path` to probe".into(),
                    )
                })?;
                let probe = did_ops::check_name(state, path).await?;
                return Ok((
                    MSG_DID_OFFER.to_string(),
                    json!({ "available": probe.available, "reserved": false }),
                ));
            }

            // T34 domain resolution mirrors the REST `request_uri` handler.
            // Same chain: explicit on the wire → caller's ACL default →
            // system default. When resolution fails (no domains
            // configured / no default / `Allowed([])` caller with no
            // explicit), we proceed with `None`; publish-time backfill
            // from `did_id` host will tag the record. This keeps the
            // legacy behaviour of un-domained installs and pre-T18
            // tests, while still surfacing the domain on the new record
            // for the common case where a default exists.
            let request_domain = msg.body.get("domain").and_then(|v| v.as_str());
            let acl_scope =
                match did_hosting_common::server::acl::get_acl_entry(&state.acl_ks, &auth.did)
                    .await?
                {
                    Some(e) => e.domains,
                    None => did_hosting_common::server::domain::DomainScope::All,
                };
            let system_default =
                did_hosting_common::server::domain::get_default_domain(&state.store)
                    .await
                    .ok()
                    .flatten();
            let resolved_domain = did_hosting_common::server::domain::resolve_request_domain(
                request_domain,
                &acl_scope,
                system_default.as_deref(),
            )
            .ok();

            // Reserve. `path == None` → auto-assign. An explicitly-named
            // path that is already taken (without `force`) is not an
            // error here: the spec says return `available: false,
            // reserved: false` and DO NOT mutate. `create_did` signals
            // that case with `Conflict`, which we translate rather than
            // surface as a problem report.
            // No fan-out on force-replace: see `routes/did_manage::request_uri`.
            match did_ops::create_did(auth, state, path, force, resolved_domain.as_deref()).await {
                Ok(result) => {
                    // Read the committed record back for the canonical
                    // response fields (timestamps, owner, version).
                    let record: did_hosting_common::did_ops::DidRecord = state
                        .dids_ks
                        .get(did_key(&result.mnemonic))
                        .await?
                        .ok_or_else(|| {
                            AppError::Internal("record missing after reservation".into())
                        })?;
                    Ok((
                        MSG_DID_OFFER.to_string(),
                        json!({
                            "available": true,
                            "reserved": true,
                            "record": spec_did_record_json(&record, &result.did_url),
                        }),
                    ))
                }
                Err(AppError::Conflict(_)) => Ok((
                    MSG_DID_OFFER.to_string(),
                    json!({ "available": false, "reserved": false }),
                )),
                Err(e) => Err(e),
            }
        }
        MSG_DID_REGISTER => {
            // Atomic claim-and-publish — see did_ops::register_did_atomic.
            // Body shape mirrors `DidRegisterRequest` from did-hosting-common,
            // including T26's `did_data` + `method` extension.
            let req: did_hosting_common::DidRegisterRequest =
                serde_json::from_value(msg.body.clone())
                    .map_err(|e| AppError::Validation(format!("invalid DidRegister body: {e}")))?;
            if req.path.is_empty() {
                return Err(AppError::Validation("missing 'path' in body".into()));
            }
            let (method, payload) = req.resolve().map_err(AppError::Validation)?;
            if method != "webvh" {
                return Err(AppError::Validation(format!(
                    "DIDComm register is currently webvh-only; received method = '{method}'.",
                )));
            }
            let did_log = std::str::from_utf8(&payload).map_err(|e| {
                AppError::Validation(format!("webvh did_data is not valid UTF-8: {e}"))
            })?;

            let result =
                did_ops::register_did_atomic(auth, state, &req.path, did_log, req.force, None)
                    .await?;
            server_push::notify_servers_did(state, result.mnemonic.clone());

            let server_did = state.config.server_did.as_deref().unwrap_or_default();
            Ok((
                MSG_DID_REGISTER_CONFIRM.to_string(),
                json!({
                    "mnemonic": result.mnemonic,
                    "did_url": result.did_url,
                    "server_did": server_did,
                }),
            ))
        }
        MSG_WITNESS_PUBLISH => {
            let mnemonic = msg
                .body
                .get("mnemonic")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::Validation("missing 'mnemonic' in body".into()))?;
            let witness = msg
                .body
                .get("witness")
                .ok_or_else(|| AppError::Validation("missing 'witness' in body".into()))?;
            let witness_str = serde_json::to_string(witness)?;
            if witness_str.is_empty() || witness_str == "null" {
                return Err(AppError::Validation(
                    "witness content cannot be empty".into(),
                ));
            }

            did_ops::upload_witness(auth, state, mnemonic, &witness_str).await?;

            let base_url = state
                .config
                .did_hosting_url
                .as_deref()
                .or(state.config.public_url.as_deref())
                .unwrap_or("http://localhost");
            let witness_url = format!("{base_url}/{mnemonic}/did-witness.json");

            server_push::notify_servers_did(state, mnemonic.to_string());
            Ok((
                MSG_WITNESS_CONFIRM.to_string(),
                json!({
                    "mnemonic": mnemonic,
                    "witness_url": witness_url,
                }),
            ))
        }
        MSG_INFO_REQUEST => {
            let mnemonic = msg
                .body
                .get("mnemonic")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::Validation("missing 'mnemonic' in body".into()))?;
            let (record, log_metadata) = did_ops::get_did_info(auth, state, mnemonic).await?;

            // Get stats for this DID
            let stats_key = format!("stats:{mnemonic}");
            let did_stats: did_hosting_common::DidStats =
                state.stats_ks.get(stats_key).await?.unwrap_or_default();

            let log_metadata_json = log_metadata
                .map(|m| serde_json::to_value(m).unwrap_or(Value::Null))
                .unwrap_or(Value::Null);

            let base_url = state
                .config
                .did_hosting_url
                .as_deref()
                .or(state.config.public_url.as_deref())
                .unwrap_or("http://localhost");
            let did_url = format!("{base_url}/{mnemonic}/did.jsonl");
            Ok((
                MSG_INFO.to_string(),
                json!({
                    "mnemonic": record.mnemonic,
                    "did_id": record.did_id,
                    "did_url": did_url,
                    "owner": record.owner,
                    "created_at": record.created_at,
                    "updated_at": record.updated_at,
                    "version_count": record.version_count,
                    "content_size": record.content_size,
                    "stats": {
                        "total_resolves": did_stats.total_resolves,
                        "total_updates": did_stats.total_updates,
                        "last_resolved_at": did_stats.last_resolved_at,
                        "last_updated_at": did_stats.last_updated_at,
                    },
                    "log_metadata": log_metadata_json,
                }),
            ))
        }
        MSG_LIST_REQUEST => {
            let requested_owner = msg.body.get("owner").and_then(|v| v.as_str());
            let entries = did_ops::list_dids(auth, state, requested_owner, None, None).await?;
            let entries_json: Vec<Value> = entries
                .into_iter()
                .map(|e| {
                    json!({
                        "mnemonic": e.mnemonic,
                        "did_id": e.did_id,
                        "created_at": e.created_at,
                        "updated_at": e.updated_at,
                        "version_count": e.version_count,
                        "total_resolves": e.total_resolves,
                    })
                })
                .collect();
            Ok((MSG_LIST.to_string(), json!({ "dids": entries_json })))
        }
        MSG_DELETE => {
            let mnemonic = msg
                .body
                .get("mnemonic")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::Validation("missing 'mnemonic' in body".into()))?;
            let did_id = did_ops::delete_did(auth, state, mnemonic, None).await?;

            server_push::notify_servers_delete(state, mnemonic.to_string());
            Ok((
                MSG_DELETE_CONFIRM.to_string(),
                json!({
                    "mnemonic": mnemonic,
                    "did_id": did_id,
                }),
            ))
        }
        MSG_DID_CHANGE_OWNER => {
            let mnemonic = msg
                .body
                .get("mnemonic")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::Validation("missing 'mnemonic' in body".into()))?;
            // Canonical wire field is `newOwner` (camelCase, per
            // did-management/did/change-owner/0.1); `new_owner` is the
            // legacy snake_case alias.
            let new_owner = msg
                .body
                .get("newOwner")
                .or_else(|| msg.body.get("new_owner"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::Validation("missing 'newOwner' in body".into()))?;
            let record = did_ops::change_did_owner(auth, state, mnemonic, new_owner).await?;
            Ok((
                MSG_DID_CHANGE_OWNER_CONFIRM.to_string(),
                json!({
                    "mnemonic": record.mnemonic,
                    "owner": record.owner,
                    "updated_at": record.updated_at,
                }),
            ))
        }
        MSG_ME_DOMAINS => {
            // Net-new DIDComm route: caller-scoped view of hosting
            // domains. Shares its compute with the REST handler
            // `GET /api/me/domains` via `fetch_me_domains_for_caller`
            // so both transports return byte-identical payloads.
            let resp = crate::routes::domain::fetch_me_domains_for_caller(auth, state).await?;
            Ok((
                did_hosting_common::did_hosting_tasks::TASK_ME_DOMAINS_RESPONSE_0_1
                    .as_str()
                    .to_string(),
                serde_json::to_value(resp)?,
            ))
        }
        MSG_AGENT_NAME_UPDATE | MSG_AGENT_NAME_REMOVE => {
            // The two mutating verbs share one `{record}` response. `update`
            // carries the declarative `state: active | parked` field
            // (did-management/agent-name/update/0.1); `remove` stays a
            // separate destructive task (agent-name/remove/0.1). Both carry
            // the caller's new signed `did.jsonl` (`didData`), whose
            // `alsoKnownAs` direction the `did_ops` engine verifies against
            // the requested state.
            let (response_type, record) = if msg.typ.as_str() == MSG_AGENT_NAME_REMOVE {
                let req: crate::routes::did_manage::AgentNameRequest =
                    serde_json::from_value(msg.body.clone()).map_err(|e| {
                        AppError::Validation(format!("invalid agent-name request body: {e}"))
                    })?;
                let record = did_ops::remove_agent_name(
                    auth,
                    state,
                    &req.mnemonic,
                    &req.name,
                    &req.did_log,
                    req.domain.as_deref(),
                )
                .await?;
                server_push::notify_servers_did(state, req.mnemonic.clone());
                info!(
                    did = %auth.did,
                    mnemonic = %req.mnemonic,
                    name = %req.name,
                    msg_type = %msg.typ,
                    "agent name removed via DIDComm"
                );
                (MSG_AGENT_NAME_REMOVE_RESPONSE, record)
            } else {
                let req: crate::routes::did_manage::AgentNameUpdateRequest =
                    serde_json::from_value(msg.body.clone()).map_err(|e| {
                        AppError::Validation(format!("invalid agent-name update body: {e}"))
                    })?;
                let record = did_ops::update_agent_name(
                    auth,
                    state,
                    &req.mnemonic,
                    &req.name,
                    &req.did_data,
                    req.domain.as_deref(),
                    req.state,
                )
                .await?;
                // Every update publishes a new DID version, so hosting
                // servers need the fan-out the REST handler sends — without
                // it a name bound over DIDComm would not resolve until the
                // next full resync.
                server_push::notify_servers_did(state, req.mnemonic.clone());
                info!(
                    did = %auth.did,
                    mnemonic = %req.mnemonic,
                    name = %req.name,
                    state = ?req.state,
                    "agent name updated via DIDComm"
                );
                (MSG_AGENT_NAME_UPDATE_RESPONSE, record)
            };

            Ok((
                response_type.to_string(),
                crate::routes::did_manage::agent_name_record_response(state, &record),
            ))
        }
        MSG_AGENT_NAME_LIST => {
            // Read-only. The registry — not the DID document — is the only
            // place a *parked* name is visible, so this is what a client needs
            // to offer "resume" for a name it disabled earlier.
            let mnemonic = msg
                .body
                .get("mnemonic")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::Validation("missing 'mnemonic' in body".into()))?;
            let request_domain = msg.body.get("domain").and_then(|v| v.as_str());
            let (domain, names) =
                did_ops::list_agent_names(auth, state, mnemonic, request_domain).await?;

            let mut body = serde_json::Map::new();
            body.insert("mnemonic".into(), json!(mnemonic));
            // Omitted rather than empty-stringed for an un-domained legacy
            // slot, matching how `spec_did_record_json` treats `domain`.
            if !domain.is_empty() {
                body.insert("domain".into(), json!(domain));
            }
            // Always present, unlike the record projection's conditional
            // `agentNames`: this verb's whole answer is the list, and a client
            // shouldn't have to distinguish "no names" from "field missing".
            //
            // Projected per did-management/agent-name/list/0.1: `createdAt`
            // is an RFC3339 timestamp on the wire (the store keeps epoch
            // seconds), matching how `spec_did_record_json` projects the
            // record's own audit fields.
            let rfc3339 = |secs: u64| {
                chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
                    .unwrap_or_default()
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            };
            let entries: Vec<Value> = names
                .iter()
                .map(|e| {
                    json!({
                        "name": e.name,
                        "enabled": e.enabled,
                        "createdAt": rfc3339(e.created_at),
                    })
                })
                .collect();
            body.insert("agentNames".into(), json!(entries));
            Ok((
                MSG_AGENT_NAME_LIST_RESPONSE.to_string(),
                Value::Object(body),
            ))
        }
        MSG_AGENT_NAME_CHECK => {
            // Read-only probe. Domain scoping is resolved by the same helper
            // the REST handler uses (explicit → caller's ACL default → system
            // default), because "is @alice free?" has no answer until the
            // domain is pinned down.
            let req: crate::routes::did_manage::AgentNameCheckRequest =
                serde_json::from_value(msg.body.clone()).map_err(|e| {
                    AppError::Validation(format!("invalid agent-name check body: {e}"))
                })?;
            let domain = crate::routes::did_manage::resolve_agent_name_domain(
                auth,
                state,
                req.domain.as_deref(),
            )
            .await?;
            let result = did_ops::check_agent_name(state, &domain, &req.name).await?;
            Ok((
                MSG_AGENT_NAME_CHECK_RESPONSE.to_string(),
                serde_json::to_value(result)?,
            ))
        }
        other => Err(AppError::Validation(format!(
            "unknown message type: {other}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Stats sync (server → control plane)
// ---------------------------------------------------------------------------

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
    use crate::routes::stats_sync;

    // Require Service role — matches REST `/api/control/stats` which is gated
    // on ServiceAuth. An Owner-role DID must not be able to write per-DID
    // stats deltas: doing so would let any tenant tamper with another
    // server's resolved/update counters.
    if !matches!(
        check_acl(&state.acl_ks, signer).await,
        Ok(crate::acl::Role::Service)
    ) {
        warn!(did = signer, "stats sync rejected: Service role required");
        return Err(InfraRejection::new(
            "e.p.stats.unauthorized",
            "service role required",
        ));
    }

    // Bind the payload to the transport-proven signer, as the REST handler
    // binds it to the JWT. `server_did` keys the replay window, so accepting a
    // foreign one would let one server advance — and so suppress — another's.
    let server_did = body
        .get("server_did")
        .and_then(|v| v.as_str())
        .unwrap_or(signer);
    if server_did != signer {
        warn!(
            did = signer,
            server_did, "stats sync rejected: server_did does not match signer"
        );
        return Err(InfraRejection::new(
            "e.p.stats.sender_mismatch",
            "server_did does not match signer",
        ));
    }

    let seq = body.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);

    // Idempotency check (reuse REST handler's static map)
    if !stats_sync::accept_seq(server_did, seq) {
        debug!(server_did, seq, "stats sync: stale sequence");
        return Ok(json!({ "status": "skipped", "reason": "stale_seq" }));
    }

    let deltas = body
        .get("did_deltas")
        .and_then(|v| v.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default();
    for d in deltas {
        let mnemonic = d.get("mnemonic").and_then(|v| v.as_str()).unwrap_or("");
        if mnemonic.is_empty() {
            continue;
        }
        let resolve_delta = d.get("resolve_delta").and_then(|v| v.as_u64()).unwrap_or(0);
        let update_delta = d.get("update_delta").and_then(|v| v.as_u64()).unwrap_or(0);
        let last_resolved_at = d.get("last_resolved_at").and_then(|v| v.as_u64());
        let last_updated_at = d.get("last_updated_at").and_then(|v| v.as_u64());

        state.stats_collector.record_deltas(
            mnemonic,
            resolve_delta,
            update_delta,
            last_resolved_at,
            last_updated_at,
        );
    }

    debug!(
        server_did,
        seq,
        delta_count = deltas.len(),
        "stats sync accepted"
    );

    Ok(json!({ "status": "accepted" }))
}

// ---------------------------------------------------------------------------
// Health pong handler (server → control plane)
// ---------------------------------------------------------------------------

/// Transport-agnostic core of health-pong handling, for the
/// `.../server/health/0.1#response` trust task over DIDComm or TSP.
///
/// `signer` is the pong's proven issuer. Only a Service-role DID may mark an
/// instance Active: the registry's liveness view decides which servers the
/// dashboard reports healthy, so it must not be writable by any DID that can
/// reach the mediator.
///
/// A pong is terminal: it never produces a reply.
pub(crate) async fn do_health_pong(state: &AppState, signer: &str, body: &Value) {
    use crate::registry::{self, ServiceStatus};

    if !matches!(
        check_acl(&state.acl_ks, signer).await,
        Ok(crate::acl::Role::Service)
    ) {
        warn!(did = signer, "health pong ignored: Service role required");
        return;
    }

    let status = body
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let version = body
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    debug!(signer, status, version, "health pong received from server");

    // Find the instance by signer DID and mark it active
    let instance_id = signer.replace(':', "_");
    let now = crate::auth::session::now_epoch();
    if let Err(e) = registry::update_instance_status(
        &state.registry_ks,
        &instance_id,
        ServiceStatus::Active,
        now,
    )
    .await
    {
        warn!(instance_id, error = %e, "failed to update instance status from health pong");
    }
}

// ---------------------------------------------------------------------------
// Sync / domain acknowledgements (server → control plane)
// ---------------------------------------------------------------------------

/// A server acknowledged a `sync/*` push. Informational: logged, nothing else.
pub(crate) fn do_sync_ack(signer: &str, type_uri: &str, body: &Value) {
    let status = body
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let mnemonic = body
        .get("mnemonic")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    info!(
        signer,
        mnemonic, status, type_uri, "DID sync: server acknowledged"
    );
}

/// A server acknowledged a `domain/{assign,unassign,purge}` push.
///
/// Mirrors the server's view of `served_domains` into the registry so the UI
/// reflects the change without waiting for the next registration:
/// `assigned` / `already_assigned` on an assign ack adds the domain, anything
/// else removes it. `signer` is the ack's proven issuer and must hold the
/// Service role — otherwise any DID could rewrite a server's `served_domains`
/// (dropping a domain hides it from the next purge fan-out).
pub(crate) async fn do_domain_ack(state: &AppState, signer: &str, type_uri: &str, body: &Value) {
    let status = body
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let Some(domain) = body.get("domain").and_then(|v| v.as_str()) else {
        return;
    };
    let op = match type_uri {
        MSG_DOMAIN_ASSIGN_ACK => "assign",
        MSG_DOMAIN_UNASSIGN_ACK => "unassign",
        _ => "purge",
    };
    info!(
        signer,
        domain, status, op, "server acknowledged domain {op}"
    );

    match check_acl(&state.acl_ks, signer).await {
        Ok(crate::acl::Role::Service) => {}
        Ok(other) => {
            warn!(did = signer, role = %other, domain, op, "domain ack rejected: Service role required");
            return;
        }
        Err(_) => {
            warn!(
                did = signer,
                domain, op, "domain ack rejected: DID not in ACL"
            );
            return;
        }
    }
    let instance_id = signer.replace(':', "_");
    match crate::registry::get_instance(&state.registry_ks, &instance_id).await {
        Ok(Some(mut instance)) => {
            let add = op == "assign" && matches!(status, "assigned" | "already_assigned");
            let mutated = if add {
                if !instance.served_domains.iter().any(|d| d == domain) {
                    instance.served_domains.push(domain.to_string());
                    instance.served_domains.sort();
                    true
                } else {
                    false
                }
            } else {
                let before = instance.served_domains.len();
                instance.served_domains.retain(|d| d != domain);
                instance.served_domains.len() != before
            };
            if mutated
                && let Err(e) =
                    crate::registry::register_instance(&state.registry_ks, &instance).await
            {
                warn!(instance_id, error = %e, "failed to update served_domains after domain ack");
            }
        }
        Ok(None) => {
            // Ack arrived before registration, or the registry was wiped; the
            // next register cycle reconciles.
            warn!(
                instance_id,
                "domain ack received for unregistered server — skipping registry update"
            );
        }
        Err(e) => {
            warn!(instance_id, error = %e, "failed to load instance for ack reconciliation");
        }
    }
}

// ---------------------------------------------------------------------------
// Server registration handler
// ---------------------------------------------------------------------------

/// A rejection an infrastructure core (registration, stats sync) can report;
/// the trust-task route turns it into a framework `ErrorResponse`.
pub(crate) struct InfraRejection {
    pub code: &'static str,
    pub comment: String,
}

impl InfraRejection {
    fn new(code: &'static str, comment: impl Into<String>) -> Self {
        Self {
            code,
            comment: comment.into(),
        }
    }
}

/// Transport-agnostic core of server registration, for the
/// `.../server/register/0.1` trust task arriving over DIDComm **or** TSP.
///
/// `signer` is the registration document's proven issuer — the DID whose key
/// signed it — so a server is registered, and synced every tenant's DIDs, only
/// on its own signature. Returns the ack body on success.
pub(crate) async fn do_server_register(
    state: &AppState,
    signer: &str,
    body: &Value,
) -> Result<Value, InfraRejection> {
    use crate::acl::check_acl;
    use crate::registry::{self, ServiceInstance, ServiceStatus, ServiceType};

    // Require pre-approved ACL entry with the Service role — matches REST
    // `/api/control/register-service` which is gated on ServiceAuth. An
    // Owner-role DID must not be able to register as a server: registration
    // triggers `sync_all_dids_to_server`, which would push every tenant's
    // DID log + witness content to the caller's inbox and add them to the
    // active-server registry so future `notify_servers_did` updates also
    // reach them.
    let role = match check_acl(&state.acl_ks, signer).await {
        Ok(crate::acl::Role::Service) => crate::acl::Role::Service,
        Ok(other) => {
            warn!(
                did = signer,
                role = %other,
                "server registration rejected: Service role required"
            );
            return Err(InfraRejection::new(
                "e.p.registration.unauthorized",
                "service role required to register as a server",
            ));
        }
        Err(_) => {
            warn!(
                did = signer,
                "server registration rejected: DID not in ACL (requires pre-approval)"
            );
            return Err(InfraRejection::new(
                "e.p.registration.unauthorized",
                "server DID must be pre-approved in the ACL before registering",
            ));
        }
    };

    let public_url = body
        .get("public_url")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    // Apply the same URL allowlist that the REST `register_service`
    // route enforces. Without this gate, an ACL'd Service-role caller
    // could register an arbitrary URL (cloud-metadata IP, RFC1918,
    // attacker-controlled host) and then wait for an Admin to hit
    // `/api/proxy/server/{instance_id}/...` — `proxy_to_service` would
    // forward the Admin's `Authorization: Bearer ...` to that URL.
    if let Err(e) =
        registry::validate_registered_url(public_url, &state.config.registry.url_allowlist)
    {
        warn!(
            did = signer,
            requested = public_url,
            "server registration rejected: URL host not in registry.url_allowlist",
        );
        return Err(InfraRejection::new(
            "e.p.registration.unauthorized",
            e.user_message(),
        ));
    }

    let label = body.get("label").and_then(|v| v.as_str()).map(String::from);

    // T27: parse capability declaration. Backwards-compat: pre-T27
    // servers don't send these fields; default to webvh-only.
    let enabled_methods: Vec<String> = body
        .get("enabled_methods")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_else(|| vec!["webvh".to_string()]);
    let claimed_served_domains: Vec<String> = body
        .get("served_domains")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    // Defense against a misbehaving server fabricating `served_domains`
    // entries to mislead operators (and the purge-fanout in
    // `delete_domain_route`). We intersect the self-asserted list
    // against the control plane's authoritative DomainEntry registry,
    // dropping names the control plane has no record of. This filters
    // the "fabricate-a-domain-name" attack vector.
    //
    // KNOWN GAP (tracked for follow-up): we can't yet verify that the
    // server is actually *authorised* to host the domains it claims —
    // the control plane fires assign/unassign messages without
    // recording them. A peer Service-role server could still claim to
    // host a real but unrelated tenant's domain. Closing that gap
    // requires a new control-plane-side dispatched-assignments table
    // (one row per outbound MSG_DOMAIN_{ASSIGN,UNASSIGN}) the register
    // handler can intersect against. Out of scope for this security
    // fix; HIGH-1 (control-plane pinning on the server-side handlers)
    // already removes the most damaging exploit (a peer issuing
    // forged domain.purge to wipe data).
    let served_domains: Vec<String> = if claimed_served_domains.is_empty() {
        Vec::new()
    } else {
        let mut keep = Vec::with_capacity(claimed_served_domains.len());
        for name in claimed_served_domains {
            match did_hosting_common::server::domain::get_domain(&state.store, &name).await {
                Ok(Some(_)) => keep.push(name),
                Ok(None) => warn!(
                    did = signer,
                    domain = %name,
                    "register: dropping served_domains entry — control plane has no DomainEntry for this name"
                ),
                Err(e) => warn!(
                    did = signer,
                    domain = %name,
                    error = %e,
                    "register: failed to look up DomainEntry during served_domains validation — dropping entry"
                ),
            }
        }
        keep
    };
    let protocol_version = body
        .get("protocol_version")
        .and_then(|v| v.as_str())
        .unwrap_or("1.0")
        .to_string();

    // Self-asserted: only a server that ships the trust-task dispatcher sends
    // this. Absent (older fleet) → false → the health loop keeps sending the
    // legacy `MSG_HEALTH_PING`, so upgrading the control plane first never
    // strands a server as Unreachable.
    let trust_task_capable = body
        .get("trust_task_capable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let sync_batch_capable = body
        .get("sync_batch")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Use the signer DID as a stable instance ID (one registration per DID)
    let instance_id = signer.replace(':', "_");

    // `register_instance` overwrites the whole record, so carry the previous
    // badge cache forward rather than blanking it. The refresh below
    // re-resolves and supersedes this; if that resolve fails, the operator
    // keeps seeing the last known services instead of an empty badge row.
    let previous = registry::get_instance(&state.registry_ks, &instance_id)
        .await
        .ok()
        .flatten();

    let instance = ServiceInstance {
        instance_id: instance_id.clone(),
        service_type: ServiceType::Server,
        label,
        url: public_url.to_string(),
        status: ServiceStatus::Active,
        last_health_check: None,
        registered_at: crate::auth::session::now_epoch(),
        metadata: json!({ "did": signer }),
        enabled_methods,
        served_domains,
        protocol_version,
        advertised_services: previous
            .as_ref()
            .and_then(|p| p.advertised_services.clone()),
        services_checked_at: previous.as_ref().and_then(|p| p.services_checked_at),
        trust_task_capable,
        sync_batch_capable,
        // `register_instance` overwrites the whole record, so the observed-link
        // history has to survive a re-register exactly as the badge cache does.
        // The caller records *this* registration's inbound transport right
        // after; the outbound side has no other source and would otherwise be
        // blanked every time a server restarts.
        last_inbound_transport: previous.as_ref().and_then(|p| p.last_inbound_transport),
        last_inbound_at: previous.as_ref().and_then(|p| p.last_inbound_at),
        last_outbound_transport: previous.as_ref().and_then(|p| p.last_outbound_transport),
        last_outbound_at: previous.as_ref().and_then(|p| p.last_outbound_at),
    };

    if let Err(e) = registry::register_instance(&state.registry_ks, &instance).await {
        warn!(did = signer, error = %e, "server registration failed");
        return Err(InfraRejection::new(
            "e.p.registration.internal-error",
            e.to_string(),
        ));
    }

    info!(
        did = signer,
        instance_id = %instance_id,
        public_url = public_url,
        role = %role,
        "server registered"
    );

    // Cache what the registering server's DID document advertises, so the
    // Servers list can badge it. Best-effort: a registration must not fail
    // because the DID momentarily won't resolve.
    if let Err(e) = registry::refresh_advertised_services(
        &state.registry_ks,
        &instance_id,
        state.did_resolver.as_ref(),
        crate::auth::session::now_epoch(),
    )
    .await
    {
        warn!(
            did = signer,
            error = %e,
            "failed to cache advertised services for registering server"
        );
    }

    // Sync DIDs to the newly registered server — only the ones it doesn't
    // already have. The server reports what it holds in `preloaded_dids`
    // (mnemonic → version_count); anything absent or stale is pushed. A client
    // that sends no `preloaded_dids` (older server, or an empty store) gets a
    // full push. This is what stops a reboot from re-syncing every DID.
    let reported: std::collections::HashMap<String, u64> = body
        .get("preloaded_dids")
        .and_then(|v| v.as_array())
        .map(|entries| {
            entries
                .iter()
                .filter_map(|e| {
                    let mnemonic = e.get("mnemonic")?.as_str()?.to_string();
                    let version = e.get("version_count")?.as_u64()?;
                    Some((mnemonic, version))
                })
                .collect()
        })
        .unwrap_or_default();
    server_push::sync_all_dids_to_server(state, signer.to_string(), reported);

    Ok(json!({
        "instance_id": instance_id,
        "status": "registered",
    }))
}

/// Answer a message this router has no arm for with a problem-report, so the
/// caller fails immediately and *knows which task we refused*.
///
/// Dropping an unrouted type silently — which this did — turns every retirement
/// into a mystery timeout on the client. When #144 retired `did/publish/0.1` and
/// the `agent-name` set/enable/disable trio, a VTA still sending them got no
/// reply at all: it burned its full 30s `send_and_wait` and surfaced
/// "bad gateway: request timed out" with no mention of the task, on four
/// separate operations. The retirements were correct; the silence is what made
/// them expensive to diagnose. Naming the type turns a 30s dead end into an
/// immediate, greppable error, and does so for the *next* retirement too.
///
/// Threading to `message.id` is load-bearing: callers demux replies by thread
/// id, so an unthreaded problem-report is discarded and the caller waits out its
/// timeout anyway — the bug would look unfixed.
///
/// Loop-safe: an inbound problem-report returns above, before we would reply,
/// and `is_problem_report` matches the type we emit — so a peer that cannot
/// route our reply logs and drops it rather than answering back.
async fn handle_fallback(
    ctx: HandlerContext,
    message: Message,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = ctx.sender_did.as_deref();
    if log_problem_report("control", sender, &message) {
        return Ok(None);
    }
    warn!(
        sender = sender.unwrap_or("unknown"),
        msg_type = %message.typ,
        "inbound DIDComm: unhandled message type — replying with a problem-report"
    );
    let (typ, body) = run_unsupported_task(&message.typ);
    Ok(Some(
        DIDCommResponse::new(typ, body).thid(message.id.clone()),
    ))
}

/// The problem-report [`handle_fallback`] answers an unrouted type with.
///
/// Returns `(typ, body)` rather than a `DIDCommResponse` for the same reason
/// the `run_*` helpers in this module do: the response type exposes no getters,
/// so a test can only assert what the builder was handed. The threading stays at
/// the call site, where `message.id` lives.
fn run_unsupported_task(msg_type: &str) -> (String, Value) {
    (
        MSG_PROBLEM_REPORT.to_string(),
        json!({
            "code": "e.p.msg.unsupported-task",
            // The type is the whole diagnostic: a retired task, a typo, and a
            // peer predating the task are indistinguishable without it, and the
            // caller cannot log what it was never told.
            "comment": format!(
                "this control plane has no handler for `{msg_type}` — it may have been retired, \
                 or this peer may be a version that predates it"
            ),
        }),
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_sender(ctx: &HandlerContext) -> Result<&str, DIDCommServiceError> {
    ctx.sender_did
        .as_deref()
        .map(|did| did.split('#').next().unwrap_or(did))
        .ok_or_else(|| DIDCommServiceError::Internal("missing sender DID".into()))
}

/// Map an internal `AppError` to its DIDComm protocol error code.
///
/// Thin wrapper around `AppError::didcomm_code()` — kept as a function
/// alias so the existing call sites (and the
/// `map_app_error_code_pinned_table` test) don't need to chase the
/// rename. The shared implementation in `did-hosting-common::server::error`
/// is backed by `ValidationKind` / `QuotaKind` tags rather than
/// substring sniffing, so a wording change in any
/// `AppError::Validation("...")` literal can no longer silently
/// re-route the protocol code.
#[cfg(test)]
fn map_app_error_code(err: &AppError) -> &'static str {
    err.didcomm_code()
}

// ---------------------------------------------------------------------------
// Trust Tasks envelope handler (v0.7.0+)
// ---------------------------------------------------------------------------

/// DIDComm handler for the Trust Tasks envelope
/// (`https://trusttasks.org/binding/didcomm/0.1/envelope`).
///
/// `message.body` is the JSON of the inner `TrustTask<Value>` document
/// (per the binding's wire shape — see `trust-tasks-didcomm/src/pack.rs`).
/// `ctx.sender_did` is the messaging layer's report of who sent it: a routing
/// hint that [`dispatch_trust_task_doc`] requires to agree with the document's
/// proof, never an authorisation on its own.
///
/// We construct a [`DidcommHandler`] reporting `local = server_did`
/// and `peer = sender`, then hand the document to the shared
/// [`dispatch_trust_task_doc`] core. The result is repacked as a new DIDComm
/// message of the same envelope type so the same routing rules
/// (mediator pickup, attachment, etc.) apply.
async fn handle_trust_tasks_envelope(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = require_sender(&ctx)?;
    info!(sender = sender, "inbound DIDComm: trust-tasks envelope");
    match run_trust_tasks_envelope(&state, sender, &message).await? {
        Some((response_type, response_body)) => Ok(Some(
            DIDCommResponse::new(response_type, response_body).thid(message.id.clone()),
        )),
        None => Ok(None),
    }
}

/// Compute the wire-level `(response_type, response_body)` tuple for
/// an inbound trust-tasks envelope. Extracted from
/// `handle_trust_tasks_envelope` so the dispatch + body-parse +
/// repack logic is testable without an `ATM`-backed
/// [`HandlerContext`]. Returns `None`
/// for the SPEC.md §8.1 routing exception (identity-mismatch with no
/// transport sender), which is unreachable on the dispatcher's
/// `require_sender_did(true)` gate.
pub(crate) async fn run_trust_tasks_envelope(
    state: &AppState,
    sender: &str,
    message: &Message,
) -> Result<Option<(String, Value)>, DIDCommServiceError> {
    let doc: trust_tasks_rs::TrustTask<Value> = match serde_json::from_value(message.body.clone()) {
        Ok(d) => d,
        Err(e) => {
            warn!(
                sender = sender,
                error = %e,
                "trust-tasks envelope: inner body did not parse as TrustTask<Value>"
            );
            // Mirror the routed-error pattern from the HTTPS
            // transport: build a `malformed_request` document and
            // pack it back inside the same envelope type so the
            // sender sees a consistent error shape across transports.
            let err_doc = body_parse_error(&e.to_string());
            let body =
                serde_json::to_value(&err_doc).expect("trust-task-error document serialises");
            return Ok(Some((trust_tasks_didcomm::ENVELOPE_TYPE.to_string(), body)));
        }
    };

    let my_vid = state
        .config
        .server_did
        .as_deref()
        .ok_or_else(|| DIDCommServiceError::Internal("server_did not configured".into()))?;

    // Replay protection is not here: a DIDComm message id is chosen per
    // message by whoever sends it, so a captured document re-wrapped in a new
    // message would sail past a `(sender, message.id)` check. The unified
    // dispatcher keys its replay cache on `(proven issuer, document id)`
    // instead — both covered by the document's own proof.
    let transport =
        trust_tasks_didcomm::DidcommHandler::new(my_vid.to_string(), sender.to_string());

    // Route through the unified trust-task dispatcher — the same entry TSP and
    // HTTPS use. Every family is reachable here: the typed
    // `did-hosting/*/1.0` protocol, auth, infra, ACL + discovery, and the
    // legacy `MSG_*` bridge.
    let verifier = require_verifier(state)?;
    match dispatch_trust_task_doc(state, sender, &transport, doc, verifier)
        .await?
        .into_document()
    {
        Some(body) => Ok(Some((trust_tasks_didcomm::ENVELOPE_TYPE.to_string(), body))),
        None => {
            // SPEC §8.1 routing exception: identity-mismatch with no
            // transport sender. Unreachable under `require_sender_did(true)`;
            // if it fires, the invariant has broken.
            tracing::error!(
                should_not_happen = true,
                sender = sender,
                "trust-tasks envelope: dispatch suppressed (identity_mismatch w/ no transport sender)"
            );
            Ok(None)
        }
    }
}

/// Build the same body-parse `trust-task-error` document that the
/// HTTPS transport uses, kept here so the two transports emit
/// byte-identical error shapes for parse failures.
pub(crate) fn body_parse_error(reason: &str) -> trust_tasks_rs::ErrorResponse {
    use trust_tasks_rs::{ErrorPayload, RejectReason, TrustTask};
    let reject = RejectReason::MalformedRequest {
        reason: format!("body did not parse as a Trust Task document: {reason}"),
    };
    let payload: ErrorPayload = reject.into();
    TrustTask {
        id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        thread_id: None,
        // The body never parsed, so there is no request to read an enclosing
        // exchange from (SPEC §4.9.2).
        parent_thread_id: None,
        // No ceremony, for the same reason as `parent_thread_id` above: SPEC
        // §7.1 carries the member forward from the request so a reply stays
        // inside its enactment, and here there is no request to carry it from.
        ceremony: None,
        type_uri: did_hosting_common::server::trust_tasks::framework_error_type_uri(),
        issuer: None,
        recipient: None,
        issued_at: Some(chrono::Utc::now()),
        expires_at: None,
        payload,
        context: None,
        proof: None,
        extra: Default::default(),
    }
}

// ---------------------------------------------------------------------------
// Unified trust-task dispatch (all transports)
// ---------------------------------------------------------------------------

/// The single dispatch entry for an inbound `TrustTask<Value>` document,
/// shared by **every** transport that carries trust-task documents — TSP,
/// the DIDComm trust-task envelope, and (behind its bearer-auth proof
/// pre-check) HTTPS `POST /api/trust-tasks`.
///
/// Routes by Type URI:
/// - Type URIs the framework dispatcher owns (ACL grant/revoke/change-role/
///   show/list, discovery) → the typed SPEC §7.2 pipeline via
///   [`dispatch_inbound`](did_hosting_common::server::trust_tasks::dispatch_inbound).
/// - Everything else (the legacy DID-management ops) → [`bridge_did_management`],
///   which reuses the transport-agnostic [`dispatch_did_op`] engine.
///
/// Returns the response document as a JSON value (`None` = the SPEC §8.1
/// identity-mismatch "suppressed" case). Each transport serialises the
/// value for its own wire (TSP → bytes, DIDComm → envelope body, HTTPS →
/// JSON response). `transport` is the caller's [`TransportHandler`] so the
/// framework path resolves identities with the right binding.
/// What a routed Trust Task produced, before any transport turns it into a
/// reply.
///
/// The variants exist because **HTTPS needs the reject code and the other two
/// transports do not**. SPEC's status table maps a framework rejection onto an
/// HTTP status; DIDComm and TSP have no status to carry, so they serialise the
/// document either way. Flattening to `Option<Value>` here — as this router used
/// to — meant the HTTPS route could not use it and had to re-implement the
/// routing itself, which is how it came to serve a strict subset: the typed
/// `did-hosting/*/1.0` family, the auth family and the infra family were all
/// unreachable over HTTPS, and an agent-name update sent there fell through to a
/// legacy table that has never heard of it and answered "unknown op".
pub(crate) enum RoutedReply {
    /// A framework outcome. Carries the reject code, so HTTPS can map a status.
    ///
    /// Boxed: `DispatchOutcome` is ~750 bytes against a `Value`'s few, and this
    /// enum is returned from every dispatch on every transport.
    Framework(Box<did_hosting_common::server::trust_tasks::DispatchOutcome>),
    /// A reply from a bridged or typed op. There is no framework reject code to
    /// map, and the problem-report shape carries any error, so HTTPS answers
    /// `200` exactly as the other two transports answer with the document.
    Document(Value),
    /// Nothing goes on the wire (SPEC §8.1: identity mismatch with no
    /// transport-authenticated sender).
    Suppressed,
}

impl RoutedReply {
    /// The reply document, for a transport with no status codes to carry.
    pub(crate) fn into_document(self) -> Option<Value> {
        use did_hosting_common::server::trust_tasks::DispatchOutcome;
        match self {
            RoutedReply::Framework(outcome) => match *outcome {
                DispatchOutcome::Handled(doc) => {
                    Some(serde_json::to_value(&doc).expect("response document serialises"))
                }
                DispatchOutcome::Rejected(err) => {
                    Some(serde_json::to_value(&err).expect("error document serialises"))
                }
                DispatchOutcome::Suppressed => None,
            },
            RoutedReply::Document(value) => Some(value),
            RoutedReply::Suppressed => None,
        }
    }
}

/// Route one Trust Task document, for **every** transport.
///
/// HTTPS, DIDComm and TSP all arrive here. Each opens its own binding and
/// establishes its own authenticated sender — that is what a binding is for —
/// and then the question "what does this document mean" is answered once, here.
///
/// The order of the checks below is load bearing and each one carries the
/// reason it sits where it does; they are not interchangeable.
pub(crate) async fn dispatch_trust_task_doc(
    state: &AppState,
    sender: &str,
    transport: &(impl trust_tasks_rs::TransportHandler + Sync),
    doc: trust_tasks_rs::TrustTask<Value>,
    verifier: &did_hosting_common::server::trust_tasks::TransportBoundVerifier,
) -> Result<RoutedReply, DIDCommServiceError> {
    use did_hosting_common::server::trust_tasks::{
        DispatchOutcome, TransportBoundVerifier, TrustTaskContext, build_dispatcher,
        dispatch_inbound, verify_sender_bound,
    };

    let my_vid = state
        .config
        .server_did
        .as_deref()
        .ok_or_else(|| DIDCommServiceError::Internal("server_did not configured".into()))?;

    let type_uri = doc.type_uri.to_string();

    // An error is terminal: it is somebody's account of a failure, not a request
    // to act on. Checked before anything else — including the proof gate below,
    // which would otherwise answer an unsigned error with an error of its own,
    // and the peer would do the same with ours. One failure became a permanent
    // exchange between two services politely answering each other's errors
    // once already, and it stopped only when the mediator started
    // rate-limiting.
    //
    // The reason is logged, not just the fact: a peer's error is often the only
    // account of what went wrong anywhere in the exchange.
    //
    // The prefix comes from `vta_sdk::inbound`, not a literal here: which URIs
    // are terminal errors is a fact about the *document*, the same for whoever
    // reads one, and a local copy is a second place for it to drift from.
    if type_uri.starts_with(vta_sdk::inbound::TRUST_TASK_ERROR_PREFIX) {
        let code = doc
            .payload
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("?");
        let message = doc
            .payload
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("");
        warn!(
            sender,
            %code,
            %message,
            "inbound trust-task error from a peer — terminal, not answered"
        );
        return Ok(RoutedReply::Suppressed);
    }

    // ── The proof gate. Every document that asks this control plane to *do*
    //    something — change state, disclose a record, mint a session — must be
    //    signed by its issuer, addressed here, and fresh; and the issuer must be
    //    the DID the transport reported (`verify_sender_bound`). From here on
    //    `principal` — the proven signer — is the only identity anything below
    //    authorises on. The transport's `sender` is a routing hint, and a
    //    document whose proof disagrees with it is refused rather than resolved
    //    in either's favour.
    //
    //    The exemptions are the two documents that authorise nothing and that a
    //    peer must be able to send before it can sign anything useful:
    //    capability discovery, and asking for an auth challenge.
    let principal = if is_proofless(&type_uri) {
        sender.to_string()
    } else {
        match verify_sender_bound(&doc, None, Some(sender), my_vid, verifier).await {
            Ok(principal) => principal,
            Err(e) => {
                warn!(sender, %type_uri, error = %e, "trust task refused: not bound to its sender");
                let reason = e.reject_reason();
                return Ok(RoutedReply::Framework(Box::new(DispatchOutcome::Rejected(
                    doc.reject_with(format!("urn:uuid:{}", uuid::Uuid::new_v4()), reason),
                ))));
            }
        }
    };

    // Replay gate, keyed on what the proof covers: the proven issuer and the
    // document id. A captured document re-submitted inside the freshness window
    // — on any transport, in any framing — is refused as an id conflict.
    if !is_proofless(&type_uri)
        && state
            .replay_cache
            .check_and_insert(&principal, &doc.id)
            .is_err()
    {
        warn!(did = %principal, doc_id = %doc.id, %type_uri, "trust task refused: replay");
        return Ok(RoutedReply::Framework(Box::new(DispatchOutcome::Rejected(
            doc.reject_with(
                format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                trust_tasks_rs::RejectReason::IdConflict,
            ),
        ))));
    }

    // Proofs are verified on every path — there is no configuration under
    // which a proof-bearing document is accepted unverified.
    let policy: trust_tasks_rs::ProofPolicy<'_, TransportBoundVerifier> =
        trust_tasks_rs::ProofPolicy::Verify(verifier);

    // Typed fit-for-purpose DID-management protocol (`did-hosting/*/1.0`).
    // Takes precedence for its own URIs; runs the framework §7.2 pipeline
    // with typed payloads (see `crate::trust_tasks_did`).
    if crate::trust_tasks_did::owns(&type_uri) {
        let outcome = crate::trust_tasks_did::dispatch::<TransportBoundVerifier>(
            state, transport, policy, doc,
        )
        .await;
        return Ok(match outcome {
            DispatchOutcome::Handled(resp) => RoutedReply::Document(
                serde_json::to_value(&resp).expect("response document serialises"),
            ),
            DispatchOutcome::Rejected(err) => RoutedReply::Document(
                serde_json::to_value(&err).expect("error document serialises"),
            ),
            DispatchOutcome::Suppressed => RoutedReply::Suppressed,
        });
    }

    // Auth (`auth/{challenge,authenticate,refresh}/0.1`). Before the framework
    // check below: the shared `build_dispatcher` does not carry this family —
    // its context is the ACL keyspace — so an auth document would fall through
    // to `bridge_did_management`, a table of DID operations that has never
    // heard of it, and come back a bogus "unknown op".
    if crate::trust_tasks_auth::owns(&type_uri) {
        return Ok(RoutedReply::Document(
            crate::trust_tasks_auth::dispatch(state, transport, policy, doc)
                .await
                .ok_or(DIDCommServiceError::Internal(
                    "auth dispatch produced no reply".into(),
                ))?,
        ));
    }

    // Control↔server infrastructure ops (server registration, health pong,
    // stats, sync and domain acks). Must be checked *before* the
    // `bridge_did_management` fallthrough below, which would otherwise hand
    // them to `dispatch_did_op` — a table of DID operations that has never
    // heard of them — and answer with a bogus "unknown op" problem report.
    if crate::trust_tasks_infra::owns(&type_uri) {
        // The dispatcher stays transport-agnostic; we only tell it which binding
        // the document came in on so the registry can record what actually moved.
        let via = did_hosting_common::server::didcomm_profile::ObservedTransport::from_binding_uri(
            transport.binding_uri(),
        );
        return Ok(
            match crate::trust_tasks_infra::dispatch(state, &principal, via, doc).await {
                Some(value) => RoutedReply::Document(value),
                None => RoutedReply::Suppressed,
            },
        );
    }

    let framework_owns = build_dispatcher()
        .registered_uris()
        .contains(&type_uri.as_str());

    if !framework_owns {
        return bridge_did_management(state, &principal, my_vid, &doc)
            .await
            .map(RoutedReply::Document);
    }

    let ctx = TrustTaskContext {
        acl_ks: &state.acl_ks,
        acl_locks: &state.acl_locks,
        my_vid,
    };

    // The framework path, and the only one whose outcome carries a reject code
    // — so it is handed back whole rather than serialised here, and HTTPS maps
    // it to a status.
    Ok(RoutedReply::Framework(Box::new(
        dispatch_inbound::<TransportBoundVerifier>(&ctx, transport, policy, doc).await,
    )))
}

/// The only Type URIs [`dispatch_trust_task_doc`] routes without a proof.
///
/// Both authorise nothing: discovery lists what this service implements, and a
/// challenge request only creates the nonce a peer must then sign to
/// authenticate. Everything else — ACL reads included — is privileged.
pub(crate) fn is_proofless(type_uri: &str) -> bool {
    use trust_tasks_rs::Payload;
    type_uri == trust_tasks_rs::specs::trust_task_discovery::v0_1::Payload::TYPE_URI
        || type_uri == trust_tasks_rs::specs::auth::challenge::v0_1::Payload::TYPE_URI
}

/// The shared proof verifier, or an error when none is configured — without
/// one no privileged document can be accepted, so dispatch refuses outright.
pub(crate) fn require_verifier(
    state: &AppState,
) -> Result<&did_hosting_common::server::trust_tasks::TransportBoundVerifier, DIDCommServiceError> {
    state.trust_tasks_verifier.as_deref().ok_or_else(|| {
        DIDCommServiceError::Internal(
            "no trust-task proof verifier configured (a DID resolver is required)".into(),
        )
    })
}

/// Bridge a legacy DID-management Trust Task document to the shared
/// [`dispatch_did_op`] table.
///
/// The DID-management ops (`did_ops::*`) are bound to the control plane's
/// `AppState`, so they cannot move into the crate-agnostic framework
/// dispatcher — but `dispatch_did_op` is *already* transport-agnostic (it
/// reads only `msg.typ` + `msg.body`). We ACL-check `sender` — the
/// document's proven issuer, established by [`dispatch_trust_task_doc`]'s
/// proof gate before this is reached — synthesise a `Message` from the Trust Task document (`type_uri` →
/// `typ`, `payload` → `body`), dispatch, and wrap the `(response_type,
/// body)` back into a Trust Task `#response` document.
pub(crate) async fn bridge_did_management(
    state: &AppState,
    sender: &str,
    my_vid: &str,
    doc: &trust_tasks_rs::TrustTask<Value>,
) -> Result<Value, DIDCommServiceError> {
    let role = match check_acl(&state.acl_ks, sender).await {
        Ok(r) => r,
        Err(e) => {
            warn!(
                sender,
                code = e.didcomm_code(),
                "trust-task DID-management: ACL denied"
            );
            return tt_reply(doc, my_vid, sender, MSG_PROBLEM_REPORT, problem_body(&e));
        }
    };
    let auth = AuthClaims {
        did: sender.to_string(),
        role,
        session_id: String::new(),
        session_pubkey_b58btc: None,
        amr: vec!["did".to_string()],
        acr: "aal1".to_string(),
    };

    // `dispatch_did_op` reads only `typ` and `body`; `id`/`from` are set for
    // completeness / logging.
    let msg = Message::build(
        doc.id.clone(),
        doc.type_uri.to_string(),
        doc.payload.clone(),
    )
    .from(sender.to_string())
    .finalize();

    match dispatch_did_op(&auth, state, &msg).await {
        Ok((resp_type, resp_body)) => tt_reply(doc, my_vid, sender, &resp_type, resp_body),
        Err(e) => {
            // `error = %e` is the point: `code` alone is a taxonomy bucket —
            // `e.p.did.validation-error` is every `AppError::Validation` whose
            // kind is `Other` — so without the message an operator reading this
            // line learns only that *something* did not validate. That is
            // exactly how a live mint failure stayed unexplained.
            warn!(
                sender,
                code = e.didcomm_code(),
                error = %e,
                msg_type = %msg.typ,
                "trust-task DID-management: protocol error"
            );
            tt_reply(doc, my_vid, sender, MSG_PROBLEM_REPORT, problem_body(&e))
        }
    }
}

/// The `{code, comment}` problem-report body the DID-management protocol
/// uses for errors, shared across transports.
fn problem_body(e: &AppError) -> Value {
    json!({ "code": e.didcomm_code(), "comment": e.user_message() })
}

/// Wrap a `(type_uri, payload)` DID-management response as a Trust Task
/// document addressed back to `sender`, threaded to the request.
fn tt_reply(
    request: &trust_tasks_rs::TrustTask<Value>,
    my_vid: &str,
    sender: &str,
    type_uri: &str,
    payload: Value,
) -> Result<Value, DIDCommServiceError> {
    let type_uri = type_uri.parse().map_err(|_| {
        DIDCommServiceError::Internal(format!("response Type URI does not parse: {type_uri}"))
    })?;
    let doc = trust_tasks_rs::TrustTask {
        id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        thread_id: Some(request.id.clone()),
        // SPEC §4.9.2 — the whole exchange shares one parent, so a response
        // stays inside whatever enclosing exchange the request named.
        parent_thread_id: request.parent_thread_id.clone(),
        // And the ceremony for the same reason (SPEC §7.1): a response stays
        // inside the enactment its request belonged to. `respond_with` carries
        // this for callers that use it — this builder does not, because it
        // needs a caller-chosen `type_uri`, so it has to carry it by hand.
        // `None` here would silently drop the response out of its ceremony.
        ceremony: request.ceremony.clone(),
        type_uri,
        issuer: Some(my_vid.to_string()),
        recipient: Some(sender.to_string()),
        issued_at: Some(chrono::Utc::now()),
        expires_at: None,
        payload,
        context: None,
        proof: None,
        extra: Default::default(),
    };
    Ok(serde_json::to_value(&doc).expect("Trust Task response serialises"))
}

#[cfg(test)]
mod tests {
    use did_hosting_common::server::store::{
        KS_ACL, KS_DIDS, KS_REGISTRY, KS_SESSIONS, KS_STATS, KS_TIMESERIES,
    };
    use std::path::PathBuf;
    use std::sync::{Arc, OnceLock};

    use affinidi_messaging_didcomm::Message;
    use did_hosting_common::did_ops::{DidRecord, did_key, owner_key};
    use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
    use did_hosting_common::server::config::{
        AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
    };
    use did_hosting_common::server::stats_collector::StatsCollector;
    use did_hosting_common::server::store::Store;
    use serde_json::json;

    use crate::auth::AuthClaims;
    use crate::config::{AppConfig, RegistryConfig};
    use crate::server::AppState;

    use super::*;

    #[test]
    fn decision_payload_parses_both_spec_decisions() {
        let approve = json!({
            "challenge": "9c1f4b7a2e6d80f35a4c9b1e7d2f6083",
            "payloadDigest": "3b0c7f1d",
            "decision": "approve",
        });
        assert_eq!(
            parse_decision_payload(&approve),
            Some(("9c1f4b7a2e6d80f35a4c9b1e7d2f6083", "3b0c7f1d", true))
        );

        let deny = json!({
            "challenge": "c",
            "payloadDigest": "d",
            "decision": "deny",
            "reason": "I did not initiate this",
        });
        assert_eq!(parse_decision_payload(&deny), Some(("c", "d", false)));
    }

    /// Anything that is not literally `approve` or `deny` resolves nothing.
    /// A device must not synthesise an approval, and neither may we — the
    /// old `confirm-response` shape (`{"approved": bool}`) lands here too,
    /// so a stale wallet cannot approve anything post-cutover.
    #[test]
    fn decision_payload_rejects_anything_but_the_two_spec_values() {
        for payload in [
            json!({ "challenge": "c", "payloadDigest": "d", "decision": "approved" }),
            json!({ "challenge": "c", "payloadDigest": "d", "decision": "" }),
            json!({ "challenge": "c", "payloadDigest": "d", "decision": true }),
            json!({ "challenge": "c", "payloadDigest": "d" }),
            json!({ "challenge": "c", "decision": "approve" }),
            json!({ "payloadDigest": "d", "decision": "approve" }),
            // The retired confirm/response/0.1 shape.
            json!({ "challenge": "c", "approved": true }),
        ] {
            assert_eq!(
                parse_decision_payload(&payload),
                None,
                "must not resolve: {payload}"
            );
        }
    }

    /// Build a minimal `AppState` backed by a tempdir-rooted fjall store. The
    /// returned `_dir` guard must outlive `state` — when it drops, fjall
    /// removes the partition files on disk.
    async fn test_state() -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store_config = StoreConfig {
            data_dir: PathBuf::from(dir.path()),
            ..StoreConfig::default()
        };
        let store = Store::open(&store_config).await.expect("open store");
        let sessions_ks = store.keyspace(KS_SESSIONS).expect("sessions ks");
        let acl_ks = store.keyspace(KS_ACL).expect("acl ks");
        let registry_ks = store.keyspace(KS_REGISTRY).expect("registry ks");
        let dids_ks = store.keyspace(KS_DIDS).expect("dids ks");
        let stats_ks = store.keyspace(KS_STATS).expect("stats ks");

        let config = AppConfig {
            features: FeaturesConfig::default(),
            server_did: Some("did:webvh:test:control.example.com".into()),
            mediator_did: None,
            public_url: Some("http://control.test".into()),
            did_hosting_url: Some("http://control.test".into()),
            server: ServerConfig::default(),
            log: LogConfig::default(),
            store: store_config,
            auth: AuthConfig::default(),
            secrets: SecretsConfig::default(),
            vta: VtaConfig::default(),
            registry: RegistryConfig::default(),
            trust_tasks: Default::default(),
            hosting: Default::default(),
            identity: Default::default(),
            config_path: PathBuf::new(),
        };

        let state = AppState {
            store: store.clone(),
            sessions_ks,
            acl_ks,
            registry_ks,
            dids_ks,
            config: Arc::new(config),
            did_resolver: None,
            secrets_resolver: None,
            identity: None,
            trust_tasks_verifier: None,
            jwt_keys: None,
            webauthn: None,
            http_client: reqwest::Client::new(),
            didcomm_service: Arc::new(OnceLock::new()),
            stats_collector: Arc::new(StatsCollector::new()),
            stats_ks: stats_ks.clone(),
            timeseries_ks: store.keyspace(KS_TIMESERIES).expect("timeseries ks"),
            signing_key_bytes: None,
            replay_cache: Arc::new(crate::replay::ReplayCache::new()),
            path_locks: crate::path_locks::PathLocks::new(),
            acl_locks: did_hosting_common::server::path_locks::PathLocks::new(),
            pending_challenges: Arc::new(crate::pending_challenges::PendingChallengeTracker::new()),
            ip_rate_limiter: Arc::new(crate::rate_limit::IpRateLimiter::new()),
            pending_confirms: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            outbox_notify: Arc::new(tokio::sync::Notify::new()),
        };

        (state, dir)
    }

    fn owner_auth(did: &str) -> AuthClaims {
        AuthClaims {
            did: did.to_string(),
            role: Role::Owner,
            session_pubkey_b58btc: None,
            session_id: String::new(),
            amr: vec!["did".to_string()],
            acr: "aal1".to_string(),
        }
    }

    fn admin_auth(did: &str) -> AuthClaims {
        AuthClaims {
            did: did.to_string(),
            role: Role::Admin,
            session_pubkey_b58btc: None,
            session_id: String::new(),
            amr: vec!["did".to_string()],
            acr: "aal1".to_string(),
        }
    }

    fn build_msg(typ: &str, body: serde_json::Value) -> Message {
        Message::build("msg-id".to_string(), typ.to_string(), body).finalize()
    }

    /// Seed a fully-formed `DidRecord` with both the `did:` and `owner:`
    /// index entries so list/info/delete dispatch arms have data to read.
    async fn seed_did(state: &AppState, owner_did: &str, mnemonic: &str) {
        let record = DidRecord {
            services: None,
            owner: owner_did.into(),
            mnemonic: mnemonic.into(),
            created_at: 1,
            updated_at: 1,
            version_count: 1,
            did_id: Some(format!("did:webvh:abc:{mnemonic}")),
            content_size: 42,
            disabled: false,
            deleted_at: None,

            // T12: legacy construction site; T13 migration fills `domain`.
            method: "webvh".to_string(),
            domain: String::new(),
            agent_names: Vec::new(),
        };
        state
            .dids_ks
            .insert(did_key(mnemonic), &record)
            .await
            .expect("seed did record");
        state
            .dids_ks
            .insert_raw(owner_key(owner_did, mnemonic), mnemonic.as_bytes().to_vec())
            .await
            .expect("seed owner index");
    }

    /// Unknown DIDComm message types must surface as `Validation` so the
    /// protocol-error mapper sends `e.p.did.validation-error`. Pinning this
    /// keeps the wire-level contract stable when handlers are added or
    /// renamed.
    #[tokio::test]
    async fn dispatch_did_op_unknown_type_returns_validation() {
        let (state, _dir) = test_state().await;
        let msg = build_msg("https://affinidi.com/webvh/1.0/not-a-real-type", json!({}));
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg)
            .await
            .expect_err("unknown type must error");
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("unknown message type")));
        assert_eq!(map_app_error_code(&err), "e.p.did.validation-error");
    }

    #[tokio::test]
    async fn dispatch_did_op_witness_missing_mnemonic_validation() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(MSG_WITNESS_PUBLISH, json!({ "witness": {} }));
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("mnemonic")));
    }

    #[tokio::test]
    async fn dispatch_did_op_witness_missing_witness_validation() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(MSG_WITNESS_PUBLISH, json!({ "mnemonic": "alpha-beta" }));
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("witness")));
    }

    #[tokio::test]
    async fn dispatch_did_op_witness_null_body_rejected() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(
            MSG_WITNESS_PUBLISH,
            json!({ "mnemonic": "alpha-beta", "witness": null }),
        );
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("witness")));
    }

    #[tokio::test]
    async fn dispatch_did_op_info_missing_mnemonic_validation() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(MSG_INFO_REQUEST, json!({}));
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("mnemonic")));
    }

    #[tokio::test]
    async fn dispatch_did_op_delete_missing_mnemonic_validation() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(MSG_DELETE, json!({}));
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("mnemonic")));
    }

    /// Owners with no DIDs see an empty list — verifies the success-path
    /// shape (`MSG_LIST` + `{ dids: [] }`) end-to-end with a real keyspace
    /// scan.
    #[tokio::test]
    async fn dispatch_did_op_list_request_empty_returns_empty_array() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(MSG_LIST_REQUEST, json!({}));
        let auth = owner_auth("did:example:caller");

        let (typ, body) = dispatch_did_op(&auth, &state, &msg).await.unwrap();
        assert_eq!(typ, MSG_LIST);
        let dids = body.get("dids").and_then(|v| v.as_array()).expect("dids[]");
        assert!(dids.is_empty(), "expected empty list, got {dids:?}");
    }

    /// Listing returns DIDs the caller owns, with the wire-level keys the
    /// VTA SDK consumes (`mnemonic`, `did_id`, `version_count`,
    /// `total_resolves`, etc.). Pinning the shape avoids silent drift if
    /// `DidListEntry` ever sprouts new fields.
    #[tokio::test]
    async fn dispatch_did_op_list_request_returns_owner_dids() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner-a";
        seed_did(&state, owner, "alpha-beta").await;
        seed_did(&state, owner, "gamma-delta").await;
        // A different owner's DID must not leak into the response.
        seed_did(&state, "did:example:other", "eta-theta").await;

        let msg = build_msg(MSG_LIST_REQUEST, json!({}));
        let auth = owner_auth(owner);

        let (typ, body) = dispatch_did_op(&auth, &state, &msg).await.unwrap();
        assert_eq!(typ, MSG_LIST);

        let dids = body.get("dids").and_then(|v| v.as_array()).expect("dids[]");
        assert_eq!(dids.len(), 2, "owner sees only their own DIDs: {dids:?}");
        let mnemonics: std::collections::HashSet<&str> = dids
            .iter()
            .filter_map(|d| d.get("mnemonic").and_then(|v| v.as_str()))
            .collect();
        assert!(mnemonics.contains("alpha-beta"));
        assert!(mnemonics.contains("gamma-delta"));
        assert!(!mnemonics.contains("eta-theta"));

        // Spot-check one entry's wire shape.
        let entry = dids
            .iter()
            .find(|d| d.get("mnemonic").and_then(|v| v.as_str()) == Some("alpha-beta"))
            .unwrap();
        assert!(entry.get("did_id").is_some());
        assert_eq!(entry.get("version_count").and_then(|v| v.as_u64()), Some(1));
        assert!(entry.get("total_resolves").is_some());
    }

    /// IDOR regression: an owner whose DID is a string-prefix of another
    /// owner's DID must NOT see the longer-DID owner's mnemonics. Owner-
    /// index keys are `owner:{did}:{mnemonic}` and DIDs naturally contain
    /// colons, so the prefix iteration is ambiguous between
    /// `did:web:tenant` and `did:web:tenant:server`. `list_dids` must
    /// re-check `record.owner == target_owner` after the iteration.
    #[tokio::test]
    async fn dispatch_did_op_list_request_filters_did_prefix_collision() {
        let (state, _dir) = test_state().await;
        let short = "did:example:tenant";
        let long = "did:example:tenant:server";
        seed_did(&state, short, "short-mn").await;
        seed_did(&state, long, "long-mn").await;

        // Caller is the SHORT-DID owner. Without the fix, the iterator
        // returns both `owner:did:example:tenant:short-mn` and
        // `owner:did:example:tenant:server:long-mn`.
        let msg = build_msg(MSG_LIST_REQUEST, json!({}));
        let auth = owner_auth(short);
        let (typ, body) = dispatch_did_op(&auth, &state, &msg).await.unwrap();
        assert_eq!(typ, MSG_LIST);
        let dids = body.get("dids").and_then(|v| v.as_array()).expect("dids[]");
        assert_eq!(
            dids.len(),
            1,
            "prefix collision must not leak the longer-DID owner's records: {dids:?}"
        );
        assert_eq!(
            dids[0].get("mnemonic").and_then(|v| v.as_str()),
            Some("short-mn")
        );
    }

    /// Admin role with no `owner` filter sees every DID across owners —
    /// pins the admin-listing branch in `did_ops::list_dids`.
    #[tokio::test]
    async fn dispatch_did_op_list_request_admin_sees_all_owners() {
        let (state, _dir) = test_state().await;
        seed_did(&state, "did:example:owner-a", "alpha-beta").await;
        seed_did(&state, "did:example:owner-b", "gamma-delta").await;

        let msg = build_msg(MSG_LIST_REQUEST, json!({}));
        let auth = admin_auth("did:example:admin");

        let (_typ, body) = dispatch_did_op(&auth, &state, &msg).await.unwrap();
        let dids = body.get("dids").and_then(|v| v.as_array()).unwrap();
        assert_eq!(dids.len(), 2, "admin must see DIDs from every owner");
    }

    /// Deleting a non-existent mnemonic surfaces as `NotFound`, which the
    /// protocol mapper turns into `e.p.did.mnemonic-not-found`.
    #[tokio::test]
    async fn dispatch_did_op_delete_unknown_mnemonic_not_found() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(MSG_DELETE, json!({ "mnemonic": "ghost-token" }));
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(
            matches!(err, AppError::NotFound(_)),
            "expected NotFound, got {err:?}"
        );
        assert_eq!(map_app_error_code(&err), "e.p.did.mnemonic-not-found");
    }

    /// `MSG_INFO_REQUEST` against a non-existent mnemonic is `NotFound` —
    /// covers the read-side counterpart to the delete case above and
    /// guards the wire-level "mnemonic-not-found" code.
    #[tokio::test]
    async fn dispatch_did_op_info_unknown_mnemonic_not_found() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(MSG_INFO_REQUEST, json!({ "mnemonic": "ghost-token" }));
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)));
        assert_eq!(map_app_error_code(&err), "e.p.did.mnemonic-not-found");
    }

    /// Cross-owner access is forbidden — Owner role can only see their own
    /// DIDs. Admins bypass this; regression-locks both branches of the
    /// `get_authorized_record` check.
    #[tokio::test]
    async fn dispatch_did_op_info_cross_owner_forbidden() {
        let (state, _dir) = test_state().await;
        seed_did(&state, "did:example:owner-a", "alpha-beta").await;

        let msg = build_msg(MSG_INFO_REQUEST, json!({ "mnemonic": "alpha-beta" }));
        let attacker = owner_auth("did:example:attacker");

        let err = dispatch_did_op(&attacker, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
        assert_eq!(map_app_error_code(&err), "e.p.did.unauthorized");

        // Admin sees through.
        let admin = admin_auth("did:example:admin");
        let (typ, body) = dispatch_did_op(&admin, &state, &msg).await.unwrap();
        assert_eq!(typ, MSG_INFO);
        assert_eq!(
            body.get("mnemonic").and_then(|v| v.as_str()),
            Some("alpha-beta")
        );
    }

    /// Auto-assign: a `check-name` with `reserve: true` and no `path`
    /// generates a fresh mnemonic, persists a `DidRecord` owned by the
    /// caller, and replies with `available: true, reserved: true` and a
    /// `record` carrying the assigned `mnemonic` + `didUrl`.
    #[tokio::test]
    async fn dispatch_did_op_did_request_auto_assign_reserves_record() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner-a";
        let msg = build_msg(MSG_DID_REQUEST, json!({ "reserve": true }));
        let auth = owner_auth(owner);

        let (typ, body) = dispatch_did_op(&auth, &state, &msg).await.unwrap();
        assert_eq!(typ, MSG_DID_OFFER);
        assert_eq!(body.get("available").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(body.get("reserved").and_then(|v| v.as_bool()), Some(true));

        let record_json = body.get("record").expect("reserved offer carries record");
        let mnemonic = record_json
            .get("mnemonic")
            .and_then(|v| v.as_str())
            .expect("record has mnemonic")
            .to_string();
        let did_url = record_json
            .get("didUrl")
            .and_then(|v| v.as_str())
            .expect("record has didUrl");
        assert!(
            did_url.ends_with(&format!("/{mnemonic}/did.jsonl")),
            "didUrl shape: {did_url}"
        );
        assert_eq!(
            record_json.get("versionCount").and_then(|v| v.as_u64()),
            Some(0)
        );

        // Verify the record landed in the dids keyspace, owned by the caller.
        let record: DidRecord = state
            .dids_ks
            .get(did_key(&mnemonic))
            .await
            .unwrap()
            .expect("record persisted");
        assert_eq!(record.owner, owner);
        assert_eq!(record.version_count, 0);
    }

    /// Auto-assign is collision-free: two successive `reserve: true`
    /// requests with no `path` yield two *different* mnemonics, each
    /// persisted. Mirrors the VTA-side regression at
    /// `vta-service/src/webvh_didcomm.rs` ("auto-assign (path == None)").
    #[tokio::test]
    async fn dispatch_did_op_auto_assign_yields_distinct_mnemonics() {
        let (state, _dir) = test_state().await;
        let auth = owner_auth("did:example:owner-a");
        let body = json!({ "reserve": true });

        let extract = |v: &Value| {
            v.get("record")
                .and_then(|r| r.get("mnemonic"))
                .and_then(|m| m.as_str())
                .map(str::to_string)
                .expect("reserved record has mnemonic")
        };
        let (_t1, b1) = dispatch_did_op(&auth, &state, &build_msg(MSG_DID_REQUEST, body.clone()))
            .await
            .unwrap();
        let (_t2, b2) = dispatch_did_op(&auth, &state, &build_msg(MSG_DID_REQUEST, body))
            .await
            .unwrap();
        let m1 = extract(&b1);
        let m2 = extract(&b2);
        assert_ne!(m1, m2, "auto-assign must not collide");
        assert!(
            state
                .dids_ks
                .get::<DidRecord>(did_key(&m1))
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            state
                .dids_ks
                .get::<DidRecord>(did_key(&m2))
                .await
                .unwrap()
                .is_some()
        );
    }

    /// Pure availability probe (`reserve` absent) is read-only: it reports
    /// `available` for the named path and persists nothing.
    #[tokio::test]
    async fn dispatch_did_op_check_name_probe_is_read_only() {
        let (state, _dir) = test_state().await;
        let auth = owner_auth("did:example:owner-a");

        // Free path → available, not reserved, no record written.
        let msg = build_msg(MSG_DID_REQUEST, json!({ "path": "free-path" }));
        let (_typ, body) = dispatch_did_op(&auth, &state, &msg).await.unwrap();
        assert_eq!(body.get("available").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(body.get("reserved").and_then(|v| v.as_bool()), Some(false));
        assert!(body.get("record").is_none());
        assert!(
            state
                .dids_ks
                .get::<DidRecord>(did_key("free-path"))
                .await
                .unwrap()
                .is_none(),
            "probe must not reserve the path"
        );

        // Taken path → not available.
        seed_did(&state, "did:example:owner-b", "taken-path").await;
        let msg = build_msg(MSG_DID_REQUEST, json!({ "path": "taken-path" }));
        let (_typ, body) = dispatch_did_op(&auth, &state, &msg).await.unwrap();
        assert_eq!(body.get("available").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(body.get("reserved").and_then(|v| v.as_bool()), Some(false));
    }

    /// A path-less request without `reserve: true` has no subject to
    /// probe and is rejected (spec §Conformance consumer rule 1).
    #[tokio::test]
    async fn dispatch_did_op_check_name_pathless_probe_rejected() {
        let (state, _dir) = test_state().await;
        let auth = owner_auth("did:example:owner-a");
        let msg = build_msg(MSG_DID_REQUEST, json!({}));
        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    /// A request bearing the canonical spec URI
    /// (`spec/did-management/did/check-name/0.1`) routes to the same
    /// `create_did` handler as the legacy `MSG_DID_REQUEST`, and the
    /// response carries the spec `#response` URI rather than the legacy
    /// `MSG_DID_OFFER` — proving inbound + outbound dialect symmetry
    /// for spec-URI callers like the VTA's `webvh_didcomm` client.
    #[tokio::test]
    async fn dispatch_did_op_spec_check_name_returns_spec_response() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:spec-owner";
        let spec_check_name = "https://trusttasks.org/spec/did-management/did/check-name/0.1";
        let spec_response =
            "https://trusttasks.org/spec/did-management/did/check-name/0.1#response";
        let msg = build_msg(spec_check_name, json!({ "reserve": true }));
        let auth = owner_auth(owner);

        let (typ, body) = dispatch_did_op(&auth, &state, &msg).await.unwrap();
        assert_eq!(typ, spec_response);
        let mnemonic = body
            .get("record")
            .and_then(|r| r.get("mnemonic"))
            .and_then(|v| v.as_str())
            .expect("response carries record.mnemonic");
        // Record persisted under caller's ownership, same as the legacy path.
        let record: DidRecord = state
            .dids_ks
            .get(did_key(mnemonic))
            .await
            .unwrap()
            .expect("record persisted");
        assert_eq!(record.owner, owner);
    }

    /// Reserving an explicit custom path that's already taken (without
    /// `force`) is NOT an error under check-name: the spec mandates
    /// `available: false, reserved: false` with no mutation.
    #[tokio::test]
    async fn dispatch_did_op_did_request_taken_path_not_available() {
        let (state, _dir) = test_state().await;
        seed_did(&state, "did:example:owner-a", "shared-path").await;

        let msg = build_msg(
            MSG_DID_REQUEST,
            json!({ "path": "shared-path", "reserve": true }),
        );
        let auth = owner_auth("did:example:owner-b");

        let (_typ, body) = dispatch_did_op(&auth, &state, &msg).await.unwrap();
        assert_eq!(body.get("available").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(body.get("reserved").and_then(|v| v.as_bool()), Some(false));
        assert!(body.get("record").is_none());
    }

    /// `.well-known` is admin-only; a non-admin reserving it gets
    /// `Forbidden` → `e.p.did.unauthorized`.
    #[tokio::test]
    async fn dispatch_did_op_did_request_well_known_forbidden_for_owner() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(
            MSG_DID_REQUEST,
            json!({ "path": ".well-known", "reserve": true }),
        );
        let auth = owner_auth("did:example:owner-a");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
        assert_eq!(map_app_error_code(&err), "e.p.did.unauthorized");
    }

    /// ACL gate covers DIDComm authentication and DID ops alike. This pins
    /// the integration: a DID added to the ACL with role `Owner` resolves
    /// through `check_acl` to that role — the input `handle_authenticate`
    /// uses to mint a JWT and `handle_webvh_message` uses for dispatch.
    #[tokio::test]
    async fn check_acl_returns_role_for_seeded_did() {
        use did_hosting_common::server::acl::check_acl;

        let (state, _dir) = test_state().await;
        let did = "did:example:owner-a";
        store_acl_entry(
            &state.acl_ks,
            &AclEntry {
                did: did.into(),
                role: Role::Owner,
                label: None,
                created_at: 0,
                max_total_size: None,
                max_did_count: None,

                domains: did_hosting_common::server::domain::DomainScope::All,
            },
        )
        .await
        .unwrap();

        let role = check_acl(&state.acl_ks, did).await.unwrap();
        assert_eq!(role, Role::Owner);

        // DID not in ACL → Forbidden.
        let err = check_acl(&state.acl_ks, "did:example:stranger")
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
    }

    /// An unrouted type is answered, not dropped. Dropping it is what made the
    /// #144 retirements expensive: the caller learned nothing for 30s and then
    /// reported a bare gateway timeout. The reply must name the type, or the
    /// caller still cannot say which task was refused.
    #[test]
    fn unsupported_task_reply_names_the_type() {
        let (typ, body) = run_unsupported_task("https://example.org/spec/made-up/0.1");
        assert_eq!(typ, MSG_PROBLEM_REPORT);
        assert_eq!(
            body.get("code").and_then(|v| v.as_str()),
            Some("e.p.msg.unsupported-task")
        );
        let comment = body.get("comment").and_then(|v| v.as_str()).unwrap();
        assert!(
            comment.contains("https://example.org/spec/made-up/0.1"),
            "the refused type is the whole diagnostic; got {comment}"
        );
    }

    /// The reply is itself a problem-report by `is_problem_report`'s reckoning,
    /// which is what makes this loop-safe: a peer that cannot route our reply
    /// logs and drops it in its own fallback instead of answering back. If the
    /// emitted type ever stopped matching, two fallbacks would ping-pong.
    #[test]
    fn unsupported_task_reply_cannot_start_a_problem_report_loop() {
        let (typ, _) = run_unsupported_task("https://example.org/spec/made-up/0.1");
        assert!(
            did_hosting_common::server::problem_report::is_problem_report(&typ),
            "{typ} must be recognised as a problem-report so peers drop rather than reply"
        );
    }

    /// The four URIs #144 retired each produce a reply naming them rather than
    /// silence — these are the exact tasks a VTA predating the cutover sends,
    /// and each one cost a 30s timeout.
    ///
    /// This asserts the *reply*, not that the URIs are unrouted: `Router`
    /// exposes no route introspection, so "is it still routed" isn't checkable
    /// from here. Re-adding a route would make these URIs bypass the fallback
    /// entirely and this test would keep passing while testing nothing about
    /// them — it guards the reply shape, which is what the client depends on.
    #[test]
    fn retired_tasks_are_refused_by_name() {
        for retired in [
            "https://trusttasks.org/spec/did-management/did/publish/0.1",
            "https://trusttasks.org/spec/did-management/agent-name/set/0.1",
            "https://trusttasks.org/spec/did-management/agent-name/enable/0.1",
            "https://trusttasks.org/spec/did-management/agent-name/disable/0.1",
            // Bare-message forms of ops that now travel only as signed Trust
            // Task documents inside the envelope.
            MSG_AUTHENTICATE,
            MSG_DELETE,
            MSG_SERVER_REGISTER,
        ] {
            let (typ, body) = run_unsupported_task(retired);
            assert_eq!(typ, MSG_PROBLEM_REPORT, "{retired}");
            assert!(
                body.get("comment")
                    .and_then(|v| v.as_str())
                    .is_some_and(|c| c.contains(retired)),
                "{retired} must be named in the reply"
            );
        }
    }

    /// Pin the AppError → DIDComm protocol-code mapping. The handler set is
    /// the wire-level contract for every external VTA, and the substring
    /// matches inside this function are easy to break with a wording change
    /// in any `AppError::*` literal elsewhere.
    #[test]
    fn map_app_error_code_pinned_table() {
        let cases: &[(AppError, &str)] = &[
            (
                AppError::Unauthorized("nope".into()),
                "e.p.did.unauthorized",
            ),
            (AppError::Forbidden("nope".into()), "e.p.did.unauthorized"),
            (
                AppError::QuotaExceeded("upload size cap exceeded".into()),
                "e.p.did.size-exceeded",
            ),
            (
                AppError::QuotaExceeded("monthly quota reached".into()),
                "e.p.did.quota-exceeded",
            ),
            (
                AppError::Conflict("path already in use".into()),
                "e.p.did.path-unavailable",
            ),
            (
                AppError::NotFound("did not found".into()),
                "e.p.did.mnemonic-not-found",
            ),
            // Tagged validations route via `ValidationKind`, not by
            // sniffing the message text — pinning these via the
            // `AppError::validation()` constructor ensures the tag is
            // the load-bearing input.
            (
                AppError::validation(
                    did_hosting_common::server::error::ValidationKind::InvalidLog,
                    "invalid log entry on line 3",
                ),
                "e.p.did.invalid-log",
            ),
            (
                AppError::validation(
                    did_hosting_common::server::error::ValidationKind::InvalidLog,
                    "malformed JSONL body",
                ),
                "e.p.did.invalid-log",
            ),
            (
                AppError::validation(
                    did_hosting_common::server::error::ValidationKind::InvalidPath,
                    "path component reserved",
                ),
                "e.p.did.path-invalid",
            ),
            (
                AppError::validation(
                    did_hosting_common::server::error::ValidationKind::InvalidWitness,
                    "witness signature failed",
                ),
                "e.p.did.witness-invalid",
            ),
            (
                AppError::validation(
                    did_hosting_common::server::error::ValidationKind::Other,
                    "something else broke",
                ),
                "e.p.did.validation-error",
            ),
            // An untagged Validation (no `[tag]` prefix) falls through to
            // the generic code rather than re-routing based on wording.
            (
                AppError::Validation("missing 'mnemonic' in body".into()),
                "e.p.did.validation-error",
            ),
            (AppError::Internal("oops".into()), "e.p.did.internal-error"),
        ];
        for (err, expected) in cases {
            let got = map_app_error_code(err);
            assert_eq!(
                got, *expected,
                "map_app_error_code({err:?}) = {got}, expected {expected}",
            );
        }
    }

    /// `MSG_DID_CHANGE_OWNER` with no `mnemonic` body field is a validation
    /// error — wire-level contract for malformed clients.
    #[tokio::test]
    async fn dispatch_did_op_change_owner_missing_mnemonic_validation() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(
            MSG_DID_CHANGE_OWNER,
            json!({ "new_owner": "did:example:new" }),
        );
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("mnemonic")));
    }

    /// `MSG_DID_CHANGE_OWNER` with no new-owner body field is a validation
    /// error surfacing the canonical camelCase field name. (The success
    /// path below still exercises the legacy snake_case `new_owner` alias.)
    #[tokio::test]
    async fn dispatch_did_op_change_owner_missing_new_owner_validation() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(MSG_DID_CHANGE_OWNER, json!({ "mnemonic": "alpha-beta" }));
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("newOwner")));
    }

    /// Owner can transfer their own DID to another ACL'd DID. Confirms the
    /// success path and the wire-level confirm body shape.
    #[tokio::test]
    async fn dispatch_did_op_change_owner_success() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner-a";
        let new_owner = "did:example:owner-b";
        seed_did(&state, owner, "alpha-beta").await;

        // Both old and new owners must be in the ACL for change-owner to
        // succeed — defense-in-depth.
        store_acl_entry(
            &state.acl_ks,
            &AclEntry {
                did: new_owner.into(),
                role: Role::Owner,
                label: None,
                created_at: 0,
                max_total_size: None,
                max_did_count: None,

                domains: did_hosting_common::server::domain::DomainScope::All,
            },
        )
        .await
        .unwrap();

        let msg = build_msg(
            MSG_DID_CHANGE_OWNER,
            json!({ "mnemonic": "alpha-beta", "new_owner": new_owner }),
        );
        let auth = owner_auth(owner);

        let (typ, body) = dispatch_did_op(&auth, &state, &msg).await.unwrap();
        assert_eq!(typ, MSG_DID_CHANGE_OWNER_CONFIRM);
        assert_eq!(body.get("owner").and_then(|v| v.as_str()), Some(new_owner));

        // Owner index swapped: old owner has none, new owner has one.
        let old_idx = state
            .dids_ks
            .prefix_iter_raw(format!("owner:{owner}:"))
            .await
            .unwrap();
        assert!(old_idx.is_empty(), "old owner index should be cleared");
        let new_idx = state
            .dids_ks
            .prefix_iter_raw(format!("owner:{new_owner}:"))
            .await
            .unwrap();
        assert_eq!(new_idx.len(), 1, "new owner should have one entry");
    }

    /// Cross-owner change-owner is forbidden — only the current owner or an
    /// admin may transfer.
    #[tokio::test]
    async fn dispatch_did_op_change_owner_cross_owner_forbidden() {
        let (state, _dir) = test_state().await;
        seed_did(&state, "did:example:owner-a", "alpha-beta").await;
        store_acl_entry(
            &state.acl_ks,
            &AclEntry {
                did: "did:example:target".into(),
                role: Role::Owner,
                label: None,
                created_at: 0,
                max_total_size: None,
                max_did_count: None,

                domains: did_hosting_common::server::domain::DomainScope::All,
            },
        )
        .await
        .unwrap();

        let msg = build_msg(
            MSG_DID_CHANGE_OWNER,
            json!({ "mnemonic": "alpha-beta", "new_owner": "did:example:target" }),
        );
        let attacker = owner_auth("did:example:attacker");

        let err = dispatch_did_op(&attacker, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
        assert_eq!(map_app_error_code(&err), "e.p.did.unauthorized");
    }

    /// New owner must be in the ACL — prevents transferring a DID to an
    /// identity that can never authenticate to claim it.
    #[tokio::test]
    async fn dispatch_did_op_change_owner_unknown_new_owner_validation() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner-a";
        seed_did(&state, owner, "alpha-beta").await;

        let msg = build_msg(
            MSG_DID_CHANGE_OWNER,
            json!({ "mnemonic": "alpha-beta", "new_owner": "did:example:not-in-acl" }),
        );
        let auth = owner_auth(owner);

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("not in the ACL")));
    }

    // -----------------------------------------------------------------------
    // agent-name/* dispatch
    // -----------------------------------------------------------------------
    //
    // The signed-log happy paths are covered by the `did_ops` unit tests; what
    // these pin is the wiring the REST tests can't see — that each verb is
    // reachable on the DIDComm dispatch table, parses the same body the REST
    // handler does, and lands in the same `did_ops` function with the caller's
    // authorization intact.

    /// Seed a DID whose registry already holds names, so the read verbs have
    /// something to project. `domain` is set explicitly rather than derived
    /// from `did_id` so the expected response is unambiguous.
    async fn seed_did_with_names(
        state: &AppState,
        owner_did: &str,
        mnemonic: &str,
        domain: &str,
        names: &[(&str, bool)],
    ) {
        seed_did(state, owner_did, mnemonic).await;
        let mut record: DidRecord = state
            .dids_ks
            .get(did_key(mnemonic))
            .await
            .unwrap()
            .expect("seeded record");
        record.domain = domain.to_string();
        record.agent_names = names
            .iter()
            .map(
                |(name, enabled)| did_hosting_common::did_ops::AgentNameEntry {
                    name: (*name).to_string(),
                    enabled: *enabled,
                    created_at: 7,
                },
            )
            .collect();
        state
            .dids_ks
            .insert(did_key(mnemonic), &record)
            .await
            .expect("update seeded record");
    }

    /// A body missing a required field is a client error, not a 500 — the
    /// update verb deserialises the REST `AgentNameUpdateRequest` verbatim.
    #[tokio::test]
    async fn dispatch_agent_name_update_missing_name_is_validation() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(
            MSG_AGENT_NAME_UPDATE,
            json!({ "mnemonic": "alpha-beta", "state": "active", "didData": "{}" }),
        );
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("agent-name")));
    }

    /// A `state` outside the spec enum is a client error — the declarative
    /// field only accepts `active` / `parked` (release is `remove`'s job).
    #[tokio::test]
    async fn dispatch_agent_name_update_invalid_state_is_validation() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(
            MSG_AGENT_NAME_UPDATE,
            json!({ "mnemonic": "alpha-beta", "name": "alice", "state": "released", "didData": "{}" }),
        );
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("agent-name")));
    }

    /// `update {state: active}` reaches `did_ops::update_agent_name` for the
    /// slot's owner: a malformed `didData` is rejected there as an invalid
    /// log, proving delegation rather than a dispatch-table dead end. The
    /// pre-cutover `didLog` spelling is accepted as an alias.
    #[tokio::test]
    async fn dispatch_agent_name_update_reaches_did_ops() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner-a";
        seed_did(&state, owner, "alpha-beta").await;

        for field in ["didData", "didLog"] {
            let msg = build_msg(
                MSG_AGENT_NAME_UPDATE,
                json!({ "mnemonic": "alpha-beta", "name": "alice", "state": "active", field: "not-a-valid-log" }),
            );
            let auth = owner_auth(owner);

            let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
            assert_eq!(map_app_error_code(&err), "e.p.did.invalid-log");
        }
    }

    /// A reserved name is refused before any storage read, and surfaces as the
    /// dedicated reserved-name code rather than a generic validation error.
    #[tokio::test]
    async fn dispatch_agent_name_update_reserved_name_rejected() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner-a";
        seed_did(&state, owner, "alpha-beta").await;

        let msg = build_msg(
            MSG_AGENT_NAME_UPDATE,
            json!({ "mnemonic": "alpha-beta", "name": "admin", "state": "active", "didData": "irrelevant" }),
        );
        let auth = owner_auth(owner);

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(
            matches!(
                err,
                AppError::AgentName(did_hosting_common::server::error::AgentNameError::Reserved)
            ),
            "expected a reserved-name error, got {err:?}"
        );
    }

    /// The owner check in `did_ops` is not weakened by the DIDComm path — a
    /// non-owner calling the destructive verb is forbidden.
    #[tokio::test]
    async fn dispatch_agent_name_remove_cross_owner_forbidden() {
        let (state, _dir) = test_state().await;
        seed_did(&state, "did:example:owner-a", "alpha-beta").await;

        let msg = build_msg(
            MSG_AGENT_NAME_REMOVE,
            json!({ "mnemonic": "alpha-beta", "name": "alice", "didLog": "x" }),
        );
        let attacker = owner_auth("did:example:attacker");

        let err = dispatch_did_op(&attacker, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
        assert_eq!(map_app_error_code(&err), "e.p.did.unauthorized");
    }

    /// `list` projects the registry, parked entries included — the whole point
    /// of the verb, since a parked name is absent from the DID document.
    #[tokio::test]
    async fn dispatch_agent_name_list_returns_registry() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner-a";
        seed_did_with_names(
            &state,
            owner,
            "alpha-beta",
            "example.com",
            &[("alice", true), ("parked", false)],
        )
        .await;

        let msg = build_msg(MSG_AGENT_NAME_LIST, json!({ "mnemonic": "alpha-beta" }));
        let auth = owner_auth(owner);

        let (typ, body) = dispatch_did_op(&auth, &state, &msg).await.unwrap();
        assert_eq!(typ, MSG_AGENT_NAME_LIST_RESPONSE);
        assert_eq!(
            body.get("domain").and_then(|v| v.as_str()),
            Some("example.com")
        );
        let names = body
            .get("agentNames")
            .and_then(|v| v.as_array())
            .expect("agentNames array");
        assert_eq!(names.len(), 2);
        assert_eq!(names[0].get("name").and_then(|v| v.as_str()), Some("alice"));
        assert_eq!(
            names[0].get("enabled").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            names[0].get("createdAt").and_then(|v| v.as_str()),
            Some("1970-01-01T00:00:07Z"),
            "createdAt is projected to RFC3339 per agent-name/list/0.1"
        );
        assert_eq!(
            names[1].get("enabled").and_then(|v| v.as_bool()),
            Some(false),
            "a parked name must still be listed"
        );
    }

    /// A DID with no names answers with an empty array, not a missing field —
    /// the caller asked for a list and should not have to tell "none" from
    /// "the host forgot to say".
    #[tokio::test]
    async fn dispatch_agent_name_list_empty_registry_is_empty_array() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner-a";
        seed_did_with_names(&state, owner, "alpha-beta", "example.com", &[]).await;

        let msg = build_msg(MSG_AGENT_NAME_LIST, json!({ "mnemonic": "alpha-beta" }));
        let (_, body) = dispatch_did_op(&owner_auth(owner), &state, &msg)
            .await
            .unwrap();
        assert_eq!(
            body.get("agentNames").and_then(|v| v.as_array()),
            Some(&vec![])
        );
    }

    /// `list` without a `mnemonic` is a validation error, matching the other
    /// mnemonic-scoped arms.
    #[tokio::test]
    async fn dispatch_agent_name_list_missing_mnemonic_is_validation() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(MSG_AGENT_NAME_LIST, json!({}));
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("mnemonic")));
    }

    /// An explicit `domain` that doesn't match the slot's is the same
    /// cross-tenant rejection publish and delete give.
    #[tokio::test]
    async fn dispatch_agent_name_list_domain_mismatch_rejected() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner-a";
        seed_did_with_names(
            &state,
            owner,
            "alpha-beta",
            "example.com",
            &[("alice", true)],
        )
        .await;

        let msg = build_msg(
            MSG_AGENT_NAME_LIST,
            json!({ "mnemonic": "alpha-beta", "domain": "other.example" }),
        );
        let err = dispatch_did_op(&owner_auth(owner), &state, &msg)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("unknown_domain")));
    }

    /// `list` is owner-scoped: another caller cannot enumerate a DID's names.
    #[tokio::test]
    async fn dispatch_agent_name_list_cross_owner_forbidden() {
        let (state, _dir) = test_state().await;
        seed_did_with_names(
            &state,
            "did:example:owner-a",
            "alpha-beta",
            "example.com",
            &[("alice", true)],
        )
        .await;

        let msg = build_msg(MSG_AGENT_NAME_LIST, json!({ "mnemonic": "alpha-beta" }));
        let err = dispatch_did_op(&owner_auth("did:example:attacker"), &state, &msg)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
    }

    /// `check` answers on the explicitly-named domain and reports a free name.
    #[tokio::test]
    async fn dispatch_agent_name_check_available() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(
            MSG_AGENT_NAME_CHECK,
            json!({ "name": "alice", "domain": "example.com" }),
        );
        let auth = owner_auth("did:example:caller");

        let (typ, body) = dispatch_did_op(&auth, &state, &msg).await.unwrap();
        assert_eq!(typ, MSG_AGENT_NAME_CHECK_RESPONSE);
        assert_eq!(body.get("name").and_then(|v| v.as_str()), Some("alice"));
        assert_eq!(
            body.get("domain").and_then(|v| v.as_str()),
            Some("example.com")
        );
        assert_eq!(body.get("available").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(body.get("reserved").and_then(|v| v.as_bool()), Some(false));
    }

    /// A reserved name reports `available: false, reserved: true` rather than
    /// erroring — the UI needs to explain *why* it can't be claimed.
    #[tokio::test]
    async fn dispatch_agent_name_check_reserved() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(
            MSG_AGENT_NAME_CHECK,
            json!({ "name": "admin", "domain": "example.com" }),
        );
        let auth = owner_auth("did:example:caller");

        let (_, body) = dispatch_did_op(&auth, &state, &msg).await.unwrap();
        assert_eq!(body.get("available").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(body.get("reserved").and_then(|v| v.as_bool()), Some(true));
    }

    /// A name already bound on the domain is unavailable — the arm reads the
    /// same `name:{domain}:{name}` index the resolver does.
    #[tokio::test]
    async fn dispatch_agent_name_check_taken() {
        let (state, _dir) = test_state().await;
        state
            .dids_ks
            .insert_raw(
                did_hosting_common::did_ops::agent_name_key("example.com", "alice"),
                b"alpha-beta".to_vec(),
            )
            .await
            .unwrap();

        let msg = build_msg(
            MSG_AGENT_NAME_CHECK,
            json!({ "name": "alice", "domain": "example.com" }),
        );
        let auth = owner_auth("did:example:caller");

        let (_, body) = dispatch_did_op(&auth, &state, &msg).await.unwrap();
        assert_eq!(body.get("available").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(body.get("reserved").and_then(|v| v.as_bool()), Some(false));
    }

    /// With no domain on the wire and no system default configured, `check`
    /// refuses rather than guessing: "is @alice free?" answered against the
    /// wrong domain is a wrong answer, not a lenient one.
    #[tokio::test]
    async fn dispatch_agent_name_check_unresolvable_domain_is_validation() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(MSG_AGENT_NAME_CHECK, json!({ "name": "alice" }));
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
    }

    /// Force-replace via `MSG_DID_REQUEST` with `force: true` succeeds when
    /// the requester is the current owner, replacing the existing slot.
    #[tokio::test]
    async fn dispatch_did_op_did_request_force_replaces_when_owner() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner-a";
        seed_did(&state, owner, "shared-path").await;
        // Seed log content so we can verify it gets cleared.
        state
            .dids_ks
            .insert_raw(
                did_hosting_common::did_ops::content_log_key("shared-path"),
                b"old log".to_vec(),
            )
            .await
            .unwrap();

        let msg = build_msg(
            MSG_DID_REQUEST,
            json!({ "path": "shared-path", "reserve": true, "force": true }),
        );
        let auth = owner_auth(owner);

        let (typ, body) = dispatch_did_op(&auth, &state, &msg).await.unwrap();
        assert_eq!(typ, MSG_DID_OFFER);
        assert_eq!(body.get("reserved").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            body.get("record")
                .and_then(|r| r.get("mnemonic"))
                .and_then(|v| v.as_str()),
            Some("shared-path")
        );

        // Old log content has been wiped; new record has version_count 0.
        let log = state
            .dids_ks
            .get_raw(did_hosting_common::did_ops::content_log_key("shared-path"))
            .await
            .unwrap();
        assert!(log.is_none(), "old log content should be wiped");
        let record: DidRecord = state
            .dids_ks
            .get(did_key("shared-path"))
            .await
            .unwrap()
            .expect("record present");
        assert_eq!(record.version_count, 0);
        assert_eq!(record.owner, owner);
    }

    /// Force-replace by a different owner is forbidden — `force` only works
    /// for admin or current owner of the existing path.
    #[tokio::test]
    async fn dispatch_did_op_did_request_force_forbidden_for_other_owner() {
        let (state, _dir) = test_state().await;
        seed_did(&state, "did:example:owner-a", "shared-path").await;

        let msg = build_msg(
            MSG_DID_REQUEST,
            json!({ "path": "shared-path", "reserve": true, "force": true }),
        );
        let auth = owner_auth("did:example:owner-b");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
    }

    /// Admins can force-replace any DID — the caller becomes the new owner.
    #[tokio::test]
    async fn dispatch_did_op_did_request_force_admin_takes_ownership() {
        let (state, _dir) = test_state().await;
        seed_did(&state, "did:example:owner-a", "shared-path").await;

        let admin = admin_auth("did:example:admin");
        let msg = build_msg(
            MSG_DID_REQUEST,
            json!({ "path": "shared-path", "reserve": true, "force": true }),
        );

        let (typ, _body) = dispatch_did_op(&admin, &state, &msg).await.unwrap();
        assert_eq!(typ, MSG_DID_OFFER);

        let record: DidRecord = state
            .dids_ks
            .get(did_key("shared-path"))
            .await
            .unwrap()
            .expect("record present");
        assert_eq!(record.owner, "did:example:admin");
    }

    // -----------------------------------------------------------------
    // run_trust_tasks_envelope tests (v0.7.0)
    //
    // The DIDComm-side dispatch was previously uncovered because the
    // outer `handle_trust_tasks_envelope` takes `HandlerContext`, which
    // an in-process test can't build. The `run_*` extraction lets us
    // exercise the unpack + dispatch + repack logic without an
    // ATM-backed context.
    // -----------------------------------------------------------------

    const CONTROL: &str = "did:webvh:test:control.example.com";

    /// `test_state` with the production verifier over the local `did:key`
    /// resolver, so signed envelopes verify without I/O.
    async fn signing_state() -> (AppState, tempfile::TempDir) {
        let (mut state, dir) = test_state().await;
        state.trust_tasks_verifier = Some(Arc::new(TransportBoundVerifier::with_resolver(
            Arc::new(DidKeyResolver),
        )));
        (state, dir)
    }

    async fn seed_role(state: &AppState, did: &str, role: Role) {
        store_acl_entry(
            &state.acl_ks,
            &AclEntry {
                did: did.into(),
                role,
                label: None,
                created_at: 1_700_000_000,
                max_total_size: None,
                max_did_count: None,
                domains: did_hosting_common::server::domain::DomainScope::All,
            },
        )
        .await
        .unwrap();
    }

    /// An unsigned request document from `issuer` to the control plane.
    fn request_doc(type_uri: &str, issuer: Option<&str>, payload: Value) -> Value {
        let mut doc = json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": type_uri,
            "recipient": CONTROL,
            // Whole seconds, `Z`: the form the typed document re-serialises
            // to, so the signature over this JSON still covers it.
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": payload,
        });
        if let Some(issuer) = issuer {
            doc["issuer"] = json!(issuer);
        }
        doc
    }

    async fn sign(doc: Value, signer: &affinidi_tdk::secrets_resolver::secrets::Secret) -> Value {
        crate::signing::sign_trust_task_document(doc, signer)
            .await
            .expect("sign")
    }

    fn envelope(body: Value) -> Message {
        // A fresh DIDComm message id each time: replay protection must not
        // depend on the transport's id.
        Message::build(
            uuid::Uuid::new_v4().to_string(),
            trust_tasks_didcomm::ENVELOPE_TYPE.to_string(),
            body,
        )
        .finalize()
    }

    async fn dispatch_envelope(state: &AppState, sender: &str, body: Value) -> Value {
        let (resp_type, resp_body) =
            super::run_trust_tasks_envelope(state, sender, &envelope(body))
                .await
                .expect("dispatch returns Ok")
                .expect("envelope produces a response");
        assert_eq!(resp_type, trust_tasks_didcomm::ENVELOPE_TYPE);
        resp_body
    }

    fn list_payload() -> Value {
        json!({})
    }

    /// Happy path: an ACL read (`acl/list/0.1`) signed by the Admin it names.
    #[tokio::test]
    async fn trust_tasks_envelope_happy_path_list_returns_handled_response() {
        let (state, _dir) = signing_state().await;
        let (admin, admin_key) = crate::signing::test_util::did_key_signer(&[21u8; 32]);
        seed_role(&state, &admin, Role::Admin).await;

        let doc = sign(
            request_doc(
                "https://trusttasks.org/spec/acl/list/0.1",
                Some(&admin),
                list_payload(),
            ),
            &admin_key,
        )
        .await;
        let resp = dispatch_envelope(&state, &admin, doc).await;

        let inner_type = resp["type"].as_str().unwrap();
        assert!(
            inner_type.ends_with("/acl/list/0.1#response"),
            "expected acl/list response type, got {inner_type}"
        );
        let entries = resp["payload"]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["subject"], admin.as_str());
    }

    /// An ACL read is privileged: without a proof it is refused even from an
    /// Admin sender.
    #[tokio::test]
    async fn trust_tasks_envelope_unsigned_acl_read_is_refused() {
        let (state, _dir) = signing_state().await;
        let (admin, _) = crate::signing::test_util::did_key_signer(&[21u8; 32]);
        seed_role(&state, &admin, Role::Admin).await;

        let doc = request_doc(
            "https://trusttasks.org/spec/acl/list/0.1",
            Some(&admin),
            list_payload(),
        );
        let resp = dispatch_envelope(&state, &admin, doc).await;
        assert_eq!(resp["payload"]["code"], "proofRequired", "{resp}");
    }

    #[tokio::test]
    async fn trust_tasks_envelope_malformed_inner_body_returns_routed_error() {
        let (state, _dir) = test_state().await;
        // Body is a valid JSON value but not a TrustTask document.
        let msg = build_msg(
            trust_tasks_didcomm::ENVELOPE_TYPE,
            json!({"not": "a-trust-task"}),
        );
        let (resp_type, resp_body) =
            super::run_trust_tasks_envelope(&state, "did:example:admin", &msg)
                .await
                .expect("dispatch returns Ok")
                .expect("malformed body emits an error doc");

        assert_eq!(resp_type, trust_tasks_didcomm::ENVELOPE_TYPE);
        assert_eq!(
            resp_body["type"].as_str().unwrap(),
            did_hosting_common::server::trust_tasks::framework_error_type_uri().to_string()
        );
        // trust-tasks-rs 0.2 serialises StandardCode in camelCase
        // (`malformedRequest`); it still reads the 0.1 snake_case form on
        // inbound, so peers on either version interoperate.
        assert_eq!(resp_body["payload"]["code"], "malformedRequest");
    }

    /// A signed DID-management op (`did/check-name`) in the envelope is bridged
    /// to `dispatch_did_op` and answered to its signer.
    #[tokio::test]
    async fn trust_tasks_envelope_bridges_did_management() {
        let (state, _dir) = signing_state().await;
        let (admin, admin_key) = crate::signing::test_util::did_key_signer(&[22u8; 32]);
        seed_role(&state, &admin, Role::Admin).await;

        let doc = sign(
            request_doc(
                MSG_DID_REQUEST,
                Some(&admin),
                json!({ "path": "bob", "reserve": false }),
            ),
            &admin_key,
        )
        .await;
        let resp = dispatch_envelope(&state, &admin, doc).await;

        assert_eq!(
            resp["type"],
            "https://trusttasks.org/spec/did-management/did/check-name/0.1#response"
        );
        assert_eq!(resp["payload"]["available"], true);
        assert_eq!(resp["issuer"], CONTROL);
        assert_eq!(resp["recipient"], admin.as_str());
    }

    /// The unsigned form of the same op — what every DIDComm client sent before
    /// — is refused, and refused *before* the ACL is consulted, so an Admin
    /// sender name on the envelope buys nothing.
    #[tokio::test]
    async fn trust_tasks_envelope_unsigned_did_management_is_refused() {
        let (state, _dir) = signing_state().await;
        let admin = "did:example:admin";
        seed_role(&state, admin, Role::Admin).await;
        seed_did(&state, admin, "victim").await;

        let doc = request_doc(MSG_DELETE, Some(admin), json!({ "mnemonic": "victim" }));
        let resp = dispatch_envelope(&state, admin, doc).await;
        assert_eq!(resp["payload"]["code"], "proofRequired", "{resp}");
        assert!(
            state
                .dids_ks
                .get::<did_hosting_common::did_ops::DidRecord>(did_key("victim"))
                .await
                .unwrap()
                .is_some(),
            "nothing was deleted"
        );
    }

    /// A validly-signed document from one DID, delivered under another DID's
    /// name (an Admin's), is refused: the proof's issuer and the transport's
    /// reported sender disagree, and the reported sender is never enough.
    #[tokio::test]
    async fn trust_tasks_envelope_proof_from_someone_else_is_refused() {
        let (state, _dir) = signing_state().await;
        let admin = "did:example:admin";
        seed_role(&state, admin, Role::Admin).await;
        seed_did(&state, admin, "victim").await;
        let (attacker, attacker_key) = crate::signing::test_util::did_key_signer(&[66u8; 32]);

        let doc = sign(
            request_doc(MSG_DELETE, Some(&attacker), json!({ "mnemonic": "victim" })),
            &attacker_key,
        )
        .await;
        let resp = dispatch_envelope(&state, admin, doc).await;
        assert_eq!(resp["payload"]["code"], "permissionDenied", "{resp}");
        assert!(
            state
                .dids_ks
                .get::<did_hosting_common::did_ops::DidRecord>(did_key("victim"))
                .await
                .unwrap()
                .is_some(),
            "nothing was deleted"
        );
    }

    /// The `acl/grant` shape that would otherwise mint a permanent Admin: a
    /// valid proof by the attacker, no in-band `issuer`, an Admin's name on the
    /// envelope. Refused — an issuer-less proof verifies as nobody.
    #[tokio::test]
    async fn trust_tasks_envelope_issuerless_grant_under_admin_name_is_refused() {
        let (state, _dir) = signing_state().await;
        let admin = "did:example:admin";
        seed_role(&state, admin, Role::Admin).await;
        let (attacker, attacker_key) = crate::signing::test_util::did_key_signer(&[66u8; 32]);

        // Sign with an issuer (the signer insists), then strip it: the proof
        // is still a valid signature by the attacker over the rest.
        let mut signed = sign(
            request_doc(
                "https://trusttasks.org/spec/acl/grant/0.1",
                Some(&attacker),
                json!({ "entry": { "subject": attacker, "role": "admin" } }),
            ),
            &attacker_key,
        )
        .await;
        signed.as_object_mut().unwrap().remove("issuer");
        let resp = dispatch_envelope(&state, admin, signed).await;
        assert_ne!(
            resp["type"].as_str().unwrap_or(""),
            "https://trusttasks.org/spec/acl/grant/0.1#response",
            "{resp}"
        );
        assert!(
            did_hosting_common::server::acl::get_acl_entry(&state.acl_ks, &attacker)
                .await
                .unwrap()
                .is_none(),
            "no ACL entry was created for the attacker"
        );
    }

    /// Replaying a captured signed document is refused, even wrapped in a fresh
    /// DIDComm message — the gate keys on the proven issuer and the document
    /// id, both covered by the proof. Uses a destructive op because that is
    /// what replay protection exists for.
    #[tokio::test]
    async fn trust_tasks_envelope_replay_is_refused() {
        let (state, _dir) = signing_state().await;
        let (admin, admin_key) = crate::signing::test_util::did_key_signer(&[23u8; 32]);
        seed_role(&state, &admin, Role::Admin).await;
        seed_did(&state, &admin, "replayed").await;

        let doc = sign(
            request_doc(MSG_DELETE, Some(&admin), json!({ "mnemonic": "replayed" })),
            &admin_key,
        )
        .await;

        let first = dispatch_envelope(&state, &admin, doc.clone()).await;
        assert_eq!(
            first["type"], MSG_DELETE_CONFIRM,
            "the first delivery must be handled, not rejected: {first}"
        );

        let replayed = dispatch_envelope(&state, &admin, doc).await;
        assert_eq!(replayed["payload"]["code"], "idConflict", "{replayed}");
    }

    fn register_payload() -> Value {
        json!({
            "public_url": "https://edge.example",
            "label": "edge",
            "trust_task_capable": true,
        })
    }

    /// A server registers only on its own signature. Unsigned, the document is
    /// refused even when the reported sender holds the Service role — the
    /// registration would otherwise enrol the sender as a sync target for every
    /// tenant's DIDs on a name alone.
    #[tokio::test]
    async fn unsigned_server_registration_is_refused() {
        let (state, _dir) = signing_state().await;
        let edge = "did:example:edge";
        seed_role(&state, edge, Role::Service).await;

        let doc = request_doc(MSG_SERVER_REGISTER, Some(edge), register_payload());
        let resp = dispatch_envelope(&state, edge, doc).await;
        assert_eq!(resp["payload"]["code"], "proofRequired", "{resp}");
        assert!(
            crate::registry::get_instance(&state.registry_ks, &edge.replace(':', "_"))
                .await
                .unwrap()
                .is_none(),
            "no instance was registered"
        );
    }

    /// The normal flow: a Service-role edge signs its registration and is
    /// registered and acknowledged.
    #[tokio::test]
    async fn signed_server_registration_is_accepted() {
        let (state, _dir) = signing_state().await;
        let (edge, edge_key) = crate::signing::test_util::did_key_signer(&[41u8; 32]);
        seed_role(&state, &edge, Role::Service).await;

        let doc = sign(
            request_doc(MSG_SERVER_REGISTER, Some(&edge), register_payload()),
            &edge_key,
        )
        .await;
        let resp = dispatch_envelope(&state, &edge, doc).await;
        assert_eq!(resp["type"], MSG_SERVER_REGISTER_ACK, "{resp}");
        assert!(
            crate::registry::get_instance(&state.registry_ks, &edge.replace(':', "_"))
                .await
                .unwrap()
                .is_some(),
            "the signing edge was registered"
        );
    }

    /// A signed pong from a DID without the Service role changes nothing: the
    /// registry's liveness view is not writable by any DID that can sign.
    #[tokio::test]
    async fn health_pong_from_a_non_service_signer_is_ignored() {
        use crate::registry::{ServiceInstance, ServiceStatus, ServiceType};

        let (state, _dir) = signing_state().await;
        let (edge, edge_key) = crate::signing::test_util::did_key_signer(&[42u8; 32]);
        seed_role(&state, &edge, Role::Owner).await;
        let instance_id = edge.replace(':', "_");
        crate::registry::register_instance(
            &state.registry_ks,
            &ServiceInstance {
                instance_id: instance_id.clone(),
                service_type: ServiceType::Server,
                label: None,
                url: "https://edge.example".into(),
                status: ServiceStatus::Unreachable,
                last_health_check: None,
                registered_at: 0,
                metadata: json!({ "did": edge }),
                enabled_methods: vec![],
                served_domains: vec![],
                protocol_version: "1.0".into(),
                advertised_services: None,
                services_checked_at: None,
                trust_task_capable: true,
                sync_batch_capable: false,
                last_inbound_transport: None,
                last_inbound_at: None,
                last_outbound_transport: None,
                last_outbound_at: None,
            },
        )
        .await
        .unwrap();

        let doc = sign(
            request_doc(MSG_HEALTH_PONG, Some(&edge), json!({ "status": "ok" })),
            &edge_key,
        )
        .await;
        let out = super::run_trust_tasks_envelope(&state, &edge, &envelope(doc))
            .await
            .expect("dispatch ok");
        assert!(out.is_none(), "a pong is terminal");
        let inst = crate::registry::get_instance(&state.registry_ks, &instance_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(inst.status, ServiceStatus::Unreachable, "status unchanged");
    }

    #[tokio::test]
    async fn trust_tasks_envelope_returns_none_when_server_did_unconfigured() {
        // server_did = None — the dispatch can't run §7.2 recipient
        // enforcement and bubbles a DIDCommServiceError::Internal.
        let (mut state, _dir) = test_state().await;
        let cfg = AppConfig {
            features: state.config.features.clone(),
            server_did: None,
            mediator_did: None,
            public_url: state.config.public_url.clone(),
            did_hosting_url: state.config.did_hosting_url.clone(),
            server: state.config.server.clone(),
            log: state.config.log.clone(),
            store: state.config.store.clone(),
            auth: state.config.auth.clone(),
            secrets: state.config.secrets.clone(),
            vta: state.config.vta.clone(),
            registry: state.config.registry.clone(),
            trust_tasks: state.config.trust_tasks.clone(),
            hosting: state.config.hosting.clone(),
            identity: Default::default(),
            config_path: state.config.config_path.clone(),
        };
        state.config = Arc::new(cfg);

        let msg = envelope(request_doc(
            "https://trusttasks.org/spec/acl/list/0.1",
            Some("did:example:admin"),
            list_payload(),
        ));
        let err = super::run_trust_tasks_envelope(&state, "did:example:admin", &msg)
            .await
            .expect_err("missing server_did should fail");
        match err {
            DIDCommServiceError::Internal(msg) => {
                assert!(msg.contains("server_did"), "operator-actionable: {msg}");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // Signed end-to-end coverage: real Data Integrity proofs over
    // did:key material, verified by the production
    // `TransportBoundVerifier` — the task-consent request→decision
    // round trip and REQUIRED-spec (`acl/grant`) envelope dispatch.
    // -----------------------------------------------------------------

    use affinidi_data_integrity::DidKeyResolver;
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use did_hosting_common::did_hosting_tasks::{
        TASK_ADMIN_ACTION_1_0, TASK_CONSENT_DECISION_0_1, TASK_CONSENT_DECISION_RESPONSE_0_1,
    };
    use did_hosting_common::server::trust_tasks::TransportBoundVerifier;

    use crate::routes::task_consent::{build_signed_request_document, wire_digest};
    use crate::server::PendingConfirm;
    use crate::signing::test_util::did_key_signer;

    /// The action text used across the round-trip tests.
    const CONSENT_ACTION: &str = "Rotate the registry signing key";

    /// `test_state` with `server_did` pinned to `control_did` and the
    /// production DI verifier over `did:key` wired in — the decision
    /// handler refuses everything without a verifier, and its audience
    /// check compares the decision's `recipient` against `server_did`.
    async fn consent_state(control_did: &str) -> (AppState, tempfile::TempDir) {
        let (mut state, dir) = test_state().await;
        let mut config = (*state.config).clone();
        config.server_did = Some(control_did.to_string());
        state.config = Arc::new(config);
        state.trust_tasks_verifier = Some(Arc::new(TransportBoundVerifier::with_resolver(
            Arc::new(DidKeyResolver),
        )));
        (state, dir)
    }

    /// Mint the signed request leg exactly as `POST /api/task-consent/request`
    /// does — same digest, same builder, same signer shape — and return
    /// `(request_document, challenge, digest)`.
    async fn minted_request(
        control_did: &str,
        control_signer: &Secret,
        holder_did: &str,
    ) -> (Value, String, String) {
        let task_type = TASK_ADMIN_ACTION_1_0.as_str();
        let challenge = "00112233445566778899aabbccddeeff".to_string();
        let digest = wire_digest(task_type, &json!({ "action": CONSENT_ACTION }), &challenge)
            .expect("wire digest");
        let document = build_signed_request_document(
            control_did,
            control_signer,
            holder_did,
            "did:example:admin",
            CONSENT_ACTION,
            task_type,
            &challenge,
            &digest,
            "2026-07-29T00:00:00Z",
            "2026-07-29T00:01:00Z",
        )
        .await
        .expect("build + sign request");
        (document, challenge, digest)
    }

    /// Wallet-side decision: an unsigned `task-consent/decision/0.1`
    /// document echoing `challenge` + `digest`.
    fn unsigned_decision(
        issuer_did: Option<&str>,
        recipient: &str,
        challenge: &str,
        digest: &str,
        decision: &str,
    ) -> Value {
        let mut doc = json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": TASK_CONSENT_DECISION_0_1.as_str(),
            "recipient": recipient,
            "issuedAt": "2026-07-29T00:00:30Z",
            "payload": {
                "challenge": challenge,
                "payloadDigest": digest,
                "decision": decision,
            },
        });
        if let Some(issuer) = issuer_did {
            doc["issuer"] = json!(issuer);
        }
        doc
    }

    /// [`unsigned_decision`], signed with the holder's key via the same
    /// signing entry point the production code uses.
    async fn signed_decision(
        signer: &Secret,
        issuer_did: &str,
        recipient: &str,
        challenge: &str,
        digest: &str,
        decision: &str,
    ) -> Value {
        crate::signing::sign_trust_task_document(
            unsigned_decision(Some(issuer_did), recipient, challenge, digest, decision),
            signer,
        )
        .await
        .expect("sign decision")
    }

    /// Park a pending consent exactly as the REST route does; the
    /// returned receiver resolves with the wallet's decision.
    async fn park_pending(
        state: &AppState,
        challenge: &str,
        holder_did: &str,
        digest: &str,
    ) -> tokio::sync::oneshot::Receiver<bool> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        state.pending_confirms.lock().await.insert(
            challenge.to_string(),
            PendingConfirm {
                holder_did: holder_did.to_string(),
                expected_digest: digest.to_string(),
                tx,
            },
        );
        rx
    }

    /// Drive a decision document through the handler and assert it is
    /// refused *silently and completely*: no acknowledgement, the parked
    /// entry survives for the legitimate wallet, and the channel never
    /// fires.
    async fn assert_decision_refused(
        state: &AppState,
        sender: &str,
        decision: Value,
        rx: &mut tokio::sync::oneshot::Receiver<bool>,
        challenge: &str,
        why: &str,
    ) {
        let msg = build_msg(TASK_CONSENT_DECISION_0_1.as_str(), decision);
        let resp = super::run_consent_decision(state, sender, &msg)
            .await
            .expect("refusals are silent, not transport errors");
        assert!(resp.is_none(), "{why}: must not be acknowledged");
        assert!(
            state.pending_confirms.lock().await.contains_key(challenge),
            "{why}: the pending entry must survive"
        );
        assert!(
            matches!(
                rx.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ),
            "{why}: the parked request must not resolve"
        );
    }

    /// The full signed round trip the retired deferral asked for: the
    /// control plane mints + signs the request leg (through the exact
    /// production builder the REST route uses), a conforming wallet
    /// verifies it before rendering — proof verifies AND `issuer` is the
    /// DID of `proof.verificationMethod` — then signs a decision echoing
    /// the *verified document's* challenge + payloadDigest, and the
    /// inbound handler verifies the decision and resolves the parked
    /// request.
    #[tokio::test]
    async fn task_consent_signed_round_trip_approve() {
        use trust_tasks_rs::ProofVerifier;

        let (control_did, control_signer) = did_key_signer(&[21u8; 32]);
        let (holder_did, holder_signer) = did_key_signer(&[22u8; 32]);
        let (state, _dir) = consent_state(&control_did).await;

        // ── Request leg, signed by the control DID.
        let (request, challenge, digest) =
            minted_request(&control_did, &control_signer, &holder_did).await;

        // ── Wallet side: verify before rendering `note`, with the same
        // verifier construction a conforming approver uses.
        let parsed: trust_tasks_rs::TrustTask<Value> =
            serde_json::from_value(request).expect("request parses as a TrustTask");
        TransportBoundVerifier::with_resolver(Arc::new(DidKeyResolver))
            .verify(&parsed)
            .await
            .expect("wallet verifies the request proof");
        assert_eq!(parsed.issuer.as_deref(), Some(control_did.as_str()));
        // The wallet echoes what the *verified document* carries — not
        // anything from the transport envelope.
        let echo_challenge = parsed.payload["challenge"].as_str().unwrap().to_string();
        let echo_digest = parsed.payload["payloadDigest"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(echo_challenge, challenge);
        assert_eq!(echo_digest, digest);

        // ── The REST route parks the pending entry keyed by challenge.
        let mut rx = park_pending(&state, &challenge, &holder_did, &digest).await;

        // ── Decision leg: holder signs an approve; the handler verifies
        // and resolves the parked request.
        let decision = signed_decision(
            &holder_signer,
            &holder_did,
            &control_did,
            &echo_challenge,
            &echo_digest,
            "approve",
        )
        .await;
        let msg = build_msg(TASK_CONSENT_DECISION_0_1.as_str(), decision);
        let (resp_type, ack) = super::run_consent_decision(&state, &holder_did, &msg)
            .await
            .expect("handler ok")
            .expect("an acknowledgement is returned");

        assert_eq!(resp_type, TASK_CONSENT_DECISION_RESPONSE_0_1.as_str());
        assert_eq!(ack["status"], "granted");
        assert_eq!(ack["approvals"], 1);
        assert_eq!(ack["payloadDigest"], digest.as_str());
        assert!(rx.try_recv().expect("decision delivered"), "approved");
        assert!(
            state.pending_confirms.lock().await.is_empty(),
            "pending entry consumed"
        );
    }

    /// Same round trip, denying: the parked request resolves `false` and
    /// the spec `#response` says `denied` with zero approvals.
    #[tokio::test]
    async fn task_consent_signed_round_trip_deny() {
        let (control_did, control_signer) = did_key_signer(&[23u8; 32]);
        let (holder_did, holder_signer) = did_key_signer(&[24u8; 32]);
        let (state, _dir) = consent_state(&control_did).await;
        let (_request, challenge, digest) =
            minted_request(&control_did, &control_signer, &holder_did).await;
        let mut rx = park_pending(&state, &challenge, &holder_did, &digest).await;

        let decision = signed_decision(
            &holder_signer,
            &holder_did,
            &control_did,
            &challenge,
            &digest,
            "deny",
        )
        .await;
        let msg = build_msg(TASK_CONSENT_DECISION_0_1.as_str(), decision);
        let (_, ack) = super::run_consent_decision(&state, &holder_did, &msg)
            .await
            .expect("handler ok")
            .expect("an acknowledgement is returned");

        assert_eq!(ack["status"], "denied");
        assert_eq!(ack["approvals"], 0);
        assert!(!rx.try_recv().expect("decision delivered"), "denied");
    }

    /// An unsigned decision is refused outright — the proof, not the
    /// authcrypt session, is the authorization.
    #[tokio::test]
    async fn task_consent_decision_without_proof_is_refused() {
        let (control_did, control_signer) = did_key_signer(&[25u8; 32]);
        let (holder_did, _holder_signer) = did_key_signer(&[26u8; 32]);
        let (state, _dir) = consent_state(&control_did).await;
        let (_request, challenge, digest) =
            minted_request(&control_did, &control_signer, &holder_did).await;
        let mut rx = park_pending(&state, &challenge, &holder_did, &digest).await;

        let decision = unsigned_decision(
            Some(&holder_did),
            &control_did,
            &challenge,
            &digest,
            "approve",
        );
        assert_decision_refused(
            &state,
            &holder_did,
            decision,
            &mut rx,
            &challenge,
            "unsigned decision",
        )
        .await;
    }

    /// Flipping the decision *after* signing must fail proof
    /// verification — the signature covers the payload, so a deny cannot
    /// be laundered into an approve in transit.
    #[tokio::test]
    async fn task_consent_decision_tampered_after_signing_is_refused() {
        let (control_did, control_signer) = did_key_signer(&[27u8; 32]);
        let (holder_did, holder_signer) = did_key_signer(&[28u8; 32]);
        let (state, _dir) = consent_state(&control_did).await;
        let (_request, challenge, digest) =
            minted_request(&control_did, &control_signer, &holder_did).await;
        let mut rx = park_pending(&state, &challenge, &holder_did, &digest).await;

        let mut decision = signed_decision(
            &holder_signer,
            &holder_did,
            &control_did,
            &challenge,
            &digest,
            "deny",
        )
        .await;
        decision["payload"]["decision"] = json!("approve");
        assert_decision_refused(
            &state,
            &holder_did,
            decision,
            &mut rx,
            &challenge,
            "tampered decision",
        )
        .await;
    }

    /// A decision signed consistently by a DID that is not the holder the
    /// request was addressed to is refused at the pending-entry binding
    /// — a valid signature from the wrong party authorizes nothing.
    #[tokio::test]
    async fn task_consent_decision_from_wrong_holder_is_refused() {
        let (control_did, control_signer) = did_key_signer(&[29u8; 32]);
        let (holder_did, _holder_signer) = did_key_signer(&[30u8; 32]);
        let (attacker_did, attacker_signer) = did_key_signer(&[66u8; 32]);
        let (state, _dir) = consent_state(&control_did).await;
        let (_request, challenge, digest) =
            minted_request(&control_did, &control_signer, &holder_did).await;
        let mut rx = park_pending(&state, &challenge, &holder_did, &digest).await;

        // Well-formed and properly signed — just by the wrong DID.
        let decision = signed_decision(
            &attacker_signer,
            &attacker_did,
            &control_did,
            &challenge,
            &digest,
            "approve",
        )
        .await;
        assert_decision_refused(
            &state,
            &attacker_did,
            decision,
            &mut rx,
            &challenge,
            "wrong holder",
        )
        .await;
    }

    /// The proof's `verificationMethod` DID must equal the authcrypt
    /// sender — a decision whose proof is someone else's key, delivered
    /// over a session authenticated as the holder, is refused at the
    /// proof↔sender binding before verification is even attempted.
    #[tokio::test]
    async fn task_consent_decision_proof_key_mismatching_sender_is_refused() {
        let (control_did, control_signer) = did_key_signer(&[31u8; 32]);
        let (holder_did, _holder_signer) = did_key_signer(&[32u8; 32]);
        let (attacker_did, attacker_signer) = did_key_signer(&[67u8; 32]);
        let (state, _dir) = consent_state(&control_did).await;
        let (_request, challenge, digest) =
            minted_request(&control_did, &control_signer, &holder_did).await;
        let mut rx = park_pending(&state, &challenge, &holder_did, &digest).await;

        // Signed by the attacker's key, but arriving on a transport
        // session the service attributes to the holder.
        let decision = signed_decision(
            &attacker_signer,
            &attacker_did,
            &control_did,
            &challenge,
            &digest,
            "approve",
        )
        .await;
        assert_decision_refused(
            &state,
            &holder_did,
            decision,
            &mut rx,
            &challenge,
            "proof key != sender",
        )
        .await;
    }

    /// A decision echoing a digest other than the one the request carried
    /// answers a different question — refused, and the legitimate pending
    /// entry survives.
    #[tokio::test]
    async fn task_consent_decision_digest_mismatch_is_refused() {
        let (control_did, control_signer) = did_key_signer(&[33u8; 32]);
        let (holder_did, holder_signer) = did_key_signer(&[34u8; 32]);
        let (state, _dir) = consent_state(&control_did).await;
        let (_request, challenge, digest) =
            minted_request(&control_did, &control_signer, &holder_did).await;
        let mut rx = park_pending(&state, &challenge, &holder_did, &digest).await;

        // A digest over a *different* action than the one we asked about.
        let other_digest = wire_digest(
            TASK_ADMIN_ACTION_1_0.as_str(),
            &json!({ "action": "Delete every hosted DID" }),
            &challenge,
        )
        .expect("wire digest");
        let decision = signed_decision(
            &holder_signer,
            &holder_did,
            &control_did,
            &challenge,
            &other_digest,
            "approve",
        )
        .await;
        assert_decision_refused(
            &state,
            &holder_did,
            decision,
            &mut rx,
            &challenge,
            "digest mismatch",
        )
        .await;
    }

    /// Audience binding: a decision addressed to another executor must
    /// not resolve a pending consent here, even when everything else
    /// checks out.
    #[tokio::test]
    async fn task_consent_decision_for_other_executor_is_refused() {
        let (control_did, control_signer) = did_key_signer(&[35u8; 32]);
        let (holder_did, holder_signer) = did_key_signer(&[36u8; 32]);
        let (other_executor, _) = did_key_signer(&[68u8; 32]);
        let (state, _dir) = consent_state(&control_did).await;
        let (_request, challenge, digest) =
            minted_request(&control_did, &control_signer, &holder_did).await;
        let mut rx = park_pending(&state, &challenge, &holder_did, &digest).await;

        let decision = signed_decision(
            &holder_signer,
            &holder_did,
            &other_executor,
            &challenge,
            &digest,
            "approve",
        )
        .await;
        assert_decision_refused(
            &state,
            &holder_did,
            decision,
            &mut rx,
            &challenge,
            "wrong recipient",
        )
        .await;
    }

    /// A decision for a challenge nothing is parked on (stale, lapsed,
    /// or already resolved) is silently ignored.
    #[tokio::test]
    async fn task_consent_decision_unknown_challenge_is_refused() {
        let (control_did, _control_signer) = did_key_signer(&[37u8; 32]);
        let (holder_did, holder_signer) = did_key_signer(&[38u8; 32]);
        let (state, _dir) = consent_state(&control_did).await;

        let decision = signed_decision(
            &holder_signer,
            &holder_did,
            &control_did,
            "ffffffffffffffffffffffffffffffff",
            "not-a-real-digest",
            "approve",
        )
        .await;
        let msg = build_msg(TASK_CONSENT_DECISION_0_1.as_str(), decision);
        let resp = super::run_consent_decision(&state, &holder_did, &msg)
            .await
            .expect("silent refusal");
        assert!(resp.is_none(), "unknown challenge must not be acknowledged");
    }

    // ── Signed REQUIRED-spec envelope dispatch (`acl/grant/0.1`) ──────

    /// Build an (unsigned) typed `acl/grant/0.1` document granting
    /// `subject` the `owner` role, issued by `admin_did` to this test
    /// control plane.
    fn unsigned_grant_doc(admin_did: &str, subject: &str) -> Value {
        use trust_tasks_rs::specs::acl::grant::v0_1 as grant;
        let entry: grant::AclEntry = grant::AclEntry::builder()
            .subject(subject)
            .role("owner")
            .scopes(vec![])
            .label(Some(
                "signed e2e grant"
                    .parse::<grant::AclEntryLabel>()
                    .expect("label"),
            ))
            .ext(
                serde_json::from_value::<Option<grant::Ext>>(json!({
                    "vnd.affinidi.webvh": { "domains": { "kind": "all" } }
                }))
                .expect("webvh ext parses"),
            )
            .try_into()
            .expect("e2e ACL entry is well formed");
        let payload: grant::Payload = grant::Payload::builder()
            .entry(entry)
            .reason(Some(
                "signed end-to-end grant"
                    .parse::<grant::PayloadReason>()
                    .expect("reason"),
            ))
            .try_into()
            .expect("e2e grant payload is well formed");
        let mut doc = trust_tasks_rs::TrustTask::for_payload(
            format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            payload,
        );
        doc.issuer = Some(admin_did.into());
        doc.recipient = Some("did:webvh:test:control.example.com".into());
        doc.issued_at = Some(chrono::Utc::now());
        serde_json::to_value(&doc).expect("grant document serialises")
    }

    /// `test_state` + the production `did:key` verifier + `admin_did`
    /// seeded as Admin, for the REQUIRED-spec envelope tests.
    async fn grant_state(admin_did: &str) -> (AppState, tempfile::TempDir) {
        let (mut state, dir) = test_state().await;
        state.trust_tasks_verifier = Some(Arc::new(TransportBoundVerifier::with_resolver(
            Arc::new(DidKeyResolver),
        )));
        assert!(
            state.config.trust_tasks.enforce_proofs,
            "strict proofs are the default"
        );
        store_acl_entry(
            &state.acl_ks,
            &AclEntry {
                did: admin_did.into(),
                role: Role::Admin,
                label: None,
                created_at: 1_700_000_000,
                max_total_size: None,
                max_did_count: None,
                domains: did_hosting_common::server::domain::DomainScope::All,
            },
        )
        .await
        .expect("seed admin");
        (state, dir)
    }

    /// The signed REQUIRED-spec dispatch the retired deferral named:
    /// `acl/grant/0.1` (proof REQUIRED) carrying a *real* Data Integrity
    /// proof, dispatched through the DIDComm envelope path under
    /// `enforce_proofs = true` and the production verifier, landing the
    /// granted entry in the ACL store.
    #[tokio::test]
    async fn trust_tasks_envelope_signed_acl_grant_verifies_end_to_end() {
        let (admin_did, admin_signer) = did_key_signer(&[41u8; 32]);
        let (state, _dir) = grant_state(&admin_did).await;

        let subject = "did:example:grantee";
        let signed = crate::signing::sign_trust_task_document(
            unsigned_grant_doc(&admin_did, subject),
            &admin_signer,
        )
        .await
        .expect("sign grant");
        let msg = build_msg(trust_tasks_didcomm::ENVELOPE_TYPE, signed);

        let (resp_type, resp_body) = super::run_trust_tasks_envelope(&state, &admin_did, &msg)
            .await
            .expect("dispatch ok")
            .expect("a response is emitted");

        assert_eq!(resp_type, trust_tasks_didcomm::ENVELOPE_TYPE);
        let inner = resp_body["type"].as_str().unwrap();
        assert!(
            inner.ends_with("/acl/grant/0.1#response"),
            "expected grant response, got {inner}"
        );
        let stored = did_hosting_common::server::acl::get_acl_entry(&state.acl_ks, subject)
            .await
            .expect("acl read")
            .expect("granted entry stored");
        assert!(
            matches!(stored.role, Role::Owner),
            "granted role is owner, got {:?}",
            stored.role
        );
    }

    /// Tampering with a signed grant after signing is refused with
    /// `proofInvalid` — and nothing lands in the ACL store.
    #[tokio::test]
    async fn trust_tasks_envelope_signed_acl_grant_tampered_is_rejected() {
        let (admin_did, admin_signer) = did_key_signer(&[42u8; 32]);
        let (state, _dir) = grant_state(&admin_did).await;

        let mut signed = crate::signing::sign_trust_task_document(
            unsigned_grant_doc(&admin_did, "did:example:grantee"),
            &admin_signer,
        )
        .await
        .expect("sign grant");
        signed["payload"]["entry"]["subject"] = json!("did:example:mallory");
        let msg = build_msg(trust_tasks_didcomm::ENVELOPE_TYPE, signed);

        let (_, resp_body) = super::run_trust_tasks_envelope(&state, &admin_did, &msg)
            .await
            .expect("dispatch ok")
            .expect("an error document is emitted");

        assert_eq!(
            resp_body["type"],
            // Takes the version from the emitter rather than naming one, so a
            // framework bump moves the assertion with the code under test.
            // What this test is about is the `code`, not the document version.
            did_hosting_common::server::trust_tasks::framework_error_type_uri().to_string()
        );
        assert_eq!(resp_body["payload"]["code"], "proofInvalid");
        for did in ["did:example:mallory", "did:example:grantee"] {
            assert!(
                did_hosting_common::server::acl::get_acl_entry(&state.acl_ks, did)
                    .await
                    .expect("acl read")
                    .is_none(),
                "{did} must not be granted"
            );
        }
    }

    /// A proofless grant is refused (`proofRequired`) even from a
    /// seeded Admin sender — for REQUIRED specs the proof, not the
    /// transport session, authorizes.
    #[tokio::test]
    async fn trust_tasks_envelope_unsigned_acl_grant_is_rejected() {
        let (admin_did, _admin_signer) = did_key_signer(&[43u8; 32]);
        let (state, _dir) = grant_state(&admin_did).await;

        let msg = build_msg(
            trust_tasks_didcomm::ENVELOPE_TYPE,
            unsigned_grant_doc(&admin_did, "did:example:grantee"),
        );
        let (_, resp_body) = super::run_trust_tasks_envelope(&state, &admin_did, &msg)
            .await
            .expect("dispatch ok")
            .expect("an error document is emitted");

        assert_eq!(
            resp_body["type"],
            // Takes the version from the emitter rather than naming one, so a
            // framework bump moves the assertion with the code under test.
            // What this test is about is the `code`, not the document version.
            did_hosting_common::server::trust_tasks::framework_error_type_uri().to_string()
        );
        assert_eq!(resp_body["payload"]["code"], "proofRequired");
        assert!(
            did_hosting_common::server::acl::get_acl_entry(&state.acl_ks, "did:example:grantee")
                .await
                .expect("acl read")
                .is_none(),
            "nothing must be granted"
        );
    }
}
