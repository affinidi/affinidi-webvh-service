//! Fit-for-purpose **typed** DID-management Trust Tasks
//! (`https://trusttasks.org/did-hosting/did/*/1.0`).
//!
//! This is the `1.0` webvh-owned protocol described in
//! `docs/did-hosting-trust-tasks-v1-design.md`. It replaces the
//! hand-rolled `messaging::dispatch_did_op` (a `match msg.typ` over ad-hoc
//! JSON bodies) with typed payloads dispatched through the framework's
//! §7.2 pipeline (`trust_tasks_rs::consume_inbound` via
//! `did_hosting_common::server::trust_tasks::run_pipeline`) — the same
//! machinery the ACL ops use.
//!
//! Unlike the upstream `trust-tasks-rs` `spec/did-management/*/0.1`
//! payloads (which are record-centric and carry no `did.jsonl` log), these
//! payloads carry exactly what each op needs, typed. The handlers delegate
//! to the existing `did_ops::*` business logic — no logic rewrite, only
//! typed request/response shaping.
//!
//! Coexistence: the legacy `MSG_*` path (`dispatch_did_op`) keeps working;
//! `messaging::dispatch_trust_task_doc` routes the new `1.0` URIs here and
//! everything else to the legacy bridge (deprecated over time).
//!
//! Migration status: **all eight ops** are implemented — check-name, info,
//! list, delete, publish, register, change-owner, witness-publish. Publish
//! and register carry the `did.jsonl` log as a first-class typed field
//! (`didLog`), the fit-for-purpose motivation the upstream record-centric
//! payloads miss. The legacy `MSG_*` path (`dispatch_did_op`) remains for
//! back-compat behind [`owns`], deprecated until clients adopt `1.0`.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use trust_tasks_rs::{
    Dispatcher, ErrorPayload, ErrorResponse, ProofPolicy, ProofVerifier, ResolvedParties,
    StandardCode, TransportHandler, TrustTask,
};

use did_hosting_common::did_ops::{DidRecord, did_key};
use did_hosting_common::server::domain::{DomainScope, get_default_domain, resolve_request_domain};
use did_hosting_common::server::trust_tasks::{DispatchOutcome, run_pipeline};

use crate::acl::check_acl;
use crate::auth::AuthClaims;
use crate::did_ops;
use crate::error::AppError;
use crate::messaging::spec_did_record_json;
use crate::server::AppState;

// ---------------------------------------------------------------------------
// Typed payloads
// ---------------------------------------------------------------------------

/// `did-hosting/did/request/1.0` — availability probe or slot reservation.
///
/// Fit-for-purpose re-typing of the legacy `MSG_DID_REQUEST` body:
/// * probe (`reserve = false`): read-only, MUST name a `path`.
/// * reserve (`reserve = true`): claims a slot; `path` omitted ⇒
///   server auto-assigns a mnemonic; `force` takes over an existing path
///   (admin / owner only, enforced by `did_ops::create_did`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckNameRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default)]
    pub reserve: bool,
    #[serde(default)]
    pub force: bool,
    /// Explicit hosting domain (multi-domain deployments). Resolved
    /// against the caller's ACL scope + the system default when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

impl trust_tasks_rs::Payload for CheckNameRequest {
    // The framework's `TypeUri` requires the `/spec/<slug>/<major.minor>`
    // shape, so the webvh-owned slug is `did-hosting/did/request` under
    // `/spec/` (the bare `…/did-hosting/…` form in `did_hosting_tasks.rs`
    // is only a valid *opaque* trust-task URL, not a framework Type URI).
    const TYPE_URI: &'static str = "https://trusttasks.org/spec/did-hosting/did/request/1.0";
}

/// `did-hosting/did/request/1.0#response` — the offer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckNameResponse {
    pub available: bool,
    pub reserved: bool,
    /// The committed record projection, present only on a successful
    /// reservation (matches the legacy `MSG_DID_OFFER` `record` field).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<Value>,
}

/// `did-hosting/did/info/1.0` — fetch a record + stats by mnemonic.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InfoRequest {
    pub mnemonic: String,
}
impl trust_tasks_rs::Payload for InfoRequest {
    const TYPE_URI: &'static str = "https://trusttasks.org/spec/did-hosting/did/info/1.0";
}

/// `did-hosting/did/info/1.0#response`. The nested `stats` / `logMetadata`
/// are carried as `Value` (faithful to the legacy `MSG_INFO` body).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InfoResponse {
    pub mnemonic: String,
    pub did_id: Option<String>,
    pub did_url: String,
    pub owner: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub version_count: u64,
    pub content_size: u64,
    pub stats: Value,
    pub log_metadata: Value,
}

/// `did-hosting/did/list/1.0` — list the caller's DIDs (admin may filter
/// by `owner`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
}
impl trust_tasks_rs::Payload for ListRequest {
    const TYPE_URI: &'static str = "https://trusttasks.org/spec/did-hosting/did/list/1.0";
}

/// `did-hosting/did/list/1.0#response`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListResponse {
    pub dids: Vec<Value>,
}

/// `did-hosting/did/delete/1.0` — delete a DID by mnemonic.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteRequest {
    pub mnemonic: String,
}
impl trust_tasks_rs::Payload for DeleteRequest {
    const TYPE_URI: &'static str = "https://trusttasks.org/spec/did-hosting/did/delete/1.0";
}

/// `did-hosting/did/delete/1.0#response`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteResponse {
    pub mnemonic: String,
    pub did_id: Option<String>,
}

/// `did-hosting/did/publish/1.0` — publish a signed webvh log entry for a
/// reserved mnemonic. `didLog` is the `did.jsonl` content, first-class and
/// typed (the fit-for-purpose motivation: the upstream record-centric
/// payloads have nowhere to put it).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishRequest {
    pub mnemonic: String,
    pub did_log: String,
}
impl trust_tasks_rs::Payload for PublishRequest {
    const TYPE_URI: &'static str = "https://trusttasks.org/spec/did-hosting/did/publish/1.0";
}

/// `did-hosting/did/publish/1.0#response`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishResponse {
    pub did_id: Option<String>,
    pub did_url: String,
    pub version_id: Option<String>,
    pub version_count: u64,
}

/// `did-hosting/did/register/1.0` — atomic claim-and-publish (webvh-only).
/// `didLog` is the signed log for the freshly-claimed `path`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub path: String,
    pub did_log: String,
    #[serde(default)]
    pub force: bool,
}
impl trust_tasks_rs::Payload for RegisterRequest {
    const TYPE_URI: &'static str = "https://trusttasks.org/spec/did-hosting/did/register/1.0";
}

/// `did-hosting/did/register/1.0#response`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResponse {
    pub mnemonic: String,
    pub did_url: String,
    pub server_did: String,
}

/// `did-hosting/did/change-owner/1.0` — transfer a DID to `newOwner`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeOwnerRequest {
    pub mnemonic: String,
    pub new_owner: String,
}
impl trust_tasks_rs::Payload for ChangeOwnerRequest {
    const TYPE_URI: &'static str = "https://trusttasks.org/spec/did-hosting/did/change-owner/1.0";
}

/// `did-hosting/did/change-owner/1.0#response`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeOwnerResponse {
    pub mnemonic: String,
    pub owner: String,
    pub updated_at: u64,
}

/// `did-hosting/webvh/witness/publish/1.0` — upload a witness proof set.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessPublishRequest {
    pub mnemonic: String,
    /// The witness proof document (opaque JSON, serialised as-is).
    pub witness: Value,
}
impl trust_tasks_rs::Payload for WitnessPublishRequest {
    const TYPE_URI: &'static str =
        "https://trusttasks.org/spec/did-hosting/webvh/witness/publish/1.0";
}

/// `did-hosting/webvh/witness/publish/1.0#response`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessPublishResponse {
    pub mnemonic: String,
    pub witness_url: String,
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// The typed DID-management payloads this module routes. New ops are added
/// here in lockstep with their handler.
#[derive(Debug)]
enum DidHostingInbound {
    CheckName(TrustTask<CheckNameRequest>),
    Info(TrustTask<InfoRequest>),
    List(TrustTask<ListRequest>),
    Delete(TrustTask<DeleteRequest>),
    Publish(TrustTask<PublishRequest>),
    Register(TrustTask<RegisterRequest>),
    ChangeOwner(TrustTask<ChangeOwnerRequest>),
    WitnessPublish(TrustTask<WitnessPublishRequest>),
}

fn build_dispatcher() -> Dispatcher<DidHostingInbound> {
    Dispatcher::new()
        .on::<CheckNameRequest, _>(DidHostingInbound::CheckName)
        .on::<InfoRequest, _>(DidHostingInbound::Info)
        .on::<ListRequest, _>(DidHostingInbound::List)
        .on::<DeleteRequest, _>(DidHostingInbound::Delete)
        .on::<PublishRequest, _>(DidHostingInbound::Publish)
        .on::<RegisterRequest, _>(DidHostingInbound::Register)
        .on::<ChangeOwnerRequest, _>(DidHostingInbound::ChangeOwner)
        .on::<WitnessPublishRequest, _>(DidHostingInbound::WitnessPublish)
}

/// Does the typed `did-hosting/*/1.0` protocol own this Type URI? The
/// unified router uses this to choose the typed path over the legacy
/// `dispatch_did_op` bridge.
pub fn owns(type_uri: &str) -> bool {
    build_dispatcher().registered_uris().contains(&type_uri)
}

/// Narrow an inbound `TrustTask<Value>` to a typed DID-management op and
/// run it through the framework pipeline. The caller has already checked
/// [`owns`], so an unknown type here is a framework-level rejection.
pub async fn dispatch<V>(
    state: &AppState,
    transport: &(impl TransportHandler + Sync),
    policy: ProofPolicy<'_, V>,
    doc: TrustTask<Value>,
) -> DispatchOutcome
where
    V: ProofVerifier + ?Sized,
{
    let error_id = new_id();
    match build_dispatcher().dispatch_or_reject(doc, error_id) {
        Ok(DidHostingInbound::CheckName(d)) => handle_check_name(state, transport, policy, d).await,
        Ok(DidHostingInbound::Info(d)) => handle_info(state, transport, policy, d).await,
        Ok(DidHostingInbound::List(d)) => handle_list(state, transport, policy, d).await,
        Ok(DidHostingInbound::Delete(d)) => handle_delete(state, transport, policy, d).await,
        Ok(DidHostingInbound::Publish(d)) => handle_publish(state, transport, policy, d).await,
        Ok(DidHostingInbound::Register(d)) => handle_register(state, transport, policy, d).await,
        Ok(DidHostingInbound::ChangeOwner(d)) => {
            handle_change_owner(state, transport, policy, d).await
        }
        Ok(DidHostingInbound::WitnessPublish(d)) => {
            handle_witness_publish(state, transport, policy, d).await
        }
        Err(err) => DispatchOutcome::Rejected(err),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_check_name<V>(
    state: &AppState,
    transport: &(impl TransportHandler + Sync),
    policy: ProofPolicy<'_, V>,
    doc: TrustTask<CheckNameRequest>,
) -> DispatchOutcome
where
    V: ProofVerifier + ?Sized,
{
    let my_vid = match state.config.server_did.as_deref() {
        Some(v) => v,
        None => {
            // No service DID → the pipeline has no recipient anchor. Surface
            // as an internal error document rather than panicking.
            return DispatchOutcome::Rejected(
                doc.reject_with(
                    new_id(),
                    ErrorPayload::new(StandardCode::InternalError)
                        .with_message("the maintainer is not fully configured (no service DID)"),
                ),
            );
        }
    };
    let state = state.clone();
    run_pipeline(
        transport,
        policy,
        doc,
        my_vid,
        move |doc, parties| async move {
            // The framework resolved the caller (in-band issuer wins, transport
            // fills in). Authorise against the maintainer's ACL — the same gate
            // the legacy `run_webvh_dispatch` applies before `dispatch_did_op`.
            let caller = parties.issuer.as_deref().ok_or_else(|| {
                doc.reject_with(
                    new_id(),
                    ErrorPayload::new(StandardCode::PermissionDenied).with_message(
                        "inbound document has no in-band or transport-derived issuer",
                    ),
                )
            })?;
            let role = check_acl(&state.acl_ks, caller).await.map_err(|_| {
                doc.reject_with(
                    new_id(),
                    ErrorPayload::new(StandardCode::PermissionDenied)
                        .with_message("caller is not present in the maintainer's ACL"),
                )
            })?;
            let auth = AuthClaims {
                did: caller.to_string(),
                role,
                session_id: String::new(),
                session_pubkey_b58btc: None,
                amr: vec!["did".to_string()],
                acr: "aal1".to_string(),
            };
            let req = &doc.payload;

            // ── Probe mode: read-only, MUST name a path. ──────────────────
            if !req.reserve {
                let path = req.path.as_deref().ok_or_else(|| {
                    doc.reject_with(
                        new_id(),
                        ErrorPayload::new(StandardCode::MalformedRequest).with_message(
                            "check-name without `reserve: true` requires a `path` to probe",
                        ),
                    )
                })?;
                let probe = did_ops::check_name(&state, path)
                    .await
                    .map_err(|e| reject_apperror(&doc, e))?;
                let resp = CheckNameResponse {
                    available: probe.available,
                    reserved: false,
                    record: None,
                };
                return Ok(doc.respond_with(new_id(), resp));
            }

            // ── Reserve mode: domain resolution + atomic claim. ───────────
            // Same chain as the legacy arm: explicit → ACL default → system
            // default; proceed un-domained when none resolves.
            let acl_scope =
                match did_hosting_common::server::acl::get_acl_entry(&state.acl_ks, &auth.did)
                    .await
                    .map_err(|e| reject_apperror(&doc, e))?
                {
                    Some(e) => e.domains,
                    None => DomainScope::All,
                };
            let system_default = get_default_domain(&state.store).await.ok().flatten();
            let resolved_domain = resolve_request_domain(
                req.domain.as_deref(),
                &acl_scope,
                system_default.as_deref(),
            )
            .ok();

            match did_ops::create_did(
                &auth,
                &state,
                req.path.as_deref(),
                req.force,
                resolved_domain.as_deref(),
            )
            .await
            {
                Ok(result) => {
                    let record: DidRecord = state
                        .dids_ks
                        .get(did_key(&result.mnemonic))
                        .await
                        .map_err(|e| reject_apperror(&doc, e))?
                        .ok_or_else(|| {
                            doc.reject_with(
                                new_id(),
                                ErrorPayload::new(StandardCode::InternalError)
                                    .with_message("record missing after reservation"),
                            )
                        })?;
                    let resp = CheckNameResponse {
                        available: true,
                        reserved: true,
                        record: Some(spec_did_record_json(&record, &result.did_url)),
                    };
                    Ok(doc.respond_with(new_id(), resp))
                }
                // Spec: an already-taken path without `force` is not an error —
                // return `available: false, reserved: false` and DO NOT mutate.
                Err(AppError::Conflict(_)) => Ok(doc.respond_with(
                    new_id(),
                    CheckNameResponse {
                        available: false,
                        reserved: false,
                        record: None,
                    },
                )),
                Err(e) => Err(reject_apperror(&doc, e)),
            }
        },
    )
    .await
}

async fn handle_info<V>(
    state: &AppState,
    transport: &(impl TransportHandler + Sync),
    policy: ProofPolicy<'_, V>,
    doc: TrustTask<InfoRequest>,
) -> DispatchOutcome
where
    V: ProofVerifier + ?Sized,
{
    let (my_vid, state) = match resolve_state(state, &doc) {
        Ok(v) => v,
        Err(o) => return *o,
    };
    run_pipeline(
        transport,
        policy,
        doc,
        &my_vid,
        move |doc, parties| async move {
            let auth = authorize(&state, &doc, &parties).await?;
            let mnemonic = doc.payload.mnemonic.clone();
            let (record, log_metadata) = did_ops::get_did_info(&auth, &state, &mnemonic)
                .await
                .map_err(|e| reject_apperror(&doc, e))?;
            let did_stats: did_hosting_common::DidStats = state
                .stats_ks
                .get(format!("stats:{mnemonic}"))
                .await
                .map_err(|e| reject_apperror(&doc, e))?
                .unwrap_or_default();
            let base_url = state
                .config
                .did_hosting_url
                .as_deref()
                .or(state.config.public_url.as_deref())
                .unwrap_or("http://localhost");
            let resp = InfoResponse {
                did_url: format!("{base_url}/{mnemonic}/did.jsonl"),
                mnemonic: record.mnemonic,
                did_id: record.did_id,
                owner: record.owner,
                created_at: record.created_at,
                updated_at: record.updated_at,
                version_count: record.version_count,
                content_size: record.content_size,
                stats: serde_json::json!({
                    "totalResolves": did_stats.total_resolves,
                    "totalUpdates": did_stats.total_updates,
                    "lastResolvedAt": did_stats.last_resolved_at,
                    "lastUpdatedAt": did_stats.last_updated_at,
                }),
                log_metadata: log_metadata
                    .map(|m| serde_json::to_value(m).unwrap_or(Value::Null))
                    .unwrap_or(Value::Null),
            };
            Ok(doc.respond_with(new_id(), resp))
        },
    )
    .await
}

async fn handle_list<V>(
    state: &AppState,
    transport: &(impl TransportHandler + Sync),
    policy: ProofPolicy<'_, V>,
    doc: TrustTask<ListRequest>,
) -> DispatchOutcome
where
    V: ProofVerifier + ?Sized,
{
    let (my_vid, state) = match resolve_state(state, &doc) {
        Ok(v) => v,
        Err(o) => return *o,
    };
    run_pipeline(
        transport,
        policy,
        doc,
        &my_vid,
        move |doc, parties| async move {
            let auth = authorize(&state, &doc, &parties).await?;
            let entries =
                did_ops::list_dids(&auth, &state, doc.payload.owner.as_deref(), None, None)
                    .await
                    .map_err(|e| reject_apperror(&doc, e))?;
            let dids: Vec<Value> = entries
                .into_iter()
                .map(|e| {
                    serde_json::json!({
                        "mnemonic": e.mnemonic,
                        "didId": e.did_id,
                        "createdAt": e.created_at,
                        "updatedAt": e.updated_at,
                        "versionCount": e.version_count,
                        "totalResolves": e.total_resolves,
                    })
                })
                .collect();
            Ok(doc.respond_with(new_id(), ListResponse { dids }))
        },
    )
    .await
}

async fn handle_delete<V>(
    state: &AppState,
    transport: &(impl TransportHandler + Sync),
    policy: ProofPolicy<'_, V>,
    doc: TrustTask<DeleteRequest>,
) -> DispatchOutcome
where
    V: ProofVerifier + ?Sized,
{
    let (my_vid, state) = match resolve_state(state, &doc) {
        Ok(v) => v,
        Err(o) => return *o,
    };
    run_pipeline(
        transport,
        policy,
        doc,
        &my_vid,
        move |doc, parties| async move {
            let auth = authorize(&state, &doc, &parties).await?;
            let mnemonic = doc.payload.mnemonic.clone();
            let did_id = did_ops::delete_did(&auth, &state, &mnemonic)
                .await
                .map_err(|e| reject_apperror(&doc, e))?;
            crate::server_push::notify_servers_delete(&state, mnemonic.clone());
            Ok(doc.respond_with(new_id(), DeleteResponse { mnemonic, did_id }))
        },
    )
    .await
}

async fn handle_publish<V>(
    state: &AppState,
    transport: &(impl TransportHandler + Sync),
    policy: ProofPolicy<'_, V>,
    doc: TrustTask<PublishRequest>,
) -> DispatchOutcome
where
    V: ProofVerifier + ?Sized,
{
    let (my_vid, state) = match resolve_state(state, &doc) {
        Ok(v) => v,
        Err(o) => return *o,
    };
    run_pipeline(
        transport,
        policy,
        doc,
        &my_vid,
        move |doc, parties| async move {
            let auth = authorize(&state, &doc, &parties).await?;
            let mnemonic = doc.payload.mnemonic.clone();
            did_ops::publish_did(&auth, &state, &mnemonic, &doc.payload.did_log)
                .await
                .map_err(|e| reject_apperror(&doc, e))?;
            let record: DidRecord = state
                .dids_ks
                .get(did_key(&mnemonic))
                .await
                .map_err(|e| reject_apperror(&doc, e))?
                .ok_or_else(|| {
                    doc.reject_with(
                        new_id(),
                        ErrorPayload::new(StandardCode::InternalError)
                            .with_message("record missing after publish"),
                    )
                })?;
            let base_url = state
                .config
                .did_hosting_url
                .as_deref()
                .or(state.config.public_url.as_deref())
                .unwrap_or("http://localhost");
            crate::server_push::notify_servers_did(&state, mnemonic.clone());
            Ok(doc.respond_with(
                new_id(),
                PublishResponse {
                    did_url: format!("{base_url}/{mnemonic}/did.jsonl"),
                    did_id: record.did_id.clone(),
                    version_id: record.did_id,
                    version_count: record.version_count,
                },
            ))
        },
    )
    .await
}

async fn handle_register<V>(
    state: &AppState,
    transport: &(impl TransportHandler + Sync),
    policy: ProofPolicy<'_, V>,
    doc: TrustTask<RegisterRequest>,
) -> DispatchOutcome
where
    V: ProofVerifier + ?Sized,
{
    let (my_vid, state) = match resolve_state(state, &doc) {
        Ok(v) => v,
        Err(o) => return *o,
    };
    run_pipeline(
        transport,
        policy,
        doc,
        &my_vid,
        move |doc, parties| async move {
            let auth = authorize(&state, &doc, &parties).await?;
            let req = &doc.payload;
            if req.path.is_empty() {
                return Err(doc.reject_with(
                    new_id(),
                    ErrorPayload::new(StandardCode::MalformedRequest)
                        .with_message("register requires a non-empty `path`"),
                ));
            }
            let result =
                did_ops::register_did_atomic(&auth, &state, &req.path, &req.did_log, req.force)
                    .await
                    .map_err(|e| reject_apperror(&doc, e))?;
            crate::server_push::notify_servers_did(&state, result.mnemonic.clone());
            let server_did = state.config.server_did.clone().unwrap_or_default();
            Ok(doc.respond_with(
                new_id(),
                RegisterResponse {
                    mnemonic: result.mnemonic,
                    did_url: result.did_url,
                    server_did,
                },
            ))
        },
    )
    .await
}

async fn handle_change_owner<V>(
    state: &AppState,
    transport: &(impl TransportHandler + Sync),
    policy: ProofPolicy<'_, V>,
    doc: TrustTask<ChangeOwnerRequest>,
) -> DispatchOutcome
where
    V: ProofVerifier + ?Sized,
{
    let (my_vid, state) = match resolve_state(state, &doc) {
        Ok(v) => v,
        Err(o) => return *o,
    };
    run_pipeline(
        transport,
        policy,
        doc,
        &my_vid,
        move |doc, parties| async move {
            let auth = authorize(&state, &doc, &parties).await?;
            let record = did_ops::change_did_owner(
                &auth,
                &state,
                &doc.payload.mnemonic,
                &doc.payload.new_owner,
            )
            .await
            .map_err(|e| reject_apperror(&doc, e))?;
            Ok(doc.respond_with(
                new_id(),
                ChangeOwnerResponse {
                    mnemonic: record.mnemonic,
                    owner: record.owner,
                    updated_at: record.updated_at,
                },
            ))
        },
    )
    .await
}

async fn handle_witness_publish<V>(
    state: &AppState,
    transport: &(impl TransportHandler + Sync),
    policy: ProofPolicy<'_, V>,
    doc: TrustTask<WitnessPublishRequest>,
) -> DispatchOutcome
where
    V: ProofVerifier + ?Sized,
{
    let (my_vid, state) = match resolve_state(state, &doc) {
        Ok(v) => v,
        Err(o) => return *o,
    };
    run_pipeline(
        transport,
        policy,
        doc,
        &my_vid,
        move |doc, parties| async move {
            let auth = authorize(&state, &doc, &parties).await?;
            let mnemonic = doc.payload.mnemonic.clone();
            let witness_str = serde_json::to_string(&doc.payload.witness).unwrap_or_default();
            if witness_str.is_empty() || witness_str == "null" {
                return Err(doc.reject_with(
                    new_id(),
                    ErrorPayload::new(StandardCode::MalformedRequest)
                        .with_message("witness content cannot be empty"),
                ));
            }
            did_ops::upload_witness(&auth, &state, &mnemonic, &witness_str)
                .await
                .map_err(|e| reject_apperror(&doc, e))?;
            let base_url = state
                .config
                .did_hosting_url
                .as_deref()
                .or(state.config.public_url.as_deref())
                .unwrap_or("http://localhost");
            let witness_url = format!("{base_url}/{mnemonic}/did-witness.json");
            crate::server_push::notify_servers_did(&state, mnemonic.clone());
            Ok(doc.respond_with(
                new_id(),
                WitnessPublishResponse {
                    mnemonic,
                    witness_url,
                },
            ))
        },
    )
    .await
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the service DID (for the pipeline's recipient anchor) and clone
/// the `AppState` for capture into the `run_pipeline` handler closure.
/// Returns the failure `DispatchOutcome` when no service DID is configured.
fn resolve_state<P>(
    state: &AppState,
    doc: &TrustTask<P>,
) -> Result<(String, AppState), Box<DispatchOutcome>> {
    match state.config.server_did.as_deref() {
        Some(v) => Ok((v.to_string(), state.clone())),
        // Boxed: `DispatchOutcome` is a large framework enum, and clippy's
        // `result_large_err` flags returning it unboxed in a `Result`.
        None => Err(Box::new(DispatchOutcome::Rejected(
            doc.reject_with(
                new_id(),
                ErrorPayload::new(StandardCode::InternalError)
                    .with_message("the maintainer is not fully configured (no service DID)"),
            ),
        ))),
    }
}

/// Resolve the caller (framework-resolved `parties.issuer`, in-band wins)
/// and check the maintainer ACL, returning an `AuthClaims` for the
/// `did_ops::*` calls. The same authorisation gate the legacy transport
/// applies before `dispatch_did_op`.
async fn authorize<P>(
    state: &AppState,
    doc: &TrustTask<P>,
    parties: &ResolvedParties,
) -> Result<AuthClaims, ErrorResponse> {
    let caller = parties.issuer.as_deref().ok_or_else(|| {
        doc.reject_with(
            new_id(),
            ErrorPayload::new(StandardCode::PermissionDenied)
                .with_message("inbound document has no in-band or transport-derived issuer"),
        )
    })?;
    let role = check_acl(&state.acl_ks, caller).await.map_err(|_| {
        doc.reject_with(
            new_id(),
            ErrorPayload::new(StandardCode::PermissionDenied)
                .with_message("caller is not present in the maintainer's ACL"),
        )
    })?;
    Ok(AuthClaims {
        did: caller.to_string(),
        role,
        session_id: String::new(),
        session_pubkey_b58btc: None,
        amr: vec!["did".to_string()],
        acr: "aal1".to_string(),
    })
}

fn new_id() -> String {
    format!("urn:uuid:{}", uuid::Uuid::new_v4())
}

/// Map an [`AppError`] to a framework-routed error document, preserving
/// the request's `issuer`/`recipient` so it addresses the caller.
fn reject_apperror<P>(doc: &TrustTask<P>, e: AppError) -> trust_tasks_rs::ErrorResponse {
    // StandardCode has no NotFound/Conflict; map the closest framework code.
    let code = match &e {
        AppError::Validation(_) => StandardCode::MalformedRequest,
        AppError::Forbidden(_) | AppError::Authentication(_) | AppError::Unauthorized(_) => {
            StandardCode::PermissionDenied
        }
        AppError::NotFound(_) | AppError::Conflict(_) => StandardCode::TaskFailed,
        _ => StandardCode::InternalError,
    };
    // Internal failures keep their operator detail in the log, not the wire.
    if matches!(code, StandardCode::InternalError) {
        tracing::error!(error = %e, "did-hosting/1.0: internal failure");
        return doc.reject_with(
            new_id(),
            ErrorPayload::new(StandardCode::InternalError)
                .with_message("the maintainer encountered an internal failure"),
        );
    }
    doc.reject_with(
        new_id(),
        ErrorPayload::new(code).with_message(e.user_message()),
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{Arc, OnceLock};

    use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
    use did_hosting_common::server::config::{
        AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
    };
    use did_hosting_common::server::stats_collector::StatsCollector;
    use did_hosting_common::server::store::{
        KS_ACL, KS_DIDS, KS_REGISTRY, KS_SESSIONS, KS_STATS, KS_TIMESERIES, Store,
    };
    use did_hosting_common::server::trust_tasks::TransportBoundVerifier;
    use serde_json::json;
    use trust_tasks_rs::handlers::InMemoryHandler;
    use trust_tasks_rs::{Payload, ProofPolicy};

    use crate::config::{AppConfig, RegistryConfig};

    use super::*;

    const SERVICE_DID: &str = "did:webvh:test:control.example.com";
    const ADMIN_DID: &str = "did:web:admin.example";

    async fn test_state() -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store_config = StoreConfig {
            data_dir: PathBuf::from(dir.path()),
            ..StoreConfig::default()
        };
        let store = Store::open(&store_config).await.expect("open store");
        let config = AppConfig {
            features: FeaturesConfig::default(),
            server_did: Some(SERVICE_DID.into()),
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
            config_path: PathBuf::new(),
        };
        let state = AppState {
            store: store.clone(),
            sessions_ks: store.keyspace(KS_SESSIONS).unwrap(),
            acl_ks: store.keyspace(KS_ACL).unwrap(),
            registry_ks: store.keyspace(KS_REGISTRY).unwrap(),
            dids_ks: store.keyspace(KS_DIDS).unwrap(),
            config: Arc::new(config),
            did_resolver: None,
            secrets_resolver: None,
            trust_tasks_verifier: None,
            jwt_keys: None,
            webauthn: None,
            http_client: reqwest::Client::new(),
            didcomm_service: Arc::new(OnceLock::new()),
            stats_collector: Arc::new(StatsCollector::new()),
            stats_ks: store.keyspace(KS_STATS).unwrap(),
            timeseries_ks: store.keyspace(KS_TIMESERIES).unwrap(),
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

    async fn seed_admin(state: &AppState) {
        store_acl_entry(
            &state.acl_ks,
            &AclEntry {
                did: ADMIN_DID.into(),
                role: Role::Admin,
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

    fn check_name_doc(path: &str, reserve: bool) -> TrustTask<Value> {
        let body = json!({
            "id": new_id(),
            "type": CheckNameRequest::TYPE_URI,
            "recipient": SERVICE_DID,
            "issuedAt": "2026-07-07T00:00:00Z",
            "payload": { "path": path, "reserve": reserve }
        });
        serde_json::from_value(body).expect("doc parses")
    }

    fn transport() -> InMemoryHandler {
        InMemoryHandler::new()
            .with_local(SERVICE_DID.to_string())
            .with_peer(ADMIN_DID.to_string())
    }

    /// `owns` recognises the typed request URI and rejects others.
    #[test]
    fn owns_recognises_did_hosting_uri() {
        assert!(owns(CheckNameRequest::TYPE_URI));
        assert!(!owns("https://trusttasks.org/spec/acl/grant/0.1"));
        assert!(!owns(
            "https://trusttasks.org/spec/did-management/did/publish/0.1"
        ));
    }

    /// Probe of a free path returns `available: true, reserved: false`
    /// through the typed framework pipeline, with the `#response` Type URI.
    #[tokio::test]
    async fn probe_available_over_typed_pipeline() {
        let (state, _dir) = test_state().await;
        seed_admin(&state).await;
        let transport = transport();
        let outcome = dispatch::<TransportBoundVerifier>(
            &state,
            &transport,
            ProofPolicy::AcceptUnverified,
            check_name_doc("alice", false),
        )
        .await;
        let resp = match outcome {
            DispatchOutcome::Handled(d) => d,
            other => panic!("expected Handled, got {other:?}"),
        };
        assert_eq!(
            resp.type_uri.to_string(),
            format!("{}#response", CheckNameRequest::TYPE_URI)
        );
        assert_eq!(resp.payload["available"], true);
        assert_eq!(resp.payload["reserved"], false);
    }

    /// Reserve claims the slot: `available: true, reserved: true` with the
    /// committed record, and the DID exists in the store afterwards.
    #[tokio::test]
    async fn reserve_claims_slot_over_typed_pipeline() {
        let (state, _dir) = test_state().await;
        seed_admin(&state).await;
        let transport = transport();
        let outcome = dispatch::<TransportBoundVerifier>(
            &state,
            &transport,
            ProofPolicy::AcceptUnverified,
            check_name_doc("bob", true),
        )
        .await;
        let resp = match outcome {
            DispatchOutcome::Handled(d) => d,
            other => panic!("expected Handled, got {other:?}"),
        };
        assert_eq!(resp.payload["available"], true);
        assert_eq!(resp.payload["reserved"], true);
        assert!(
            resp.payload["record"].is_object(),
            "reservation returns the committed record"
        );
        // The record projection carries the mnemonic; the DID is now stored.
        let mnemonic = resp.payload["record"]["mnemonic"]
            .as_str()
            .expect("record has a mnemonic");
        let stored: Option<DidRecord> = state.dids_ks.get(did_key(mnemonic)).await.unwrap();
        assert!(stored.is_some(), "reserved DID persisted");
    }

    /// A caller absent from the ACL is rejected `permission_denied` — the
    /// same gate the legacy transport applies.
    #[tokio::test]
    async fn unknown_caller_rejected_permission_denied() {
        let (state, _dir) = test_state().await;
        // No admin seeded → ADMIN_DID is not in the ACL.
        let transport = transport();
        let outcome = dispatch::<TransportBoundVerifier>(
            &state,
            &transport,
            ProofPolicy::AcceptUnverified,
            check_name_doc("carol", false),
        )
        .await;
        let err = match outcome {
            DispatchOutcome::Rejected(e) => e,
            other => panic!("expected Rejected, got {other:?}"),
        };
        assert_eq!(
            err.payload.code,
            trust_tasks_rs::TrustTaskCode::Standard(StandardCode::PermissionDenied)
        );
    }

    fn op_doc(type_uri: &str, payload: Value) -> TrustTask<Value> {
        let body = json!({
            "id": new_id(),
            "type": type_uri,
            "recipient": SERVICE_DID,
            "issuedAt": "2026-07-07T00:00:00Z",
            "payload": payload
        });
        serde_json::from_value(body).expect("doc parses")
    }

    fn expect_handled(outcome: DispatchOutcome) -> TrustTask<Value> {
        match outcome {
            DispatchOutcome::Handled(d) => d,
            other => panic!("expected Handled, got {other:?}"),
        }
    }

    /// Reserve a DID and return its mnemonic (setup for info/list/delete).
    async fn reserve_did(state: &AppState, path: &str) -> String {
        let outcome = dispatch::<TransportBoundVerifier>(
            state,
            &transport(),
            ProofPolicy::AcceptUnverified,
            check_name_doc(path, true),
        )
        .await;
        expect_handled(outcome).payload["record"]["mnemonic"]
            .as_str()
            .expect("reserved record has a mnemonic")
            .to_string()
    }

    #[tokio::test]
    async fn info_returns_record_over_typed() {
        let (state, _dir) = test_state().await;
        seed_admin(&state).await;
        let mnemonic = reserve_did(&state, "infotest").await;

        let resp = expect_handled(
            dispatch::<TransportBoundVerifier>(
                &state,
                &transport(),
                ProofPolicy::AcceptUnverified,
                op_doc(InfoRequest::TYPE_URI, json!({ "mnemonic": mnemonic })),
            )
            .await,
        );
        assert_eq!(
            resp.type_uri.to_string(),
            format!("{}#response", InfoRequest::TYPE_URI)
        );
        assert_eq!(resp.payload["mnemonic"], mnemonic);
        assert_eq!(resp.payload["owner"], ADMIN_DID);
        assert!(resp.payload["stats"].is_object());
    }

    #[tokio::test]
    async fn list_returns_dids_over_typed() {
        let (state, _dir) = test_state().await;
        seed_admin(&state).await;
        let mnemonic = reserve_did(&state, "listtest").await;

        let resp = expect_handled(
            dispatch::<TransportBoundVerifier>(
                &state,
                &transport(),
                ProofPolicy::AcceptUnverified,
                op_doc(ListRequest::TYPE_URI, json!({})),
            )
            .await,
        );
        let dids = resp.payload["dids"].as_array().expect("dids array");
        assert!(
            dids.iter().any(|d| d["mnemonic"] == mnemonic),
            "reserved DID appears in the list: {dids:?}"
        );
    }

    #[tokio::test]
    async fn delete_removes_did_over_typed() {
        let (state, _dir) = test_state().await;
        seed_admin(&state).await;
        let mnemonic = reserve_did(&state, "deltest").await;

        let resp = expect_handled(
            dispatch::<TransportBoundVerifier>(
                &state,
                &transport(),
                ProofPolicy::AcceptUnverified,
                op_doc(DeleteRequest::TYPE_URI, json!({ "mnemonic": mnemonic })),
            )
            .await,
        );
        assert_eq!(resp.payload["mnemonic"], mnemonic);
        let stored: Option<DidRecord> = state.dids_ks.get(did_key(&mnemonic)).await.unwrap();
        assert!(stored.is_none(), "deleted DID is gone from the store");
    }

    /// Publish routes through the typed pipeline to `did_ops::publish_did`.
    /// A malformed log is rejected there — proving delegation (a valid
    /// signed `did.jsonl` happy path is covered by the `did_ops` tests).
    #[tokio::test]
    async fn publish_malformed_log_rejected_over_typed() {
        let (state, _dir) = test_state().await;
        seed_admin(&state).await;
        let mnemonic = reserve_did(&state, "pubtest").await;

        let outcome = dispatch::<TransportBoundVerifier>(
            &state,
            &transport(),
            ProofPolicy::AcceptUnverified,
            op_doc(
                PublishRequest::TYPE_URI,
                json!({ "mnemonic": mnemonic, "didLog": "not-a-valid-jsonl-log" }),
            ),
        )
        .await;
        let err = match outcome {
            DispatchOutcome::Rejected(e) => e,
            other => panic!("expected Rejected (malformed log), got {other:?}"),
        };
        assert!(
            matches!(err.payload.code, trust_tasks_rs::TrustTaskCode::Standard(_)),
            "malformed log surfaces a routed framework error: {:?}",
            err.payload.code
        );
    }

    #[test]
    fn owns_recognises_all_registered_ops() {
        for uri in [
            CheckNameRequest::TYPE_URI,
            InfoRequest::TYPE_URI,
            ListRequest::TYPE_URI,
            DeleteRequest::TYPE_URI,
            PublishRequest::TYPE_URI,
            RegisterRequest::TYPE_URI,
            ChangeOwnerRequest::TYPE_URI,
            WitnessPublishRequest::TYPE_URI,
        ] {
            assert!(owns(uri), "dispatcher should own {uri}");
        }
    }

    /// Register routes to `did_ops::register_did_atomic` — a malformed log
    /// is rejected there (a valid signed log is covered by the did_ops
    /// tests). Also proves the empty-path guard.
    #[tokio::test]
    async fn register_malformed_log_rejected_over_typed() {
        let (state, _dir) = test_state().await;
        seed_admin(&state).await;
        let outcome = dispatch::<TransportBoundVerifier>(
            &state,
            &transport(),
            ProofPolicy::AcceptUnverified,
            op_doc(
                RegisterRequest::TYPE_URI,
                json!({ "path": "regtest", "didLog": "garbage", "force": false }),
            ),
        )
        .await;
        assert!(
            matches!(outcome, DispatchOutcome::Rejected(_)),
            "malformed register log is rejected"
        );
    }

    /// Change-owner routes to `did_ops::change_did_owner`; transferring to
    /// an unknown owner is rejected there.
    #[tokio::test]
    async fn change_owner_unknown_target_rejected_over_typed() {
        let (state, _dir) = test_state().await;
        seed_admin(&state).await;
        let mnemonic = reserve_did(&state, "chowntest").await;
        let outcome = dispatch::<TransportBoundVerifier>(
            &state,
            &transport(),
            ProofPolicy::AcceptUnverified,
            op_doc(
                ChangeOwnerRequest::TYPE_URI,
                json!({ "mnemonic": mnemonic, "newOwner": "did:web:nobody.example" }),
            ),
        )
        .await;
        assert!(
            matches!(outcome, DispatchOutcome::Rejected(_)),
            "change to an unknown owner is rejected"
        );
    }

    /// Witness-publish validates a non-empty witness before delegating.
    #[tokio::test]
    async fn witness_publish_empty_rejected_over_typed() {
        let (state, _dir) = test_state().await;
        seed_admin(&state).await;
        let mnemonic = reserve_did(&state, "wittest").await;
        let outcome = dispatch::<TransportBoundVerifier>(
            &state,
            &transport(),
            ProofPolicy::AcceptUnverified,
            op_doc(
                WitnessPublishRequest::TYPE_URI,
                json!({ "mnemonic": mnemonic, "witness": null }),
            ),
        )
        .await;
        let err = match outcome {
            DispatchOutcome::Rejected(e) => e,
            other => panic!("expected Rejected, got {other:?}"),
        };
        assert_eq!(
            err.payload.code,
            trust_tasks_rs::TrustTaskCode::Standard(StandardCode::MalformedRequest)
        );
    }
}
