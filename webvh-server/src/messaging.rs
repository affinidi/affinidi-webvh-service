//! DIDComm sync handlers for the WebVH server edge node.
//!
//! The server is a read-only node that receives `sync-update` and
//! `sync-delete` messages from the control plane via the mediator.
//! All DID provisioning (VTA protocol) is handled by the control plane.

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommServiceError, Extension, HandlerContext, MESSAGE_PICKUP_STATUS_TYPE,
    MessagePolicy, RequestLogging, Router, TRUST_PING_TYPE, handler_fn, ignore_handler,
    trust_ping_handler,
};
use serde_json::{Value, json};
use tracing::{info, warn};

use affinidi_webvh_common::didcomm_types::*;

use crate::acl::{Role, check_acl};
use crate::server::AppState;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the DIDComm router for the WebVH server.
///
/// Handles only sync messages from the control plane (sync-update,
/// sync-delete). VTA provisioning is handled by the control plane.
pub fn build_server_router(state: AppState) -> Result<Router, DIDCommServiceError> {
    Ok(Router::new()
        .extension(state)
        .route(TRUST_PING_TYPE, handler_fn(trust_ping_handler))?
        .route(MESSAGE_PICKUP_STATUS_TYPE, handler_fn(ignore_handler))?
        .route(MSG_SYNC_UPDATE, handler_fn(handle_sync_update))?
        .route(MSG_SYNC_DELETE, handler_fn(handle_sync_delete))?
        .fallback(handler_fn(handle_fallback))
        .layer(
            MessagePolicy::new()
                .require_encrypted(true)
                .require_sender_did(true),
        )
        .layer(RequestLogging))
}

// ---------------------------------------------------------------------------
// Sync handlers (control plane → server via mediator)
// ---------------------------------------------------------------------------

async fn handle_sync_update(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = require_sender(&ctx)?;

    let (response_type, response_body) = match do_sync_update(sender, &state, &message).await {
        Ok(r) => r,
        Err(e) => problem_report("e.p.did.internal-error", &e),
    };

    Ok(Some(
        DIDCommResponse::new(response_type, response_body).thid(message.id.clone()),
    ))
}

async fn handle_sync_delete(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = require_sender(&ctx)?;

    let (response_type, response_body) = match do_sync_delete(sender, &state, &message).await {
        Ok(r) => r,
        Err(e) => problem_report("e.p.did.internal-error", &e),
    };

    Ok(Some(
        DIDCommResponse::new(response_type, response_body).thid(message.id.clone()),
    ))
}

async fn handle_fallback(
    _ctx: HandlerContext,
    message: Message,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    warn!(msg_type = %message.typ, "unknown message type — ignoring");
    Ok(None)
}

// ---------------------------------------------------------------------------
// Sync message handling
// ---------------------------------------------------------------------------

async fn do_sync_update(
    sender: &str,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), String> {
    use crate::control_register::apply_single_update;
    use affinidi_webvh_common::DidSyncUpdate;

    let role = check_acl(&state.acl_ks, sender)
        .await
        .map_err(|e| e.to_string())?;
    if !matches!(role, Role::Admin | Role::Service) {
        warn!(
            did = sender,
            "sync message rejected: requires admin or service role"
        );
        return Ok(problem_report(
            "e.p.did.unauthorized",
            "admin or service role required for sync messages",
        ));
    }

    let mnemonic = msg
        .body
        .get("mnemonic")
        .and_then(|v| v.as_str())
        .ok_or("missing 'mnemonic' in sync-update")?;
    let did_id = msg
        .body
        .get("did_id")
        .and_then(|v| v.as_str())
        .ok_or("missing 'did_id' in sync-update")?;
    let log_content = msg
        .body
        .get("log_content")
        .and_then(|v| v.as_str())
        .ok_or("missing 'log_content' in sync-update")?;
    let witness_content = msg
        .body
        .get("witness_content")
        .and_then(|v| v.as_str())
        .map(String::from);
    let version_count = msg
        .body
        .get("version_count")
        .and_then(|v| v.as_u64())
        .ok_or("missing 'version_count' in sync-update")?;

    let update = DidSyncUpdate {
        mnemonic: mnemonic.to_string(),
        did_id: did_id.to_string(),
        log_content: log_content.to_string(),
        witness_content,
        version_count,
    };

    apply_single_update(&state.dids_ks, &state.store, &update, &state.did_cache)
        .await
        .map_err(|e| e.to_string())?;

    info!(
        did = sender,
        mnemonic = %mnemonic,
        version_count,
        "applied DID sync update from control plane via mediator"
    );

    Ok((
        MSG_SYNC_UPDATE_ACK.to_string(),
        json!({ "mnemonic": mnemonic, "status": "applied" }),
    ))
}

async fn do_sync_delete(
    sender: &str,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), String> {
    use crate::did_ops;

    let role = check_acl(&state.acl_ks, sender)
        .await
        .map_err(|e| e.to_string())?;
    if !matches!(role, Role::Admin | Role::Service) {
        warn!(
            did = sender,
            "sync message rejected: requires admin or service role"
        );
        return Ok(problem_report(
            "e.p.did.unauthorized",
            "admin or service role required for sync messages",
        ));
    }

    let mnemonic = msg
        .body
        .get("mnemonic")
        .and_then(|v| v.as_str())
        .ok_or("missing 'mnemonic' in sync-delete")?;

    let record: Option<did_ops::DidRecord> = state
        .dids_ks
        .get(did_ops::did_key(mnemonic))
        .await
        .unwrap_or(None);

    if let Some(record) = record {
        let mut batch = state.store.batch();
        batch.remove(&state.dids_ks, did_ops::did_key(mnemonic));
        batch.remove(&state.dids_ks, did_ops::content_log_key(mnemonic));
        batch.remove(&state.dids_ks, did_ops::content_witness_key(mnemonic));
        batch.remove(&state.dids_ks, did_ops::owner_key(&record.owner, mnemonic));
        batch.remove(&state.dids_ks, did_ops::watcher_sync_key(mnemonic));
        batch.commit().await.map_err(|e| e.to_string())?;

        info!(did = sender, mnemonic = %mnemonic, "deleted DID via sync from control plane");
    } else {
        info!(mnemonic = %mnemonic, "sync delete: DID not found locally");
    }

    Ok((
        MSG_SYNC_DELETE_ACK.to_string(),
        json!({ "mnemonic": mnemonic, "status": "deleted" }),
    ))
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

fn problem_report(code: &str, comment: &str) -> (String, Value) {
    (
        MSG_PROBLEM_REPORT.to_string(),
        json!({ "code": code, "comment": comment }),
    )
}
