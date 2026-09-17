use axum::Json;
use axum::extract::FromRequestParts;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::request::Parts;
use tracing::{info, warn};

use crate::error::AppError;
use crate::server::AppState;
use crate::watcher_ops::{self, WatcherRecord};
use did_hosting_common::server::auth::constant_time_eq;
use did_hosting_common::server::mnemonic::validate_mnemonic;
use did_hosting_common::{SyncDeleteRequest, SyncDidRequest};

// ---------------------------------------------------------------------------
// SyncAuth extractor — validates bearer token against configured push_tokens
// ---------------------------------------------------------------------------

pub struct SyncAuth;

impl FromRequestParts<AppState> for SyncAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(AppError::Authentication("missing sync token".into()))?;

        if state
            .config
            .sync
            .push_tokens
            .iter()
            .any(|t| constant_time_eq(t.as_bytes(), token.as_bytes()))
        {
            Ok(SyncAuth)
        } else {
            Err(AppError::Authentication("invalid sync token".into()))
        }
    }
}

// ---------------------------------------------------------------------------
// POST /api/sync/did — receive pushed DID content
// ---------------------------------------------------------------------------

pub async fn receive_did(
    State(state): State<AppState>,
    _auth: SyncAuth,
    Json(req): Json<SyncDidRequest>,
) -> Result<StatusCode, AppError> {
    // Validate mnemonic format to prevent store key injection
    validate_mnemonic(&req.mnemonic)?;

    // Verify the log CRYPTOGRAPHICALLY, not just structurally — the watcher is
    // an independent verifying mirror, and it serves this content publicly from
    // its own hostname. Structural validation alone would let a leaked/valid
    // push token plant a forged-but-well-formed did.jsonl for any mnemonic.
    // `verify_did_log_proofs` runs the full signature / hash-chain / pre-rotation
    // checks (and also caps the entry count), matching the edge publish path
    // (SEC-4045 W9). Logs pushed by a control plane are already verified there,
    // so legitimate syncs pass.
    if req.log_content.is_empty() {
        return Err(AppError::Validation("log_content cannot be empty".into()));
    }
    did_hosting_common::did_ops::verify_did_log_proofs(&req.log_content).map_err(|e| {
        warn!(mnemonic = %req.mnemonic, error = %e, "unverified WebVH JSONL in sync push");
        AppError::Validation(format!("WebVH log content failed verification: {e}"))
    })?;

    let record = WatcherRecord {
        mnemonic: req.mnemonic.clone(),
        did_id: req.did_id,
        source_url: req.source_url,
        updated_at: req.updated_at,
        disabled: req.disabled,
    };

    // Store the record metadata
    watcher_ops::store_record(&state.dids_ks, &record).await?;

    // Store log content
    state
        .dids_ks
        .insert_raw(
            watcher_ops::content_log_key(&req.mnemonic),
            req.log_content.into_bytes(),
        )
        .await?;

    // Store witness content if present
    if let Some(witness) = req.witness_content {
        state
            .dids_ks
            .insert_raw(
                watcher_ops::content_witness_key(&req.mnemonic),
                witness.into_bytes(),
            )
            .await?;
    }

    info!(mnemonic = %req.mnemonic, "DID content synced from source");

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// POST /api/sync/delete — receive DID deletion
// ---------------------------------------------------------------------------

pub async fn receive_delete(
    State(state): State<AppState>,
    _auth: SyncAuth,
    Json(req): Json<SyncDeleteRequest>,
) -> Result<StatusCode, AppError> {
    // Validate mnemonic format
    validate_mnemonic(&req.mnemonic)?;

    watcher_ops::delete_record(&state.dids_ks, &req.mnemonic).await?;

    info!(mnemonic = %req.mnemonic, source = %req.source_url, "DID deleted via sync");

    Ok(StatusCode::NO_CONTENT)
}
