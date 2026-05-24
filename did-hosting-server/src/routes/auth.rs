use axum::Json;
use axum::extract::State;
use serde::Deserialize;

use did_hosting_common::server::didcomm_unpack;
use did_hosting_common::{AuthenticateResponse, ChallengeResponse, RefreshResponse};

use crate::error::AppError;
use crate::server::AppState;
use tracing::info;

// ---------- POST /auth/challenge ----------

#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    pub did: String,
}

/// Thin dispatcher: validates DID length, dispatches to the
/// canonical handler. The canonical handler enforces the per-DID
/// rate limit (default 10 concurrent pending), ACL gate, and
/// session persistence.
pub async fn challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, AppError> {
    if req.did.len() > 512 {
        return Err(AppError::Validation("DID exceeds maximum length".into()));
    }

    let backend = crate::auth::DidHostingServerAuthBackend::from_state(&state)?;
    let canonical = vti_common::auth::handlers::handle_challenge(
        &backend,
        vti_common::auth::ChallengeInput {
            did: req.did.clone(),
            session_pubkey_b58btc: None,
        },
    )
    .await?;

    #[cfg(feature = "metrics")]
    did_hosting_common::server::metrics::inc_auth_challenge();
    info!(audit = true, did = %req.did, "auth challenge issued");

    Ok(Json(ChallengeResponse {
        challenge: canonical.challenge,
        session_id: canonical.session_id,
        expires_at: canonical.expires_at,
    }))
}

// ---------- POST /auth/ ----------

pub async fn authenticate(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<AuthenticateResponse>, AppError> {
    let (did_resolver, _secrets_resolver, _jwt_keys) = state.require_didcomm_auth()?;

    let (msg, sender_base) = didcomm_unpack::unpack_signed(&body, did_resolver).await?;

    // L4: accept both legacy + canonical Trust-Task URIs during
    // the migration window.
    if !matches!(
        msg.typ.as_str(),
        "https://affinidi.com/webvh/1.0/authenticate"
            | "https://trusttasks.org/spec/auth/authenticate/0.1"
    ) {
        return Err(AppError::Authentication(format!(
            "unexpected message type: {}",
            msg.typ
        )));
    }

    let challenge = msg.body["challenge"]
        .as_str()
        .ok_or_else(|| AppError::Authentication("missing challenge in message body".into()))?
        .to_string();
    let session_id = msg.body["session_id"]
        .as_str()
        .ok_or_else(|| AppError::Authentication("missing session_id in message body".into()))?
        .to_string();

    let backend = crate::auth::DidHostingServerAuthBackend::from_state(&state)?;
    let resp = vti_common::auth::handlers::handle_authenticate(
        &backend,
        vti_common::auth::AuthenticateInput {
            session_id,
            challenge,
            signer_did: sender_base.clone(),
            // DIDComm created_time threaded into the canonical
            // handler — was previously the route's `created_time
            // < session.created_at || now - created_time > TTL`
            // pair of checks; the canonical handler implements
            // both inside `check_freshness`.
            created_time: msg.created_time,
            session_pubkey_b58btc: None,
        },
    )
    .await?;

    #[cfg(feature = "metrics")]
    did_hosting_common::server::metrics::inc_auth_success();
    info!(audit = true, did = %sender_base, "authentication successful");

    Ok(Json(AuthenticateResponse {
        session: did_hosting_common::Session {
            id: resp.session.id,
            subject: resp.session.subject,
            issued_at: resp.session.issued_at,
            expires_at: resp.session.expires_at,
            amr: resp.session.amr,
            acr: resp.session.acr,
        },
        tokens: did_hosting_common::TokenBundle {
            access_token: resp.tokens.access_token,
            refresh_token: resp.tokens.refresh_token,
            token_type: resp.tokens.token_type,
            expires_in: resp.tokens.expires_in,
            refresh_expires_in: resp.tokens.refresh_expires_in,
            scope: resp.tokens.scope,
        },
    }))
}

// ---------- POST /auth/refresh ----------

pub async fn refresh(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<RefreshResponse>, AppError> {
    let (did_resolver, _secrets_resolver, _jwt_keys) = state.require_didcomm_auth()?;

    let (msg, sender_base) = didcomm_unpack::unpack_signed(&body, did_resolver).await?;

    if !matches!(
        msg.typ.as_str(),
        "https://affinidi.com/webvh/1.0/authenticate/refresh"
            | "https://trusttasks.org/spec/auth/refresh/0.1"
    ) {
        return Err(AppError::Authentication(format!(
            "unexpected message type: {}",
            msg.typ
        )));
    }

    let refresh_token = msg.body["refresh_token"]
        .as_str()
        .ok_or_else(|| AppError::Authentication("missing refresh_token in message body".into()))?
        .to_string();

    let backend = crate::auth::DidHostingServerAuthBackend::from_state(&state)?;
    let resp = vti_common::auth::handlers::handle_refresh(
        &backend,
        vti_common::auth::RefreshInput {
            refresh_token,
            signer_did: Some(sender_base),
        },
    )
    .await?;

    info!(audit = true, "token refreshed");

    Ok(Json(AuthenticateResponse {
        session: did_hosting_common::Session {
            id: resp.session.id,
            subject: resp.session.subject,
            issued_at: resp.session.issued_at,
            expires_at: resp.session.expires_at,
            amr: resp.session.amr,
            acr: resp.session.acr,
        },
        tokens: did_hosting_common::TokenBundle {
            access_token: resp.tokens.access_token,
            refresh_token: resp.tokens.refresh_token,
            token_type: resp.tokens.token_type,
            expires_in: resp.tokens.expires_in,
            refresh_expires_in: resp.tokens.refresh_expires_in,
            scope: resp.tokens.scope,
        },
    }))
}
