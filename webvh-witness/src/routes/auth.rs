use axum::Json;
use axum::extract::State;
use serde::Deserialize;

use crate::error::AppError;
use crate::server::AppState;

#[derive(Deserialize)]
pub struct ChallengeRequest {
    pub did: String,
}

// Wire types reuse did-hosting-common's canonical shapes
// (spec/auth/challenge/0.1#response, spec/auth/authenticate/0.1#response)
// so the witness exposes the same wire contract as the main
// did-hosting daemon.
pub use did_hosting_common::{AuthenticateResponse, ChallengeResponse};

/// Translate the canonical
/// `vti_common::auth::handlers::handle_*` response into
/// did-hosting's workspace-vta-sdk-pinned wire type. Both
/// shapes are byte-identical on the wire — Rust treats the two
/// versions of vta-sdk as distinct types so we copy fields
/// explicitly. Disappears when vta-sdk publishes alongside
/// vti-common.
fn canonical_to_local_auth_response(
    a: vta_sdk::protocols::auth::AuthenticateResponse,
) -> AuthenticateResponse {
    AuthenticateResponse {
        session: did_hosting_common::Session {
            id: a.session.id,
            subject: a.session.subject,
            issued_at: a.session.issued_at,
            expires_at: a.session.expires_at,
            amr: a.session.amr,
            acr: a.session.acr,
        },
        tokens: did_hosting_common::TokenBundle {
            access_token: a.tokens.access_token,
            refresh_token: a.tokens.refresh_token,
            token_type: a.tokens.token_type,
            expires_in: a.tokens.expires_in,
            refresh_expires_in: a.tokens.refresh_expires_in,
            scope: a.tokens.scope,
        },
    }
}

pub async fn challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, AppError> {
    let backend = crate::auth::WebvhWitnessAuthBackend::from_state(&state)?;
    let canonical = vti_common::auth::handlers::handle_challenge(
        &backend,
        vti_common::auth::ChallengeInput {
            did: req.did,
            session_pubkey_b58btc: None,
        },
    )
    .await?;
    Ok(Json(ChallengeResponse {
        challenge: canonical.challenge,
        session_id: canonical.session_id,
        expires_at: canonical.expires_at,
    }))
}

pub async fn authenticate(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<AuthenticateResponse>, AppError> {
    let (did_resolver, _secrets_resolver, _jwt_keys) = state.require_didcomm_auth()?;

    let (msg, sender_base) =
        did_hosting_common::server::didcomm_unpack::unpack_signed(&body, did_resolver).await?;

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

    let challenge = msg
        .body
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Authentication("missing challenge in message body".into()))?
        .to_string();

    let session_id = msg
        .body
        .get("session_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Authentication("missing session_id in message body".into()))?
        .to_string();

    let backend = crate::auth::WebvhWitnessAuthBackend::from_state(&state)?;
    let resp = vti_common::auth::handlers::handle_authenticate(
        &backend,
        vti_common::auth::AuthenticateInput {
            session_id,
            challenge,
            signer_did: sender_base,
            created_time: msg.created_time,
            session_pubkey_b58btc: None,
        },
    )
    .await?;
    Ok(Json(canonical_to_local_auth_response(resp)))
}

pub async fn refresh(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<serde_json::Value>, AppError> {
    let (did_resolver, _secrets_resolver, _jwt_keys) = state.require_didcomm_auth()?;

    let (msg, sender_base) =
        did_hosting_common::server::didcomm_unpack::unpack_signed(&body, did_resolver).await?;

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

    let refresh_token = msg
        .body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Authentication("missing refresh_token".into()))?
        .to_string();

    let backend = crate::auth::WebvhWitnessAuthBackend::from_state(&state)?;
    let resp = vti_common::auth::handlers::handle_refresh(
        &backend,
        vti_common::auth::RefreshInput {
            refresh_token,
            signer_did: Some(sender_base),
        },
    )
    .await?;

    Ok(Json(serde_json::to_value(
        canonical_to_local_auth_response(resp),
    )?))
}
