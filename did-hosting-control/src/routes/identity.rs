//! Operator surface for the service's own identity generations.
//!
//! Two endpoints, both admin-only:
//!
//! - `GET  /api/identity/generations` — what key material this service still
//!   honours, and when each superseded generation stops being honoured.
//! - `POST /api/identity/generations/{id}/retire` — the **kill switch**: stop
//!   honouring a superseded generation *now*, ahead of its grace period.
//!
//! # Why this exists and the CLI is not enough
//!
//! The CLI mutates the store directly and fjall takes an exclusive lock, so it
//! cannot run against a live service — and even if it could, deleting a record
//! on disk would not reach into the running process's secrets resolver, which is
//! where the compromised key actually still lives. These endpoints run
//! **in-process**: the key is dropped from the resolver and the listener profile
//! before the response is written. That is what makes this the real kill switch
//! and the CLI the offline fallback.

use axum::extract::{Path, State};
use axum::{Json, http::StatusCode};
use serde::Serialize;

use did_hosting_common::server::auth::extractor::AdminAuth;

use crate::error::AppError;
use crate::server::AppState;

/// One generation of the service's own identity, as the operator sees it.
///
/// Carries no key material — only the key *identifiers*, which are public (they
/// are what the DID document advertises).
#[derive(Debug, Serialize)]
pub struct GenerationView {
    pub id: u64,
    pub did: String,
    /// `true` for the generation the DID document currently advertises. Exactly
    /// one is current, and it cannot be retired — see the handler below.
    pub current: bool,
    pub signing_kid: String,
    pub key_agreement_kid: String,
    pub mediator_did: Option<String>,
    pub didcomm: bool,
    pub tsp: bool,
    pub created_at: u64,
    /// When this generation stopped being current. `None` on the current one.
    pub retired_at: Option<u64>,
    /// When it stops being honoured and its key material is dropped. `None` on
    /// the current one — it never expires while it is current.
    pub expires_at: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct GenerationsResponse {
    pub generations: Vec<GenerationView>,
    /// The configured grace period, in seconds — how long a generation retired
    /// from now would keep being honoured.
    pub rotation_grace_secs: u64,
}

/// `GET /api/identity/generations`
pub async fn list_generations(
    _auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<GenerationsResponse>, AppError> {
    let Some(identity) = state.identity.as_ref() else {
        return Ok(Json(GenerationsResponse {
            generations: Vec::new(),
            rotation_grace_secs: state.config.identity.rotation_grace_secs(),
        }));
    };

    let generations = identity.generations();
    let current_id = generations.first().map(|g| g.id);

    Ok(Json(GenerationsResponse {
        generations: generations
            .iter()
            .map(|g| GenerationView {
                id: g.id,
                did: g.did.clone(),
                current: Some(g.id) == current_id,
                signing_kid: g.signing_kid.clone(),
                key_agreement_kid: g.ka_kid.clone(),
                mediator_did: g.mediator_did.clone(),
                didcomm: g.protocols.didcomm,
                tsp: g.protocols.tsp,
                created_at: g.created_at,
                retired_at: g.retired_at,
                expires_at: g.expires_at,
            })
            .collect(),
        rotation_grace_secs: state.config.identity.rotation_grace_secs(),
    }))
}

/// `POST /api/identity/generations/{id}/retire` — the kill switch.
///
/// Stops honouring a superseded generation immediately. Messages still addressed
/// to its key-agreement key will no longer decrypt: peers whose cached DID
/// document still names the old key cannot reach us until their cache expires.
/// That breakage is the *point* when the key is compromised, and the caller is
/// taken to have meant it.
///
/// Refuses to retire the **current** generation — that would drop the key the
/// service is actively using and leave it unable to decrypt anything at all. To
/// stop using the current key, publish a new DID document; the rotation makes it
/// superseded, and then this endpoint can retire it.
pub async fn retire_generation(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> Result<StatusCode, AppError> {
    crate::identity_rotation::retire_generation_now(&state, id).await?;
    Ok(StatusCode::NO_CONTENT)
}
