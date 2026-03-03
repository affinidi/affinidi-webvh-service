use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::auth::{AdminAuth, AuthClaims};
use crate::error::AppError;
use crate::server::AppState;
use crate::witness_ops;

#[derive(Deserialize)]
pub struct CreateWitnessRequest {
    pub label: Option<String>,
}

#[derive(Serialize)]
pub struct WitnessResponse {
    pub witness_id: String,
    pub did: String,
    pub label: Option<String>,
    pub created_at: u64,
    pub proofs_signed: u64,
}

impl From<&witness_ops::WitnessRecord> for WitnessResponse {
    fn from(r: &witness_ops::WitnessRecord) -> Self {
        Self {
            witness_id: r.witness_id.clone(),
            did: r.did.clone(),
            label: r.label.clone(),
            created_at: r.created_at,
            proofs_signed: r.proofs_signed,
        }
    }
}

#[derive(Serialize)]
pub struct WitnessListResponse {
    pub witnesses: Vec<WitnessResponse>,
}

#[derive(Deserialize)]
pub struct SignProofRequest {
    pub version_id: String,
}

#[derive(Serialize)]
pub struct SignProofResponse {
    pub version_id: String,
    pub proof: serde_json::Value,
}

pub async fn create_witness(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<CreateWitnessRequest>,
) -> Result<(StatusCode, Json<WitnessResponse>), AppError> {
    let record = witness_ops::create_witness(&state.witnesses_ks, req.label).await?;
    Ok((StatusCode::CREATED, Json(WitnessResponse::from(&record))))
}

pub async fn list_witnesses(
    _auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<WitnessListResponse>, AppError> {
    let records = witness_ops::list_witnesses(&state.witnesses_ks).await?;
    let witnesses = records.iter().map(WitnessResponse::from).collect();
    Ok(Json(WitnessListResponse { witnesses }))
}

pub async fn get_witness(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(witness_id): Path<String>,
) -> Result<Json<WitnessResponse>, AppError> {
    let record = witness_ops::get_witness(&state.witnesses_ks, &witness_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("witness not found: {witness_id}")))?;
    Ok(Json(WitnessResponse::from(&record)))
}

pub async fn delete_witness(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(witness_id): Path<String>,
) -> Result<StatusCode, AppError> {
    // Verify witness exists
    if witness_ops::get_witness(&state.witnesses_ks, &witness_id)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound(format!(
            "witness not found: {witness_id}"
        )));
    }

    witness_ops::delete_witness(&state.witnesses_ks, &witness_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn sign_proof(
    _auth: AuthClaims,
    State(state): State<AppState>,
    Path(witness_id): Path<String>,
    Json(req): Json<SignProofRequest>,
) -> Result<Json<SignProofResponse>, AppError> {
    let (version_id, proof) = witness_ops::sign_witness_proof(
        &state.witnesses_ks,
        state.signer.as_ref(),
        &witness_id,
        &req.version_id,
    )
    .await?;

    // Serialize the DataIntegrityProof to JSON
    let proof_json = serde_json::to_value(&proof)?;

    Ok(Json(SignProofResponse {
        version_id,
        proof: proof_json,
    }))
}
