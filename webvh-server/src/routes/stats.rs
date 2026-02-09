use axum::Json;
use axum::extract::{Path, State};

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;
use crate::stats::{DidStats, get_stats};

/// GET /stats/{mnemonic}
pub async fn get_did_stats(
    _auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<Json<DidStats>, AppError> {
    // Verify the DID exists
    let key = format!("did:{mnemonic}");
    if !state.dids_ks.contains_key(key).await? {
        return Err(AppError::NotFound(format!("DID not found: {mnemonic}")));
    }

    let stats = get_stats(&state.stats_ks, &mnemonic).await?;
    Ok(Json(stats))
}
