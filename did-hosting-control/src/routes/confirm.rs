//! RP-initiated wallet confirmation over DIDComm.
//!
//! The control plane (Relying Party) asks a wallet to confirm a
//! sensitive action: it generates a random `challenge`, sends a
//! `confirm/1.0` DIDComm message to the holder DID (authcrypt +
//! forward via the holder's mediator), and parks the REST request on a
//! `oneshot` channel until the wallet authcrypts a `confirm-response/1.0`
//! back. Correlation is by `challenge`; the inbound response handler
//! (see [`crate::messaging::handle_confirm_response`]) resolves the wait.
//!
//! ## Wire contract (must match the wallet implementation)
//!
//! - **Request** (RP → wallet): DIDComm message
//!   `type = "https://trusttasks.org/wallet/confirm/1.0"`, `to =
//!   [holder_did]`, `body = { "challenge": "<hex>", "action": "<string>",
//!   "rpName": "<optional>" }`.
//! - **Response** (wallet → RP): inbound DIDComm message
//!   `type = "https://trusttasks.org/wallet/confirm-response/1.0"`,
//!   authcrypt-sender = the holder DID, `body = { "approved": bool,
//!   "challenge": "<hex echoed>" }`.
//!
//! Auth model: the authcrypt envelope *is* the authentication. The
//! response is only honoured if its authcrypt sender equals the holder
//! DID the request was sent to and the echoed `challenge` matches.

use std::time::Duration;

use affinidi_messaging_didcomm::Message;
use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, warn};

use crate::auth::AdminAuth;
use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::server::{AppState, PendingConfirm};

/// DIDComm message type the RP sends to the wallet.
pub const MSG_WALLET_CONFIRM: &str = "https://trusttasks.org/wallet/confirm/1.0";

/// DIDComm message type the wallet authcrypts back to the RP.
pub const MSG_WALLET_CONFIRM_RESPONSE: &str = "https://trusttasks.org/wallet/confirm-response/1.0";

/// DIDComm listener id the control plane registers (see
/// `server::start_didcomm_service`). Outbound `send_message` calls are
/// scoped to this listener.
const CONTROL_LISTENER_ID: &str = "control";

/// How long the REST request waits for the wallet's decision.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Deserialize)]
pub struct ConfirmRequest {
    /// The wallet holder DID to prompt.
    pub holder_did: String,
    /// Human-readable description of the action being confirmed.
    pub action: String,
}

#[derive(Debug, Serialize)]
pub struct ConfirmResult {
    /// `true` if the user approved, `false` if denied.
    pub approved: bool,
}

/// POST /api/confirm/request — admin-only.
///
/// Generates a random hex `challenge`, sends a `confirm/1.0` DIDComm
/// message to `holder_did`, then waits (up to 60s) for the wallet's
/// authcrypted `confirm-response/1.0`. Returns `{ "approved": bool }`.
pub async fn request(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<ConfirmRequest>,
) -> Result<Json<ConfirmResult>, AppError> {
    if req.holder_did.is_empty() {
        return Err(AppError::Validation("holder_did must not be empty".into()));
    }
    if req.holder_did.len() > 512 {
        return Err(AppError::Validation(
            "holder_did exceeds maximum length".into(),
        ));
    }

    // The control DID is the authcrypt sender of the outbound request.
    let control_did = state
        .config
        .server_did
        .as_deref()
        .ok_or_else(|| AppError::Config("server_did not configured; cannot send confirm".into()))?
        .to_string();

    // The DIDComm service must be up to send + receive the round-trip.
    let svc = state
        .didcomm_service
        .get()
        .ok_or_else(|| AppError::Internal("DIDComm service not started".into()))?;

    // Fresh 16-byte challenge, hex-encoded (mirrors the auth-nonce shape).
    let challenge = rand::random::<[u8; 16]>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    // Register the pending entry *before* sending so a fast wallet
    // response can never arrive before the correlation slot exists.
    let (tx, rx) = tokio::sync::oneshot::channel::<bool>();
    {
        let mut pending = state.pending_confirms.lock().await;
        pending.insert(
            challenge.clone(),
            PendingConfirm {
                holder_did: req.holder_did.clone(),
                tx,
            },
        );
    }

    let message = Message::build(
        uuid::Uuid::new_v4().to_string(),
        MSG_WALLET_CONFIRM.to_string(),
        json!({
            "challenge": challenge,
            "action": req.action,
            "rpName": state.config.server_did,
        }),
    )
    .from(control_did)
    .to(req.holder_did.clone())
    .created_time(now_epoch())
    .finalize();

    info!(
        holder_did = %req.holder_did,
        challenge = %challenge,
        "sending wallet confirm request"
    );

    if let Err(e) = svc
        .send_message(CONTROL_LISTENER_ID, message, &req.holder_did)
        .await
    {
        // Drop the pending entry — no response will ever resolve it.
        state.pending_confirms.lock().await.remove(&challenge);
        return Err(AppError::Internal(format!(
            "failed to send confirm request: {e}"
        )));
    }

    match tokio::time::timeout(CONFIRM_TIMEOUT, rx).await {
        Ok(Ok(approved)) => {
            info!(holder_did = %req.holder_did, approved, "wallet confirm resolved");
            Ok(Json(ConfirmResult { approved }))
        }
        Ok(Err(_recv_err)) => {
            // Sender dropped without sending — the pending entry was
            // already removed by the response handler. Treat as internal.
            state.pending_confirms.lock().await.remove(&challenge);
            Err(AppError::Internal(
                "confirm channel closed before a decision arrived".into(),
            ))
        }
        Err(_timed_out) => {
            // Remove the abandoned pending entry on timeout.
            state.pending_confirms.lock().await.remove(&challenge);
            warn!(holder_did = %req.holder_did, "wallet confirm timed out");
            Err(AppError::Internal(
                "wallet did not respond within the confirmation window".into(),
            ))
        }
    }
}
