//! `ClientError` — the typed error surface shared across the
//! client crate's modules.
//!
//! Variants follow spec §6.4: callers should be able to switch on
//! the discriminant without parsing prose. Each variant maps to a
//! concrete user response (e.g. `Auth` → reauth, `Forbidden` →
//! surface to the user, `Network` → retry with backoff).

use thiserror::Error;

/// Error returned by every public entry point in the client crate.
///
/// The variants are deliberately coarse: the integrator decides what
/// to *do* about each one, so we don't bake in retry policy here.
/// Carry enough context (URL, status, upstream message) that the
/// caller can audit-log a useful trace without further parsing.
#[derive(Debug, Error)]
pub enum ClientError {
    /// The daemon rejected the credentials (401). The integrator
    /// should drop cached tokens and re-run the challenge-response.
    #[error("authentication failed: {0}")]
    Auth(String),

    /// 403 from the daemon — the caller is authenticated but not
    /// permitted to perform the operation. Don't retry; surface to
    /// the user.
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// 404 from the daemon. Distinct from `Validation` because
    /// the request shape was fine; the resource just doesn't exist.
    #[error("not found: {0}")]
    NotFound(String),

    /// 409 — owner-takeover without `force`, slot already owned, etc.
    #[error("conflict: {0}")]
    Conflict(String),

    /// 400 from the daemon, OR a precondition that this crate
    /// enforces locally (e.g. non-HTTPS base URL outside loopback,
    /// malformed input). Carries the upstream message verbatim.
    #[error("validation error: {0}")]
    Validation(String),

    /// Transport-layer failure (connect refused, TLS handshake,
    /// DNS, timeout). Retry candidate.
    #[error("network error: {0}")]
    Network(String),

    /// 5xx from the daemon. Body is included for audit-log clarity
    /// but the daemon's generic 5xx body collapses to a redacted
    /// `internal server error` — the value here is the status
    /// itself.
    #[error("server error ({status}): {body}")]
    Server {
        /// HTTP status code (≥ 500).
        status: u16,
        /// Response body (may be the daemon's structured payload
        /// for `DomainDisabled` 503, otherwise a redacted message).
        body: String,
    },

    /// Wire-level protocol error: the daemon returned a 2xx but
    /// the body didn't decode as the expected type, or a header
    /// invariant was violated (e.g. `Trust-Task` mismatch on a
    /// route the daemon accepted). Indicates a version skew
    /// between client and daemon.
    #[error("protocol error: {0}")]
    Protocol(String),
}

impl ClientError {
    /// Whether the integrator should consider retrying this
    /// operation. Network + 5xx are candidate retries (with
    /// backoff); the others should be surfaced.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Network(_) | Self::Server { .. })
    }
}
