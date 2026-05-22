use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tracing::{debug, warn};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("store error: {0}")]
    Store(String),

    #[error("secret store error: {0}")]
    SecretStore(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("authentication error: {0}")]
    Authentication(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    /// The caller is authenticated but the operation requires a higher
    /// assurance level (`acr == aal2`) than the session currently holds.
    /// Renders to 403 with the distinct body `{ "error":
    /// "step_up_required", "required_acr": "aal2" }` so the wallet can
    /// trigger a step-up ceremony rather than treating it as a plain
    /// permission denial.
    #[error("step-up required: {0}")]
    StepUpRequired(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("quota exceeded: {0}")]
    QuotaExceeded(String),

    // ---- Trust-Tasks transport errors (REST `Trust-Task:` header) ----
    //
    // Surfaced by `super::trust_task` (router + extractor). The router
    // enforces exact-match at attach time; the response body for these
    // variants is structured (`{ "error": "<VariantName>", ... }`) so
    // callers can switch on the discriminant without parsing prose.
    /// `Trust-Task` header was absent on a route that requires it.
    /// Renders to 400 Bad Request with body `{ "error": "TrustTaskMissing" }`.
    #[error("Trust-Task header missing")]
    TrustTaskMissing,

    /// `Trust-Task` header was present but malformed (non-HTTPS, empty,
    /// or contained control characters). Carries the offending value so
    /// callers can debug. Renders to 400 with body
    /// `{ "error": "TrustTaskMalformed", "received": "..." }`.
    #[error("Trust-Task header malformed: {0}")]
    TrustTaskMalformed(String),

    /// `Trust-Task` header was well-formed but did not exact-match the
    /// route's registered task. Renders to 415 Unsupported Media Type
    /// with body `{ "error": "TrustTaskMismatch", "expected": "...",
    /// "received": "..." }`.
    #[error("Trust-Task header mismatch: expected {expected}, got {received:?}")]
    TrustTaskMismatch {
        expected: String,
        received: Option<String>,
    },

    /// Resolution attempted against a configured-but-disabled domain.
    /// Per `docs/multi-domain-spec.md` §3, renders to **503** with the
    /// maintenance-status JSON body `{ "status": "disabled", "domain":
    /// "<name>", "message"?, "eta"? }`. Distinct from `NotFound` —
    /// 404 means "we don't serve this", 503 means "we serve this but
    /// it's temporarily unavailable".
    #[error("domain '{domain}' is disabled")]
    DomainDisabled {
        domain: String,
        message: Option<String>,
    },
}

/// Semantic tags for finer-grained error classification without string matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationKind {
    InvalidLog,
    InvalidPath,
    InvalidWitness,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaKind {
    Size,
    Count,
}

impl AppError {
    /// Create a tagged validation error.
    pub fn validation(kind: ValidationKind, msg: impl Into<String>) -> Self {
        let mut s = msg.into();
        // Embed a machine-readable tag prefix for structured matching
        let tag = match kind {
            ValidationKind::InvalidLog => "[log]",
            ValidationKind::InvalidPath => "[path]",
            ValidationKind::InvalidWitness => "[witness]",
            ValidationKind::Other => "",
        };
        if !tag.is_empty() {
            s = format!("{tag} {s}");
        }
        AppError::Validation(s)
    }

    /// Classify a Validation error's kind by its tag prefix.
    pub fn validation_kind(&self) -> ValidationKind {
        match self {
            AppError::Validation(msg) => {
                if msg.starts_with("[log]") {
                    ValidationKind::InvalidLog
                } else if msg.starts_with("[path]") {
                    ValidationKind::InvalidPath
                } else if msg.starts_with("[witness]") {
                    ValidationKind::InvalidWitness
                } else {
                    ValidationKind::Other
                }
            }
            _ => ValidationKind::Other,
        }
    }

    /// Classify a QuotaExceeded error's kind by its content.
    pub fn quota_kind(&self) -> QuotaKind {
        match self {
            AppError::QuotaExceeded(msg) if msg.contains("size") => QuotaKind::Size,
            _ => QuotaKind::Count,
        }
    }
}

/// Maximum length of a user-facing error message in an HTTP response
/// body. Prevents accidental reflection of unbounded user input
/// (long DIDs, large pasted blobs) into logs and headers.
const MAX_USER_MESSAGE_LEN: usize = 256;

/// Strip ASCII control characters and cap length. Used for variants
/// whose `Display` includes user-supplied input — Validation, Conflict,
/// QuotaExceeded — to prevent log injection / response splitting via a
/// caller-controlled string and to bound response-body size.
fn sanitize_user_message(s: &str) -> String {
    let mut out: String = s.chars().filter(|c| !c.is_ascii_control()).collect();
    if out.len() > MAX_USER_MESSAGE_LEN {
        out.truncate(MAX_USER_MESSAGE_LEN);
        out.push('…');
    }
    out
}

impl AppError {
    /// Stable wire-level DIDComm protocol-error code for this `AppError`.
    ///
    /// Backed by `ValidationKind` tags rather than substring sniffing on
    /// the `Display` message, so a wording change in any
    /// `AppError::Validation("...")` literal doesn't silently re-route
    /// the protocol code. Both DIDComm dispatchers
    /// (`messaging::dispatch_did_op` and `routes/didcomm.rs::dispatch`)
    /// call this so the same error always produces the same wire code
    /// regardless of transport.
    ///
    /// The mapping:
    /// - `Unauthorized` / `Forbidden` → `e.p.did.unauthorized`
    /// - `QuotaExceeded(Size)` → `e.p.did.size-exceeded`
    /// - `QuotaExceeded(Count)` → `e.p.did.quota-exceeded`
    /// - `Conflict` → `e.p.did.path-unavailable`
    /// - `NotFound` → `e.p.did.mnemonic-not-found`
    /// - `Validation(InvalidLog)` → `e.p.did.invalid-log`
    /// - `Validation(InvalidPath)` → `e.p.did.path-invalid`
    /// - `Validation(InvalidWitness)` → `e.p.did.witness-invalid`
    /// - `Validation(Other)` → `e.p.did.validation-error`
    /// - everything else (5xx-shaped) → `e.p.did.internal-error`
    pub fn didcomm_code(&self) -> &'static str {
        match self {
            AppError::Unauthorized(_) | AppError::Forbidden(_) => "e.p.did.unauthorized",
            AppError::QuotaExceeded(_) => match self.quota_kind() {
                QuotaKind::Size => "e.p.did.size-exceeded",
                QuotaKind::Count => "e.p.did.quota-exceeded",
            },
            AppError::Conflict(_) => "e.p.did.path-unavailable",
            AppError::NotFound(_) => "e.p.did.mnemonic-not-found",
            AppError::Validation(_) => match self.validation_kind() {
                ValidationKind::InvalidLog => "e.p.did.invalid-log",
                ValidationKind::InvalidPath => "e.p.did.path-invalid",
                ValidationKind::InvalidWitness => "e.p.did.witness-invalid",
                ValidationKind::Other => "e.p.did.validation-error",
            },
            _ => "e.p.did.internal-error",
        }
    }

    /// Stable public message intended for HTTP responses. Decoupled from
    /// `Display` (which tracing/logging uses) so the wire-level contract
    /// doesn't drift when an `AppError(...)` literal's wording changes
    /// elsewhere.
    ///
    /// Variants that name internal identifiers (`Forbidden` may carry a
    /// DID or ACL reason; `NotFound` may include a mnemonic) collapse
    /// to a fixed string. Variants that are user-input-shaped
    /// (`Validation`, `Conflict`, `QuotaExceeded`) pass the message
    /// through `sanitize_user_message` so a caller can't get arbitrary
    /// control characters echoed back. 5xx variants never reach this
    /// path (the response builder short-circuits to a generic body).
    pub fn user_message(&self) -> String {
        match self {
            AppError::NotFound(_) => "not found".into(),
            AppError::Authentication(_) => "authentication failed".into(),
            AppError::Unauthorized(_) => "unauthorized".into(),
            AppError::Forbidden(_) => "forbidden".into(),
            AppError::StepUpRequired(_) => "step_up_required".into(),
            AppError::Validation(msg) => sanitize_user_message(msg),
            AppError::Conflict(msg) => sanitize_user_message(msg),
            AppError::QuotaExceeded(msg) => sanitize_user_message(msg),
            // 5xx variants — covered by the server-error branch in
            // into_response — but return a stable string here too in
            // case anyone calls `user_message()` directly.
            _ => "internal error".into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::SecretStore(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Serialization(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::Authentication(_) => StatusCode::UNAUTHORIZED,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::StepUpRequired(_) => StatusCode::FORBIDDEN,
            AppError::Validation(_) => StatusCode::BAD_REQUEST,
            AppError::QuotaExceeded(_) => StatusCode::FORBIDDEN,
            AppError::TrustTaskMissing => StatusCode::BAD_REQUEST,
            AppError::TrustTaskMalformed(_) => StatusCode::BAD_REQUEST,
            AppError::TrustTaskMismatch { .. } => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            AppError::DomainDisabled { .. } => StatusCode::SERVICE_UNAVAILABLE,
        };

        // DomainDisabled is a 5xx but the body is part of the public
        // contract (status / domain / message) so clients can render a
        // maintenance page. Fall through to the structured-body branch
        // below; everything else 5xx collapses to a generic message.
        if status.is_server_error() && !matches!(self, AppError::DomainDisabled { .. }) {
            warn!(status = %status.as_u16(), error = %self, "server error");
            let body = serde_json::json!({ "error": "internal server error" });
            return (status, axum::Json(body)).into_response();
        }

        debug!(status = %status.as_u16(), error = %self, "client error");

        // Trust-Task variants use a structured body so callers can switch
        // on the discriminant. Match the VTI canonical impl's shape so
        // the parity harness in T9 can assert byte-equivalent responses.
        let body = match &self {
            AppError::TrustTaskMissing => serde_json::json!({ "error": "TrustTaskMissing" }),
            AppError::TrustTaskMalformed(received) => serde_json::json!({
                "error": "TrustTaskMalformed",
                "received": received,
            }),
            AppError::TrustTaskMismatch { expected, received } => serde_json::json!({
                "error": "TrustTaskMismatch",
                "expected": expected,
                "received": received,
            }),
            AppError::DomainDisabled { domain, message } => serde_json::json!({
                "status": "disabled",
                "domain": domain,
                "message": message,
            }),
            AppError::StepUpRequired(_) => serde_json::json!({
                "error": "step_up_required",
                "required_acr": "aal2",
            }),
            _ => serde_json::json!({ "error": self.user_message() }),
        };
        (status, axum::Json(body)).into_response()
    }
}

#[cfg(test)]
mod response_tests {
    use super::*;

    #[test]
    fn forbidden_always_collapses_to_fixed_string() {
        // Pre-fix behaviour: substring `"ACL"` redacted, but
        // "not the owner of this DID" leaked through. Now both collapse.
        let leaky = AppError::Forbidden("not the owner of this DID".into());
        assert_eq!(leaky.user_message(), "forbidden");
        let acl = AppError::Forbidden("DID not in the ACL: did:web:bob".into());
        assert_eq!(acl.user_message(), "forbidden");
    }

    #[test]
    fn validation_strips_control_chars() {
        // Caller submits `did:web:tenant\nrest` as new_owner; the
        // resulting Validation message would otherwise reflect the
        // newline back into the response body.
        let err = AppError::Validation("bad input: did:web:t\nrest".into());
        let msg = err.user_message();
        assert!(!msg.contains('\n'));
        assert!(!msg.contains('\r'));
    }

    #[test]
    fn validation_caps_length() {
        let huge = "x".repeat(MAX_USER_MESSAGE_LEN + 100);
        let err = AppError::Validation(huge);
        let msg = err.user_message();
        assert!(msg.chars().count() <= MAX_USER_MESSAGE_LEN + 1); // +1 for '…'
        assert!(msg.ends_with('…'));
    }

    #[test]
    fn validation_preserves_short_messages_unchanged() {
        let err = AppError::Validation("path 'foo' is already taken".into());
        assert_eq!(err.user_message(), "path 'foo' is already taken");
    }

    #[test]
    fn not_found_does_not_leak_mnemonic() {
        let err = AppError::NotFound("DID not found: super-secret-mnemonic".into());
        assert_eq!(err.user_message(), "not found");
    }
}
