//! [`AppError`]: the error type every service returns, its HTTP mapping and
//! the typed validation kinds callers match on.

use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use tracing::{debug, warn};

/// Response header naming the service whose own limiter refused a request.
///
/// Part of the ecosystem-wide 429 contract: every refusal a service's *own*
/// limiter emits carries this header, so a client can tell it apart from a
/// `429` raised by a reverse proxy, a load balancer, or another service on the
/// path (the VTA sends `vta`, the VTC `vtc`, the mediator `mediator`). A `429`
/// without it is, by contract, unattributable. The VTI client reads it in
/// `vta_sdk::rate_limit`.
pub const RATE_LIMIT_SOURCE_HEADER: &str = "x-rate-limit-source";

/// This workspace's value for [`RATE_LIMIT_SOURCE_HEADER`]. Every binary here
/// (control, server, daemon, witness) is a DID host from the client's point of
/// view, and the operator guidance a client prints for `did-host` applies to
/// all of them.
pub const RATE_LIMIT_SOURCE: &str = "did-host";

/// Limiter name for the per-DID cap on concurrently pending auth challenges.
pub const LIMITER_PENDING_CHALLENGES_PER_DID: &str = "auth-challenge-pending-per-did";

/// Retry hint for a pending-challenge cap raised where the deployment's
/// configured timings are not known (the conversion from the canonical
/// `AuthError`): `AuthConfig::pending_challenge_retry_after_secs` over the
/// default `challenge_ttl` and `session_cleanup_interval`. Route handlers
/// substitute the configured values via [`AppError::with_retry_after`].
pub const DEFAULT_PENDING_CHALLENGE_RETRY_AFTER_SECS: u64 = 30 + 600;

/// [`AppError::RateLimited::limiter`] for a store request the store refused
/// for its throughput: the store's limit, not this service's.
pub const LIMITER_STORE_THROUGHPUT: &str = "store-throughput";

/// [`AppError::RateLimited::limiter`] for a signed request refused because
/// the replay cache is at a bound.
pub const LIMITER_REPLAY_CACHE: &str = "replay-cache";

/// What a caller is told to wait after a throttled store request. Short: the
/// store's SDK has already backed off, and a client backs off further on
/// repeats.
pub const STORE_THROTTLED_RETRY_AFTER_SECS: u64 = 2;

/// The `message` of an [`AppError::InvalidForwardedFor`] body: the
/// `affinidi-rate-limit` layer's own wording, so a handler's refusal and the
/// layer's are byte-identical.
pub const INVALID_FORWARDED_FOR_MESSAGE: &str = "Invalid X-Forwarded-For header; request rejected.";

/// The instant `secs` from now: a Trust Task `retryAfter`.
pub fn retry_at(secs: u64) -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() + chrono::Duration::seconds(secs as i64)
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("store error: {0}")]
    Store(String),

    /// The store is held by another process (an embedded store's lock file),
    /// typically a running service. Distinct from [`AppError::Store`] so a
    /// caller such as the health check can say so without reading the
    /// backend's wording.
    #[error("store locked: {0}")]
    StoreLocked(String),

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

    /// The request is malformed or refused on its content. `kind` is the
    /// machine-readable classification wire codes are chosen from; `message`
    /// is for people and never read for that purpose.
    #[error("validation error: {message}")]
    Validation {
        kind: ValidationKind,
        message: String,
    },

    /// A limit on what may be stored was reached. `kind` says which limit;
    /// `message` is for people and never read for that purpose.
    #[error("quota exceeded: {message}")]
    QuotaExceeded { kind: QuotaKind, message: String },

    /// One of this service's own rate limiters refused the request, or the
    /// service is over capacity for now (a throttled store, a full replay
    /// cache): either way, retrying after `retry_after_secs` can succeed.
    ///
    /// Renders to **429** with `x-rate-limit-source: did-host`, a
    /// `Retry-After` in seconds, and the body `{ "error": "rate_limited",
    /// "limiter": "<limiter>", "message": "...", "retryAfterSecs": N }`.
    /// Deliberately not `Validation`: a refusal rendered as `400` reads as a
    /// malformed request, so no client can recognise it as a limit and back
    /// off.
    #[error("rate limited ({limiter}): {message}")]
    RateLimited {
        /// Stable, machine-readable name of the limiter that refused, so an
        /// operator can tell which limit applies.
        limiter: &'static str,
        message: String,
        /// Seconds after which a retry can succeed. Rendered as at least 1.
        retry_after_secs: u64,
    },

    /// A trusted proxy sent an `X-Forwarded-For` chain that cannot be
    /// attributed to a client, so the request cannot be charged to anyone.
    ///
    /// Renders to **400** exactly as the `affinidi-rate-limit` layer refuses
    /// it on DID resolution: `x-rate-limit-source: did-host` and the body
    /// `{ "error": "invalid_forwarded_for", "limiter": "<limiter>",
    /// "message": "..." }`, so the condition reads the same on every route.
    #[error("invalid X-Forwarded-For chain from a trusted proxy ({limiter})")]
    InvalidForwardedFor {
        /// The limiter that could not attribute the request.
        limiter: &'static str,
    },

    // ---- Trust-Tasks `Trust-Task:` header errors ----
    //
    // From the header-tagged REST binding, which is gone: nothing in this
    // workspace constructs these variants now. Their response body is structured (`{ "error": "<VariantName>", ... }`) so
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
    /// Per `docs/archive/multi-domain-spec.md` §3, renders to **503** with the
    /// maintenance-status JSON body `{ "status": "disabled", "domain":
    /// "<name>", "message"?, "eta"? }`. Distinct from `NotFound` —
    /// 404 means "we don't serve this", 503 means "we serve this but
    /// it's temporarily unavailable".
    #[error("domain '{domain}' is disabled")]
    DomainDisabled {
        domain: String,
        message: Option<String>,
    },

    /// An agent-name operation (`did_ops::set_agent_name` and friends) failed
    /// a name-specific precondition. Carries a typed [`AgentNameError`] so the
    /// Trust Task surface can map it to a spec error code without
    /// sniffing message prose — the same discipline `ValidationKind` follows.
    #[error("agent name error: {0}")]
    AgentName(#[from] AgentNameError),
}

/// Failure modes specific to the agent-name operations. Kept as a typed enum,
/// rather than folded into `Validation`/`Conflict`/`NotFound`, so each maps
/// one-to-one onto its `did-management/agent-name/*` spec error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AgentNameError {
    /// The requested name is on the host's reserved list (`@admin`,
    /// `@support`, …) → `name_reserved`.
    #[error("agent name is reserved")]
    Reserved,

    /// The name is already bound to a different DID on this domain →
    /// `name_taken`.
    #[error("agent name is already taken")]
    Taken,

    /// No such name is bound to this DID → `not_found`.
    #[error("agent name not found")]
    NotFound,

    /// An `enable` target is not in the disabled state → `not_disabled`.
    #[error("agent name is not disabled")]
    NotDisabled,

    /// A `disable` target is already disabled → `already_disabled`.
    #[error("agent name is already disabled")]
    AlreadyDisabled,

    /// The submitted document's `alsoKnownAs` does not match the operation's
    /// requirement — it must claim the name for `set`/`enable`, and must not
    /// for `remove`/`disable` → `also_known_as_mismatch`.
    #[error("submitted document's alsoKnownAs does not match the requested name")]
    AlsoKnownAsMismatch,
}

impl AgentNameError {
    /// The HTTP status this failure renders to.
    fn http_status(self) -> StatusCode {
        match self {
            AgentNameError::NotFound => StatusCode::NOT_FOUND,
            AgentNameError::Reserved
            | AgentNameError::Taken
            | AgentNameError::NotDisabled
            | AgentNameError::AlreadyDisabled => StatusCode::CONFLICT,
            AgentNameError::AlsoKnownAsMismatch => StatusCode::BAD_REQUEST,
        }
    }
}

/// What an [`AppError::Validation`] refused, carried in the variant so wire
/// codes are chosen without reading the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationKind {
    /// The DID data (log, key event log, document) does not verify.
    InvalidLog,
    InvalidPath,
    InvalidWitness,
    /// A log that does not extend the history already served for its DID: a
    /// rollback, a fork, or a slot asked to change method.
    HistoryRewrite,
    /// A change to a DID whose history already deactivated it.
    Deactivated,
    /// The request names a domain the caller may not use, or that is not
    /// served (`did-management:unknown_domain`).
    UnknownDomain,
    /// A version number outside the slot's log (a rollback target below 1 or
    /// past the last entry).
    InvalidTargetVersion,
    Other,
}

/// Which limit an [`AppError::QuotaExceeded`] reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaKind {
    /// One item is larger than may be stored.
    Size,
    /// A count limit (DIDs per owner, say) was reached.
    Count,
}

/// Conversion from the canonical auth-flow errors in
/// vti-common into did-hosting's `AppError`. Mirrors the
/// `From<AuthError> for vti_common::AppError` impl on the
/// VTI side — the canonical /auth/* handlers raise
/// `vti_common::AuthError` variants and each service's
/// `AppError` knows how to render them through its own
/// `IntoResponse` plumbing.
impl From<vti_common::auth::backend::AuthError> for AppError {
    fn from(e: vti_common::auth::backend::AuthError) -> Self {
        use vti_common::auth::backend::AuthError as A;
        match e {
            A::Forbidden | A::DidMethodRejected => AppError::Forbidden(e.to_string()),
            A::PendingChallengeLimitReached => AppError::RateLimited {
                limiter: LIMITER_PENDING_CHALLENGES_PER_DID,
                message: e.to_string(),
                retry_after_secs: DEFAULT_PENDING_CHALLENGE_RETRY_AFTER_SECS,
            },
            A::SessionNotFound
            | A::SessionStateMismatch
            | A::ChallengeMismatch
            | A::ChallengeExpired
            | A::SignerMismatch
            | A::StaleMessage
            | A::RefreshTokenInvalid
            | A::RefreshTokenExpired
            | A::SessionIdleTimeout
            | A::WrongRecipient { .. } => AppError::Authentication(e.to_string()),
            A::MissingRecipient => AppError::invalid(e.to_string()),
            A::AttestationFailed(msg) => AppError::Internal(format!("tee attestation: {msg}")),
            A::Internal(msg) => AppError::Internal(msg),
            // `AuthError` is `#[non_exhaustive]` since vti-common 0.20, so a
            // wildcard is mandatory here. A variant this build does not know
            // is still an auth-flow refusal: fail closed as a 401 rather than
            // surface it as a server fault.
            _ => AppError::Authentication(e.to_string()),
        }
    }
}

impl AppError {
    /// A store request the store refused for its throughput (after its own
    /// retries). The message names nothing internal: the operation goes in
    /// the operator log.
    pub fn store_throttled() -> Self {
        AppError::RateLimited {
            limiter: LIMITER_STORE_THROUGHPUT,
            message: "the store is over its throughput; retry later".into(),
            retry_after_secs: STORE_THROTTLED_RETRY_AFTER_SECS,
        }
    }

    /// Whether this is [`Self::store_throttled`].
    pub fn is_store_throttled(&self) -> bool {
        matches!(
            self,
            AppError::RateLimited {
                limiter: LIMITER_STORE_THROUGHPUT,
                ..
            }
        )
    }

    /// The Trust Task refusal for a failure that says nothing about the
    /// request or its sender (a store or internal error met while deciding):
    /// `unavailable` with `retryAfter` when this service is over capacity, so
    /// the sender retries; else `internalError` with a fixed message, the
    /// detail being for the operator log.
    pub fn failure_reject_reason(&self) -> trust_tasks_rs::RejectReason {
        match self.retry_after_secs() {
            Some(secs) => trust_tasks_rs::RejectReason::Unavailable {
                retry_after: Some(retry_at(secs)),
            },
            None => trust_tasks_rs::RejectReason::InternalError {
                reason: "the maintainer encountered an internal failure".into(),
            },
        }
    }

    /// Seconds after which a retry can succeed, for a refusal that is only
    /// about load ([`AppError::RateLimited`]).
    pub fn retry_after_secs(&self) -> Option<u64> {
        match self {
            AppError::RateLimited {
                retry_after_secs, ..
            } => Some((*retry_after_secs).max(1)),
            _ => None,
        }
    }

    /// Replace the retry hint on an [`AppError::RateLimited`]; any other
    /// variant is returned unchanged. For route handlers that know the
    /// deployment's configured timings when the refusal was raised by code
    /// that does not (the canonical challenge handler).
    pub fn with_retry_after(self, secs: u64) -> Self {
        match self {
            AppError::RateLimited {
                limiter, message, ..
            } => AppError::RateLimited {
                limiter,
                message,
                retry_after_secs: secs,
            },
            other => other,
        }
    }

    /// A validation error of `kind`.
    pub fn validation(kind: ValidationKind, msg: impl Into<String>) -> Self {
        AppError::Validation {
            kind,
            message: msg.into(),
        }
    }

    /// A validation error no more specific kind applies to
    /// ([`ValidationKind::Other`]).
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::validation(ValidationKind::Other, msg)
    }

    /// A quota error of `kind`.
    pub fn quota(kind: QuotaKind, msg: impl Into<String>) -> Self {
        AppError::QuotaExceeded {
            kind,
            message: msg.into(),
        }
    }

    /// The kind of a [`AppError::Validation`]; [`ValidationKind::Other`] for
    /// any other variant.
    pub fn validation_kind(&self) -> ValidationKind {
        match self {
            AppError::Validation { kind, .. } => *kind,
            _ => ValidationKind::Other,
        }
    }

    /// The kind of a [`AppError::QuotaExceeded`]; [`QuotaKind::Count`] for any
    /// other variant.
    pub fn quota_kind(&self) -> QuotaKind {
        match self {
            AppError::QuotaExceeded { kind, .. } => *kind,
            _ => QuotaKind::Count,
        }
    }

    /// The message of a [`AppError::Validation`], `None` for any other
    /// variant.
    pub fn validation_message(&self) -> Option<&str> {
        match self {
            AppError::Validation { message, .. } => Some(message),
            _ => None,
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
        // On a character boundary: `String::truncate` panics mid-character,
        // and this text is caller-supplied.
        out.truncate(out.floor_char_boundary(MAX_USER_MESSAGE_LEN));
        out.push('…');
    }
    out
}

impl AppError {
    /// Stable wire-level DIDComm protocol-error code for this `AppError`.
    ///
    /// Backed by `ValidationKind` tags rather than substring sniffing on
    /// the `Display` message, so a wording change in any
    /// `AppError::invalid("...")` literal doesn't silently re-route
    /// the protocol code: the same error always produces the same wire
    /// code.
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
            AppError::QuotaExceeded { kind, .. } => match kind {
                QuotaKind::Size => "e.p.did.size-exceeded",
                QuotaKind::Count => "e.p.did.quota-exceeded",
            },
            AppError::Conflict(_) => "e.p.did.path-unavailable",
            AppError::NotFound(_) => "e.p.did.mnemonic-not-found",
            AppError::Validation { kind, .. } => match kind {
                ValidationKind::InvalidLog => "e.p.did.invalid-log",
                ValidationKind::InvalidPath => "e.p.did.path-invalid",
                ValidationKind::InvalidWitness => "e.p.did.witness-invalid",
                // Never tagged before these kinds existed: their code is unchanged.
                ValidationKind::HistoryRewrite
                | ValidationKind::Deactivated
                | ValidationKind::UnknownDomain
                | ValidationKind::InvalidTargetVersion
                | ValidationKind::Other => "e.p.did.validation-error",
            },
            // Legacy did-management DIDComm codes for agent-name failures. The
            // dedicated agent-name Trust Tasks (PR 4) carry their own spec
            // error codes in the response; these keep a stray agent-name error
            // on the old dispatch path from collapsing to `internal-error`.
            AppError::AgentName(e) => match e {
                AgentNameError::NotFound => "e.p.did.mnemonic-not-found",
                AgentNameError::Reserved => "e.p.did.path-invalid",
                AgentNameError::Taken => "e.p.did.path-unavailable",
                AgentNameError::NotDisabled
                | AgentNameError::AlreadyDisabled
                | AgentNameError::AlsoKnownAsMismatch => "e.p.did.validation-error",
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
            AppError::Validation { message, .. } => sanitize_user_message(message),
            AppError::Conflict(msg) => sanitize_user_message(msg),
            AppError::QuotaExceeded { message, .. } => sanitize_user_message(message),
            AppError::RateLimited { message, .. } => sanitize_user_message(message),
            // Fixed, name-free strings — safe to surface verbatim.
            AppError::AgentName(e) => e.to_string(),
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
            AppError::StoreLocked(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::SecretStore(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Serialization(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::Authentication(_) => StatusCode::UNAUTHORIZED,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::StepUpRequired(_) => StatusCode::FORBIDDEN,
            AppError::Validation { .. } => StatusCode::BAD_REQUEST,
            AppError::QuotaExceeded { .. } => StatusCode::FORBIDDEN,
            AppError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            AppError::InvalidForwardedFor { .. } => StatusCode::BAD_REQUEST,
            AppError::TrustTaskMissing => StatusCode::BAD_REQUEST,
            AppError::TrustTaskMalformed(_) => StatusCode::BAD_REQUEST,
            AppError::TrustTaskMismatch { .. } => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            AppError::DomainDisabled { .. } => StatusCode::SERVICE_UNAVAILABLE,
            AppError::AgentName(e) => e.http_status(),
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

        if let AppError::RateLimited {
            limiter,
            message,
            retry_after_secs,
        } = &self
        {
            // `Retry-After: 0` would invite an immediate retry into the same
            // refusal; one second is the smallest honest hint.
            let retry_after_secs = (*retry_after_secs).max(1);
            let body = serde_json::json!({
                "error": "rate_limited",
                "limiter": limiter,
                "message": sanitize_user_message(message),
                "retryAfterSecs": retry_after_secs,
            });
            let mut response = (status, axum::Json(body)).into_response();
            let headers = response.headers_mut();
            headers.insert(
                RATE_LIMIT_SOURCE_HEADER,
                HeaderValue::from_static(RATE_LIMIT_SOURCE),
            );
            headers.insert(
                axum::http::header::RETRY_AFTER,
                HeaderValue::from(retry_after_secs),
            );
            return response;
        }

        if let AppError::InvalidForwardedFor { limiter } = &self {
            let body = serde_json::json!({
                "error": affinidi_rate_limit::INVALID_FORWARDED_FOR_ERROR,
                "limiter": limiter,
                "message": INVALID_FORWARDED_FOR_MESSAGE,
            });
            let mut response = (status, axum::Json(body)).into_response();
            response.headers_mut().insert(
                RATE_LIMIT_SOURCE_HEADER,
                HeaderValue::from_static(RATE_LIMIT_SOURCE),
            );
            return response;
        }

        // Trust-Task variants use a structured body so callers can switch
        // on the discriminant. Match the VTI canonical impl's shape so
        // the two can be compared byte for byte.
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

    /// The kind is carried, not read back out of the message: a quota message
    /// that mentions "size" is still a count limit, and the reverse (#367).
    #[test]
    fn a_quota_code_follows_its_kind_not_its_wording() {
        let count = AppError::quota(QuotaKind::Count, "size of the DID count limit reached");
        assert_eq!(count.didcomm_code(), "e.p.did.quota-exceeded");
        let size = AppError::quota(QuotaKind::Size, "over the store's limit");
        assert_eq!(size.didcomm_code(), "e.p.did.size-exceeded");
    }

    /// A validation kind changes the code and nothing in the message: the
    /// `[log]`-style tags no longer leak into what a client reads.
    #[test]
    fn a_validation_kind_is_not_written_into_the_message() {
        let err = AppError::validation(ValidationKind::InvalidLog, "the chain does not verify");
        assert_eq!(err.didcomm_code(), "e.p.did.invalid-log");
        assert_eq!(err.user_message(), "the chain does not verify");
        // Text that looks like an old tag is just text.
        let untagged = AppError::invalid("[log] not a tag");
        assert_eq!(untagged.validation_kind(), ValidationKind::Other);
        assert_eq!(untagged.didcomm_code(), "e.p.did.validation-error");
        // The kinds added for the edge's history check keep the code an
        // untagged message always had.
        for kind in [
            ValidationKind::HistoryRewrite,
            ValidationKind::Deactivated,
            ValidationKind::UnknownDomain,
            ValidationKind::InvalidTargetVersion,
        ] {
            assert_eq!(
                AppError::validation(kind, "x").didcomm_code(),
                "e.p.did.validation-error"
            );
        }
    }

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
        let err = AppError::invalid("bad input: did:web:t\nrest");
        let msg = err.user_message();
        assert!(!msg.contains('\n'));
        assert!(!msg.contains('\r'));
    }

    #[test]
    fn validation_caps_length() {
        let huge = "x".repeat(MAX_USER_MESSAGE_LEN + 100);
        let err = AppError::invalid(huge);
        let msg = err.user_message();
        assert!(msg.chars().count() <= MAX_USER_MESSAGE_LEN + 1); // +1 for '…'
        assert!(msg.ends_with('…'));
    }

    #[test]
    fn validation_caps_length_on_a_character_boundary() {
        // A two-byte character straddling the cap.
        let text = format!(
            "{}é{}",
            "x".repeat(MAX_USER_MESSAGE_LEN - 1),
            "y".repeat(50)
        );
        let msg = AppError::invalid(text).user_message();
        assert_eq!(msg, format!("{}…", "x".repeat(MAX_USER_MESSAGE_LEN - 1)));
        let msg = AppError::Conflict("😀".repeat(200)).user_message();
        assert!(msg.ends_with('…'));
        assert!(msg.len() <= MAX_USER_MESSAGE_LEN + '…'.len_utf8());
    }

    #[test]
    fn validation_preserves_short_messages_unchanged() {
        let err = AppError::invalid("path 'foo' is already taken");
        assert_eq!(err.user_message(), "path 'foo' is already taken");
    }

    #[tokio::test]
    async fn rate_limited_renders_the_429_contract() {
        use http_body_util::BodyExt;

        let response = AppError::RateLimited {
            limiter: "auth-challenge-per-ip",
            message: "slow down".into(),
            retry_after_secs: 17,
        }
        .into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()["x-rate-limit-source"], "did-host");
        assert_eq!(response.headers()["retry-after"], "17");
        assert_eq!(response.headers()["content-type"], "application/json");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "error": "rate_limited",
                "limiter": "auth-challenge-per-ip",
                "message": "slow down",
                "retryAfterSecs": 17,
            })
        );
    }

    /// A zero hint would invite an immediate retry into the same refusal.
    #[test]
    fn rate_limited_retry_after_is_at_least_one_second() {
        let response = AppError::RateLimited {
            limiter: "x",
            message: String::new(),
            retry_after_secs: 0,
        }
        .into_response();
        assert_eq!(response.headers()["retry-after"], "1");
    }

    #[test]
    fn pending_challenge_limit_is_a_rate_limit_not_a_validation_error() {
        let err: AppError =
            vti_common::auth::backend::AuthError::PendingChallengeLimitReached.into();
        assert!(matches!(
            err,
            AppError::RateLimited {
                limiter: LIMITER_PENDING_CHALLENGES_PER_DID,
                ..
            }
        ));
        assert!(matches!(
            err.with_retry_after(42),
            AppError::RateLimited {
                retry_after_secs: 42,
                ..
            }
        ));
        assert!(matches!(
            AppError::Conflict("c".into()).with_retry_after(5),
            AppError::Conflict(_)
        ));
    }

    #[test]
    fn not_found_does_not_leak_mnemonic() {
        let err = AppError::NotFound("DID not found: super-secret-mnemonic".into());
        assert_eq!(err.user_message(), "not found");
    }
}
