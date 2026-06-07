//! Axum extractor + middleware function for the `Trust-Task` header.
//!
//! Two surfaces:
//!
//! - [`TrustTaskHeader`] — extractor for handlers that want to **read**
//!   the validated task. Useful for diagnostic endpoints; routes that
//!   only need to **enforce** the task should use
//!   [`super::router::TrustTaskRouter`] instead.
//! - [`validate_header`] — the middleware function the router builder
//!   layers onto each route. Public-crate (`pub(crate)`) so the router
//!   can compose it; not part of the user-facing API.

use axum::extract::{FromRequestParts, Request};
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::Response;

use super::{HEADER_NAME, TrustTask};
use crate::server::error::AppError;

/// Axum extractor: pulls the `Trust-Task` header off a request and
/// parses it into a validated [`TrustTask`].
///
/// Rejections (per spec §16.2):
/// - missing header → [`AppError::TrustTaskMissing`] (400)
/// - malformed value → [`AppError::TrustTaskMalformed`] (400)
/// - non-UTF-8 header → [`AppError::Validation`] (400)
///
/// **Note**: using this extractor *does not* enforce exact-match against
/// a handler's expected task. That correctness check lives in
/// [`super::router::TrustTaskRouter::route_with_task`]. Use this
/// extractor only when a handler genuinely needs to read the task
/// (e.g. for logging or for forwarding it to another service).
pub struct TrustTaskHeader(pub TrustTask);

impl<S> FromRequestParts<S> for TrustTaskHeader
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let raw = parts
            .headers
            .get(HEADER_NAME)
            .ok_or(AppError::TrustTaskMissing)?;
        let s = raw
            .to_str()
            .map_err(|_| AppError::Validation("Trust-Task header is not valid UTF-8".into()))?;
        let task = TrustTask::new(s)?;
        Ok(Self(task))
    }
}

/// Middleware function: enforce exact-match of the request's
/// `Trust-Task` header against `expected`.
///
/// Wired in by [`super::router::TrustTaskRouter::route_with_task`].
/// Returns the structured `AppError::TrustTaskMismatch` on mismatch
/// (which renders to 415 with a JSON body naming the expected task)
/// and `AppError::TrustTaskMissing` if the header is absent.
pub(crate) async fn validate_header(
    expected: &TrustTask,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let raw = request
        .headers()
        .get(HEADER_NAME)
        .ok_or(AppError::TrustTaskMissing)?;
    let received = raw
        .to_str()
        .map_err(|_| AppError::Validation("Trust-Task header is not valid UTF-8".into()))?;

    if received != expected.as_str() {
        return Err(AppError::TrustTaskMismatch {
            expected: expected.as_str().to_string(),
            received: Some(received.to_string()),
        });
    }

    Ok(next.run(request).await)
}

/// Multi-version permissive variant of [`validate_header_permissive`]:
/// accepts the header when it exact-matches **any** of `accepted`.
///
/// Used by
/// [`super::router::TrustTaskRouter::route_with_tasks_permissive`] to
/// support a spec-version bump without breaking existing clients: the
/// route's current (primary) Type URI sits at `accepted[0]` and any
/// deprecated-but-still-accepted versions follow. Behaviour matches the
/// single-task permissive form otherwise:
///
/// - Header absent → pass through.
/// - Header present + matches any accepted version → pass through.
/// - Header present + matches none → 415 `TrustTaskMismatch`, naming the
///   primary (`accepted[0]`) as `expected`.
/// - Header present + non-UTF-8 → 400 `Validation`.
///
/// `accepted` must be non-empty; the caller (the router builder) always
/// supplies at least the primary task.
pub(crate) async fn validate_header_permissive_any(
    accepted: &[TrustTask],
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let Some(raw) = request.headers().get(HEADER_NAME) else {
        // Header absent — let the request through.
        return Ok(next.run(request).await);
    };
    let received = raw
        .to_str()
        .map_err(|_| AppError::Validation("Trust-Task header is not valid UTF-8".into()))?;

    if accepted.iter().any(|t| t.as_str() == received) {
        return Ok(next.run(request).await);
    }

    Err(AppError::TrustTaskMismatch {
        // Name the primary (current) version as the expected one; the
        // deprecated aliases are an accepted fallback, not the canonical
        // identifier a client should send.
        expected: accepted[0].as_str().to_string(),
        received: Some(received.to_string()),
    })
}

/// Permissive variant of [`validate_header`]: clients MAY send the
/// `Trust-Task` header but aren't required to.
///
/// - Header absent → pass through.
/// - Header present + exact-match → pass through.
/// - Header present + mismatch → 415 `TrustTaskMismatch` (same as
///   strict — once a client opts in to declaring a task, it must
///   declare the right one).
/// - Header present + non-UTF-8 → 400 `Validation` (same as strict).
///
/// Wired in by
/// [`super::router::TrustTaskRouter::route_with_task_permissive`].
pub(crate) async fn validate_header_permissive(
    expected: &TrustTask,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let Some(raw) = request.headers().get(HEADER_NAME) else {
        // Header absent — let the request through.
        return Ok(next.run(request).await);
    };
    let received = raw
        .to_str()
        .map_err(|_| AppError::Validation("Trust-Task header is not valid UTF-8".into()))?;

    if received != expected.as_str() {
        return Err(AppError::TrustTaskMismatch {
            expected: expected.as_str().to_string(),
            received: Some(received.to_string()),
        });
    }

    Ok(next.run(request).await)
}
