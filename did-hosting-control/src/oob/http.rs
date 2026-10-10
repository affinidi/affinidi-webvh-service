//! The HTTPS binding of `auth/oob/*` on `POST /api/trust-tasks`, and the
//! [`OobEnv`] this control plane supplies.
//!
//! Why here and not a `control_tasks!` row: the table is keyed on generated
//! `Payload::TYPE_URI`s, and `trust-tasks-rs` has no `auth/oob/*` bindings
//! yet. The family is also HTTPS-only by design: the starter is a browser,
//! and the wallet reaches the service over its `TrustTaskHTTPS` service (C4).
//! Once the bindings are published these become rows.
//! TODO: replace with generated trust-tasks types, and move into `control_tasks`.
//!
//! What this layer adds to the state machine:
//! - `Cache-Control: no-store` and `Referrer-Policy: no-referrer` on every
//!   response;
//! - `request` only from the portal's origin (base design 12 item 10);
//! - per-address rate limits;
//! - requester details from the connection (IP, User-Agent; no GeoIP);
//! - on a successful `redeem`, this service's existing session: a bearer
//!   session bound to `K_b` as its session key.

use std::net::IpAddr;
use std::sync::OnceLock;

use async_trait::async_trait;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use did_hosting_common::server::auth::session::{create_authenticated_session, now_epoch};
use did_hosting_common::server::rate_limit::IpRateLimiter;
use did_hosting_common::server::trust_tasks::TransportBoundVerifier;
use serde_json::Value;
use trust_tasks_proof::affinidi::{CryptoSuite, SignOptions, sign_trust_task};

use super::service::{
    ApprovedSession, Connection, OOB_AMR, OobConfig, OobEnv, OobReply, OobService,
};
use super::types::{OobErrorCode, TYPE_REDEEM, TYPE_REQUEST, is_oob_type};
use crate::server::AppState;

/// The `ext` namespace of the redeem response that carries this service's
/// bearer tokens (see [`create_session`] for why).
pub const SESSION_EXT_NAMESPACE: &str = "com.affinidi.did-hosting";

/// The largest `auth/oob/*` document accepted. `prove` and `respond` carry one
/// signed document each; 32 KiB is generous.
pub const MAX_OOB_DOCUMENT_BYTES: usize = 32 * 1024;
/// `request` documents per client address per minute.
pub const REQUEST_MAX_PER_MINUTE: u64 = 20;
/// Other `auth/oob/*` documents per client address per minute. A redeem long
/// poll re-sends every 25 s, so this leaves room for several sign-ins.
pub const OTHER_MAX_PER_MINUTE: u64 = 120;

/// Per-process state: the service (built on first use, from config) and the
/// limiters.
pub struct OobRuntime {
    service: OnceLock<Option<OobService>>,
    request_limiter: IpRateLimiter,
    other_limiter: IpRateLimiter,
}

impl Default for OobRuntime {
    fn default() -> Self {
        Self {
            service: OnceLock::new(),
            request_limiter: IpRateLimiter::new(
                "auth-oob-request-per-ip",
                REQUEST_MAX_PER_MINUTE,
                60,
            ),
            other_limiter: IpRateLimiter::new("auth-oob-per-ip", OTHER_MAX_PER_MINUTE, 60),
        }
    }
}

impl OobRuntime {
    /// The service, or `None` when this deployment has no service DID or
    /// public URL (and so no portal origin and no `SignInPortal` service).
    fn service(&self, state: &AppState) -> Option<&OobService> {
        self.service
            .get_or_init(|| {
                let did = state.config.server_did.clone()?;
                let (origin, host) = portal_origin(state.config.public_url.as_deref()?)?;
                Some(OobService::new(OobConfig::new(did, host, origin)))
            })
            .as_ref()
    }
}

/// The origin and host of the portal, from the control plane's public URL:
/// the console's login page is served there (`SignInPortal`, C4).
pub fn portal_origin(public_url: &str) -> Option<(String, String)> {
    let url = url::Url::parse(public_url).ok()?;
    let host = url.host_str()?.to_string();
    Some((url.origin().ascii_serialization(), host))
}

/// The `SignInPortal` endpoint for a control plane at `public_url`: its
/// console's login page.
pub fn sign_in_portal_endpoint(public_url: &str) -> Option<String> {
    let (origin, _) = portal_origin(public_url)?;
    Some(format!("{origin}/login"))
}

/// This control plane's [`OobEnv`].
struct AppEnv<'a> {
    state: &'a AppState,
}

#[async_trait]
impl OobEnv for AppEnv<'_> {
    fn now(&self) -> u64 {
        now_epoch()
    }

    fn member_verifier(&self) -> Option<&TransportBoundVerifier> {
        self.state.trust_tasks_verifier.as_deref()
    }

    async fn is_allowed(&self, did: &str) -> bool {
        did.len() <= 512
            && matches!(
                crate::acl::get_acl_entry(&self.state.acl_ks, did).await,
                Ok(Some(_))
            )
    }

    async fn display_name(&self, did: &str) -> Option<String> {
        crate::acl::get_acl_entry(&self.state.acl_ks, did)
            .await
            .ok()
            .flatten()
            .and_then(|e| e.label)
            .filter(|l| !l.trim().is_empty())
    }

    async fn sign(&self, unsigned: Value, proof_purpose: &str) -> Result<Value, String> {
        let did = self
            .state
            .config
            .server_did
            .as_deref()
            .ok_or("server_did not configured")?;
        let secret =
            crate::signing::control_signing_secret(self.state, did).map_err(|e| e.to_string())?;
        sign_trust_task(
            &unsigned,
            &secret,
            SignOptions::new()
                .with_proof_purpose(proof_purpose)
                .with_cryptosuite(CryptoSuite::EddsaJcs2022),
        )
        .await
        .map_err(|e| e.to_string())
    }
}

/// If `body` is an `auth/oob/*` document, handle it and return the response.
/// `None` for anything else, which the ordinary dispatch then serves.
pub async fn maybe_handle(
    state: &AppState,
    ip: IpAddr,
    headers: &HeaderMap,
    body: &[u8],
) -> Option<Response> {
    let raw: Value = serde_json::from_slice(body).ok()?;
    let type_uri = raw.get("type")?.as_str()?.to_string();
    if !is_oob_type(&type_uri) {
        return None;
    }
    Some(handle(state, ip, headers, body.len(), raw, &type_uri).await)
}

async fn handle(
    state: &AppState,
    ip: IpAddr,
    headers: &HeaderMap,
    len: usize,
    raw: Value,
    type_uri: &str,
) -> Response {
    let Some(service) = state.oob.service(state) else {
        return plain_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "wallet sign-in is not configured on this server",
        );
    };
    let env = AppEnv { state };
    let refuse = |code: OobErrorCode, msg: &str| {
        let err = super::service::OobError::new(code, msg);
        reply(
            err.code.http_status(),
            service_error(service, &env, &raw, err),
        )
    };
    if len > MAX_OOB_DOCUMENT_BYTES {
        return refuse(OobErrorCode::MalformedRequest, "document too large");
    }
    let limiter = if type_uri == TYPE_REQUEST {
        &state.oob.request_limiter
    } else {
        &state.oob.other_limiter
    };
    if limiter.try_consume(ip, now_epoch()).is_err() {
        tracing::warn!(%ip, type_uri, "auth/oob rate limited");
        return refuse(OobErrorCode::RateLimited, "too many requests");
    }
    // `request` only from the portal itself: a browser always sends
    // `Origin` on a POST, and no CORS is offered, so another site's page
    // cannot open requests in this service's name.
    if type_uri == TYPE_REQUEST {
        let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
        if origin != Some(service.config.origin.as_str()) {
            tracing::warn!(
                ?origin,
                "auth/oob/request refused: not from the portal origin"
            );
            return refuse(OobErrorCode::NotAuthorized, "not from the sign-in portal");
        }
    }

    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let (browser, os) = parse_user_agent(ua);
    let conn = Connection {
        ip: Some(ip.to_string()),
        // No local GeoIP database: "unknown" (base design 12 item 6).
        location: None,
        browser: Some(browser.to_string()),
        os: Some(os.to_string()),
    };

    match service.handle(&env, raw.clone(), &conn).await {
        OobReply::Document { status, body } => reply(status, body),
        OobReply::Approved { request, session } => {
            debug_assert_eq!(request.type_uri.to_string(), TYPE_REDEEM);
            match create_session(state, &session).await {
                Ok(extra) => match service
                    .redeem_response(&env, &request, &session, Some(extra))
                    .await
                {
                    Ok(body) => reply(200, body),
                    Err(err) => reply(
                        err.code.http_status(),
                        service_error(service, &env, &raw, err),
                    ),
                },
                Err(e) => {
                    tracing::error!(error = %e, "auth/oob/redeem: session creation failed");
                    refuse(OobErrorCode::NotAuthorized, "not authorized")
                }
            }
        }
    }
}

/// Create this service's session for `session.subject`, bound to `K_b`.
///
/// CONTRACT CONFLICT (C9): C9 says the session travels in HttpOnly cookies
/// and the redeem body never carries tokens. This service has no cookie
/// session: every client is a bearer client (`server::auth::extractor`), and
/// the console holds its access and refresh tokens exactly as after a passkey
/// or wallet login. Until that is settled, the tokens ride in a `tokens`
/// member of the response's `ext`, under [`SESSION_EXT_NAMESPACE`] (the
/// schema's only open member), and the C9 fields are unchanged. Only the holder of
/// `K_b` can redeem, so this reaches no one the passkey login's response
/// would not.
async fn create_session(state: &AppState, session: &ApprovedSession) -> Result<Value, String> {
    let role = crate::acl::check_acl(&state.acl_ks, &session.subject)
        .await
        .map_err(|e| e.to_string())?;
    let jwt_keys = state.jwt_keys.as_ref().ok_or("JWT keys not configured")?;
    let multikey = session
        .session_key
        .strip_prefix("did:key:")
        .ok_or("session key is not a did:key")?
        .to_string();
    let now = now_epoch();
    let ttl = session.not_after.saturating_sub(now).max(1);
    let auth = &state.config.auth;
    let tokens = create_authenticated_session(
        &state.sessions_ks,
        jwt_keys,
        &session.subject,
        &role,
        auth.access_token_expiry.min(ttl),
        auth.refresh_token_expiry.min(ttl),
        Some(multikey),
        Some((
            OOB_AMR.iter().map(|s| s.to_string()).collect(),
            "aal1".to_string(),
        )),
    )
    .await
    .map_err(|e| e.to_string())?;
    // The absolute lifetime `auth/refresh` enforces: never past `notAfter`.
    let absolute = session.not_after.min(now + auth.absolute_session_lifetime);
    crate::trust_tasks_auth::store_auth_proxy_meta(state, &tokens.session_id, None, absolute)
        .await
        .map_err(|e| e.to_string())?;
    let canonical = tokens.into_canonical();
    let tokens = serde_json::to_value(&canonical.tokens).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ SESSION_EXT_NAMESPACE: { "tokens": tokens } }))
}

fn service_error(
    service: &OobService,
    env: &AppEnv<'_>,
    raw: &Value,
    err: super::service::OobError,
) -> Value {
    service.error_document(env, raw, &err)
}

fn reply(status: u16, body: Value) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST);
    let mut resp = (status, axum::Json(body)).into_response();
    no_store(resp.headers_mut());
    resp
}

fn plain_error(status: StatusCode, msg: &str) -> Response {
    let mut resp = (status, msg.to_string()).into_response();
    no_store(resp.headers_mut());
    resp
}

fn no_store(h: &mut HeaderMap) {
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
}

/// Browser family and OS from a User-Agent, coarsely. Order matters: Edge
/// and Opera also say Chrome, Chrome also says Safari.
pub fn parse_user_agent(ua: &str) -> (&'static str, &'static str) {
    let browser = if ua.contains("Edg/") || ua.contains("EdgA/") || ua.contains("EdgiOS/") {
        "Edge"
    } else if ua.contains("OPR/") || ua.contains("Opera") {
        "Opera"
    } else if ua.contains("Firefox/") || ua.contains("FxiOS/") {
        "Firefox"
    } else if ua.contains("Chrome/") || ua.contains("CriOS/") {
        "Chrome"
    } else if ua.contains("Safari/") {
        "Safari"
    } else {
        "unknown"
    };
    let os = if ua.contains("iPhone") || ua.contains("iPad") || ua.contains("iPod") {
        "iOS"
    } else if ua.contains("Android") {
        "Android"
    } else if ua.contains("CrOS") {
        "ChromeOS"
    } else if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("Mac OS X") || ua.contains("Macintosh") {
        "macOS"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        "unknown"
    };
    (browser, os)
}

#[cfg(test)]
impl OobRuntime {
    pub(crate) fn service_for_tests(&self, state: &AppState) -> &OobService {
        self.service(state).expect("configured")
    }
}
