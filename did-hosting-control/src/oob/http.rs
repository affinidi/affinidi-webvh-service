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
//! - a size limit on the document ([`MAX_OOB_DOCUMENT_BYTES`]), under the
//!   route's own body limit;
//! - `request` only from the portal's origin (base design 12 item 10): exactly
//!   one `Origin` header, naming the portal's scheme, host and port
//!   ([`origin_is_portal`]);
//! - per-address rate limits on every `auth/oob/*` document, and a global
//!   one on `request`, so addresses that multiply (many hosts, or a too-broad
//!   `trusted_proxies`) still meet a ceiling;
//! - requester details from the connection (IP, User-Agent; no GeoIP);
//! - on a successful `redeem`, this service's existing session: a bearer
//!   session bound to `K_b` as its session key.
//!
//! What the state machine ([`super::service`]) checks on every document, in
//! place of the `control_tasks` gate: the envelope (`type`, `id`, in-band
//! `issuer`, `recipient` = this service, fresh `issuedAt`, `expiresAt`), an
//! Ed25519 `did:key` issuer whose proof verifies with its own key and no I/O,
//! replay on `(issuer, id)`, and the per-request key bindings (`request`,
//! `redeem`: `K_b`; `claim`, `prove`, `respond`: the lock `K_a`; `cancel`:
//! either). Member documents (`identify`, `grant`) are checked against the
//! ACL by issuer string before any DID resolution, then verified with the
//! shared [`TransportBoundVerifier`] (`verify_operational`,
//! `verify_approval`). Every success is signed; only errors are unsigned.
//! A bearer session sent with an `auth/oob/*` document is ignored: nothing
//! here is authorised by one.

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
/// `request` documents per minute from all addresses together: the ceiling
/// that holds when the per-address limit is spread over many addresses.
pub const GLOBAL_REQUEST_MAX_PER_MINUTE: u64 = 600;

/// The single key of the global limiter (an [`IpRateLimiter`] with one
/// bucket).
const GLOBAL_KEY: IpAddr = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);

/// Per-process state: the service (built on first use, from config) and the
/// limiters.
pub struct OobRuntime {
    service: OnceLock<Option<OobService>>,
    request_limiter: IpRateLimiter,
    global_request_limiter: IpRateLimiter,
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
            global_request_limiter: IpRateLimiter::new(
                "auth-oob-request-global",
                GLOBAL_REQUEST_MAX_PER_MINUTE,
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
///
/// `None` unless the URL is `http` or `https` with a host: any other scheme
/// has an opaque origin, which serialises as `null` — the `Origin` a
/// sandboxed frame on any site sends.
pub fn portal_origin(public_url: &str) -> Option<(String, String)> {
    let url = url::Url::parse(public_url).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let host = url.host_str()?.to_string();
    let origin = url.origin();
    if !origin.is_tuple() {
        return None;
    }
    Some((origin.ascii_serialization(), host))
}

/// Whether the request's `Origin` is the portal's: exactly one `Origin`
/// header, not `null`, an `http` or `https` origin whose scheme, host and
/// port equal `portal`'s, written as a browser writes it (no path, no
/// trailing slash, no user info). Anything else — missing, repeated,
/// unparseable, opaque — is refused.
pub fn origin_is_portal(headers: &HeaderMap, portal: &str) -> bool {
    let mut values = headers.get_all(header::ORIGIN).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return false;
    };
    let Ok(sent) = value.to_str() else {
        return false;
    };
    if sent == "null" {
        return false;
    }
    let Ok(url) = url::Url::parse(sent) else {
        return false;
    };
    if !matches!(url.scheme(), "http" | "https") {
        return false;
    }
    let origin = url.origin();
    if !origin.is_tuple() {
        return false;
    }
    let canonical = origin.ascii_serialization();
    canonical == sent && canonical == portal
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
        // `type_uri` is the caller's; log a bounded prefix only.
        let type_prefix: String = type_uri.chars().take(64).collect();
        tracing::warn!(%ip, type_uri = %type_prefix, "auth/oob rate limited");
        return refuse(OobErrorCode::RateLimited, "too many requests");
    }
    if type_uri == TYPE_REQUEST {
        // `request` only from the portal itself: a browser always sends
        // `Origin` on a POST, and no CORS is offered for POST, so another
        // site's page cannot open requests in this service's name.
        if !origin_is_portal(headers, &service.config.origin) {
            let origin: Vec<_> = headers
                .get_all(header::ORIGIN)
                .iter()
                .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
                .collect();
            tracing::warn!(
                ?origin,
                "auth/oob/request refused: not from the portal origin"
            );
            return refuse(OobErrorCode::NotAuthorized, "not from the sign-in portal");
        }
        // Counted after the origin check, so another site's page cannot
        // spend the global budget.
        if state
            .oob
            .global_request_limiter
            .try_consume(GLOBAL_KEY, now_epoch())
            .is_err()
        {
            tracing::warn!("auth/oob/request refused: global rate limit");
            return refuse(OobErrorCode::RateLimited, "too many sign-in requests");
        }
    }
    tracing::debug!(target: "auth_oob", %ip, type_uri, "auth/oob document handled outside the control_tasks table");

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
/// Contract C9, "Redeem on a bearer-token service": a service without cookie
/// sessions returns its tokens to the starter in `redeem`'s `ext` under its
/// own namespace, and never to the approver. This service is one: every
/// client is a bearer client (`server::auth::extractor`), and the console
/// holds its access and refresh tokens exactly as after a passkey or wallet
/// login. So the tokens ride in a `tokens` member of the response's `ext`,
/// under [`SESSION_EXT_NAMESPACE`], and the C9 body fields are unchanged.
/// Only the holder of `K_b` can redeem, so this reaches no one the passkey
/// login's response would not. The session is bound to `K_b`, so a refresh
/// needs a proof by that key (`auth/refresh:sessionKeyProofRequired`).
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
