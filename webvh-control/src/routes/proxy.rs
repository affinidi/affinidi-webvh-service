//! Reverse proxy — forwards API requests to backend service instances.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tracing::debug;

use crate::auth::AdminAuth;
use crate::error::AppError;
use crate::registry;
use crate::server::AppState;

/// ANY /api/server/{instance_id}/{*path}
/// ANY /api/witness/{instance_id}/{*path}
///
/// Restricted to Admin role. The proxy forwards the caller's `Authorization`
/// header to the backend, and the control plane and backends typically share
/// JWT keys; gating on Admin keeps Owner-role JWTs from probing arbitrary
/// backend routes via the proxy.
pub async fn proxy_to_service(
    State(state): State<AppState>,
    _auth: AdminAuth,
    Path((instance_id, path)): Path<(String, String)>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let instance = registry::get_instance(&state.registry_ks, &instance_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("instance {instance_id}")))?;

    let base = instance.url.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let url = format!("{base}/api/{path}{query}");

    debug!(instance_id = %instance_id, url = %url, "proxying request");

    let method = req.method().clone();
    let mut proxy_req = state.http_client.request(method, &url);

    // Forward auth and content-type headers
    if let Some(auth) = req.headers().get("authorization") {
        proxy_req = proxy_req.header("authorization", auth);
    }
    if let Some(ct) = req.headers().get("content-type") {
        proxy_req = proxy_req.header("content-type", ct);
    }

    // Forward body
    let body_bytes = axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024)
        .await
        .map_err(|e| AppError::Internal(format!("body read: {e}")))?;
    if !body_bytes.is_empty() {
        proxy_req = proxy_req.body(body_bytes);
    }

    let resp = proxy_req
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("proxy: {e}")))?;

    // Convert reqwest::Response to axum::Response
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let resp_headers = resp.headers().clone();
    let body = resp
        .bytes()
        .await
        .map_err(|e| AppError::Internal(format!("proxy body: {e}")))?;

    let mut response = (status, body).into_response();
    // Strip hop-by-hop headers (RFC 7230 §6.1) and per-connection metadata
    // before forwarding the upstream response. Forwarding them through a
    // proxy boundary can cause subtle bugs (e.g. browsers reusing keep-alive
    // settings the upstream meant for its own peer) and surprise security
    // posture (e.g. a `Set-Cookie` leaking into the admin UI's cookie jar).
    for (name, value) in resp_headers.iter() {
        if is_hop_by_hop_or_unsafe_to_forward(name.as_str()) {
            continue;
        }
        response.headers_mut().insert(name.clone(), value.clone());
    }
    Ok(response)
}

fn is_hop_by_hop_or_unsafe_to_forward(name: &str) -> bool {
    // Names compared case-insensitively (HTTP header names are case-
    // insensitive per RFC 7230 §3.2). reqwest already lowercases.
    matches!(
        name.to_ascii_lowercase().as_str(),
        // RFC 7230 §6.1 hop-by-hop headers
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            // Cookies set by an upstream backend must not leak into the
            // control plane's cookie jar / admin UI.
            | "set-cookie"
    )
}
