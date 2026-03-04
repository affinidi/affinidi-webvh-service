//! Reverse proxy — forwards API requests to backend service instances.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tracing::debug;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::registry;
use crate::server::AppState;

/// ANY /api/server/{instance_id}/{*path}
/// ANY /api/witness/{instance_id}/{*path}
///
/// Requires authentication to prevent SSRF via the proxy.
pub async fn proxy_to_service(
    State(state): State<AppState>,
    _auth: AuthClaims,
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
    for (name, value) in resp_headers.iter() {
        response.headers_mut().insert(name.clone(), value.clone());
    }
    Ok(response)
}
