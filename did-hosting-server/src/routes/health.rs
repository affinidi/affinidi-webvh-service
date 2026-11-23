//! `GET /api/health`: the unauthenticated liveness probe.

use axum::Json;
use axum::http::StatusCode;
use serde::Serialize;

use crate::server::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

/// Unauthenticated liveness probe; degraded while the service's own DID is
/// not being served.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/health",
    tag = "system",
    responses(
        (status = 200, description = "Service is up and its own DID (if configured) resolves locally; returns status + version", content_type = "application/json"),
        (status = 503, description = "Service is up but its own DID isn't being served locally, or it has not reconciled with its control plane within the staleness bound", content_type = "application/json"),
    ),
))]
// Deliberately generic — no configuration or DID detail — but it must not
// claim healthy while the service's own DID isn't being served locally
// (Keyring VTI-17): see
// `did_hosting_common::server::health::own_did_served_locally`.
//
// Takes `AppState` directly rather than axum's `State` extractor: the
// route is registered *after* `Router::with_state` (deliberately outside
// the CORS/security-header layers — see `run_rest_thread`), so by the time
// it's added the router's state type is already `()` and an extractor-based
// handler would no longer type-check. The caller closes over a cloned
// `AppState` instead.
//
// It also answers 503 once the edge has gone longer than
// `replication.staleness_bound_secs` without a clean reconcile against its
// control plane (`crate::replication`), so a load balancer drains an edge that
// may be serving out-of-date state. The body stays generic either way.
pub async fn health(state: AppState) -> (StatusCode, Json<HealthResponse>) {
    let ok = did_hosting_common::server::health::own_did_served_locally(
        &state.dids_ks,
        state.config.server_did.as_deref(),
    )
    .await
        && crate::replication::is_fresh(&state);

    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(HealthResponse {
            status: if ok { "ok" } else { "degraded" },
            version: env!("CARGO_PKG_VERSION"),
        }),
    )
}

/// The edge's `/readyz` check: its store, then the condition `/api/health`
/// reports, as the `serving` check. Both say the same thing to a load
/// balancer: an edge whose own DID is not served, or that has gone past its
/// replication staleness bound, may serve wrong or out-of-date state, which
/// is exactly an instance that should not receive traffic.
pub fn readiness_probe(state: &AppState) -> did_hosting_common::server::probes::ReadinessProbe {
    let serving_state = state.clone();
    did_hosting_common::server::probes::ReadinessProbe::new(state.dids_ks.clone())
        .with_serving_check(std::sync::Arc::new(move || {
            let state = serving_state.clone();
            Box::pin(async move {
                if !did_hosting_common::server::health::own_did_served_locally(
                    &state.dids_ks,
                    state.config.server_did.as_deref(),
                )
                .await
                {
                    return Err("the service's own DID is not served from the local store".into());
                }
                if !crate::replication::is_fresh(&state) {
                    return Err(format!(
                        "no clean reconcile with the control plane within {} s",
                        state.config.replication.staleness_bound_secs
                    ));
                }
                Ok(())
            })
        }))
}

/// `GET /livez` and `GET /readyz` (see [`did_hosting_common::server::probes`]),
/// merged after the router's layers, beside `/api/health`.
pub fn probe_routes(state: &AppState) -> axum::Router {
    did_hosting_common::server::probes::router(readiness_probe(state))
}
