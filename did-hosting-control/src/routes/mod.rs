mod acl;
mod auth;
mod did_manage;
mod didcomm;
mod domain;
pub mod health;
mod passkey;
mod proxy;
mod registry;
pub(crate) mod stats_sync;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{any, get, post, put};
use did_hosting_common::did_hosting_tasks::*;
use did_hosting_common::server::trust_task::TrustTaskRouter;

use crate::server::AppState;

/// Build the control plane router without the UI fallback (daemon mode).
///
/// ## T8b: Trust-Task header gating
///
/// Every authenticated route is registered through [`TrustTaskRouter`]
/// in **permissive** mode so existing clients (UI, CLI) keep working
/// during the v0.7→v0.8 migration. A new client that opts in to the
/// `Trust-Task:` header gets the exact-match correctness guarantee
/// from the middleware. The exempt routes are:
///
/// - `/api/health` — operator monitoring; never authed.
/// - `/api/didcomm` — terminal DIDComm envelope; the inner message
///   `typ` is the actual task identifier, validated separately by
///   the DIDComm dispatcher.
/// - `/api/proxy/...` — pass-through to a registered service; the
///   upstream service runs its own Trust-Task validation.
/// - `/api/control/stats` — server-to-control stats sync; servers
///   self-identify by DID, not by Trust-Task header.
pub fn router_without_fallback() -> Router<AppState> {
    let control: Router<AppState> = TrustTaskRouter::new()
        .route_with_task_permissive(
            "/registry",
            get(registry::list).post(registry::register),
            (*TASK_REGISTRY_LIST_1_0).clone(),
        )
        .route_with_task_permissive(
            "/registry/{instance_id}",
            get(registry::get).delete(registry::deregister),
            (*TASK_REGISTRY_GET_1_0).clone(),
        )
        .route_with_task_permissive(
            "/registry/{instance_id}/health",
            post(registry::health_check),
            (*TASK_REGISTRY_HEALTH_1_0).clone(),
        )
        // T28: admin-triggered domain assignment to a specific server.
        // Both routes are fire-and-forget DIDComm pushes; the server's
        // ack flows back asynchronously. Idempotent on the server side.
        .route_with_task_permissive(
            "/registry/{instance_id}/domains/{domain}/assign",
            post(registry::assign_domain_to_server),
            (*TASK_DOMAIN_ASSIGN_1_0).clone(),
        )
        .route_with_task_permissive(
            "/registry/{instance_id}/domains/{domain}/unassign",
            post(registry::unassign_domain_from_server),
            (*TASK_DOMAIN_UNASSIGN_1_0).clone(),
        )
        // T30: admin "Purge now". Bypasses the grace period.
        .route_with_task_permissive(
            "/registry/{instance_id}/domains/{domain}/purge",
            post(registry::purge_domain_on_server),
            (*TASK_DOMAIN_PURGE_1_0).clone(),
        )
        .route_with_task_permissive(
            "/register-service",
            post(registry::register_service),
            (*TASK_SERVER_REGISTER_1_0).clone(),
        )
        .into_router();

    // Upload routes with a custom body-size limit (DID log + witness).
    // `/dids/register` carries the full did.jsonl in the body too — same
    // ceiling, same router so the limit applies uniformly.
    let upload_routes: Router<AppState> = TrustTaskRouter::new()
        .route_with_task_permissive(
            "/dids/{*mnemonic}",
            put(did_manage::upload_did),
            (*TASK_DID_PUBLISH_1_0).clone(),
        )
        .route_with_task_permissive(
            "/witness/{*mnemonic}",
            put(did_manage::upload_witness),
            (*TASK_WEBVH_WITNESS_PUBLISH_1_0).clone(),
        )
        .route_with_task_permissive(
            "/dids/register",
            post(did_manage::register_did),
            (*TASK_DID_REGISTER_1_0).clone(),
        )
        .into_router()
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024)); // 10 MB

    let api: Router<AppState> = TrustTaskRouter::new()
        // Auth (DIDComm challenge-response)
        .route_with_task_permissive(
            "/auth/challenge",
            post(auth::challenge),
            (*TASK_AUTH_CHALLENGE_1_0).clone(),
        )
        .route_with_task_permissive(
            "/auth/",
            post(auth::authenticate),
            (*TASK_AUTH_AUTHENTICATE_1_0).clone(),
        )
        .route_with_task_permissive(
            "/auth/refresh",
            post(auth::refresh),
            (*TASK_AUTH_REFRESH_1_0).clone(),
        )
        // Passkey (WebAuthn)
        .route_with_task_permissive(
            "/auth/passkey/enroll/start",
            post(passkey::enroll_start::<AppState>),
            (*TASK_AUTH_PASSKEY_ENROLL_START_1_0).clone(),
        )
        .route_with_task_permissive(
            "/auth/passkey/enroll/finish",
            post(passkey::enroll_finish::<AppState>),
            (*TASK_AUTH_PASSKEY_ENROLL_FINISH_1_0).clone(),
        )
        .route_with_task_permissive(
            "/auth/passkey/login/start",
            post(passkey::login_start::<AppState>),
            (*TASK_AUTH_PASSKEY_LOGIN_START_1_0).clone(),
        )
        .route_with_task_permissive(
            "/auth/passkey/login/finish",
            post(passkey::login_finish::<AppState>),
            (*TASK_AUTH_PASSKEY_LOGIN_FINISH_1_0).clone(),
        )
        .route_with_task_permissive(
            "/auth/passkey/invite",
            post(passkey::create_invite::<AppState>),
            (*TASK_AUTH_PASSKEY_INVITE_1_0).clone(),
        )
        .route_with_task_permissive(
            "/auth/passkey/invites",
            get(passkey::list_invites::<AppState>),
            (*TASK_AUTH_PASSKEY_INVITE_1_0).clone(),
        )
        .route_with_task_permissive(
            "/auth/passkey/invite/{token}",
            put(passkey::update_invite::<AppState>).delete(passkey::revoke_invite::<AppState>),
            (*TASK_AUTH_PASSKEY_INVITE_1_0).clone(),
        )
        // ACL
        .route_with_task_permissive(
            "/acl",
            get(acl::list_acl).post(acl::create_acl),
            (*TASK_ACL_LIST_1_0).clone(),
        )
        .route_with_task_permissive(
            "/acl/{did}",
            put(acl::update_acl).delete(acl::delete_acl),
            (*TASK_ACL_UPDATE_1_0).clone(),
        )
        // Domains (multi-domain)
        .route_with_task_permissive(
            "/domains",
            get(domain::list_domains),
            (*TASK_DOMAIN_LIST_1_0).clone(),
        )
        .route_with_task_permissive(
            "/me/domains",
            get(domain::list_my_domains),
            (*TASK_ME_DOMAINS_1_0).clone(),
        )
        // DID management (authenticated)
        .route_with_task_permissive(
            "/dids/check",
            post(did_manage::check_name),
            (*TASK_DID_CHECK_NAME_1_0).clone(),
        )
        .route_with_task_permissive(
            "/dids",
            post(did_manage::request_uri).get(did_manage::list_dids),
            (*TASK_DID_REQUEST_1_0).clone(),
        )
        .route_with_task_permissive(
            "/dids/{*mnemonic}",
            get(did_manage::get_did).delete(did_manage::delete_did),
            (*TASK_DID_INFO_1_0).clone(),
        )
        .route_with_task_permissive(
            "/log/{*mnemonic}",
            get(did_manage::get_did_log),
            (*TASK_DID_LOG_1_0).clone(),
        )
        .route_with_task_permissive(
            "/owner/{*mnemonic}",
            put(did_manage::change_owner),
            (*TASK_DID_CHANGE_OWNER_1_0).clone(),
        )
        .route_with_task_permissive(
            "/disable/{*mnemonic}",
            put(did_manage::disable_did),
            (*TASK_DID_DISABLE_1_0).clone(),
        )
        .route_with_task_permissive(
            "/enable/{*mnemonic}",
            put(did_manage::enable_did),
            (*TASK_DID_ENABLE_1_0).clone(),
        )
        .route_with_task_permissive(
            "/rollback/{*mnemonic}",
            post(did_manage::rollback_did),
            (*TASK_DID_ROLLBACK_1_0).clone(),
        )
        .route_with_task_permissive(
            "/raw/{*mnemonic}",
            get(did_manage::get_raw_log),
            (*TASK_DID_RAW_LOG_1_0).clone(),
        )
        // Stats & time-series
        .route_with_task_permissive(
            "/stats",
            get(did_manage::get_server_stats),
            (*TASK_STATS_SERVER_1_0).clone(),
        )
        .route_with_task_permissive(
            "/stats/{*mnemonic}",
            get(did_manage::get_did_stats),
            (*TASK_STATS_DID_1_0).clone(),
        )
        .route_with_task_permissive(
            "/timeseries",
            get(did_manage::get_server_timeseries),
            (*TASK_TIMESERIES_SERVER_1_0).clone(),
        )
        .route_with_task_permissive(
            "/timeseries/{*mnemonic}",
            get(did_manage::get_did_timeseries),
            (*TASK_TIMESERIES_DID_1_0).clone(),
        )
        .route_with_task_permissive(
            "/services/overview",
            get(did_manage::get_services_overview),
            (*TASK_SERVICES_OVERVIEW_1_0).clone(),
        )
        .route_with_task_permissive(
            "/config",
            get(did_manage::get_config),
            (*TASK_CONFIG_1_0).clone(),
        )
        // Exempt: DIDComm envelope (inner message type is the real
        // task identifier).
        .route_exempt("/didcomm", post(didcomm::handle))
        // Exempt: server-to-control stats sync (servers self-identify
        // by DID, not by Trust-Task header).
        .route_exempt("/control/stats", post(stats_sync::receive_stats))
        // Exempt: proxy pass-through. The upstream service runs its
        // own validation.
        .route_exempt(
            "/proxy/server/{instance_id}/{*path}",
            any(proxy::proxy_to_service),
        )
        .route_exempt(
            "/proxy/witness/{instance_id}/{*path}",
            any(proxy::proxy_to_service),
        )
        .into_router()
        // Control plane (admin operations) — nested separately so the
        // /control/* prefix gates its own subset of Trust-Task URLs.
        .nest("/control", control)
        // Merge upload routes (body-limited).
        .merge(upload_routes);

    #[allow(unused_mut)]
    let mut router = Router::new()
        .nest("/api", api)
        .route("/api/health", get(health::health));

    // Prometheus metrics endpoint (only when metrics feature is enabled)
    #[cfg(feature = "metrics")]
    {
        router = router.route("/metrics", get(metrics_handler));
    }

    router
}

/// Build the full control plane router with UI fallback (standalone mode).
pub fn router() -> Router<AppState> {
    #[allow(unused_mut)]
    let mut r = router_without_fallback();

    #[cfg(feature = "ui")]
    {
        r = r.fallback(crate::frontend::static_handler);
    }

    r
}

#[cfg(feature = "metrics")]
async fn metrics_handler() -> (
    axum::http::StatusCode,
    [(&'static str, &'static str); 1],
    String,
) {
    (
        axum::http::StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        did_hosting_common::server::metrics::render(),
    )
}
