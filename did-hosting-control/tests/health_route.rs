//! HTTP-shape coverage for the unauthenticated `/api/health` probe.
//!
//! Keyring VTI-17: a daemon that lost its own DID at `.well-known` — the
//! `--force-reprovision`-to-a-new-`public_url` case, where the store kept
//! serving the previous identity — used to report healthy regardless.
//! `/api/health` must fail when the service's own DID isn't actually being
//! served locally, and stay generic while doing it (liveness + this one
//! check, no DID detail in the body). See
//! `did_hosting_common::server::health::own_did_served_locally`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use did_hosting_common::did_ops::{DidRecord, content_log_key};
use did_hosting_common::server::auth::session::now_epoch;
use did_hosting_control::test_support::{TestServer, TestServerOptions};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

async fn call_health(app: axum::Router) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).expect("health body is JSON");
    (status, json)
}

fn own_did_record(did_id: &str) -> DidRecord {
    let now = now_epoch();
    DidRecord {
        owner: "system".into(),
        mnemonic: ".well-known".into(),
        created_at: now,
        updated_at: now,
        version_count: 1,
        did_id: Some(did_id.into()),
        content_size: 2,
        disabled: false,
        deleted_at: None,
        method: "webvh".into(),
        domain: String::new(),
        services: None,
        agent_names: Vec::new(),
    }
}

/// Seed a `.well-known` record (metadata + content bytes) for `did_id` —
/// everything `serve_root_did_log` needs to actually serve it.
async fn seed_own_did(ts: &TestServer, did_id: &str) {
    ts.put_did(&own_did_record(did_id)).await;
    ts.state
        .dids_ks
        .insert_raw(content_log_key(".well-known"), b"{}".to_vec())
        .await
        .expect("seed .well-known content");
}

/// No `server_did` configured at all: nothing to check, so this reports
/// healthy by construction (a fresh node before setup completes).
#[tokio::test]
async fn healthy_when_no_server_did_is_configured() {
    let ts = TestServer::start_with(TestServerOptions {
        server_did: Some(None),
        ..Default::default()
    })
    .await;

    let (status, body) = call_health(ts.router()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

/// Nothing stored at `.well-known` at all: many valid deployments host their
/// own DID on a separate process or server and never import it into this
/// store, so absence alone must not fail health.
#[tokio::test]
async fn healthy_when_well_known_was_never_imported() {
    let ts = TestServer::start().await;

    let (status, _) = call_health(ts.router()).await;
    assert_eq!(status, StatusCode::OK);
}

/// `.well-known` holds exactly the configured `server_did`, content
/// included — the healthy case a real deployment lands in after setup.
#[tokio::test]
async fn healthy_when_well_known_matches_server_did() {
    let ts = TestServer::start().await;
    let server_did = ts.state.config.server_did.clone().unwrap();
    seed_own_did(&ts, &server_did).await;

    let (status, body) = call_health(ts.router()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

/// Keyring VTI-17 itself: `.well-known` holds a *different* DID than the
/// configured `server_did` — the stale-DID-after-reprovision case. Health
/// must fail, and stay generic doing it (no DID leaked into the body).
#[tokio::test]
async fn unhealthy_when_well_known_holds_a_different_did() {
    let ts = TestServer::start().await;
    seed_own_did(&ts, "did:webvh:stale:old-host.example").await;

    let (status, body) = call_health(ts.router()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["status"], "degraded");
    let dump = body.to_string();
    assert!(
        !dump.contains("did:webvh"),
        "the probe must stay generic — no DID detail: {dump}"
    );
}

/// A disabled `.well-known` record fails the check even though `did_id`
/// still matches — disabled means "don't serve this".
#[tokio::test]
async fn unhealthy_when_well_known_is_disabled() {
    let ts = TestServer::start().await;
    let server_did = ts.state.config.server_did.clone().unwrap();
    let mut record = own_did_record(&server_did);
    record.disabled = true;
    ts.put_did(&record).await;
    ts.state
        .dids_ks
        .insert_raw(content_log_key(".well-known"), b"{}".to_vec())
        .await
        .expect("seed .well-known content");

    let (status, _) = call_health(ts.router()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}
