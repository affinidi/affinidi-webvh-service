//! The control plane's own limiters answer with the ecosystem 429 contract:
//! status `429`, `x-rate-limit-source: did-host`, a `Retry-After` in seconds,
//! and a JSON body naming the limiter. Before this, both refused with `400`
//! (`AppError::Validation`), which no client can tell apart from a malformed
//! request — so nothing backed off, and an operator could not see which service
//! had refused.
//!
//! Driven through the real router (`tower::ServiceExt::oneshot`), because the
//! contract is the HTTP response, not the error value.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use did_hosting_common::server::config::AuthConfig;
use did_hosting_control::pending_challenges::PendingChallengeTracker;
use did_hosting_control::rate_limit::{MAX_PER_WINDOW, WINDOW_SECS};
use did_hosting_control::test_support::TestServer;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

fn challenge_request(did: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/auth/challenge")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({ "did": did })).unwrap(),
        ))
        .unwrap();
    // `oneshot` does not populate `ConnectInfo`; the per-IP limiter needs it.
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [203, 0, 113, 7],
            40000,
        ))));
    req
}

/// Assert the full 429 contract and return the body for limiter-specific checks.
async fn assert_rate_limited(response: Response, limiter: &str) -> Value {
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()["x-rate-limit-source"], "did-host");
    assert_eq!(response.headers()["content-type"], "application/json");
    let retry_after: u64 = response.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .expect("Retry-After is delta-seconds");
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"], "rate_limited");
    assert_eq!(body["limiter"], limiter);
    assert!(body["message"].as_str().is_some_and(|m| !m.is_empty()));
    assert_eq!(body["retryAfterSecs"], retry_after, "header and body agree");
    body
}

#[tokio::test]
async fn per_ip_challenge_limit_answers_429_with_retry_after_from_the_window() {
    let ts = TestServer::start().await;
    let app = ts.router();

    // Distinct DIDs, so the per-DID pending cap never bites first.
    for i in 0..MAX_PER_WINDOW {
        let response = app
            .clone()
            .oneshot(challenge_request(&format!("did:example:ip-{i}")))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "request {i} under the cap"
        );
    }

    let response = app
        .oneshot(challenge_request("did:example:ip-over"))
        .await
        .unwrap();
    let body = assert_rate_limited(response, "auth-challenge-per-ip").await;
    // The refusal lands inside the window that opened moments ago, so the hint
    // is the window's remainder: positive and never more than the window.
    let retry = body["retryAfterSecs"].as_u64().unwrap();
    assert!((1..=WINDOW_SECS).contains(&retry), "retry {retry}");
}

/// At the per-DID cap the oldest challenge is evicted, not the new one
/// refused: asking for challenges in a DID's name cannot lock its owner out.
/// The evicted challenge's row goes with it, so it cannot be redeemed outside
/// the cap (VTI-SES-005).
#[tokio::test]
async fn per_did_pending_challenge_cap_evicts_the_oldest() {
    use did_hosting_common::server::acl::Role;
    use did_hosting_common::server::auth::session::get_session;

    let ts = TestServer::start().await;
    // Enrolled, so the canonical handler persists a row per challenge.
    let did = "did:example:pending";
    ts.add_acl(did, Role::Owner).await;
    let app = ts.router();

    // `MAX_PENDING_CHALLENGES_PER_DID` in `routes::auth` is 10.
    let mut session_ids = Vec::new();
    for i in 0..=10 {
        let response = app.clone().oneshot(challenge_request(did)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "challenge {i}");
        let body: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        session_ids.push(body["sessionId"].as_str().unwrap().to_string());
    }

    assert_eq!(ts.state.pending_challenges.count_for(did), 10);
    let gone = get_session(&ts.state.sessions_ks, &session_ids[0])
        .await
        .unwrap();
    assert!(
        gone.is_none(),
        "the evicted challenge can no longer be redeemed"
    );
    let kept = get_session(&ts.state.sessions_ks, &session_ids[10])
        .await
        .unwrap();
    assert!(kept.is_some(), "the new challenge was issued");
}

/// A tracker whose clock the test moves, installed on `ts` before routing.
fn install_manual_clock(ts: &mut TestServer, global_cap: usize) -> Arc<Mutex<Instant>> {
    let now = Arc::new(Mutex::new(Instant::now()));
    let clock = now.clone();
    ts.state.pending_challenges = Arc::new(PendingChallengeTracker::with_clock(
        Duration::from_secs(AuthConfig::default().challenge_ttl),
        global_cap,
        Arc::new(move || *clock.lock().unwrap()),
    ));
    now
}

async fn retry_after_of(response: Response, limiter: &str) -> u64 {
    assert_rate_limited(response, limiter).await["retryAfterSecs"]
        .as_u64()
        .unwrap()
}

/// Regression: challenges nobody redeems must give their slots back when they
/// expire. The tracker used to free a slot only when its challenge
/// authenticated, so ten abandoned challenges locked the DID out until
/// restart. Eviction now keeps the DID answerable at the cap, but expiry must
/// still empty the count — or every new challenge would evict a live one.
#[tokio::test]
async fn abandoned_challenges_leave_the_per_did_count_on_expiry() {
    let mut ts = TestServer::start().await;
    let now = install_manual_clock(&mut ts, 10_000);
    let app = ts.router();
    let did = "did:example:abandoned";

    for i in 0..10 {
        let response = app.clone().oneshot(challenge_request(did)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "challenge {i}");
    }
    assert_eq!(ts.state.pending_challenges.count_for(did), 10);

    *now.lock().unwrap() += Duration::from_secs(AuthConfig::default().challenge_ttl + 1);
    assert_eq!(ts.state.pending_challenges.count_for(did), 0);
    let response = app.oneshot(challenge_request(did)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(ts.state.pending_challenges.count_for(did), 1);
}

/// The same for the global cap — the case that took the whole control plane
/// down: enough abandoned challenges across distinct DIDs refused every DID's
/// login until restart.
#[tokio::test]
async fn abandoned_challenges_free_the_global_cap_on_expiry() {
    let mut ts = TestServer::start().await;
    let now = install_manual_clock(&mut ts, 5);
    let app = ts.router();

    for i in 0..5 {
        let response = app
            .clone()
            .oneshot(challenge_request(&format!("did:example:sweep-{i}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "challenge {i}");
    }
    let response = app
        .clone()
        .oneshot(challenge_request("did:example:victim"))
        .await
        .unwrap();
    let retry = retry_after_of(response, "auth-challenge-pending-global").await;
    assert_eq!(retry, AuthConfig::default().challenge_ttl);

    *now.lock().unwrap() += Duration::from_secs(retry);
    let response = app
        .oneshot(challenge_request("did:example:victim"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
