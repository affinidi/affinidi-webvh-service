//! The control plane's own limiters answer with the ecosystem 429 contract:
//! status `429`, `x-rate-limit-source: did-host`, a `Retry-After` in seconds,
//! and a JSON body naming the limiter. Before this, both refused with `400`
//! (`AppError::Validation`), which no client can tell apart from a malformed
//! request — so nothing backed off, and an operator could not see which service
//! had refused.
//!
//! Driven through the real router (`tower::ServiceExt::oneshot`), because the
//! contract is the HTTP response, not the error value.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use did_hosting_common::server::config::AuthConfig;
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

#[tokio::test]
async fn per_did_pending_challenge_cap_answers_429() {
    let ts = TestServer::start().await;
    let app = ts.router();
    let did = "did:example:pending";

    // `MAX_PENDING_CHALLENGES_PER_DID` in `routes::auth` is 10.
    for i in 0..10 {
        let response = app.clone().oneshot(challenge_request(did)).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "challenge {i} under the cap"
        );
    }

    let response = app.oneshot(challenge_request(did)).await.unwrap();
    let body = assert_rate_limited(response, "auth-challenge-pending-per-did").await;
    assert_eq!(
        body["retryAfterSecs"],
        AuthConfig::default().pending_challenge_retry_after_secs()
    );
}
