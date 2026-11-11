//! A request the console marks as background (`x-background-request`) is
//! served like any other, but it does not count as session activity: the idle
//! timeout is measured from `Session::last_seen`, and a dashboard that refreshes
//! itself on a timer must not keep moving it.
//!
//! Driven through the real router, because what matters is that the header
//! reaches the extractor on `POST /api/trust-tasks`, the path every console
//! call takes.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use did_hosting_common::server::acl::Role;
use did_hosting_common::server::auth::BACKGROUND_REQUEST_HEADER;
use did_hosting_common::server::auth::session::{get_session, now_epoch, store_session};
use did_hosting_control::test_support::TestServer;
use tower::ServiceExt;

const ADMIN: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

/// One hour back: far outside the throttle in `touch_last_seen`, so any
/// recorded activity shows up as a move.
const BACKDATE_SECS: u64 = 3600;

/// Mint an admin session and backdate its `last_seen`, returning the token and
/// the session id.
async fn idle_admin_session(ts: &TestServer) -> (String, String, u64) {
    ts.add_acl(ADMIN, Role::Admin).await;
    let token = ts.mint_token(ADMIN, Role::Admin).await;
    let session_id = ts
        .state
        .jwt_keys
        .as_ref()
        .unwrap()
        .decode(&token)
        .unwrap()
        .session_id;
    let mut session = get_session(&ts.state.sessions_ks, &session_id)
        .await
        .unwrap()
        .unwrap();
    let backdated = now_epoch() - BACKDATE_SECS;
    session.last_seen = backdated;
    store_session(&ts.state.sessions_ks, &session)
        .await
        .unwrap();
    (token, session_id, backdated)
}

/// A bearer-authenticated `POST /api/trust-tasks`. The body is not a valid
/// document: the session is authenticated before the body is read, which is
/// all this test is about.
fn trust_task_post(token: &str, background: bool) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/trust-tasks")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"));
    if background {
        builder = builder.header(BACKGROUND_REQUEST_HEADER, "1");
    }
    builder.body(Body::from("{}")).unwrap()
}

async fn last_seen(ts: &TestServer, session_id: &str) -> u64 {
    get_session(&ts.state.sessions_ks, session_id)
        .await
        .unwrap()
        .unwrap()
        .last_seen
}

#[tokio::test]
async fn a_background_request_leaves_the_idle_clock_alone() {
    let ts = TestServer::start().await;
    let (token, session_id, backdated) = idle_admin_session(&ts).await;

    for _ in 0..3 {
        let resp = ts
            .router()
            .oneshot(trust_task_post(&token, true))
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "a background request still authenticates"
        );
    }

    assert_eq!(last_seen(&ts, &session_id).await, backdated);
}

#[tokio::test]
async fn an_ordinary_request_moves_the_idle_clock() {
    let ts = TestServer::start().await;
    let (token, session_id, backdated) = idle_admin_session(&ts).await;

    let resp = ts
        .router()
        .oneshot(trust_task_post(&token, false))
        .await
        .unwrap();
    assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);

    assert!(last_seen(&ts, &session_id).await > backdated);
}
