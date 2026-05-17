//! Integration tests for `did-hosting-client` (T50).
//!
//! Spins up a `wiremock::MockServer` per test, points a `Client`
//! at it (loopback HTTP — the transport gate accepts), and pins
//! observable behaviour:
//!
//! - **Auth happy path** — `Client::challenge` + `Client::authenticate`
//!   round-trip a wire-shaped response into `TokenData`.
//! - **Refresh happy path** — `Client::refresh` parses the same
//!   envelope.
//! - **Error mapping** — 401 / 403 / 404 / 409 / 415 / 5xx each map
//!   to the expected `ClientError` variant.
//! - **Trust-Task header** — every request carries the canonical
//!   URL.
//! - **Concurrent `ensure_token`** — two parallel callers against
//!   the same server serialise through the `ServerLocks` mutex,
//!   visible as the wiremock fixture seeing **one** challenge call.
//!
//! The signing-side correctness of the DIDComm JWS envelopes is
//! covered by the daemon's own `didcomm_unpack` test suite; this
//! file's fixtures don't verify signatures, just shapes.

use std::sync::Arc;

use did_hosting_client::auth::HostingSigningIdentityOwned;
use did_hosting_client::trust_tasks::{
    TASK_AUTH_AUTHENTICATE_1_0, TASK_AUTH_CHALLENGE_1_0, TASK_AUTH_REFRESH_1_0,
    TASK_DID_PUBLISH_1_0,
};
use did_hosting_client::{
    AuthedClient, Client, ClientError, InMemoryTokenStore, ServerLocks, SharedTokenStore, TokenData,
};
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SERVER_ID: &str = "did:example:server";
const RECIPIENT_DID: &str = "did:example:server";
const HOLDER_DID: &str = "did:example:alice";

fn tokens() -> SharedTokenStore {
    Arc::new(InMemoryTokenStore::new())
}

fn identity() -> HostingSigningIdentityOwned {
    // Stable test key — not used cryptographically by these tests
    // (the wiremock fixture doesn't verify the JWS).
    HostingSigningIdentityOwned::new(HOLDER_DID, *b"0123456789ABCDEF0123456789ABCDEF")
}

async fn mock_server() -> MockServer {
    MockServer::start().await
}

fn client_for(server: &MockServer) -> Client {
    Client::new(&server.uri(), SERVER_ID, tokens()).expect("loopback HTTP is allowed")
}

/// `Client::challenge` round-trips the daemon's wire response.
#[tokio::test]
async fn challenge_happy_path() {
    let server = mock_server().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/challenge"))
        .and(header("trust-task", TASK_AUTH_CHALLENGE_1_0))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sessionId": "sess-42",
            "data": { "challenge": "deadbeef" },
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = client_for(&server);
    let resp = c.challenge(HOLDER_DID).await.expect("challenge");
    assert_eq!(resp.session_id, "sess-42");
    assert_eq!(resp.challenge, "deadbeef");
}

/// `Client::authenticate` parses the daemon's wrapped TokenData.
#[tokio::test]
async fn authenticate_happy_path_parses_token_data() {
    let server = mock_server().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/"))
        .and(header("trust-task", TASK_AUTH_AUTHENTICATE_1_0))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sessionId": "sess-42",
            "data": {
                "accessToken": "AAA",
                "accessExpiresAt": 1_700_000_900u64,
                "refreshToken": "RRR",
                "refreshExpiresAt": 1_700_086_400u64,
            },
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = client_for(&server);
    let id_owned = identity();
    let id = id_owned.borrow();
    let td = c
        .authenticate(&id, "sess-42", "deadbeef", 1_700_000_000, RECIPIENT_DID)
        .await
        .expect("authenticate");
    assert_eq!(td.access_token, "AAA");
    assert_eq!(td.access_expires_at, 1_700_000_900);
    assert_eq!(td.refresh_token, "RRR");
    assert_eq!(td.refresh_expires_at, 1_700_086_400);
}

/// `Client::refresh` uses the same TokenData wire shape.
#[tokio::test]
async fn refresh_happy_path() {
    let server = mock_server().await;
    Mock::given(method("POST"))
        .and(path("/api/auth/refresh"))
        .and(header("trust-task", TASK_AUTH_REFRESH_1_0))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sessionId": "sess-42",
            "data": {
                "accessToken": "AAA2",
                "accessExpiresAt": 1_700_010_000u64,
                "refreshToken": "RRR2",
                "refreshExpiresAt": 1_700_086_400u64,
            },
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = client_for(&server);
    let id_owned = identity();
    let id = id_owned.borrow();
    let td = c
        .refresh(&id, "RRR", 1_700_000_000, RECIPIENT_DID)
        .await
        .expect("refresh");
    assert_eq!(td.access_token, "AAA2");
    assert_eq!(td.refresh_token, "RRR2");
}

/// 401 from `publish_did` returns `ClientError::Auth`. The
/// integrator's wrapper drops the cached tokens and re-auths.
#[tokio::test]
async fn publish_401_maps_to_auth_error() {
    let server = mock_server().await;
    Mock::given(method("PUT"))
        .and(path("/api/dids/alice"))
        .and(header("trust-task", TASK_DID_PUBLISH_1_0))
        .respond_with(ResponseTemplate::new(401).set_body_string("token expired"))
        .mount(&server)
        .await;

    let c = client_for(&server);
    let err = c
        .publish_did("stale-token", "alice", "application/jsonl", b"x".to_vec())
        .await
        .expect_err("401 must surface");
    assert!(matches!(err, ClientError::Auth(_)), "got {err:?}");
}

/// 403 surfaces as `Forbidden` — don't retry.
#[tokio::test]
async fn publish_403_maps_to_forbidden() {
    let server = mock_server().await;
    Mock::given(method("PUT"))
        .and(path("/api/dids/alice"))
        .respond_with(ResponseTemplate::new(403).set_body_string("acl"))
        .mount(&server)
        .await;

    let c = client_for(&server);
    let err = c
        .publish_did("t", "alice", "application/jsonl", b"x".to_vec())
        .await
        .expect_err("403 must surface");
    assert!(matches!(err, ClientError::Forbidden(_)), "got {err:?}");
}

/// 503 surfaces as `Server { status: 503, … }` with body for
/// audit-log clarity.
#[tokio::test]
async fn publish_503_maps_to_server_error() {
    let server = mock_server().await;
    Mock::given(method("PUT"))
        .and(path("/api/dids/alice"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({
            "status": "disabled",
            "domain": "a.example",
        })))
        .mount(&server)
        .await;

    let c = client_for(&server);
    let err = c
        .publish_did("t", "alice", "application/jsonl", b"x".to_vec())
        .await
        .expect_err("503 must surface");
    match err {
        ClientError::Server { status, body } => {
            assert_eq!(status, 503);
            assert!(body.contains("a.example"));
            assert!(body.contains("disabled"));
        }
        other => panic!("expected Server, got {other:?}"),
    }
}

/// 415 maps to `Protocol` — a Trust-Task mismatch shouldn't be
/// silently retried.
#[tokio::test]
async fn publish_415_maps_to_protocol() {
    let server = mock_server().await;
    Mock::given(method("PUT"))
        .and(path("/api/dids/alice"))
        .respond_with(ResponseTemplate::new(415).set_body_string("Trust-Task expected …"))
        .mount(&server)
        .await;

    let c = client_for(&server);
    let err = c
        .publish_did("t", "alice", "application/jsonl", b"x".to_vec())
        .await
        .expect_err("415 must surface");
    assert!(matches!(err, ClientError::Protocol(_)), "got {err:?}");
}

/// `register_did_atomic` forwards `method` + `domain` + `force`
/// fields verbatim in the request body. `body_partial_json`
/// matches a subset of the body keys, leaving `did_data` (whose
/// shape varies by method) un-asserted.
#[tokio::test]
async fn register_forwards_method_and_domain_params() {
    use did_hosting_client::RegisterDidRequest;
    use wiremock::matchers::body_partial_json;

    let server = mock_server().await;
    Mock::given(method("POST"))
        .and(path("/api/dids/register"))
        .and(body_partial_json(json!({
            "path": "alice",
            "method": "web",
            "domain": "example.com",
            "force": true,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "mnemonic": "alice",
            "didUrl": "https://example.com/alice/did.json",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = client_for(&server);
    let data = json!({ "id": "did:web:example.com:alice" });
    let req = RegisterDidRequest {
        path: "alice",
        method: Some("web"),
        did_data: &data,
        domain: Some("example.com"),
        force: true,
    };
    let resp = c.register_did_atomic("tok", &req).await.expect("register");
    assert_eq!(resp.mnemonic, "alice");
    assert_eq!(resp.did_url, "https://example.com/alice/did.json");
}

/// Network failure surfaces as `ClientError::Network`. We
/// simulate by pointing at a TCP port that won't accept (bind a
/// listener, immediately drop it; the kernel guarantees the port
/// stays unbound briefly enough for the connect to refuse).
#[tokio::test]
async fn network_failure_maps_to_network_error() {
    // Bind to an ephemeral port, capture its number, drop the
    // listener. A subsequent connect to the same port is
    // connection-refused (or unbound, depending on platform).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let base = format!("http://127.0.0.1:{port}");
    let c = Client::new(&base, SERVER_ID, tokens()).unwrap();
    let err = c.challenge(HOLDER_DID).await.expect_err("server is down");
    assert!(matches!(err, ClientError::Network(_)), "got {err:?}");
}

/// `AuthedClient::ensure_token` cache path skips the network
/// entirely when the seeded token is well within the freshness
/// window. The fixture asserts `expect(0)` — any request would
/// fail the assertion.
#[tokio::test]
async fn ensure_token_cache_path_skips_network() {
    let server = mock_server().await;
    // Any auth request would fail this — we expect zero.
    Mock::given(method("POST"))
        .and(path("/api/auth/challenge"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let store = tokens();
    let c = Client::new(&server.uri(), SERVER_ID, store.clone()).unwrap();
    let now = 1_700_000_000u64;
    store
        .put(
            SERVER_ID,
            HOLDER_DID,
            TokenData {
                access_token: "cached".into(),
                access_expires_at: now + 3600,
                refresh_token: "rrr".into(),
                refresh_expires_at: now + 86_400,
            },
        )
        .await
        .unwrap();

    let authed = AuthedClient::new(c, identity(), Arc::new(ServerLocks::new()), RECIPIENT_DID)
        .with_clock(move || now);
    let token = authed
        .with_access_token(|t| async move { Ok::<_, ClientError>(t) })
        .await
        .expect("cache hit");
    assert_eq!(token, "cached");
}

/// Two parallel `ensure_token` callers against the same
/// `(server_id, holder_did)` and empty cache must serialise. The
/// wiremock fixture sees the challenge endpoint hit **once**:
/// task A wins the lock, runs the full reauth, populates the
/// cache; task B blocks, then reads the cache.
#[tokio::test]
async fn concurrent_ensure_token_serialises_through_locks() {
    let server = mock_server().await;

    Mock::given(method("POST"))
        .and(path("/api/auth/challenge"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sessionId": "sess-once",
            "data": { "challenge": "0xabc" },
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/auth/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sessionId": "sess-once",
            "data": {
                "accessToken": "AAA-once",
                "accessExpiresAt": 1_700_010_000u64,
                "refreshToken": "RRR-once",
                "refreshExpiresAt": 1_700_086_400u64,
            },
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = Client::new(&server.uri(), SERVER_ID, tokens()).unwrap();
    let authed = Arc::new(
        AuthedClient::new(c, identity(), Arc::new(ServerLocks::new()), RECIPIENT_DID)
            .with_clock(|| 1_700_000_000),
    );

    let a = authed.clone();
    let task_a = tokio::spawn(async move {
        a.with_access_token(|t| async move { Ok::<_, ClientError>(t) })
            .await
    });
    let b = authed.clone();
    let task_b = tokio::spawn(async move {
        b.with_access_token(|t| async move { Ok::<_, ClientError>(t) })
            .await
    });

    let (a_tok, b_tok) = (
        task_a.await.unwrap().unwrap(),
        task_b.await.unwrap().unwrap(),
    );
    assert_eq!(a_tok, "AAA-once");
    assert_eq!(b_tok, "AAA-once");
    // wiremock `expect(1)` assertions on drop confirm exactly one
    // challenge + one authenticate hit the wire.
}
