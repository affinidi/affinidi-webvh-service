//! Shared plumbing for the daemon's end-to-end smoke tests
//! (`tests/e2e_distributed.rs`, `tests/e2e_daemon.rs`).
//!
//! The one thing neither `mediator_replication_smoke.rs` nor any other test
//! in this workspace has: a Trust Task **requester** that speaks TSP or
//! DIDComm over a real mediator socket. Every other TSP/DIDComm test dispatches
//! in-process (calls the frame/envelope handler function directly); this file
//! is the real thing — [`AdminClient`] mints its own `did:peer`, registers with
//! the mediator, runs a real `DIDCommService` listener, and correlates a
//! request to its asynchronous reply by `threadId`.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommService, DIDCommServiceConfig, DIDCommServiceError, Extension,
    HandlerContext, ListenerConfig, Protocols, RestartPolicy, RetryConfig, Router, TspHandler,
    TspResponse, handler_fn, ignore_handler,
};
use affinidi_messaging_test_mediator::TestMediatorHandle;
use affinidi_tdk::dids::{
    DID, KeyType, OneOrMany, PeerKeyRole, PeerService, PeerServiceEndpoint, PeerServiceEndpointLong,
};
use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde_json::Value;
use tokio::sync::{Mutex, oneshot};
use tokio_util::sync::CancellationToken;

use did_hosting_common::server::didcomm_profile::build_tdk_profile_for_identity;
use did_hosting_common::server::identity::{ProtocolSet, ServiceIdentity};
use did_hosting_common::server::trust_tasks::send::{build_signed_request, post_trust_task_https};
use did_hosting_common::server::tsp_binding::{self, Carriage};

/// The transport an admin request is driven over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Tsp,
    Didcomm,
    Https,
}

/// Poll `check` until it returns `true` or `timeout` elapses.
pub async fn wait_until<Fut>(mut check: impl FnMut() -> Fut, timeout: Duration, what: &str)
where
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if check().await {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for: {what}");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// A `did:key` signer — resolves with no network I/O, so it is used for
/// parties whose reachability isn't under test (the witness, and a daemon-mode
/// admin over plain HTTPS).
pub fn did_key_signer(seed: u8) -> (String, Secret) {
    let secret = Secret::generate_ed25519(None, Some(&[seed; 32]));
    let pk = secret.get_public_keymultibase().expect("public key");
    let did = format!("did:key:{pk}");
    let mut s = secret;
    s.id = format!("{did}#{pk}");
    (did, s)
}

/// A `DIDCommMessaging` service entry — see `mediator_replication_smoke.rs`'s
/// `didcomm_service()` for why the endpoint is a placeholder rather than the
/// mediator's own DID.
fn didcomm_service_entry() -> PeerService {
    PeerService {
        type_: "DIDCommMessaging".into(),
        endpoint: PeerServiceEndpoint::Long(OneOrMany::One(PeerServiceEndpointLong {
            uri: "urn:mediator:placeholder".into(),
            accept: vec!["didcomm/v2".into()],
            routing_keys: vec![],
        })),
        id: Some("#vta-didcomm".into()),
    }
}

/// A `TrustTaskHTTPS` service entry pointing at `base_url` (the Trust-Task
/// base; the request itself goes to `{base_url}/trust-tasks`).
pub fn https_service(base_url: &str) -> PeerService {
    PeerService {
        type_: "TrustTaskHTTPS".into(),
        endpoint: PeerServiceEndpoint::Uri(base_url.to_string()),
        id: Some("#trust-tasks".into()),
    }
}

/// Mint a `did:peer:2` with Ed25519 (verification) + X25519 (encryption) keys
/// and a `DIDCommMessaging` service, and register it with `mediator` (`LOCAL`,
/// `ALLOW_ALL`) — the prerequisite for its listener to ever complete a
/// handshake. Returns `(did, signing_secret, ka_secret)`.
pub async fn mint_mediator_peer(mediator: &TestMediatorHandle) -> (String, Secret, Secret) {
    let (did, secrets) = DID::generate_did_peer_with_services(
        vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ],
        Some(vec![didcomm_service_entry()]),
    )
    .expect("generate did:peer");
    let mut secrets = secrets.into_iter();
    let signing = secrets.next().expect("verification secret");
    let ka = secrets.next().expect("encryption secret");
    mediator
        .register_local_did(&did)
        .await
        .expect("register did:peer with the test mediator");
    (did, signing, ka)
}

/// Mint a `did:peer:2` with only a verification key and a `TrustTaskHTTPS`
/// service at `base_url` — HTTPS carries no encryption, so no key-agreement
/// key is needed. Returns `(did, signing_secret)`.
pub fn mint_https_peer(base_url: &str) -> (String, Secret) {
    let (did, secrets) = DID::generate_did_peer_with_services(
        vec![(PeerKeyRole::Verification, KeyType::Ed25519)],
        Some(vec![https_service(base_url)]),
    )
    .expect("generate did:peer");
    let signing = secrets.into_iter().next().expect("verification secret");
    (did, signing)
}

/// Build a one-entry did:webvh log at `host`/`mnemonic`, signed by `signing`,
/// optionally naming `witness_id` (a `did:key` witness identifier) in its
/// `witness` parameter (threshold 1) and `watchers` (URLs) in its `watchers`
/// parameter. Returns `(jsonl, version_id)`.
pub async fn build_did_log(
    host: &str,
    mnemonic: &str,
    signing: &Secret,
    witness_id: Option<&str>,
    watchers: &[&str],
) -> (String, String) {
    use didwebvh_rs::log_entry::LogEntryMethods;
    use didwebvh_rs::witness::{Witness, Witnesses};

    let pk_mb = signing.get_public_keymultibase().expect("public key");
    let mut signing_key = signing.clone();
    signing_key.id = format!("did:key:{pk_mb}#{pk_mb}");

    let doc = did_hosting_common::did::build_did_document(
        host,
        mnemonic,
        &pk_mb,
        &did_hosting_common::did::DidDocumentOptions::default(),
    );
    let params = didwebvh_rs::parameters::Parameters {
        update_keys: Some(Arc::new(vec![pk_mb.clone().into()])),
        witness: witness_id.map(|id| {
            Arc::new(Witnesses::Value {
                threshold: 1,
                witnesses: vec![Witness {
                    id: id.to_string().into(),
                }],
            })
        }),
        watchers: (!watchers.is_empty())
            .then(|| Arc::new(watchers.iter().map(|w| w.to_string()).collect())),
        ..Default::default()
    };
    let mut state = didwebvh_rs::DIDWebVHState::default();
    state
        .create_log_entry(
            Some((chrono::Utc::now() - chrono::Duration::hours(1)).fixed_offset()),
            &doc,
            &params,
            &signing_key,
        )
        .await
        .expect("create webvh log entry");
    let entries = state.log_entries();
    let last = entries.last().expect("at least one entry");
    let version_id = last.log_entry.get_version_id().to_string();
    let jsonl = entries
        .iter()
        .map(|e| serde_json::to_string(&e.log_entry).expect("serialise log entry"))
        .collect::<Vec<_>>()
        .join("\n");
    (jsonl, version_id)
}

// ---------------------------------------------------------------------------
// AdminClient — a Trust Task requester that can drive TSP, DIDComm or HTTPS
// ---------------------------------------------------------------------------

type Pending = Arc<Mutex<HashMap<String, oneshot::Sender<trust_tasks_rs::TrustTask<Value>>>>>;

/// Reply captured on the admin's own DIDComm-envelope route: parse
/// `message.body` as a `TrustTask<Value>` and resolve whichever pending call
/// its `threadId` names.
async fn capture_envelope(
    _ctx: HandlerContext,
    message: Message,
    Extension(pending): Extension<Pending>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    if let Ok(doc) =
        serde_json::from_value::<trust_tasks_rs::TrustTask<Value>>(message.body.clone())
        && let Some(thread_id) = doc.thread_id.clone()
        && let Some(tx) = pending.lock().await.remove(&thread_id)
    {
        let _ = tx.send(doc);
    }
    Ok(None)
}

/// [`affinidi_messaging_didcomm_service::TspHandler`] that opens whichever
/// binding dialect the frame arrived in ([`tsp_binding::open`]), parses the
/// document, and resolves the pending call its `threadId` names. Every other
/// TSP-driving test in this workspace dispatches in-process; this is the
/// socket-facing counterpart for the admin RPC client's own listener.
struct CapturingTsp {
    pending: Pending,
}

#[async_trait::async_trait]
impl TspHandler for CapturingTsp {
    async fn handle(
        &self,
        _ctx: HandlerContext,
        payload: Vec<u8>,
        _sender_vid: String,
    ) -> Result<Option<TspResponse>, DIDCommServiceError> {
        let (document, _carriage) = tsp_binding::open(&payload);
        if let Ok(doc) = serde_json::from_slice::<trust_tasks_rs::TrustTask<Value>>(&document)
            && let Some(thread_id) = doc.thread_id.clone()
            && let Some(tx) = self.pending.lock().await.remove(&thread_id)
        {
            let _ = tx.send(doc);
        }
        Ok(None)
    }
}

/// A Trust Task requester with its own `did:peer` identity, a real
/// `DIDCommService` listener (TSP + DIDComm) on the mediator, and a plain
/// `reqwest` client for HTTPS — able to drive a signed request to a peer over
/// whichever of the three transports a test names, and await the verified
/// reply.
pub struct AdminClient {
    pub did: String,
    signer: Secret,
    svc: DIDCommService,
    listener_id: String,
    pending: Pending,
    did_resolver: DIDCacheClient,
    shutdown: CancellationToken,
}

impl AdminClient {
    /// Mint the admin's identity, register it with `mediator`, and start its
    /// listener.
    pub async fn start(mediator: &TestMediatorHandle, did_resolver: DIDCacheClient) -> Self {
        let (did, signing, ka) = mint_mediator_peer(mediator).await;
        let identity = ServiceIdentity::for_didcomm_test(
            &did,
            signing.clone(),
            ka,
            mediator.did(),
            ProtocolSet {
                didcomm: true,
                tsp: true,
            },
        )
        .await
        .expect("admin identity");
        let profile = build_tdk_profile_for_identity("admin", &identity, Some(mediator.did()))
            .await
            .expect("admin TDK profile");

        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let listener_id = "admin".to_string();
        let listener = ListenerConfig {
            id: listener_id.clone(),
            profile,
            restart_policy: RestartPolicy::Always {
                backoff: RetryConfig::default(),
            },
            auto_delete: true,
            protocols: Protocols::BOTH,
            ..Default::default()
        };
        let router = Router::new()
            .extension(pending.clone())
            .route(
                trust_tasks_didcomm::ENVELOPE_TYPE,
                handler_fn(capture_envelope),
            )
            .expect("route envelope handler")
            .fallback(handler_fn(ignore_handler));
        let config = DIDCommServiceConfig {
            listeners: vec![listener],
        };
        let shutdown = CancellationToken::new();
        let svc = DIDCommService::start_with_tsp(
            config,
            router,
            CapturingTsp {
                pending: pending.clone(),
            },
            shutdown.clone(),
        )
        .await
        .expect("start admin DIDComm/TSP service");
        svc.wait_connected(&listener_id, Duration::from_secs(20))
            .await
            .expect("admin listener connects to the mediator");

        Self {
            did,
            signer: signing,
            svc,
            listener_id,
            pending,
            did_resolver,
            shutdown,
        }
    }

    /// Sign a `type_uri` request to `to` and drive it over `via`, returning
    /// the verified reply document (a task `#response` or a signed
    /// `trust-task-error`). `https_url` is the peer's base URL (its
    /// `POST /api/trust-tasks` route is derived from it); only read when
    /// `via == Via::Https`.
    pub async fn call(
        &self,
        via: Via,
        to: &str,
        https_url: &str,
        type_uri: &str,
        payload: Value,
    ) -> trust_tasks_rs::TrustTask<Value> {
        let doc = build_signed_request(type_uri, &self.did, to, payload, &self.signer)
            .await
            .unwrap_or_else(|e| panic!("build request {type_uri}: {e}"));

        match via {
            Via::Https => {
                let url = format!("{}/api/trust-tasks", https_url.trim_end_matches('/'));
                post_trust_task_https(&self.did, to, &url, &doc, Some(&self.did_resolver))
                    .await
                    .unwrap_or_else(|e| panic!("https send {type_uri} to {to}: {e}"))
            }
            Via::Tsp => {
                self.svc
                    .tsp_ensure_relationship(&self.listener_id, to)
                    .await
                    .unwrap_or_else(|e| panic!("tsp relationship with {to}: {e}"));
                let rx = self.await_reply(&doc.id).await;
                let framed = tsp_binding::frame(
                    serde_json::to_vec(&doc).expect("serialise request"),
                    Carriage::Envelope,
                );
                self.svc
                    .send_tsp(&self.listener_id, to, &framed)
                    .await
                    .unwrap_or_else(|e| panic!("tsp send {type_uri} to {to}: {e}"));
                self.recv_reply(rx, via, type_uri).await
            }
            Via::Didcomm => {
                let rx = self.await_reply(&doc.id).await;
                let msg = Message::build(
                    uuid::Uuid::new_v4().to_string(),
                    trust_tasks_didcomm::ENVELOPE_TYPE.to_string(),
                    serde_json::to_value(&doc).expect("serialise request"),
                )
                .from(self.did.clone())
                .to(to.to_string())
                .created_time(did_hosting_common::server::auth::session::now_epoch())
                .finalize();
                self.svc
                    .send_message(&self.listener_id, msg, to)
                    .await
                    .unwrap_or_else(|e| panic!("didcomm send {type_uri} to {to}: {e}"));
                self.recv_reply(rx, via, type_uri).await
            }
        }
    }

    async fn await_reply(
        &self,
        request_id: &str,
    ) -> oneshot::Receiver<trust_tasks_rs::TrustTask<Value>> {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(request_id.to_string(), tx);
        rx
    }

    async fn recv_reply(
        &self,
        rx: oneshot::Receiver<trust_tasks_rs::TrustTask<Value>>,
        via: Via,
        type_uri: &str,
    ) -> trust_tasks_rs::TrustTask<Value> {
        tokio::time::timeout(Duration::from_secs(20), rx)
            .await
            .unwrap_or_else(|_| panic!("{via:?}: timed out waiting for a reply to {type_uri}"))
            .expect("reply sender dropped without a reply")
    }
}

impl Drop for AdminClient {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// The reply's payload when it is `type_uri`'s `#response`, else a panic
/// naming what came back.
pub fn ok(reply: &trust_tasks_rs::TrustTask<Value>, type_uri: &str) -> Value {
    let got = reply.type_uri.to_string();
    assert_eq!(
        got,
        format!("{type_uri}#response"),
        "expected a response, got {got}: {reply:?}"
    );
    reply.payload.clone()
}
