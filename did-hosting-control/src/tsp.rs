//! TSP (Trust Spanning Protocol) transport binding for the control plane.
//!
//! The messaging-service framework carries TSP on the *same* shared
//! mediator websocket as DIDComm (see `ListenerConfig::protocols`). It
//! unpacks each inbound TSP frame, authenticates the sender VID
//! cryptographically, and hands us the cleartext payload via
//! [`affinidi_messaging_didcomm_service::TspHandler`].
//!
//! We treat the payload as a Trust Task document (`TrustTask<Value>`) and
//! route it through the *same* transport-agnostic
//! [`dispatch_inbound`](did_hosting_common::server::trust_tasks::dispatch_inbound)
//! core the HTTPS (`POST /api/trust-tasks`) and DIDComm-envelope
//! transports use. Because dispatch is transport-agnostic, every op
//! registered in the framework dispatcher is reachable over TSP with zero
//! extra wiring: the ACL + discovery ops today, and — once the legacy
//! `MSG_*` DID-management ops are migrated onto the framework — those too.
//!
//! The framework handles the response for us: return `Some(TspResponse)`
//! and it seals the bytes to the authenticated sender and routes them back
//! over the same socket, so this module never touches outbound TSP
//! plumbing.

use affinidi_messaging_didcomm_service::{
    DIDCommServiceError, HandlerContext, TspHandler, TspResponse,
};
use async_trait::async_trait;
use serde_json::Value;
use tracing::{info, warn};

use did_hosting_common::server::trust_tasks::TspTransportHandler;

use did_hosting_common::server::tsp_binding;

use crate::messaging::{body_parse_error, dispatch_trust_task_doc};
use crate::server::AppState;

/// messaging-service [`TspHandler`] that dispatches inbound TSP trust-task
/// documents through the shared Trust-Tasks core.
pub struct WebvhTspHandler {
    state: AppState,
}

impl WebvhTspHandler {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TspHandler for WebvhTspHandler {
    async fn handle(
        &self,
        _ctx: HandlerContext,
        payload: Vec<u8>,
        sender_vid: String,
    ) -> Result<Option<TspResponse>, DIDCommServiceError> {
        info!(sender = %sender_vid, "inbound TSP: trust-task document");
        match run_tsp_trust_task(&self.state, &sender_vid, &payload).await? {
            Some(bytes) => Ok(Some(TspResponse::new(bytes))),
            None => Ok(None),
        }
    }

    /// Answer an inbound TSP relationship control message. The accept policy —
    /// accept an invite from any framework-authenticated sender, authorize at
    /// the task layer — lives in `did_hosting_common` so the control plane and
    /// the edge server answer identically. See its module docs.
    async fn handle_control(
        &self,
        ctx: HandlerContext,
        control: affinidi_tsp::message::control::ControlMessage,
        sender_vid: String,
        thread_digest: [u8; 32],
    ) {
        did_hosting_common::server::tsp_relationship::answer_inbound_control(
            &ctx,
            &control,
            &sender_vid,
            thread_digest,
        )
        .await
    }
}

/// Compute the response bytes for an inbound TSP trust-task payload.
///
/// Extracted from [`WebvhTspHandler::handle`] so the parse + dispatch +
/// serialise logic is testable without a live TSP socket — mirrors the
/// `run_trust_tasks_envelope` / `run_webvh_dispatch` pattern in
/// [`crate::messaging`]. Returns `Ok(None)` for the SPEC §8.1 routing
/// exception (identity-mismatch with no transport sender), which the
/// TSP socket's authenticated-sender guarantee makes unreachable.
pub(crate) async fn run_tsp_trust_task(
    state: &AppState,
    sender: &str,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, DIDCommServiceError> {
    // Read whichever dialect the frame is in before parsing it. A conformant
    // peer sends the `binding/tsp/0.1` envelope; a not-yet-upgraded sibling
    // sends the bare document. See `tsp_binding` for why both are accepted.
    let (document, carriage) = tsp_binding::open(payload);

    let doc: trust_tasks_rs::TrustTask<Value> = match serde_json::from_slice(&document) {
        Ok(d) => d,
        Err(e) => {
            warn!(sender, error = %e, "TSP: payload did not parse as TrustTask<Value>");
            // Same `malformed_request` shape the DIDComm/HTTPS transports
            // emit, so a producer sees a consistent error across transports.
            //
            // Framed for the carriage it answers. Returning this bare to a
            // conformant peer is what made the original failure undiagnosable:
            // the VTA refused the very error that would have explained itself,
            // and waited out its timeout instead.
            let err_doc = body_parse_error(&e.to_string());
            let body = serde_json::to_vec(&err_doc).expect("trust-task-error serialises");
            return Ok(Some(tsp_binding::frame(body, carriage)));
        }
    };

    // Replay protection runs inside `dispatch_trust_task_doc`, keyed on the
    // proven issuer and the document id, after the proof has been verified.

    let my_vid = state
        .config
        .server_did
        .as_deref()
        .ok_or_else(|| DIDCommServiceError::Internal("server_did not configured".into()))?;

    // Dispatch through the unified trust-task router shared with the DIDComm
    // and HTTPS transports (`messaging::dispatch_trust_task_doc`). It routes
    // ACL + discovery ops to the typed framework pipeline and DID-management
    // ops to `dispatch_did_op`, so every op is reachable over TSP as a Trust
    // Task document.
    let transport = TspTransportHandler::new(my_vid.to_string(), sender.to_string());
    // No status codes on this transport, so the reply is the document either
    // way — `into_document` is where that flattening belongs, beside the router
    // rather than in each binding.
    let verifier = crate::messaging::require_verifier(state)?;
    match dispatch_trust_task_doc(state, sender, &transport, doc, verifier)
        .await?
        .into_document()
    {
        Some(value) => Ok(Some(tsp_binding::frame(
            serde_json::to_vec(&value).expect("response serialises"),
            carriage,
        ))),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{Arc, OnceLock};

    use did_hosting_common::server::config::{
        AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
    };
    use did_hosting_common::server::stats_collector::StatsCollector;
    use did_hosting_common::server::store::{
        KS_ACL, KS_DIDS, KS_REGISTRY, KS_SESSIONS, KS_STATS, KS_TIMESERIES, Store,
    };
    use serde_json::{Value, json};

    use crate::config::{AppConfig, RegistryConfig};
    use crate::server::AppState;

    use super::*;

    const SERVICE_DID: &str = "did:webvh:test:control.example.com";
    const SENDER_DID: &str = "did:web:admin.example";

    async fn test_state() -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store_config = StoreConfig {
            data_dir: PathBuf::from(dir.path()),
            ..StoreConfig::default()
        };
        let store = Store::open(&store_config).await.expect("open store");
        let config = AppConfig {
            features: FeaturesConfig {
                tsp: true,
                ..Default::default()
            },
            server_did: Some(SERVICE_DID.into()),
            mediator_did: None,
            public_url: Some("http://control.test".into()),
            did_hosting_url: Some("http://control.test".into()),
            server: ServerConfig::default(),
            log: LogConfig::default(),
            store: store_config,
            auth: AuthConfig::default(),
            secrets: SecretsConfig::default(),
            vta: VtaConfig::default(),
            registry: RegistryConfig::default(),
            trust_tasks: Default::default(),
            hosting: Default::default(),
            identity: Default::default(),
            config_path: PathBuf::new(),
        };
        let state = AppState {
            store: store.clone(),
            sessions_ks: store.keyspace(KS_SESSIONS).unwrap(),
            acl_ks: store.keyspace(KS_ACL).unwrap(),
            registry_ks: store.keyspace(KS_REGISTRY).unwrap(),
            dids_ks: store.keyspace(KS_DIDS).unwrap(),
            config: Arc::new(config),
            did_resolver: None,
            secrets_resolver: None,
            identity: None,
            trust_tasks_verifier: Some(Arc::new(
                did_hosting_common::server::trust_tasks::TransportBoundVerifier::with_resolver(
                    Arc::new(affinidi_data_integrity::DidKeyResolver),
                ),
            )),
            jwt_keys: None,
            webauthn: None,
            http_client: reqwest::Client::new(),
            didcomm_service: Arc::new(OnceLock::new()),
            stats_collector: Arc::new(StatsCollector::new()),
            stats_ks: store.keyspace(KS_STATS).unwrap(),
            timeseries_ks: store.keyspace(KS_TIMESERIES).unwrap(),
            signing_key_bytes: None,
            replay_cache: Arc::new(crate::replay::ReplayCache::new()),
            path_locks: crate::path_locks::PathLocks::new(),
            acl_locks: did_hosting_common::server::path_locks::PathLocks::new(),
            pending_challenges: Arc::new(crate::pending_challenges::PendingChallengeTracker::new()),
            ip_rate_limiter: Arc::new(crate::rate_limit::IpRateLimiter::new()),
            pending_confirms: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            outbox_notify: Arc::new(tokio::sync::Notify::new()),
        };
        (state, dir)
    }

    /// A malformed TSP payload comes back as a serialised
    /// `trust-task-error` document, not an `Err` — the sender gets a
    /// consistent error shape across every transport.
    #[tokio::test]
    async fn malformed_payload_yields_trust_task_error_doc() {
        let (state, _dir) = test_state().await;
        let out = run_tsp_trust_task(&state, SENDER_DID, b"{not json")
            .await
            .expect("handler does not error on bad input");
        let bytes = out.expect("a response is emitted");
        let doc: Value = serde_json::from_slice(&bytes).expect("response is JSON");
        assert_eq!(
            doc["type"],
            did_hosting_common::server::trust_tasks::framework_error_type_uri().to_string()
        );
    }

    /// A well-formed Trust Task document is dispatched through the shared
    /// `dispatch_inbound` core exactly as the HTTPS/DIDComm transports do.
    /// With no proof and the default proof policy the framework rejects it,
    /// which still proves the full parse → dispatch → serialise path ran
    /// over TSP and produced a routed error document addressed back to the
    /// TSP-authenticated sender.
    #[tokio::test]
    async fn well_formed_doc_routes_through_dispatch_inbound() {
        let (state, _dir) = test_state().await;
        let body = json!({
            "id": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "type": "https://trusttasks.org/spec/acl/grant/0.1",
            "recipient": SERVICE_DID,
            "issuedAt": "2026-07-06T00:00:00Z",
            "payload": {
                "entry": {
                    "subject": "did:web:carol.example",
                    "role": "owner",
                    "ext": { "vnd.affinidi.webvh": { "domains": { "kind": "all" } } }
                }
            }
        });
        let payload = serde_json::to_vec(&body).unwrap();
        let out = run_tsp_trust_task(&state, SENDER_DID, &payload)
            .await
            .expect("handler does not error");
        let bytes = out.expect("a response is emitted");
        let doc: Value = serde_json::from_slice(&bytes).expect("response is JSON");
        // The dispatch core ran and produced a typed document (a routed
        // rejection here, since no proof was supplied under the default
        // policy) — the TSP wrapper parsed, dispatched, and serialised.
        assert!(
            doc.get("type").and_then(Value::as_str).is_some(),
            "dispatch produced a typed trust-task document: {doc}"
        );
    }

    /// The reported failure, end to end at this handler.
    ///
    /// The VTA wraps every Trust Task in the `binding/tsp/0.1` envelope. This
    /// handler used to parse the payload straight as a `TrustTask<Value>`, so
    /// the envelope itself failed Type-URI validation — `type URI path must be
    /// /spec/<slug>/<major.minor>` — and the `trust-task-error` we sent back to
    /// say so went out bare, which the VTA refused in turn. Neither half of the
    /// round trip survived, and minting a persona DID died on a reply timeout
    /// for an answer that had already been sent and discarded.
    #[tokio::test]
    async fn an_enveloped_request_is_understood_and_answered_in_kind() {
        let (state, _dir) = test_state().await;
        let body = json!({
            "id": "urn:uuid:22222222-2222-2222-2222-222222222222",
            "type": "https://trusttasks.org/spec/acl/grant/0.1",
            "recipient": SERVICE_DID,
            "issuedAt": "2026-07-06T00:00:00Z",
            "payload": {
                "entry": {
                    "subject": "did:web:carol.example",
                    "role": "owner",
                    "ext": { "vnd.affinidi.webvh": { "domains": { "kind": "all" } } }
                }
            }
        });
        let wire = vta_sdk::tsp_binding::wrap_envelope(&serde_json::to_vec(&body).unwrap());

        let bytes = run_tsp_trust_task(&state, SENDER_DID, &wire)
            .await
            .expect("handler does not error")
            .expect("a response is emitted");

        // The answer is an envelope the VTA can open — not the bare document
        // it spent its whole timeout budget refusing.
        let document =
            vta_sdk::tsp_binding::open_envelope(&bytes).expect("the reply is a binding envelope");
        let doc: Value = serde_json::from_slice(&document).expect("document is JSON");
        // And the dispatcher saw *our task*, not the envelope. The reply is a
        // rejection — the sender has no ACL entry, so it is turned away before
        // any proof work — but what matters is that it answers `acl/grant`. Before the fix the
        // envelope's own type URI was all the parser ever saw, so no reply
        // could name the task inside it.
        assert_eq!(
            doc["payload"]["inResponseTo"]["typeUri"], "https://trusttasks.org/spec/acl/grant/0.1",
            "the reply answers the task the envelope carried: {doc}"
        );
        assert_eq!(
            doc["payload"]["code"], "permissionDenied",
            "it reached the authorisation gate, i.e. past parsing: {doc}"
        );
    }

    /// The other side of the tolerance: a sibling still on the pre-binding
    /// build sends bare and must still get a bare answer back. Wrapping its
    /// reply would break it exactly the way sending bare broke the VTA.
    #[tokio::test]
    async fn a_bare_request_is_still_answered_bare() {
        let (state, _dir) = test_state().await;
        let bytes = run_tsp_trust_task(&state, SENDER_DID, b"{not json")
            .await
            .expect("handler does not error on bad input")
            .expect("a response is emitted");
        assert!(
            vta_sdk::tsp_binding::open_envelope(&bytes).is_err(),
            "a bare request's reply is not wrapped"
        );
        let doc: Value = serde_json::from_slice(&bytes).expect("response is JSON");
        assert_eq!(
            doc["type"],
            did_hosting_common::server::trust_tasks::framework_error_type_uri().to_string()
        );
    }

    /// The loop, pinned. An error document used to fall through to
    /// `bridge_did_management`, be dispatched as a DID op, fail validation, and
    /// be answered with a problem report — which the peer answered in kind.
    /// Nothing may go back for one now, whatever it threads to.
    #[tokio::test]
    async fn an_inbound_error_is_terminal_and_is_never_answered() {
        let (state, _dir) = test_state().await;
        let error_doc = json!({
            "id": "urn:uuid:33333333-3333-3333-3333-333333333333",
            "threadId": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "type": "https://trusttasks.org/spec/trust-task-error/0.5",
            "recipient": SERVICE_DID,
            "issuedAt": "2026-07-06T00:00:00Z",
            "payload": {"code": "e.p.did.validation-error", "message": "nope"},
        });
        let wire = vta_sdk::tsp_binding::wrap_envelope(&serde_json::to_vec(&error_doc).unwrap());

        let out = run_tsp_trust_task(&state, SENDER_DID, &wire)
            .await
            .expect("handler does not error");

        assert!(
            out.is_none(),
            "answering an error is the loop — got: {:?}",
            out.map(|b| String::from_utf8_lossy(&b).into_owned())
        );
    }

    /// A DID-management op (`did/check-name`) sent over TSP as a Trust Task
    /// document is bridged to the legacy `dispatch_did_op` table and comes
    /// back as a Trust Task `#response` document — proving DID-management is
    /// a first-class trust task over TSP, not just the ACL/discovery ops.
    #[tokio::test]
    async fn did_management_check_name_bridges_over_tsp() {
        use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
        use did_hosting_common::server::domain::DomainScope;

        let (state, _dir) = test_state().await;
        // The document must be signed by its sender; a did:key signer
        // verifies without I/O. check_acl must then resolve that signer.
        let (sender, signer) = crate::signing::test_util::did_key_signer(&[31u8; 32]);
        store_acl_entry(
            &state.acl_ks,
            &AclEntry {
                did: sender.clone(),
                role: Role::Admin,
                label: None,
                created_at: 1_700_000_000,
                max_total_size: None,
                max_did_count: None,
                domains: DomainScope::All,
            },
        )
        .await
        .unwrap();

        let body = json!({
            "id": "urn:uuid:22222222-2222-2222-2222-222222222222",
            "type": "https://trusttasks.org/spec/did-management/did/check-name/0.1",
            "issuer": sender,
            "recipient": SERVICE_DID,
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            // A read-only availability probe: params ride in `payload`,
            // which the bridge maps to the synthesised `Message.body`.
            "payload": { "path": "alice", "reserve": false }
        });
        let signed = crate::signing::test_util::sign_operational(body, &signer).await;
        let payload = serde_json::to_vec(&signed).unwrap();
        let out = run_tsp_trust_task(&state, &sender, &payload)
            .await
            .expect("handler ok")
            .expect("a response is emitted");
        let doc: Value = serde_json::from_slice(&out).expect("response is JSON");

        // Bridged to dispatch_did_op → check-name `#response`, addressed back
        // to the proven signer, threaded to the request.
        assert_eq!(
            doc["type"],
            "https://trusttasks.org/spec/did-management/did/check-name/0.1#response"
        );
        assert_eq!(doc["payload"]["available"], true);
        assert_eq!(doc["payload"]["reserved"], false);
        assert_eq!(doc["issuer"], SERVICE_DID);
        assert_eq!(doc["recipient"], sender.as_str());
        assert_eq!(
            doc["threadId"], "urn:uuid:22222222-2222-2222-2222-222222222222",
            "response threads to the request id"
        );
    }

    /// The same probe unsigned — which is how every TSP client sent it before
    /// — is refused before the ACL is consulted, whatever sender VID TSP
    /// reported.
    #[tokio::test]
    async fn unsigned_did_management_over_tsp_is_refused() {
        use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
        use did_hosting_common::server::domain::DomainScope;

        let (state, _dir) = test_state().await;
        store_acl_entry(
            &state.acl_ks,
            &AclEntry {
                did: SENDER_DID.into(),
                role: Role::Admin,
                label: None,
                created_at: 1_700_000_000,
                max_total_size: None,
                max_did_count: None,
                domains: DomainScope::All,
            },
        )
        .await
        .unwrap();
        let body = json!({
            "id": "urn:uuid:55555555-5555-5555-5555-555555555555",
            "type": "https://trusttasks.org/spec/did-management/did/check-name/0.1",
            "issuer": SENDER_DID,
            "recipient": SERVICE_DID,
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": { "path": "alice", "reserve": true }
        });
        let out = run_tsp_trust_task(&state, SENDER_DID, &serde_json::to_vec(&body).unwrap())
            .await
            .expect("handler ok")
            .expect("a response is emitted");
        let doc: Value = serde_json::from_slice(&out).expect("response is JSON");
        assert_eq!(doc["payload"]["code"], "proofRequired", "{doc}");
    }

    /// `auth/challenge/0.1` over a messaging binding is held to the same
    /// pending-challenge caps as `POST /api/auth/challenge`. It used to call
    /// the canonical handler directly with its per-DID limit disabled, so
    /// challenges over DIDComm/TSP were unbounded. A refusal answers
    /// `permissionDenied` — the arm's mapping for every challenge failure; the
    /// specification defines no rate-limit code — and the slots free when the
    /// challenges expire.
    #[tokio::test]
    async fn challenge_over_tsp_is_capped_and_frees_on_expiry() {
        use std::sync::Mutex;
        use std::time::{Duration, Instant};

        use crate::pending_challenges::PendingChallengeTracker;

        let (mut state, _dir) = test_state().await;
        state.jwt_keys = Some(Arc::new(
            crate::auth::jwt::JwtKeys::from_ed25519_bytes(&[7u8; 32]).unwrap(),
        ));
        let now = Arc::new(Mutex::new(Instant::now()));
        let clock = now.clone();
        let ttl = Duration::from_secs(AuthConfig::default().challenge_ttl);
        state.pending_challenges = Arc::new(PendingChallengeTracker::with_clock(
            ttl,
            crate::pending_challenges::MAX_GLOBAL_PENDING,
            Arc::new(move || *clock.lock().unwrap()),
        ));

        let challenge = |i: u32| {
            serde_json::to_vec(&json!({
                "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                "type": "https://trusttasks.org/spec/auth/challenge/0.1",
                "recipient": SERVICE_DID,
                "issuedAt": chrono::Utc::now().to_rfc3339(),
                "payload": { "purpose": format!("login-{i}") }
            }))
            .unwrap()
        };
        async fn send(state: &AppState, body: &[u8]) -> Value {
            let out = run_tsp_trust_task(state, SENDER_DID, body)
                .await
                .expect("handler ok")
                .expect("a response is emitted");
            serde_json::from_slice(&out).expect("response is JSON")
        }

        for i in 0..crate::routes::auth::MAX_PENDING_CHALLENGES_PER_DID as u32 {
            let doc = send(&state, &challenge(i)).await;
            assert_eq!(
                doc["type"], "https://trusttasks.org/spec/auth/challenge/0.1#response",
                "challenge {i} under the cap: {doc}"
            );
        }
        assert_eq!(state.pending_challenges.count_for(SENDER_DID), 10);

        let refused = send(&state, &challenge(99)).await;
        assert_eq!(
            refused["payload"]["code"], "permissionDenied",
            "over the cap: {refused}"
        );
        assert_eq!(state.pending_challenges.count_for(SENDER_DID), 10);

        // Nobody redeems them. Once they expire the DID can ask again.
        *now.lock().unwrap() += ttl + Duration::from_secs(1);
        let doc = send(&state, &challenge(100)).await;
        assert_eq!(
            doc["type"], "https://trusttasks.org/spec/auth/challenge/0.1#response",
            "{doc}"
        );
        assert_eq!(state.pending_challenges.count_for(SENDER_DID), 1);
    }

    /// A failed authenticate leaves the challenge redeemable, so it keeps its
    /// slot; a successful one frees exactly that slot — including when the
    /// challenge was issued on another binding, since release is keyed by the
    /// session id rather than by which route issued it.
    #[tokio::test]
    async fn authenticate_over_tsp_releases_only_on_success() {
        use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
        use did_hosting_common::server::domain::DomainScope;

        // `auth/authenticate/0.1` requires a proof, so the caller is a did:key
        // that signs its documents, verified without network I/O.
        let (caller, signer) = crate::signing::test_util::did_key_signer(&[21u8; 32]);
        let (mut state, _dir) = test_state().await;
        state.jwt_keys = Some(Arc::new(
            crate::auth::jwt::JwtKeys::from_ed25519_bytes(&[7u8; 32]).unwrap(),
        ));
        state.trust_tasks_verifier = Some(Arc::new(
            did_hosting_common::server::trust_tasks::TransportBoundVerifier::with_resolver(
                Arc::new(affinidi_data_integrity::DidKeyResolver),
            ),
        ));
        // Enrolled, so the challenge row is persisted and can be redeemed.
        store_acl_entry(
            &state.acl_ks,
            &AclEntry {
                did: caller.clone(),
                role: Role::Owner,
                label: None,
                created_at: crate::auth::session::now_epoch(),
                max_total_size: None,
                max_did_count: None,
                domains: DomainScope::All,
            },
        )
        .await
        .unwrap();

        // Two challenges, issued the way `POST /api/auth/challenge` issues them.
        let first = crate::routes::auth::issue_challenge(&state, caller.clone())
            .await
            .unwrap();
        let _second = crate::routes::auth::issue_challenge(&state, caller.clone())
            .await
            .unwrap();
        assert_eq!(state.pending_challenges.count_for(&caller), 2);

        let authenticate = async |challenge: &str| {
            let unsigned = json!({
                "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                "type": "https://trusttasks.org/spec/auth/authenticate/0.1",
                "issuer": caller,
                "recipient": SERVICE_DID,
                "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                "payload": { "sessionId": first.session_id, "challenge": challenge }
            });
            let signed = crate::signing::test_util::sign_operational(unsigned, &signer).await;
            let out = run_tsp_trust_task(&state, &caller, &serde_json::to_vec(&signed).unwrap())
                .await
                .unwrap()
                .unwrap();
            serde_json::from_slice::<Value>(&out).unwrap()
        };

        let doc = authenticate(&"00".repeat(32)).await;
        assert_eq!(doc["payload"]["code"], "permissionDenied", "{doc}");
        assert_eq!(
            state.pending_challenges.count_for(&caller),
            2,
            "a failed authenticate does not consume the challenge, so it keeps its slot"
        );

        let doc = authenticate(&first.challenge).await;
        assert_eq!(
            doc["type"], "https://trusttasks.org/spec/auth/authenticate/0.1#response",
            "{doc}"
        );
        assert_eq!(state.pending_challenges.count_for(&caller), 1);
        assert!(
            !state.pending_challenges.release_session(&first.session_id),
            "already released: a second release is a no-op"
        );
        assert_eq!(state.pending_challenges.count_for(&caller), 1);
    }

    /// Every non-error reply is signed by the control plane: `issuer` is the
    /// control plane, `recipient` the requester, `proofPurpose:
    /// authentication` — checked here exactly as a client would, with
    /// `verify_sender_bound` from the requester's side. Covers the two replies
    /// clients depend on first: the challenge and the session.
    #[tokio::test]
    async fn challenge_and_authenticate_replies_are_signed_by_the_control_plane() {
        use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
        use did_hosting_common::server::domain::DomainScope;
        use did_hosting_common::server::identity::ServiceIdentity;
        use did_hosting_common::server::trust_tasks::{
            TransportBoundVerifier, verify_sender_bound,
        };

        let (control, control_key) = crate::signing::test_util::did_key_signer(&[61u8; 32]);
        let (caller, caller_key) = crate::signing::test_util::did_key_signer(&[62u8; 32]);
        let (mut state, _dir) = test_state().await;
        let mut cfg = (*state.config).clone();
        cfg.server_did = Some(control.clone());
        state.config = Arc::new(cfg);
        state.identity = Some(
            ServiceIdentity::from_signing_secret(&control, control_key)
                .await
                .unwrap(),
        );
        state.jwt_keys = Some(Arc::new(
            crate::auth::jwt::JwtKeys::from_ed25519_bytes(&[7u8; 32]).unwrap(),
        ));
        store_acl_entry(
            &state.acl_ks,
            &AclEntry {
                did: caller.clone(),
                role: Role::Owner,
                label: None,
                created_at: crate::auth::session::now_epoch(),
                max_total_size: None,
                max_did_count: None,
                domains: DomainScope::All,
            },
        )
        .await
        .unwrap();
        let client_verifier = TransportBoundVerifier::with_resolver(Arc::new(
            affinidi_data_integrity::DidKeyResolver,
        ));
        let now = || chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        // Challenge — proofless request, signed reply.
        let request = json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": "https://trusttasks.org/spec/auth/challenge/0.1",
            "issuer": caller,
            "recipient": control,
            "issuedAt": now(),
            "payload": { "purpose": "login" }
        });
        let out = run_tsp_trust_task(&state, &caller, &serde_json::to_vec(&request).unwrap())
            .await
            .unwrap()
            .unwrap();
        let reply: trust_tasks_rs::TrustTask<Value> = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            reply.type_uri.to_string(),
            "https://trusttasks.org/spec/auth/challenge/0.1#response"
        );
        verify_sender_bound(&reply, Some(&control), None, &caller, &client_verifier)
            .await
            .expect("challenge reply is signed by the control plane, for the caller");
        let session_id = reply.payload["sessionId"].as_str().unwrap().to_string();
        let challenge = reply.payload["challenge"].as_str().unwrap().to_string();

        // Authenticate — signed request, signed reply.
        let request = crate::signing::test_util::sign_operational(
            json!({
                "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                "type": "https://trusttasks.org/spec/auth/authenticate/0.1",
                "issuer": caller,
                "recipient": control,
                "issuedAt": now(),
                "payload": { "sessionId": session_id, "challenge": challenge }
            }),
            &caller_key,
        )
        .await;
        let out = run_tsp_trust_task(&state, &caller, &serde_json::to_vec(&request).unwrap())
            .await
            .unwrap()
            .unwrap();
        let reply: trust_tasks_rs::TrustTask<Value> = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            reply.type_uri.to_string(),
            "https://trusttasks.org/spec/auth/authenticate/0.1#response",
            "{reply:?}"
        );
        verify_sender_bound(&reply, Some(&control), None, &caller, &client_verifier)
            .await
            .expect("authenticate reply is signed by the control plane, for the caller");
    }
}
