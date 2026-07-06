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
    let doc: trust_tasks_rs::TrustTask<Value> = match serde_json::from_slice(payload) {
        Ok(d) => d,
        Err(e) => {
            warn!(sender, error = %e, "TSP: payload did not parse as TrustTask<Value>");
            // Same `malformed_request` shape the DIDComm/HTTPS transports
            // emit, so a producer sees a consistent error across transports.
            let err_doc = body_parse_error(&e.to_string());
            let body = serde_json::to_vec(&err_doc).expect("trust-task-error/0.1 serialises");
            return Ok(Some(body));
        }
    };

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
    match dispatch_trust_task_doc(state, sender, &transport, doc).await? {
        Some(value) => Ok(Some(serde_json::to_vec(&value).expect("response serialises"))),
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
            step_up_trusted_vta_did: None,
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
            trust_tasks_verifier: None,
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
    /// `trust-task-error/0.1` document, not an `Err` — the sender gets a
    /// consistent error shape across every transport.
    #[tokio::test]
    async fn malformed_payload_yields_trust_task_error_doc() {
        let (state, _dir) = test_state().await;
        let out = run_tsp_trust_task(&state, SENDER_DID, b"{not json")
            .await
            .expect("handler does not error on bad input");
        let bytes = out.expect("a response is emitted");
        let doc: Value = serde_json::from_slice(&bytes).expect("response is JSON");
        assert_eq!(doc["type"], "https://trusttasks.org/spec/trust-task-error/0.1");
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

    /// A DID-management op (`did/check-name`) sent over TSP as a Trust Task
    /// document is bridged to the legacy `dispatch_did_op` table and comes
    /// back as a Trust Task `#response` document — proving DID-management is
    /// a first-class trust task over TSP, not just the ACL/discovery ops.
    #[tokio::test]
    async fn did_management_check_name_bridges_over_tsp() {
        use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
        use did_hosting_common::server::domain::DomainScope;

        let (state, _dir) = test_state().await;
        // check_acl must resolve the sender; seed an admin entry.
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
            "id": "urn:uuid:22222222-2222-2222-2222-222222222222",
            "type": "https://trusttasks.org/spec/did-management/did/check-name/0.1",
            "recipient": SERVICE_DID,
            "issuedAt": "2026-07-06T00:00:00Z",
            // A read-only availability probe: params ride in `payload`,
            // which the bridge maps to the synthesised `Message.body`.
            "payload": { "path": "alice", "reserve": false }
        });
        let payload = serde_json::to_vec(&body).unwrap();
        let out = run_tsp_trust_task(&state, SENDER_DID, &payload)
            .await
            .expect("handler ok")
            .expect("a response is emitted");
        let doc: Value = serde_json::from_slice(&out).expect("response is JSON");

        // Bridged to dispatch_did_op → check-name `#response`, addressed back
        // to the TSP-authenticated sender, threaded to the request.
        assert_eq!(
            doc["type"],
            "https://trusttasks.org/spec/did-management/did/check-name/0.1#response"
        );
        assert_eq!(doc["payload"]["available"], true);
        assert_eq!(doc["payload"]["reserved"], false);
        assert_eq!(doc["issuer"], SERVICE_DID);
        assert_eq!(doc["recipient"], SENDER_DID);
        assert_eq!(
            doc["threadId"], "urn:uuid:22222222-2222-2222-2222-222222222222",
            "response threads to the request id"
        );
    }
}
