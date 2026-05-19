//! Trust Tasks dispatch core — the shared seam between the HTTPS
//! transport (`POST /trust-tasks`), the DIDComm envelope route, and
//! the daemon's in-process wiring.
//!
//! The control plane and daemon both call [`dispatch_inbound`] with a
//! parsed [`TrustTask<serde_json::Value>`], a [`TransportHandler`]
//! configured for whatever transport delivered the document, and
//! optionally a [`ProofVerifier`]. The function:
//!
//! 1. Narrows the untyped document to one of the [`TypedInbound`]
//!    variants via the shared [`build_dispatcher`].
//! 2. Runs SPEC.md §7.2 items 4–8 against the typed document via
//!    [`trust_tasks_rs::consume_inbound`].
//! 3. Hands the typed document to the matching async handler
//!    (`handlers::*`).
//! 4. Returns a [`DispatchOutcome`] the calling transport serialises
//!    onto the wire.
//!
//! The skeleton in this commit lays down the module shape, types, and
//! dispatcher wiring. Handler implementations follow per-spec in
//! subsequent commits.
//!
//! ## Why we don't use `HttpsServer::on(...)` directly
//!
//! `trust_tasks_https::HttpsServerBuilder::on` takes a **sync**
//! `Fn(&TrustTask<P>, &RequestContext) -> Result<Resp, RejectReason>`.
//! Every ACL handler we ship needs async fjall I/O, which doesn't
//! compose cleanly with the sync signature without `block_in_place`.
//! Owning our own async dispatch core lets HTTPS and DIDComm share a
//! single set of handlers with no sync→async shim.

pub mod entry;
pub mod ext;
pub mod handlers;

use chrono::Utc;
use serde::Serialize;
use trust_tasks_rs::{
    Dispatcher, ErrorResponse, Payload, ProofVerifier, RejectReason, TransportHandler, TrustTask,
    VerificationError,
    specs::{
        acl::{change_role, grant, list, revoke, show},
        trust_task_discovery as discovery,
    },
};
use uuid::Uuid;

use crate::server::path_locks::PathLocks;
use crate::server::store::KeyspaceHandle;

/// The set of inbound Trust Task payloads this service routes. New
/// spec families are added here in lockstep with new handler modules.
///
/// Constructed by [`build_dispatcher`], which the dispatch core uses
/// to narrow an inbound [`TrustTask<serde_json::Value>`] to one of
/// these typed variants before invoking the async handler matched on
/// the variant.
#[derive(Debug)]
pub enum TypedInbound {
    Grant(TrustTask<grant::v0_1::Payload>),
    Revoke(TrustTask<revoke::v0_1::Payload>),
    ChangeRole(TrustTask<change_role::v0_1::Payload>),
    Show(TrustTask<show::v0_1::Payload>),
    List(TrustTask<list::v0_1::Payload>),
    Discovery(TrustTask<discovery::v0_1::Payload>),
}

/// Build the shared [`Dispatcher`] keyed on each registered Type URI.
///
/// The dispatcher is sync and runs SPEC.md §7.2 items 1–3 (framework
/// schema + payload-type narrowing + unknown-type rejection). Items
/// 4–8 are deferred to [`trust_tasks_rs::consume_inbound`] inside
/// `dispatch_inbound` so they can run async alongside the business
/// handler.
pub fn build_dispatcher() -> Dispatcher<TypedInbound> {
    Dispatcher::new()
        .on::<grant::v0_1::Payload, _>(TypedInbound::Grant)
        .on::<revoke::v0_1::Payload, _>(TypedInbound::Revoke)
        .on::<change_role::v0_1::Payload, _>(TypedInbound::ChangeRole)
        .on::<show::v0_1::Payload, _>(TypedInbound::Show)
        .on::<list::v0_1::Payload, _>(TypedInbound::List)
        .on::<discovery::v0_1::Payload, _>(TypedInbound::Discovery)
}

/// Result of [`dispatch_inbound`]. The calling transport (HTTPS or
/// DIDComm) decides how to emit each variant.
#[derive(Debug)]
pub enum DispatchOutcome {
    /// A typed success response document. The transport serialises
    /// it as the response body / packed envelope.
    Handled(TrustTask<serde_json::Value>),
    /// A framework-level or handler-level rejection. Already routed
    /// per SPEC.md §8.1; the transport emits it as the response.
    Rejected(ErrorResponse),
    /// SPEC.md §8.1 routing exception: identity-mismatch rejection
    /// with no transport-authenticated sender. The transport SHOULD
    /// log this and emit nothing on the wire.
    Suppressed,
}

/// Per-request context handed to every typed handler.
///
/// Holds the storage + identity needed by the maintainer-policy logic
/// the handlers implement. Constructed by each transport (HTTPS or
/// DIDComm) before [`dispatch_inbound`] is called.
///
/// Not [`Debug`] — [`KeyspaceHandle`] wraps a `fjall::Keyspace` whose
/// internal state isn't usefully Debug-printable. Hand-derive on
/// fields rather than the struct if you need diagnostics.
#[derive(Clone)]
pub struct TrustTaskContext<'a> {
    /// Handle to the `KS_ACL` keyspace — every ACL handler reads /
    /// writes through this.
    pub acl_ks: &'a KeyspaceHandle,
    /// Per-key mutex registry the ACL write handlers acquire to
    /// serialise their read-then-write critical sections. All three
    /// write handlers (`grant`, `change-role`, `revoke`) acquire the
    /// same well-known key (`ACL_WRITE_LOCK_KEY`) so concurrent
    /// admins targeting *different* subjects still serialise — that's
    /// the only way to make the last-authority guard race-free
    /// without per-row read locks. Contention is negligible: ACL
    /// writes are admin-action-rate (tens per day at most).
    pub acl_locks: &'a PathLocks,
    /// The local service DID (our `recipient` from the framework's
    /// perspective). Used by [`TrustTask::validate_basic`] for SPEC.md
    /// §7.2 item 5 recipient enforcement, and surfaces as `issuer` on
    /// outbound response documents.
    pub my_vid: &'a str,
}

/// Single shared key under which every ACL write serialises. A
/// per-subject key would let parallel grants on different subjects
/// proceed, but the last-authority guard reads the *whole* ACL —
/// per-subject locking can't make that guard race-free. The simpler
/// global gate is correct and cheap.
pub const ACL_WRITE_LOCK_KEY: &str = "::trust-tasks::acl-write";

/// Run SPEC.md §7.2 items 4–8 against a typed inbound document, then
/// invoke `handler` and wrap the result in a [`DispatchOutcome`].
///
/// This is the per-handler scaffolding that turns "I have a
/// [`TrustTask<P>`] and an async business handler" into a wire-ready
/// outcome. It is the maintainer-side counterpart to
/// [`trust_tasks_rs::consume_inbound`], with one shape difference: the
/// handler returns [`ErrorResponse`] directly on the rejection path
/// (rather than [`RejectReason`]), so a handler can mint a fully-
/// custom error payload — `permission_denied + details`, the extended
/// code `acl/revoke:last_authority_protected`, etc — without losing
/// the SPEC.md §8.1 routing (`issuer` and `recipient` are copied from
/// the request before the handler consumes the doc, so the error is
/// always routed back to the producer).
///
/// `V` is left generic (with `?Sized`) so callers pass either a
/// concrete verifier reference (`&AffinidiVerifier`) or a
/// trait-object-equivalent. `Option::<&V>::None` opts out of strict
/// proof enforcement; in that mode an absent `proof` on a non-bearer
/// spec is accepted (the [`TransportHandler`] is still trusted for
/// identity).
pub async fn run_pipeline<P, R, V, F, Fut>(
    transport: &(impl TransportHandler + Sync),
    verifier: Option<&V>,
    doc: TrustTask<P>,
    my_vid: &str,
    handler: F,
) -> DispatchOutcome
where
    P: Payload + Serialize + Send + Sync,
    R: Serialize,
    V: ProofVerifier + ?Sized,
    F: FnOnce(TrustTask<P>) -> Fut,
    Fut: std::future::Future<Output = Result<TrustTask<R>, ErrorResponse>>,
{
    let now = Utc::now();
    let new_id = || format!("urn:uuid:{}", Uuid::new_v4());

    // §7.2 items 4 + 5 — expiry and recipient identity.
    if let Err(reason) = doc.validate_basic(now, my_vid) {
        return DispatchOutcome::Rejected(doc.reject_with(new_id(), reason));
    }

    // §7.2 item 6 — in-band vs transport-derived identity cross-check.
    // Under IdentityMismatch the framework routes the rejection to the
    // transport-authenticated sender (NOT the contested in-band issuer),
    // and may suppress the response entirely when the transport
    // authenticated nothing — see SPEC.md §8.1.
    let resolved = match transport.resolve_parties(&doc) {
        Ok(r) => r,
        Err(mismatch) => {
            let reason = RejectReason::IdentityMismatch(mismatch);
            return match transport.reject(&doc, new_id(), reason) {
                Some(err) => DispatchOutcome::Rejected(err),
                None => DispatchOutcome::Suppressed,
            };
        }
    };

    // SPEC.md §4.8.1: when `issuer` / `recipient` are absent in-band,
    // the consumer MAY treat the transport-derived value as if it had
    // been carried in-band. We fold the resolved identity into the
    // document before invoking the typed handler so the handler can
    // unconditionally read `doc.issuer` / `doc.recipient` regardless
    // of whether the producer included them on the wire — this is the
    // pattern that lets a JWT-bearer client emit an envelope with no
    // `issuer` (the JWT's `sub` becomes the issuer) and have the
    // handler-side ACL check work uniformly.
    let mut doc = doc;
    if doc.issuer.is_none() {
        doc.issuer = resolved.issuer.clone();
    }
    if doc.recipient.is_none() {
        doc.recipient = resolved.recipient.clone();
    }

    // §7.2 item 7 — proof verification (when present) + spec-mandated
    // proof: REQUIRED enforcement. Four cases:
    //
    //   - proof + verifier → verify, reject `proof_invalid` on failure.
    //   - no proof + verifier + non-bearer spec → `proof_required`.
    //   - **proof + no verifier** → reject `malformed_request`. A
    //     producer carrying a Data Integrity proof has explicitly
    //     opted into the signed-envelope contract; if the maintainer
    //     has not opted into verification (default
    //     `trust_tasks.enforce_proofs = false`) the proof would be
    //     silently dropped, which is a misleading wire shape and a
    //     security-relevant footgun (the producer believes their
    //     signing key is authenticating the request; only the
    //     transport's bearer JWT is). We refuse the ambiguity
    //     loudly so the producer or operator fixes the mismatch.
    //   - no proof + no verifier (or bearer spec) → fine.
    match (doc.proof.as_ref(), verifier) {
        (Some(_), Some(v)) => {
            if let Err(verr) = v.verify(&doc).await {
                return DispatchOutcome::Rejected(
                    doc.reject_with(new_id(), verification_error_to_reason(verr)),
                );
            }
        }
        (Some(_), None) => {
            return DispatchOutcome::Rejected(
                doc.reject_with(
                    new_id(),
                    RejectReason::MalformedRequest {
                        reason: "document carries a `proof` member but this maintainer has \
                                 not opted into proof verification (`trust_tasks.enforce_proofs \
                                 = false`). Either omit the proof and authenticate via the \
                                 transport, or ask the operator to enable enforcement."
                            .to_string(),
                    },
                ),
            );
        }
        (None, Some(_)) if !P::IS_BEARER => {
            return DispatchOutcome::Rejected(
                doc.reject_with(new_id(), RejectReason::ProofRequired),
            );
        }
        _ => {}
    }

    // §7.2 item 8 — audience binding (proof present + recipient absent
    // on a non-bearer spec).
    if let Err(reason) = doc.enforce_audience_binding() {
        return DispatchOutcome::Rejected(doc.reject_with(new_id(), reason));
    }

    // All framework checks passed — hand to the maintainer's logic.
    match handler(doc).await {
        Ok(typed_resp) => {
            // Re-shape the typed response as a TrustTask<Value> so the
            // dispatch layer can hand it to whichever transport without
            // pinning the response's payload type in DispatchOutcome.
            let value = serde_json::to_value(&typed_resp)
                .expect("typed response document serialises (codegened structs)");
            let value_doc: TrustTask<serde_json::Value> = serde_json::from_value(value)
                .expect("TrustTask<Value> from any TrustTask<Serialize> round-trips");
            DispatchOutcome::Handled(value_doc)
        }
        Err(error_doc) => DispatchOutcome::Rejected(error_doc),
    }
}

/// Translate a [`VerificationError`] into the framework's
/// [`RejectReason::ProofInvalid`] form. Verification errors collapse
/// to `proof_invalid` on the wire per SPEC.md §8.3; the structured
/// failure-mode taxonomy stays in operator logs via the embedded
/// `reason` string.
fn verification_error_to_reason(e: VerificationError) -> RejectReason {
    let reason = match e {
        VerificationError::UnsupportedCryptosuite(s) => format!("unsupported cryptosuite: {s}"),
        VerificationError::MalformedProof(s) => format!("malformed proof: {s}"),
        VerificationError::IssuerMismatch(s) => {
            format!("verification method does not bind to issuer: {s}")
        }
        VerificationError::SignatureInvalid => "signature verification failed".to_string(),
        VerificationError::Other(s) => format!("proof verification failed: {s}"),
    };
    RejectReason::ProofInvalid { reason }
}

/// Build a `trust-task-error/0.1` document addressed to the request's
/// `issuer`, carrying a custom `ErrorPayload` — used by handlers that
/// need to emit spec-defined error shapes that don't fit the
/// framework's [`RejectReason`] variants (e.g. `permission_denied`
/// with structured `details`, or extension codes like
/// `acl/revoke:last_authority_protected`).
pub(crate) fn reject_with<P>(
    request: &TrustTask<P>,
    payload: trust_tasks_rs::ErrorPayload,
) -> ErrorResponse {
    let id = format!("urn:uuid:{}", Uuid::new_v4());
    request.reject_with(id, payload)
}

/// Type-anchor for the no-verifier case of [`run_pipeline`] /
/// [`dispatch_inbound`].
///
/// The pipeline functions are generic in `V: ProofVerifier + ?Sized`,
/// which means `Option::<&V>::None` still needs a concrete `V` for
/// inference. This uninhabited type fills that slot: it satisfies the
/// trait bound *structurally* (the `ProofVerifier` impl exists) but
/// can never be instantiated. `Some(&NoVerifier)` won't compile —
/// you can only ever pass `None::<&NoVerifier>`.
///
/// Used when the operator has not opted into strict proof
/// enforcement (`trust_tasks.enforce_proofs = false`); the dispatch
/// layer routes through `Option::<&NoVerifier>::None`. The
/// `(Some(proof), None)` arm of [`run_pipeline`] returns
/// `malformed_request` rather than silently dropping a present
/// proof — see the match arms there.
pub enum NoVerifier {}

#[async_trait::async_trait]
impl ProofVerifier for NoVerifier {
    async fn verify<P>(&self, _doc: &TrustTask<P>) -> Result<(), VerificationError>
    where
        P: serde::Serialize + Send + Sync,
    {
        // Unreachable by construction: `NoVerifier` has no variants,
        // so `&self` is uninhabited. Rust's exhaustiveness analysis
        // doesn't *prove* this without `unreachable!()` because the
        // trait method takes a generic `P`; the unreachable! is
        // belt-and-braces.
        unreachable!("NoVerifier has no variants; verify cannot be called");
    }
}

/// Top-level dispatch: narrow an untyped inbound document, then call
/// the matching async handler.
///
/// Steps:
/// 1. SPEC.md §7.2 items 1–3 — framework / payload schema validation
///    and Type URI routing — via [`build_dispatcher`].
/// 2. Hand the typed document to the per-spec handler, which itself
///    runs items 4–8 via [`run_pipeline`] before invoking its business
///    logic.
///
/// Returns a [`DispatchOutcome`] the calling transport (HTTPS or
/// DIDComm) serialises onto the wire.
pub async fn dispatch_inbound<V>(
    ctx: &TrustTaskContext<'_>,
    transport: &(impl TransportHandler + Sync),
    verifier: Option<&V>,
    doc: TrustTask<serde_json::Value>,
) -> DispatchOutcome
where
    V: ProofVerifier + ?Sized,
{
    let error_id = format!("urn:uuid:{}", Uuid::new_v4());
    let typed = match build_dispatcher().dispatch_or_reject(doc, error_id) {
        Ok(t) => t,
        Err(err) => return DispatchOutcome::Rejected(err),
    };
    match typed {
        TypedInbound::Grant(d) => handlers::grant::handle(ctx, transport, verifier, d).await,
        TypedInbound::Revoke(d) => handlers::revoke::handle(ctx, transport, verifier, d).await,
        TypedInbound::ChangeRole(d) => {
            handlers::change_role::handle(ctx, transport, verifier, d).await
        }
        TypedInbound::Show(d) => handlers::show::handle(ctx, transport, verifier, d).await,
        TypedInbound::List(d) => handlers::list::handle(ctx, transport, verifier, d).await,
        TypedInbound::Discovery(d) => {
            handlers::discovery::handle(ctx, transport, verifier, d).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_tasks_rs::{Payload, handlers::InMemoryHandler};

    use crate::server::acl::{self, AclEntry, Role};
    use crate::server::config::StoreConfig;
    use crate::server::domain::DomainScope;
    use crate::server::store::{KS_ACL, Store};

    const SERVICE_DID: &str = "did:web:maintainer.example";
    const ADMIN_DID: &str = "did:web:admin.example";

    #[test]
    fn dispatcher_routes_every_registered_type() {
        let d = build_dispatcher();
        let registered: std::collections::HashSet<&str> = d.registered_uris().into_iter().collect();
        for uri in [
            grant::v0_1::Payload::TYPE_URI,
            revoke::v0_1::Payload::TYPE_URI,
            change_role::v0_1::Payload::TYPE_URI,
            show::v0_1::Payload::TYPE_URI,
            list::v0_1::Payload::TYPE_URI,
            discovery::v0_1::Payload::TYPE_URI,
        ] {
            assert!(
                registered.contains(uri),
                "dispatcher missing route for {uri}"
            );
        }
    }

    /// End-to-end check that the shared [`dispatch_inbound`] entry
    /// point — the function both HTTPS (`POST /api/trust-tasks`) and
    /// DIDComm (`https://trusttasks.org/binding/didcomm/0.1/envelope`)
    /// call — successfully narrows an untyped inbound document,
    /// passes it through the §7.2 pipeline, and produces a typed
    /// response. This is the daemon-parity assertion that CLAUDE.md
    /// asks for: any transport that calls `dispatch_inbound` gets the
    /// same behaviour as any other.
    #[tokio::test]
    async fn dispatch_inbound_runs_full_pipeline_end_to_end() {
        // Stand up a real fjall store + ACL keyspace so the grant
        // handler's read/write hits a real backend (not a mock).
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        };
        std::mem::forget(dir);
        let store = Store::open(&cfg).await.expect("open store");
        let acl_ks = store.keyspace(KS_ACL).expect("acl keyspace");
        acl::store_acl_entry(
            &acl_ks,
            &AclEntry {
                did: ADMIN_DID.into(),
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

        let acl_locks = crate::server::path_locks::PathLocks::new();
        let ctx = TrustTaskContext {
            acl_ks: &acl_ks,
            acl_locks: &acl_locks,
            my_vid: SERVICE_DID,
        };
        let transport = InMemoryHandler::new()
            .with_local(SERVICE_DID.to_string())
            .with_peer(ADMIN_DID.to_string());

        // Construct an untyped `acl/grant/0.1` envelope by way of a
        // JSON value — exactly the shape the HTTPS body extractor and
        // the DIDComm `message.body` produce.
        let body = serde_json::json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": grant::v0_1::Payload::TYPE_URI,
            "issuer": ADMIN_DID,
            "recipient": SERVICE_DID,
            "issuedAt": chrono::Utc::now().to_rfc3339(),
            "payload": {
                "entry": {
                    "subject": "did:web:carol.example",
                    "role": "owner",
                    "ext": {
                        "vnd.affinidi.webvh": {
                            "domains": { "kind": "all" }
                        }
                    }
                }
            }
        });
        let doc: TrustTask<serde_json::Value> = serde_json::from_value(body).expect("parse");

        let outcome = dispatch_inbound::<NoVerifier>(&ctx, &transport, None, doc).await;

        match outcome {
            DispatchOutcome::Handled(resp) => {
                assert_eq!(
                    resp.type_uri.to_string(),
                    format!("{}#response", grant::v0_1::Payload::TYPE_URI)
                );
                assert_eq!(resp.payload["entry"]["subject"], "did:web:carol.example");
            }
            other => panic!("expected Handled, got {other:?}"),
        }

        // Stored entry is reachable via the storage layer — both
        // transports observe the same persistence.
        assert!(
            acl::get_acl_entry(&acl_ks, "did:web:carol.example")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn dispatch_inbound_rejects_unknown_type_uri() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        };
        std::mem::forget(dir);
        let store = Store::open(&cfg).await.expect("open store");
        let acl_ks = store.keyspace(KS_ACL).expect("acl keyspace");
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let ctx = TrustTaskContext {
            acl_ks: &acl_ks,
            acl_locks: &acl_locks,
            my_vid: SERVICE_DID,
        };
        let transport = InMemoryHandler::new()
            .with_local(SERVICE_DID.to_string())
            .with_peer(ADMIN_DID.to_string());

        // Type URI the dispatcher does not have a handler for.
        let body = serde_json::json!({
            "id": "urn:uuid:test",
            "type": "https://trusttasks.org/spec/kyc-handoff/1.0",
            "issuer": ADMIN_DID,
            "recipient": SERVICE_DID,
            "issuedAt": "2026-05-18T10:00:00Z",
            "payload": {}
        });
        let doc: TrustTask<serde_json::Value> = serde_json::from_value(body).expect("parse");
        let outcome = dispatch_inbound::<NoVerifier>(&ctx, &transport, None, doc).await;
        match outcome {
            DispatchOutcome::Rejected(err) => assert_eq!(
                err.payload.code,
                trust_tasks_rs::TrustTaskCode::Standard(
                    trust_tasks_rs::StandardCode::UnsupportedType
                )
            ),
            other => panic!("expected Rejected, got {other:?}"),
        }
    }
}
