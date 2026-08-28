//! Trust Tasks dispatch core — the shared seam between the HTTPS
//! transport (`POST /trust-tasks`), the DIDComm envelope route, and
//! the daemon's in-process wiring.
//!
//! The control plane and daemon both call [`dispatch_inbound`] with a
//! parsed [`TrustTask<serde_json::Value>`], a [`TransportHandler`]
//! configured for whatever transport delivered the document, and a
//! [`ProofPolicy`] selecting how the maintainer handles `proof`
//! members. The function:
//!
//! 1. Narrows the untyped document to one of the [`TypedInbound`]
//!    variants via the shared [`build_dispatcher`].
//! 2. Runs SPEC.md §7.2 items 4–8 against the typed document via
//!    [`trust_tasks_rs::consume_inbound`].
//! 3. Hands the typed document to the matching async handler
//!    (`handlers::*`), passing the framework-resolved [`ResolvedParties`]
//!    so handlers can read transport-derived issuer/recipient
//!    uniformly with in-band values.
//! 4. Returns a [`DispatchOutcome`] the calling transport serialises
//!    onto the wire.
//!
//! ## Why we don't use `HttpsServer::on(...)` directly
//!
//! `trust_tasks_https::HttpsServerBuilder::on` takes a **sync**
//! `Fn(&TrustTask<P>, &RequestContext) -> Result<Resp, RejectReason>`.
//! Every ACL handler we ship needs async fjall I/O, which doesn't
//! compose cleanly with the sync signature without `block_in_place`.
//! Owning our own async dispatch core lets HTTPS and DIDComm share a
//! single set of handlers with no sync→async shim — and lets us tap
//! [`trust_tasks_rs::consume_inbound`] directly for the §7.2
//! pipeline, which is the cleanest async surface upstream offers.

pub mod entry;
pub mod ext;
// Every handler returns `Result<TrustTask<Resp>, ErrorResponse>`, and
// `ErrorResponse` is `trust_tasks_rs::TrustTask<ErrorPayload>` — 752
// bytes, over `result_large_err`'s threshold. Rust 1.98.0 started
// firing the lint here; nothing in this repo changed.
//
// Allowed rather than fixed, because the two fixes on offer are both
// worse. The type is upstream, so we cannot shrink it. Boxing it at our
// boundary would change the signature of every handler and every call
// site in the dispatcher to buy one avoided 752-byte move on a path
// that is already about to do DIDComm or HTTPS I/O — and the error
// still has to be unboxed to be serialised onto the wire.
//
// Scoped to this module on purpose: it says "these handlers return an
// upstream error type", not "this crate does not care about error
// size". Drop the allow if `trust-tasks-rs` ever boxes `ErrorPayload`.
#[allow(clippy::result_large_err)]
pub mod handlers;
pub mod send;
pub mod transport;
pub mod verifier;

pub use transport::{TSP_BINDING_URI, TspTransportHandler};
pub use verifier::TransportBoundVerifier;

use chrono::Utc;
use serde::Serialize;
use trust_tasks_rs::{
    ConsumeChecks, ConsumeOutcome, Dispatcher, ErrorResponse, NoValidator, Payload, PayloadPolicy,
    ProofPolicy, ProofVerifier, ResolvedParties, TransportHandler, TrustTask, consume_inbound,
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
    // Boxed: `AclEntry` carries the widest payload in this enum (scopes,
    // step-up, approve authority, key filter), so an unboxed variant sets the
    // size of every inbound message. See clippy::large_enum_variant.
    Grant(Box<TrustTask<grant::v0_1::Payload>>),
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
        .on::<grant::v0_1::Payload, _>(|d| TypedInbound::Grant(Box::new(d)))
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
/// Thin shim over [`trust_tasks_rs::consume_inbound`]: the framework
/// crate does the §7.2 pipeline, this function adapts the
/// [`ConsumeOutcome`] to the maintainer-side [`DispatchOutcome`] (and
/// re-encodes the typed response as `TrustTask<Value>` so the dispatch
/// layer doesn't have to pin the response payload type in the enum).
///
/// `handler` receives the request **and** the SPEC §4.8.1-resolved
/// parties — handlers read `parties.issuer` when authorising the
/// caller so the same code path serves in-band-issuer producers and
/// transport-derived-issuer producers (JWT-bearer client emits an
/// envelope with no `issuer`; the JWT's `sub` becomes the resolved
/// issuer). The framework no longer mutates the document.
///
/// On rejection the handler builds an [`ErrorResponse`] directly —
/// `permission_denied + details`, extended codes like
/// `acl/revoke:last_authority_protected`, etc — without losing the
/// SPEC.md §8.1 routing.
///
/// `V` is left generic (with `?Sized`) so callers pass either a
/// concrete verifier reference or a trait-object-equivalent.
pub async fn run_pipeline<P, R, V, F, Fut>(
    transport: &(impl TransportHandler + Sync),
    policy: ProofPolicy<'_, V>,
    doc: TrustTask<P>,
    my_vid: &str,
    handler: F,
) -> DispatchOutcome
where
    P: Payload + Serialize + Send + Sync,
    R: Serialize,
    V: ProofVerifier + ?Sized,
    F: FnOnce(TrustTask<P>, ResolvedParties) -> Fut,
    Fut: std::future::Future<Output = Result<TrustTask<R>, ErrorResponse>>,
{
    let now = Utc::now();
    let new_id = || format!("urn:uuid:{}", Uuid::new_v4());

    // SPEC.md §7.2 item 2, decided here rather than at each of the ~28 call
    // sites, because the answer is the same at every one of them and a future
    // change of mind should be one edit, not twenty-eight.
    //
    // `AcceptUnvalidated` is what this shim has always done, now stated rather
    // than implied. Deserializing into `P` already enforced most of item 2: the
    // codegen `Payload` structs carry `#[serde(deny_unknown_fields)]` plus
    // newtypes that reject `minLength` / pattern violations at parse time, which
    // is the same reasoning the workspace `Cargo.toml` gives for leaving the
    // `validate` feature off. What `Validate` adds is the residue a Rust type
    // cannot express — `minProperties`, `minItems` on an optional array,
    // conditional subschemas.
    //
    // Turning it on is a *behaviour* change: it can begin refusing documents a
    // peer sends today. It needs the `validate` feature, a `PayloadValidator`,
    // and its own rollout — not a dependency bump.
    // SPEC.md §7.2 items 4 and 11, a required argument since trust-tasks 0.17
    // (`ConsumeChecks`) rather than a default the framework chose for us.
    //
    // `not_consequential()` is what this shim has always done — 0.9 ran no
    // duplicate-execution record at all — so taking it here changes no
    // behaviour with the dependency bump. It is *not* the right long-term
    // answer for the ACL writes (`acl/grant`, `acl/revoke`,
    // `acl/change-role`), which are consequential by §2: a mediator redelivery
    // of one grant document would be executed twice. Fixing that needs a
    // `ReplayGuard` with storage behind it and a decision about which
    // processes share a VID (the control plane, the server and the daemon all
    // consume), which is its own change rather than a dependency bump.
    let outcome: ConsumeOutcome<R> = consume_inbound(
        transport,
        policy,
        PayloadPolicy::<NoValidator>::AcceptUnvalidated,
        ConsumeChecks::not_consequential(),
        doc,
        my_vid,
        now,
        new_id,
        handler,
    )
    .await;

    match outcome {
        ConsumeOutcome::Handled(typed_resp) => {
            // Re-shape the typed response as a TrustTask<Value> so the
            // dispatch layer can hand it to whichever transport without
            // pinning the response payload type in DispatchOutcome.
            let value = serde_json::to_value(&typed_resp)
                .expect("typed response document serialises (codegened structs)");
            let value_doc: TrustTask<serde_json::Value> = serde_json::from_value(value)
                .expect("TrustTask<Value> from any TrustTask<Serialize> round-trips");
            DispatchOutcome::Handled(value_doc)
        }
        ConsumeOutcome::Rejected(err) => DispatchOutcome::Rejected(err),
        ConsumeOutcome::Suppressed => DispatchOutcome::Suppressed,
        // SPEC.md §7.2 item 11, *Disposition of a duplicate*: not a failure —
        // the task did not fail, it already happened — so this must never fold
        // into `Rejected`. Emit what the first execution produced when the
        // guard retained it, and nothing when it did not (or when that
        // execution is still running).
        //
        // Unreachable while the `ConsumeChecks` above is `not_consequential()`:
        // with no record kept, nothing is ever found to be a duplicate. Written
        // out so that wiring a `ReplayGuard` is one edit there and none here.
        ConsumeOutcome::Duplicate {
            prior_response,
            in_flight,
        } => match prior_response {
            Some(value) => match serde_json::from_value::<TrustTask<serde_json::Value>>(value) {
                Ok(prior) => DispatchOutcome::Handled(prior),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "replay guard held a prior response that is not a Trust Task document; \
                         emitting nothing"
                    );
                    DispatchOutcome::Suppressed
                }
            },
            None => {
                tracing::info!(
                    in_flight,
                    "duplicate document absorbed with no prior response to return"
                );
                DispatchOutcome::Suppressed
            }
        },
    }
}

/// The framework's error-document Type URI — the one `TrustTask::reject_with`
/// stamps on every *routed* rejection this service emits.
///
/// Named here because `trust-tasks-rs` keeps `trust_task_error_type_uri()`
/// `pub(crate)`, so the handful of **unrouted** paths — where the body never
/// parsed into a Trust Task and there is no request document to reject from —
/// have to write the value out. They wrote `0.1` while every routed reject went
/// out as `0.3` (the framework has emitted `0.3` since its own 0.3 release, for
/// the §8.2 `inResponseTo` member that `0.2`'s `additionalProperties: false`
/// payload schema cannot admit). One service emitting two versions, split only
/// by whether the request happened to parse, is a trap for exactly the consumer
/// that pins one of them — and that consumer existed: a client enumerating
/// `0.1`/`0.2` read every `0.3` rejection as a *success*.
///
/// Now `0.5`, tracking `trust-tasks-rs` 0.9. The framework moved twice more for
/// the same reason it moved to `0.3`: a new standard code that the older payload
/// schema's `code` enum does not list and whose extended-code pattern does not
/// match, so a document carrying it would not validate as the older version.
/// `0.4` carries `idConflict`, `0.5` carries `cancelled` (SPEC §8.3). Per SPEC
/// §5.2 forward-minor compatibility a consumer pinned to `0.3` SHOULD accept
/// these.
///
/// One definition for the whole workspace, pinned by
/// `unrouted_and_routed_errors_agree_on_the_type_uri` below, which compares it
/// against a real `reject_with`. A framework bump fails that test rather than
/// re-splitting the service in two — which is exactly how this bump was caught.
pub fn framework_error_type_uri() -> trust_tasks_rs::TypeUri {
    "https://trusttasks.org/spec/trust-task-error/0.5"
        .parse()
        .expect("framework error Type URI parses")
}

/// Build a framework error document addressed to the request's
/// `issuer`, carrying a custom `ErrorPayload` — used by handlers that
/// need to emit spec-defined error shapes that don't fit the
/// framework's [`trust_tasks_rs::RejectReason`] variants (e.g.
/// `permission_denied` with structured `details`, or extension codes
/// like `acl/revoke:last_authority_protected`).
pub(crate) fn reject_with<P>(
    request: &TrustTask<P>,
    payload: trust_tasks_rs::ErrorPayload,
) -> ErrorResponse {
    let id = format!("urn:uuid:{}", Uuid::new_v4());
    request.reject_with(id, payload)
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
/// `policy` selects how the maintainer handles inbound `proof`
/// members. The control plane maps `trust_tasks.enforce_proofs` to:
/// * `true` + verifier configured → [`ProofPolicy::Verify`]
/// * `false` (default) → [`ProofPolicy::RejectIfPresent`] (a
///   proof-bearing document is rejected `malformed_request` per the
///   framework's [`trust_tasks_rs::PROOF_NOT_ACCEPTED_BY_POLICY`]
///   rule — silently dropping a producer-supplied proof would mislead
///   the producer about the integrity guarantees of the exchange).
///
/// Returns a [`DispatchOutcome`] the calling transport (HTTPS or
/// DIDComm) serialises onto the wire.
pub async fn dispatch_inbound<V>(
    ctx: &TrustTaskContext<'_>,
    transport: &(impl TransportHandler + Sync),
    policy: ProofPolicy<'_, V>,
    doc: TrustTask<serde_json::Value>,
) -> DispatchOutcome
where
    V: ProofVerifier + ?Sized,
{
    // Operator-actionable diagnostic for the `RejectIfPresent` +
    // proof-present case. The framework's wire message is
    // deliberately sanitised (it would otherwise let an unauth probe
    // enumerate which deployments in a fleet lack verifier coverage),
    // so the verbose form — naming the `enforce_proofs` knob — moves
    // into the operator's log stream.
    if matches!(policy, ProofPolicy::RejectIfPresent) && doc.proof.is_some() {
        tracing::warn!(
            type_uri = %doc.type_uri,
            "inbound trust-task carries a `proof` member but this maintainer has not opted \
             into proof verification (`trust_tasks.enforce_proofs = false`). Rejecting with \
             malformed_request. Flip `enforce_proofs = true` to enable strict-mode verification."
        );
    }

    let error_id = format!("urn:uuid:{}", Uuid::new_v4());
    let typed = match build_dispatcher().dispatch_or_reject(doc, error_id) {
        Ok(t) => t,
        Err(err) => return DispatchOutcome::Rejected(err),
    };
    match typed {
        TypedInbound::Grant(d) => handlers::grant::handle(ctx, transport, policy, *d).await,
        TypedInbound::Revoke(d) => handlers::revoke::handle(ctx, transport, policy, d).await,
        TypedInbound::ChangeRole(d) => {
            handlers::change_role::handle(ctx, transport, policy, d).await
        }
        TypedInbound::Show(d) => handlers::show::handle(ctx, transport, policy, d).await,
        TypedInbound::List(d) => handlers::list::handle(ctx, transport, policy, d).await,
        TypedInbound::Discovery(d) => handlers::discovery::handle(ctx, transport, policy, d).await,
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

    /// The unrouted body-parse errors must claim the same document type as a
    /// routed rejection. They cannot ask the framework —
    /// `trust_task_error_type_uri()` is `pub(crate)` there — so
    /// [`framework_error_type_uri`] names the version, and this compares it
    /// against what `reject_with` actually stamps.
    ///
    /// A framework bump fails here instead of splitting the service into two
    /// dialects, which is how the unrouted paths came to say `0.1` while every
    /// routed reject said `0.3`.
    #[test]
    fn unrouted_and_routed_errors_agree_on_the_type_uri() {
        let request: TrustTask<serde_json::Value> = TrustTask::new(
            "urn:uuid:probe",
            list::v0_1::Payload::TYPE_URI
                .parse()
                .expect("acl/list Type URI parses"),
            serde_json::json!({}),
        );
        let routed = request.reject_with(
            "urn:uuid:routed",
            trust_tasks_rs::RejectReason::InternalError {
                reason: "probe".into(),
            },
        );
        assert_eq!(
            framework_error_type_uri(),
            routed.type_uri,
            "the unrouted error paths name a different document type than the \
             framework stamps on a routed rejection"
        );
    }

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
        // the DIDComm `message.body` produce. `acl/grant/0.1` is a
        // REQUIRED spec, so the framework's IS_PROOF_REQUIRED check
        // refuses proofless documents regardless of policy; we
        // attach a stub proof so the pipeline reaches the handler
        // under `AcceptUnverified`.
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
            },
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": format!("{ADMIN_DID}#key-1"),
                "created": chrono::Utc::now().to_rfc3339(),
                "proofPurpose": "assertionMethod",
                "proofValue": "z-stub"
            }
        });
        let doc: TrustTask<serde_json::Value> = serde_json::from_value(body).expect("parse");

        let outcome = dispatch_inbound::<trust_tasks_proof::affinidi::Verifier>(
            &ctx,
            &transport,
            ProofPolicy::AcceptUnverified,
            doc,
        )
        .await;

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

    /// Regression for the passkey 401 (`proofInvalid` / "no in-band issuer
    /// to bind it to"). Reproduces the delegation shape end-to-end through
    /// the real §7.2 pipeline with proof verification ENABLED:
    ///
    /// * the proof is signed by an **ephemeral `did:key`** (the session key)
    ///   that is *not* the caller's ACL identity;
    /// * the envelope carries **no in-band `issuer`** (exactly what the UI
    ///   sends on the passkey path);
    /// * the transport authenticates the caller as `ADMIN_DID` (the JWT
    ///   `sub`, an ACL admin).
    ///
    /// `TransportBoundVerifier` verifies the signature without demanding an
    /// in-band issuer, `resolve_parties` transport-fills `issuer = ADMIN_DID`,
    /// and the grant is authorised and applied. The stock `affinidi::Verifier`
    /// would have rejected this with `proof_invalid` before the handler ran.
    #[tokio::test]
    async fn dispatch_inbound_accepts_session_key_proof_without_in_band_issuer() {
        use affinidi_data_integrity::{DataIntegrityProof, DidKeyResolver, SignOptions};
        use affinidi_secrets_resolver::secrets::Secret;
        use std::sync::Arc;

        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        };
        std::mem::forget(dir);
        let store = Store::open(&cfg).await.expect("open store");
        let acl_ks = store.keyspace(KS_ACL).expect("acl keyspace");
        // ADMIN_DID is the caller's real (ACL) identity — the JWT subject the
        // transport authenticates, NOT the key that signs the proof.
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

        // Ephemeral "session" keypair — a did:key distinct from ADMIN_DID.
        let secret = Secret::generate_ed25519(None, Some(&[9u8; 32]));
        let pk_mb = secret.get_public_keymultibase().unwrap();
        let mut signer = secret.clone();
        signer.id = format!("did:key:{pk_mb}#{pk_mb}");

        // Envelope WITHOUT an in-band issuer; recipient bound to the service.
        let body = serde_json::json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": grant::v0_1::Payload::TYPE_URI,
            "recipient": SERVICE_DID,
            "issuedAt": chrono::Utc::now().to_rfc3339(),
            "payload": {
                "entry": {
                    "subject": "did:web:dave.example",
                    "role": "owner",
                    "ext": { "vnd.affinidi.webvh": { "domains": { "kind": "all" } } }
                }
            }
        });
        let doc_noproof: TrustTask<serde_json::Value> =
            serde_json::from_value(body).expect("parse");
        let signing_value = serde_json::to_value(&doc_noproof).unwrap();
        let di_proof = DataIntegrityProof::sign(&signing_value, &signer, SignOptions::new())
            .await
            .expect("sign");
        let mut full = signing_value;
        full.as_object_mut().unwrap().insert(
            "proof".to_string(),
            serde_json::to_value(&di_proof).unwrap(),
        );
        let doc: TrustTask<serde_json::Value> = serde_json::from_value(full).expect("proofed");
        assert!(doc.issuer.is_none(), "fixture must omit in-band issuer");

        // Transport authenticates the caller as ADMIN_DID (the JWT sub).
        let transport = InMemoryHandler::new()
            .with_local(SERVICE_DID.to_string())
            .with_peer(ADMIN_DID.to_string());
        let verifier = super::TransportBoundVerifier::with_resolver(Arc::new(DidKeyResolver));

        let outcome = dispatch_inbound(&ctx, &transport, ProofPolicy::Verify(&verifier), doc).await;

        match outcome {
            DispatchOutcome::Handled(resp) => {
                assert_eq!(resp.payload["entry"]["subject"], "did:web:dave.example");
            }
            other => panic!("expected Handled (grant applied), got {other:?}"),
        }
        assert!(
            acl::get_acl_entry(&acl_ks, "did:web:dave.example")
                .await
                .unwrap()
                .is_some(),
            "grant must be persisted — authz resolved issuer from the transport"
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
        let outcome = dispatch_inbound::<trust_tasks_proof::affinidi::Verifier>(
            &ctx,
            &transport,
            ProofPolicy::RejectIfPresent,
            doc,
        )
        .await;
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
