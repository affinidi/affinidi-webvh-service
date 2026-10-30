//! `acl/grant/0.2` handler — an admin adds a subject to the ACL with a
//! named role and an explicitly stated authority (AclEntry 0.2).
//!
//! Spec contract (`specs/acl/grant/0.2/spec.md`, consumer items):
//!
//! 1. An unrecognised role is `roleNotRecognized`, never a default role.
//! 2. An `act` or `approve` scope this maintainer cannot hold is
//!    `invalidActScope`; listed capabilities are `unknownCapability` (it
//!    recognises none). Nothing is accepted by dropping it — see
//!    [`SpecAclEntry::into_local`] for every member it refuses.
//! 3. The granter is evaluated against its **stored** entry: only an
//!    `Admin` may grant, and an `Admin` holds every axis this maintainer can
//!    express, so a grant it may make never exceeds it.
//! 4. A subject that is the granter itself is `permissionDenied`.
//! 5. A subject held under a different role is `permissionDenied`
//!    pointing at `acl/change-role/0.2`. Under the same role the grant is
//!    an idempotent re-assertion, or a widening; it never narrows — a
//!    narrower `act` is `permissionDenied` pointing at `acl/revoke/0.2`.
//! 6. The maintainer sets `createdAt`/`createdBy` itself and returns the
//!    realized entry.

use serde_json::json;
use trust_tasks_rs::{
    ErrorPayload, ErrorResponse, ProofPolicy, ProofVerifier, ResolvedParties, StandardCode,
    TransportHandler, TrustTask,
};

use crate::server::acl::{self, AclEntry, Role};
use crate::server::auth::session::now_epoch;
use crate::server::error::AppError;
use crate::server::trust_tasks::entry::{EntryRefusal, SpecAclEntry, act_covers, act_of};
use crate::server::trust_tasks::{DispatchOutcome, TrustTaskContext, reject_with, run_pipeline};
use crate::tasks::acl::grant::v0_2 as grant;

/// Run the framework pipeline + business logic for an inbound
/// `acl/grant/0.2` request.
pub async fn handle<V>(
    ctx: &TrustTaskContext<'_>,
    transport: &(impl TransportHandler + Sync),
    policy: ProofPolicy<'_, V>,
    doc: TrustTask<grant::Payload>,
) -> DispatchOutcome
where
    V: ProofVerifier + ?Sized,
{
    let acl_ks = ctx.acl_ks.clone();
    let acl_locks = ctx.acl_locks.clone();
    let signing_oracle = ctx.signing_oracle;
    run_pipeline(
        transport,
        policy,
        doc,
        ctx.my_vid,
        move |doc, parties| async move {
            // Serialise every ACL mutation through one global lock so
            // the read-existing → check-policy → store window is
            // race-free. See `ACL_WRITE_LOCK_KEY` doc-comment for
            // why per-subject locking is insufficient.
            let _guard = acl_locks
                .guard(crate::server::trust_tasks::ACL_WRITE_LOCK_KEY)
                .await;
            handle_inner(&acl_ks, doc, &parties, signing_oracle).await
        },
    )
    .await
}

async fn handle_inner(
    acl_ks: &crate::server::store::KeyspaceHandle,
    doc: TrustTask<grant::Payload>,
    parties: &ResolvedParties,
    signing_oracle: bool,
) -> Result<TrustTask<grant::Response>, ErrorResponse> {
    // ─── 1. Authorise the caller against its stored entry. ─────────
    let caller = parties.issuer.as_deref().ok_or_else(|| {
        reject_with(
            &doc,
            ErrorPayload::new(StandardCode::PermissionDenied)
                .with_message("inbound document has no in-band or transport-derived issuer"),
        )
    })?;
    match acl::check_acl(acl_ks, caller).await {
        Ok(Role::Admin) => {}
        Ok(_) => {
            return Err(reject_with(
                &doc,
                ErrorPayload::new(StandardCode::PermissionDenied)
                    .with_message("only Admin callers may emit acl/grant/0.2"),
            ));
        }
        Err(e) if acl::is_acl_refusal(&e) => {
            return Err(reject_with(
                &doc,
                ErrorPayload::new(StandardCode::PermissionDenied)
                    .with_message("caller is not present in the maintainer's ACL"),
            ));
        }
        Err(e) => return Err(internal(&doc, e)),
    }

    // ─── 2. Translate the proposed entry to our local shape. ──────
    let proposed = SpecAclEntry::from_spec(&doc.payload.entry)
        .and_then(|e| e.into_local(0, signing_oracle))
        .map_err(|refusal| reject_with(&doc, refusal_payload(refusal)))?;

    // The subject must be a DID. Resolving an agent name to its DID is the
    // client's job (the console does it through `agent-name/resolve`); a
    // name stored verbatim would be an ACL entry no signer can ever match.
    if proposed
        .did
        .parse::<affinidi_tdk::did_common::DID>()
        .is_err()
    {
        return Err(reject_with(
            &doc,
            ErrorPayload::new(StandardCode::MalformedRequest)
                .with_message("the entry's subject is not a DID; resolve an agent name first"),
        ));
    }

    // ─── 3. No subject may grant to itself. ───────────────────────
    if crate::scid::same_reference(caller, &proposed.did) {
        return Err(reject_with(
            &doc,
            ErrorPayload::new(StandardCode::PermissionDenied)
                .with_message("a granter may not grant to itself"),
        ));
    }

    // ─── 4. Apply the spec's idempotent-insert / role-change rules. ─
    let existing = acl::get_acl_entry(acl_ks, &proposed.did)
        .await
        .map_err(|e| internal(&doc, e))?;

    let created_by = existing.is_none().then(|| caller.to_string());
    let realized = match existing {
        Some(current) if current.role == proposed.role => {
            // An idempotent re-assertion or a widening. The non-authority
            // members (label, quota, default domain) take the producer's
            // values; `created_at` stays the maintainer's insertion time.
            let (old_act, new_act) = (act_of(&current), act_of(&proposed));
            if !act_covers(&new_act, &old_act) {
                return Err(reject_with(
                    &doc,
                    ErrorPayload::new(StandardCode::PermissionDenied)
                        .with_message(
                            "a grant may not narrow an existing entry's act scope; narrow it \
                             with acl/revoke/0.2",
                        )
                        .with_details(json!({
                            "reason": "narrowing_requires_revoke",
                            "currentAct": serde_json::to_value(&old_act)
                                .expect("AuthorityScope serialises"),
                            "suggestedTask": "https://trusttasks.org/spec/acl/revoke/0.2"
                        })),
                ));
            }
            let merged = AclEntry {
                did: current.did.clone(),
                role: current.role.clone(),
                label: proposed.label.clone(),
                created_at: current.created_at,
                max_total_size: proposed.max_total_size,
                max_did_count: proposed.max_did_count,
                domains: proposed.domains.clone(),
            };
            if merged.label != current.label
                || merged.max_total_size != current.max_total_size
                || merged.max_did_count != current.max_did_count
                || merged.domains != current.domains
            {
                acl::store_acl_entry(acl_ks, &merged)
                    .await
                    .map_err(|e| internal(&doc, e))?;
            }
            merged
        }
        Some(current) => {
            return Err(reject_with(
                &doc,
                ErrorPayload::new(StandardCode::PermissionDenied)
                    .with_message(
                        "subject already exists with a different role; role changes must use \
                         acl/change-role/0.2",
                    )
                    .with_details(json!({
                        "reason": "role_change_required",
                        "existingRole": current.role.to_string(),
                        "proposedRole": proposed.role.to_string(),
                        "suggestedTask": "https://trusttasks.org/spec/acl/change-role/0.2"
                    })),
            ));
        }
        None => {
            let mut entry = proposed;
            entry.created_at = now_epoch();
            acl::store_acl_entry(acl_ks, &entry)
                .await
                .map_err(|e| internal(&doc, e))?;
            entry
        }
    };

    // ─── 5. Build the response document. ──────────────────────────
    let mut neutral = SpecAclEntry::from_local(&realized, signing_oracle);
    neutral.created_by = created_by;
    // The generated payload types are `#[non_exhaustive]`: built through the
    // generated builder, whose `try_into` can only fail on a field left unset.
    let resp_payload: grant::Response = grant::Response::builder()
        .entry(neutral.into_spec::<grant::AclEntry>())
        .try_into()
        .expect("grant response has every required field set");
    let resp_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    Ok(doc.respond_with(resp_id, resp_payload))
}

/// Render an [`EntryRefusal`] with the code `acl/grant/0.2` declares for it.
fn refusal_payload(refusal: EntryRefusal) -> ErrorPayload {
    let message = refusal.to_string();
    match refusal {
        EntryRefusal::RoleNotRecognized(role) => {
            ErrorPayload::from(grant::error_codes::ROLE_NOT_RECOGNIZED)
                .with_message(message)
                .with_details(json!({
                    "offendingRole": role,
                    "knownRoles": ["admin", "owner", "service", "metricsReader"],
                }))
        }
        EntryRefusal::InvalidActScope { member, .. } => {
            ErrorPayload::from(grant::error_codes::INVALID_ACT_SCOPE)
                .with_message(message)
                .with_details(json!({ "member": member }))
        }
        EntryRefusal::UnknownCapability(caps) => {
            ErrorPayload::from(grant::error_codes::UNKNOWN_CAPABILITY)
                .with_message(message)
                .with_details(json!({ "capabilities": caps }))
        }
        EntryRefusal::NotSupported { member, .. } => ErrorPayload::new(StandardCode::TaskFailed)
            .with_retryable(false)
            .with_message(message)
            .with_details(json!({ "reason": "notSupportedByMaintainer", "member": member })),
        EntryRefusal::Malformed(_) => {
            ErrorPayload::new(StandardCode::MalformedRequest).with_message(message)
        }
    }
}

fn internal<P>(doc: &TrustTask<P>, err: AppError) -> ErrorResponse {
    // A store or internal failure says nothing about the request: the wire
    // gets `unavailable` with a retry time when the store is over capacity,
    // else a bare `internalError`; the detail stays in the operator log.
    tracing::error!(error = %err, "acl/grant internal failure");
    reject_with(doc, err.failure_reject_reason().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_tasks_rs::{Payload, ProofVerifier, VerificationError, handlers::InMemoryHandler};

    use crate::server::config::StoreConfig;
    use crate::server::domain::DomainScope;
    use crate::server::store::{KS_ACL, Store};
    use crate::server::trust_tasks::TrustTaskContext;
    use crate::server::trust_tasks::ext::WEBVH_EXT_KEY;

    /// Type-anchor only — `RejectIfPresent` doesn't carry a verifier
    /// reference, but [`ProofPolicy`] is generic in `V` and needs *some*
    /// concrete type to fix inference. `verify` panics because the
    /// pipeline never reaches a verifier under this policy.
    struct PanickingVerifier;

    #[async_trait::async_trait]
    impl ProofVerifier for PanickingVerifier {
        async fn verify<P>(&self, _doc: &TrustTask<P>) -> Result<(), VerificationError>
        where
            P: serde::Serialize + Send + Sync,
        {
            panic!("verifier called under RejectIfPresent policy");
        }
    }

    /// Default test policy: `AcceptUnverified`. Since the upstream
    /// 0.1.1 framework enforces `P::IS_PROOF_REQUIRED` authoritatively
    /// (`acl/grant` / `acl/revoke` / `acl/change-role` mandate a
    /// proof regardless of consumer policy), every REQUIRED-spec test
    /// request carries a stub proof via [`add_stub_proof`]. Pairing
    /// that with `AcceptUnverified` lets the framework pipeline reach
    /// the handler's business logic without a real verifier
    /// configured. Tests that *do* want to exercise verification build
    /// a `ProofPolicy::Verify(...)` directly with one of the stub
    /// verifiers defined below.
    fn no_verifier() -> ProofPolicy<'static, PanickingVerifier> {
        ProofPolicy::AcceptUnverified
    }

    const SERVICE_DID: &str = "did:web:maintainer.example";
    const ADMIN_DID: &str = "did:web:admin.example";
    const ALICE_DID: &str = "did:web:alice.example";

    /// Test harness wiring. Returns a `Store` + `KeyspaceHandle` for the
    /// ACL keyspace, with `ADMIN_DID` pre-seeded as Admin so handlers
    /// pass the authorisation check.
    async fn harness() -> (Store, crate::server::store::KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        };
        // Hold the tempdir for the test's lifetime via leak — fjall keeps
        // the dir open and dropping it under the open keyspace is racy.
        std::mem::forget(dir);
        let store = Store::open(&cfg).await.expect("open fjall");
        let acl_ks = store.keyspace(KS_ACL).expect("acl keyspace");

        acl::store_acl_entry(
            &acl_ks,
            &AclEntry {
                did: ADMIN_DID.into(),
                role: Role::Admin,
                label: Some("test admin".into()),
                created_at: 1_700_000_000,
                max_total_size: None,
                max_did_count: None,
                domains: DomainScope::All,
            },
        )
        .await
        .unwrap();

        (store, acl_ks)
    }

    /// Build a typed `acl/grant/0.2` request document for `subject` at
    /// `role`, acting on every domain, the issuer pinned to `issuer_did`, and
    /// recipient pinned to `SERVICE_DID`.
    fn grant_request(issuer_did: &str, subject: &str, role: &str) -> TrustTask<grant::Payload> {
        grant_request_with(
            issuer_did,
            serde_json::json!({
                "subject": subject,
                "role": role,
                "act": { "scope": "all" },
                "keys": { "scope": "none" },
                "capabilities": { "scope": "ceiling" },
                "label": "test entry"
            }),
        )
    }

    /// Build a typed `acl/grant/0.2` request carrying `entry` verbatim.
    fn grant_request_with(issuer_did: &str, entry: serde_json::Value) -> TrustTask<grant::Payload> {
        let entry: grant::AclEntry =
            serde_json::from_value(entry).expect("test ACL entry is an AclEntry 0.2");
        let payload: grant::Payload = grant::Payload::builder()
            .entry(entry)
            .reason(Some(
                "integration test grant"
                    .parse::<grant::PayloadReason>()
                    .expect("reason"),
            ))
            .try_into()
            .expect("test grant payload is well formed");
        let mut doc = TrustTask::for_payload(format!("urn:uuid:{}", uuid::Uuid::new_v4()), payload);
        doc.issuer = Some(issuer_did.into());
        doc.recipient = Some(SERVICE_DID.into());
        doc.issued_at = Some(chrono::Utc::now());
        // `acl/grant/0.2` is REQUIRED: framework rejects proofless
        // documents with `proof_required` regardless of policy. Every
        // request carries a stub proof so the pipeline reaches the handler
        // under `ProofPolicy::AcceptUnverified`.
        add_stub_proof(&mut doc);
        doc
    }

    fn owner_entry(contexts: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "subject": ALICE_DID,
            "role": "owner",
            "act": { "scope": "contexts", "contexts": contexts },
            "keys": { "scope": "none" },
            "capabilities": { "scope": "ceiling" },
            "label": "test entry"
        })
    }

    fn rejected(outcome: DispatchOutcome) -> ErrorResponse {
        match outcome {
            DispatchOutcome::Rejected(e) => e,
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    fn ctx<'a>(
        acl_ks: &'a crate::server::store::KeyspaceHandle,
        acl_locks: &'a crate::server::path_locks::PathLocks,
    ) -> TrustTaskContext<'a> {
        TrustTaskContext {
            acl_ks,
            acl_locks,
            my_vid: SERVICE_DID,
            signing_oracle: false,
        }
    }

    fn transport(peer: &str) -> InMemoryHandler {
        InMemoryHandler::new()
            .with_local(SERVICE_DID.to_string())
            .with_peer(peer.to_string())
    }

    /// Stub verifier that accepts every proof. Used to exercise the
    /// `enforce_proofs = true` happy-path branch in `run_pipeline`.
    struct AlwaysOkVerifier;
    #[async_trait::async_trait]
    impl ProofVerifier for AlwaysOkVerifier {
        async fn verify<P>(&self, _doc: &TrustTask<P>) -> Result<(), VerificationError>
        where
            P: serde::Serialize + Send + Sync,
        {
            Ok(())
        }
    }

    /// Stub verifier that rejects every proof with `SignatureInvalid`.
    /// Used to exercise the `proof_invalid` rejection branch.
    struct AlwaysErrVerifier;
    #[async_trait::async_trait]
    impl ProofVerifier for AlwaysErrVerifier {
        async fn verify<P>(&self, _doc: &TrustTask<P>) -> Result<(), VerificationError>
        where
            P: serde::Serialize + Send + Sync,
        {
            Err(VerificationError::SignatureInvalid)
        }
    }

    /// Add a minimal stub `proof` member to a grant request so the
    /// pipeline takes the verifier path. The proof shape isn't
    /// validated by the stub verifiers — we just need it present.
    fn add_stub_proof(doc: &mut TrustTask<grant::Payload>) {
        doc.proof = Some(trust_tasks_rs::Proof {
            proof_type: "DataIntegrityProof".into(),
            cryptosuite: "eddsa-rdfc-2022".into(),
            verification_method: "did:web:admin.example#key-1".into(),
            created: chrono::Utc::now(),
            proof_purpose: "authentication".into(),
            proof_value: "z-stub".into(),
            extra: Default::default(),
        });
    }

    #[tokio::test]
    async fn a_subject_that_is_not_a_did_is_refused() {
        let (_store, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let ctx = ctx(&acl_ks, &acl_locks);
        let transport = transport(ADMIN_DID);
        let doc = grant_request(ADMIN_DID, "alice@example.com", "owner");

        let outcome = handle(&ctx, &transport, no_verifier(), doc).await;

        match outcome {
            DispatchOutcome::Rejected(e) => {
                assert!(serde_json::to_string(&e).unwrap().contains("not a DID"));
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fresh_grant_inserts_and_returns_realized_entry() {
        let (_store, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let ctx = ctx(&acl_ks, &acl_locks);
        let transport = transport(ADMIN_DID);
        let doc = grant_request(ADMIN_DID, ALICE_DID, "owner");

        let outcome = handle(&ctx, &transport, no_verifier(), doc).await;

        let resp = match outcome {
            DispatchOutcome::Handled(d) => d,
            other => panic!("expected Handled, got {other:?}"),
        };
        assert_eq!(
            resp.type_uri.to_string(),
            format!("{}#response", grant::Payload::TYPE_URI)
        );

        let entry_value = resp.payload.get("entry").expect("response has entry");
        assert_eq!(entry_value["subject"], ALICE_DID);
        assert_eq!(entry_value["role"], "owner");
        // Maintainer-filled fields: createdAt set to now, createdBy the granter.
        assert!(entry_value.get("createdAt").is_some());
        assert_eq!(entry_value["createdBy"], ADMIN_DID);
        // Authority stated explicitly.
        assert_eq!(entry_value["act"], serde_json::json!({ "scope": "all" }));
        assert_eq!(entry_value["keys"], serde_json::json!({ "scope": "none" }));
        assert_eq!(
            entry_value["capabilities"],
            serde_json::json!({ "scope": "ceiling" })
        );

        let stored = acl::get_acl_entry(&acl_ks, ALICE_DID).await.unwrap();
        assert!(stored.is_some());
        assert_eq!(stored.unwrap().role, Role::Owner);
    }

    #[tokio::test]
    async fn idempotent_regrant_returns_existing_entry() {
        let (_store, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let ctx = ctx(&acl_ks, &acl_locks);
        let transport = transport(ADMIN_DID);

        // First grant lands.
        let _ = handle(
            &ctx,
            &transport,
            no_verifier(),
            grant_request(ADMIN_DID, ALICE_DID, "owner"),
        )
        .await;
        let first = acl::get_acl_entry(&acl_ks, ALICE_DID)
            .await
            .unwrap()
            .unwrap();

        // Re-emit an identical grant; the entry must not be mutated and
        // the response carries the existing entry verbatim.
        let outcome = handle(
            &ctx,
            &transport,
            no_verifier(),
            grant_request(ADMIN_DID, ALICE_DID, "owner"),
        )
        .await;
        assert!(matches!(outcome, DispatchOutcome::Handled(_)));
        let second = acl::get_acl_entry(&acl_ks, ALICE_DID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.created_at, first.created_at);
    }

    #[tokio::test]
    async fn role_change_attempt_returns_permission_denied_with_details() {
        let (_store, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let ctx = ctx(&acl_ks, &acl_locks);
        let transport = transport(ADMIN_DID);

        // Seed Alice as owner.
        let _ = handle(
            &ctx,
            &transport,
            no_verifier(),
            grant_request(ADMIN_DID, ALICE_DID, "owner"),
        )
        .await;

        // Re-grant Alice as admin — must reject with permission_denied
        // pointing to acl/change-role and structured details.
        let outcome = handle(
            &ctx,
            &transport,
            no_verifier(),
            grant_request(ADMIN_DID, ALICE_DID, "admin"),
        )
        .await;
        let err = match outcome {
            DispatchOutcome::Rejected(e) => e,
            other => panic!("expected Rejected, got {other:?}"),
        };
        assert_eq!(
            err.payload.code,
            trust_tasks_rs::TrustTaskCode::Standard(StandardCode::PermissionDenied)
        );
        let details = err
            .payload
            .details
            .expect("details on role-change rejection");
        assert_eq!(details["reason"], "role_change_required");
        assert_eq!(details["existingRole"], "owner");
        assert_eq!(details["proposedRole"], "admin");
        assert_eq!(
            details["suggestedTask"],
            "https://trusttasks.org/spec/acl/change-role/0.2"
        );
    }

    #[tokio::test]
    async fn non_admin_caller_rejected() {
        let (_store, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let ctx = ctx(&acl_ks, &acl_locks);

        // Seed Alice as owner.
        acl::store_acl_entry(
            &acl_ks,
            &AclEntry {
                did: ALICE_DID.into(),
                role: Role::Owner,
                label: None,
                created_at: 1_700_000_000,
                max_total_size: None,
                max_did_count: None,
                domains: DomainScope::All,
            },
        )
        .await
        .unwrap();

        // Alice (an Owner, not Admin) attempts to grant Bob admin.
        let transport = transport(ALICE_DID);
        let outcome = handle(
            &ctx,
            &transport,
            no_verifier(),
            grant_request(ALICE_DID, "did:web:bob.example", "admin"),
        )
        .await;
        let err = match outcome {
            DispatchOutcome::Rejected(e) => e,
            other => panic!("expected Rejected, got {other:?}"),
        };
        assert_eq!(
            err.payload.code,
            trust_tasks_rs::TrustTaskCode::Standard(StandardCode::PermissionDenied)
        );
        // Bob must not have landed in the ACL.
        assert!(
            acl::get_acl_entry(&acl_ks, "did:web:bob.example")
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Re-grant with the same role, a wider act scope and changed
    /// `label` / quota / default domain persists the producer's view: a
    /// grant may re-assert or widen an entry.
    #[tokio::test]
    async fn same_role_regrant_that_widens_persists_updates() {
        let (_store, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let ctx = ctx(&acl_ks, &acl_locks);
        let transport = transport(ADMIN_DID);

        let first = handle(
            &ctx,
            &transport,
            no_verifier(),
            grant_request_with(ADMIN_DID, owner_entry(&["alpha.example"])),
        )
        .await;
        assert!(matches!(first, DispatchOutcome::Handled(_)), "{first:?}");
        let before = acl::get_acl_entry(&acl_ks, ALICE_DID)
            .await
            .unwrap()
            .unwrap();

        let mut wider = owner_entry(&["alpha.example", "beta.example"]);
        wider["label"] = serde_json::json!("Alice — updated");
        wider["ext"] = serde_json::json!({
            WEBVH_EXT_KEY: { "quota": { "maxDidCount": 25 }, "defaultDomain": "beta.example" }
        });
        let resp = match handle(
            &ctx,
            &transport,
            no_verifier(),
            grant_request_with(ADMIN_DID, wider),
        )
        .await
        {
            DispatchOutcome::Handled(d) => d,
            other => panic!("expected Handled, got {other:?}"),
        };
        assert_eq!(resp.payload["entry"]["label"], "Alice — updated");
        assert_eq!(
            resp.payload["entry"]["act"],
            serde_json::json!({ "scope": "contexts", "contexts": ["alpha.example", "beta.example"] })
        );
        assert_eq!(
            resp.payload["entry"]["ext"][WEBVH_EXT_KEY]["defaultDomain"],
            "beta.example"
        );

        let after = acl::get_acl_entry(&acl_ks, ALICE_DID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.created_at, before.created_at);
        assert_eq!(after.label, Some("Alice — updated".into()));
        assert_eq!(after.max_did_count, Some(25));
        assert_eq!(
            after.domains,
            DomainScope::AllowedWithDefault {
                domains: vec!["alpha.example".into(), "beta.example".into()],
                default: "beta.example".into(),
            }
        );
    }

    /// A grant never narrows: dropping a domain is `acl/revoke/0.2`'s job.
    #[tokio::test]
    async fn same_role_regrant_that_narrows_is_refused() {
        let (_store, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let ctx = ctx(&acl_ks, &acl_locks);
        let transport = transport(ADMIN_DID);
        let _ = handle(
            &ctx,
            &transport,
            no_verifier(),
            grant_request_with(ADMIN_DID, owner_entry(&["alpha.example", "beta.example"])),
        )
        .await;

        let err = rejected(
            handle(
                &ctx,
                &transport,
                no_verifier(),
                grant_request_with(ADMIN_DID, owner_entry(&["alpha.example"])),
            )
            .await,
        );
        assert_eq!(
            err.payload.code,
            trust_tasks_rs::TrustTaskCode::Standard(StandardCode::PermissionDenied)
        );
        assert_eq!(
            err.payload.details.unwrap()["suggestedTask"],
            "https://trusttasks.org/spec/acl/revoke/0.2"
        );
        let after = acl::get_acl_entry(&acl_ks, ALICE_DID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            after.domains,
            DomainScope::Allowed {
                domains: vec!["alpha.example".into(), "beta.example".into()]
            }
        );
    }

    /// Two concurrent `acl/grant` requests targeting the same fresh
    /// subject must serialise — exactly one stores the entry, the
    /// other observes it via the idempotent branch. Without the
    /// `acl_locks` guard, both observe `existing == None` and both
    /// `store_acl_entry`, racing on insertion. Pinning this catches
    /// a regression where the lock acquisition is dropped from
    /// `handle`.
    #[tokio::test]
    async fn concurrent_fresh_grants_for_same_subject_serialise() {
        let (_store, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let transport_a = transport(ADMIN_DID);
        let transport_b = transport(ADMIN_DID);

        let ctx_a_ks = acl_ks.clone();
        let ctx_a_locks = acl_locks.clone();
        let task_a = tokio::spawn(async move {
            let ctx = TrustTaskContext {
                acl_ks: &ctx_a_ks,
                acl_locks: &ctx_a_locks,
                my_vid: SERVICE_DID,
                signing_oracle: false,
            };
            handle(
                &ctx,
                &transport_a,
                no_verifier(),
                grant_request(ADMIN_DID, ALICE_DID, "owner"),
            )
            .await
        });
        let ctx_b_ks = acl_ks.clone();
        let ctx_b_locks = acl_locks.clone();
        let task_b = tokio::spawn(async move {
            let ctx = TrustTaskContext {
                acl_ks: &ctx_b_ks,
                acl_locks: &ctx_b_locks,
                my_vid: SERVICE_DID,
                signing_oracle: false,
            };
            handle(
                &ctx,
                &transport_b,
                no_verifier(),
                grant_request(ADMIN_DID, ALICE_DID, "owner"),
            )
            .await
        });
        let (a, b) = tokio::join!(task_a, task_b);
        assert!(matches!(a.unwrap(), DispatchOutcome::Handled(_)));
        assert!(matches!(b.unwrap(), DispatchOutcome::Handled(_)));

        let entries = acl::list_acl_entries(&acl_ks).await.unwrap();
        let alice_entries: Vec<_> = entries.iter().filter(|e| e.did == ALICE_DID).collect();
        assert_eq!(
            alice_entries.len(),
            1,
            "race produced duplicate entries: {alice_entries:?}"
        );
    }

    /// `enforce_proofs = true` + present proof + verifier accepts →
    /// the grant lands. Exercises the `(Some(proof), Some(v))`
    /// happy-path branch of `run_pipeline`.
    #[tokio::test]
    async fn enforce_proofs_with_valid_proof_grant_lands() {
        let (_store, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let ctx = ctx(&acl_ks, &acl_locks);
        let transport = transport(ADMIN_DID);
        let mut doc = grant_request(ADMIN_DID, ALICE_DID, "owner");
        add_stub_proof(&mut doc);

        let outcome = handle(
            &ctx,
            &transport,
            ProofPolicy::Verify(&AlwaysOkVerifier),
            doc,
        )
        .await;
        assert!(matches!(outcome, DispatchOutcome::Handled(_)));
        assert!(
            acl::get_acl_entry(&acl_ks, ALICE_DID)
                .await
                .unwrap()
                .is_some()
        );
    }

    /// `enforce_proofs = true` + present proof + verifier rejects →
    /// `proof_invalid`. Exercises the `(Some(proof), Some(v))` →
    /// verify-fails branch.
    #[tokio::test]
    async fn enforce_proofs_with_invalid_proof_rejects_proof_invalid() {
        let (_store, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let ctx = ctx(&acl_ks, &acl_locks);
        let transport = transport(ADMIN_DID);
        let mut doc = grant_request(ADMIN_DID, ALICE_DID, "owner");
        add_stub_proof(&mut doc);

        let outcome = handle(
            &ctx,
            &transport,
            ProofPolicy::Verify(&AlwaysErrVerifier),
            doc,
        )
        .await;
        let err = match outcome {
            DispatchOutcome::Rejected(e) => e,
            other => panic!("expected Rejected, got {other:?}"),
        };
        assert_eq!(
            err.payload.code,
            trust_tasks_rs::TrustTaskCode::Standard(StandardCode::ProofInvalid)
        );
        // No partial write.
        assert!(
            acl::get_acl_entry(&acl_ks, ALICE_DID)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// REQUIRED spec + absent proof → `proof_required`. Under upstream
    /// 0.1.1 this fires authoritatively from `P::IS_PROOF_REQUIRED`
    /// regardless of the consumer's `ProofPolicy`. Test pins the
    /// framework's per-spec enforcement on `acl/grant/0.2`.
    #[tokio::test]
    async fn required_spec_with_missing_proof_rejects_proof_required() {
        let (_store, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let ctx = ctx(&acl_ks, &acl_locks);
        let transport = transport(ADMIN_DID);
        // Build a request, then strip the stub proof that
        // `grant_request()` attached by default.
        let mut doc = grant_request(ADMIN_DID, ALICE_DID, "owner");
        doc.proof = None;

        let outcome = handle(
            &ctx,
            &transport,
            ProofPolicy::Verify(&AlwaysOkVerifier),
            doc,
        )
        .await;
        let err = match outcome {
            DispatchOutcome::Rejected(e) => e,
            other => panic!("expected Rejected, got {other:?}"),
        };
        assert_eq!(
            err.payload.code,
            trust_tasks_rs::TrustTaskCode::Standard(StandardCode::ProofRequired)
        );
        assert!(
            acl::get_acl_entry(&acl_ks, ALICE_DID)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// `enforce_proofs = false` (`ProofPolicy::RejectIfPresent`) +
    /// present proof → `malformed_request`. The previous behaviour
    /// (silent drop of a present proof) was the security-relevant
    /// footgun the v0.7.0 review pass surfaced. This test pins the
    /// new explicit-reject behaviour.
    #[tokio::test]
    async fn proof_present_under_reject_if_present_rejects_malformed_request() {
        let (_store, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let ctx = ctx(&acl_ks, &acl_locks);
        let transport = transport(ADMIN_DID);
        // grant_request() already attaches a stub proof for the
        // IS_PROOF_REQUIRED gate; that same proof here triggers the
        // RejectIfPresent rejection.
        let doc = grant_request(ADMIN_DID, ALICE_DID, "owner");

        let outcome =
            handle::<PanickingVerifier>(&ctx, &transport, ProofPolicy::RejectIfPresent, doc).await;
        let err = match outcome {
            DispatchOutcome::Rejected(e) => e,
            other => panic!("expected Rejected, got {other:?}"),
        };
        assert_eq!(
            err.payload.code,
            trust_tasks_rs::TrustTaskCode::Standard(StandardCode::MalformedRequest)
        );
        // The wire message is the framework-shared sanitised constant
        // (see trust_tasks_rs::PROOF_NOT_ACCEPTED_BY_POLICY) — the
        // verbose operator-actionable form ("flip enforce_proofs =
        // true") lives in a tracing::warn! emitted by dispatch_inbound,
        // not on the wire. Sanitising the wire prevents an unauth
        // probe from enumerating verifier coverage across a fleet.
        let msg = err.payload.message.as_deref().unwrap_or("");
        assert!(
            msg.contains("SPEC §7.2 item 7"),
            "framework's sanitised wire message expected, got: {msg}"
        );
    }

    #[tokio::test]
    async fn a_granter_may_not_grant_to_itself() {
        let (_store, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let err = rejected(
            handle(
                &ctx(&acl_ks, &acl_locks),
                &transport(ADMIN_DID),
                no_verifier(),
                grant_request(ADMIN_DID, ADMIN_DID, "admin"),
            )
            .await,
        );
        assert_eq!(
            err.payload.code,
            trust_tasks_rs::TrustTaskCode::Standard(StandardCode::PermissionDenied)
        );
    }

    /// Each authority member this maintainer cannot hold is refused with the
    /// code `acl/grant/0.2` declares for it — never accepted by dropping it.
    #[tokio::test]
    async fn authority_this_maintainer_cannot_hold_is_refused() {
        let (_store, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let ctx = ctx(&acl_ks, &acl_locks);
        let transport = transport(ADMIN_DID);

        let mut admin_narrow = owner_entry(&["alpha.example"]);
        admin_narrow["role"] = serde_json::json!("admin");
        let mut approver = owner_entry(&["alpha.example"]);
        approver["approve"] = serde_json::json!({ "scope": "all" });
        let mut listed = owner_entry(&["alpha.example"]);
        listed["capabilities"] =
            serde_json::json!({ "scope": "listed", "grants": [{ "capability": "did.publish" }] });
        let mut unknown_role = owner_entry(&["alpha.example"]);
        unknown_role["role"] = serde_json::json!("superuser");
        let mut expiring = owner_entry(&["alpha.example"]);
        expiring["expiresAt"] = serde_json::json!("2030-01-01T00:00:00Z");

        let cases = [
            (
                admin_narrow,
                trust_tasks_rs::TrustTaskCode::from(grant::error_codes::INVALID_ACT_SCOPE),
            ),
            (approver, grant::error_codes::INVALID_ACT_SCOPE.into()),
            (listed, grant::error_codes::UNKNOWN_CAPABILITY.into()),
            (unknown_role, grant::error_codes::ROLE_NOT_RECOGNIZED.into()),
            (expiring, StandardCode::TaskFailed.into()),
        ];
        for (entry, code) in cases {
            let err = rejected(
                handle(
                    &ctx,
                    &transport,
                    no_verifier(),
                    grant_request_with(ADMIN_DID, entry),
                )
                .await,
            );
            assert_eq!(err.payload.code, code, "{:?}", err.payload.message);
            assert!(
                acl::get_acl_entry(&acl_ks, ALICE_DID)
                    .await
                    .unwrap()
                    .is_none(),
                "nothing written"
            );
        }
    }
}
