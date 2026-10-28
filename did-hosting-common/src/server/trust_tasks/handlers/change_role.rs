//! `acl/change-role/0.2` handler — record a role transition with an
//! optimistic-concurrency check against the subject's prior role.
//!
//! Spec contract (`specs/acl/change-role/0.2/spec.md`, consumer items):
//!
//! * `stateMismatch` when the stored role is not `fromRole` (or the subject
//!   is absent); `roleNotRecognized` when either role is unknown.
//! * The entry is re-checked against `toRole`'s ceiling. Every entry here
//!   holds `capabilities: ceiling` (AclEntry 0.2) and no approvable
//!   capabilities, so there is never a listed capability to fall outside it.
//! * Only an `Admin` may change a role, and an `Admin` is the highest role,
//!   so `toRole` is never above the changer's.
//! * A change whose subject is the changer itself is `permissionDenied`.
//! * Last-authority guard: a change that demotes the only Admin is
//!   refused with the maintainer-minted `acl/change-role:lastAuthorityProtected`
//!   (SPEC.md §8.5; `acl/revoke/0.2` declares the same code for removal).
//! * The response entry carries `updatedAt` / `updatedBy`.

use serde_json::json;
use trust_tasks_rs::{
    ErrorPayload, ErrorResponse, Payload, ProofPolicy, ProofVerifier, ResolvedParties,
    StandardCode, TransportHandler, TrustTask,
};

use crate::server::acl::{self, AclEntry, Role};
use crate::server::trust_tasks::entry::SpecAclEntry;
use crate::server::trust_tasks::{DispatchOutcome, TrustTaskContext, reject_with, run_pipeline};
use crate::tasks::acl::change_role::v0_2 as change_role;

/// Maintainer-minted (SPEC.md §8.5): `change-role/0.2` declares no code for
/// the last-authority refusal, so it carries the spelling `acl/revoke/0.2`
/// declares for the same rule, under this task's own slug.
const ERR_LAST_AUTHORITY: &str = "lastAuthorityProtected";

/// Run the framework pipeline + business logic for an inbound
/// `acl/change-role/0.2` request.
pub async fn handle<V>(
    ctx: &TrustTaskContext<'_>,
    transport: &(impl TransportHandler + Sync),
    policy: ProofPolicy<'_, V>,
    doc: TrustTask<change_role::Payload>,
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
            // the read-then-write critical section is race-free
            // across concurrent admins. See `ACL_WRITE_LOCK_KEY` for
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
    doc: TrustTask<change_role::Payload>,
    parties: &ResolvedParties,
    signing_oracle: bool,
) -> Result<TrustTask<change_role::Response>, ErrorResponse> {
    // ─── 1. Authorise: caller must be Admin. ──────────────────────
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
                    .with_message("only Admin callers may emit acl/change-role/0.2"),
            ));
        }
        Err(_) => {
            return Err(reject_with(
                &doc,
                ErrorPayload::new(StandardCode::PermissionDenied)
                    .with_message("caller is not present in the maintainer's ACL"),
            ));
        }
    }

    let from_role_str: String = (*doc.payload.from_role).clone();
    let to_role_str: String = (*doc.payload.to_role).clone();

    // ─── 2. Role-vocabulary check. ────────────────────────────────
    let from_role = parse_role(&from_role_str).map_err(|()| {
        reject_with(
            &doc,
            ErrorPayload::from(change_role::error_codes::ROLE_NOT_RECOGNIZED)
                .with_message(format!("fromRole {from_role_str:?} is not recognised"))
                .with_details(role_not_recognized_details(&from_role_str)),
        )
    })?;
    let to_role = parse_role(&to_role_str).map_err(|()| {
        reject_with(
            &doc,
            ErrorPayload::from(change_role::error_codes::ROLE_NOT_RECOGNIZED)
                .with_message(format!("toRole {to_role_str:?} is not recognised"))
                .with_details(role_not_recognized_details(&to_role_str)),
        )
    })?;

    // ─── 3. No authority changes its own role. ────────────────────
    if crate::scid::same_reference(caller, &doc.payload.subject) {
        return Err(reject_with(
            &doc,
            ErrorPayload::new(StandardCode::PermissionDenied)
                .with_message("a changing authority may not change its own role"),
        ));
    }

    // ─── 4. Load the subject's current entry + state-check. ───────
    let existing = acl::get_acl_entry(acl_ks, &doc.payload.subject)
        .await
        .map_err(|e| internal(&doc, e))?;
    let mut entry = match existing {
        Some(e) => e,
        None => {
            // No dedicated code for "subject absent"; its current role is
            // "absent", which matches no `fromRole` a producer could send.
            // `currentRole` is omitted: the declared details schema types it
            // as a string.
            return Err(reject_with(
                &doc,
                ErrorPayload::from(change_role::error_codes::STATE_MISMATCH)
                    .with_message(format!(
                        "subject {} is not in the maintainer's ACL",
                        *doc.payload.subject
                    ))
                    .with_details(json!({})),
            ));
        }
    };

    if entry.role != from_role {
        return Err(reject_with(
            &doc,
            ErrorPayload::from(change_role::error_codes::STATE_MISMATCH)
                .with_message(format!(
                    "subject's current role is {:?}, not {:?}",
                    entry.role.to_string(),
                    from_role.to_string()
                ))
                .with_details(json!({ "currentRole": entry.role.to_string() })),
        ));
    }

    // ─── 5. Idempotent no-op. ─────────────────────────────────────
    if from_role == to_role {
        return Ok(build_response(&doc, &entry, signing_oracle, None));
    }

    // ─── 6. Last-authority guard. ────────────────────────────────
    if matches!(from_role, Role::Admin) && !matches!(to_role, Role::Admin) {
        let all = acl::list_acl_entries(acl_ks)
            .await
            .map_err(|e| internal(&doc, e))?;
        let other_admins: Vec<String> = all
            .iter()
            .filter(|e| matches!(e.role, Role::Admin) && e.did != *doc.payload.subject)
            .map(|e| e.did.clone())
            .collect();
        if other_admins.is_empty() {
            return Err(reject_with(
                &doc,
                ErrorPayload::new(change_role::Payload::extended_code(
                    ERR_LAST_AUTHORITY.to_string(),
                ))
                .with_message("this role change would leave the maintainer with no Admin entries")
                .with_details(json!({
                    "protectedRole": "admin",
                    "remainingHolders": other_admins,
                })),
            ));
        }
    }

    // ─── 7. Apply the transition. ────────────────────────────────
    // A `MetricsReader`'s domain scope is never consulted (it reads counters
    // only), so it is `All` by default — and carrying that over would make the
    // promoted entry, an Owner say, an Owner on every domain. Leaving the role
    // resets the act scope to `none` instead; the operator then widens it with
    // `acl/grant` (the console's role edit does exactly that, right after this
    // task). Other roles keep their scope: for Admin and Service `All` is a
    // real grant, and changing role widens nothing.
    if entry.role == Role::MetricsReader {
        entry.domains = crate::server::domain::DomainScope::Allowed { domains: vec![] };
    }
    entry.role = to_role;
    acl::store_acl_entry(acl_ks, &entry)
        .await
        .map_err(|e| internal(&doc, e))?;

    Ok(build_response(&doc, &entry, signing_oracle, Some(caller)))
}

fn parse_role(s: &str) -> Result<Role, ()> {
    s.parse::<Role>().map_err(|_| ())
}

fn role_not_recognized_details(offending: &str) -> serde_json::Value {
    json!({
        "offendingRole": offending,
        "knownRoles": ["admin", "owner", "service", "metricsReader"],
    })
}

/// The response, with `updatedAt` / `updatedBy` set when the entry changed.
fn build_response(
    request: &TrustTask<change_role::Payload>,
    local: &AclEntry,
    signing_oracle: bool,
    updated_by: Option<&str>,
) -> TrustTask<change_role::Response> {
    let mut neutral = SpecAclEntry::from_local(local, signing_oracle);
    if let Some(by) = updated_by {
        neutral.updated_at = Some(chrono::Utc::now());
        neutral.updated_by = Some(by.to_string());
    }
    // The generated payload types are `#[non_exhaustive]`: built through the
    // generated builder, whose `try_into` can only fail on a field left unset.
    let payload: change_role::Response = change_role::Response::builder()
        .entry(neutral.into_spec::<change_role::AclEntry>())
        .try_into()
        .expect("change-role response has every required field set");
    let id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    request.respond_with(id, payload)
}

fn internal<P>(doc: &TrustTask<P>, err: impl std::fmt::Display) -> ErrorResponse {
    tracing::error!(error = %err, "acl/change-role internal failure");
    reject_with(
        doc,
        ErrorPayload::new(StandardCode::InternalError)
            .with_message("the maintainer encountered an internal failure"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_tasks_rs::{Payload, VerificationError, handlers::InMemoryHandler};

    use crate::server::config::StoreConfig;
    use crate::server::domain::DomainScope;
    use crate::server::store::{KS_ACL, Store};
    use crate::server::trust_tasks::TrustTaskContext;

    const SERVICE_DID: &str = "did:web:maintainer.example";
    const ADMIN_DID: &str = "did:web:admin.example";
    const SECOND_ADMIN: &str = "did:web:admin2.example";
    const ALICE_DID: &str = "did:web:alice.example";

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
    /// Default test policy: `AcceptUnverified`. `acl/change-role/0.2`
    /// is REQUIRED — `request()` attaches a stub proof so the
    /// framework's IS_PROOF_REQUIRED gate passes; the unverified
    /// policy then accepts it without invoking any verifier.
    fn no_verifier() -> ProofPolicy<'static, PanickingVerifier> {
        ProofPolicy::AcceptUnverified
    }

    /// Stub proof so the IS_PROOF_REQUIRED gate accepts the request
    /// under `ProofPolicy::AcceptUnverified`.
    fn add_stub_proof(doc: &mut TrustTask<change_role::Payload>) {
        doc.proof = Some(trust_tasks_rs::Proof {
            proof_type: "DataIntegrityProof".into(),
            cryptosuite: "eddsa-jcs-2022".into(),
            verification_method: "did:web:admin.example#key-1".into(),
            created: chrono::Utc::now(),
            proof_purpose: "authentication".into(),
            proof_value: "z-stub".into(),
            extra: Default::default(),
        });
    }

    async fn harness() -> (Store, crate::server::store::KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        };
        std::mem::forget(dir);
        let store = Store::open(&cfg).await.expect("open fjall");
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
        (store, acl_ks)
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

    async fn seed(ks: &crate::server::store::KeyspaceHandle, did: &str, role: Role) {
        acl::store_acl_entry(
            ks,
            &AclEntry {
                did: did.into(),
                role,
                label: None,
                created_at: 1_700_000_000,
                max_total_size: None,
                max_did_count: None,
                domains: DomainScope::All,
            },
        )
        .await
        .unwrap();
    }

    fn request(
        issuer_did: &str,
        subject: &str,
        from: &str,
        to: &str,
    ) -> TrustTask<change_role::Payload> {
        let from_role: change_role::PayloadFromRole =
            from.to_string().try_into().expect("fromRole non-empty");
        let to_role: change_role::PayloadToRole =
            to.to_string().try_into().expect("toRole non-empty");
        let payload: change_role::Payload = change_role::Payload::builder()
            .from_role(from_role)
            .reason(Some(
                "test"
                    .parse::<change_role::PayloadReason>()
                    .expect("reason"),
            ))
            .subject(subject)
            .to_role(to_role)
            .try_into()
            .expect("test change-role payload is well formed");
        let mut doc = TrustTask::for_payload(format!("urn:uuid:{}", uuid::Uuid::new_v4()), payload);
        doc.issuer = Some(issuer_did.into());
        doc.recipient = Some(SERVICE_DID.into());
        doc.issued_at = Some(chrono::Utc::now());
        add_stub_proof(&mut doc);
        doc
    }

    #[tokio::test]
    async fn successful_role_transition_persists() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed(&acl_ks, ALICE_DID, Role::Owner).await;
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ADMIN_DID),
            no_verifier(),
            request(ADMIN_DID, ALICE_DID, "owner", "service"),
        )
        .await;
        let resp = match outcome {
            DispatchOutcome::Handled(d) => d,
            other => panic!("expected Handled, got {other:?}"),
        };
        assert_eq!(
            resp.type_uri.to_string(),
            format!("{}#response", change_role::Payload::TYPE_URI)
        );
        assert_eq!(resp.payload["entry"]["role"], "service");
        // AclEntry 0.2: authority stated explicitly, and the change recorded.
        assert_eq!(resp.payload["entry"]["act"], json!({ "scope": "all" }));
        assert_eq!(
            resp.payload["entry"]["capabilities"],
            json!({ "scope": "ceiling" })
        );
        assert_eq!(resp.payload["entry"]["updatedBy"], ADMIN_DID);
        assert!(resp.payload["entry"]["updatedAt"].is_string());
        let updated = acl::get_acl_entry(&acl_ks, ALICE_DID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.role, Role::Service);
    }

    #[tokio::test]
    async fn state_mismatch_when_fromrole_wrong() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed(&acl_ks, ALICE_DID, Role::Owner).await;
        // Caller claims Alice was a `service` but she's an `owner`.
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ADMIN_DID),
            no_verifier(),
            request(ADMIN_DID, ALICE_DID, "service", "admin"),
        )
        .await;
        let err = match outcome {
            DispatchOutcome::Rejected(e) => e,
            other => panic!("expected Rejected, got {other:?}"),
        };
        assert_eq!(
            err.payload.code,
            trust_tasks_rs::TrustTaskCode::from(change_role::error_codes::STATE_MISMATCH)
        );
        assert_eq!(err.payload.details.unwrap()["currentRole"], "owner");
        // Storage unchanged.
        assert_eq!(
            acl::get_acl_entry(&acl_ks, ALICE_DID)
                .await
                .unwrap()
                .unwrap()
                .role,
            Role::Owner
        );
    }

    #[tokio::test]
    async fn unknown_role_string_rejected() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed(&acl_ks, ALICE_DID, Role::Owner).await;
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ADMIN_DID),
            no_verifier(),
            request(ADMIN_DID, ALICE_DID, "owner", "superuser"),
        )
        .await;
        let err = match outcome {
            DispatchOutcome::Rejected(e) => e,
            other => panic!("expected Rejected, got {other:?}"),
        };
        assert_eq!(
            err.payload.code,
            trust_tasks_rs::TrustTaskCode::from(change_role::error_codes::ROLE_NOT_RECOGNIZED)
        );
        let details = err.payload.details.unwrap();
        assert_eq!(details["offendingRole"], "superuser");
        assert_eq!(
            details["knownRoles"],
            json!(["admin", "owner", "service", "metricsReader"])
        );
    }

    /// A MetricsReader's unused all-domains scope does not survive a role
    /// change: promoted to Owner, it holds no domain until a grant gives it
    /// one, rather than every domain.
    #[tokio::test]
    async fn leaving_metrics_reader_resets_the_scope_to_no_domains() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed(&acl_ks, ALICE_DID, Role::MetricsReader).await;
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ADMIN_DID),
            no_verifier(),
            request(ADMIN_DID, ALICE_DID, "metricsReader", "owner"),
        )
        .await;
        assert!(matches!(outcome, DispatchOutcome::Handled(_)));
        let entry = acl::get_acl_entry(&acl_ks, ALICE_DID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(entry.role, Role::Owner);
        assert_eq!(entry.domains, DomainScope::Allowed { domains: vec![] });
        assert!(!entry.domains.allows("example.com"));
    }

    /// A changing authority may not change its own role — not even an
    /// Admin demoting itself (which would otherwise be the last-authority
    /// case).
    #[tokio::test]
    async fn an_authority_cannot_change_its_own_role() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed(&acl_ks, SECOND_ADMIN, Role::Admin).await;
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ADMIN_DID),
            no_verifier(),
            request(ADMIN_DID, ADMIN_DID, "admin", "owner"),
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
        assert_eq!(
            acl::get_acl_entry(&acl_ks, ADMIN_DID)
                .await
                .unwrap()
                .unwrap()
                .role,
            Role::Admin
        );
    }

    #[tokio::test]
    async fn admin_demote_allowed_when_another_admin_exists() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed(&acl_ks, SECOND_ADMIN, Role::Admin).await;
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(SECOND_ADMIN),
            no_verifier(),
            request(SECOND_ADMIN, ADMIN_DID, "admin", "owner"),
        )
        .await;
        assert!(matches!(outcome, DispatchOutcome::Handled(_)));
        assert_eq!(
            acl::get_acl_entry(&acl_ks, ADMIN_DID)
                .await
                .unwrap()
                .unwrap()
                .role,
            Role::Owner
        );
    }

    #[tokio::test]
    async fn non_admin_caller_rejected() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed(&acl_ks, ALICE_DID, Role::Owner).await;
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ALICE_DID),
            no_verifier(),
            request(ALICE_DID, ALICE_DID, "owner", "service"),
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
    }

    #[tokio::test]
    async fn missing_subject_returns_state_mismatch_with_null() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ADMIN_DID),
            no_verifier(),
            request(ADMIN_DID, "did:web:nobody.example", "owner", "service"),
        )
        .await;
        let err = match outcome {
            DispatchOutcome::Rejected(e) => e,
            other => panic!("expected Rejected, got {other:?}"),
        };
        assert_eq!(
            err.payload.code,
            trust_tasks_rs::TrustTaskCode::from(change_role::error_codes::STATE_MISMATCH)
        );
        assert_eq!(
            err.payload.details.unwrap()["currentRole"],
            serde_json::Value::Null
        );
    }

    #[tokio::test]
    async fn same_role_is_idempotent_noop() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed(&acl_ks, ALICE_DID, Role::Owner).await;
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ADMIN_DID),
            no_verifier(),
            request(ADMIN_DID, ALICE_DID, "owner", "owner"),
        )
        .await;
        assert!(matches!(outcome, DispatchOutcome::Handled(_)));
        // Entry unchanged.
        assert_eq!(
            acl::get_acl_entry(&acl_ks, ALICE_DID)
                .await
                .unwrap()
                .unwrap()
                .role,
            Role::Owner
        );
    }
}
