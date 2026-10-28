//! `acl/revoke/0.2` handler — remove a subject's entry, or narrow its act
//! scope.
//!
//! Spec contract (`specs/acl/revoke/0.2/spec.md`, consumer items):
//!
//! * What is revoked is stated in `payload.revocation`:
//!   `{"kind": "entry"}` removes the entry; `{"kind": "act", "act": …}`
//!   narrows its act scope to the stated result.
//! * **Self-revocation** — `issuer == payload.subject` — is permitted;
//!   otherwise only an `Admin` may revoke.
//! * `subjectNotPresent` when the subject has no entry.
//! * A narrowing that is not strictly narrower than the stored act scope is
//!   `notNarrowing`; one this maintainer cannot hold is `invalidActScope`.
//! * `lastAuthorityProtected` when a removal would leave no `Admin`.
//! * The revocation applies at the subject's next authorization decision:
//!   every request reads the ACL afresh.
//!
//! ## Narrowing an act scope
//!
//! An entry's act scope is its domains (see [`super::super::entry`]).
//! Narrowing an `Owner` (or `MetricsReader`) from `all` or from a list of
//! domains to a strict subset of them — or to `none` — rewrites its
//! [`DomainScope`]; a default domain survives only while it is still one of
//! the entry's domains. `Admin` and `Service` act on every domain whatever
//! their entry says, so their act scope cannot be narrowed at all.

use serde_json::json;
use trust_tasks_rs::{
    ErrorPayload, ErrorResponse, ProofPolicy, ProofVerifier, ResolvedParties, StandardCode,
    TransportHandler, TrustTask, guards::acl::reject_last_authority,
};

use crate::server::acl::{self, AclEntry, Role};
use crate::server::domain::DomainScope;
use crate::server::trust_tasks::entry::{
    AuthorityScope, SpecAclEntry, act_covers, act_of, check_authority_scope, domains_for_act,
    role_is_domain_scoped,
};
use crate::server::trust_tasks::{DispatchOutcome, TrustTaskContext, reject_with, run_pipeline};
use crate::tasks::acl::revoke::v0_2 as revoke;

/// What `payload.revocation` asks for.
#[derive(Debug)]
enum Revocation {
    Entry,
    NarrowAct(AuthorityScope),
}

/// Run the framework pipeline + business logic for an inbound
/// `acl/revoke/0.2` request.
pub async fn handle<V>(
    ctx: &TrustTaskContext<'_>,
    transport: &(impl TransportHandler + Sync),
    policy: ProofPolicy<'_, V>,
    doc: TrustTask<revoke::Payload>,
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
            // the read-then-write critical section (auth check, last-
            // authority guard, write) is race-free across concurrent
            // admins targeting different subjects. See
            // `ACL_WRITE_LOCK_KEY` for why per-subject locking is
            // insufficient.
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
    doc: TrustTask<revoke::Payload>,
    parties: &ResolvedParties,
    signing_oracle: bool,
) -> Result<TrustTask<revoke::Response>, ErrorResponse> {
    let subject: String = (*doc.payload.subject).clone();
    let caller = parties.issuer.as_deref().ok_or_else(|| {
        reject_with(
            &doc,
            ErrorPayload::new(StandardCode::PermissionDenied)
                .with_message("inbound document has no in-band or transport-derived issuer"),
        )
    })?;
    let self_revoke = crate::scid::same_reference(caller, &subject);

    // Authorise: admin (any target) OR self-revoker (own target).
    if !self_revoke {
        match acl::check_acl(acl_ks, caller).await {
            Ok(Role::Admin) => {}
            Ok(_) => {
                return Err(reject_with(
                    &doc,
                    ErrorPayload::new(StandardCode::PermissionDenied)
                        .with_message("only Admin callers may revoke another subject"),
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
    }

    let revocation = parse_revocation(&doc.payload.revocation).map_err(|msg| {
        reject_with(
            &doc,
            ErrorPayload::new(StandardCode::MalformedRequest).with_message(msg),
        )
    })?;

    // Look up the target subject.
    let existing = acl::get_acl_entry(acl_ks, &subject)
        .await
        .map_err(|e| internal(&doc, e))?;
    let existing = match existing {
        Some(e) => e,
        None => {
            return Err(reject_with(
                &doc,
                ErrorPayload::from(revoke::error_codes::SUBJECT_NOT_PRESENT)
                    .with_message(format!("subject {subject} is not in the maintainer's ACL")),
            ));
        }
    };

    let response_entry = match revocation {
        Revocation::Entry => {
            // Full removal — first run the last-authority guard.
            let all_entries = acl::list_acl_entries(acl_ks)
                .await
                .map_err(|e| internal(&doc, e))?;
            if reject_last_authority(
                all_entries.iter(),
                |e: &&AclEntry| matches!(e.role, Role::Admin),
                |e: &&AclEntry| e.did == subject,
            )
            .is_some()
            {
                let remaining_admins: Vec<String> = all_entries
                    .iter()
                    .filter(|e| matches!(e.role, Role::Admin) && e.did != subject)
                    .map(|e| e.did.clone())
                    .collect();
                return Err(reject_with(
                    &doc,
                    ErrorPayload::from(revoke::error_codes::LAST_AUTHORITY_PROTECTED)
                        .with_message(
                            "this revocation would leave the maintainer with no Admin entries",
                        )
                        .with_details(json!({
                            "protectedRole": "admin",
                            "remainingHolders": remaining_admins,
                        })),
                ));
            }

            acl::delete_acl_entry(acl_ks, &subject)
                .await
                .map_err(|e| internal(&doc, e))?;
            None
        }
        Revocation::NarrowAct(target) => {
            let narrowed =
                narrow_act(&existing, &target).map_err(|refusal| reject_with(&doc, refusal))?;
            acl::store_acl_entry(acl_ks, &narrowed)
                .await
                .map_err(|e| internal(&doc, e))?;
            Some(narrowed)
        }
    };

    let resp_entry = response_entry
        .as_ref()
        .map(|e| SpecAclEntry::from_local(e, signing_oracle).into_spec::<revoke::AclEntry>());
    // The generated payload types are `#[non_exhaustive]`: built through the
    // generated builder, whose `try_into` can only fail on a field left unset.
    let resp_payload: revoke::Response = revoke::Response::builder()
        .entry(resp_entry)
        .try_into()
        .expect("revoke response has every required field set");
    let resp_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    Ok(doc.respond_with(resp_id, resp_payload))
}

/// Read `payload.revocation` by its `kind`. Read from the JSON rather than
/// the generated untagged enum, whose `kind` members are untyped.
fn parse_revocation(revocation: &revoke::Revocation) -> Result<Revocation, String> {
    let value = serde_json::to_value(revocation).map_err(|e| format!("revocation: {e}"))?;
    match value.get("kind").and_then(serde_json::Value::as_str) {
        Some("entry") => Ok(Revocation::Entry),
        Some("act") => {
            let act = value
                .get("act")
                .cloned()
                .ok_or("`revocation.act` is required for kind `act`")?;
            let act: AuthorityScope = serde_json::from_value(act)
                .map_err(|e| format!("`revocation.act` is not an act scope: {e}"))?;
            check_authority_scope(&act, "revocation.act").map_err(|e| e.to_string())?;
            Ok(Revocation::NarrowAct(act))
        }
        _ => Err("`revocation.kind` must be `entry` or `act`".into()),
    }
}

/// The entry `existing` becomes when its act scope is narrowed to `target`,
/// or the refusal `acl/revoke/0.2` declares.
fn narrow_act(existing: &AclEntry, target: &AuthorityScope) -> Result<AclEntry, ErrorPayload> {
    let current = act_of(existing);
    if !role_is_domain_scoped(&existing.role) {
        // Admin and Service act everywhere; there is no narrower scope this
        // maintainer can hold for them.
        if *target == AuthorityScope::All {
            return Err(not_narrowing(&current));
        }
        return Err(ErrorPayload::from(revoke::error_codes::INVALID_ACT_SCOPE)
            .with_message(format!(
                "a {} entry acts on every domain; its act scope cannot be narrowed — change \
                 its role or remove it",
                existing.role
            ))
            .with_details(json!({ "offendingContexts": offending_contexts(target) })));
    }
    // Strictly narrower: covered by the current scope, and not equal to it.
    if !act_covers(&current, target) || act_covers(target, &current) {
        return Err(not_narrowing(&current));
    }
    let default = match &existing.domains {
        DomainScope::AllowedWithDefault { default, .. } => Some(default.as_str()),
        _ => None,
    };
    let mut narrowed = existing.clone();
    narrowed.domains = domains_for_act(target, default);
    Ok(narrowed)
}

fn not_narrowing(current: &AuthorityScope) -> ErrorPayload {
    ErrorPayload::from(revoke::error_codes::NOT_NARROWING).with_message(format!(
        "the stated act scope is not strictly narrower than the entry's current one ({})",
        serde_json::to_string(current).expect("AuthorityScope serialises")
    ))
}

fn offending_contexts(scope: &AuthorityScope) -> Vec<String> {
    match scope {
        AuthorityScope::Contexts { contexts } => contexts.clone(),
        AuthorityScope::All | AuthorityScope::None => Vec::new(),
    }
}

fn internal<P>(doc: &TrustTask<P>, err: impl std::fmt::Display) -> ErrorResponse {
    tracing::error!(error = %err, "acl/revoke internal failure");
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

    /// Default test policy: `AcceptUnverified`. `acl/revoke/0.2` is
    /// REQUIRED — every test request carries a stub proof for the
    /// IS_PROOF_REQUIRED gate, and AcceptUnverified lets the framework
    /// pipeline reach the handler.
    fn no_verifier() -> ProofPolicy<'static, PanickingVerifier> {
        ProofPolicy::AcceptUnverified
    }

    /// Stub proof attached to every test request so the framework's
    /// `IS_PROOF_REQUIRED` check passes. Shape is not validated under
    /// `ProofPolicy::AcceptUnverified` — we just need a present
    /// `proof` member.
    fn add_stub_proof(doc: &mut TrustTask<revoke::Payload>) {
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

    /// A removal (`act: None`) or a narrowing to `act`.
    fn revoke_request(
        issuer_did: &str,
        subject: &str,
        act: Option<serde_json::Value>,
    ) -> TrustTask<revoke::Payload> {
        let revocation = match act {
            None => serde_json::json!({ "kind": "entry" }),
            Some(act) => serde_json::json!({ "kind": "act", "act": act }),
        };
        let payload: revoke::Payload = serde_json::from_value(serde_json::json!({
            "subject": subject,
            "revocation": revocation,
            "reason": "integration test"
        }))
        .expect("test revoke payload is well formed");
        let mut doc = TrustTask::for_payload(format!("urn:uuid:{}", uuid::Uuid::new_v4()), payload);
        doc.issuer = Some(issuer_did.into());
        doc.recipient = Some(SERVICE_DID.into());
        doc.issued_at = Some(chrono::Utc::now());
        add_stub_proof(&mut doc);
        doc
    }

    fn contexts(c: &[&str]) -> Option<serde_json::Value> {
        Some(serde_json::json!({ "scope": "contexts", "contexts": c }))
    }

    fn rejected(outcome: DispatchOutcome) -> ErrorResponse {
        match outcome {
            DispatchOutcome::Rejected(e) => e,
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    /// Helper: seed an entry with the given DID + role + scope.
    async fn seed(
        ks: &crate::server::store::KeyspaceHandle,
        did: &str,
        role: Role,
        domains: DomainScope,
    ) {
        acl::store_acl_entry(
            ks,
            &AclEntry {
                did: did.into(),
                role,
                label: None,
                created_at: 1_700_000_000,
                max_total_size: None,
                max_did_count: None,
                domains,
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn full_removal_returns_entry_null_and_deletes() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed(&acl_ks, ALICE_DID, Role::Owner, DomainScope::All).await;
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ADMIN_DID),
            no_verifier(),
            revoke_request(ADMIN_DID, ALICE_DID, None),
        )
        .await;
        let resp = match outcome {
            DispatchOutcome::Handled(d) => d,
            other => panic!("expected Handled, got {other:?}"),
        };
        assert_eq!(
            resp.type_uri.to_string(),
            format!("{}#response", revoke::Payload::TYPE_URI)
        );
        assert_eq!(resp.payload["entry"], serde_json::Value::Null);
        assert!(
            acl::get_acl_entry(&acl_ks, ALICE_DID)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn narrowing_act_drops_domains() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed(
            &acl_ks,
            ALICE_DID,
            Role::Owner,
            DomainScope::Allowed {
                domains: vec!["a.example".into(), "b.example".into()],
            },
        )
        .await;

        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ADMIN_DID),
            no_verifier(),
            revoke_request(ADMIN_DID, ALICE_DID, contexts(&["a.example"])),
        )
        .await;
        let resp = match outcome {
            DispatchOutcome::Handled(d) => d,
            other => panic!("expected Handled, got {other:?}"),
        };
        let entry = resp.payload["entry"].clone();
        assert_eq!(entry["subject"], ALICE_DID);
        assert_eq!(
            entry["act"],
            serde_json::json!({ "scope": "contexts", "contexts": ["a.example"] })
        );
        let updated = acl::get_acl_entry(&acl_ks, ALICE_DID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            updated.domains,
            DomainScope::Allowed {
                domains: vec!["a.example".into()]
            }
        );
    }

    #[tokio::test]
    async fn narrowing_away_the_default_demotes_to_allowed() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed(
            &acl_ks,
            ALICE_DID,
            Role::Owner,
            DomainScope::AllowedWithDefault {
                domains: vec!["a.example".into(), "b.example".into()],
                default: "a.example".into(),
            },
        )
        .await;
        let _ = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ADMIN_DID),
            no_verifier(),
            revoke_request(ADMIN_DID, ALICE_DID, contexts(&["b.example"])),
        )
        .await;
        let updated = acl::get_acl_entry(&acl_ks, ALICE_DID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            updated.domains,
            DomainScope::Allowed {
                domains: vec!["b.example".into()]
            }
        );
    }

    /// Narrowing to `none` keeps the entry — it states an entry that may act
    /// nowhere — rather than removing it.
    #[tokio::test]
    async fn narrowing_to_none_keeps_an_entry_that_acts_nowhere() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed(&acl_ks, ALICE_DID, Role::Owner, DomainScope::All).await;
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ADMIN_DID),
            no_verifier(),
            revoke_request(
                ADMIN_DID,
                ALICE_DID,
                Some(serde_json::json!({ "scope": "none" })),
            ),
        )
        .await;
        let resp = match outcome {
            DispatchOutcome::Handled(d) => d,
            other => panic!("expected Handled, got {other:?}"),
        };
        assert_eq!(
            resp.payload["entry"]["act"],
            serde_json::json!({ "scope": "none" })
        );
        let updated = acl::get_acl_entry(&acl_ks, ALICE_DID)
            .await
            .unwrap()
            .unwrap();
        assert!(!updated.domains.allows("a.example"));
    }

    /// A stated scope that is not strictly narrower is `notNarrowing`: the
    /// same scope, a wider one, or one naming a domain the entry lacks.
    #[tokio::test]
    async fn a_scope_that_does_not_narrow_is_refused() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed(
            &acl_ks,
            ALICE_DID,
            Role::Owner,
            DomainScope::Allowed {
                domains: vec!["a.example".into()],
            },
        )
        .await;
        for act in [
            contexts(&["a.example"]),
            contexts(&["a.example", "b.example"]),
            contexts(&["b.example"]),
            Some(serde_json::json!({ "scope": "all" })),
        ] {
            let err = rejected(
                handle(
                    &ctx(&acl_ks, &acl_locks),
                    &transport(ADMIN_DID),
                    no_verifier(),
                    revoke_request(ADMIN_DID, ALICE_DID, act),
                )
                .await,
            );
            assert!(
                revoke::error_codes::NOT_NARROWING.matches(&err.payload.code),
                "{:?}",
                err.payload.code
            );
        }
    }

    /// An Admin acts on every domain whatever its entry says; a narrower act
    /// scope is one this maintainer cannot hold.
    #[tokio::test]
    async fn an_admin_act_scope_cannot_be_narrowed() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed(&acl_ks, SECOND_ADMIN, Role::Admin, DomainScope::All).await;
        let err = rejected(
            handle(
                &ctx(&acl_ks, &acl_locks),
                &transport(ADMIN_DID),
                no_verifier(),
                revoke_request(ADMIN_DID, SECOND_ADMIN, contexts(&["a.example"])),
            )
            .await,
        );
        assert!(
            revoke::error_codes::INVALID_ACT_SCOPE.matches(&err.payload.code),
            "{:?}",
            err.payload.code
        );
    }

    #[tokio::test]
    async fn last_authority_guard_blocks_sole_admin_removal() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        // ADMIN_DID is the only admin from harness().
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ADMIN_DID),
            no_verifier(),
            revoke_request(ADMIN_DID, ADMIN_DID, None), // self-revoke as sole admin
        )
        .await;
        let err = match outcome {
            DispatchOutcome::Rejected(e) => e,
            other => panic!("expected Rejected, got {other:?}"),
        };
        assert_eq!(
            err.payload.code,
            trust_tasks_rs::TrustTaskCode::from(revoke::error_codes::LAST_AUTHORITY_PROTECTED)
        );
        let details = err.payload.details.expect("details present");
        assert_eq!(details["protectedRole"], "admin");
        assert_eq!(details["remainingHolders"], serde_json::json!([]));
        // Admin entry MUST still exist.
        assert!(
            acl::get_acl_entry(&acl_ks, ADMIN_DID)
                .await
                .unwrap()
                .is_some()
        );
    }

    /// Two concurrent `acl/revoke` requests targeting the two
    /// remaining Admins must NOT both succeed — the maintainer must
    /// always retain at least one Admin. Without the `acl_locks`
    /// guard, each request reads the ACL before the other writes,
    /// sees the *other* Admin present, passes the last-authority
    /// check, and commits — emptying the privileged role set. Pinning
    /// this catches a regression where the lock acquisition is
    /// dropped from `handle`.
    #[tokio::test]
    async fn concurrent_revokes_of_remaining_admins_preserve_admin_set() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed(&acl_ks, SECOND_ADMIN, Role::Admin, DomainScope::All).await;
        // Two admins now: ADMIN_DID (from harness) + SECOND_ADMIN.

        let transport_a = transport(ADMIN_DID);
        let transport_b = transport(SECOND_ADMIN);

        let ks_a = acl_ks.clone();
        let locks_a = acl_locks.clone();
        let task_a = tokio::spawn(async move {
            let ctx = TrustTaskContext {
                acl_ks: &ks_a,
                acl_locks: &locks_a,
                my_vid: SERVICE_DID,
                signing_oracle: false,
            };
            handle(
                &ctx,
                &transport_a,
                no_verifier(),
                revoke_request(ADMIN_DID, SECOND_ADMIN, None),
            )
            .await
        });
        let ks_b = acl_ks.clone();
        let locks_b = acl_locks.clone();
        let task_b = tokio::spawn(async move {
            let ctx = TrustTaskContext {
                acl_ks: &ks_b,
                acl_locks: &locks_b,
                my_vid: SERVICE_DID,
                signing_oracle: false,
            };
            handle(
                &ctx,
                &transport_b,
                no_verifier(),
                revoke_request(SECOND_ADMIN, ADMIN_DID, None),
            )
            .await
        });

        let (a, b) = tokio::join!(task_a, task_b);
        // Exactly one revoke succeeds — the second runs after the
        // lock guard releases, sees only one Admin left, and is
        // rejected with `last_authority_protected`.
        let outcomes = [a.unwrap(), b.unwrap()];
        let handled_count = outcomes
            .iter()
            .filter(|o| matches!(o, DispatchOutcome::Handled(_)))
            .count();
        let rejected_count = outcomes
            .iter()
            .filter(|o| matches!(o, DispatchOutcome::Rejected(_)))
            .count();
        assert_eq!(
            handled_count, 1,
            "exactly one revoke should succeed; got {outcomes:?}"
        );
        assert_eq!(
            rejected_count, 1,
            "exactly one revoke should be rejected; got {outcomes:?}"
        );

        // At least one Admin remains.
        let entries = acl::list_acl_entries(&acl_ks).await.unwrap();
        let admins_left: Vec<_> = entries
            .iter()
            .filter(|e| matches!(e.role, Role::Admin))
            .collect();
        assert!(
            !admins_left.is_empty(),
            "ACL must retain at least one Admin: {entries:?}"
        );
    }

    #[tokio::test]
    async fn second_admin_removal_succeeds_when_another_remains() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed(&acl_ks, SECOND_ADMIN, Role::Admin, DomainScope::All).await;
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ADMIN_DID),
            no_verifier(),
            revoke_request(ADMIN_DID, SECOND_ADMIN, None),
        )
        .await;
        assert!(matches!(outcome, DispatchOutcome::Handled(_)));
    }

    #[tokio::test]
    async fn subject_not_in_acl_returns_extended_code() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ADMIN_DID),
            no_verifier(),
            revoke_request(ADMIN_DID, "did:web:nobody.example", None),
        )
        .await;
        let err = match outcome {
            DispatchOutcome::Rejected(e) => e,
            other => panic!("expected Rejected, got {other:?}"),
        };
        assert_eq!(
            err.payload.code,
            trust_tasks_rs::TrustTaskCode::from(revoke::error_codes::SUBJECT_NOT_PRESENT)
        );
    }

    #[tokio::test]
    async fn self_revoke_permitted_when_not_last_authority() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed(&acl_ks, ALICE_DID, Role::Owner, DomainScope::All).await;
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ALICE_DID),
            no_verifier(),
            revoke_request(ALICE_DID, ALICE_DID, None),
        )
        .await;
        assert!(matches!(outcome, DispatchOutcome::Handled(_)));
        assert!(
            acl::get_acl_entry(&acl_ks, ALICE_DID)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn non_admin_revoking_other_subject_rejected() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed(&acl_ks, ALICE_DID, Role::Owner, DomainScope::All).await;
        seed(
            &acl_ks,
            "did:web:bob.example",
            Role::Owner,
            DomainScope::All,
        )
        .await;
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ALICE_DID),
            no_verifier(),
            revoke_request(ALICE_DID, "did:web:bob.example", None),
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
}
