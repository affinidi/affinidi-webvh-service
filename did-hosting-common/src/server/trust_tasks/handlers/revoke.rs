//! `acl/revoke/0.1` handler — record the removal of a subject (or the
//! reduction of their scopes).
//!
//! Spec contract (from `specs/acl/revoke/0.1/spec.md`):
//!
//! * **Full removal** — `payload.scopes` absent; entire entry deleted.
//! * **Scope reduction** — `payload.scopes` present; named scopes
//!   removed from the entry. The webvh maintainer interprets each
//!   `scopes` item with a `domain:` prefix as a domain-scope item;
//!   items without that prefix are rejected as `malformed_request`
//!   because this maintainer has no other opaque scope vocabulary.
//! * **Self-revocation** — `issuer == payload.subject`; permitted
//!   subject to the [`reject_last_authority`] guard.
//! * **`acl/revoke:subject_not_present`** when the subject is absent.
//! * **`acl/revoke:last_authority_protected`** when the revocation
//!   would empty the privileged-role (Admin) set.
//!
//! ## Translating `scopes` → `DomainScope` reduction
//!
//! Each `payload.scopes` item is parsed as `domain:<name>`. The set is
//! subtracted from the entry's [`DomainScope::Allowed`] or
//! [`DomainScope::AllowedWithDefault`] list. Three cases:
//!
//! 1. Scope set becomes empty → the entry is **fully removed** (the
//!    response carries `entry: null`).
//! 2. The `default` of an `AllowedWithDefault` is in the removed set →
//!    the entry is demoted to plain `Allowed { remaining }`.
//! 3. Otherwise → the entry's scope is reduced in place.
//!
//! Scope-reducing an `All`-scoped entry is malformed (no list to
//! subtract from); the producer must grant a narrower scope first.

use serde_json::json;
use trust_tasks_rs::{
    ErrorPayload, ErrorResponse, Payload, ProofPolicy, ProofVerifier, ResolvedParties,
    StandardCode, TransportHandler, TrustTask, guards::acl::reject_last_authority,
    specs::acl::revoke::v0_1 as revoke,
};

use crate::server::acl::{self, AclEntry, Role};
use crate::server::domain::DomainScope;
use crate::server::trust_tasks::{
    DispatchOutcome, TrustTaskContext, entry::SpecAclEntry, reject_with, run_pipeline,
};

const SCOPE_DOMAIN_PREFIX: &str = "domain:";

/// Spec-extended error codes published in the `acl/revoke/0.1` front
/// matter. Minted via [`Payload::extended_code`] so the slug is sourced
/// from `TYPE_URI` and can't drift.
const ERR_SUBJECT_NOT_PRESENT: &str = "subject_not_present";
const ERR_LAST_AUTHORITY: &str = "last_authority_protected";

/// Run the framework pipeline + business logic for an inbound
/// `acl/revoke/0.1` request.
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
            handle_inner(&acl_ks, doc, &parties).await
        },
    )
    .await
}

async fn handle_inner(
    acl_ks: &crate::server::store::KeyspaceHandle,
    doc: TrustTask<revoke::Payload>,
    parties: &ResolvedParties,
) -> Result<TrustTask<revoke::Response>, ErrorResponse> {
    let subject = doc.payload.subject.clone();
    let caller = parties.issuer.as_deref().ok_or_else(|| {
        reject_with(
            &doc,
            ErrorPayload::new(StandardCode::PermissionDenied)
                .with_message("inbound document has no in-band or transport-derived issuer"),
        )
    })?;
    let self_revoke = caller == subject;

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

    // Look up the target subject.
    let existing = acl::get_acl_entry(acl_ks, &subject)
        .await
        .map_err(|e| internal(&doc, e))?;
    let existing = match existing {
        Some(e) => e,
        None => {
            return Err(reject_with(
                &doc,
                ErrorPayload::new(extended_code(ERR_SUBJECT_NOT_PRESENT))
                    .with_message(format!("subject {subject} is not in the maintainer's ACL",)),
            ));
        }
    };

    let response_entry = if doc.payload.scopes.is_empty() {
        // Full removal — first run the last-authority guard.
        let all_entries = acl::list_acl_entries(acl_ks)
            .await
            .map_err(|e| internal(&doc, e))?;
        if let Some(code) = reject_last_authority(
            all_entries.iter(),
            |e: &&AclEntry| matches!(e.role, Role::Admin),
            |e: &&AclEntry| e.did == subject,
        ) {
            debug_assert_eq!(
                code, "acl/revoke:last_authority_protected",
                "guard returned unexpected code"
            );
            let remaining_admins: Vec<String> = all_entries
                .iter()
                .filter(|e| matches!(e.role, Role::Admin) && e.did != subject)
                .map(|e| e.did.clone())
                .collect();
            return Err(reject_with(
                &doc,
                ErrorPayload::new(extended_code(ERR_LAST_AUTHORITY))
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
    } else {
        // Scope reduction — interpret the wire scopes as `domain:<name>`.
        let scope_items: Vec<String> = doc.payload.scopes.iter().map(|s| (**s).clone()).collect();
        let domains_to_remove = parse_domain_scopes(&scope_items).map_err(|msg| {
            reject_with(
                &doc,
                ErrorPayload::new(StandardCode::MalformedRequest).with_message(msg),
            )
        })?;

        match apply_scope_reduction(&existing.domains, &domains_to_remove) {
            ScopeReduction::EntryRemoved => {
                acl::delete_acl_entry(acl_ks, &subject)
                    .await
                    .map_err(|e| internal(&doc, e))?;
                None
            }
            ScopeReduction::Narrowed(new_scope) => {
                let mut updated = existing;
                updated.domains = new_scope;
                acl::store_acl_entry(acl_ks, &updated)
                    .await
                    .map_err(|e| internal(&doc, e))?;
                Some(updated)
            }
            ScopeReduction::NoOp => {
                // Removing zero matching scopes is idempotent — keep
                // the existing entry unchanged.
                Some(existing)
            }
            ScopeReduction::ScopeReduceOnAll => {
                return Err(reject_with(
                    &doc,
                    ErrorPayload::new(StandardCode::MalformedRequest).with_message(
                        "cannot scope-reduce an entry whose domain scope is `all`; grant a \
                         narrower scope first",
                    ),
                ));
            }
        }
    };

    let resp_entry = response_entry.as_ref().map(into_spec_entry);
    let resp_payload = revoke::Response {
        entry: resp_entry,
        ext: None,
    };
    let resp_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    Ok(doc.respond_with(resp_id, resp_payload))
}

/// Parse the wire-form `scopes` array (e.g. `["domain:a.example",
/// "domain:b.example"]`) into bare domain names. Any item without the
/// `domain:` prefix is rejected; this maintainer has no other opaque
/// scope vocabulary.
fn parse_domain_scopes(items: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        match item.strip_prefix(SCOPE_DOMAIN_PREFIX) {
            Some(name) if !name.is_empty() => out.push(name.to_string()),
            _ => {
                return Err(format!(
                    "scope item {item:?} is not understood by this maintainer; supported form is \
                     `domain:<name>`",
                ));
            }
        }
    }
    Ok(out)
}

#[derive(Debug, PartialEq, Eq)]
enum ScopeReduction {
    /// The reduction removed every remaining domain — entry should be
    /// fully removed.
    EntryRemoved,
    /// The reduction succeeded; the new domain scope is enclosed.
    Narrowed(DomainScope),
    /// None of the requested scopes were present on the entry — the
    /// reduction is a no-op.
    NoOp,
    /// The entry's scope is `All`; scope-reduction is not meaningful.
    ScopeReduceOnAll,
}

/// Apply a set of domain removals to a [`DomainScope`].
fn apply_scope_reduction(current: &DomainScope, remove: &[String]) -> ScopeReduction {
    let remove_set: std::collections::HashSet<&str> = remove.iter().map(String::as_str).collect();
    match current {
        DomainScope::All => ScopeReduction::ScopeReduceOnAll,
        DomainScope::Allowed { domains } => {
            let (kept, dropped): (Vec<String>, Vec<String>) = domains
                .iter()
                .cloned()
                .partition(|d| !remove_set.contains(d.as_str()));
            if dropped.is_empty() {
                ScopeReduction::NoOp
            } else if kept.is_empty() {
                ScopeReduction::EntryRemoved
            } else {
                ScopeReduction::Narrowed(DomainScope::Allowed { domains: kept })
            }
        }
        DomainScope::AllowedWithDefault { domains, default } => {
            let (kept, dropped): (Vec<String>, Vec<String>) = domains
                .iter()
                .cloned()
                .partition(|d| !remove_set.contains(d.as_str()));
            if dropped.is_empty() {
                ScopeReduction::NoOp
            } else if kept.is_empty() {
                ScopeReduction::EntryRemoved
            } else if kept.contains(default) {
                ScopeReduction::Narrowed(DomainScope::AllowedWithDefault {
                    domains: kept,
                    default: default.clone(),
                })
            } else {
                // The default was removed — demote to plain Allowed.
                ScopeReduction::Narrowed(DomainScope::Allowed { domains: kept })
            }
        }
    }
}

fn into_spec_entry(local: &AclEntry) -> revoke::AclEntry {
    let neutral = SpecAclEntry::from_local(local);
    let value = serde_json::to_value(&neutral).expect("SpecAclEntry serialises");
    serde_json::from_value(value).expect("revoke::AclEntry from SpecAclEntry value")
}

fn extended_code(local: &str) -> trust_tasks_rs::TrustTaskCode {
    revoke::Payload::extended_code(local.to_string())
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
    use crate::server::trust_tasks::ext::WEBVH_EXT_KEY;

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

    /// Default test policy: `AcceptUnverified`. `acl/revoke/0.1` is
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
            proof_purpose: "assertionMethod".into(),
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
        }
    }

    fn transport(peer: &str) -> InMemoryHandler {
        InMemoryHandler::new()
            .with_local(SERVICE_DID.to_string())
            .with_peer(peer.to_string())
    }

    fn revoke_request(
        issuer_did: &str,
        subject: &str,
        scopes: &[&str],
    ) -> TrustTask<revoke::Payload> {
        let scopes: Vec<revoke::PayloadScopesItem> = scopes
            .iter()
            .map(|s| (*s).to_string().try_into().expect("scope item parses"))
            .collect();
        let payload = revoke::Payload {
            ext: None,
            reason: Some("integration test".into()),
            scopes,
            subject: subject.into(),
        };
        let mut doc = TrustTask::for_payload(format!("urn:uuid:{}", uuid::Uuid::new_v4()), payload);
        doc.issuer = Some(issuer_did.into());
        doc.recipient = Some(SERVICE_DID.into());
        doc.issued_at = Some(chrono::Utc::now());
        add_stub_proof(&mut doc);
        doc
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
            revoke_request(ADMIN_DID, ALICE_DID, &[]),
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
    async fn scope_reduction_narrows_allowed_domains() {
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
            revoke_request(ADMIN_DID, ALICE_DID, &["domain:b.example"]),
        )
        .await;
        let resp = match outcome {
            DispatchOutcome::Handled(d) => d,
            other => panic!("expected Handled, got {other:?}"),
        };
        // entry is the reduced AclEntry
        let entry = resp.payload["entry"].clone();
        assert_eq!(entry["subject"], ALICE_DID);
        // vendor ext carries the reduced domain set
        let domains = &entry["ext"][WEBVH_EXT_KEY]["domains"];
        assert_eq!(domains["kind"], "allowed");
        assert_eq!(domains["domains"], serde_json::json!(["a.example"]));

        // Storage reflects the reduction
        let updated = acl::get_acl_entry(&acl_ks, ALICE_DID)
            .await
            .unwrap()
            .unwrap();
        match updated.domains {
            DomainScope::Allowed { domains } => assert_eq!(domains, vec!["a.example"]),
            other => panic!("expected Allowed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn scope_reduction_removing_default_demotes_to_allowed() {
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
            revoke_request(ADMIN_DID, ALICE_DID, &["domain:a.example"]),
        )
        .await;
        let updated = acl::get_acl_entry(&acl_ks, ALICE_DID)
            .await
            .unwrap()
            .unwrap();
        match updated.domains {
            DomainScope::Allowed { domains } => assert_eq!(domains, vec!["b.example"]),
            other => panic!("default-removed entry must demote to Allowed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn scope_reduction_emptying_set_deletes_entry() {
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
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ADMIN_DID),
            no_verifier(),
            revoke_request(ADMIN_DID, ALICE_DID, &["domain:a.example"]),
        )
        .await;
        let resp = match outcome {
            DispatchOutcome::Handled(d) => d,
            other => panic!("expected Handled, got {other:?}"),
        };
        assert_eq!(resp.payload["entry"], serde_json::Value::Null);
        assert!(
            acl::get_acl_entry(&acl_ks, ALICE_DID)
                .await
                .unwrap()
                .is_none()
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
            revoke_request(ADMIN_DID, ADMIN_DID, &[]), // self-revoke as sole admin
        )
        .await;
        let err = match outcome {
            DispatchOutcome::Rejected(e) => e,
            other => panic!("expected Rejected, got {other:?}"),
        };
        assert_eq!(err.payload.code, extended_code(ERR_LAST_AUTHORITY));
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
            };
            handle(
                &ctx,
                &transport_a,
                no_verifier(),
                revoke_request(ADMIN_DID, SECOND_ADMIN, &[]),
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
            };
            handle(
                &ctx,
                &transport_b,
                no_verifier(),
                revoke_request(SECOND_ADMIN, ADMIN_DID, &[]),
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
            revoke_request(ADMIN_DID, SECOND_ADMIN, &[]),
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
            revoke_request(ADMIN_DID, "did:web:nobody.example", &[]),
        )
        .await;
        let err = match outcome {
            DispatchOutcome::Rejected(e) => e,
            other => panic!("expected Rejected, got {other:?}"),
        };
        assert_eq!(err.payload.code, extended_code(ERR_SUBJECT_NOT_PRESENT));
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
            revoke_request(ALICE_DID, ALICE_DID, &[]),
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
            revoke_request(ALICE_DID, "did:web:bob.example", &[]),
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
    async fn scope_with_unknown_prefix_rejected_as_malformed() {
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
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ADMIN_DID),
            no_verifier(),
            revoke_request(ADMIN_DID, ALICE_DID, &["context:project-alpha"]),
        )
        .await;
        let err = match outcome {
            DispatchOutcome::Rejected(e) => e,
            other => panic!("expected Rejected, got {other:?}"),
        };
        assert_eq!(
            err.payload.code,
            trust_tasks_rs::TrustTaskCode::Standard(StandardCode::MalformedRequest)
        );
    }

    #[tokio::test]
    async fn scope_reduce_on_all_rejected() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed(&acl_ks, ALICE_DID, Role::Owner, DomainScope::All).await;
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ADMIN_DID),
            no_verifier(),
            revoke_request(ADMIN_DID, ALICE_DID, &["domain:a.example"]),
        )
        .await;
        let err = match outcome {
            DispatchOutcome::Rejected(e) => e,
            other => panic!("expected Rejected, got {other:?}"),
        };
        assert_eq!(
            err.payload.code,
            trust_tasks_rs::TrustTaskCode::Standard(StandardCode::MalformedRequest)
        );
    }
}
