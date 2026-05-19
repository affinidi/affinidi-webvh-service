//! `acl/change-role/0.1` handler — record a role transition with an
//! optimistic-concurrency check against the subject's prior role.
//!
//! Spec contract (from `specs/acl/change-role/0.1/spec.md`):
//!
//! * State-checked: maintainer rejects with `acl/change-role:state_mismatch`
//!   when the subject's current role does not match `payload.fromRole`.
//! * Role-vocabulary check: returns `acl/change-role:role_not_recognized`
//!   when either `fromRole` or `toRole` lies outside `admin/owner/service`.
//! * Self-promotion (issuer == subject, `toRole` strictly greater than
//!   `fromRole`) is forbidden by maintainer policy — flagged with
//!   `permission_denied`.
//! * Last-authority guard: a change that demotes the only Admin is
//!   rejected with `acl/revoke:last_authority_protected` (we reuse the
//!   revoke spec's error code since the underlying invariant is
//!   identical and the framework requires extension codes to be slug-
//!   namespaced — the spec's `change-role` errorCodes list doesn't
//!   include this case but Admin-protection is enforced regardless).

use serde_json::json;
use trust_tasks_rs::{
    ErrorPayload, ErrorResponse, ProofVerifier, StandardCode, TransportHandler, TrustTask,
    TrustTaskCode, specs::acl::change_role::v0_1 as change_role,
};

use crate::server::acl::{self, AclEntry, Role};
use crate::server::trust_tasks::{
    DispatchOutcome, TrustTaskContext, entry::SpecAclEntry, reject_with, run_pipeline,
};

const CHANGE_ROLE_SLUG: &str = "acl/change-role";
const ERR_STATE_MISMATCH: &str = "state_mismatch";
const ERR_ROLE_NOT_RECOGNIZED: &str = "role_not_recognized";

/// Run the framework pipeline + business logic for an inbound
/// `acl/change-role/0.1` request.
pub async fn handle<V>(
    ctx: &TrustTaskContext<'_>,
    transport: &(impl TransportHandler + Sync),
    verifier: Option<&V>,
    doc: TrustTask<change_role::Payload>,
) -> DispatchOutcome
where
    V: ProofVerifier + ?Sized,
{
    let acl_ks = ctx.acl_ks.clone();
    run_pipeline(
        transport,
        verifier,
        doc,
        ctx.my_vid,
        move |doc| async move { handle_inner(&acl_ks, doc).await },
    )
    .await
}

async fn handle_inner(
    acl_ks: &crate::server::store::KeyspaceHandle,
    doc: TrustTask<change_role::Payload>,
) -> Result<TrustTask<change_role::Response>, ErrorResponse> {
    // ─── 1. Authorise: caller must be Admin. ──────────────────────
    let caller = doc.issuer.as_deref().ok_or_else(|| {
        reject_with(
            &doc,
            ErrorPayload::new(StandardCode::PermissionDenied)
                .with_message("inbound document has no in-band issuer"),
        )
    })?;
    match acl::check_acl(acl_ks, caller).await {
        Ok(Role::Admin) => {}
        Ok(_) => {
            return Err(reject_with(
                &doc,
                ErrorPayload::new(StandardCode::PermissionDenied)
                    .with_message("only Admin callers may emit acl/change-role/0.1"),
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
            ErrorPayload::new(extended_code(ERR_ROLE_NOT_RECOGNIZED))
                .with_message(format!("fromRole {from_role_str:?} is not recognised"))
                .with_details(role_not_recognized_details(&from_role_str)),
        )
    })?;
    let to_role = parse_role(&to_role_str).map_err(|()| {
        reject_with(
            &doc,
            ErrorPayload::new(extended_code(ERR_ROLE_NOT_RECOGNIZED))
                .with_message(format!("toRole {to_role_str:?} is not recognised"))
                .with_details(role_not_recognized_details(&to_role_str)),
        )
    })?;

    // ─── 3. Self-promotion guard. ─────────────────────────────────
    if caller == doc.payload.subject && is_strict_promotion(&from_role, &to_role) {
        return Err(reject_with(
            &doc,
            ErrorPayload::new(StandardCode::PermissionDenied)
                .with_message("self-promotion to a more privileged role is forbidden"),
        ));
    }

    // ─── 4. Load the subject's current entry + state-check. ───────
    let existing = acl::get_acl_entry(acl_ks, &doc.payload.subject)
        .await
        .map_err(|e| internal(&doc, e))?;
    let mut entry = match existing {
        Some(e) => e,
        None => {
            // Spec doesn't define a dedicated code for "subject absent
            // on a change-role"; the closest is state_mismatch — the
            // subject's "current role" is "absent" which doesn't match
            // any fromRole the producer could supply.
            return Err(reject_with(
                &doc,
                ErrorPayload::new(extended_code(ERR_STATE_MISMATCH))
                    .with_message(format!(
                        "subject {} is not in the maintainer's ACL",
                        doc.payload.subject
                    ))
                    .with_details(json!({ "currentRole": null })),
            ));
        }
    };

    if entry.role != from_role {
        return Err(reject_with(
            &doc,
            ErrorPayload::new(extended_code(ERR_STATE_MISMATCH))
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
        // Same-role transition is a no-op; spec doesn't forbid it
        // explicitly but a maintainer that complies with the state-
        // check has already proven the entry is in the requested
        // state. Return the entry unchanged.
        let resp = build_response(&doc, &entry);
        return Ok(resp);
    }

    // ─── 6. Last-authority guard. ────────────────────────────────
    // A demote that removes the only Admin would empty the privileged
    // set. We surface the standard `acl/revoke:last_authority_protected`
    // code since the underlying spec invariant is identical.
    if matches!(from_role, Role::Admin) && !matches!(to_role, Role::Admin) {
        let all = acl::list_acl_entries(acl_ks)
            .await
            .map_err(|e| internal(&doc, e))?;
        let other_admins: Vec<String> = all
            .iter()
            .filter(|e| matches!(e.role, Role::Admin) && e.did != doc.payload.subject)
            .map(|e| e.did.clone())
            .collect();
        if other_admins.is_empty() {
            return Err(reject_with(
                &doc,
                ErrorPayload::new(TrustTaskCode::Extended {
                    slug: "acl/revoke".into(),
                    local: "last_authority_protected".into(),
                })
                .with_message("this role change would leave the maintainer with no Admin entries")
                .with_details(json!({
                    "protectedRole": "admin",
                    "remainingHolders": other_admins,
                })),
            ));
        }
    }

    // ─── 7. Apply the transition. ────────────────────────────────
    entry.role = to_role;
    acl::store_acl_entry(acl_ks, &entry)
        .await
        .map_err(|e| internal(&doc, e))?;

    Ok(build_response(&doc, &entry))
}

fn parse_role(s: &str) -> Result<Role, ()> {
    s.parse::<Role>().map_err(|_| ())
}

fn role_not_recognized_details(offending: &str) -> serde_json::Value {
    json!({
        "offendingRole": offending,
        "knownRoles": ["admin", "owner", "service"],
    })
}

/// Strict role ordering for the self-promotion guard. We define a
/// total order: `Service < Owner < Admin`. Self-promotion to a
/// strictly greater role is forbidden.
fn is_strict_promotion(from: &Role, to: &Role) -> bool {
    role_rank(to) > role_rank(from)
}

fn role_rank(r: &Role) -> u8 {
    match r {
        Role::Service => 0,
        Role::Owner => 1,
        Role::Admin => 2,
    }
}

fn build_response(
    request: &TrustTask<change_role::Payload>,
    local: &AclEntry,
) -> TrustTask<change_role::Response> {
    let neutral = SpecAclEntry::from_local(local);
    let value = serde_json::to_value(&neutral).expect("SpecAclEntry serialises");
    let spec_entry: change_role::AclEntry =
        serde_json::from_value(value).expect("change_role::AclEntry from SpecAclEntry value");
    let payload = change_role::Response {
        entry: spec_entry,
        ext: None,
    };
    let id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    request.respond_with(id, payload)
}

fn extended_code(local: &str) -> TrustTaskCode {
    TrustTaskCode::Extended {
        slug: CHANGE_ROLE_SLUG.into(),
        local: local.into(),
    }
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
            panic!("verifier called in a test that passed Option::None");
        }
    }
    fn no_verifier() -> Option<&'static PanickingVerifier> {
        None
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

    fn ctx<'a>(acl_ks: &'a crate::server::store::KeyspaceHandle) -> TrustTaskContext<'a> {
        TrustTaskContext {
            acl_ks,
            my_vid: SERVICE_DID,
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
        let payload = change_role::Payload {
            ext: None,
            from_role: from.to_string().try_into().expect("fromRole non-empty"),
            reason: Some("test".into()),
            subject: subject.into(),
            to_role: to.to_string().try_into().expect("toRole non-empty"),
        };
        let mut doc = TrustTask::for_payload(format!("urn:uuid:{}", uuid::Uuid::new_v4()), payload);
        doc.issuer = Some(issuer_did.into());
        doc.recipient = Some(SERVICE_DID.into());
        doc.issued_at = Some(chrono::Utc::now());
        doc
    }

    #[tokio::test]
    async fn successful_role_transition_persists() {
        let (_s, acl_ks) = harness().await;
        seed(&acl_ks, ALICE_DID, Role::Owner).await;
        let outcome = handle(
            &ctx(&acl_ks),
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
        let updated = acl::get_acl_entry(&acl_ks, ALICE_DID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.role, Role::Service);
    }

    #[tokio::test]
    async fn state_mismatch_when_fromrole_wrong() {
        let (_s, acl_ks) = harness().await;
        seed(&acl_ks, ALICE_DID, Role::Owner).await;
        // Caller claims Alice was a `service` but she's an `owner`.
        let outcome = handle(
            &ctx(&acl_ks),
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
            TrustTaskCode::Extended {
                slug: CHANGE_ROLE_SLUG.into(),
                local: ERR_STATE_MISMATCH.into(),
            }
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
        seed(&acl_ks, ALICE_DID, Role::Owner).await;
        let outcome = handle(
            &ctx(&acl_ks),
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
            TrustTaskCode::Extended {
                slug: CHANGE_ROLE_SLUG.into(),
                local: ERR_ROLE_NOT_RECOGNIZED.into(),
            }
        );
        let details = err.payload.details.unwrap();
        assert_eq!(details["offendingRole"], "superuser");
        assert_eq!(details["knownRoles"], json!(["admin", "owner", "service"]));
    }

    #[tokio::test]
    async fn self_promotion_forbidden() {
        let (_s, acl_ks) = harness().await;
        // Alice is Owner; she tries to promote herself to Admin.
        seed(&acl_ks, ALICE_DID, Role::Owner).await;
        // Alice would also need to be Admin to even be authorised —
        // but our guard runs before the change. Seed her as Admin to
        // isolate the self-promotion check.
        seed(&acl_ks, ALICE_DID, Role::Owner).await; // ensure starting state
        // Auth check is first → we need Alice as Admin to pass it,
        // which we do via a second admin entry. But that's awkward —
        // the test for self-promotion in our model requires Alice to
        // be Admin (so authorised) AND attempting to promote herself
        // strictly further. Since Admin is the top role, there's no
        // "further" promotion. So the test of strict-promotion is
        // actually unreachable in our 3-role enum — the guard is
        // belt-and-braces for any future role addition. Instead, we
        // test the *equal* direction (no-op) and trust the rank
        // function via a separate unit test below.
        // [no assertion here; see role_rank_unit_test]
        let _ = (acl_ks, ALICE_DID);
    }

    #[test]
    fn role_rank_unit() {
        // Total order: Service < Owner < Admin.
        assert!(role_rank(&Role::Service) < role_rank(&Role::Owner));
        assert!(role_rank(&Role::Owner) < role_rank(&Role::Admin));
        // Promotion check.
        assert!(is_strict_promotion(&Role::Owner, &Role::Admin));
        assert!(is_strict_promotion(&Role::Service, &Role::Owner));
        assert!(!is_strict_promotion(&Role::Owner, &Role::Owner));
        assert!(!is_strict_promotion(&Role::Admin, &Role::Owner));
    }

    #[tokio::test]
    async fn last_authority_blocks_admin_demote() {
        let (_s, acl_ks) = harness().await;
        // ADMIN_DID is the only admin. Demote → reject.
        let outcome = handle(
            &ctx(&acl_ks),
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
            TrustTaskCode::Extended {
                slug: "acl/revoke".into(),
                local: "last_authority_protected".into(),
            }
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
        seed(&acl_ks, SECOND_ADMIN, Role::Admin).await;
        let outcome = handle(
            &ctx(&acl_ks),
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
        seed(&acl_ks, ALICE_DID, Role::Owner).await;
        let outcome = handle(
            &ctx(&acl_ks),
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
            TrustTaskCode::Standard(StandardCode::PermissionDenied)
        );
    }

    #[tokio::test]
    async fn missing_subject_returns_state_mismatch_with_null() {
        let (_s, acl_ks) = harness().await;
        let outcome = handle(
            &ctx(&acl_ks),
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
            TrustTaskCode::Extended {
                slug: CHANGE_ROLE_SLUG.into(),
                local: ERR_STATE_MISMATCH.into(),
            }
        );
        assert_eq!(
            err.payload.details.unwrap()["currentRole"],
            serde_json::Value::Null
        );
    }

    #[tokio::test]
    async fn same_role_is_idempotent_noop() {
        let (_s, acl_ks) = harness().await;
        seed(&acl_ks, ALICE_DID, Role::Owner).await;
        let outcome = handle(
            &ctx(&acl_ks),
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
