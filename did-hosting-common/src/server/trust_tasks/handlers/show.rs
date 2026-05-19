//! `acl/show/0.1` handler — look up a single subject by VID.
//!
//! Spec contract (from `specs/acl/show/0.1/spec.md`):
//!
//! * Returns the canonical `AclEntry` for `payload.subject`, or
//!   `entry: null` when the subject is absent — "no such entry" is a
//!   successful response, not an error.
//! * Self-lookup convention: `issuer == payload.subject` is always
//!   permitted, even when broader policy denies general lookups. Our
//!   maintainer policy: Admin may look up anyone; non-Admin callers
//!   may only look up themselves.

use trust_tasks_rs::{
    ErrorPayload, ErrorResponse, ProofPolicy, ProofVerifier, ResolvedParties, StandardCode,
    TransportHandler, TrustTask, specs::acl::show::v0_1 as show,
};

use crate::server::acl::{self, AclEntry, Role};
use crate::server::trust_tasks::{
    DispatchOutcome, TrustTaskContext, entry::SpecAclEntry, reject_with, run_pipeline,
};

pub async fn handle<V>(
    ctx: &TrustTaskContext<'_>,
    transport: &(impl TransportHandler + Sync),
    policy: ProofPolicy<'_, V>,
    doc: TrustTask<show::Payload>,
) -> DispatchOutcome
where
    V: ProofVerifier + ?Sized,
{
    let acl_ks = ctx.acl_ks.clone();
    run_pipeline(
        transport,
        policy,
        doc,
        ctx.my_vid,
        move |doc, parties| async move { handle_inner(&acl_ks, doc, &parties).await },
    )
    .await
}

async fn handle_inner(
    acl_ks: &crate::server::store::KeyspaceHandle,
    doc: TrustTask<show::Payload>,
    parties: &ResolvedParties,
) -> Result<TrustTask<show::Response>, ErrorResponse> {
    let subject = (*doc.payload.subject).clone();
    let caller = parties.issuer.as_deref().ok_or_else(|| {
        reject_with(
            &doc,
            ErrorPayload::new(StandardCode::PermissionDenied)
                .with_message("inbound document has no in-band or transport-derived issuer"),
        )
    })?;
    let self_lookup = caller == subject;

    // Authorise: Admin may look up anyone; everyone else only
    // themselves.
    if !self_lookup {
        match acl::check_acl(acl_ks, caller).await {
            Ok(Role::Admin) => {}
            Ok(_) | Err(_) => {
                return Err(reject_with(
                    &doc,
                    ErrorPayload::new(StandardCode::PermissionDenied)
                        .with_message("only Admin callers may look up other subjects"),
                ));
            }
        }
    }

    let existing = acl::get_acl_entry(acl_ks, &subject)
        .await
        .map_err(|e| internal(&doc, e))?;

    let resp_entry = existing.as_ref().map(into_spec_entry);
    let resp_payload = show::Response {
        entry: resp_entry,
        ext: None,
        redacted_fields: Vec::new(),
    };
    let resp_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    Ok(doc.respond_with(resp_id, resp_payload))
}

fn into_spec_entry(local: &AclEntry) -> show::AclEntry {
    let neutral = SpecAclEntry::from_local(local);
    let value = serde_json::to_value(&neutral).expect("SpecAclEntry serialises");
    serde_json::from_value(value).expect("show::AclEntry from SpecAclEntry value")
}

fn internal<P>(doc: &TrustTask<P>, err: impl std::fmt::Display) -> ErrorResponse {
    tracing::error!(error = %err, "acl/show internal failure");
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

    const SERVICE_DID: &str = "did:web:maintainer.example";
    const ADMIN_DID: &str = "did:web:admin.example";
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
    fn no_verifier() -> ProofPolicy<'static, PanickingVerifier> {
        ProofPolicy::RejectIfPresent
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

    fn request(issuer_did: &str, subject: &str) -> TrustTask<show::Payload> {
        let payload = show::Payload {
            ext: None,
            subject: subject.to_string().try_into().expect("subject non-empty"),
        };
        let mut doc = TrustTask::for_payload(format!("urn:uuid:{}", uuid::Uuid::new_v4()), payload);
        doc.issuer = Some(issuer_did.into());
        doc.recipient = Some(SERVICE_DID.into());
        doc.issued_at = Some(chrono::Utc::now());
        doc
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

    #[tokio::test]
    async fn admin_lookup_returns_entry() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed(&acl_ks, ALICE_DID, Role::Owner).await;
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ADMIN_DID),
            no_verifier(),
            request(ADMIN_DID, ALICE_DID),
        )
        .await;
        let resp = match outcome {
            DispatchOutcome::Handled(d) => d,
            other => panic!("expected Handled, got {other:?}"),
        };
        assert_eq!(
            resp.type_uri.to_string(),
            format!("{}#response", show::Payload::TYPE_URI)
        );
        assert_eq!(resp.payload["entry"]["subject"], ALICE_DID);
        assert_eq!(resp.payload["entry"]["role"], "owner");
    }

    #[tokio::test]
    async fn missing_subject_returns_entry_null() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ADMIN_DID),
            no_verifier(),
            request(ADMIN_DID, "did:web:nobody.example"),
        )
        .await;
        let resp = match outcome {
            DispatchOutcome::Handled(d) => d,
            other => panic!("expected Handled, got {other:?}"),
        };
        assert_eq!(resp.payload["entry"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn self_lookup_permitted_for_non_admin() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed(&acl_ks, ALICE_DID, Role::Owner).await;
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ALICE_DID),
            no_verifier(),
            request(ALICE_DID, ALICE_DID),
        )
        .await;
        let resp = match outcome {
            DispatchOutcome::Handled(d) => d,
            other => panic!("expected Handled, got {other:?}"),
        };
        assert_eq!(resp.payload["entry"]["subject"], ALICE_DID);
    }

    #[tokio::test]
    async fn non_admin_lookup_of_other_rejected() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed(&acl_ks, ALICE_DID, Role::Owner).await;
        seed(&acl_ks, "did:web:bob.example", Role::Owner).await;
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ALICE_DID),
            no_verifier(),
            request(ALICE_DID, "did:web:bob.example"),
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
