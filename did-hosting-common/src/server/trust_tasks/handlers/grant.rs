//! `acl/grant/0.1` handler — admin records that a subject has been
//! added to the ACL with a named role and optional scopes.
//!
//! Spec contract (from `specs/acl/grant/0.1/spec.md`):
//!
//! 1. **Idempotent**. Re-emitting an identical grant against an
//!    unchanged ACL produces no state change.
//! 2. A grant that **changes** an existing subject's role MUST NOT use
//!    this task; respond with `permission_denied` plus `details.reason`
//!    pointing to `acl/change-role/0.1`. We attach a richer `details`
//!    body so clients can auto-recover.
//! 3. On acceptance, persist the document as the evidentiary record
//!    and return the canonical resulting [`AclEntry`].

use serde_json::json;
use trust_tasks_rs::{
    ErrorPayload, ErrorResponse, ProofVerifier, StandardCode, TransportHandler, TrustTask,
    specs::acl::grant::v0_1 as grant,
};

use crate::server::acl::{self, AclEntry, Role};
use crate::server::auth::session::now_epoch;
use crate::server::trust_tasks::{
    DispatchOutcome, TrustTaskContext, entry::SpecAclEntry, reject_with, run_pipeline,
};

/// Run the framework pipeline + business logic for an inbound
/// `acl/grant/0.1` request.
pub async fn handle<V>(
    ctx: &TrustTaskContext<'_>,
    transport: &(impl TransportHandler + Sync),
    verifier: Option<&V>,
    doc: TrustTask<grant::Payload>,
) -> DispatchOutcome
where
    V: ProofVerifier + ?Sized,
{
    let acl_ks = ctx.acl_ks.clone();
    let my_vid = ctx.my_vid.to_string();
    run_pipeline(
        transport,
        verifier,
        doc,
        ctx.my_vid,
        move |doc| async move { handle_inner(&acl_ks, &my_vid, doc).await },
    )
    .await
}

async fn handle_inner(
    acl_ks: &crate::server::store::KeyspaceHandle,
    _my_vid: &str,
    doc: TrustTask<grant::Payload>,
) -> Result<TrustTask<grant::Response>, ErrorResponse> {
    // ─── 1. Authorise the caller. ──────────────────────────────────
    // The framework has already validated identity (in-band issuer
    // matches transport-derived sender, proof verified, ...). We need
    // to additionally check the maintainer-side policy: only Admin
    // entries in our own ACL may grant.
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
                    .with_message("only Admin callers may emit acl/grant/0.1"),
            ));
        }
        Err(_) => {
            // Not in ACL at all.
            return Err(reject_with(
                &doc,
                ErrorPayload::new(StandardCode::PermissionDenied)
                    .with_message("caller is not present in the maintainer's ACL"),
            ));
        }
    }

    // ─── 2. Translate the proposed entry to our local shape. ──────
    let proposed = into_local_entry(&doc.payload.entry).map_err(|msg| {
        reject_with(
            &doc,
            ErrorPayload::new(StandardCode::MalformedRequest).with_message(msg),
        )
    })?;

    // ─── 3. Spec invariants on the proposed entry shape. ──────────
    // The spec models scopes as an opaque string array (e.g.
    // `["context:project-alpha"]`). We don't model webvh's domain
    // scope through `scopes` — it lives in
    // `ext.vnd.affinidi.webvh.domains`. A grant carrying an opaque
    // `scopes` array confuses the wire form (which scope binds?), so
    // we refuse it for now. acl/revoke is welcome to carry `scopes`
    // for scope-reduction; on grant, hold the line.
    if !doc.payload.entry.scopes.is_empty() {
        return Err(reject_with(
            &doc,
            ErrorPayload::new(StandardCode::MalformedRequest).with_message(
                "acl/grant/0.1 with `scopes` is not supported by this maintainer — \
                 use `ext.vnd.affinidi.webvh.domains` for per-entry domain scope",
            ),
        ));
    }

    // ─── 4. Apply the spec's idempotent-insert / role-change rules. ─
    let existing = acl::get_acl_entry(acl_ks, &proposed.did)
        .await
        .map_err(|e| internal(&doc, e))?;

    let realized = match existing {
        Some(current) if current.role == proposed.role => {
            // Idempotent: spec §3 — re-emitting an identical grant
            // produces no state change. We return the maintainer's
            // canonical entry verbatim, which may include createdAt,
            // createdBy, etc the producer did not supply.
            current
        }
        Some(current) => {
            return Err(reject_with(
                &doc,
                ErrorPayload::new(StandardCode::PermissionDenied)
                    .with_message(
                        "subject already exists with a different role; role changes must use \
                         acl/change-role/0.1",
                    )
                    .with_details(json!({
                        "reason": "role_change_required",
                        "existingRole": current.role.to_string(),
                        "proposedRole": proposed.role.to_string(),
                        "suggestedTask": "https://trusttasks.org/spec/acl/change-role/0.1"
                    })),
            ));
        }
        None => {
            // Persist the new entry; the maintainer fills in createdAt
            // / createdBy from the request metadata.
            let mut entry = proposed;
            entry.created_at = now_epoch();
            acl::store_acl_entry(acl_ks, &entry)
                .await
                .map_err(|e| internal(&doc, e))?;
            entry
        }
    };

    // ─── 5. Build the response document. ──────────────────────────
    let resp_entry = into_spec_entry(&realized);
    let resp_payload = grant::Response {
        entry: resp_entry,
        ext: None,
    };
    let resp_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    Ok(doc.respond_with(resp_id, resp_payload))
}

/// `grant::AclEntry` → local [`AclEntry`].
///
/// Routes the spec-typed entry through the neutral [`SpecAclEntry`]
/// shape (same JSON, no per-spec Rust-type duplication). Returns
/// `Err(message)` on translation failure — caller wraps as
/// `MalformedRequest`.
fn into_local_entry(spec: &grant::AclEntry) -> Result<AclEntry, String> {
    let value = serde_json::to_value(spec).map_err(|e| format!("entry serialises: {e}"))?;
    let neutral: SpecAclEntry =
        serde_json::from_value(value).map_err(|e| format!("entry round-trip: {e}"))?;
    // created_at_fallback = 0 here so absent createdAt surfaces as 0
    // (the legacy "no timestamp" sentinel). handle_inner overwrites
    // with now_epoch() at insert time.
    neutral.into_local(0).map_err(|e| e.to_string())
}

/// Local [`AclEntry`] → `grant::AclEntry` (the canonical response
/// form).
fn into_spec_entry(local: &AclEntry) -> grant::AclEntry {
    let neutral = SpecAclEntry::from_local(local);
    let value = serde_json::to_value(&neutral).expect("SpecAclEntry serialises");
    serde_json::from_value(value).expect("grant::AclEntry from SpecAclEntry value")
}

fn internal<P>(doc: &TrustTask<P>, err: impl std::fmt::Display) -> ErrorResponse {
    // Internal failures (fjall I/O, JSON shape bugs, …) collapse to
    // `internal_error` on the wire. Operator detail stays in the log
    // stream rather than leaking into the response.
    tracing::error!(error = %err, "acl/grant internal failure");
    reject_with(
        doc,
        ErrorPayload::new(StandardCode::InternalError)
            .with_message("the maintainer encountered an internal failure"),
    )
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

    /// Test-only [`ProofVerifier`] used to pin the generic `V` type on
    /// the handler when we pass `Option::<&_>::None`. `verify` panics
    /// because the pipeline does not invoke the verifier when the
    /// `Option` is `None` — if this ever runs, the test setup is wrong.
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

    /// Build a typed `acl/grant/0.1` request document with `payload.entry`
    /// for `subject` at `role`, the issuer pinned to `issuer_did`, and
    /// recipient pinned to `SERVICE_DID`.
    fn grant_request(issuer_did: &str, subject: &str, role: &str) -> TrustTask<grant::Payload> {
        let entry = grant::AclEntry {
            subject: subject.into(),
            role: role.into(),
            scopes: vec![],
            label: Some("test entry".into()),
            created_at: None,
            created_by: None,
            updated_at: None,
            updated_by: None,
            expires_at: None,
            // Owner needs domains; we always supply it via the webvh ext
            // so the entry handler accepts it on translate.
            ext: serde_json::from_value(serde_json::json!({
                WEBVH_EXT_KEY: { "domains": { "kind": "all" } }
            }))
            .unwrap(),
        };
        let payload = grant::Payload {
            entry,
            ext: None,
            reason: Some("integration test grant".into()),
        };
        let mut doc = TrustTask::for_payload(format!("urn:uuid:{}", uuid::Uuid::new_v4()), payload);
        doc.issuer = Some(issuer_did.into());
        doc.recipient = Some(SERVICE_DID.into());
        doc.issued_at = Some(chrono::Utc::now());
        doc
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

    #[tokio::test]
    async fn fresh_grant_inserts_and_returns_realized_entry() {
        let (_store, acl_ks) = harness().await;
        let ctx = ctx(&acl_ks);
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
        // Maintainer-filled fields: createdAt set to now.
        assert!(entry_value.get("createdAt").is_some());
        // Vendor ext round-tripped.
        assert_eq!(entry_value["ext"][WEBVH_EXT_KEY]["domains"]["kind"], "all");

        let stored = acl::get_acl_entry(&acl_ks, ALICE_DID).await.unwrap();
        assert!(stored.is_some());
        assert_eq!(stored.unwrap().role, Role::Owner);
    }

    #[tokio::test]
    async fn idempotent_regrant_returns_existing_entry() {
        let (_store, acl_ks) = harness().await;
        let ctx = ctx(&acl_ks);
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
        let ctx = ctx(&acl_ks);
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
            "https://trusttasks.org/spec/acl/change-role/0.1"
        );
    }

    #[tokio::test]
    async fn non_admin_caller_rejected() {
        let (_store, acl_ks) = harness().await;
        let ctx = ctx(&acl_ks);

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

    #[tokio::test]
    async fn opaque_scopes_on_grant_rejected_as_malformed() {
        let (_store, acl_ks) = harness().await;
        let ctx = ctx(&acl_ks);
        let transport = transport(ADMIN_DID);

        let mut doc = grant_request(ADMIN_DID, ALICE_DID, "owner");
        doc.payload.entry.scopes = vec!["context:project-alpha".into()];

        let outcome = handle(&ctx, &transport, no_verifier(), doc).await;
        let err = match outcome {
            DispatchOutcome::Rejected(e) => e,
            other => panic!("expected Rejected, got {other:?}"),
        };
        assert_eq!(
            err.payload.code,
            trust_tasks_rs::TrustTaskCode::Standard(StandardCode::MalformedRequest)
        );
        // No partial write — Alice never landed.
        assert!(
            acl::get_acl_entry(&acl_ks, ALICE_DID)
                .await
                .unwrap()
                .is_none()
        );
    }
}
