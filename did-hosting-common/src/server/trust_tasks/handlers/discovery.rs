//! `trust-task-discovery/0.1` handler — advertise the set of Type URIs
//! this maintainer routes for, plus per-type `requiredExt` annotations
//! so producers know our `vnd.affinidi.webvh` namespace is expected on
//! the entry-emitting operations.
//!
//! ## What we advertise as `requiredExt`
//!
//! `acl/grant/0.1` and `acl/change-role/0.1` produce or transition
//! entries; both touch the `domains` scope that lives in
//! `ext.vnd.affinidi.webvh`. Strictly the namespace is only required
//! for Owner entries (Admin/Service entries fall back to
//! `DomainScope::All`), but advertising it on these two types is the
//! safe hint to clients — a producer who populates it will always be
//! accepted, and an Admin-targeted grant that omits it still works.
//!
//! `acl/revoke/0.1`, `acl/show/0.1`, `acl/list/0.1`, and the
//! discovery spec itself do NOT require our namespace — they are
//! read-only or carry no entry — so we list them as plain Type URI
//! strings.
//!
//! ## Why we use `DiscoveryRegistry::respond_to`
//!
//! The trust-tasks-rs `DiscoveryRegistry` already encodes the
//! slug-glob matcher, requiredExt expansion, and lexicographic
//! ordering. Wrapping it in our pipeline keeps the §7.2 framework
//! checks consistent with the ACL handlers above.

use trust_tasks_rs::{
    ErrorResponse, Payload, ProofPolicy, ProofVerifier, TransportHandler, TrustTask,
    discovery::DiscoveryRegistry,
    specs::{
        acl::{
            change_role::v0_1 as change_role, grant::v0_1 as grant, list::v0_1 as list,
            revoke::v0_1 as revoke, show::v0_1 as show,
        },
        trust_task_discovery::v0_1 as discovery,
    },
};

use crate::server::trust_tasks::{
    DispatchOutcome, TrustTaskContext, ext::WEBVH_EXT_KEY, run_pipeline,
};

/// Build the [`DiscoveryRegistry`] this maintainer advertises.
///
/// Public so tests / docs / external callers can introspect what the
/// service announces without going through a wire round-trip.
pub fn registry() -> DiscoveryRegistry {
    let mut reg = DiscoveryRegistry::new()
        .framework_version("0.1")
        .with::<grant::Payload>()
        .with::<revoke::Payload>()
        .with::<change_role::Payload>()
        .with::<show::Payload>()
        .with::<list::Payload>()
        .with::<discovery::Payload>();

    // Annotate the two entry-emitting types so producers know to
    // include our namespace.
    reg.require_ext(grant::Payload::type_uri(), [WEBVH_EXT_KEY]);
    reg.require_ext(change_role::Payload::type_uri(), [WEBVH_EXT_KEY]);
    reg
}

pub async fn handle<V>(
    ctx: &TrustTaskContext<'_>,
    transport: &(impl TransportHandler + Sync),
    policy: ProofPolicy<'_, V>,
    doc: TrustTask<discovery::Payload>,
) -> DispatchOutcome
where
    V: ProofVerifier + ?Sized,
{
    run_pipeline(
        transport,
        policy,
        doc,
        ctx.my_vid,
        |doc, _parties| async move { handle_inner(doc).await },
    )
    .await
}

async fn handle_inner(
    doc: TrustTask<discovery::Payload>,
) -> Result<TrustTask<discovery::Response>, ErrorResponse> {
    // No auth check: discovery is non-authoritative metadata. SPEC.md
    // §11 + the spec's Privacy considerations note that a maintainer
    // MAY return a filtered subset (or no response) for unknown
    // discoverers; for v0.7.0 we publish the full set. A future tighten
    // (admin-only discovery) lands as a thin wrapper that checks the
    // ACL before calling registry().respond_to.
    let response = registry().respond_to(&doc.payload);
    let resp_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    Ok(doc.respond_with(resp_id, response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_tasks_rs::{
        Payload, VerificationError, handlers::InMemoryHandler,
        specs::trust_task_discovery::v0_1::ResponseSupportedTypesItem,
    };

    const SERVICE_DID: &str = "did:web:maintainer.example";
    const CALLER_DID: &str = "did:web:caller.example";

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

    // Discovery doesn't touch the ACL store, but the harness type
    // requires a KeyspaceHandle so we point at a throwaway tempdir.
    async fn ctx_storage() -> (
        tempfile::TempDir,
        crate::server::store::Store,
        crate::server::store::KeyspaceHandle,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = crate::server::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..Default::default()
        };
        let store = crate::server::store::Store::open(&cfg).await.expect("open");
        let ks = store
            .keyspace(crate::server::store::KS_ACL)
            .expect("acl ks");
        (dir, store, ks)
    }

    fn transport() -> InMemoryHandler {
        InMemoryHandler::new()
            .with_local(SERVICE_DID.to_string())
            .with_peer(CALLER_DID.to_string())
    }

    fn request(patterns: &[&str]) -> TrustTask<discovery::Payload> {
        let patterns: Vec<discovery::PayloadPatternsItem> = patterns
            .iter()
            .map(|p| (*p).to_string().try_into().expect("pattern parses"))
            .collect();
        let payload = discovery::Payload { patterns };
        let mut doc = TrustTask::for_payload(format!("urn:uuid:{}", uuid::Uuid::new_v4()), payload);
        doc.issuer = Some(CALLER_DID.into());
        doc.recipient = Some(SERVICE_DID.into());
        doc.issued_at = Some(chrono::Utc::now());
        doc
    }

    fn unwrap_response(outcome: DispatchOutcome) -> TrustTask<serde_json::Value> {
        match outcome {
            DispatchOutcome::Handled(d) => d,
            other => panic!("expected Handled, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_patterns_returns_all_six_types() {
        let (_dir, _store, ks) = ctx_storage().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let ctx = TrustTaskContext {
            acl_ks: &ks,
            acl_locks: &acl_locks,
            my_vid: SERVICE_DID,
        };
        let resp = unwrap_response(handle(&ctx, &transport(), no_verifier(), request(&[])).await);
        assert_eq!(
            resp.type_uri.to_string(),
            format!("{}#response", discovery::Payload::TYPE_URI)
        );

        let types = resp.payload["supportedTypes"]
            .as_array()
            .expect("supportedTypes is array");
        let uris: Vec<String> = types
            .iter()
            .map(|t| match t {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Object(o) => o["type"].as_str().unwrap().to_string(),
                _ => panic!("unexpected entry shape: {t}"),
            })
            .collect();
        for expected in [
            grant::Payload::TYPE_URI,
            revoke::Payload::TYPE_URI,
            change_role::Payload::TYPE_URI,
            show::Payload::TYPE_URI,
            list::Payload::TYPE_URI,
            discovery::Payload::TYPE_URI,
        ] {
            assert!(
                uris.iter().any(|u| u == expected),
                "missing {expected} in {uris:?}"
            );
        }
        assert_eq!(resp.payload["frameworkVersion"], "0.1");
    }

    #[tokio::test]
    async fn acl_pattern_returns_only_acl_types() {
        let (_dir, _store, ks) = ctx_storage().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let ctx = TrustTaskContext {
            acl_ks: &ks,
            acl_locks: &acl_locks,
            my_vid: SERVICE_DID,
        };
        let resp =
            unwrap_response(handle(&ctx, &transport(), no_verifier(), request(&["acl/*"])).await);

        let types = resp.payload["supportedTypes"].as_array().unwrap();
        for t in types {
            let uri = match t {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Object(o) => o["type"].as_str().unwrap().to_string(),
                _ => panic!(),
            };
            assert!(uri.contains("/spec/acl/"), "expected acl/* type, got {uri}");
        }
        // Five acl/* types.
        assert_eq!(types.len(), 5);
    }

    #[tokio::test]
    async fn grant_advertises_required_ext_namespace() {
        let (_dir, _store, ks) = ctx_storage().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let ctx = TrustTaskContext {
            acl_ks: &ks,
            acl_locks: &acl_locks,
            my_vid: SERVICE_DID,
        };
        let resp = unwrap_response(
            handle(&ctx, &transport(), no_verifier(), request(&["acl/grant"])).await,
        );
        let types = resp.payload["supportedTypes"].as_array().unwrap();
        assert_eq!(types.len(), 1);
        let entry = &types[0];
        // Expanded form with requiredExt
        assert!(
            entry.is_object(),
            "expanded entry expected for grant: {entry}"
        );
        assert_eq!(entry["type"], grant::Payload::TYPE_URI);
        assert_eq!(entry["requiredExt"], serde_json::json!([WEBVH_EXT_KEY]));
    }

    #[test]
    fn registry_includes_change_role_required_ext() {
        let reg = registry();
        let resp = reg.respond_to(&discovery::Payload {
            patterns: vec!["acl/change-role".to_string().try_into().unwrap()],
        });
        assert_eq!(resp.supported_types.len(), 1);
        match &resp.supported_types[0] {
            ResponseSupportedTypesItem::Object {
                type_,
                required_ext,
            } => {
                assert_eq!(type_, change_role::Payload::TYPE_URI);
                let ext = required_ext.as_ref().expect("change-role has requiredExt");
                assert!(ext.iter().any(|n| **n == *WEBVH_EXT_KEY));
            }
            other => panic!("expected expanded form, got {other:?}"),
        }
    }
}
