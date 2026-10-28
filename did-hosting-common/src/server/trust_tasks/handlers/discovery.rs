//! `trust-task-discovery/0.3` handler — advertise the set of Type URIs
//! this maintainer routes for.
//!
//! Nothing is advertised as `requiredExt`: with AclEntry 0.2 an entry's
//! domains are its `act` scope, and the `vnd.affinidi.webvh` namespace
//! carries only optional members (quota, default domain), so a producer
//! that omits it is accepted.
//!
//! Only 0.3 is served: the service speaks the latest version of each task
//! it serves. A discoverer that asks in 0.1 or 0.2 is refused
//! `unsupportedType` and may retry in 0.3.
//!
//! ## Why we use `DiscoveryRegistry::respond_to_v0_3`
//!
//! The trust-tasks-rs `DiscoveryRegistry` already encodes the
//! slug-glob matcher and lexicographic ordering. Wrapping it in our
//! pipeline keeps the §7.2 framework checks consistent with the ACL
//! handlers above. `frameworkVersion` is the registry's default: the
//! framework release the runtime targets, in its three-part form.

use trust_tasks_rs::{
    ErrorResponse, ProofPolicy, ProofVerifier, TransportHandler, TrustTask,
    discovery::DiscoveryRegistry, specs::trust_task_discovery::v0_3 as discovery,
};

use crate::server::trust_tasks::{DispatchOutcome, TrustTaskContext, run_pipeline};
use crate::tasks::acl::{
    change_role::v0_2 as change_role, grant::v0_2 as grant, list::v0_3 as list,
    revoke::v0_2 as revoke, show::v0_2 as show,
};

/// Build the [`DiscoveryRegistry`] this maintainer advertises.
///
/// Public so tests / docs / external callers can introspect what the
/// service announces without going through a wire round-trip.
pub fn registry() -> DiscoveryRegistry {
    DiscoveryRegistry::new()
        .with::<grant::Payload>()
        .with::<revoke::Payload>()
        .with::<change_role::Payload>()
        .with::<show::Payload>()
        .with::<list::Payload>()
        .with::<discovery::Payload>()
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
    // discoverers; we publish the full set.
    let response = registry().respond_to_v0_3(&doc.payload);
    let resp_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    Ok(doc.respond_with(resp_id, response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_tasks_rs::{Payload, VerificationError, handlers::InMemoryHandler};

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
        let payload: discovery::Payload = discovery::Payload::builder()
            .patterns(patterns)
            .try_into()
            .expect("test discovery payload is well formed");
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
            signing_oracle: false,
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
        assert_eq!(uris.len(), 6, "only the latest version of each: {uris:?}");
        // The framework release, in the three-part form 0.2+ requires.
        let fv = resp.payload["frameworkVersion"]
            .as_str()
            .expect("frameworkVersion");
        assert_eq!(fv.split('.').count(), 3, "{fv}");
    }

    #[tokio::test]
    async fn acl_pattern_returns_only_acl_types() {
        let (_dir, _store, ks) = ctx_storage().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let ctx = TrustTaskContext {
            acl_ks: &ks,
            acl_locks: &acl_locks,
            my_vid: SERVICE_DID,
            signing_oracle: false,
        };
        let resp =
            unwrap_response(handle(&ctx, &transport(), no_verifier(), request(&["acl/*"])).await);

        let types = resp.payload["supportedTypes"].as_array().unwrap();
        for t in types {
            let uri = t
                .as_str()
                .expect("no expanded entries: nothing requires ext");
            assert!(uri.contains("/spec/acl/"), "expected acl/* type, got {uri}");
        }
        // Five acl/* types.
        assert_eq!(types.len(), 5);
    }
}
