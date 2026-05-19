//! `acl/list/0.1` handler — enumerate ACL entries with optional
//! filters and opaque-cursor paging.
//!
//! Spec contract (from `specs/acl/list/0.1/spec.md`):
//!
//! * Read-only; never mutates the ACL.
//! * Filters (`role`, `scope`, `subjectPrefix`) are conjunctive.
//!   Unrecognised filter values produce zero matches (NOT an error).
//! * `pageSize`: maintainer chooses default + ceiling. We use 50 /
//!   500. The spec's schema caps `pageSize` at 1000 — our ceiling
//!   stays under that for safety on large ACL tables.
//! * `cursor`: opaque to consumers. We encode `{offset: N}` as
//!   base64 of its JSON for stable bookmarking; future maintainers
//!   may change the inner shape without breaking clients (per spec
//!   "consumers MUST treat the cursor as opaque").
//! * `truncated` set to `true` when more matching entries exist;
//!   `cursor` carries the continuation token in that case.
//!
//! ## Why our cursor is a simple offset
//!
//! fjall's keyspace iteration is sorted by key; offsets are stable
//! across read-mostly workloads. A future maintainer with a
//! write-heavy ACL would swap this for a "last key seen" cursor —
//! the change is invisible to clients because the cursor is opaque.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use trust_tasks_rs::{
    ErrorPayload, ErrorResponse, ProofVerifier, StandardCode, TransportHandler, TrustTask,
    specs::acl::list::v0_1 as list,
};

use crate::server::acl::{self, AclEntry, Role};
use crate::server::trust_tasks::{
    DispatchOutcome, TrustTaskContext, entry::SpecAclEntry, reject_with, run_pipeline,
};

const DEFAULT_PAGE_SIZE: usize = 50;
const MAX_PAGE_SIZE: usize = 500;
const SCOPE_DOMAIN_PREFIX: &str = "domain:";

/// Internal cursor shape. Round-tripped via base64+JSON; opaque to
/// consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CursorState {
    offset: usize,
}

pub async fn handle<V>(
    ctx: &TrustTaskContext<'_>,
    transport: &(impl TransportHandler + Sync),
    verifier: Option<&V>,
    doc: TrustTask<list::Payload>,
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
    doc: TrustTask<list::Payload>,
) -> Result<TrustTask<list::Response>, ErrorResponse> {
    let caller = doc.issuer.as_deref().ok_or_else(|| {
        reject_with(
            &doc,
            ErrorPayload::new(StandardCode::PermissionDenied)
                .with_message("inbound document has no in-band issuer"),
        )
    })?;
    match acl::check_acl(acl_ks, caller).await {
        Ok(Role::Admin) => {}
        Ok(_) | Err(_) => {
            return Err(reject_with(
                &doc,
                ErrorPayload::new(StandardCode::PermissionDenied)
                    .with_message("only Admin callers may enumerate the ACL"),
            ));
        }
    }

    // Parse the cursor (if present).
    let start_offset = match doc.payload.cursor.as_deref() {
        Some(c) => decode_cursor(c).map_err(|msg| {
            reject_with(
                &doc,
                ErrorPayload::new(StandardCode::MalformedRequest).with_message(msg),
            )
        })?,
        None => 0usize,
    };

    let page_size = doc
        .payload
        .page_size
        .map(|n| (u64::from(n) as usize).min(MAX_PAGE_SIZE))
        .unwrap_or(DEFAULT_PAGE_SIZE);

    // Load every entry once. Acceptable for ACLs whose size is in the
    // 10s–1000s; a maintainer with millions of entries would push
    // filtering into the keyspace iteration. For now, simplicity wins.
    let all = acl::list_acl_entries(acl_ks)
        .await
        .map_err(|e| internal(&doc, e))?;

    // Filter conjunctively.
    let role_filter = doc.payload.role.as_deref().map(String::from);
    let scope_filter = doc.payload.scope.as_deref().map(String::from);
    let prefix_filter = doc.payload.subject_prefix.as_deref().map(String::from);

    let filtered: Vec<&AclEntry> = all
        .iter()
        .filter(|e| match &role_filter {
            Some(want) => e.role.to_string() == *want,
            None => true,
        })
        .filter(|e| match &scope_filter {
            Some(want) => entry_has_scope(e, want),
            None => true,
        })
        .filter(|e| match &prefix_filter {
            Some(want) => e.did.starts_with(want),
            None => true,
        })
        .collect();

    // Sort by subject DID for stable ordering across pages.
    let mut sorted = filtered;
    sorted.sort_by(|a, b| a.did.cmp(&b.did));

    let total_matching = sorted.len();
    let page: Vec<&AclEntry> = sorted
        .into_iter()
        .skip(start_offset)
        .take(page_size)
        .collect();
    let next_offset = start_offset + page.len();
    let truncated = next_offset < total_matching;
    let cursor = if truncated {
        Some(encode_cursor(next_offset))
    } else {
        None
    };

    let entries: Vec<list::AclEntry> = page.iter().map(|e| into_spec_entry(e)).collect();
    let resp_payload = list::Response {
        cursor,
        entries,
        ext: None,
        redacted_fields: Vec::new(),
        truncated,
    };
    let resp_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    Ok(doc.respond_with(resp_id, resp_payload))
}

fn entry_has_scope(entry: &AclEntry, want: &str) -> bool {
    // Match domain: prefixed filters against the entry's DomainScope.
    // `All`-scoped entries carry no scope strings on the wire — they
    // match by *role* rather than by enumerated scope — so a scope
    // filter against them returns false (the spec's "scopes filter"
    // is about the entries' opaque scope list, which `All` has none
    // of). Use the role filter to enumerate Admin / Service.
    if let Some(domain) = want.strip_prefix(SCOPE_DOMAIN_PREFIX) {
        return match &entry.domains {
            crate::server::domain::DomainScope::All => false,
            crate::server::domain::DomainScope::Allowed { domains } => {
                domains.iter().any(|d| d == domain)
            }
            crate::server::domain::DomainScope::AllowedWithDefault { domains, .. } => {
                domains.iter().any(|d| d == domain)
            }
        };
    }
    // Unrecognised filter prefix — spec says zero matches, not an error.
    false
}

fn into_spec_entry(local: &AclEntry) -> list::AclEntry {
    let neutral = SpecAclEntry::from_local(local);
    let value = serde_json::to_value(&neutral).expect("SpecAclEntry serialises");
    serde_json::from_value(value).expect("list::AclEntry from SpecAclEntry value")
}

fn encode_cursor(offset: usize) -> String {
    let state = CursorState { offset };
    let json = serde_json::to_vec(&state).expect("CursorState serialises");
    URL_SAFE_NO_PAD.encode(json)
}

fn decode_cursor(s: &str) -> Result<usize, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| format!("cursor is not valid base64url: {e}"))?;
    let state: CursorState =
        serde_json::from_slice(&bytes).map_err(|e| format!("cursor payload malformed: {e}"))?;
    Ok(state.offset)
}

fn internal<P>(doc: &TrustTask<P>, err: impl std::fmt::Display) -> ErrorResponse {
    tracing::error!(error = %err, "acl/list internal failure");
    reject_with(
        doc,
        ErrorPayload::new(StandardCode::InternalError)
            .with_message("the maintainer encountered an internal failure"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;
    use trust_tasks_rs::{Payload, VerificationError, handlers::InMemoryHandler};

    use crate::server::config::StoreConfig;
    use crate::server::domain::DomainScope;
    use crate::server::store::{KS_ACL, Store};

    const SERVICE_DID: &str = "did:web:maintainer.example";
    const ADMIN_DID: &str = "did:web:admin.example";

    struct PanickingVerifier;
    #[async_trait::async_trait]
    impl ProofVerifier for PanickingVerifier {
        async fn verify<P>(&self, _doc: &TrustTask<P>) -> Result<(), VerificationError>
        where
            P: serde::Serialize + Send + Sync,
        {
            panic!("unexpected verify");
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

    async fn seed_many(
        ks: &crate::server::store::KeyspaceHandle,
        prefix: &str,
        n: usize,
        role: Role,
    ) {
        for i in 0..n {
            acl::store_acl_entry(
                ks,
                &AclEntry {
                    did: format!("{prefix}{i:03}"),
                    role: role.clone(),
                    label: None,
                    created_at: 1_700_000_000,
                    max_total_size: None,
                    max_did_count: None,
                    domains: DomainScope::Allowed {
                        domains: vec!["a.example".into()],
                    },
                },
            )
            .await
            .unwrap();
        }
    }

    fn request(
        issuer_did: &str,
        page_size: Option<u64>,
        cursor: Option<&str>,
        role: Option<&str>,
        scope: Option<&str>,
        prefix: Option<&str>,
    ) -> TrustTask<list::Payload> {
        let payload = list::Payload {
            cursor: cursor.map(|s| s.to_string()),
            ext: None,
            page_size: page_size.and_then(NonZeroU64::new),
            role: role.map(|s| s.to_string().try_into().expect("role parses")),
            scope: scope.map(|s| s.to_string().try_into().expect("scope parses")),
            subject_prefix: prefix.map(|s| s.to_string().try_into().expect("prefix parses")),
        };
        let mut doc = TrustTask::for_payload(format!("urn:uuid:{}", uuid::Uuid::new_v4()), payload);
        doc.issuer = Some(issuer_did.into());
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
    async fn lists_all_when_no_filters() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed_many(&acl_ks, "did:web:o", 5, Role::Owner).await;

        let resp = unwrap_response(
            handle(
                &ctx(&acl_ks, &acl_locks),
                &transport(ADMIN_DID),
                no_verifier(),
                request(ADMIN_DID, None, None, None, None, None),
            )
            .await,
        );

        assert_eq!(
            resp.type_uri.to_string(),
            format!("{}#response", list::Payload::TYPE_URI)
        );
        let entries = resp.payload["entries"].as_array().unwrap();
        // 5 owners + 1 admin from harness
        assert_eq!(entries.len(), 6);
        assert_eq!(resp.payload["truncated"], false);
        assert!(resp.payload.get("cursor").is_none() || resp.payload["cursor"].is_null());
    }

    #[tokio::test]
    async fn role_filter_narrows_results() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed_many(&acl_ks, "did:web:o", 3, Role::Owner).await;
        seed_many(&acl_ks, "did:web:s", 2, Role::Service).await;

        let resp = unwrap_response(
            handle(
                &ctx(&acl_ks, &acl_locks),
                &transport(ADMIN_DID),
                no_verifier(),
                request(ADMIN_DID, None, None, Some("owner"), None, None),
            )
            .await,
        );
        let entries = resp.payload["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 3);
        for e in entries {
            assert_eq!(e["role"], "owner");
        }
    }

    #[tokio::test]
    async fn pagination_returns_cursor_and_truncated() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed_many(&acl_ks, "did:web:o", 12, Role::Owner).await;

        let resp1 = unwrap_response(
            handle(
                &ctx(&acl_ks, &acl_locks),
                &transport(ADMIN_DID),
                no_verifier(),
                request(ADMIN_DID, Some(5), None, Some("owner"), None, None),
            )
            .await,
        );
        let entries1 = resp1.payload["entries"].as_array().unwrap();
        assert_eq!(entries1.len(), 5);
        assert_eq!(resp1.payload["truncated"], true);
        let cursor1 = resp1.payload["cursor"].as_str().unwrap().to_string();

        let resp2 = unwrap_response(
            handle(
                &ctx(&acl_ks, &acl_locks),
                &transport(ADMIN_DID),
                no_verifier(),
                request(
                    ADMIN_DID,
                    Some(5),
                    Some(&cursor1),
                    Some("owner"),
                    None,
                    None,
                ),
            )
            .await,
        );
        let entries2 = resp2.payload["entries"].as_array().unwrap();
        assert_eq!(entries2.len(), 5);
        assert_eq!(resp2.payload["truncated"], true);

        let resp3 = unwrap_response(
            handle(
                &ctx(&acl_ks, &acl_locks),
                &transport(ADMIN_DID),
                no_verifier(),
                request(
                    ADMIN_DID,
                    Some(5),
                    resp2.payload["cursor"].as_str(),
                    Some("owner"),
                    None,
                    None,
                ),
            )
            .await,
        );
        let entries3 = resp3.payload["entries"].as_array().unwrap();
        assert_eq!(entries3.len(), 2);
        assert_eq!(resp3.payload["truncated"], false);

        // Sum of all pages == total matching, no duplicates.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for e in entries1
            .iter()
            .chain(entries2.iter())
            .chain(entries3.iter())
        {
            assert!(seen.insert(e["subject"].as_str().unwrap().into()), "dup");
        }
        assert_eq!(seen.len(), 12);
    }

    #[tokio::test]
    async fn unrecognised_scope_filter_returns_empty() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed_many(&acl_ks, "did:web:o", 3, Role::Owner).await;
        // `domain:nonexistent.example` should match nothing.
        let resp = unwrap_response(
            handle(
                &ctx(&acl_ks, &acl_locks),
                &transport(ADMIN_DID),
                no_verifier(),
                request(
                    ADMIN_DID,
                    None,
                    None,
                    None,
                    Some("domain:nonexistent.example"),
                    None,
                ),
            )
            .await,
        );
        let entries = resp.payload["entries"].as_array().unwrap();
        assert!(entries.is_empty());
        assert_eq!(resp.payload["truncated"], false);
    }

    #[tokio::test]
    async fn subject_prefix_filter() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed_many(&acl_ks, "did:web:o", 3, Role::Owner).await;
        seed_many(&acl_ks, "did:key:k", 4, Role::Owner).await;

        let resp = unwrap_response(
            handle(
                &ctx(&acl_ks, &acl_locks),
                &transport(ADMIN_DID),
                no_verifier(),
                request(ADMIN_DID, None, None, None, None, Some("did:key:")),
            )
            .await,
        );
        let entries = resp.payload["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 4);
        for e in entries {
            assert!(e["subject"].as_str().unwrap().starts_with("did:key:"));
        }
    }

    #[tokio::test]
    async fn malformed_cursor_rejected() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport(ADMIN_DID),
            no_verifier(),
            request(ADMIN_DID, None, Some("not-a-cursor!"), None, None, None),
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
    async fn non_admin_rejected() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        acl::store_acl_entry(
            &acl_ks,
            &AclEntry {
                did: "did:web:alice.example".into(),
                role: Role::Owner,
                label: None,
                created_at: 0,
                max_total_size: None,
                max_did_count: None,
                domains: DomainScope::All,
            },
        )
        .await
        .unwrap();
        let outcome = handle(
            &ctx(&acl_ks, &acl_locks),
            &transport("did:web:alice.example"),
            no_verifier(),
            request("did:web:alice.example", None, None, None, None, None),
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
