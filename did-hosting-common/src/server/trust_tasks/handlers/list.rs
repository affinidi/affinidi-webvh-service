//! `acl/list/0.3` handler — enumerate ACL entries with optional
//! filters and opaque-cursor paging.
//!
//! Spec contract (`specs/acl/list/0.3/spec.md`, consumer items):
//!
//! * Read-only; only an `Admin` may enumerate (this maintainer has no
//!   approvers, so no entry's approve scope reaches anyone else).
//! * A `context` or `resource` filter without `direction`, or a `direction`
//!   with neither, is `malformedRequest`; there is no default direction.
//! * Filters are conjunctive. An entry's contexts are its domains (see
//!   [`super::super::entry`]), and they are flat, so for a queried domain:
//!   `actingIn` matches an entry whose act scope is `all` or names it;
//!   `subtree` matches an entry that names it (an unrestricted entry is not
//!   a grant *of* the domain); `any` matches either.
//! * `capability` and `resource` are evaluated against an entry's effective
//!   capabilities. This maintainer recognises no capability and qualifies
//!   none, so either filter matches nothing — an unrecognised filter value is
//!   zero matches, not an error.
//! * `limit`: the maintainer chooses default + ceiling (50 / 500; the schema
//!   caps it at 1000). `nextCursor` is present if, and only if, more matching
//!   entries remain.
//! * The cursor binds the filters and `direction` it was minted under; one
//!   resumed under any other is `cursorMismatch`.
//!
//! ## Why the cursor encodes `last_seen` rather than an offset
//!
//! Entries are returned in sorted-by-`did` order. With a positional
//! offset cursor (`{offset: N}`), a delete of an entry before the
//! cursor would shift every subsequent entry's index — the next
//! page would silently skip one row. An add at the same place would
//! repeat one. Encoding the last subject DID we returned makes
//! pagination stable: the next page starts at the first row whose
//! `did > last_seen`.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use trust_tasks_rs::{
    ErrorPayload, ErrorResponse, ProofPolicy, ProofVerifier, ResolvedParties, StandardCode,
    TransportHandler, TrustTask,
};

use crate::server::acl::{self, AclEntry, Role};
use crate::server::trust_tasks::entry::{AuthorityScope, SpecAclEntry, act_of};
use crate::server::trust_tasks::{DispatchOutcome, TrustTaskContext, reject_with, run_pipeline};
use crate::tasks::acl::list::v0_3 as list;

const DEFAULT_PAGE_SIZE: usize = 50;
const MAX_PAGE_SIZE: usize = 500;

/// Internal cursor shape, opaque to consumers: the subject DID of the last
/// entry on the previous page, and the filters the cursor was minted under.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CursorState {
    /// Last subject DID returned in the previous page. The next page
    /// begins at the first entry whose `did > last_seen`.
    last_seen: String,
    /// [`Filters::binding`] of the request that minted the cursor.
    filters: String,
}

/// The request's filters, as one value the cursor can bind.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Filters {
    role: Option<String>,
    subject_prefix: Option<String>,
    context: Option<String>,
    capability: Option<String>,
    resource: Option<String>,
    direction: Option<String>,
}

impl Filters {
    fn of(p: &list::Payload) -> Self {
        Self {
            role: p.role.as_deref().map(String::from),
            subject_prefix: p.subject_prefix.as_deref().map(String::from),
            context: p.context.as_deref().map(String::from),
            capability: p.capability.as_deref().map(String::from),
            resource: p.resource.as_deref().map(String::from),
            direction: p.direction.map(|d| d.to_string()),
        }
    }

    fn binding(&self) -> String {
        serde_json::to_string(self).expect("Filters serialises")
    }
}

pub async fn handle<V>(
    ctx: &TrustTaskContext<'_>,
    transport: &(impl TransportHandler + Sync),
    policy: ProofPolicy<'_, V>,
    doc: TrustTask<list::Payload>,
) -> DispatchOutcome
where
    V: ProofVerifier + ?Sized,
{
    let acl_ks = ctx.acl_ks.clone();
    let signing_oracle = ctx.signing_oracle;
    run_pipeline(
        transport,
        policy,
        doc,
        ctx.my_vid,
        move |doc, parties| async move {
            handle_inner(&acl_ks, doc, &parties, signing_oracle).await
        },
    )
    .await
}

async fn handle_inner(
    acl_ks: &crate::server::store::KeyspaceHandle,
    doc: TrustTask<list::Payload>,
    parties: &ResolvedParties,
    signing_oracle: bool,
) -> Result<TrustTask<list::Response>, ErrorResponse> {
    let caller = parties.issuer.as_deref().ok_or_else(|| {
        reject_with(
            &doc,
            ErrorPayload::new(StandardCode::PermissionDenied)
                .with_message("inbound document has no in-band or transport-derived issuer"),
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

    let filters = Filters::of(&doc.payload);
    let hierarchical = filters.context.is_some() || filters.resource.is_some();
    match (hierarchical, filters.direction.is_some()) {
        (true, false) => {
            return Err(reject_with(
                &doc,
                ErrorPayload::new(StandardCode::MalformedRequest).with_message(
                    "a `context` or `resource` filter needs a `direction`: one of `actingIn`, \
                     `subtree`, `any`",
                ),
            ));
        }
        (false, true) => {
            return Err(reject_with(
                &doc,
                ErrorPayload::new(StandardCode::MalformedRequest)
                    .with_message("`direction` applies only with a `context` or `resource` filter"),
            ));
        }
        _ => {}
    }

    // Parse the cursor (if present) and hold it to the filters it was
    // minted under.
    let last_seen = match doc.payload.cursor.as_deref() {
        Some(c) => {
            let state = decode_cursor(c).map_err(|msg| {
                reject_with(
                    &doc,
                    ErrorPayload::new(StandardCode::MalformedRequest).with_message(msg),
                )
            })?;
            if state.filters != filters.binding() {
                return Err(reject_with(
                    &doc,
                    ErrorPayload::from(list::error_codes::CURSOR_MISMATCH)
                        .with_message("the cursor was issued for different filters or direction"),
                ));
            }
            Some(state.last_seen)
        }
        None => None,
    };

    let page_size = doc
        .payload
        .limit
        .map(|n| (n.get() as usize).min(MAX_PAGE_SIZE))
        .unwrap_or(DEFAULT_PAGE_SIZE);

    // Load every entry once. Acceptable for ACLs whose size is in the
    // 10s–1000s; a maintainer with millions of entries would push
    // filtering into the keyspace iteration. For now, simplicity wins.
    let all = acl::list_acl_entries(acl_ks)
        .await
        .map_err(|e| internal(&doc, e))?;

    let mut sorted: Vec<&AclEntry> = all.iter().filter(|e| matches(e, &filters)).collect();
    // Sort by subject DID for stable ordering across pages — the
    // `last_seen` cursor relies on this monotonic order.
    sorted.sort_by(|a, b| a.did.cmp(&b.did));

    let page: Vec<&AclEntry> = match last_seen.as_deref() {
        Some(last) => sorted
            .into_iter()
            .skip_while(|e| e.did.as_str() <= last)
            .take(page_size + 1)
            .collect(),
        None => sorted.into_iter().take(page_size + 1).collect(),
    };
    // `take(page_size + 1)` lets us look one entry past the page end:
    // if we got one more than we asked for, more remain.
    let has_more = page.len() > page_size;
    let page: Vec<&AclEntry> = page.into_iter().take(page_size).collect();
    let next_cursor = if has_more {
        page.last().map(|e| encode_cursor(&e.did, &filters))
    } else {
        None
    };

    let entries: Vec<list::AclEntry> = page
        .iter()
        .map(|e| SpecAclEntry::from_local(e, signing_oracle).into_spec())
        .collect();
    let next_cursor = next_cursor
        .map(|c| c.parse::<list::ResponseNextCursor>())
        .transpose()
        .map_err(|e| internal(&doc, e))?;
    // The generated payload types are `#[non_exhaustive]`: built through the
    // generated builder, whose `try_into` can only fail on a field left unset.
    let resp_payload: list::Response = list::Response::builder()
        .entries(entries)
        .next_cursor(next_cursor)
        .redacted_fields(Vec::new())
        .try_into()
        .expect("list response has every required field set");
    let resp_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    Ok(doc.respond_with(resp_id, resp_payload))
}

/// Whether `entry` matches every filter in `f`.
fn matches(entry: &AclEntry, f: &Filters) -> bool {
    if f.role
        .as_deref()
        .is_some_and(|r| entry.role.to_string() != r)
    {
        return false;
    }
    if f.subject_prefix
        .as_deref()
        .is_some_and(|p| !entry.did.starts_with(p))
    {
        return false;
    }
    // No capability is recognised and none is qualified: these filters
    // match nothing.
    if f.capability.is_some() || f.resource.is_some() {
        return false;
    }
    if let Some(context) = f.context.as_deref() {
        let act = act_of(entry);
        let names_it = matches!(&act, AuthorityScope::Contexts { contexts } if contexts.iter().any(|c| c == context));
        let unrestricted = act == AuthorityScope::All;
        let hit = match f.direction.as_deref() {
            Some("actingIn") => unrestricted || names_it,
            Some("subtree") => names_it,
            Some("any") => unrestricted || names_it,
            _ => false,
        };
        if !hit {
            return false;
        }
    }
    true
}

fn encode_cursor(last_seen: &str, filters: &Filters) -> String {
    let state = CursorState {
        last_seen: last_seen.to_string(),
        filters: filters.binding(),
    };
    let json = serde_json::to_vec(&state).expect("CursorState serialises");
    URL_SAFE_NO_PAD.encode(json)
}

fn decode_cursor(s: &str) -> Result<CursorState, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| "the cursor was not issued by this maintainer".to_string())?;
    serde_json::from_slice(&bytes)
        .map_err(|_| "the cursor was not issued by this maintainer".to_string())
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
            signing_oracle: false,
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

    /// `context` is `(context, direction)`.
    fn request(
        issuer_did: &str,
        limit: Option<u64>,
        cursor: Option<&str>,
        role: Option<&str>,
        context: Option<(&str, &str)>,
        prefix: Option<&str>,
    ) -> TrustTask<list::Payload> {
        let mut payload = serde_json::json!({});
        if let Some(n) = limit {
            payload["limit"] = n.into();
        }
        if let Some(c) = cursor {
            payload["cursor"] = c.into();
        }
        if let Some(r) = role {
            payload["role"] = r.into();
        }
        if let Some((c, d)) = context {
            payload["context"] = c.into();
            payload["direction"] = d.into();
        }
        if let Some(p) = prefix {
            payload["subjectPrefix"] = p.into();
        }
        request_with(issuer_did, payload)
    }

    fn request_with(issuer_did: &str, payload: serde_json::Value) -> TrustTask<list::Payload> {
        let payload: list::Payload =
            serde_json::from_value(payload).expect("test list payload is well formed");
        let mut doc = TrustTask::for_payload(format!("urn:uuid:{}", uuid::Uuid::new_v4()), payload);
        doc.issuer = Some(issuer_did.into());
        doc.recipient = Some(SERVICE_DID.into());
        doc.issued_at = Some(chrono::Utc::now());
        doc
    }

    async fn list(
        acl_ks: &crate::server::store::KeyspaceHandle,
        doc: TrustTask<list::Payload>,
    ) -> DispatchOutcome {
        let acl_locks = crate::server::path_locks::PathLocks::new();
        handle(
            &ctx(acl_ks, &acl_locks),
            &transport(ADMIN_DID),
            no_verifier(),
            doc,
        )
        .await
    }

    fn rejected(outcome: DispatchOutcome) -> ErrorResponse {
        match outcome {
            DispatchOutcome::Rejected(e) => e,
            other => panic!("expected Rejected, got {other:?}"),
        }
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
        assert!(
            resp.payload.get("nextCursor").is_none(),
            "last page has no nextCursor"
        );
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
    async fn pagination_returns_next_cursor_until_the_last_page() {
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
        assert!(resp1.payload.get("nextCursor").is_some());
        let cursor1 = resp1.payload["nextCursor"].as_str().unwrap().to_string();

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
        assert!(resp2.payload.get("nextCursor").is_some());

        let resp3 = unwrap_response(
            handle(
                &ctx(&acl_ks, &acl_locks),
                &transport(ADMIN_DID),
                no_verifier(),
                request(
                    ADMIN_DID,
                    Some(5),
                    resp2.payload["nextCursor"].as_str(),
                    Some("owner"),
                    None,
                    None,
                ),
            )
            .await,
        );
        let entries3 = resp3.payload["entries"].as_array().unwrap();
        assert_eq!(entries3.len(), 2);
        assert!(resp3.payload.get("nextCursor").is_none());

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

    /// `context: X, direction: actingIn` returns the entries that *may act*
    /// on domain X — those naming it, *plus* `act: all` entries (which act on
    /// any domain). So a domain no owner holds still returns the
    /// unrestricted admin: "who can publish to alpha.example" includes it.
    #[tokio::test]
    async fn domain_filter_includes_all_scoped_entries() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        // 3 owners with Allowed{["a.example"]} (seeded by seed_many).
        seed_many(&acl_ks, "did:web:o", 3, Role::Owner).await;
        // Filter by a domain none of the owners hold; the harness
        // Admin is `All`-scoped, so it matches.
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
                    Some(("nonexistent.example", "actingIn")),
                    None,
                ),
            )
            .await,
        );
        let entries = resp.payload["entries"].as_array().unwrap();
        // Just the harness Admin matches; no owners do.
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["role"], "admin");
        assert!(resp.payload.get("nextCursor").is_none());
    }

    /// `subtree` asks what is granted *of* a domain: an unrestricted entry
    /// names no domain, so it does not match.
    #[tokio::test]
    async fn subtree_excludes_unrestricted_entries() {
        let (_s, acl_ks) = harness().await;
        seed_many(&acl_ks, "did:web:o", 3, Role::Owner).await;
        let resp = unwrap_response(
            list(
                &acl_ks,
                request(
                    ADMIN_DID,
                    None,
                    None,
                    None,
                    Some(("a.example", "subtree")),
                    None,
                ),
            )
            .await,
        );
        let entries = resp.payload["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 3, "the three owners, not the admin");
        for e in entries {
            assert_eq!(e["role"], "owner");
        }
    }

    /// This maintainer recognises no capability and qualifies none, so a
    /// `capability` or `resource` filter matches nothing — not an error.
    #[tokio::test]
    async fn capability_and_resource_filters_match_nothing() {
        let (_s, acl_ks) = harness().await;
        seed_many(&acl_ks, "did:web:o", 3, Role::Owner).await;
        for payload in [
            serde_json::json!({ "capability": "did.publish" }),
            serde_json::json!({ "resource": "domain:a.example", "direction": "actingIn" }),
        ] {
            let resp = unwrap_response(list(&acl_ks, request_with(ADMIN_DID, payload)).await);
            assert!(resp.payload["entries"].as_array().unwrap().is_empty());
        }
    }

    /// There is no default direction: a hierarchical filter without one, or
    /// a direction without a filter, is malformed.
    #[tokio::test]
    async fn direction_and_hierarchical_filter_go_together() {
        let (_s, acl_ks) = harness().await;
        for payload in [
            serde_json::json!({ "context": "a.example" }),
            serde_json::json!({ "direction": "subtree" }),
        ] {
            let err = rejected(list(&acl_ks, request_with(ADMIN_DID, payload)).await);
            assert_eq!(
                err.payload.code,
                trust_tasks_rs::TrustTaskCode::Standard(StandardCode::MalformedRequest)
            );
        }
    }

    /// A cursor binds the filters it was minted under.
    #[tokio::test]
    async fn cursor_resumed_under_other_filters_is_cursor_mismatch() {
        let (_s, acl_ks) = harness().await;
        seed_many(&acl_ks, "did:web:o", 4, Role::Owner).await;
        let resp = unwrap_response(
            list(
                &acl_ks,
                request(ADMIN_DID, Some(2), None, Some("owner"), None, None),
            )
            .await,
        );
        let cursor = resp.payload["nextCursor"].as_str().unwrap().to_string();
        let err = rejected(
            list(
                &acl_ks,
                request(ADMIN_DID, Some(2), Some(&cursor), None, None, None),
            )
            .await,
        );
        assert!(
            list::error_codes::CURSOR_MISMATCH.matches(&err.payload.code),
            "{:?}",
            err.payload.code
        );
    }

    /// Cursor stability under concurrent deletes: if the entry at the
    /// last-seen position is deleted between pages, the next page's
    /// `last_seen` cursor still works (skips to the next strictly
    /// greater DID). Offset-based cursors would have skipped an entry
    /// here; the test pins our `last_seen` cursor's stability.
    #[tokio::test]
    async fn cursor_survives_concurrent_delete_of_last_seen() {
        let (_s, acl_ks) = harness().await;
        let acl_locks = crate::server::path_locks::PathLocks::new();
        seed_many(&acl_ks, "did:web:o", 6, Role::Owner).await;

        // Page 1: take 3 owners.
        let resp1 = unwrap_response(
            handle(
                &ctx(&acl_ks, &acl_locks),
                &transport(ADMIN_DID),
                no_verifier(),
                request(ADMIN_DID, Some(3), None, Some("owner"), None, None),
            )
            .await,
        );
        let entries1 = resp1.payload["entries"].as_array().unwrap().clone();
        assert_eq!(entries1.len(), 3);
        let cursor1 = resp1.payload["nextCursor"].as_str().unwrap().to_string();
        let last_did = entries1[2]["subject"].as_str().unwrap().to_string();

        // Delete the entry the cursor points at.
        acl::delete_acl_entry(&acl_ks, &last_did).await.unwrap();

        // Page 2 with the stale cursor: must still resolve, returning
        // the 3 owners strictly after `last_did` (positions 3-5 of
        // the original 6, of which we deleted one — leaving 2 owners
        // and any other non-Owner entries that happen to sort after).
        let resp2 = unwrap_response(
            handle(
                &ctx(&acl_ks, &acl_locks),
                &transport(ADMIN_DID),
                no_verifier(),
                request(
                    ADMIN_DID,
                    Some(3),
                    Some(&cursor1),
                    Some("owner"),
                    None,
                    None,
                ),
            )
            .await,
        );
        let entries2 = resp2.payload["entries"].as_array().unwrap();
        // 2 owners remain after the deletion (we had 3 in positions
        // 3-5, deleted one). No duplicates with page 1.
        let seen_in_page1: std::collections::HashSet<&str> = entries1
            .iter()
            .map(|e| e.get("subject").unwrap().as_str().unwrap())
            .collect();
        for e in entries2 {
            let did = e["subject"].as_str().unwrap();
            assert!(
                !seen_in_page1.contains(did),
                "cursor straddled a duplicate: {did}"
            );
        }
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
