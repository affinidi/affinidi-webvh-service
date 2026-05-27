//! Safety checks at the boundary between an inbound write and storage.
//!
//! Per `docs/multi-domain-spec.md` §3 row "Safety check on create /
//! publish": every create / publish must, **before any storage write**:
//!
//! 1. Parse the DID identifier embedded in the caller's payload (the
//!    `state.id` from the latest jsonl entry, or the `id` from a
//!    did:web doc — surfaced through [`super::super::super::method::DidMethod`]).
//! 2. Verify the parsed host is an [`DomainStatus::Active`] domain in
//!    the `KS_DOMAINS` keyspace. Missing or disabled → `400`
//!    (`AppError::Validation`).
//! 3. Verify the caller's ACL [`DomainScope`] permits that host.
//!    Not-allowed → `403` (`AppError::Forbidden`).
//!
//! The two error codes are distinct so the UI can render different
//! messages — "we don't serve that domain" (operator misconfig) vs
//! "you can't post there" (ACL misconfig).

use super::super::acl::{AclEntry, Role};
use super::super::error::AppError;
use super::super::store::Store;
use super::store::get_domain;
use crate::method::{method_by_name, parse_did_method};

/// Verify that `host` is an active configured domain on this server.
///
/// Returns `Err(AppError::Validation)` if the domain doesn't exist OR
/// is disabled. The two cases collapse to the same response code (400)
/// — operators get the active-domain set via the admin list anyway.
pub async fn assert_host_is_active_domain(store: &Store, host: &str) -> Result<(), AppError> {
    let entry = get_domain(store, host).await?.ok_or_else(|| {
        AppError::Validation(format!(
            "did host '{host}' is not a configured domain on this server"
        ))
    })?;
    if !entry.status.is_active() {
        return Err(AppError::Validation(format!(
            "did host '{host}' is configured but disabled"
        )));
    }
    Ok(())
}

/// Verify that the caller's ACL [`DomainScope`] permits operating on
/// `host`. Admin and Service roles short-circuit per spec §3.
///
/// Returns `Err(AppError::Forbidden)` if the ACL scope doesn't allow
/// the host. The error body intentionally doesn't echo the host —
/// avoids leaking which domains the caller IS allowed on via
/// timing / message diffs.
pub fn assert_acl_allows_host(acl_entry: &AclEntry, host: &str) -> Result<(), AppError> {
    if matches!(acl_entry.role, Role::Admin | Role::Service) {
        return Ok(());
    }
    if acl_entry.domains.allows(host) {
        return Ok(());
    }
    Err(AppError::Forbidden(format!(
        "caller is not authorised to operate on domain '{host}'"
    )))
}

/// Parse a DID identifier and extract its host segment via the
/// [`DidMethod`] dispatcher.
///
/// Returns `Err(AppError::Validation)` on:
/// - malformed identifier (no `did:` prefix, empty method, etc.)
/// - unknown method (the compiled binary doesn't know about
///   `did:webs` if `method-webs` is off — same response shape as a
///   malformed identifier so callers can't fingerprint our feature
///   set).
pub fn extract_did_host(did: &str) -> Result<String, AppError> {
    let method_name = parse_did_method(did)
        .map_err(|e| AppError::Validation(format!("malformed DID identifier '{did}': {e}")))?;
    let method = method_by_name(method_name).ok_or_else(|| {
        AppError::Validation(format!(
            "DID method '{method_name}' is not supported by this server"
        ))
    })?;
    let parsed = method.parse_identifier(did).map_err(|e| {
        AppError::Validation(format!("could not parse DID identifier '{did}': {e}"))
    })?;
    Ok(parsed.domain)
}

/// One-shot check covering all three steps. The intended entry point
/// for `did_ops::create_did` / `register_did_atomic` / `publish_did`:
/// call this immediately after extracting the embedded DID identifier
/// and before any storage write.
///
/// - 400 if the identifier is malformed / wrong method / unknown
///   method.
/// - 400 if the host isn't a configured domain on this server.
/// - 400 if the host is configured but Disabled.
/// - 403 if the caller's ACL doesn't allow the host.
pub async fn assert_did_host_allowed(
    store: &Store,
    acl_entry: &AclEntry,
    did: &str,
) -> Result<(), AppError> {
    let host = extract_did_host(did)?;
    assert_host_is_active_domain(store, &host).await?;
    assert_acl_allows_host(acl_entry, &host)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Resolve-side safety (T21)
// ---------------------------------------------------------------------------

/// Resolve-side check: the request's `Host` header (already
/// normalised + resolved through trusted-CIDR gating in T19) must
/// match the DID identifier's embedded host.
///
/// Per `docs/multi-domain-spec.md` §3 safety-check-on-resolution:
/// mismatch returns **404** (not 403) to avoid confirming the DID
/// exists elsewhere. Same shape as `NotFound`; callers shouldn't
/// need to distinguish "wrong domain" from "really gone".
///
/// The embedded host is percent-decoded before comparison: the
/// did:webvh / did:web specs require the port colon (and any other
/// reserved character) to be percent-encoded in the identifier
/// (`localhost%3A8534`), while the HTTP `Host` header carries the
/// literal form (`localhost:8534`). Without the decode the two
/// representations of the same host never match.
pub fn assert_request_host_matches_did(request_host: &str, did_id: &str) -> Result<(), AppError> {
    let embedded_host_raw = extract_did_host(did_id).map_err(|_| {
        // Storage carries an unparseable DID identifier — return 404
        // rather than 500 so the response is honest about "we can't
        // serve this".
        AppError::NotFound(format!("did identifier unparseable: {did_id}"))
    })?;
    // Fall back to the literal segment when decoding fails — preserves
    // the original behaviour for any DID whose host contains malformed
    // percent escapes; the comparison just fails further down instead
    // of silently succeeding.
    let embedded_host = percent_decode_to_string(&embedded_host_raw).unwrap_or(embedded_host_raw);
    if request_host.eq_ignore_ascii_case(&embedded_host) {
        return Ok(());
    }
    tracing::warn!(
        request_host = %request_host,
        did_host = %embedded_host,
        did_id = %did_id,
        "resolution rejected: request Host does not match embedded did.host"
    );
    Err(AppError::NotFound(format!(
        "no DID resolvable at host {request_host}"
    )))
}

/// Minimal percent-decoder for the resolve-side host check. Decodes
/// any `%XX` sequence (the spec allows `%3A`, `%2F`, …); returns
/// `None` if a `%` isn't followed by two hex digits or the result
/// isn't valid UTF-8. Scoped tight so we don't take a new dep just
/// to decode one segment.
fn percent_decode_to_string(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = (bytes[i + 1] as char).to_digit(16)?;
            let lo = (bytes[i + 2] as char).to_digit(16)?;
            out.push(((hi << 4) | lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Resolve-side check: the named domain must be `Active`. Disabled
/// or missing returns the appropriate error code per spec §3.
///
/// - **Disabled** → `AppError::DomainDisabled` → 503 with maintenance
///   JSON body `{ "status": "disabled", "domain": "..." }`.
/// - **Missing** → `AppError::NotFound` → 404. Should not happen on
///   the resolve path (we already matched the embedded did.host
///   against the configured domain), but guarded for safety.
pub async fn assert_domain_active_for_resolution(
    store: &Store,
    host: &str,
) -> Result<(), AppError> {
    let entry = get_domain(store, host).await?.ok_or_else(|| {
        // Unexpected — the host came from the embedded DID, and the
        // create-side check refused to write it without a matching
        // active domain. Reaching this branch means a domain was
        // deleted out from under a hosted DID; 404 is honest.
        AppError::NotFound(format!("domain not configured: {host}"))
    })?;
    if entry.status.is_active() {
        return Ok(());
    }
    Err(AppError::DomainDisabled {
        domain: host.to_string(),
        message: None,
    })
}

/// Permissive variant of [`assert_did_host_allowed`] used by the
/// did_ops write paths.
///
/// Behaviour:
/// - If the `domains` keyspace contains **at least one** entry, the
///   strict check runs and the same error semantics apply
///   (400 / 403).
/// - If the keyspace is **empty**, the check is **skipped** with a
///   warn-log. This is the legacy state — pre-T18 deployments, test
///   fixtures that haven't seeded a domain — and is the only
///   ergonomically-tolerable behaviour for the transition window.
///
/// Production daemons run T18's first-boot seed before serving
/// requests, so the empty-keyspace path is unreachable in practice
/// once the daemon is up. The warn-log makes the legacy state
/// visible to operators if they hit it.
///
/// The strict [`assert_did_host_allowed`] stays available for code
/// paths that want hard enforcement regardless of keyspace state
/// (e.g. an admin tool walking the store for a one-shot audit).
pub async fn assert_did_host_allowed_when_domains_configured(
    store: &Store,
    acl_entry: &AclEntry,
    did: &str,
) -> Result<(), AppError> {
    use crate::server::store::KS_DOMAINS;
    let ks = store.keyspace(KS_DOMAINS)?;
    let any_domain = ks
        .prefix_iter_raw(b"".to_vec())
        .await?
        .into_iter()
        .next()
        .is_some();
    if !any_domain {
        tracing::warn!(
            did = %did,
            "domains keyspace is empty — skipping host-vs-domain safety check. \
             Configure `[hosting] bootstrap_domains` or create a domain via the \
             admin API to enable enforcement."
        );
        return Ok(());
    }
    assert_did_host_allowed(store, acl_entry, did).await
}

/// Resolve-side bundle: enforce host-match + domain-active in one call.
///
/// Wraps [`assert_request_host_matches_did`] and
/// [`assert_domain_active_for_resolution`] with the same
/// "permissive when [`KS_DOMAINS`] is empty" pattern used by
/// [`assert_did_host_allowed_when_domains_configured`] on the write
/// path. The legacy state (pre-T18 seed, fresh test fixtures) keeps
/// resolving its DIDs; the moment a domain exists, enforcement turns
/// on automatically.
///
/// Returns:
/// - **404** (`AppError::NotFound`) on host mismatch (per spec, hide
///   the DID from the wrong domain).
/// - **503** (`AppError::DomainDisabled`) when the matched domain is
///   disabled.
/// - **Ok** when the keyspace is empty (legacy), or when host matches
///   and the domain is active.
///
/// [`KS_DOMAINS`]: crate::server::store::KS_DOMAINS
pub async fn assert_resolution_allowed(
    store: &Store,
    request_host: &str,
    did_id: &str,
) -> Result<(), AppError> {
    use crate::server::store::KS_DOMAINS;
    let ks = store.keyspace(KS_DOMAINS)?;
    let any_domain = ks
        .prefix_iter_raw(b"".to_vec())
        .await?
        .into_iter()
        .next()
        .is_some();
    if !any_domain {
        tracing::warn!(
            did = %did_id,
            request_host = %request_host,
            "domains keyspace is empty — skipping resolve-side safety check"
        );
        return Ok(());
    }
    assert_request_host_matches_did(request_host, did_id)?;
    assert_domain_active_for_resolution(store, request_host).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::acl::AclEntry;
    use crate::server::config::StoreConfig;
    use crate::server::domain::scope::DomainScope;
    use crate::server::domain::store::{create_domain, set_default_domain};
    use crate::server::domain::types::{DomainEntry, DomainStatus, DomainUrlScheme};

    async fn fjall_store() -> Store {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        };
        std::mem::forget(dir);
        Store::open(&cfg).await.expect("open fjall")
    }

    fn entry(name: &str, status: DomainStatus) -> DomainEntry {
        DomainEntry {
            name: name.into(),
            label: None,
            scheme: DomainUrlScheme::Https,
            status,
            created_at: 0,
            default_domain: false,
            branding: None,
            witnesses: None,
            watchers: None,
            quota: None,
            well_known_enabled: false,
            disabled_at: None,
            purge_at: None,
        }
    }

    fn acl(role: Role, scope: DomainScope) -> AclEntry {
        AclEntry {
            did: "did:example:caller".into(),
            role,
            label: None,
            created_at: 0,
            max_total_size: None,
            max_did_count: None,
            domains: scope,
        }
    }

    // ---- extract_did_host ----

    #[test]
    fn extract_host_webvh() {
        let host = extract_did_host("did:webvh:QmABC:example.com:user1").unwrap();
        assert_eq!(host, "example.com");
    }

    #[test]
    fn extract_host_webvh_with_port_encoded() {
        let host = extract_did_host("did:webvh:QmABC:example.com%3A8085:user1").unwrap();
        assert_eq!(host, "example.com%3A8085");
    }

    #[test]
    fn extract_host_unknown_method_rejects() {
        // method-webs is not compiled in by default; treating an
        // unknown method as Validation matches the contract.
        let err = extract_did_host("did:webs:scid:example.com:user1").expect_err("unknown method");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn extract_host_web() {
        let host = extract_did_host("did:web:example.com:user1").unwrap();
        assert_eq!(host, "example.com");
    }

    #[test]
    fn extract_host_web_no_path() {
        let host = extract_did_host("did:web:example.com").unwrap();
        assert_eq!(host, "example.com");
    }

    #[test]
    fn extract_host_malformed_rejects() {
        for bad in ["not-a-did", "did:", "did::body", "did:webvh:onlyone"] {
            let err = extract_did_host(bad).expect_err(bad);
            assert!(matches!(err, AppError::Validation(_)));
        }
    }

    // ---- assert_host_is_active_domain ----

    #[tokio::test]
    async fn host_must_be_configured_domain() {
        let store = fjall_store().await;
        let err = assert_host_is_active_domain(&store, "missing.example")
            .await
            .expect_err("must reject missing domain");
        assert!(matches!(err, AppError::Validation(_)));
        assert!(err.to_string().contains("not a configured domain"));
    }

    #[tokio::test]
    async fn host_must_be_active_not_disabled() {
        let store = fjall_store().await;
        create_domain(&store, &entry("disabled.example", DomainStatus::Disabled))
            .await
            .unwrap();
        let err = assert_host_is_active_domain(&store, "disabled.example")
            .await
            .expect_err("must reject disabled");
        assert!(matches!(err, AppError::Validation(_)));
        assert!(err.to_string().contains("disabled"));
    }

    #[tokio::test]
    async fn active_domain_passes() {
        let store = fjall_store().await;
        create_domain(&store, &entry("active.example", DomainStatus::Active))
            .await
            .unwrap();
        assert!(
            assert_host_is_active_domain(&store, "active.example")
                .await
                .is_ok()
        );
    }

    // ---- assert_acl_allows_host ----

    #[test]
    fn admin_short_circuits_regardless_of_scope() {
        let e = acl(
            Role::Admin,
            DomainScope::Allowed {
                domains: vec!["a.example".into()],
            },
        );
        // Admin has scope = Allowed([a]) but tries to operate on b.
        assert!(assert_acl_allows_host(&e, "b.example").is_ok());
    }

    #[test]
    fn service_short_circuits_regardless_of_scope() {
        let e = acl(
            Role::Service,
            DomainScope::Allowed {
                domains: vec!["a.example".into()],
            },
        );
        assert!(assert_acl_allows_host(&e, "b.example").is_ok());
    }

    #[test]
    fn owner_all_scope_allows_anything() {
        let e = acl(Role::Owner, DomainScope::All);
        assert!(assert_acl_allows_host(&e, "any.example").is_ok());
    }

    #[test]
    fn owner_allowed_scope_membership_only() {
        let e = acl(
            Role::Owner,
            DomainScope::Allowed {
                domains: vec!["a.example".into(), "b.example".into()],
            },
        );
        assert!(assert_acl_allows_host(&e, "a.example").is_ok());
        assert!(assert_acl_allows_host(&e, "b.example").is_ok());
        let err = assert_acl_allows_host(&e, "c.example").expect_err("not in scope");
        assert!(matches!(err, AppError::Forbidden(_)));
    }

    #[test]
    fn forbidden_error_does_not_leak_allowed_list() {
        let e = acl(
            Role::Owner,
            DomainScope::Allowed {
                domains: vec!["secret-tenant.example".into()],
            },
        );
        let err = assert_acl_allows_host(&e, "other.example").expect_err("not in scope");
        // The Forbidden message names the rejected host (caller already
        // sent it) but MUST NOT echo any names from the allowed list.
        let s = err.to_string();
        assert!(s.contains("other.example"));
        assert!(!s.contains("secret-tenant.example"));
    }

    // ---- T21: resolve-side checks ----

    #[test]
    fn request_host_matches_did_happy_path() {
        assert!(
            assert_request_host_matches_did("example.com", "did:webvh:Q1:example.com:user1")
                .is_ok()
        );
    }

    #[test]
    fn request_host_matches_did_case_insensitive() {
        // DNS is case-insensitive — operators sometimes get
        // mixed-case Host headers from buggy clients. Accept.
        assert!(
            assert_request_host_matches_did("Example.COM", "did:webvh:Q1:example.com:user1")
                .is_ok()
        );
    }

    #[test]
    fn request_host_matches_did_mismatch_yields_404() {
        let err = assert_request_host_matches_did(
            "domain-b.example",
            "did:webvh:Q1:domain-a.example:user1",
        )
        .expect_err("mismatch must reject");
        assert!(matches!(err, AppError::NotFound(_)));
    }

    #[test]
    fn request_host_matches_did_unparseable_yields_404() {
        let err = assert_request_host_matches_did("example.com", "garbage")
            .expect_err("unparseable did must reject");
        assert!(matches!(err, AppError::NotFound(_)));
    }

    #[test]
    fn request_host_matches_did_with_encoded_port() {
        // The webvh / web identifier encodes the port colon as `%3A`;
        // the HTTP Host header carries the literal `:`. Must match.
        assert!(
            assert_request_host_matches_did("localhost:8534", "did:webvh:Q1:localhost%3A8534")
                .is_ok()
        );
        assert!(
            assert_request_host_matches_did("example.com:8443", "did:web:example.com%3A8443:user1")
                .is_ok()
        );
    }

    #[test]
    fn request_host_matches_did_with_encoded_port_mismatch_yields_404() {
        // Right host, wrong port — still a mismatch after decoding.
        let err =
            assert_request_host_matches_did("localhost:9999", "did:webvh:Q1:localhost%3A8534")
                .expect_err("port mismatch must reject");
        assert!(matches!(err, AppError::NotFound(_)));
    }

    #[test]
    fn percent_decode_helpers() {
        assert_eq!(
            percent_decode_to_string("localhost%3A8534").as_deref(),
            Some("localhost:8534")
        );
        // Lowercase hex.
        assert_eq!(
            percent_decode_to_string("localhost%3a8534").as_deref(),
            Some("localhost:8534")
        );
        // No escapes — identity.
        assert_eq!(
            percent_decode_to_string("example.com").as_deref(),
            Some("example.com")
        );
        // Multiple escapes (host%2Fpath form, though we don't mint
        // these — exercise the general path anyway).
        assert_eq!(
            percent_decode_to_string("a%2Fb%3Ac").as_deref(),
            Some("a/b:c")
        );
        // Malformed: trailing `%`, short escape, non-hex.
        assert_eq!(percent_decode_to_string("bad%"), None);
        assert_eq!(percent_decode_to_string("bad%3"), None);
        assert_eq!(percent_decode_to_string("bad%ZZ"), None);
    }

    #[tokio::test]
    async fn resolution_against_disabled_domain_yields_503() {
        let store = fjall_store().await;
        create_domain(&store, &entry("disabled.example", DomainStatus::Disabled))
            .await
            .unwrap();
        let err = assert_domain_active_for_resolution(&store, "disabled.example")
            .await
            .expect_err("disabled must reject");
        match err {
            AppError::DomainDisabled { domain, .. } => {
                assert_eq!(domain, "disabled.example");
            }
            other => panic!("expected DomainDisabled, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolution_against_missing_domain_yields_404() {
        let store = fjall_store().await;
        let err = assert_domain_active_for_resolution(&store, "missing.example")
            .await
            .expect_err("missing must reject");
        assert!(matches!(err, AppError::NotFound(_)));
    }

    #[tokio::test]
    async fn resolution_against_active_domain_passes() {
        let store = fjall_store().await;
        create_domain(&store, &entry("active.example", DomainStatus::Active))
            .await
            .unwrap();
        assert!(
            assert_domain_active_for_resolution(&store, "active.example")
                .await
                .is_ok()
        );
    }

    // ---- bundle: assert_resolution_allowed ----

    #[tokio::test]
    async fn resolution_allowed_empty_keyspace_is_permissive() {
        let store = fjall_store().await;
        assert!(
            assert_resolution_allowed(&store, "example.com", "did:webvh:Q1:example.com:user1")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn resolution_allowed_happy_path() {
        let store = fjall_store().await;
        create_domain(&store, &entry("example.com", DomainStatus::Active))
            .await
            .unwrap();
        assert!(
            assert_resolution_allowed(&store, "example.com", "did:webvh:Q1:example.com:user1")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn resolution_allowed_cross_domain_leakage_rejected() {
        // Hosted: domain-a (active) AND domain-b (active). A request
        // arriving on domain-b for a DID issued at domain-a must NOT
        // resolve — return 404, not the DID.
        let store = fjall_store().await;
        create_domain(&store, &entry("domain-a.example", DomainStatus::Active))
            .await
            .unwrap();
        create_domain(&store, &entry("domain-b.example", DomainStatus::Active))
            .await
            .unwrap();
        let err = assert_resolution_allowed(
            &store,
            "domain-b.example",
            "did:webvh:Q1:domain-a.example:user1",
        )
        .await
        .expect_err("cross-domain resolve must reject");
        assert!(matches!(err, AppError::NotFound(_)));
    }

    #[tokio::test]
    async fn resolution_allowed_disabled_domain_returns_503() {
        let store = fjall_store().await;
        create_domain(&store, &entry("disabled.example", DomainStatus::Disabled))
            .await
            .unwrap();
        let err = assert_resolution_allowed(
            &store,
            "disabled.example",
            "did:webvh:Q1:disabled.example:user1",
        )
        .await
        .expect_err("disabled domain must 503");
        assert!(matches!(err, AppError::DomainDisabled { .. }));
    }

    // ---- end-to-end: assert_did_host_allowed ----

    #[tokio::test]
    async fn end_to_end_happy_path() {
        let store = fjall_store().await;
        create_domain(&store, &entry("example.com", DomainStatus::Active))
            .await
            .unwrap();
        set_default_domain(&store, "example.com").await.unwrap();
        let e = acl(
            Role::Owner,
            DomainScope::AllowedWithDefault {
                domains: vec!["example.com".into()],
                default: "example.com".into(),
            },
        );
        let did = "did:webvh:QmABC:example.com:user1";
        assert!(assert_did_host_allowed(&store, &e, did).await.is_ok());
    }

    #[tokio::test]
    async fn end_to_end_did_host_not_configured() {
        let store = fjall_store().await;
        create_domain(&store, &entry("example.com", DomainStatus::Active))
            .await
            .unwrap();
        let e = acl(Role::Owner, DomainScope::All);
        let did = "did:webvh:QmABC:other.example:user1";
        let err = assert_did_host_allowed(&store, &e, did)
            .await
            .expect_err("must reject");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[tokio::test]
    async fn end_to_end_acl_rejects() {
        let store = fjall_store().await;
        create_domain(&store, &entry("example.com", DomainStatus::Active))
            .await
            .unwrap();
        let e = acl(
            Role::Owner,
            DomainScope::Allowed {
                domains: vec!["allowed.example".into()],
            },
        );
        // Add the "other" domain so the active-domain check passes;
        // it's the ACL that rejects.
        create_domain(&store, &entry("allowed.example", DomainStatus::Active))
            .await
            .unwrap();
        let did = "did:webvh:QmABC:example.com:user1";
        let err = assert_did_host_allowed(&store, &e, did)
            .await
            .expect_err("must reject");
        assert!(matches!(err, AppError::Forbidden(_)));
    }

    #[tokio::test]
    async fn end_to_end_disabled_domain_rejects_with_400() {
        let store = fjall_store().await;
        create_domain(&store, &entry("example.com", DomainStatus::Disabled))
            .await
            .unwrap();
        let e = acl(Role::Admin, DomainScope::All);
        let did = "did:webvh:QmABC:example.com:user1";
        // Even Admin can't write to a disabled domain — the active-
        // domain check runs first and is role-blind.
        let err = assert_did_host_allowed(&store, &e, did)
            .await
            .expect_err("disabled rejects");
        assert!(matches!(err, AppError::Validation(_)));
    }
}
