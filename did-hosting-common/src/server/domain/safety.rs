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
    let method_name = parse_did_method(did).map_err(|e| {
        AppError::Validation(format!("malformed DID identifier '{did}': {e}"))
    })?;
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
        let host =
            extract_did_host("did:webvh:QmABC:example.com%3A8085:user1").unwrap();
        assert_eq!(host, "example.com%3A8085");
    }

    #[test]
    fn extract_host_unknown_method_rejects() {
        // method-webs is not compiled in by default; treating an
        // unknown method as Validation matches the contract.
        let err =
            extract_did_host("did:webs:scid:example.com:user1").expect_err("unknown method");
        assert!(matches!(err, AppError::Validation(_)));
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
        assert!(assert_host_is_active_domain(&store, "active.example").await.is_ok());
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
        let err = assert_did_host_allowed(&store, &e, did).await.expect_err("must reject");
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
        let err = assert_did_host_allowed(&store, &e, did).await.expect_err("must reject");
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
        let err = assert_did_host_allowed(&store, &e, did).await.expect_err("disabled rejects");
        assert!(matches!(err, AppError::Validation(_)));
    }
}
