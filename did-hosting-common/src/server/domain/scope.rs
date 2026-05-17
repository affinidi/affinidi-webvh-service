//! [`DomainScope`] — per-ACL-entry rule describing which domains an
//! authenticated caller may operate against.
//!
//! Per `docs/multi-domain-spec.md` §3 design table row "ACL domain
//! scope". Added as a field on `super::super::acl::AclEntry` in T16;
//! enforced on every create / publish / list operation in T20.
//!
//! ## Variants
//!
//! - [`Self::All`] — no per-domain restriction. The default for `Admin`
//!   and `Service` ACL roles (where role-based access already
//!   constrains the surface). Pre-rollout `Owner` entries that exist
//!   in stores at upgrade time also deserialize as `All` for
//!   backwards-compat — see the migration banner + ACL-lockdown tool
//!   in T22 / T42.
//! - [`Self::Allowed`] — explicit whitelist of allowed domain names.
//!   No implicit default; a missing `domain` on the wire is rejected.
//! - [`Self::AllowedWithDefault`] — whitelist plus an explicit default
//!   used when the caller omits `domain`. **The new default for
//!   freshly-created `Owner` entries** in T22.
//!
//! ## Serialisation
//!
//! Tagged-enum form, `tag = "kind"`, value lower-snake-case. The
//! shape is stable; downstream consumers (audit logs, the admin UI in
//! T42) match on the tag string.

use serde::{Deserialize, Serialize};

/// Per-ACL-entry rule describing which domains a caller may use.
///
/// Default is [`Self::All`] for backwards-compat with v0.6-vintage
/// stores (where ACL entries had no scope field at all) — see the
/// `#[default]` mark below. That choice preserves on-disk
/// deserialisation: a stored ACL entry without a `domains` field
/// reads as `All`, matching `docs/multi-domain-spec.md` §3 "ACL
/// domain scope". T22 flips the default for **newly-created**
/// `Owner` entries to [`Self::AllowedWithDefault`].
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DomainScope {
    /// No per-domain restriction. Default for `Admin` / `Service` roles
    /// and for pre-rollout `Owner` entries via the migration.
    #[default]
    All,

    /// Caller may operate only on the listed domains. A request that
    /// omits `domain` is rejected with 400 (per spec §3 "Default-
    /// domain selection ... Reject if the caller is `Allowed([…])` with
    /// no default and the request omits `domain`").
    Allowed { domains: Vec<String> },

    /// Caller may operate on the listed domains; `default` is used
    /// when `domain` is omitted from the request. `default` MUST be a
    /// member of `domains` — enforced at construction by [`Self::new_allowed_with_default`].
    AllowedWithDefault {
        domains: Vec<String>,
        default: String,
    },
}

impl DomainScope {
    /// Construct an `AllowedWithDefault` after validating that
    /// `default` appears in `domains` (and that `domains` is non-empty).
    /// Returns `Err` with a human-readable reason on misuse.
    pub fn new_allowed_with_default(domains: Vec<String>, default: String) -> Result<Self, String> {
        if domains.is_empty() {
            return Err("AllowedWithDefault requires a non-empty domain list".into());
        }
        if !domains.iter().any(|d| d == &default) {
            return Err(format!(
                "default '{default}' is not a member of allowed list {domains:?}"
            ));
        }
        Ok(Self::AllowedWithDefault { domains, default })
    }

    /// Check whether the scope allows operating on `domain`.
    ///
    /// `Admin` / `Service` callers should not call this — their role
    /// short-circuits the check upstream. This is the per-`Owner`
    /// authorisation primitive.
    pub fn allows(&self, domain: &str) -> bool {
        match self {
            Self::All => true,
            Self::Allowed { domains } => domains.iter().any(|d| d == domain),
            Self::AllowedWithDefault { domains, .. } => domains.iter().any(|d| d == domain),
        }
    }

    /// The default domain to use when a request omits `domain`.
    ///
    /// Returns `Some` only for [`Self::AllowedWithDefault`] — the other
    /// variants either don't restrict (`All`, which falls back to the
    /// **system** default elsewhere) or deliberately have no default
    /// (`Allowed`, which forces an explicit `domain` on every call).
    pub fn default_domain(&self) -> Option<&str> {
        match self {
            Self::AllowedWithDefault { default, .. } => Some(default),
            _ => None,
        }
    }
}

/// Resolve the effective `domain` for a DID-management request per
/// spec §3 "Default-domain selection". T34 makes this the single
/// authoritative resolver so REST and DIDComm handlers can't drift
/// on the precedence rules.
///
/// Precedence:
/// 1. `request_domain` (explicit on the wire) — if set, use it.
/// 2. `caller_scope.default_domain()` — caller's ACL
///    `AllowedWithDefault.default`.
/// 3. `system_default` — the daemon's default domain.
/// 4. Reject: caller is `Allowed([…])` with no default and the
///    request omits `domain`.
///
/// The `Allow`-without-default rejection is deliberate: callers
/// pinned to a specific domain set without a default must make the
/// target explicit on every request to avoid the server having to
/// guess.
///
/// Returns the resolved domain name (already canonical if the
/// caller normalised before calling) or a domain-resolution error
/// the handler can surface as 400.
pub fn resolve_request_domain(
    request_domain: Option<&str>,
    caller_scope: &DomainScope,
    system_default: Option<&str>,
) -> Result<String, DomainResolveError> {
    // Tier 1: explicit on the wire.
    if let Some(d) = request_domain
        && !d.is_empty()
    {
        return Ok(d.to_string());
    }
    // Tier 2: caller's ACL default.
    if let Some(d) = caller_scope.default_domain() {
        return Ok(d.to_string());
    }
    // Tier 3: system default. Falls through for `All`-scope callers
    // who haven't specified an explicit domain.
    if matches!(caller_scope, DomainScope::All)
        && let Some(d) = system_default
    {
        return Ok(d.to_string());
    }
    // Tier 4: `Allowed([…])` callers with no default must declare
    // a domain. System default isn't applicable because the caller
    // may not be authorised on it.
    Err(DomainResolveError::NoDefault)
}

/// Failure modes for [`resolve_request_domain`].
#[derive(Debug, PartialEq, Eq)]
pub enum DomainResolveError {
    /// Caller is `Allowed([…])` (no default) and the request omitted
    /// `domain`. The caller must declare a target explicitly.
    NoDefault,
}

impl std::fmt::Display for DomainResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDefault => write!(
                f,
                "request omits `domain` and the caller's ACL scope has no default; \
                 explicit `domain` is required for this caller"
            ),
        }
    }
}

#[cfg(test)]
mod resolve_tests {
    use super::*;

    fn allowed(names: &[&str]) -> DomainScope {
        DomainScope::Allowed {
            domains: names.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn with_default(names: &[&str], default: &str) -> DomainScope {
        DomainScope::AllowedWithDefault {
            domains: names.iter().map(|s| s.to_string()).collect(),
            default: default.to_string(),
        }
    }

    #[test]
    fn explicit_request_domain_wins() {
        let r = resolve_request_domain(
            Some("explicit.example"),
            &with_default(&["a.example", "b.example"], "a.example"),
            Some("system.example"),
        );
        assert_eq!(r.unwrap(), "explicit.example");
    }

    #[test]
    fn empty_request_domain_falls_through_to_default() {
        let r = resolve_request_domain(
            Some(""),
            &with_default(&["a.example"], "a.example"),
            Some("system.example"),
        );
        assert_eq!(r.unwrap(), "a.example");
    }

    #[test]
    fn acl_default_used_when_request_omits() {
        let r = resolve_request_domain(
            None,
            &with_default(&["a.example", "b.example"], "b.example"),
            Some("system.example"),
        );
        assert_eq!(r.unwrap(), "b.example");
    }

    #[test]
    fn all_scope_falls_back_to_system_default() {
        let r = resolve_request_domain(None, &DomainScope::All, Some("system.example"));
        assert_eq!(r.unwrap(), "system.example");
    }

    #[test]
    fn allowed_without_default_rejects_implicit() {
        let err = resolve_request_domain(
            None,
            &allowed(&["a.example", "b.example"]),
            Some("system.example"),
        )
        .expect_err("must require explicit domain");
        assert_eq!(err, DomainResolveError::NoDefault);
    }

    #[test]
    fn all_scope_with_no_system_default_rejects() {
        let err = resolve_request_domain(None, &DomainScope::All, None)
            .expect_err("no source of truth — must reject");
        assert_eq!(err, DomainResolveError::NoDefault);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_all() {
        assert!(matches!(DomainScope::default(), DomainScope::All));
    }

    #[test]
    fn all_allows_everything() {
        assert!(DomainScope::All.allows("any-domain.example"));
        assert!(DomainScope::All.allows("another.example"));
    }

    #[test]
    fn allowed_gates_by_membership() {
        let scope = DomainScope::Allowed {
            domains: vec!["a.example".into(), "b.example".into()],
        };
        assert!(scope.allows("a.example"));
        assert!(scope.allows("b.example"));
        assert!(!scope.allows("c.example"));
    }

    #[test]
    fn allowed_with_default_validates_default_membership() {
        let ok = DomainScope::new_allowed_with_default(
            vec!["a.example".into(), "b.example".into()],
            "a.example".into(),
        )
        .expect("default in list");
        assert_eq!(ok.default_domain(), Some("a.example"));

        let err =
            DomainScope::new_allowed_with_default(vec!["a.example".into()], "b.example".into())
                .expect_err("default not in list must reject");
        assert!(err.contains("not a member"));
    }

    #[test]
    fn allowed_with_default_rejects_empty_list() {
        let err = DomainScope::new_allowed_with_default(vec![], "a.example".into())
            .expect_err("empty list must reject");
        assert!(err.contains("non-empty"));
    }

    #[test]
    fn default_domain_only_on_allowed_with_default() {
        assert_eq!(DomainScope::All.default_domain(), None);
        assert_eq!(
            DomainScope::Allowed {
                domains: vec!["x".into()]
            }
            .default_domain(),
            None
        );
        let scoped = DomainScope::new_allowed_with_default(vec!["x".into()], "x".into()).unwrap();
        assert_eq!(scoped.default_domain(), Some("x"));
    }

    #[test]
    fn round_trips_all_variant() {
        let scope = DomainScope::All;
        let json = serde_json::to_string(&scope).unwrap();
        assert_eq!(json, r#"{"kind":"all"}"#);
        let back: DomainScope = serde_json::from_str(&json).unwrap();
        assert_eq!(scope, back);
    }

    #[test]
    fn round_trips_allowed_variant() {
        let scope = DomainScope::Allowed {
            domains: vec!["a".into(), "b".into()],
        };
        let json = serde_json::to_string(&scope).unwrap();
        let back: DomainScope = serde_json::from_str(&json).unwrap();
        assert_eq!(scope, back);
    }

    #[test]
    fn round_trips_allowed_with_default_variant() {
        let scope = DomainScope::AllowedWithDefault {
            domains: vec!["a".into(), "b".into()],
            default: "a".into(),
        };
        let json = serde_json::to_string(&scope).unwrap();
        let back: DomainScope = serde_json::from_str(&json).unwrap();
        assert_eq!(scope, back);
    }

    #[test]
    fn snake_case_tag_in_wire_form() {
        let scope = DomainScope::AllowedWithDefault {
            domains: vec!["a".into()],
            default: "a".into(),
        };
        let json = serde_json::to_string(&scope).unwrap();
        assert!(
            json.contains("\"kind\":\"allowed_with_default\""),
            "expected snake_case tag, got {json}"
        );
    }
}
