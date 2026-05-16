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
/// stores (where ACL entries had no scope field at all). T22 flips the
/// default for **newly-created** `Owner` entries to
/// [`Self::AllowedWithDefault`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DomainScope {
    /// No per-domain restriction. Default for `Admin` / `Service` roles
    /// and for pre-rollout `Owner` entries via the migration.
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

impl Default for DomainScope {
    fn default() -> Self {
        // Defaulting to `All` preserves the v0.6-vintage shape on
        // deserialisation — a stored ACL entry without a `domains`
        // field reads as `All`. Same rationale as
        // `multi-domain-spec.md` §3 "ACL domain scope" entry.
        Self::All
    }
}

impl DomainScope {
    /// Construct an `AllowedWithDefault` after validating that
    /// `default` appears in `domains` (and that `domains` is non-empty).
    /// Returns `Err` with a human-readable reason on misuse.
    pub fn new_allowed_with_default(
        domains: Vec<String>,
        default: String,
    ) -> Result<Self, String> {
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

        let err = DomainScope::new_allowed_with_default(
            vec!["a.example".into()],
            "b.example".into(),
        )
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
        let scoped = DomainScope::new_allowed_with_default(
            vec!["x".into()],
            "x".into(),
        )
        .unwrap();
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
