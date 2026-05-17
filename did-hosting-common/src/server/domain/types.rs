//! Data types for the multi-domain feature: [`DomainEntry`] plus its
//! component value types.
//!
//! Every field's role is documented inline against
//! `docs/multi-domain-spec.md` §3 — the design table there is the
//! source of truth, this file is the typed shape.

use serde::{Deserialize, Serialize};

/// One configured domain.
///
/// Serialised under `domains:{name}` in the `KS_DOMAINS` keyspace.
/// `name` is the lookup key AND a field on the value — denormalisation
/// is intentional so a `DomainEntry` is self-describing in audit logs
/// and DIDComm payloads without the keyspace context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainEntry {
    /// Lower-cased + IDNA-normalised hostname (T15 normaliser). Acts
    /// as the storage key; **immutable** after creation per spec §3.
    /// Path-prefix forms supported (e.g. `example.com/webvh-a`).
    pub name: String,

    /// Operator-facing display label. Defaults to `name` when unset.
    /// Free-form; not used for routing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// URL scheme used when constructing the resolution URL for DIDs
    /// hosted on this domain. The hosting service never terminates TLS
    /// itself (operators run a reverse proxy upstream); the scheme is
    /// recorded so URL composition is correct.
    pub scheme: DomainUrlScheme,

    /// Lifecycle state. `Active` → serves resolution + accepts writes.
    /// `Disabled` → resolution returns 503 with maintenance JSON,
    /// writes are rejected, but data is retained.
    pub status: DomainStatus,

    /// Unix seconds at creation.
    pub created_at: u64,

    /// Set on exactly one domain at a time. The `meta:default_domain`
    /// pointer in the `meta` keyspace is the canonical source — this
    /// field is derived for response convenience. Setting it via the
    /// CRUD layer (T15) updates the pointer, not this field directly.
    #[serde(default)]
    pub default_domain: bool,

    /// Optional branding metadata surfaced via
    /// `/.well-known/did-hosting-domain.json` (only when
    /// `well_known_enabled` is true). All sub-fields are optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branding: Option<DomainBranding>,

    /// Per-domain witness override (webvh-specific; advisory in this
    /// release per spec §3 "Per-domain witness/watcher | Schema only").
    /// `None` falls back to the global witness config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witnesses: Option<Vec<String>>,

    /// Per-domain watcher override (advisory in this release). `None`
    /// falls back to the global watcher config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watchers: Option<Vec<String>>,

    /// Per-domain quota override. `None` falls back to global limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<DomainQuota>,

    /// When true, this domain serves
    /// `/.well-known/did-hosting-domain.json` with its `branding` block.
    /// Default off per spec §3 — operators opt in per-domain.
    #[serde(default)]
    pub well_known_enabled: bool,
}

/// URL scheme used in resolution URLs for DIDs hosted on this domain.
///
/// Operators terminate TLS upstream; this field tells webvh which scheme
/// to embed in resolution URLs (and which scheme inbound `Host` /
/// `Forwarded` resolution will match against).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainUrlScheme {
    /// Production default. Operators with HTTPS termination upstream
    /// pick this.
    Https,
    /// Dev / loopback only. Setup wizards emit a loud warning when
    /// this is selected for a non-loopback hostname.
    Http,
}

/// Lifecycle state of a domain.
///
/// Disabled domains retain their data; the state purely gates the
/// public resolution + management surfaces. Removing data requires an
/// explicit admin action (T30's `domain.purge`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainStatus {
    /// Resolution returns DID data; create / publish accepted.
    Active,
    /// Resolution returns 503 + structured JSON. Writes rejected with
    /// a `domain disabled` error. Data is preserved.
    Disabled,
}

impl DomainStatus {
    /// True for [`DomainStatus::Active`]. Convenience for `if`-let-style
    /// guards in handler code; reads better than `== Active`.
    pub fn is_active(self) -> bool {
        matches!(self, DomainStatus::Active)
    }
}

/// Optional branding metadata for the well-known endpoint.
///
/// Surfaced at `/.well-known/did-hosting-domain.json` **only** when the
/// parent `DomainEntry.well_known_enabled` is true.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainBranding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// External URL — not validated beyond serde shape. Operators link
    /// to their own static-hosted logo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tos_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact_email: Option<String>,
}

/// Per-domain quota override. Both fields independent; `None` = no
/// override (falls back to global).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainQuota {
    /// Cap on the number of DIDs that can be hosted in this domain
    /// across all ACL entries. `None` = no per-domain cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_dids_in_domain: Option<u64>,
    /// Cap on total bytes across all DID logs in this domain.
    /// `None` = no per-domain cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_size_in_domain: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> DomainEntry {
        DomainEntry {
            name: "example.com".into(),
            label: Some("Example Tenant".into()),
            scheme: DomainUrlScheme::Https,
            status: DomainStatus::Active,
            created_at: 1_700_000_000,
            default_domain: true,
            branding: Some(DomainBranding {
                display_name: Some("Example".into()),
                logo_url: Some("https://cdn.example.com/logo.png".into()),
                tos_url: None,
                contact_email: Some("ops@example.com".into()),
            }),
            witnesses: Some(vec!["did:webvh:WIT1:witness.example.com".into()]),
            watchers: None,
            quota: Some(DomainQuota {
                max_dids_in_domain: Some(1000),
                max_total_size_in_domain: None,
            }),
            well_known_enabled: true,
        }
    }

    #[test]
    fn round_trips_full_entry() {
        let original = sample_entry();
        let json = serde_json::to_string(&original).unwrap();
        let back: DomainEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn round_trips_minimal_entry() {
        let minimal = DomainEntry {
            name: "tenant.example.com".into(),
            label: None,
            scheme: DomainUrlScheme::Https,
            status: DomainStatus::Active,
            created_at: 1_700_000_000,
            default_domain: false,
            branding: None,
            witnesses: None,
            watchers: None,
            quota: None,
            well_known_enabled: false,
        };
        let json = serde_json::to_string(&minimal).unwrap();
        let back: DomainEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(minimal, back);
    }

    #[test]
    fn minimal_entry_omits_optional_fields() {
        let minimal = DomainEntry {
            name: "tenant.example.com".into(),
            label: None,
            scheme: DomainUrlScheme::Https,
            status: DomainStatus::Active,
            created_at: 0,
            default_domain: false,
            branding: None,
            witnesses: None,
            watchers: None,
            quota: None,
            well_known_enabled: false,
        };
        let json = serde_json::to_string(&minimal).unwrap();
        // `skip_serializing_if = "Option::is_none"` should keep the
        // wire shape compact.
        assert!(!json.contains("label"));
        assert!(!json.contains("branding"));
        assert!(!json.contains("witnesses"));
        assert!(!json.contains("watchers"));
        assert!(!json.contains("quota"));
    }

    #[test]
    fn legacy_entries_deserialize_with_defaults() {
        // A v0.6.0 future-shape preview: a stored entry without the
        // optional fields must continue to load. Forward-compatibility
        // is enforced by `#[serde(default)]` on the bool fields and
        // `Option<_>` defaults to None.
        let legacy = r#"{
            "name": "example.com",
            "scheme": "https",
            "status": "active",
            "created_at": 1700000000
        }"#;
        let e: DomainEntry = serde_json::from_str(legacy).unwrap();
        assert_eq!(e.name, "example.com");
        assert!(!e.default_domain);
        assert!(!e.well_known_enabled);
        assert!(e.branding.is_none());
    }

    #[test]
    fn scheme_serialises_lowercase() {
        let https = serde_json::to_string(&DomainUrlScheme::Https).unwrap();
        assert_eq!(https, "\"https\"");
        let http = serde_json::to_string(&DomainUrlScheme::Http).unwrap();
        assert_eq!(http, "\"http\"");
    }

    #[test]
    fn status_serialises_lowercase() {
        assert_eq!(
            serde_json::to_string(&DomainStatus::Active).unwrap(),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&DomainStatus::Disabled).unwrap(),
            "\"disabled\""
        );
    }

    #[test]
    fn status_is_active_helper() {
        assert!(DomainStatus::Active.is_active());
        assert!(!DomainStatus::Disabled.is_active());
    }

    #[test]
    fn branding_round_trips_with_all_fields() {
        let b = DomainBranding {
            display_name: Some("X".into()),
            logo_url: Some("https://cdn/x.png".into()),
            tos_url: Some("https://x/tos".into()),
            contact_email: Some("a@x".into()),
        };
        let json = serde_json::to_string(&b).unwrap();
        let back: DomainBranding = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
    }

    #[test]
    fn quota_partial_unset_fields_round_trip() {
        let q = DomainQuota {
            max_dids_in_domain: Some(50),
            max_total_size_in_domain: None,
        };
        let json = serde_json::to_string(&q).unwrap();
        // Only the set field should appear on the wire.
        assert!(json.contains("max_dids_in_domain"));
        assert!(!json.contains("max_total_size_in_domain"));
        let back: DomainQuota = serde_json::from_str(&json).unwrap();
        assert_eq!(q, back);
    }
}
