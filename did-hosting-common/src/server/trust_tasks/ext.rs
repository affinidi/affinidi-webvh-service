//! `vnd.affinidi.webvh` — webvh-specific extension shape carried in the
//! `ext` slot of every `acl/*` AclEntry 0.2 document we emit or accept.
//!
//! See SPEC.md §4.5.1 (Trust Tasks framework). The `ext` slot is the
//! sanctioned extension point for ecosystem-defined fields that the
//! base specification does not enumerate. Reverse-DNS namespaces; we
//! own `vnd.affinidi.webvh`.
//!
//! ## Wire shape
//!
//! ```json
//! "ext": {
//!   "vnd.affinidi.webvh": {
//!     "quota":         { "maxTotalSize": 1048576, "maxDidCount": 50 },
//!     "defaultDomain": "a.example"
//!   }
//! }
//! ```
//!
//! Nothing here confers authority: AclEntry 0.2 forbids reading an
//! extension member as a grant. Where an entry may act — its domains — is
//! the entry's `act` scope (see [`super::entry`]). This namespace carries
//! only the two things that are not authority:
//!
//! - `quota` — per-entry limits. Both members are individually optional; an
//!   absent value means "inherit the deployment-wide default".
//! - `defaultDomain` — the domain used when a request names none. It must be
//!   one of the entry's `act` contexts, and is meaningless otherwise.
//!
//! Consumers that do not implement webvh **MUST** ignore this namespace
//! per the framework's unrecognized-member rule.

use serde::{Deserialize, Serialize};

/// Reverse-DNS key under which webvh-specific ACL extensions land.
pub const WEBVH_EXT_KEY: &str = "vnd.affinidi.webvh";

/// Typed view over the `vnd.affinidi.webvh` namespace inside an
/// AclEntry's `ext` member.
///
/// Deserialised on the way in and serialised on the way out; the rest
/// of the `ext` object (other vendor namespaces) is ignored — this struct
/// only models the slice that belongs to us.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WebvhAclEntryExt {
    /// Quota knobs (max bytes per DID, max DID count). Both members are
    /// optional; an absent value means "use the deployment default."
    #[serde(default, skip_serializing_if = "WebvhQuota::is_empty")]
    pub quota: WebvhQuota,

    /// The domain a request that names none is served on. One of the
    /// entry's `act` contexts; absent when the entry has no default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_domain: Option<String>,
}

impl WebvhAclEntryExt {
    /// Whether the namespace says nothing, so it can be left off the wire.
    pub fn is_empty(&self) -> bool {
        self.quota.is_empty() && self.default_domain.is_none()
    }
}

/// Quota knobs on a per-AclEntry basis. Both members are individually
/// optional. Empty (`{}`) is the legal "everything inherits the
/// deployment default" form and is omitted on serialisation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WebvhQuota {
    /// Per-account ceiling on the sum of all DID document sizes in
    /// bytes. `None` ⇒ inherit the deployment-wide
    /// `max_total_size_default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_size: Option<u64>,

    /// Per-account ceiling on the number of DIDs an Owner may host.
    /// `None` ⇒ inherit the deployment-wide `max_did_count_default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_did_count: Option<u64>,
}

impl WebvhQuota {
    /// Whether every member is `None`. Drives `skip_serializing_if` on
    /// [`WebvhAclEntryExt::quota`] so an empty quota object doesn't
    /// land on the wire.
    pub fn is_empty(&self) -> bool {
        self.max_total_size.is_none() && self.max_did_count.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_trips_full_shape() {
        let ext = WebvhAclEntryExt {
            quota: WebvhQuota {
                max_total_size: Some(1_048_576),
                max_did_count: Some(50),
            },
            default_domain: Some("a.example".into()),
        };
        let value = serde_json::to_value(&ext).unwrap();
        assert_eq!(
            value,
            json!({
                "quota": { "maxTotalSize": 1_048_576, "maxDidCount": 50 },
                "defaultDomain": "a.example"
            })
        );
        let back: WebvhAclEntryExt = serde_json::from_value(value).unwrap();
        assert_eq!(back, ext);
    }

    #[test]
    fn empty_namespace_serialises_as_empty_object() {
        let ext = WebvhAclEntryExt::default();
        assert!(ext.is_empty());
        assert_eq!(serde_json::to_value(&ext).unwrap(), json!({}));
    }

    #[test]
    fn deserialise_rejects_unknown_member_at_top_level() {
        // `deny_unknown_fields` on WebvhAclEntryExt — typos like
        // `"qouta"` (sic) are rejected at parse time rather than being
        // silently dropped. The framework requires consumers to ignore
        // unknown *namespaces*, but inside our namespace we control
        // the shape and can be strict.
        assert!(serde_json::from_value::<WebvhAclEntryExt>(json!({ "qouta": {} })).is_err());
    }

    #[test]
    fn the_0_1_domains_member_is_refused() {
        // Domain authority moved to the entry's `act` scope with AclEntry
        // 0.2; a producer still sending it here must not have it ignored.
        let legacy = json!({ "domains": { "kind": "all" } });
        assert!(serde_json::from_value::<WebvhAclEntryExt>(legacy).is_err());
    }

    #[test]
    fn quota_round_trips_partial() {
        // max_total_size set, max_did_count unset — only the set
        // member is emitted, the unset member is omitted.
        let q = WebvhQuota {
            max_total_size: Some(500_000),
            max_did_count: None,
        };
        let value = serde_json::to_value(&q).unwrap();
        assert_eq!(value, json!({ "maxTotalSize": 500_000 }));
        let back: WebvhQuota = serde_json::from_value(value).unwrap();
        assert_eq!(back, q);
    }
}
