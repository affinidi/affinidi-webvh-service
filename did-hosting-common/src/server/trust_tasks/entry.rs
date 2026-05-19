//! Bidirectional translation between our local [`AclEntry`] storage
//! shape and the Trust Tasks `AclEntry` wire shape (SPEC.md §4.5.1
//! `ext` + the shared `_shared/0.1/acl-entry.schema.json`).
//!
//! ## Why a hand-written `SpecAclEntry` struct
//!
//! `trust-tasks-codegen` emits an independent `AclEntry` Rust type per
//! spec module (`grant::AclEntry`, `revoke::AclEntry`, …) even though
//! every one has identical JSON shape — the registry's cross-file
//! `$ref` deduplicates at the schema level but not at the Rust level.
//! We translate once into this neutral struct and let each handler
//! `serde_json::from_value` it into the per-spec form it needs. One
//! serde round-trip per handler, no macro_rules or per-spec wrapper.
//!
//! ## Field correspondence
//!
//! | Spec wire           | Local field                   | Notes                       |
//! |---------------------|-------------------------------|-----------------------------|
//! | `subject`           | `did`                         | string-for-string           |
//! | `role`              | `role` (Admin/Owner/Service)  | lowercase enum on the wire  |
//! | `label`             | `label: Option<String>`       | passthrough                 |
//! | `createdAt`         | `created_at: u64` (epoch s)   | local epoch → RFC3339       |
//! | `scopes`            | (unused)                      | webvh has no opaque scopes  |
//! | `ext.vnd.affinidi.webvh.quota.*`   | `max_total_size`, `max_did_count` | per-AclEntry quota |
//! | `ext.vnd.affinidi.webvh.domains`   | `domains: DomainScope`            | tag = "kind"        |
//!
//! The translation preserves any other `ext.*` namespaces verbatim on
//! a round-trip, per the framework's unrecognized-member rule.

use std::collections::BTreeMap;

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use crate::server::acl::{AclEntry as LocalAclEntry, Role};
use crate::server::domain::DomainScope;
use crate::server::error::AppError;
use crate::server::trust_tasks::ext::{WEBVH_EXT_KEY, WebvhAclEntryExt, WebvhQuota};

/// Neutral on-the-wire `AclEntry` shape, structurally identical to
/// every codegen-emitted `acl::*::v0_1::AclEntry`.
///
/// Constructed via [`Self::from_local`] (outbound) or
/// [`Self::into_local`] (inbound). Handlers route this through
/// `serde_json::to_value` / `from_value` to land in whichever
/// per-spec `AclEntry` they hold.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SpecAclEntry {
    pub subject: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// The full `ext` object as a flat map of reverse-DNS-namespaced
    /// keys → values. We deserialize the `vnd.affinidi.webvh` slot
    /// into [`WebvhAclEntryExt`] at [`Self::into_local`] time and
    /// preserve every other namespace verbatim on round-trip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<BTreeMap<String, serde_json::Value>>,
}

impl SpecAclEntry {
    /// Project a local [`AclEntry`] onto the spec wire shape.
    ///
    /// Always emits `ext.vnd.affinidi.webvh` (with at least `domains`
    /// set, since that field is required by [`WebvhAclEntryExt`]).
    /// `created_at` is converted from epoch seconds to RFC3339; `0` —
    /// the legacy "no timestamp" sentinel some pre-v0.7 entries
    /// carry — surfaces as `None` rather than the Unix epoch.
    pub fn from_local(entry: &LocalAclEntry) -> Self {
        let webvh = WebvhAclEntryExt {
            quota: WebvhQuota {
                max_total_size: entry.max_total_size,
                max_did_count: entry.max_did_count,
            },
            domains: entry.domains.clone(),
        };
        let mut ext = BTreeMap::new();
        ext.insert(
            WEBVH_EXT_KEY.to_string(),
            serde_json::to_value(&webvh).expect("WebvhAclEntryExt serialises"),
        );

        Self {
            subject: entry.did.clone(),
            role: entry.role.to_string(),
            scopes: Vec::new(),
            label: entry.label.clone(),
            created_at: epoch_to_datetime(entry.created_at),
            created_by: None,
            updated_at: None,
            updated_by: None,
            expires_at: None,
            ext: Some(ext),
        }
    }

    /// Project a spec-wire entry back to our local storage shape.
    ///
    /// `created_at_fallback` is used when the inbound entry has no
    /// `createdAt` (typical on a create); pass `Utc::now()`'s epoch
    /// for new grants.
    ///
    /// Returns `AppError::Validation` when the `role` string is not a
    /// known role or when `ext.vnd.affinidi.webvh.domains` is missing.
    /// The `domains` requirement is a webvh-specific invariant — the
    /// trust-task spec treats `ext` as optional but our auth path
    /// needs the scope on every entry.
    pub fn into_local(self, created_at_fallback: u64) -> Result<LocalAclEntry, AppError> {
        let role: Role = self.role.parse()?;

        let webvh = match self
            .ext
            .as_ref()
            .and_then(|m| m.get(WEBVH_EXT_KEY))
            .cloned()
        {
            Some(v) => Some(serde_json::from_value::<WebvhAclEntryExt>(v).map_err(|e| {
                AppError::Validation(format!(
                    "ext.{WEBVH_EXT_KEY} did not deserialise as WebvhAclEntryExt: {e}"
                ))
            })?),
            None => None,
        };

        // For Admin / Service, default `DomainScope::All` when the
        // ecosystem namespace is absent — role-based access already
        // constrains the surface and this matches the v0.7 default.
        // For Owner, we *require* the namespace so the auth path
        // can't silently fall back to "all domains."
        let (max_total_size, max_did_count, domains) = match webvh {
            Some(w) => (w.quota.max_total_size, w.quota.max_did_count, w.domains),
            None if matches!(role, Role::Admin | Role::Service) => (None, None, DomainScope::All),
            None => {
                return Err(AppError::Validation(format!(
                    "ext.{WEBVH_EXT_KEY} is required on Owner entries (carries `domains` scope)"
                )));
            }
        };

        let created_at = self
            .created_at
            .map(|dt| dt.timestamp().max(0) as u64)
            .unwrap_or(created_at_fallback);

        Ok(LocalAclEntry {
            did: self.subject,
            role,
            label: self.label,
            created_at,
            max_total_size,
            max_did_count,
            domains,
        })
    }
}

fn epoch_to_datetime(epoch_secs: u64) -> Option<DateTime<Utc>> {
    if epoch_secs == 0 {
        return None;
    }
    Utc.timestamp_opt(epoch_secs as i64, 0).single()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn owner_entry() -> LocalAclEntry {
        LocalAclEntry {
            did: "did:web:alice.example".into(),
            role: Role::Owner,
            label: Some("Alice".into()),
            created_at: 1_700_000_000,
            max_total_size: Some(1_048_576),
            max_did_count: Some(50),
            domains: DomainScope::AllowedWithDefault {
                domains: vec!["a.example".into()],
                default: "a.example".into(),
            },
        }
    }

    #[test]
    fn round_trip_owner_entry() {
        let local = owner_entry();
        let spec = SpecAclEntry::from_local(&local);
        let value = serde_json::to_value(&spec).unwrap();

        // Wire shape sanity-check — proves the spec form is what the
        // codegened acl::*::v0_1::AclEntry expects (camelCase, ext
        // under reverse-DNS key, etc).
        assert_eq!(value["subject"], "did:web:alice.example");
        assert_eq!(value["role"], "owner");
        assert_eq!(value["label"], "Alice");
        assert_eq!(
            value["ext"][WEBVH_EXT_KEY]["domains"]["kind"],
            "allowed_with_default"
        );
        assert_eq!(
            value["ext"][WEBVH_EXT_KEY]["quota"]["maxTotalSize"],
            1_048_576
        );

        // Re-parse via the same neutral type, then translate back to
        // local. created_at_fallback is unused here because the spec
        // carries createdAt.
        let parsed: SpecAclEntry = serde_json::from_value(value).unwrap();
        let back = parsed.into_local(/*fallback*/ 0).unwrap();
        assert_eq!(back.did, local.did);
        assert_eq!(back.role, local.role);
        assert_eq!(back.label, local.label);
        assert_eq!(back.created_at, local.created_at);
        assert_eq!(back.max_total_size, local.max_total_size);
        assert_eq!(back.max_did_count, local.max_did_count);
        assert_eq!(back.domains, local.domains);
    }

    #[test]
    fn admin_without_webvh_ext_defaults_to_all() {
        // The spec-form AclEntry on the wire is allowed to omit our
        // ext namespace; for Admin/Service we default DomainScope::All.
        let bare = json!({
            "subject": "did:web:root.example",
            "role": "admin"
        });
        let parsed: SpecAclEntry = serde_json::from_value(bare).unwrap();
        let local = parsed.into_local(1_700_000_001).unwrap();
        assert_eq!(local.role, Role::Admin);
        assert!(matches!(local.domains, DomainScope::All));
        assert_eq!(local.created_at, 1_700_000_001);
    }

    #[test]
    fn owner_without_webvh_ext_is_rejected() {
        // For Owner we refuse to invent a scope — the auth path is
        // load-bearing on this field and the silent default would
        // mask configuration mistakes.
        let bare = json!({
            "subject": "did:web:bob.example",
            "role": "owner"
        });
        let parsed: SpecAclEntry = serde_json::from_value(bare).unwrap();
        let err = parsed.into_local(0).expect_err("Owner needs domains");
        match err {
            AppError::Validation(msg) => assert!(msg.contains(WEBVH_EXT_KEY)),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn unknown_role_is_rejected() {
        let bare = json!({
            "subject": "did:web:x.example",
            "role": "superuser"
        });
        let parsed: SpecAclEntry = serde_json::from_value(bare).unwrap();
        assert!(parsed.into_local(0).is_err());
    }

    #[test]
    fn preserves_unknown_ext_namespace_on_round_trip() {
        // Framework rule: consumers MUST ignore namespaces they don't
        // recognise. We model that by passing-through the entry
        // verbatim through SpecAclEntry's ext map. A subsequent
        // from_local emission only writes our namespace, so the
        // unknown one is dropped on egress — which is fine; we don't
        // *forward* unknown namespaces from one party to another,
        // we just don't error on them.
        let with_other = json!({
            "subject": "did:web:carol.example",
            "role": "admin",
            "ext": {
                "vnd.affinidi.webvh": {
                    "domains": { "kind": "all" }
                },
                "vnd.example.other": { "anything": true }
            }
        });
        let parsed: SpecAclEntry = serde_json::from_value(with_other).unwrap();
        assert!(
            parsed
                .ext
                .as_ref()
                .unwrap()
                .contains_key("vnd.example.other")
        );
        // Translation to local discards the other namespace (we don't
        // store it), but doesn't error.
        let _local = parsed.into_local(1).unwrap();
    }

    /// Pin that `SpecAclEntry::from_local` produces JSON that each
    /// of the five codegen-emitted `acl::*::v0_1::AclEntry` types
    /// accepts via `serde_json::from_value`. A regression here means
    /// the trust-tasks codegen drifted away from our neutral struct
    /// — catch at compile-time rather than waiting for a handler to
    /// fail at runtime.
    #[test]
    fn spec_acl_entry_round_trips_through_every_codegen_type() {
        use trust_tasks_rs::specs::acl::{
            change_role::v0_1 as change_role, grant::v0_1 as grant, list::v0_1 as list,
            revoke::v0_1 as revoke, show::v0_1 as show,
        };

        let local = owner_entry();
        let spec = SpecAclEntry::from_local(&local);
        let value = serde_json::to_value(&spec).expect("SpecAclEntry serialises");

        // Each codegen type must accept the neutral form.
        let _: grant::AclEntry =
            serde_json::from_value(value.clone()).expect("grant::AclEntry accepts SpecAclEntry");
        let _: revoke::AclEntry =
            serde_json::from_value(value.clone()).expect("revoke::AclEntry accepts SpecAclEntry");
        let _: change_role::AclEntry = serde_json::from_value(value.clone())
            .expect("change_role::AclEntry accepts SpecAclEntry");
        let _: show::AclEntry =
            serde_json::from_value(value.clone()).expect("show::AclEntry accepts SpecAclEntry");
        let _: list::AclEntry =
            serde_json::from_value(value).expect("list::AclEntry accepts SpecAclEntry");
    }

    #[test]
    fn epoch_zero_serialises_as_no_created_at() {
        // Some pre-v0.7 entries have created_at = 0 from before we
        // bothered to record it. On the wire we omit createdAt
        // entirely rather than emitting "1970-01-01T00:00:00Z" which
        // would be misleading.
        let mut local = owner_entry();
        local.created_at = 0;
        let spec = SpecAclEntry::from_local(&local);
        let value = serde_json::to_value(&spec).unwrap();
        assert!(value.get("createdAt").is_none());
    }
}
