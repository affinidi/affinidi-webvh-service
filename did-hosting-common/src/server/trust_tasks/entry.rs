//! Bidirectional translation between our local [`AclEntry`] storage
//! shape and the Trust Tasks AclEntry 0.2 wire shape
//! (`acl/_shared/0.2/acl-entry.schema.json`), used by every `acl/*` task
//! this service serves.
//!
//! ## Why a hand-written `SpecAclEntry` struct
//!
//! The generator emits an independent `AclEntry` Rust type per spec module
//! (`grant::AclEntry`, `revoke::AclEntry`, …) even though every one has the
//! same JSON shape. We translate once into this neutral struct and let each
//! handler `serde_json::from_value` it into the per-spec form it needs.
//!
//! ## How this maintainer states authority
//!
//! AclEntry 0.2 states every element of authority explicitly; nothing is
//! inferred from an absent member or an empty list. This maintainer's model
//! is a role plus, for the roles that are domain-checked, the set of domains
//! the subject may act on. It maps onto 0.2 like this:
//!
//! | 0.2 member            | This maintainer                                   |
//! |-----------------------|---------------------------------------------------|
//! | `act`                 | The entry's domains are its contexts. `Admin` and `Service` are never domain-checked (`domain::safety`), so their act is always `all`. For `Owner` and `MetricsReader`: `DomainScope::All` → `all`; a non-empty domain list → `contexts`; an empty one → `none`. |
//! | `keys`                | `none` — except on a service that runs a signing oracle (the witness), where an `Admin` may have the witness sign with any of its keys: `all`. |
//! | `capabilities`        | `ceiling`. This maintainer has no capability registry; a role's whole ceiling is what an entry holds. |
//! | `approve`, `approveCapabilities` | absent (none): this maintainer has no approvers. |
//! | `delegatedBy`         | absent: the maintainer records no provenance.     |
//! | `ext.vnd.affinidi.webvh` | `quota` and `defaultDomain` — never authority. |
//!
//! Inbound, an entry this maintainer cannot hold *exactly* is refused, never
//! approximated: holding less than was asked silently is a different grant,
//! and holding more is a widening. See [`SpecAclEntry::into_local`].

use std::collections::BTreeMap;

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use crate::server::acl::{AclEntry as LocalAclEntry, Role};
use crate::server::domain::DomainScope;
use crate::server::trust_tasks::ext::{WEBVH_EXT_KEY, WebvhAclEntryExt, WebvhQuota};

/// An explicit authority scope — AclEntry 0.2's `act` and `approve`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "camelCase")]
pub enum AuthorityScope {
    /// Unrestricted.
    All,
    /// No authority on this axis.
    None,
    /// The named contexts — for this maintainer, domains. Never empty on the
    /// wire; an empty list is malformed.
    Contexts { contexts: Vec<String> },
}

/// An explicit key scope — AclEntry 0.2's `keys`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "camelCase")]
pub enum KeyScope {
    All,
    None,
    Listed { keys: Vec<String> },
}

/// An explicit capability scope — AclEntry 0.2's `capabilities` and
/// `approveCapabilities`. The listed grants are kept as JSON: this
/// maintainer recognises no capability, so it only ever reads their names.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "camelCase")]
pub enum CapabilityScope {
    Ceiling,
    None,
    Listed { grants: Vec<serde_json::Value> },
}

/// Neutral AclEntry 0.2 wire shape, structurally identical to every
/// generated `acl::*::v0_2::AclEntry` (and `acl::list::v0_3::AclEntry`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SpecAclEntry {
    pub subject: String,
    pub role: String,
    pub act: AuthorityScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approve: Option<AuthorityScope>,
    pub keys: KeyScope,
    pub capabilities: CapabilityScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approve_capabilities: Option<CapabilityScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_by: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_up: Option<serde_json::Value>,
    /// The full `ext` object as a flat map of reverse-DNS-namespaced
    /// keys → values. Only `vnd.affinidi.webvh` is read; other namespaces
    /// are ignored, per the framework's unrecognized-member rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<BTreeMap<String, serde_json::Value>>,
}

/// Why an inbound entry cannot be held. Each handler renders it with the
/// error code its own specification declares for the case.
#[derive(Debug, Clone, PartialEq)]
pub enum EntryRefusal {
    /// The role is not in this maintainer's vocabulary (`roleNotRecognized`).
    RoleNotRecognized(String),
    /// An `act` or `approve` scope this maintainer cannot hold
    /// (`invalidActScope`). `member` is `act` or `approve`.
    InvalidActScope {
        member: &'static str,
        message: String,
    },
    /// Listed capabilities; this maintainer recognises none
    /// (`unknownCapability`).
    UnknownCapability(Vec<String>),
    /// A member this maintainer has no way to hold and will not drop
    /// (`expiresAt`, `stepUp`, a key scope or capability scope other than the
    /// one it holds).
    NotSupported {
        member: &'static str,
        message: String,
    },
    /// Well-formed JSON the specification nonetheless rules out (an empty
    /// list, a `defaultDomain` outside the act scope, …).
    Malformed(String),
}

impl std::fmt::Display for EntryRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RoleNotRecognized(r) => write!(f, "role {r:?} is not recognised"),
            Self::InvalidActScope { message, .. } | Self::Malformed(message) => {
                f.write_str(message)
            }
            Self::UnknownCapability(c) => {
                write!(f, "this maintainer recognises no capability: {c:?}")
            }
            Self::NotSupported { message, .. } => f.write_str(message),
        }
    }
}

/// Whether `role` is checked against the entry's domains. `Admin` and
/// `Service` short-circuit the check (`domain::safety::assert_acl_allows_host`),
/// so their act scope is `all` whatever their stored domains say.
pub fn role_is_domain_scoped(role: &Role) -> bool {
    !matches!(role, Role::Admin | Role::Service)
}

/// The act scope a local entry holds.
pub fn act_of(entry: &LocalAclEntry) -> AuthorityScope {
    if !role_is_domain_scoped(&entry.role) {
        return AuthorityScope::All;
    }
    act_of_domains(&entry.domains)
}

/// The act scope a domain scope states, for a domain-checked role.
pub fn act_of_domains(domains: &DomainScope) -> AuthorityScope {
    let list = match domains {
        DomainScope::All => return AuthorityScope::All,
        DomainScope::Allowed { domains } | DomainScope::AllowedWithDefault { domains, .. } => {
            domains
        }
    };
    if list.is_empty() {
        AuthorityScope::None
    } else {
        AuthorityScope::Contexts {
            contexts: list.clone(),
        }
    }
}

/// The key scope a local entry holds. `signing_oracle` is whether this
/// service will sign on an ACL member's behalf (the witness does, for an
/// `Admin`, with any witness key).
pub fn keys_of(role: &Role, signing_oracle: bool) -> KeyScope {
    if signing_oracle && matches!(role, Role::Admin) {
        KeyScope::All
    } else {
        KeyScope::None
    }
}

/// Whether act scope `wide` covers every context `narrow` does.
pub fn act_covers(wide: &AuthorityScope, narrow: &AuthorityScope) -> bool {
    match (wide, narrow) {
        (AuthorityScope::All, _) | (_, AuthorityScope::None) => true,
        (AuthorityScope::None, _) | (AuthorityScope::Contexts { .. }, AuthorityScope::All) => false,
        (AuthorityScope::Contexts { contexts: w }, AuthorityScope::Contexts { contexts: n }) => {
            n.iter().all(|c| w.contains(c))
        }
    }
}

/// Reject an empty or repeated context list, which the schema rules out.
pub fn check_authority_scope(scope: &AuthorityScope, member: &str) -> Result<(), EntryRefusal> {
    if let AuthorityScope::Contexts { contexts } = scope {
        if contexts.is_empty() {
            return Err(EntryRefusal::Malformed(format!(
                "`{member}.contexts` is empty; state `{{\"scope\": \"none\"}}` instead"
            )));
        }
        let mut seen = std::collections::HashSet::new();
        if !contexts.iter().all(|c| !c.is_empty() && seen.insert(c)) {
            return Err(EntryRefusal::Malformed(format!(
                "`{member}.contexts` repeats a context or names an empty one"
            )));
        }
    }
    Ok(())
}

/// The domain scope a domain-checked role holds for `act`, keeping
/// `default` only where it is still one of the domains.
pub fn domains_for_act(act: &AuthorityScope, default: Option<&str>) -> DomainScope {
    match act {
        AuthorityScope::All => DomainScope::All,
        AuthorityScope::None => DomainScope::Allowed { domains: vec![] },
        AuthorityScope::Contexts { contexts } => match default {
            Some(d) if contexts.iter().any(|c| c == d) => DomainScope::AllowedWithDefault {
                domains: contexts.clone(),
                default: d.to_string(),
            },
            _ => DomainScope::Allowed {
                domains: contexts.clone(),
            },
        },
    }
}

impl SpecAclEntry {
    /// Project a local [`AclEntry`] onto the AclEntry 0.2 wire shape.
    ///
    /// `created_at` is converted from epoch seconds to RFC3339; `0` — the
    /// legacy "no timestamp" sentinel some pre-v0.7 entries carry — surfaces
    /// as `None` rather than the Unix epoch.
    pub fn from_local(entry: &LocalAclEntry, signing_oracle: bool) -> Self {
        let default_domain = match &entry.domains {
            DomainScope::AllowedWithDefault { default, .. }
                if role_is_domain_scoped(&entry.role) =>
            {
                Some(default.clone())
            }
            _ => None,
        };
        let webvh = WebvhAclEntryExt {
            quota: WebvhQuota {
                max_total_size: entry.max_total_size,
                max_did_count: entry.max_did_count,
            },
            default_domain,
        };
        let ext = (!webvh.is_empty()).then(|| {
            BTreeMap::from([(
                WEBVH_EXT_KEY.to_string(),
                serde_json::to_value(&webvh).expect("WebvhAclEntryExt serialises"),
            )])
        });

        Self {
            subject: entry.did.clone(),
            role: entry.role.to_string(),
            act: act_of(entry),
            approve: None,
            keys: keys_of(&entry.role, signing_oracle),
            capabilities: CapabilityScope::Ceiling,
            approve_capabilities: None,
            delegated_by: None,
            label: entry.label.clone(),
            created_at: epoch_to_datetime(entry.created_at),
            created_by: None,
            updated_at: None,
            updated_by: None,
            expires_at: None,
            step_up: None,
            ext,
        }
    }

    /// Project a spec-wire entry back to our local storage shape, refusing
    /// anything this maintainer cannot hold exactly.
    ///
    /// `created_at_fallback` is used when the inbound entry has no
    /// `createdAt` (typical on a create). The provenance members
    /// (`createdAt`/`By`, `updatedAt`/`By`, `delegatedBy`) are the
    /// maintainer's to set and are otherwise ignored.
    pub fn into_local(
        self,
        created_at_fallback: u64,
        signing_oracle: bool,
    ) -> Result<LocalAclEntry, EntryRefusal> {
        let role: Role = self
            .role
            .parse()
            .map_err(|_| EntryRefusal::RoleNotRecognized(self.role.clone()))?;

        check_authority_scope(&self.act, "act")?;
        if let Some(approve) = &self.approve {
            check_authority_scope(approve, "approve")?;
            if *approve != AuthorityScope::None {
                return Err(EntryRefusal::InvalidActScope {
                    member: "approve",
                    message: "this maintainer has no approvers; `approve` must be absent or `none`"
                        .into(),
                });
            }
        }
        if !role_is_domain_scoped(&role) && self.act != AuthorityScope::All {
            return Err(EntryRefusal::InvalidActScope {
                member: "act",
                message: format!(
                    "a {role} entry acts on every domain; its act scope can only be `all`"
                ),
            });
        }

        match &self.capabilities {
            CapabilityScope::Ceiling => {}
            CapabilityScope::Listed { grants } if grants.is_empty() => {
                return Err(EntryRefusal::Malformed(
                    "`capabilities.grants` is empty; state `{\"scope\": \"none\"}` instead".into(),
                ));
            }
            CapabilityScope::Listed { grants } => {
                return Err(EntryRefusal::UnknownCapability(
                    grants
                        .iter()
                        .map(|g| {
                            g.get("capability")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or_default()
                                .to_string()
                        })
                        .collect(),
                ));
            }
            CapabilityScope::None => {
                return Err(EntryRefusal::NotSupported {
                    member: "capabilities",
                    message: "this maintainer's roles carry their whole ceiling; \
                              `capabilities` can only be `ceiling`"
                        .into(),
                });
            }
        }
        // `approveCapabilities` confers nothing while `approve` is absent or
        // none (checked above), so whatever it states is not held.

        if let KeyScope::Listed { keys } = &self.keys
            && keys.is_empty()
        {
            return Err(EntryRefusal::Malformed(
                "`keys.keys` is empty; state `{\"scope\": \"none\"}` instead".into(),
            ));
        }
        let held_keys = keys_of(&role, signing_oracle);
        if self.keys != held_keys {
            return Err(EntryRefusal::NotSupported {
                member: "keys",
                message: format!(
                    "a {role} entry here holds the key scope {}; this maintainer cannot hold \
                     another",
                    serde_json::to_string(&held_keys).expect("KeyScope serialises")
                ),
            });
        }
        if self.expires_at.is_some() {
            return Err(EntryRefusal::NotSupported {
                member: "expiresAt",
                message: "this maintainer does not expire entries; omit `expiresAt` rather \
                          than have it ignored"
                    .into(),
            });
        }
        if self.step_up.is_some() {
            return Err(EntryRefusal::NotSupported {
                member: "stepUp",
                message: "this maintainer has no per-entry step-up; omit `stepUp` rather than \
                          have it ignored"
                    .into(),
            });
        }

        let webvh = match self
            .ext
            .as_ref()
            .and_then(|m| m.get(WEBVH_EXT_KEY))
            .cloned()
        {
            Some(v) => serde_json::from_value::<WebvhAclEntryExt>(v).map_err(|e| {
                EntryRefusal::Malformed(format!(
                    "ext.{WEBVH_EXT_KEY} is malformed (its members are `quota` and \
                     `defaultDomain`; an entry's domains are its `act` scope): {e}"
                ))
            })?,
            None => WebvhAclEntryExt::default(),
        };

        let domains = if role_is_domain_scoped(&role) {
            if let Some(default) = webvh.default_domain.as_deref() {
                let in_act = matches!(
                    &self.act,
                    AuthorityScope::Contexts { contexts } if contexts.iter().any(|c| c == default)
                );
                if !in_act {
                    return Err(EntryRefusal::Malformed(format!(
                        "ext.{WEBVH_EXT_KEY}.defaultDomain {default:?} is not one of the entry's \
                         act contexts"
                    )));
                }
            }
            domains_for_act(&self.act, webvh.default_domain.as_deref())
        } else {
            if webvh.default_domain.is_some() {
                return Err(EntryRefusal::Malformed(format!(
                    "a {role} entry is not domain-scoped; ext.{WEBVH_EXT_KEY}.defaultDomain \
                     does not apply"
                )));
            }
            DomainScope::All
        };

        let created_at = self
            .created_at
            .map(|dt| dt.timestamp().max(0) as u64)
            .unwrap_or(created_at_fallback);

        Ok(LocalAclEntry {
            // Recorded under the identity: a did:scid subject without the
            // `src` locator a request may carry (VTI-KEY-160).
            did: crate::scid::identity(&self.subject),
            role,
            label: self.label,
            created_at,
            max_total_size: webvh.quota.max_total_size,
            max_did_count: webvh.quota.max_did_count,
            domains,
        })
    }

    /// Re-type this entry as a generated spec `AclEntry` (same JSON shape).
    pub fn into_spec<T: serde::de::DeserializeOwned>(&self) -> T {
        let value = serde_json::to_value(self).expect("SpecAclEntry serialises");
        serde_json::from_value(value).expect("generated AclEntry accepts the SpecAclEntry shape")
    }

    /// Read a generated spec `AclEntry` as this neutral shape.
    pub fn from_spec<T: Serialize>(spec: &T) -> Result<Self, EntryRefusal> {
        let value = serde_json::to_value(spec)
            .map_err(|e| EntryRefusal::Malformed(format!("entry serialises: {e}")))?;
        serde_json::from_value(value)
            .map_err(|e| EntryRefusal::Malformed(format!("entry is not an AclEntry 0.2: {e}")))
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
                domains: vec!["a.example".into(), "b.example".into()],
                default: "a.example".into(),
            },
        }
    }

    fn parse(v: serde_json::Value) -> SpecAclEntry {
        serde_json::from_value(v).expect("AclEntry 0.2 shape")
    }

    #[test]
    fn round_trip_owner_entry() {
        let local = owner_entry();
        let spec = SpecAclEntry::from_local(&local, false);
        let value = serde_json::to_value(&spec).unwrap();

        assert_eq!(value["subject"], "did:web:alice.example");
        assert_eq!(value["role"], "owner");
        assert_eq!(
            value["act"],
            json!({ "scope": "contexts", "contexts": ["a.example", "b.example"] })
        );
        assert_eq!(value["keys"], json!({ "scope": "none" }));
        assert_eq!(value["capabilities"], json!({ "scope": "ceiling" }));
        assert!(
            value.get("approve").is_none(),
            "no approvers: absent = none"
        );
        assert_eq!(value["ext"][WEBVH_EXT_KEY]["defaultDomain"], "a.example");
        assert_eq!(
            value["ext"][WEBVH_EXT_KEY]["quota"]["maxTotalSize"],
            1_048_576
        );

        let back = parse(value).into_local(0, false).unwrap();
        assert_eq!(back.did, local.did);
        assert_eq!(back.role, local.role);
        assert_eq!(back.label, local.label);
        assert_eq!(back.created_at, local.created_at);
        assert_eq!(back.max_total_size, local.max_total_size);
        assert_eq!(back.max_did_count, local.max_did_count);
        assert_eq!(back.domains, local.domains);
    }

    #[test]
    fn act_states_the_domains_and_never_widens_an_empty_list() {
        let mut e = owner_entry();
        e.domains = DomainScope::Allowed { domains: vec![] };
        assert_eq!(
            act_of(&e),
            AuthorityScope::None,
            "no domains is `none`, never `all`"
        );
        e.domains = DomainScope::All;
        assert_eq!(act_of(&e), AuthorityScope::All);
        // Admin and Service are not domain-checked: `all` whatever is stored.
        e.role = Role::Admin;
        e.domains = DomainScope::Allowed { domains: vec![] };
        assert_eq!(act_of(&e), AuthorityScope::All);
    }

    #[test]
    fn keys_track_the_signing_oracle() {
        assert_eq!(keys_of(&Role::Admin, false), KeyScope::None);
        assert_eq!(keys_of(&Role::Admin, true), KeyScope::All);
        assert_eq!(keys_of(&Role::Owner, true), KeyScope::None);
    }

    fn admin(act: serde_json::Value) -> serde_json::Value {
        json!({
            "subject": "did:web:root.example",
            "role": "admin",
            "act": act,
            "keys": { "scope": "none" },
            "capabilities": { "scope": "ceiling" }
        })
    }

    #[test]
    fn admin_entry_maps_to_all_domains() {
        let local = parse(admin(json!({ "scope": "all" })))
            .into_local(1_700_000_001, false)
            .unwrap();
        assert_eq!(local.role, Role::Admin);
        assert!(matches!(local.domains, DomainScope::All));
        assert_eq!(local.created_at, 1_700_000_001);
    }

    #[test]
    fn an_admin_act_scope_narrower_than_all_is_refused() {
        let err = parse(admin(
            json!({ "scope": "contexts", "contexts": ["a.example"] }),
        ))
        .into_local(0, false)
        .unwrap_err();
        assert!(
            matches!(err, EntryRefusal::InvalidActScope { member: "act", .. }),
            "{err:?}"
        );
    }

    #[test]
    fn owner_with_act_none_holds_no_domains() {
        let mut v = admin(json!({ "scope": "none" }));
        v["role"] = json!("owner");
        let local = parse(v).into_local(0, false).unwrap();
        assert_eq!(local.domains, DomainScope::Allowed { domains: vec![] });
    }

    #[test]
    fn empty_contexts_are_malformed_not_all_or_none() {
        let mut v = admin(json!({ "scope": "contexts", "contexts": [] }));
        v["role"] = json!("owner");
        assert!(matches!(
            parse(v).into_local(0, false).unwrap_err(),
            EntryRefusal::Malformed(_)
        ));
    }

    #[test]
    fn default_domain_must_be_an_act_context() {
        let mut v = admin(json!({ "scope": "contexts", "contexts": ["a.example"] }));
        v["role"] = json!("owner");
        v["ext"] = json!({ WEBVH_EXT_KEY: { "defaultDomain": "b.example" } });
        assert!(matches!(
            parse(v).into_local(0, false).unwrap_err(),
            EntryRefusal::Malformed(_)
        ));
    }

    #[test]
    fn what_this_maintainer_cannot_hold_is_refused_not_dropped() {
        let cases = [
            ("approve", json!({ "scope": "all" })),
            ("capabilities", json!({ "scope": "none" })),
            ("keys", json!({ "scope": "all" })),
            ("expiresAt", json!("2030-01-01T00:00:00Z")),
            ("stepUp", json!({ "require": "self" })),
        ];
        for (member, value) in cases {
            let mut v = admin(json!({ "scope": "all" }));
            v[member] = value;
            assert!(
                parse(v).into_local(0, false).is_err(),
                "{member} must be refused"
            );
        }
        let mut v = admin(json!({ "scope": "all" }));
        v["capabilities"] = json!({ "scope": "listed", "grants": [{ "capability": "keys.sign" }] });
        assert_eq!(
            parse(v).into_local(0, false).unwrap_err(),
            EntryRefusal::UnknownCapability(vec!["keys.sign".into()])
        );
    }

    #[test]
    fn unknown_role_is_refused() {
        let mut v = admin(json!({ "scope": "all" }));
        v["role"] = json!("superuser");
        assert_eq!(
            parse(v).into_local(0, false).unwrap_err(),
            EntryRefusal::RoleNotRecognized("superuser".into())
        );
    }

    #[test]
    fn unknown_ext_namespace_is_ignored() {
        let mut v = admin(json!({ "scope": "all" }));
        v["ext"] = json!({ "vnd.example.other": { "anything": true } });
        parse(v).into_local(1, false).unwrap();
    }

    /// `SpecAclEntry::from_local` produces JSON that each generated
    /// `AclEntry` type accepts: catch generator drift here rather than in a
    /// handler at runtime.
    #[test]
    fn spec_acl_entry_round_trips_through_every_codegen_type() {
        use crate::tasks::acl::{
            change_role::v0_2 as change_role, grant::v0_2 as grant, list::v0_3 as list,
            revoke::v0_2 as revoke, show::v0_2 as show,
        };
        for oracle in [false, true] {
            for role in [Role::Owner, Role::Admin] {
                let mut local = owner_entry();
                local.role = role;
                let spec = SpecAclEntry::from_local(&local, oracle);
                let _: grant::AclEntry = spec.into_spec();
                let _: revoke::AclEntry = spec.into_spec();
                let _: change_role::AclEntry = spec.into_spec();
                let _: show::AclEntry = spec.into_spec();
                let _: list::AclEntry = spec.into_spec();
            }
        }
    }

    #[test]
    fn epoch_zero_serialises_as_no_created_at() {
        let mut local = owner_entry();
        local.created_at = 0;
        let value = serde_json::to_value(SpecAclEntry::from_local(&local, false)).unwrap();
        assert!(value.get("createdAt").is_none());
    }
}
