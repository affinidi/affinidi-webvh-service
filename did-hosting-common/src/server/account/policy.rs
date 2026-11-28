//! Each hosting domain's self-registration terms, held at runtime.
//!
//! Whether a domain admits parties with no account
//! (`did-management/account/register`), by which evidence, which authorising
//! parties' vouchers it trusts, where their DIDs sit, what they may hold and
//! when they expire: an administrator reads and replaces these with
//! `did-management/account/policy/{list,set}` while the service runs, and
//! every registration reads them as they stand. `[[hosting.guest_register]]`
//! in the configuration only seeds a domain that has no stored terms
//! ([`seed_from_config`]), as `bootstrap_domains` seeds the domain registry:
//! after that, the stored terms are what apply.
//!
//! A domain with no terms, or with terms that are not `enabled`, admits no
//! one. Closing a domain removes no account: its existing self-registered
//! accounts keep their DIDs, renew and expire under the terms as they stand.

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::server::config::{GuestAdmission, GuestRegistration};
use crate::server::domain::normalize_domain_name;
use crate::server::error::AppError;
use crate::server::store::KeyspaceHandle;

/// The prefix every domain's terms are stored under.
pub const POLICY_PREFIX: &str = "acct_policy:";

/// The `updated_by` of terms seeded from the configuration.
pub const OPERATOR: &str = "operator";

fn policy_key(domain: &str) -> String {
    let canonical = normalize_domain_name(domain).unwrap_or_else(|_| domain.to_string());
    format!("{POLICY_PREFIX}{canonical}")
}

/// An authorising party whose `DidHostingVoucher`s admit a registrant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedIssuer {
    /// The party's DID: a voucher's `issuer`.
    pub did: String,
    /// The operator's name for it. Never published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// One domain's terms.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelfRegistrationPolicy {
    /// The hosting domain, canonical.
    pub domain: String,
    /// Whether it admits new registrations now.
    pub enabled: bool,
    pub admissions: Vec<GuestAdmission>,
    pub trusted_issuers: Vec<TrustedIssuer>,
    /// Every DID a self-registered account holds sits under one of these
    /// `/`-separated prefixes, on whole segments. Empty: any path.
    pub path_prefixes: Vec<String>,
    pub max_registrations: u32,
    /// `None`: the service's ordinary per-account limit.
    pub max_did_count: Option<u64>,
    /// `None`: the service's ordinary per-account limit.
    pub max_total_size: Option<u64>,
    /// `0`: accounts on this domain do not expire.
    pub inactivity_days: u32,
    pub grace_days: u32,
    pub max_pending_invites: u32,
    pub updated_at: u64,
    /// The administrator's DID, or [`OPERATOR`] for seeded terms.
    pub updated_by: String,
}

impl SelfRegistrationPolicy {
    /// The terms `[[hosting.guest_register]]` states, seeded by the operator.
    pub fn from_config(entry: &GuestRegistration, now: u64) -> Self {
        Self {
            domain: normalize_domain_name(&entry.domain).unwrap_or_else(|_| entry.domain.clone()),
            enabled: true,
            admissions: entry.admissions.clone(),
            trusted_issuers: entry
                .trusted_voucher_issuers
                .iter()
                .map(|did| TrustedIssuer {
                    did: did.clone(),
                    label: None,
                })
                .collect(),
            path_prefixes: entry.path_prefixes.clone(),
            max_registrations: entry.max_registrations,
            max_did_count: entry.max_did_count.map(|n| n.get()),
            max_total_size: entry.max_total_size,
            inactivity_days: entry.inactivity_days,
            grace_days: entry.grace_days,
            max_pending_invites: entry.max_pending_invites,
            updated_at: now,
            updated_by: OPERATOR.into(),
        }
    }

    /// Whether the domain admits a new registration by `admission` now.
    pub fn admits(&self, admission: GuestAdmission) -> bool {
        self.enabled && self.admissions.contains(&admission)
    }

    /// Whether a slot at `path` sits under one of the prefixes, on whole
    /// `/`-separated segments, with a segment of its own after the prefix.
    pub fn admits_path(&self, path: &str) -> bool {
        self.path_prefixes.is_empty()
            || self.path_prefixes.iter().any(|prefix| {
                let prefix = prefix.trim_matches('/');
                !prefix.is_empty()
                    && path
                        .strip_prefix(prefix)
                        .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1)
            })
    }

    /// Whether `issuer` (compared as an identity) is a party whose vouchers
    /// the domain accepts now.
    pub fn trusts_voucher_issuer(&self, issuer: &str) -> bool {
        self.admits(GuestAdmission::Voucher)
            && self
                .trusted_issuers
                .iter()
                .any(|t| crate::scid::same_reference(&t.did, issuer))
    }

    /// The terms, checked as a whole. The reason names what is inconsistent.
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled && self.admissions.is_empty() {
            return Err("an open domain must admit by invite, voucher or both".into());
        }
        let vouchers = self.admissions.contains(&GuestAdmission::Voucher);
        if vouchers && self.trusted_issuers.is_empty() {
            return Err("vouchers are admitted but no trusted issuer is named".into());
        }
        if !vouchers && !self.trusted_issuers.is_empty() {
            return Err("trusted issuers are named but vouchers are not admitted".into());
        }
        for (i, issuer) in self.trusted_issuers.iter().enumerate() {
            if !issuer.did.starts_with("did:") {
                return Err(format!("trusted issuer `{}` is not a DID", issuer.did));
            }
            if self.trusted_issuers[..i]
                .iter()
                .any(|other| crate::scid::same_reference(&other.did, &issuer.did))
            {
                return Err(format!("trusted issuer `{}` is named twice", issuer.did));
            }
        }
        if self.max_did_count == Some(0) {
            return Err("maxDidCount must be at least 1".into());
        }
        Ok(())
    }
}

/// `domain`'s terms, if it has any.
pub async fn get(
    ks: &KeyspaceHandle,
    domain: &str,
) -> Result<Option<SelfRegistrationPolicy>, AppError> {
    ks.get(policy_key(domain)).await
}

/// Every domain's terms, by domain name.
pub async fn list(ks: &KeyspaceHandle) -> Result<Vec<SelfRegistrationPolicy>, AppError> {
    let mut out: Vec<SelfRegistrationPolicy> = ks
        .prefix_iter_raw(POLICY_PREFIX)
        .await?
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
        .collect();
    out.sort_by(|a, b| a.domain.cmp(&b.domain));
    Ok(out)
}

/// Replace `policy.domain`'s terms. The caller has validated them.
pub async fn set(ks: &KeyspaceHandle, policy: &SelfRegistrationPolicy) -> Result<(), AppError> {
    ks.insert(policy_key(&policy.domain), policy).await
}

/// Store the configured terms of every domain that has none yet. Returns how
/// many were seeded. A domain an administrator has set terms for — or closed
/// — keeps them: the configuration seeds, it does not override.
pub async fn seed_from_config(
    ks: &KeyspaceHandle,
    entries: &[GuestRegistration],
    now: u64,
) -> Result<usize, AppError> {
    let mut seeded = 0;
    for entry in entries {
        if get(ks, &entry.domain).await?.is_some() {
            continue;
        }
        let policy = SelfRegistrationPolicy::from_config(entry, now);
        set(ks, &policy).await?;
        info!(target: "audit", event = "account.policy_seeded", domain = %policy.domain,
              "self-registration terms seeded from [[hosting.guest_register]]");
        seeded += 1;
    }
    Ok(seeded)
}

#[cfg(all(test, feature = "store-fjall"))]
mod tests {
    use super::*;
    use crate::server::account::test_ks;

    fn entry(domain: &str) -> GuestRegistration {
        GuestRegistration {
            domain: domain.into(),
            path_prefixes: vec!["g".into()],
            ..GuestRegistration::default()
        }
    }

    #[tokio::test]
    async fn the_configuration_seeds_and_never_overrides() {
        let (ks, _dir) = test_ks().await;
        assert_eq!(
            seed_from_config(&ks, &[entry("a.example")], 1)
                .await
                .unwrap(),
            1
        );
        let mut stored = get(&ks, "a.example").await.unwrap().unwrap();
        assert!(stored.enabled);
        assert_eq!(stored.updated_by, OPERATOR);
        assert_eq!(stored.max_did_count, None);

        // An administrator closes it; a restart's seed leaves that alone.
        stored.enabled = false;
        stored.updated_by = "did:example:admin".into();
        set(&ks, &stored).await.unwrap();
        assert_eq!(
            seed_from_config(&ks, &[entry("a.example")], 2)
                .await
                .unwrap(),
            0
        );
        assert!(!get(&ks, "a.example").await.unwrap().unwrap().enabled);
    }

    #[test]
    fn inconsistent_terms_are_refused() {
        let base = SelfRegistrationPolicy::from_config(&entry("a.example"), 0);
        assert!(base.validate().is_ok());

        let mut voucher_no_issuer = base.clone();
        voucher_no_issuer.admissions.push(GuestAdmission::Voucher);
        assert!(voucher_no_issuer.validate().is_err());

        let mut twice = voucher_no_issuer.clone();
        twice.trusted_issuers = vec![
            TrustedIssuer {
                did: "did:scid:vh:1:Qm".into(),
                label: None,
            },
            TrustedIssuer {
                did: "did:scid:vh:1:Qm?src=x".into(),
                label: None,
            },
        ];
        assert!(twice.validate().unwrap_err().contains("twice"));

        let mut open_with_nothing = base.clone();
        open_with_nothing.admissions.clear();
        assert!(open_with_nothing.validate().is_err());
        open_with_nothing.enabled = false;
        assert!(open_with_nothing.validate().is_ok());
    }

    #[test]
    fn a_closed_domain_admits_nothing() {
        let mut p = SelfRegistrationPolicy::from_config(&entry("a.example"), 0);
        assert!(p.admits(GuestAdmission::Invite));
        p.enabled = false;
        assert!(!p.admits(GuestAdmission::Invite));
        assert!(p.admits_path("g/x") && !p.admits_path("gx/x") && !p.admits_path("g"));
    }
}
