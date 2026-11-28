//! Guest accounts: parties that registered themselves
//! (`did-management/account/register/0.1`) rather than being added by an
//! administrator.
//!
//! A self-registered account is an ordinary owner's ACL entry — that is what
//! authorises it, exactly as any other entry does — plus an [`AccountRecord`]
//! kept beside it in the ACL keyspace (`account:{subject}`). The record is
//! what sets the account apart: how it was admitted and by whose referral,
//! when its holder was last active, and where it stands in the inactivity
//! lifecycle; while it exists, the account is held to its domain's terms
//! ([`policy`]: path prefixes, quotas, the lifecycle, no agent names).
//! Keeping it apart leaves [`AclEntry`] — written by every ACL path —
//! unchanged.
//!
//! - [`invite`]: the operator invites that admit a guest
//!   (`did-management/account/invite/*`).
//! - [`voucher`]: the single-use record of each community voucher accepted.
//!
//! [`AclEntry`]: crate::server::acl::AclEntry

pub mod invite;
pub mod policy;
pub mod voucher;

use serde::{Deserialize, Serialize};

use crate::server::config::GuestAdmission;
use crate::server::error::AppError;
use crate::server::store::KeyspaceHandle;

/// The prefix every [`AccountRecord`] is stored under.
pub const ACCOUNT_PREFIX: &str = "account:";

fn account_key(subject: &str) -> String {
    format!("{ACCOUNT_PREFIX}{}", crate::scid::identity(subject))
}

/// How a self-registered account came to the service: attribution, never
/// authority.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Referral {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Whether the admission evidence supports it.
    #[serde(default)]
    pub verified: bool,
}

/// Where an account stands in the inactivity lifecycle.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AccountState {
    /// Its DIDs are served.
    Active,
    /// Its DIDs are served, its disablement is near, and at least one notice
    /// has been sent.
    Warned,
    /// Its DIDs are not served; its holder may still renew until the purge.
    Disabled,
}

impl AccountState {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            AccountState::Active => "active",
            AccountState::Warned => "warned",
            AccountState::Disabled => "disabled",
        }
    }
}

/// A guest account's own record. Holds no secret.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountRecord {
    /// The account's identity: the DID it registered as, a `did:scid`
    /// without its `src`.
    pub subject: String,
    /// The hosting domain it was admitted on, as the request named it.
    pub domain: String,
    /// How it was admitted.
    pub admission: GuestAdmission,
    /// What admitted it: the invite's id, or the voucher's `issuer` and `id`.
    pub admitted_by: String,
    /// When it was created (epoch seconds).
    pub registered_at: u64,
    /// The last liveness signal from its holder (epoch seconds).
    pub last_active_at: u64,
    /// Its lifecycle state.
    pub state: AccountState,
    /// When it was disabled for inactivity (epoch seconds); `None` unless
    /// `state` is `Disabled`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_at: Option<u64>,
    /// The slots the lifecycle disabled for inactivity — and so the only ones
    /// a renewal re-enables. A DID its owner disabled itself stays disabled.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expiry_disabled: Vec<String>,
    /// The expiry notices sent for the current lifecycle stage, by stage
    /// name, so a restart does not send them twice. Cleared on renewal.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notices_sent: Vec<String>,
    /// Where it came from, when it said or its evidence did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referral: Option<Referral>,
    /// An administrator exempted it from its domain's terms
    /// (`did-management/account/exempt`): an ordinary owner in all but name.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exempt: bool,
}

/// Whether `subject` holds a self-registered account, exempt or not.
pub async fn is_self_registered(ks: &KeyspaceHandle, subject: &str) -> Result<bool, AppError> {
    ks.contains_key(account_key(subject)).await
}

/// Whether `subject` is held to its domain's terms: a self-registered account
/// an administrator has not exempted.
pub async fn is_held_to_terms(ks: &KeyspaceHandle, subject: &str) -> Result<bool, AppError> {
    Ok(get(ks, subject).await?.is_some_and(|r| !r.exempt))
}

/// The record for `subject`, if it has one.
pub async fn get(ks: &KeyspaceHandle, subject: &str) -> Result<Option<AccountRecord>, AppError> {
    ks.get(account_key(subject)).await
}

/// Store (or rewrite) a record.
pub async fn save(ks: &KeyspaceHandle, record: &AccountRecord) -> Result<(), AppError> {
    ks.insert(account_key(&record.subject), record).await
}

/// Remove `subject`'s record, if any.
pub async fn remove(ks: &KeyspaceHandle, subject: &str) -> Result<(), AppError> {
    ks.remove(account_key(subject)).await
}

/// Every stored record.
pub async fn list(ks: &KeyspaceHandle) -> Result<Vec<AccountRecord>, AppError> {
    Ok(ks
        .prefix_iter_raw(ACCOUNT_PREFIX)
        .await?
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
        .collect())
}

/// How many accounts were admitted on `domain` (compared after
/// normalisation).
pub async fn count_on_domain(ks: &KeyspaceHandle, domain: &str) -> Result<usize, AppError> {
    use crate::server::domain::normalize_domain_name;
    let canonical = normalize_domain_name(domain).unwrap_or_else(|_| domain.to_string());
    Ok(list(ks)
        .await?
        .into_iter()
        .filter(|r| {
            normalize_domain_name(&r.domain).unwrap_or_else(|_| r.domain.clone()) == canonical
        })
        .count())
}

/// A fresh ACL keyspace in a temp-dir store, for this module's tests.
#[cfg(all(test, feature = "store-fjall"))]
pub(crate) async fn test_ks() -> (KeyspaceHandle, tempfile::TempDir) {
    use crate::server::config::StoreConfig;
    use crate::server::store::{KS_ACL, Store};
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&StoreConfig {
        data_dir: dir.path().to_path_buf(),
        ..StoreConfig::default()
    })
    .await
    .unwrap();
    (store.keyspace(KS_ACL).unwrap(), dir)
}

#[cfg(all(test, feature = "store-fjall"))]
mod tests {
    use super::*;

    fn record(subject: &str, domain: &str) -> AccountRecord {
        AccountRecord {
            subject: subject.into(),
            domain: domain.into(),
            admission: GuestAdmission::Invite,
            admitted_by: "inv-1".into(),
            registered_at: 10,
            last_active_at: 10,
            state: AccountState::Active,
            disabled_at: None,
            expiry_disabled: Vec::new(),
            notices_sent: Vec::new(),
            referral: None,
            exempt: false,
        }
    }

    #[tokio::test]
    async fn a_did_scid_subject_is_keyed_without_its_src() {
        let (ks, _dir) = test_ks().await;
        save(&ks, &record("did:scid:vh:1:Qm", "a.example"))
            .await
            .unwrap();
        let found = get(&ks, "did:scid:vh:1:Qm?src=a.example")
            .await
            .unwrap()
            .expect("found by its identity");
        assert_eq!(found.subject, "did:scid:vh:1:Qm");
    }

    #[tokio::test]
    async fn counts_only_the_domain_asked_for() {
        let (ks, _dir) = test_ks().await;
        save(&ks, &record("did:example:a", "a.example"))
            .await
            .unwrap();
        save(&ks, &record("did:example:b", "a.example"))
            .await
            .unwrap();
        save(&ks, &record("did:example:c", "b.example"))
            .await
            .unwrap();
        assert_eq!(count_on_domain(&ks, "a.example").await.unwrap(), 2);
        assert_eq!(count_on_domain(&ks, "c.example").await.unwrap(), 0);
    }
}
