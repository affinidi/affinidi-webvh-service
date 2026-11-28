//! `[hosting]`: multi-domain bootstrap, the unassignment lifecycle, grace
//! periods, `did:webs` self-registration and guest accounts.

use crate::server::error::AppError;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU64;

use super::default_true;
use super::env::parse_env_bool;

// ---------------------------------------------------------------------------
// HostingConfig — multi-domain bootstrap + unassignment lifecycle
// ---------------------------------------------------------------------------

/// Settings for the multi-domain hosting feature.
///
/// Per `docs/archive/multi-domain-spec.md` §3: domains are runtime-managed,
/// but the daemon needs to know what to seed on a fresh deployment
/// (when no `domains` keyspace entries exist yet) and how long to
/// retain unassigned-domain data before purging.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HostingConfig {
    /// Domain names to seed into the `domains` keyspace on first boot
    /// when the keyspace is empty. Used only when the operator hasn't
    /// already created domains with the `domain/create` Trust Task. The first entry
    /// becomes the default domain (per spec §3 cold-start fallback
    /// chain — tier 1).
    ///
    /// Empty (default) falls through to tier 2: derive a single
    /// default domain from the legacy `public_url`'s host.
    #[serde(default)]
    pub bootstrap_domains: Vec<String>,

    /// Grace period before a server-locally-unassigned domain's data
    /// is purged. Per spec §3 retain-then-purge semantics. Format:
    /// duration string (`"2h"`, `"30m"`, `"7d"`, `"45s"`, or bare
    /// seconds). Default: `"2h"`.
    ///
    /// Parsed when the config is loaded: a value that is not a duration
    /// stops the service at startup, naming this key.
    #[serde(
        default = "default_unassigned_purge_grace",
        deserialize_with = "deserialize_unassigned_purge_grace"
    )]
    pub unassigned_purge_grace: GracePeriod,

    /// Grace period before a *disabled* domain (and every DID hosted
    /// under it) is permanently removed. Disable is a soft-delete:
    /// the operator gets this window to re-enable and cancel the
    /// removal. Format matches `unassigned_purge_grace`. Default:
    /// `"30d"` — long enough to recover from an accidental disable,
    /// short enough that abandoned domains don't accumulate forever.
    ///
    /// Parsed when the config is loaded, like `unassigned_purge_grace`.
    #[serde(
        default = "default_disable_purge_grace",
        deserialize_with = "deserialize_disable_purge_grace"
    )]
    pub disable_purge_grace: GracePeriod,

    /// Whether a DID this service creates for itself lists its
    /// `did:scid:vh:1:<scid>?src=…` alias in `alsoKnownAs`, linking its
    /// did:webvh and did:scid forms as one subject (VTI-KEY-166 of the VTI
    /// specification). Applies when the log is created; an existing DID keeps
    /// what it published. Default: `true`. Env: `<PREFIX>_HOSTING_SCID_ALSO_KNOWN_AS`.
    #[serde(default = "default_true")]
    pub scid_also_known_as: bool,

    /// Hosting domains on which a `did:webs` may register itself, with no
    /// ACL entry: a `did/register/0.1` whose `issuer` is the `did:webs`
    /// the slot builds and whose proof verifies under the key state its own
    /// submitted `keri.cesr` establishes. The key event log is the proof of
    /// control; nothing else is asked for. Empty (default): no domain
    /// accepts it, and an unknown `did:webs` is refused as any caller
    /// outside the ACL is.
    ///
    /// Read only by a control plane built with `method-webs`; ignored
    /// otherwise. See `docs/did-webs-hosting.md` ("Self-registration").
    ///
    /// ```toml
    /// [[hosting.webs_self_register]]
    /// domain = "did.example.com"
    /// path_prefixes = ["nodes"]   # optional; empty = any path
    /// ```
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub webs_self_register: Vec<WebsSelfRegistration>,

    /// The self-registration terms to **seed** on domains that have none:
    /// where a party with no account may register one with
    /// `did-management/account/register/0.1`, submitting its own
    /// self-certifying `did:webvh` log and an operator invite or a trusted
    /// authorising party's voucher. Seeded at startup into the runtime store
    /// (`account::policy`), which an administrator then manages with
    /// `did-management/account/policy/{list,set}`; a domain that already has
    /// stored terms keeps them. Empty (default): nothing is seeded.
    ///
    /// ```toml
    /// [[hosting.guest_register]]
    /// domain = "did.example.com"
    /// path_prefixes = ["g"]                       # optional; empty = any path
    /// admissions = ["invite", "voucher"]          # default ["invite"]
    /// trusted_voucher_issuers = ["did:webvh:…"]   # required with "voucher"
    /// ```
    ///
    /// See `docs/guest-registration-design.md`.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_guest_register"
    )]
    pub guest_register: Vec<GuestRegistration>,
}

/// What admits a guest account (`did-management/account/register/0.1`'s
/// `admission`).
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum GuestAdmission {
    /// Both halves of an invite an administrator issued
    /// (`did-management/account/invite/issue/0.1`).
    Invite,
    /// A `DidHostingVoucher` signed by one of the domain's
    /// `trusted_voucher_issuers`.
    Voucher,
}

impl GuestAdmission {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            GuestAdmission::Invite => "invite",
            GuestAdmission::Voucher => "voucher",
        }
    }
}

/// One hosting domain's self-registration terms, as the configuration seeds
/// them ([`HostingConfig::guest_register`]); see
/// `crate::server::account::policy`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuestRegistration {
    /// The hosting domain, as it is configured in the domain registry
    /// (compared after normalisation).
    pub domain: String,
    /// Leading path segments a guest's slot must sit under, matched on whole
    /// `/`-separated segments, as [`WebsSelfRegistration::path_prefixes`].
    /// Empty: any path the domain's grammar admits.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_prefixes: Vec<String>,
    /// The admission evidence the domain accepts. Default: `["invite"]`.
    #[serde(default = "default_guest_admissions")]
    pub admissions: Vec<GuestAdmission>,
    /// The DIDs of the trust communities whose vouchers admit a guest here.
    /// Required, and only allowed, when `admissions` includes `voucher`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_voucher_issuers: Vec<String>,
    /// The most guest accounts the domain holds at once (default
    /// [`DEFAULT_GUEST_MAX_REGISTRATIONS`]). Per-process like the rate limits:
    /// replicas behind one store can overshoot it by at most one each.
    #[serde(default = "default_guest_max_registrations")]
    pub max_registrations: u32,
    /// How many DIDs a self-registered account may hold, its own included.
    /// Unset (default): the service's ordinary per-account limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_did_count: Option<NonZeroU64>,
    /// The most bytes of DID content a self-registered account may hold.
    /// Unset (default): the service's ordinary per-account limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_size: Option<u64>,
    /// Days a guest account may go without a liveness signal before its DIDs
    /// are disabled (default [`DEFAULT_GUEST_INACTIVITY_DAYS`]). `0`: guest
    /// accounts on this domain never expire.
    #[serde(default = "default_guest_inactivity_days")]
    pub inactivity_days: u32,
    /// Days a disabled guest account is kept, and can be restored by its
    /// holder's renewal, before it is purged (default
    /// [`DEFAULT_GUEST_GRACE_DAYS`]).
    #[serde(default = "default_guest_grace_days")]
    pub grace_days: u32,
    /// The most invites that may be pending for the domain at once (default
    /// [`DEFAULT_GUEST_MAX_PENDING_INVITES`]).
    #[serde(default = "default_guest_max_pending_invites")]
    pub max_pending_invites: u32,
}

/// The default [`GuestRegistration::max_registrations`].
pub const DEFAULT_GUEST_MAX_REGISTRATIONS: u32 = 1000;
/// The default [`GuestRegistration::inactivity_days`].
pub const DEFAULT_GUEST_INACTIVITY_DAYS: u32 = 90;
/// The default [`GuestRegistration::grace_days`].
pub const DEFAULT_GUEST_GRACE_DAYS: u32 = 30;
/// The default [`GuestRegistration::max_pending_invites`].
pub const DEFAULT_GUEST_MAX_PENDING_INVITES: u32 = 1000;

fn default_guest_admissions() -> Vec<GuestAdmission> {
    vec![GuestAdmission::Invite]
}
fn default_guest_max_registrations() -> u32 {
    DEFAULT_GUEST_MAX_REGISTRATIONS
}
fn default_guest_inactivity_days() -> u32 {
    DEFAULT_GUEST_INACTIVITY_DAYS
}
fn default_guest_grace_days() -> u32 {
    DEFAULT_GUEST_GRACE_DAYS
}
fn default_guest_max_pending_invites() -> u32 {
    DEFAULT_GUEST_MAX_PENDING_INVITES
}

impl Default for GuestRegistration {
    fn default() -> Self {
        Self {
            domain: String::new(),
            path_prefixes: Vec::new(),
            admissions: default_guest_admissions(),
            trusted_voucher_issuers: Vec::new(),
            max_registrations: DEFAULT_GUEST_MAX_REGISTRATIONS,
            max_did_count: None,
            max_total_size: None,
            inactivity_days: DEFAULT_GUEST_INACTIVITY_DAYS,
            grace_days: DEFAULT_GUEST_GRACE_DAYS,
            max_pending_invites: DEFAULT_GUEST_MAX_PENDING_INVITES,
        }
    }
}

impl GuestRegistration {
    /// The terms, checked as a whole: a domain, at least one admission, and
    /// trusted issuers exactly when vouchers are accepted.
    fn validate(&self) -> Result<(), String> {
        if self.domain.trim().is_empty() {
            return Err("a [[hosting.guest_register]] entry needs a `domain`".into());
        }
        if self.admissions.is_empty() {
            return Err(format!(
                "[[hosting.guest_register]] `{}`: `admissions` is empty, so nothing could admit a \
                 guest; remove the entry to close the domain",
                self.domain
            ));
        }
        let vouchers = self.admissions.contains(&GuestAdmission::Voucher);
        if vouchers && self.trusted_voucher_issuers.is_empty() {
            return Err(format!(
                "[[hosting.guest_register]] `{}`: `admissions` includes \"voucher\" but \
                 `trusted_voucher_issuers` names no issuer",
                self.domain
            ));
        }
        if !vouchers && !self.trusted_voucher_issuers.is_empty() {
            return Err(format!(
                "[[hosting.guest_register]] `{}`: `trusted_voucher_issuers` is set but \
                 `admissions` does not include \"voucher\"",
                self.domain
            ));
        }
        if let Some(bad) = self
            .trusted_voucher_issuers
            .iter()
            .find(|d| !d.starts_with("did:"))
        {
            return Err(format!(
                "[[hosting.guest_register]] `{}`: trusted voucher issuer `{bad}` is not a DID",
                self.domain
            ));
        }
        Ok(())
    }
}

fn deserialize_guest_register<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<GuestRegistration>, D::Error> {
    let entries = Vec::<GuestRegistration>::deserialize(d)?;
    for entry in &entries {
        entry.validate().map_err(serde::de::Error::custom)?;
    }
    Ok(entries)
}

/// Whether `path` sits under one of `prefixes` on whole `/`-separated
/// segments, with at least one segment of its own after the prefix. Empty
/// `prefixes` admit any path.
fn path_under_prefixes(prefixes: &[String], path: &str) -> bool {
    prefixes.is_empty()
        || prefixes.iter().any(|prefix| {
            let prefix = prefix.trim_matches('/');
            !prefix.is_empty()
                && path
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1)
        })
}

/// One hosting domain's opt-in to `did:webs` self-registration
/// ([`HostingConfig::webs_self_register`]).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebsSelfRegistration {
    /// The hosting domain, as it is configured in the domain registry
    /// (compared after normalisation).
    pub domain: String,
    /// Leading path segments a self-registered slot must sit under, each
    /// `a/b` matched on whole segments (`nodes` admits `nodes/{AID}` and
    /// `nodes/eu/{AID}`, not `nodesx/{AID}`). Empty: any path on the
    /// domain, the bare `{AID}` included.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_prefixes: Vec<String>,
    /// The most identifiers that may hold a self-registered slot on this
    /// domain at once (default [`DEFAULT_WEBS_SELF_REGISTER_MAX`]). Opting a
    /// domain in opens it to anyone with a key event log, and each AID is
    /// free to mint, so the rate limits bound how fast slots can be taken
    /// and this bounds how many. Counted from the owner entries
    /// self-registration grants; an administrator who deletes one frees its
    /// place. Per-process like the rate limits: replicas behind one store
    /// can overshoot it by at most one each.
    #[serde(default = "default_webs_self_register_max")]
    pub max_registrations: u32,
    /// How many DIDs each self-registered identifier may hold on this domain,
    /// its own included: the `max_did_count` of the `Owner` entry
    /// self-registration grants it (default 1, its own slot only). A node
    /// that publishes the DIDs it creates here — a VTA hosting a community's
    /// or a persona's DID — needs more. At least 1. Applies to entries granted
    /// from then on; an entry already granted keeps its limit until an
    /// administrator changes it.
    #[serde(default = "default_webs_self_register_dids")]
    pub max_dids_per_identifier: NonZeroU64,
}

/// The default [`WebsSelfRegistration::max_registrations`]: enough for a
/// deployment's own nodes, not a public registry.
pub const DEFAULT_WEBS_SELF_REGISTER_MAX: u32 = 100;

fn default_webs_self_register_max() -> u32 {
    DEFAULT_WEBS_SELF_REGISTER_MAX
}

/// The default [`WebsSelfRegistration::max_dids_per_identifier`]: the
/// identifier's own slot and nothing more.
pub const DEFAULT_WEBS_SELF_REGISTER_DIDS: NonZeroU64 = NonZeroU64::MIN;

fn default_webs_self_register_dids() -> NonZeroU64 {
    DEFAULT_WEBS_SELF_REGISTER_DIDS
}

impl Default for WebsSelfRegistration {
    fn default() -> Self {
        Self {
            domain: String::new(),
            path_prefixes: Vec::new(),
            max_registrations: DEFAULT_WEBS_SELF_REGISTER_MAX,
            max_dids_per_identifier: DEFAULT_WEBS_SELF_REGISTER_DIDS,
        }
    }
}

impl WebsSelfRegistration {
    /// Whether a slot at `path` (`/`-separated, ending in the AID) is
    /// under one of this domain's prefixes.
    pub fn admits_path(&self, path: &str) -> bool {
        path_under_prefixes(&self.path_prefixes, path)
    }
}

/// A `[hosting]` grace period: a duration string (`"2h"`, `"30m"`, `"7d"`,
/// `"45s"`, or bare seconds), parsed when the config is loaded so no call site
/// re-parses it or falls back to a default. Serialises back to the text it was
/// written as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GracePeriod {
    secs: u64,
    text: String,
}

/// The units a [`GracePeriod`] accepts, for error messages.
pub const GRACE_PERIOD_UNITS: &str =
    "an integer with an optional unit s, m, h or d (e.g. \"45s\", \"30m\", \"2h\", \"7d\")";

impl GracePeriod {
    /// Parse a duration string; the error says what was wrong and which
    /// units are accepted.
    pub fn parse(text: &str) -> Result<Self, String> {
        crate::server::pending_purge::parse_grace_string(text)
            .map(|secs| Self {
                secs,
                text: text.trim().to_string(),
            })
            .map_err(|e| format!("invalid duration `{text}` ({e}); expected {GRACE_PERIOD_UNITS}"))
    }

    /// The period in seconds.
    pub fn as_secs(&self) -> u64 {
        self.secs
    }

    /// The text it was written as.
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl std::fmt::Display for GracePeriod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

impl Serialize for GracePeriod {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.text)
    }
}

impl<'de> Deserialize<'de> for GracePeriod {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// Deserialise the grace period `[section] key`, naming the key in the error.
pub(super) fn deserialize_grace_in<'de, D: serde::Deserializer<'de>>(
    section: &str,
    key: &str,
    d: D,
) -> Result<GracePeriod, D::Error> {
    let text = String::deserialize(d)?;
    GracePeriod::parse(&text)
        .map_err(|e| serde::de::Error::custom(format!("[{section}] {key}: {e}")))
}

/// Deserialise the `[hosting]` grace period `key`, naming the key in the error.
fn deserialize_grace_for<'de, D: serde::Deserializer<'de>>(
    key: &str,
    d: D,
) -> Result<GracePeriod, D::Error> {
    deserialize_grace_in("hosting", key, d)
}

fn deserialize_unassigned_purge_grace<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<GracePeriod, D::Error> {
    deserialize_grace_for("unassigned_purge_grace", d)
}

fn deserialize_disable_purge_grace<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<GracePeriod, D::Error> {
    deserialize_grace_for("disable_purge_grace", d)
}

fn default_unassigned_purge_grace() -> GracePeriod {
    GracePeriod::parse("2h").expect("the default grace parses")
}

fn default_disable_purge_grace() -> GracePeriod {
    GracePeriod::parse("30d").expect("the default grace parses")
}

impl Default for HostingConfig {
    fn default() -> Self {
        Self {
            bootstrap_domains: Vec::new(),
            unassigned_purge_grace: default_unassigned_purge_grace(),
            disable_purge_grace: default_disable_purge_grace(),
            scid_also_known_as: true,
            webs_self_register: Vec::new(),
            guest_register: Vec::new(),
        }
    }
}

/// Apply environment variable overrides to [`HostingConfig`]. `prefix` is the
/// same namespace [`apply_env_overrides`](super::apply_env_overrides) takes.
pub fn apply_hosting_env_overrides(
    prefix: &str,
    hosting: &mut HostingConfig,
) -> Result<(), AppError> {
    hosting.scid_also_known_as = scid_also_known_as_from_env(prefix, hosting.scid_also_known_as)?;
    Ok(())
}

/// `<PREFIX>_HOSTING_SCID_ALSO_KNOWN_AS` when set (see [`parse_env_bool`]),
/// `default` otherwise. For setup paths that mint the service's DID before
/// any config file exists. A value that is not a boolean is refused.
pub fn scid_also_known_as_from_env(prefix: &str, default: bool) -> Result<bool, AppError> {
    let var = format!("{prefix}_HOSTING_SCID_ALSO_KNOWN_AS");
    match std::env::var(&var) {
        Ok(v) => parse_env_bool(&var, &v),
        Err(_) => Ok(default),
    }
}
