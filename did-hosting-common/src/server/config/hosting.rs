//! `[hosting]`: multi-domain bootstrap, the unassignment lifecycle, grace
//! periods and `did:webs` self-registration.

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
        self.path_prefixes.is_empty()
            || self.path_prefixes.iter().any(|prefix| {
                let prefix = prefix.trim_matches('/');
                !prefix.is_empty()
                    && path
                        .strip_prefix(prefix)
                        .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1)
            })
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
