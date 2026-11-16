//! `[vta]` and `[identity]`: the parent VTA connection, and how the
//! service's own identity is produced and rotated.

use serde::{Deserialize, Serialize};

use super::hosting::{GracePeriod, deserialize_grace_in};

/// VTA (Verifiable Trust Architecture) connection configuration.
///
/// Used by services that integrate with a VTA for key management and DID operations.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VtaConfig {
    /// VTA REST URL for remote key management
    pub url: Option<String>,
    /// VTA DID for DIDComm communication
    pub did: Option<String>,
    /// VTA context ID for this service's keys
    pub context_id: Option<String>,
}

/// How the service obtains its own operating identity (signing key, KA key, DID).
///
/// `Vta` (the default) means a parent VTA provisions and rotates the service's
/// own keys at setup time. `SelfManaged` means the service generates its own
/// keys and self-hosts a `did:webvh` identifier with no parent VTA — a
/// daemon-only mode in v1. See `docs/archive/self-managed-mode-spec.md`.
#[derive(Debug, Default, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityMode {
    #[default]
    Vta,
    SelfManaged,
}

/// Identity configuration — selects how the service's own keys and DID are
/// produced, and how long a superseded identity keeps being honoured.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    #[serde(default)]
    pub mode: IdentityMode,

    /// How long a superseded identity generation stays decryptable after the
    /// DID document is updated. Format: duration string (`"1h"`, `"30m"`,
    /// `"7d"`); `"0"` retires immediately.
    ///
    /// This exists because peers cache DID documents. After a key rotation they
    /// keep encrypting to the *old* key-agreement key until their cache
    /// expires, and those messages only decrypt while we still hold the old
    /// secret. The window should comfortably exceed the longest DID-document
    /// cache TTL among your peers; the resolver in this workspace defaults to
    /// 300s, so `"1h"` is a wide margin.
    ///
    /// Setting `"0"` is the right choice for a **compromised** key — you want
    /// the old key to stop being honoured at once and you accept that in-flight
    /// messages addressed to it will fail.
    ///
    /// Parsed when the config is loaded: a value that is not a duration
    /// stops the service at startup, naming this key.
    #[serde(
        default = "default_rotation_grace_period",
        deserialize_with = "deserialize_rotation_grace_period"
    )]
    pub rotation_grace_period: GracePeriod,
}

fn default_rotation_grace_period() -> GracePeriod {
    GracePeriod::parse("1h").expect("the default grace parses")
}

fn deserialize_rotation_grace_period<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<GracePeriod, D::Error> {
    deserialize_grace_in("identity", "rotation_grace_period", d)
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            mode: IdentityMode::default(),
            rotation_grace_period: default_rotation_grace_period(),
        }
    }
}

impl IdentityConfig {
    /// The grace period in seconds. The value was validated when the config
    /// was loaded, so there is nothing to fall back from here.
    pub fn rotation_grace_secs(&self) -> u64 {
        self.rotation_grace_period.as_secs()
    }
}
