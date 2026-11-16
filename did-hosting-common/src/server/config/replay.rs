//! `[replay]`: bounds of the anti-replay cache for signed inbound requests.

use crate::server::error::AppError;
use serde::{Deserialize, Serialize};

/// Bounds of the anti-replay cache for signed inbound requests
/// (`[replay]`; see [`crate::server::replay`]).
///
/// The cache remembers every accepted `(signer, id)` pair for as long as
/// the freshness window would accept its document (about 7 minutes,
/// with margin) and refuses new signed requests at either bound rather than
/// forget one, so the per-signer bound caps one signer's sustained rate at
/// about `max_entries_per_signer / 420` requests a second. Each record holds
/// about 32 bytes ([`crate::server::replay::BYTES_PER_RECORD`]), so
/// `max_entries` also bounds the cache's memory. Every service has its own
/// cache; a daemon has up to three (control plane, witness, watcher), each
/// with these bounds.
///
/// Leave the table out to take the defaults, which may rise in later
/// releases; generated configs omit it unless it differs from them.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReplayConfig {
    /// Records held across all signers. Default
    /// [`MAX_ENTRIES`](crate::server::replay::MAX_ENTRIES), 1,000,000 (about
    /// 32 MB).
    pub max_entries: usize,
    /// Records held for any one signer, so one authorised signer cannot
    /// exhaust the cache for the others. Default
    /// [`MAX_ENTRIES_PER_SIGNER`](crate::server::replay::MAX_ENTRIES_PER_SIGNER),
    /// 250,000 (about 600 signed requests a second, sustained).
    pub max_entries_per_signer: usize,
}

/// The most records `[replay] max_entries` may allow: about 320 MB.
const REPLAY_MAX_ENTRIES_CEILING: usize = 10_000_000;

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            max_entries: crate::server::replay::MAX_ENTRIES,
            max_entries_per_signer: crate::server::replay::MAX_ENTRIES_PER_SIGNER,
        }
    }
}

impl ReplayConfig {
    /// Whether this is the default, so a generated config can leave the
    /// table out and pick up later defaults.
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// Refuse a zero bound, a per-signer bound above the global one, and a
    /// global bound above the ceiling.
    pub fn validate(&self) -> Result<(), AppError> {
        if self.max_entries == 0 || self.max_entries_per_signer == 0 {
            return Err(AppError::Config(
                "replay.max_entries and replay.max_entries_per_signer must be at least 1".into(),
            ));
        }
        if self.max_entries_per_signer > self.max_entries {
            return Err(AppError::Config(format!(
                "replay.max_entries_per_signer ({}) must not exceed replay.max_entries ({})",
                self.max_entries_per_signer, self.max_entries
            )));
        }
        if self.max_entries > REPLAY_MAX_ENTRIES_CEILING {
            return Err(AppError::Config(format!(
                "replay.max_entries ({}) must not exceed {REPLAY_MAX_ENTRIES_CEILING}",
                self.max_entries
            )));
        }
        Ok(())
    }

    /// Apply `{prefix}_REPLAY_MAX_ENTRIES` and
    /// `{prefix}_REPLAY_MAX_ENTRIES_PER_SIGNER` env overrides, then validate.
    pub fn apply_env_overrides(&mut self, prefix: &str) -> Result<(), AppError> {
        self.apply_env_overrides_for(&[prefix])
    }

    /// [`Self::apply_env_overrides`] for several prefixes in turn (a later
    /// one wins), validating once after all of them, so a pair of values
    /// split across a deprecated and a current prefix is judged together.
    pub fn apply_env_overrides_for(&mut self, prefixes: &[&str]) -> Result<(), AppError> {
        self.apply_overrides(prefixes, |var| std::env::var(var).ok())
    }

    /// [`Self::apply_env_overrides_for`] reading variables through `lookup`.
    pub(super) fn apply_overrides(
        &mut self,
        prefixes: &[&str],
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<(), AppError> {
        for prefix in prefixes {
            for (suffix, field) in [
                ("MAX_ENTRIES", &mut self.max_entries),
                ("MAX_ENTRIES_PER_SIGNER", &mut self.max_entries_per_signer),
            ] {
                let var = format!("{prefix}_REPLAY_{suffix}");
                if let Some(v) = lookup(&var) {
                    *field = v
                        .trim()
                        .parse()
                        .map_err(|e| AppError::Config(format!("invalid {var}: {e}")))?;
                }
            }
        }
        self.validate()
    }
}
