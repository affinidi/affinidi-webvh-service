//! `[server.resolve_cache]` and `[server.resolve_rate_limit]`: caching
//! headers and the per-client limit on public DID resolution.

use crate::server::error::AppError;
use serde::{Deserialize, Serialize};

/// The `Cache-Control` header sent with successful DID-resolution responses
/// (`did.jsonl`, `did-witness.json`, `did.json`, `keri.cesr`, and the
/// `/@name` redirect).
///
/// Every value is in seconds. The trade-off is staleness: a resolver or CDN
/// holding a cached copy will not see an update, key rotation or deactivation
/// until its copy expires. Lower `max_age_secs` when that window matters more
/// than origin load.
///
/// Error responses are unaffected: they keep the global `no-store`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveCacheConfig {
    /// `max-age` — how long any cache (browser, resolver, CDN) may reuse a
    /// response. `0` sends `no-cache`: caches must revalidate every time.
    /// Default 300.
    #[serde(default = "default_resolve_max_age_secs")]
    pub max_age_secs: u32,
    /// `s-maxage` — overrides `max_age_secs` for shared caches (CDNs,
    /// proxies) only. Unset (default) omits it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_max_age_secs: Option<u32>,
    /// `stale-while-revalidate` — how long a cache may keep serving an
    /// expired copy while it refetches in the background. Unset (default)
    /// omits it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_while_revalidate_secs: Option<u32>,
}

fn default_resolve_max_age_secs() -> u32 {
    300
}

/// The longest any resolve-cache duration may be: one year, the ceiling
/// RFC 9111 suggests for "never expires".
pub(super) const RESOLVE_CACHE_MAX_SECS: u32 = 31_536_000;

impl Default for ResolveCacheConfig {
    fn default() -> Self {
        Self {
            max_age_secs: default_resolve_max_age_secs(),
            shared_max_age_secs: None,
            stale_while_revalidate_secs: None,
        }
    }
}

impl ResolveCacheConfig {
    /// The `Cache-Control` header value for a successful resolve.
    pub fn header_value(&self) -> String {
        if self.max_age_secs == 0 && self.shared_max_age_secs.is_none() {
            return "no-cache".to_string();
        }
        let mut value = format!("public, max-age={}", self.max_age_secs);
        if let Some(s) = self.shared_max_age_secs {
            value.push_str(&format!(", s-maxage={s}"));
        }
        if let Some(s) = self.stale_while_revalidate_secs {
            value.push_str(&format!(", stale-while-revalidate={s}"));
        }
        value
    }

    /// Refuse durations past one year.
    pub fn validate(&self) -> Result<(), AppError> {
        let fields = [
            ("max_age_secs", Some(self.max_age_secs)),
            ("shared_max_age_secs", self.shared_max_age_secs),
            (
                "stale_while_revalidate_secs",
                self.stale_while_revalidate_secs,
            ),
        ];
        for (name, value) in fields {
            if let Some(v) = value
                && v > RESOLVE_CACHE_MAX_SECS
            {
                return Err(AppError::Config(format!(
                    "server.resolve_cache.{name} ({v}) must be at most \
                     {RESOLVE_CACHE_MAX_SECS} (one year)"
                )));
            }
        }
        Ok(())
    }

    /// Apply `{prefix}_SERVER_RESOLVE_CACHE_*` env overrides, then validate.
    ///
    /// For the optional fields an empty value clears the setting.
    pub fn apply_env_overrides(&mut self, prefix: &str) -> Result<(), AppError> {
        fn parse(var: &str, v: &str) -> Result<u32, AppError> {
            v.trim()
                .parse()
                .map_err(|e| AppError::Config(format!("invalid {var}: {e}")))
        }
        let var = format!("{prefix}_SERVER_RESOLVE_CACHE_MAX_AGE_SECS");
        if let Ok(v) = std::env::var(&var) {
            self.max_age_secs = parse(&var, &v)?;
        }
        for (suffix, field) in [
            ("SHARED_MAX_AGE_SECS", &mut self.shared_max_age_secs),
            (
                "STALE_WHILE_REVALIDATE_SECS",
                &mut self.stale_while_revalidate_secs,
            ),
        ] {
            let var = format!("{prefix}_SERVER_RESOLVE_CACHE_{suffix}");
            if let Ok(v) = std::env::var(&var) {
                *field = if v.trim().is_empty() {
                    None
                } else {
                    Some(parse(&var, &v)?)
                };
            }
        }
        self.validate()
    }
}

/// A per-client-address limit on public DID resolution (`did.jsonl`,
/// `did-witness.json`, `did.json`, `keri.cesr`, `.well-known` and the
/// `/@name` redirect).
///
/// Resolution is unauthenticated, and each one costs store reads, so without
/// a limit one client can use up a metered store's capacity for everyone. A
/// client may spend `max_per_window` requests at once and regains one every
/// `window_secs / max_per_window`; past that it gets `429 Too Many Requests`
/// with `Retry-After` until its next request.
///
/// The client address is the TCP peer unless `server.trusted_proxies` names
/// that peer, in which case it is read from `X-Forwarded-For`. Behind a load
/// balancer, set `trusted_proxies` before turning this on: otherwise every
/// client shares the load balancer's address and one limit.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveRateLimitConfig {
    /// Resolution requests one client address may make per window. Unset
    /// (default) means no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_per_window: Option<u64>,
    /// The window the allowance refills over, in seconds. Default 10.
    #[serde(default = "default_resolve_rate_limit_window_secs")]
    pub window_secs: u64,
}

pub(super) fn default_resolve_rate_limit_window_secs() -> u64 {
    10
}

/// The longest resolve rate-limit window: one hour.
const RESOLVE_RATE_LIMIT_MAX_WINDOW_SECS: u64 = 3600;

impl Default for ResolveRateLimitConfig {
    fn default() -> Self {
        Self {
            max_per_window: None,
            window_secs: default_resolve_rate_limit_window_secs(),
        }
    }
}

impl ResolveRateLimitConfig {
    /// Refuse a zero limit and a window outside 1 second to one hour.
    pub fn validate(&self) -> Result<(), AppError> {
        if self.max_per_window == Some(0) {
            return Err(AppError::Config(
                "server.resolve_rate_limit.max_per_window must be at least 1; \
                 leave it unset for no limit"
                    .into(),
            ));
        }
        if !(1..=RESOLVE_RATE_LIMIT_MAX_WINDOW_SECS).contains(&self.window_secs) {
            return Err(AppError::Config(format!(
                "server.resolve_rate_limit.window_secs ({}) must be between 1 and \
                 {RESOLVE_RATE_LIMIT_MAX_WINDOW_SECS}",
                self.window_secs
            )));
        }
        Ok(())
    }

    /// Apply `{prefix}_SERVER_RESOLVE_RATE_LIMIT_MAX_PER_WINDOW` (an empty
    /// value clears it) and `{prefix}_SERVER_RESOLVE_RATE_LIMIT_WINDOW_SECS`
    /// (an empty value restores the default) env overrides, then validate.
    pub fn apply_env_overrides(&mut self, prefix: &str) -> Result<(), AppError> {
        self.apply_overrides(prefix, |var| std::env::var(var).ok())
    }

    /// [`Self::apply_env_overrides`] reading variables through `lookup`.
    pub(super) fn apply_overrides(
        &mut self,
        prefix: &str,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<(), AppError> {
        fn parse(var: &str, v: &str) -> Result<u64, AppError> {
            v.trim()
                .parse()
                .map_err(|e| AppError::Config(format!("invalid {var}: {e}")))
        }
        let var = format!("{prefix}_SERVER_RESOLVE_RATE_LIMIT_MAX_PER_WINDOW");
        if let Some(v) = lookup(&var) {
            self.max_per_window = if v.trim().is_empty() {
                None
            } else {
                Some(parse(&var, &v)?)
            };
        }
        let var = format!("{prefix}_SERVER_RESOLVE_RATE_LIMIT_WINDOW_SECS");
        if let Some(v) = lookup(&var) {
            self.window_secs = if v.trim().is_empty() {
                default_resolve_rate_limit_window_secs()
            } else {
                parse(&var, &v)?
            };
        }
        self.validate()
    }
}
