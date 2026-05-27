//! Cold-start domain-seed logic.
//!
//! Per `docs/multi-domain-spec.md` §3 row "Cold-start bootstrap":
//! three-tier fallback when the `domains` keyspace is empty:
//!
//!   1. `bootstrap_domains` from `config.toml` (operator-seeded)
//!   2. Legacy `public_url` host (upgrade path from a v0.6-vintage
//!      single-domain deployment)
//!   3. Empty — daemon boots but won't accept create-DID requests
//!      until the operator adds a domain via the admin API.
//!
//! Loud `warn!` log if tier 2 or 3 is reached so operators see the
//! drop-through in the boot output and aren't surprised by `403 no
//! domain` on first request.
//!
//! Once the keyspace has any entry, this function is a no-op — the
//! daemon never re-seeds. Add/disable/delete is the admin's job
//! thereafter.

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::normalize::normalize_domain_name;
use super::store::{create_domain, get_default_domain, list_domains, set_default_domain};
use super::types::{DomainEntry, DomainStatus, DomainUrlScheme};
use crate::server::error::AppError;
use crate::server::store::Store;

/// Which tier of the fallback chain produced the seed (or that no seed
/// was needed). Surface via `info!` / `warn!` from the daemon's boot
/// path so operators see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeedTier {
    /// `domains` keyspace already populated — no seed needed.
    AlreadySeeded,
    /// Tier 1: seeded from `config.bootstrap_domains`.
    FromBootstrapDomains,
    /// Tier 2: seeded from the legacy `public_url`'s host (upgrade
    /// path). Warn-logged because operators with a v0.6-vintage
    /// config should consider moving the value to `bootstrap_domains`
    /// for explicit intent.
    FromLegacyPublicUrl,
    /// Tier 3: no seed available — daemon boots with an empty domain
    /// set. Warn-logged loudly; the daemon will reject create-DID
    /// requests with 503 / no-active-domain until an operator adds
    /// one.
    NoSeed,
}

/// Outcome of [`seed_domains_first_boot`]. Surfaces the tier + the
/// number of entries that ended up in the store so callers can log a
/// single coherent line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedOutcome {
    pub tier: SeedTier,
    /// Domain entries currently in the keyspace after the seed runs.
    /// Always reflects the post-seed state, not the delta — easier to
    /// reason about for the daemon's startup-log line.
    pub final_count: usize,
    /// Current default-domain pointer post-seed. `None` for `NoSeed`
    /// tier; otherwise always populated (the seed sets the default to
    /// the first entry it inserts).
    pub default: Option<String>,
}

/// Idempotent cold-start seed. Call on every daemon boot — does
/// nothing on subsequent boots when the keyspace is already
/// populated.
///
/// Per spec, the **first** entry in `bootstrap_domains` (tier 1) or
/// the legacy `public_url` host (tier 2) becomes the default. Tier 1
/// entries beyond index 0 land as additional non-default domains.
pub async fn seed_domains_first_boot(
    store: &Store,
    bootstrap_domains: &[String],
    legacy_public_url: Option<&str>,
) -> Result<SeedOutcome, AppError> {
    // Tier 0: store already has entries → no-op.
    let existing = list_domains(store).await?;
    if !existing.is_empty() {
        let default = get_default_domain(store).await?;
        return Ok(SeedOutcome {
            tier: SeedTier::AlreadySeeded,
            final_count: existing.len(),
            default,
        });
    }

    // Tier 1: bootstrap_domains.
    if !bootstrap_domains.is_empty() {
        let first = &bootstrap_domains[0];
        seed_entry(store, first, /* default = */ true).await?;
        for d in &bootstrap_domains[1..] {
            seed_entry(store, d, false).await?;
        }
        let final_count = list_domains(store).await?.len();
        info!(
            tier = "bootstrap_domains",
            count = final_count,
            default = %first,
            "first-boot domain seed complete"
        );
        return Ok(SeedOutcome {
            tier: SeedTier::FromBootstrapDomains,
            final_count,
            default: Some(normalize_domain_name(first)?),
        });
    }

    // Tier 2: legacy public_url host.
    if let Some(url) = legacy_public_url
        && let Some(host) = host_from_public_url(url)
    {
        warn!(
            legacy_public_url = %url,
            derived_host = %host,
            "first-boot domain seed: bootstrap_domains empty — falling back to legacy public_url host. \
             Consider moving '{host}' to config `[hosting] bootstrap_domains` for explicit intent."
        );
        seed_entry(store, &host, /* default = */ true).await?;
        return Ok(SeedOutcome {
            tier: SeedTier::FromLegacyPublicUrl,
            final_count: 1,
            default: Some(normalize_domain_name(&host)?),
        });
    }

    // Tier 3: nothing to seed. Loud warn so operators see it.
    warn!(
        "first-boot domain seed: no domains configured — neither \
         [hosting] bootstrap_domains nor a legacy public_url is set. \
         The daemon will reject create-DID requests until an admin \
         adds a domain. Add one via `did-hosting-control domain create` \
         or the admin UI."
    );
    Ok(SeedOutcome {
        tier: SeedTier::NoSeed,
        final_count: 0,
        default: None,
    })
}

/// Construct a `DomainEntry` from a name + insert it, then optionally
/// set the default-domain pointer to it.
async fn seed_entry(store: &Store, name: &str, is_default: bool) -> Result<(), AppError> {
    let canonical = normalize_domain_name(name)?;
    let entry = DomainEntry {
        name: canonical.clone(),
        label: None,
        scheme: DomainUrlScheme::Https,
        status: DomainStatus::Active,
        created_at: now_secs(),
        default_domain: is_default,
        branding: None,
        witnesses: None,
        watchers: None,
        quota: None,
        well_known_enabled: false,
        disabled_at: None,
        purge_at: None,
    };
    create_domain(store, &entry).await?;
    if is_default {
        set_default_domain(store, &canonical).await?;
    }
    Ok(())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Extract the host portion of a `public_url` for the legacy fallback
/// path. Returns `None` if the URL doesn't parse or has no host.
///
/// Preserves a non-default port so that a daemon hosted at
/// `http://localhost:8534` ends up with the domain `localhost:8534`
/// rather than the bare `localhost`. Without the port, every webvh
/// DID minted from the same `public_url` would carry the encoded
/// host `localhost%3A8534` and never match the stored domain.
fn host_from_public_url(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_lowercase();
    Some(match parsed.port() {
        Some(p) => format!("{host}:{p}"),
        None => host,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::config::StoreConfig;

    async fn fjall_store() -> Store {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        };
        std::mem::forget(dir);
        Store::open(&cfg).await.expect("open fjall")
    }

    #[tokio::test]
    async fn tier_1_seeds_first_as_default_and_rest_as_extra() {
        let store = fjall_store().await;
        let outcome = seed_domains_first_boot(
            &store,
            &[
                "primary.example".to_string(),
                "secondary.example".to_string(),
            ],
            None,
        )
        .await
        .unwrap();
        assert_eq!(outcome.tier, SeedTier::FromBootstrapDomains);
        assert_eq!(outcome.final_count, 2);
        assert_eq!(outcome.default.as_deref(), Some("primary.example"));
        // Default flag set on primary, cleared on secondary.
        let listed = list_domains(&store).await.unwrap();
        let primary = listed.iter().find(|d| d.name == "primary.example").unwrap();
        let secondary = listed
            .iter()
            .find(|d| d.name == "secondary.example")
            .unwrap();
        assert!(primary.default_domain);
        assert!(!secondary.default_domain);
    }

    #[tokio::test]
    async fn tier_1_single_entry() {
        let store = fjall_store().await;
        let outcome = seed_domains_first_boot(&store, &["only.example".to_string()], None)
            .await
            .unwrap();
        assert_eq!(outcome.tier, SeedTier::FromBootstrapDomains);
        assert_eq!(outcome.final_count, 1);
        assert_eq!(outcome.default.as_deref(), Some("only.example"));
    }

    #[tokio::test]
    async fn tier_2_seeds_from_legacy_public_url() {
        let store = fjall_store().await;
        let outcome =
            seed_domains_first_boot(&store, &[], Some("https://old.example.com/some/path"))
                .await
                .unwrap();
        assert_eq!(outcome.tier, SeedTier::FromLegacyPublicUrl);
        assert_eq!(outcome.final_count, 1);
        assert_eq!(outcome.default.as_deref(), Some("old.example.com"));
    }

    #[tokio::test]
    async fn tier_2_lowercases_host() {
        let store = fjall_store().await;
        let outcome = seed_domains_first_boot(&store, &[], Some("https://OLD.example.com"))
            .await
            .unwrap();
        assert_eq!(outcome.tier, SeedTier::FromLegacyPublicUrl);
        assert_eq!(outcome.default.as_deref(), Some("old.example.com"));
    }

    #[tokio::test]
    async fn tier_3_empty_seed_yields_no_seed() {
        let store = fjall_store().await;
        let outcome = seed_domains_first_boot(&store, &[], None).await.unwrap();
        assert_eq!(outcome.tier, SeedTier::NoSeed);
        assert_eq!(outcome.final_count, 0);
        assert_eq!(outcome.default, None);
        assert!(list_domains(&store).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn already_seeded_short_circuits() {
        let store = fjall_store().await;
        // First seed.
        seed_domains_first_boot(&store, &["a.example".to_string()], None)
            .await
            .unwrap();
        // Second call with different inputs must be a no-op.
        let outcome = seed_domains_first_boot(
            &store,
            &["b.example".to_string()],
            Some("https://c.example"),
        )
        .await
        .unwrap();
        assert_eq!(outcome.tier, SeedTier::AlreadySeeded);
        assert_eq!(outcome.final_count, 1);
        assert_eq!(outcome.default.as_deref(), Some("a.example"));
        // Only the original entry should be present.
        let listed = list_domains(&store).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "a.example");
    }

    #[tokio::test]
    async fn rejects_non_canonical_bootstrap_domain() {
        let store = fjall_store().await;
        // `Example.com` non-canonical → normalisation rejects → the
        // whole seed fails.
        let err = seed_domains_first_boot(&store, &["Example.com".to_string()], None)
            .await
            .expect_err("non-canonical must reject");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[tokio::test]
    async fn tier_1_preferred_over_tier_2_when_both_set() {
        let store = fjall_store().await;
        let outcome = seed_domains_first_boot(
            &store,
            &["preferred.example".to_string()],
            Some("https://legacy.example.com"),
        )
        .await
        .unwrap();
        assert_eq!(outcome.tier, SeedTier::FromBootstrapDomains);
        assert_eq!(outcome.default.as_deref(), Some("preferred.example"));
        // Legacy URL is ignored when tier 1 has entries.
        let listed = list_domains(&store).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "preferred.example");
    }

    #[tokio::test]
    async fn unparseable_legacy_url_falls_through_to_no_seed() {
        let store = fjall_store().await;
        let outcome = seed_domains_first_boot(&store, &[], Some("not-a-url"))
            .await
            .unwrap();
        assert_eq!(outcome.tier, SeedTier::NoSeed);
    }

    #[test]
    fn host_extraction() {
        // Non-default port is preserved so the seeded domain matches
        // the host that webvh DIDs minted from the same URL embed.
        assert_eq!(
            host_from_public_url("https://example.com:8080/path"),
            Some("example.com:8080".to_string())
        );
        // Default port for the scheme is dropped (url::Url::port()
        // returns None for `https://...:443`), which is what we want
        // — the embedded DID host won't carry it either.
        assert_eq!(
            host_from_public_url("https://example.com:443"),
            Some("example.com".to_string())
        );
        assert_eq!(
            host_from_public_url("http://Example.COM"),
            Some("example.com".to_string())
        );
        assert_eq!(
            host_from_public_url("http://localhost:8534"),
            Some("localhost:8534".to_string())
        );
        assert_eq!(host_from_public_url("not-a-url"), None);
    }
}
