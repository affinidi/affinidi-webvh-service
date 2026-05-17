//! First-boot seed for the `KS_ASSIGNMENTS` keyspace (T29).
//!
//! T28 made the control plane the source of truth for which domains
//! a server hosts. But a freshly-deployed server hasn't received any
//! `MSG_DOMAIN_ASSIGN` yet, and an offline control plane means it
//! never will until reconnected. To avoid the new server being
//! unable to host *anything* until the control plane reaches it, the
//! server seeds `KS_ASSIGNMENTS` from local config on first boot.
//!
//! ## Fallback chain
//!
//! Identical priority to T18's domain seed so operators only have to
//! configure one place:
//!
//! 1. **`KS_ASSIGNMENTS` already populated** → no-op (prior boot or
//!    a control-plane push already wrote entries).
//! 2. **`[hosting] bootstrap_domains`** → each entry becomes an
//!    assignment with `assigner = "bootstrap-config"`. Idempotent
//!    (the `assign()` helper short-circuits on existing entries).
//! 3. **legacy `public_url` host** → the host portion of the URL
//!    becomes a single assignment with `assigner = "legacy-public-url"`.
//!    Upgrade path from pre-multi-domain deployments.
//! 4. **Empty** → loud warn-log. The server starts but rejects every
//!    resolve until either the control plane assigns a domain or an
//!    operator pushes a domain through `did-hosting-control`.
//!
//! ## When the control plane catches up
//!
//! The control plane's `MSG_DOMAIN_ASSIGN` handler runs the same
//! idempotent `assign()` — so a fallback-seeded entry that the
//! control plane also "owns" stays as a single row (the `assigner`
//! field is preserved on the first write). If the control plane
//! later sends `MSG_DOMAIN_UNASSIGN`, the row is removed; the
//! fallback does NOT re-seed because the keyspace is no longer
//! empty. This matches the spec's "control plane is authoritative
//! once contacted" rule.

use tracing::{info, warn};
use url::Url;

use super::assignment::{AssignOutcome, assign, list};
use super::error::AppError;
use super::store::Store;

/// Tier identifier returned by [`seed_assignments_first_boot`] so the
/// caller can log which path the deployment is on.
#[derive(Debug, PartialEq, Eq)]
pub enum AssignmentSeedTier {
    /// Tier 0: keyspace already has entries from a prior boot or a
    /// control-plane push.
    AlreadySeeded,
    /// Tier 1: seeded from `config.hosting.bootstrap_domains`.
    FromBootstrapDomains,
    /// Tier 2: seeded from the legacy `public_url`'s host. Upgrade
    /// path from a pre-multi-domain deployment.
    FromLegacyPublicUrl,
    /// Tier 3: nothing configured — keyspace stays empty.
    NoSeed,
}

/// Outcome of [`seed_assignments_first_boot`]. Surfaces the tier
/// chosen + the resulting effective set so the caller can log it.
#[derive(Debug)]
pub struct AssignmentSeedOutcome {
    pub tier: AssignmentSeedTier,
    pub final_count: usize,
    /// Effective domain list after seeding. Empty when `tier =
    /// NoSeed`.
    pub domains: Vec<String>,
}

/// Seed `KS_ASSIGNMENTS` from local config on first boot.
///
/// `now_epoch` is passed in by the caller (rather than read from the
/// system clock here) so the seed timestamp lines up with whatever
/// other startup events are recording.
pub async fn seed_assignments_first_boot(
    store: &Store,
    bootstrap_domains: &[String],
    legacy_public_url: Option<&str>,
    now_epoch: u64,
) -> Result<AssignmentSeedOutcome, AppError> {
    // Tier 0: keyspace already populated.
    let existing = list(store).await?;
    if !existing.is_empty() {
        return Ok(AssignmentSeedOutcome {
            tier: AssignmentSeedTier::AlreadySeeded,
            final_count: existing.len(),
            domains: existing.into_iter().map(|e| e.domain).collect(),
        });
    }

    // Tier 1: bootstrap_domains.
    if !bootstrap_domains.is_empty() {
        let mut seeded = Vec::with_capacity(bootstrap_domains.len());
        for d in bootstrap_domains {
            match assign(store, d, "bootstrap-config", now_epoch).await? {
                AssignOutcome::Created(e) | AssignOutcome::Existing(e) => seeded.push(e.domain),
            }
        }
        info!(
            tier = "bootstrap_domains",
            count = seeded.len(),
            "first-boot assignment seed complete"
        );
        return Ok(AssignmentSeedOutcome {
            tier: AssignmentSeedTier::FromBootstrapDomains,
            final_count: seeded.len(),
            domains: seeded,
        });
    }

    // Tier 2: legacy public_url host.
    if let Some(url) = legacy_public_url
        && let Some(host) = host_from_public_url(url)
    {
        warn!(
            legacy_public_url = %url,
            derived_host = %host,
            "first-boot assignment seed: bootstrap_domains empty — \
             falling back to legacy public_url host. Consider moving \
             '{host}' to config `[hosting] bootstrap_domains`."
        );
        let outcome = assign(store, &host, "legacy-public-url", now_epoch).await?;
        let domain = match outcome {
            AssignOutcome::Created(e) | AssignOutcome::Existing(e) => e.domain,
        };
        return Ok(AssignmentSeedOutcome {
            tier: AssignmentSeedTier::FromLegacyPublicUrl,
            final_count: 1,
            domains: vec![domain],
        });
    }

    // Tier 3: nothing to seed.
    warn!(
        "first-boot assignment seed: no domains configured — neither \
         [hosting] bootstrap_domains nor a legacy public_url is set. \
         The server will reject every resolve until either the control \
         plane assigns a domain or an admin pushes one through the \
         control plane."
    );
    Ok(AssignmentSeedOutcome {
        tier: AssignmentSeedTier::NoSeed,
        final_count: 0,
        domains: Vec::new(),
    })
}

/// Extract the host (without port) from a URL like
/// `https://example.com:8443/foo`. Returns `None` if the URL is
/// unparseable or has no host component.
fn host_from_public_url(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    Some(host.to_ascii_lowercase())
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
    async fn tier_1_seeds_each_bootstrap_domain() {
        let store = fjall_store().await;
        let outcome =
            seed_assignments_first_boot(&store, &["a.example".into(), "b.example".into()], None, 1)
                .await
                .unwrap();
        assert_eq!(outcome.tier, AssignmentSeedTier::FromBootstrapDomains);
        assert_eq!(outcome.final_count, 2);
        let mut domains = outcome.domains.clone();
        domains.sort();
        assert_eq!(domains, vec!["a.example", "b.example"]);
    }

    #[tokio::test]
    async fn tier_2_seeds_host_from_legacy_public_url() {
        let store = fjall_store().await;
        let outcome = seed_assignments_first_boot(
            &store,
            &[],
            Some("https://legacy.example.com:8443/path"),
            1,
        )
        .await
        .unwrap();
        assert_eq!(outcome.tier, AssignmentSeedTier::FromLegacyPublicUrl);
        assert_eq!(outcome.domains, vec!["legacy.example.com"]);
    }

    #[tokio::test]
    async fn tier_3_empty_warns_no_seed() {
        let store = fjall_store().await;
        let outcome = seed_assignments_first_boot(&store, &[], None, 1)
            .await
            .unwrap();
        assert_eq!(outcome.tier, AssignmentSeedTier::NoSeed);
        assert!(outcome.domains.is_empty());
    }

    #[tokio::test]
    async fn tier_0_already_seeded_short_circuits() {
        let store = fjall_store().await;
        // First boot — tier 1.
        seed_assignments_first_boot(&store, &["x.example".into()], None, 1)
            .await
            .unwrap();

        // Second boot — even with different bootstrap_domains config,
        // the existing entries win.
        let outcome =
            seed_assignments_first_boot(&store, &["y.example".into(), "z.example".into()], None, 2)
                .await
                .unwrap();
        assert_eq!(outcome.tier, AssignmentSeedTier::AlreadySeeded);
        assert_eq!(outcome.domains, vec!["x.example"]);
    }

    #[tokio::test]
    async fn bootstrap_takes_priority_over_legacy_public_url() {
        let store = fjall_store().await;
        let outcome = seed_assignments_first_boot(
            &store,
            &["preferred.example".into()],
            Some("https://legacy.example.com/path"),
            1,
        )
        .await
        .unwrap();
        assert_eq!(outcome.tier, AssignmentSeedTier::FromBootstrapDomains);
        assert_eq!(outcome.domains, vec!["preferred.example"]);
    }

    #[tokio::test]
    async fn unparseable_legacy_url_falls_through_to_no_seed() {
        let store = fjall_store().await;
        let outcome = seed_assignments_first_boot(&store, &[], Some("not a url"), 1)
            .await
            .unwrap();
        assert_eq!(outcome.tier, AssignmentSeedTier::NoSeed);
    }
}
