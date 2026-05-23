//! Control-plane purge sweep — local cleanup of soft-deleted domain
//! entries after their grace period expires.
//!
//! Split-deployment companion to the server-side sweep in
//! `did-hosting-server::purge_sweep`. Both sweepers tick
//! independently against their own fjall store:
//!
//! - **Server sweep** purges hosted DID records + deletes its local
//!   `DomainEntry` for `disable-grace` rows. Also handles
//!   `grace-expired` (unassign) rows by purging matching DIDs.
//! - **Control sweep** (this module) only needs to delete its own
//!   `DomainEntry` for ripe `disable-grace` rows — control has no
//!   hosted DIDs to purge, and never schedules `grace-expired` rows.
//!
//! Without this loop, a disabled-then-grace-expired domain would stay
//! in control's `KS_DOMAINS` forever, even though every server
//! serving it has already wiped its own copy.
//!
//! Eventually-consistent: a few seconds of skew between control's
//! delete and the servers' deletes is acceptable.

use std::time::Duration;

use did_hosting_common::server::domain::{self, DISABLE_PURGE_REASON};
use did_hosting_common::server::pending_purge;
use did_hosting_common::server::store::Store;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::auth::session::now_epoch;

/// 60-second tick — matches the server sweep cadence. Operators
/// expecting prompt cleanup tune the grace value (`hosting
/// .disable_purge_grace`), not the sweep interval.
pub const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Run one sweep cycle. Returns the number of ripe `disable-grace`
/// rows processed. Public so tests can drive a tick without waiting
/// for the timer.
pub async fn run_sweep_once(store: &Store) -> u64 {
    let pending = match pending_purge::list(store).await {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "control purge sweep: failed to list pending entries; skipping tick");
            return 0;
        }
    };
    if pending.is_empty() {
        debug!("control purge sweep: no pending entries");
        return 0;
    }

    let now = now_epoch();
    let mut purged = 0u64;
    for entry in pending {
        if !entry.is_ripe(now) {
            continue;
        }
        if entry.reason != DISABLE_PURGE_REASON {
            // `grace-expired` (unassign) only matters to servers —
            // they own the DID records. Leave the row alone; the
            // server-side sweep will clear it on the relevant peer.
            continue;
        }
        match domain::delete_domain_record(store, &entry.domain).await {
            Ok(()) => {
                info!(
                    domain = %entry.domain,
                    "control purge sweep: disabled-domain record deleted"
                );
            }
            Err(e) => {
                // Retain the pending row — next tick will retry.
                warn!(
                    domain = %entry.domain,
                    error = %e,
                    "control purge sweep: delete_domain_record failed; entry retained for next tick"
                );
                continue;
            }
        }
        if let Err(e) = pending_purge::cancel(store, &entry.domain).await {
            warn!(
                domain = %entry.domain,
                error = %e,
                "control purge sweep: failed to clear pending entry; will retry next tick"
            );
        }
        purged += 1;
    }
    purged
}

/// Long-running background driver for [`run_sweep_once`]. Spawn one
/// of these per control-plane process; standalone control binaries
/// call it from their startup chain.
pub async fn run_purge_sweep_loop(store: Store, mut shutdown: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(DEFAULT_SWEEP_INTERVAL);
    // First-tick: skip the immediate fire so startup logs aren't
    // crowded by an empty-sweep line.
    ticker.tick().await;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let purged = run_sweep_once(&store).await;
                if purged > 0 {
                    info!(count = purged, "control purge sweep tick completed");
                }
            }
            _ = shutdown.changed() => {
                info!("control purge sweep loop shutting down");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use did_hosting_common::server::config::StoreConfig;
    use did_hosting_common::server::domain::{
        DomainEntry, DomainStatus, DomainUrlScheme, create_domain, get_domain,
    };
    use did_hosting_common::server::pending_purge::schedule;
    use did_hosting_common::server::store::KS_DOMAINS;

    async fn fjall_store() -> Store {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        };
        std::mem::forget(dir);
        Store::open(&cfg).await.expect("open fjall")
    }

    fn entry(
        name: &str,
        status: DomainStatus,
        disabled_at: Option<u64>,
        purge_at: Option<u64>,
    ) -> DomainEntry {
        DomainEntry {
            name: name.into(),
            label: None,
            scheme: DomainUrlScheme::Https,
            status,
            created_at: 1,
            default_domain: false,
            branding: None,
            witnesses: None,
            watchers: None,
            quota: None,
            well_known_enabled: false,
            disabled_at,
            purge_at,
        }
    }

    /// A ripe `disable-grace` row → DomainEntry deleted, pending row
    /// cleared. Confirms control's sweep handles the soft-delete
    /// completion path.
    #[tokio::test]
    async fn sweep_deletes_disabled_domain_record() {
        let store = fjall_store().await;
        create_domain(
            &store,
            &entry("ripe.example", DomainStatus::Disabled, Some(0), Some(1)),
        )
        .await
        .unwrap();
        schedule(&store, "ripe.example", 0, 1, DISABLE_PURGE_REASON, "did:c")
            .await
            .unwrap();

        let purged = run_sweep_once(&store).await;
        assert_eq!(purged, 1);

        assert!(get_domain(&store, "ripe.example").await.unwrap().is_none());
        assert!(
            pending_purge::get(&store, "ripe.example")
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Unassign-grace rows (server-only concern) are left alone. The
    /// regression guard against control's sweep over-reaching into
    /// the server's lifecycle.
    #[tokio::test]
    async fn sweep_skips_unassign_grace_rows() {
        let store = fjall_store().await;
        create_domain(
            &store,
            &entry("other.example", DomainStatus::Active, None, None),
        )
        .await
        .unwrap();
        schedule(&store, "other.example", 0, 1, "grace-expired", "did:c")
            .await
            .unwrap();

        let purged = run_sweep_once(&store).await;
        assert_eq!(purged, 0);

        // Both the DomainEntry and the pending row remain.
        assert!(get_domain(&store, "other.example").await.unwrap().is_some());
        let domains_ks = store.keyspace(KS_DOMAINS).unwrap();
        assert!(
            domains_ks
                .get::<DomainEntry>(b"other.example".to_vec())
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            pending_purge::get(&store, "other.example")
                .await
                .unwrap()
                .is_some()
        );
    }

    /// Not-yet-ripe entries stay untouched.
    #[tokio::test]
    async fn sweep_leaves_unripe_rows_alone() {
        let store = fjall_store().await;
        create_domain(
            &store,
            &entry(
                "future.example",
                DomainStatus::Disabled,
                Some(u64::MAX - 1),
                Some(u64::MAX),
            ),
        )
        .await
        .unwrap();
        let now = now_epoch();
        schedule(
            &store,
            "future.example",
            now,
            3600,
            DISABLE_PURGE_REASON,
            "did:c",
        )
        .await
        .unwrap();

        let purged = run_sweep_once(&store).await;
        assert_eq!(purged, 0);
        assert!(
            get_domain(&store, "future.example")
                .await
                .unwrap()
                .is_some()
        );
    }
}
