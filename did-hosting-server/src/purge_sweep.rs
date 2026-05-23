//! Background grace-expired purge sweep (T30 pass 3).
//!
//! Runs on a 60-second tick. Each tick:
//! 1. Lists every `PendingPurge` in `KS_PENDING_PURGES`.
//! 2. For each entry whose grace window has elapsed
//!    ([`did_hosting_common::server::pending_purge::PendingPurge::is_ripe`]),
//!    calls [`did_hosting_common::server::domain_purge::purge_domain_dids`]
//!    to delete the matching DID records and removes the pending
//!    entry afterwards.
//!
//! Not-ripe entries are left for a future tick. The 60s cadence is
//! a config-fixed compromise — fast enough that the deviation
//! between configured grace and observed-purge time stays under a
//! minute, slow enough that an idle deployment doesn't churn on
//! empty keyspace scans.
//!
//! ## Restart safety
//!
//! `KS_PENDING_PURGES` is persisted. A crash or restart between
//! `unassign` and the eventual sweep doesn't lose the schedule —
//! the next sweep tick picks up the same ripe set. Conversely,
//! `purge_domain_dids` + `pending_purge::cancel` aren't atomic
//! across a restart: a crash after the purge succeeds but before
//! the pending entry is removed leaves a stale pending entry, and
//! the next sweep will harmlessly call `purge_domain_dids` again
//! (it's a no-op on already-empty records) and then remove the
//! pending entry on this second pass.

use std::time::Duration;

use did_hosting_common::server::domain::{self, DISABLE_PURGE_REASON};
use did_hosting_common::server::domain_purge::purge_domain_dids;
use did_hosting_common::server::pending_purge;
use did_hosting_common::server::store::Store;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::auth::session::now_epoch;

/// Default tick cadence. Public so the daemon can override it for
/// integration tests (fast loop) if needed.
pub const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Run one sweep cycle synchronously. Returns the number of pending
/// entries that were ripe and purged. Used both by the background
/// loop and by tests that want to observe one tick's effect without
/// waiting for the timer.
pub async fn run_sweep_once(store: &Store) -> u64 {
    let pending = match pending_purge::list(store).await {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "purge sweep: failed to list pending entries; skipping tick");
            return 0;
        }
    };
    if pending.is_empty() {
        debug!("purge sweep: no pending entries");
        return 0;
    }

    let now = now_epoch();
    let mut purged = 0u64;
    for entry in pending {
        if !entry.is_ripe(now) {
            continue;
        }
        match purge_domain_dids(store, &entry.domain, &entry.reason).await {
            Ok(report) => {
                info!(
                    domain = %entry.domain,
                    reason = %entry.reason,
                    deleted = report.deleted,
                    "purge sweep: ripe entry processed"
                );

                // Soft-delete-with-grace path: the DomainEntry itself
                // must be removed too. Unassign-grace (the other
                // reason) keeps the DomainEntry so the operator can
                // re-assign the domain to a different server later.
                if entry.reason == DISABLE_PURGE_REASON {
                    match domain::delete_domain_record(store, &entry.domain).await {
                        Ok(()) => {
                            info!(
                                domain = %entry.domain,
                                "purge sweep: disabled-domain record deleted"
                            );
                        }
                        Err(e) => {
                            // The pending entry stays — next tick
                            // will retry. DIDs are already gone;
                            // worst case we leave a 'Disabled' shell
                            // entry until the operator intervenes.
                            warn!(
                                domain = %entry.domain,
                                error = %e,
                                "purge sweep: failed to delete domain record; entry retained for next tick"
                            );
                            continue;
                        }
                    }
                }

                if let Err(e) = pending_purge::cancel(store, &entry.domain).await {
                    // Stale entry will be re-tried on the next tick;
                    // the second `purge_domain_dids` call is harmless
                    // (no records remain to delete).
                    warn!(
                        domain = %entry.domain,
                        error = %e,
                        "purge sweep: failed to clear pending entry; will retry next tick"
                    );
                }
                purged += 1;
            }
            Err(e) => {
                warn!(
                    domain = %entry.domain,
                    error = %e,
                    "purge sweep: purge failed; entry retained for next tick"
                );
            }
        }
    }
    purged
}

/// Long-running background task driving [`run_sweep_once`] on a
/// 60-second tick until `shutdown` flips. The daemon spawns one of
/// these per process; standalone servers spawn it in their own
/// startup chain.
pub async fn run_purge_sweep_loop(store: Store, mut shutdown: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(DEFAULT_SWEEP_INTERVAL);
    // Skip the immediate first tick — the daemon's startup is busy
    // enough already, and a fresh boot is unlikely to have ripe
    // entries that need attention in the first 60s.
    ticker.tick().await;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let purged = run_sweep_once(&store).await;
                if purged > 0 {
                    info!(count = purged, "purge sweep tick completed");
                }
            }
            _ = shutdown.changed() => {
                info!("purge sweep loop shutting down");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use did_hosting_common::did_ops::{DidRecord, content_log_key, did_key};
    use did_hosting_common::server::config::StoreConfig;
    use did_hosting_common::server::pending_purge::schedule;
    use did_hosting_common::server::store::KS_DIDS;

    async fn fjall_store() -> Store {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        };
        std::mem::forget(dir);
        Store::open(&cfg).await.expect("open fjall")
    }

    fn record(mnemonic: &str, domain: &str) -> DidRecord {
        DidRecord {
            owner: format!("did:example:owner-{mnemonic}"),
            mnemonic: mnemonic.into(),
            created_at: 1,
            updated_at: 1,
            version_count: 1,
            did_id: Some(format!("did:webvh:Q1:{domain}:{mnemonic}")),
            content_size: 0,
            disabled: false,
            deleted_at: None,
            method: "webvh".into(),
            domain: domain.into(),
        }
    }

    async fn seed(store: &Store, mnemonic: &str, domain: &str) {
        let ks = store.keyspace(KS_DIDS).unwrap();
        let r = record(mnemonic, domain);
        ks.insert(did_key(mnemonic), &r).await.unwrap();
        ks.insert_raw(content_log_key(mnemonic), b"log".to_vec())
            .await
            .unwrap();
    }

    /// A pending entry scheduled in the past with a 1-second grace
    /// is ripe by now and must be processed. An entry scheduled now
    /// with a 1-hour grace is not ripe and must be retained.
    #[tokio::test]
    async fn sweep_processes_ripe_only() {
        let store = fjall_store().await;
        seed(&store, "alice", "ripe.example").await;
        seed(&store, "bob", "fresh.example").await;

        // ripe.example: scheduled long ago, 1s grace → ripe.
        schedule(&store, "ripe.example", 0, 1, "grace-expired", "did:c")
            .await
            .unwrap();
        // fresh.example: scheduled at current time, 1h grace → not ripe.
        let now = now_epoch();
        schedule(&store, "fresh.example", now, 3600, "grace-expired", "did:c")
            .await
            .unwrap();

        let purged = run_sweep_once(&store).await;
        assert_eq!(purged, 1, "only the ripe entry should be processed");

        let ks = store.keyspace(KS_DIDS).unwrap();
        // alice (ripe.example) was deleted; bob (fresh.example) survives.
        assert!(
            ks.get::<DidRecord>(did_key("alice"))
                .await
                .unwrap()
                .is_none()
        );
        assert!(ks.get::<DidRecord>(did_key("bob")).await.unwrap().is_some());

        // Pending entry for ripe.example was cleared; fresh.example
        // is retained for the next tick.
        assert!(
            pending_purge::get(&store, "ripe.example")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            pending_purge::get(&store, "fresh.example")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn sweep_with_no_pending_entries_is_noop() {
        let store = fjall_store().await;
        let purged = run_sweep_once(&store).await;
        assert_eq!(purged, 0);
    }

    /// Stale pending entry (purge previously ran but the cancellation
    /// crashed) is harmless on the next tick — no records left to
    /// delete, but the entry is still cleared.
    #[tokio::test]
    async fn sweep_retried_on_already_empty_records_clears_entry() {
        let store = fjall_store().await;
        // No records seeded — just a ripe pending entry.
        schedule(&store, "stale.example", 0, 1, "grace-expired", "did:c")
            .await
            .unwrap();

        let purged = run_sweep_once(&store).await;
        assert_eq!(purged, 1, "stale entry still processed and cleared");
        assert!(
            pending_purge::get(&store, "stale.example")
                .await
                .unwrap()
                .is_none()
        );
    }

    /// `disable-grace` ripe entry → DIDs purged AND domain record
    /// itself removed. Distinguishes the soft-delete path from the
    /// unassignment path (which retains the DomainEntry).
    #[tokio::test]
    async fn sweep_deletes_domain_record_for_disable_grace() {
        use did_hosting_common::server::domain::{DomainEntry, DomainStatus, DomainUrlScheme};
        use did_hosting_common::server::store::KS_DOMAINS;

        let store = fjall_store().await;
        seed(&store, "alice", "soft-delete.example").await;

        // Seed the DomainEntry directly (skip the disable_domain
        // helper to avoid the default-domain conflict check; this
        // test just needs the row present so we can verify the
        // sweeper deletes it).
        let domains_ks = store.keyspace(KS_DOMAINS).unwrap();
        let entry = DomainEntry {
            name: "soft-delete.example".into(),
            label: None,
            scheme: DomainUrlScheme::Https,
            status: DomainStatus::Disabled,
            created_at: 1,
            default_domain: false,
            branding: None,
            witnesses: None,
            watchers: None,
            quota: None,
            well_known_enabled: false,
            disabled_at: Some(0),
            purge_at: Some(1),
        };
        domains_ks
            .insert(b"soft-delete.example".to_vec(), &entry)
            .await
            .unwrap();

        // Ripe disable-grace pending row.
        schedule(
            &store,
            "soft-delete.example",
            0,
            1,
            DISABLE_PURGE_REASON,
            "did:example:admin",
        )
        .await
        .unwrap();

        let purged = run_sweep_once(&store).await;
        assert_eq!(purged, 1);

        // DIDs gone.
        let dids_ks = store.keyspace(KS_DIDS).unwrap();
        assert!(
            dids_ks
                .get::<DidRecord>(did_key("alice"))
                .await
                .unwrap()
                .is_none()
        );
        // Domain record gone.
        assert!(
            domain::get_domain(&store, "soft-delete.example")
                .await
                .unwrap()
                .is_none()
        );
        // Pending entry cleared.
        assert!(
            pending_purge::get(&store, "soft-delete.example")
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Existing unassign sweep path still retains the DomainEntry —
    /// regression guard for the new branch above.
    #[tokio::test]
    async fn sweep_unassign_grace_preserves_domain_record() {
        use did_hosting_common::server::domain::{DomainEntry, DomainStatus, DomainUrlScheme};
        use did_hosting_common::server::store::KS_DOMAINS;

        let store = fjall_store().await;
        seed(&store, "carol", "unassign.example").await;

        let domains_ks = store.keyspace(KS_DOMAINS).unwrap();
        let entry = DomainEntry {
            name: "unassign.example".into(),
            label: None,
            scheme: DomainUrlScheme::Https,
            status: DomainStatus::Active,
            created_at: 1,
            default_domain: false,
            branding: None,
            witnesses: None,
            watchers: None,
            quota: None,
            well_known_enabled: false,
            disabled_at: None,
            purge_at: None,
        };
        domains_ks
            .insert(b"unassign.example".to_vec(), &entry)
            .await
            .unwrap();

        schedule(&store, "unassign.example", 0, 1, "grace-expired", "did:c")
            .await
            .unwrap();

        let purged = run_sweep_once(&store).await;
        assert_eq!(purged, 1);

        // DomainEntry retained.
        assert!(
            domain::get_domain(&store, "unassign.example")
                .await
                .unwrap()
                .is_some()
        );
    }
}
