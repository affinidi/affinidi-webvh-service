use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use did_hosting_common::DidStats;
use did_hosting_common::server::config::StoreConfig;
use did_hosting_common::server::stats_tiers::{
    BUCKET_SECS, StatsMode, StatsResolution, StatsTierConfig, fine_slot,
};

use super::*;
use crate::store::Store;

async fn keyspaces() -> (tempfile::TempDir, Store, KeyspaceHandle, KeyspaceHandle) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(&StoreConfig {
        data_dir: dir.path().to_path_buf(),
        ..StoreConfig::default()
    })
    .await
    .expect("open fjall");
    let stats_ks = store.keyspace("stats").unwrap();
    let timeseries_ks = store.keyspace("timeseries").unwrap();
    (dir, store, stats_ks, timeseries_ks)
}

/// The start of the bucket before the one `now` is in: closed.
pub(crate) fn last_bucket(now: u64) -> u64 {
    now / BUCKET_SECS * BUCKET_SECS - BUCKET_SECS
}

/// Give `mnemonic` `resolves` in the last closed bucket, as events recorded
/// then would have: its delta, its bucket and the server-wide bucket.
fn resolved(collector: &StatsCollector, mnemonic: &str, resolves: u64, now: u64) {
    let epoch = last_bucket(now);
    collector.requeue_deltas(vec![DidStatsDelta {
        mnemonic: mnemonic.into(),
        resolve_delta: resolves,
        update_delta: 0,
        last_resolved_at: Some(epoch),
        last_updated_at: None,
    }]);
    let bucket = |m: &str| DrainedBucket {
        mnemonic: m.into(),
        epoch,
        resolves,
        updates: 0,
    };
    collector.requeue_buckets(vec![bucket(mnemonic), bucket(ALL_SERIES)]);
}

async fn totals(stats_ks: &KeyspaceHandle, m: &str) -> (u64, u64) {
    let s: DidStats = stats_ks.get(stats_key(m)).await.unwrap().unwrap();
    (s.total_resolves, s.total_updates)
}

async fn row(stats_ks: &KeyspaceHandle, m: &str) -> StoredDidStats {
    stats_ks.get(stats_key(m)).await.unwrap().unwrap()
}

async fn slot(ts_ks: &KeyspaceHandle, m: &str, epoch: u64) -> Option<FineSlot> {
    ts_ks.get(fine_key(m, epoch)).await.unwrap()
}

fn hourly_resolves(s: &CoarseSeries) -> u64 {
    s.hourly().map(|(_, r, _)| r).sum()
}

/// A flush whose writes start failing part-way keeps every row it did not
/// write, and the next flush writes them without counting any event twice.
#[tokio::test]
async fn failed_stats_flush_loses_no_counts() {
    let (_dir, store, _, _) = keyspaces().await;
    let allowed = Arc::new(AtomicUsize::new(1));
    let stats_ks = store
        .keyspace("stats")
        .unwrap()
        .failing_writes_after(allowed.clone());
    let ts_ks = store
        .keyspace("timeseries")
        .unwrap()
        .failing_writes_after(allowed.clone());
    let now = now_epoch();
    let collector = StatsCollector::new();
    for m in ["alice", "bob", "carol"] {
        resolved(&collector, m, 1, now);
    }
    resolved(&collector, "alice", 1, now);

    flush_stats_to_store(&collector, &stats_ks, &ts_ks, usize::MAX, now)
        .await
        .expect_err("writes fail after the first");
    resolved(&collector, "bob", 1, now);
    allowed.store(usize::MAX, Ordering::SeqCst);
    flush_stats_to_store(&collector, &stats_ks, &ts_ks, usize::MAX, now)
        .await
        .expect("retry flushes everything");

    assert_eq!(totals(&stats_ks, "alice").await, (2, 0));
    assert_eq!(totals(&stats_ks, "bob").await, (2, 0));
    assert_eq!(totals(&stats_ks, "carol").await, (1, 0));
    let all: CoarseSeries = ts_ks.get(ALL_COARSE_KEY).await.unwrap().unwrap();
    assert_eq!(
        hourly_resolves(&all),
        5,
        "server-wide coarse series counts each event once"
    );
    let s = slot(&ts_ks, ALL_SERIES, last_bucket(now)).await.unwrap();
    assert_eq!(s.r, 5, "and so does its fine slot");
}

/// Rows past the budget wait for the next flush, the server-wide series
/// first.
#[tokio::test]
async fn stats_flush_defers_rows_past_its_budget() {
    let (_dir, _store, stats_ks, ts_ks) = keyspaces().await;
    let now = now_epoch();
    let collector = StatsCollector::new();
    for m in ["alice", "bob"] {
        resolved(&collector, m, 1, now);
    }

    flush_stats_to_store(&collector, &stats_ks, &ts_ks, 1, now)
        .await
        .unwrap();
    assert!(ts_ks.get_raw(ALL_COARSE_KEY).await.unwrap().is_some());
    flush_stats_to_store(&collector, &stats_ks, &ts_ks, 1, now)
        .await
        .unwrap();
    assert!(
        slot(&ts_ks, ALL_SERIES, last_bucket(now)).await.is_some(),
        "the server-wide slot comes next, deferred with the rest"
    );
    assert!(stats_ks.prefix_iter_raw("stats:").await.unwrap().is_empty());

    for _ in 0..2 {
        flush_stats_to_store(&collector, &stats_ks, &ts_ks, 1, now)
            .await
            .unwrap();
    }
    assert_eq!(collector.pending_rows(), 0);
    for m in ["alice", "bob"] {
        assert_eq!(totals(&stats_ks, m).await, (1, 0), "{m}");
    }
}

/// The periodic flush leaves the open bucket, and a DID whose only activity
/// is in it, for later.
#[tokio::test]
async fn the_open_bucket_waits_until_it_closes() {
    let (_dir, _store, stats_ks, ts_ks) = keyspaces().await;
    let collector = StatsCollector::new();
    collector.record_resolve("alice");
    let now = now_epoch();
    flush_stats_to_store(&collector, &stats_ks, &ts_ks, usize::MAX, now)
        .await
        .unwrap();
    assert!(
        stats_ks
            .get_raw(stats_key("alice"))
            .await
            .unwrap()
            .is_none()
    );

    flush_stats_to_store(&collector, &stats_ks, &ts_ks, usize::MAX, now + BUCKET_SECS)
        .await
        .unwrap();
    assert_eq!(totals(&stats_ks, "alice").await, (1, 0));
    assert_eq!(collector.pending_rows(), 0);
}

/// A quiet DID keeps only its coarse series; a busy one is promoted and
/// gets its 5-minute slot from the bucket that promoted it.
#[tokio::test]
async fn busy_dids_get_fine_slots_and_quiet_ones_do_not() {
    let (_dir, _store, stats_ks, ts_ks) = keyspaces().await;
    let now = now_epoch();
    let collector = StatsCollector::new();
    resolved(&collector, "quiet", 3, now);
    resolved(&collector, "busy", 500, now);
    flush_stats_to_store(&collector, &stats_ks, &ts_ks, usize::MAX, now)
        .await
        .unwrap();

    let coarse = row(&stats_ks, "quiet").await.coarse.expect("coarse series");
    assert_eq!(coarse.fine_since, None);
    assert_eq!(hourly_resolves(&coarse), 3);
    assert!(slot(&ts_ks, "quiet", last_bucket(now)).await.is_none());

    let busy = row(&stats_ks, "busy").await;
    assert_eq!(busy.coarse.unwrap().fine_since, Some(now));
    let s = slot(&ts_ks, "busy", last_bucket(now)).await.unwrap();
    assert_eq!((s.e, s.r), (last_bucket(now), 500));
    assert_eq!(collector.tiers().promoted_count(), 1);
}

#[tokio::test]
async fn pins_decide_the_tier() {
    let (_dir, _store, stats_ks, ts_ks) = keyspaces().await;
    let now = now_epoch();
    let collector = StatsCollector::new();
    collector.tiers().set_pin("pinned", StatsResolution::Fine);
    collector.tiers().set_pin("off", StatsResolution::Off);
    resolved(&collector, "pinned", 1, now);
    resolved(&collector, "off", 500, now);
    flush_stats_to_store(&collector, &stats_ks, &ts_ks, usize::MAX, now)
        .await
        .unwrap();

    assert!(slot(&ts_ks, "pinned", last_bucket(now)).await.is_some());
    let off = row(&stats_ks, "off").await;
    assert!(off.coarse.is_none(), "totals only");
    assert_eq!(off.totals.total_resolves, 500);
    assert!(slot(&ts_ks, "off", last_bucket(now)).await.is_none());
}

#[tokio::test]
async fn coarse_mode_writes_no_per_did_slots() {
    let (_dir, _store, stats_ks, ts_ks) = keyspaces().await;
    let now = now_epoch();
    let collector = StatsCollector::new();
    collector.configure_tiers(StatsTierConfig {
        mode: StatsMode::Coarse,
        ..StatsTierConfig::default()
    });
    resolved(&collector, "busy", 500, now);
    flush_stats_to_store(&collector, &stats_ks, &ts_ks, usize::MAX, now)
        .await
        .unwrap();
    assert!(slot(&ts_ks, "busy", last_bucket(now)).await.is_none());
    assert!(
        slot(&ts_ks, ALL_SERIES, last_bucket(now)).await.is_some(),
        "the server-wide series is always fine"
    );
}

/// A fine slot whose write fails is retried on its own: its DID's row,
/// already written, does not count the bucket again.
#[tokio::test]
async fn a_failed_slot_is_retried_without_recounting_its_row() {
    let (_dir, store, stats_ks, _) = keyspaces().await;
    // The time-series keyspace takes one write, `c:_all`; its slot fails.
    let allowed = Arc::new(AtomicUsize::new(1));
    let ts_ks = store
        .keyspace("timeseries")
        .unwrap()
        .failing_writes_after(allowed.clone());
    let now = now_epoch();
    let collector = StatsCollector::new();
    collector.tiers().set_pin("alice", StatsResolution::Fine);
    resolved(&collector, "alice", 4, now);
    let _ = flush_stats_to_store(&collector, &stats_ks, &ts_ks, usize::MAX, now).await;
    allowed.store(usize::MAX, Ordering::SeqCst);
    flush_stats_to_store(&collector, &stats_ks, &ts_ks, usize::MAX, now)
        .await
        .unwrap();
    flush_stats_to_store(&collector, &stats_ks, &ts_ks, usize::MAX, now)
        .await
        .unwrap();

    assert_eq!(collector.pending_rows(), 0);
    assert_eq!(totals(&stats_ks, "alice").await, (4, 0));
    let coarse = row(&stats_ks, "alice").await.coarse.unwrap();
    assert_eq!(hourly_resolves(&coarse), 4);
    assert_eq!(slot(&ts_ks, "alice", last_bucket(now)).await.unwrap().r, 4);
    assert_eq!(
        slot(&ts_ks, ALL_SERIES, last_bucket(now)).await.unwrap().r,
        4
    );
    let all: CoarseSeries = ts_ks.get(ALL_COARSE_KEY).await.unwrap().unwrap();
    assert_eq!(hourly_resolves(&all), 4);
}

/// The ring overwrites a slot it comes round to.
#[tokio::test]
async fn a_fine_slot_is_overwritten_a_day_later() {
    let (_dir, _store, _, ts_ks) = keyspaces().await;
    let b = |epoch, r| DrainedBucket {
        mnemonic: "a".into(),
        epoch,
        resolves: r,
        updates: 0,
    };
    let day = 288 * BUCKET_SECS;
    write_fine_slot(&ts_ks, &b(600, 2)).await.unwrap();
    write_fine_slot(&ts_ks, &b(600, 1)).await.unwrap();
    assert_eq!(slot(&ts_ks, "a", 600).await.unwrap().r, 3);
    write_fine_slot(&ts_ks, &b(600 + day, 5)).await.unwrap();
    assert_eq!(fine_slot(600), fine_slot(600 + day));
    let s = slot(&ts_ks, "a", 600).await.unwrap();
    assert_eq!((s.e, s.r), (600 + day, 5));
}

/// A paced flush writes at the configured rate.
#[tokio::test]
async fn a_paced_flush_spreads_its_rows_at_the_configured_rate() {
    let (_dir, _store, stats_ks, ts_ks) = keyspaces().await;
    let collector = StatsCollector::new();
    // Events in the previous bucket by the real clock, so they are due.
    let now = now_epoch();
    for m in ["alice", "bob"] {
        resolved(&collector, m, 1, now);
    }
    // c:_all, its slot, alice, bob: four rows at two a second.
    let budget = crate::config::StatsFlushConfig {
        max_rows_per_second: 2,
    };
    let (_tx, stop) = watch::channel(false);
    let started = std::time::Instant::now();
    flush_stats_paced(&collector, &stats_ks, &ts_ks, &budget, stop)
        .await
        .unwrap();
    assert_eq!(collector.pending_rows(), 0);
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "took {:?}",
        started.elapsed()
    );
}

/// Shutdown ends a paced flush at once; what it did not write goes back to
/// the collector, and the shutdown flush writes it.
#[tokio::test]
async fn shutdown_cuts_a_paced_flush_short_and_loses_nothing() {
    let (_dir, _store, stats_ks, ts_ks) = keyspaces().await;
    let collector = StatsCollector::new();
    let now = now_epoch();
    for m in ["alice", "bob"] {
        resolved(&collector, m, 1, now);
    }
    let budget = crate::config::StatsFlushConfig {
        max_rows_per_second: 1,
    };
    let (tx, stop) = watch::channel(false);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = tx.send(true);
    });
    let started = std::time::Instant::now();
    flush_stats_paced(&collector, &stats_ks, &ts_ks, &budget, stop)
        .await
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(collector.pending_rows() > 0, "the rest is requeued");

    flush_remaining_stats(&collector, &stats_ks, &ts_ks).await;
    assert_eq!(collector.pending_rows(), 0);
    assert_eq!(stats_ks.prefix_iter_raw("stats:").await.unwrap().len(), 2);
}

/// The shutdown flush also writes the open bucket.
#[tokio::test]
async fn the_shutdown_flush_writes_the_open_bucket() {
    let (_dir, _store, stats_ks, ts_ks) = keyspaces().await;
    let collector = StatsCollector::new();
    collector.record_resolve("alice");
    flush_remaining_stats(&collector, &stats_ks, &ts_ks).await;
    assert_eq!(totals(&stats_ks, "alice").await, (1, 0));
    assert_eq!(collector.pending_rows(), 0);
}

/// A write the store applied but reported as failed is not retried, so it
/// is not counted twice.
#[tokio::test]
async fn an_applied_write_reported_as_failed_is_not_counted_twice() {
    let (_dir, _store, stats_ks, ts_ks) = keyspaces().await;
    let allowed = Arc::new(AtomicUsize::new(0));
    let stats_ks = stats_ks.failing_acks_after(allowed.clone());
    let ts_ks = ts_ks.failing_acks_after(allowed.clone());
    let now = now_epoch();
    let collector = StatsCollector::new();
    resolved(&collector, "alice", 1, now);
    flush_stats_to_store(&collector, &stats_ks, &ts_ks, usize::MAX, now)
        .await
        .expect("every failed write is found applied on read-back");
    assert_eq!(collector.pending_rows(), 0, "nothing is requeued");
    assert_eq!(totals(&stats_ks, "alice").await, (1, 0));
}

/// A bucket older than the maximum age is dropped, not written or kept; the
/// DID's other rows still arrive.
#[tokio::test]
async fn stats_flush_drops_buckets_past_the_maximum_age() {
    let (_dir, _store, stats_ks, ts_ks) = keyspaces().await;
    let now = now_epoch();
    let collector = StatsCollector::new();
    collector.requeue_buckets(vec![DrainedBucket {
        mnemonic: "alice".into(),
        epoch: 300,
        resolves: 1,
        updates: 0,
    }]);
    resolved(&collector, "bob", 1, now);
    flush_stats_to_store(&collector, &stats_ks, &ts_ks, usize::MAX, now)
        .await
        .unwrap();
    assert_eq!(collector.pending_rows(), 0);
    assert!(
        stats_ks
            .get_raw(stats_key("alice"))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(totals(&stats_ks, "bob").await, (1, 0));
}
