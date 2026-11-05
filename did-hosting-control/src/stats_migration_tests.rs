use did_hosting_common::server::config::StoreConfig;
use did_hosting_common::server::stats_tiers::{FineSlot, fine_key};

use super::*;
use crate::store::Store;

struct Fixture {
    _dir: tempfile::TempDir,
    stats_ks: KeyspaceHandle,
    ts_ks: KeyspaceHandle,
    dids_ks: KeyspaceHandle,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(&StoreConfig {
        data_dir: dir.path().to_path_buf(),
        ..StoreConfig::default()
    })
    .await
    .expect("open fjall");
    Fixture {
        stats_ks: store.keyspace("stats").unwrap(),
        ts_ks: store.keyspace("timeseries").unwrap(),
        dids_ks: store.keyspace("dids").unwrap(),
        _dir: dir,
    }
}

impl Fixture {
    fn maintenance(&self) -> StatsMaintenance {
        StatsMaintenance::new(
            self.stats_ks.clone(),
            self.ts_ks.clone(),
            self.dids_ks.clone(),
        )
    }

    async fn did(&self, m: &str) {
        self.dids_ks
            .insert_raw(did_key(m), b"{}".to_vec())
            .await
            .unwrap();
    }

    async fn legacy(&self, series: &str, epoch: u64, r: u64) {
        self.ts_ks
            .insert(
                format!("ts:{series}:{epoch}").as_str(),
                &serde_json::json!({ "r": r, "u": 0 }),
            )
            .await
            .unwrap();
    }

    async fn coarse(&self, m: &str) -> Option<CoarseSeries> {
        let row: Option<StoredDidStats> = self.stats_ks.get(stats_key(m)).await.unwrap();
        row.and_then(|r| r.coarse)
    }

    async fn all(&self) -> CoarseSeries {
        self.ts_ks.get(ALL_COARSE_KEY).await.unwrap().unwrap()
    }

    async fn marker(&self) -> Option<MigrationMarker> {
        self.ts_ks.get(MIGRATION_MARKER_KEY).await.unwrap()
    }
}

/// A tick deadline far enough away not to matter.
fn later() -> tokio::time::Instant {
    tokio::time::Instant::now() + std::time::Duration::from_secs(3600)
}

fn budget() -> StatsFlushConfig {
    StatsFlushConfig {
        max_rows_per_second: 10_000,
    }
}

/// Step a fresh maintenance run until it has nothing in hand.
async fn run(f: &Fixture, collector: &StatsCollector) -> StatsMaintenance {
    let mut m = f.maintenance();
    let (_tx, stop) = watch::channel(false);
    m.step(collector, &budget(), stop.clone(), later())
        .await
        .unwrap();
    while m.busy() {
        m.step(collector, &budget(), stop.clone(), later())
            .await
            .unwrap();
    }
    m
}

fn resolves(s: &CoarseSeries) -> u64 {
    s.hourly().map(|(_, r, _)| r).sum()
}

fn bucket_ago(now: u64, secs: u64) -> u64 {
    (now - secs) / BUCKET_SECS * BUCKET_SECS
}

#[tokio::test]
async fn legacy_rows_are_folded_into_the_tiered_rows() {
    let f = fixture().await;
    let now = now_epoch();
    f.did("quiet").await;
    f.did("busy").await;
    // `gone` has history but no DID record any more.
    f.legacy("quiet", bucket_ago(now, 3 * DAY_SECS), 2).await;
    f.legacy("quiet", bucket_ago(now, 20 * DAY_SECS), 5).await;
    f.legacy("busy", bucket_ago(now, 600), 400).await;
    f.legacy("gone", bucket_ago(now, 600), 9).await;
    f.legacy(ALL_SERIES, bucket_ago(now, 600), 409).await;
    f.legacy(ALL_SERIES, bucket_ago(now, 3 * DAY_SECS), 2).await;

    let collector = StatsCollector::new();
    run(&f, &collector).await;

    let quiet = f.coarse("quiet").await.unwrap();
    assert_eq!(resolves(&quiet), 2, "hourly keeps 7 days");
    assert_eq!(
        quiet.daily().map(|(_, r, _)| r).sum::<u64>(),
        7,
        "daily keeps 30"
    );
    assert_eq!(quiet.fine_since, None);
    assert!(
        f.ts_ks
            .get_raw(fine_key("quiet", bucket_ago(now, 3 * DAY_SECS)))
            .await
            .unwrap()
            .is_none()
    );

    let busy = f.coarse("busy").await.unwrap();
    assert!(busy.fine_since.is_some(), "promoted on its legacy traffic");
    let slot: FineSlot = f
        .ts_ks
        .get(fine_key("busy", bucket_ago(now, 600)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(slot.r, 400);

    assert!(
        f.stats_ks
            .get_raw(stats_key("gone"))
            .await
            .unwrap()
            .is_none()
    );
    let all = f.all().await;
    assert_eq!(resolves(&all), 411);
    let slot: FineSlot = f
        .ts_ks
        .get(fine_key(ALL_SERIES, bucket_ago(now, 600)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(slot.r, 409);

    let marker = f.marker().await.unwrap();
    assert!(marker.completed_at.is_some());
    assert!(
        crate::stats_query::tiered_ready(&f.ts_ks).await.unwrap(),
        "charts now read the tiered rows"
    );
    assert_eq!(
        f.ts_ks.prefix_iter_raw("ts:").await.unwrap().len(),
        6,
        "legacy rows are kept for rollback"
    );
}

/// Running again, after an interruption or by a second instance, never
/// counts a bucket twice.
#[tokio::test]
async fn a_second_run_counts_nothing_twice() {
    let f = fixture().await;
    let now = now_epoch();
    f.did("alice").await;
    f.legacy("alice", bucket_ago(now, 600), 3).await;
    f.legacy(ALL_SERIES, bucket_ago(now, 600), 3).await;
    let collector = StatsCollector::new();
    run(&f, &collector).await;
    // Forget completion, as an interrupted run would have, and run again
    // (a new hour's lease, as a restart would take).
    let mut m = f.marker().await.unwrap();
    m.completed_at = None;
    f.ts_ks.insert(MIGRATION_MARKER_KEY, &m).await.unwrap();
    f.ts_ks
        .remove(format!("meta:stats-migration-lease:{}", now / HOUR_SECS))
        .await
        .unwrap();
    run(&f, &collector).await;

    assert_eq!(resolves(&f.coarse("alice").await.unwrap()), 3);
    assert_eq!(resolves(&f.all().await), 3);
}

/// A row the new flush wrote before the migration reached it keeps its
/// counts; the legacy history is added to them.
#[tokio::test]
async fn history_is_added_to_what_the_flush_already_wrote() {
    let f = fixture().await;
    let now = now_epoch();
    f.did("alice").await;
    let mut c = CoarseSeries::default();
    c.add(SeriesKind::Did, bucket_ago(now, 0), 1, 0);
    let mut row = StoredDidStats {
        coarse: Some(c),
        ..StoredDidStats::default()
    };
    row.totals.total_resolves = 10;
    f.stats_ks
        .insert(stats_key("alice").as_str(), &row)
        .await
        .unwrap();
    f.legacy("alice", bucket_ago(now, 2 * HOUR_SECS), 4).await;

    run(&f, &StatsCollector::new()).await;

    let row: StoredDidStats = f.stats_ks.get(stats_key("alice")).await.unwrap().unwrap();
    assert_eq!(row.totals.total_resolves, 10, "totals are not touched");
    assert_eq!(resolves(&row.coarse.unwrap()), 5);
}

/// After a rollback, an older binary writes `ts:` rows again; the next
/// start migrates just those.
#[tokio::test]
async fn rows_an_older_binary_wrote_after_a_rollback_are_migrated() {
    let f = fixture().await;
    let now = now_epoch();
    f.did("alice").await;
    f.legacy("alice", bucket_ago(now, 3 * HOUR_SECS), 3).await;
    f.legacy(ALL_SERIES, bucket_ago(now, 3 * HOUR_SECS), 3)
        .await;
    let collector = StatsCollector::new();
    run(&f, &collector).await;
    // Mark completion two hours ago, then "the old binary" writes again.
    let mut m = f.marker().await.unwrap();
    m.completed_at = Some(now - 2 * HOUR_SECS);
    f.ts_ks.insert(MIGRATION_MARKER_KEY, &m).await.unwrap();
    f.ts_ks
        .remove(format!("meta:stats-migration-lease:{}", now / HOUR_SECS))
        .await
        .unwrap();
    f.legacy("alice", bucket_ago(now, 600), 2).await;
    f.legacy(ALL_SERIES, bucket_ago(now, 600), 2).await;

    run(&f, &collector).await;

    assert_eq!(resolves(&f.coarse("alice").await.unwrap()), 5);
    assert_eq!(resolves(&f.all().await), 5);
    assert!(f.marker().await.unwrap().completed_at.unwrap() >= now);
}

#[tokio::test]
async fn legacy_rows_are_deleted_after_the_retention_period() {
    let f = fixture().await;
    let now = now_epoch();
    f.did("alice").await;
    f.legacy("alice", bucket_ago(now, 600), 1).await;
    let collector = StatsCollector::new();
    run(&f, &collector).await;
    assert_eq!(f.ts_ks.prefix_iter_raw("ts:").await.unwrap().len(), 1);

    let mut m = f.marker().await.unwrap();
    m.completed_at = Some(now - LEGACY_RETENTION_SECS - 1);
    f.ts_ks.insert(MIGRATION_MARKER_KEY, &m).await.unwrap();
    run(&f, &collector).await;

    assert!(f.ts_ks.prefix_iter_raw("ts:").await.unwrap().is_empty());
    assert!(f.marker().await.unwrap().legacy_purged_at.is_some());
    assert_eq!(resolves(&f.coarse("alice").await.unwrap()), 1, "kept");
}

#[tokio::test]
async fn purge_now_migrates_first_then_deletes() {
    let f = fixture().await;
    let now = now_epoch();
    f.did("alice").await;
    f.legacy("alice", bucket_ago(now, 600), 1).await;
    f.legacy(ALL_SERIES, bucket_ago(now, 600), 1).await;

    let deleted = f
        .maintenance()
        .purge_legacy_now(&StatsCollector::new(), &budget())
        .await
        .unwrap();

    assert_eq!(deleted, 2);
    assert!(f.ts_ks.prefix_iter_raw("ts:").await.unwrap().is_empty());
    assert_eq!(resolves(&f.coarse("alice").await.unwrap()), 1);
    assert!(f.marker().await.unwrap().legacy_purged_at.is_some());
}

/// Step `m` until it has nothing in hand.
async fn drive(mut m: StatsMaintenance, collector: &StatsCollector) {
    let (_tx, stop) = watch::channel(false);
    m.step(collector, &budget(), stop.clone(), later())
        .await
        .unwrap();
    while m.busy() {
        m.step(collector, &budget(), stop.clone(), later())
            .await
            .unwrap();
    }
}

/// Several series with several buckets each, for the paging tests.
async fn history(f: &Fixture, now: u64) {
    for (m, n) in [("alice", 3u64), ("bob", 1), ("carol", 4)] {
        f.did(m).await;
        for i in 0..n {
            f.legacy(m, bucket_ago(now, (i + 1) * HOUR_SECS), i + 1)
                .await;
        }
    }
    f.legacy(ALL_SERIES, bucket_ago(now, HOUR_SECS), 6).await;
    f.legacy(ALL_SERIES, bucket_ago(now, 2 * HOUR_SECS), 9)
        .await;
}

/// Read two rows at a time, so series cross page boundaries: the result is
/// the same as reading them all at once.
#[tokio::test]
async fn a_migration_read_a_page_at_a_time_counts_every_bucket_once() {
    let f = fixture().await;
    let now = now_epoch();
    history(&f, now).await;

    drive(f.maintenance().with_page_rows(2), &StatsCollector::new()).await;

    assert_eq!(resolves(&f.coarse("alice").await.unwrap()), 1 + 2 + 3);
    assert_eq!(resolves(&f.coarse("bob").await.unwrap()), 1);
    assert_eq!(resolves(&f.coarse("carol").await.unwrap()), 1 + 2 + 3 + 4);
    assert_eq!(resolves(&f.all().await), 15);
    assert!(f.marker().await.unwrap().completed_at.is_some());
}

/// A backend that cannot list in key order is read whole, as before.
#[tokio::test]
async fn a_backend_without_key_order_is_read_whole() {
    let f = fixture().await;
    let now = now_epoch();
    history(&f, now).await;

    let m = StatsMaintenance::new(
        f.stats_ks.clone(),
        f.ts_ks.without_ordered_pages(),
        f.dids_ks.clone(),
    )
    .with_page_rows(2);
    drive(m, &StatsCollector::new()).await;

    assert_eq!(resolves(&f.coarse("alice").await.unwrap()), 6);
    assert_eq!(resolves(&f.coarse("carol").await.unwrap()), 10);
    assert_eq!(resolves(&f.all().await), 15);
}

/// A read that fails part-way (a throttled store) leaves the migration where
/// it was: the next step reads on from the last key read, rather than from
/// the start, and rather than the instance waiting an hour behind its own
/// lease.
#[tokio::test]
async fn a_failed_page_read_is_retried_from_where_it_stopped() {
    let f = fixture().await;
    let now = now_epoch();
    for m in ["bob", "carol", "dave"] {
        f.did(m).await;
        f.legacy(m, bucket_ago(now, HOUR_SECS), 1).await;
    }
    let collector = StatsCollector::new();
    // Reads allowed on the time-series keyspace: the marker, then the first
    // page (bob, carol); the second page fails. bob is migrated first.
    let mut m = StatsMaintenance::new(
        f.stats_ks.clone(),
        f.ts_ks.failing_reads_after(2, AppError::store_throttled),
        f.dids_ks.clone(),
    )
    .with_page_rows(2);
    let (_tx, stop) = watch::channel(false);
    m.step(&collector, &budget(), stop.clone(), later())
        .await
        .unwrap();
    let err = m.step(&collector, &budget(), stop.clone(), later()).await;
    assert!(err.is_err(), "the second page read fails");
    assert!(m.busy(), "still migrating, not waiting an hour");
    assert_eq!(resolves(&f.coarse("bob").await.unwrap()), 1, "bob was done");

    // A row behind the cursor: a re-read from the start would pick it up.
    f.did("aaron").await;
    f.legacy("aaron", bucket_ago(now, HOUR_SECS), 1).await;
    // The store recovers.
    m.timeseries_ks = f.ts_ks.clone();
    while m.busy() {
        m.step(&collector, &budget(), stop.clone(), later())
            .await
            .unwrap();
    }

    assert!(f.coarse("aaron").await.is_none(), "read on from the cursor");
    for d in ["bob", "carol", "dave"] {
        assert_eq!(resolves(&f.coarse(d).await.unwrap()), 1, "{d}");
    }
    assert!(f.marker().await.unwrap().completed_at.is_some());
}

/// On a backend without key order a failed read is a failed whole read,
/// which starts from the beginning again: it waits before retrying rather
/// than re-reading everything every flush.
#[tokio::test]
async fn a_failed_whole_read_waits_before_reading_again() {
    let f = fixture().await;
    let now = now_epoch();
    history(&f, now).await;
    let collector = StatsCollector::new();
    // The marker read is allowed; every read after it fails.
    let mut m = StatsMaintenance::new(
        f.stats_ks.clone(),
        // Outermost: answering "no key order" takes no read, as a real
        // backend without it does.
        f.ts_ks
            .failing_reads_after(1, AppError::store_throttled)
            .without_ordered_pages(),
        f.dids_ks.clone(),
    );
    let (_tx, stop) = watch::channel(false);
    m.step(&collector, &budget(), stop.clone(), later())
        .await
        .unwrap();
    assert!(
        m.step(&collector, &budget(), stop.clone(), later())
            .await
            .is_err()
    );

    // The next flush does not read again (a read would fail here).
    m.step(&collector, &budget(), stop.clone(), later())
        .await
        .expect("waits instead of re-reading");
    assert!(m.busy(), "still migrating");
}

/// A step starts nothing after its deadline: the flush tick's end, so a
/// tick that also migrates keeps its interval.
#[tokio::test]
async fn a_step_starts_nothing_after_its_deadline() {
    let f = fixture().await;
    let now = now_epoch();
    history(&f, now).await;
    let collector = StatsCollector::new();
    let mut m = f.maintenance();
    let (_tx, stop) = watch::channel(false);
    m.step(&collector, &budget(), stop.clone(), later())
        .await
        .unwrap();

    let passed = tokio::time::Instant::now();
    m.step(&collector, &budget(), stop.clone(), passed)
        .await
        .unwrap();

    assert!(m.busy());
    assert!(f.coarse("alice").await.is_none(), "nothing migrated");
}

/// A marker write that fails after this instance took the hour's lease
/// does not make it wait an hour behind its own lease.
#[tokio::test]
async fn a_failed_start_does_not_lock_out_the_instance_holding_the_lease() {
    let f = fixture().await;
    let now = now_epoch();
    history(&f, now).await;
    let collector = StatsCollector::new();
    let allowed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(1));
    // One write allowed: the lease; the marker write fails.
    let mut m = StatsMaintenance::new(
        f.stats_ks.clone(),
        f.ts_ks.failing_writes_after(allowed.clone()),
        f.dids_ks.clone(),
    );
    let (_tx, stop) = watch::channel(false);
    assert!(
        m.step(&collector, &budget(), stop.clone(), later())
            .await
            .is_err()
    );

    allowed.store(usize::MAX, std::sync::atomic::Ordering::SeqCst);
    m.step(&collector, &budget(), stop.clone(), later())
        .await
        .unwrap();
    assert!(m.busy(), "migrating, not idle behind its own lease");
}

/// The purge reads keys a page at a time too, and reports what it deleted.
#[tokio::test]
async fn purge_now_deletes_a_page_at_a_time() {
    let f = fixture().await;
    let now = now_epoch();
    history(&f, now).await;

    let deleted = f
        .maintenance()
        .with_page_rows(3)
        .purge_legacy_now(&StatsCollector::new(), &budget())
        .await
        .unwrap();

    assert_eq!(deleted, 10);
    assert!(f.ts_ks.prefix_iter_raw("ts:").await.unwrap().is_empty());
    assert_eq!(resolves(&f.all().await), 15);
}

/// Pages in hash order, as DynamoDB's `Scan` returns them: a series' rows
/// are spread across pages, and some pages hold no legacy rows at all. The
/// result is the same as reading every row at once.
#[tokio::test]
async fn a_migration_read_in_hash_order_counts_every_bucket_once() {
    let f = fixture().await;
    let now = now_epoch();
    history(&f, now).await;

    let m = StatsMaintenance::new(
        f.stats_ks.clone(),
        f.ts_ks.with_hash_ordered_pages(),
        f.dids_ks.clone(),
    )
    .with_page_rows(2);
    drive(m, &StatsCollector::new()).await;

    assert_eq!(resolves(&f.coarse("alice").await.unwrap()), 1 + 2 + 3);
    assert_eq!(resolves(&f.coarse("bob").await.unwrap()), 1);
    assert_eq!(resolves(&f.coarse("carol").await.unwrap()), 1 + 2 + 3 + 4);
    assert_eq!(resolves(&f.all().await), 15);
    assert!(f.marker().await.unwrap().completed_at.is_some());
}

/// A hash-ordered walk that fails part-way resumes from its cursor with
/// what it held so far, rather than reading from the start or waiting.
#[tokio::test]
async fn a_failed_hash_ordered_read_resumes_from_its_cursor() {
    let f = fixture().await;
    let now = now_epoch();
    history(&f, now).await;
    let collector = StatsCollector::new();
    // Reads: the marker, then one page; the next page fails.
    let mut m = StatsMaintenance::new(
        f.stats_ks.clone(),
        f.ts_ks
            .with_hash_ordered_pages()
            .failing_reads_after(2, AppError::store_throttled),
        f.dids_ks.clone(),
    )
    .with_page_rows(2);
    let (_tx, stop) = watch::channel(false);
    m.step(&collector, &budget(), stop.clone(), later())
        .await
        .unwrap();
    assert!(
        m.step(&collector, &budget(), stop.clone(), later())
            .await
            .is_err()
    );
    assert!(m.busy(), "still migrating");

    m.timeseries_ks = f.ts_ks.with_hash_ordered_pages();
    // The very next step reads on: no pause after a failed page.
    m.step(&collector, &budget(), stop.clone(), later())
        .await
        .unwrap();
    while m.busy() {
        m.step(&collector, &budget(), stop.clone(), later())
            .await
            .unwrap();
    }

    assert_eq!(resolves(&f.coarse("alice").await.unwrap()), 6);
    assert_eq!(resolves(&f.coarse("carol").await.unwrap()), 10);
    assert_eq!(resolves(&f.all().await), 15);
}

/// The purge deletes behind a hash-ordered cursor and still finds every row.
#[tokio::test]
async fn purge_now_in_hash_order_deletes_every_row() {
    let f = fixture().await;
    let now = now_epoch();
    history(&f, now).await;

    let deleted = StatsMaintenance::new(
        f.stats_ks.clone(),
        f.ts_ks.with_hash_ordered_pages(),
        f.dids_ks.clone(),
    )
    .with_page_rows(3)
    .purge_legacy_now(&StatsCollector::new(), &budget())
    .await
    .unwrap();

    assert_eq!(deleted, 10);
    assert!(f.ts_ks.prefix_iter_raw("ts:").await.unwrap().is_empty());
    assert_eq!(resolves(&f.all().await), 15);
}

/// Buckets older than any chart shows are not migrated (or held in memory
/// while reading), but are still deleted with the rest.
#[tokio::test]
async fn buckets_past_the_horizon_are_not_migrated_but_are_purged() {
    let f = fixture().await;
    let now = now_epoch();
    f.did("alice").await;
    f.legacy("alice", bucket_ago(now, HOUR_SECS), 2).await;
    f.legacy("alice", bucket_ago(now, LEGACY_HORIZON_SECS + DAY_SECS), 50)
        .await;
    f.did("old").await;
    f.legacy("old", bucket_ago(now, 90 * DAY_SECS), 7).await;

    let deleted = f
        .maintenance()
        .purge_legacy_now(&StatsCollector::new(), &budget())
        .await
        .unwrap();

    assert_eq!(resolves(&f.coarse("alice").await.unwrap()), 2);
    let alice_daily: u64 = f
        .coarse("alice")
        .await
        .unwrap()
        .daily()
        .map(|(_, r, _)| r)
        .sum();
    assert_eq!(
        alice_daily, 2,
        "the old bucket is not in the daily series either"
    );
    assert!(f.coarse("old").await.is_none(), "nothing recent to migrate");
    assert_eq!(deleted, 3, "every legacy row is deleted");
}

#[test]
fn legacy_keys_parse() {
    assert_eq!(parse_legacy_key(b"ts:alice:300"), Some(("alice", 300)));
    assert_eq!(parse_legacy_key(b"ts:a:b:600"), Some(("a:b", 600)));
    assert_eq!(parse_legacy_key(b"t5:alice:3"), None);
    assert_eq!(parse_legacy_key(b"ts:alice:x"), None);
}
