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

fn budget() -> StatsFlushConfig {
    StatsFlushConfig {
        max_rows_per_second: 10_000,
    }
}

/// Step a fresh maintenance run until it has nothing in hand.
async fn run(f: &Fixture, collector: &StatsCollector) -> StatsMaintenance {
    let mut m = f.maintenance();
    let (_tx, stop) = watch::channel(false);
    m.step(collector, &budget(), stop.clone()).await.unwrap();
    while m.busy() {
        m.step(collector, &budget(), stop.clone()).await.unwrap();
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

#[test]
fn legacy_keys_parse() {
    assert_eq!(parse_legacy_key(b"ts:alice:300"), Some(("alice", 300)));
    assert_eq!(parse_legacy_key(b"ts:a:b:600"), Some(("a:b", 600)));
    assert_eq!(parse_legacy_key(b"t5:alice:3"), None);
    assert_eq!(parse_legacy_key(b"ts:alice:x"), None);
}
