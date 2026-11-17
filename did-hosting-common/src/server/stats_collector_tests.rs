//! Tests for [`super`].

use super::*;

#[test]
fn requeued_deltas_merge_with_new_events() {
    let collector = StatsCollector::new();
    collector.record_resolve("alice");
    let drained = collector.drain_for_sync();
    collector.record_resolve("alice");

    collector.requeue_deltas(drained);

    let deltas = collector.drain_for_sync();
    assert_eq!(deltas.len(), 1);
    assert_eq!(deltas[0].resolve_delta, 2);
    assert_eq!(
        collector.get_aggregate().total_resolves,
        2,
        "requeueing must not count the events again"
    );
}

#[test]
fn requeue_stops_taking_new_dids_at_the_cap() {
    let collector = StatsCollector::new();
    let delta = |m: String| DidStatsDelta {
        mnemonic: m,
        resolve_delta: 1,
        update_delta: 0,
        last_resolved_at: None,
        last_updated_at: None,
    };
    let full: Vec<_> = (0..MAX_PENDING_DIDS)
        .map(|i| delta(format!("did-{i}")))
        .collect();
    assert_eq!(collector.requeue_deltas(full), 0);

    let dropped = collector.requeue_deltas(vec![delta("new".into()), delta("did-0".into())]);

    assert_eq!(
        dropped, 1,
        "a new DID is dropped, a pending one still merges"
    );
    let deltas = collector.drain_for_sync();
    assert_eq!(deltas.len(), MAX_PENDING_DIDS);
    let did_0 = deltas.iter().find(|d| d.mnemonic == "did-0");
    assert_eq!(did_0.map(|d| d.resolve_delta), Some(2));
}

#[test]
fn requeued_buckets_merge_with_new_events() {
    let collector = StatsCollector::new();
    collector.record_update("alice");
    let drained = collector.drain_buckets();
    collector.record_update("alice");

    collector.requeue_buckets(drained);

    let mut buckets = collector.drain_buckets();
    buckets.sort_by(|a, b| a.mnemonic.cmp(&b.mnemonic));
    let counts: Vec<_> = buckets
        .iter()
        .map(|b| (b.mnemonic.as_str(), b.updates))
        .collect();
    assert_eq!(counts, [("_all", 2), ("alice", 2)]);
    assert!(
        collector.drain_buckets().is_empty(),
        "a drain empties the map"
    );
}

/// New events past the cap are dropped from the per-DID rows, not just
/// requeued ones; the aggregate and the server-wide series still count
/// them.
#[test]
fn recording_stops_taking_new_dids_at_the_cap() {
    let collector = StatsCollector::new();
    for i in 0..MAX_PENDING_DIDS {
        collector.record_deltas(&format!("did-{i}"), 1, 0, None, None);
    }
    collector.record_deltas("over", 1, 0, None, None);
    collector.record_deltas("did-0", 1, 0, None, None);

    let deltas = collector.drain_for_sync();
    assert_eq!(deltas.len(), MAX_PENDING_DIDS);
    assert!(deltas.iter().all(|d| d.mnemonic != "over"));
    assert_eq!(
        collector.get_aggregate().total_resolves,
        MAX_PENDING_DIDS as u64 + 2
    );
    let all: u64 = collector
        .drain_buckets()
        .iter()
        .filter(|b| b.mnemonic == ALL_SERIES)
        .map(|b| b.resolves)
        .sum();
    assert_eq!(all, MAX_PENDING_DIDS as u64 + 2);
    assert_eq!(collector.take_dropped(0), Some(1));
}

#[test]
fn bucket_cap_drops_new_did_buckets_but_not_the_server_wide_series() {
    let collector = StatsCollector::new();
    let bucket = |m: &str, epoch: u64| DrainedBucket {
        mnemonic: m.into(),
        epoch,
        resolves: 1,
        updates: 0,
    };
    collector.requeue_buckets(
        (0..MAX_PENDING_BUCKETS as u64)
            .map(|i| bucket("did", i * BUCKET_SECS))
            .collect(),
    );
    collector.requeue_buckets(vec![bucket("other", 0), bucket(ALL_SERIES, 0)]);

    let drained = collector.drain_buckets();
    assert_eq!(drained.len(), MAX_PENDING_BUCKETS + 1);
    assert!(drained.iter().all(|b| b.mnemonic != "other"));
    assert!(drained.iter().any(|b| b.mnemonic == ALL_SERIES));
}

#[test]
fn dropped_rows_are_reported_at_most_once_per_period() {
    let collector = StatsCollector::new();
    collector.dropped.store(3, Ordering::Relaxed);
    assert_eq!(collector.take_dropped(3600), Some(3));
    collector.dropped.store(2, Ordering::Relaxed);
    assert_eq!(collector.take_dropped(3600), None, "within the period");
    assert_eq!(collector.take_dropped(0), Some(2));
    assert_eq!(collector.take_dropped(0), None, "nothing new to report");
}

#[test]
fn an_edge_collector_keeps_no_timeseries() {
    let collector = StatsCollector::without_timeseries();
    collector.record_resolve("alice");
    collector.record_update("alice");
    assert!(collector.drain_buckets().is_empty());
    assert_eq!(collector.drain_for_sync().len(), 1);
}

/// Synced deltas are filed under the edge's latest event time, unless
/// that time is implausible.
#[test]
fn synced_deltas_are_bucketed_by_event_time() {
    let collector = StatsCollector::new();
    let now = now_epoch();
    let earlier = now - 2 * BUCKET_SECS;
    collector.record_deltas("alice", 2, 1, Some(earlier), Some(now + 3600));

    let mut buckets: Vec<_> = collector
        .drain_buckets()
        .into_iter()
        .filter(|b| b.mnemonic == "alice")
        .map(|b| (b.epoch, b.resolves, b.updates))
        .collect();
    buckets.sort();
    assert_eq!(
        buckets,
        [
            (bucket_epoch(earlier), 2, 0),
            (bucket_epoch(now), 0, 1), // a future time is filed now
        ]
    );
}

/// Only closed buckets, and the DIDs they belong to, are due; a DID
/// whose only activity is in the open bucket waits for it to close.
#[test]
fn drain_due_takes_closed_buckets_and_their_dids() {
    let collector = StatsCollector::new();
    let now = 1_000 * BUCKET_SECS + 7;
    let open = now / BUCKET_SECS * BUCKET_SECS;
    let delta = |m: &str| DidStatsDelta {
        mnemonic: m.into(),
        resolve_delta: 1,
        update_delta: 0,
        last_resolved_at: None,
        last_updated_at: None,
    };
    let bucket = |m: &str, epoch| DrainedBucket {
        mnemonic: m.into(),
        epoch,
        resolves: 1,
        updates: 0,
    };
    collector.requeue_deltas(vec![delta("old"), delta("new")]);
    collector.requeue_buckets(vec![bucket("old", open - BUCKET_SECS), bucket("new", open)]);

    let (deltas, buckets) = collector.drain_due(now);
    let due: Vec<_> = deltas.iter().map(|d| d.mnemonic.as_str()).collect();
    let closed: Vec<_> = buckets
        .iter()
        .map(|b| (b.mnemonic.as_str(), b.epoch))
        .collect();
    assert_eq!(due, ["old"]);
    assert_eq!(closed, [("old", open - BUCKET_SECS)]);

    let (deltas, buckets) = collector.drain_due(open + BUCKET_SECS);
    assert_eq!(deltas.len(), 1, "`new` once its bucket closes");
    assert_eq!(buckets.len(), 1);
    assert_eq!(collector.pending_rows(), 0);
}

#[test]
fn a_delta_without_a_bucket_is_due_at_once() {
    let collector = StatsCollector::without_timeseries();
    collector.record_resolve("alice");
    let (deltas, buckets) = collector.drain_due(now_epoch());
    assert_eq!(deltas.len(), 1);
    assert!(buckets.is_empty());
}

#[test]
fn pending_counts_are_visible_before_the_flush() {
    let collector = StatsCollector::new();
    collector.record_resolve("alice");
    collector.record_resolve("alice");
    assert_eq!(
        collector.pending_for("alice").map(|d| d.resolve_delta),
        Some(2)
    );
    assert!(collector.pending_for("bob").is_none());
}

#[test]
fn retried_slots_merge_and_count_as_pending() {
    let collector = StatsCollector::new();
    let b = |r| DrainedBucket {
        mnemonic: "a".into(),
        epoch: 300,
        resolves: r,
        updates: 0,
    };
    collector.requeue_slots(vec![b(1), b(2)]);
    assert_eq!(collector.pending_rows(), 1);
    let slots = collector.drain_slot_retry();
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0].resolves, 3);
}

#[test]
fn decrement_total_dids_stops_at_zero() {
    let collector = StatsCollector::new();
    collector.increment_total_dids();
    collector.decrement_total_dids();
    collector.decrement_total_dids();
    assert_eq!(collector.get_aggregate().total_dids, 0);
}

#[test]
fn subtract_total_dids_stops_at_zero() {
    let collector = StatsCollector::new();
    collector.set_total_dids(5);
    collector.subtract_total_dids(3);
    assert_eq!(collector.get_aggregate().total_dids, 2);
    collector.subtract_total_dids(10);
    assert_eq!(collector.get_aggregate().total_dids, 0);
}
