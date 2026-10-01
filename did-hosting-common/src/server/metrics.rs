//! Operational counters for DID Hosting services.
//!
//! Gated behind the `metrics` feature flag. When enabled, counts DID
//! operations, auth events, cache performance and stats syncs. They are read
//! through the admin-only `did-management/server/metrics/0.1` Trust Task
//! ([`counters`]); there is no unauthenticated scrape endpoint.

use std::sync::atomic::{AtomicU64, Ordering};

static RESOLVES: AtomicU64 = AtomicU64::new(0);
static UPDATES: AtomicU64 = AtomicU64::new(0);
static AUTH_CHALLENGES: AtomicU64 = AtomicU64::new(0);
static AUTH_SUCCESSES: AtomicU64 = AtomicU64::new(0);
static AUTH_FAILURES: AtomicU64 = AtomicU64::new(0);
static CACHE_HITS: AtomicU64 = AtomicU64::new(0);
static CACHE_MISSES: AtomicU64 = AtomicU64::new(0);
static STATS_SYNCS: AtomicU64 = AtomicU64::new(0);

/// Every counter, with the name it is reported under, sorted by name.
static COUNTERS: [(&str, &AtomicU64); 8] = [
    ("webvh_auth_challenges_total", &AUTH_CHALLENGES),
    ("webvh_auth_failures_total", &AUTH_FAILURES),
    ("webvh_auth_successes_total", &AUTH_SUCCESSES),
    ("webvh_cache_hits_total", &CACHE_HITS),
    ("webvh_cache_misses_total", &CACHE_MISSES),
    ("webvh_resolves_total", &RESOLVES),
    ("webvh_stats_syncs_total", &STATS_SYNCS),
    ("webvh_updates_total", &UPDATES),
];

fn inc(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// Increment the DID resolve counter.
pub fn inc_resolve() {
    inc(&RESOLVES);
}

/// Increment the DID update/publish counter.
pub fn inc_update() {
    inc(&UPDATES);
}

/// Increment the auth challenge counter.
pub fn inc_auth_challenge() {
    inc(&AUTH_CHALLENGES);
}

/// Increment the auth success counter.
pub fn inc_auth_success() {
    inc(&AUTH_SUCCESSES);
}

/// Increment the auth failure counter.
pub fn inc_auth_failure() {
    inc(&AUTH_FAILURES);
}

/// Increment the cache hit counter.
pub fn inc_cache_hit() {
    inc(&CACHE_HITS);
}

/// Increment the cache miss counter.
pub fn inc_cache_miss() {
    inc(&CACHE_MISSES);
}

/// Increment the stats sync counter.
pub fn inc_stats_sync() {
    inc(&STATS_SYNCS);
}

/// Every counter this service keeps, as `(name, value)`, sorted by name.
///
/// For the authenticated `did-management/server/metrics` Trust Task. The
/// names are the ones the retired Prometheus exposition carried, so a
/// dashboard re-points with a name mapping only.
pub fn counters() -> Vec<(String, f64)> {
    COUNTERS
        .iter()
        .map(|(name, c)| (name.to_string(), c.load(Ordering::Relaxed) as f64))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(name: &str) -> f64 {
        counters()
            .into_iter()
            .find(|(n, _)| n == name)
            .expect("counter exists")
            .1
    }

    #[test]
    fn counters_are_sorted_by_name_and_count() {
        let names: Vec<String> = counters().into_iter().map(|(n, _)| n).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);

        let before = value("webvh_stats_syncs_total");
        inc_stats_sync();
        assert!(value("webvh_stats_syncs_total") >= before + 1.0);
    }
}
