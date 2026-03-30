//! Prometheus metrics for WebVH services.
//!
//! Gated behind the `metrics` feature flag. When enabled, provides counters
//! for DID operations, auth events, cache performance, and stats sync.
//! Access via `GET /metrics` (unauthenticated).

use prometheus::{
    Encoder, IntCounter, Registry, TextEncoder,
};
use std::sync::LazyLock;

static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

static RESOLVES: LazyLock<IntCounter> = LazyLock::new(|| {
    let c = IntCounter::new("webvh_resolves_total", "Total DID resolutions").unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

static UPDATES: LazyLock<IntCounter> = LazyLock::new(|| {
    let c = IntCounter::new("webvh_updates_total", "Total DID updates/publishes").unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

static AUTH_CHALLENGES: LazyLock<IntCounter> = LazyLock::new(|| {
    let c = IntCounter::new("webvh_auth_challenges_total", "Total auth challenges issued").unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

static AUTH_SUCCESSES: LazyLock<IntCounter> = LazyLock::new(|| {
    let c = IntCounter::new("webvh_auth_successes_total", "Total successful authentications").unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

static AUTH_FAILURES: LazyLock<IntCounter> = LazyLock::new(|| {
    let c = IntCounter::new("webvh_auth_failures_total", "Total failed authentications").unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

static CACHE_HITS: LazyLock<IntCounter> = LazyLock::new(|| {
    let c = IntCounter::new("webvh_cache_hits_total", "Total cache hits").unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

static CACHE_MISSES: LazyLock<IntCounter> = LazyLock::new(|| {
    let c = IntCounter::new("webvh_cache_misses_total", "Total cache misses").unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

static STATS_SYNCS: LazyLock<IntCounter> = LazyLock::new(|| {
    let c = IntCounter::new("webvh_stats_syncs_total", "Total stats sync operations").unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Increment the DID resolve counter.
pub fn inc_resolve() {
    RESOLVES.inc();
}

/// Increment the DID update counter.
pub fn inc_update() {
    UPDATES.inc();
}

/// Increment the auth challenge counter.
pub fn inc_auth_challenge() {
    AUTH_CHALLENGES.inc();
}

/// Increment the auth success counter.
pub fn inc_auth_success() {
    AUTH_SUCCESSES.inc();
}

/// Increment the auth failure counter.
pub fn inc_auth_failure() {
    AUTH_FAILURES.inc();
}

/// Increment the cache hit counter.
pub fn inc_cache_hit() {
    CACHE_HITS.inc();
}

/// Increment the cache miss counter.
pub fn inc_cache_miss() {
    CACHE_MISSES.inc();
}

/// Increment the stats sync counter.
pub fn inc_stats_sync() {
    STATS_SYNCS.inc();
}

/// Render all metrics as Prometheus text format.
pub fn render() -> String {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap_or_default();
    String::from_utf8(buffer).unwrap_or_default()
}
