//! A warning that a request can trigger, written at most once per interval.
//!
//! Some conditions are worth an operator's attention but are reported from a
//! per-request path: a peer outside the trusted proxies sending
//! `X-Forwarded-Host`, or resolution with no domain configured. Logging each
//! occurrence at `warn` lets any client fill the log. [`WarnLimit`] lets the
//! first occurrence in each interval through at `warn` with a count of those
//! held back since; the caller logs the rest at `debug`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Interval for the per-request warnings in this crate.
pub const DEFAULT_INTERVAL_SECS: u64 = 60;

/// Admits one warning per interval. A `static` per call site.
#[derive(Debug)]
pub struct WarnLimit {
    interval_secs: u64,
    /// Unix seconds of the last admitted warning, `0` before the first.
    last: AtomicU64,
    /// Warnings held back since the last admitted one.
    held: AtomicU64,
}

impl WarnLimit {
    pub const fn new(interval_secs: u64) -> Self {
        Self {
            interval_secs,
            last: AtomicU64::new(0),
            held: AtomicU64::new(0),
        }
    }

    /// `Some(held)` when this occurrence should be logged at `warn`, with the
    /// number held back since the previous one; `None` when it should be
    /// logged at `debug` instead.
    pub fn admit(&self) -> Option<u64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.admit_at(now)
    }

    fn admit_at(&self, now: u64) -> Option<u64> {
        let last = self.last.load(Ordering::Relaxed);
        if last != 0 && now < last.saturating_add(self.interval_secs) {
            self.held.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        // One caller wins the interval; a concurrent one is held back.
        if self
            .last
            .compare_exchange(last, now.max(1), Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            self.held.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        Some(self.held.swap(0, Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_warning_per_interval_with_a_count_of_the_rest() {
        let limit = WarnLimit::new(60);
        assert_eq!(limit.admit_at(1_000), Some(0));
        assert_eq!(limit.admit_at(1_001), None);
        assert_eq!(limit.admit_at(1_059), None);
        assert_eq!(limit.admit_at(1_060), Some(2));
        assert_eq!(limit.admit_at(1_061), None);
    }
}
