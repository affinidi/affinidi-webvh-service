//! Grace-period scheduling for domain unassignment purges (T30).
//!
//! When `MSG_DOMAIN_UNASSIGN` arrives, the server immediately stops
//! resolving the domain (the T21 safety check rejects on
//! disabled / missing) but does NOT delete the underlying DID
//! records right away. Operators may re-assign the same domain
//! within a grace window (default: 2h) — typical scenarios are a
//! brief migration between servers or an operator typo on the
//! control plane.
//!
//! This module stores **pending purge** entries in `KS_PENDING_PURGES`
//! per (domain) row. The background sweep — which lives in
//! `did-hosting-server` and runs on a 60s tick — consumes these
//! entries: any row whose `scheduled_at + grace_seconds < now()` is
//! ripe and triggers the actual DID-record purge.
//!
//! ## Storage shape
//!
//! - **Key**: `pending_purges:<domain>` — single-row-per-domain.
//!   Re-scheduling a domain (e.g. unassign → assign → unassign)
//!   overwrites the row and resets the timer.
//! - **Value**: [`PendingPurge`] — JSON-serialised.
//!
//! ## Why per-domain rather than per-(server, domain)?
//!
//! The keyspace const docstring mentions `pending_purges:<server>:<domain>`
//! but each running server only knows about itself — there is no
//! cross-server enumeration on this side of the protocol. The
//! per-(server, domain) shape only matters if a control plane
//! ever stores pending purges itself, which is a separate concern.
//! Keep the on-server schema flat.

use serde::{Deserialize, Serialize};

use super::error::AppError;
use super::store::{KS_PENDING_PURGES, Store};

/// One row in the per-server pending-purge queue.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingPurge {
    /// Normalised domain name (matches the
    /// [`super::assignment::AssignmentEntry`] form).
    pub domain: String,
    /// Epoch second the unassignment landed.
    pub scheduled_at: u64,
    /// How long after `scheduled_at` the purge becomes eligible.
    /// Sourced from `[hosting] unassigned_purge_grace` and parsed
    /// from its duration-string form on schedule.
    pub grace_seconds: u64,
    /// Why this purge was scheduled. The two production reasons are
    /// `"grace-expired"` (sweep) and `"admin-immediate"` (admin
    /// Purge Now). Stored here so the sweep can audit-log the same
    /// reason it inherited on scheduling.
    pub reason: String,
    /// The DID that issued the unassignment (control plane DID in
    /// the standard flow). Stored for audit-log clarity.
    pub scheduled_by: String,
}

fn pending_key(domain: &str) -> String {
    format!("pending_purges:{domain}")
}

/// Outcome of [`schedule`]. The caller may audit-log differently on
/// `Replaced` vs `Created` — both are valid, but `Replaced` means a
/// previously-scheduled purge had its timer reset.
#[derive(Debug, PartialEq, Eq)]
pub enum ScheduleOutcome {
    Created(PendingPurge),
    Replaced {
        previous: PendingPurge,
        new: PendingPurge,
    },
}

/// Outcome of [`cancel`]. `Removed` is the common case during the
/// "operator re-assigned during grace" flow; `Missing` is a quiet
/// no-op for assignments that never had a pending purge.
#[derive(Debug, PartialEq, Eq)]
pub enum CancelOutcome {
    Removed(PendingPurge),
    Missing,
}

/// Schedule a pending purge. Overwrites any prior entry for the same
/// domain (resetting the timer), so the caller doesn't need to
/// cancel-then-schedule.
pub async fn schedule(
    store: &Store,
    domain: &str,
    scheduled_at: u64,
    grace_seconds: u64,
    reason: &str,
    scheduled_by: &str,
) -> Result<ScheduleOutcome, AppError> {
    let ks = store.keyspace(KS_PENDING_PURGES)?;
    let key = pending_key(domain);

    let new = PendingPurge {
        domain: domain.to_string(),
        scheduled_at,
        grace_seconds,
        reason: reason.to_string(),
        scheduled_by: scheduled_by.to_string(),
    };

    let outcome = match ks.get::<PendingPurge>(key.clone()).await? {
        Some(previous) => ScheduleOutcome::Replaced {
            previous,
            new: new.clone(),
        },
        None => ScheduleOutcome::Created(new.clone()),
    };
    ks.insert(key, &new).await?;
    Ok(outcome)
}

/// Cancel a pending purge — typically called when a domain is re-
/// assigned within the grace window.
pub async fn cancel(store: &Store, domain: &str) -> Result<CancelOutcome, AppError> {
    let ks = store.keyspace(KS_PENDING_PURGES)?;
    let key = pending_key(domain);

    let Some(existing) = ks.get::<PendingPurge>(key.clone()).await? else {
        return Ok(CancelOutcome::Missing);
    };
    ks.remove(key).await?;
    Ok(CancelOutcome::Removed(existing))
}

/// Look up a single pending purge.
pub async fn get(store: &Store, domain: &str) -> Result<Option<PendingPurge>, AppError> {
    let ks = store.keyspace(KS_PENDING_PURGES)?;
    ks.get(pending_key(domain)).await
}

/// Enumerate every pending purge. Used by the sweep to decide which
/// rows are ripe.
pub async fn list(store: &Store) -> Result<Vec<PendingPurge>, AppError> {
    let ks = store.keyspace(KS_PENDING_PURGES)?;
    let raw = ks.prefix_iter_raw(b"pending_purges:".to_vec()).await?;
    let mut out = Vec::with_capacity(raw.len());
    for (_k, v) in raw {
        if let Ok(p) = serde_json::from_slice::<PendingPurge>(&v) {
            out.push(p);
        }
    }
    Ok(out)
}

impl PendingPurge {
    /// `true` when the purge's grace window has elapsed by `now_epoch`.
    pub fn is_ripe(&self, now_epoch: u64) -> bool {
        self.scheduled_at.saturating_add(self.grace_seconds) <= now_epoch
    }
}

/// Parse a duration string like `"2h"`, `"30m"`, `"7d"`, `"45s"` into
/// seconds. Accepts integers + a single suffix unit. Lenient on
/// case (`"2H"` works). Returns `Err` for malformed input.
///
/// Why a custom parser rather than e.g. `humantime`: the project
/// already has zero parsing-helper dependencies in `did-hosting-
/// common`, and the surface area we need is a single integer +
/// unit. The `humantime` crate would add ~50KB of compiled code
/// and another transitive crate just to read 4 unit suffixes.
pub fn parse_grace_string(s: &str) -> Result<u64, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("empty duration".into());
    }
    let (digits, unit_idx) = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .map(|i| (&trimmed[..i], i))
        .unwrap_or((trimmed, trimmed.len()));
    if digits.is_empty() {
        return Err(format!("missing leading digits in '{s}'"));
    }
    let n: u64 = digits
        .parse()
        .map_err(|e| format!("invalid digits '{digits}': {e}"))?;
    let unit = trimmed[unit_idx..].trim().to_ascii_lowercase();
    let multiplier: u64 = match unit.as_str() {
        "" | "s" | "sec" | "secs" | "second" | "seconds" => 1,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => 60 * 60,
        "d" | "day" | "days" => 24 * 60 * 60,
        other => {
            return Err(format!("unsupported unit '{other}'; use s / m / h / d"));
        }
    };
    n.checked_mul(multiplier)
        .ok_or_else(|| format!("duration '{s}' overflows u64 seconds"))
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
    async fn schedule_then_get() {
        let store = fjall_store().await;
        let outcome = schedule(&store, "a.example", 100, 60, "grace-expired", "did:c")
            .await
            .unwrap();
        assert!(matches!(outcome, ScheduleOutcome::Created(_)));

        let fetched = get(&store, "a.example").await.unwrap().unwrap();
        assert_eq!(fetched.domain, "a.example");
        assert_eq!(fetched.scheduled_at, 100);
        assert_eq!(fetched.grace_seconds, 60);
        assert_eq!(fetched.reason, "grace-expired");
    }

    #[tokio::test]
    async fn schedule_replaces_existing_and_resets_timer() {
        let store = fjall_store().await;
        schedule(&store, "a.example", 100, 60, "first", "did:c")
            .await
            .unwrap();
        let outcome = schedule(&store, "a.example", 500, 120, "second", "did:c2")
            .await
            .unwrap();
        let ScheduleOutcome::Replaced { previous, new } = outcome else {
            panic!("expected Replaced");
        };
        assert_eq!(previous.scheduled_at, 100);
        assert_eq!(new.scheduled_at, 500);
        assert_eq!(new.grace_seconds, 120);
    }

    #[tokio::test]
    async fn cancel_removes_existing() {
        let store = fjall_store().await;
        schedule(&store, "a.example", 1, 60, "x", "y")
            .await
            .unwrap();
        let outcome = cancel(&store, "a.example").await.unwrap();
        let CancelOutcome::Removed(_) = outcome else {
            panic!("expected Removed");
        };
        assert!(get(&store, "a.example").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn cancel_missing_is_no_op() {
        let store = fjall_store().await;
        let outcome = cancel(&store, "absent.example").await.unwrap();
        assert_eq!(outcome, CancelOutcome::Missing);
    }

    #[tokio::test]
    async fn list_yields_every_pending() {
        let store = fjall_store().await;
        schedule(&store, "a.example", 1, 1, "x", "y").await.unwrap();
        schedule(&store, "b.example", 1, 1, "x", "y").await.unwrap();
        schedule(&store, "c.example", 1, 1, "x", "y").await.unwrap();
        let mut names: Vec<String> = list(&store)
            .await
            .unwrap()
            .into_iter()
            .map(|p| p.domain)
            .collect();
        names.sort();
        assert_eq!(names, vec!["a.example", "b.example", "c.example"]);
    }

    #[test]
    fn ripeness_check() {
        let p = PendingPurge {
            domain: "x".into(),
            scheduled_at: 100,
            grace_seconds: 60,
            reason: "x".into(),
            scheduled_by: "y".into(),
        };
        assert!(!p.is_ripe(100));
        assert!(!p.is_ripe(159));
        assert!(p.is_ripe(160));
        assert!(p.is_ripe(u64::MAX));
    }

    #[test]
    fn parse_grace_string_known_units() {
        assert_eq!(parse_grace_string("30s").unwrap(), 30);
        assert_eq!(parse_grace_string("45").unwrap(), 45); // bare seconds
        assert_eq!(parse_grace_string("5m").unwrap(), 300);
        assert_eq!(parse_grace_string("2h").unwrap(), 7200);
        assert_eq!(parse_grace_string("1d").unwrap(), 86_400);
        assert_eq!(parse_grace_string("  2H ").unwrap(), 7200); // case + trim
    }

    #[test]
    fn parse_grace_string_rejects_garbage() {
        assert!(parse_grace_string("").is_err());
        assert!(parse_grace_string("h").is_err()); // no digits
        assert!(parse_grace_string("10x").is_err()); // unknown unit
        assert!(parse_grace_string("abc").is_err());
    }
}
