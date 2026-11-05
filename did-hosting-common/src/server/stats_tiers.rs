//! Tiered, round-robin statistics.
//!
//! Every DID keeps a **coarse** series inside its `stats:{mnemonic}` row: an
//! hourly window of [`DID_HOURS`] and a daily window of [`DID_DAYS`], pruned on
//! every write so nothing ever needs a sweep. A busy DID (or one an admin pins)
//! also keeps a **fine** series: a ring of [`FINE_SLOTS`] 5-minute rows,
//! `t5:{mnemonic}:{slot}`, each overwritten when the ring comes round again.
//! The server-wide series (`_all`) is always fine, and keeps its coarse series
//! at [`ALL_COARSE_KEY`] with a 30-day hourly window.
//!
//! Which tier a DID is in is decided by [`TierState::observe`] each time its
//! row is written: promotion on the last hour's resolves, demotion on the last
//! 24 hours' average, a cap on how many DIDs are promoted automatically, and a
//! per-DID override ([`StatsResolution`]) stored at `statspin:{mnemonic}`.
//!
//! See `docs/stats-tiers.md`.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::DidStats;
use crate::server::error::AppError;

/// Width of a fine bucket, and of the buckets the collector keeps.
pub const BUCKET_SECS: u64 = 300;
/// Slots in a fine ring: 24 hours of 5-minute buckets.
pub const FINE_SLOTS: u64 = 288;
pub const HOUR_SECS: u64 = 3600;
pub const DAY_SECS: u64 = 86_400;
/// Hourly points a DID's coarse series keeps (7 days).
pub const DID_HOURS: u64 = 168;
/// Daily points a DID's coarse series keeps (30 days).
pub const DID_DAYS: u64 = 30;
/// Hourly points the server-wide coarse series keeps (30 days): it is one
/// row, so it can afford the 30-day chart at 4-hour resolution.
pub const ALL_HOURS: u64 = 720;

/// Key, in the time-series keyspace, of the server-wide coarse series.
pub const ALL_COARSE_KEY: &str = "c:_all";
/// Key, in the time-series keyspace, of the migration marker.
pub const MIGRATION_MARKER_KEY: &str = "meta:stats-migration";

/// `stats:{mnemonic}`, in the stats keyspace.
pub fn stats_key(mnemonic: &str) -> String {
    format!("stats:{mnemonic}")
}

/// `statspin:{mnemonic}`, in the stats keyspace: a DID's override, present
/// only when it is not [`StatsResolution::Auto`].
pub fn pin_key(mnemonic: &str) -> String {
    format!("statspin:{mnemonic}")
}

/// Prefix of every override row.
pub const PIN_PREFIX: &str = "statspin:";

/// The fine-ring slot for a bucket starting at `epoch`.
pub fn fine_slot(epoch: u64) -> u64 {
    (epoch / BUCKET_SECS) % FINE_SLOTS
}

/// `t5:{mnemonic}:{slot}`, in the time-series keyspace. A new prefix, so a
/// fine row can never be mistaken for a legacy `ts:{mnemonic}:{epoch}` row.
pub fn fine_key(mnemonic: &str, epoch: u64) -> String {
    format!("t5:{mnemonic}:{}", fine_slot(epoch))
}

/// One fine-ring slot: the bucket it holds now, and its counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FineSlot {
    /// Start of the bucket this slot holds.
    pub e: u64,
    pub r: u64,
    pub u: u64,
}

impl FineSlot {
    /// Add a bucket's counts to this slot: added to the bucket it holds, or
    /// replacing an older bucket the ring has come round to. A bucket older
    /// than the one held is a late arrival the ring has already overwritten:
    /// `None`, nothing to write.
    pub fn add(self, epoch: u64, r: u64, u: u64) -> Option<FineSlot> {
        match epoch.cmp(&self.e) {
            std::cmp::Ordering::Equal => Some(FineSlot {
                e: epoch,
                r: self.r + r,
                u: self.u + u,
            }),
            std::cmp::Ordering::Greater => Some(FineSlot { e: epoch, r, u }),
            std::cmp::Ordering::Less if self.e == 0 => Some(FineSlot { e: epoch, r, u }),
            std::cmp::Ordering::Less => None,
        }
    }
}

/// Which windows a coarse series keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeriesKind {
    /// A DID: 7 days hourly, 30 days daily.
    Did,
    /// The server-wide series: 30 days hourly, 30 days daily.
    All,
}

impl SeriesKind {
    pub fn hours(self) -> u64 {
        match self {
            Self::Did => DID_HOURS,
            Self::All => ALL_HOURS,
        }
    }
}

/// A coarse series: sparse hourly and daily points, each `[index, resolves,
/// updates]` where index is the hour (or day) since the Unix epoch, oldest
/// first. Sparse because most DIDs are quiet: a DID resolved in three hours
/// of the week stores three points, not 168 zeros.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CoarseSeries {
    #[serde(default, rename = "h", skip_serializing_if = "Vec::is_empty")]
    pub hours: Vec<[u64; 3]>,
    #[serde(default, rename = "d", skip_serializing_if = "Vec::is_empty")]
    pub days: Vec<[u64; 3]>,
    /// When this series started keeping 5-minute detail; `None` while it is
    /// coarse. A reader uses the fine ring only for a window that starts at
    /// or after this, so a newly promoted DID's chart has no gap.
    #[serde(default, rename = "fs", skip_serializing_if = "Option::is_none")]
    pub fine_since: Option<u64>,
    /// Legacy `ts:` buckets starting before this have been merged in (see
    /// the migration). Absent until a migration has touched this series.
    #[serde(default, rename = "mt", skip_serializing_if = "Option::is_none")]
    pub migrated_through: Option<u64>,
}

fn add_point(points: &mut Vec<[u64; 3]>, idx: u64, r: u64, u: u64, window: u64) {
    match points.binary_search_by_key(&idx, |p| p[0]) {
        Ok(i) => {
            points[i][1] += r;
            points[i][2] += u;
        }
        Err(i) => {
            let newest = points.last().map_or(idx, |p| p[0].max(idx));
            if idx + window <= newest {
                return; // older than the window: the ring has passed it
            }
            points.insert(i, [idx, r, u]);
        }
    }
    let newest = points.last().map_or(0, |p| p[0]);
    let keep_from = (newest + 1).saturating_sub(window);
    let stale = points.partition_point(|p| p[0] < keep_from);
    points.drain(..stale);
}

fn sum_between(points: &[[u64; 3]], from: u64, to: u64) -> (u64, u64) {
    points
        .iter()
        .filter(|p| p[0] >= from && p[0] < to)
        .fold((0, 0), |(r, u), p| (r + p[1], u + p[2]))
}

impl CoarseSeries {
    /// Add a bucket's counts at `epoch` to the hourly and daily windows.
    pub fn add(&mut self, kind: SeriesKind, epoch: u64, r: u64, u: u64) {
        if r == 0 && u == 0 {
            return;
        }
        add_point(&mut self.hours, epoch / HOUR_SECS, r, u, kind.hours());
        add_point(&mut self.days, epoch / DAY_SECS, r, u, DID_DAYS);
    }

    /// Resolves in the hour holding `now`, or the hour before if that was
    /// busier: the current hour is still filling.
    pub fn recent_hour_resolves(&self, now: u64) -> u64 {
        let h = now / HOUR_SECS;
        let (cur, _) = sum_between(&self.hours, h, h + 1);
        let (prev, _) = sum_between(&self.hours, h.saturating_sub(1), h);
        cur.max(prev)
    }

    /// Average resolves per hour over the 24 hours before `now`.
    pub fn day_average_resolves(&self, now: u64) -> u64 {
        let h = now / HOUR_SECS;
        let (r, _) = sum_between(&self.hours, h.saturating_sub(23), h + 1);
        r / 24
    }

    /// Hourly `(start epoch, resolves, updates)` points, oldest first.
    pub fn hourly(&self) -> impl Iterator<Item = (u64, u64, u64)> + '_ {
        self.hours.iter().map(|p| (p[0] * HOUR_SECS, p[1], p[2]))
    }

    /// Daily `(start epoch, resolves, updates)` points.
    pub fn daily(&self) -> impl Iterator<Item = (u64, u64, u64)> + '_ {
        self.days.iter().map(|p| (p[0] * DAY_SECS, p[1], p[2]))
    }
}

/// A `stats:{mnemonic}` row: the totals every reader already knows
/// ([`DidStats`]) plus the coarse series. Readers that deserialize only
/// [`DidStats`] ignore `coarse`, so this is compatible both ways.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoredDidStats {
    #[serde(flatten)]
    pub totals: DidStats,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coarse: Option<CoarseSeries>,
}

/// A DID's statistics override.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StatsResolution {
    /// Promoted and demoted by traffic, under `[stats]`.
    #[default]
    Auto,
    /// Always 5-minute detail. Admin only: it costs writes and bypasses the
    /// cap.
    Fine,
    /// Never promoted.
    Coarse,
    /// Totals only, no series.
    Off,
}

impl StatsResolution {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Fine => "fine",
            Self::Coarse => "coarse",
            Self::Off => "off",
        }
    }
}

impl std::str::FromStr for StatsResolution {
    type Err = AppError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auto" => Ok(Self::Auto),
            "fine" => Ok(Self::Fine),
            "coarse" => Ok(Self::Coarse),
            "off" => Ok(Self::Off),
            other => Err(AppError::Validation(format!(
                "unknown stats resolution `{other}` (auto, fine, coarse, off)"
            ))),
        }
    }
}

/// The deployment-wide policy (`[stats] mode`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StatsMode {
    /// Busy DIDs get 5-minute detail, by `promote_per_hour` and
    /// `demote_per_hour`, up to `max_fine_dids`.
    #[default]
    Auto,
    /// Every DID gets 5-minute detail (no cap).
    Fine,
    /// No DID does, unless pinned.
    Coarse,
}

/// Largest `max_fine_dids` accepted.
pub const MAX_FINE_DIDS_LIMIT: u32 = 1_000_000;

/// `[stats]`: how DIDs are tiered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatsTierConfig {
    #[serde(default)]
    pub mode: StatsMode,
    /// Promote a DID once an hour holds at least this many resolves.
    #[serde(default = "default_promote")]
    pub promote_per_hour: u32,
    /// Demote it once its last 24 hours average below this many an hour.
    #[serde(default = "default_demote")]
    pub demote_per_hour: u32,
    /// Most DIDs promoted automatically. Pinned DIDs are not counted.
    #[serde(default = "default_max_fine")]
    pub max_fine_dids: u32,
}

fn default_promote() -> u32 {
    60
}
fn default_demote() -> u32 {
    20
}
fn default_max_fine() -> u32 {
    1000
}

impl Default for StatsTierConfig {
    fn default() -> Self {
        Self {
            mode: StatsMode::Auto,
            promote_per_hour: default_promote(),
            demote_per_hour: default_demote(),
            max_fine_dids: default_max_fine(),
        }
    }
}

impl StatsTierConfig {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// Thresholds must leave a gap (demotion strictly below promotion), or
    /// a DID at the threshold would flip every write.
    pub fn validate(&self) -> Result<(), AppError> {
        if self.promote_per_hour == 0 {
            return Err(AppError::Config(
                "stats.promote_per_hour must be at least 1".into(),
            ));
        }
        if self.demote_per_hour >= self.promote_per_hour {
            return Err(AppError::Config(format!(
                "stats.demote_per_hour ({}) must be below stats.promote_per_hour ({})",
                self.demote_per_hour, self.promote_per_hour
            )));
        }
        if self.max_fine_dids > MAX_FINE_DIDS_LIMIT {
            return Err(AppError::Config(format!(
                "stats.max_fine_dids ({}) must be at most {MAX_FINE_DIDS_LIMIT}",
                self.max_fine_dids
            )));
        }
        Ok(())
    }

    /// Apply `{prefix}_STATS_MODE`, `{prefix}_STATS_PROMOTE_PER_HOUR`,
    /// `{prefix}_STATS_DEMOTE_PER_HOUR` and `{prefix}_STATS_MAX_FINE_DIDS`,
    /// then validate.
    pub fn apply_env_overrides(&mut self, prefix: &str) -> Result<(), AppError> {
        fn num(var: &str) -> Result<Option<u32>, AppError> {
            match std::env::var(var) {
                Ok(v) => v
                    .trim()
                    .parse()
                    .map(Some)
                    .map_err(|e| AppError::Config(format!("invalid {var}: {e}"))),
                Err(_) => Ok(None),
            }
        }
        let mode_var = format!("{prefix}_STATS_MODE");
        if let Ok(v) = std::env::var(&mode_var) {
            self.mode = match v.trim() {
                "auto" => StatsMode::Auto,
                "fine" => StatsMode::Fine,
                "coarse" => StatsMode::Coarse,
                other => {
                    return Err(AppError::Config(format!(
                        "invalid {mode_var}: `{other}` (auto, fine, coarse)"
                    )));
                }
            };
        }
        if let Some(v) = num(&format!("{prefix}_STATS_PROMOTE_PER_HOUR"))? {
            self.promote_per_hour = v;
        }
        if let Some(v) = num(&format!("{prefix}_STATS_DEMOTE_PER_HOUR"))? {
            self.demote_per_hour = v;
        }
        if let Some(v) = num(&format!("{prefix}_STATS_MAX_FINE_DIDS"))? {
            self.max_fine_dids = v;
        }
        self.validate()
    }
}

/// A DID's effective tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Totals only.
    Off,
    Coarse,
    /// Coarse plus the 5-minute ring.
    Fine,
}

/// Why a DID is in its tier, for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierReason {
    /// The per-DID override.
    Pinned,
    /// `[stats] mode` is `fine` or `coarse`.
    Mode,
    /// Promoted or demoted by traffic.
    Traffic,
}

/// Tiering state the flush consults: the policy, the overrides, and which
/// DIDs are promoted automatically.
#[derive(Debug, Default)]
pub struct TierState {
    pub config: StatsTierConfig,
    /// Overrides other than `Auto`.
    pins: HashMap<String, StatsResolution>,
    /// DIDs promoted by traffic, counted against `max_fine_dids`.
    promoted: HashSet<String>,
}

impl TierState {
    pub fn new(config: StatsTierConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    pub fn pin(&self, mnemonic: &str) -> StatsResolution {
        self.pins.get(mnemonic).copied().unwrap_or_default()
    }

    pub fn set_pin(&mut self, mnemonic: &str, pin: StatsResolution) {
        if pin == StatsResolution::Auto {
            self.pins.remove(mnemonic);
        } else {
            self.pins.insert(mnemonic.to_string(), pin);
            // A pinned DID no longer takes an automatic place.
            self.promoted.remove(mnemonic);
        }
    }

    /// Replace every override at once (startup).
    pub fn load_pins(&mut self, pins: impl IntoIterator<Item = (String, StatsResolution)>) {
        self.pins = pins
            .into_iter()
            .filter(|(_, p)| *p != StatsResolution::Auto)
            .collect();
        let pins = &self.pins;
        self.promoted.retain(|m| !pins.contains_key(m));
    }

    /// Forget a deleted DID.
    pub fn forget(&mut self, mnemonic: &str) {
        self.pins.remove(mnemonic);
        self.promoted.remove(mnemonic);
    }

    pub fn promoted_count(&self) -> usize {
        self.promoted.len()
    }

    /// The tier a DID is in, as last observed, and why.
    pub fn tier_of(&self, mnemonic: &str, series: Option<&CoarseSeries>) -> (Tier, TierReason) {
        match self.pin(mnemonic) {
            StatsResolution::Fine => return (Tier::Fine, TierReason::Pinned),
            StatsResolution::Coarse => return (Tier::Coarse, TierReason::Pinned),
            StatsResolution::Off => return (Tier::Off, TierReason::Pinned),
            StatsResolution::Auto => {}
        }
        match self.config.mode {
            StatsMode::Fine => (Tier::Fine, TierReason::Mode),
            StatsMode::Coarse => (Tier::Coarse, TierReason::Mode),
            StatsMode::Auto => {
                let fine = self.promoted.contains(mnemonic)
                    || series.is_some_and(|s| s.fine_since.is_some());
                let tier = if fine { Tier::Fine } else { Tier::Coarse };
                (tier, TierReason::Traffic)
            }
        }
    }

    /// Decide a DID's tier after its counts were added to `series`, and
    /// record the decision in it (`fine_since`). Called by the flush for
    /// every row it writes, so a restart rebuilds the promoted set as rows
    /// are written.
    pub fn observe(&mut self, mnemonic: &str, series: &mut CoarseSeries, now: u64) -> Tier {
        let tier = match self.pin(mnemonic) {
            StatsResolution::Fine => Tier::Fine,
            StatsResolution::Coarse => Tier::Coarse,
            StatsResolution::Off => Tier::Off,
            StatsResolution::Auto => match self.config.mode {
                StatsMode::Fine => Tier::Fine,
                StatsMode::Coarse => Tier::Coarse,
                StatsMode::Auto => self.auto_tier(mnemonic, series, now),
            },
        };
        match tier {
            Tier::Fine => {
                series.fine_since.get_or_insert(now);
            }
            Tier::Coarse | Tier::Off => series.fine_since = None,
        }
        tier
    }

    fn auto_tier(&mut self, mnemonic: &str, series: &CoarseSeries, now: u64) -> Tier {
        let cfg = self.config;
        let was_fine = self.promoted.contains(mnemonic) || series.fine_since.is_some();
        let recent = series.recent_hour_resolves(now);
        if was_fine {
            // Demote only when both the last hour and the last day are
            // quiet: a burst keeps its detail for the day it is in view.
            let quiet = recent < u64::from(cfg.demote_per_hour)
                && series.day_average_resolves(now) < u64::from(cfg.demote_per_hour);
            if quiet {
                self.promoted.remove(mnemonic);
                return Tier::Coarse;
            }
            if self.promoted.contains(mnemonic) {
                return Tier::Fine;
            }
            // Fine in the store but not in memory: a restart. Take a place
            // again if there is one.
        } else if recent < u64::from(cfg.promote_per_hour) {
            return Tier::Coarse;
        }
        if self.promoted.len() < cfg.max_fine_dids as usize {
            self.promoted.insert(mnemonic.to_string());
            Tier::Fine
        } else {
            Tier::Coarse
        }
    }
}

/// Migration marker, at [`MIGRATION_MARKER_KEY`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationMarker {
    pub version: u32,
    pub started_at: u64,
    #[serde(default)]
    pub completed_at: Option<u64>,
    /// When the legacy `ts:` rows were deleted.
    #[serde(default)]
    pub legacy_purged_at: Option<u64>,
}

/// Current migration version.
pub const MIGRATION_VERSION: u32 = 2;

/// How long legacy rows are kept after the migration completes, so an
/// older binary rolled back to still finds them.
pub const LEGACY_RETENTION_SECS: u64 = 30 * DAY_SECS;

#[cfg(test)]
mod tests {
    use super::*;

    const H: u64 = HOUR_SECS;

    #[test]
    fn coarse_points_merge_and_stay_sorted() {
        let mut s = CoarseSeries::default();
        s.add(SeriesKind::Did, 10 * H + 5, 2, 0);
        s.add(SeriesKind::Did, 8 * H, 1, 1);
        s.add(SeriesKind::Did, 10 * H + 600, 3, 0);
        assert_eq!(s.hours, vec![[8, 1, 1], [10, 5, 0]]);
        assert_eq!(s.days, vec![[0, 6, 1]]);
    }

    #[test]
    fn coarse_window_drops_what_the_ring_has_passed() {
        let mut s = CoarseSeries::default();
        s.add(SeriesKind::Did, 0, 1, 0);
        s.add(SeriesKind::Did, DID_HOURS * H, 1, 0);
        assert_eq!(
            s.hours,
            vec![[DID_HOURS, 1, 0]],
            "hour 0 is out of the window"
        );
        // A late bucket for an hour the window has passed is not stored.
        s.add(SeriesKind::Did, 0, 1, 0);
        assert_eq!(s.hours.len(), 1);
        // The server-wide series keeps 30 days.
        let mut all = CoarseSeries::default();
        all.add(SeriesKind::All, 0, 1, 0);
        all.add(SeriesKind::All, DID_HOURS * H, 1, 0);
        assert_eq!(all.hours.len(), 2);
    }

    #[test]
    fn coarse_days_keep_thirty() {
        let mut s = CoarseSeries::default();
        for d in 0..40 {
            s.add(SeriesKind::Did, d * DAY_SECS, 1, 0);
        }
        assert_eq!(s.days.len(), DID_DAYS as usize);
        assert_eq!(s.days[0][0], 10);
    }

    #[test]
    fn fine_slot_adds_to_its_bucket_and_replaces_an_older_one() {
        let held = FineSlot { e: 600, r: 2, u: 0 };
        assert_eq!(held.add(600, 1, 1), Some(FineSlot { e: 600, r: 3, u: 1 }));
        let later = 600 + FINE_SLOTS * BUCKET_SECS;
        assert_eq!(
            held.add(later, 1, 0),
            Some(FineSlot {
                e: later,
                r: 1,
                u: 0
            })
        );
        assert_eq!(held.add(300, 1, 0), None, "the ring has overwritten it");
        assert_eq!(
            FineSlot::default().add(0, 1, 0),
            Some(FineSlot { e: 0, r: 1, u: 0 })
        );
        assert_eq!(fine_slot(600), fine_slot(later));
    }

    #[test]
    fn stored_stats_reads_as_did_stats_and_back() {
        let mut row = StoredDidStats::default();
        row.totals.total_resolves = 7;
        let mut c = CoarseSeries::default();
        c.add(SeriesKind::Did, H, 7, 0);
        row.coarse = Some(c);
        let json = serde_json::to_vec(&row).unwrap();
        let plain: DidStats = serde_json::from_slice(&json).unwrap();
        assert_eq!(plain.total_resolves, 7, "older readers still see totals");
        let legacy = br#"{"totalResolves":3,"totalUpdates":1}"#;
        let row: StoredDidStats = serde_json::from_slice(legacy).unwrap();
        assert_eq!(row.totals.total_resolves, 3);
        assert!(row.coarse.is_none());
    }

    fn busy(now: u64, per_hour: u64) -> CoarseSeries {
        let mut s = CoarseSeries::default();
        s.add(SeriesKind::Did, now, per_hour, 0);
        s
    }

    #[test]
    fn auto_promotes_busy_dids_up_to_the_cap() {
        let now = 1000 * H;
        let mut t = TierState::new(StatsTierConfig {
            max_fine_dids: 1,
            ..StatsTierConfig::default()
        });
        let mut a = busy(now, 60);
        assert_eq!(t.observe("a", &mut a, now), Tier::Fine);
        assert_eq!(a.fine_since, Some(now));
        let mut b = busy(now, 500);
        assert_eq!(t.observe("b", &mut b, now), Tier::Coarse, "cap reached");
        assert_eq!(b.fine_since, None);
        let mut quiet = busy(now, 59);
        assert_eq!(t.observe("q", &mut quiet, now), Tier::Coarse);
    }

    #[test]
    fn auto_demotes_only_when_the_hour_and_the_day_are_quiet() {
        let now = 1000 * H;
        let mut t = TierState::new(StatsTierConfig::default());
        let mut s = busy(now, 1000);
        assert_eq!(t.observe("a", &mut s, now), Tier::Fine);
        // Two hours on, the burst is still in the day's average (1000/24).
        let later = now + 2 * H;
        assert_eq!(t.observe("a", &mut s, later), Tier::Fine);
        // A day on, it has left the window.
        let day_on = now + 25 * H;
        assert_eq!(t.observe("a", &mut s, day_on), Tier::Coarse);
        assert_eq!(s.fine_since, None);
        assert_eq!(t.promoted_count(), 0, "its place is free again");
    }

    #[test]
    fn a_restart_rebuilds_the_promoted_set_from_the_rows() {
        let now = 1000 * H;
        let mut s = busy(now, 100);
        s.fine_since = Some(now - H);
        let mut t = TierState::new(StatsTierConfig::default());
        assert_eq!(t.tier_of("a", Some(&s)).0, Tier::Fine);
        assert_eq!(t.observe("a", &mut s, now), Tier::Fine);
        assert_eq!(s.fine_since, Some(now - H), "kept, not restarted");
        assert_eq!(t.promoted_count(), 1);
    }

    #[test]
    fn pins_and_mode_override_traffic() {
        let now = 1000 * H;
        let mut t = TierState::new(StatsTierConfig::default());
        t.set_pin("quiet", StatsResolution::Fine);
        let mut s = CoarseSeries::default();
        assert_eq!(t.observe("quiet", &mut s, now), Tier::Fine);
        assert_eq!(t.promoted_count(), 0, "a pin takes no automatic place");
        t.set_pin("busy", StatsResolution::Off);
        let mut s = busy(now, 10_000);
        assert_eq!(t.observe("busy", &mut s, now), Tier::Off);
        t.set_pin("busy", StatsResolution::Auto);
        assert_eq!(t.observe("busy", &mut s, now), Tier::Fine);

        let mut coarse_mode = TierState::new(StatsTierConfig {
            mode: StatsMode::Coarse,
            ..StatsTierConfig::default()
        });
        let mut s = busy(now, 10_000);
        assert_eq!(coarse_mode.observe("busy", &mut s, now), Tier::Coarse);
    }

    #[test]
    fn config_needs_a_gap_between_thresholds() {
        assert!(StatsTierConfig::default().validate().is_ok());
        let flat = StatsTierConfig {
            promote_per_hour: 20,
            demote_per_hour: 20,
            ..StatsTierConfig::default()
        };
        assert!(flat.validate().is_err());
        let parsed: Result<StatsTierConfig, _> = toml::from_str("promote = 5");
        assert!(parsed.is_err(), "unknown keys are refused");
        let parsed: StatsTierConfig = toml::from_str("mode = \"coarse\"").unwrap();
        assert_eq!(parsed.mode, StatsMode::Coarse);
    }
}
