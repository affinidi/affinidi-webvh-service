//! Offline statistics commands, shared by `did-hosting-control` and
//! `did-hosting-daemon`: `stats-show`, `stats-set` and `stats-purge-legacy`.
//!
//! Like the other offline commands they open the store directly, so the
//! service must be stopped (fjall locks it); the running service reads an
//! override at its next start. The operator running them holds the store, so
//! `stats-set` may set any resolution, `fine` included.

use did_hosting_common::did_ops::did_key;
use did_hosting_common::server::config::StoreConfig;
use did_hosting_common::server::stats_collector::StatsCollector;
use did_hosting_common::server::stats_tiers::{
    MIGRATION_MARKER_KEY, MigrationMarker, StatsResolution, StatsTierConfig, StoredDidStats,
    pin_key, stats_key,
};
use did_hosting_common::server::store::{KS_DIDS, KS_STATS, KS_TIMESERIES};

use crate::config::StatsFlushConfig;
use crate::store::Store;

type CliResult = Result<(), Box<dyn std::error::Error>>;

/// `stats-show`: a DID's override, recorded tier and totals.
pub async fn run_stats_show(store_config: &StoreConfig, mnemonic: &str) -> CliResult {
    let store = Store::open(store_config).await?;
    let dids_ks = store.keyspace(KS_DIDS)?;
    let stats_ks = store.keyspace(KS_STATS)?;
    if !dids_ks.contains_key(did_key(mnemonic)).await? {
        return Err(format!("no DID at `{mnemonic}`").into());
    }
    let pin: StatsResolution = stats_ks.get(pin_key(mnemonic)).await?.unwrap_or_default();
    let row: StoredDidStats = stats_ks.get(stats_key(mnemonic)).await?.unwrap_or_default();
    println!("DID:             {mnemonic}");
    println!("Resolution:      {}", pin.as_str());
    let tier = match row.coarse.as_ref() {
        None if pin == StatsResolution::Off => "off (totals only)".to_string(),
        None => "none recorded yet".to_string(),
        Some(c) => match c.fine_since {
            Some(at) => format!("fine (5-minute detail since {at})"),
            None => "coarse (hourly and daily)".to_string(),
        },
    };
    println!("Recorded tier:   {tier}");
    println!("Total resolves:  {}", row.totals.total_resolves);
    println!("Total updates:   {}", row.totals.total_updates);
    Ok(())
}

/// `stats-set`: set a DID's override.
pub async fn run_stats_set(
    store_config: &StoreConfig,
    mnemonic: &str,
    resolution: &str,
) -> CliResult {
    let resolution: StatsResolution = resolution.parse()?;
    let store = Store::open(store_config).await?;
    let dids_ks = store.keyspace(KS_DIDS)?;
    let stats_ks = store.keyspace(KS_STATS)?;
    if !dids_ks.contains_key(did_key(mnemonic)).await? {
        return Err(format!("no DID at `{mnemonic}`").into());
    }
    if resolution == StatsResolution::Auto {
        stats_ks.remove(pin_key(mnemonic)).await?;
    } else {
        stats_ks
            .insert(pin_key(mnemonic).as_str(), &resolution)
            .await?;
    }
    store.persist().await?;
    println!(
        "{mnemonic}: statistics resolution set to `{}`; the service applies it at its next start.",
        resolution.as_str()
    );
    Ok(())
}

/// `stats-purge-legacy`: finish the migration if it has not, then delete
/// the legacy `ts:` rows now rather than after the retention period.
pub async fn run_stats_purge_legacy(
    store_config: &StoreConfig,
    flush: &StatsFlushConfig,
    tiers: &StatsTierConfig,
) -> CliResult {
    let store = Store::open(store_config).await?;
    let stats_ks = store.keyspace(KS_STATS)?;
    let timeseries_ks = store.keyspace(KS_TIMESERIES)?;
    let dids_ks = store.keyspace(KS_DIDS)?;
    let marker: Option<MigrationMarker> = timeseries_ks.get(MIGRATION_MARKER_KEY).await?;
    if marker.as_ref().and_then(|m| m.legacy_purged_at).is_some() {
        println!("Legacy statistics rows were already deleted.");
        return Ok(());
    }
    let collector = StatsCollector::new();
    did_hosting_common::server::stats_collector::seed_from_store(&collector, &stats_ks, &dids_ks)
        .await;
    collector.configure_tiers(*tiers);
    let mut maintenance =
        crate::stats_migration::StatsMaintenance::new(stats_ks, timeseries_ks, dids_ks);
    let deleted = maintenance.purge_legacy_now(&collector, flush).await?;
    store.persist().await?;
    println!("Deleted {deleted} legacy statistics rows.");
    Ok(())
}
