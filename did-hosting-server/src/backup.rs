use crate::config::AppConfig;
use crate::error::AppError;
use crate::store::{RawKvPair, Store};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use did_hosting_common::server::store::{
    KS_ASSIGNMENTS, KS_DIDS, KS_DOMAINS, KS_META, KS_PENDING_PURGES, KS_REGISTRY, KS_STATS,
    KS_TIMESERIES, KS_WITNESSES,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Backup-format version.
///
/// - **v1**: original shape — `{ dids, acl, stats, sessions }`.
///   Restored as a no-op for any keyspace introduced after.
/// - **v2**: adds `{ domains, assignments, pending_purges, registry,
///   timeseries, meta, witnesses }` — every keyspace introduced by the
///   multi-domain rollout (T18/T27/T28/T29/T30) plus the previously-undumped
///   bookkeeping keyspaces (registry, timeseries, meta, witnesses).
/// - **v3** (current): drops `acl` and `sessions` — the edge's own auth and
///   ACL were deleted (its only authority is `control_did`, checked on each
///   Trust Task's proof), so both keyspaces are permanently empty on this
///   binary and never worth a backup entry. Restoring an older backup still
///   works; its `acl`/`sessions` data, if any, is simply not restored.
const BACKUP_VERSION: u32 = 3;

#[derive(Serialize, Deserialize)]
struct Backup {
    version: u32,
    created_at: String,
    server_version: String,
    config: String,
    keyspaces: BackupKeyspaces,
}

#[derive(Serialize, Deserialize)]
struct BackupKeyspaces {
    dids: Vec<KvEntry>,
    stats: Vec<KvEntry>,
    // ---- T54: new keyspaces (v2 backup) ----
    //
    // `#[serde(default)]` keeps v1 backups loadable: a missing key
    // deserialises as `Vec::new()`, and the restore loop runs zero
    // batches for that keyspace. The daemon's first-boot seed
    // (T18, T29) populates the empty `domains` + `assignments`
    // keyspaces from config; backwards-compat is preserved without
    // a separate migration path.
    #[serde(default)]
    domains: Vec<KvEntry>,
    #[serde(default)]
    assignments: Vec<KvEntry>,
    #[serde(default)]
    pending_purges: Vec<KvEntry>,
    #[serde(default)]
    registry: Vec<KvEntry>,
    #[serde(default)]
    timeseries: Vec<KvEntry>,
    #[serde(default)]
    meta: Vec<KvEntry>,
    #[serde(default)]
    witnesses: Vec<KvEntry>,
}

#[derive(Clone, Serialize, Deserialize)]
struct KvEntry {
    key: String,
    value: String,
}

fn encode_pairs(pairs: Vec<RawKvPair>) -> Vec<KvEntry> {
    pairs
        .into_iter()
        .map(|(k, v)| KvEntry {
            key: BASE64.encode(&k),
            value: BASE64.encode(&v),
        })
        .collect()
}

pub async fn run_backup(config_path: Option<PathBuf>, output: String) -> Result<(), AppError> {
    let config = AppConfig::load(config_path)?;

    let config_json = serde_json::to_string_pretty(&config)
        .map_err(|e| AppError::Config(format!("failed to serialize config: {e}")))?;

    let store = Store::open(&config.store).await?;

    let dids_ks = store.keyspace(KS_DIDS)?;
    let stats_ks = store.keyspace(KS_STATS)?;
    let domains_ks = store.keyspace(KS_DOMAINS)?;
    let assignments_ks = store.keyspace(KS_ASSIGNMENTS)?;
    let pending_purges_ks = store.keyspace(KS_PENDING_PURGES)?;
    let registry_ks = store.keyspace(KS_REGISTRY)?;
    let timeseries_ks = store.keyspace(KS_TIMESERIES)?;
    let meta_ks = store.keyspace(KS_META)?;
    let witnesses_ks = store.keyspace(KS_WITNESSES)?;

    let dids = encode_pairs(dids_ks.iter_all().await?);
    let stats = encode_pairs(stats_ks.iter_all().await?);
    let domains = encode_pairs(domains_ks.iter_all().await?);
    let assignments = encode_pairs(assignments_ks.iter_all().await?);
    let pending_purges = encode_pairs(pending_purges_ks.iter_all().await?);
    let registry = encode_pairs(registry_ks.iter_all().await?);
    let timeseries = encode_pairs(timeseries_ks.iter_all().await?);
    let meta = encode_pairs(meta_ks.iter_all().await?);
    let witnesses = encode_pairs(witnesses_ks.iter_all().await?);

    let backup = Backup {
        version: BACKUP_VERSION,
        created_at: chrono::Utc::now().to_rfc3339(),
        server_version: env!("CARGO_PKG_VERSION").to_string(),
        config: config_json,
        keyspaces: BackupKeyspaces {
            dids,
            stats,
            domains,
            assignments,
            pending_purges,
            registry,
            timeseries,
            meta,
            witnesses,
        },
    };

    let json = serde_json::to_string_pretty(&backup)?;

    if output == "-" {
        println!("{json}");
    } else {
        std::fs::write(&output, &json).map_err(AppError::Io)?;
    }

    let total = backup.keyspaces.dids.len()
        + backup.keyspaces.stats.len()
        + backup.keyspaces.domains.len()
        + backup.keyspaces.assignments.len()
        + backup.keyspaces.pending_purges.len()
        + backup.keyspaces.registry.len()
        + backup.keyspaces.timeseries.len()
        + backup.keyspaces.meta.len()
        + backup.keyspaces.witnesses.len();

    eprintln!();
    eprintln!("  Backup complete!");
    eprintln!();
    eprintln!("  dids:           {} entries", backup.keyspaces.dids.len());
    eprintln!("  stats:          {} entries", backup.keyspaces.stats.len());
    eprintln!(
        "  domains:        {} entries",
        backup.keyspaces.domains.len()
    );
    eprintln!(
        "  assignments:    {} entries",
        backup.keyspaces.assignments.len()
    );
    eprintln!(
        "  pending_purges: {} entries",
        backup.keyspaces.pending_purges.len()
    );
    eprintln!(
        "  registry:       {} entries",
        backup.keyspaces.registry.len()
    );
    eprintln!(
        "  timeseries:     {} entries",
        backup.keyspaces.timeseries.len()
    );
    eprintln!("  meta:           {} entries", backup.keyspaces.meta.len());
    eprintln!(
        "  witnesses:      {} entries",
        backup.keyspaces.witnesses.len()
    );
    eprintln!("  total:          {total} entries");
    eprintln!();
    if output != "-" {
        eprintln!("  Output: {output}");
        eprintln!();
    }

    Ok(())
}

pub async fn run_restore(config_path: Option<PathBuf>, input: String) -> Result<(), AppError> {
    let json = std::fs::read_to_string(&input)
        .map_err(|e| AppError::Config(format!("failed to read backup file {input}: {e}")))?;

    let backup: Backup = serde_json::from_str(&json)
        .map_err(|e| AppError::Config(format!("invalid backup JSON: {e}")))?;

    if backup.version > BACKUP_VERSION {
        return Err(AppError::Config(format!(
            "backup version {} is newer than this binary supports (max {BACKUP_VERSION}); \
             upgrade the daemon or use a matching backup",
            backup.version
        )));
    }
    if backup.version < 1 {
        return Err(AppError::Config(format!(
            "unsupported backup version {} (minimum 1)",
            backup.version
        )));
    }
    if backup.version < BACKUP_VERSION {
        eprintln!(
            "  Note: restoring v{} backup with v{BACKUP_VERSION} binary. \
             Missing keyspaces ({{domains, assignments, ...}}) will be \
             populated by first-boot seed on next daemon startup, and any \
             `acl`/`sessions` data in the backup is not restored — this \
             binary has no use for either (the edge's own auth and ACL were \
             deleted; its only authority is `control_did`).",
            backup.version
        );
    }

    // Deserialize the embedded AppConfig from the backup
    let backup_config: AppConfig = serde_json::from_str(&backup.config)
        .map_err(|e| AppError::Config(format!("invalid config in backup: {e}")))?;

    let config_file_path = config_path
        .clone()
        .or_else(|| {
            std::env::var("DID_HOSTING_CONFIG_PATH")
                .ok()
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from("config.toml"));
    let config_toml = toml::to_string_pretty(&backup_config)
        .map_err(|e| AppError::Config(format!("failed to serialize config as TOML: {e}")))?;

    // The store the backup's config names, after the environment overrides
    // the service itself applies when it loads that config. Nothing has been
    // written yet: the backup is checked against this store first.
    let mut store_config = backup_config.store.clone();
    {
        let mut effective = backup_config.clone();
        for prefix in ["WEBVH", "DID_HOSTING"] {
            did_hosting_common::server::config::apply_env_overrides(
                prefix,
                &mut effective.features,
                &mut effective.server,
                &mut effective.log,
                &mut store_config,
                &mut effective.auth,
                &mut effective.secrets,
            )?;
        }
    }
    eprintln!(
        "  Restoring into the store at {}",
        store_config.data_dir.display()
    );
    let store = Store::open(&store_config).await?;
    let dids_ks = store.keyspace(KS_DIDS)?;

    // Every DID log the backup carries is checked, against itself and against
    // the history this store has served, before anything is written: a
    // refused restore changes nothing, config.toml included.
    let dids_plan = plan_dids_restore(&dids_ks, &backup.keyspaces.dids).await?;

    std::fs::write(&config_file_path, &config_toml).map_err(|e| {
        AppError::Config(format!(
            "failed to write config to {}: {e}",
            config_file_path.display()
        ))
    })?;
    eprintln!("  Config restored to: {}", config_file_path.display());

    let stats_ks = store.keyspace(KS_STATS)?;
    let domains_ks = store.keyspace(KS_DOMAINS)?;
    let assignments_ks = store.keyspace(KS_ASSIGNMENTS)?;
    let pending_purges_ks = store.keyspace(KS_PENDING_PURGES)?;
    let registry_ks = store.keyspace(KS_REGISTRY)?;
    let timeseries_ks = store.keyspace(KS_TIMESERIES)?;
    let meta_ks = store.keyspace(KS_META)?;
    let witnesses_ks = store.keyspace(KS_WITNESSES)?;

    let dids_count = restore_dids(&store, &dids_ks, dids_plan).await?;
    let stats_count = restore_keyspace(&store, &stats_ks, &backup.keyspaces.stats).await?;
    let domains_count = restore_keyspace(&store, &domains_ks, &backup.keyspaces.domains).await?;
    let assignments_count =
        restore_keyspace(&store, &assignments_ks, &backup.keyspaces.assignments).await?;
    let pending_purges_count =
        restore_keyspace(&store, &pending_purges_ks, &backup.keyspaces.pending_purges).await?;
    let registry_count = restore_keyspace(&store, &registry_ks, &backup.keyspaces.registry).await?;
    let timeseries_count =
        restore_keyspace(&store, &timeseries_ks, &backup.keyspaces.timeseries).await?;
    let meta_count = restore_keyspace(&store, &meta_ks, &backup.keyspaces.meta).await?;
    let witnesses_count =
        restore_keyspace(&store, &witnesses_ks, &backup.keyspaces.witnesses).await?;

    let total = dids_count
        + stats_count
        + domains_count
        + assignments_count
        + pending_purges_count
        + registry_count
        + timeseries_count
        + meta_count
        + witnesses_count;

    eprintln!();
    eprintln!("  Restore complete!");
    eprintln!();
    eprintln!("  dids:           {dids_count} entries");
    eprintln!("  stats:          {stats_count} entries");
    eprintln!("  domains:        {domains_count} entries");
    eprintln!("  assignments:    {assignments_count} entries");
    eprintln!("  pending_purges: {pending_purges_count} entries");
    eprintln!("  registry:       {registry_count} entries");
    eprintln!("  timeseries:     {timeseries_count} entries");
    eprintln!("  meta:           {meta_count} entries");
    eprintln!("  witnesses:      {witnesses_count} entries");
    eprintln!("  total:          {total} entries");
    eprintln!();

    Ok(())
}

/// Entries written per restore batch.
const BATCH_SIZE: usize = 1000;

fn decode_entry(entry: &KvEntry) -> Result<RawKvPair, AppError> {
    let key = BASE64
        .decode(&entry.key)
        .map_err(|e| AppError::Config(format!("invalid base64url key: {e}")))?;
    let value = BASE64
        .decode(&entry.value)
        .map_err(|e| AppError::Config(format!("invalid base64url value: {e}")))?;
    Ok((key, value))
}

async fn restore_keyspace(
    store: &Store,
    ks: &crate::store::KeyspaceHandle,
    entries: &[KvEntry],
) -> Result<usize, AppError> {
    let pairs = entries
        .iter()
        .map(decode_entry)
        .collect::<Result<Vec<_>, _>>()?;
    write_pairs(store, ks, pairs).await
}

async fn write_pairs(
    store: &Store,
    ks: &crate::store::KeyspaceHandle,
    pairs: Vec<RawKvPair>,
) -> Result<usize, AppError> {
    let count = pairs.len();
    for chunk in pairs.chunks(BATCH_SIZE) {
        let mut batch = store.batch();
        for (key, value) in chunk {
            batch.insert_raw(ks, key.clone(), value.clone());
        }
        // A restore is a bulk load that is safe to re-run, and a chunk of
        // 1,000 entries can be over one DynamoDB transaction, so it need
        // not land atomically.
        batch.commit_in_parts().await?;
    }
    Ok(count)
}

/// A DID log a restore puts back, checked by
/// [`crate::control_register::verify_history`].
struct RestoredLog {
    identity: String,
    mnemonic: String,
    did_id: String,
    method: String,
    log: String,
}

/// What a restore writes to the `dids` keyspace.
struct DidsRestore {
    /// Every entry to write as it is: all of the backup's, less the
    /// high-water marks this store already holds further.
    pairs: Vec<RawKvPair>,
    /// The logs whose high-water marks are recorded once `pairs` is written.
    logs: Vec<RestoredLog>,
}

/// Check the backup's `dids` keyspace, and decide what to write. Nothing is
/// written here.
///
/// A restore replaces logs, so it is held to the rule every other path that
/// replaces an edge's log is. The plan is driven by the backup's logs
/// (`content:{slot}:log`), not its records, so no log escapes it. Each log of
/// a method with a history (`did:webvh`, and `did:webs` in a build with
/// `method-webs`) must:
///
/// - have a record in the backup, naming the DID the log establishes;
/// - verify: its chain and witness proofs (webvh), or its key event log and
///   the AID the slot's identifier names (webs);
/// - extend what this store holds for its DID and slot, and the high-water
///   marks it keeps ([`crate::control_register::verify_history`]);
/// - extend the backup's own high-water mark for its DID.
///
/// A backup's high-water mark is written only where this store holds none for
/// that DID or it extends the one held; one this store already holds further
/// is kept. Any failure refuses the whole restore.
async fn plan_dids_restore(
    ks: &crate::store::KeyspaceHandle,
    entries: &[KvEntry],
) -> Result<DidsRestore, AppError> {
    use crate::control_register::{
        HIGH_WATER_IDENTITY_PREFIX, HIGH_WATER_SLOT_PREFIX, has_history, high_water_to_restore,
        verify_extends, verify_history,
    };
    use crate::did_ops::{DidRecord, content_witness_key, did_key};
    use std::collections::BTreeMap;

    let backup: BTreeMap<Vec<u8>, Vec<u8>> =
        entries.iter().map(decode_entry).collect::<Result<_, _>>()?;
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();

    // What is wrong with the backup itself, whatever store it goes into.
    let mut unsound = Vec::new();
    // What would roll back a history this store has served.
    let mut rollbacks = Vec::new();
    let mut logs = Vec::new();
    for (key, value) in &backup {
        let Some(mnemonic) = key
            .strip_prefix(b"content:")
            .and_then(|rest| rest.strip_suffix(b":log"))
        else {
            continue;
        };
        let mnemonic = text(mnemonic);
        let log = text(value);
        let Some(record) = backup.get(did_key(&mnemonic).as_bytes()) else {
            unsound.push(format!(
                "{mnemonic}: the backup holds a log for this slot but no record"
            ));
            continue;
        };
        let record: DidRecord = serde_json::from_slice(record).map_err(|e| {
            AppError::Config(format!(
                "the backup's record for {mnemonic} is unreadable: {e}"
            ))
        })?;
        if !has_history(&record.method) {
            continue;
        }
        let method = record.method.as_str();

        // The DID the log establishes, and the log's own validity.
        let did_id = match method {
            "webvh" => {
                let Some(did_id) = did_hosting_common::did_ops::extract_did_id(&log) else {
                    unsound.push(format!("{mnemonic}: the backup's log establishes no DID"));
                    continue;
                };
                if record.did_id.as_deref() != Some(did_id.as_str()) {
                    unsound.push(format!(
                        "{mnemonic}: the backup's record names {}, its log establishes {did_id}",
                        record.did_id.as_deref().unwrap_or("no DID")
                    ));
                    continue;
                }
                let witness = backup
                    .get(content_witness_key(&mnemonic).as_bytes())
                    .map(|w| text(w));
                if let Err(e) = did_hosting_common::did_ops::verify_did_log_and_witness_proofs(
                    &log,
                    witness.as_deref(),
                ) {
                    unsound.push(format!(
                        "{mnemonic} ({did_id}): the log does not verify: {e}"
                    ));
                    continue;
                }
                did_id
            }
            #[cfg(feature = "method-webs")]
            "webs" => {
                let Some(did_id) = record.did_id.clone() else {
                    unsound.push(format!("{mnemonic}: the backup's record names no DID"));
                    continue;
                };
                if let Err(e) = did_hosting_common::method::webs::Webs::verify_artifacts(
                    &did_id,
                    log.as_bytes(),
                    None,
                ) {
                    unsound.push(format!(
                        "{mnemonic} ({did_id}): the log does not verify: {e}"
                    ));
                    continue;
                }
                did_id
            }
            other => {
                unsound.push(format!("{mnemonic}: this build cannot verify {other} logs"));
                continue;
            }
        };

        let identity = match verify_history(ks, &mnemonic, &did_id, &log, method).await {
            Ok(identity) => identity,
            Err(e) => {
                rollbacks.push(format!("{mnemonic} ({did_id}): {e}"));
                continue;
            }
        };
        // A log behind the backup's own mark is wrong whatever store it goes
        // into: a store an earlier version's CLI wrote to can hold one.
        let mark_key = format!("{HIGH_WATER_IDENTITY_PREFIX}{identity}");
        if let Some(mark) = backup.get(mark_key.as_bytes())
            && verify_extends(method, &did_id, &text(mark), &log).is_err()
        {
            unsound.push(format!(
                "{mnemonic} ({did_id}): this backup's log is older than a version it has \
                 already served (its own high-water mark)"
            ));
            continue;
        }
        logs.push(RestoredLog {
            identity,
            mnemonic,
            did_id,
            method: record.method,
            log,
        });
    }

    let mut pairs = Vec::with_capacity(backup.len());
    for (key, value) in backup {
        if let Some(identity) = key.strip_prefix(HIGH_WATER_IDENTITY_PREFIX.as_bytes()) {
            let identity = text(identity);
            match high_water_to_restore(ks, &identity, &text(&value)).await {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    rollbacks.push(format!("{identity}: {e}"));
                    continue;
                }
            }
        } else if key.starts_with(HIGH_WATER_SLOT_PREFIX.as_bytes())
            && ks.get_raw(key.clone()).await?.is_some()
        {
            // The slot's held record stays; a restored log records its own.
            continue;
        }
        pairs.push((key, value));
    }

    if unsound.is_empty() && rollbacks.is_empty() {
        return Ok(DidsRestore { pairs, logs });
    }
    let mut message = String::from("restore refused, nothing was written.");
    if !unsound.is_empty() {
        message.push_str(&format!(
            "\n  The backup is not consistent ({} slots), so it cannot be restored into \
             any store as it is:\n    {}",
            unsound.len(),
            unsound.join("\n    ")
        ));
    }
    if !rollbacks.is_empty() {
        message.push_str(&format!(
            "\n  The backup would roll back {} DID histories this store has served. \
             Restore into an empty store to start from the backup's state:\n    {}",
            rollbacks.len(),
            rollbacks.join("\n    ")
        ));
    }
    Err(AppError::Validation(message))
}

/// Write a [`plan_dids_restore`] plan: its entries, then the high-water marks
/// of the logs it restored.
async fn restore_dids(
    store: &Store,
    ks: &crate::store::KeyspaceHandle,
    plan: DidsRestore,
) -> Result<usize, AppError> {
    let count = write_pairs(store, ks, plan.pairs).await?;
    for chunk in plan.logs.chunks(BATCH_SIZE / 2) {
        let mut batch = store.batch();
        for log in chunk {
            crate::control_register::stage_high_water(
                &mut batch,
                ks,
                &log.identity,
                &log.mnemonic,
                &log.did_id,
                &log.method,
                &log.log,
            )?;
        }
        batch.commit_in_parts().await?;
    }
    Ok(count)
}

#[cfg(test)]
mod history_tests {
    use super::*;
    use crate::bootstrap::{import_did_at_path, test_logs};
    use crate::did_ops::{DidRecord, content_log_key, did_key};
    use crate::store::KeyspaceHandle;
    use did_hosting_common::server::config::StoreConfig;

    async fn store() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        })
        .await
        .expect("open store");
        let ks = store.keyspace(KS_DIDS).expect("dids keyspace");
        (dir, store, ks)
    }

    /// The `dids` keyspace as a backup carries it.
    async fn dump(ks: &KeyspaceHandle) -> Vec<KvEntry> {
        encode_pairs(ks.iter_all().await.unwrap())
    }

    async fn held_log(ks: &KeyspaceHandle, mnemonic: &str) -> Option<String> {
        ks.get_raw(content_log_key(mnemonic))
            .await
            .unwrap()
            .map(|b| String::from_utf8(b).unwrap())
    }

    /// Into an empty store, a backup restores with its high-water marks.
    #[tokio::test]
    async fn a_backup_restores_into_an_empty_store_with_its_marks() {
        let logs = test_logs::versions("example.com", "alice", 2).await;
        let (_a, source, source_ks) = store().await;
        import_did_at_path(&source, &source_ks, "alice", &logs[1], None)
            .await
            .unwrap();
        let backup = dump(&source_ks).await;

        let (_b, target, ks) = store().await;
        let plan = plan_dids_restore(&ks, &backup).await.expect("restores");
        restore_dids(&target, &ks, plan).await.unwrap();
        assert_eq!(held_log(&ks, "alice").await.as_deref(), Some(&*logs[1]));

        // The restored marks hold: an older version cannot be loaded.
        let mut batch = target.batch();
        batch.remove(&ks, did_key("alice"));
        batch.remove(&ks, content_log_key("alice"));
        batch.commit().await.unwrap();
        assert!(
            import_did_at_path(&target, &ks, "alice", &logs[0], None)
                .await
                .is_err()
        );
    }

    /// A backup older than what the store has served is refused whole, and
    /// nothing is written: neither its log nor its high-water marks.
    #[tokio::test]
    async fn an_older_backup_does_not_roll_a_held_log_back() {
        let logs = test_logs::versions("example.com", "alice", 3).await;
        let (_a, older, older_ks) = store().await;
        import_did_at_path(&older, &older_ks, "alice", &logs[0], None)
            .await
            .unwrap();
        let backup = dump(&older_ks).await;

        let (_b, target, ks) = store().await;
        import_did_at_path(&target, &ks, "alice", &logs[2], None)
            .await
            .unwrap();
        let before = ks.iter_all().await.unwrap();
        let Err(AppError::Validation(message)) = plan_dids_restore(&ks, &backup).await else {
            panic!("an older backup must be refused");
        };
        assert!(message.contains("alice"), "{message}");
        assert_eq!(ks.iter_all().await.unwrap(), before, "nothing was written");
    }

    /// The mark of a DID that has since been removed still counts: a backup
    /// from before the DID's later versions cannot put an older log back.
    #[tokio::test]
    async fn an_older_backup_does_not_roll_a_removed_dids_history_back() {
        let logs = test_logs::versions("example.com", "alice", 2).await;
        let (_a, older, older_ks) = store().await;
        import_did_at_path(&older, &older_ks, "alice", &logs[0], None)
            .await
            .unwrap();
        let backup = dump(&older_ks).await;

        let (_b, target, ks) = store().await;
        import_did_at_path(&target, &ks, "alice", &logs[1], None)
            .await
            .unwrap();
        let mut batch = target.batch();
        batch.remove(&ks, did_key("alice"));
        batch.remove(&ks, content_log_key("alice"));
        batch.commit().await.unwrap();

        assert!(plan_dids_restore(&ks, &backup).await.is_err());
    }

    /// A backup entry's key, decoded.
    fn key_of(entry: &KvEntry) -> Vec<u8> {
        BASE64.decode(&entry.key).unwrap()
    }

    fn refusal(result: Result<DidsRestore, AppError>) -> String {
        match result {
            Err(AppError::Validation(message)) => message,
            Err(other) => panic!("expected a refusal, got {other:?}"),
            Ok(_) => panic!("expected a refusal, the restore was planned"),
        }
    }

    /// A log with no record in the backup is not restored unchecked: the
    /// restore is refused.
    #[tokio::test]
    async fn a_log_without_a_record_is_refused() {
        let logs = test_logs::versions("example.com", "alice", 1).await;
        let (_a, source, source_ks) = store().await;
        import_did_at_path(&source, &source_ks, "alice", &logs[0], None)
            .await
            .unwrap();
        let backup: Vec<KvEntry> = dump(&source_ks)
            .await
            .into_iter()
            .filter(|e| key_of(e) != did_key("alice").into_bytes())
            .collect();

        let (_b, _target, ks) = store().await;
        let message = refusal(plan_dids_restore(&ks, &backup).await);
        assert!(message.contains("no record"), "{message}");
    }

    /// A record naming another DID than its log establishes is refused.
    #[tokio::test]
    async fn a_record_that_names_another_did_is_refused() {
        let logs = test_logs::versions("example.com", "alice", 1).await;
        let (_a, source, source_ks) = store().await;
        import_did_at_path(&source, &source_ks, "alice", &logs[0], None)
            .await
            .unwrap();
        let mut record: DidRecord = source_ks.get(did_key("alice")).await.unwrap().unwrap();
        record.did_id = Some("did:webvh:QmOther:example.com:alice".into());
        source_ks.insert(did_key("alice"), &record).await.unwrap();
        let backup = dump(&source_ks).await;

        let (_b, _target, ks) = store().await;
        let message = refusal(plan_dids_restore(&ks, &backup).await);
        assert!(message.contains("its log establishes"), "{message}");
    }

    /// A backup whose log is behind its own high-water mark (a store an
    /// earlier CLI wrote an older log into) is refused even into an empty
    /// store, and says so.
    #[tokio::test]
    async fn a_backup_behind_its_own_mark_is_refused_into_any_store() {
        let logs = test_logs::versions("example.com", "alice", 2).await;
        let (_a, source, source_ks) = store().await;
        import_did_at_path(&source, &source_ks, "alice", &logs[1], None)
            .await
            .unwrap();
        source_ks
            .insert_raw(content_log_key("alice"), logs[0].as_bytes().to_vec())
            .await
            .unwrap();
        let backup = dump(&source_ks).await;

        let (_b, _target, ks) = store().await;
        let message = refusal(plan_dids_restore(&ks, &backup).await);
        assert!(
            message.contains("older than a version it has already served"),
            "{message}"
        );
        assert!(
            !message.contains("Restore into an empty store"),
            "{message}"
        );
    }

    /// A refused restore writes nothing, config.toml included: the backup is
    /// checked against the store its config names before anything is written.
    #[tokio::test]
    async fn a_refused_restore_leaves_the_config_unwritten() {
        use did_hosting_common::server::config::{
            AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, VtaConfig,
        };
        let logs = test_logs::versions("example.com", "alice", 2).await;
        let (_a, older, older_ks) = store().await;
        import_did_at_path(&older, &older_ks, "alice", &logs[0], None)
            .await
            .unwrap();
        let dids = dump(&older_ks).await;

        let target = tempfile::tempdir().unwrap();
        let store_config = StoreConfig {
            data_dir: target.path().to_path_buf(),
            ..StoreConfig::default()
        };
        {
            let store = Store::open(&store_config).await.unwrap();
            let ks = store.keyspace(KS_DIDS).unwrap();
            import_did_at_path(&store, &ks, "alice", &logs[1], None)
                .await
                .unwrap();
            store.persist().await.unwrap();
        }
        let config = AppConfig {
            fjall: Default::default(),
            features: FeaturesConfig::default(),
            server_did: None,
            mediator_did: None,
            public_url: None,
            server: ServerConfig::default(),
            log: LogConfig::default(),
            store: store_config,
            auth: AuthConfig::default(),
            hosting: Default::default(),
            secrets: SecretsConfig::default(),
            limits: Default::default(),
            replication: Default::default(),
            stats: Default::default(),
            control_did: None,
            vta: VtaConfig::default(),
            identity: Default::default(),
            replay: Default::default(),
            config_path: PathBuf::new(),
        };
        let backup = Backup {
            version: BACKUP_VERSION,
            created_at: "now".into(),
            server_version: "test".into(),
            config: serde_json::to_string(&config).unwrap(),
            keyspaces: BackupKeyspaces {
                dids,
                stats: vec![],
                domains: vec![],
                assignments: vec![],
                pending_purges: vec![],
                registry: vec![],
                timeseries: vec![],
                meta: vec![],
                witnesses: vec![],
            },
        };
        let work = tempfile::tempdir().unwrap();
        let input = work.path().join("backup.json");
        std::fs::write(&input, serde_json::to_string(&backup).unwrap()).unwrap();
        let config_file = work.path().join("config.toml");

        let err = run_restore(
            Some(config_file.clone()),
            input.to_string_lossy().into_owned(),
        )
        .await
        .expect_err("an older backup is refused");
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
        assert!(!config_file.exists(), "config.toml was not written");
    }

    /// A backup carrying only an older high-water mark (its DID removed
    /// before the backup) leaves the further mark this store holds in place.
    #[tokio::test]
    async fn a_held_mark_further_than_the_backups_is_kept() {
        let logs = test_logs::versions("example.com", "alice", 2).await;
        let (_a, older, older_ks) = store().await;
        import_did_at_path(&older, &older_ks, "alice", &logs[0], None)
            .await
            .unwrap();
        let mut batch = older.batch();
        batch.remove(&older_ks, did_key("alice"));
        batch.remove(&older_ks, content_log_key("alice"));
        batch.commit().await.unwrap();
        let backup = dump(&older_ks).await;

        let (_b, target, ks) = store().await;
        import_did_at_path(&target, &ks, "alice", &logs[1], None)
            .await
            .unwrap();
        let plan = plan_dids_restore(&ks, &backup).await.expect("restores");
        restore_dids(&target, &ks, plan).await.unwrap();

        // The held log and its mark are as they were: v1 is still refused.
        assert_eq!(held_log(&ks, "alice").await.as_deref(), Some(&*logs[1]));
        let record: DidRecord = ks.get(did_key("alice")).await.unwrap().unwrap();
        assert_eq!(record.version_count, 2);
        let mut batch = target.batch();
        batch.remove(&ks, did_key("alice"));
        batch.remove(&ks, content_log_key("alice"));
        batch.commit().await.unwrap();
        assert!(
            import_did_at_path(&target, &ks, "alice", &logs[0], None)
                .await
                .is_err()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A v1 backup body — pre-T54, only the four original keyspaces.
    /// Used to pin backwards-compat: a v1 dump must still
    /// deserialise against the v2 `BackupKeyspaces` shape with the
    /// new fields defaulting to empty.
    fn v1_backup_json() -> String {
        // Encode `{ key: "k", value: "v" }` as the inner pair.
        let k = BASE64.encode(b"k");
        let v = BASE64.encode(b"v");
        format!(
            r#"{{
              "version": 1,
              "created_at": "2026-05-17T00:00:00Z",
              "server_version": "0.6.0",
              "config": "{{}}",
              "keyspaces": {{
                "dids":     [{{ "key": "{k}", "value": "{v}" }}],
                "acl":      [],
                "stats":    [],
                "sessions": []
              }}
            }}"#
        )
    }

    /// v1 backups (pre-T54, no domain/assignment data) deserialise
    /// against the current `Backup` shape with the new fields
    /// defaulting to empty `Vec`. This is the upgrade-path
    /// guarantee.
    #[test]
    fn v1_backup_deserialises_with_empty_new_keyspaces() {
        let json = v1_backup_json();
        let parsed: Backup = serde_json::from_str(&json).expect("v1 backup must deserialise");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.keyspaces.dids.len(), 1);
        // All new keyspaces default to empty.
        assert!(parsed.keyspaces.domains.is_empty());
        assert!(parsed.keyspaces.assignments.is_empty());
        assert!(parsed.keyspaces.pending_purges.is_empty());
        assert!(parsed.keyspaces.registry.is_empty());
        assert!(parsed.keyspaces.timeseries.is_empty());
        assert!(parsed.keyspaces.meta.is_empty());
        assert!(parsed.keyspaces.witnesses.is_empty());
    }

    /// A current-version backup with non-empty `domains` / `assignments` /
    /// `pending_purges` round-trips through serde without losing the
    /// new-keyspace data, and carries no `acl`/`sessions` fields at all.
    #[test]
    fn current_backup_round_trips_every_keyspace() {
        let k = BASE64.encode(b"key1");
        let v = BASE64.encode(b"val1");
        let entry = vec![KvEntry {
            key: k.clone(),
            value: v.clone(),
        }];

        let original = Backup {
            version: BACKUP_VERSION,
            created_at: "now".into(),
            server_version: "0.7.0".into(),
            config: "{}".into(),
            keyspaces: BackupKeyspaces {
                dids: entry.clone(),
                stats: entry.clone(),
                domains: entry.clone(),
                assignments: entry.clone(),
                pending_purges: entry.clone(),
                registry: entry.clone(),
                timeseries: entry.clone(),
                meta: entry.clone(),
                witnesses: entry.clone(),
            },
        };

        let json = serde_json::to_string(&original).unwrap();
        let parsed: Backup = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.version, BACKUP_VERSION);
        assert_eq!(parsed.keyspaces.dids.len(), 1);
        assert_eq!(parsed.keyspaces.domains.len(), 1);
        assert_eq!(parsed.keyspaces.assignments.len(), 1);
        assert_eq!(parsed.keyspaces.pending_purges.len(), 1);
        assert_eq!(parsed.keyspaces.registry.len(), 1);
        assert_eq!(parsed.keyspaces.timeseries.len(), 1);
        assert_eq!(parsed.keyspaces.meta.len(), 1);
        assert_eq!(parsed.keyspaces.witnesses.len(), 1);

        // Spot-check the round-trip preserved the b64 payload.
        assert_eq!(parsed.keyspaces.domains[0].key, k);
        assert_eq!(parsed.keyspaces.assignments[0].value, v);
    }

    /// `KvEntry` round-trips arbitrary bytes through base64url
    /// without padding. Pin the encoding so a future change of
    /// `BASE64` engine doesn't break old backup files.
    #[test]
    fn kv_entry_round_trips_arbitrary_bytes() {
        let bytes: &[u8] = &[0, 1, 2, 254, 255, b'!', b'-', b'_'];
        let encoded = BASE64.encode(bytes);
        let decoded = BASE64.decode(&encoded).unwrap();
        assert_eq!(decoded, bytes);
        // base64url-no-pad never emits `=`.
        assert!(!encoded.contains('='));
    }
}
