use crate::config::AppConfig;
use crate::error::AppError;
use crate::store::{RawKvPair, Store};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use did_hosting_common::server::store::{
    KS_ACL, KS_ASSIGNMENTS, KS_DIDS, KS_DOMAINS, KS_META, KS_PENDING_PURGES, KS_REGISTRY,
    KS_SESSIONS, KS_STATS, KS_TIMESERIES, KS_WITNESSES,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Backup-format version.
///
/// - **v1**: original shape — `{ dids, acl, stats, sessions }`.
///   Restored as a no-op for any keyspace introduced after.
/// - **v2** (current, T54): adds `{ domains, assignments,
///   pending_purges, registry, timeseries, meta, witnesses }` —
///   every keyspace introduced by the multi-domain rollout
///   (T18/T27/T28/T29/T30) plus the previously-undumped
///   bookkeeping keyspaces (registry, timeseries, meta, witnesses).
const BACKUP_VERSION: u32 = 2;

/// Durable session key prefixes to include in backups.
const DURABLE_SESSION_PREFIXES: &[&str] = &["pk_user:", "pk_cred:", "pk_did:", "enroll:"];

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
    acl: Vec<KvEntry>,
    stats: Vec<KvEntry>,
    sessions: Vec<KvEntry>,
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
    let acl_ks = store.keyspace(KS_ACL)?;
    let stats_ks = store.keyspace(KS_STATS)?;
    let sessions_ks = store.keyspace(KS_SESSIONS)?;
    let domains_ks = store.keyspace(KS_DOMAINS)?;
    let assignments_ks = store.keyspace(KS_ASSIGNMENTS)?;
    let pending_purges_ks = store.keyspace(KS_PENDING_PURGES)?;
    let registry_ks = store.keyspace(KS_REGISTRY)?;
    let timeseries_ks = store.keyspace(KS_TIMESERIES)?;
    let meta_ks = store.keyspace(KS_META)?;
    let witnesses_ks = store.keyspace(KS_WITNESSES)?;

    let dids = encode_pairs(dids_ks.iter_all().await?);
    let acl = encode_pairs(acl_ks.iter_all().await?);
    let stats = encode_pairs(stats_ks.iter_all().await?);
    let domains = encode_pairs(domains_ks.iter_all().await?);
    let assignments = encode_pairs(assignments_ks.iter_all().await?);
    let pending_purges = encode_pairs(pending_purges_ks.iter_all().await?);
    let registry = encode_pairs(registry_ks.iter_all().await?);
    let timeseries = encode_pairs(timeseries_ks.iter_all().await?);
    let meta = encode_pairs(meta_ks.iter_all().await?);
    let witnesses = encode_pairs(witnesses_ks.iter_all().await?);

    // Filter sessions to only include durable prefixes
    let all_sessions = sessions_ks.iter_all().await?;
    let durable_sessions: Vec<RawKvPair> = all_sessions
        .into_iter()
        .filter(|(key, _)| {
            let key_str = String::from_utf8_lossy(key);
            DURABLE_SESSION_PREFIXES
                .iter()
                .any(|prefix| key_str.starts_with(prefix))
        })
        .collect();
    let sessions = encode_pairs(durable_sessions);

    let backup = Backup {
        version: BACKUP_VERSION,
        created_at: chrono::Utc::now().to_rfc3339(),
        server_version: env!("CARGO_PKG_VERSION").to_string(),
        config: config_json,
        keyspaces: BackupKeyspaces {
            dids,
            acl,
            stats,
            sessions,
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
        + backup.keyspaces.acl.len()
        + backup.keyspaces.stats.len()
        + backup.keyspaces.sessions.len()
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
    eprintln!("  acl:            {} entries", backup.keyspaces.acl.len());
    eprintln!("  stats:          {} entries", backup.keyspaces.stats.len());
    eprintln!(
        "  sessions:       {} entries",
        backup.keyspaces.sessions.len()
    );
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
             populated by first-boot seed on next daemon startup.",
            backup.version
        );
    }

    // Deserialize the embedded AppConfig from the backup
    let backup_config: AppConfig = serde_json::from_str(&backup.config)
        .map_err(|e| AppError::Config(format!("invalid config in backup: {e}")))?;

    // Write config.toml from the backup
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
    std::fs::write(&config_file_path, &config_toml).map_err(|e| {
        AppError::Config(format!(
            "failed to write config to {}: {e}",
            config_file_path.display()
        ))
    })?;
    eprintln!("  Config restored to: {}", config_file_path.display());

    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store).await?;

    let dids_ks = store.keyspace(KS_DIDS)?;
    let acl_ks = store.keyspace(KS_ACL)?;
    let stats_ks = store.keyspace(KS_STATS)?;
    let sessions_ks = store.keyspace(KS_SESSIONS)?;
    let domains_ks = store.keyspace(KS_DOMAINS)?;
    let assignments_ks = store.keyspace(KS_ASSIGNMENTS)?;
    let pending_purges_ks = store.keyspace(KS_PENDING_PURGES)?;
    let registry_ks = store.keyspace(KS_REGISTRY)?;
    let timeseries_ks = store.keyspace(KS_TIMESERIES)?;
    let meta_ks = store.keyspace(KS_META)?;
    let witnesses_ks = store.keyspace(KS_WITNESSES)?;

    let dids_count = restore_keyspace(&store, &dids_ks, &backup.keyspaces.dids).await?;
    let acl_count = restore_keyspace(&store, &acl_ks, &backup.keyspaces.acl).await?;
    let stats_count = restore_keyspace(&store, &stats_ks, &backup.keyspaces.stats).await?;
    let sessions_count = restore_keyspace(&store, &sessions_ks, &backup.keyspaces.sessions).await?;
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
        + acl_count
        + stats_count
        + sessions_count
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
    eprintln!("  acl:            {acl_count} entries");
    eprintln!("  stats:          {stats_count} entries");
    eprintln!("  sessions:       {sessions_count} entries");
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

async fn restore_keyspace(
    store: &Store,
    ks: &crate::store::KeyspaceHandle,
    entries: &[KvEntry],
) -> Result<usize, AppError> {
    const BATCH_SIZE: usize = 1000;

    for chunk in entries.chunks(BATCH_SIZE) {
        let mut batch = store.batch();
        for entry in chunk {
            let key = BASE64
                .decode(&entry.key)
                .map_err(|e| AppError::Config(format!("invalid base64url key: {e}")))?;
            let value = BASE64
                .decode(&entry.value)
                .map_err(|e| AppError::Config(format!("invalid base64url value: {e}")))?;
            batch.insert_raw(ks, key, value);
        }
        batch.commit().await?;
    }

    Ok(entries.len())
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

    /// A v2 backup with non-empty `domains` / `assignments` /
    /// `pending_purges` round-trips through serde without losing
    /// the new-keyspace data.
    #[test]
    fn v2_backup_round_trips_every_keyspace() {
        let k = BASE64.encode(b"key1");
        let v = BASE64.encode(b"val1");
        let entry = vec![KvEntry {
            key: k.clone(),
            value: v.clone(),
        }];

        let original = Backup {
            version: BACKUP_VERSION,
            created_at: "now".into(),
            server_version: "0.7.1".into(),
            config: "{}".into(),
            keyspaces: BackupKeyspaces {
                dids: entry.clone(),
                acl: entry.clone(),
                stats: entry.clone(),
                sessions: entry.clone(),
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
