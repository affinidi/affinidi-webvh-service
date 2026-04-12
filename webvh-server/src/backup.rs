use crate::config::AppConfig;
use crate::error::AppError;
use crate::store::{RawKvPair, Store};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const BACKUP_VERSION: u32 = 1;

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
}

#[derive(Serialize, Deserialize)]
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

    let dids_ks = store.keyspace("dids")?;
    let acl_ks = store.keyspace("acl")?;
    let stats_ks = store.keyspace("stats")?;
    let sessions_ks = store.keyspace("sessions")?;

    let dids = encode_pairs(dids_ks.iter_all().await?);
    let acl = encode_pairs(acl_ks.iter_all().await?);
    let stats = encode_pairs(stats_ks.iter_all().await?);

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
        + backup.keyspaces.sessions.len();

    eprintln!();
    eprintln!("  Backup complete!");
    eprintln!();
    eprintln!("  dids:     {} entries", backup.keyspaces.dids.len());
    eprintln!("  acl:      {} entries", backup.keyspaces.acl.len());
    eprintln!("  stats:    {} entries", backup.keyspaces.stats.len());
    eprintln!("  sessions: {} entries", backup.keyspaces.sessions.len());
    eprintln!("  total:    {total} entries");
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

    let backup: Backup =
        serde_json::from_str(&json).map_err(|e| AppError::Config(format!("invalid backup JSON: {e}")))?;

    if backup.version != BACKUP_VERSION {
        return Err(AppError::Config(format!(
            "unsupported backup version {} (expected {BACKUP_VERSION})",
            backup.version
        )));
    }

    // Deserialize the embedded AppConfig from the backup
    let backup_config: AppConfig = serde_json::from_str(&backup.config)
        .map_err(|e| AppError::Config(format!("invalid config in backup: {e}")))?;

    // Write config.toml from the backup
    let config_file_path = config_path
        .clone()
        .or_else(|| std::env::var("WEBVH_CONFIG_PATH").ok().map(PathBuf::from))
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

    let dids_ks = store.keyspace("dids")?;
    let acl_ks = store.keyspace("acl")?;
    let stats_ks = store.keyspace("stats")?;
    let sessions_ks = store.keyspace("sessions")?;

    let dids_count = restore_keyspace(&store, &dids_ks, &backup.keyspaces.dids).await?;
    let acl_count = restore_keyspace(&store, &acl_ks, &backup.keyspaces.acl).await?;
    let stats_count = restore_keyspace(&store, &stats_ks, &backup.keyspaces.stats).await?;
    let sessions_count = restore_keyspace(&store, &sessions_ks, &backup.keyspaces.sessions).await?;

    let total = dids_count + acl_count + stats_count + sessions_count;

    eprintln!();
    eprintln!("  Restore complete!");
    eprintln!();
    eprintln!("  dids:     {dids_count} entries");
    eprintln!("  acl:      {acl_count} entries");
    eprintln!("  stats:    {stats_count} entries");
    eprintln!("  sessions: {sessions_count} entries");
    eprintln!("  total:    {total} entries");
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
