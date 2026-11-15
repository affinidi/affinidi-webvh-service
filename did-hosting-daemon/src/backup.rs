//! `did-hosting-daemon backup` / `restore`.
//!
//! The daemon owns more than an edge: its control plane keeps the ACL, login
//! and step-up passkeys, identity generations, did:scid floors and the
//! outbound queue in the main store, and the embedded witness keeps its own
//! ACL and witness identities in `[witness_store]`. So the daemon declares its
//! own backup — both stores, an explicit keyspace list for each, and the
//! configuration file carried verbatim — on the shared machinery in
//! [`did_hosting_common::server::backup`], rather than borrowing the edge's.
//!
//! Every keyspace the workspace declares
//! ([`did_hosting_common::server::store::ALL_KEYSPACES`]) is either backed up
//! here or named in [`EXCLUDED`] with the reason; a test holds that.

use std::collections::BTreeMap;
use std::path::PathBuf;

use did_hosting_common::server::backup::{
    MultiStoreBackup, StoreDump, dump_store_except, restore_store, write_private_file,
};
use did_hosting_common::server::error::AppError;
use did_hosting_common::server::store::{
    KS_ACL, KS_ASSIGNMENTS, KS_DIDS, KS_DOMAINS, KS_IDENTITY, KS_META, KS_OUTBOUND_QUEUE,
    KS_PASSKEY_STEP_UP, KS_PENDING_PURGES, KS_REGISTRY, KS_SCID_FLOORS, KS_SESSIONS, KS_STATS,
    KS_TIMESERIES, KS_TSP_RELATIONSHIPS, KS_WITNESSES, Store,
};

use crate::config::{self, DaemonConfig};

/// The `format` a daemon backup carries.
pub const FORMAT: &str = "did-hosting-daemon";
/// The format version this binary writes and the newest it restores.
pub const VERSION: u32 = 1;

/// The main store (`[store]`).
pub const MAIN_STORE: &str = "main";
/// The embedded witness's store (`[witness_store]`).
pub const WITNESS_STORE: &str = "witness";

/// What the main store's backup carries: everything the server, control
/// plane and watcher keep there.
pub const MAIN_KEYSPACES: &[&str] = &[
    KS_DIDS,
    KS_ACL,
    KS_SESSIONS,
    KS_PASSKEY_STEP_UP,
    KS_STATS,
    KS_TIMESERIES,
    KS_REGISTRY,
    KS_WITNESSES,
    KS_META,
    KS_DOMAINS,
    KS_ASSIGNMENTS,
    KS_PENDING_PURGES,
    KS_IDENTITY,
    KS_OUTBOUND_QUEUE,
    KS_SCID_FLOORS,
];

/// What the witness store's backup carries: the same, less the DID logs,
/// which only the main store hosts (a restore verifies those, and a witness
/// store has none to verify).
pub const WITNESS_KEYSPACES: &[&str] = &[
    KS_ACL,
    KS_SESSIONS,
    KS_PASSKEY_STEP_UP,
    KS_STATS,
    KS_TIMESERIES,
    KS_REGISTRY,
    KS_WITNESSES,
    KS_META,
    KS_DOMAINS,
    KS_ASSIGNMENTS,
    KS_PENDING_PURGES,
    KS_IDENTITY,
    KS_OUTBOUND_QUEUE,
    KS_SCID_FLOORS,
];

/// Keyspaces deliberately left out of a backup, and why.
pub const EXCLUDED: &[(&str, &str)] = &[(
    KS_TSP_RELATIONSHIPS,
    "TSP relationship state is per-peer session state the next handshake re-establishes; \
     a restored copy is stale against every peer's",
)];

/// Entries left out of the keyspaces a backup carries, by key prefix: live
/// sign-in sessions and their refresh tokens are bearer credentials, so a
/// backup never holds them (a restored deployment signs its users in again).
/// The passkey credentials beside them in the same keyspace are kept.
pub const SKIPPED_PREFIXES: &[(&str, &[&str])] = &[
    (KS_SESSIONS, &["session:", "refresh:"]),
    (KS_PASSKEY_STEP_UP, &["session:", "refresh:"]),
];

/// What each store declares, for [`MultiStoreBackup::check_declared`].
const DECLARED: &[(&str, &[&str])] = &[
    (MAIN_STORE, MAIN_KEYSPACES),
    (WITNESS_STORE, WITNESS_KEYSPACES),
];

/// The configuration file's path and its text.
fn read_config(config_path: Option<PathBuf>) -> Result<(PathBuf, String), AppError> {
    let path = DaemonConfig::resolve_path(config_path);
    let text = std::fs::read_to_string(&path).map_err(|e| {
        AppError::Config(format!(
            "cannot read the configuration file {}: {e}",
            path.display()
        ))
    })?;
    Ok((path, text))
}

/// The two stores `config` names. The witness store is `None` when it
/// reaches the main store's data: then it has nothing of its own to back up
/// or restore (and the daemon would refuse to start with the witness on).
async fn open_stores(config: &DaemonConfig) -> Result<(Store, Option<Store>), AppError> {
    let main = Store::open_with(&config.store, &config.fjall).await?;
    let witness = Store::open_with(&config.witness_store, &config.fjall).await?;
    if config::witness_store_shares_main_data(&main, &witness).await? {
        eprintln!(
            "  Note: [witness_store] reaches the same data as [store]; only [store] is used."
        );
        return Ok((main, None));
    }
    Ok((main, Some(witness)))
}

/// Build a backup of the daemon's stores, as `config_text` (at `path`)
/// names them.
pub async fn build_backup(
    path: PathBuf,
    config_text: String,
) -> Result<MultiStoreBackup, AppError> {
    let config = DaemonConfig::from_toml(&config_text, path)?;
    let (main, witness) = open_stores(&config).await?;
    let mut stores = BTreeMap::new();
    stores.insert(
        MAIN_STORE.to_string(),
        dump_store_except(&main, MAIN_KEYSPACES, SKIPPED_PREFIXES).await?,
    );
    if let Some(witness) = witness.as_ref() {
        stores.insert(
            WITNESS_STORE.to_string(),
            dump_store_except(witness, WITNESS_KEYSPACES, SKIPPED_PREFIXES).await?,
        );
    }
    Ok(MultiStoreBackup {
        format: FORMAT.to_string(),
        version: VERSION,
        created_at: chrono::Utc::now().to_rfc3339(),
        binary_version: env!("CARGO_PKG_VERSION").to_string(),
        config: config_text,
        stores,
    })
}

pub async fn run_backup(config_path: Option<PathBuf>, output: String) -> Result<(), AppError> {
    let (path, text) = read_config(config_path)?;
    let backup = build_backup(path, text).await?;
    let json = serde_json::to_string_pretty(&backup)?;
    if output == "-" {
        println!("{json}");
    } else {
        write_private_file(std::path::Path::new(&output), json.as_bytes())?;
    }

    eprintln!();
    eprintln!("  Backup complete!");
    print_counts(
        backup
            .stores
            .iter()
            .map(|(store, dump)| (store.as_str(), counts_of(dump))),
    );
    eprintln!("  total: {} entries", backup.total_entries());
    for (ks, why) in EXCLUDED {
        eprintln!("  not backed up: {ks} ({why})");
    }
    eprintln!(
        "  The backup holds the ACL, passkey credentials and the configuration unencrypted: \
         keep it as you keep the service's secrets."
    );
    if output != "-" {
        eprintln!("  Output: {output}");
    }
    eprintln!();
    Ok(())
}

fn counts_of(dump: &StoreDump) -> BTreeMap<String, usize> {
    dump.iter().map(|(k, v)| (k.clone(), v.len())).collect()
}

fn print_counts<'a>(stores: impl Iterator<Item = (&'a str, BTreeMap<String, usize>)>) {
    for (store, counts) in stores {
        eprintln!();
        eprintln!("  [{store}]");
        for (ks, n) in counts {
            eprintln!("    {ks:<18} {n} entries");
        }
    }
    eprintln!();
}

/// Restore `backup` into the stores its configuration names (after the
/// environment overrides the daemon itself applies), and write that
/// configuration, verbatim, to `config_file`.
///
/// Nothing is written until the backup has been checked: its format and
/// keyspaces against what this binary declares, and every DID log against
/// itself and the history the target store has served (the edge's rule —
/// [`did_hosting_server::backup::plan_dids_restore`]).
pub async fn restore_backup(
    backup: &MultiStoreBackup,
    config_file: PathBuf,
) -> Result<BTreeMap<String, BTreeMap<String, usize>>, AppError> {
    if backup.format != FORMAT {
        return Err(AppError::Config(format!(
            "this is a `{}` backup, not a {FORMAT} one",
            backup.format
        )));
    }
    if backup.version == 0 || backup.version > VERSION {
        return Err(AppError::Config(format!(
            "unsupported backup version {} (this binary restores 1..={VERSION})",
            backup.version
        )));
    }
    backup.check_declared(DECLARED)?;

    let config = DaemonConfig::from_toml(&backup.config, config_file.clone())?;
    eprintln!(
        "  Restoring into {} (and the witness store at {})",
        config.store.data_dir.display(),
        config.witness_store.data_dir.display()
    );
    let (main, witness) = open_stores(&config).await?;
    let empty = StoreDump::new();
    let main_dump = backup.stores.get(MAIN_STORE).unwrap_or(&empty);
    let witness_dump = backup.stores.get(WITNESS_STORE).unwrap_or(&empty);
    if witness.is_none() && witness_dump.values().any(|e| !e.is_empty()) {
        return Err(AppError::Config(
            "the backup holds witness-store data, but the configuration's [witness_store] \
             reaches the same data as [store]; give [witness_store] its own data first"
                .into(),
        ));
    }

    let dids_ks = main.keyspace(KS_DIDS)?;
    let dids = main_dump.get(KS_DIDS).map(Vec::as_slice).unwrap_or(&[]);
    let plan = did_hosting_server::backup::plan_dids_restore(&dids_ks, dids).await?;

    // Verbatim: the daemon's configuration is never re-serialised through
    // another binary's config type, which would drop what it does not model.
    std::fs::write(&config_file, &backup.config).map_err(|e| {
        AppError::Config(format!(
            "failed to write config to {}: {e}",
            config_file.display()
        ))
    })?;
    eprintln!("  Config restored to: {}", config_file.display());

    let mut counts = BTreeMap::new();
    let dids_count = did_hosting_server::backup::restore_dids(&main, &dids_ks, plan).await?;
    let mut main_counts = restore_store(&main, main_dump, &[KS_DIDS]).await?;
    main_counts.insert(KS_DIDS.to_string(), dids_count);
    main.persist().await?;
    counts.insert(MAIN_STORE.to_string(), main_counts);
    if let Some(witness) = witness.as_ref() {
        counts.insert(
            WITNESS_STORE.to_string(),
            restore_store(witness, witness_dump, &[]).await?,
        );
        witness.persist().await?;
    }
    Ok(counts)
}

pub async fn run_restore(config_path: Option<PathBuf>, input: String) -> Result<(), AppError> {
    let json = std::fs::read_to_string(&input)
        .map_err(|e| AppError::Config(format!("failed to read backup file {input}: {e}")))?;
    let backup: MultiStoreBackup = serde_json::from_str(&json).map_err(|e| {
        AppError::Config(format!(
            "invalid backup JSON (a did-hosting-daemon backup is expected; an edge's \
             backup restores with did-hosting-server): {e}"
        ))
    })?;
    let counts = restore_backup(&backup, DaemonConfig::resolve_path(config_path)).await?;
    eprintln!();
    eprintln!("  Restore complete!");
    print_counts(counts.iter().map(|(s, c)| (s.as_str(), c.clone())));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use did_hosting_common::server::store::ALL_KEYSPACES;

    /// Every keyspace the workspace declares is in the main store's backup or
    /// explicitly excluded — never both, never neither. A new `KS_*` fails
    /// here until someone decides.
    #[test]
    fn every_keyspace_is_backed_up_or_excluded() {
        for ks in ALL_KEYSPACES {
            let backed_up = MAIN_KEYSPACES.contains(ks);
            let excluded = EXCLUDED.iter().any(|(name, _)| name == ks);
            assert!(
                backed_up ^ excluded,
                "keyspace `{ks}` must be in exactly one of MAIN_KEYSPACES and EXCLUDED"
            );
            // The witness store carries everything the main store does, bar
            // the DID logs it never hosts.
            if *ks != KS_DIDS {
                assert_eq!(
                    WITNESS_KEYSPACES.contains(ks),
                    backed_up,
                    "keyspace `{ks}`: the witness store's list disagrees"
                );
            }
        }
        for ks in MAIN_KEYSPACES.iter().chain(WITNESS_KEYSPACES) {
            assert!(
                ALL_KEYSPACES.contains(ks),
                "`{ks}` is not a declared keyspace"
            );
        }
    }

    fn config_text(main: &std::path::Path, witness: &std::path::Path) -> String {
        format!(
            r#"# kept verbatim, comment and all
public_url = "https://daemon.example.com"

[store]
data_dir = "{}"

[witness_store]
data_dir = "{}"

[enable]
watcher = true

[registry]
"#,
            main.display(),
            witness.display()
        )
    }

    /// A backup carries both stores — the control plane's ACL, passkeys and
    /// identity, and the witness's own ACL and keys — and restores them into
    /// empty stores, writing the configuration back byte for byte.
    #[tokio::test]
    async fn a_daemon_backup_round_trips_both_stores_and_the_config_verbatim() {
        let src = tempfile::tempdir().unwrap();
        let (main_dir, witness_dir) = (src.path().join("main"), src.path().join("witness"));
        let text = config_text(&main_dir, &witness_dir);
        {
            let config = DaemonConfig::from_toml(&text, src.path().join("config.toml")).unwrap();
            let (main, witness) = open_stores(&config).await.unwrap();
            let witness = witness.expect("separate stores");
            main.keyspace(KS_SESSIONS)
                .unwrap()
                .insert_raw("session:live", b"bearer".to_vec())
                .await
                .unwrap();
            for (ks, key) in [
                (KS_ACL, "acl:did:example:admin"),
                (KS_SESSIONS, "pk_user:1"),
                (KS_PASSKEY_STEP_UP, "pk_user:2"),
                (KS_IDENTITY, "identity:current"),
                (KS_SCID_FLOORS, "scid_floor:x"),
                (KS_OUTBOUND_QUEUE, "outbox:x"),
            ] {
                main.keyspace(ks)
                    .unwrap()
                    .insert_raw(key, b"main".to_vec())
                    .await
                    .unwrap();
            }
            witness
                .keyspace(KS_ACL)
                .unwrap()
                .insert_raw("acl:did:example:edge", b"witness".to_vec())
                .await
                .unwrap();
            witness
                .keyspace(KS_WITNESSES)
                .unwrap()
                .insert_raw("w1", b"witness".to_vec())
                .await
                .unwrap();
            main.persist().await.unwrap();
            witness.persist().await.unwrap();
        }
        let backup = build_backup(src.path().join("config.toml"), text.clone())
            .await
            .unwrap();
        // The backup round-trips through its JSON form.
        let backup: MultiStoreBackup =
            serde_json::from_str(&serde_json::to_string(&backup).unwrap()).unwrap();

        // Restore elsewhere: point the backup's config at fresh directories.
        let dst = tempfile::tempdir().unwrap();
        let (main_dir2, witness_dir2) = (dst.path().join("main"), dst.path().join("witness"));
        let moved = MultiStoreBackup {
            config: config_text(&main_dir2, &witness_dir2),
            ..backup
        };
        let config_file = dst.path().join("config.toml");
        let counts = restore_backup(&moved, config_file.clone()).await.unwrap();
        assert_eq!(counts[MAIN_STORE][KS_ACL], 1);
        assert_eq!(counts[WITNESS_STORE][KS_ACL], 1);

        assert_eq!(
            std::fs::read_to_string(&config_file).unwrap(),
            moved.config,
            "the config is written verbatim"
        );
        let config = DaemonConfig::from_toml(&moved.config, config_file).unwrap();
        let (main, witness) = open_stores(&config).await.unwrap();
        let witness = witness.unwrap();
        for (ks, key) in [
            (KS_ACL, "acl:did:example:admin"),
            (KS_SESSIONS, "pk_user:1"),
            (KS_PASSKEY_STEP_UP, "pk_user:2"),
            (KS_IDENTITY, "identity:current"),
            (KS_SCID_FLOORS, "scid_floor:x"),
            (KS_OUTBOUND_QUEUE, "outbox:x"),
        ] {
            assert_eq!(
                main.keyspace(ks).unwrap().get_raw(key).await.unwrap(),
                Some(b"main".to_vec()),
                "{ks}"
            );
        }
        assert_eq!(
            witness
                .keyspace(KS_ACL)
                .unwrap()
                .get_raw("acl:did:example:edge")
                .await
                .unwrap(),
            Some(b"witness".to_vec())
        );
        assert!(
            main.keyspace(KS_SESSIONS)
                .unwrap()
                .get_raw("session:live")
                .await
                .unwrap()
                .is_none(),
            "a live session is never backed up"
        );
        assert!(
            main.keyspace(KS_ACL)
                .unwrap()
                .get_raw("acl:did:example:edge")
                .await
                .unwrap()
                .is_none(),
            "the witness's ACL stays in the witness store"
        );
    }

    /// A backup of another binary, or holding a keyspace this binary does not
    /// restore, is refused before anything is written.
    #[tokio::test]
    async fn a_foreign_or_unknown_backup_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join("config.toml");
        let base = MultiStoreBackup {
            format: FORMAT.into(),
            version: VERSION,
            created_at: "now".into(),
            binary_version: "test".into(),
            config: config_text(&dir.path().join("m"), &dir.path().join("w")),
            stores: BTreeMap::new(),
        };
        let foreign = MultiStoreBackup {
            format: "did-hosting-server".into(),
            ..base.clone()
        };
        assert!(restore_backup(&foreign, config_file.clone()).await.is_err());
        let mut unknown = base.clone();
        unknown.stores.insert(
            MAIN_STORE.into(),
            StoreDump::from([(KS_TSP_RELATIONSHIPS.to_string(), vec![])]),
        );
        assert!(restore_backup(&unknown, config_file.clone()).await.is_err());
        assert!(!config_file.exists(), "nothing was written");
    }
}
