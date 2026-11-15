//! `m03_index_did_records` — build the per-owner usage counters and the
//! per-domain slot index ([`crate::server::did_index`]) from the records.
//!
//! ## Why
//!
//! The quota checks and `did/list`'s domain filter read these derived rows
//! instead of walking every record. Every write path keeps them current from
//! the version that introduced them; records already on disk have none until
//! this sweep builds them.
//!
//! ## What gets touched
//!
//! - one `domain:{domain}:{mnemonic}` row per record with a domain;
//! - one `usage:{owner}` row per owner, set to what that owner's records add
//!   up to, and any `usage:` row of an owner holding no record removed.
//!
//! Every write sets a value computed from the records, never adds to one, so
//! re-running the sweep (after a crash, or by hand) converges on the same
//! rows. It runs at boot, before the service takes writes.
//!
//! ## Who runs it
//!
//! The control plane and the daemon, whose writes keep the rows current. An
//! edge does not read them and does not run it.

use std::collections::BTreeMap;

use tracing::{info, warn};

use super::super::did_index::{self, OwnerUsage};
use super::super::store::{KS_DIDS, Store};
use super::{Migration, MigrationFuture, MigrationOutcome};
use crate::did_ops::DidRecord;

/// Public migration ID. Stable wire identifier — never rename.
pub const ID: &str = "m03_index_did_records";

/// Rows one batch of the sweep writes.
const WRITE_BATCH_ROWS: usize = 64;

pub struct M03IndexDidRecords;

impl Migration for M03IndexDidRecords {
    fn id(&self) -> &'static str {
        ID
    }

    fn description(&self) -> &'static str {
        "build the per-owner usage counters and the per-domain DID index"
    }

    fn run<'a>(&'a self, store: &'a Store) -> MigrationFuture<'a> {
        Box::pin(async move {
            let dids = store.keyspace(KS_DIDS)?;
            let mut usage: BTreeMap<String, OwnerUsage> = BTreeMap::new();
            let mut indexed = 0u64;
            let mut skipped = 0u64;

            let mut walk = dids.walk(b"did:".to_vec(), super::MIGRATION_PAGE_ROWS);
            while let Some(rows) = walk.next_page().await? {
                let mut batch = store.batch();
                for (key, value) in rows {
                    let record: DidRecord = match serde_json::from_slice(&value) {
                        Ok(r) => r,
                        Err(e) => {
                            warn!(
                                migration_id = ID,
                                key = %String::from_utf8_lossy(&key),
                                error = %e,
                                "skipping unparseable DidRecord"
                            );
                            skipped += 1;
                            continue;
                        }
                    };
                    let u = usage.entry(record.owner.clone()).or_default();
                    u.count += 1;
                    u.bytes = u.bytes.saturating_add(record.content_size);
                    if let Some(domain) = did_index::record_domain(&record) {
                        batch.insert_raw(
                            &dids,
                            did_index::domain_index_key(&domain, &record.mnemonic),
                            record.mnemonic.as_bytes().to_vec(),
                        );
                        indexed += 1;
                    }
                }
                batch.commit_in_parts().await?;
            }

            // Counters: set every owner's, and drop any row for an owner
            // that holds nothing (a re-run after deletes).
            let mut stale = Vec::new();
            let mut usage_walk = dids.walk(
                did_index::USAGE_PREFIX.as_bytes().to_vec(),
                super::MIGRATION_PAGE_ROWS,
            );
            while let Some(rows) = usage_walk.next_page().await? {
                for (key, _) in rows {
                    let owner = key
                        .strip_prefix(did_index::USAGE_PREFIX.as_bytes())
                        .and_then(|o| std::str::from_utf8(o).ok());
                    if owner.is_none_or(|o| !usage.contains_key(o)) {
                        stale.push(key);
                    }
                }
            }
            let owners = usage.len();
            let mut batch = store.batch();
            let mut pending = 0;
            for key in stale {
                batch.remove(&dids, key);
                pending += 1;
            }
            for (owner, u) in &usage {
                batch.insert(&dids, did_index::usage_key(owner), u)?;
                pending += 1;
                if pending >= WRITE_BATCH_ROWS {
                    std::mem::replace(&mut batch, store.batch())
                        .commit_in_parts()
                        .await?;
                    pending = 0;
                }
            }
            batch.commit_in_parts().await?;

            info!(migration_id = ID, indexed, owners, skipped, "M-03 complete");
            Ok(MigrationOutcome::Complete)
        })
    }
}

#[cfg(all(test, feature = "store-fjall"))]
mod tests {
    use super::*;
    use crate::did_ops::did_key;
    use crate::server::config::StoreConfig;
    use crate::server::did_index::{domain_index_key, owner_usage, usage_key};
    use crate::server::migrations::MigrationRunner;

    fn record(owner: &str, mnemonic: &str, domain: &str, size: u64) -> DidRecord {
        DidRecord {
            owner: owner.into(),
            mnemonic: mnemonic.into(),
            created_at: 0,
            updated_at: 0,
            version_count: 1,
            did_id: Some(format!("did:webvh:Q1:legacy.example:{mnemonic}")),
            content_size: size,
            disabled: false,
            disabled_by_admin: false,
            deleted_at: None,
            method: "webvh".into(),
            domain: domain.into(),
            services: None,
            agent_names: Vec::new(),
        }
    }

    #[tokio::test]
    async fn builds_counters_and_the_domain_index_from_the_records() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        })
        .await
        .unwrap();
        let dids = store.keyspace(KS_DIDS).unwrap();
        for r in [
            record("did:example:a", "one", "a.example", 10),
            record("did:example:a", "two", "b.example", 20),
            record("did:example:b", "three", "a.example", 5),
            // A legacy record: its domain is its DID's host.
            record("did:example:b", "four", "", 1),
        ] {
            dids.insert(did_key(&r.mnemonic), &r).await.unwrap();
        }
        // A counter left for an owner that holds nothing goes.
        dids.insert(
            usage_key("did:example:gone"),
            &OwnerUsage { count: 3, bytes: 3 },
        )
        .await
        .unwrap();

        let summary = MigrationRunner::new(vec![std::sync::Arc::new(M03IndexDidRecords)])
            .run_pending(&store)
            .await
            .unwrap();
        assert_eq!(summary.applied, vec![ID.to_string()]);

        assert_eq!(
            owner_usage(&dids, "did:example:a").await.unwrap(),
            OwnerUsage {
                count: 2,
                bytes: 30
            }
        );
        assert_eq!(
            owner_usage(&dids, "did:example:b").await.unwrap(),
            OwnerUsage { count: 2, bytes: 6 }
        );
        assert!(
            dids.get_raw(usage_key("did:example:gone"))
                .await
                .unwrap()
                .is_none()
        );
        for (domain, m) in [
            ("a.example", "one"),
            ("b.example", "two"),
            ("a.example", "three"),
            ("legacy.example", "four"),
        ] {
            assert_eq!(
                dids.get_raw(domain_index_key(domain, m)).await.unwrap(),
                Some(m.as_bytes().to_vec()),
                "{domain}/{m}"
            );
        }
    }
}
