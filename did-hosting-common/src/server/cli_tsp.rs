//! CLI for this service's persisted TSP relationships — the **offline** operator
//! surface for inspecting and clearing Rev 3 §7.2.2 relationship state.
//!
//! # What a relationship is here
//!
//! Each endpoint keeps its own half of every relationship, in its own store
//! ([`crate::server::tsp_relationship_store`]). The mediator holds none of it,
//! so wiping the mediator does not reset anything: to make two nodes meet as
//! strangers again, both halves have to go — this service's (these commands)
//! and the peer's (its own equivalent, e.g. `vta tsp-relationships`).
//!
//! # Reset versus delete
//!
//! - **reset** puts our half back to `None` and clears the thread digests —
//!   exactly what the SDK's `reset_relationship` does when a reply times out.
//!   The cached peer capability survives. The next send to the peer re-invites.
//! - **delete** removes every facet of the record (state, digests, reply path,
//!   capability, last-active), as the SDK's idle eviction does.
//!
//! Both are purely local. A peer that kept its half re-forms the relationship
//! on the next invite; a peer that sends first, before we re-invite, is dropped
//! by our §7.2.2 gate until its own recovery re-invites.
//!
//! # Offline
//!
//! These commands open the store directly. The embedded store takes an
//! exclusive lock, so they refuse to run against a live service; stop it first.
//! On a shared backend (DynamoDB, Firestore, …) there is no lock, and the
//! running service reads relationship state from the store on every message, so
//! a change here takes effect immediately.
//!
//! Every read and write goes through the SDK's `PersistentRelationshipStore`,
//! which owns the key layout; nothing here decodes a key itself.

use affinidi_messaging_sdk::protocols::tsp::{RelationshipState, RelationshipStore, ThreadDigests};

use crate::server::config::StoreConfig;
use crate::server::store::{KS_TSP_RELATIONSHIPS, Store};
use crate::server::tsp_relationship_store::{KeyspaceRelationshipStore, open_relationship_store};

type CliResult = Result<(), Box<dyn std::error::Error>>;

/// Which relationships a reset or delete applies to.
pub enum Target {
    /// Every relationship this service holds with `peer`. With `our`, only the
    /// one held under that local VID — the way to reach a half-formed pair,
    /// which the store can enumerate only once it is established.
    Peer { peer: String, our: Option<String> },
    /// Every record in the relationship keyspace, established or not.
    All,
}

/// `tsp-relationship-list` — the relationships this service has established.
pub async fn run_list(store_config: &StoreConfig) -> CliResult {
    let store = Store::open(store_config).await?;
    let relationships = open_relationship_store(&store)?;
    let established = relationships.established_relationships().await?;
    let records = store
        .keyspace(KS_TSP_RELATIONSHIPS)?
        .approximate_len()
        .await?;

    eprintln!();
    if established.is_empty() {
        eprintln!("  No established TSP relationships.");
    } else {
        let now_ms = crate::server::auth::session::now_epoch() * 1000;
        for (our, their) in &established {
            eprintln!("  {their}");
            eprintln!("    local VID   : {our}");
            match relationships.last_active(our, their).await? {
                Some(at_ms) => eprintln!(
                    "    last active : {} ago",
                    format_age(now_ms.saturating_sub(at_ms) / 1000)
                ),
                None => eprintln!("    last active : never recorded"),
            }
            eprintln!();
        }
    }
    if records > 0 {
        eprintln!(
            "  {records} stored record(s) in total. A half-formed relationship (invite sent or\n  \
             received, never accepted) is stored but not listed; `tsp-relationship-delete --all`\n  \
             clears it, or target it with `--peer <did> --our <vid>`."
        );
        eprintln!();
    }
    Ok(())
}

/// `tsp-relationship-reset` — put our half back to `None`, so the next send
/// re-invites.
pub async fn run_reset(store_config: &StoreConfig, target: Target) -> CliResult {
    let store = Store::open(store_config).await?;
    let relationships = open_relationship_store(&store)?;
    let Target::Peer { peer, our } = target else {
        return Err(
            "reset takes a --peer; use `tsp-relationship-delete --all` to clear everything".into(),
        );
    };
    let pairs = pairs_for(&relationships, &peer, our).await?;

    for (our, their) in &pairs {
        relationships
            .set(our, their, RelationshipState::None)
            .await?;
        relationships
            .set_thread_digests(our, their, ThreadDigests::default())
            .await?;
        eprintln!("  Reset relationship with {their} (local VID {our}).");
    }
    eprintln!("  The next send to the peer re-invites; restart the service to pick this up.");
    Ok(())
}

/// `tsp-relationship-delete` — remove relationship records outright.
///
/// `--all` without `yes` only reports what it would remove.
pub async fn run_delete(store_config: &StoreConfig, target: Target, yes: bool) -> CliResult {
    let store = Store::open(store_config).await?;
    let relationships = open_relationship_store(&store)?;

    match target {
        Target::Peer { peer, our } => {
            for (our, their) in pairs_for(&relationships, &peer, our).await? {
                relationships.forget(&our, &their).await?;
                eprintln!("  Deleted relationship with {their} (local VID {our}).");
            }
        }
        Target::All => {
            // The whole keyspace, not just the established pairs: a half-formed
            // relationship is exactly what an operator clearing state wants gone,
            // and it cannot be enumerated through the store.
            let ks = store.keyspace(KS_TSP_RELATIONSHIPS)?;
            let keys: Vec<Vec<u8>> = ks
                .prefix_iter_raw(Vec::new())
                .await?
                .into_iter()
                .map(|(k, _)| k)
                .collect();
            let established = relationships.established_relationships().await?.len();
            if keys.is_empty() {
                eprintln!("  No TSP relationship records; nothing to delete.");
                return Ok(());
            }
            if !yes {
                eprintln!(
                    "  Would delete {} record(s) ({established} established relationship(s)). \
                     Re-run with --yes to delete.",
                    keys.len()
                );
                return Ok(());
            }
            for key in &keys {
                ks.remove(key.clone()).await?;
            }
            eprintln!(
                "  Deleted {} record(s) ({established} established relationship(s)).",
                keys.len()
            );
        }
    }
    eprintln!("  Peers that kept their half re-form it on the next invite.");
    Ok(())
}

/// The `(our_vid, their_vid)` pairs a `--peer` target names.
///
/// With `our`, exactly that pair — whatever state it is in. Without it, every
/// established pair with the peer; a peer with no established relationship is
/// an error rather than a silent no-op, so a typo in the DID is noticed.
async fn pairs_for(
    relationships: &KeyspaceRelationshipStore,
    peer: &str,
    our: Option<String>,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    if let Some(our) = our {
        return Ok(vec![(our, peer.to_string())]);
    }
    let pairs: Vec<_> = relationships
        .established_relationships()
        .await?
        .into_iter()
        .filter(|(_, their)| their == peer)
        .collect();
    if pairs.is_empty() {
        return Err(format!(
            "no established TSP relationship with `{peer}` (run `tsp-relationship-list`). \
             A half-formed one needs `--our <vid>`, or clear everything with \
             `tsp-relationship-delete --all`."
        )
        .into());
    }
    Ok(pairs)
}

fn format_age(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h {}m", s / 3600, (s % 3600) / 60),
        s => format!("{}d {}h", s / 86_400, (s % 86_400) / 3600),
    }
}

#[cfg(all(test, feature = "store-fjall"))]
mod tests {
    use super::*;

    fn store_config(dir: &tempfile::TempDir) -> StoreConfig {
        StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        }
    }

    /// Seed two established relationships and one half-formed one, then close
    /// the store so the command under test can take the lock.
    async fn seed(config: &StoreConfig) {
        let store = Store::open(config).await.expect("open store");
        let rel = open_relationship_store(&store).expect("relationship store");
        for peer in ["did:example:vta", "did:example:edge"] {
            rel.set("did:example:us", peer, RelationshipState::Bidirectional)
                .await
                .expect("seed established");
        }
        rel.set(
            "did:example:us",
            "did:example:half",
            RelationshipState::Pending,
        )
        .await
        .expect("seed pending");
        store.persist().await.expect("persist");
    }

    async fn state(config: &StoreConfig, peer: &str) -> RelationshipState {
        let store = Store::open(config).await.expect("open store");
        open_relationship_store(&store)
            .expect("relationship store")
            .get("did:example:us", peer)
            .await
            .expect("get")
    }

    #[tokio::test]
    async fn reset_returns_one_peer_to_none_and_leaves_the_rest() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = store_config(&dir);
        seed(&config).await;

        run_reset(
            &config,
            Target::Peer {
                peer: "did:example:vta".into(),
                our: None,
            },
        )
        .await
        .expect("reset");

        assert_eq!(
            state(&config, "did:example:vta").await,
            RelationshipState::None
        );
        assert_eq!(
            state(&config, "did:example:edge").await,
            RelationshipState::Bidirectional,
            "only the named peer is reset"
        );
    }

    #[tokio::test]
    async fn an_unknown_peer_is_an_error_not_a_silent_no_op() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = store_config(&dir);
        seed(&config).await;

        let err = run_reset(
            &config,
            Target::Peer {
                peer: "did:example:typo".into(),
                our: None,
            },
        )
        .await
        .expect_err("a peer with no relationship must be refused");
        assert!(err.to_string().contains("no established TSP relationship"));
    }

    /// A half-formed relationship is not enumerable through the store, so it is
    /// reachable only by naming the local VID.
    #[tokio::test]
    async fn a_half_formed_relationship_is_deleted_by_naming_the_local_vid() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = store_config(&dir);
        seed(&config).await;

        run_delete(
            &config,
            Target::Peer {
                peer: "did:example:half".into(),
                our: Some("did:example:us".into()),
            },
            false,
        )
        .await
        .expect("delete");

        assert_eq!(
            state(&config, "did:example:half").await,
            RelationshipState::None
        );
    }

    #[tokio::test]
    async fn delete_all_only_reports_without_yes_and_clears_everything_with_it() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = store_config(&dir);
        seed(&config).await;

        run_delete(&config, Target::All, false)
            .await
            .expect("dry run");
        assert_eq!(
            state(&config, "did:example:vta").await,
            RelationshipState::Bidirectional,
            "without --yes nothing is deleted"
        );

        run_delete(&config, Target::All, true)
            .await
            .expect("delete all");
        let store = Store::open(&config).await.expect("open store");
        assert_eq!(
            store
                .keyspace(KS_TSP_RELATIONSHIPS)
                .expect("keyspace")
                .approximate_len()
                .await
                .expect("len"),
            0,
            "--all removes half-formed records too"
        );
    }
}
