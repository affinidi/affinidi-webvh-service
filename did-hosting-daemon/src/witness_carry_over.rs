//! A one-off copy of the witness's rows into the witness store's own key
//! namespace, for a daemon whose two stores share one DynamoDB single table.
//!
//! Before the daemon gave its witness store a namespace on a shared table
//! (`config::separate_witness_store`), both stores read and wrote the same
//! partitions: the witness's `acl` was the control plane's ACL, and its signed
//! proofs (`witnesses`) sat beside the control plane's rows. Once the witness
//! store is namespaced, those rows are out of its sight, so an upgraded
//! daemon's witness would start with no ACL and none of its proofs. This copies
//! them across once, on the first boot with the namespace, so the witness keeps
//! the access it had and the proofs it signed.
//!
//! - **Once.** A marker in the witness store's `meta` keyspace records that it
//!   ran; later boots do nothing, so the two ACLs are free to diverge.
//! - **Never over the witness's own rows.** A keyspace the namespace already
//!   holds rows in is left alone: the witness has written there, and an older
//!   shared row must not undo it (a revoked entry coming back).
//! - **Source rows stay.** The main store keeps its ACL, and a rollback to a
//!   build without the namespace finds the witness's rows where it left them.
//! - **Re-runnable.** The copy is idempotent and the marker is written last,
//!   so a boot that fails part-way copies again from the top.

use did_hosting_common::server::error::AppError;
use did_hosting_common::server::migrations::AppliedMarker;
use did_hosting_common::server::store::{KS_ACL, KS_META, KS_WITNESSES, Store};

/// The marker's key in the witness store's `meta` keyspace, in the migration
/// runner's `migration:applied:{id}` form. Never rename: deployed stores
/// carry it.
const MARKER_KEY: &str = "migration:applied:witness_namespace_carry_over";

const DESCRIPTION: &str = "copy the witness's acl and witnesses rows from the shared \
     partitions into the witness store's namespace";

/// The witness's keyspaces that shared the main store's partitions.
const KEYSPACES: [&str; 2] = [KS_ACL, KS_WITNESSES];

/// What a carry-over did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CarryOver {
    /// The marker was present: an earlier boot did it.
    AlreadyDone,
    /// Rows copied per keyspace; a keyspace the namespace already held rows
    /// in is listed as skipped.
    Done {
        copied: Vec<(&'static str, usize)>,
        skipped: Vec<&'static str>,
    },
}

/// Copy the witness's rows from `main` (the shared, un-namespaced partitions)
/// into `witness` (the namespaced store), once.
pub(crate) async fn carry_over_witness_rows(
    main: &Store,
    witness: &Store,
) -> Result<CarryOver, AppError> {
    let meta = witness.keyspace_consistent(KS_META)?;
    if meta.contains_key(MARKER_KEY).await? {
        return Ok(CarryOver::AlreadyDone);
    }

    let mut copied = Vec::new();
    let mut skipped = Vec::new();
    for name in KEYSPACES {
        let target = witness.keyspace_consistent_with_scans(name)?;
        if !target.iter_all().await?.is_empty() {
            skipped.push(name);
            continue;
        }
        let rows = main
            .keyspace_consistent_with_scans(name)?
            .iter_all()
            .await?;
        if rows.is_empty() {
            copied.push((name, 0));
            continue;
        }
        let count = rows.len();
        let mut batch = witness.batch();
        for (key, value) in rows {
            batch.insert_raw(&target, key, value);
        }
        // Not atomic on DynamoDB past one transaction's bound; safe because
        // the copy is idempotent and the marker comes after it.
        batch.commit_in_parts().await?;
        copied.push((name, count));
    }

    let marker = AppliedMarker {
        applied_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        description: DESCRIPTION.to_string(),
    };
    meta.insert(MARKER_KEY, &marker).await?;
    Ok(CarryOver::Done { copied, skipped })
}

#[cfg(all(test, feature = "store-fjall"))]
mod tests {
    use super::*;
    use did_hosting_common::server::config::StoreConfig;

    /// Two stores standing in for the shared partitions and the witness's
    /// namespace. The copy uses only the store API, so the backend does not
    /// change what it does; the namespace itself is covered by the
    /// single-table backend's tests.
    async fn stores() -> (Store, Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let open = |sub: &str| StoreConfig {
            data_dir: dir.path().join(sub),
            ..StoreConfig::default()
        };
        let main = Store::open(&open("main")).await.expect("main store");
        let witness = Store::open(&open("witness")).await.expect("witness store");
        (main, witness, dir)
    }

    async fn put(store: &Store, ks: &str, key: &str, value: &str) {
        store
            .keyspace(ks)
            .expect("keyspace")
            .insert_raw(key, value.as_bytes().to_vec())
            .await
            .expect("insert");
    }

    async fn rows(store: &Store, ks: &str) -> Vec<(String, String)> {
        store
            .keyspace(ks)
            .expect("keyspace")
            .iter_all()
            .await
            .expect("iter")
            .into_iter()
            .map(|(k, v)| {
                (
                    String::from_utf8(k).expect("utf8"),
                    String::from_utf8(v).expect("utf8"),
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn test_carry_over_copies_the_shared_acl_and_proofs_and_leaves_the_source() {
        let (main, witness, _dir) = stores().await;
        put(&main, KS_ACL, "acl:did:example:admin", "admin").await;
        put(&main, KS_WITNESSES, "witnesses:abc", "proof").await;

        let outcome = carry_over_witness_rows(&main, &witness)
            .await
            .expect("carry over");

        assert_eq!(
            outcome,
            CarryOver::Done {
                copied: vec![(KS_ACL, 1), (KS_WITNESSES, 1)],
                skipped: vec![],
            }
        );
        assert_eq!(
            rows(&witness, KS_ACL).await,
            vec![("acl:did:example:admin".into(), "admin".into())]
        );
        assert_eq!(
            rows(&witness, KS_WITNESSES).await,
            vec![("witnesses:abc".into(), "proof".into())]
        );
        assert_eq!(
            rows(&main, KS_ACL).await.len(),
            1,
            "the control plane's ACL must stay where it is"
        );
        assert_eq!(
            rows(&main, KS_WITNESSES).await.len(),
            1,
            "kept for a rollback"
        );
    }

    #[tokio::test]
    async fn test_carry_over_runs_once_so_the_acls_can_diverge() {
        let (main, witness, _dir) = stores().await;
        put(&main, KS_ACL, "acl:did:example:admin", "admin").await;
        carry_over_witness_rows(&main, &witness)
            .await
            .expect("first boot");

        // The witness revokes the admin; the control plane adds someone.
        witness
            .keyspace(KS_ACL)
            .expect("keyspace")
            .remove("acl:did:example:admin")
            .await
            .expect("revoke");
        put(&main, KS_ACL, "acl:did:example:other", "admin").await;

        let outcome = carry_over_witness_rows(&main, &witness)
            .await
            .expect("second boot");

        assert_eq!(outcome, CarryOver::AlreadyDone);
        assert!(
            rows(&witness, KS_ACL).await.is_empty(),
            "a later boot must neither restore the revoked entry nor copy new ones"
        );
    }

    #[tokio::test]
    async fn test_carry_over_never_writes_over_rows_the_witness_already_has() {
        let (main, witness, _dir) = stores().await;
        put(&main, KS_ACL, "acl:did:example:admin", "admin").await;
        put(&main, KS_WITNESSES, "witnesses:abc", "old proof").await;
        // A daemon that already ran with the namespace before this copy existed.
        put(&witness, KS_ACL, "acl:did:example:witness-admin", "admin").await;

        let outcome = carry_over_witness_rows(&main, &witness)
            .await
            .expect("carry over");

        assert_eq!(
            outcome,
            CarryOver::Done {
                copied: vec![(KS_WITNESSES, 1)],
                skipped: vec![KS_ACL],
            }
        );
        assert_eq!(
            rows(&witness, KS_ACL).await,
            vec![("acl:did:example:witness-admin".into(), "admin".into())]
        );
    }

    #[tokio::test]
    async fn test_carry_over_of_an_empty_store_still_marks_it_done() {
        let (main, witness, _dir) = stores().await;
        let first = carry_over_witness_rows(&main, &witness)
            .await
            .expect("first boot");
        assert_eq!(
            first,
            CarryOver::Done {
                copied: vec![(KS_ACL, 0), (KS_WITNESSES, 0)],
                skipped: vec![],
            }
        );

        // An admin added to the control plane after the first boot is not the
        // witness's: the stores are separate from here on.
        put(&main, KS_ACL, "acl:did:example:admin", "admin").await;
        assert_eq!(
            carry_over_witness_rows(&main, &witness)
                .await
                .expect("second boot"),
            CarryOver::AlreadyDone
        );
        assert!(rows(&witness, KS_ACL).await.is_empty());
    }
}

/// The upgrade itself, on one DynamoDB table: rows written by a daemon whose
/// stores shared the table's partitions, read back through the witness store
/// under its namespace.
///
/// Needs DynamoDB Local or LocalStack and a table with `pk` (HASH, S) and
/// `sk` (RANGE, S):
///
/// ```bash
/// aws --endpoint-url http://localhost:4566 dynamodb create-table \
///   --table-name carry-over --billing-mode PAY_PER_REQUEST \
///   --attribute-definitions AttributeName=pk,AttributeType=S AttributeName=sk,AttributeType=S \
///   --key-schema AttributeName=pk,KeyType=HASH AttributeName=sk,KeyType=RANGE
/// DYNAMODB_SINGLE_TEST_ENDPOINT=http://localhost:4566 CARRY_OVER_TEST_TABLE=carry-over \
///   cargo test -p did-hosting-daemon --no-default-features \
///   --features store-dynamodb-single,did-methods --bin did-hosting-daemon \
///   witness_carry_over -- --ignored
/// ```
#[cfg(all(test, feature = "store-dynamodb-single"))]
mod single_table_tests {
    use super::*;
    use did_hosting_common::server::config::StoreConfig;

    async fn open(endpoint: &str, table: &str, namespace: Option<&str>) -> Store {
        // SAFETY: test-only; the AWS SDK reads these when the store opens, and
        // this ignored test runs on its own.
        unsafe {
            std::env::set_var("AWS_ENDPOINT_URL", endpoint);
            std::env::set_var("AWS_ACCESS_KEY_ID", "test");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        }
        Store::open(&StoreConfig {
            dynamodb_table_name: Some(table.to_string()),
            dynamodb_region: Some("us-east-1".to_string()),
            dynamodb_key_namespace: namespace.map(str::to_string),
            ..StoreConfig::default()
        })
        .await
        .expect("open single-table store")
    }

    #[tokio::test]
    #[ignore = "needs DYNAMODB_SINGLE_TEST_ENDPOINT and CARRY_OVER_TEST_TABLE; see the module docs"]
    async fn test_an_upgraded_daemons_witness_sees_its_shared_rows_under_its_namespace() {
        let endpoint = std::env::var("DYNAMODB_SINGLE_TEST_ENDPOINT").expect("endpoint");
        let table = std::env::var("CARRY_OVER_TEST_TABLE").expect("table");
        let main = open(&endpoint, &table, None).await;
        let witness = open(&endpoint, &table, Some("witness")).await;
        let suffix = uuid::Uuid::new_v4();
        let acl_key = format!("acl:did:example:{suffix}");
        let proof_key = format!("witnesses:{suffix}");

        // What the old build left: the witness's rows in the shared partitions.
        main.keyspace(KS_ACL)
            .expect("acl")
            .insert_raw(acl_key.clone(), b"admin".to_vec())
            .await
            .expect("seed acl");
        main.keyspace(KS_WITNESSES)
            .expect("witnesses")
            .insert_raw(proof_key.clone(), b"proof".to_vec())
            .await
            .expect("seed proof");
        let witness_acl = witness.keyspace_consistent(KS_ACL).expect("acl");
        assert_eq!(
            witness_acl.get_raw(acl_key.clone()).await.expect("read"),
            None,
            "the namespace hides the shared rows: the upgrade problem"
        );

        let outcome = carry_over_witness_rows(&main, &witness)
            .await
            .expect("carry over");

        assert!(matches!(outcome, CarryOver::Done { .. }), "{outcome:?}");
        assert_eq!(
            witness_acl.get_raw(acl_key.clone()).await.expect("read"),
            Some(b"admin".to_vec())
        );
        assert_eq!(
            witness
                .keyspace_consistent(KS_WITNESSES)
                .expect("witnesses")
                .get_raw(proof_key)
                .await
                .expect("read"),
            Some(b"proof".to_vec())
        );
        assert_eq!(
            main.keyspace_consistent(KS_ACL)
                .expect("acl")
                .get_raw(acl_key)
                .await
                .expect("read"),
            Some(b"admin".to_vec()),
            "the control plane's ACL stays"
        );
        assert_eq!(
            carry_over_witness_rows(&main, &witness)
                .await
                .expect("second boot"),
            CarryOver::AlreadyDone
        );
    }
}
