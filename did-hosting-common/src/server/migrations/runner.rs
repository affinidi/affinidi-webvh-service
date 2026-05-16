//! [`MigrationRunner`] — walks a registered list of migrations in order,
//! skipping any whose applied-marker is already present.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::super::error::AppError;
use super::super::store::Store;
use super::{AppliedMarker, Migration, applied_key, meta_keyspace};

/// Outcome of one runner invocation. Useful for boot-time logging and
/// integration-test assertions.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunSummary {
    /// Migrations whose marker was missing and that completed successfully.
    pub applied: Vec<String>,
    /// Migrations skipped because the marker was already present.
    pub skipped: Vec<String>,
}

impl RunSummary {
    pub fn total(&self) -> usize {
        self.applied.len() + self.skipped.len()
    }
}

/// Idempotent runner. Hand it the registered migrations and a [`Store`];
/// it does the rest.
pub struct MigrationRunner {
    migrations: Vec<Arc<dyn Migration>>,
}

impl MigrationRunner {
    pub fn new(migrations: Vec<Arc<dyn Migration>>) -> Self {
        Self { migrations }
    }

    /// Walk the registered list in order. For each migration:
    ///   1. Skip if `meta:migration:applied:{id}` exists.
    ///   2. Otherwise call `run`. On `Ok`, write the marker and continue.
    ///   3. On `Err`, return immediately without writing a marker — the
    ///      next boot retries from this migration's top.
    pub async fn run_pending(&self, store: &Store) -> Result<RunSummary, AppError> {
        let meta = meta_keyspace(store)?;
        let mut summary = RunSummary::default();

        for migration in &self.migrations {
            let id = migration.id();
            let key = applied_key(id);

            let already_applied = meta.contains_key(key.as_bytes().to_vec()).await?;
            if already_applied {
                tracing::debug!(migration_id = id, "migration already applied; skipping");
                summary.skipped.push(id.to_string());
                continue;
            }

            tracing::info!(
                migration_id = id,
                description = migration.description(),
                "applying migration"
            );

            // Fails fast: a migration that returns Err leaves no marker,
            // so the next runner invocation re-attempts it from the top.
            migration.run(store).await?;

            let marker = AppliedMarker::now(migration.description().to_string());
            meta.insert(key.as_bytes().to_vec(), &marker).await?;

            tracing::info!(migration_id = id, "migration applied");
            summary.applied.push(id.to_string());
        }

        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    use crate::server::config::StoreConfig;
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn fjall_store() -> Store {
        // The fjall backend can write to a temp dir without external
        // infra. Other backends are out of scope for the runner's own
        // tests — their `KeyspaceOps` implementations are covered
        // elsewhere. `StoreConfig` selects fjall when the `store-fjall`
        // feature is compiled in and no cloud-backend fields are set.
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            redis_url: None,
            dynamodb_table_prefix: None,
            dynamodb_region: None,
            firestore_project: None,
            firestore_database: None,
            cosmosdb_connection_string: None,
            cosmosdb_database: None,
            cosmosdb_region: None,
        };
        // Leak the tempdir so the path stays valid for the duration of
        // the test process. Acceptable in tests; fjall holds an internal
        // file handle anyway.
        std::mem::forget(dir);
        Store::open(&cfg).await.expect("open fjall store")
    }

    struct CountingMigration {
        id: &'static str,
        runs: Arc<AtomicUsize>,
        should_fail: bool,
    }

    impl Migration for CountingMigration {
        fn id(&self) -> &'static str {
            self.id
        }
        fn description(&self) -> &'static str {
            "test migration"
        }
        fn run<'a>(&'a self, _store: &'a Store) -> MigrationFuture<'a> {
            Box::pin(async move {
                self.runs.fetch_add(1, Ordering::SeqCst);
                if self.should_fail {
                    Err(AppError::Internal("migration intentionally failed".into()))
                } else {
                    Ok(())
                }
            })
        }
    }

    #[tokio::test]
    async fn empty_set_runs_cleanly_on_fresh_store() {
        let store = fjall_store().await;
        let runner = MigrationRunner::new(vec![]);
        let summary = runner
            .run_pending(&store)
            .await
            .expect("empty set must succeed");
        assert!(summary.applied.is_empty());
        assert!(summary.skipped.is_empty());
        assert_eq!(summary.total(), 0);
    }

    #[tokio::test]
    async fn first_run_applies_then_subsequent_skip() {
        let store = fjall_store().await;
        let runs = Arc::new(AtomicUsize::new(0));
        let migrations: Vec<Arc<dyn Migration>> = vec![Arc::new(CountingMigration {
            id: "m_test_apply_then_skip",
            runs: runs.clone(),
            should_fail: false,
        })];

        let summary = MigrationRunner::new(migrations.clone())
            .run_pending(&store)
            .await
            .expect("first run");
        assert_eq!(summary.applied, vec!["m_test_apply_then_skip"]);
        assert!(summary.skipped.is_empty());
        assert_eq!(runs.load(Ordering::SeqCst), 1);

        let summary2 = MigrationRunner::new(migrations)
            .run_pending(&store)
            .await
            .expect("second run");
        assert!(summary2.applied.is_empty());
        assert_eq!(summary2.skipped, vec!["m_test_apply_then_skip"]);
        // Confirm the migration's body did NOT run a second time.
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "migration body must not re-run once applied marker is written"
        );
    }

    #[tokio::test]
    async fn failing_migration_does_not_get_marker_and_retries_next_boot() {
        let store = fjall_store().await;
        let runs = Arc::new(AtomicUsize::new(0));

        // First run: fail-by-design.
        let failing: Vec<Arc<dyn Migration>> = vec![Arc::new(CountingMigration {
            id: "m_test_fail",
            runs: runs.clone(),
            should_fail: true,
        })];
        let err = MigrationRunner::new(failing)
            .run_pending(&store)
            .await
            .expect_err("must surface migration error");
        assert!(err.to_string().contains("intentionally failed"));
        assert_eq!(runs.load(Ordering::SeqCst), 1);

        // The marker MUST NOT have been written. Verify directly to lock
        // the contract — a future change that writes the marker before
        // checking the Result would break this assertion.
        let meta = meta_keyspace(&store).expect("meta keyspace");
        let marker = meta
            .get_raw(applied_key("m_test_fail").as_bytes().to_vec())
            .await
            .expect("get_raw");
        assert!(
            marker.is_none(),
            "applied marker must NOT exist after a failed migration"
        );

        // Second run: succeed this time. Must re-attempt and mark applied.
        let succeeding: Vec<Arc<dyn Migration>> = vec![Arc::new(CountingMigration {
            id: "m_test_fail",
            runs: runs.clone(),
            should_fail: false,
        })];
        let summary = MigrationRunner::new(succeeding)
            .run_pending(&store)
            .await
            .expect("retry must succeed");
        assert_eq!(summary.applied, vec!["m_test_fail"]);
        assert_eq!(
            runs.load(Ordering::SeqCst),
            2,
            "retried migration body must execute the second time"
        );
    }

    #[tokio::test]
    async fn migrations_run_in_registration_order() {
        let store = fjall_store().await;
        let runs_a = Arc::new(AtomicUsize::new(0));
        let runs_b = Arc::new(AtomicUsize::new(0));

        // B's run reads A's marker — if order is wrong, B sees nothing.
        struct OrderedMigration {
            id: &'static str,
            runs: Arc<AtomicUsize>,
            require_prior_id: Option<&'static str>,
        }
        impl Migration for OrderedMigration {
            fn id(&self) -> &'static str {
                self.id
            }
            fn run<'a>(&'a self, store: &'a Store) -> MigrationFuture<'a> {
                Box::pin(async move {
                    if let Some(prior) = self.require_prior_id {
                        let meta = meta_keyspace(store)?;
                        let present = meta
                            .contains_key(applied_key(prior).as_bytes().to_vec())
                            .await?;
                        if !present {
                            return Err(AppError::Internal(format!(
                                "expected prior migration {prior} to be applied"
                            )));
                        }
                    }
                    self.runs.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
            }
        }

        let migrations: Vec<Arc<dyn Migration>> = vec![
            Arc::new(OrderedMigration {
                id: "m_order_a",
                runs: runs_a.clone(),
                require_prior_id: None,
            }),
            Arc::new(OrderedMigration {
                id: "m_order_b",
                runs: runs_b.clone(),
                require_prior_id: Some("m_order_a"),
            }),
        ];
        let summary = MigrationRunner::new(migrations)
            .run_pending(&store)
            .await
            .expect("ordered run must succeed");
        assert_eq!(summary.applied, vec!["m_order_a", "m_order_b"]);
        assert_eq!(runs_a.load(Ordering::SeqCst), 1);
        assert_eq!(runs_b.load(Ordering::SeqCst), 1);
    }
}
