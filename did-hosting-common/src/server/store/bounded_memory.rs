//! An in-memory backend with the batch ceiling of a transactional store, for
//! tests of code that writes in bulk.
//!
//! A batch over `max_ops` is refused whole, as the DynamoDB single-table backend
//! refuses one over its transaction limit. Knobs make a given commit fail, and
//! make the backend report that a failed commit may have written part of a batch,
//! so callers can be tested against both kinds of backend without a database.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use crate::server::error::AppError;

use super::{BatchLimits, BatchOps, KeyspaceOps, RawKvPair, StorageBackend, Store};

type Fut<T> = Pin<Box<dyn Future<Output = T> + Send>>;
type Rows = Arc<Mutex<HashMap<String, BTreeMap<Vec<u8>, Vec<u8>>>>>;

/// See the module docs.
#[derive(Clone)]
pub struct BoundedMemory {
    rows: Rows,
    limits: BatchLimits,
    fail_commit: Option<usize>,
    commits: Arc<Mutex<Vec<usize>>>,
    atomic: bool,
}

impl BoundedMemory {
    /// A backend whose atomic write holds at most `max_ops` operations.
    pub fn new(max_ops: usize) -> Self {
        Self {
            rows: Rows::default(),
            limits: BatchLimits {
                max_ops,
                max_bytes: 4 * 1024 * 1024,
            },
            fail_commit: None,
            commits: Arc::default(),
            atomic: true,
        }
    }

    /// Make the `n`-th commit (0-based) fail without writing anything.
    pub fn fail_commit(mut self, n: usize) -> Self {
        self.fail_commit = Some(n);
        self
    }

    /// Report that a failed commit may have written part of its batch.
    pub fn non_atomic(mut self) -> Self {
        self.atomic = false;
        self
    }

    /// A [`Store`] over this backend. Clones share the rows.
    pub fn store(&self) -> Store {
        Store::from_backend(Arc::new(self.clone()))
    }

    /// Operation counts of the commits that went through, in order.
    pub fn committed_batch_sizes(&self) -> Vec<usize> {
        self.commits
            .lock()
            .unwrap()
            .iter()
            .copied()
            .filter(|n| *n != usize::MAX)
            .collect()
    }
}

struct Keyspace {
    name: String,
    rows: Rows,
}

impl KeyspaceOps for Keyspace {
    fn insert_raw(&self, key: Vec<u8>, value: Vec<u8>) -> Fut<Result<(), AppError>> {
        self.rows
            .lock()
            .unwrap()
            .entry(self.name.clone())
            .or_default()
            .insert(key, value);
        Box::pin(async { Ok(()) })
    }
    fn get_raw(&self, key: Vec<u8>) -> Fut<Result<Option<Vec<u8>>, AppError>> {
        let v = self
            .rows
            .lock()
            .unwrap()
            .get(&self.name)
            .and_then(|m| m.get(&key).cloned());
        Box::pin(async move { Ok(v) })
    }
    fn remove(&self, key: Vec<u8>) -> Fut<Result<(), AppError>> {
        if let Some(m) = self.rows.lock().unwrap().get_mut(&self.name) {
            m.remove(&key);
        }
        Box::pin(async { Ok(()) })
    }
    fn contains_key(&self, key: Vec<u8>) -> Fut<Result<bool, AppError>> {
        let v = self
            .rows
            .lock()
            .unwrap()
            .get(&self.name)
            .is_some_and(|m| m.contains_key(&key));
        Box::pin(async move { Ok(v) })
    }
    fn prefix_iter_raw(&self, prefix: Vec<u8>) -> Fut<Result<Vec<RawKvPair>, AppError>> {
        let v = self
            .rows
            .lock()
            .unwrap()
            .get(&self.name)
            .map(|m| {
                m.iter()
                    .filter(|(k, _)| k.starts_with(&prefix))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default();
        Box::pin(async move { Ok(v) })
    }
    fn take_raw_atomic(&self, key: Vec<u8>) -> Fut<Result<Option<Vec<u8>>, AppError>> {
        let v = self
            .rows
            .lock()
            .unwrap()
            .get_mut(&self.name)
            .and_then(|m| m.remove(&key));
        Box::pin(async move { Ok(v) })
    }
    fn incr_raw(&self, key: Vec<u8>) -> Fut<Result<u64, AppError>> {
        let mut rows = self.rows.lock().unwrap();
        let m = rows.entry(self.name.clone()).or_default();
        let next = m
            .get(&key)
            .and_then(|v| std::str::from_utf8(v).ok()?.parse::<u64>().ok())
            .unwrap_or(0)
            + 1;
        m.insert(key, next.to_string().into_bytes());
        Box::pin(async move { Ok(next) })
    }
}

struct Batch {
    backend: BoundedMemory,
    ops: Vec<(String, Vec<u8>, Option<Vec<u8>>)>,
}

impl BatchOps for Batch {
    fn insert_raw(&mut self, keyspace: &str, key: Vec<u8>, value: Vec<u8>) {
        self.ops.push((keyspace.to_string(), key, Some(value)));
    }
    fn remove(&mut self, keyspace: &str, key: Vec<u8>) {
        self.ops.push((keyspace.to_string(), key, None));
    }
    fn commit(self: Box<Self>) -> Fut<Result<(), AppError>> {
        let b = *self;
        let result = {
            let mut commits = b.backend.commits.lock().unwrap();
            let attempt = commits.len();
            if b.ops.len() > b.backend.limits.max_ops {
                Err(AppError::Validation(format!(
                    "batch of {} operations is over the limit of {}",
                    b.ops.len(),
                    b.backend.limits.max_ops
                )))
            } else if b.backend.fail_commit == Some(attempt) {
                commits.push(usize::MAX); // marks the failed attempt
                Err(AppError::Internal("injected commit failure".into()))
            } else {
                commits.push(b.ops.len());
                let mut rows = b.backend.rows.lock().unwrap();
                for (ks, key, value) in b.ops {
                    let m = rows.entry(ks).or_default();
                    match value {
                        Some(v) => m.insert(key, v),
                        None => m.remove(&key),
                    };
                }
                Ok(())
            }
        };
        Box::pin(async move { result })
    }
}

impl StorageBackend for BoundedMemory {
    fn keyspace(&self, name: &str) -> Result<(String, Arc<dyn KeyspaceOps>), AppError> {
        Ok((
            name.to_string(),
            Arc::new(Keyspace {
                name: name.to_string(),
                rows: self.rows.clone(),
            }),
        ))
    }
    fn batch(&self) -> Box<dyn BatchOps> {
        Box::new(Batch {
            backend: self.clone(),
            ops: Vec::new(),
        })
    }
    fn persist(&self) -> Fut<Result<(), AppError>> {
        Box::pin(async { Ok(()) })
    }
    fn batch_limits(&self) -> Option<BatchLimits> {
        Some(self.limits)
    }
    fn commits_atomically(&self) -> bool {
        self.atomic
    }
}
