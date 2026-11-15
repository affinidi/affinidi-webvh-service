//! A page-at-a-time walk over a keyspace prefix, so an edge's periodic and
//! boot-time scans (registration, reconcile, cleanup, migrations) hold one
//! page of rows rather than every DID it hosts.

use did_hosting_common::server::store::{KeyspaceHandle, RawKvPair};

use crate::error::AppError;

/// Walks the pairs under a prefix with [`KeyspaceHandle::prefix_page_raw`];
/// on a backend that cannot page, it reads the whole prefix once instead. A
/// page may be empty while more follow; the walk ends when
/// [`Self::next_page`] answers `None`.
pub struct PageWalk<'a> {
    ks: &'a KeyspaceHandle,
    prefix: Vec<u8>,
    cursor: Option<Vec<u8>>,
    page_size: usize,
    done: bool,
}

impl<'a> PageWalk<'a> {
    pub fn new(ks: &'a KeyspaceHandle, prefix: impl Into<Vec<u8>>, page_size: usize) -> Self {
        Self {
            ks,
            prefix: prefix.into(),
            cursor: None,
            page_size,
            done: false,
        }
    }

    /// The next page's pairs, or `None` once the walk is complete.
    pub async fn next_page(&mut self) -> Result<Option<Vec<RawKvPair>>, AppError> {
        if self.done {
            return Ok(None);
        }
        match self
            .ks
            .prefix_page_raw(self.prefix.clone(), self.cursor.take(), self.page_size)
            .await?
        {
            Some(page) => {
                self.cursor = page.next;
                self.done = self.cursor.is_none();
                Ok(Some(page.rows))
            }
            None => {
                self.done = true;
                Ok(Some(self.ks.prefix_iter_raw(self.prefix.clone()).await?))
            }
        }
    }
}

/// Rows an edge reads a page of DID records at.
pub const DID_PAGE_ROWS: usize = 256;
