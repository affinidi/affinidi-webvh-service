//! Page sizes for an edge's periodic and boot-time scans (registration,
//! reconcile, cleanup, migrations), which walk the store a page at a time
//! with [`did_hosting_common::server::store::KeyspaceHandle::walk`] so they
//! hold one page of rows rather than every DID the edge hosts.

/// Rows an edge reads a page of DID records at.
pub const DID_PAGE_ROWS: usize = 256;
