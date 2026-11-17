//! The paged `did/list` listing ([`list_dids_page`]) and the owner-on-domain
//! lookup.

use did_hosting_common::did_ops::{DidRecord, agent_name_key, did_key, owner_key};
use did_hosting_common::server::did_index;
use tracing::debug;

use crate::auth::AuthClaims;
use crate::server::AppState;
use did_hosting_common::server::error::AppError;

/// What a `did/list` page is narrowed to, beyond the caller's own scope.
#[derive(Debug, Default, Clone, Copy)]
pub struct ListFilter<'a> {
    /// Admin only: one owner's slots.
    pub owner: Option<&'a str>,
    /// Canonical hosting domain: only slots hosted under it.
    pub domain: Option<&'a str>,
    /// Case-insensitive substring of the mnemonic, DID or an agent name.
    pub search: Option<&'a str>,
    /// An exact agent name, held on `domain` (required with it): answered
    /// from the name index, so at most one slot.
    pub agent_name: Option<&'a str>,
}

/// One page of [`list_dids_page`].
#[derive(Debug, Default)]
pub struct ListPage {
    /// The page's slots in mnemonic order, each with its lifetime resolves.
    pub records: Vec<(DidRecord, u64)>,
    /// Where the next page starts (strictly after this), or `None` when the
    /// listing is complete. Not always the last record's mnemonic: a page
    /// whose scan budget ran out before it filled ends where the scan did.
    pub resume_after: Option<String>,
}

/// The most slots one `did/list` page returns.
pub(super) const MAX_LIST_LIMIT: usize = 1000;
/// Rows one page of a listing's store walk reads.
pub(super) const LIST_WALK_ROWS: usize = 256;
/// Rows a filtered page reads before returning what it has (with a cursor
/// where the scan stopped), so a selective filter cannot make one request
/// read the whole store. Only a key-ordered store can resume mid-walk; any
/// other reads it all (see [`list_dids_page`]).
pub(super) const LIST_SCAN_BUDGET: usize = 5000;

/// One page of the slots a caller may see, with each slot's lifetime resolve
/// count.
///
/// The scoping rule: an admin sees every slot, or one owner's when
/// `filter.owner` names one; anyone else sees their own. Refusing a
/// non-admin who names another owner is the caller's job — this never
/// widens a non-admin's view, whatever it is passed. `replica` is set when the
/// caller is a hosting server this control plane drives, reconciling against
/// the full listing (see `control_tasks::did::list`): with no owner filter it
/// is shown every slot, as an administrator is.
///
/// Ordered by mnemonic, and the page starts strictly after `after` (a
/// previous page's [`ListPage::resume_after`]), so paging is stable under
/// concurrent writes: a slot added or removed between pages is seen or not,
/// but no present slot is repeated or skipped.
///
/// How the page is read depends on the store:
///
/// - **Key-ordered (fjall, Redis).** The walk starts at `after` in the
///   narrowest source that covers the scope — the `owner:` index, the
///   `domain:` index ([`did_index`]) or the `did:` records — and stops once
///   the page is full, so an unfiltered page reads about `limit` rows
///   whatever the store holds. A `search` reads at most
///   `LIST_SCAN_BUDGET` rows a page.
/// - **Hash-ordered (DynamoDB, Cosmos DB, Firestore).** Pages are not in key
///   order, so the only correct page is a full walk of the records keeping
///   the `limit` smallest mnemonics after `after` — memory stays at one page,
///   but each page reads every record. The order and the cursor are the same
///   as on a key-ordered store.
pub async fn list_dids_page(
    auth: &AuthClaims,
    replica: bool,
    state: &AppState,
    filter: &ListFilter<'_>,
    limit: Option<usize>,
    after: Option<&str>,
) -> Result<ListPage, AppError> {
    use did_hosting_common::server::acl::Role;

    let limit = limit.unwrap_or(MAX_LIST_LIMIT).clamp(1, MAX_LIST_LIMIT);
    let target_owner = if (auth.role == Role::Admin || replica) && filter.owner.is_none() {
        None
    } else if auth.role == Role::Admin {
        Some(filter.owner.unwrap_or(&auth.did))
    } else {
        Some(auth.did.as_str())
    };
    let domain = filter.domain.map(str::to_ascii_lowercase);
    let search = filter
        .search
        .map(str::to_lowercase)
        .filter(|s| !s.is_empty());
    let matches = |record: &DidRecord| -> bool {
        target_owner.is_none_or(|o| record.owner == o)
            && domain
                .as_deref()
                .is_none_or(|d| did_index::record_domain(record).as_deref() == Some(d))
            && search
                .as_deref()
                .is_none_or(|s| record_matches_search(record, s))
            && filter
                .agent_name
                .is_none_or(|n| record.agent_names.iter().any(|e| e.name == n))
    };

    let (records, resume_after) = if let Some(name) = filter.agent_name {
        // The name index names the one slot that can hold it.
        let Some(domain) = domain.as_deref() else {
            return Err(AppError::invalid("`agentName` needs a `domain`"));
        };
        let holder = state
            .dids_ks
            .get_raw(agent_name_key(domain, name))
            .await?
            .and_then(|m| String::from_utf8(m).ok())
            .filter(|m| after.is_none_or(|a| m.as_str() > a));
        let mut out = Vec::new();
        if let Some(m) = holder
            && let Some(record) = state.dids_ks.get::<DidRecord>(did_key(&m)).await?
            && matches(&record)
        {
            out.push(record);
        }
        (out, None)
    } else if state.dids_ks.pages_in_key_order() {
        list_in_key_order(
            state,
            target_owner,
            domain.as_deref(),
            &matches,
            limit,
            after,
        )
        .await?
    } else {
        list_by_full_walk(state, &matches, limit, after).await?
    };

    let mut page = ListPage {
        records: Vec::with_capacity(records.len()),
        resume_after,
    };
    for record in records {
        let stats = crate::stats_admin::live_did_stats(state, &record.mnemonic).await?;
        page.records.push((record, stats.total_resolves));
    }
    debug!(
        did = %auth.did,
        returned = page.records.len(),
        more = page.resume_after.is_some(),
        "DID page listed on control plane"
    );
    Ok(page)
}

/// Whether `search` (lowercased) is in the record's mnemonic, DID or one of
/// its agent names.
pub(super) fn record_matches_search(record: &DidRecord, search: &str) -> bool {
    record.mnemonic.to_lowercase().contains(search)
        || record
            .did_id
            .as_deref()
            .is_some_and(|d| d.to_lowercase().contains(search))
        || record
            .agent_names
            .iter()
            .any(|e| e.name.to_lowercase().contains(search))
}

/// The mnemonics of `owner`'s slots hosted under `domain` (canonical), from
/// the owner's index: one record read per slot the owner holds, bounded by
/// its quota rather than by the store.
pub async fn owner_mnemonics_on_domain(
    state: &AppState,
    owner: &str,
    domain: &str,
) -> Result<Vec<String>, AppError> {
    let domain = domain.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut walk = state.dids_ks.walk(owner_key(owner, ""), LIST_WALK_ROWS);
    while let Some(rows) = walk.next_page().await? {
        for (key, value) in rows {
            let Some(m) = did_index::index_row_mnemonic(&key, &value, |m| owner_key(owner, m))
            else {
                continue;
            };
            if let Some(record) = state.dids_ks.get::<DidRecord>(did_key(&m)).await?
                && record.owner == owner
                && did_index::record_domain(&record).as_deref() == Some(domain.as_str())
            {
                out.push(m);
            }
        }
    }
    Ok(out)
}

/// [`list_dids_page`] on a key-ordered store: walk the narrowest source from
/// `after`, stopping once the page has `limit` slots and one more proves
/// another page follows, or the scan budget is spent.
pub(super) async fn list_in_key_order(
    state: &AppState,
    owner: Option<&str>,
    domain: Option<&str>,
    matches: &(dyn Fn(&DidRecord) -> bool + Sync),
    limit: usize,
    after: Option<&str>,
) -> Result<(Vec<DidRecord>, Option<String>), AppError> {
    // The source: an index whose rows name a mnemonic (re-checked against
    // the key, since an index prefix can also hold a longer neighbour's
    // rows), or the records themselves.
    enum Source {
        Index(Box<dyn Fn(&str) -> String + Send + Sync>),
        Records,
    }
    let (prefix, source) = match (owner, domain) {
        (Some(owner), _) => {
            let owner = owner.to_string();
            (
                owner_key(&owner, ""),
                Source::Index(Box::new(move |m| owner_key(&owner, m))),
            )
        }
        (None, Some(domain)) => {
            let domain = domain.to_string();
            (
                did_index::domain_index_prefix(&domain),
                Source::Index(Box::new(move |m| did_index::domain_index_key(&domain, m))),
            )
        }
        (None, None) => ("did:".to_string(), Source::Records),
    };
    let start = after.map(|a| format!("{prefix}{a}").into_bytes());
    let mut walk = state
        .dids_ks
        .walk_after(prefix.clone(), start, LIST_WALK_ROWS);

    let mut out: Vec<DidRecord> = Vec::new();
    let mut scanned = 0usize;
    // The key suffix of the last row read: where a cut-short page resumes.
    let mut last_read: Option<String> = None;
    while let Some(rows) = walk.next_page().await? {
        for (key, value) in rows {
            scanned += 1;
            let suffix = key
                .get(prefix.len()..)
                .and_then(|s| std::str::from_utf8(s).ok())
                .map(str::to_string);
            let record = match &source {
                Source::Records => serde_json::from_slice::<DidRecord>(&value).ok(),
                Source::Index(key_of) => {
                    match did_index::index_row_mnemonic(&key, &value, key_of) {
                        Some(m) => state.dids_ks.get::<DidRecord>(did_key(&m)).await?,
                        None => None,
                    }
                }
            };
            if let Some(record) = record.filter(|r| matches(r)) {
                if out.len() == limit {
                    // One more than the page: another page follows.
                    let resume = out.last().map(|r| r.mnemonic.clone());
                    return Ok((out, resume));
                }
                out.push(record);
            }
            last_read = suffix.or(last_read);
            if scanned >= LIST_SCAN_BUDGET {
                // Spent: return what there is, resuming where the scan
                // stopped. A page can be short, or empty, with more to come.
                return Ok((out, last_read));
            }
        }
    }
    Ok((out, None))
}

/// [`list_dids_page`] on a hash-ordered store: read every record a page at a
/// time, keeping only the `limit + 1` smallest mnemonics after `after`.
pub(super) async fn list_by_full_walk(
    state: &AppState,
    matches: &(dyn Fn(&DidRecord) -> bool + Sync),
    limit: usize,
    after: Option<&str>,
) -> Result<(Vec<DidRecord>, Option<String>), AppError> {
    use std::collections::BinaryHeap;

    // A max-heap on mnemonic holding the smallest `limit + 1` seen.
    struct ByMnemonic(DidRecord);
    impl PartialEq for ByMnemonic {
        fn eq(&self, other: &Self) -> bool {
            self.0.mnemonic == other.0.mnemonic
        }
    }
    impl Eq for ByMnemonic {}
    impl PartialOrd for ByMnemonic {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }
    impl Ord for ByMnemonic {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.0.mnemonic.cmp(&other.0.mnemonic)
        }
    }

    let mut best: BinaryHeap<ByMnemonic> = BinaryHeap::with_capacity(limit + 2);
    let mut walk = state.dids_ks.walk("did:", LIST_WALK_ROWS);
    while let Some(rows) = walk.next_page().await? {
        for (_key, value) in rows {
            let Ok(record) = serde_json::from_slice::<DidRecord>(&value) else {
                continue;
            };
            if after.is_some_and(|a| record.mnemonic.as_str() <= a) || !matches(&record) {
                continue;
            }
            if best.len() <= limit {
                best.push(ByMnemonic(record));
            } else if best
                .peek()
                .is_some_and(|top| record.mnemonic < top.0.mnemonic)
            {
                best.pop();
                best.push(ByMnemonic(record));
            }
        }
    }
    let mut out: Vec<DidRecord> = best.into_sorted_vec().into_iter().map(|b| b.0).collect();
    let resume = if out.len() > limit {
        out.truncate(limit);
        out.last().map(|r| r.mnemonic.clone())
    } else {
        None
    };
    Ok((out, resume))
}
