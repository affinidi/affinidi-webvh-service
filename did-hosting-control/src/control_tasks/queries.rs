//! Reads the control plane's Trust Task rows share: domain scoping for an
//! agent-name probe, the caller's hosting domains, time-series buckets, and
//! what this service advertises about itself.

use serde::Serialize;
use tracing::info;

use did_hosting_common::did_ops::{DidRecord, did_key};
use did_hosting_common::server::acl;
use did_hosting_common::server::domain::{self, DomainEntry, DomainScope};
use did_hosting_common::server::identity::mnemonic_from_did;

use crate::auth::AuthClaims;
use crate::server::AppState;
use did_hosting_common::server::error::AppError;

/// Resolve the domain an agent-name probe is scoped to.
///
/// Names are domain-scoped, so a bare `@alice` is meaningless until a domain
/// is pinned down: the same name may be free on one domain and taken on
/// another. Resolution is the same chain register uses — explicit → caller's
/// ACL default → system default — and, unlike the reservation path, a failure
/// here is fatal: answering "available" against a guessed domain would be a
/// wrong answer, not a lenient one.
///
pub(crate) async fn resolve_agent_name_domain(
    auth: &AuthClaims,
    state: &AppState,
    requested: Option<&str>,
) -> Result<String, AppError> {
    let acl_scope =
        match did_hosting_common::server::acl::get_acl_entry(&state.acl_ks, &auth.did).await? {
            Some(e) => e.domains,
            None => did_hosting_common::server::domain::DomainScope::All,
        };
    let system_default =
        did_hosting_common::server::domain::get_default_domain(&state.store).await?;
    did_hosting_common::server::domain::resolve_request_domain(
        requested,
        &acl_scope,
        system_default.as_deref(),
    )
    .map_err(|e| AppError::invalid(e.to_string()))
}

#[derive(Debug, Serialize)]
pub struct TimeSeriesPoint {
    pub timestamp: u64,
    pub resolves: u64,
    pub updates: u64,
}

/// Query time-series buckets for a given mnemonic and range.
///
/// The legacy reader, used until the tiered-stats migration has completed
/// (see [`crate::stats_query`]). Reads from the `timeseries_ks` keyspace; the
/// rows have shape `ts:{mnemonic}:{bucket_epoch} -> {r,u}`. The literal
/// `mnemonic` `_all` is the server-wide aggregate.
pub(crate) async fn query_timeseries(
    timeseries_ks: &did_hosting_common::server::store::KeyspaceHandle,
    mnemonic: &str,
    range: &str,
) -> Result<Vec<TimeSeriesPoint>, AppError> {
    legacy_series(timeseries_ks, &[mnemonic], range).await
}

/// The `ts:` bucket width the legacy rows were written at.
const LEGACY_BUCKET_SECS: u64 = 300;

/// Sum the legacy `ts:` buckets of every mnemonic in `mnemonics` over
/// `range` (`1h`, `7d`, `30d`, anything else 24 hours) into display points
/// of the range's step width.
async fn legacy_series(
    timeseries_ks: &did_hosting_common::server::store::KeyspaceHandle,
    mnemonics: &[&str],
    range: &str,
) -> Result<Vec<TimeSeriesPoint>, AppError> {
    #[derive(serde::Deserialize, Default)]
    struct BucketData {
        r: u64,
        u: u64,
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (duration, step) = match range {
        "1h" => (3600u64, LEGACY_BUCKET_SECS),
        "7d" => (7 * 24 * 3600, 3600),
        "30d" => (30 * 24 * 3600, 14400),
        _ => (24 * 3600, 900), // default 24h
    };
    let cutoff = now.saturating_sub(duration);
    let start = cutoff / LEGACY_BUCKET_SECS * LEGACY_BUCKET_SECS;
    let end = now / LEGACY_BUCKET_SECS * LEGACY_BUCKET_SECS;

    // Raw buckets within range, summed across the mnemonics.
    let mut bucket_map: std::collections::HashMap<u64, (u64, u64)> =
        std::collections::HashMap::new();
    for mnemonic in mnemonics {
        let prefix = format!("ts:{mnemonic}:");
        let raw = timeseries_ks.prefix_iter_raw(prefix.as_str()).await?;
        let prefix_len = prefix.len();
        for (key, value) in &raw {
            let key_str = std::str::from_utf8(key).unwrap_or_default();
            if let Some(epoch_str) = key_str.get(prefix_len..)
                && let Ok(epoch) = epoch_str.parse::<u64>()
                && epoch >= cutoff
                && let Ok(data) = serde_json::from_slice::<BucketData>(value)
            {
                let entry = bucket_map.entry(epoch).or_insert((0, 0));
                entry.0 += data.r;
                entry.1 += data.u;
            }
        }
    }

    // Aggregate the buckets into display points of `step` width.
    let mut points = Vec::new();
    let mut ts = start;
    while ts <= end {
        let mut resolves = 0u64;
        let mut updates = 0u64;
        let mut bucket_ts = ts;
        let window_end = ts.saturating_add(step);
        while bucket_ts < window_end && bucket_ts <= end {
            if let Some(&(r, u)) = bucket_map.get(&bucket_ts) {
                resolves += r;
                updates += u;
            }
            bucket_ts = bucket_ts.saturating_add(LEGACY_BUCKET_SECS);
        }
        points.push(TimeSeriesPoint {
            timestamp: ts,
            resolves,
            updates,
        });
        ts = ts.saturating_add(step);
    }

    Ok(points)
}

/// The mnemonics of the DIDs hosted under `domain` (canonical): every record
/// whose `domain`, or for a slot not yet backfilled the host of its DID, is
/// `domain` — read from the domain index, in no particular order.
pub(crate) async fn domain_mnemonics(
    state: &AppState,
    domain: &str,
) -> Result<Vec<String>, AppError> {
    use did_hosting_common::server::did_index::{
        domain_index_key, domain_index_prefix, index_row_mnemonic,
    };

    // The domain's index rows (kept in step with the records by every write,
    // see `did_index`), not every record: a key read per slot on the domain.
    // A row of a longer domain sharing the prefix (`a.example:8443`) is not
    // this domain's, and is dropped by the exact-key check.
    let mut mnemonics: Vec<String> = Vec::new();
    let mut walk = state.dids_ks.walk(domain_index_prefix(domain), 512);
    while let Some(rows) = walk.next_page().await? {
        mnemonics.extend(
            rows.iter()
                .filter_map(|(k, v)| index_row_mnemonic(k, v, |m| domain_index_key(domain, m))),
        );
    }
    Ok(mnemonics)
}

/// Read-time per-domain timeseries aggregation (the legacy reader).
///
/// Reads the domain's mnemonics from the domain index, then sums each one's
/// per-DID `ts:` buckets at the same step granularity as
/// [`query_timeseries`]. Cost is O(N_dids_in_domain × buckets_in_range); the
/// dashboard chart is not the hot path. A domain with no DIDs yields the
/// all-zeros series the chart already renders cleanly.
pub(crate) async fn query_timeseries_by_domain(
    state: &AppState,
    domain: &str,
    range: &str,
) -> Result<Vec<TimeSeriesPoint>, AppError> {
    let mnemonics = domain_mnemonics(state, domain).await?;
    let mnemonics: Vec<&str> = mnemonics.iter().map(String::as_str).collect();
    legacy_series(&state.timeseries_ks, &mnemonics, range).await
}

/// Resolve what the control plane's own DID document advertises.
///
/// `None` means "unknown", and both preconditions yield it: no configured
/// control DID, or no configured DID resolver.
///
/// Deliberately does **not** pass `None` through to
/// `resolve_service_types`, which would build a throwaway `DIDCacheClient`
/// and hit the network. These run on request-handling paths
/// (`server/config`, `server/info`), so that fallback would turn a page load
/// into an outbound fetch, once per request. With a resolver
/// configured, the shared client's cache makes everything after the first call
/// cheap.
pub(crate) async fn control_advertised_services(state: &AppState) -> Option<Vec<String>> {
    let did = state.config.server_did.as_deref()?;
    let resolver = state.did_resolver.as_ref()?;
    did_hosting_common::server::didcomm_profile::resolve_service_types(did, Some(resolver)).await
}

/// A domain listing. `default` carries the current
/// default-domain pointer so the UI can highlight it without a second
/// round-trip.
#[derive(Debug, Serialize)]
pub struct DomainListResponse {
    pub domains: Vec<DomainEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
}

/// The `me/domains/0.1` projection: the hosting domains the caller may operate
/// on.
///
/// Admin / Service / `All` scope see every domain; scoped Owners see only what
/// their ACL permits; `default` is the caller's `AllowedWithDefault.default`
/// when set, else the system default.
pub(crate) async fn fetch_me_domains_for_caller(
    auth: &AuthClaims,
    state: &AppState,
) -> Result<DomainListResponse, AppError> {
    let all = domain::list_domains(&state.store).await?;

    // Resolve the caller's ACL entry. A missing entry shouldn't
    // happen for an authenticated caller (auth itself requires an
    // ACL row) — but be defensive: treat as scope = All.
    let scope = match acl::get_acl_entry(&state.acl_ks, &auth.did).await? {
        Some(entry) => entry.domains,
        None => DomainScope::All,
    };

    // Admin / Service roles short-circuit per spec §3 — full list
    // regardless of scope field. (Service is an internal-account role
    // that doesn't usually call this endpoint; including for symmetry
    // with the auth-extractor's gating elsewhere.)
    let role_overrides_scope = matches!(
        auth.role,
        did_hosting_common::server::acl::Role::Admin
            | did_hosting_common::server::acl::Role::Service
    );

    let mut domains: Vec<DomainEntry> = if role_overrides_scope {
        all
    } else {
        all.into_iter().filter(|d| scope.allows(&d.name)).collect()
    };
    domains.sort_by(|a, b| a.name.cmp(&b.name));

    // Default: caller's `AllowedWithDefault.default` if set, else
    // system default (so a caller without an explicit default still
    // gets a sensible hint).
    let default = match scope.default_domain() {
        Some(d) => Some(d.to_string()),
        None => domain::get_default_domain(&state.store).await?,
    };

    info!(
        caller = %auth.did,
        count = domains.len(),
        "caller listed scoped domains"
    );
    Ok(DomainListResponse { domains, default })
}

/// The served agent names of the server's own DID, best-effort.
///
/// Resolved rather than configured, so it cannot drift from what the edge
/// actually serves. Every failure — feature off, no configured DID, an
/// unparseable identifier, no such record, a store error — yields an empty
/// list: this is informational, and a login page that renders one
/// fewer chip is a better failure than one that will not load.
///
/// The `did_id` equality check is the load-bearing line. `mnemonic_from_did`
/// maps an identifier to the slot it *would* occupy, which for a root DID is
/// the single global `.well-known` slot — so without confirming the slot holds
/// this exact DID, a deployment whose configured `server_did` was minted
/// elsewhere would advertise whichever root DID happens to be hosted here.
pub(crate) async fn server_agent_names(state: &AppState) -> Vec<String> {
    if !state.config.features.agent_names {
        return Vec::new();
    }
    let Some(did) = state.config.server_did.as_deref() else {
        return Vec::new();
    };
    let Some(mnemonic) = mnemonic_from_did(did) else {
        return Vec::new();
    };
    let Ok(Some(record)) = state.dids_ks.get::<DidRecord>(did_key(&mnemonic)).await else {
        return Vec::new();
    };
    if record.did_id.as_deref() != Some(did) || record.disabled || record.deleted_at.is_some() {
        return Vec::new();
    }
    record
        .agent_names
        .iter()
        .filter(|e| e.enabled)
        .map(|e| e.name.clone())
        .collect()
}
