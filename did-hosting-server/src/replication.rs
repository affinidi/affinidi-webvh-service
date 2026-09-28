//! The replication staleness bound: periodic reconcile against the control
//! plane, and the freshness the health probe reports.
//!
//! The control plane delivers every change through its durable outbox and
//! retries until this edge acknowledges it. That is the primary path. This
//! module is the backstop for what still goes missing — an outbox entry that
//! exhausted its retry budget while the edge was down, say:
//!
//! 1. Every [`ReplicationConfig::reconcile_interval_secs`] the edge asks its
//!    control plane for the full `did-management/did/list/0.1`, as a signed
//!    Trust Task over the binding the control plane's DID document advertises.
//!    The reply must itself be signed by the configured control plane and
//!    addressed to this edge, exactly as a directive must.
//! 2. A slot whose `disabled` state differs is repaired on the spot: the
//!    listing is the control plane's signed word, and a DID the control plane
//!    disabled must stop resolving here now, not whenever a push lands.
//! 3. A slot this edge is missing, holds at an older version or another DID,
//!    or holds but the control plane no longer lists, cannot be repaired from
//!    a listing (it carries no logs). The edge re-registers, reporting what it
//!    holds, and the control plane queues exactly the updates and deletes it
//!    needs through the outbox.
//! 4. A reconcile is *clean* when the listing arrived, verified, and — after
//!    the disable repairs — nothing else differed. When the last clean
//!    reconcile is older than [`ReplicationConfig::staleness_bound_secs`], the
//!    edge's `/api/health` answers `503` and a load balancer drains it.
//!
//! [`ReplicationConfig::reconcile_interval_secs`]: crate::config::ReplicationConfig
//! [`ReplicationConfig::staleness_bound_secs`]: crate::config::ReplicationConfig

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use did_hosting_common::did_ops::{DidRecord, content_log_key, did_key};
use did_hosting_common::server::auth::session::now_epoch;

use crate::server::AppState;

/// `did-management/did/list/0.1`.
pub const MSG_DID_LIST: &str = "https://trusttasks.org/spec/did-management/did/list/0.1";

/// The spec's page ceiling.
const PAGE_LIMIT: u64 = 1000;

/// How long one page of the listing may take to come back.
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// This edge's replication freshness, shared by the reconcile loop, the health
/// probe and `server/metrics`.
#[derive(Debug)]
pub struct ReplicationStatus {
    /// When this process started, epoch seconds: an edge that has not had
    /// time to reconcile yet is not stale.
    started_at: u64,
    /// Epoch seconds of the last clean reconcile; 0 when there has been none.
    last_reconciled_at: AtomicU64,
    /// Slots the last reconcile found behind and could not repair on the spot.
    stale_slots: AtomicU64,
    /// Disabled flags repaired from listings since start.
    repaired_total: AtomicU64,
}

impl ReplicationStatus {
    pub fn new(now: u64) -> Self {
        Self {
            started_at: now,
            last_reconciled_at: AtomicU64::new(0),
            stale_slots: AtomicU64::new(0),
            repaired_total: AtomicU64::new(0),
        }
    }

    /// Record a clean reconcile at `now`.
    pub fn mark_reconciled(&self, now: u64) {
        self.last_reconciled_at.store(now, Ordering::Relaxed);
        self.stale_slots.store(0, Ordering::Relaxed);
    }

    /// Epoch seconds of the last clean reconcile, if any.
    pub fn last_reconciled_at(&self) -> Option<u64> {
        match self.last_reconciled_at.load(Ordering::Relaxed) {
            0 => None,
            t => Some(t),
        }
    }

    /// Seconds since the last clean reconcile — or since start, when there has
    /// been none.
    pub fn age(&self, now: u64) -> u64 {
        now.saturating_sub(self.last_reconciled_at().unwrap_or(self.started_at))
    }

    /// Whether the edge is within `bound` seconds of its control plane.
    pub fn is_fresh(&self, now: u64, bound: u64) -> bool {
        self.age(now) <= bound
    }

    pub fn stale_slots(&self) -> u64 {
        self.stale_slots.load(Ordering::Relaxed)
    }

    pub fn repaired_total(&self) -> u64 {
        self.repaired_total.load(Ordering::Relaxed)
    }

    /// Backdate the last clean reconcile, for tests of the bound.
    #[doc(hidden)]
    pub fn set_last_reconciled_at(&self, at: u64) {
        self.last_reconciled_at.store(at, Ordering::Relaxed);
    }
}

/// Whether this edge's replication is within its bound. An edge with no
/// control plane — the daemon's embedded server, which reads the store its
/// in-process control plane writes — has nothing to fall behind.
pub fn is_fresh(state: &AppState) -> bool {
    if state.config.control_did.is_none() {
        return true;
    }
    state
        .replication
        .is_fresh(now_epoch(), state.config.replication.staleness_bound_secs)
}

// ---------------------------------------------------------------------------
// Awaited replies
// ---------------------------------------------------------------------------

type Waiters = Mutex<HashMap<String, oneshot::Sender<trust_tasks_rs::TrustTask<Value>>>>;

/// Requests this edge has sent and awaits the reply to, by document id.
static PENDING: std::sync::LazyLock<Waiters> = std::sync::LazyLock::new(Default::default);

/// Hand an inbound document to the request it answers, if one is awaited.
/// Returns the document back when nothing awaits it. The waiter verifies it.
pub fn deliver_reply(
    doc: trust_tasks_rs::TrustTask<Value>,
) -> Option<trust_tasks_rs::TrustTask<Value>> {
    let Some(thread) = doc.thread_id.clone() else {
        return Some(doc);
    };
    let waiter = PENDING.lock().ok()?.remove(&thread);
    match waiter {
        Some(tx) => {
            let _ = tx.send(doc);
            None
        }
        None => Some(doc),
    }
}

/// Send `doc` to the control plane over the binding its DID document
/// advertises and wait for the reply threaded to it.
async fn exchange_over_messaging(
    state: &AppState,
    doc: trust_tasks_rs::TrustTask<Value>,
) -> Result<trust_tasks_rs::TrustTask<Value>, String> {
    use did_hosting_common::server::didcomm_profile::TransportFallback;
    use did_hosting_common::server::trust_tasks::send::send_trust_task;

    let svc = state
        .didcomm_service
        .get()
        .ok_or("the messaging service is not running")?;
    let (Some(server_did), Some(control_did)) = (
        state.config.server_did.as_deref(),
        state.config.control_did.as_deref(),
    ) else {
        return Err("server_did or control_did is not configured".into());
    };
    let (tx, rx) = oneshot::channel();
    PENDING
        .lock()
        .map_err(|_| "reply table poisoned")?
        .insert(doc.id.clone(), tx);
    let fallback = TransportFallback::from_config(
        state.config.mediator_did.as_deref(),
        state.config.features.tsp,
    );
    let sent = send_trust_task(
        svc,
        "server",
        server_did,
        control_did,
        &doc,
        &fallback,
        state.did_resolver.as_ref(),
    )
    .await;
    let outcome = match sent {
        Ok(_) => match tokio::time::timeout(REPLY_TIMEOUT, rx).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(_)) => Err("the reply channel closed".into()),
            Err(_) => Err("no reply within the timeout".into()),
        },
        Err(e) => Err(format!("send failed: {e}")),
    };
    if let Ok(mut pending) = PENDING.lock() {
        pending.remove(&doc.id);
    }
    outcome
}

// ---------------------------------------------------------------------------
// Reconcile
// ---------------------------------------------------------------------------

/// The control plane's view of one slot, as `did/list` carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Listed {
    did_id: Option<String>,
    version_count: u64,
    disabled: bool,
}

/// What one reconcile found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Slots whose `disabled` state was repaired from the listing.
    pub repaired: Vec<String>,
    /// Slots this edge is missing or holds behind the control plane.
    pub behind: Vec<String>,
    /// Slots this edge holds that the control plane no longer lists.
    pub extra: Vec<String>,
}

impl ReconcileReport {
    /// Nothing is left out of step once the repairs are applied.
    pub fn is_clean(&self) -> bool {
        self.behind.is_empty() && self.extra.is_empty()
    }
}

/// A signed `did/list` request for one page, from this edge to its control
/// plane.
pub async fn list_request(
    state: &AppState,
    offset: u64,
) -> Result<trust_tasks_rs::TrustTask<Value>, String> {
    use did_hosting_common::server::trust_tasks::send::build_signed_request;

    let (Some(identity), Some(server_did), Some(control_did)) = (
        state.identity.as_deref(),
        state.config.server_did.as_deref(),
        state.config.control_did.as_deref(),
    ) else {
        return Err("identity, server_did or control_did is not configured".into());
    };
    let signer =
        did_hosting_common::server::trust_tasks::identity_signing_secret(identity, server_did)
            .map_err(|e| e.to_string())?;
    build_signed_request(
        MSG_DID_LIST,
        server_did,
        control_did,
        json!({ "limit": PAGE_LIMIT, "offset": offset }),
        &signer,
    )
    .await
    .map_err(|e| e.to_string())
}

/// Read a listing reply: signed by the configured control plane, addressed to
/// this edge, fresh, threaded to `request_id`, and a `did/list` response.
async fn verified_page(
    state: &AppState,
    request_id: &str,
    reply: trust_tasks_rs::TrustTask<Value>,
) -> Result<(Vec<(String, Listed)>, u64), String> {
    let verifier =
        crate::messaging::state_verifier(state).ok_or("no DID resolver to verify the reply")?;
    crate::messaging::verify_control_plane(state, None, &reply, &verifier)
        .await
        .map_err(|r| format!("the listing did not verify: {}", r.reject_reason()))?;
    if reply.thread_id.as_deref() != Some(request_id) {
        return Err("the listing answers another request".into());
    }
    let type_uri = reply.type_uri.to_string();
    if type_uri != format!("{MSG_DID_LIST}#response") {
        let code = reply
            .payload
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("?");
        return Err(format!("the control plane refused the listing: {code}"));
    }
    use trust_tasks_rs::specs::did_management::did::list::v0_1 as list;
    let _typed: list::Response = serde_json::from_value(reply.payload.clone())
        .map_err(|e| format!("the listing does not fit its schema: {e}"))?;
    let total = reply
        .payload
        .get("total")
        .and_then(Value::as_u64)
        .ok_or("the listing has no total")?;
    let records = reply
        .payload
        .get("records")
        .and_then(Value::as_array)
        .ok_or("the listing has no records")?
        .iter()
        .filter_map(|r| {
            Some((
                r.get("mnemonic")?.as_str()?.to_string(),
                Listed {
                    did_id: r.get("didId").and_then(Value::as_str).map(String::from),
                    version_count: r.get("versionCount")?.as_u64()?,
                    disabled: r.get("disabled").and_then(Value::as_bool).unwrap_or(false),
                },
            ))
        })
        .collect();
    Ok((records, total))
}

/// One reconcile, with `exchange` carrying each request to the control plane
/// and returning its reply. Applies the disable repairs, updates
/// [`ReplicationStatus`], and returns what it found.
pub async fn reconcile_once<F, Fut>(
    state: &AppState,
    exchange: F,
) -> Result<ReconcileReport, String>
where
    F: Fn(trust_tasks_rs::TrustTask<Value>) -> Fut,
    Fut: std::future::Future<Output = Result<trust_tasks_rs::TrustTask<Value>, String>>,
{
    // The whole listing, page by page.
    let mut listed: HashMap<String, Listed> = HashMap::new();
    let mut offset = 0u64;
    loop {
        let request = list_request(state, offset).await?;
        let request_id = request.id.clone();
        let reply = exchange(request).await?;
        let (page, total) = verified_page(state, &request_id, reply).await?;
        let got = page.len() as u64;
        listed.extend(page);
        offset += got;
        if got == 0 || offset >= total {
            if (listed.len() as u64) < total {
                return Err(format!(
                    "the listing ended at {} of {total} slots",
                    listed.len()
                ));
            }
            break;
        }
    }

    let report = apply_listing(state, &listed).await?;
    let now = now_epoch();
    state
        .replication
        .repaired_total
        .fetch_add(report.repaired.len() as u64, Ordering::Relaxed);
    if report.is_clean() {
        state.replication.mark_reconciled(now);
        debug!(slots = listed.len(), "reconcile clean");
    } else {
        state.replication.stale_slots.store(
            (report.behind.len() + report.extra.len()) as u64,
            Ordering::Relaxed,
        );
        info!(
            behind = report.behind.len(),
            extra = report.extra.len(),
            "reconcile found slots out of step with the control plane"
        );
    }
    Ok(report)
}

/// Compare this edge's slots with the control plane's listing, repairing
/// `disabled` where the content is otherwise current.
async fn apply_listing(
    state: &AppState,
    listed: &HashMap<String, Listed>,
) -> Result<ReconcileReport, String> {
    let mut report = ReconcileReport::default();
    let held: Vec<DidRecord> = state
        .dids_ks
        .prefix_iter_raw("did:")
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<DidRecord>(&v).ok())
        .filter(|r| r.version_count > 0 && r.deleted_at.is_none())
        .collect();
    let held_names: HashSet<&str> = held.iter().map(|r| r.mnemonic.as_str()).collect();

    for (mnemonic, want) in listed {
        if want.version_count == 0 {
            continue; // a reservation: nothing to serve
        }
        if !held_names.contains(mnemonic.as_str()) {
            report.behind.push(mnemonic.clone());
        }
    }
    for mut record in held {
        let Some(want) = listed.get(&record.mnemonic) else {
            report.extra.push(record.mnemonic.clone());
            continue;
        };
        if want.version_count == 0 {
            report.extra.push(record.mnemonic.clone());
            continue;
        }
        if want.did_id != record.did_id || want.version_count > record.version_count {
            report.behind.push(record.mnemonic.clone());
            // Still honour a disable: whatever version this edge holds, the
            // control plane has said the DID must not resolve.
        }
        if want.disabled != record.disabled {
            record.disabled = want.disabled;
            state
                .dids_ks
                .insert(did_key(&record.mnemonic), &record)
                .await
                .map_err(|e| e.to_string())?;
            state
                .did_cache
                .invalidate(&content_log_key(&record.mnemonic));
            warn!(
                mnemonic = %record.mnemonic,
                disabled = want.disabled,
                "reconcile repaired a disabled state the edge had missed"
            );
            report.repaired.push(record.mnemonic.clone());
        }
    }
    report.behind.sort();
    report.extra.sort();
    report.repaired.sort();
    Ok(report)
}

/// Reconcile every interval for as long as the process runs. A reconcile
/// that leaves slots out of step re-registers, so the control plane queues
/// what this edge is missing.
pub async fn run_reconcile_loop(
    state: AppState,
    svc: affinidi_messaging_didcomm_service::DIDCommService,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let interval = Duration::from_secs(state.config.replication.reconcile_interval_secs.max(1));
    let mut timer = tokio::time::interval(interval);
    loop {
        tokio::select! {
            _ = timer.tick() => {}
            _ = shutdown.changed() => break,
        }
        let outcome = reconcile_once(&state, |doc| exchange_over_messaging(&state, doc)).await;
        match outcome {
            Ok(report) if report.is_clean() => {}
            Ok(_) => crate::control_register::register_via_didcomm(&state, &svc).await,
            Err(e) => warn!(error = %e, "reconcile with the control plane failed"),
        }
    }
}
