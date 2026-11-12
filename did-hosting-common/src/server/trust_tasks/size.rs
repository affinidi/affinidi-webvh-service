//! The largest document each Trust Task type may be, checked before the
//! document is parsed.
//!
//! `POST /api/trust-tasks` used one blanket 64 KiB body limit for every
//! type — generous for an ACL entry or a handful of identifiers, but too
//! small for `did/register`'s payload, which carries a DID's whole
//! `did:webvh` log: every entry it has ever had, each a signed DID
//! document. A log above 64 KiB had no HTTPS route at all.
//!
//! One cap for every type is either too small for the few tasks whose
//! payload is legitimately large or far too large for the many whose
//! payload is a handful of identifiers. The body is attacker-supplied and
//! arrives unauthenticated (proof verification happens later in the
//! pipeline), so the cap is what bounds the parsing this module does
//! before it knows who is asking.
//!
//! So each type declares its own maximum in [`DECLARED`], and every other
//! type takes [`DEFAULT_MAX_DOCUMENT_BYTES`]. A value is raised above the
//! default only where the task's specification needs it, and says why.
//!
//! A declared maximum is **in force only while this deployment serves the
//! type** — the caller passes its own served-type list to [`check`],
//! [`max_document_bytes`] and [`largest_max_document_bytes`]. This service
//! narrows an inbound document's proof (canonicalising the whole document
//! and resolving its signer's DID) before it refuses a type it does not
//! route, so a raised limit on a type nobody serves would buy an
//! unauthenticated caller that much more work for nothing. Until a
//! declared type is dispatched it takes the default like any other.
//!
//! # Before the parse
//!
//! A body no larger than the default is admitted without looking at it:
//! every type accepts that much. A larger body has only its top-level
//! `type` read — a scan that keeps nothing else — and is refused unless
//! that type declares a maximum it fits. Nothing else in it is parsed,
//! validated or verified. The refusal is a framework `trust-task-error`
//! with the standard `malformedRequest` code and the limit under
//! `details.maxBytes`.
//!
//! [`check`] is called from every transport (HTTPS, TSP, DIDComm) before
//! that transport's own `TrustTask<Value>` parse, so the gate is the same
//! regardless of how the document arrived. The HTTPS door additionally
//! caps its request body at [`largest_max_document_bytes`], so no body
//! larger than any served type accepts is ever buffered by that route.
//!
//! # A claimed issuer is not a verified one
//!
//! [`check_for_known_issuer`] grants the raised limit to a document whose
//! in-band `issuer` merely *names* a DID with an ACL entry — the field is
//! read straight off the unparsed body, before any proof is checked. That
//! is deliberate (a stranger could never be authorised for a raised task
//! anyway, so refusing it earlier costs it nothing legitimate), but taken
//! alone it is a DoS amplifier: anyone who has ever seen an admin's DID can
//! claim it as `issuer` and buy themselves the full 1 MiB of parsing and
//! proof verification, over and over, whether or not they can actually
//! sign for it. [`LargeDocumentBudget`] closes that gap — the caller
//! charges one address-scoped budget before granting the raised limit, and
//! [`settle_large_document_charge`] doubles that address's next cost
//! whenever the claim does not pan out (a verification failure, or a
//! verified issuer that turns out to be someone else). The raised cost
//! halves every [`PENALTY_HALF_LIFE_SECS`] and on each claim that does
//! verify, so an address is not held to it indefinitely.
//!
//! Claimed and verified issuers are compared as identities
//! ([`crate::scid::identity`]): a `did:scid` issuer may carry a `?src=`
//! locator that the verified identity does not, and that is the same
//! issuer, not a mismatch.

use trust_tasks_rs::{ErrorPayload, ErrorResponse, Payload, RejectReason, TrustTask};

use crate::server::rate_limit::KeyedRateLimiter;

/// Every type not in [`DECLARED`] accepts a document of at most 64 KiB —
/// generous for a handful of identifiers, an ACL entry or a discovery
/// reply, and small enough that an unauthenticated flood of them is cheap
/// to refuse.
pub const DEFAULT_MAX_DOCUMENT_BYTES: usize = 64 * 1024;

/// `did-management/did/register/0.1`: 1 MiB.
///
/// `didData` is the DID's complete `did:webvh` log — every entry it has
/// ever had, each a signed DID document — so it grows with the DID's age
/// and cannot be bounded by its shape. `did/publish/0.1` (spec
/// `supersededBy: did/register`) carries the same log shape, but this
/// service does not route it — #144 retired the route in favour of
/// `did/register`'s owner-update rule, so it takes the default like any
/// other unserved type.
pub const DID_REGISTER_MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// The types that accept more than [`DEFAULT_MAX_DOCUMENT_BYTES`], and how
/// much. Keyed by the full Type URI, so a new version of a task takes the
/// default until it declares its own.
pub const DECLARED: &[(&str, usize)] = &[(
    <crate::tasks::did_management::did::register::v0_1::Payload as Payload>::TYPE_URI,
    DID_REGISTER_MAX_DOCUMENT_BYTES,
)];

/// The `details` member naming the limit a refused document exceeded.
pub const DETAILS_MAX_BYTES: &str = "maxBytes";

/// The largest document any type in `served` accepts — the HTTPS door's
/// body cap. The default while nothing in [`DECLARED`] is served.
pub fn largest_max_document_bytes(served: &[&str]) -> usize {
    largest_in(DECLARED, served)
}

fn largest_in(declared: &[(&str, usize)], served: &[&str]) -> usize {
    declared
        .iter()
        .filter(|(uri, _)| served.contains(uri))
        .map(|(_, max)| *max)
        .fold(DEFAULT_MAX_DOCUMENT_BYTES, usize::max)
}

/// The largest document `type_uri` accepts, in bytes, given the deployment
/// serves the types named in `served`.
pub fn max_document_bytes(type_uri: &str, served: &[&str]) -> usize {
    max_in(type_uri, DECLARED, served)
}

fn max_in(type_uri: &str, declared: &[(&str, usize)], served: &[&str]) -> usize {
    declared
        .iter()
        .find(|(uri, _)| *uri == type_uri && served.contains(uri))
        .map_or(DEFAULT_MAX_DOCUMENT_BYTES, |(_, max)| *max)
}

/// The longest `type` a refusal names. A caller's own `type` is echoed
/// back only when it is short enough to plausibly be a Type URI; anything
/// longer is not one, and repeating it would turn the refusal into an
/// echo of the caller's body.
const MAX_NAMED_TYPE_CHARS: usize = 256;

/// Admit `body`, or refuse it for its size before it is parsed. `served`
/// is the full list of Type URIs this deployment dispatches — the ACL
/// family plus the control plane's task table.
pub fn check(body: &[u8], served: &[&str]) -> Result<(), ErrorResponse> {
    check_with(body, |type_uri| max_document_bytes(type_uri, served))
}

/// Large documents (over [`DEFAULT_MAX_DOCUMENT_BYTES`]) a single address may
/// have [`check_for_known_issuer`] grant the raised limit to per minute,
/// before its claimed issuer's proof has even been read. See the module
/// docs: this is what keeps naming a known admin's DID from being free rein
/// to make the service parse and verify 1 MiB documents indefinitely. 5 is
/// generous for a legitimate high-frequency `did/register` caller and cheap
/// to hold an attacker to.
pub const LARGE_DOCUMENT_BUDGET_PER_WINDOW: u64 = 5;

/// Window, in seconds, for [`LargeDocumentBudget`]'s limits: token buckets
/// on `affinidi-rate-limit`, so an address spends its allowance at once and
/// regains one large document every `window / allowance`.
pub const LARGE_DOCUMENT_BUDGET_WINDOW_SECS: u64 = 60;

/// Large documents admitted per window across *every* address together.
///
/// The per-address budget is keyed on something a caller can vary — a client
/// IP behind a large pool, or on the messaging transports a sender VID anyone
/// can mint — so it bounds one address, not the service. This bounds the
/// service: however many addresses a caller spreads across, the raised-limit
/// parse-and-verify path runs at most this many times a window. A legitimate
/// deployment registers far fewer large DIDs than this per minute.
pub const LARGE_DOCUMENT_GLOBAL_BUDGET_PER_WINDOW: u64 = 60;

/// The `limiter` the per-address budget logs its refusals under.
const PER_ADDRESS_LIMITER: &str = "large-document-per-address";

/// The `limiter` the every-address budget logs its refusals under.
const GLOBAL_LIMITER: &str = "large-document-global";

/// Most addresses tracked at once, by the per-address budget and by the
/// penalty table each. Past it the budget refuses a new address (after
/// sweeping the ones whose allowance has refilled) while tracked ones are
/// unaffected; the penalty table drops the penalties that have decayed away
/// and otherwise keeps every one it holds, recording no new one (see
/// [`LargeDocumentBudget::penalize`]).
const MAX_TRACKED_ADDRESSES: usize = 10_000;

/// The highest per-document cost a penalty raises an address to: one more
/// than a whole window's allowance, which no address can ever pay. Doubling
/// past it would change nothing but the number.
const MAX_COST: u64 = LARGE_DOCUMENT_BUDGET_PER_WINDOW + 1;

/// How long a raised per-document cost takes to halve with no further
/// unverified claim from its address. The highest cost ([`MAX_COST`]) is back
/// to 1 within two half-lives, so an address that once sent unverifiable
/// large documents — or shares an egress address with one that did — is held
/// to the raised cost for under an hour, not until the process restarts.
pub const PENALTY_HALF_LIFE_SECS: u64 = 15 * 60;

/// One address's raised per-document cost and when it last changed.
#[derive(Debug, Clone, Copy)]
struct Penalty {
    cost: u64,
    since: std::time::Instant,
}

impl Penalty {
    /// The cost at `now`: halved once for every whole half-life since it last
    /// changed, and never below 1.
    fn cost_at(&self, now: std::time::Instant) -> u64 {
        let halvings = now.saturating_duration_since(self.since).as_secs() / PENALTY_HALF_LIFE_SECS;
        u32::try_from(halvings)
            .ok()
            .and_then(|h| self.cost.checked_shr(h))
            .unwrap_or(0)
            .max(1)
    }
}

/// Per-address budget for documents [`check_for_known_issuer`] grants the
/// raised limit to before their claimed issuer is verified. See the module
/// docs.
///
/// Both limits — per address and across every address — are
/// [`KeyedRateLimiter`]s on `affinidi-rate-limit`, like every other limit in
/// this workspace. What is this budget's own is the penalty: an address whose
/// claim did not verify pays double for its next large document, then double
/// again, until it can pay for none. A penalty is against the address, not the
/// minute it was earned in, so it outlives the address's bucket; it halves
/// every [`PENALTY_HALF_LIFE_SECS`], and on each claim from the address that
/// does verify, and is forgotten once back to 1.
#[derive(Debug)]
pub struct LargeDocumentBudget {
    per_address: KeyedRateLimiter<String>,
    global: KeyedRateLimiter<()>,
    /// Each penalised address's raised cost per large document (an address
    /// that is absent, or whose penalty has decayed to 1, costs 1).
    penalties: std::sync::Mutex<std::collections::HashMap<String, Penalty>>,
}

impl Default for LargeDocumentBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl LargeDocumentBudget {
    pub fn new() -> Self {
        Self::with_max_tracked_addresses(MAX_TRACKED_ADDRESSES)
    }

    fn with_max_tracked_addresses(max_tracked: usize) -> Self {
        Self {
            per_address: KeyedRateLimiter::new(
                PER_ADDRESS_LIMITER,
                LARGE_DOCUMENT_BUDGET_PER_WINDOW,
                LARGE_DOCUMENT_BUDGET_WINDOW_SECS,
            )
            .with_max_tracked_keys(max_tracked),
            global: KeyedRateLimiter::new(
                GLOBAL_LIMITER,
                LARGE_DOCUMENT_GLOBAL_BUDGET_PER_WINDOW,
                LARGE_DOCUMENT_BUDGET_WINDOW_SECS,
            ),
            penalties: Default::default(),
        }
    }

    /// Sweep addresses whose allowance has refilled out of the budget's
    /// memory every minute until `shutdown` fires. Penalties are not swept
    /// here: they decay, and [`Self::penalize`] drops the decayed ones when
    /// the table is full. Must run on a Tokio runtime.
    pub fn spawn_gc(&self, shutdown: &tokio_util::sync::CancellationToken) {
        self.per_address.spawn_gc(shutdown.clone());
        self.global.spawn_gc(shutdown.clone());
    }

    /// Charge `address` for one large document, at its current per-document
    /// cost, then the every-address budget for one. `Err` is the number of
    /// seconds until a retry can succeed.
    ///
    /// The address is charged first, so an address over its own budget never
    /// spends the shared one. A penalised address that cannot pay its whole
    /// cost loses what it could pay: it has already been caught once.
    fn try_charge(&self, address: &str) -> Result<(), u64> {
        for _ in 0..self.cost(address) {
            self.per_address
                .try_consume(address.to_owned())
                .map_err(retry_after)?;
        }
        self.global.try_consume(()).map_err(retry_after)
    }

    /// Double `address`'s per-document cost — called once a claimed issuer
    /// this budget let through turns out to have failed verification, or
    /// proven to be someone else. Persists across windows (a penalty is
    /// against the address, not the minute it earned it), up to a cost no
    /// window's allowance covers, and decays from there
    /// ([`PENALTY_HALF_LIFE_SECS`]).
    ///
    /// A full table first drops the penalties that have decayed back to 1,
    /// then keeps every live penalty it holds and records no new one:
    /// evicting a live penalty to make room would let a flood of fresh
    /// addresses wipe it on purpose, and refusing unpenalised addresses
    /// instead would let one shut out every large document. A fresh address
    /// still meets both budgets.
    fn penalize(&self, address: &str) {
        self.penalize_at(address, std::time::Instant::now());
    }

    fn penalize_at(&self, address: &str, now: std::time::Instant) {
        let mut penalties = self.lock_penalties();
        if let Some(penalty) = penalties.get_mut(address) {
            let cost = penalty.cost_at(now).saturating_mul(2).min(MAX_COST);
            *penalty = Penalty { cost, since: now };
            return;
        }
        if penalties.len() >= MAX_TRACKED_ADDRESSES {
            penalties.retain(|_, penalty| penalty.cost_at(now) > 1);
        }
        if penalties.len() < MAX_TRACKED_ADDRESSES {
            penalties.insert(
                address.to_owned(),
                Penalty {
                    cost: 2,
                    since: now,
                },
            );
        } else {
            tracing::warn!(
                address,
                "large-document penalty table full; not recording this address's penalty"
            );
        }
    }

    /// Halve `address`'s raised cost — called once a claim from it verified
    /// to exactly the issuer it named. A penalty earned by another sender
    /// behind the same address (a shared egress, a proxy missing from
    /// `trusted_proxies`) then does not hold back a caller that keeps proving
    /// who it is.
    fn relieve(&self, address: &str) {
        self.relieve_at(address, std::time::Instant::now());
    }

    fn relieve_at(&self, address: &str, now: std::time::Instant) {
        let mut penalties = self.lock_penalties();
        let Some(penalty) = penalties.get_mut(address) else {
            return;
        };
        let cost = penalty.cost_at(now) / 2;
        if cost > 1 {
            *penalty = Penalty { cost, since: now };
        } else {
            penalties.remove(address);
        }
    }

    /// `address`'s cost per large document: 1 unless penalised.
    fn cost(&self, address: &str) -> u64 {
        self.cost_at(address, std::time::Instant::now())
    }

    fn cost_at(&self, address: &str, now: std::time::Instant) -> u64 {
        let mut penalties = self.lock_penalties();
        let Some(cost) = penalties.get(address).map(|p| p.cost_at(now)) else {
            return 1;
        };
        if cost <= 1 {
            penalties.remove(address);
        }
        cost
    }

    fn lock_penalties(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, Penalty>> {
        self.penalties
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The retry hint of a [`KeyedRateLimiter`] refusal.
fn retry_after(refusal: crate::server::error::AppError) -> u64 {
    match refusal {
        crate::server::error::AppError::RateLimited {
            retry_after_secs, ..
        } => retry_after_secs,
        _ => LARGE_DOCUMENT_BUDGET_WINDOW_SECS,
    }
}

/// A per-address [`LargeDocumentBudget`] charge [`check_for_known_issuer`]
/// made before this document's proof was verified. Pass it to
/// [`settle_large_document_charge`] once the caller's own verification
/// concludes.
#[derive(Debug)]
pub struct LargeDocumentCharge {
    address: String,
    /// The claimed issuer's identity ([`crate::scid::identity`]).
    claimed_issuer: String,
}

/// [`check`], but a raised limit is granted only to a document whose
/// claimed `issuer` already holds an entry in `acl` — and even then, only
/// while `address`'s [`LargeDocumentBudget`] has room for it.
///
/// The limit is decided before any signature is verified, so an
/// unauthenticated caller could otherwise claim a raised type (1 MiB for
/// `did/register`) and make the service parse and verify that much for
/// nothing. A caller with no ACL entry could never be authorised for a
/// raised task anyway, so it gets the default, with no charge against
/// `budget` — the ACL lookup alone already holds it to the cheap path. A
/// known claimed issuer past its address's budget is refused `unavailable`
/// rather than admitted, even one that would have gone on to verify
/// correctly; that trade-off is what a budget is for.
///
/// Returns the charge to settle once verification concludes
/// ([`settle_large_document_charge`]), or `None` when no charge was made.
pub async fn check_for_known_issuer(
    body: &[u8],
    served: &[&str],
    acl: &crate::server::store::KeyspaceHandle,
    budget: &LargeDocumentBudget,
    address: &str,
) -> Result<Option<LargeDocumentCharge>, ErrorResponse> {
    if body.len() <= DEFAULT_MAX_DOCUMENT_BYTES {
        return Ok(None);
    }
    let claimed_issuer = match peek_issuer(body) {
        Some(issuer) => match crate::server::acl::get_acl_entry(acl, &issuer).await {
            Ok(Some(_)) => Some(issuer),
            Ok(None) => None,
            // A failed lookup says nothing about the issuer: refusing the
            // document as oversized for a stranger would be final, and wrong.
            Err(e) => {
                tracing::warn!(error = %e, "large document deferred: ACL lookup failed");
                return Err(unrouted_error(e.failure_reject_reason().into()));
            }
        },
        None => None,
    };
    let Some(claimed_issuer) = claimed_issuer else {
        check_with(body, |_| DEFAULT_MAX_DOCUMENT_BYTES)?;
        return Ok(None);
    };
    if let Err(retry_after_secs) = budget.try_charge(address) {
        return Err(unrouted_error(
            RejectReason::Unavailable {
                retry_after: Some(crate::server::error::retry_at(retry_after_secs)),
            }
            .into(),
        ));
    }
    check(body, served)?;
    Ok(Some(LargeDocumentCharge {
        address: address.to_string(),
        claimed_issuer: crate::scid::identity(&claimed_issuer),
    }))
}

/// Settle a [`LargeDocumentCharge`] once the caller's own proof verification
/// concludes. `verified_issuer` is the proven signer on success, or `None`
/// on any verification failure. A `verified_issuer` that is not the identity
/// the charge was granted against — including a failure, which proves none at
/// all — doubles the address's cost for its next large document
/// ([`LargeDocumentBudget::penalize`]). A charge that verified to its claimed
/// issuer costs nothing extra, and halves any raised cost the address holds.
///
/// The two are compared as identities ([`crate::scid::identity`]): a
/// `did:scid` issuer's `?src=` locator is not part of who it is, and the
/// verifier reports the identity without it.
///
/// A no-op when `charge` is `None` — the document never carried one.
pub fn settle_large_document_charge(
    budget: &LargeDocumentBudget,
    charge: Option<&LargeDocumentCharge>,
    verified_issuer: Option<&str>,
) {
    let Some(charge) = charge else {
        return;
    };
    match verified_issuer {
        Some(verified) if crate::scid::identity(verified) == charge.claimed_issuer => {
            budget.relieve(&charge.address);
        }
        _ => budget.penalize(&charge.address),
    }
}

/// The document's top-level `issuer`, read the same way as [`peek_type`].
fn peek_issuer(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct IssuerOnly {
        issuer: String,
    }
    serde_json::from_slice::<IssuerOnly>(body)
        .ok()
        .map(|t| t.issuer)
}

fn check_with(body: &[u8], limit: impl Fn(&str) -> usize) -> Result<(), ErrorResponse> {
    if body.len() <= DEFAULT_MAX_DOCUMENT_BYTES {
        return Ok(());
    }
    let type_uri = peek_type(body);
    let max = type_uri
        .as_deref()
        .map_or(DEFAULT_MAX_DOCUMENT_BYTES, &limit);
    if body.len() <= max {
        return Ok(());
    }
    let named = match type_uri.as_deref() {
        Some(t) if t.chars().count() <= MAX_NAMED_TYPE_CHARS => t,
        Some(_) => "its type",
        None => "a document of no readable type",
    };
    let payload: ErrorPayload = RejectReason::MalformedRequest {
        reason: format!(
            "the document is {} bytes; {named} accepts at most {max}",
            body.len()
        ),
    }
    .into();
    Err(unrouted_error(payload.with_details(
        serde_json::json!({ DETAILS_MAX_BYTES: max }),
    )))
}

/// The document's top-level `type`, read without keeping anything else.
///
/// `None` for a body that is not a JSON object with a string `type` — the
/// derived `Deserialize` ignores every other member (so a full document
/// still reads), but refuses a *duplicate* `type` member as an ambiguous
/// shape rather than picking one. A body that declares nothing readable
/// takes the default limit, as an undeclared type does.
fn peek_type(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct TypeOnly {
        #[serde(rename = "type")]
        type_uri: String,
    }
    serde_json::from_slice::<TypeOnly>(body)
        .ok()
        .map(|t| t.type_uri)
}

/// Build an unrouted `trust-task-error` document for a size refusal.
///
/// There is no source `TrustTask` to draw `issuer`/`recipient`/`threadId`
/// from — the whole point is that the body is refused before it is
/// parsed — so the response is unrouted, exactly as a body-parse failure
/// is (the framework permits this: the producer can correlate on the
/// response `id`).
fn unrouted_error(payload: ErrorPayload) -> ErrorResponse {
    TrustTask {
        id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        thread_id: None,
        parent_thread_id: None,
        ceremony: None,
        type_uri: super::framework_error_type_uri(),
        issuer: None,
        recipient: None,
        issued_at: Some(chrono::Utc::now()),
        expires_at: None,
        payload,
        context: None,
        proof: None,
        extra: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID_REGISTER: &str =
        <crate::tasks::did_management::did::register::v0_1::Payload as Payload>::TYPE_URI;
    const ACL_SHOW: &str = <crate::tasks::acl::show::v0_2::Payload as Payload>::TYPE_URI;

    fn register_doc(issuer: &str, bytes: usize) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "type": DID_REGISTER,
            "issuer": issuer,
            "payload": { "log": "x".repeat(bytes) },
        }))
        .unwrap()
    }

    async fn acl_with(did: &str) -> crate::server::store::KeyspaceHandle {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = crate::server::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..Default::default()
        };
        std::mem::forget(dir);
        let store = crate::server::store::Store::open(&cfg)
            .await
            .expect("open store");
        let acl = store
            .keyspace(crate::server::store::KS_ACL)
            .expect("acl keyspace");
        crate::server::acl::store_acl_entry(
            &acl,
            &crate::server::acl::AclEntry {
                did: did.into(),
                role: crate::server::acl::Role::Admin,
                label: None,
                created_at: 1_700_000_000,
                max_total_size: None,
                max_did_count: None,
                domains: crate::server::domain::DomainScope::All,
            },
        )
        .await
        .expect("store entry");
        acl
    }

    #[tokio::test]
    async fn a_raised_limit_is_granted_only_to_a_known_issuer() {
        let acl = acl_with("did:web:admin.example").await;
        let served = [DID_REGISTER];
        let budget = LargeDocumentBudget::new();
        let big = register_doc("did:web:admin.example", 200 * 1024);
        assert!(
            check_for_known_issuer(&big, &served, &acl, &budget, "ip:1.2.3.4")
                .await
                .is_ok()
        );
        let stranger = register_doc("did:web:stranger.example", 200 * 1024);
        assert!(
            check_for_known_issuer(&stranger, &served, &acl, &budget, "ip:5.6.7.8")
                .await
                .is_err()
        );
    }

    /// A failed ACL read says nothing about the issuer: the large document is
    /// deferred with a retry time, not refused as oversized for a stranger.
    #[tokio::test]
    async fn a_throttled_acl_read_defers_a_large_document() {
        let acl = acl_with("did:web:admin.example").await.throttled_reads();
        let big = register_doc("did:web:admin.example", 200 * 1024);
        let err = check_for_known_issuer(
            &big,
            &[DID_REGISTER],
            &acl,
            &LargeDocumentBudget::new(),
            "ip:1.2.3.4",
        )
        .await
        .expect_err("deferred");
        assert_eq!(err.payload.code.to_string(), "unavailable");
        assert!(err.payload.retry_after.is_some());
    }

    /// Repeated large documents from one address, all naming the same known
    /// (but not yet verified) issuer, are refused once the address's budget
    /// is spent — the DoS amplification the module docs describe.
    #[tokio::test]
    async fn repeated_large_documents_from_one_address_are_refused_past_the_budget() {
        let acl = acl_with("did:web:admin.example").await;
        let served = [DID_REGISTER];
        let budget = LargeDocumentBudget::new();
        let doc = register_doc("did:web:admin.example", 200 * 1024);
        for _ in 0..LARGE_DOCUMENT_BUDGET_PER_WINDOW {
            assert!(
                check_for_known_issuer(&doc, &served, &acl, &budget, "ip:9.9.9.9")
                    .await
                    .is_ok()
            );
        }
        let err = check_for_known_issuer(&doc, &served, &acl, &budget, "ip:9.9.9.9")
            .await
            .unwrap_err();
        assert_eq!(refusal(err)["code"], "unavailable");
        // A different address is unaffected.
        assert!(
            check_for_known_issuer(&doc, &served, &acl, &budget, "ip:1.1.1.1")
                .await
                .is_ok()
        );
    }

    /// A verified known issuer, still within its address's budget, is
    /// granted the raised limit and settles for free — no penalty when the
    /// verified issuer is exactly the one it claimed.
    #[tokio::test]
    async fn a_verified_known_issuer_within_its_budget_passes() {
        let acl = acl_with("did:web:admin.example").await;
        let served = [DID_REGISTER];
        let budget = LargeDocumentBudget::new();
        let doc = register_doc("did:web:admin.example", 200 * 1024);
        let charge = check_for_known_issuer(&doc, &served, &acl, &budget, "ip:1.2.3.4")
            .await
            .expect("within budget")
            .expect("a large document charges the budget");
        settle_large_document_charge(&budget, Some(&charge), Some("did:web:admin.example"));
        assert_eq!(
            budget.cost("ip:1.2.3.4"),
            1,
            "a verified claim is not penalised"
        );
    }

    /// Settling a charge whose claimed issuer did not verify — a mismatch,
    /// or an outright verification failure (`None`) — doubles the address's
    /// next cost, so repeating the same lie exhausts its budget faster.
    #[tokio::test]
    async fn an_unverified_or_mismatched_issuer_penalises_the_address() {
        let budget = LargeDocumentBudget::new();
        let charge = LargeDocumentCharge {
            address: "ip:1.2.3.4".to_string(),
            claimed_issuer: "did:web:admin.example".to_string(),
        };
        settle_large_document_charge(&budget, Some(&charge), None);
        assert_eq!(budget.cost("ip:1.2.3.4"), 2);
        settle_large_document_charge(&budget, Some(&charge), Some("did:web:someone-else.example"));
        assert_eq!(budget.cost("ip:1.2.3.4"), 4);
        // A `None` charge (no large document was charged) never touches the
        // budget.
        settle_large_document_charge(&budget, None, None);
        assert_eq!(budget.cost("ip:1.2.3.4"), 4);
    }

    /// A document at or under the default is never charged against the
    /// budget, whatever it claims — the whole point of the default is that
    /// every type accepts that much for free.
    #[test]
    fn many_addresses_together_are_held_to_the_global_budget() {
        let budget = LargeDocumentBudget::new();
        for i in 0..LARGE_DOCUMENT_GLOBAL_BUDGET_PER_WINDOW {
            assert!(budget.try_charge(&format!("vid:{i}")).is_ok());
        }
        assert!(
            budget.try_charge("vid:fresh").is_err(),
            "a fresh address does not escape the service-wide cap"
        );
    }

    /// An address over its own budget does not spend the shared one.
    #[test]
    fn a_refused_address_spends_none_of_the_global_budget() {
        let budget = LargeDocumentBudget::new();
        for _ in 0..LARGE_DOCUMENT_BUDGET_PER_WINDOW {
            budget.try_charge("ip:busy").unwrap();
        }
        for _ in 0..LARGE_DOCUMENT_GLOBAL_BUDGET_PER_WINDOW {
            assert!(budget.try_charge("ip:busy").is_err());
        }
        for i in 0..(LARGE_DOCUMENT_GLOBAL_BUDGET_PER_WINDOW - LARGE_DOCUMENT_BUDGET_PER_WINDOW) {
            assert!(budget.try_charge(&format!("vid:{i}")).is_ok());
        }
    }

    /// A penalised address pays its raised cost from its allowance, and one
    /// penalised past the allowance can pay for nothing.
    #[test]
    fn a_penalised_address_pays_its_cost() {
        let budget = LargeDocumentBudget::new();
        budget.penalize("ip:liar");
        budget.penalize("ip:liar");
        assert_eq!(budget.cost("ip:liar"), 4);
        assert!(budget.try_charge("ip:liar").is_ok(), "4 of its 5");
        assert!(budget.try_charge("ip:liar").is_err(), "1 left, cost 4");

        for _ in 0..10 {
            budget.penalize("ip:repeat");
        }
        assert_eq!(budget.cost("ip:repeat"), MAX_COST);
        assert!(budget.try_charge("ip:repeat").is_err());
    }

    #[test]
    fn a_full_penalty_table_keeps_its_penalties() {
        let budget = LargeDocumentBudget::new();
        budget.penalize("ip:abuser");
        {
            let mut penalties = budget.penalties.lock().unwrap();
            for i in 1..MAX_TRACKED_ADDRESSES {
                penalties.insert(
                    format!("ip:{i}"),
                    Penalty {
                        cost: 2,
                        since: std::time::Instant::now(),
                    },
                );
            }
        }
        budget.penalize("ip:new");
        assert_eq!(budget.cost("ip:new"), 1, "no room for a new penalty");
        budget.penalize("ip:abuser");
        assert_eq!(budget.cost("ip:abuser"), 4, "a held penalty still grows");
    }

    /// A raised cost halves every half-life, and is forgotten once it is back
    /// to 1.
    #[test]
    fn a_penalty_decays() {
        use std::time::{Duration, Instant};
        let budget = LargeDocumentBudget::new();
        let start = Instant::now();
        for _ in 0..10 {
            budget.penalize_at("ip:shared", start);
        }
        assert_eq!(budget.cost_at("ip:shared", start), MAX_COST);
        let half_life = Duration::from_secs(PENALTY_HALF_LIFE_SECS);
        assert_eq!(
            budget.cost_at("ip:shared", start + half_life - Duration::from_secs(1)),
            MAX_COST
        );
        assert_eq!(budget.cost_at("ip:shared", start + half_life), MAX_COST / 2);
        assert_eq!(budget.cost_at("ip:shared", start + half_life * 2), 1);
        assert!(
            budget.penalties.lock().unwrap().is_empty(),
            "a decayed penalty is forgotten"
        );

        // A further unverified claim doubles the decayed cost, not the old one.
        budget.penalize_at("ip:again", start);
        budget.penalize_at("ip:again", start);
        budget.penalize_at("ip:again", start + half_life);
        assert_eq!(budget.cost_at("ip:again", start + half_life), 4);
    }

    /// A claim that verifies halves its address's raised cost.
    #[tokio::test]
    async fn a_verified_claim_relieves_its_address() {
        let acl = acl_with("did:web:admin.example").await;
        let served = [DID_REGISTER];
        let budget = LargeDocumentBudget::new();
        for _ in 0..2 {
            budget.penalize("ip:shared");
        }
        assert_eq!(budget.cost("ip:shared"), 4);
        let doc = register_doc("did:web:admin.example", 200 * 1024);
        let charge = budget_charge(&doc, &served, &acl, &budget, "ip:shared").await;
        settle_large_document_charge(&budget, Some(&charge), Some("did:web:admin.example"));
        assert_eq!(budget.cost("ip:shared"), 2);
        budget.relieve("ip:shared");
        assert_eq!(budget.cost("ip:shared"), 1);
        assert!(budget.penalties.lock().unwrap().is_empty());
    }

    /// A `did:scid` issuer that names its `?src=` locator is the identity the
    /// verifier reports without it: not a mismatch, and not penalised.
    #[tokio::test]
    async fn a_did_scid_issuer_with_its_locator_is_not_penalised() {
        let identity = "did:scid:vh:1:QmScidIssuer";
        let acl = acl_with(identity).await;
        let served = [DID_REGISTER];
        let budget = LargeDocumentBudget::new();
        let doc = register_doc(&format!("{identity}?src=hosting.example/alice"), 200 * 1024);
        for _ in 0..LARGE_DOCUMENT_BUDGET_PER_WINDOW {
            let charge = budget_charge(&doc, &served, &acl, &budget, "ip:scid").await;
            settle_large_document_charge(&budget, Some(&charge), Some(identity));
            assert_eq!(budget.cost("ip:scid"), 1);
        }

        // A different identity is still a mismatch.
        let charge = LargeDocumentCharge {
            address: "ip:scid".into(),
            claimed_issuer: identity.into(),
        };
        settle_large_document_charge(&budget, Some(&charge), Some("did:scid:vh:1:QmOther"));
        assert_eq!(budget.cost("ip:scid"), 2);
    }

    /// A full table makes room for a new penalty by dropping the ones that
    /// have decayed.
    #[test]
    fn a_full_penalty_table_drops_decayed_penalties() {
        use std::time::{Duration, Instant};
        let budget = LargeDocumentBudget::new();
        let start = Instant::now();
        {
            let mut penalties = budget.penalties.lock().unwrap();
            for i in 0..MAX_TRACKED_ADDRESSES {
                penalties.insert(
                    format!("ip:{i}"),
                    Penalty {
                        cost: 2,
                        since: start,
                    },
                );
            }
        }
        let later = start + Duration::from_secs(PENALTY_HALF_LIFE_SECS);
        budget.penalize_at("ip:live", later);
        budget.penalize_at("ip:new", later);
        assert_eq!(budget.cost_at("ip:new", later), 2);
        assert_eq!(budget.penalties.lock().unwrap().len(), 2);
    }

    async fn budget_charge(
        doc: &[u8],
        served: &[&str],
        acl: &crate::server::store::KeyspaceHandle,
        budget: &LargeDocumentBudget,
        address: &str,
    ) -> LargeDocumentCharge {
        check_for_known_issuer(doc, served, acl, budget, address)
            .await
            .expect("within budget")
            .expect("a large document charges the budget")
    }

    #[test]
    fn a_full_budget_of_live_addresses_refuses_a_new_one() {
        let budget = LargeDocumentBudget::with_max_tracked_addresses(2);
        budget.try_charge("ip:0").unwrap();
        budget.try_charge("ip:1").unwrap();
        assert!(budget.try_charge("ip:new").is_err());
        assert!(
            budget.try_charge("ip:0").is_ok(),
            "a tracked address still charges"
        );
    }

    #[tokio::test]
    async fn small_documents_are_never_charged() {
        let acl = acl_with("did:web:admin.example").await;
        let served = [DID_REGISTER];
        let budget = LargeDocumentBudget::new();
        let small = register_doc("did:web:admin.example", 10);
        assert!(small.len() <= DEFAULT_MAX_DOCUMENT_BYTES);
        for _ in 0..(LARGE_DOCUMENT_BUDGET_PER_WINDOW * 3) {
            let charge = check_for_known_issuer(&small, &served, &acl, &budget, "ip:2.2.2.2")
                .await
                .expect("small document admitted");
            assert!(
                charge.is_none(),
                "a small document never charges the budget"
            );
        }
    }

    /// `did/register` as though this deployment served it (the only
    /// caller-relevant fact `max_in`/`largest_in` read from `served`).
    fn served_register(type_uri: &str) -> usize {
        max_in(type_uri, DECLARED, &[DID_REGISTER])
    }

    /// A document of `type_uri` padded to exactly `len` bytes.
    fn document_of(type_uri: &str, len: usize) -> Vec<u8> {
        let head = format!(r#"{{"type":"{type_uri}","payload":{{"pad":""#);
        let tail = r#""}}"#;
        let pad = len - head.len() - tail.len();
        let body = format!("{head}{}{tail}", "x".repeat(pad));
        assert_eq!(body.len(), len);
        body.into_bytes()
    }

    fn refusal(err: ErrorResponse) -> serde_json::Value {
        serde_json::to_value(&err.payload).unwrap()
    }

    #[test]
    fn every_declared_type_is_raised_above_the_default() {
        for (uri, max) in DECLARED {
            assert!(
                *max > DEFAULT_MAX_DOCUMENT_BYTES,
                "{uri} declares {max}, which is not above the default; drop it"
            );
        }
        let mut uris: Vec<&str> = DECLARED.iter().map(|(u, _)| *u).collect();
        uris.sort_unstable();
        uris.dedup();
        assert_eq!(uris.len(), DECLARED.len(), "a type is declared twice");
    }

    #[test]
    fn an_undeclared_type_takes_the_default() {
        assert_eq!(served_register(ACL_SHOW), DEFAULT_MAX_DOCUMENT_BYTES);
        assert_eq!(
            served_register(DID_REGISTER),
            DID_REGISTER_MAX_DOCUMENT_BYTES
        );
    }

    /// A raised limit on a type this deployment does not serve would only
    /// let an unauthenticated caller make the pipeline canonicalise and
    /// verify a larger document before refusing it as unrouted.
    #[test]
    fn a_declared_type_that_is_not_served_takes_the_default() {
        assert_eq!(
            max_in(DID_REGISTER, DECLARED, &[]),
            DEFAULT_MAX_DOCUMENT_BYTES
        );
        assert_eq!(largest_in(DECLARED, &[]), DEFAULT_MAX_DOCUMENT_BYTES);
        assert_eq!(
            largest_in(DECLARED, &[DID_REGISTER]),
            DID_REGISTER_MAX_DOCUMENT_BYTES
        );
        assert_eq!(
            max_document_bytes(DID_REGISTER, &[]),
            DEFAULT_MAX_DOCUMENT_BYTES
        );
        assert_eq!(
            max_document_bytes(DID_REGISTER, &[DID_REGISTER]),
            DID_REGISTER_MAX_DOCUMENT_BYTES
        );
        assert!(largest_max_document_bytes(&[]) >= DEFAULT_MAX_DOCUMENT_BYTES);
    }

    #[test]
    fn a_document_at_its_types_limit_is_admitted() {
        assert!(check(&document_of(ACL_SHOW, DEFAULT_MAX_DOCUMENT_BYTES), &[]).is_ok());
        assert!(
            check_with(
                &document_of(DID_REGISTER, DID_REGISTER_MAX_DOCUMENT_BYTES),
                served_register
            )
            .is_ok()
        );
    }

    #[test]
    fn a_document_over_the_default_is_refused_for_a_type_that_declares_nothing() {
        let err = check(&document_of(ACL_SHOW, DEFAULT_MAX_DOCUMENT_BYTES + 1), &[]).unwrap_err();
        let payload = refusal(err);
        assert_eq!(payload["code"], "malformedRequest");
        assert_eq!(
            payload["details"][DETAILS_MAX_BYTES],
            DEFAULT_MAX_DOCUMENT_BYTES
        );
    }

    #[test]
    fn a_1mib_register_document_is_admitted_and_over_the_limit_is_refused() {
        assert!(
            check(
                &document_of(DID_REGISTER, DID_REGISTER_MAX_DOCUMENT_BYTES),
                &[DID_REGISTER]
            )
            .is_ok()
        );
        let err = check(
            &document_of(DID_REGISTER, DID_REGISTER_MAX_DOCUMENT_BYTES + 1),
            &[DID_REGISTER],
        )
        .unwrap_err();
        let payload = refusal(err);
        assert_eq!(payload["code"], "malformedRequest");
        assert_eq!(
            payload["details"][DETAILS_MAX_BYTES],
            DID_REGISTER_MAX_DOCUMENT_BYTES
        );
    }

    /// A type this deployment does not serve claiming the raised limit
    /// gets only the default, even though it is in `DECLARED`.
    #[test]
    fn an_unserved_type_claiming_a_large_limit_gets_only_the_default() {
        let err = check(
            &document_of(DID_REGISTER, DEFAULT_MAX_DOCUMENT_BYTES + 1),
            &[], // did/register is declared, but not served here.
        )
        .unwrap_err();
        let payload = refusal(err);
        assert_eq!(
            payload["details"][DETAILS_MAX_BYTES],
            DEFAULT_MAX_DOCUMENT_BYTES
        );
    }

    /// The `type` is the top-level one wherever it sits: one placed after
    /// a large member is still the one the limit is looked up by, and a
    /// nested `type` is not it.
    #[test]
    fn the_type_is_the_top_level_one_wherever_it_sits() {
        let pad = "x".repeat(DEFAULT_MAX_DOCUMENT_BYTES);
        let late = format!(
            r#"{{"payload":{{"type":"{ACL_SHOW}","pad":"{pad}"}},"type":"{DID_REGISTER}"}}"#
        );
        assert!(check_with(late.as_bytes(), served_register).is_ok());
        let nested_only = format!(r#"{{"payload":{{"type":"{DID_REGISTER}","pad":"{pad}"}}}}"#);
        assert_eq!(
            refusal(check_with(nested_only.as_bytes(), served_register).unwrap_err())["details"]
                [DETAILS_MAX_BYTES],
            DEFAULT_MAX_DOCUMENT_BYTES
        );
    }

    /// A late `type` — one that appears after a lot of padding rather
    /// than first in the object — is still the one read, because
    /// `serde_json` reads the whole object rather than stopping at the
    /// first member.
    #[test]
    fn a_late_type_in_the_body_is_still_read() {
        let pad = "x".repeat(DEFAULT_MAX_DOCUMENT_BYTES);
        let late = format!(r#"{{"pad":"{pad}","type":"{DID_REGISTER}"}}"#);
        assert!(check_with(late.as_bytes(), served_register).is_ok());
    }

    /// Two top-level `type` members cannot claim the larger limit: the
    /// strict, single-field probe refuses the shape and the body takes
    /// the default.
    #[test]
    fn a_duplicated_type_takes_the_default() {
        let pad = "x".repeat(DEFAULT_MAX_DOCUMENT_BYTES);
        let body = format!(r#"{{"type":"{ACL_SHOW}","type":"{DID_REGISTER}","pad":"{pad}"}}"#);
        assert_eq!(
            refusal(check_with(body.as_bytes(), served_register).unwrap_err())["details"]
                [DETAILS_MAX_BYTES],
            DEFAULT_MAX_DOCUMENT_BYTES
        );
    }

    /// The refusal repeats a caller's `type` only when it could be a Type
    /// URI; an oversized `type` string is not echoed.
    #[test]
    fn a_refusal_does_not_echo_an_oversized_type() {
        let huge = "t".repeat(DEFAULT_MAX_DOCUMENT_BYTES + 1);
        let body = format!(r#"{{"type":"{huge}"}}"#);
        let payload = refusal(check(body.as_bytes(), &[]).unwrap_err());
        let text = payload.to_string();
        assert!(
            text.len() < 1024,
            "the refusal echoes the body: {} bytes",
            text.len()
        );
        assert_eq!(
            payload["details"],
            serde_json::json!({ DETAILS_MAX_BYTES: DEFAULT_MAX_DOCUMENT_BYTES })
        );
    }

    /// An oversized body with no readable `type` cannot claim a raised
    /// limit: it is held to the default, and refused without being
    /// parsed further.
    #[test]
    fn an_oversized_body_with_no_readable_type_takes_the_default() {
        let junk = vec![b'['; DEFAULT_MAX_DOCUMENT_BYTES + 1];
        let payload = refusal(check(&junk, &[]).unwrap_err());
        assert_eq!(payload["code"], "malformedRequest");
        assert_eq!(
            payload["details"][DETAILS_MAX_BYTES],
            DEFAULT_MAX_DOCUMENT_BYTES
        );
    }
}
