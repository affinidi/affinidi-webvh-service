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
//! The budget across every address is split. An address whose large claim has
//! verified within [`PROVEN_ADDRESS_TTL_SECS`] draws on a share that no other
//! address can spend; every other address draws only on
//! [`LARGE_DOCUMENT_UNPROVEN_SHARE_PER_WINDOW`]. Claims that never verify can
//! then use up that share, but not what proven callers rely on.
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

/// The part of [`LARGE_DOCUMENT_GLOBAL_BUDGET_PER_WINDOW`] that addresses
/// with no recently verified large claim may spend between them per window.
/// The rest is kept for proven addresses (see [`PROVEN_ADDRESS_TTL_SECS`]),
/// which fall back to this share only once theirs is spent. A caller's first
/// large document, before it has proven anything, comes from this share.
pub const LARGE_DOCUMENT_UNPROVEN_SHARE_PER_WINDOW: u64 = 20;

/// How long an address counts as proven after a large document from it
/// verified to exactly the issuer it claimed. Each further verified claim
/// renews it; a claim that does not verify ends it.
pub const PROVEN_ADDRESS_TTL_SECS: u64 = 60 * 60;

/// The `limiter` the proven addresses' share logs its refusals under.
const GLOBAL_PROVEN_LIMITER: &str = "large-document-global-proven";

/// The `limiter` the per-address budget logs its refusals under.
const PER_ADDRESS_LIMITER: &str = "large-document-per-address";

/// The `limiter` the share for unproven addresses logs its refusals under.
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
/// unverified claim from its address. The highest cost (`MAX_COST`) is back
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
    /// The every-address share open to any address
    /// ([`LARGE_DOCUMENT_UNPROVEN_SHARE_PER_WINDOW`]).
    global: KeyedRateLimiter<()>,
    /// The rest of the every-address budget, open only to proven addresses.
    global_proven: KeyedRateLimiter<()>,
    /// Addresses whose large claim last verified, and when; bounded by
    /// [`MAX_TRACKED_ADDRESSES`].
    proven: std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
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
                LARGE_DOCUMENT_UNPROVEN_SHARE_PER_WINDOW,
                LARGE_DOCUMENT_BUDGET_WINDOW_SECS,
            ),
            global_proven: KeyedRateLimiter::new(
                GLOBAL_PROVEN_LIMITER,
                LARGE_DOCUMENT_GLOBAL_BUDGET_PER_WINDOW - LARGE_DOCUMENT_UNPROVEN_SHARE_PER_WINDOW,
                LARGE_DOCUMENT_BUDGET_WINDOW_SECS,
            ),
            proven: Default::default(),
            penalties: Default::default(),
        }
    }

    /// Sweep addresses whose allowance has refilled out of the budget's
    /// memory every minute until `shutdown` fires. Penalties are not swept
    /// here: they decay, and `Self::penalize` drops the decayed ones when
    /// the table is full. Must run on a Tokio runtime.
    pub fn spawn_gc(&self, shutdown: &tokio_util::sync::CancellationToken) {
        self.per_address.spawn_gc(shutdown.clone());
        self.global.spawn_gc(shutdown.clone());
        self.global_proven.spawn_gc(shutdown.clone());
    }

    /// Charge `address` for one large document, at its current per-document
    /// cost, then the every-address budget for one: a proven address's own
    /// share first, then the share open to all. `Err` is the number of
    /// seconds until a retry can succeed.
    ///
    /// The address is charged first, so an address over its own budget never
    /// spends the shared one. A penalised address that cannot pay its whole
    /// cost loses what it could pay: it has already been caught once.
    fn try_charge(&self, address: &str) -> Result<(), u64> {
        self.try_charge_at(address, std::time::Instant::now())
    }

    fn try_charge_at(&self, address: &str, now: std::time::Instant) -> Result<(), u64> {
        for _ in 0..self.cost_at(address, now) {
            self.per_address
                .try_consume(address.to_owned())
                .map_err(retry_after)?;
        }
        if self.is_proven_at(address, now) && self.global_proven.try_consume(()).is_ok() {
            return Ok(());
        }
        self.global.try_consume(()).map_err(retry_after)
    }

    /// Whether a large claim from `address` verified within
    /// [`PROVEN_ADDRESS_TTL_SECS`] of `now`.
    fn is_proven_at(&self, address: &str, now: std::time::Instant) -> bool {
        self.lock_proven().get(address).is_some_and(|at| {
            now.saturating_duration_since(*at).as_secs() < PROVEN_ADDRESS_TTL_SECS
        })
    }

    /// Record that a large claim from `address` verified at `now`. A full
    /// table drops the expired entries, then the oldest: only verified
    /// callers add entries, so no stranger can push one out.
    fn mark_proven_at(&self, address: &str, now: std::time::Instant) {
        let mut proven = self.lock_proven();
        if proven.len() >= MAX_TRACKED_ADDRESSES && !proven.contains_key(address) {
            proven.retain(|_, at| {
                now.saturating_duration_since(*at).as_secs() < PROVEN_ADDRESS_TTL_SECS
            });
            if proven.len() >= MAX_TRACKED_ADDRESSES
                && let Some(oldest) = proven
                    .iter()
                    .min_by_key(|(_, at)| **at)
                    .map(|(k, _)| k.clone())
            {
                proven.remove(&oldest);
            }
        }
        proven.insert(address.to_owned(), now);
    }

    fn lock_proven(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, std::time::Instant>> {
        self.proven
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
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
        // A claim that did not verify ends the address's proven standing.
        self.lock_proven().remove(address);
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

    /// Halve `address`'s raised cost, and count it as proven — called once a
    /// claim from it verified to exactly the issuer it named. A penalty earned
    /// by another sender behind the same address (a shared egress, a proxy
    /// missing from `trusted_proxies`) then does not hold back a caller that
    /// keeps proving who it is.
    fn relieve(&self, address: &str) {
        self.relieve_at(address, std::time::Instant::now());
    }

    fn relieve_at(&self, address: &str, now: std::time::Instant) {
        self.mark_proven_at(address, now);
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
    #[cfg(test)]
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
/// (`LargeDocumentBudget::penalize`). A charge that verified to its claimed
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
#[path = "size_tests.rs"]
mod tests;
