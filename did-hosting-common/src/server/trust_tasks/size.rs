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
//! verified issuer that turns out to be someone else).

use trust_tasks_rs::{ErrorPayload, ErrorResponse, Payload, RejectReason, TrustTask};

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
    <trust_tasks_rs::specs::did_management::did::register::v0_1::Payload as Payload>::TYPE_URI,
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

/// Fixed-window length, in seconds, for [`LargeDocumentBudget`].
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

/// Hard cap on tracked-address map size. Past it, addresses with nothing at
/// stake — an expired window and no penalty — are evicted; if the map is
/// still full, a new address is refused rather than tracked. Clearing the map
/// wholesale, as the per-IP limiters do, would also wipe every penalty, which
/// a novel-address flood could then trigger on purpose.
const MAX_TRACKED_ADDRESSES: usize = 10_000;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Cost units spent in the current window.
    spent: u64,
    /// `now` (epoch seconds) of the window start.
    window_start: u64,
    /// The cost of this address's *next* charge — 1 until
    /// [`LargeDocumentBudget::penalize`] doubles it.
    cost: u64,
}

/// Per-address budget for documents [`check_for_known_issuer`] grants the
/// raised limit to before their claimed issuer is verified. See the module
/// docs.
#[derive(Debug, Default)]
pub struct LargeDocumentBudget {
    inner: std::sync::Mutex<BudgetState>,
}

#[derive(Debug, Default)]
struct BudgetState {
    buckets: std::collections::HashMap<String, Bucket>,
    /// The every-address window: see [`LARGE_DOCUMENT_GLOBAL_BUDGET_PER_WINDOW`].
    global_spent: u64,
    global_window_start: u64,
}

impl LargeDocumentBudget {
    pub fn new() -> Self {
        Self::default()
    }

    /// Charge `address` for one large document, at its current per-charge
    /// cost. `Err` is the number of seconds until the window rolls over,
    /// once spending would exceed [`LARGE_DOCUMENT_BUDGET_PER_WINDOW`] for
    /// the current one.
    fn try_charge(&self, address: &str, now: u64) -> Result<(), u64> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = &mut *state;

        if now.saturating_sub(state.global_window_start) >= LARGE_DOCUMENT_BUDGET_WINDOW_SECS {
            state.global_spent = 0;
            state.global_window_start = now;
        }
        let global_retry =
            (state.global_window_start + LARGE_DOCUMENT_BUDGET_WINDOW_SECS).saturating_sub(now);
        if state.global_spent >= LARGE_DOCUMENT_GLOBAL_BUDGET_PER_WINDOW {
            return Err(global_retry);
        }

        let buckets = &mut state.buckets;
        if buckets.len() >= MAX_TRACKED_ADDRESSES && !buckets.contains_key(address) {
            buckets.retain(|_, b| {
                b.cost > 1 || now.saturating_sub(b.window_start) < LARGE_DOCUMENT_BUDGET_WINDOW_SECS
            });
            if buckets.len() >= MAX_TRACKED_ADDRESSES {
                return Err(global_retry);
            }
        }

        let entry = buckets.entry(address.to_string()).or_insert(Bucket {
            spent: 0,
            window_start: now,
            cost: 1,
        });

        if now.saturating_sub(entry.window_start) >= LARGE_DOCUMENT_BUDGET_WINDOW_SECS {
            entry.spent = 0;
            entry.window_start = now;
        }

        if entry.spent.saturating_add(entry.cost) > LARGE_DOCUMENT_BUDGET_PER_WINDOW {
            let retry_after_secs =
                (entry.window_start + LARGE_DOCUMENT_BUDGET_WINDOW_SECS).saturating_sub(now);
            return Err(retry_after_secs);
        }
        entry.spent += entry.cost;
        state.global_spent += 1;
        Ok(())
    }

    /// Double `address`'s per-charge cost — called once a claimed issuer
    /// this budget let through turns out to have failed verification, or
    /// proven to be someone else. Persists across windows (a penalty is
    /// against the address, not the minute it earned it); capped well
    /// short of overflow, since a handful of doublings already exhausts the
    /// window on its own.
    fn penalize(&self, address: &str) {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = state.buckets.entry(address.to_string()).or_insert(Bucket {
            spent: 0,
            window_start: 0,
            cost: 1,
        });
        entry.cost = entry.cost.saturating_mul(2).min(1 << 20);
    }

    #[cfg(test)]
    fn cost(&self, address: &str) -> u64 {
        self.inner
            .lock()
            .unwrap()
            .buckets
            .get(address)
            .map(|b| b.cost)
            .unwrap_or(1)
    }
}

/// A per-address [`LargeDocumentBudget`] charge [`check_for_known_issuer`]
/// made before this document's proof was verified. Pass it to
/// [`settle_large_document_charge`] once the caller's own verification
/// concludes.
#[derive(Debug)]
pub struct LargeDocumentCharge {
    address: String,
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
    now: u64,
) -> Result<Option<LargeDocumentCharge>, ErrorResponse> {
    if body.len() <= DEFAULT_MAX_DOCUMENT_BYTES {
        return Ok(None);
    }
    let claimed_issuer = match peek_issuer(body) {
        Some(issuer)
            if matches!(
                crate::server::acl::get_acl_entry(acl, &issuer).await,
                Ok(Some(_))
            ) =>
        {
            Some(issuer)
        }
        _ => None,
    };
    let Some(claimed_issuer) = claimed_issuer else {
        check_with(body, |_| DEFAULT_MAX_DOCUMENT_BYTES)?;
        return Ok(None);
    };
    if let Err(retry_after_secs) = budget.try_charge(address, now) {
        return Err(unrouted_error(
            RejectReason::Unavailable {
                retry_after: Some(
                    chrono::Utc::now() + chrono::Duration::seconds(retry_after_secs as i64),
                ),
            }
            .into(),
        ));
    }
    check(body, served)?;
    Ok(Some(LargeDocumentCharge {
        address: address.to_string(),
        claimed_issuer,
    }))
}

/// Settle a [`LargeDocumentCharge`] once the caller's own proof verification
/// concludes. `verified_issuer` is the proven signer on success, or `None`
/// on any verification failure. A `verified_issuer` that is not exactly the
/// one the charge was granted against — including a failure, which proves
/// none at all — doubles the address's cost for its next large document
/// ([`LargeDocumentBudget::penalize`]). A charge that verified to exactly
/// its claimed issuer costs nothing extra.
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
    if verified_issuer != Some(charge.claimed_issuer.as_str()) {
        budget.penalize(&charge.address);
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
        <trust_tasks_rs::specs::did_management::did::register::v0_1::Payload as Payload>::TYPE_URI;
    const ACL_SHOW: &str = <trust_tasks_rs::specs::acl::show::v0_1::Payload as Payload>::TYPE_URI;

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
            check_for_known_issuer(&big, &served, &acl, &budget, "ip:1.2.3.4", 0)
                .await
                .is_ok()
        );
        let stranger = register_doc("did:web:stranger.example", 200 * 1024);
        assert!(
            check_for_known_issuer(&stranger, &served, &acl, &budget, "ip:5.6.7.8", 0)
                .await
                .is_err()
        );
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
                check_for_known_issuer(&doc, &served, &acl, &budget, "ip:9.9.9.9", 0)
                    .await
                    .is_ok()
            );
        }
        let err = check_for_known_issuer(&doc, &served, &acl, &budget, "ip:9.9.9.9", 0)
            .await
            .unwrap_err();
        assert_eq!(refusal(err)["code"], "unavailable");
        // A different address is unaffected.
        assert!(
            check_for_known_issuer(&doc, &served, &acl, &budget, "ip:1.1.1.1", 0)
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
        let charge = check_for_known_issuer(&doc, &served, &acl, &budget, "ip:1.2.3.4", 0)
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
            assert!(budget.try_charge(&format!("vid:{i}"), 1_000).is_ok());
        }
        assert!(
            budget.try_charge("vid:fresh", 1_000).is_err(),
            "a fresh address does not escape the service-wide cap"
        );
        assert!(
            budget
                .try_charge("vid:fresh", 1_000 + LARGE_DOCUMENT_BUDGET_WINDOW_SECS)
                .is_ok(),
            "the next window has room again"
        );
    }

    #[test]
    fn a_full_map_keeps_its_penalties() {
        let budget = LargeDocumentBudget::new();
        budget.penalize("ip:abuser");
        {
            let mut state = budget.inner.lock().unwrap();
            for i in 0..MAX_TRACKED_ADDRESSES {
                state.buckets.insert(
                    format!("ip:{i}"),
                    Bucket {
                        spent: 0,
                        window_start: 0,
                        cost: 1,
                    },
                );
            }
        }
        // Every filler's window has expired: they are evicted, the penalty is not.
        assert!(budget.try_charge("ip:new", 10_000).is_ok());
        assert_eq!(budget.cost("ip:abuser"), 2);
    }

    #[test]
    fn a_full_map_of_live_addresses_refuses_a_new_one() {
        let budget = LargeDocumentBudget::new();
        {
            let mut state = budget.inner.lock().unwrap();
            for i in 0..MAX_TRACKED_ADDRESSES {
                state.buckets.insert(
                    format!("ip:{i}"),
                    Bucket {
                        spent: 1,
                        window_start: 10_000,
                        cost: 1,
                    },
                );
            }
        }
        assert!(budget.try_charge("ip:new", 10_000).is_err());
        assert!(
            budget.try_charge("ip:0", 10_000).is_ok(),
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
            let charge = check_for_known_issuer(&small, &served, &acl, &budget, "ip:2.2.2.2", 0)
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
