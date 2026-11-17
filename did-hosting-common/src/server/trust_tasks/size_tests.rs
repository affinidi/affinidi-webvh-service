//! Tests for [`super`].

// The tests that open a store are fjall-only (a fresh temp-dir store
// each); what only they use is unused on other backends.
#![cfg_attr(not(feature = "store-fjall"), allow(unused_imports, dead_code))]
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

#[cfg(feature = "store-fjall")]
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

#[cfg(feature = "store-fjall")]
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
#[cfg(feature = "store-fjall")]
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
#[cfg(feature = "store-fjall")]
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
#[cfg(feature = "store-fjall")]
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
    for i in 0..LARGE_DOCUMENT_UNPROVEN_SHARE_PER_WINDOW {
        assert!(budget.try_charge(&format!("vid:{i}")).is_ok());
    }
    assert!(
        budget.try_charge("vid:fresh").is_err(),
        "a fresh address does not escape the service-wide cap"
    );
}

/// Addresses that have never proven a claim can spend only their share of
/// the every-address budget: a proven address still gets the rest, and
/// together they never exceed the whole.
#[test]
fn unproven_addresses_cannot_spend_the_proven_share() {
    let budget = LargeDocumentBudget::new();
    let proven = (0..LARGE_DOCUMENT_GLOBAL_BUDGET_PER_WINDOW)
        .map(|i| format!("ip:proven-{i}"))
        .collect::<Vec<_>>();
    for address in &proven {
        budget.relieve(address);
    }
    for i in 0..LARGE_DOCUMENT_UNPROVEN_SHARE_PER_WINDOW {
        budget.try_charge(&format!("vid:stranger-{i}")).unwrap();
    }
    assert!(
        budget.try_charge("vid:another-stranger").is_err(),
        "strangers have spent their share"
    );
    let proven_share =
        LARGE_DOCUMENT_GLOBAL_BUDGET_PER_WINDOW - LARGE_DOCUMENT_UNPROVEN_SHARE_PER_WINDOW;
    for address in proven.iter().take(proven_share as usize) {
        assert!(
            budget.try_charge(address).is_ok(),
            "a proven address is admitted though strangers spent theirs"
        );
    }
    assert!(
        budget.try_charge(&proven[proven_share as usize]).is_err(),
        "the whole budget is still the cap"
    );
}

/// A proven address draws on the open share once its own is spent.
#[test]
fn a_proven_address_falls_back_to_the_open_share() {
    let budget = LargeDocumentBudget::new();
    let proven_share =
        LARGE_DOCUMENT_GLOBAL_BUDGET_PER_WINDOW - LARGE_DOCUMENT_UNPROVEN_SHARE_PER_WINDOW;
    for _ in 0..proven_share {
        budget.global_proven.try_consume(()).unwrap();
    }
    budget.relieve("ip:proven");
    assert!(budget.try_charge("ip:proven").is_ok());
}

/// Proven standing lapses after its time, and ends at once when a claim
/// from the address does not verify.
#[test]
fn proven_standing_lapses_and_ends_on_a_failed_claim() {
    use std::time::{Duration, Instant};
    let budget = LargeDocumentBudget::new();
    let start = Instant::now();
    budget.relieve_at("ip:a", start);
    assert!(budget.is_proven_at("ip:a", start));
    assert!(!budget.is_proven_at("ip:a", start + Duration::from_secs(PROVEN_ADDRESS_TTL_SECS)));

    budget.relieve_at("ip:b", start);
    let charge = LargeDocumentCharge {
        address: "ip:b".into(),
        claimed_issuer: "did:web:admin.example".into(),
    };
    settle_large_document_charge(&budget, Some(&charge), None);
    assert!(!budget.is_proven_at("ip:b", start));
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
    for i in 0..(LARGE_DOCUMENT_UNPROVEN_SHARE_PER_WINDOW - LARGE_DOCUMENT_BUDGET_PER_WINDOW) {
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
#[cfg(feature = "store-fjall")]
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
#[cfg(feature = "store-fjall")]
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

#[cfg(feature = "store-fjall")]
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
    let late =
        format!(r#"{{"payload":{{"type":"{ACL_SHOW}","pad":"{pad}"}},"type":"{DID_REGISTER}"}}"#);
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
