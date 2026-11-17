//! Tests for `did/list` paging, filters and the derived rows (#375).

use super::test_helpers::*;
use super::*;

use crate::server::AppState;
use did_hosting_common::server::acl::Role;

// ---- did/list paging, filters and the derived rows (#375) ----

/// Seed a record as the write paths leave it: record, owner index and the
/// derived rows, in one batch.
async fn seed_listed(state: &AppState, owner: &str, mnemonic: &str, domain: &str, names: &[&str]) {
    let record = DidRecord {
        owner: owner.into(),
        mnemonic: mnemonic.into(),
        created_at: 1,
        updated_at: 1,
        version_count: 1,
        did_id: Some(format!("did:webvh:scid:{domain}:{mnemonic}")),
        content_size: 10,
        disabled: false,
        disabled_by_admin: false,
        deleted_at: None,
        method: "webvh".into(),
        domain: domain.into(),
        services: None,
        agent_names: names
            .iter()
            .map(|n| AgentNameEntry {
                name: (*n).into(),
                enabled: true,
                created_at: 1,
            })
            .collect(),
    };
    let mut batch = state.store.batch();
    batch
        .insert(&state.dids_ks, did_key(mnemonic), &record)
        .unwrap();
    batch.insert_raw(
        &state.dids_ks,
        owner_key(owner, mnemonic),
        mnemonic.as_bytes().to_vec(),
    );
    for n in names {
        batch.insert_raw(
            &state.dids_ks,
            agent_name_key(domain, n),
            mnemonic.as_bytes().to_vec(),
        );
    }
    let _g = stage_index(state, &mut batch, None, Some(&record))
        .await
        .unwrap();
    batch.commit().await.unwrap();
}

/// Every page of a listing, followed to the end; with the size of each.
async fn all_pages(
    state: &AppState,
    auth: &AuthClaims,
    filter: &ListFilter<'_>,
    limit: usize,
) -> (Vec<String>, Vec<usize>) {
    let (mut seen, mut sizes) = (Vec::new(), Vec::new());
    let mut after: Option<String> = None;
    for _ in 0..1000 {
        let page = list_dids_page(auth, false, state, filter, Some(limit), after.as_deref())
            .await
            .unwrap();
        assert!(page.records.len() <= limit);
        sizes.push(page.records.len());
        seen.extend(page.records.into_iter().map(|(r, _)| r.mnemonic));
        match page.resume_after {
            Some(next) => after = Some(next),
            None => return (seen, sizes),
        }
    }
    panic!("the listing never ended");
}

/// 23 slots across two owners and two domains, plus one owner whose DID
/// is a string prefix of another's.
async fn seed_listing(state: &AppState) -> Vec<String> {
    let mut all = Vec::new();
    for i in 0..23 {
        let m = format!("slot-{i:02}");
        let owner = if i % 3 == 0 {
            "did:example:b"
        } else {
            "did:example:a"
        };
        let domain = if i % 2 == 0 { "a.example" } else { "b.example" };
        let names: &[&str] = if i == 7 { &["seven"] } else { &[] };
        seed_listed(state, owner, &m, domain, names).await;
        all.push(m);
    }
    // `did:example:a` is a string prefix of this owner, and `a.example`
    // of this domain: neither may leak into the other's listing.
    seed_listed(state, "did:example:a:x", "zz-prefix", "a.example:8443", &[]).await;
    all.push("zz-prefix".into());
    all
}

async fn check_listings(state: &AppState) {
    let all = seed_listing(state).await;
    let admin = admin_auth("did:example:admin");

    // Everything, in order, exactly once, across pages.
    let (seen, _) = all_pages(state, &admin, &ListFilter::default(), 4).await;
    assert_eq!(seen, all);

    // One domain.
    let filter = ListFilter {
        domain: Some("a.example"),
        ..Default::default()
    };
    let (seen, _) = all_pages(state, &admin, &filter, 3).await;
    let expected: Vec<String> = (0..23)
        .filter(|i| i % 2 == 0)
        .map(|i| format!("slot-{i:02}"))
        .collect();
    assert_eq!(seen, expected, "the :8443 neighbour is not a.example's");

    // An owner's own slots (not the prefix-sharing owner's).
    let (seen, _) = all_pages(
        state,
        &owner_auth("did:example:a"),
        &ListFilter::default(),
        5,
    )
    .await;
    let expected: Vec<String> = (0..23)
        .filter(|i| i % 3 != 0)
        .map(|i| format!("slot-{i:02}"))
        .collect();
    assert_eq!(seen, expected);

    // Owner and domain together.
    let filter = ListFilter {
        domain: Some("b.example"),
        ..Default::default()
    };
    let (seen, _) = all_pages(state, &owner_auth("did:example:b"), &filter, 2).await;
    assert_eq!(seen, ["slot-03", "slot-09", "slot-15", "slot-21"]);

    // Search: mnemonic, DID or agent name, ignoring case.
    let filter = ListFilter {
        search: Some("SLOT-1"),
        ..Default::default()
    };
    let (seen, _) = all_pages(state, &admin, &filter, 4).await;
    let expected: Vec<String> = (10..20).map(|i| format!("slot-{i:02}")).collect();
    assert_eq!(seen, expected);
    let filter = ListFilter {
        search: Some("seve"),
        ..Default::default()
    };
    assert_eq!(all_pages(state, &admin, &filter, 4).await.0, ["slot-07"]);

    // One agent name, from the name index.
    let filter = ListFilter {
        domain: Some("b.example"),
        agent_name: Some("seven"),
        ..Default::default()
    };
    assert_eq!(all_pages(state, &admin, &filter, 4).await.0, ["slot-07"]);
    // Not on another domain, and not for an owner who does not hold it.
    let filter = ListFilter {
        domain: Some("a.example"),
        agent_name: Some("seven"),
        ..Default::default()
    };
    assert!(all_pages(state, &admin, &filter, 4).await.0.is_empty());
    let filter = ListFilter {
        domain: Some("b.example"),
        agent_name: Some("seven"),
        ..Default::default()
    };
    assert!(
        all_pages(state, &owner_auth("did:example:b"), &filter, 4)
            .await
            .0
            .is_empty()
    );
}

#[tokio::test]
async fn listing_pages_are_ordered_complete_and_filtered_on_a_key_ordered_store() {
    let (state, _dir) = test_state().await;
    assert!(state.dids_ks.pages_in_key_order());
    check_listings(&state).await;
}

#[tokio::test]
async fn listing_pages_are_the_same_on_a_hash_ordered_store() {
    let (mut state, _dir) = test_state().await;
    state.dids_ks = state.dids_ks.with_hash_ordered_pages();
    assert!(!state.dids_ks.pages_in_key_order());
    check_listings(&state).await;
}

#[tokio::test]
async fn a_listing_resumes_after_a_slot_removed_between_pages() {
    let (state, _dir) = test_state().await;
    let all = seed_listing(&state).await;
    let admin = admin_auth("did:example:admin");
    let first = list_dids_page(&admin, false, &state, &ListFilter::default(), Some(5), None)
        .await
        .unwrap();
    let after = first.resume_after.clone().unwrap();
    assert_eq!(after, "slot-04");
    // The slot the cursor names goes; the next page still starts after it.
    state.dids_ks.remove(did_key("slot-04")).await.unwrap();
    let next = list_dids_page(
        &admin,
        false,
        &state,
        &ListFilter::default(),
        Some(5),
        Some(&after),
    )
    .await
    .unwrap();
    let got: Vec<&str> = next
        .records
        .iter()
        .map(|(r, _)| r.mnemonic.as_str())
        .collect();
    assert_eq!(got, &all[5..10]);
}

#[tokio::test]
async fn a_selective_search_returns_short_pages_within_its_scan_budget() {
    let (state, _dir) = test_state().await;
    let mut batch = state.store.batch();
    let mut records = Vec::new();
    for i in 0..(LIST_SCAN_BUDGET + 10) {
        let m = format!("m{i:06}");
        let record = DidRecord {
            owner: "did:example:a".into(),
            mnemonic: m.clone(),
            created_at: 1,
            updated_at: 1,
            version_count: 0,
            did_id: None,
            content_size: 0,
            disabled: false,
            disabled_by_admin: false,
            deleted_at: None,
            method: "webvh".into(),
            domain: String::new(),
            services: None,
            agent_names: Vec::new(),
        };
        batch.insert(&state.dids_ks, did_key(&m), &record).unwrap();
        records.push(record);
    }
    batch.commit_in_parts().await.unwrap();
    // Only the very last slot matches.
    let needle = format!("m{:06}", LIST_SCAN_BUDGET + 9);
    let filter = ListFilter {
        search: Some(&needle),
        ..Default::default()
    };
    let admin = admin_auth("did:example:admin");
    let first = list_dids_page(&admin, false, &state, &filter, Some(10), None)
        .await
        .unwrap();
    assert!(first.records.is_empty(), "the budget ran out first");
    assert!(
        first.resume_after.is_some(),
        "and the page says where to resume"
    );
    let (seen, _) = all_pages(&state, &admin, &filter, 10).await;
    assert_eq!(seen, [needle]);
}

#[tokio::test]
async fn usage_counters_follow_register_transfer_and_delete() {
    let (state, _dir) = test_state().await;
    register_owned(&state, "did:example:a", "alpha").await;
    register_owned(&state, "did:example:a", "beta").await;
    let size = |state: &AppState, m: &'static str| {
        let state = state.clone();
        async move {
            state
                .dids_ks
                .get::<DidRecord>(did_key(m))
                .await
                .unwrap()
                .unwrap()
                .content_size
        }
    };
    let (a, b) = (size(&state, "alpha").await, size(&state, "beta").await);
    assert_eq!(
        owner_usage(&state, "did:example:a").await.unwrap(),
        (2, a + b)
    );

    seed_caller_acl(
        &state,
        "did:example:b",
        Role::Owner,
        did_hosting_common::server::domain::DomainScope::All,
    )
    .await;
    // An admin moves one slot to another owner.
    change_did_owner(
        &admin_auth("did:example:admin"),
        &state,
        "beta",
        "did:example:b",
        None,
    )
    .await
    .map_err(|e| format!("{e}"))
    .unwrap();
    assert_eq!(owner_usage(&state, "did:example:a").await.unwrap(), (1, a));
    assert_eq!(owner_usage(&state, "did:example:b").await.unwrap(), (1, b));

    delete_did(&owner_auth("did:example:a"), &state, "alpha", None)
        .await
        .unwrap();
    assert_eq!(owner_usage(&state, "did:example:a").await.unwrap(), (0, 0));

    // The domain index followed the slots too.
    let mnemonics = crate::control_tasks::queries::domain_mnemonics(&state, "control.test")
        .await
        .unwrap();
    assert_eq!(mnemonics, ["beta"]);
}
