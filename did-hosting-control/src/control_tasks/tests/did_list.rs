//! `did/list` filters and its webvh extension.

use super::*;

/// Create the active hosting domain `name`.
pub(super) async fn seed_hosting_domain(state: &AppState, name: &str) {
    did_hosting_common::server::domain::create_domain(
        &state.store,
        &did_hosting_common::server::domain::DomainEntry {
            name: name.into(),
            label: None,
            scheme: did_hosting_common::server::domain::DomainUrlScheme::Https,
            status: did_hosting_common::server::domain::DomainStatus::Active,
            created_at: 7,
            default_domain: false,
            branding: None,
            witnesses: None,
            watchers: None,
            quota: None,
            well_known_enabled: false,
            disabled_at: None,
            purge_at: None,
        },
    )
    .await
    .unwrap();
}

/// `did/list`'s webvh extension: `search` narrows the listing, binds its
/// cursor, and an unknown member is refused rather than ignored.
#[tokio::test]
async fn list_searches_through_the_webvh_extension() {
    let (state, _dir) = state().await;
    let owner = member(&state, 40, Role::Owner).await;
    for m in ["alpha-one", "alpha-two", "beta-one", "alpha-three"] {
        seed_did(&state, &owner.did, m).await;
    }
    let search = |s: &str| json!({ "vnd.affinidi.webvh": { "search": s } });

    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        LIST,
        json!({ "limit": 2, "ext": search("ALPHA") }),
    )
    .await;
    conforms(&reply);
    let body = ok(&reply, LIST);
    let names = |body: &Value| -> Vec<String> {
        body["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["mnemonic"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(names(&body), ["alpha-one", "alpha-three"]);
    let cursor = body["nextCursor"].as_str().unwrap().to_string();

    // The cursor belongs to the searched listing only.
    let reply = call(&state, Via::Tsp, &owner, LIST, json!({ "cursor": cursor })).await;
    assert_eq!(code(&reply), "malformedRequest", "{reply}");
    let body = ok(
        &call(
            &state,
            Via::Tsp,
            &owner,
            LIST,
            json!({ "limit": 2, "cursor": cursor, "ext": search("ALPHA") }),
        )
        .await,
        LIST,
    );
    assert_eq!(names(&body), ["alpha-two"]);
    assert!(body.get("nextCursor").is_none(), "{body}");

    // Unknown members, an empty search, and agentName without a domain.
    for ext in [
        json!({ "vnd.affinidi.webvh": { "sort": "name" } }),
        search(""),
        json!({ "vnd.affinidi.webvh": { "agentName": "alice" } }),
    ] {
        let reply = call(&state, Via::Tsp, &owner, LIST, json!({ "ext": ext })).await;
        assert_eq!(code(&reply), "malformedRequest", "{ext}: {reply}");
    }
}

/// `stats/get`'s per-domain aggregate: every slot on the domain for an
/// admin, the caller's own for an owner.
#[tokio::test]
async fn stats_get_answers_a_domain_aggregate_through_the_webvh_extension() {
    let (state, _dir) = state().await;
    let admin = member(&state, 41, Role::Admin).await;
    let owner = member(&state, 42, Role::Owner).await;
    seed_hosting_domain(&state, "control.test").await;
    seed_did(&state, &owner.did, "mine-one").await;
    seed_did(&state, &owner.did, "mine-two").await;
    seed_did(&state, "did:example:someone-else", "theirs").await;
    state.stats_collector.record_resolve("mine-one");
    state.stats_collector.record_resolve("theirs");
    state.stats_collector.record_resolve("theirs");

    let uri = t("did-management/stats/get/0.1");
    let ext = json!({ "vnd.affinidi.webvh": { "domain": "control.test" } });
    let body = ok(
        &call(&state, Via::Tsp, &admin, &uri, json!({ "ext": ext })).await,
        &uri,
    );
    assert_eq!(body["totalDids"], 3, "{body}");
    assert_eq!(body["totalResolves"], 3, "{body}");
    let body = ok(
        &call(&state, Via::Tsp, &owner, &uri, json!({ "ext": ext })).await,
        &uri,
    );
    assert_eq!(body["totalDids"], 2, "{body}");
    assert_eq!(body["totalResolves"], 1, "{body}");

    // An unknown domain, and a mnemonic alongside the domain.
    let unknown = json!({ "vnd.affinidi.webvh": { "domain": "nowhere.test" } });
    let reply = call(&state, Via::Tsp, &admin, &uri, json!({ "ext": unknown })).await;
    assert_eq!(code(&reply), "did-management/stats/get:notFound", "{reply}");
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &uri,
        json!({ "mnemonic": "mine-one", "ext": ext }),
    )
    .await;
    assert_eq!(code(&reply), "malformedRequest", "{reply}");
}
