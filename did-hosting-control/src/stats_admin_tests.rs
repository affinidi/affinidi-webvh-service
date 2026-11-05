use did_hosting_common::server::stats_tiers::{CoarseSeries, FineSlot, SeriesKind, fine_key};

use super::*;
use crate::test_support::TestServer;

fn auth(did: &str, role: Role) -> AuthClaims {
    AuthClaims {
        did: did.to_string(),
        role,
        session_pubkey_b58btc: None,
        session_id: String::new(),
        amr: vec!["did".to_string()],
        acr: "aal1".to_string(),
    }
}

const OWNER: &str = "did:key:z6MkOwner";
const ADMIN: &str = "did:key:z6MkAdmin";
const STRANGER: &str = "did:key:z6MkStranger";

#[tokio::test]
async fn only_an_admin_can_pin_fine() {
    let ts = TestServer::start().await;
    ts.seed_did(OWNER, "alice").await;
    let owner = auth(OWNER, Role::Owner);

    let err = set_stats_resolution(&owner, &ts.state, "alice", StatsResolution::Fine)
        .await
        .expect_err("an owner cannot ask for more detail");
    assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");

    set_stats_resolution(
        &auth(ADMIN, Role::Admin),
        &ts.state,
        "alice",
        StatsResolution::Fine,
    )
    .await
    .unwrap();
    let info = stats_tier(&owner, &ts.state, "alice").await.unwrap();
    assert_eq!(info.resolution, StatsResolution::Fine);
    assert_eq!((info.tier, info.reason), (Tier::Fine, TierReason::Pinned));
}

#[tokio::test]
async fn an_owner_can_ask_for_less_detail_and_go_back_to_auto() {
    let ts = TestServer::start().await;
    ts.seed_did(OWNER, "alice").await;
    let owner = auth(OWNER, Role::Owner);

    let prev = set_stats_resolution(&owner, &ts.state, "alice", StatsResolution::Off)
        .await
        .unwrap();
    assert_eq!(prev, StatsResolution::Auto);
    let stored: Option<StatsResolution> = ts.state.stats_ks.get(pin_key("alice")).await.unwrap();
    assert_eq!(
        stored,
        Some(StatsResolution::Off),
        "persisted for the next start"
    );

    set_stats_resolution(&owner, &ts.state, "alice", StatsResolution::Auto)
        .await
        .unwrap();
    assert!(
        ts.state
            .stats_ks
            .get_raw(pin_key("alice"))
            .await
            .unwrap()
            .is_none(),
        "auto is the absence of an override"
    );
    assert_eq!(
        ts.state.stats_collector.tiers().pin("alice"),
        StatsResolution::Auto
    );
}

#[tokio::test]
async fn a_stranger_cannot_change_someone_elses_did() {
    let ts = TestServer::start().await;
    ts.seed_did(OWNER, "alice").await;
    let err = set_stats_resolution(
        &auth(STRANGER, Role::Owner),
        &ts.state,
        "alice",
        StatsResolution::Off,
    )
    .await
    .expect_err("not the owner");
    assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");
}

#[tokio::test]
async fn deleting_a_did_deletes_its_statistics() {
    let ts = TestServer::start().await;
    ts.seed_did(OWNER, "alice").await;
    let mut c = CoarseSeries::default();
    c.add(SeriesKind::Did, 3600, 1, 0);
    c.fine_since = Some(3600);
    let row = StoredDidStats {
        coarse: Some(c),
        ..StoredDidStats::default()
    };
    ts.state
        .stats_ks
        .insert(stats_key("alice").as_str(), &row)
        .await
        .unwrap();
    ts.state
        .timeseries_ks
        .insert(
            fine_key("alice", 3600).as_str(),
            &FineSlot {
                e: 3600,
                r: 1,
                u: 0,
            },
        )
        .await
        .unwrap();
    set_stats_resolution(
        &auth(OWNER, Role::Owner),
        &ts.state,
        "alice",
        StatsResolution::Coarse,
    )
    .await
    .unwrap();

    crate::did_ops::delete_did(&auth(OWNER, Role::Owner), &ts.state, "alice", None)
        .await
        .unwrap();

    assert!(
        ts.state
            .stats_ks
            .get_raw(stats_key("alice"))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        ts.state
            .stats_ks
            .get_raw(pin_key("alice"))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        ts.state
            .timeseries_ks
            .get_raw(fine_key("alice", 3600))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        ts.state.stats_collector.tiers().pin("alice"),
        StatsResolution::Auto
    );
}
