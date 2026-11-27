//! The last administrator stays: removing it is refused on every transport,
//! and no administrator may demote itself. The
//! handlers' own tests pin the rule; these pin that the control plane's
//! dispatch keeps it.

use super::platform::t;
use super::*;

fn is_last_authority(reply: &Value) -> bool {
    code(reply).ends_with("lastAuthorityProtected")
}

#[tokio::test]
async fn the_last_admin_cannot_remove_itself_on_any_transport() {
    let (state, _dir) = state().await;
    let admin = member(&state, 81, Role::Admin).await;
    let uri = t("acl/revoke/0.2");

    for via in VIAS {
        let reply = call(
            &state,
            via,
            &admin,
            &uri,
            json!({ "subject": admin.did, "revocation": { "kind": "entry" } }),
        )
        .await;
        assert!(is_last_authority(&reply), "{via:?}: {reply}");
        assert_eq!(reply["payload"]["details"]["remainingHolders"], json!([]));
        assert_eq!(
            did_hosting_common::server::acl::check_acl(&state.acl_ks, &admin.did)
                .await
                .unwrap(),
            Role::Admin,
            "{via:?}: the last admin was removed"
        );
    }
}

/// No admin may change its own role at all, so `change-role` can never
/// demote the last one: only another admin could, and then it is not the last.
#[tokio::test]
async fn an_admin_cannot_demote_itself() {
    let (state, _dir) = state().await;
    let admin = member(&state, 82, Role::Admin).await;

    let reply = call(
        &state,
        Via::Https,
        &admin,
        &t("acl/change-role/0.2"),
        json!({ "subject": admin.did, "fromRole": "admin", "toRole": "owner" }),
    )
    .await;
    assert_eq!(code(&reply), "permissionDenied", "{reply}");
    assert_eq!(
        did_hosting_common::server::acl::check_acl(&state.acl_ks, &admin.did)
            .await
            .unwrap(),
        Role::Admin
    );
}

#[tokio::test]
async fn an_admin_may_remove_itself_while_another_remains() {
    let (state, _dir) = state().await;
    let admin = member(&state, 83, Role::Admin).await;
    let other = member(&state, 84, Role::Admin).await;
    let uri = t("acl/revoke/0.2");

    let reply = call(
        &state,
        Via::Https,
        &admin,
        &uri,
        json!({ "subject": admin.did, "revocation": { "kind": "entry" } }),
    )
    .await;
    ok(&reply, &uri);

    // ...and then the one left is the last.
    let reply = call(
        &state,
        Via::Https,
        &other,
        &uri,
        json!({ "subject": other.did, "revocation": { "kind": "entry" } }),
    )
    .await;
    assert!(is_last_authority(&reply), "{reply}");
}
