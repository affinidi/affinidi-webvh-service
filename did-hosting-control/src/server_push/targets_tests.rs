//! Tests for the registry's push targets (`PushTargets`).

use super::*;
use serde_json::json;

fn instance(id: &str, kind: &str, status: &str, did: Option<&str>) -> registry::ServiceInstance {
    let metadata = did.map_or(json!({}), |d| json!({ "did": d }));
    serde_json::from_value(json!({
        "instanceId": id,
        "serviceType": kind,
        "url": "https://edge.example",
        "status": status,
        "registeredAt": 0,
        "metadata": metadata,
    }))
    .expect("instance")
}

#[test]
fn test_push_targets_empty_registry_is_none_registered() {
    assert_eq!(
        PushTargets::from_instances(vec![]),
        PushTargets::NoneRegistered
    );
}

#[test]
fn test_push_targets_registered_edges_that_are_down_are_told_apart_from_none() {
    let down = vec![
        instance("a", "server", "degraded", Some("did:example:a")),
        instance("b", "server", "unreachable", Some("did:example:b")),
        instance("c", "server", "active", None),
    ];
    assert_eq!(PushTargets::from_instances(down), PushTargets::NoneActive);
}

#[test]
fn test_push_targets_only_active_servers_with_a_did_are_pushed_to() {
    let mixed = vec![
        instance("a", "server", "active", Some("did:example:a")),
        instance("b", "server", "degraded", Some("did:example:b")),
    ];
    assert_eq!(
        PushTargets::from_instances(mixed),
        PushTargets::Active(vec![("did:example:a".into(), "a".into())])
    );
}
