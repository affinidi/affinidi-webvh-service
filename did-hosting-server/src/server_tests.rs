//! Tests for [`super`].

use super::*;

#[test]
fn mnemonic_from_did_simple() {
    let did =
        "did:webvh:QmaErmPvnHUDaaiM4phkDgrK58T49cxgmCUtKon9gwyWtJ:webvh.storm.ws:webvh:server1";
    assert_eq!(mnemonic_from_did(did).unwrap(), "webvh/server1");
}

#[test]
fn mnemonic_from_did_single_path() {
    let did = "did:webvh:QmABC:example.com:my-did";
    assert_eq!(mnemonic_from_did(did).unwrap(), "my-did");
}

#[test]
fn mnemonic_from_did_deep_path() {
    let did = "did:webvh:QmABC:example.com:people:staff:glenn";
    assert_eq!(mnemonic_from_did(did).unwrap(), "people/staff/glenn");
}

/// A standalone edge with no control plane is not a supported shape: the
/// server refuses to start rather than run with nothing able to write to it.
#[test]
fn an_edge_without_a_control_plane_does_not_start() {
    let config = |control: Option<&str>, server: Option<&str>| {
        let mut c: AppConfig = toml::from_str("").expect("defaults parse");
        c.control_did = control.map(String::from);
        c.server_did = server.map(String::from);
        c
    };
    for (control, server) in [
        (None, Some("did:key:edge")),
        (Some(""), Some("did:key:edge")),
        (Some("did:key:control"), None),
    ] {
        let err = require_control_plane(&config(control, server)).unwrap_err();
        assert!(matches!(err, AppError::Config(_)), "{err:?}");
    }
    let err = require_control_plane(&config(None, Some("did:key:edge"))).unwrap_err();
    assert!(err.to_string().contains("did-hosting-daemon"), "{err}");
    require_control_plane(&config(Some("did:key:control"), Some("did:key:edge")))
        .expect("an edge with a control plane starts");
}

#[test]
fn mnemonic_from_did_invalid() {
    assert!(mnemonic_from_did("did:web:example.com").is_none());
    assert!(mnemonic_from_did("not-a-did").is_none());
}
