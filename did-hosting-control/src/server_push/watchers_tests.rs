//! Tests for the watchers a DID log names.

use super::*;
use crate::config::WatcherPeer;
use serde_json::json;

fn log(params: &[serde_json::Value]) -> String {
    params
        .iter()
        .map(|p| json!({ "versionId": "1-x", "parameters": p }).to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_last_watchers_parameter_wins() {
    let l = log(&[
        json!({ "watchers": ["https://a.example/"] }),
        json!({}),
        json!({ "watchers": ["https://b.example", "https://c.example"] }),
    ]);
    assert_eq!(
        watchers_named(&l),
        vec!["https://b.example", "https://c.example"]
    );
    let cleared = log(&[
        json!({ "watchers": ["https://a.example"] }),
        json!({ "watchers": null }),
    ]);
    assert!(watchers_named(&cleared).is_empty());
}

#[test]
fn only_configured_watchers_are_pushed_to() {
    let peers = vec![WatcherPeer {
        url: "https://b.example/".into(),
        did: "did:example:b".into(),
    }];
    let l = log(&[json!({ "watchers": ["https://a.example", "https://b.example"] })]);
    assert_eq!(watcher_dids_for(&peers, &l), vec!["did:example:b"]);
}
