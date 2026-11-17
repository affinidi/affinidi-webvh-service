//! Watchers: which configured watchers a DID's log names, and the record of
//! who a slot was last published to.

use tracing::warn;

use crate::server::AppState;

/// Key holding the watcher DIDs a mnemonic's log named the last time
/// `notify_servers_did` ran for it. Read (and cleared) by
/// `notify_servers_delete`, so a delete reaches only the watchers the DID was
/// actually published to.
pub(super) fn notified_watchers_key(mnemonic: &str) -> String {
    format!("notified_watchers:{mnemonic}")
}

/// The watcher URLs a did:webvh log names: its `watchers` parameter as last
/// set (parameters carry forward; `null` or `[]` clears it).
pub fn watchers_named(log: &str) -> Vec<String> {
    let mut current: Vec<String> = Vec::new();
    for line in log.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(watchers) = entry.get("parameters").and_then(|p| p.get("watchers")) else {
            continue;
        };
        current = watchers
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .map(|u| u.trim_end_matches('/').to_string())
                    .collect()
            })
            .unwrap_or_default();
    }
    current
}

/// The DIDs of the configured watchers `log` names. A named URL with no
/// configured DID is skipped (and logged): the control plane pushes only to
/// watchers it was told the DID of.
pub fn watcher_dids_for(peers: &[crate::config::WatcherPeer], log: &str) -> Vec<String> {
    let mut dids = Vec::new();
    for url in watchers_named(log) {
        match peers.iter().find(|p| p.url.trim_end_matches('/') == url) {
            Some(peer) if !dids.contains(&peer.did) => dids.push(peer.did.clone()),
            Some(_) => {}
            None => {
                warn!(watcher_url = %url, "DID sync: the log names a watcher with no configured DID; not pushing to it")
            }
        }
    }
    dids
}

/// Whether `did` is a watcher this control plane is configured to push to —
/// the only standing a watcher has here: acknowledging what it was sent.
pub fn is_configured_watcher(state: &AppState, did: &str) -> bool {
    state.config.registry.watchers.iter().any(|p| p.did == did)
}

#[cfg(test)]
#[path = "watchers_tests.rs"]
mod watcher_tests;
