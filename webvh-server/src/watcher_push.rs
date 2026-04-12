//! Fire-and-forget push of DID state changes to registered watcher instances.
//!
//! When a DID's log declares watchers in its parameters, only the configured
//! watchers whose URLs match the DID's list receive pushes.  After each push
//! round the per-watcher sync status is persisted so the API can report it.

use crate::auth::session::now_epoch;
use crate::config::AppConfig;
use crate::did_ops;
use crate::store::KeyspaceHandle;
use affinidi_webvh_common::{SyncDeleteRequest, SyncDidRequest};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::warn;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Per-watcher sync status stored alongside the DID record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatcherSyncStatus {
    pub watcher_url: String,
    pub last_synced_version_id: Option<String>,
    pub last_synced_at: Option<u64>,
    pub last_error: Option<String>,
    pub ok: bool,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------


/// Normalize a URL for comparison by trimming trailing slashes.
fn normalize_url(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

// ---------------------------------------------------------------------------
// Push logic
// ---------------------------------------------------------------------------

/// Push the current state of a DID to watchers that the DID declares.
///
/// The DID's log parameters may contain a `watchers` array of URLs.  Only
/// configured watchers (`config.watchers`) whose normalized URL appears in
/// that list are pushed to.  Watchers declared by the DID but not configured
/// on this server are recorded with an error status.
///
/// After pushing, the sync status for every matched watcher is written to
/// the store under `watcher_sync:{mnemonic}`.
pub fn notify_watchers_did(
    config: &Arc<AppConfig>,
    http: &reqwest::Client,
    dids_ks: &KeyspaceHandle,
    mnemonic: String,
) {
    let http = http.clone();
    let config = config.clone();
    let dids_ks = dids_ks.clone();

    tokio::spawn(async move {
        let record = match dids_ks
            .get::<did_ops::DidRecord>(did_ops::did_key(&mnemonic))
            .await
        {
            Ok(Some(r)) => r,
            Ok(None) => return,
            Err(e) => {
                warn!(mnemonic = %mnemonic, error = %e, "watcher push: failed to read record");
                return;
            }
        };

        let log_content = match dids_ks
            .get_raw(did_ops::content_log_key(&mnemonic))
            .await
        {
            Ok(Some(bytes)) => match String::from_utf8(bytes) {
                Ok(s) => s,
                Err(_) => {
                    warn!(mnemonic = %mnemonic, "watcher push: invalid UTF-8 in log content");
                    return;
                }
            },
            Ok(None) => return,
            Err(e) => {
                warn!(mnemonic = %mnemonic, error = %e, "watcher push: failed to read log");
                return;
            }
        };

        let witness_content = match dids_ks
            .get_raw(did_ops::content_witness_key(&mnemonic))
            .await
        {
            Ok(Some(bytes)) => String::from_utf8(bytes).ok(),
            _ => None,
        };

        // Extract metadata to get the DID's declared watcher URLs and version.
        let meta = did_ops::extract_log_metadata(&log_content);

        // If the DID declares no watchers and no watchers are configured, nothing to do.
        if meta.watcher_urls.is_empty() && config.watchers.is_empty() {
            return;
        }

        let payload = SyncDidRequest {
            mnemonic: mnemonic.clone(),
            did_id: record.did_id,
            log_content,
            witness_content,
            source_url: config.public_base_url(),
            updated_at: record.updated_at,
            disabled: record.disabled,
        };

        let did_watcher_urls: Vec<String> =
            meta.watcher_urls.iter().map(|u| normalize_url(u)).collect();

        let mut statuses: Vec<WatcherSyncStatus> = Vec::new();

        // Build a set of normalized configured watcher URLs for quick lookup.
        let configured_urls: Vec<String> = config
            .watchers
            .iter()
            .map(|w| normalize_url(&w.url))
            .collect();

        // Push to each configured watcher whose URL is declared by the DID.
        for watcher in &config.watchers {
            let norm = normalize_url(&watcher.url);
            if !did_watcher_urls.is_empty() && !did_watcher_urls.contains(&norm) {
                continue;
            }

            let url = format!("{}/api/sync/did", norm);
            let mut req = http.post(&url).json(&payload);
            if let Some(token) = &watcher.token {
                req = req.bearer_auth(token);
            }

            let (ok, last_error) = match req.send().await {
                Ok(resp) if resp.status().is_success() => (true, None),
                Ok(resp) => (
                    false,
                    Some(format!("HTTP {}", resp.status())),
                ),
                Err(e) => {
                    warn!(url = %url, error = %e, "failed to push DID to watcher");
                    (false, Some(e.to_string()))
                }
            };

            statuses.push(WatcherSyncStatus {
                watcher_url: watcher.url.clone(),
                last_synced_version_id: if ok {
                    meta.latest_version_id.clone()
                } else {
                    None
                },
                last_synced_at: if ok { Some(now_epoch()) } else { None },
                last_error,
                ok,
            });
        }

        // Record DID-declared watchers that are NOT configured on this server.
        for did_url in &meta.watcher_urls {
            let norm = normalize_url(did_url);
            if !configured_urls.contains(&norm) {
                statuses.push(WatcherSyncStatus {
                    watcher_url: did_url.clone(),
                    last_synced_version_id: None,
                    last_synced_at: None,
                    last_error: Some("watcher not configured on this server".into()),
                    ok: false,
                });
            }
        }

        // Persist sync statuses.
        if !statuses.is_empty() {
            if let Err(e) = dids_ks
                .insert(did_ops::watcher_sync_key(&mnemonic), &statuses)
                .await
            {
                warn!(mnemonic = %mnemonic, error = %e, "failed to persist watcher sync status");
            }
        }
    });
}

/// Notify all configured watchers that a DID has been deleted, and remove
/// the persisted sync status.
pub fn notify_watchers_delete(
    config: &Arc<AppConfig>,
    http: &reqwest::Client,
    dids_ks: &KeyspaceHandle,
    mnemonic: String,
) {
    let http = http.clone();
    let config = config.clone();
    let dids_ks = dids_ks.clone();

    tokio::spawn(async move {
        // Clean up persisted sync status.
        let _ = dids_ks.remove(did_ops::watcher_sync_key(&mnemonic)).await;

        if config.watchers.is_empty() {
            return;
        }

        let payload = SyncDeleteRequest {
            mnemonic: mnemonic.clone(),
            source_url: config.public_base_url(),
        };

        for watcher in &config.watchers {
            let url = format!("{}/api/sync/delete", watcher.url.trim_end_matches('/'));
            let mut req = http.post(&url).json(&payload);
            if let Some(token) = &watcher.token {
                req = req.bearer_auth(token);
            }
            if let Err(e) = req.send().await {
                warn!(url = %url, error = %e, "failed to push DID delete to watcher");
            }
        }
    });
}
