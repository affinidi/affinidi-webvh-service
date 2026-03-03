//! Fire-and-forget push of DID state changes to registered watcher instances.

use crate::config::AppConfig;
use crate::did_ops;
use crate::store::KeyspaceHandle;
use affinidi_webvh_common::{SyncDeleteRequest, SyncDidRequest};
use std::sync::Arc;
use tracing::warn;

fn source_url(config: &AppConfig) -> String {
    config.public_url.clone().unwrap_or_else(|| {
        format!("http://{}:{}", config.server.host, config.server.port)
    })
}

/// Push the current state of a DID to all configured watchers.
///
/// Reads the latest record, log, and witness content from the store and
/// sends it to each watcher endpoint. Failures are logged but never block
/// the caller.
pub fn notify_watchers_did(
    config: &Arc<AppConfig>,
    http: &reqwest::Client,
    dids_ks: &KeyspaceHandle,
    mnemonic: String,
) {
    if config.watchers.is_empty() {
        return;
    }

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
                Err(_) => return,
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

        let payload = SyncDidRequest {
            mnemonic: mnemonic.clone(),
            did_id: record.did_id,
            log_content,
            witness_content,
            source_url: source_url(&config),
            updated_at: record.updated_at,
            disabled: record.disabled,
        };

        for watcher in &config.watchers {
            let url = format!("{}/api/sync/did", watcher.url.trim_end_matches('/'));
            let mut req = http.post(&url).json(&payload);
            if let Some(token) = &watcher.token {
                req = req.bearer_auth(token);
            }
            if let Err(e) = req.send().await {
                warn!(url = %url, error = %e, "failed to push DID to watcher");
            }
        }
    });
}

/// Notify all configured watchers that a DID has been deleted.
pub fn notify_watchers_delete(
    config: &Arc<AppConfig>,
    http: &reqwest::Client,
    mnemonic: String,
) {
    if config.watchers.is_empty() {
        return;
    }

    let http = http.clone();
    let config = config.clone();

    tokio::spawn(async move {
        let payload = SyncDeleteRequest {
            mnemonic: mnemonic.clone(),
            source_url: source_url(&config),
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
