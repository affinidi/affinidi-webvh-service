//! Read-only extraction from a `did.jsonl`: the DID identifier, service
//! types, agent names, log metadata, the did:web bridge document and the
//! per-entry summaries.

use super::record::{LogEntryInfo, LogMetadata};

/// Extract the `did:webvh:...` identifier from the last non-blank line of
/// JSONL content via the `state.id` field. Trailing blank lines are skipped.
pub fn extract_did_id(jsonl_content: &str) -> Option<String> {
    let last_line = jsonl_content.lines().rfind(|l| !l.trim().is_empty())?;
    let value: serde_json::Value = serde_json::from_str(last_line).ok()?;
    value
        .get("state")
        .and_then(|state| state.get("id"))
        .and_then(|id| id.as_str())
        .filter(|s| s.starts_with("did:webvh:"))
        .map(|s| s.to_string())
}

/// Extract the advertised `service[].type` values from the DID document in
/// the last non-blank line of JSONL content.
///
/// Returns `None` when there is no parseable log entry with a `state` — i.e.
/// the document is unavailable, so callers must not cache an empty vector and
/// conclude "advertises nothing". `Some(vec![])` means the document was read
/// and carries no services. This maps directly onto [`DidRecord::services`](super::DidRecord::services).
pub fn extract_service_types(jsonl_content: &str) -> Option<Vec<String>> {
    let last_line = jsonl_content.lines().rfind(|l| !l.trim().is_empty())?;
    let value: serde_json::Value = serde_json::from_str(last_line).ok()?;
    let state = value.get("state")?;
    Some(crate::did::service_types_from_doc(state))
}

/// Extract the agent names a DID document claims, for a given hosting domain.
///
/// Reads `alsoKnownAs` from the latest log entry's document state and keeps the
/// entries that are agent names (`/@…`) on `domain`.
///
/// # Why derive rather than track separately
///
/// The log is signed; `alsoKnownAs` is inside the signed document. Deriving the
/// resolvable set from it means a node **structurally cannot** serve a name the
/// DID does not claim — the agent-name specification's Layer-1 anti-spoofing
/// rule holds by construction rather than by remembering to check it. It is the
/// same reasoning that makes [`extract_service_types`] read the log instead of
/// trusting a pushed list.
///
/// Canonicalisation goes through the `agent-names` crate so the name derived
/// here is byte-identical to the one a resolver will compare against
/// `alsoKnownAs`. Re-implementing that normalisation is how the two sides drift
/// and every name silently fails to verify.
pub fn extract_agent_names(jsonl_content: &str, domain: &str) -> Vec<String> {
    let Some(last_line) = jsonl_content.lines().rfind(|l| !l.trim().is_empty()) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(last_line) else {
        return Vec::new();
    };
    let Some(state) = value.get("state") else {
        return Vec::new();
    };
    agent_names_from_document(state, domain)
}

/// Extract the agent names a DID document claims, for a given hosting domain.
///
/// The method-agnostic half of [`extract_agent_names`]. That function knows
/// how to find the current document inside a `did:webvh` log; this one works
/// on the document itself, whatever produced it — a webvh log entry's `state`,
/// a `did:web` document as published, or the document a `did:webs` key event
/// log was verified into.
///
/// Keeping the rule in one place is the point. `alsoKnownAs` is where an
/// agent name is claimed, and the Layer-1 anti-spoofing property depends on
/// every method deriving names the same way — a second implementation for a
/// second method is how the two drift and a name silently stops verifying.
pub fn agent_names_from_document(document: &serde_json::Value, domain: &str) -> Vec<String> {
    let Some(entries) = document.get("alsoKnownAs").and_then(|a| a.as_array()) else {
        return Vec::new();
    };

    let mut names = Vec::new();
    for entry in entries.iter().filter_map(|e| e.as_str()) {
        let Ok(parsed) = agent_names::AgentName::parse(entry) else {
            continue; // not an agent name — alsoKnownAs legitimately holds other URIs
        };
        if parsed.authority() != domain {
            continue; // a name on somebody else's domain; not ours to serve
        }
        let local = parsed.local_name().to_string();
        if !names.contains(&local) {
            names.push(local);
        }
    }
    names
}

/// Parse JSONL content and extract metadata from the log entries.
pub fn extract_log_metadata(jsonl_content: &str) -> LogMetadata {
    let lines: Vec<&str> = jsonl_content.lines().collect();
    let mut meta = LogMetadata {
        log_entry_count: lines.len() as u64,
        ..Default::default()
    };

    let Some(last_line) = lines.last() else {
        return meta;
    };
    let Ok(entry) = serde_json::from_str::<serde_json::Value>(last_line) else {
        return meta;
    };

    meta.latest_version_id = entry
        .get("versionId")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    meta.latest_version_time = entry
        .get("versionTime")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    meta.scid_alias = entry.get("state").and_then(crate::scid::scid_alias_info);

    if let Some(params) = entry.get("parameters") {
        meta.method = params
            .get("method")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        meta.portable = params
            .get("portable")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        meta.pre_rotation = params
            .get("nextKeyHashes")
            .and_then(|v| v.as_array())
            .is_some_and(|a| !a.is_empty());

        meta.deactivated = params
            .get("deactivated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        meta.ttl = params.get("ttl").and_then(|v| v.as_u64()).map(|v| v as u32);

        if let Some(witness) = params.get("witness") {
            let threshold = witness
                .get("threshold")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let count = witness
                .get("witnesses")
                .and_then(|v| v.as_array())
                .map(|a| a.len() as u32)
                .unwrap_or(0);
            if count > 0 {
                meta.witnesses = true;
                meta.witness_count = count;
                meta.witness_threshold = threshold;
            }
        }

        if let Some(watchers_val) = params.get("watchers")
            && let Some(arr) = watchers_val.as_array()
            && !arr.is_empty()
        {
            meta.watchers = true;
            meta.watcher_count = arr.len() as u32;
            meta.watcher_urls = arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        }
    }

    meta
}

/// Extract a did:web document from JSONL content by rewriting the did:webvh identity.
///
/// Returns `Some(json_bytes)` if the last log entry's `state.alsoKnownAs` contains
/// the expected `did:web` identifier.
pub fn extract_did_web_document(jsonl_content: &str, expected_did_web: &str) -> Option<Vec<u8>> {
    let last_line = jsonl_content.lines().last()?;
    let entry: serde_json::Value = serde_json::from_str(last_line).ok()?;
    let state = entry.get("state")?;

    let webvh_id = state.get("id")?.as_str()?;
    if !webvh_id.starts_with("did:webvh:") {
        return None;
    }

    let also_known_as = state.get("alsoKnownAs")?.as_array()?;
    let found = also_known_as
        .iter()
        .any(|v| v.as_str() == Some(expected_did_web));
    if !found {
        return None;
    }

    let state_json = serde_json::to_string(state).ok()?;
    let rewritten = state_json.replace(webvh_id, expected_did_web);
    Some(rewritten.into_bytes())
}

/// Parse JSONL log entries into structured `LogEntryInfo` values.
pub fn parse_log_entries(jsonl_content: &str) -> Vec<LogEntryInfo> {
    jsonl_content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let value: serde_json::Value = serde_json::from_str(line).ok()?;
            Some(LogEntryInfo {
                version_id: value
                    .get("versionId")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                version_time: value
                    .get("versionTime")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                state: value.get("state").cloned(),
                parameters: value.get("parameters").cloned(),
            })
        })
        .collect()
}

#[cfg(test)]
#[path = "agent_name_tests.rs"]
mod agent_name_tests;
