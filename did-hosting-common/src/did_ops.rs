//! Shared DID types and pure helper functions used by both did-hosting-server and
//! did-hosting-control.
//!
//! This module contains the data types and validation/extraction functions that
//! are independent of any particular server's `AppState` or business logic.

use didwebvh_rs::DIDWebVHState;
use didwebvh_rs::log_entry::LogEntry;
use didwebvh_rs::log_entry_state::{LogEntryState, LogEntryValidationStatus};
use didwebvh_rs::parameters::Parameters;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// A record tracking a hosted DID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidRecord {
    pub owner: String,
    pub mnemonic: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub version_count: u64,
    #[serde(default)]
    pub did_id: Option<String>,
    #[serde(default)]
    pub content_size: u64,
    #[serde(default)]
    pub disabled: bool,
    /// Soft-delete timestamp. When set, the DID is treated as deleted but
    /// content is preserved for recovery within the retention period.
    #[serde(default)]
    pub deleted_at: Option<u64>,

    // ---- Multi-method + multi-domain fields (T12) ----
    //
    // Both `#[serde(default)]` for backwards-compat — v0.6-vintage
    // `DidRecord`s lack these fields and deserialise unchanged. T13's
    // M-01 migration walks the keyspace and populates them
    // (`method = "webvh"` for every legacy record; `domain` derived
    // from the legacy `public_url` host that T18's bootstrap_domains
    // seed surfaced).
    //
    // The dual storage model (this record carries metadata; raw
    // content lives at `content_log_key` / `content_witness_key`)
    // is kept intentionally — see `docs/multi-method-hosting-spec.md`
    // §3 "Storage" tradeoff note. Inlining `data: Vec<u8>` into the
    // record made `list_dids` pull content bytes on every scan; the
    // split keeps metadata reads cheap.
    /// DID method this record was registered under. Always one of the
    /// enabled-at-compile-time methods (`webvh`, `web`); the daemon
    /// rejects any other value on the write path. Legacy records
    /// (pre-T13 migration) default to `"webvh"` via the `#[serde(default)]`
    /// fallback in [`Self::default_method`].
    #[serde(default = "default_method")]
    pub method: String,

    /// Domain (hostname) this DID is hosted under. Matches the host
    /// segment of the DID identifier (`did:{method}:…:{domain}:…`).
    /// Legacy records (pre-T13 migration) default to the empty string;
    /// the migration fills it with the host derived from the legacy
    /// `public_url`. New records always carry a normalised non-empty
    /// value.
    #[serde(default)]
    pub domain: String,

    /// Cached `service[].type` values from the latest log entry's DID
    /// document, in document order. Lets `list_dids` render per-DID
    /// service badges without reading log bytes — the whole reason the
    /// dual storage model exists (see the module note above).
    ///
    /// Tri-state, and the distinction matters:
    /// - `None` — not yet computed. Either a slot with no document
    ///   (`create_did`, `version_count == 0`) or a legacy record written
    ///   before this field existed. The UI renders no badges.
    /// - `Some(vec![])` — the document was read and genuinely advertises
    ///   no services. The UI renders no badges, same as `None`, but the
    ///   backfill paths know not to re-read the log.
    /// - `Some(types)` — advertised services.
    ///
    /// Kept fresh by every write path that touches `content_log_key`
    /// (`register_did_atomic`, `publish_did`, the server's sync-from-control
    /// import, bootstrap). `M-02` sweeps legacy records at boot on all three
    /// deployments — server and daemon via the full migration registry,
    /// standalone control via a runner carrying M-02 alone. `publish_did`
    /// additionally self-heals a `None` it finds, so a record the sweep
    /// deferred still converges.
    #[serde(default)]
    pub services: Option<Vec<String>>,

    /// Agent names (`/@alice`) that resolve to this DID.
    ///
    /// A DID may carry several — the agent name specification does not limit a
    /// subject to one, and a deployment may want a personal name plus
    /// role-scoped ones.
    ///
    /// `#[serde(default)]` so records written before this field existed
    /// deserialise unchanged; an empty vec and a missing field are the same
    /// thing, so no migration is needed.
    ///
    /// The authoritative name→DID lookup is the `name:{domain}:{name}` index,
    /// not this list. This is the forward view, kept in the same write batch as
    /// the index so the two cannot drift.
    #[serde(default)]
    pub agent_names: Vec<AgentNameEntry>,
}

/// One agent name bound to a hosted DID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentNameEntry {
    /// The name's local part, without the `@` — `alice` for `/@alice`.
    ///
    /// Stored bare rather than as a full URL because the domain is already on
    /// the record, and a name is only meaningful within its domain.
    pub name: String,

    /// Whether the name currently resolves.
    ///
    /// Disabling stops the redirect but **keeps the name reserved**, so nobody
    /// else can claim it while it is parked. Removing is what releases it.
    pub enabled: bool,

    /// When the name was first bound to this DID.
    pub created_at: u64,
}

fn default_method() -> String {
    "webvh".to_string()
}

/// A single parsed log entry with its DID document and parameters.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntryInfo {
    pub version_id: Option<String>,
    pub version_time: Option<String>,
    pub state: Option<serde_json::Value>,
    pub parameters: Option<serde_json::Value>,
}

/// Summary of WebVH log entry metadata parsed from the stored JSONL content.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogMetadata {
    pub log_entry_count: u64,
    pub latest_version_id: Option<String>,
    pub latest_version_time: Option<String>,
    pub method: Option<String>,
    pub portable: bool,
    pub pre_rotation: bool,
    pub deactivated: bool,
    pub ttl: Option<u32>,
    pub witnesses: bool,
    pub witness_count: u32,
    pub witness_threshold: u32,
    pub watchers: bool,
    pub watcher_count: u32,
    pub watcher_urls: Vec<String>,
}

// ---------------------------------------------------------------------------
// Store key helpers
// ---------------------------------------------------------------------------

pub fn did_key(mnemonic: &str) -> String {
    format!("did:{mnemonic}")
}

pub fn content_log_key(mnemonic: &str) -> String {
    format!("content:{mnemonic}:log")
}

pub fn content_witness_key(mnemonic: &str) -> String {
    format!("content:{mnemonic}:witness")
}

pub fn owner_key(did: &str, mnemonic: &str) -> String {
    format!("owner:{did}:{mnemonic}")
}

/// Reverse index: an agent name resolves to the mnemonic that owns it.
///
/// Scoped by domain because this service is multi-domain — `@alice` on one
/// hosted domain is a different name from `@alice` on another, and they must be
/// claimable independently.
///
/// Mirrors the `owner:` reverse-index pattern; written in the same batch as the
/// `DidRecord` so the index and `DidRecord::agent_names` cannot diverge.
pub fn agent_name_key(domain: &str, name: &str) -> String {
    format!("name:{domain}:{name}")
}

pub fn watcher_sync_key(mnemonic: &str) -> String {
    format!("watcher_sync:{mnemonic}")
}

// ---------------------------------------------------------------------------
// JSONL validation & extraction
// ---------------------------------------------------------------------------

/// Validate that every line in the JSONL body is a well-formed did:webvh log entry.
///
/// In addition to structural shape, the *last* entry's `state.id` must start
/// with `did:webvh:`. This rules out leaked-push-token attackers republishing
/// arbitrary JSON that happens to deserialise into the LogEntry shape but
/// targets a different DID method.
///
/// Returns an error string on failure (caller wraps in their own error type).
pub fn validate_did_jsonl(content: &str) -> Result<(), String> {
    if content.is_empty() {
        return Err("did.jsonl content cannot be empty".into());
    }

    let mut had_entry = false;
    for (idx, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        LogEntry::deserialize_string(line, None)
            .map_err(|e| format!("invalid log entry at line {}: {e}", idx + 1))?;
        had_entry = true;
    }

    if !had_entry {
        return Err("did.jsonl content has no entries".into());
    }

    // Must encode a did:webvh identifier on the latest entry.
    match extract_did_id(content) {
        Some(id) if id.starts_with("did:webvh:") => Ok(()),
        Some(other) => Err(format!(
            "did.jsonl latest entry must encode a did:webvh identifier (got {other})",
        )),
        None => Err("did.jsonl latest entry has no resolvable state.id".into()),
    }
}

/// Verify the cryptographic proofs on every log entry in a `did.jsonl`
/// chain.
///
/// This is the semantic-correctness gate for the DID method —
/// `validate_did_jsonl` is structural-only (it parses each line and
/// confirms the latest `state.id` is `did:webvh:`) but does not check
/// that the embedded `proof` actually verifies against
/// `parameters.updateKeys`. An authenticated owner (or admin via
/// force) could otherwise publish a `did.jsonl` whose proof is invalid
/// or signed with an unknown key — clients resolving the DID would
/// then encounter a chain that doesn't verify and produce inscrutable
/// downstream failures.
///
/// Wraps the upstream `didwebvh-rs::DIDWebVHState::validate` —
/// signature verification, parameter-transition rules, hash-chain,
/// pre-rotation key authorisation, and post-deactivation tamper
/// detection are all enforced. Witness proofs are NOT validated here
/// (they're optional and uploaded separately via
/// `MSG_WITNESS_PUBLISH`); use `assert_complete()` if you need to
/// reject any partial-chain truncation.
///
/// Returns the structural-validation message verbatim on parse-time
/// failures and a "proof verification failed: ..." prefix on the
/// upstream verifier's report.
pub fn verify_did_log_proofs(content: &str) -> Result<(), String> {
    // Re-run the structural parse so callers can use this function
    // as a single gate. Cheap relative to the proof-verification cost.
    validate_did_jsonl(content)?;

    let mut state = DIDWebVHState::default();
    let mut version = None;
    for (idx, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry = LogEntry::deserialize_string(line, version)
            .map_err(|e| format!("invalid log entry at line {}: {e}", idx + 1))?;
        version = Some(entry.get_webvh_version());
        let version_number = entry
            .get_version_id_fields()
            .map_err(|e| format!("invalid versionId at line {}: {e}", idx + 1))?
            .0;
        state.log_entries_mut().push(LogEntryState {
            log_entry: entry,
            version_number,
            validation_status: LogEntryValidationStatus::NotValidated,
            validated_parameters: Parameters::default(),
        });
    }

    let report = state
        .validate()
        .map_err(|e| format!("proof verification failed: {e}"))?;

    // assert_complete rejects truncation — any entry that failed
    // verification or any post-deactivation tampering surfaces here.
    report
        .assert_complete()
        .map_err(|e| format!("proof verification failed (chain incomplete): {e}"))?;

    Ok(())
}

/// Verify that a `did:webvh:...` identifier names the host described
/// by `server_base_url` and resolves at the slot named by `request_path`.
///
/// Used by atomic claim-and-publish flows where the caller asserts a
/// pre-built `did.jsonl`. Without this check, anyone with write
/// access to a slot could upload content claiming a different host
/// (impersonation) or a different path on this host (claim-jumping).
///
/// `server_base_url` is the URL the server publishes DIDs at — i.e.
/// the resulting hosting URL is `<server_base_url>/<request_path>/did.jsonl`.
/// Trailing slashes on `server_base_url` are tolerated.
pub fn validate_did_id_matches_request(
    did_id: &str,
    request_path: &str,
    server_base_url: &str,
) -> Result<(), String> {
    use didwebvh_rs::url::WebVHURL;
    use url::Url;

    let id_parsed = WebVHURL::parse_did_url(did_id)
        .map_err(|e| format!("did_log's DID identifier {did_id} is not a valid did:webvh: {e}"))?;

    let expected_str = format!(
        "{}/{request_path}/did.jsonl",
        server_base_url.trim_end_matches('/')
    );
    let expected_url = Url::parse(&expected_str).map_err(|e| {
        format!(
            "internal: server_base_url {server_base_url} cannot form a valid URL when combined \
             with the requested path: {e}"
        )
    })?;
    let expected_parsed = WebVHURL::parse_url(&expected_url).map_err(|e| {
        format!(
            "internal: the URL this server would publish at ({expected_str}) cannot be expressed \
             as a webvh URL: {e}"
        )
    })?;

    if id_parsed.domain != expected_parsed.domain || id_parsed.port != expected_parsed.port {
        return Err(format!(
            "did_log's DID host (domain={}, port={:?}) does not match this server's host \
             (domain={}, port={:?})",
            id_parsed.domain, id_parsed.port, expected_parsed.domain, expected_parsed.port,
        ));
    }
    if id_parsed.path != expected_parsed.path {
        return Err(format!(
            "did_log's DID path '{}' does not resolve at the requested path '{}' on this server \
             (server would publish at '{}')",
            id_parsed.path.trim_matches('/'),
            request_path,
            expected_parsed.path.trim_matches('/'),
        ));
    }

    Ok(())
}

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
/// and carries no services. This maps directly onto [`DidRecord::services`].
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
    let Some(entries) = value
        .get("state")
        .and_then(|s| s.get("alsoKnownAs"))
        .and_then(|a| a.as_array())
    else {
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

/// Fold the names a document claims into the registry a record already carries.
///
/// The control plane keeps the authoritative registry; the document decides
/// which of its entries currently *resolve*. This reconciles the two:
///
/// - a derived name already in the registry keeps its `created_at` (the binding
///   is the same binding — a republish is not a re-claim) and is enabled;
/// - a derived name that is new is appended, enabled, stamped `now`;
/// - a registry entry the document no longer claims is **disabled, not
///   dropped**. Disabling stops the redirect but keeps the name reserved to
///   this slot, which is exactly the state the data model calls "parked". A
///   name only leaves the registry when it is explicitly released.
///
/// That last rule is what makes the registry a superset of the document rather
/// than a mirror of it, and it is why the control plane can hold a reservation
/// the signed log has no way to express.
///
/// The edge does not use this — [`extract_agent_names`] alone is its rule, so
/// an edge is structurally unable to serve a name the document does not claim.
pub fn reconcile_agent_names(
    previous: &[AgentNameEntry],
    derived: &[String],
    now: u64,
) -> Vec<AgentNameEntry> {
    let mut out: Vec<AgentNameEntry> = previous
        .iter()
        .map(|entry| AgentNameEntry {
            enabled: derived.contains(&entry.name),
            ..entry.clone()
        })
        .collect();

    for name in derived {
        if !out.iter().any(|entry| &entry.name == name) {
            out.push(AgentNameEntry {
                name: name.clone(),
                enabled: true,
                created_at: now,
            });
        }
    }

    out
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

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- T12: DidRecord new fields backwards-compat ----

    #[test]
    fn legacy_did_record_deserialises_with_webvh_default_method() {
        // A v0.6-vintage stored record lacks `method` + `domain`.
        // The `#[serde(default)]` fallback on both fields must accept
        // it: `method = "webvh"`, `domain = ""`. T13's M-01 migration
        // walks the keyspace and fills `domain` with the legacy
        // public_url host.
        let legacy = r#"{
            "owner": "did:example:owner",
            "mnemonic": "tenant/user1",
            "created_at": 1700000000,
            "updated_at": 1700000000,
            "version_count": 1,
            "did_id": null,
            "content_size": 0,
            "disabled": false,
            "deleted_at": null
        }"#;
        let rec: DidRecord = serde_json::from_str(legacy).unwrap();
        assert_eq!(rec.method, "webvh");
        assert_eq!(rec.domain, "");
    }

    #[test]
    fn new_did_record_round_trips_method_and_domain() {
        let original = DidRecord {
            owner: "did:example:owner".into(),
            mnemonic: "user1".into(),
            created_at: 0,
            updated_at: 0,
            version_count: 1,
            did_id: None,
            content_size: 0,
            disabled: false,
            deleted_at: None,
            method: "web".into(),
            domain: "tenant-a.example.com".into(),
            services: None,
            agent_names: Vec::new(),
        };
        let json = serde_json::to_string(&original).unwrap();
        let back: DidRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.method, "web");
        assert_eq!(back.domain, "tenant-a.example.com");
    }

    #[test]
    fn explicit_empty_domain_round_trips() {
        // Mid-migration state: M-01 set `method` but `domain` is
        // still the default empty string. Must round-trip cleanly so
        // the migration is idempotent.
        let legacy = r#"{
            "owner": "did:example:owner",
            "mnemonic": "u",
            "created_at": 0,
            "updated_at": 0,
            "version_count": 0,
            "method": "webvh"
        }"#;
        let rec: DidRecord = serde_json::from_str(legacy).unwrap();
        assert_eq!(rec.method, "webvh");
        assert_eq!(rec.domain, "");
    }

    #[test]
    fn extract_did_id_from_state_id() {
        let jsonl = r#"{"versionId":"1-abc","parameters":{"method":"did:webvh:1.0"},"state":{"id":"did:webvh:abc123:example.com:test"}}"#;
        assert_eq!(
            extract_did_id(jsonl),
            Some("did:webvh:abc123:example.com:test".to_string())
        );
    }

    #[test]
    fn extract_did_id_returns_none_without_state() {
        let jsonl = r#"{"parameters":{"method":"did:webvh:1.0"}}"#;
        assert_eq!(extract_did_id(jsonl), None);
    }

    #[test]
    fn extract_did_id_returns_none_for_non_webvh() {
        let jsonl = r#"{"state":{"id":"did:key:z6Mk..."}}"#;
        assert_eq!(extract_did_id(jsonl), None);
    }

    #[test]
    fn extract_did_id_uses_last_line() {
        let jsonl = r#"{"state":{"id":"did:webvh:first:host:path"}}
{"state":{"id":"did:webvh:second:host:path"}}"#;
        assert_eq!(
            extract_did_id(jsonl),
            Some("did:webvh:second:host:path".to_string())
        );
    }

    #[test]
    fn log_metadata_empty_content() {
        let meta = extract_log_metadata("");
        assert_eq!(meta.log_entry_count, 0);
        assert_eq!(meta.latest_version_id, None);
    }

    #[test]
    fn log_metadata_basic_entry() {
        let jsonl = r#"{"versionId":"1-QmHash","versionTime":"2025-01-23T04:12:36Z","parameters":{"method":"did:webvh:1.0","portable":true}}"#;
        let meta = extract_log_metadata(jsonl);
        assert_eq!(meta.log_entry_count, 1);
        assert_eq!(meta.latest_version_id.as_deref(), Some("1-QmHash"));
        assert!(meta.portable);
    }

    #[test]
    fn validate_jsonl_empty_rejected() {
        assert!(validate_did_jsonl("").is_err());
    }

    #[test]
    fn validate_jsonl_invalid_json_rejected() {
        assert!(validate_did_jsonl("not json").is_err());
    }

    #[test]
    fn did_record_deserialize_without_content_size() {
        let json = r#"{"owner":"did:example:a","mnemonic":"test","created_at":100,"updated_at":100,"version_count":1}"#;
        let record: DidRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.content_size, 0);
        assert!(record.did_id.is_none());
    }

    #[test]
    fn parse_log_entries_works() {
        let jsonl = r#"{"versionId":"1-abc","state":{"id":"test"},"parameters":{"method":"1.0"}}"#;
        let entries = parse_log_entries(jsonl);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].version_id.as_deref(), Some("1-abc"));
    }
}

#[cfg(test)]
mod agent_name_tests {
    use super::*;

    fn log_with_aka(aka: &[&str]) -> String {
        let list = aka
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"versionId\":\"1\",\"state\":{{\"id\":\"did:webvh:x:host.example\",\"alsoKnownAs\":[{list}]}}}}"
        )
    }

    #[test]
    fn extracts_names_on_the_hosting_domain() {
        let log = log_with_aka(&["https://host.example/@alice", "host.example/@bob"]);
        let mut names = extract_agent_names(&log, "host.example");
        names.sort();
        assert_eq!(names, vec!["alice", "bob"]);
    }

    #[test]
    fn ignores_names_on_other_domains() {
        let log = log_with_aka(&["https://elsewhere.example/@alice"]);
        assert!(extract_agent_names(&log, "host.example").is_empty());
    }

    #[test]
    fn ignores_non_agent_name_entries() {
        // alsoKnownAs legitimately holds other identifier types.
        let log = log_with_aka(&[
            "did:web:host.example:someone",
            "https://host.example/@alice",
        ]);
        assert_eq!(extract_agent_names(&log, "host.example"), vec!["alice"]);
    }

    #[test]
    fn deduplicates() {
        let log = log_with_aka(&["host.example/@alice", "https://host.example/@alice"]);
        assert_eq!(extract_agent_names(&log, "host.example"), vec!["alice"]);
    }

    #[test]
    fn no_also_known_as_is_empty() {
        let log = "{\"versionId\":\"1\",\"state\":{\"id\":\"did:webvh:x:host.example\"}}";
        assert!(extract_agent_names(log, "host.example").is_empty());
    }

    fn entry(name: &str, enabled: bool, created_at: u64) -> AgentNameEntry {
        AgentNameEntry {
            name: name.into(),
            enabled,
            created_at,
        }
    }

    #[test]
    fn reconcile_adds_newly_claimed_names() {
        let out = reconcile_agent_names(&[], &["alice".into()], 100);
        assert_eq!(out, vec![entry("alice", true, 100)]);
    }

    #[test]
    fn reconcile_keeps_the_original_claim_time() {
        // A republish is not a re-claim; `created_at` is the binding's age.
        let out = reconcile_agent_names(&[entry("alice", true, 100)], &["alice".into()], 500);
        assert_eq!(out, vec![entry("alice", true, 100)]);
    }

    #[test]
    fn reconcile_parks_a_name_the_document_dropped() {
        // Retained, so the reservation holds; disabled, so it stops resolving.
        let out = reconcile_agent_names(&[entry("alice", true, 100)], &[], 500);
        assert_eq!(out, vec![entry("alice", false, 100)]);
    }

    #[test]
    fn reconcile_reenables_a_reclaimed_name() {
        let out = reconcile_agent_names(&[entry("alice", false, 100)], &["alice".into()], 500);
        assert_eq!(out, vec![entry("alice", true, 100)]);
    }
}
