//! The stored DID data types ([`DidRecord`], [`AgentNameEntry`],
//! [`LogMetadata`], [`LogEntryInfo`]) and the store key builders.

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
    /// Set when an admin suspended the slot. Only an admin can then resume
    /// it: the owner's `active` is refused, and a re-register or a forced
    /// re-create carries the suspension forward. Cleared when an admin
    /// resumes the slot. Records written before this field existed read as
    /// `false`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled_by_admin: bool,
    /// Soft-delete timestamp. When set, the DID is treated as deleted but
    /// content is preserved for recovery within the retention period.
    #[serde(default)]
    pub deleted_at: Option<u64>,

    // ---- Multi-method + multi-domain fields ----
    //
    // Both `#[serde(default)]` for backwards-compat — `DidRecord`s
    // written before multi-method hosting lack these fields and
    // deserialise unchanged. The M-01 migration walks the keyspace and
    // populates them (`method = "webvh"` for every legacy record;
    // `domain` derived from the legacy `public_url` host that the
    // first-boot domain seed surfaced).
    //
    // The dual storage model (this record carries metadata; raw
    // content lives at `content_log_key` / `content_witness_key`)
    // is kept intentionally — see
    // `docs/archive/multi-method-hosting-spec.md` §3 "Storage" tradeoff
    // note. Inlining `data: Vec<u8>` into the record made every DID
    // listing pull content bytes on every scan; the split keeps metadata
    // reads cheap.
    /// DID method this record was registered under. Always one of the
    /// enabled-at-compile-time methods (`webvh`, `web`); the daemon
    /// rejects any other value on the write path. Legacy records
    /// (not yet migrated by M-01) default to `"webvh"` via the `#[serde(default)]`
    /// fallback in `Self::default_method`.
    #[serde(default = "default_method")]
    pub method: String,

    /// Domain (hostname) this DID is hosted under. Matches the host
    /// segment of the DID identifier (`did:{method}:…:{domain}:…`).
    /// Legacy records (not yet migrated by M-01) default to the empty string;
    /// the migration fills it with the host derived from the legacy
    /// `public_url`. New records always carry a normalised non-empty
    /// value.
    #[serde(default)]
    pub domain: String,

    /// Cached `service[].type` values from the latest log entry's DID
    /// document, in document order. Lets `did/list` render per-DID
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
    /// (`register_did_atomic`, the agent-name ops, the server's sync-from-control
    /// import, bootstrap). `M-02` sweeps legacy records at boot on all three
    /// deployments — server and daemon via the full migration registry,
    /// standalone control via a runner carrying M-02 alone. Every publish
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
    /// The did:scid alias of the latest document and whether it lists it
    /// (VTI-KEY-164); `None` when the latest document is not did:webvh.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scid_alias: Option<crate::scid::ScidAliasInfo>,
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
    format!("owner:{}:{mnemonic}", crate::scid::strip_scid_src(did))
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
