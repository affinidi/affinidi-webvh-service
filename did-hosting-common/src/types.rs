use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Auth types
// ---------------------------------------------------------------------------

/// Wire shape for `POST /api/auth/challenge`. Conforms to
/// `spec/auth/challenge/0.1`: the `did` field serialises as `subject`
/// per the canonical payload schema. The Rust identifier stays `did`
/// for consistency with the rest of the codebase. `alias = "did"`
/// keeps clients that still send the legacy name working through one
/// upgrade cycle.
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeRequest {
    #[serde(rename = "subject", alias = "did")]
    pub did: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    pub session_id: String,
    pub data: ChallengeData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeData {
    pub challenge: String,
}

/// Payload of the `did-hosting/auth/authenticate/1.0` Trust-Task
/// envelope (SIOPv2 self-issued login).
///
/// The browser wallet self-issues an `id_token` (a compact EdDSA JWS
/// signed by its `did:key`) and carries it in the Trust-Task
/// envelope's `payload`. The server verifies the token by resolving
/// the issuer DID, then binds the session.
///
/// Field naming is `snake_case` on the wire to match the wallet's
/// emitted payload (`id_token`, `session_id`, `session_pubkey_b58btc`).
/// This is the *inner* Trust-Task payload, not a top-level response
/// type, so it intentionally does not use the `camelCase` convention
/// the response types do.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatePayload {
    /// SIOPv2 self-issued `id_token` — a compact EdDSA JWS
    /// (`header.payload.signature`, base64url no-pad).
    pub id_token: String,
    /// The challenge session this login answers. The token's `nonce`
    /// must equal the session's issued challenge.
    pub session_id: String,
    /// Optional ephemeral session pubkey (Ed25519 multikey,
    /// base58btc-encoded with the `z` prefix). Bound to the issued JWT
    /// so subsequent Trust-Task Data-Integrity proofs can be tied to
    /// the same browser session. Only `z6Mk…` (Ed25519) is accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_pubkey_b58btc: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticateResponse {
    pub session_id: String,
    pub data: AuthenticateData,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticateData {
    pub access_token: String,
    pub access_expires_at: u64,
    pub refresh_token: String,
    pub refresh_expires_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResponse {
    pub session_id: String,
    pub data: RefreshData,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshData {
    pub access_token: String,
    pub access_expires_at: u64,
    /// New refresh token. Refresh always rotates the refresh token; the old
    /// one is invalidated atomically and clients must use this new token for
    /// the next refresh.
    pub refresh_token: String,
    pub refresh_expires_at: u64,
}

// ---------------------------------------------------------------------------
// DID management types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDidRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckNameRequest {
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckNameResponse {
    pub available: bool,
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestUriResponse {
    pub mnemonic: String,
    pub did_url: String,
}

/// Atomic claim-and-publish request — see `MSG_DID_REGISTER` for the
/// motivation. `path` is required; the DID payload is supplied via
/// `did_data` (preferred) or `did_log` (legacy, webvh-only alias).
/// `force` is only honoured when the caller is an admin taking over a
/// slot owned by a different DID (no force needed when the caller is
/// already the owner; the operation is idempotent in that case).
///
/// Server-side validation rejects payloads whose embedded DID
/// identifier does not name this host or does not name `path`, so an
/// admin can't upload arbitrary content under a path they happen to
/// own.
///
/// ## Multi-method wire shape (T26)
///
/// - `method`: one of `"webvh"`, `"web"`. Optional; if omitted, the
///   server attempts to derive it from `did_data.id` and falls back to
///   `"webvh"` for backwards-compat (matching the pre-T26 wire shape
///   that only supports webvh).
/// - `did_data`: the method-specific payload. For `webvh` this is the
///   `did.jsonl` log (either a JSON string carrying the raw text, or a
///   JSON array of log entries that will be serialised to jsonl). For
///   `web` this is a `did.json` document (object).
/// - `domain`: the hosting domain this DID should be registered under.
///   Optional; defaults to the caller's ACL default-domain per spec
///   §3.
/// - `did_log`: deprecated legacy field. When set without `did_data`,
///   treated as `method = "webvh"` and the string is the jsonl
///   payload. Setting both `did_data` and `did_log` is a 400 (the
///   server can't tell which the caller meant).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DidRegisterRequest {
    pub path: String,

    /// Preferred T26 shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_data: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,

    /// Legacy pre-T26 field — webvh-only. Use `did_data` + `method`
    /// for new clients; this field is accepted unchanged for v0.7
    /// backwards-compat and will be removed in a future release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_log: Option<String>,

    /// Required when admin is replacing a slot they don't own; ignored
    /// when caller is already the owner or the slot is free. Defaults
    /// to false.
    #[serde(default)]
    pub force: bool,
}

impl DidRegisterRequest {
    /// Normalise the multi-shape wire form into `(method, payload_bytes)`
    /// pairs the server-side handlers can act on directly.
    ///
    /// Returns:
    /// - `Err` with `Validation` when the request is ambiguous (both
    ///   `did_data` and `did_log` set), missing payload entirely, or
    ///   the declared `method` mismatches the method derived from
    ///   `did_data.id`.
    /// - `Ok((method, payload))` where `method` is one of the known
    ///   strings (`"webvh"`, `"web"`) and `payload` is the bytes the
    ///   storage layer will persist (the jsonl text for webvh, the
    ///   did.json bytes for web).
    pub fn resolve(&self) -> Result<(String, Vec<u8>), String> {
        if self.did_data.is_some() && self.did_log.is_some() {
            return Err("request carries both `did_data` and `did_log`; supply exactly one".into());
        }

        if let Some(did_log) = &self.did_log {
            // Legacy: did_log implies webvh. If `method` is explicit
            // and contradicts, reject.
            let method = self.method.as_deref().unwrap_or("webvh");
            if method != "webvh" {
                return Err(format!(
                    "`did_log` legacy field is webvh-only; received method = '{method}'. \
                     Use `did_data` for non-webvh methods.",
                ));
            }
            return Ok(("webvh".to_string(), did_log.clone().into_bytes()));
        }

        let did_data = self
            .did_data
            .as_ref()
            .ok_or_else(|| "request requires either `did_data` or `did_log`".to_string())?;

        // Derive the method from `did_data.id` when present, then
        // cross-check with the explicit `method` if both supplied.
        let derived_method = derive_method_from_did_data(did_data);
        let method = match (&self.method, &derived_method) {
            (Some(m), Some(d)) if m != d => {
                return Err(format!(
                    "method mismatch: request declares `method = \"{m}\"` but \
                     `did_data.id` resolves to method `\"{d}\"`. \
                     Either remove `method` (it will be derived) or fix `did_data.id`.",
                ));
            }
            (Some(m), _) => m.clone(),
            (None, Some(d)) => d.clone(),
            (None, None) => {
                return Err(
                    "request requires `method` (or a `did_data.id` from which it can \
                     be derived)"
                        .into(),
                );
            }
        };

        let bytes = match method.as_str() {
            "webvh" => {
                // webvh payload is jsonl text. Accept either a JSON
                // string (preferred) or an array of objects (one per
                // log entry — serialise to jsonl).
                if let Some(s) = did_data.as_str() {
                    s.as_bytes().to_vec()
                } else if let Some(arr) = did_data.as_array() {
                    let mut buf = String::new();
                    for (i, entry) in arr.iter().enumerate() {
                        if i > 0 {
                            buf.push('\n');
                        }
                        buf.push_str(
                            &serde_json::to_string(entry).map_err(|e| format!("entry {i}: {e}"))?,
                        );
                    }
                    buf.into_bytes()
                } else {
                    return Err(
                        "webvh `did_data` must be a jsonl string or an array of log entries".into(),
                    );
                }
            }
            "web" => {
                if did_data.is_object() {
                    serde_json::to_vec(did_data).map_err(|e| e.to_string())?
                } else {
                    return Err("web `did_data` must be a did.json object".into());
                }
            }
            other => {
                return Err(format!(
                    "unknown or unsupported method `{other}`; compiled-in methods: webvh, web",
                ));
            }
        };

        Ok((method, bytes))
    }
}

/// Best-effort extraction of `"<method>"` from `did_data.id`, e.g.
/// `did_data.id = "did:web:example.com:alice"` → `Some("web")`.
/// Returns `None` when `id` is missing or malformed.
fn derive_method_from_did_data(did_data: &serde_json::Value) -> Option<String> {
    let id = did_data.get("id")?.as_str()?;
    // Fast extraction: split on ':'; expect "did:<method>:<rest>".
    let mut parts = id.splitn(3, ':');
    let prefix = parts.next()?;
    let method = parts.next()?;
    let _rest = parts.next()?;
    if prefix != "did" || method.is_empty() {
        return None;
    }
    Some(method.to_string())
}

#[cfg(test)]
mod did_register_request_tests {
    use super::*;
    use serde_json::json;

    fn req() -> DidRegisterRequest {
        DidRegisterRequest {
            path: "alpha".into(),
            ..Default::default()
        }
    }

    #[test]
    fn legacy_did_log_resolves_as_webvh() {
        let r = DidRegisterRequest {
            did_log: Some("line1\nline2".into()),
            ..req()
        };
        let (method, payload) = r.resolve().unwrap();
        assert_eq!(method, "webvh");
        assert_eq!(payload, b"line1\nline2");
    }

    #[test]
    fn legacy_did_log_with_explicit_webvh_method_ok() {
        let r = DidRegisterRequest {
            method: Some("webvh".into()),
            did_log: Some("line".into()),
            ..req()
        };
        let (method, _) = r.resolve().unwrap();
        assert_eq!(method, "webvh");
    }

    #[test]
    fn legacy_did_log_with_non_webvh_method_rejected() {
        let r = DidRegisterRequest {
            method: Some("web".into()),
            did_log: Some("line".into()),
            ..req()
        };
        let err = r.resolve().expect_err("conflict must reject");
        assert!(err.contains("webvh-only"), "got: {err}");
    }

    #[test]
    fn both_did_data_and_did_log_rejected() {
        let r = DidRegisterRequest {
            did_data: Some(json!("line")),
            did_log: Some("line".into()),
            ..req()
        };
        let err = r.resolve().expect_err("ambiguous must reject");
        assert!(err.contains("both"), "got: {err}");
    }

    #[test]
    fn neither_did_data_nor_did_log_rejected() {
        let err = req().resolve().expect_err("missing payload must reject");
        assert!(err.contains("either"), "got: {err}");
    }

    #[test]
    fn did_data_webvh_string_passes_through() {
        let r = DidRegisterRequest {
            method: Some("webvh".into()),
            did_data: Some(json!("the\njsonl\nbytes")),
            ..req()
        };
        let (method, payload) = r.resolve().unwrap();
        assert_eq!(method, "webvh");
        assert_eq!(payload, b"the\njsonl\nbytes");
    }

    #[test]
    fn did_data_webvh_array_serialises_to_jsonl() {
        let r = DidRegisterRequest {
            method: Some("webvh".into()),
            did_data: Some(json!([{"v": 1}, {"v": 2}])),
            ..req()
        };
        let (_, payload) = r.resolve().unwrap();
        let text = String::from_utf8(payload).unwrap();
        assert_eq!(text, "{\"v\":1}\n{\"v\":2}");
    }

    #[test]
    fn did_data_web_object_serialises() {
        let r = DidRegisterRequest {
            method: Some("web".into()),
            did_data: Some(json!({ "id": "did:web:example.com:alice" })),
            ..req()
        };
        let (method, payload) = r.resolve().unwrap();
        assert_eq!(method, "web");
        let parsed: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(
            parsed.get("id").and_then(|v| v.as_str()).unwrap(),
            "did:web:example.com:alice"
        );
    }

    #[test]
    fn method_mismatch_explicit_vs_did_data_id_rejected() {
        let r = DidRegisterRequest {
            method: Some("webvh".into()),
            did_data: Some(json!({ "id": "did:web:example.com:alice" })),
            ..req()
        };
        let err = r.resolve().expect_err("method mismatch must reject");
        assert!(err.contains("mismatch"), "got: {err}");
    }

    #[test]
    fn method_derived_from_did_data_id_when_not_explicit() {
        let r = DidRegisterRequest {
            did_data: Some(json!({ "id": "did:web:example.com:bob" })),
            ..req()
        };
        let (method, _) = r.resolve().unwrap();
        assert_eq!(method, "web");
    }

    #[test]
    fn unknown_method_rejected() {
        let r = DidRegisterRequest {
            method: Some("webxyz".into()),
            did_data: Some(json!("some-bytes")),
            ..req()
        };
        let err = r.resolve().expect_err("unknown method must reject");
        assert!(err.contains("unsupported"), "got: {err}");
    }
}

/// Atomic register response. `mnemonic` equals `path` (custom paths are
/// their own mnemonic on the server side); included for symmetry with
/// `RequestUriResponse`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidRegisterResponse {
    pub mnemonic: String,
    pub did_url: String,
}

// ---------------------------------------------------------------------------
// DID list / stats types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidListEntry {
    pub mnemonic: String,
    pub owner: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub version_count: u64,
    pub did_id: Option<String>,
    pub total_resolves: u64,
    #[serde(default)]
    pub disabled: bool,
    /// DID hosting method (`"webvh"` / `"web"`). Surfaced on the
    /// wire so the UI can render a method badge per row without
    /// loading the full record. Pre-T12 records that haven't been
    /// migrated yet ship as `None` and the UI hides the badge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Hosting domain (T12 / M-01). Same shape contract as
    /// `method` above — `None` for unmigrated records, populated
    /// for everything M-01 has run over.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DidStats {
    #[serde(alias = "total_resolves")]
    pub total_resolves: u64,
    #[serde(alias = "total_updates")]
    pub total_updates: u64,
    #[serde(alias = "last_resolved_at")]
    pub last_resolved_at: Option<u64>,
    #[serde(alias = "last_updated_at")]
    pub last_updated_at: Option<u64>,
}

// ---------------------------------------------------------------------------
// Stats sync (server → control plane)
// ---------------------------------------------------------------------------

/// Per-DID counter delta for a single sync interval.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidStatsDelta {
    pub mnemonic: String,
    pub resolve_delta: u64,
    pub update_delta: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_resolved_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_updated_at: Option<u64>,
}

/// Payload sent by did-hosting-server to the control plane with per-DID deltas.
///
/// Pushed periodically (configurable via `stats.sync_interval_secs`).
/// Only sent when there are actual changes — empty syncs are skipped.
/// The control plane merges these deltas into its persistent per-DID stats.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsSyncPayload {
    /// DID of the reporting server.
    pub server_did: String,
    /// Monotonic sequence number (incremented on each sync). Used by the
    /// control plane to detect replayed or out-of-order payloads.
    pub seq: u64,
    /// Per-DID counter deltas since the last sync.
    pub did_deltas: Vec<DidStatsDelta>,
}

// ---------------------------------------------------------------------------
// Witness types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessResponse {
    pub witness_id: String,
    pub did: String,
    pub label: Option<String>,
    pub created_at: u64,
    pub proofs_signed: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WitnessListResponse {
    pub witnesses: Vec<WitnessResponse>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignProofRequest {
    pub version_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignProofResponse {
    pub version_id: String,
    pub proof: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateWitnessRequest {
    pub label: Option<String>,
}

// ---------------------------------------------------------------------------
// Watcher sync types
// ---------------------------------------------------------------------------

/// Pushed from did-hosting-server to webvh-watcher when a DID is published.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncDidRequest {
    pub mnemonic: String,
    pub did_id: Option<String>,
    pub log_content: String,
    pub witness_content: Option<String>,
    pub source_url: String,
    pub updated_at: u64,
    pub disabled: bool,
}

/// Pushed from did-hosting-server to webvh-watcher when a DID is deleted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncDeleteRequest {
    pub mnemonic: String,
    pub source_url: String,
}

// ---------------------------------------------------------------------------
// High-level create result
// ---------------------------------------------------------------------------

/// Result of the high-level `create_did` operation.
#[derive(Debug)]
pub struct CreateDidResult {
    /// The mnemonic / path assigned to this DID on the server.
    pub mnemonic: String,
    /// The full public URL where the DID log is served.
    pub did_url: String,
    /// The self-certifying identifier derived from the log entry.
    pub scid: String,
    /// The final `did:webvh:...` identifier.
    pub did: String,
    /// The public key multibase of the signing key.
    pub public_key_multibase: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_list_entry_serializes_camel_case() {
        let entry = DidListEntry {
            mnemonic: "test".to_string(),
            owner: "did:example:owner".to_string(),
            created_at: 1000,
            updated_at: 2000,
            version_count: 1,
            did_id: Some("did:webvh:abc:host:path".to_string()),
            total_resolves: 42,
            disabled: false,
            method: None,
            domain: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"createdAt\""));
        assert!(json.contains("\"updatedAt\""));
        assert!(json.contains("\"versionCount\""));
        assert!(json.contains("\"didId\""));
        assert!(json.contains("\"totalResolves\""));
        assert!(!json.contains("\"created_at\""));
        assert!(!json.contains("\"updated_at\""));
        assert!(!json.contains("\"version_count\""));
        assert!(!json.contains("\"did_id\""));
        assert!(!json.contains("\"total_resolves\""));
    }

    #[test]
    fn did_list_entry_did_id_none_serializes_as_null() {
        let entry = DidListEntry {
            mnemonic: "test".to_string(),
            owner: "did:example:owner".to_string(),
            created_at: 0,
            updated_at: 0,
            version_count: 0,
            did_id: None,
            total_resolves: 0,
            disabled: false,
            method: None,
            domain: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"didId\":null"));
    }

    #[test]
    fn did_list_entry_roundtrip() {
        let entry = DidListEntry {
            mnemonic: "test".to_string(),
            owner: "did:example:owner".to_string(),
            created_at: 1000,
            updated_at: 2000,
            version_count: 3,
            did_id: Some("did:webvh:abc:host:path".to_string()),
            total_resolves: 99,
            disabled: false,
            method: Some("webvh".to_string()),
            domain: Some("host.example".to_string()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: DidListEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.mnemonic, "test");
        assert_eq!(back.version_count, 3);
        assert_eq!(back.did_id, Some("did:webvh:abc:host:path".to_string()));
        assert_eq!(back.total_resolves, 99);
    }

    #[test]
    fn did_stats_default_values() {
        let stats = DidStats::default();
        assert_eq!(stats.total_resolves, 0);
        assert_eq!(stats.total_updates, 0);
        assert_eq!(stats.last_resolved_at, None);
        assert_eq!(stats.last_updated_at, None);
    }

    #[test]
    fn did_stats_serializes_camel_case() {
        let stats = DidStats {
            total_resolves: 10,
            total_updates: 5,
            last_resolved_at: Some(1000),
            last_updated_at: Some(2000),
        };
        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("\"totalResolves\""));
        assert!(json.contains("\"totalUpdates\""));
        assert!(json.contains("\"lastResolvedAt\""));
        assert!(json.contains("\"lastUpdatedAt\""));
        assert!(!json.contains("\"total_resolves\""));
    }

    #[test]
    fn request_uri_response_camel_case() {
        let resp = RequestUriResponse {
            mnemonic: "test".to_string(),
            did_url: "http://example.com/test/did.jsonl".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"didUrl\""));
        assert!(!json.contains("\"did_url\""));
    }
}
