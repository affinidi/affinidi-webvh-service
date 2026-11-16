//! Unit tests for the `did_ops` record types, JSONL validation and extraction.

use super::*;

/// The did:web bridge rewrites the did:webvh id only: a did:scid alias
/// the document lists survives into the did:web document unchanged.
#[test]
fn the_did_web_bridge_keeps_the_scid_alias() {
    let line = serde_json::json!({
        "versionId": "1-Qm",
        "state": {
            "id": "did:webvh:Qm1:a.example:alice",
            "alsoKnownAs": ["did:web:a.example:alice", "did:scid:vh:1:Qm1?src=a.example/alice"]
        }
    })
    .to_string();
    let doc = extract_did_web_document(&line, "did:web:a.example:alice").expect("bridged");
    let doc: serde_json::Value = serde_json::from_slice(&doc).unwrap();
    assert_eq!(doc["id"], "did:web:a.example:alice");
    assert_eq!(
        doc["alsoKnownAs"],
        serde_json::json!([
            "did:web:a.example:alice",
            "did:scid:vh:1:Qm1?src=a.example/alice"
        ])
    );
}

/// A did:scid alias is not an agent name, and claims none.
#[test]
fn a_scid_alias_claims_no_agent_name() {
    let doc = serde_json::json!({
        "alsoKnownAs": ["did:scid:vh:1:Qm1?src=a.example/alice", "https://a.example/@alice"]
    });
    assert_eq!(
        agent_names_from_document(&doc, "a.example"),
        vec!["alice".to_string()]
    );
}

// ---- DidRecord multi-method fields: backwards-compat ----

#[test]
fn legacy_did_record_deserialises_with_webvh_default_method() {
    // A record stored before multi-method hosting lacks `method` +
    // `domain`. The `#[serde(default)]` fallback on both fields must
    // accept it: `method = "webvh"`, `domain = ""`. The M-01 migration
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
        disabled_by_admin: false,
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
    assert_eq!(meta.scid_alias, None);
}

/// The did:scid alias state is read from the latest entry only.
#[test]
fn log_metadata_scid_alias_from_latest_state() {
    use crate::scid::ScidAliasStatus;
    let jsonl = concat!(
        r#"{"versionId":"1-a","state":{"id":"did:webvh:Qm1:a.example:alice","alsoKnownAs":["did:scid:vh:1:Qm1?src=a.example/alice"]}}"#,
        "\n",
        r#"{"versionId":"2-b","state":{"id":"did:webvh:Qm1:b.example:alice","alsoKnownAs":["did:scid:vh:1:Qm1?src=a.example/alice"]}}"#,
    );
    let alias = extract_log_metadata(jsonl).scid_alias.unwrap();
    assert_eq!(alias.did_url, "did:scid:vh:1:Qm1?src=b.example/alice");
    assert_eq!(alias.status, ScidAliasStatus::Stale);
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
fn validate_jsonl_too_many_entries_rejected() {
    // One line over the cap is refused on the count check, before any
    // per-entry parse/verify work (SEC hardening — DoS guard).
    let content = "x\n".repeat(MAX_LOG_ENTRIES + 1);
    let err = validate_did_jsonl(&content).unwrap_err();
    assert!(
        err.contains("too many log entries"),
        "expected entry-count rejection, got: {err}"
    );
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
