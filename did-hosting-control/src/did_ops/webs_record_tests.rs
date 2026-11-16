//! Tests for when a slot's path is read under the did:webs grammar.

use super::*;

fn record(method: &str, mnemonic: &str, did_id: Option<&str>) -> DidRecord {
    DidRecord {
        owner: "did:key:z6Mkowner".to_string(),
        mnemonic: mnemonic.to_string(),
        created_at: 0,
        updated_at: 0,
        version_count: 1,
        did_id: did_id.map(str::to_string),
        content_size: 0,
        disabled: false,
        disabled_by_admin: false,
        deleted_at: None,
        method: method.to_string(),
        domain: "example.com".to_string(),
        services: None,
        agent_names: Vec::new(),
    }
}

#[test]
fn the_webs_grammar_needs_the_record_to_be_a_webs_record_for_the_path() {
    let path = "people/EAbCdEf";
    let did = "did:webs:example.com:people:EAbCdEf";
    assert!(is_webs_record_for(&record("webs", path, Some(did)), path));
    // The method field alone is not enough.
    assert!(!is_webs_record_for(
        &record(
            "webs",
            path,
            Some("did:webvh:scid:example.com:people:EAbCdEf")
        ),
        path
    ));
    assert!(!is_webs_record_for(&record("webs", path, None), path));
    assert!(!is_webs_record_for(
        &record("webs", path, Some("did:webs:example.com:people:EOther")),
        path
    ));
    assert!(!is_webs_record_for(
        &record("webs", "people/EOther", Some(did)),
        path
    ));
    assert!(!is_webs_record_for(&record("webvh", path, Some(did)), path));
}
