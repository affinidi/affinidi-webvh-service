//! Unit tests for agent-name extraction from `alsoKnownAs`.

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
