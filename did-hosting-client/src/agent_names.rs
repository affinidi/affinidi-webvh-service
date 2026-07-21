//! Wire types for the agent-name surface — a human-memorable
//! `example.com/@alice` that redirects to a hosted DID.
//!
//! ## What an agent name is
//!
//! `GET https://example.com/@alice` answers `302` to the DID's resolution
//! URL. The binding is only honoured when the DID's **signed document claims
//! the name back** via `alsoKnownAs` — a resolver is expected to verify that
//! round-trip, and a host structurally cannot serve a name the document does
//! not claim. That is the specification's Layer-1 anti-spoofing rule, and it
//! is why every mutating verb here carries a full new signed `did.jsonl`
//! rather than just a name.
//!
//! ## The four verbs
//!
//! | verb      | document must     | registry effect                    |
//! |-----------|-------------------|------------------------------------|
//! | `set`     | claim the name    | bind it to this DID                |
//! | `enable`  | claim the name    | resume serving a parked name       |
//! | `disable` | *not* claim it    | park: stops resolving, stays yours |
//! | `remove`  | *not* claim it    | release: anyone may reclaim it     |
//!
//! Submitting a document whose `alsoKnownAs` disagrees with the verb is
//! rejected (`also_known_as_mismatch`) — that check is what keeps the served
//! state and the signed document from ever diverging.
//!
//! `disable` and `remove` differ in exactly one way, and it is the one that
//! matters: parking keeps the reservation, so no other DID can take the name
//! while you are not using it. Removing gives it up.
//!
//! ## Errors worth distinguishing
//!
//! A caller needs different UI for each of these, so the host reports them
//! distinctly rather than as one generic failure: `name_taken` (bound to
//! another DID — pick another), `name_reserved` (on the host's reserved list,
//! e.g. `@admin` / `@support`), `not_owner` (you do not control this DID),
//! and `also_known_as_mismatch` (the submitted document does not match the
//! verb).

use serde::{Deserialize, Serialize};

/// Request body for the four mutating verbs — `POST
/// /api/agent-names/{set,remove,enable,disable}`.
///
/// The same shape for every verb; the operation is the URL, not a field.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentNameRequest<'a> {
    /// The hosted DID's mnemonic / path.
    pub mnemonic: &'a str,
    /// The name's local part — the `alice` in `/@alice`, without the `@`.
    /// A leading `@` is tolerated and canonicalised away by the host.
    pub name: &'a str,
    /// The complete new signed `did.jsonl`, whose `alsoKnownAs` must claim
    /// (`set`/`enable`) or no longer claim (`remove`/`disable`) the name.
    /// The host republishes this as a new DID version and applies the
    /// registry change in the same commit.
    pub did_log: &'a str,
    /// Hosting domain. Omit to let the host use the DID's own host, which is
    /// the usual case — a name is only meaningful within its domain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<&'a str>,
}

/// Request body for `POST /api/agent-names/check`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentNameCheckRequest<'a> {
    /// The name's local part, without the `@`.
    pub name: &'a str,
    /// Domain to check against. Availability is domain-scoped: the same name
    /// may be free on one host and taken on another.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<&'a str>,
}

/// Response from `POST /api/agent-names/check`.
///
/// Probing before you sign is the point of this endpoint: without it the only
/// way to discover a collision is to publish a new DID version and have the
/// bind rejected.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentNameAvailability {
    /// The canonicalised local part.
    pub name: String,
    /// The domain the answer applies to.
    pub domain: String,
    /// Free to claim: neither reserved nor already bound on this domain.
    pub available: bool,
    /// On the host's reserved list (`@admin`, `@support`, …). Unavailable but
    /// well-formed — distinct from a grammar error, which is a 400.
    pub reserved: bool,
}

/// One name bound to a hosted DID, as returned in a record's `agentNames`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentNameEntry {
    /// The local part, without the `@`.
    pub name: String,
    /// Whether the name currently resolves.
    ///
    /// `false` means **parked, not gone**: the name still belongs to this DID
    /// and nobody else can claim it. This flag is the only way to see a parked
    /// name at all — parking works by dropping the claim from `alsoKnownAs`,
    /// so the DID document cannot show you one.
    pub enabled: bool,
    /// Unix seconds when the name was first bound to this DID.
    pub created_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The daemon reads camelCase; `did_log` must not go out as `did_log`.
    #[test]
    fn request_serialises_camel_case_and_omits_absent_domain() {
        let body = serde_json::to_value(AgentNameRequest {
            mnemonic: "slot-one",
            name: "alice",
            did_log: "<jsonl>",
            domain: None,
        })
        .unwrap();
        assert_eq!(body["didLog"], "<jsonl>");
        assert_eq!(body["mnemonic"], "slot-one");
        assert!(
            body.get("domain").is_none(),
            "an absent domain must be omitted, not sent as null: {body}"
        );

        let body = serde_json::to_value(AgentNameRequest {
            mnemonic: "slot-one",
            name: "alice",
            did_log: "<jsonl>",
            domain: Some("example.com"),
        })
        .unwrap();
        assert_eq!(body["domain"], "example.com");
    }

    #[test]
    fn availability_deserialises_the_daemon_body() {
        let a: AgentNameAvailability = serde_json::from_str(
            r#"{"name":"admin","domain":"example.com","available":false,"reserved":true}"#,
        )
        .unwrap();
        assert!(!a.available);
        assert!(a.reserved, "reserved must survive as its own signal");
    }

    /// A parked entry is the case that matters: it must round-trip as
    /// `enabled: false` rather than being confused with an absent name.
    #[test]
    fn entry_deserialises_a_parked_name() {
        let e: AgentNameEntry =
            serde_json::from_str(r#"{"name":"alice","enabled":false,"createdAt":1700000000}"#)
                .unwrap();
        assert_eq!(e.name, "alice");
        assert!(!e.enabled);
        assert_eq!(e.created_at, 1_700_000_000);
    }
}
