//! `did:scid:vh:1` identities, as callers present them and as hosted logs
//! list them.
//!
//! A hosted log is always a `did:webvh` log; its `did:scid:vh:1:<scid>` DID is
//! verified by that same log but is a distinct identity (VTI-KEY-164). Callers
//! — owners, ACL subjects, proof signers — may present either. A did:scid
//! identity is the bare DID: its `?src=` is a locator for the log, not part of
//! the identity (VTI-KEY-160), so it is recorded, keyed and compared without
//! it. A reference that carries `src` (an issuer, a `verificationMethod`, a
//! DIDComm `from`) matches the bare DID.

use didwebvh_rs::DIDWebVHState;
use serde_json::Value;

pub use affinidi_did_common::scid::{same_reference, scid_src, strip_scid_src};

/// The identity a caller-presented DID (or DID URL) names: a did:scid without
/// its `src` locator, anything else unchanged.
pub fn identity(did: &str) -> String {
    strip_scid_src(did).into_owned()
}

/// The `did:scid:vh:1:<scid>?src=…` alias of a hosted `did:webvh` log: what a
/// log lists in `alsoKnownAs` to link its two forms (VTI-KEY-166).
pub fn scid_alias(webvh_did: &str) -> String {
    DIDWebVHState::convert_webvh_id_to_scid_id(webvh_did)
}

/// Whether a did:webvh document lists its own did:scid alias, and for where.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ScidAliasStatus {
    /// `alsoKnownAs` lists [`scid_alias`] of the document's `id` — the forms
    /// are one subject (VTI-KEY-164).
    Listed,
    /// No `alsoKnownAs` entry is a did:scid DID of this SCID.
    NotListed,
    /// A did:scid DID of this SCID is listed, but not with the `src` of the
    /// log's current location — a location before a move, or no `src` at all.
    Stale,
}

/// The did:scid alias of a did:webvh document and whether it lists it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScidAliasInfo {
    /// The DID URL the document would list: `did:scid:vh:1:<scid>?src=…`.
    pub did_url: String,
    pub status: ScidAliasStatus,
}

/// Why [`with_scid_alias`] produced no new document.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScidAliasError {
    /// The document's `id` is not a `did:webvh:<scid>:<location>` DID, so it
    /// has no did:scid alias to list.
    #[error("the document's id is not a did:webvh DID")]
    NotWebvh,
    /// The document already says what was asked. Publishing it anyway would
    /// append an entry that changes nothing — and, where pre-rotation applies,
    /// still rotate the update key.
    #[error("{0}")]
    NoChange(&'static str),
}

/// The did:scid alias of a did:webvh `id`, or `None` when `id` is not one.
fn alias_of(id: &str) -> Option<String> {
    let rest = id.strip_prefix("did:webvh:")?;
    let (scid, location) = rest.split_once(':')?;
    if scid.is_empty() || location.is_empty() {
        return None;
    }
    Some(scid_alias(id))
}

/// The `alsoKnownAs` entries of `document`, as strings (anything else kept
/// verbatim by the callers that rewrite the list).
fn also_known_as(document: &Value) -> &[Value] {
    document
        .get("alsoKnownAs")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

/// Whether `entry` is the did:scid DID of the SCID whose alias is `alias`,
/// with any `src` or none.
fn names_this_scid(entry: &Value, alias: &str) -> bool {
    entry
        .as_str()
        .is_some_and(|e| e.starts_with("did:scid:") && strip_scid_src(e) == strip_scid_src(alias))
}

/// The did:scid alias state of a did:webvh document: the DID URL it would
/// list, and whether it lists it for its current location. `None` when the
/// document's `id` is not a did:webvh DID.
pub fn scid_alias_info(document: &Value) -> Option<ScidAliasInfo> {
    let did_url = alias_of(document.get("id")?.as_str()?)?;
    let mine: Vec<&str> = also_known_as(document)
        .iter()
        .filter(|e| names_this_scid(e, &did_url))
        .filter_map(Value::as_str)
        .collect();
    let status = if mine.is_empty() {
        ScidAliasStatus::NotListed
    } else if mine.iter().all(|e| *e == did_url) {
        ScidAliasStatus::Listed
    } else {
        ScidAliasStatus::Stale
    };
    Some(ScidAliasInfo { did_url, status })
}

/// `document` with its did:scid alias listed (`list`) or removed (`!list`) —
/// the `scidAlsoKnownAs` semantics of `vta/webvh/dids/update/1.1`.
///
/// Listing adds [`scid_alias`] of the document's `id` after the entries
/// already there; a did:scid entry of the same SCID with another `src` (or
/// none) is replaced by it in place, never kept beside it. Removing drops
/// every did:scid entry of this SCID, with or without `src`, and leaves every
/// other entry as it was (an emptied `alsoKnownAs` is dropped).
///
/// Returns [`ScidAliasError::NoChange`] rather than an identical document, so
/// a caller never signs an entry that changes nothing.
pub fn with_scid_alias(document: &Value, list: bool) -> Result<Value, ScidAliasError> {
    let alias = document
        .get("id")
        .and_then(Value::as_str)
        .and_then(alias_of)
        .ok_or(ScidAliasError::NotWebvh)?;

    let current = also_known_as(document);
    let mut next: Vec<Value> = Vec::with_capacity(current.len() + 1);
    let mut placed = false;
    for entry in current {
        if !names_this_scid(entry, &alias) {
            next.push(entry.clone());
        } else if list && !placed {
            // The first did:scid entry of this SCID becomes the current alias,
            // where it stood; any further one is a duplicate and goes.
            next.push(Value::String(alias.clone()));
            placed = true;
        }
    }
    if list && !placed {
        next.push(Value::String(alias.clone()));
    }

    if next.as_slice() == current {
        return Err(ScidAliasError::NoChange(if list {
            "the document already lists its did:scid alias for its current location"
        } else {
            "the document does not list a did:scid alias"
        }));
    }

    let mut out = document.clone();
    if let Some(obj) = out.as_object_mut() {
        if next.is_empty() {
            obj.remove("alsoKnownAs");
        } else {
            obj.insert("alsoKnownAs".into(), Value::Array(next));
        }
    }
    Ok(out)
}

/// The `did:webvh` DID of the log that verifies `did`, where it can be told.
///
/// A did:webvh is its own log. A did:scid with a `src` names its log. A bare
/// did:scid names none, so the resolved `document` is consulted: under the
/// native resolution the TDK performs, it lists the did:webvh DID in
/// `alsoKnownAs`; under an older resolver its `id` is the did:webvh DID.
/// The SCID must match either way, or nothing is returned.
pub fn webvh_log_did(did: &str, document: Option<&Value>) -> Option<String> {
    let did = did.split('#').next().unwrap_or(did);
    if did.starts_with("did:webvh:") {
        return Some(did.to_string());
    }
    if !did.starts_with("did:scid:vh:1:") {
        return None;
    }
    if let Some(webvh) = DIDWebVHState::convert_scid_id_to_webvh_id(did) {
        return Some(webvh);
    }
    let scid = did.strip_prefix("did:scid:vh:1:")?;
    let document = document?;
    let candidates = document
        .get("id")
        .into_iter()
        .chain(
            document
                .get("alsoKnownAs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        )
        .filter_map(Value::as_str);
    candidates
        .filter(|c| {
            c.strip_prefix("did:webvh:")
                .and_then(|rest| rest.split(':').next())
                == Some(scid)
        })
        .map(str::to_string)
        .next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn identity_drops_only_the_scid_locator() {
        assert_eq!(
            identity("did:scid:vh:1:Qm1?src=dids.example.org/alice"),
            "did:scid:vh:1:Qm1"
        );
        assert_eq!(
            identity("did:webvh:Qm1:dids.example.org"),
            "did:webvh:Qm1:dids.example.org"
        );
        assert_eq!(identity("did:key:z6Mk"), "did:key:z6Mk");
    }

    #[test]
    fn alias_of_a_hosted_log() {
        assert_eq!(
            scid_alias("did:webvh:Qm1:dids.example.org:alice"),
            "did:scid:vh:1:Qm1?src=dids.example.org/alice"
        );
    }

    const DID: &str = "did:webvh:Qm1:localhost%3A8534:people:alice";
    const ALIAS: &str = "did:scid:vh:1:Qm1?src=localhost%3A8534/people/alice";
    const OLD: &str = "did:scid:vh:1:Qm1?src=old.example/alice";

    fn doc(aka: Option<Value>) -> Value {
        let mut d = json!({ "id": DID, "authentication": ["#key-0"] });
        if let Some(aka) = aka {
            d["alsoKnownAs"] = aka;
        }
        d
    }

    #[test]
    fn listing_appends_the_alias_after_existing_entries() {
        let out = with_scid_alias(&doc(Some(json!(["https://a.example/@alice"]))), true).unwrap();
        assert_eq!(
            out["alsoKnownAs"],
            json!(["https://a.example/@alice", ALIAS])
        );
        // Keeps percent-encoding; derived by the shared `scid_alias`.
        assert_eq!(scid_alias(DID), ALIAS);
        // Everything else untouched.
        assert_eq!(out["authentication"], json!(["#key-0"]));
        // No alsoKnownAs at all.
        let out = with_scid_alias(&doc(None), true).unwrap();
        assert_eq!(out["alsoKnownAs"], json!([ALIAS]));
    }

    #[test]
    fn listing_replaces_a_stale_src_in_place() {
        let d = doc(Some(json!([OLD, "https://a.example/@alice"])));
        assert_eq!(scid_alias_info(&d).unwrap().status, ScidAliasStatus::Stale);
        let out = with_scid_alias(&d, true).unwrap();
        assert_eq!(
            out["alsoKnownAs"],
            json!([ALIAS, "https://a.example/@alice"])
        );
        assert_eq!(
            scid_alias_info(&out).unwrap().status,
            ScidAliasStatus::Listed
        );

        // A bare did:scid and a duplicate are folded into the one current alias.
        let d = doc(Some(json!(["did:scid:vh:1:Qm1", "x:y", ALIAS])));
        assert_eq!(scid_alias_info(&d).unwrap().status, ScidAliasStatus::Stale);
        let out = with_scid_alias(&d, true).unwrap();
        assert_eq!(out["alsoKnownAs"], json!([ALIAS, "x:y"]));
    }

    #[test]
    fn listing_leaves_another_scids_alias_alone() {
        let other = "did:scid:vh:1:Qm2?src=a.example";
        let out = with_scid_alias(&doc(Some(json!([other]))), true).unwrap();
        assert_eq!(out["alsoKnownAs"], json!([other, ALIAS]));
    }

    #[test]
    fn removing_drops_every_entry_of_this_scid_only() {
        let other = "did:scid:vh:1:Qm2?src=a.example";
        let d = doc(Some(json!([
            ALIAS,
            "https://a.example/@alice",
            OLD,
            "did:scid:vh:1:Qm1",
            other
        ])));
        let out = with_scid_alias(&d, false).unwrap();
        assert_eq!(
            out["alsoKnownAs"],
            json!(["https://a.example/@alice", other])
        );
        assert_eq!(
            scid_alias_info(&out).unwrap().status,
            ScidAliasStatus::NotListed
        );

        // An emptied list is dropped.
        let out = with_scid_alias(&doc(Some(json!([ALIAS]))), false).unwrap();
        assert!(out.get("alsoKnownAs").is_none(), "{out}");
    }

    #[test]
    fn nothing_to_change_is_refused() {
        assert!(matches!(
            with_scid_alias(&doc(Some(json!([ALIAS]))), true),
            Err(ScidAliasError::NoChange(_))
        ));
        assert!(matches!(
            with_scid_alias(&doc(None), false),
            Err(ScidAliasError::NoChange(_))
        ));
        assert!(matches!(
            with_scid_alias(&doc(Some(json!(["https://a.example/@alice"]))), false),
            Err(ScidAliasError::NoChange(_))
        ));
    }

    #[test]
    fn only_a_did_webvh_document_has_an_alias() {
        let d = json!({ "id": "did:web:a.example" });
        assert_eq!(with_scid_alias(&d, true), Err(ScidAliasError::NotWebvh));
        assert_eq!(scid_alias_info(&d), None);
        let d = json!({ "id": "did:webvh:Qm1" });
        assert_eq!(with_scid_alias(&d, true), Err(ScidAliasError::NotWebvh));
    }

    #[test]
    fn alias_info_reports_the_current_did_url() {
        let info = scid_alias_info(&doc(Some(json!([ALIAS])))).unwrap();
        assert_eq!(info.did_url, ALIAS);
        assert_eq!(info.status, ScidAliasStatus::Listed);
        assert_eq!(
            serde_json::to_value(&info).unwrap(),
            json!({ "didUrl": ALIAS, "status": "listed" })
        );
        assert_eq!(
            scid_alias_info(&doc(None)).unwrap().status,
            ScidAliasStatus::NotListed
        );
    }

    #[test]
    fn webvh_log_of_each_form() {
        assert_eq!(
            webvh_log_did("did:webvh:Qm1:a.example#key-0", None).as_deref(),
            Some("did:webvh:Qm1:a.example")
        );
        assert_eq!(
            webvh_log_did("did:scid:vh:1:Qm1?src=a.example/x", None).as_deref(),
            Some("did:webvh:Qm1:a.example:x")
        );
        // A bare did:scid: from the native document's alsoKnownAs.
        let native = json!({
            "id": "did:scid:vh:1:Qm1",
            "alsoKnownAs": ["did:scid:vh:1:Qm1?src=a.example", "did:webvh:Qm1:a.example"]
        });
        assert_eq!(
            webvh_log_did("did:scid:vh:1:Qm1", Some(&native)).as_deref(),
            Some("did:webvh:Qm1:a.example")
        );
        // Another SCID's log is not this one's.
        let other =
            json!({ "id": "did:scid:vh:1:Qm1", "alsoKnownAs": ["did:webvh:Qm2:a.example"] });
        assert_eq!(webvh_log_did("did:scid:vh:1:Qm1", Some(&other)), None);
        assert_eq!(webvh_log_did("did:scid:vh:1:Qm1", None), None);
        assert_eq!(webvh_log_did("did:key:z6Mk", None), None);
    }
}
