//! The largest document each Trust Task type may be, checked before the
//! document is parsed.
//!
//! `POST /api/trust-tasks` used one blanket 64 KiB body limit for every
//! type — generous for an ACL entry or a handful of identifiers, but too
//! small for `did/register`'s payload, which carries a DID's whole
//! `did:webvh` log: every entry it has ever had, each a signed DID
//! document. A log above 64 KiB had no HTTPS route at all.
//!
//! One cap for every type is either too small for the few tasks whose
//! payload is legitimately large or far too large for the many whose
//! payload is a handful of identifiers. The body is attacker-supplied and
//! arrives unauthenticated (proof verification happens later in the
//! pipeline), so the cap is what bounds the parsing this module does
//! before it knows who is asking.
//!
//! So each type declares its own maximum in [`DECLARED`], and every other
//! type takes [`DEFAULT_MAX_DOCUMENT_BYTES`]. A value is raised above the
//! default only where the task's specification needs it, and says why.
//!
//! A declared maximum is **in force only while this deployment serves the
//! type** — the caller passes its own served-type list to [`check`],
//! [`max_document_bytes`] and [`largest_max_document_bytes`]. This service
//! narrows an inbound document's proof (canonicalising the whole document
//! and resolving its signer's DID) before it refuses a type it does not
//! route, so a raised limit on a type nobody serves would buy an
//! unauthenticated caller that much more work for nothing. Until a
//! declared type is dispatched it takes the default like any other.
//!
//! # Before the parse
//!
//! A body no larger than the default is admitted without looking at it:
//! every type accepts that much. A larger body has only its top-level
//! `type` read — a scan that keeps nothing else — and is refused unless
//! that type declares a maximum it fits. Nothing else in it is parsed,
//! validated or verified. The refusal is a framework `trust-task-error`
//! with the standard `malformedRequest` code and the limit under
//! `details.maxBytes`.
//!
//! [`check`] is called from every transport (HTTPS, TSP, DIDComm) before
//! that transport's own `TrustTask<Value>` parse, so the gate is the same
//! regardless of how the document arrived. The HTTPS door additionally
//! caps its request body at [`largest_max_document_bytes`], so no body
//! larger than any served type accepts is ever buffered by that route.

use trust_tasks_rs::{ErrorPayload, ErrorResponse, Payload, RejectReason, TrustTask};

/// Every type not in [`DECLARED`] accepts a document of at most 64 KiB —
/// generous for a handful of identifiers, an ACL entry or a discovery
/// reply, and small enough that an unauthenticated flood of them is cheap
/// to refuse.
pub const DEFAULT_MAX_DOCUMENT_BYTES: usize = 64 * 1024;

/// `did-management/did/register/0.1`: 1 MiB.
///
/// `didData` is the DID's complete `did:webvh` log — every entry it has
/// ever had, each a signed DID document — so it grows with the DID's age
/// and cannot be bounded by its shape. `did/publish/0.1` (spec
/// `supersededBy: did/register`) carries the same log shape, but this
/// service does not route it — #144 retired the route in favour of
/// `did/register`'s owner-update rule, so it takes the default like any
/// other unserved type.
pub const DID_REGISTER_MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// The types that accept more than [`DEFAULT_MAX_DOCUMENT_BYTES`], and how
/// much. Keyed by the full Type URI, so a new version of a task takes the
/// default until it declares its own.
pub const DECLARED: &[(&str, usize)] = &[(
    <trust_tasks_rs::specs::did_management::did::register::v0_1::Payload as Payload>::TYPE_URI,
    DID_REGISTER_MAX_DOCUMENT_BYTES,
)];

/// The `details` member naming the limit a refused document exceeded.
pub const DETAILS_MAX_BYTES: &str = "maxBytes";

/// The largest document any type in `served` accepts — the HTTPS door's
/// body cap. The default while nothing in [`DECLARED`] is served.
pub fn largest_max_document_bytes(served: &[&str]) -> usize {
    largest_in(DECLARED, served)
}

fn largest_in(declared: &[(&str, usize)], served: &[&str]) -> usize {
    declared
        .iter()
        .filter(|(uri, _)| served.contains(uri))
        .map(|(_, max)| *max)
        .fold(DEFAULT_MAX_DOCUMENT_BYTES, usize::max)
}

/// The largest document `type_uri` accepts, in bytes, given the deployment
/// serves the types named in `served`.
pub fn max_document_bytes(type_uri: &str, served: &[&str]) -> usize {
    max_in(type_uri, DECLARED, served)
}

fn max_in(type_uri: &str, declared: &[(&str, usize)], served: &[&str]) -> usize {
    declared
        .iter()
        .find(|(uri, _)| *uri == type_uri && served.contains(uri))
        .map_or(DEFAULT_MAX_DOCUMENT_BYTES, |(_, max)| *max)
}

/// The longest `type` a refusal names. A caller's own `type` is echoed
/// back only when it is short enough to plausibly be a Type URI; anything
/// longer is not one, and repeating it would turn the refusal into an
/// echo of the caller's body.
const MAX_NAMED_TYPE_CHARS: usize = 256;

/// Admit `body`, or refuse it for its size before it is parsed. `served`
/// is the full list of Type URIs this deployment dispatches — the ACL
/// family plus the control plane's task table.
pub fn check(body: &[u8], served: &[&str]) -> Result<(), ErrorResponse> {
    check_with(body, |type_uri| max_document_bytes(type_uri, served))
}

fn check_with(body: &[u8], limit: impl Fn(&str) -> usize) -> Result<(), ErrorResponse> {
    if body.len() <= DEFAULT_MAX_DOCUMENT_BYTES {
        return Ok(());
    }
    let type_uri = peek_type(body);
    let max = type_uri
        .as_deref()
        .map_or(DEFAULT_MAX_DOCUMENT_BYTES, &limit);
    if body.len() <= max {
        return Ok(());
    }
    let named = match type_uri.as_deref() {
        Some(t) if t.chars().count() <= MAX_NAMED_TYPE_CHARS => t,
        Some(_) => "its type",
        None => "a document of no readable type",
    };
    let payload: ErrorPayload = RejectReason::MalformedRequest {
        reason: format!(
            "the document is {} bytes; {named} accepts at most {max}",
            body.len()
        ),
    }
    .into();
    Err(unrouted_error(payload.with_details(
        serde_json::json!({ DETAILS_MAX_BYTES: max }),
    )))
}

/// The document's top-level `type`, read without keeping anything else.
///
/// `None` for a body that is not a JSON object with a string `type` — the
/// derived `Deserialize` ignores every other member (so a full document
/// still reads), but refuses a *duplicate* `type` member as an ambiguous
/// shape rather than picking one. A body that declares nothing readable
/// takes the default limit, as an undeclared type does.
fn peek_type(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct TypeOnly {
        #[serde(rename = "type")]
        type_uri: String,
    }
    serde_json::from_slice::<TypeOnly>(body)
        .ok()
        .map(|t| t.type_uri)
}

/// Build an unrouted `trust-task-error` document for a size refusal.
///
/// There is no source `TrustTask` to draw `issuer`/`recipient`/`threadId`
/// from — the whole point is that the body is refused before it is
/// parsed — so the response is unrouted, exactly as a body-parse failure
/// is (the framework permits this: the producer can correlate on the
/// response `id`).
fn unrouted_error(payload: ErrorPayload) -> ErrorResponse {
    TrustTask {
        id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        thread_id: None,
        parent_thread_id: None,
        ceremony: None,
        type_uri: super::framework_error_type_uri(),
        issuer: None,
        recipient: None,
        issued_at: Some(chrono::Utc::now()),
        expires_at: None,
        payload,
        context: None,
        proof: None,
        extra: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID_REGISTER: &str =
        <trust_tasks_rs::specs::did_management::did::register::v0_1::Payload as Payload>::TYPE_URI;
    const ACL_SHOW: &str = <trust_tasks_rs::specs::acl::show::v0_1::Payload as Payload>::TYPE_URI;

    /// `did/register` as though this deployment served it (the only
    /// caller-relevant fact `max_in`/`largest_in` read from `served`).
    fn served_register(type_uri: &str) -> usize {
        max_in(type_uri, DECLARED, &[DID_REGISTER])
    }

    /// A document of `type_uri` padded to exactly `len` bytes.
    fn document_of(type_uri: &str, len: usize) -> Vec<u8> {
        let head = format!(r#"{{"type":"{type_uri}","payload":{{"pad":""#);
        let tail = r#""}}"#;
        let pad = len - head.len() - tail.len();
        let body = format!("{head}{}{tail}", "x".repeat(pad));
        assert_eq!(body.len(), len);
        body.into_bytes()
    }

    fn refusal(err: ErrorResponse) -> serde_json::Value {
        serde_json::to_value(&err.payload).unwrap()
    }

    #[test]
    fn every_declared_type_is_raised_above_the_default() {
        for (uri, max) in DECLARED {
            assert!(
                *max > DEFAULT_MAX_DOCUMENT_BYTES,
                "{uri} declares {max}, which is not above the default; drop it"
            );
        }
        let mut uris: Vec<&str> = DECLARED.iter().map(|(u, _)| *u).collect();
        uris.sort_unstable();
        uris.dedup();
        assert_eq!(uris.len(), DECLARED.len(), "a type is declared twice");
    }

    #[test]
    fn an_undeclared_type_takes_the_default() {
        assert_eq!(served_register(ACL_SHOW), DEFAULT_MAX_DOCUMENT_BYTES);
        assert_eq!(
            served_register(DID_REGISTER),
            DID_REGISTER_MAX_DOCUMENT_BYTES
        );
    }

    /// A raised limit on a type this deployment does not serve would only
    /// let an unauthenticated caller make the pipeline canonicalise and
    /// verify a larger document before refusing it as unrouted.
    #[test]
    fn a_declared_type_that_is_not_served_takes_the_default() {
        assert_eq!(
            max_in(DID_REGISTER, DECLARED, &[]),
            DEFAULT_MAX_DOCUMENT_BYTES
        );
        assert_eq!(largest_in(DECLARED, &[]), DEFAULT_MAX_DOCUMENT_BYTES);
        assert_eq!(
            largest_in(DECLARED, &[DID_REGISTER]),
            DID_REGISTER_MAX_DOCUMENT_BYTES
        );
        assert_eq!(
            max_document_bytes(DID_REGISTER, &[]),
            DEFAULT_MAX_DOCUMENT_BYTES
        );
        assert_eq!(
            max_document_bytes(DID_REGISTER, &[DID_REGISTER]),
            DID_REGISTER_MAX_DOCUMENT_BYTES
        );
        assert!(largest_max_document_bytes(&[]) >= DEFAULT_MAX_DOCUMENT_BYTES);
    }

    #[test]
    fn a_document_at_its_types_limit_is_admitted() {
        assert!(check(&document_of(ACL_SHOW, DEFAULT_MAX_DOCUMENT_BYTES), &[]).is_ok());
        assert!(
            check_with(
                &document_of(DID_REGISTER, DID_REGISTER_MAX_DOCUMENT_BYTES),
                served_register
            )
            .is_ok()
        );
    }

    #[test]
    fn a_document_over_the_default_is_refused_for_a_type_that_declares_nothing() {
        let err = check(&document_of(ACL_SHOW, DEFAULT_MAX_DOCUMENT_BYTES + 1), &[]).unwrap_err();
        let payload = refusal(err);
        assert_eq!(payload["code"], "malformedRequest");
        assert_eq!(
            payload["details"][DETAILS_MAX_BYTES],
            DEFAULT_MAX_DOCUMENT_BYTES
        );
    }

    #[test]
    fn a_1mib_register_document_is_admitted_and_over_the_limit_is_refused() {
        assert!(
            check(
                &document_of(DID_REGISTER, DID_REGISTER_MAX_DOCUMENT_BYTES),
                &[DID_REGISTER]
            )
            .is_ok()
        );
        let err = check(
            &document_of(DID_REGISTER, DID_REGISTER_MAX_DOCUMENT_BYTES + 1),
            &[DID_REGISTER],
        )
        .unwrap_err();
        let payload = refusal(err);
        assert_eq!(payload["code"], "malformedRequest");
        assert_eq!(
            payload["details"][DETAILS_MAX_BYTES],
            DID_REGISTER_MAX_DOCUMENT_BYTES
        );
    }

    /// A type this deployment does not serve claiming the raised limit
    /// gets only the default, even though it is in `DECLARED`.
    #[test]
    fn an_unserved_type_claiming_a_large_limit_gets_only_the_default() {
        let err = check(
            &document_of(DID_REGISTER, DEFAULT_MAX_DOCUMENT_BYTES + 1),
            &[], // did/register is declared, but not served here.
        )
        .unwrap_err();
        let payload = refusal(err);
        assert_eq!(
            payload["details"][DETAILS_MAX_BYTES],
            DEFAULT_MAX_DOCUMENT_BYTES
        );
    }

    /// The `type` is the top-level one wherever it sits: one placed after
    /// a large member is still the one the limit is looked up by, and a
    /// nested `type` is not it.
    #[test]
    fn the_type_is_the_top_level_one_wherever_it_sits() {
        let pad = "x".repeat(DEFAULT_MAX_DOCUMENT_BYTES);
        let late = format!(
            r#"{{"payload":{{"type":"{ACL_SHOW}","pad":"{pad}"}},"type":"{DID_REGISTER}"}}"#
        );
        assert!(check_with(late.as_bytes(), served_register).is_ok());
        let nested_only = format!(r#"{{"payload":{{"type":"{DID_REGISTER}","pad":"{pad}"}}}}"#);
        assert_eq!(
            refusal(check_with(nested_only.as_bytes(), served_register).unwrap_err())["details"]
                [DETAILS_MAX_BYTES],
            DEFAULT_MAX_DOCUMENT_BYTES
        );
    }

    /// A late `type` — one that appears after a lot of padding rather
    /// than first in the object — is still the one read, because
    /// `serde_json` reads the whole object rather than stopping at the
    /// first member.
    #[test]
    fn a_late_type_in_the_body_is_still_read() {
        let pad = "x".repeat(DEFAULT_MAX_DOCUMENT_BYTES);
        let late = format!(r#"{{"pad":"{pad}","type":"{DID_REGISTER}"}}"#);
        assert!(check_with(late.as_bytes(), served_register).is_ok());
    }

    /// Two top-level `type` members cannot claim the larger limit: the
    /// strict, single-field probe refuses the shape and the body takes
    /// the default.
    #[test]
    fn a_duplicated_type_takes_the_default() {
        let pad = "x".repeat(DEFAULT_MAX_DOCUMENT_BYTES);
        let body = format!(r#"{{"type":"{ACL_SHOW}","type":"{DID_REGISTER}","pad":"{pad}"}}"#);
        assert_eq!(
            refusal(check_with(body.as_bytes(), served_register).unwrap_err())["details"]
                [DETAILS_MAX_BYTES],
            DEFAULT_MAX_DOCUMENT_BYTES
        );
    }

    /// The refusal repeats a caller's `type` only when it could be a Type
    /// URI; an oversized `type` string is not echoed.
    #[test]
    fn a_refusal_does_not_echo_an_oversized_type() {
        let huge = "t".repeat(DEFAULT_MAX_DOCUMENT_BYTES + 1);
        let body = format!(r#"{{"type":"{huge}"}}"#);
        let payload = refusal(check(body.as_bytes(), &[]).unwrap_err());
        let text = payload.to_string();
        assert!(
            text.len() < 1024,
            "the refusal echoes the body: {} bytes",
            text.len()
        );
        assert_eq!(
            payload["details"],
            serde_json::json!({ DETAILS_MAX_BYTES: DEFAULT_MAX_DOCUMENT_BYTES })
        );
    }

    /// An oversized body with no readable `type` cannot claim a raised
    /// limit: it is held to the default, and refused without being
    /// parsed further.
    #[test]
    fn an_oversized_body_with_no_readable_type_takes_the_default() {
        let junk = vec![b'['; DEFAULT_MAX_DOCUMENT_BYTES + 1];
        let payload = refusal(check(&junk, &[]).unwrap_err());
        assert_eq!(payload["code"], "malformedRequest");
        assert_eq!(
            payload["details"][DETAILS_MAX_BYTES],
            DEFAULT_MAX_DOCUMENT_BYTES
        );
    }
}
