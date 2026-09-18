//! Which dialect an inbound TSP trust-task frame is in, and how to answer in
//! kind.
//!
//! The Trust Tasks TSP binding carries a document inside an envelope object:
//!
//! ```json
//! { "type": "https://trusttasks.org/binding/tsp/0.1/envelope", "document": { … } }
//! ```
//!
//! This repo never spoke it. Both TSP handlers parsed the payload straight as a
//! `TrustTask<Value>` and returned their reply the same way, and
//! [`send`](super::trust_tasks::send) sealed the bare document too. That agreed
//! with itself and with nothing else — and it is why minting a persona DID
//! failed:
//!
//! ```text
//! # here, on the VTA's request
//! TSP: payload did not parse as TrustTask<Value>
//!   error=type URI path must be /spec/<slug>/<major.minor>:
//!         https://trusttasks.org/binding/tsp/0.1/envelope
//!
//! # at the VTA, on our answer to it
//! refused a TSP frame that is not a binding envelope
//!   (got `https://trusttasks.org/spec/trust-task-error/0.5`)
//! ```
//!
//! Both halves of the round trip were lost: we could not read the envelope, and
//! the error we sent back to say so was itself unreadable. The VTA then waited
//! out its budget for a reply it had already discarded, and the caller saw only
//! "timed out waiting for the TSP reply".
//!
//! The wrap/open pair itself is `vta_sdk::tsp_binding`, not a copy here. Its own
//! module note argues that a binding only one end can see is the private dialect
//! it exists to end, and that the SDK is the leaf both ends already depend on —
//! which is exactly our position, so we take it from there. `trust-tasks-tsp`
//! sits in the workspace manifest but cannot serve: its `pack`/`unpack` do the
//! HPKE sealing too, and the messaging-service framework has already unsealed
//! what reaches our handlers.
//!
//! # Why inbound stays tolerant
//!
//! The SDK refuses a bare document outright, and says why: accepting one "just
//! in case" keeps the dialect alive on the wire for as long as anyone speaks it,
//! and nothing was deployed that needed the kindness. At the VTA that was true.
//! Here it is not — *we* are what is deployed speaking bare, on the control
//! plane's health probes and the edge server's registration, and those peers
//! upgrade one at a time.
//!
//! So inbound accepts either dialect and [`frame`] answers in the one the
//! request arrived in. A conformant peer is understood and answered
//! conformantly; a not-yet-upgraded sibling keeps working unchanged. No flag
//! day in either direction, and the bare arm can be deleted once the fleet is
//! past it.
//!
//! [`send`]: super::trust_tasks::send

use std::borrow::Cow;

/// How an inbound TSP trust-task payload was carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carriage {
    /// A `binding/tsp/0.1` envelope — what a conformant peer sends.
    Envelope,
    /// A bare document: this repo's pre-binding dialect. Accepted during the
    /// fleet migration, answered in kind, and due for removal after it.
    Bare,
}

/// Read an inbound TSP payload, reporting the document bytes and the dialect
/// they arrived in.
///
/// A payload that does not open as an envelope is handed back untouched as
/// [`Carriage::Bare`] rather than refused — the caller parses it and reports
/// the parse failure, so a genuinely malformed frame is still diagnosed, just
/// against the document it claims to be.
#[must_use]
pub fn open(payload: &[u8]) -> (Cow<'_, [u8]>, Carriage) {
    match vta_sdk::tsp_binding::open_envelope(payload) {
        Ok(document) => (Cow::Owned(document), Carriage::Envelope),
        Err(_) => (Cow::Borrowed(payload), Carriage::Bare),
    }
}

/// Frame an outbound trust-task document for the carriage it answers.
///
/// Replying in the dialect the request arrived in is what keeps this tolerant:
/// wrapping a legacy peer's answer would break it just as surely as sending a
/// conformant peer a bare one.
#[must_use]
pub fn frame(document: Vec<u8>, carriage: Carriage) -> Vec<u8> {
    match carriage {
        Carriage::Envelope => vta_sdk::tsp_binding::wrap_envelope(&document),
        Carriage::Bare => document,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &[u8] = br#"{"id":"urn:uuid:1","type":"https://trusttasks.org/spec/messaging/ping/0.1","payload":{}}"#;

    /// The VTA's frame — the one that used to fail to parse here at all.
    #[test]
    fn an_envelope_is_opened_to_the_document_it_carries() {
        let wire = vta_sdk::tsp_binding::wrap_envelope(DOC);
        let (document, carriage) = open(&wire);
        assert_eq!(carriage, Carriage::Envelope);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&document).unwrap(),
            serde_json::from_slice::<serde_json::Value>(DOC).unwrap(),
        );
    }

    /// A not-yet-upgraded sibling's frame still reads, untouched.
    #[test]
    fn a_bare_document_is_passed_through_as_bare() {
        let (document, carriage) = open(DOC);
        assert_eq!(carriage, Carriage::Bare);
        assert_eq!(&*document, DOC);
    }

    /// The property the whole migration rests on: an answer goes back in the
    /// dialect the request came in, so neither kind of peer is broken.
    #[test]
    fn a_reply_is_framed_the_way_the_request_arrived() {
        let wrapped = frame(DOC.to_vec(), Carriage::Envelope);
        assert_ne!(wrapped, DOC, "an envelope reply is wrapped");
        // …and it is an envelope the other end can open, carrying our document.
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &vta_sdk::tsp_binding::open_envelope(&wrapped).unwrap()
            )
            .unwrap(),
            serde_json::from_slice::<serde_json::Value>(DOC).unwrap(),
        );
        assert_eq!(frame(DOC.to_vec(), Carriage::Bare), DOC, "bare stays bare");
    }

    /// Opening is value-preserving, and **only** value-preserving:
    /// `open_envelope` re-serialises the carried value, so the bytes that come
    /// back need not be the bytes that went in. Whether key order survives is
    /// not even a fixed property — it depends on whether anything in the build
    /// turns on `serde_json/preserve_order`, which Cargo unifies across the
    /// workspace, so this crate's own test binary and the workspace build can
    /// legitimately disagree. Hence the assertion is on the value alone.
    ///
    /// Stated here because it looks alarming next to the SDK's warning that a
    /// wrapper "must not reshape the document — the proof is taken over the
    /// document". Nothing here verifies a proof over these bytes: the document
    /// is parsed into a `TrustTask<Value>` and the framework canonicalises
    /// (JCS) before checking any proof, so byte order is not load-bearing. It
    /// is also the exact path the VTA's own receiver takes through the same SDK
    /// function, against proofs that verify in production.
    #[test]
    fn opening_preserves_the_value() {
        let opened = vta_sdk::tsp_binding::open_envelope(&frame(DOC.to_vec(), Carriage::Envelope))
            .expect("opens");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&opened).unwrap(),
            serde_json::from_slice::<serde_json::Value>(DOC).unwrap(),
        );
    }

    /// Garbage is not silently claimed as an envelope; it falls through to the
    /// caller's parse, which is what reports it.
    #[test]
    fn a_non_json_payload_falls_through_to_the_caller() {
        let (document, carriage) = open(b"not json at all");
        assert_eq!(carriage, Carriage::Bare);
        assert_eq!(&*document, b"not json at all");
    }
}
