//! One router, for every transport.
//!
//! HTTPS, DIDComm and TSP each open their own binding and establish their own
//! authenticated sender — that is what a binding is for — and then hand the
//! document to `messaging::dispatch_trust_task_doc`. What a document *means* is
//! decided once.
//!
//! ## The drift this exists to stop, which already happened
//!
//! The HTTPS route used to re-implement the routing: an `acl`-dispatcher
//! membership check, then a fallthrough to the legacy `dispatch_did_op` bridge.
//! Its comment claimed "parity with the TSP + DIDComm transports", and it had
//! parity with one branch of five — the real router checks the typed
//! `did-hosting/*/1.0` family, the auth family and the infra family *before*
//! that fallthrough.
//!
//! So over HTTPS an agent-name update reached a table of legacy `MSG_*` ops that
//! has never heard of it and came back "unknown op" — the exact failure the
//! router's own comments warn about, reached by the one transport that did not
//! go through it. Nothing failed loudly; the binding simply served less than the
//! other two, and the comment said otherwise.
//!
//! Source-level because the property is about *where* the decision is made. A
//! second router that happens to agree today passes every behavioural test there
//! is, and drifts the moment a family is added to one and not the other — which
//! is precisely how this arose.

use std::fs;
use std::path::Path;

/// Files that take an inbound Trust-Task document off a transport.
const TRANSPORT_ENTRIES: &[(&str, &str)] = &[
    ("src/routes/trust_tasks.rs", "HTTPS"),
    ("src/tsp.rs", "TSP"),
];

#[test]
fn every_transport_routes_through_the_one_dispatcher() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (rel, transport) in TRANSPORT_ENTRIES {
        let src = fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        let production = src.split("#[cfg(test)]").next().unwrap_or(&src);
        assert!(
            production.contains("dispatch_trust_task_doc("),
            "the {transport} entry ({rel}) no longer routes through \
             `messaging::dispatch_trust_task_doc`. Every transport decides what a \
             document means in the same place; a second router agrees with the first \
             until a family is added to one of them."
        );
    }
}

/// The half that actually caught the bug: a transport must not decide, itself,
/// which family a document belongs to. Membership questions belong to the
/// router — it asks them in an order whose reasons are written down there.
#[test]
fn no_transport_asks_which_family_a_document_belongs_to() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for (rel, transport) in TRANSPORT_ENTRIES {
        let src = fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        let production = src.split("#[cfg(test)]").next().unwrap_or(&src);
        for (n, line) in production.lines().enumerate() {
            let decides = line.contains("registered_uris()")
                || line.contains("trust_tasks_did::owns")
                || line.contains("trust_tasks_auth::owns")
                || line.contains("trust_tasks_infra::owns")
                || line.contains("bridge_did_management(");
            if decides {
                offenders.push(format!("{rel}:{}  ({transport})  {}", n + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these transports decide for themselves which family a document belongs \
         to:\n  {}\n\nThat decision is `dispatch_trust_task_doc`'s, and it is made in \
         an order whose reasons live beside it. A transport that asks its own version \
         of the question serves whatever subset it happens to know about — which is \
         how HTTPS came to be missing three families while its comment claimed parity.",
        offenders.join("\n  ")
    );
}
