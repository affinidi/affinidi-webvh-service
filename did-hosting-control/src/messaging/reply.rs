//! What a routed Trust Task produced ([`RoutedReply`]) and how a reply is
//! sealed: addressed back to the requester and signed with the operational key.

use super::*;

// ---------------------------------------------------------------------------
// Unified trust-task dispatch (all transports)
// ---------------------------------------------------------------------------

/// What a routed Trust Task produced, before any transport turns it into a
/// reply.
///
/// The variants exist because **HTTPS needs the reject code and the other two
/// transports do not**. SPEC's status table maps a framework rejection onto an
/// HTTP status; DIDComm and TSP have no status to carry, so they serialise the
/// document either way. Flattening to `Option<Value>` here — as this router used
/// to — meant the HTTPS route could not use it and had to re-implement the
/// routing itself, which is how it came to serve a strict subset: the typed
/// `did-hosting/*/1.0` family, the auth family and the infra family were all
/// unreachable over HTTPS, and an agent-name update sent there fell through to a
/// legacy table that has never heard of it and answered "unknown op".
pub(crate) enum RoutedReply {
    /// A framework outcome. Carries the reject code, so HTTPS can map a status.
    ///
    /// Boxed: `DispatchOutcome` is ~750 bytes against a `Value`'s few, and this
    /// enum is returned from every dispatch on every transport.
    Framework(Box<did_hosting_common::server::trust_tasks::DispatchOutcome>),
    /// A reply from a bridged or typed op. There is no framework reject code to
    /// map, and the problem-report shape carries any error, so HTTPS answers
    /// `200` exactly as the other two transports answer with the document.
    Document(Value),
    /// Nothing goes on the wire because the document was itself an answer:
    /// a health pong, a sync or domain acknowledgement, a peer's
    /// `trust-task-error`. The normal end of an exchange, not a failure.
    Terminal,
    /// A reply a bound-key row (`ProofRule::BoundKey`) produced whole: a
    /// success its task signed under its own specification's rule (wallet
    /// sign-in's step 1 and step 2 for `assertionMethod`, and a step 2 whose
    /// signed bytes the member's grant is bound to), or an unsigned
    /// `trust-task-error` in its family's documented shape. [`seal_reply`]
    /// passes it through untouched — re-signing would break exactly that
    /// binding — and HTTPS answers with its status, never cached.
    Sealed(crate::control_tasks::SealedReply),
}

impl RoutedReply {
    /// Whether this is a refusal with the standard `unavailable` code: the
    /// task did not run, and the same document can be sent again.
    pub(crate) fn is_unavailable(&self) -> bool {
        use did_hosting_common::server::trust_tasks::DispatchOutcome;
        const UNAVAILABLE: &str = "unavailable";
        match self {
            RoutedReply::Framework(outcome) => matches!(
                outcome.as_ref(),
                DispatchOutcome::Rejected(err) if err.payload.code.to_string() == UNAVAILABLE
            ),
            RoutedReply::Document(value) => {
                value["payload"]["code"].as_str() == Some(UNAVAILABLE)
                    && value["type"]
                        .as_str()
                        .is_some_and(|t| t.contains("/trust-task-error/"))
            }
            RoutedReply::Terminal | RoutedReply::Sealed(_) => false,
        }
    }

    /// Whether the document was itself an answer, so nothing is sent back
    /// ([`RoutedReply::Terminal`]).
    pub(crate) fn is_terminal(&self) -> bool {
        matches!(self, RoutedReply::Terminal)
    }

    /// The reply document, for a transport with no status codes to carry.
    pub(crate) fn into_document(self) -> Option<Value> {
        use did_hosting_common::server::trust_tasks::DispatchOutcome;
        match self {
            RoutedReply::Framework(outcome) => match *outcome {
                DispatchOutcome::Handled(doc) => {
                    Some(serde_json::to_value(&doc).expect("response document serialises"))
                }
                DispatchOutcome::Rejected(err) => {
                    Some(serde_json::to_value(&err).expect("error document serialises"))
                }
                DispatchOutcome::Suppressed => None,
            },
            RoutedReply::Document(value) => Some(value),
            RoutedReply::Terminal => None,
            RoutedReply::Sealed(sealed) => sealed.into_document(),
        }
    }
}

/// Sign every non-error reply the control plane emits, on every transport.
///
/// A response is a document from this control plane to the requester, and a
/// requester must be able to attribute it by signature, not by the channel it
/// arrived on: `auth/authenticate/0.3` declares a proof REQUIRED and SPEC §7.3
/// item 8 applies that to its response, and clients refuse unsigned non-error
/// replies. So each reply is re-stamped `issuer` = this control plane,
/// `recipient` = the requester (when the request named none), `issuedAt` = now,
/// and signed with the operational key (`proofPurpose: authentication`).
///
/// `trust-task-error` documents stay unsigned, as the framework allows. A
/// control plane that cannot sign does not start, and
/// [`dispatch_trust_task_doc`] refuses every request up front should the key
/// ever be missing at request time.
pub(super) async fn seal_reply(
    state: &AppState,
    secret: &affinidi_tdk::secrets_resolver::secrets::Secret,
    requester: &str,
    reply: RoutedReply,
) -> RoutedReply {
    use did_hosting_common::server::trust_tasks::DispatchOutcome;
    match reply {
        RoutedReply::Framework(outcome) => match *outcome {
            DispatchOutcome::Handled(doc) => RoutedReply::Framework(Box::new(
                DispatchOutcome::Handled(sign_reply_doc(state, secret, requester, doc).await),
            )),
            other => RoutedReply::Framework(Box::new(other)),
        },
        RoutedReply::Document(value) => {
            let is_error = value
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|t| t.starts_with(vta_sdk::inbound::TRUST_TASK_ERROR_PREFIX));
            if is_error {
                return RoutedReply::Document(value);
            }
            match serde_json::from_value::<trust_tasks_rs::TrustTask<Value>>(value.clone()) {
                Ok(doc) => RoutedReply::Document(
                    serde_json::to_value(sign_reply_doc(state, secret, requester, doc).await)
                        .expect("signed reply serialises"),
                ),
                Err(_) => RoutedReply::Document(value),
            }
        }
        RoutedReply::Terminal => RoutedReply::Terminal,
        sealed @ RoutedReply::Sealed(_) => sealed,
    }
}

/// Stamp and sign one reply document. See [`seal_reply`].
///
/// A reply that cannot be signed is replaced by an (unsigned) internal-error
/// document rather than sent unsigned.
pub(crate) async fn sign_reply_doc(
    state: &AppState,
    secret: &affinidi_tdk::secrets_resolver::secrets::Secret,
    requester: &str,
    mut doc: trust_tasks_rs::TrustTask<Value>,
) -> trust_tasks_rs::TrustTask<Value> {
    let my_vid = state.config.server_did.clone().unwrap_or_default();
    doc.issuer = Some(my_vid);
    // An anonymous request (a public read that named no issuer) is answered
    // with no `recipient`.
    if doc.recipient.is_none() && !requester.is_empty() {
        doc.recipient = Some(requester.to_string());
    }
    doc.issued_at = Some(chrono::Utc::now());
    doc.proof = None;
    match did_hosting_common::server::trust_tasks::sign_document(&doc, secret).await {
        Ok(signed) => signed,
        Err(e) => {
            tracing::error!(error = %e, type_uri = %doc.type_uri, "cannot sign trust-task reply; refusing it");
            let mut err = doc.reject_with(
                format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                trust_tasks_rs::RejectReason::InternalError {
                    reason: "this service could not sign its reply".into(),
                },
            );
            // Rejecting a *reply* swaps its parties; address it back to the
            // requester.
            err.issuer = doc.issuer.clone();
            err.recipient = Some(requester.to_string());
            serde_json::from_value(serde_json::to_value(&err).expect("error serialises"))
                .expect("error re-reads as a TrustTask")
        }
    }
}
