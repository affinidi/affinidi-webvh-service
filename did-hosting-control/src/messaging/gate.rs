//! The transport-agnostic Trust Task gate: every inbound document, whatever
//! carried it, is admitted, pre-filtered against the ACL, proof-verified,
//! replay-checked and routed here ([`dispatch_trust_task_doc`]).

use super::*;

/// What the HTTPS binding knows about the request a document arrived in,
/// which the document cannot carry: the client address, the headers (a
/// browser's `Origin`, its `User-Agent`) and the body's size. `None` on the
/// messaging transports.
///
/// Read only by a bound-key row's admission and handler (`ProofRule::
/// BoundKey`), which is served over HTTPS alone.
pub(crate) struct HttpsFacts<'a> {
    /// The client address, as `routes::trust_tasks` resolved it; `None` for a
    /// direct call with no socket (tests), which shares one bucket.
    pub ip: Option<std::net::IpAddr>,
    pub headers: &'a axum::http::HeaderMap,
    pub body_len: usize,
}

/// Route one Trust Task document, for **every** transport.
///
/// HTTPS, DIDComm and TSP all arrive here. Each opens its own binding and
/// establishes its own authenticated sender — that is what a binding is for —
/// and then the question "what does this document mean" is answered once, here.
///
/// The order of the checks below is load bearing and each one carries the
/// reason it sits where it does; they are not interchangeable.
///
/// `sender` is the transport's report of who sent the document (empty for an
/// anonymous HTTPS request that names no issuer); `bearer` is the session an
/// HTTPS request presented, when it presented one. Neither authorises anything
/// on its own.
///
/// `large_doc_charge` is what the caller's own `size::check_for_known_issuer`
/// returned, if this document was large enough to need one — settled below,
/// once proof verification concludes, against exactly the address it was
/// charged against.
// One argument per thing a binding knows; a struct here would only rename them.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn dispatch_trust_task_doc(
    state: &AppState,
    sender: &str,
    bearer: Option<&crate::auth::AuthClaims>,
    https: Option<&HttpsFacts<'_>>,
    transport: &(impl trust_tasks_rs::TransportHandler + Sync),
    doc: trust_tasks_rs::TrustTask<Value>,
    verifier: &did_hosting_common::server::trust_tasks::TransportBoundVerifier,
    large_doc_charge: Option<did_hosting_common::server::trust_tasks::size::LargeDocumentCharge>,
) -> Result<RoutedReply, DIDCommServiceError> {
    // Fail closed: a control plane that cannot sign refuses to start (see
    // `signing::require_signing_identity`), and this is the same rule at
    // request time — no trust task is acted on that could not then be
    // answered with a signed reply. There is no unsigned mode.
    let secret = match state
        .config
        .server_did
        .as_deref()
        .ok_or_else(|| "server_did not configured".to_string())
        .and_then(|did| {
            crate::signing::control_signing_secret(state, did).map_err(|e| e.to_string())
        }) {
        Ok(secret) => secret,
        Err(e) => {
            tracing::error!(error = %e, "refusing trust task: this control plane cannot sign its replies");
            return Ok(RoutedReply::Framework(Box::new(
                did_hosting_common::server::trust_tasks::DispatchOutcome::Rejected(
                    doc.reject_with(
                        format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                        trust_tasks_rs::RejectReason::InternalError {
                            reason: "this service cannot sign its replies".into(),
                        },
                    ),
                ),
            )));
        }
    };
    let reply = route_trust_task_doc(
        state,
        sender,
        bearer,
        https,
        transport,
        doc,
        verifier,
        large_doc_charge,
    )
    .await?;
    Ok(seal_reply(state, &secret, sender, reply).await)
}

/// The routing half of [`dispatch_trust_task_doc`]; replies are signed by the
/// caller.
///
/// A pipeline of stages, each a method of [`Gate`] that either hands the next
/// stage what it established or ends the exchange with the refusal it carries:
///
/// 1. a peer's `trust-task-error` is terminal ([`settle_peer_error`]), before
///    anything else;
/// 2. [`Gate::admit`]: the bound-key row's transport and admission, a
///    `did:webs` self-registration's admission, a session ceremony's key kind
///    — all before any proof work;
/// 3. [`Gate::prefilter`]: the ACL pre-filter, and whether the signer is
///    listed;
/// 4. [`Gate::verify`]: the proof, which names the `principal` everything
///    after authorises on, and settles any large-document charge;
/// 5. [`Gate::check_replay`]: the replay gate, in the partition
///    [`replay_partition`] picks;
/// 6. [`Gate::route`]: the auth family, the infrastructure family, the
///    control table, then the framework family.
///
/// The order is load bearing and each stage's doc says why it sits where it
/// does; they are not interchangeable.
// One argument per thing a binding knows; a struct here would only rename them.
#[allow(clippy::too_many_arguments)]
pub(super) async fn route_trust_task_doc(
    state: &AppState,
    sender: &str,
    bearer: Option<&crate::auth::AuthClaims>,
    https: Option<&HttpsFacts<'_>>,
    transport: &(impl trust_tasks_rs::TransportHandler + Sync),
    doc: trust_tasks_rs::TrustTask<Value>,
    verifier: &did_hosting_common::server::trust_tasks::TransportBoundVerifier,
    large_doc_charge: Option<did_hosting_common::server::trust_tasks::size::LargeDocumentCharge>,
) -> Result<RoutedReply, DIDCommServiceError> {
    let my_vid = state
        .config
        .server_did
        .as_deref()
        .ok_or_else(|| DIDCommServiceError::Internal("server_did not configured".into()))?;

    let type_uri = doc.type_uri.to_string();

    // An error is terminal: it is somebody's account of a failure, not a request
    // to act on. Checked before anything else — including the proof gate below,
    // which would otherwise answer an unsigned error with an error of its own,
    // and the peer would do the same with ours. One failure became a permanent
    // exchange between two services politely answering each other's errors
    // once already, and it stopped only when the mediator started
    // rate-limiting.
    //
    // The prefix comes from `vta_sdk::inbound`, not a literal here: which URIs
    // are terminal errors is a fact about the *document*, the same for whoever
    // reads one, and a local copy is a second place for it to drift from.
    if type_uri.starts_with(vta_sdk::inbound::TRUST_TASK_ERROR_PREFIX) {
        settle_peer_error(state, sender, my_vid, verifier, &doc).await;
        return Ok(RoutedReply::Terminal);
    }

    let gate = Gate {
        state,
        sender,
        https,
        verifier,
        my_vid,
        rule: proof_rule(&type_uri),
        type_uri,
    };
    let admitted = match gate.admit(&doc).await {
        Ok(admitted) => admitted,
        Err(refused) => return Ok(refused),
    };
    let listed_signer = match gate.prefilter(&doc, &admitted).await {
        Ok(listed_signer) => listed_signer,
        Err(refused) => return Ok(refused),
    };
    let signed = admitted.signed;
    let self_registering = admitted.self_registering;
    let verified = match gate
        .verify(&doc, admitted, listed_signer, large_doc_charge.as_ref())
        .await
    {
        Ok(verified) => verified,
        Err(refused) => return Ok(refused),
    };
    let replay_cache = match gate.check_replay(
        &doc,
        signed,
        listed_signer,
        self_registering,
        &verified.principal,
    ) {
        Ok(replay_cache) => replay_cache,
        Err(refused) => return Ok(refused),
    };
    let recorded =
        replay_cache.map(|_| (verified.principal.clone(), doc.id.clone(), doc.issued_at));

    let (reply, wrote) = did_hosting_common::server::store::track_writes(Box::pin(
        gate.route(bearer, transport, signed, &verified, doc),
    ))
    .await;

    // A task refused as `unavailable` (over capacity) before it wrote
    // anything did not run, and a refused document can be sent again as a
    // retry: forget its record, or the resend would be refused as a replay.
    // One that attempted a write may have applied part of it, so its record
    // stays and a retry must be a new document.
    if let Some((signer, id, issued_at)) = &recorded
        && let Some(replay_cache) = replay_cache
        && !wrote
        && matches!(&reply, Ok(r) if r.is_unavailable())
    {
        replay_cache.release(signer, id, *issued_at);
    }
    reply
}

/// The refusal of `doc` with `reason`, as the framework answers it.
fn rejected(
    doc: &trust_tasks_rs::TrustTask<Value>,
    reason: impl Into<trust_tasks_rs::ErrorPayload>,
) -> RoutedReply {
    RoutedReply::Framework(Box::new(
        did_hosting_common::server::trust_tasks::DispatchOutcome::Rejected(
            doc.reject_with(format!("urn:uuid:{}", uuid::Uuid::new_v4()), reason),
        ),
    ))
}

/// A peer's `trust-task-error`, which is never answered.
///
/// The reason is logged, not just the fact: a peer's error is often the only
/// account of what went wrong anywhere in the exchange.
///
/// A server's *signed*, non-retryable refusal of an op this control plane sent
/// settles that outbox entry: the target has said it will not apply it, so
/// re-sending would only stall its queue. An unsigned error settles nothing —
/// anyone could send one.
async fn settle_peer_error(
    state: &AppState,
    sender: &str,
    my_vid: &str,
    verifier: &did_hosting_common::server::trust_tasks::TransportBoundVerifier,
    doc: &trust_tasks_rs::TrustTask<Value>,
) {
    use did_hosting_common::server::trust_tasks::verify_sender_bound;

    let code = doc
        .payload
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let message = doc
        .payload
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("");
    warn!(
        sender,
        %code,
        %message,
        "inbound trust-task error from a peer — terminal, not answered"
    );
    let retryable = doc
        .payload
        .get("retryable")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if doc.proof.is_some()
        && !retryable
        && (crate::server_push::is_configured_watcher(state, sender)
            || matches!(
                did_hosting_common::server::acl::get_acl_entry(&state.acl_ks, sender).await,
                Ok(Some(_))
            ))
        && let Ok(signer) = verify_sender_bound(doc, None, Some(sender), my_vid, verifier).await
    {
        crate::messaging::infra::acknowledge_outbox(state, &signer, doc).await;
    }
}

/// The proof gate. Every document that asks this control plane to *do*
/// something — change state, disclose a record, mint a session — must be
/// signed by its issuer, addressed here, and fresh; and the issuer must be
/// the DID the transport reported (`verify_sender_bound`). From
/// [`Gate::verify`] on, `principal` — the proven signer — is the only
/// identity anything authorises on. The transport's `sender` is a routing
/// hint, and a document whose proof disagrees with it is refused rather
/// than resolved in either's favour.
///
/// Each task's `ProofRule` says what its proof must be:
/// - `Optional`: capability discovery, the public `server/info`,
///   opening a passkey login, and the whole `auth/challenge` /
///   `auth/authenticate` / `auth/refresh` family — not because a proof
///   is optional there (several of these require one), but because the
///   ACL pre-filter is the wrong question for a family whose own
///   handlers already decide who may act, on a signer the ACL may
///   legitimately never list (a proxied login's delegate) or has not
///   listed yet (a first login);
/// - `Authentication`: an operational request, `proofPurpose:
///   authentication` under the signer's `authentication` relationship;
/// - `AssertionMethod`: a human approver's decision, an attestation under
///   the approver's `assertionMethod` relationship;
/// - `SessionKey`: a ceremony that mints a session for a key the caller
///   has just generated, signed by that `did:key` — which has no ACL entry
///   of its own; the ceremony names the subject;
/// - `BoundKey(purposes)`: a step of an exchange whose parties are fresh
///   Ed25519 `did:key`s the exchange binds (wallet sign-in). HTTPS only.
///   The row's admission runs first — its size cap, rate limits and, for
///   a browser's step, the origin — before any proof work. Then a proof
///   by exactly the issuer's own key, for one of the row's purposes,
///   verified locally (`verify_bound_key`); no ACL pre-filter (the key is
///   never in the ACL) and no shared replay cache (the row keeps its own,
///   which a stranger cannot fill; see `ProofRule::BoundKey`). The row
///   then checks that the key is the one the exchange recorded.
///
/// A document that carries a proof it was not required to carry is held
/// to the same rule: a proof that is present is verified, never ignored.
///
/// Each stage reads what the binding reported and the document's type and
/// [`ProofRule`] from here, fixed once.
struct Gate<'a, 'h> {
    state: &'a AppState,
    sender: &'a str,
    https: Option<&'a HttpsFacts<'h>>,
    verifier: &'a did_hosting_common::server::trust_tasks::TransportBoundVerifier,
    my_vid: &'a str,
    type_uri: String,
    rule: ProofRule,
}

/// What [`Gate::admit`] established about a document it let through.
struct Admission {
    /// Whether its proof is verified: it is required to carry one, or it
    /// carries one anyway.
    signed: bool,
    /// Whether it is held to the ACL pre-filter.
    needs_acl: bool,
    /// Whether it is a `did:webs` self-registration.
    self_registering: bool,
    /// The self-registration whose proof [`Gate::verify`] checks.
    #[cfg(feature = "method-webs")]
    webs_candidate: Option<crate::webs_self_register::Candidate>,
}

/// What [`Gate::verify`] proved.
struct Verified {
    /// The proven signer (the transport's sender for an unsigned document).
    principal: String,
    /// A self-registration's identifier, which the register row runs as.
    self_certified: Option<crate::webs_self_register::SelfCertifiedWebs>,
}

impl Gate<'_, '_> {
    /// Admission: everything decided before the ACL is read or a proof is
    /// looked at.
    ///
    /// - A bound-key row is served over HTTPS only, and its own admission
    ///   (size cap, rate limits, origin) runs here, before any proof work.
    /// - A `did/register/0.1` from a `did:webs` the ACL does not list, on a
    ///   domain whose operator enabled it (`crate::webs_self_register`), is
    ///   authenticated by the key event log it submits instead of by an ACL
    ///   entry: checked here — before the ACL pre-filter it is exempt from,
    ///   and before any proof work — and its proof is then verified against
    ///   that log's key state in [`Gate::verify`]. Anything else (`None`)
    ///   goes through this gate unchanged.
    /// - A session ceremony is signed by a `did:key` the caller holds: as the
    ///   issuer itself, or — for a session that already exists — as that
    ///   session's delegate key.
    async fn admit(
        &self,
        doc: &trust_tasks_rs::TrustTask<Value>,
    ) -> Result<Admission, RoutedReply> {
        let (sender, type_uri, rule) = (self.sender, self.type_uri.as_str(), self.rule);
        if let ProofRule::BoundKey(_) = rule {
            let Some(https) = self.https else {
                warn!(sender, %type_uri, "trust task refused: a bound-key exchange is served over HTTPS only");
                return Err(rejected(
                    doc,
                    trust_tasks_rs::RejectReason::PermissionDenied {
                        reason: "this task is served over HTTPS only".into(),
                    },
                ));
            };
            if let Err(refused) = crate::control_tasks::admit_bound(self.state, https, doc).await {
                return Err(RoutedReply::Sealed(refused));
            }
        }
        #[cfg(feature = "method-webs")]
        let webs_candidate =
            match crate::webs_self_register::admit(self.state, sender, self.https, type_uri, doc)
                .await
            {
                Ok(candidate) => candidate,
                Err(reason) => return Err(rejected(doc, reason)),
            };
        #[cfg(feature = "method-webs")]
        let self_registering = webs_candidate.is_some();
        #[cfg(not(feature = "method-webs"))]
        let self_registering = false;

        let signed = rule != ProofRule::Optional || doc.proof.is_some();
        let needs_acl = matches!(rule, ProofRule::Authentication | ProofRule::AssertionMethod)
            && !self_registering;
        if rule == ProofRule::SessionKey
            && doc
                .proof
                .as_ref()
                .is_some_and(|p| !p.verification_method.starts_with("did:key:"))
        {
            warn!(sender, %type_uri, "trust task refused: a session ceremony must be signed by a did:key");
            return Err(rejected(
                doc,
                trust_tasks_rs::RejectReason::PermissionDenied {
                    reason:
                        "this ceremony must be signed by the did:key its session will be bound to"
                            .into(),
                },
            ));
        }
        Ok(Admission {
            signed,
            needs_acl,
            self_registering,
            #[cfg(feature = "method-webs")]
            webs_candidate,
        })
    }

    /// The ACL pre-filter, and whether the signer is listed.
    ///
    /// Before any signature work — which can mean resolving a DID over the
    /// network — the reported sender must at least *have* an ACL entry: every
    /// privileged op requires one, so a stranger is turned away for the cost
    /// of a key lookup, and never reaches the resolver or the replay cache.
    /// This is a cheap pre-filter, not the authorisation; the proof still has
    /// to bind the document to that same DID in [`Gate::verify`].
    ///
    /// A configured watcher has no ACL entry: its only standing here is
    /// acknowledging the syncs it was sent, so that — and nothing else — gets
    /// past this pre-filter on its DID.
    ///
    /// Returns whether the signer is one this service has a standing
    /// relationship with: past the pre-filter, or — for a rule without one —
    /// listed in the ACL. The proof binds the proven signer to `sender`, so by
    /// the time the replay cache is chosen this describes the proven signer.
    /// An unlisted signer's proof is verified under the bounds of
    /// `crate::unlisted_signers`, and its record goes into that module's own
    /// replay cache, never the shared one. A failed lookup counts as
    /// unlisted: the stricter of the two.
    async fn prefilter(
        &self,
        doc: &trust_tasks_rs::TrustTask<Value>,
        admitted: &Admission,
    ) -> Result<bool, RoutedReply> {
        let (state, sender, type_uri) = (self.state, self.sender, self.type_uri.as_str());
        let watcher_ack = matches!(
            type_uri,
            MSG_SYNC_UPDATE_ACK | MSG_SYNC_DELETE_ACK | MSG_SYNC_BATCH_ACK
        ) && crate::server_push::is_configured_watcher(state, sender);
        if admitted.needs_acl && !watcher_ack {
            let refusal = match did_hosting_common::server::acl::get_acl_entry(
                &state.acl_ks,
                sender,
            )
            .await
            {
                Ok(Some(_)) => None,
                Ok(None) => {
                    warn!(sender, %type_uri, "trust task refused: sender has no ACL entry");
                    Some(trust_tasks_rs::RejectReason::PermissionDenied {
                        reason: "caller is not present in the maintainer's ACL".into(),
                    })
                }
                // A failed lookup says nothing about the sender: refusing it as
                // "not in the ACL" would read as a revoked grant.
                Err(e) => {
                    warn!(sender, %type_uri, error = %e, "trust task deferred: ACL lookup failed");
                    Some(e.failure_reject_reason())
                }
            };
            if let Some(reason) = refusal {
                return Err(rejected(doc, reason));
            }
        }
        Ok(admitted.needs_acl
            || (admitted.signed
                && matches!(
                    did_hosting_common::server::acl::get_acl_entry(&state.acl_ks, sender).await,
                    Ok(Some(_))
                )))
    }

    /// The proof: the `principal` it proves, which is the only identity
    /// anything after this authorises on.
    ///
    /// - A self-registration's proof is verified against the key state its
    ///   own key event log establishes (never a resolved document).
    /// - An approver's decision is held to `assertionMethod`.
    /// - A bound-key row's proof is by the issuer's own key, verified locally.
    /// - A listed signer, or the delegate of a proxied login whose principal,
    ///   an ACL member, signed the evidence naming it, is verified as members
    ///   are; any other signer under `crate::unlisted_signers`' bounds.
    ///
    /// Any large-document charge is settled against this verification's own
    /// outcome — before a refusal, so a claimed issuer that failed to verify
    /// is penalised exactly as one that verified to someone else. See
    /// `size`'s module docs.
    async fn verify(
        &self,
        doc: &trust_tasks_rs::TrustTask<Value>,
        admitted: Admission,
        listed_signer: bool,
        large_doc_charge: Option<
            &did_hosting_common::server::trust_tasks::size::LargeDocumentCharge,
        >,
    ) -> Result<Verified, RoutedReply> {
        use did_hosting_common::server::trust_tasks::size::settle_large_document_charge;
        use did_hosting_common::server::trust_tasks::{
            verify_bound_key, verify_sender_bound, verify_sender_bound_approval,
        };

        let (state, sender, my_vid, verifier) =
            (self.state, self.sender, self.my_vid, self.verifier);
        let type_uri = self.type_uri.as_str();

        #[cfg(feature = "method-webs")]
        let (self_certified, self_bound) = match admitted.webs_candidate {
            Some(candidate) => match candidate.verify(doc, sender, my_vid).await {
                Ok(webs) => {
                    let did = webs.did().to_string();
                    (Some(webs), Some(Ok(did)))
                }
                Err(e) => (None, Some(Err(e))),
            },
            None => (None, None),
        };
        #[cfg(not(feature = "method-webs"))]
        let (self_certified, self_bound): (
            Option<crate::webs_self_register::SelfCertifiedWebs>,
            Option<Result<String, did_hosting_common::server::trust_tasks::BoundError>>,
        ) = (None, None);

        if !admitted.signed {
            return Ok(Verified {
                principal: sender.to_string(),
                self_certified,
            });
        }
        let bound = match self.rule {
            ProofRule::AssertionMethod => {
                verify_sender_bound_approval(doc, Some(sender), my_vid, verifier).await
            }
            ProofRule::BoundKey(purposes) => match verify_bound_key(doc, purposes).await {
                Ok(issuer) => Ok(issuer),
                Err(e) => {
                    settle_large_document_charge(
                        &state.large_document_budget,
                        large_doc_charge,
                        None,
                    );
                    // Not `sender`: here it is the document's own, unverified
                    // issuer, as long as the caller cares to make it.
                    warn!(%type_uri, error = %e, "trust task refused: not signed by its bound key");
                    return Err(RoutedReply::Sealed(crate::control_tasks::refuse_bound(
                        state, doc, &e,
                    )));
                }
            },
            _ => match self_bound {
                Some(bound) => bound,
                None if listed_signer => {
                    verify_sender_bound(doc, None, Some(sender), my_vid, verifier).await
                }
                // The delegate of a proxied login whose principal, an ACL
                // member, signed the evidence naming it: verified as the
                // member's own requests are.
                None if crate::trust_tasks_auth::vouched_delegate(state, doc).await => {
                    verify_sender_bound(doc, None, Some(sender), my_vid, verifier).await
                }
                None => match state
                    .unlisted_signers
                    .verify(doc, sender, my_vid, verifier)
                    .await
                {
                    Ok(principal) => Ok(principal),
                    Err(Err(e)) => Err(e),
                    Err(Ok(reason)) => {
                        settle_large_document_charge(
                            &state.large_document_budget,
                            large_doc_charge,
                            None,
                        );
                        warn!(sender, %type_uri, "trust task deferred: unlisted signer over its verification bounds");
                        return Err(rejected(doc, reason));
                    }
                },
            },
        };
        settle_large_document_charge(
            &state.large_document_budget,
            large_doc_charge,
            bound.as_ref().ok().map(String::as_str),
        );
        match bound {
            Ok(principal) => Ok(Verified {
                principal,
                self_certified,
            }),
            Err(e) => {
                warn!(sender, %type_uri, error = %e, "trust task refused: not bound to its sender");
                Err(rejected(doc, e.reject_reason()))
            }
        }
    }

    /// The replay gate, keyed on what the proof covers: the proven issuer and
    /// the document id. A captured document re-submitted inside the freshness
    /// window — on any transport, in any framing — is refused as an id
    /// conflict. At its bounds the cache refuses (retryable) rather than
    /// forgetting.
    ///
    /// Which cache, if any, is [`replay_partition`]'s choice: ACL members' go
    /// to the shared one, and nothing a signer the ACL does not list sends can
    /// fill it (see `crate::unlisted_signers`). A record already in another
    /// cache — the signer's ACL entry changed inside the window — is a replay
    /// too. Returns the cache the document was recorded in, if any.
    fn check_replay(
        &self,
        doc: &trust_tasks_rs::TrustTask<Value>,
        signed: bool,
        listed_signer: bool,
        self_registering: bool,
        principal: &str,
    ) -> Result<Option<&did_hosting_common::server::replay::ReplayCache>, RoutedReply> {
        let state = self.state;
        let replay_cache = if signed {
            state.unlisted_signers.cache(
                replay_partition(&self.type_uri, self.rule, listed_signer, self_registering),
                &state.replay_cache,
            )
        } else {
            None
        };
        let Some(cache) = replay_cache else {
            return Ok(None);
        };
        let replayed = state
            .unlisted_signers
            .all(&state.replay_cache)
            .into_iter()
            .filter(|other| !std::ptr::eq(*other, cache))
            .any(|other| other.contains(principal, &doc.id, doc.issued_at));
        let refusal = if replayed {
            Some(did_hosting_common::server::replay::ReplayError::Duplicate.reject_reason())
        } else if std::ptr::eq(cache, &state.unlisted_signers.sign_in)
            && let Err(reason) = state.unlisted_signers.charge_sign_in(match self.https {
                Some(h) => h.ip.map_or_else(
                    || "ip:unknown".to_string(),
                    |ip| format!("ip:{}", state.client_ips.key_of(ip)),
                ),
                None => format!("vid:{}", self.sender),
            })
        {
            Some(reason)
        } else {
            cache
                .check(principal, &doc.id, doc.issued_at)
                .err()
                .map(|e| e.reject_reason())
        };
        if let Some(reason) = refusal {
            warn!(did = %principal, doc_id = %doc.id, type_uri = %self.type_uri, ?reason, "trust task refused: replay cache");
            return Err(rejected(doc, reason));
        }
        Ok(Some(cache))
    }

    /// Routing a document that passed every check above: the auth family, the
    /// infrastructure family, the control plane's own table, and what is left
    /// to the shared framework family (ACL, discovery).
    async fn route(
        &self,
        bearer: Option<&crate::auth::AuthClaims>,
        transport: &(impl trust_tasks_rs::TransportHandler + Sync),
        signed: bool,
        verified: &Verified,
        doc: trust_tasks_rs::TrustTask<Value>,
    ) -> Result<RoutedReply, DIDCommServiceError> {
        use did_hosting_common::server::trust_tasks::TransportBoundVerifier;

        let (state, type_uri) = (self.state, self.type_uri.as_str());
        let principal = verified.principal.as_str();

        // Proofs are verified on every path — there is no configuration under
        // which a proof-bearing document is accepted unverified.
        let policy: trust_tasks_rs::ProofPolicy<'_, TransportBoundVerifier> =
            trust_tasks_rs::ProofPolicy::Verify(self.verifier);

        // Auth (`auth/*`). Neither the control table nor the shared
        // `build_dispatcher` (whose context is the ACL keyspace) carries this
        // family, so it is claimed here, ahead of both; otherwise it would be
        // refused below as `unsupportedType`.
        if crate::trust_tasks_auth::owns(type_uri) {
            return Ok(RoutedReply::Document(
                crate::trust_tasks_auth::dispatch(state, transport, policy, doc)
                    .await
                    .ok_or(DIDCommServiceError::Internal(
                        "auth dispatch produced no reply".into(),
                    ))?,
            ));
        }

        // Control↔server infrastructure ops (server registration, health pong,
        // stats, sync and domain acks). Claimed here for the same reason: neither
        // the control table nor the framework family below carries them.
        if crate::messaging::infra::owns(type_uri) {
            // The dispatcher stays transport-agnostic; we only tell it which binding
            // the document came in on so the registry can record what actually moved.
            let via =
                did_hosting_common::server::didcomm_profile::ObservedTransport::from_binding_uri(
                    transport.binding_uri(),
                );
            return Ok(
                match crate::messaging::infra::dispatch(state, principal, via, doc).await {
                    Some(value) => RoutedReply::Document(value),
                    None => RoutedReply::Terminal,
                },
            );
        }

        // The control plane's own table: DID management, agent names, domains.
        // Every row is typed against its generated request and response.
        //
        // The gate above has verified every proof this document carries, on the
        // document as it arrived. Narrowing it into a generated type can
        // materialise a schema default the signer never wrote (`reserve: false`),
        // which a second verification over the re-serialised document would read
        // as tampering; so the rows do not verify again.
        let doc = match crate::control_tasks::route(
            state,
            bearer,
            verified.self_certified.as_ref(),
            self.https,
            transport,
            trust_tasks_rs::ProofPolicy::<TransportBoundVerifier>::AcceptUnverified,
            doc,
        )
        .await
        {
            Ok(reply) => return Ok(reply),
            Err(unclaimed) => *unclaimed,
        };

        self.route_framework(bearer, transport, signed, principal, policy, doc)
            .await
    }

    /// What is left after the gate's own families: the shared framework
    /// family (ACL, discovery). A Type URI nobody serves is refused there as
    /// `unsupportedType`.
    ///
    /// The framework path is the only one whose outcome carries a reject code
    /// — so it is handed back whole rather than serialised here, and HTTPS
    /// maps it to a status.
    async fn route_framework(
        &self,
        bearer: Option<&crate::auth::AuthClaims>,
        transport: &(impl trust_tasks_rs::TransportHandler + Sync),
        signed: bool,
        principal: &str,
        policy: trust_tasks_rs::ProofPolicy<
            '_,
            did_hosting_common::server::trust_tasks::TransportBoundVerifier,
        >,
        doc: trust_tasks_rs::TrustTask<Value>,
    ) -> Result<RoutedReply, DIDCommServiceError> {
        use did_hosting_common::server::trust_tasks::{
            DispatchOutcome, TransportBoundVerifier, TrustTaskContext, dispatch_inbound,
        };

        let state = self.state;
        let ctx = TrustTaskContext {
            acl_ks: &state.acl_ks,
            acl_locks: &state.acl_locks,
            my_vid: self.my_vid,
            signing_oracle: false,
        };

        // Making a subject an administrator (or a service account) from a
        // session needs that session stepped up, as every other destructive
        // or privilege-raising task does. A request with no bearer session is
        // authorised by its own proof alone and is not affected. Asked only
        // of an administrator, so anybody else still gets the handler's own
        // refusal rather than a step-up that could not help them.
        if signed
            && raises_to_privileged_role(&doc)
            && crate::control_tasks::session_needs_step_up(bearer, principal)
            && matches!(
                did_hosting_common::server::acl::check_acl(&state.acl_ks, principal).await,
                Ok(did_hosting_common::server::acl::Role::Admin)
            )
        {
            return Ok(rejected(
                &doc,
                trust_tasks_rs::ErrorPayload::new(trust_tasks_rs::StandardCode::PermissionDenied)
                    .with_message(
                        did_hosting_common::server::error::AppError::StepUpRequired(String::new())
                            .user_message(),
                    ),
            ));
        }

        // A removed ACL entry takes what it authorised with it. The removal
        // lock is held from before the entry goes until its invites are
        // withdrawn, so no invite redemption (which takes it too) runs in
        // between and recreates the entry. It is taken only for a removal the
        // proven issuer may make (an administrator, or the subject itself), so
        // a doomed one never holds up redemptions; and the gate above has
        // already verified the proof, so the handler is not asked to verify it
        // again (no DID resolution while the lock is held).
        let removal = match acl_entry_removal_subject(&doc) {
            Some(subject) if signed && may_remove_entry(state, principal, &subject).await => {
                Some(subject)
            }
            _ => None,
        };
        let (_removal_guard, policy) = match removal {
            Some(_) => {
                let Ok(guard) = tokio::time::timeout(
                    ACL_REMOVAL_LOCK_WAIT,
                    state
                        .acl_locks
                        .guard(crate::control_tasks::enrol::ACL_REMOVAL_LOCK_KEY),
                )
                .await
                else {
                    warn!(type_uri = %self.type_uri, "acl/revoke deferred: the ACL removal lock is busy");
                    return Ok(rejected(
                        &doc,
                        trust_tasks_rs::ErrorPayload::new(
                            trust_tasks_rs::StandardCode::Unavailable,
                        )
                        .with_message("another ACL change is in progress; retry"),
                    ));
                };
                (
                    Some(guard),
                    trust_tasks_rs::ProofPolicy::<TransportBoundVerifier>::AcceptUnverified,
                )
            }
            // The gate above verified every proof a signed document carries,
            // so the framework handler is not asked to verify it again (a
            // second canonicalisation, signature check and possibly a DID
            // resolution per ACL task), exactly as the witness runs it. An
            // unsigned document (discovery) has nothing to verify either way.
            None if signed => (
                None,
                trust_tasks_rs::ProofPolicy::<TransportBoundVerifier>::AcceptUnverified,
            ),
            None => (None, policy),
        };
        let removes_entry = removal;

        let outcome =
            dispatch_inbound::<TransportBoundVerifier>(&ctx, transport, policy, doc).await;
        if let Some(subject) = removes_entry
            && matches!(outcome, DispatchOutcome::Handled(_))
        {
            withdraw_removed_member(state, &subject).await;
        }
        Ok(RoutedReply::Framework(Box::new(outcome)))
    }
}

/// The subject of `doc` when it is an `acl/revoke` that removes the subject's
/// entry (`revocation.kind: entry`), not one that narrows its act scope.
pub(super) fn acl_entry_removal_subject(doc: &trust_tasks_rs::TrustTask<Value>) -> Option<String> {
    use did_hosting_common::tasks::acl::revoke::v0_2 as revoke;
    use trust_tasks_rs::Payload as _;
    if doc.type_uri.to_string() != revoke::Payload::TYPE_URI {
        return None;
    }
    let kind = doc
        .payload
        .pointer("/revocation/kind")
        .and_then(Value::as_str);
    if kind != Some("entry") {
        return None;
    }
    doc.payload
        .get("subject")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Whether `doc` gives its subject a privileged role: an `acl/grant` of an
/// `admin` or `service` entry, or an `acl/change-role` to one of those. Those
/// roles act across every domain, so granting one from a console session needs
/// it stepped up.
pub(super) fn raises_to_privileged_role(doc: &trust_tasks_rs::TrustTask<Value>) -> bool {
    use did_hosting_common::tasks::acl::{change_role::v0_2 as change_role, grant::v0_2 as grant};
    use trust_tasks_rs::Payload as _;
    let type_uri = doc.type_uri.to_string();
    let role = if type_uri == grant::Payload::TYPE_URI {
        doc.payload.pointer("/entry/role")
    } else if type_uri == change_role::Payload::TYPE_URI {
        doc.payload.get("toRole")
    } else {
        return false;
    };
    matches!(
        role.and_then(Value::as_str)
            .and_then(|r| r.parse::<did_hosting_common::server::acl::Role>().ok()),
        Some(
            did_hosting_common::server::acl::Role::Admin
                | did_hosting_common::server::acl::Role::Service
        )
    )
}

/// The longest an `acl/revoke` waits for the ACL removal lock (R1.2).
pub(super) const ACL_REMOVAL_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Whether `issuer` may remove `subject`'s ACL entry: an administrator, or
/// the subject itself (`acl/revoke` permits self-revocation). The handler
/// decides again under the ACL write lock; this only keeps a removal that is
/// bound to be refused from taking the removal lock.
pub(super) async fn may_remove_entry(state: &AppState, issuer: &str, subject: &str) -> bool {
    did_hosting_common::scid::same_reference(issuer, subject)
        || matches!(
            did_hosting_common::server::acl::check_acl(&state.acl_ks, issuer).await,
            Ok(did_hosting_common::server::acl::Role::Admin)
        )
}

/// End what a removed ACL entry authorised: every session of its subject,
/// and every enrolment invite issued for it or by it, so neither a live session nor a
/// later redemption carries on as the member it no longer is.
///
/// Runs once the removal has committed. A failure here does not undo the
/// removal, which already refuses the subject's next Trust Task; it is logged
/// for the operator, and the sessions it missed end at their own expiry.
pub(crate) async fn withdraw_removed_member(state: &AppState, subject: &str) {
    match did_hosting_common::server::acl_removal::withdraw_removed_member(
        &state.sessions_ks,
        subject,
    )
    .await
    {
        Ok((settled, withdrawn)) => {
            for session_id in &settled.ended {
                if let Err(e) =
                    crate::trust_tasks_auth::delete_auth_proxy_meta(state, session_id).await
                {
                    warn!(session_id = %session_id, error = %e, "ended session's meta row was not removed");
                }
            }
            if !settled.ended.is_empty() || withdrawn > 0 {
                info!(
                    subject = %subject,
                    sessions_ended = settled.ended.len(),
                    invites_withdrawn = withdrawn,
                    "ACL entry removed: the subject's sessions ended and its invites withdrawn"
                );
            }
        }
        Err(e) => {
            error!(
                subject = %subject,
                error = %e,
                "ACL entry removed, but its sessions and invites could not all be withdrawn"
            );
        }
    }
}

/// What [`dispatch_trust_task_doc`] requires of `type_uri`'s proof.
///
/// The control plane's table says for its own rows. Of the rest, capability
/// discovery and the whole auth family (`crate::trust_tasks_auth::owns`:
/// challenge, authenticate, refresh) get `Optional` too — not because their
/// proof is optional (`auth/authenticate`'s is REQUIRED by its own spec, and
/// `signed` below still verifies whichever proof is present), but because the
/// upfront **ACL pre-filter** `needs_acl` gates on is the wrong question for
/// this family. A proxied `auth/authenticate/0.3`'s issuer is a *delegate*
/// that may never itself hold an ACL entry — only the `principal` it
/// authenticates as does — and an ordinary login's own subject, and a
/// refresh's session key, are exactly the identities this family's own arms
/// already authorise (an ACL lookup on the acting party inside
/// `handle_authenticate`, a bound-key check inside `refresh_v2_arm`). Gating
/// on the *signer* holding one first would refuse every proxied login
/// outright, and gating an ordinary first login on an ACL entry that same
/// login is what establishes control of is circular. Every other task — ACL
/// reads included — is privileged, including a Type URI nobody serves, which
/// is then refused as unsupported only once it has been proven.
///
/// The one exception is an `auth/oob/*` version the table does not serve
/// (only the latest of each task is). That family's callers are fresh
/// `did:key`s that are never in the ACL, and a wallet negotiates the version
/// by trying its newest and falling back only on `unsupportedType` (a
/// `permissionDenied` from the pre-filter would end the sign-in instead). So
/// it is `Optional`, and reaches the framework's `unsupportedType`. That says
/// only which versions of an already-public family are served.
pub(crate) fn proof_rule(type_uri: &str) -> ProofRule {
    use trust_tasks_rs::Payload;
    if let Some(rule) = crate::control_tasks::proof_rule(type_uri) {
        return rule;
    }
    if let Some(rule) = crate::messaging::infra::proof_rule(type_uri) {
        return rule;
    }
    if type_uri == trust_tasks_rs::specs::trust_task_discovery::v0_4::Payload::TYPE_URI
        || crate::trust_tasks_auth::owns(type_uri)
        || type_uri.starts_with(OOB_FAMILY_PREFIX)
    {
        return ProofRule::Optional;
    }
    ProofRule::Authentication
}

/// Where a signed `type_uri` document's `(signer, id)` record goes (see
/// [`crate::unlisted_signers`]): nowhere for an open read — `server/info`,
/// capability discovery, an `auth/oob/*` version this service does not serve
/// — or a bound-key row, which keeps its own; the shared cache for a signer
/// the ACL lists (or the gate admitted as a configured watcher); otherwise,
/// for a signer the ACL does not list, the sign-in cache, or the cache for
/// everything else (a `did:webs` self-registration).
pub(crate) fn replay_partition(
    type_uri: &str,
    rule: ProofRule,
    listed_signer: bool,
    self_registering: bool,
) -> crate::unlisted_signers::ReplayPartition {
    use crate::unlisted_signers::ReplayPartition;
    use trust_tasks_rs::Payload;
    let open_read = type_uri
        == did_hosting_common::tasks::did_management::server::info::v0_1::Payload::TYPE_URI
        || type_uri == trust_tasks_rs::specs::trust_task_discovery::v0_4::Payload::TYPE_URI
        || (rule == ProofRule::Optional && type_uri.starts_with(OOB_FAMILY_PREFIX));
    if !rule.uses_shared_replay_cache() || open_read {
        ReplayPartition::None
    } else if listed_signer {
        ReplayPartition::Shared
    } else if self_registering {
        ReplayPartition::Other
    } else {
        ReplayPartition::SignIn
    }
}

/// The `auth/oob/*` family's Type URIs (see [`proof_rule`]).
pub(super) const OOB_FAMILY_PREFIX: &str = "https://trusttasks.org/spec/auth/oob/";

/// Whether a session key bound at login (`auth/authenticate/0.3`, or a passkey
/// login's browser key) may sign `type_uri` for its session's subject.
///
/// Only an ordinary operational request (`ProofRule::Authentication`) may be
/// signed this way, and not the auth family itself. That rules out:
///
/// - an approval (`AssertionMethod`: step-up approve-response). The spec
///   forbids a session key wherever an `assertionMethod` attestation is
///   required (Conformance item 11);
/// - `auth/authenticate` and `auth/refresh`, which would let a session key mint
///   or extend a session past what the subject's own login granted
///   (Conformance item 12). A refresh is authorised by the refresh token, and
///   any proof on it must be the subject's own;
/// - `Optional` and `SessionKey` ceremonies, which are never signed as a
///   session's subject.
pub(crate) fn session_key_may_sign(type_uri: &str) -> bool {
    proof_rule(type_uri) == ProofRule::Authentication && !crate::trust_tasks_auth::owns(type_uri)
}

/// The shared proof verifier, or an error when none is configured — without
/// one no privileged document can be accepted, so dispatch refuses outright.
pub(crate) fn require_verifier(
    state: &AppState,
) -> Result<&did_hosting_common::server::trust_tasks::TransportBoundVerifier, DIDCommServiceError> {
    state.trust_tasks_verifier.as_deref().ok_or_else(|| {
        DIDCommServiceError::Internal(
            "no trust-task proof verifier configured (a DID resolver is required)".into(),
        )
    })
}
