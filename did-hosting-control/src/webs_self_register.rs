//! `did:webs` self-registration: a `did/register/0.1` from a `did:webs` that
//! is not in the ACL, accepted because the key event log it submits proves
//! control of the identifier it registers.
//!
//! ## Why a `did:webs` needs this
//!
//! A `did:webs` does not exist until a host publishes it, and every other
//! caller authenticates here as a DID this service resolves and finds in its
//! ACL. A node whose own durable identity is to be a `did:webs` therefore has
//! nothing to authenticate as before its first publication. But it does not
//! need anything: a `did:webs` is self-certifying. Its AID is the digest of its
//! inception event, which names the keys that control it, and the slot builds
//! the identifier (`did:webs:{domain}:{path}:{AID}`). A request document signed
//! by a key that the submitted key event log establishes as that identifier's
//! current signing key is signed by the identifier's controller — there is no
//! one else it could be.
//!
//! ## The rule
//!
//! Only a `did/register/0.1` whose `issuer` is a `did:webs` with **no ACL
//! entry** takes this path ([`admit`]); a `did:webs` the ACL already lists, and
//! every other DID and task, takes the ordinary one unchanged. Then, in order:
//!
//! 1. the target domain's operator has enabled it
//!    (`[[hosting.webs_self_register]]`), and the path is under one of the
//!    domain's `path_prefixes`, when it lists any. No domain is enabled by
//!    default, and with none enabled the document is refused exactly as any
//!    caller outside the ACL is;
//! 2. the payload registers `did:webs` — `method: "webs"`, a named `domain`,
//!    and no `force` (only an administrator takes over a slot). A `did:webvh`
//!    is never registered this way: its log is verified by its own update
//!    keys, but nothing ties a `did:webvh` that does not resolve yet to the
//!    caller in the way an AID ties a `did:webs` to its inception keys;
//! 3. the `issuer` is exactly the identifier the slot builds
//!    ([`Webs::slot_did`]) — the same function the write path builds it with;
//! 4. a per-source rate limit
//!    ([`crate::rate_limit::webs_self_register_limiter`]) and one shared by
//!    every source ([`crate::rate_limit::webs_self_register_global_limiter`]),
//!    before the work a stranger can otherwise ask for. A source on TSP or
//!    DIDComm is its sender, and a sender can be a fresh `did:key` each time,
//!    so only the shared bucket bounds the whole;
//! 5. the submitted `keri.cesr` verifies in full — the same
//!    [`Webs::verified_document`] the write path and every resolver use —
//!    and establishes that identifier's AID;
//! 6. the document is sender-bound exactly as every privileged document is
//!    ([`verify_sender_bound`]: issuer, transport sender, recipient,
//!    freshness, `proofPurpose: authentication`), with one difference: its
//!    proof is checked against the document the verified key event log
//!    implies, **not** one resolved over the network. The DID does not
//!    resolve yet, and it is that log, not whatever a network fetch returns,
//!    that this service is about to publish. The resolver that does it
//!    ([`OneDocument`]) answers for that one identifier and nothing else, so no
//!    verification method can send it to the network.
//!
//! What passes is a [`SelfCertifiedWebs`], constructible only by
//! [`Candidate::verify`]. The register row then runs as that identifier, an
//! `Owner` with no ACL entry, one self-registration on the domain at a time
//! ([`SelfCertifiedWebs::reserve`]): it refuses a domain already holding its
//! `max_registrations`, then `register_did_atomic` verifies the log again,
//! refuses a slot owned by anyone else, and commits. Only after the commit does
//! the row give the identifier an ACL entry ([`SelfCertifiedWebs::
//! grant_owner_entry`]), so that its later publications — key rotations — take
//! the ordinary owner path, authenticated by resolving the published
//! identifier from this host.

#[cfg(feature = "method-webs")]
use std::sync::Arc;

#[cfg(feature = "method-webs")]
use serde_json::Value;
use tracing::info;
#[cfg(feature = "method-webs")]
use tracing::warn;
use trust_tasks_rs::Payload as _;
#[cfg(feature = "method-webs")]
use trust_tasks_rs::{RejectReason, TrustTask};

use did_hosting_common::did_ops::DidRecord;
use did_hosting_common::server::acl::{AclEntry, Role, get_acl_entry, store_acl_entry};
use did_hosting_common::server::domain::DomainScope;
use did_hosting_common::tasks::did_management::did::register;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;

/// The one Type URI this path serves.
pub(crate) const SELF_REGISTER_TYPE_URI: &str = register::v0_1::Payload::TYPE_URI;

/// The `amr` a self-certified registration carries: the key event log, not a
/// login, is what authenticated it.
const AMR: &str = "keri";

/// The label of the owner entry a self-registration grants, by which
/// [`SelfCertifiedWebs::reserve`] counts a domain's self-registered slots.
pub(crate) const SELF_REGISTERED_LABEL: &str = "self-registered did:webs";

/// A `did:webs` outside the ACL that proved control of itself: its
/// `did/register/0.1` verified against the key state its own submitted key
/// event log establishes. Built only by [`Candidate::verify`].
#[derive(Debug)]
pub(crate) struct SelfCertifiedWebs {
    did: String,
    /// The `domain` exactly as the payload named it — what the row hands
    /// `register_did_atomic`, so both build the same identifier.
    domain: String,
    path: String,
    /// What the transport vouched for (`ip:…` or `vid:…`), for the audit
    /// record.
    source: String,
    /// The domain's `max_registrations`.
    max_registrations: u32,
}

impl SelfCertifiedWebs {
    /// The `did:webs` that proved control of itself.
    #[cfg(feature = "method-webs")]
    pub(crate) fn did(&self) -> &str {
        &self.did
    }

    /// The identifier, which the row registers as: an owner with no ACL
    /// entry, at the base assurance level.
    pub(crate) fn claims(&self) -> AuthClaims {
        AuthClaims {
            did: self.did.clone(),
            role: Role::Owner,
            session_id: String::new(),
            session_pubkey_b58btc: None,
            amr: vec![AMR.to_string()],
            acr: "aal1".to_string(),
        }
    }

    /// Refuse a payload that is not the one the gate verified. The row reads
    /// the same document, so this holds unless the routing between them is
    /// broken — and then nothing is written.
    pub(crate) fn matches(
        &self,
        path: &str,
        domain: Option<&str>,
        method: &str,
        force: bool,
    ) -> Result<(), AppError> {
        if path != self.path || domain != Some(self.domain.as_str()) || method != "webs" || force {
            return Err(AppError::Internal(
                "a self-registration reached the register row with a payload the gate did not \
                 verify"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Hold this domain's self-registration lock for the rest of the row, and
    /// refuse when the domain already holds its `max_registrations`
    /// self-registered identifiers. Held across the count, the commit and the
    /// grant, so concurrent self-registrations on one domain cannot each see
    /// room for one more (per process: see `max_registrations`).
    pub(crate) async fn reserve(
        &self,
        state: &AppState,
    ) -> Result<did_hosting_common::server::path_locks::PathGuard, AppError> {
        use did_hosting_common::server::acl::list_acl_entries;
        use did_hosting_common::server::domain::normalize_domain_name;

        let canonical = normalize_domain_name(&self.domain).unwrap_or_else(|_| self.domain.clone());
        let guard = state
            .acl_locks
            .guard(&format!("webs-self-register:{canonical}"))
            .await;
        let held = list_acl_entries(&state.acl_ks)
            .await?
            .into_iter()
            .filter(|e| e.label.as_deref() == Some(SELF_REGISTERED_LABEL) && e.did != self.did)
            .filter(|e| match &e.domains {
                DomainScope::Allowed { domains } => domains
                    .iter()
                    .any(|d| normalize_domain_name(d).ok().as_deref() == Some(canonical.as_str())),
                _ => false,
            })
            .count();
        if held >= self.max_registrations as usize {
            tracing::warn!(
                target: "audit",
                event = "did.webs.self_register_refused",
                did = %self.did,
                domain = %self.domain,
                source = %self.source,
                held,
                max = self.max_registrations,
                "did:webs self-registration refused: the domain holds its maximum"
            );
            return Err(AppError::QuotaExceeded(format!(
                "domain `{}` already holds its {} self-registered did:webs identifiers \
                 (`max_registrations`); an administrator registers this one, or raises the limit",
                self.domain, self.max_registrations
            )));
        }
        Ok(guard)
    }

    /// Give the newly registered identifier an `Owner` ACL entry, scoped to
    /// its domain and to the one slot it holds (`max_did_count = 1`), so that
    /// its later publications take the ordinary owner path. Left alone when
    /// it has an entry already (an administrator's, or one an earlier attempt
    /// granted). Audited either way.
    pub(crate) async fn grant_owner_entry(
        &self,
        state: &AppState,
        record: &DidRecord,
    ) -> Result<(), AppError> {
        // The record's identifier is the one the write path built; it must be
        // the one the proof was checked against.
        if record.did_id.as_deref() != Some(self.did.as_str()) || record.owner != self.did {
            return Err(AppError::Internal(format!(
                "self-registered slot {} records {:?} owned by {}, not {}",
                record.mnemonic, record.did_id, record.owner, self.did
            )));
        }
        // Serialised with every other ACL write, so an administrator's
        // concurrent grant is never overwritten by this one.
        let _guard = state
            .acl_locks
            .guard(did_hosting_common::server::trust_tasks::ACL_WRITE_LOCK_KEY)
            .await;
        let granted = if get_acl_entry(&state.acl_ks, &self.did).await?.is_none() {
            store_acl_entry(
                &state.acl_ks,
                &AclEntry {
                    did: self.did.clone(),
                    role: Role::Owner,
                    label: Some(SELF_REGISTERED_LABEL.into()),
                    created_at: did_hosting_common::server::auth::session::now_epoch(),
                    max_total_size: None,
                    max_did_count: Some(1),
                    domains: DomainScope::Allowed {
                        domains: vec![record.domain.clone()],
                    },
                },
            )
            .await?;
            true
        } else {
            false
        };
        info!(
            target: "audit",
            event = "did.webs.self_registered",
            did = %self.did,
            path = %record.mnemonic,
            domain = %record.domain,
            source = %self.source,
            version = record.version_count,
            acl_granted = granted,
            "did:webs registered itself, authenticated by its own key event log"
        );
        Ok(())
    }
}

/// A self-registration that has passed every check but the proof: the key
/// event log verified, and the identifier it establishes is the issuer's.
/// [`Candidate::verify`] checks the document's proof against it.
#[cfg(feature = "method-webs")]
pub(crate) struct Candidate {
    did: String,
    domain: String,
    path: String,
    source: String,
    max_registrations: u32,
    document: affinidi_did_common::Document,
}

#[cfg(feature = "method-webs")]
impl Candidate {
    /// Hold `doc` to the sender-bound rule every privileged document is held
    /// to, with its proof verified against the key state the submitted key
    /// event log establishes rather than a resolved document.
    pub(crate) async fn verify(
        self,
        doc: &TrustTask<Value>,
        sender: &str,
        my_vid: &str,
    ) -> Result<SelfCertifiedWebs, did_hosting_common::server::trust_tasks::BoundError> {
        use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
        use did_hosting_common::server::trust_tasks::{
            BoundError, TransportBoundVerifier, verify_sender_bound,
        };
        use trust_tasks_rs::VerificationError;

        // A cache holding this one document, so the library's own
        // relationship check (listed under `authentication`, controlled by
        // the DID that names it) and key decoding decide the key — the same
        // code every other proof here goes through.
        let mut client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .map_err(|e| {
                BoundError::Proof(VerificationError::Other(format!(
                    "could not hold the derived did:webs document: {e}"
                )))
            })?;
        client.add_did_document(&self.did, self.document).await;
        let verifier = TransportBoundVerifier::with_resolver(Arc::new(OneDocument {
            did: self.did.clone(),
            decode: trust_tasks_proof::affinidi::CachedDidResolver::new(Arc::new(client)),
        }));
        let proven =
            verify_sender_bound(doc, Some(&self.did), Some(sender), my_vid, &verifier).await?;
        if proven != self.did {
            return Err(BoundError::UnexpectedIssuer {
                issuer: proven,
                expected: self.did,
            });
        }
        Ok(SelfCertifiedWebs {
            did: self.did,
            domain: self.domain,
            path: self.path,
            source: self.source,
            max_registrations: self.max_registrations,
        })
    }
}

/// Resolves verification methods of exactly one identifier, from the document
/// its verified key event log implies. Any other DID is refused here, before
/// the cache could treat it as a miss and resolve it over the network.
#[cfg(feature = "method-webs")]
struct OneDocument {
    did: String,
    decode: trust_tasks_proof::affinidi::CachedDidResolver,
}

#[cfg(feature = "method-webs")]
#[async_trait::async_trait]
impl trust_tasks_proof::affinidi::ProofPurposeResolver for OneDocument {
    async fn resolve_vm_for_purpose(
        &self,
        vm: &str,
        purpose: trust_tasks_proof::affinidi::ProofPurpose,
    ) -> Result<affinidi_data_integrity::ResolvedKey, affinidi_data_integrity::DataIntegrityError>
    {
        if did_hosting_common::server::trust_tasks::verifier::controller_did(vm) != self.did {
            return Err(affinidi_data_integrity::DataIntegrityError::Resolver(
                "the proof's verificationMethod is not a key of the did:webs being registered"
                    .into(),
            ));
        }
        self.decode.resolve_vm_for_purpose(vm, purpose).await
    }
}

/// Decide whether `doc` is a self-registration, and run every check on it
/// short of its proof.
///
/// `Ok(None)`: it is not one — another task, an issuer that is not a
/// `did:webs`, a `did:webs` the ACL lists (or whose entry could not be read),
/// or no domain enabled at all — and the ordinary gate handles it unchanged.
/// `Err`: it is one, and is refused. `Ok(Some)`: verify its proof with
/// [`Candidate::verify`].
#[cfg(feature = "method-webs")]
pub(crate) async fn admit(
    state: &AppState,
    sender: &str,
    https: Option<&crate::messaging::HttpsFacts<'_>>,
    type_uri: &str,
    doc: &TrustTask<Value>,
) -> Result<Option<Candidate>, RejectReason> {
    use did_hosting_common::method::webs::Webs;
    use did_hosting_common::server::domain::normalize_domain_name;

    let enabled = &state.config.hosting.webs_self_register;
    if type_uri != SELF_REGISTER_TYPE_URI || enabled.is_empty() {
        return Ok(None);
    }
    let Some(issuer) = doc.issuer.as_deref().filter(|i| i.starts_with("did:webs:")) else {
        return Ok(None);
    };
    match get_acl_entry(&state.acl_ks, issuer).await {
        Ok(None) => {}
        // Listed: the ordinary path. Unreadable: the ordinary path too, whose
        // own lookup reports the failure as what it is.
        Ok(Some(_)) | Err(_) => return Ok(None),
    }

    let denied = |reason: String| {
        warn!(%issuer, %reason, "did:webs self-registration refused");
        RejectReason::PermissionDenied { reason }
    };

    let p: register::v0_1::Payload = serde_json::from_value(doc.payload.clone()).map_err(|e| {
        RejectReason::MalformedRequest {
            reason: format!("invalid register payload: {e}"),
        }
    })?;
    let domain = p.domain.as_deref().map(|d| d.to_string()).ok_or_else(|| {
        denied(
            "caller is not present in the maintainer's ACL, and a did:webs registers itself only \
             on a domain it names (`domain`)"
                .into(),
        )
    })?;
    let canonical = normalize_domain_name(&domain).ok();
    let Some(policy) = enabled
        .iter()
        .find(|e| canonical.is_some() && normalize_domain_name(&e.domain).ok() == canonical)
    else {
        return Err(denied(format!(
            "caller is not present in the maintainer's ACL, and domain `{domain}` does not accept \
             self-registered did:webs identifiers"
        )));
    };
    let path = p.path.as_str().to_string();
    if !policy.admits_path(&path) {
        return Err(denied(format!(
            "domain `{domain}` accepts self-registered did:webs identifiers only under {:?}",
            policy.path_prefixes
        )));
    }
    if p.force {
        return Err(denied(
            "a self-registration may not force: only an administrator takes over a slot".into(),
        ));
    }
    let (method, did_data) =
        crate::control_tasks::did::register_method_and_data(&p).map_err(|e| {
            RejectReason::MalformedRequest {
                reason: e.to_string(),
            }
        })?;
    if method != "webs" {
        return Err(denied(format!(
            "self-registration is for did:webs only, authenticated by its key event log; \
             method `{method}` is registered by a caller in the maintainer's ACL"
        )));
    }
    let slot_did = Webs::slot_did(&domain, &path);
    if issuer != slot_did {
        return Err(denied(format!(
            "a self-registering did:webs must issue its own registration: this slot builds \
             `{slot_did}`, not `{issuer}`"
        )));
    }

    // Everything above was a cheap read of the document. What follows
    // verifies a key event log a stranger chose, so it is counted first.
    let source = match https {
        Some(facts) => facts
            .ip
            .map_or_else(|| "ip:unknown".to_string(), |ip| format!("ip:{ip}")),
        None => format!("vid:{sender}"),
    };
    // Per source, then all sources together: a sender on TSP or DIDComm can
    // be a new `did:key` every time, so only the shared bucket bounds what
    // strangers together can make this verify.
    for limited in [
        state.webs_self_register_limiter.try_consume(source.clone()),
        state
            .webs_self_register_global_limiter
            .try_consume(crate::rate_limit::WEBS_SELF_REGISTER_GLOBAL_KEY.to_string()),
    ] {
        if let Err(AppError::RateLimited {
            retry_after_secs, ..
        }) = limited
        {
            warn!(%issuer, %source, "did:webs self-registration refused: rate limited");
            return Err(RejectReason::Unavailable {
                retry_after: Some(
                    chrono::Utc::now() + chrono::Duration::seconds(retry_after_secs as i64),
                ),
            });
        }
    }

    let document = Webs::verified_document(&slot_did, &did_data).map_err(|e| {
        warn!(%issuer, error = %e, "did:webs self-registration refused: key event log");
        RejectReason::ProofInvalid {
            reason: format!(
                "the submitted keri.cesr does not verify, so it establishes no key to check this \
                 registration's proof against: {e}"
            ),
        }
    })?;
    Ok(Some(Candidate {
        did: slot_did,
        domain,
        path,
        source,
        max_registrations: policy.max_registrations,
        document,
    }))
}

#[cfg(test)]
mod tests {
    //! Self-registration end to end, through each transport's own entry point
    //! and the one gate they share. Every identifier is a real `did:webs`,
    //! incepted here, and every request is signed as its key.

    use std::sync::Arc;

    use affinidi_keri::config::InceptionConfig;
    use affinidi_keri::hab::Hab;
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use serde_json::{Value, json};

    use did_hosting_common::did_ops::{DidRecord, did_key};
    use did_hosting_common::server::acl::{Role, get_acl_entry};
    use did_hosting_common::server::config::WebsSelfRegistration;
    #[cfg(feature = "method-webs")]
    use did_hosting_common::server::domain::DomainScope;

    use crate::control_tasks::harness::*;
    use crate::server::AppState;

    use super::SELF_REGISTER_TYPE_URI as REGISTER;

    /// The hosting domain every test registers under.
    const DOMAIN: &str = "control.test";

    /// A `did:webs` controller: its inception event and current signing key.
    struct Webs {
        aid: String,
        kel: String,
        /// The key's CESR encoding: its verification method's fragment.
        key_qb64: String,
        seed: Vec<u8>,
    }

    impl Webs {
        /// Incept an identifier, deterministically from `salt`.
        fn incept(salt: u8) -> Self {
            let config = InceptionConfig {
                salt: Some(vec![salt; 16]),
                ..InceptionConfig::default()
            };
            let (hab, inception) = Hab::incept_event("did:webs", &config).expect("incept");
            let signer = &hab.signers()[0];
            Webs {
                aid: hab.prefix().to_string(),
                kel: String::from_utf8(inception.composed).expect("CESR is text"),
                key_qb64: signer.verfer().qb64().expect("key qb64"),
                seed: signer.raw().to_vec(),
            }
        }

        /// The identifier at `path` (`/`-separated, without the AID).
        fn did_at(&self, path: &str) -> String {
            let slot = self.slot(path);
            format!("did:webs:{DOMAIN}:{}", slot.replace('/', ":"))
        }

        fn slot(&self, path: &str) -> String {
            if path.is_empty() {
                self.aid.clone()
            } else {
                format!("{path}/{}", self.aid)
            }
        }

        /// This identifier's signing key, as a verification method of `did`.
        fn key_for(&self, did: &str) -> Secret {
            let seed: [u8; 32] = self.seed.as_slice().try_into().expect("Ed25519 seed");
            let mut secret = Secret::generate_ed25519(None, Some(&seed));
            secret.id = format!("{did}#{}", self.key_qb64);
            secret
        }

        /// A caller whose DID is this identifier at `path`.
        fn caller(&self, path: &str) -> Caller {
            let did = self.did_at(path);
            Caller {
                key: self.key_for(&did),
                did,
                role: Role::Owner,
            }
        }

        fn payload(&self, path: &str) -> Value {
            json!({
                "path": self.slot(path),
                "method": "webs",
                "didData": self.kel,
                "force": false,
                "domain": DOMAIN,
            })
        }
    }

    /// A control plane on which `DOMAIN` accepts self-registration, under
    /// `prefixes` when any are given.
    #[cfg(feature = "method-webs")]
    async fn enabled(prefixes: &[&str]) -> (AppState, tempfile::TempDir) {
        let (mut state, dir) = state().await;
        let mut config = (*state.config).clone();
        config.hosting.webs_self_register = vec![WebsSelfRegistration {
            domain: DOMAIN.into(),
            path_prefixes: prefixes.iter().map(|p| p.to_string()).collect(),
            ..Default::default()
        }];
        state.config = Arc::new(config);
        (state, dir)
    }

    /// `payload` signed by `caller`'s key and sent from it over `via`.
    async fn register_as(state: &AppState, via: Via, caller: &Caller, payload: Value) -> Value {
        Box::pin(call(state, via, caller, REGISTER, payload)).await
    }

    async fn stored(state: &AppState, slot: &str) -> Option<DidRecord> {
        state.dids_ks.get(did_key(slot)).await.unwrap()
    }

    fn refused_with(reply: &Value, expected: &str, needle: &str) {
        assert_eq!(code(reply), expected, "{reply}");
        assert!(
            reply["payload"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains(needle),
            "expected `{needle}` in {reply}"
        );
    }

    #[cfg(feature = "method-webs")]
    #[tokio::test]
    async fn a_did_webs_registers_itself_on_an_enabled_domain_on_every_transport() {
        for (i, via) in VIAS.into_iter().enumerate() {
            let (state, _dir) = enabled(&[]).await;
            let webs = Webs::incept(1 + i as u8);
            let caller = webs.caller("");
            let reply = register_as(&state, via, &caller, webs.payload("")).await;
            conforms(&reply);
            let record = &ok(&reply, REGISTER)["record"];
            assert_eq!(record["owner"], caller.did, "{via:?}: {reply}");

            let stored = stored(&state, &webs.aid).await.expect("slot");
            assert_eq!(stored.owner, caller.did);
            assert_eq!(stored.did_id.as_deref(), Some(caller.did.as_str()));
            assert_eq!(stored.method, "webs");

            // Its later publications take the ordinary owner path: an owner
            // entry, held to its own domain and its one slot.
            let entry = get_acl_entry(&state.acl_ks, &caller.did)
                .await
                .unwrap()
                .expect("granted an ACL entry");
            assert_eq!(entry.role, Role::Owner);
            assert_eq!(entry.max_did_count, Some(1));
            assert_eq!(
                entry.domains,
                DomainScope::Allowed {
                    domains: vec![DOMAIN.into()]
                }
            );
        }
    }

    #[cfg(feature = "method-webs")]
    #[tokio::test]
    async fn a_retry_after_a_lost_grant_registers_again_and_grants_it() {
        let (state, _dir) = enabled(&[]).await;
        let webs = Webs::incept(9);
        let caller = webs.caller("");
        ok(
            &register_as(&state, Via::Https, &caller, webs.payload("")).await,
            REGISTER,
        );
        // The process died between the slot and the grant.
        did_hosting_common::server::acl::delete_acl_entry(&state.acl_ks, &caller.did)
            .await
            .unwrap();

        let reply = register_as(&state, Via::Https, &caller, webs.payload("")).await;
        ok(&reply, REGISTER);
        assert_eq!(stored(&state, &webs.aid).await.unwrap().owner, caller.did);
        assert!(
            get_acl_entry(&state.acl_ks, &caller.did)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[cfg(feature = "method-webs")]
    #[tokio::test]
    async fn a_path_prefix_admits_only_the_slots_under_it() {
        let (state, _dir) = enabled(&["nodes"]).await;
        let webs = Webs::incept(2);

        let outside = webs.caller("");
        let reply = register_as(&state, Via::Https, &outside, webs.payload("")).await;
        refused_with(&reply, "permissionDenied", "only under");
        assert!(stored(&state, &webs.aid).await.is_none());

        let inside = webs.caller("nodes");
        let reply = register_as(&state, Via::Https, &inside, webs.payload("nodes")).await;
        ok(&reply, REGISTER);
        let record = stored(&state, &webs.slot("nodes")).await.expect("slot");
        assert_eq!(
            record.did_id.as_deref(),
            Some(format!("did:webs:{DOMAIN}:nodes:{}", webs.aid).as_str())
        );
    }

    /// A domain holds at most its `max_registrations` self-registered
    /// identifiers: AIDs are free to mint, so the rate limits alone would let
    /// strangers fill it slowly.
    #[cfg(feature = "method-webs")]
    #[tokio::test]
    async fn a_domain_at_its_maximum_refuses_another_self_registration() {
        let (mut state, _dir) = enabled(&[]).await;
        let mut config = (*state.config).clone();
        config.hosting.webs_self_register[0].max_registrations = 1;
        state.config = Arc::new(config);

        let first = Webs::incept(20);
        ok(
            &register_as(&state, Via::Https, &first.caller(""), first.payload("")).await,
            REGISTER,
        );

        let second = Webs::incept(21);
        let caller = second.caller("");
        let reply = register_as(&state, Via::Https, &caller, second.payload("")).await;
        assert!(
            !reply["type"]
                .as_str()
                .unwrap_or_default()
                .ends_with("#response"),
            "{reply}"
        );
        assert!(stored(&state, &second.aid).await.is_none());
        assert!(
            get_acl_entry(&state.acl_ks, &caller.did)
                .await
                .unwrap()
                .is_none()
        );

        // An administrator freeing the first's place makes room again.
        did_hosting_common::server::acl::delete_acl_entry(&state.acl_ks, &first.did_at(""))
            .await
            .unwrap();
        ok(
            &register_as(&state, Via::Https, &caller, second.payload("")).await,
            REGISTER,
        );
    }

    /// Without an operator's opt-in, a `did:webs` outside the ACL is refused
    /// exactly as any other caller outside it — on a build with or without
    /// `method-webs`.
    #[tokio::test]
    async fn a_domain_that_has_not_enabled_it_refuses_as_the_acl_does() {
        let webs = Webs::incept(3);
        let caller = webs.caller("");

        let (state, _dir) = state().await;
        let reply = register_as(&state, Via::Https, &caller, webs.payload("")).await;
        refused_with(
            &reply,
            "permissionDenied",
            "not present in the maintainer's ACL",
        );

        // Enabled, but for another domain.
        let (mut state, _dir2) = super::super::control_tasks::harness::state().await;
        let mut config = (*state.config).clone();
        config.hosting.webs_self_register = vec![WebsSelfRegistration {
            domain: "elsewhere.test".into(),
            ..Default::default()
        }];
        state.config = Arc::new(config);
        let reply = register_as(&state, Via::Https, &caller, webs.payload("")).await;
        assert_eq!(code(&reply), "permissionDenied", "{reply}");
        assert!(stored(&state, &webs.aid).await.is_none());
        assert!(
            get_acl_entry(&state.acl_ks, &caller.did)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[cfg(feature = "method-webs")]
    #[tokio::test]
    async fn a_proof_by_any_key_but_the_logs_is_refused() {
        let (state, _dir) = enabled(&[]).await;
        let webs = Webs::incept(4);
        let did = webs.did_at("");

        // Another key, claiming to be the log's.
        let impostor = Webs::incept(5);
        let mut key = impostor.key_for(&did);
        key.id = format!("{did}#{}", webs.key_qb64);
        let caller = Caller {
            did: did.clone(),
            key,
            role: Role::Owner,
        };
        let reply = register_as(&state, Via::Https, &caller, webs.payload("")).await;
        assert_eq!(code(&reply), "proofInvalid", "{reply}");

        // Another key, named as itself: not a key the log establishes.
        let caller = Caller {
            did: did.clone(),
            key: impostor.key_for(&did),
            role: Role::Owner,
        };
        let reply = register_as(&state, Via::Https, &caller, webs.payload("")).await;
        assert_eq!(code(&reply), "proofInvalid", "{reply}");

        assert!(stored(&state, &webs.aid).await.is_none());
        assert!(get_acl_entry(&state.acl_ks, &did).await.unwrap().is_none());
    }

    #[cfg(feature = "method-webs")]
    #[tokio::test]
    async fn an_issuer_that_is_not_the_slots_identifier_is_refused() {
        let (state, _dir) = enabled(&[]).await;
        let webs = Webs::incept(7);
        let other = Webs::incept(8);

        // `other` signs a registration of `webs`'s log, at `webs`'s slot.
        let caller = other.caller("");
        let reply = register_as(&state, Via::Https, &caller, webs.payload("")).await;
        refused_with(
            &reply,
            "permissionDenied",
            "must issue its own registration",
        );

        // `webs` itself, at a path its identifier does not name.
        let caller = webs.caller("");
        let reply = register_as(&state, Via::Https, &caller, webs.payload("nodes")).await;
        refused_with(
            &reply,
            "permissionDenied",
            "must issue its own registration",
        );

        assert!(stored(&state, &webs.aid).await.is_none());
    }

    #[cfg(feature = "method-webs")]
    #[tokio::test]
    async fn a_tampered_key_event_log_is_refused() {
        let (state, _dir) = enabled(&[]).await;
        let webs = Webs::incept(10);
        let caller = webs.caller("");
        let mut payload = webs.payload("");
        // Flip the last character of the inception event's signature.
        let kel = webs.kel.trim_end();
        let last = kel.chars().last().unwrap();
        let flipped = if last == 'A' { 'B' } else { 'A' };
        payload["didData"] = json!(format!("{}{flipped}", &kel[..kel.len() - 1]));

        let reply = register_as(&state, Via::Https, &caller, payload).await;
        // The wire carries only the code; the reason is logged.
        assert_eq!(code(&reply), "proofInvalid", "{reply}");
        assert!(stored(&state, &webs.aid).await.is_none());
    }

    #[cfg(feature = "method-webs")]
    #[tokio::test]
    async fn a_slot_held_by_someone_else_is_not_taken() {
        let (state, _dir) = enabled(&[]).await;
        let webs = Webs::incept(11);
        let holder = member(&state, 40, Role::Owner).await;
        seed_did(&state, &holder.did, &webs.aid).await;

        let caller = webs.caller("");
        let reply = register_as(&state, Via::Https, &caller, webs.payload("")).await;
        assert!(
            !reply["type"]
                .as_str()
                .unwrap_or_default()
                .ends_with("#response"),
            "{reply}"
        );
        assert_eq!(stored(&state, &webs.aid).await.unwrap().owner, holder.did);
        assert!(
            get_acl_entry(&state.acl_ks, &caller.did)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[cfg(feature = "method-webs")]
    #[tokio::test]
    async fn only_did_webs_registers_this_way() {
        let (state, _dir) = enabled(&[]).await;
        let webs = Webs::incept(12);
        let caller = webs.caller("");
        let mut payload = webs.payload("");
        payload["method"] = json!("webvh");
        payload["didData"] = json!("{\"versionId\":\"1-x\"}");
        let reply = register_as(&state, Via::Https, &caller, payload).await;
        refused_with(&reply, "permissionDenied", "did:webs only");

        // Nor may a self-registration force a takeover.
        let mut payload = webs.payload("");
        payload["force"] = json!(true);
        let reply = register_as(&state, Via::Https, &caller, payload).await;
        refused_with(&reply, "permissionDenied", "may not force");

        // And a did:webvh outside the ACL is refused as it always was.
        let stranger = stranger(13);
        let reply = register_as(&state, Via::Https, &stranger, webs.payload("")).await;
        refused_with(
            &reply,
            "permissionDenied",
            "not present in the maintainer's ACL",
        );
        assert!(stored(&state, &webs.aid).await.is_none());
    }

    /// A self-registration's standing is that one task: the same identifier,
    /// verified the same way, gets nothing on any other row.
    #[cfg(feature = "method-webs")]
    #[tokio::test]
    async fn the_identifier_has_no_standing_on_other_tasks() {
        let (state, _dir) = enabled(&[]).await;
        let webs = Webs::incept(14);
        let caller = webs.caller("");
        let reply = call(
            &state,
            Via::Https,
            &caller,
            "https://trusttasks.org/spec/did-management/did/check-name/0.1",
            json!({ "path": webs.aid, "reserve": true }),
        )
        .await;
        refused_with(
            &reply,
            "permissionDenied",
            "not present in the maintainer's ACL",
        );
    }
}
