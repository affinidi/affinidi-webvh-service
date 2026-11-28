//! Guest self-registration: a `did-management/account/register/0.1` from a
//! party with no account, admitted by an operator invite or a trusted
//! community's voucher, and authenticated by the `did:webvh` log it submits.
//!
//! ## Why the log authenticates it
//!
//! The registrant's DID does not resolve until this task publishes it, so its
//! signing key cannot be looked up. It need not be: a `did:webvh` is
//! self-certifying. Its SCID commits to the genesis entry, which names the
//! DID (domain and path) and the keys that control it, and every later entry
//! is signed by the update keys then in force. A log that verifies from
//! genesis therefore fixes the document of the DID it names, and the request
//! is checked against that document ([`crate::self_certify`]), never one
//! resolved over the network.
//!
//! ## Why that is not enough
//!
//! A self-certifying DID costs nothing to mint, so proving who is asking
//! says nothing about whether they should be given space. The admission
//! evidence does: both halves of an invite an administrator issued
//! (`did_hosting_common::server::account::invite`), or a `DidHostingVoucher`
//! from an authorising party the domain's terms trust
//! (`did_hosting_common::server::account::policy`, set at runtime). The
//! registrant becomes an ordinary owner, held while its account lasts to its
//! domain's terms — path prefixes, quotas, no agent names — and its account
//! expires when unused.
//!
//! ## The order of checks
//!
//! [`admit`] runs every check that does not need the proof, cheapest first, so
//! a stranger without valid evidence costs a key lookup and a claim-code hash,
//! never a log verification or a resolution:
//!
//! 1. the type, the payload's shape, and an issuer with no ACL entry
//!    (`alreadyRegistered`);
//! 2. the domain admits guests by this kind of evidence
//!    (`registrationClosed`), and the path satisfies its rules
//!    (`pathNotAllowed`);
//! 3. a per-source and a service-wide rate limit (shared with `did:webs`
//!    self-registration: one budget for strangers asking for log
//!    verification);
//! 4. the admission evidence — an invite's two halves, or a voucher's issuer,
//!    audience, subject, validity, single use and then its proof
//!    (`admissionRefused`);
//! 5. the log, in full, establishing the DID the slot builds (`invalidLog`);
//! 6. the issuer: that DID, or its `did:scid` alias where the document lists
//!    it (`issuerNotSubject`).
//!
//! [`Candidate::verify`] then checks the proof. The register row
//! (`control_tasks::account::register`) re-checks the evidence under its
//! lock, enforces the domain's capacity, commits, and only then consumes the
//! evidence and grants the ACL entry.

// The refusals here are framework `ErrorPayload`s, handed to the gate's
// `rejected` whole, as `trust_tasks_auth`'s are; boxing each one would only
// move them.
#![allow(clippy::result_large_err)]

use serde_json::Value;
use tracing::warn;
use trust_tasks_rs::{DeclaredErrorCode, ErrorPayload, Payload as _, StandardCode, TrustTask};

use did_hosting_common::server::account::policy::SelfRegistrationPolicy;
use did_hosting_common::server::account::{Referral, invite, policy, voucher};
use did_hosting_common::server::acl::get_acl_entry;
use did_hosting_common::server::config::GuestAdmission;
use did_hosting_common::server::domain::normalize_domain_name;
use did_hosting_common::tasks::did_management::account::register::v0_1 as register;

use crate::server::AppState;

/// The one Type URI this path serves.
pub(crate) const REGISTER_TYPE_URI: &str = register::Payload::TYPE_URI;

/// The label of the ACL entry a self-registration grants.
pub(crate) const SELF_REGISTERED_LABEL: &str = "self-registered account";

/// What admitted a registrant, as the row consumes it.
#[derive(Debug, Clone)]
pub(crate) enum Admitted {
    Invite {
        invite_id: String,
    },
    Voucher {
        issuer: String,
        id: String,
        valid_until: u64,
    },
}

impl Admitted {
    pub(crate) fn kind(&self) -> GuestAdmission {
        match self {
            Admitted::Invite { .. } => GuestAdmission::Invite,
            Admitted::Voucher { .. } => GuestAdmission::Voucher,
        }
    }

    /// What the account record keeps of it.
    pub(crate) fn reference(&self) -> String {
        match self {
            Admitted::Invite { invite_id } => invite_id.clone(),
            Admitted::Voucher { issuer, id, .. } => format!("{issuer} {id}"),
        }
    }
}

/// A registrant that proved control of the DID it registers and presented
/// evidence that admits it. Built only by [`Candidate::verify`].
#[derive(Debug)]
pub(crate) struct SelfRegisteredAccount {
    /// The account's identity: the issuer, a `did:scid` without its `src`.
    pub subject: String,
    /// The `domain` exactly as the payload named it.
    pub domain: String,
    pub path: String,
    pub admitted: Admitted,
    /// What the transport vouched for (`ip:…` or `vid:…`), for the audit
    /// record.
    pub source: String,
    /// The domain's terms, as they stood when the request was admitted.
    pub policy: SelfRegistrationPolicy,
    /// Where it came from, as it said or its evidence did.
    pub referral: Option<Referral>,
}

/// A registration that passed every check but its proof.
pub(crate) struct Candidate {
    account: SelfRegisteredAccount,
    /// The document the proof is checked against: the log's latest
    /// document, or its `did:scid` form when the issuer is that alias.
    document: affinidi_did_common::Document,
}

impl Candidate {
    /// Hold `doc` to the sender-bound rule every privileged document is held
    /// to, with its proof verified against the document the submitted log
    /// implies.
    pub(crate) async fn verify(
        self,
        doc: &TrustTask<Value>,
        sender: &str,
        my_vid: &str,
    ) -> Result<SelfRegisteredAccount, did_hosting_common::server::trust_tasks::BoundError> {
        crate::self_certify::verify_against_document(
            doc,
            &self.account.subject,
            self.document,
            sender,
            my_vid,
        )
        .await?;
        Ok(self.account)
    }
}

/// A refusal [`admit`] answers with.
fn declared(code: DeclaredErrorCode, message: impl Into<String>) -> ErrorPayload {
    ErrorPayload::from(code).with_message(message.into())
}

fn refused(reason: &str, message: impl Into<String>) -> ErrorPayload {
    declared(register::error_codes::ADMISSION_REFUSED, message)
        .with_details(serde_json::json!({ "reason": reason }))
}

/// Decide whether `doc` is a guest registration, and run every check on it
/// short of its proof.
///
/// `Ok(None)`: it is another task. `Err`: it is one, and is refused with the
/// returned error. `Ok(Some)`: verify its proof with [`Candidate::verify`].
/// A registration never falls through to the ordinary, ACL-authorised path.
pub(crate) async fn admit(
    state: &AppState,
    sender: &str,
    https: Option<&crate::messaging::HttpsFacts<'_>>,
    my_vid: &str,
    type_uri: &str,
    doc: &TrustTask<Value>,
) -> Result<Option<Candidate>, ErrorPayload> {
    if type_uri != REGISTER_TYPE_URI {
        return Ok(None);
    }
    // Nothing can authenticate a registrant but its proof, so a document
    // without one is refused before any other work.
    if doc.proof.is_none() {
        return Err(ErrorPayload::new(StandardCode::ProofRequired)
            .with_message("a registration must be signed by the registrant"));
    }
    let Some(issuer) = doc.issuer.as_deref() else {
        return Err(ErrorPayload::new(StandardCode::PermissionDenied)
            .with_message("a registration names its registrant as `issuer`"));
    };
    let subject = did_hosting_common::scid::identity(issuer);
    let p: register::Payload = serde_json::from_value(doc.payload.clone()).map_err(|e| {
        ErrorPayload::new(StandardCode::MalformedRequest)
            .with_message(format!("invalid account/register payload: {e}"))
    })?;

    // 1. A party that holds an account registers nothing new here.
    match get_acl_entry(&state.acl_ks, &subject).await {
        Ok(None) => {}
        Ok(Some(_)) => {
            return Err(declared(
                register::error_codes::ALREADY_REGISTERED,
                "the issuer already holds an account here; publish with did-management/did/register",
            ));
        }
        Err(e) => return Err(e.failure_reject_reason().into()),
    }

    // 2. The domain's terms.
    let domain = p.domain.as_str().to_string();
    let path = p.path.as_str().to_string();
    let kind = match &p.admission {
        register::Admission::InviteAdmission(_) => GuestAdmission::Invite,
        register::Admission::VoucherAdmission(_) => GuestAdmission::Voucher,
        _ => {
            return Err(ErrorPayload::new(StandardCode::MalformedRequest)
                .with_message("this service admits by invite or voucher"));
        }
    };
    let canonical = normalize_domain_name(&domain).ok();
    let terms = match &canonical {
        Some(c) => policy::get(&state.acl_ks, c)
            .await
            .map_err(|e| e.failure_reject_reason())?,
        None => None,
    };
    let offered: Vec<&'static str> = terms
        .as_ref()
        .filter(|t| t.enabled)
        .map(|t| t.admissions.iter().map(|a| a.as_str()).collect())
        .unwrap_or_default();
    let Some(policy) = terms.filter(|t| t.admits(kind)) else {
        return Err(declared(
            register::error_codes::REGISTRATION_CLOSED,
            format!(
                "domain `{domain}` does not admit guest accounts by {}",
                kind.as_str()
            ),
        )
        .with_details(serde_json::json!({ "domain": domain, "admissionsOffered": offered })));
    };
    let path_refused = |reason: String| {
        declared(register::error_codes::PATH_NOT_ALLOWED, reason.clone())
            .with_details(serde_json::json!({ "path": path, "reason": reason }))
    };
    if let Err(e) = did_hosting_common::server::mnemonic::validate_mnemonic(&path) {
        return Err(path_refused(e.user_message()));
    }
    if !policy.admits_path(&path) {
        return Err(path_refused(format!(
            "domain `{domain}` admits guest DIDs only under {:?}",
            policy.path_prefixes
        )));
    }

    // 3. Rate limits, before the work a stranger can ask for.
    let source = match https {
        Some(facts) => facts
            .ip
            .map_or_else(|| "ip:unknown".to_string(), |ip| format!("ip:{ip}")),
        None => format!("vid:{sender}"),
    };
    for limited in [
        state.webs_self_register_limiter.try_consume(source.clone()),
        state
            .webs_self_register_global_limiter
            .try_consume(crate::rate_limit::WEBS_SELF_REGISTER_GLOBAL_KEY.to_string()),
    ] {
        if let Err(e @ did_hosting_common::server::error::AppError::RateLimited { .. }) = limited {
            warn!(%subject, %source, "guest registration refused: rate limited");
            let retry = e
                .retry_after_secs()
                .map(did_hosting_common::server::error::retry_at);
            let payload = ErrorPayload::new(StandardCode::Unavailable)
                .with_message("too many registrations; retry later");
            return Err(match retry {
                Some(at) => payload.with_retry_after(at),
                None => payload,
            });
        }
    }

    // 4. The admission evidence.
    let mut invite_referral: Option<Referral> = None;
    let admitted = match &p.admission {
        register::Admission::InviteAdmission(a) => {
            let checked = invite::check(
                &state.acl_ks,
                a.invite.token.as_str(),
                a.invite.claim_code.as_str(),
                state.config.auth.claim_code_hash_wait(),
            )
            .await
            .map_err(|e| e.failure_reject_reason())?;
            let found = match checked {
                Ok(found) => found,
                Err(refusal) => {
                    return Err(refused(
                        refusal.reason(),
                        "the invite does not admit this registration",
                    ));
                }
            };
            if normalize_domain_name(&found.domain).ok() != canonical || !found.admits_path(&path) {
                return Err(refused(
                    "inviteScope",
                    "the invite admits an account on another domain or under another path",
                ));
            }
            invite_referral = found.referral.clone();
            Admitted::Invite {
                invite_id: found.invite_id,
            }
        }
        register::Admission::VoucherAdmission(_) => {
            // The voucher exactly as it was signed: from the document, not
            // the typed payload.
            let raw = doc
                .payload
                .get("admission")
                .and_then(|a| a.get("voucher"))
                .cloned()
                .unwrap_or(Value::Null);
            check_voucher(state, &policy, &raw, &subject, my_vid, canonical.as_deref()).await?
        }
        // Refused above, with the kind.
        _ => unreachable!("an admission kind the terms lookup already refused"),
    };

    // 5. The log, in full, establishing the DID this slot holds.
    let invalid_log = |reason: String| {
        declared(register::error_codes::INVALID_LOG, reason.clone())
            .with_details(serde_json::json!({ "reason": reason }))
    };
    let publication = did_hosting_common::method::publication::verify_publication(
        &domain,
        &path,
        p.did_data.as_str().as_bytes(),
        None,
        None,
    )
    .map_err(|e| invalid_log(e.to_string()))?;
    if publication.method != "webvh" {
        return Err(invalid_log(
            "the submitted log is not a did:webvh log".into(),
        ));
    }
    let (Some(did_id), Some(document)) = (publication.did_id, publication.document) else {
        return Err(invalid_log(
            "the log's latest entry establishes no did:webvh document".into(),
        ));
    };
    crate::did_ops::check_webvh_slot_identifier(state, &path, &domain, &did_id)
        .map_err(|e| invalid_log(e.user_message()))?;

    // 6. Who may sign: the DID itself, or its did:scid alias where the
    // document lists it (VTI-KEY-164: a distinct identity, verified by this
    // same log).
    let document = if subject == did_hosting_common::scid::identity(&did_id) {
        document
    } else if subject
        == did_hosting_common::scid::identity(&did_hosting_common::scid::scid_alias(&did_id))
        && did_hosting_common::scid::scid_alias_info(&document)
            .is_some_and(|i| i.status == did_hosting_common::scid::ScidAliasStatus::Listed)
    {
        did_hosting_common::scid::scid_document(&document)
            .map_err(|e| invalid_log(format!("could not derive the did:scid document: {e}")))?
    } else {
        return Err(declared(
            register::error_codes::ISSUER_NOT_SUBJECT,
            format!(
                "the registrant must issue its own registration as `{did_id}` or as its did:scid \
                 alias the document lists, not `{issuer}`"
            ),
        ));
    };
    let document: affinidi_did_common::Document = serde_json::from_value(document)
        .map_err(|e| invalid_log(format!("the log's document is not a DID document: {e}")))?;

    let referral = referral_for(&doc.payload, &admitted, invite_referral);
    Ok(Some(Candidate {
        account: SelfRegisteredAccount {
            subject,
            domain,
            path,
            admitted,
            source,
            policy,
            referral,
        },
        document,
    }))
}

/// The referral an account records: an invite's own, verified; a stated one
/// that a voucher's issuer bears out, verified (its `via` filled from the
/// issuer when the registrant named none); otherwise what the registrant
/// stated, unverified. Attribution only — nothing is authorised on it.
fn referral_for(
    payload: &Value,
    admitted: &Admitted,
    invite_referral: Option<Referral>,
) -> Option<Referral> {
    if let Some(r) = invite_referral {
        return Some(Referral {
            verified: true,
            ..r
        });
    }
    let stated = payload.get("referral");
    let text = |name: &str| {
        stated
            .and_then(|r| r.get(name))
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let (via, label) = (text("via"), text("label"));
    match admitted {
        Admitted::Voucher { issuer, .. }
            if via
                .as_deref()
                .is_none_or(|v| did_hosting_common::scid::same_reference(v, issuer)) =>
        {
            Some(Referral {
                via: Some(via.unwrap_or_else(|| issuer.clone())),
                label,
                verified: true,
            })
        }
        _ if via.is_some() || label.is_some() => Some(Referral {
            via,
            label,
            verified: false,
        }),
        _ => None,
    }
}

/// Check a `DidHostingVoucher` for this registration: cheap checks first,
/// then single use, then its proof.
async fn check_voucher(
    state: &AppState,
    policy: &SelfRegistrationPolicy,
    raw: &Value,
    subject: &str,
    my_vid: &str,
    canonical_domain: Option<&str>,
) -> Result<Admitted, ErrorPayload> {
    use did_hosting_common::scid::same_reference;

    let field = |path: &[&str]| {
        let mut v = raw;
        for p in path {
            v = v.get(p)?;
        }
        v.as_str().map(str::to_string)
    };
    let types_ok = raw
        .get("type")
        .and_then(Value::as_array)
        .is_some_and(|t| t.iter().any(|t| t.as_str() == Some("DidHostingVoucher")));
    if !types_ok {
        return Err(refused(
            "voucherInvalid",
            "the voucher's type does not include DidHostingVoucher",
        ));
    }
    let issuer = field(&["issuer"]).unwrap_or_default();
    let id = field(&["id"]).unwrap_or_default();
    if !policy.trusts_voucher_issuer(&issuer) {
        return Err(refused(
            "untrustedIssuer",
            format!(
                "domain `{}` does not trust vouchers from `{issuer}`",
                policy.domain
            ),
        ));
    }
    if !field(&["credentialSubject", "hostingService"]).is_some_and(|h| same_reference(&h, my_vid))
    {
        return Err(refused(
            "voucherAudience",
            "the voucher is for another hosting service",
        ));
    }
    if !field(&["credentialSubject", "id"]).is_some_and(|s| same_reference(&s, subject)) {
        return Err(refused(
            "voucherSubject",
            "the voucher admits another DID than the registrant",
        ));
    }
    if let Some(d) = field(&["credentialSubject", "domain"])
        && normalize_domain_name(&d).ok().as_deref() != canonical_domain
    {
        return Err(refused(
            "voucherDomain",
            "the voucher admits an account on another domain",
        ));
    }
    let now = chrono::Utc::now();
    let instant =
        |name: &str| field(&[name]).and_then(|t| chrono::DateTime::parse_from_rfc3339(&t).ok());
    let Some(valid_until) = instant("validUntil") else {
        return Err(refused("voucherInvalid", "the voucher has no validUntil"));
    };
    if valid_until <= now || instant("validFrom").is_some_and(|f| f > now) {
        return Err(refused(
            "voucherExpired",
            "the voucher is outside its validity period",
        ));
    }
    match voucher::is_used(&state.acl_ks, &issuer, &id).await {
        Ok(false) => {}
        Ok(true) => {
            return Err(refused("voucherUsed", "the voucher has already been used"));
        }
        Err(e) => return Err(e.failure_reject_reason().into()),
    }
    verify_voucher_proof(state, raw, &issuer).await?;
    Ok(Admitted::Voucher {
        issuer: did_hosting_common::scid::identity(&issuer),
        id,
        valid_until: valid_until.timestamp().max(0) as u64,
    })
}

/// Verify the voucher's own Data Integrity proof: by a key of `issuer`, for
/// and under `assertionMethod`, over the voucher without its proof. The
/// issuer is a DID the operator configured, resolved through the service's
/// shared cache.
async fn verify_voucher_proof(
    state: &AppState,
    raw: &Value,
    issuer: &str,
) -> Result<(), ErrorPayload> {
    use affinidi_data_integrity::{DataIntegrityProof, VerifyOptions};
    use trust_tasks_proof::affinidi::{CachedDidResolver, ProofPurpose, ProofPurposeResolver};

    let invalid = |why: String| {
        warn!(%issuer, reason = %why, "guest registration refused: voucher proof");
        refused(
            "voucherInvalid",
            format!("the voucher's proof does not verify: {why}"),
        )
    };
    let Some(client) = state.did_resolver.clone() else {
        return Err(ErrorPayload::new(StandardCode::Unavailable)
            .with_message("this service cannot resolve DIDs to verify a voucher"));
    };
    let mut unsigned = raw.clone();
    let proof_value = unsigned
        .as_object_mut()
        .and_then(|o| o.remove("proof"))
        .ok_or_else(|| invalid("no proof".into()))?;
    let proof: DataIntegrityProof =
        serde_json::from_value(proof_value).map_err(|e| invalid(e.to_string()))?;
    let vm = proof.verification_method.clone();
    if !did_hosting_common::scid::same_reference(
        did_hosting_common::server::trust_tasks::verifier::controller_did(&vm),
        issuer,
    ) {
        return Err(invalid("its key is not the issuer's".into()));
    }
    let resolver = CachedDidResolver::new(std::sync::Arc::new(client));
    let key = resolver
        .resolve_vm_for_purpose(
            &did_hosting_common::scid::strip_scid_src(&vm),
            ProofPurpose::AssertionMethod,
        )
        .await
        .map_err(|e| invalid(e.to_string()))?;
    proof
        .verify_with_public_key(&unsigned, &key.public_key_bytes, VerifyOptions::default())
        .map_err(|e| invalid(e.to_string()))
}

/// The account tasks a self-registered account sends about itself, verified
/// against its own stored log rather than by resolving its DID.
///
/// Its DID is a slot this host holds, so the stored log is the authority on
/// its keys, as the submitted log is at registration. Resolution would also
/// fail exactly when these tasks matter most: a disabled account's DID does
/// not resolve (it answers 404), and `account/renew` is how its holder
/// restores it, `account/status` how it learns it must.
fn held_signer_type(type_uri: &str) -> bool {
    use did_hosting_common::tasks::did_management::account::{renew, status};
    type_uri == renew::v0_1::Payload::TYPE_URI || type_uri == status::v0_1::Payload::TYPE_URI
}

/// A self-registered account's DID, with the document its stored log implies.
pub(crate) struct HeldSigner {
    did: String,
    document: affinidi_did_common::Document,
}

impl HeldSigner {
    /// Hold `doc` to the sender-bound rule, with its proof verified against
    /// the stored log's document.
    pub(crate) async fn verify(
        self,
        doc: &TrustTask<Value>,
        sender: &str,
        my_vid: &str,
    ) -> Result<String, did_hosting_common::server::trust_tasks::BoundError> {
        crate::self_certify::verify_against_document(doc, &self.did, self.document, sender, my_vid)
            .await
    }
}

/// When `doc` is an account task from a self-registered account, the DID it
/// is signed by and the document the host's stored log implies for it.
///
/// `Ok(None)`: another task, or a signer with no account record or no slot
/// here — the ordinary path. `Err`: the account's log no longer authenticates
/// anyone (deactivated, or unreadable).
pub(crate) async fn held_signer(
    state: &AppState,
    type_uri: &str,
    doc: &TrustTask<Value>,
) -> Result<Option<HeldSigner>, ErrorPayload> {
    use did_hosting_common::did_ops::{DidRecord, content_log_key, did_key, extract_log_metadata};
    use did_hosting_common::scid::{identity, scid_alias};

    if !held_signer_type(type_uri) {
        return Ok(None);
    }
    let Some(issuer) = doc.issuer.as_deref() else {
        return Ok(None);
    };
    let subject = identity(issuer);
    let Some(record) = did_hosting_common::server::account::get(&state.acl_ks, &subject)
        .await
        .map_err(|e| ErrorPayload::from(e.failure_reject_reason()))?
    else {
        return Ok(None);
    };
    let slots = crate::did_ops::owner_mnemonics_on_domain(state, &subject, &record.domain)
        .await
        .map_err(|e| ErrorPayload::from(e.failure_reject_reason()))?;
    for slot in slots {
        let Ok(Some(rec)) = state.dids_ks.get::<DidRecord>(did_key(&slot)).await else {
            continue;
        };
        let Some(did_id) = rec.did_id.clone() else {
            continue;
        };
        let as_webvh = identity(&did_id) == subject;
        let as_scid = identity(&scid_alias(&did_id)) == subject;
        if !as_webvh && !as_scid {
            continue;
        }
        let Ok(Some(log)) = state.dids_ks.get_raw(content_log_key(&slot)).await else {
            continue;
        };
        let unusable = |why: &str| {
            warn!(%subject, %slot, reason = why, "account task refused: its stored log");
            ErrorPayload::new(StandardCode::PermissionDenied)
                .with_message(format!("the account's DID {why}"))
        };
        let log_text = std::str::from_utf8(&log).map_err(|_| unusable("log is unreadable"))?;
        if extract_log_metadata(log_text).deactivated {
            return Err(unusable("is deactivated, so its keys sign nothing"));
        }
        let publication = did_hosting_common::method::publication::verify_publication(
            &record.domain,
            &slot,
            &log,
            None,
            None,
        )
        .map_err(|_| unusable("log does not verify"))?;
        let Some(document) = publication.document else {
            return Err(unusable("log implies no document"));
        };
        let document = if as_webvh {
            document
        } else if did_hosting_common::scid::scid_alias_info(&document)
            .is_some_and(|i| i.status == did_hosting_common::scid::ScidAliasStatus::Listed)
        {
            did_hosting_common::scid::scid_document(&document)
                .map_err(|_| unusable("did:scid document cannot be derived"))?
        } else {
            // The alias is no longer listed: the did:scid no longer names
            // this DID.
            return Err(unusable(
                "document no longer lists the did:scid alias that signed",
            ));
        };
        let document = serde_json::from_value(document)
            .map_err(|_| unusable("document is not a DID document"))?;
        return Ok(Some(HeldSigner {
            did: subject,
            document,
        }));
    }
    Ok(None)
}
