//! The `auth/oob/*` state machine: this control plane as the sign-in service
//! (base design sections 7 and 12, contract C5 and C9).
//!
//! `pending → claimed → identified → approved → consumed`; `declined`,
//! `cancelled` and `expired` are final. Every change is a compare-and-set
//! ([`OobStore::compare_and_set`]). A failed `prove` or `respond` from the
//! lock holder declines the request, so each request allows one attempt.
//!
//! Transport-neutral and free of `AppState`: everything this needs from the
//! deployment (clock, ACL, the member-DID verifier, the response signer) comes
//! through [`OobEnv`], so the tests drive the real checks with `did:key`
//! members and a fake clock.

use std::sync::Arc;
use std::time::Duration;

use affinidi_data_integrity::DidKeyResolver;
use async_trait::async_trait;
use did_hosting_common::server::auth::session::is_ed25519_multikey;
use did_hosting_common::server::trust_tasks::TransportBoundVerifier;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trust_tasks_rs::{ProofVerifier, TrustTask};

use super::store::{CreateError, OobRecord, OobStore};
use super::types::*;

/// Oldest acceptable `issuedAt`, seconds.
pub const MAX_DOCUMENT_AGE_SECS: u64 = 300;
/// Allowed `issuedAt` in the future, seconds.
pub const CLOCK_SKEW_SECS: u64 = 60;
/// How long a document id is remembered: longer than it is acceptable.
pub const SEEN_ID_TTL_SECS: u64 = 600;
/// The `amr` of a session this flow creates (base design 7.6).
pub const OOB_AMR: [&str; 3] = ["did", "oob", "uv"];

/// What the deployment supplies.
#[async_trait]
pub trait OobEnv: Send + Sync {
    /// Epoch seconds.
    fn now(&self) -> u64;
    /// Verifies member DIDs' proofs: `identify` for `authentication`,
    /// `grant` for `assertionMethod`. `None` when no DID resolver is
    /// configured, in which case no member proof can be accepted.
    fn member_verifier(&self) -> Option<&TransportBoundVerifier>;
    /// Is this DID an allowed user (in the ACL)? Called on the issuer string
    /// before any DID resolution.
    async fn is_allowed(&self, did: &str) -> bool;
    /// Display name for "Continue as …?".
    async fn display_name(&self, did: &str) -> Option<String>;
    /// Sign a response document with this service's key for `proof_purpose`.
    async fn sign(&self, unsigned: Value, proof_purpose: &str) -> Result<Value, String>;
}

/// Fixed settings.
#[derive(Debug, Clone)]
pub struct OobConfig {
    pub service_did: String,
    /// The name shown in step 1.
    pub service_name: String,
    /// The portal origin, the origin of the `SignInPortal` service.
    pub origin: String,
    /// Seconds. At most 180; 120 recommended.
    pub claim_window_secs: u64,
    /// Seconds. At most 180; 120 recommended.
    pub decision_window_secs: u64,
    /// Upper bound on a session, seconds.
    pub session_limit_secs: u64,
    /// How long `redeem` holds an undecided request.
    pub redeem_hold: Duration,
    /// Open `redeem` polls per client address.
    pub max_polls_per_ip: usize,
}

impl OobConfig {
    pub fn new(service_did: String, service_name: String, origin: String) -> Self {
        Self {
            service_did,
            service_name,
            origin,
            claim_window_secs: 120,
            decision_window_secs: 120,
            session_limit_secs: 8 * 3600,
            redeem_hold: Duration::from_secs(25),
            max_polls_per_ip: 8,
        }
    }
}

/// A refusal, carried to the caller as a `trust-task-error`.
#[derive(Debug, Clone, PartialEq)]
pub struct OobError {
    pub code: OobErrorCode,
    pub message: String,
    pub details: Option<Value>,
}

impl OobError {
    pub fn new(code: OobErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }
    fn not_authorized() -> Self {
        Self::new(OobErrorCode::NotAuthorized, "not authorized")
    }
    fn malformed(m: impl Into<String>) -> Self {
        Self::new(OobErrorCode::MalformedRequest, m)
    }
}

/// The session a successful `redeem` creates. The binding creates the
/// service's own session from it.
#[derive(Debug, Clone)]
pub struct ApprovedSession {
    /// The DID that signed the grant.
    pub subject: String,
    /// `K_b`, the only key that may sign as `subject` in this session.
    pub session_key: String,
    /// Epoch seconds: the earlier of the grant's `notAfter` and the limit.
    pub not_after: u64,
    pub display_name: Option<String>,
    /// The signed grant, for the audit record.
    pub grant: Value,
}

/// What [`OobService::handle`] returns.
#[derive(Debug)]
pub enum OobReply {
    /// A signed response or an error document.
    Document { status: u16, body: Value },
    /// `redeem` succeeded: create the session, then answer with
    /// [`OobService::redeem_response`].
    Approved {
        request: Box<TrustTask<Value>>,
        session: ApprovedSession,
    },
}

/// The service.
pub struct OobService {
    pub config: OobConfig,
    store: OobStore,
    /// Verifies `K_a` / `K_b` documents locally, with no I/O.
    key_verifier: TransportBoundVerifier,
}

impl OobService {
    pub fn new(config: OobConfig) -> Self {
        assert!(
            config.claim_window_secs <= 180 && config.decision_window_secs <= 180,
            "claim and decision windows are at most 180 s"
        );
        Self {
            config,
            store: OobStore::new(),
            key_verifier: TransportBoundVerifier::with_resolver(Arc::new(DidKeyResolver)),
        }
    }

    pub fn store(&self) -> &OobStore {
        &self.store
    }

    /// Route a parsed body by its `type`. Never fails: a refusal is an error
    /// document.
    pub async fn handle(&self, env: &dyn OobEnv, raw: Value, conn: &Connection) -> OobReply {
        let type_uri = raw
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or_default()
            .to_string();
        let result = match type_uri.as_str() {
            TYPE_REQUEST => self.request(env, &raw, conn).await,
            TYPE_CLAIM => self.claim(env, &raw).await,
            TYPE_PROVE => self.prove(env, &raw, conn).await,
            TYPE_RESPOND => self.respond(env, &raw).await,
            TYPE_REDEEM => match self.redeem(env, &raw, conn).await {
                Ok((request, session)) => {
                    return OobReply::Approved {
                        request: Box::new(request),
                        session,
                    };
                }
                Err(e) => Err(e),
            },
            TYPE_CANCEL => self.cancel(env, &raw).await,
            _ => Err(OobError::malformed(format!("unsupported type {type_uri}"))),
        };
        match result {
            Ok(body) => OobReply::Document { status: 200, body },
            Err(err) => OobReply::Document {
                status: err.code.http_status(),
                body: self.error_document(env, &raw, &err),
            },
        }
    }

    /// The signed `redeem` response: `{ subject, displayName, notAfter, amr }`
    /// (C9), plus a vendor-namespaced `ext` the binding may add (the schema's
    /// only open member).
    pub async fn redeem_response(
        &self,
        env: &dyn OobEnv,
        request: &TrustTask<Value>,
        session: &ApprovedSession,
        ext: Option<Value>,
    ) -> Result<Value, OobError> {
        let body = RedeemResponse {
            subject: session.subject.clone(),
            display_name: display_name_or_did(session.display_name.as_deref(), &session.subject),
            not_after: session.not_after,
            amr: OOB_AMR.iter().map(|s| s.to_string()).collect(),
            ext,
        };
        let payload = serde_json::to_value(body).expect("redeem response serialises");
        let issuer = request.issuer.clone().unwrap_or_default();
        self.signed(env, request, &issuer, payload, OPERATIONAL)
            .await
    }

    // ---- request ------------------------------------------------------------

    async fn request(
        &self,
        env: &dyn OobEnv,
        raw: &Value,
        conn: &Connection,
    ) -> Result<Value, OobError> {
        let (doc, payload) = self
            .key_doc::<RequestPayload>(env, raw, TYPE_REQUEST)
            .await?;
        if payload.purpose != "login" {
            return Err(OobError::new(
                OobErrorCode::PurposeUnsupported,
                "purpose must be login",
            ));
        }
        if payload.mode != "scan" {
            return Err(OobError::new(
                OobErrorCode::ModeUnsupported,
                "mode must be scan",
            ));
        }
        self.fresh(env, &doc)?;
        let now = env.now();
        let request_id = new_request_id();
        let claim_deadline = now + self.config.claim_window_secs;
        let record = OobRecord {
            request_id: request_id.clone(),
            state: OobState::Pending,
            version: 0,
            purpose: "login".into(),
            origin: self.config.origin.clone(),
            start_key: doc.issuer.clone().unwrap_or_default(),
            start_network: conn.ip.clone(),
            location: conn.location.clone().unwrap_or_else(|| "unknown".into()),
            browser: conn.browser.clone().unwrap_or_else(|| "unknown".into()),
            os: conn.os.clone().unwrap_or_else(|| "unknown".into()),
            created_at: now,
            approver_key: None,
            match_number: None,
            identified_did: None,
            step2_digest: None,
            claim_deadline,
            decision_deadline: None,
            grant: None,
            grant_not_after: None,
            finished_at: None,
        };
        self.store.create(record, now).map_err(|e| match e {
            CreateError::Full => OobError::new(OobErrorCode::RateLimited, "too many open requests"),
            CreateError::Duplicate => OobError::malformed("request id collision"),
        })?;
        tracing::info!(audit = true, op = "auth/oob/request", request_id = %request_id, "sign-in request opened");
        let body = RequestResponse {
            request_id,
            claim_deadline,
        };
        let recipient = doc.issuer.clone().unwrap_or_default();
        self.signed(
            env,
            &doc,
            &recipient,
            serde_json::to_value(body).expect("serialises"),
            OPERATIONAL,
        )
        .await
    }

    // ---- claim (7.3) --------------------------------------------------------

    async fn claim(&self, env: &dyn OobEnv, raw: &Value) -> Result<Value, OobError> {
        let (doc, payload) = self
            .key_doc::<RequestIdPayload>(env, raw, TYPE_CLAIM)
            .await?;
        if !is_request_id(&payload.request_id) {
            return Err(OobError::malformed("payload.requestId is malformed"));
        }
        // VTI-LNK-054, C5: the handle travels as `parentThreadId` too.
        if doc.parent_thread_id.as_deref() != Some(payload.request_id.as_str()) {
            return Err(OobError::malformed(
                "parentThreadId must equal payload.requestId",
            ));
        }
        self.fresh(env, &doc)?;
        let rec = self.current(env, &payload.request_id)?;
        if rec.state == OobState::Expired {
            return Err(OobError::new(
                OobErrorCode::RequestExpired,
                "request expired",
            ));
        }
        if rec.state != OobState::Pending {
            // No details: a bystander learns nothing.
            return Err(OobError::new(
                OobErrorCode::AlreadyClaimed,
                "already claimed",
            ));
        }
        let now = env.now();
        let approver_key = doc.issuer.clone().unwrap_or_default();
        let mut next = rec.next(OobState::Claimed, now);
        next.approver_key = Some(approver_key.clone());
        next.match_number = Some(two_digits());
        next.decision_deadline = Some(now + self.config.decision_window_secs);
        if !self.store.compare_and_set(rec.version, next.clone()) {
            return Err(OobError::new(
                OobErrorCode::AlreadyClaimed,
                "already claimed",
            ));
        }
        tracing::info!(audit = true, op = "auth/oob/claim", request_id = %rec.request_id, "sign-in request claimed");
        let step1 = self.step1(&next);
        self.signed(
            env,
            &doc,
            &approver_key,
            serde_json::to_value(step1).expect("serialises"),
            ATTESTATION,
        )
        .await
    }

    // ---- prove (7.4) --------------------------------------------------------

    async fn prove(
        &self,
        env: &dyn OobEnv,
        raw: &Value,
        conn: &Connection,
    ) -> Result<Value, OobError> {
        let (doc, payload) = self.key_doc::<Value>(env, raw, TYPE_PROVE).await?;
        let identify_raw = carried(&payload, "identify")?;
        let request_id = carried_request_id(&identify_raw)?;
        same_thread(&doc, &request_id)?;
        // 1. The outer issuer holds the lock; the request is claimed and in
        //    its decision window.
        let issuer = doc.issuer.clone().unwrap_or_default();
        let rec = self.lock_holder_record(env, &request_id, &issuer, OobState::Claimed)?;
        self.fresh(env, &doc)?;

        // From here every failure declines the request.
        let outcome = self.prove_checks(env, &rec, identify_raw).await;
        let (identify_did, identify_payload) = match outcome {
            Ok(v) => v,
            Err(err) => return Err(self.decline(env, &rec, err, "auth/oob/prove")),
        };
        // 5. The number.
        if Some(&identify_payload.entered_number) != rec.match_number.as_ref() {
            return Err(self.decline(
                env,
                &rec,
                OobError::new(OobErrorCode::NumberMismatch, "the number does not match"),
                "auth/oob/prove",
            ));
        }

        // 6. Step 2, signed, and its digest stored.
        let same_network = match (&rec.start_network, &conn.ip) {
            (Some(a), Some(b)) => Value::Bool(a == b),
            _ => Value::String("unknown".into()),
        };
        let step2 = Step2Response {
            step1: self.step1(&rec),
            session_key: rec.start_key.clone(),
            requester: Requester {
                location: rec.location.clone(),
                browser: rec.browser.clone(),
                os: rec.os.clone(),
                created_at: rfc3339(rec.created_at),
                same_network,
            },
            identified_as: identify_did.clone(),
        };
        let signed = self
            .signed(
                env,
                &doc,
                &issuer,
                serde_json::to_value(step2).expect("serialises"),
                ATTESTATION,
            )
            .await?;
        let now = env.now();
        let mut next = rec.next(OobState::Identified, now);
        next.identified_did = Some(identify_did.clone());
        next.step2_digest = Some(context_digest(&signed));
        if !self.store.compare_and_set(rec.version, next) {
            return Err(OobError::new(
                OobErrorCode::RequestExpired,
                "request changed",
            ));
        }
        tracing::info!(audit = true, op = "auth/oob/prove", request_id = %rec.request_id, did = %identify_did, "sign-in request identified");
        Ok(signed)
    }

    /// Steps 2 to 4 of 7.4. Any `Err` declines the request.
    async fn prove_checks(
        &self,
        env: &dyn OobEnv,
        rec: &OobRecord,
        identify_raw: Value,
    ) -> Result<(String, IdentifyPayload), OobError> {
        let identify: TrustTask<Value> =
            serde_json::from_value(identify_raw).map_err(|_| OobError::not_authorized())?;
        // 2. The same request and lock.
        let approver = identify.payload.get("approverKey").and_then(|v| v.as_str());
        if approver != rec.approver_key.as_deref() {
            return Err(OobError::not_authorized());
        }
        // 3. The ACL check on the issuer string, before any DID resolution.
        let did = identify.issuer.clone().unwrap_or_default();
        if did.is_empty() || !env.is_allowed(&did).await {
            return Err(OobError::not_authorized());
        }
        // 4. The proof, against `authentication` (C5), and the envelope.
        self.envelope(env, &identify, TYPE_IDENTIFY)
            .map_err(|_| OobError::not_authorized())?;
        let verifier = env.member_verifier().ok_or_else(OobError::not_authorized)?;
        if let Err(e) = verifier.verify_operational(&identify).await {
            tracing::warn!(error = %e, "auth/oob identify proof refused");
            return Err(OobError::not_authorized());
        }
        let payload: IdentifyPayload = serde_json::from_value(identify.payload.clone())
            .map_err(|_| OobError::not_authorized())?;
        if payload.request_id != rec.request_id {
            return Err(OobError::not_authorized());
        }
        if !self.store.remember_document(
            &did,
            &identify.id,
            env.now() + SEEN_ID_TTL_SECS,
            env.now(),
        ) {
            return Err(OobError::not_authorized());
        }
        Ok((did, payload))
    }

    // ---- respond (7.5) ------------------------------------------------------

    async fn respond(&self, env: &dyn OobEnv, raw: &Value) -> Result<Value, OobError> {
        let (doc, payload) = self.key_doc::<Value>(env, raw, TYPE_RESPOND).await?;
        let grant_raw = carried(&payload, "grant")?;
        let request_id = carried_request_id(&grant_raw)?;
        same_thread(&doc, &request_id)?;
        let issuer = doc.issuer.clone().unwrap_or_default();
        // 1.
        let rec = self.lock_holder_record(env, &request_id, &issuer, OobState::Identified)?;
        self.fresh(env, &doc)?;

        let (decision, not_after) = match self.grant_checks(env, &rec, &grant_raw).await {
            Ok(v) => v,
            Err(err) => return Err(self.decline(env, &rec, err, "auth/oob/respond")),
        };
        // 6.
        let approve = decision == "approve";
        let now = env.now();
        let mut next = rec.next(
            if approve {
                OobState::Approved
            } else {
                OobState::Declined
            },
            now,
        );
        next.grant = Some(grant_raw);
        next.grant_not_after = Some(not_after);
        // An approved request still waits for redeem; the start network is
        // no longer needed either way.
        next.start_network = None;
        if !self.store.compare_and_set(rec.version, next) {
            return Err(OobError::new(
                OobErrorCode::AlreadyDecided,
                "already decided",
            ));
        }
        tracing::info!(audit = true, op = "auth/oob/respond", request_id = %rec.request_id, decision = %decision, "sign-in request decided");
        let status = if approve { "approved" } else { "declined" };
        self.signed(env, &doc, &issuer, json!({ "status": status }), OPERATIONAL)
            .await
    }

    /// Steps 2 to 5 of 7.5. Any `Err` declines the request.
    async fn grant_checks(
        &self,
        env: &dyn OobEnv,
        rec: &OobRecord,
        grant_raw: &Value,
    ) -> Result<(String, u64), OobError> {
        let grant: TrustTask<Value> =
            serde_json::from_value(grant_raw.clone()).map_err(|_| OobError::not_authorized())?;
        // 2. Issued by the DID that proved, against `assertionMethod`.
        let did = rec.identified_did.clone().unwrap_or_default();
        if grant.issuer.as_deref() != Some(did.as_str()) {
            return Err(OobError::not_authorized());
        }
        self.envelope(env, &grant, TYPE_GRANT)
            .map_err(|_| OobError::not_authorized())?;
        let verifier = env.member_verifier().ok_or_else(OobError::not_authorized)?;
        if let Err(e) = verifier.verify_approval(&grant).await {
            tracing::warn!(error = %e, "auth/oob grant proof refused");
            return Err(OobError::not_authorized());
        }
        if !self
            .store
            .remember_document(&did, &grant.id, env.now() + SEEN_ID_TTL_SECS, env.now())
        {
            return Err(OobError::not_authorized());
        }
        let p: GrantPayload = serde_json::from_value(grant.payload.clone())
            .map_err(|_| OobError::not_authorized())?;
        if p.decision != "approve" && p.decision != "decline" {
            return Err(OobError::not_authorized());
        }
        let not_after = p.not_after;
        // 3. and 4. The bindings.
        let mismatch = || OobError::new(OobErrorCode::ContextMismatch, "context mismatch");
        if p.request_id != rec.request_id
            || Some(&p.approver_key) != rec.approver_key.as_ref()
            || p.session_key != rec.start_key
            || p.origin != rec.origin
        {
            return Err(mismatch());
        }
        let stored = rec.step2_digest.as_deref().unwrap_or_default();
        if !context_digests_equal(&p.context_digest, stored) {
            return Err(mismatch());
        }
        if p.decision == "approve" && not_after <= env.now() {
            return Err(OobError::not_authorized());
        }
        // 5. Still allowed.
        if !env.is_allowed(&did).await {
            return Err(OobError::not_authorized());
        }
        Ok((p.decision, not_after))
    }

    // ---- redeem (7.6) -------------------------------------------------------

    async fn redeem(
        &self,
        env: &dyn OobEnv,
        raw: &Value,
        conn: &Connection,
    ) -> Result<(TrustTask<Value>, ApprovedSession), OobError> {
        let (doc, payload) = self
            .key_doc::<RequestIdPayload>(env, raw, TYPE_REDEEM)
            .await?;
        let rec = self.current(env, &payload.request_id)?;
        if doc.issuer.as_deref() != Some(rec.start_key.as_str()) {
            return Err(OobError::new(OobErrorCode::NotStarter, "not the starter"));
        }
        self.fresh(env, &doc)?;

        let ip = conn.ip.clone().unwrap_or_else(|| "unknown".into());
        let Some(_guard) = self
            .store
            .open_poll(&rec.request_id, &ip, self.config.max_polls_per_ip)
        else {
            return Err(OobError::new(
                OobErrorCode::RateLimited,
                "a poll is already open for this request",
            ));
        };
        let notify = self.store.waiter(&rec.request_id);
        let until = tokio::time::Instant::now() + self.config.redeem_hold;
        loop {
            let notified = notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let rec = self.current(env, &payload.request_id)?;
            match rec.state {
                OobState::Approved => return self.consume(env, doc, rec).await,
                OobState::Declined | OobState::Cancelled => {
                    return Err(OobError::new(
                        OobErrorCode::Declined,
                        format!("request {}", rec.state.as_str()),
                    )
                    .with_details(json!({ "state": rec.state.as_str() })));
                }
                OobState::Expired | OobState::Consumed => {
                    return Err(
                        OobError::new(OobErrorCode::RequestExpired, "request expired")
                            .with_details(json!({ "state": rec.state.as_str() })),
                    );
                }
                _ => {}
            }
            let now = tokio::time::Instant::now();
            if now >= until {
                let mut details = json!({ "state": rec.state.as_str() });
                // Only the holder of K_b ever receives the number.
                if let Some(n) = &rec.match_number {
                    details["matchNumber"] = json!(n);
                }
                return Err(
                    OobError::new(OobErrorCode::Pending, "not decided yet").with_details(details)
                );
            }
            // Wake on a change, or at least every second to apply deadlines.
            let wait = (until - now).min(Duration::from_secs(1));
            let _ = tokio::time::timeout(wait, notified).await;
        }
    }

    async fn consume(
        &self,
        env: &dyn OobEnv,
        doc: TrustTask<Value>,
        rec: OobRecord,
    ) -> Result<(TrustTask<Value>, ApprovedSession), OobError> {
        let now = env.now();
        if !self
            .store
            .compare_and_set(rec.version, rec.next(OobState::Consumed, now))
        {
            return Err(OobError::new(
                OobErrorCode::RequestExpired,
                "already redeemed",
            ));
        }
        let did = rec.identified_did.clone().unwrap_or_default();
        if !env.is_allowed(&did).await {
            return Err(OobError::not_authorized());
        }
        let limit = now + self.config.session_limit_secs;
        let not_after = rec.grant_not_after.unwrap_or(limit).min(limit);
        tracing::info!(audit = true, op = "auth/oob/redeem", request_id = %rec.request_id, did = %did, "sign-in request redeemed");
        Ok((
            doc,
            ApprovedSession {
                subject: did.clone(),
                session_key: rec.start_key.clone(),
                not_after,
                display_name: env.display_name(&did).await,
                grant: rec.grant.clone().unwrap_or(Value::Null),
            },
        ))
    }

    // ---- cancel -------------------------------------------------------------

    async fn cancel(&self, env: &dyn OobEnv, raw: &Value) -> Result<Value, OobError> {
        let (doc, payload) = self
            .key_doc::<RequestIdPayload>(env, raw, TYPE_CANCEL)
            .await?;
        let rec = self.current(env, &payload.request_id)?;
        let issuer = doc.issuer.clone().unwrap_or_default();
        if issuer != rec.start_key && Some(&issuer) != rec.approver_key.as_ref() {
            return Err(OobError::not_authorized());
        }
        self.fresh(env, &doc)?;
        let body = json!({ "status": "cancelled" });
        if rec.state == OobState::Cancelled {
            return self.signed(env, &doc, &issuer, body, OPERATIONAL).await;
        }
        if rec.state.is_final() || rec.state == OobState::Approved {
            return Err(OobError::new(
                OobErrorCode::AlreadyDecided,
                format!("request {}", rec.state.as_str()),
            ));
        }
        if !self
            .store
            .compare_and_set(rec.version, rec.next(OobState::Cancelled, env.now()))
        {
            return Err(OobError::new(
                OobErrorCode::AlreadyDecided,
                "request changed",
            ));
        }
        tracing::info!(audit = true, op = "auth/oob/cancel", request_id = %rec.request_id, "sign-in request cancelled");
        self.signed(env, &doc, &issuer, body, OPERATIONAL).await
    }

    // ---- helpers ------------------------------------------------------------

    /// Parse, check the envelope, and verify a document issued and signed by
    /// an Ed25519 `did:key` (`K_a` or `K_b`). Anything else is
    /// `keyUnsupported`.
    async fn key_doc<P: DeserializeOwned>(
        &self,
        env: &dyn OobEnv,
        raw: &Value,
        type_uri: &str,
    ) -> Result<(TrustTask<Value>, P), OobError> {
        let doc: TrustTask<Value> = serde_json::from_value(raw.clone())
            .map_err(|_| OobError::malformed("not a Trust Task document"))?;
        self.envelope(env, &doc, type_uri)?;
        let issuer = doc.issuer.as_deref().unwrap_or_default();
        let Some(multikey) = issuer.strip_prefix("did:key:") else {
            return Err(OobError::new(
                OobErrorCode::KeyUnsupported,
                "Ed25519 did:key only",
            ));
        };
        if !is_ed25519_multikey(multikey) {
            return Err(OobError::new(
                OobErrorCode::KeyUnsupported,
                "Ed25519 did:key only",
            ));
        }
        let Some(proof) = &doc.proof else {
            return Err(OobError::not_authorized());
        };
        if proof.verification_method != format!("{issuer}#{multikey}") {
            return Err(OobError::not_authorized());
        }
        if let Err(e) = ProofVerifier::verify(&self.key_verifier, &doc).await {
            tracing::debug!(error = %e, "auth/oob key proof refused");
            return Err(OobError::not_authorized());
        }
        let payload: P = serde_json::from_value(doc.payload.clone())
            .map_err(|e| OobError::malformed(format!("payload: {e}")))?;
        Ok((doc, payload))
    }

    /// Type, `id`, `issuer`, `recipient` and freshness.
    fn envelope(
        &self,
        env: &dyn OobEnv,
        doc: &TrustTask<Value>,
        type_uri: &str,
    ) -> Result<(), OobError> {
        if doc.type_uri.to_string() != type_uri {
            return Err(OobError::malformed(format!("expected {type_uri}")));
        }
        if doc.id.is_empty() || doc.issuer.as_deref().unwrap_or_default().is_empty() {
            return Err(OobError::malformed("missing id or issuer"));
        }
        if doc.recipient.as_deref() != Some(self.config.service_did.as_str()) {
            return Err(OobError::not_authorized());
        }
        let now = env.now() as i64;
        let Some(issued_at) = doc.issued_at.map(|t| t.timestamp()) else {
            return Err(OobError::malformed("missing issuedAt"));
        };
        if issued_at > now + CLOCK_SKEW_SECS as i64
            || now - issued_at > MAX_DOCUMENT_AGE_SECS as i64
        {
            return Err(OobError::not_authorized());
        }
        if let Some(exp) = doc.expires_at
            && exp.timestamp() <= now
        {
            return Err(OobError::not_authorized());
        }
        Ok(())
    }

    /// Refuse a replayed `(issuer, id)`.
    fn fresh(&self, env: &dyn OobEnv, doc: &TrustTask<Value>) -> Result<(), OobError> {
        let now = env.now();
        if self.store.remember_document(
            doc.issuer.as_deref().unwrap_or_default(),
            &doc.id,
            now + SEEN_ID_TTL_SECS,
            now,
        ) {
            Ok(())
        } else {
            Err(OobError::new(
                OobErrorCode::NotAuthorized,
                "document id already used",
            ))
        }
    }

    /// The record, with an elapsed deadline applied.
    fn current(&self, env: &dyn OobEnv, request_id: &str) -> Result<OobRecord, OobError> {
        loop {
            let rec = self
                .store
                .get(request_id)
                .ok_or_else(|| OobError::new(OobErrorCode::RequestNotFound, "no such request"))?;
            let now = env.now();
            if !rec.lapsed(now) {
                return Ok(rec);
            }
            let next = rec.next(OobState::Expired, now);
            if self.store.compare_and_set(rec.version, next.clone()) {
                tracing::info!(audit = true, op = "auth/oob/expire", request_id = %request_id, "sign-in request expired");
                return Ok(next);
            }
        }
    }

    fn lock_holder_record(
        &self,
        env: &dyn OobEnv,
        request_id: &str,
        issuer: &str,
        expected: OobState,
    ) -> Result<OobRecord, OobError> {
        let rec = self.current(env, request_id)?;
        if rec.approver_key.as_deref() != Some(issuer) {
            return Err(OobError::new(OobErrorCode::NotClaimant, "not the claimant"));
        }
        if rec.state == OobState::Expired {
            return Err(OobError::new(
                OobErrorCode::RequestExpired,
                "request expired",
            ));
        }
        if rec.state != expected {
            let code = if expected == OobState::Identified {
                OobErrorCode::AlreadyDecided
            } else {
                OobErrorCode::RequestExpired
            };
            return Err(OobError::new(
                code,
                format!("request is {}", rec.state.as_str()),
            ));
        }
        Ok(rec)
    }

    /// Move `rec` to `declined` (best effort: a lost race means someone else
    /// already ended it) and return `err`.
    fn decline(&self, env: &dyn OobEnv, rec: &OobRecord, err: OobError, op: &str) -> OobError {
        let _ = self
            .store
            .compare_and_set(rec.version, rec.next(OobState::Declined, env.now()));
        tracing::info!(audit = true, op = %op, request_id = %rec.request_id, code = err.code.as_str(), "sign-in request declined");
        err
    }

    fn step1(&self, rec: &OobRecord) -> Step1Response {
        Step1Response {
            request_id: rec.request_id.clone(),
            service: ServiceRef {
                did: self.config.service_did.clone(),
                name: self.config.service_name.clone(),
            },
            origin: rec.origin.clone(),
            purpose: rec.purpose.clone(),
            decision_deadline: rec.decision_deadline.unwrap_or_default(),
        }
    }

    /// A response document to `request`, signed for `purpose`.
    async fn signed(
        &self,
        env: &dyn OobEnv,
        request: &TrustTask<Value>,
        recipient: &str,
        payload: Value,
        purpose: &str,
    ) -> Result<Value, OobError> {
        let unsigned = json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": format!("{}#response", request.type_uri),
            "issuer": self.config.service_did,
            "recipient": recipient,
            "issuedAt": rfc3339(env.now()),
            "threadId": request.id,
            "payload": payload,
        });
        env.sign(unsigned, purpose).await.map_err(|e| {
            tracing::error!(error = %e, "auth/oob: could not sign the response");
            OobError::new(
                OobErrorCode::MalformedRequest,
                "the service could not sign its response",
            )
        })
    }

    /// An unsigned `trust-task-error` document (only errors stay unsigned).
    pub fn error_document(&self, env: &dyn OobEnv, raw: &Value, err: &OobError) -> Value {
        let mut payload = json!({ "code": err.code.as_str(), "message": err.message });
        if let Some(d) = &err.details {
            payload["details"] = d.clone();
        }
        let mut doc = json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": did_hosting_common::server::trust_tasks::framework_error_type_uri().to_string(),
            "issuer": self.config.service_did,
            "issuedAt": rfc3339(env.now()),
            "payload": payload,
        });
        if let Some(id) = raw.get("id").and_then(|v| v.as_str()) {
            doc["threadId"] = json!(id);
        }
        if let Some(iss) = raw.get("issuer").and_then(|v| v.as_str()) {
            doc["recipient"] = json!(iss);
        }
        doc
    }
}

/// The proof purpose of the step 1 and step 2 responses (C5).
const ATTESTATION: &str = "assertionMethod";
/// The proof purpose of every other response (this service's rule for its
/// own operational messages).
const OPERATIONAL: &str = "authentication";

/// Facts about the HTTP connection, which the documents cannot carry.
#[derive(Debug, Clone, Default)]
pub struct Connection {
    /// Egress IP. Used only to compute `sameNetwork`; never returned.
    pub ip: Option<String>,
    /// City and country from a local GeoIP lookup, or `None`.
    pub location: Option<String>,
    pub browser: Option<String>,
    pub os: Option<String>,
}

fn carried(payload: &Value, member: &str) -> Result<Value, OobError> {
    let obj = payload
        .as_object()
        .ok_or_else(|| OobError::malformed("payload must be an object"))?;
    if obj.keys().any(|k| k != member && k != "ext") {
        return Err(OobError::malformed(format!(
            "payload must be exactly {{{member}}}"
        )));
    }
    obj.get(member)
        .filter(|v| v.is_object())
        .cloned()
        .ok_or_else(|| OobError::malformed(format!("payload.{member} missing")))
}

/// `prove` and `respond` SHOULD carry `parentThreadId` (C9); when they do,
/// it must name the request.
fn same_thread(doc: &TrustTask<Value>, request_id: &str) -> Result<(), OobError> {
    match doc.parent_thread_id.as_deref() {
        Some(p) if p != request_id => Err(OobError::malformed(
            "parentThreadId must equal the requestId",
        )),
        _ => Ok(()),
    }
}

fn carried_request_id(doc: &Value) -> Result<String, OobError> {
    doc.get("payload")
        .and_then(|p| p.get("requestId"))
        .and_then(|v| v.as_str())
        .filter(|s| is_request_id(s))
        .map(str::to_string)
        .ok_or_else(|| OobError::malformed("carried requestId missing"))
}

/// 16 random bytes, unpadded base64url: 22 characters (C1, VTI-LNK-103).
pub fn new_request_id() -> String {
    let bytes: [u8; 16] = rand::random();
    let s = multibase::encode(multibase::Base::Base64Url, bytes);
    s[1..].to_string()
}

fn is_request_id(s: &str) -> bool {
    (22..=43).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Two uniformly random digits, "00" to "99".
fn two_digits() -> String {
    format!("{:02}", rand::random_range(0..100u8))
}

/// RFC 3339 UTC at whole seconds.
pub fn rfc3339(epoch: u64) -> String {
    chrono::DateTime::from_timestamp(epoch as i64, 0)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// The redeem response's `displayName` (required, 1 to 128 characters): the
/// ACL label, else the DID, shortened if it has to be.
fn display_name_or_did(label: Option<&str>, did: &str) -> String {
    let name = label.filter(|l| !l.trim().is_empty()).unwrap_or(did);
    if name.chars().count() <= 128 {
        name.to_string()
    } else {
        let mut s: String = name.chars().take(127).collect();
        s.push('…');
        s
    }
}

/// `contextDigest` (C9): SHA-256 of the JCS-canonical signed step 2 response,
/// proof included, as a sha2-256 multihash in base58btc multibase (`z…`).
pub fn context_digest(signed_step2: &Value) -> String {
    let canonical =
        serde_json_canonicalizer::to_vec(signed_step2).expect("a JSON value canonicalises");
    let digest = Sha256::digest(&canonical);
    let mut mh = Vec::with_capacity(34);
    mh.extend_from_slice(&[0x12, 0x20]);
    mh.extend_from_slice(&digest);
    multibase::encode(multibase::Base::Base58Btc, mh)
}

/// The 32 digest bytes of a context digest: a `z` (base58btc) or `u`
/// (base64url) sha2-256 multihash. Nothing else: the schema type is
/// `DigestMultibase` (C9).
fn decode_digest(s: &str) -> Option<Vec<u8>> {
    if !(s.starts_with('z') || s.starts_with('u')) {
        return None;
    }
    let (_, bytes) = multibase::decode(s).ok()?;
    (bytes.len() == 34 && bytes[0] == 0x12 && bytes[1] == 0x20).then(|| bytes[2..].to_vec())
}

/// Compare two context digests by their bytes, in constant time.
pub fn context_digests_equal(a: &str, b: &str) -> bool {
    match (decode_digest(a), decode_digest(b)) {
        (Some(x), Some(y)) if x.len() == y.len() => {
            x.iter().zip(&y).fold(0u8, |acc, (p, q)| acc | (p ^ q)) == 0
        }
        _ => false,
    }
}
