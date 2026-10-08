//! The control plane's Trust Task table.
//!
//! Every task this module serves is one row of [`control_tasks!`], keyed on the
//! generated `Payload::TYPE_URI` and typed end to end: the request is narrowed
//! into the generated `Payload` (so an unknown or misspelt member is refused,
//! `deny_unknown_fields`), and the handler returns the generated `Response`, so
//! a reply cannot leave this module in a shape its schema does not allow. The
//! reply is wrapped with `respond_with`, which keeps the request's thread,
//! parent thread and ceremony.
//!
//! Errors are `trust-task-error` documents. A handler raises a [`TaskError`];
//! an [`AppError`] is mapped onto the code the task's own specification
//! declares for that failure (`notFound`, `notOwner`, `did-management:
//! unknownDomain`, …) when it declares one, and onto the closest standard code
//! when it does not. Internal failures never carry their detail onto the wire.
//!
//! What this module does not do is decide who may send a document. That is
//! the gate in `messaging::route_trust_task_doc`, which runs before any row
//! here and reads each row's [`ProofRule`]. The handlers authorise on
//! [`Cx::auth`] — the proven issuer and its ACL role — and never on anything a
//! transport reported.

use serde::de::DeserializeOwned;
use serde_json::Value;
use tracing::warn;
use trust_tasks_rs::{
    DeclaredErrorCode, Dispatcher, ErrorPayload, ErrorResponse, ProofPolicy, ProofVerifier,
    RequestPayload, ResolvedParties, StandardCode, TransportHandler, TrustTask,
};

use did_hosting_common::did_ops::DidRecord;
use did_hosting_common::server::error::{AgentNameError, ValidationKind};
use did_hosting_common::server::trust_tasks::{DispatchOutcome, ProofRule, run_pipeline};

use crate::acl::check_acl;
use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;

pub(crate) mod agent_name;
pub(crate) mod auth;
pub(crate) mod did;
pub(crate) mod domain;
pub(crate) mod enrol;
#[cfg(test)]
mod enrol_tests;
#[cfg(test)]
pub(crate) mod harness;
pub(crate) mod passkey;
pub(crate) mod queries;
pub(crate) mod registry;
pub(crate) mod server;
#[cfg(test)]
pub(crate) mod soft_passkey;
#[cfg(test)]
mod tests;

use trust_tasks_rs::specs::{
    auth::{
        passkey::{
            admin_list as tt_pk_admin_list, enroll as tt_enroll, enroll::invite as tt_invite,
            list as tt_pk_list, login as tt_login, revoke as tt_pk_revoke,
        },
        revoke_session as tt_revoke_session, step_up as tt_step_up,
    },
    did_management::{
        agent_name as tt_agent_name, did as tt_did, domain as tt_domain, identity as tt_identity,
        me as tt_me, registry as tt_registry, server as tt_server, stats as tt_stats,
    },
    webvh::witness as tt_witness,
};

/// One row per served task: `module => proof rule, handler;`.
///
/// Expands to [`TASKS`] — the Type URIs and their proof rules, which the gate
/// and the tests read — and [`route`], which narrows a document into the
/// row's generated `Payload` and runs its handler. There is no second list to
/// keep in step: a task is served exactly when it has a row.
macro_rules! control_tasks {
    ($( $($seg:ident)::+ => $rule:ident, $handler:path; )*) => {
        /// Every Trust Task [`route`] serves, with the proof it requires.
        pub(crate) const TASKS: &[(&str, ProofRule)] = &[
            $( (<$($seg)::+::Payload as trust_tasks_rs::Payload>::TYPE_URI, ProofRule::$rule), )*
        ];

        /// Run `doc` through its row, or hand it back when no row claims it.
        pub(crate) async fn route<V>(
            state: &AppState,
            bearer: Option<&AuthClaims>,
            transport: &(impl TransportHandler + Sync),
            policy: ProofPolicy<'_, V>,
            doc: TrustTask<Value>,
        ) -> Result<DispatchOutcome, Box<TrustTask<Value>>>
        where
            V: ProofVerifier + ?Sized,
        {
            let type_uri = doc.type_uri.to_string();
            $(
                if type_uri == <$($seg)::+::Payload as trust_tasks_rs::Payload>::TYPE_URI {
                    return Ok(
                        serve::<$($seg)::+::Payload, _>(
                            state,
                            bearer,
                            transport,
                            policy,
                            doc,
                            $($seg)::+::ERROR_CODES,
                            $handler,
                        )
                        .await,
                    );
                }
            )*
            Err(Box::new(doc))
        }
    };
}

control_tasks! {
    // DID slots.
    tt_did::check_name::v0_1 => Authentication, did::check_name;
    tt_did::register::v0_1 => Authentication, did::register;
    tt_did::info::v0_1 => Authentication, did::info;
    tt_did::list::v0_1 => Authentication, did::list;
    tt_did::delete::v0_1 => Authentication, did::delete;
    tt_did::change_owner::v0_1 => Authentication, did::change_owner;
    tt_did::set_state::v0_1 => Authentication, did::set_state;
    tt_did::rollback::v0_1 => Authentication, did::rollback;
    tt_did::log::v0_1 => Authentication, did::log;
    tt_witness::publish::v0_1 => Authentication, did::witness_publish;
    // Agent names.
    tt_agent_name::update::v0_1 => Authentication, agent_name::update;
    tt_agent_name::remove::v0_1 => Authentication, agent_name::remove;
    tt_agent_name::list::v0_1 => Authentication, agent_name::list;
    tt_agent_name::check::v0_1 => Authentication, agent_name::check;
    tt_agent_name::resolve::v0_1 => Authentication, agent_name::resolve;
    // Hosting domains.
    tt_me::domains::v0_1 => Authentication, domain::me_domains;
    tt_domain::list::v0_1 => Authentication, domain::list;
    tt_domain::create::v0_1 => Authentication, domain::create;
    tt_domain::update::v0_1 => Authentication, domain::update;
    tt_domain::set_state::v0_1 => Authentication, domain::set_state;
    tt_domain::set_default::v0_1 => Authentication, domain::set_default;
    tt_domain::purge::v0_1 => Authentication, domain::purge;
    tt_domain::assign::v0_1 => Authentication, domain::assign;
    tt_domain::unassign::v0_1 => Authentication, domain::unassign;
    // The fleet.
    tt_registry::list::v0_1 => Authentication, registry::list;
    tt_registry::get::v0_1 => Authentication, registry::get;
    tt_registry::check::v0_1 => Authentication, registry::check;
    tt_registry::admin_register::v0_1 => Authentication, registry::admin_register;
    tt_registry::deregister::v0_1 => Authentication, registry::deregister;
    tt_registry::purge_domain::v0_1 => Authentication, registry::purge_domain;
    // The service itself.
    tt_server::info::v0_1 => Optional, server::info;
    tt_server::config::v0_1 => Authentication, server::config;
    tt_server::metrics::v0_1 => Authentication, server::metrics;
    tt_stats::get::v0_1 => Authentication, server::stats_get;
    tt_stats::timeseries::v0_1 => Authentication, server::timeseries;
    tt_identity::list::v0_1 => Authentication, server::identity_list;
    tt_identity::retire::v0_1 => Authentication, server::identity_retire;
    // Step-up: the start is the session subject's operational request; the
    // decision is the approver's attestation.
    tt_step_up::start::v0_1 => Authentication, auth::step_up_start;
    tt_step_up::approve_response::v0_5 => AssertionMethod, auth::approve_response;
    // Logout: end one of the caller's own sessions, and any session key bound
    // to it.
    tt_revoke_session::v0_2 => Authentication, auth::revoke_session;
    // Passkey login: opening a ceremony authorises nothing; finishing one
    // mints a session for the did:key that signs it.
    tt_login::start::v0_2 => Optional, auth::login_start;
    tt_login::finish::v0_2 => SessionKey, auth::login_finish;
    // Passkey enrolment. An administrator's invite is an operational request;
    // redeeming it is not signed by anyone the service knows yet — the token
    // and the separately delivered claim code are the authorisation — so its
    // proof is optional (and verified when present). An authenticated
    // subject's own enrolment is signed as that subject.
    tt_invite::v0_2 => Authentication, enrol::invite;
    tt_enroll::redeem::start::v0_1 => Optional, enrol::redeem_start;
    tt_enroll::redeem::finish::v0_1 => Optional, enrol::redeem_finish;
    tt_enroll::start::v0_2 => Authentication, enrol::start;
    tt_enroll::finish::v0_2 => Authentication, enrol::finish;
    // Enrolment invites, addressed by inviteId.
    tt_invite::list::v0_1 => Authentication, enrol::invite_list;
    tt_invite::update::v0_1 => Authentication, enrol::invite_update;
    tt_invite::revoke::v0_1 => Authentication, enrol::invite_revoke;
    // Passkey management: a subject's own inventory, an administrator's
    // purpose-scoped read of another's, and revoking one — a re-
    // authentication ceremony like enrolment's own user-verification, not a
    // bare delete.
    tt_pk_list::v0_1 => Authentication, passkey::list;
    tt_pk_admin_list::v0_1 => Authentication, passkey::admin_list;
    tt_pk_revoke::start::v0_2 => Authentication, passkey::revoke_start;
    tt_pk_revoke::finish::v0_2 => Authentication, passkey::revoke_finish;
}

/// The proof rule for `type_uri`, when this table serves it.
pub(crate) fn proof_rule(type_uri: &str) -> Option<ProofRule> {
    TASKS
        .iter()
        .find(|(uri, _)| *uri == type_uri)
        .map(|(_, rule)| *rule)
}

/// Every Type URI this control plane dispatches: this table's rows plus
/// the ACL family `did_hosting_common::server::trust_tasks` routes.
///
/// The single "served" list `size::check` and
/// `size::largest_max_document_bytes` take — a type raised above the
/// default in `size::DECLARED` (`did/register`) is in force only while it
/// appears here, so a type this deployment does not actually route can't
/// buy an unauthenticated caller a larger body to canonicalise before it
/// is refused as unrouted.
///
/// Computed once: `TASKS` and `ACL_TASK_URIS` are both `'static`, but they
/// live in two different const arrays of two different shapes, and `const`
/// arithmetic can't concatenate them into one array whose length isn't
/// spelled out by hand.
pub(crate) static SERVED_TRUST_TASK_URIS: std::sync::LazyLock<Vec<&'static str>> =
    std::sync::LazyLock::new(|| {
        let mut uris: Vec<&'static str> = TASKS.iter().map(|(uri, _)| *uri).collect();
        uris.extend_from_slice(did_hosting_common::server::trust_tasks::ACL_TASK_URIS);
        uris
    });

/// Narrow `doc` into `P`, run the framework pipeline, and hand the typed
/// payload to `handler`.
async fn serve<P, V>(
    state: &AppState,
    bearer: Option<&AuthClaims>,
    transport: &(impl TransportHandler + Sync),
    policy: ProofPolicy<'_, V>,
    doc: TrustTask<Value>,
    codes: &'static [DeclaredErrorCode],
    handler: impl AsyncFnOnce(&Cx<'_>, P) -> Result<P::Response, TaskError>,
) -> DispatchOutcome
where
    P: RequestPayload + Clone + Send + Sync + 'static,
    P::Response: serde::Serialize,
    V: ProofVerifier + ?Sized,
{
    let Some(my_vid) = state.config.server_did.as_deref() else {
        return DispatchOutcome::Rejected(
            doc.reject_with(
                new_id(),
                ErrorPayload::new(StandardCode::InternalError)
                    .with_message("this service has no DID configured"),
            ),
        );
    };
    // SPEC §7.2 items 1–3 for this one type: the framework shape, then the
    // payload into its generated type. A payload that does not parse is
    // `malformedRequest`, addressed back to the issuer.
    let typed: TrustTask<P> = match Dispatcher::new()
        .on::<P, _>(|d| d)
        .dispatch_or_reject(doc, new_id())
    {
        Ok(typed) => typed,
        Err(err) => return DispatchOutcome::Rejected(err),
    };
    run_pipeline(
        transport,
        policy,
        typed,
        my_vid,
        |doc: TrustTask<P>, parties: ResolvedParties| async move {
            let cx = Cx {
                state,
                caller: parties.issuer.clone(),
                bearer,
                proof_vm: doc.proof.as_ref().map(|p| p.verification_method.clone()),
                proof_created: doc.proof.as_ref().map(|p| p.created),
                via: did_hosting_common::server::didcomm_profile::ObservedTransport::from_binding_uri(
                    transport.binding_uri(),
                ),
            };
            match handler(&cx, doc.payload.clone()).await {
                Ok(resp) => Ok(doc.respond_with(new_id(), resp)),
                Err(e) => Err(e.reject(&doc, codes)),
            }
        },
    )
    .await
}

/// What a handler sees of the request beyond its payload.
pub(crate) struct Cx<'a> {
    pub state: &'a AppState,
    /// The issuer the framework resolved. On every task that requires a proof
    /// this is the proven signer: the gate has refused anything else before a
    /// row runs.
    caller: Option<String>,
    /// The bearer session an HTTPS request presented, if any. Its assurance
    /// level applies only when its subject is the proven caller.
    bearer: Option<&'a AuthClaims>,
    /// The request proof's `verificationMethod`, when it carried a proof.
    pub proof_vm: Option<String>,
    /// The request proof's `created`, when it carried a proof.
    #[allow(dead_code)]
    pub proof_created: Option<chrono::DateTime<chrono::Utc>>,
    /// The transport the request arrived on, when it is one this service knows.
    #[allow(dead_code)]
    pub via: Option<did_hosting_common::server::didcomm_profile::ObservedTransport>,
}

impl Cx<'_> {
    /// The proven caller, or `permissionDenied` when there is none.
    #[allow(dead_code)] // the next stage's public reads use it
    pub fn caller(&self) -> Result<&str, TaskError> {
        self.caller.as_deref().ok_or_else(|| {
            TaskError::Standard(
                StandardCode::PermissionDenied,
                "the request carries no verified issuer".into(),
            )
        })
    }

    /// The bearer session the request presented, when it presented one.
    pub fn bearer_session(&self) -> Option<&AuthClaims> {
        self.bearer
    }

    /// [`Cx::auth`], refused with `permissionDenied` unless the caller is an
    /// administrator.
    pub async fn admin(&self) -> Result<AuthClaims, TaskError> {
        let auth = self.auth().await?;
        if auth.role != crate::acl::Role::Admin {
            return Err(TaskError::Standard(
                StandardCode::PermissionDenied,
                "this task requires administrator standing".into(),
            ));
        }
        Ok(auth)
    }

    /// [`Cx::auth`], refused with `permissionDenied` unless the caller is an
    /// administrator **or** a `MetricsReader`. The returned claims carry the
    /// caller's role so a handler can still narrow what it exposes (the
    /// `metrics` task gives a `MetricsReader` the counters only, gauges
    /// `Admin`-only).
    pub async fn metrics_read(&self) -> Result<AuthClaims, TaskError> {
        use crate::acl::Role;
        let auth = self.auth().await?;
        if !matches!(auth.role, Role::Admin | Role::MetricsReader) {
            return Err(TaskError::Standard(
                StandardCode::PermissionDenied,
                "this task requires administrator or metrics-reader standing".into(),
            ));
        }
        Ok(auth)
    }

    /// The caller's authority: the proven issuer and the role its ACL entry
    /// grants now. A document is a single signed request, not a session, so
    /// its assurance level is the base one — unless it arrived with a bearer
    /// session whose subject is that same caller, whose level (and session)
    /// it then carries.
    pub async fn auth(&self) -> Result<AuthClaims, TaskError> {
        let did = self.caller.as_deref().ok_or_else(|| {
            TaskError::Standard(
                StandardCode::PermissionDenied,
                "the request carries no verified issuer".into(),
            )
        })?;
        let role = check_acl(&self.state.acl_ks, did).await.map_err(|_| {
            TaskError::Standard(
                StandardCode::PermissionDenied,
                "caller is not present in the maintainer's ACL".into(),
            )
        })?;
        if let Some(bearer) = self.bearer.filter(|b| b.did == did) {
            return Ok(AuthClaims {
                role,
                ..bearer.clone()
            });
        }
        Ok(AuthClaims {
            did: did.to_string(),
            role,
            session_id: String::new(),
            session_pubkey_b58btc: None,
            amr: vec!["did".to_string()],
            acr: "aal1".to_string(),
        })
    }
}

/// A handler's failure, before it is addressed back to the requester.
#[derive(Debug)]
pub(crate) enum TaskError {
    /// A failure from the shared engine, mapped by [`TaskError::reject`].
    App(AppError),
    /// A code the task's specification declares.
    Declared(DeclaredErrorCode, String),
    /// A framework standard code.
    Standard(StandardCode, String),
}

impl From<AppError> for TaskError {
    fn from(e: AppError) -> Self {
        TaskError::App(e)
    }
}

impl From<serde_json::Error> for TaskError {
    fn from(e: serde_json::Error) -> Self {
        TaskError::App(AppError::Serialization(e))
    }
}

impl TaskError {
    /// A declared code by its local part, when `codes` has it.
    fn declared(codes: &'static [DeclaredErrorCode], locals: &[&str]) -> Option<DeclaredErrorCode> {
        locals
            .iter()
            .find_map(|local| codes.iter().find(|c| c.local() == *local))
            .copied()
    }

    /// The error payload for this failure, preferring a code the task's own
    /// specification declares.
    pub(crate) fn payload(self, codes: &'static [DeclaredErrorCode]) -> ErrorPayload {
        let (code, message) = match self {
            TaskError::Declared(code, message) => {
                return ErrorPayload::from(code).with_message(message);
            }
            TaskError::Standard(code, message) => {
                return ErrorPayload::new(code).with_message(message);
            }
            TaskError::App(e) => (map_app_error(&e, codes), e),
        };
        match code {
            Mapped::Declared(code) => ErrorPayload::from(code).with_message(message.user_message()),
            Mapped::Standard(StandardCode::InternalError) => {
                // The operator gets the detail; the wire gets nothing a caller
                // could learn the service's internals from.
                tracing::error!(error = %message, "trust task: internal failure");
                ErrorPayload::new(StandardCode::InternalError)
                    .with_message("the maintainer encountered an internal failure")
            }
            Mapped::Standard(StandardCode::Unavailable) => {
                let retry_after = match &message {
                    AppError::RateLimited {
                        retry_after_secs, ..
                    } => Some(
                        chrono::Utc::now() + chrono::Duration::seconds(*retry_after_secs as i64),
                    ),
                    _ => None,
                };
                let p = ErrorPayload::new(StandardCode::Unavailable)
                    .with_message(message.user_message());
                match retry_after {
                    Some(at) => p.with_retry_after(at),
                    None => p,
                }
            }
            Mapped::Standard(code) => ErrorPayload::new(code).with_message(message.user_message()),
        }
    }

    /// The `trust-task-error` document for this failure, addressed to the
    /// request's issuer.
    pub(crate) fn reject<P>(
        self,
        doc: &TrustTask<P>,
        codes: &'static [DeclaredErrorCode],
    ) -> ErrorResponse {
        doc.reject_with(new_id(), self.payload(codes))
    }
}

enum Mapped {
    Declared(DeclaredErrorCode),
    Standard(StandardCode),
}

/// Map a shared-engine failure onto the task's declared codes, falling back to
/// the standard code closest in meaning.
fn map_app_error(e: &AppError, codes: &'static [DeclaredErrorCode]) -> Mapped {
    let pick = |locals: &[&str], fallback: StandardCode| match TaskError::declared(codes, locals) {
        Some(code) => Mapped::Declared(code),
        None => Mapped::Standard(fallback),
    };
    match e {
        AppError::NotFound(_) => pick(&["notFound"], StandardCode::TaskFailed),
        AppError::Forbidden(_) | AppError::Unauthorized(_) | AppError::Authentication(_) => pick(
            &["notOwner", "forbidden", "notAuthorized"],
            StandardCode::PermissionDenied,
        ),
        AppError::StepUpRequired(_) => pick(&["stepUpRequired"], StandardCode::PermissionDenied),
        AppError::Conflict(_) => pick(
            &["pathTaken", "nameTaken", "alreadyExists", "conflict"],
            StandardCode::TaskFailed,
        ),
        AppError::Validation(message) => {
            if message.contains("unknown_domain") {
                return pick(&["unknownDomain"], StandardCode::MalformedRequest);
            }
            match e.validation_kind() {
                ValidationKind::InvalidLog => pick(
                    &["invalidLog", "invalidDidData"],
                    StandardCode::MalformedRequest,
                ),
                ValidationKind::InvalidPath => {
                    pick(&["invalidPath"], StandardCode::MalformedRequest)
                }
                ValidationKind::InvalidWitness => {
                    pick(&["invalidWitness"], StandardCode::MalformedRequest)
                }
                ValidationKind::Other => Mapped::Standard(StandardCode::MalformedRequest),
            }
        }
        AppError::QuotaExceeded(_) => pick(&["quotaExceeded"], StandardCode::TaskFailed),
        AppError::DomainDisabled { .. } => pick(&["domainDisabled"], StandardCode::TaskFailed),
        AppError::RateLimited { .. } => Mapped::Standard(StandardCode::Unavailable),
        AppError::AgentName(kind) => match kind {
            AgentNameError::Reserved => pick(&["nameReserved"], StandardCode::TaskFailed),
            AgentNameError::Taken => pick(&["nameTaken"], StandardCode::TaskFailed),
            AgentNameError::NotFound => pick(&["notFound"], StandardCode::TaskFailed),
            AgentNameError::AlsoKnownAsMismatch => {
                pick(&["alsoKnownAsMismatch"], StandardCode::MalformedRequest)
            }
            AgentNameError::NotDisabled | AgentNameError::AlreadyDisabled => {
                Mapped::Standard(StandardCode::TaskFailed)
            }
        },
        _ => Mapped::Standard(StandardCode::InternalError),
    }
}

pub(crate) fn new_id() -> String {
    format!("urn:uuid:{}", uuid::Uuid::new_v4())
}

/// The resolvable URL of a slot's log, from the configured hosting base.
pub(crate) fn did_url(state: &AppState, mnemonic: &str) -> String {
    let base_url = state
        .config
        .did_hosting_url
        .as_deref()
        .or(state.config.public_url.as_deref())
        .unwrap_or("http://localhost");
    format!("{}/{mnemonic}/did.jsonl", base_url.trim_end_matches('/'))
}

/// A stored record in any task's generated `DidRecord` type.
///
/// Every `did-management` task carries its own copy of the shared `DidRecord`
/// definition, so the projection is made once ([`crate::messaging::
/// spec_did_record_json`]) and read into the task's type — which, being
/// `deny_unknown_fields`, refuses the projection outright if it ever grows a
/// member the schema does not allow.
pub(crate) fn spec_record<T: DeserializeOwned>(
    state: &AppState,
    record: &DidRecord,
) -> Result<T, TaskError> {
    let value = crate::messaging::spec_did_record_json(record, &did_url(state, &record.mnemonic));
    serde_json::from_value(value).map_err(|e| {
        warn!(error = %e, mnemonic = %record.mnemonic, "DID record does not fit its schema");
        TaskError::App(AppError::Internal(format!(
            "DID record projection does not fit its schema: {e}"
        )))
    })
}

/// Read a value into a generated type, for response members built as JSON.
pub(crate) fn typed<T: DeserializeOwned>(value: Value, what: &str) -> Result<T, TaskError> {
    serde_json::from_value(value).map_err(|e| {
        TaskError::App(AppError::Internal(format!(
            "{what} does not fit its schema: {e}"
        )))
    })
}

/// RFC 3339 from the store's epoch seconds.
pub(crate) fn at(secs: u64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0).unwrap_or_default()
}
