//! `server/register`: an edge registering itself (or re-registering) with the
//! control plane, and the refusals it can earn.

use super::*;

// ---------------------------------------------------------------------------
// Server registration handler
// ---------------------------------------------------------------------------

/// Why an infrastructure core (registration, stats sync) refused a document.
/// Each kind reaches the edge as its own standard code, so it can tell "not
/// authorised" from "malformed" from "too large" without reading prose.
#[derive(Debug)]
pub(crate) enum InfraRejection {
    /// The signer may not do this: it is not in the ACL, or not a Service
    /// (`permissionDenied`).
    NotAuthorised(String),
    /// The payload is not one this service reads (`malformedRequest`).
    Malformed(String),
    /// The payload names a server other than the one that signed it
    /// (`identityMismatch`).
    SenderMismatch { claimed: String, signer: String },
    /// The payload is over what one document may carry (`taskFailed`, with
    /// `details.limit`).
    TooLarge { message: String, limit: usize },
    /// What the payload asks for is held by someone else (`taskFailed`).
    Conflict(String),
    /// Not about the document at all: a failure of this service, reported as
    /// `unavailable` (retry) or `internalError`.
    Failed(Box<trust_tasks_rs::RejectReason>),
}

impl InfraRejection {
    pub(in crate::messaging) fn not_authorised(message: impl Into<String>) -> Self {
        Self::NotAuthorised(message.into())
    }

    pub(in crate::messaging) fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }

    pub(in crate::messaging) fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict(message.into())
    }

    /// The sender's role could not be read (a throttled store, say). That is
    /// no answer about the sender, so it is not refused as unauthorised: it
    /// is told to retry, or that the failure was ours.
    pub(in crate::messaging) fn lookup_failed(
        e: &did_hosting_common::server::error::AppError,
    ) -> Self {
        Self::Failed(Box::new(e.failure_reject_reason()))
    }

    /// The refusal that goes on the wire.
    pub(crate) fn reject_reason(&self) -> trust_tasks_rs::RejectReason {
        use trust_tasks_rs::RejectReason;
        match self {
            Self::NotAuthorised(reason) => RejectReason::PermissionDenied {
                reason: reason.clone(),
            },
            Self::Malformed(reason) => RejectReason::MalformedRequest {
                reason: reason.clone(),
            },
            Self::SenderMismatch { claimed, signer } => {
                RejectReason::IdentityMismatch(trust_tasks_rs::ConsistencyError::IssuerMismatch {
                    in_band: claimed.clone(),
                    transport: signer.clone(),
                })
            }
            Self::TooLarge { message, limit } => RejectReason::TaskFailed {
                reason: message.clone(),
                details: Some(json!({ "limit": limit })),
            },
            Self::Conflict(reason) => RejectReason::TaskFailed {
                reason: reason.clone(),
                details: None,
            },
            Self::Failed(reason) => (**reason).clone(),
        }
    }
}

impl std::fmt::Display for InfraRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAuthorised(m) => write!(f, "not authorised: {m}"),
            Self::Malformed(m) => write!(f, "malformed: {m}"),
            Self::SenderMismatch { claimed, signer } => {
                write!(f, "payload names {claimed} but {signer} signed it")
            }
            Self::TooLarge { message, .. } => write!(f, "too large: {message}"),
            Self::Conflict(m) => write!(f, "conflict: {m}"),
            Self::Failed(reason) => write!(f, "failed: {reason}"),
        }
    }
}

/// The sender's role, for the edge-facing tasks that require Service:
/// `Ok(true)` for Service, `Ok(false)` for any other answer from the ACL,
/// `Err` when the ACL could not be read.
pub(in crate::messaging) async fn is_service(
    state: &AppState,
    signer: &str,
) -> Result<bool, did_hosting_common::server::error::AppError> {
    match check_acl(&state.acl_ks, signer).await {
        Ok(role) => Ok(role == did_hosting_common::server::acl::Role::Service),
        Err(e) if did_hosting_common::server::acl::is_acl_refusal(&e) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Transport-agnostic core of server registration, for the
/// `.../server/register/0.2` trust task arriving over DIDComm **or** TSP.
///
/// The payload must parse as the generated `server/register/0.2` type (it is
/// closed: an unknown member is refused, not dropped), `did` must be the
/// signer and `instanceId` the signer's registry key. This service's own hints
/// ride under `ext` in [`REGISTER_EXT_NAMESPACE`].
///
/// `signer` is the registration document's proven issuer — the DID whose key
/// signed it — so a server is registered, and synced every tenant's DIDs, only
/// on its own signature. Returns the ack body on success.
///
/// The stages, in order: the signer's role ([`require_service_role`]), the
/// payload ([`parse_registration`]), the registry id
/// ([`previous_registration`]), the URL allowlist, the served domains
/// ([`assigned_served_domains`]), the record ([`upsert_registration`]), then
/// the badge refresh and resync ([`after_server_registration`]).
pub(crate) async fn do_server_register(
    state: &AppState,
    signer: &str,
    body: &Value,
) -> Result<
    did_hosting_common::tasks::did_management::server::register::v0_2::Response,
    InfraRejection,
> {
    use crate::registry::{self, ServiceInstance, ServiceStatus, ServiceType};

    let role = require_service_role(state, signer).await?;
    let (payload, instance_id) = parse_registration(signer, body)?;
    let previous = previous_registration(state, signer, &instance_id).await?;
    // This service's hints (`ext`, in its namespace). A server that sends none
    // gets the conservative defaults: single sync frames and a full sync.
    let hints = payload
        .ext
        .as_ref()
        .and_then(|ext| {
            ext.iter()
                .find(|(k, _)| k.as_str() == REGISTER_EXT_NAMESPACE)
                .map(|(_, v)| v.clone())
        })
        .unwrap_or(Value::Null);
    let public_url = payload.public_url.as_str();

    // Apply the same URL allowlist `registry/admin-register` enforces, so an
    // ACL'd Service-role caller cannot record an arbitrary URL
    // (cloud-metadata IP, RFC1918, attacker-controlled host) in the registry.
    if let Err(e) =
        registry::validate_registered_url(public_url, &state.config.registry.url_allowlist)
    {
        warn!(
            did = signer,
            requested = public_url,
            "server registration rejected: URL host not in registry.url_allowlist",
        );
        return Err(InfraRejection::not_authorised(e.user_message()));
    }

    let label = payload.label.as_ref().map(|l| l.to_string());

    // Parse the capability declaration. Backwards-compat: servers that
    // predate it don't send these fields; default to webvh-only.
    let enabled_methods: Vec<String> = if payload.enabled_methods.is_empty() {
        vec!["webvh".to_string()]
    } else {
        payload
            .enabled_methods
            .iter()
            .map(|m| m.to_string())
            .collect()
    };
    let served_domains = assigned_served_domains(
        state,
        signer,
        payload.served_domains.clone(),
        previous.as_ref(),
    )
    .await?;
    let protocol_version = payload
        .protocol_version
        .as_ref()
        .map_or_else(|| "1.0".to_string(), |v| v.to_string());

    let sync_batch_capable = hints
        .get("sync_batch")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // `register_instance` overwrites the whole record, so `previous` (read
    // above) carries the badge cache forward rather than blanking it. The
    // refresh below re-resolves and supersedes this; if that resolve fails,
    // the operator keeps seeing the last known services instead of an empty
    // badge row.

    let resync_domains = served_domains.clone();
    let build = |previous: Option<ServiceInstance>| ServiceInstance {
        instance_id: instance_id.clone(),
        service_type: ServiceType::Server,
        label,
        url: public_url.to_string(),
        status: ServiceStatus::Active,
        last_health_check: None,
        registered_at: crate::auth::session::now_epoch(),
        metadata: json!({ "did": signer }),
        enabled_methods,
        served_domains,
        protocol_version,
        advertised_services: previous
            .as_ref()
            .and_then(|p| p.advertised_services.clone()),
        services_checked_at: previous.as_ref().and_then(|p| p.services_checked_at),
        sync_batch_capable,
        // `register_instance` overwrites the whole record, so the observed-link
        // history has to survive a re-register exactly as the badge cache does.
        // The caller records *this* registration's inbound transport right
        // after; the outbound side has no other source and would otherwise be
        // blanked every time a server restarts.
        last_inbound_transport: previous.as_ref().and_then(|p| p.last_inbound_transport),
        last_inbound_at: previous.as_ref().and_then(|p| p.last_inbound_at),
        last_outbound_transport: previous.as_ref().and_then(|p| p.last_outbound_transport),
        last_outbound_at: previous.as_ref().and_then(|p| p.last_outbound_at),
        last_ack_at: previous.as_ref().and_then(|p| p.last_ack_at),
        last_reconcile_at: previous.as_ref().and_then(|p| p.last_reconcile_at),
    };
    upsert_registration(state, signer, &instance_id, build).await?;

    info!(
        did = signer,
        instance_id = %instance_id,
        public_url = public_url,
        role = %role,
        "server registered"
    );

    after_server_registration(state, signer, &instance_id, &hints, resync_domains).await;

    Ok(
        did_hosting_common::tasks::did_management::server::register::v0_2::Response::builder()
            .accepted(true)
            .instance_id(instance_id)
            .last_seen_at(chrono::SubsecRound::trunc_subsecs(chrono::Utc::now(), 0))
            .try_into()
            .expect("a register ack is well formed"),
    )
}

/// Require a pre-approved ACL entry with the Service role. An Owner-role DID
/// must not be able to register as a server: registration triggers
/// `sync_all_dids_to_server`, which would push every tenant's DID log +
/// witness content to the caller's inbox and add them to the active-server
/// registry so future `notify_servers_did` updates also reach them.
///
/// Decided before the payload is read, so a signer without the role learns
/// nothing about what a registration must carry.
async fn require_service_role(
    state: &AppState,
    signer: &str,
) -> Result<did_hosting_common::server::acl::Role, InfraRejection> {
    use did_hosting_common::server::acl::check_acl;

    match check_acl(&state.acl_ks, signer).await {
        Ok(did_hosting_common::server::acl::Role::Service) => {
            Ok(did_hosting_common::server::acl::Role::Service)
        }
        Ok(other) => {
            warn!(
                did = signer,
                role = %other,
                "server registration rejected: Service role required"
            );
            Err(InfraRejection::not_authorised(
                "service role required to register as a server",
            ))
        }
        Err(e) if !did_hosting_common::server::acl::is_acl_refusal(&e) => {
            warn!(did = signer, error = %e, "server registration deferred: ACL lookup failed");
            Err(InfraRejection::lookup_failed(&e))
        }
        Err(_) => {
            warn!(
                did = signer,
                "server registration rejected: DID not in ACL (requires pre-approval)"
            );
            Err(InfraRejection::not_authorised(
                "server DID must be pre-approved in the ACL before registering",
            ))
        }
    }
}

/// The registration payload, which must name its signer: `did` is the
/// signer and `instanceId` the signer's registry key (one registration per
/// DID). Returns the payload and that registry key.
fn parse_registration(
    signer: &str,
    body: &Value,
) -> Result<
    (
        did_hosting_common::tasks::did_management::server::register::v0_2::Payload,
        String,
    ),
    InfraRejection,
> {
    let payload: did_hosting_common::tasks::did_management::server::register::v0_2::Payload =
        serde_json::from_value(body.clone()).map_err(|e| {
            warn!(did = signer, error = %e, "server registration rejected: malformed payload");
            InfraRejection::malformed(format!("not a server/register/0.2 payload: {e}"))
        })?;
    // Use the signer DID as a stable instance ID (one registration per DID).
    let instance_id = crate::registry::instance_id_for(signer);
    if payload.did.as_str() != signer || payload.instance_id.as_str() != instance_id {
        warn!(
            did = signer,
            "server registration rejected: did/instanceId do not name the signer"
        );
        return Err(InfraRejection::malformed(format!(
            "`did` must be the signer and `instanceId` must be `{instance_id}`"
        )));
    }
    Ok((payload, instance_id))
}

/// The record already under `instance_id`, if it is `signer`'s own. The
/// registry id is not one-to-one with DIDs (`instance_id_for`): a record
/// under this id that another DID registered stays that DID's.
async fn previous_registration(
    state: &AppState,
    signer: &str,
    instance_id: &str,
) -> Result<Option<crate::registry::ServiceInstance>, InfraRejection> {
    let previous = match crate::registry::get_instance(&state.registry_ks, instance_id).await {
        Ok(previous) => previous,
        Err(e) => {
            warn!(did = signer, error = %e, "server registration deferred: registry lookup failed");
            return Err(InfraRejection::lookup_failed(&e));
        }
    };
    if let Some(holder) = previous.as_ref().and_then(|p| p.did())
        && holder != signer
    {
        warn!(
            did = signer,
            holder, instance_id, "server registration rejected: instance id held by another DID"
        );
        return Err(InfraRejection::conflict(
            "another server's registration holds this instance id",
        ));
    }
    Ok(previous)
}

/// The domains of `claimed` the server is kept as serving.
///
/// A server's claim to serve a domain is kept only if the control plane
/// assigned it the domain: its latest recorded domain operation for this
/// server is an assign (`server_push::DomainIntent`). A claim to a domain
/// the control plane has no record of, or assigned to another server only,
/// is dropped, so it cannot block `registry/purge-domain` with
/// `STILL_ASSIGNED` or mislead the purge fan-out.
///
/// A server with no recorded domain operation at all was assigned its
/// domains before they were recorded: it keeps a claim the registry
/// already listed for it, and nothing new.
async fn assigned_served_domains(
    state: &AppState,
    signer: &str,
    claimed: Vec<String>,
    previous: Option<&crate::registry::ServiceInstance>,
) -> Result<Vec<String>, InfraRejection> {
    if claimed.is_empty() {
        return Ok(Vec::new());
    }
    let intents = match crate::server_push::domain_intents(state, signer).await {
        Ok(intents) => intents,
        Err(e) => {
            warn!(did = signer, error = %e, "server registration deferred: domain intents lookup failed");
            return Err(InfraRejection::lookup_failed(&e));
        }
    };
    let assigned = |name: &str| {
        if intents.is_empty() {
            previous.is_some_and(|p| p.served_domains.iter().any(|d| d == name))
        } else {
            intents
                .iter()
                .any(|i| i.domain == name && i.op == crate::server_push::DomainOp::Assign)
        }
    };
    let mut keep = Vec::with_capacity(claimed.len());
    for name in claimed {
        if !assigned(&name) {
            warn!(
                did = signer,
                domain = %name,
                "register: dropping served_domains entry — this server was not assigned the domain"
            );
            continue;
        }
        match did_hosting_common::server::domain::get_domain(&state.store, &name).await {
            Ok(Some(_)) => keep.push(name),
            Ok(None) => warn!(
                did = signer,
                domain = %name,
                "register: dropping served_domains entry — control plane has no DomainEntry for this name"
            ),
            Err(e) => warn!(
                did = signer,
                domain = %name,
                error = %e,
                "register: failed to look up DomainEntry during served_domains validation — dropping entry"
            ),
        }
    }
    Ok(keep)
}

/// Write the registration `build` makes from the record as it stands under
/// the instance's lock, so a pong or ack recorded since the previous record
/// was read is carried forward too. A record another DID took meanwhile is
/// left alone, and refused as a conflict.
async fn upsert_registration(
    state: &AppState,
    signer: &str,
    instance_id: &str,
    build: impl FnOnce(Option<crate::registry::ServiceInstance>) -> crate::registry::ServiceInstance,
) -> Result<(), InfraRejection> {
    let written =
        crate::registry::upsert_instance(&state.registry_ks, instance_id, |current| match current
            .as_ref()
            .and_then(|c| c.did())
        {
            Some(holder) if holder != signer => None,
            _ => Some(build(current)),
        })
        .await;
    let written = match written {
        Ok(Some(instance)) if instance.did() == Some(signer) => Ok(()),
        Ok(_) => {
            warn!(
                did = signer,
                instance_id, "server registration rejected: instance id taken meanwhile"
            );
            return Err(InfraRejection::conflict(
                "another server's registration holds this instance id",
            ));
        }
        Err(e) => Err(e),
    };
    if let Err(e) = written {
        warn!(did = signer, error = %e, "server registration failed");
        // The store's own text stays in the log: it describes this service,
        // not the request.
        return Err(InfraRejection::Failed(Box::new(e.failure_reject_reason())));
    }
    Ok(())
}

/// What follows a written registration: the badge cache, then the resync.
async fn after_server_registration(
    state: &AppState,
    signer: &str,
    instance_id: &str,
    hints: &Value,
    resync_domains: Vec<String>,
) {
    // Cache what the registering server's DID document advertises, so the
    // Servers list can badge it. Best-effort: a registration must not fail
    // because the DID momentarily won't resolve.
    if let Err(e) = crate::registry::refresh_advertised_services(
        &state.registry_ks,
        instance_id,
        state.did_resolver.as_ref(),
        crate::auth::session::now_epoch(),
    )
    .await
    {
        warn!(
            did = signer,
            error = %e,
            "failed to cache advertised services for registering server"
        );
    }

    // Sync DIDs to the newly registered server — only the ones it doesn't
    // already have. The server reports what it holds in `preloaded_dids`
    // (mnemonic → DID + version_count); anything absent, stale, or a different
    // DID at that slot is pushed. A server with an empty store sends none and
    // gets a full push. This is what stops a reboot from re-syncing every DID.
    //
    // Domains first, then DIDs, in one task: the order their rows queue in
    // for this server is then deterministic.
    let reported = server_push::parse_reported(hints);
    server_push::resync_server(state, signer.to_string(), reported, resync_domains);
}
