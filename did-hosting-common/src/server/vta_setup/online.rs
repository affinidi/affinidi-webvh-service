//! Online provisioning: asking a reachable VTA for this service's DID over
//! DIDComm (`vta_sdk::provision_client`) and turning its reply into setup
//! outcomes.

use super::*;

// ---------------------------------------------------------------------------
// Online provision-integration helper
//
// Wraps the SDK's `vta_sdk::provision_client::run_provision` for the three
// webvh setup wizards. Each binary owns its own dialoguer prompts (config
// path, public URL, host/port, log/data dir, secrets backend, mediator
// choice, admin ACL) and calls into here for the VTA round-trip itself.
// ---------------------------------------------------------------------------

/// Inputs the consumer (each binary's setup wizard) gathers before
/// invoking the online provision-integration round-trip.
pub struct OnlineProvisionInputs {
    /// VTA DID the integration is provisioning into.
    pub vta_did: String,
    /// VTA context the integration will live in.
    pub context_id: String,
    /// Pre-built `ProvisionAsk` (e.g. from
    /// `ProvisionAsk::did_host_http` or `did_host_didcomm`).
    pub ask: vta_sdk::provision_client::ProvisionAsk,
    /// Per-binary user-facing labels and `pnm contexts create` command
    /// hint.
    pub messages: std::sync::Arc<dyn vta_sdk::provision_client::OperatorMessages>,
    /// Setup did:key the operator just enrolled at the VTA via the
    /// printed PNM command. The wizard mints + persists this; we
    /// consume it here.
    pub setup_key: vta_sdk::provision_client::EphemeralSetupKey,
}

/// Result of a successful online provision-integration round-trip,
/// flattened into the shape the wizard needs to write `ServerSecrets`,
/// `AppConfig`, the DID document log file, and the local DID store.
pub struct OnlineProvisionOutcome {
    /// Integration DID minted by the VTA (the binary's own service DID).
    pub integration_did: String,
    /// Multibase-encoded Ed25519 signing key for the integration DID.
    pub integration_signing_key_mb: String,
    /// Multibase-encoded X25519 key-agreement key for the integration DID.
    pub integration_ka_key_mb: String,
    /// `did.jsonl` content for the integration DID. Present when the
    /// template emitted a `WebvhLog` output (every webvh template does
    /// today).
    pub did_log_entry: Option<String>,
    /// Long-term admin DID. Equals the rolled-over DID minted by the
    /// VTA's `vta-admin` template render; the ephemeral setup DID is
    /// throwaway after this point.
    pub admin_did: String,
    /// Multibase-encoded Ed25519 private key paired with `admin_did`.
    pub admin_signing_key_mb: String,
    /// VTA DID the integration was provisioned against. Echoed back so
    /// the wizard can populate `config.vta.did` and run mediator lookup.
    pub vta_did: String,
    /// REST URL advertised by the VTA's DID document. Persisted so the
    /// runtime can re-authenticate without re-resolving the VTA DID.
    pub vta_url: Option<String>,
    /// Pre-encoded `vta_credential` value for `ServerSecrets` — base64url
    /// of a JSON `CredentialBundle` keyed to the rolled-over admin DID.
    /// The runtime path is unchanged: it deserialises this and calls
    /// `SessionStore::login` exactly like before.
    pub vta_credential_b64: String,
}

/// Drive the online provision-integration round-trip end-to-end.
///
/// The wizard is responsible for everything around this call: minting +
/// printing + confirming the setup DID, prompting for VTA DID / context,
/// picking the ask, etc. This helper just runs the round-trip, drains
/// progress events to stderr, and flattens the reply into the shape the
/// wizard's persistence layer needs.
pub async fn online_provision_setup(
    inputs: OnlineProvisionInputs,
) -> Result<OnlineProvisionOutcome, Box<dyn std::error::Error>> {
    use vta_sdk::provision_client::{VtaIntent, run_provision};

    let OnlineProvisionInputs {
        vta_did,
        context_id: _context_id,
        ask,
        messages,
        setup_key,
    } = inputs;

    let setup_did = setup_key.did.clone();
    let setup_pk_mb = setup_key.private_key_multibase().to_string();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let drain = tokio::spawn(async move { drain_provision_events_to_stderr(&mut rx).await });

    let reply = run_provision(
        VtaIntent::FullSetup,
        vta_did.clone(),
        setup_did,
        setup_pk_mb.clone(),
        ask,
        None,
        messages,
        tx,
    )
    .await?;

    // Make sure the event drain finishes before we keep going so the
    // operator sees the final lines before our success summary.
    let _ = drain.await;

    reply_to_outcome(reply, vta_did, &setup_pk_mb)
}

/// Drive the online provision-integration round-trip *honouring the
/// operator's explicit webvh choice already baked into `ask`*.
///
/// The default [`online_provision_setup`] above delegates to the SDK's
/// `run_provision`, which always auto-picks a registered webvh hosting
/// server (server-managed mode) and refuses to guess when 2+ are
/// registered — it gives the operator no say in *where* their DID is
/// published. This helper replicates `run_provision`'s orchestration but
/// deliberately bypasses that auto-pick: on the DIDComm preflight it hands
/// `run_provision_flight` `None`/`None` for the server/path arguments so
/// the `WEBVH_SERVER` / `WEBVH_DOMAIN` / `WEBVH_PATH` vars already present
/// in `ask` flow through verbatim. That makes an explicit server choice —
/// or an explicit *serverless* choice — work on both transports.
///
/// The REST path needs no special handling: its one-shot attempt already
/// forwards the ask's vars unchanged. Transport is auto-selected
/// (DIDComm-first when both are advertised), matching `run_provision`'s
/// default. Events are rendered to stderr for UX parity with
/// [`online_provision_setup`].
pub async fn online_provision_flight(
    vta_did: String,
    setup_key: vta_sdk::provision_client::EphemeralSetupKey,
    ask: vta_sdk::provision_client::ProvisionAsk,
    messages: std::sync::Arc<dyn vta_sdk::provision_client::OperatorMessages>,
) -> Result<OnlineProvisionOutcome, Box<dyn std::error::Error>> {
    use vta_sdk::provision_client::{
        VtaEvent, VtaIntent, run_connection_test, run_provision_flight,
    };

    let setup_did = setup_key.did.clone();
    let setup_pk_mb = setup_key.private_key_multibase().to_string();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(run_connection_test(
        VtaIntent::FullSetup,
        vta_did.clone(),
        setup_did.clone(),
        setup_pk_mb.clone(),
        ask.clone(),
        None,
        tx,
    ));

    while let Some(event) = rx.recv().await {
        match event {
            // REST one-shot path completes here.
            VtaEvent::Connected { reply, .. } => {
                return reply_to_outcome(reply, vta_did, &setup_pk_mb);
            }
            VtaEvent::Failed(reason) => {
                eprintln!();
                eprintln!("  ✗ {reason}");
                return Err(reason.into());
            }
            // DIDComm FullSetup: preflight done — drive the flight with the
            // explicit choice baked into `ask` (None/None → no auto-pick).
            VtaEvent::PreflightDone {
                rest_url,
                mediator_did,
                ..
            } => {
                let (ftx, mut frx) = tokio::sync::mpsc::unbounded_channel();
                tokio::spawn(run_provision_flight(
                    vta_did.clone(),
                    setup_did.clone(),
                    setup_pk_mb.clone(),
                    mediator_did,
                    rest_url,
                    ask.clone(),
                    None,
                    None,
                    messages.clone(),
                    ftx,
                ));
                while let Some(fev) = frx.recv().await {
                    match fev {
                        VtaEvent::Connected { reply, .. } => {
                            return reply_to_outcome(reply, vta_did, &setup_pk_mb);
                        }
                        VtaEvent::Failed(reason) => {
                            eprintln!();
                            eprintln!("  ✗ {reason}");
                            return Err(reason.into());
                        }
                        other => render_event_to_stderr(other),
                    }
                }
                return Err("provisioning ended without a terminal event".into());
            }
            other => render_event_to_stderr(other),
        }
    }

    Err("provisioning ended without a terminal event".into())
}

/// Flatten a successful `VtaReply` into the [`OnlineProvisionOutcome`]
/// shape the wizard's persistence layer needs. Shared by
/// [`online_provision_setup`] (the `run_provision`-based path) and
/// [`online_provision_flight`] (the explicit-webvh-choice path) so both
/// produce an identical outcome from the same reply.
///
/// `setup_pk_mb` is the ephemeral setup key's private half, used as the
/// admin signing key when the VTA performed no admin rollover (the setup
/// DID is then itself the long-term admin DID).
pub(super) fn reply_to_outcome(
    reply: vta_sdk::provision_client::VtaReply,
    vta_did: String,
    setup_pk_mb: &str,
) -> Result<OnlineProvisionOutcome, Box<dyn std::error::Error>> {
    use vta_sdk::provision_client::VtaReply;

    let result = match reply {
        VtaReply::Full(boxed) => *boxed,
        VtaReply::AdminOnly(_) => {
            return Err(
                "VTA returned an AdminOnly reply but FullSetup was requested — \
                 this is a wiring bug; please report"
                    .into(),
            );
        }
    };

    let integration_did = result
        .integration_did()
        .ok_or("provision reply missing integration DID")?
        .to_string();
    let integration_keys = result
        .integration_key()
        .ok_or("provision reply missing integration key material")?;
    let integration_signing_key_mb = integration_keys.signing_key.private_key_multibase.clone();
    let integration_ka_key_mb = integration_keys.ka_key.private_key_multibase.clone();

    let did_log_entry = result.webvh_log().map(str::to_string);

    let admin_did = result.admin_did().to_string();
    let admin_signing_key_mb = match result.admin_key() {
        Some(km) => km.signing_key.private_key_multibase.clone(),
        // No rollover happened: the setup DID *is* the long-term admin
        // DID. Fall back to the setup key's private half.
        None => setup_pk_mb.to_string(),
    };

    let vta_url = result.payload.config.vta_url.clone();

    let vta_credential_b64 = build_vta_credential_b64(
        &admin_did,
        &admin_signing_key_mb,
        &vta_did,
        vta_url.as_deref(),
    )?;

    Ok(OnlineProvisionOutcome {
        integration_did,
        integration_signing_key_mb,
        integration_ka_key_mb,
        did_log_entry,
        admin_did,
        admin_signing_key_mb,
        vta_did,
        vta_url,
        vta_credential_b64,
    })
}

/// Build the `ServerSecrets.vta_credential` value (base64url of a JSON
/// `CredentialBundle`) from the rolled-over admin DID + key, so the
/// runtime path that calls `SessionStore::login` keeps working unchanged.
pub fn build_vta_credential_b64(
    admin_did: &str,
    admin_signing_key_mb: &str,
    vta_did: &str,
    vta_url: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let bundle = CredentialBundle {
        did: admin_did.to_string(),
        private_key_multibase: admin_signing_key_mb.to_string(),
        vta_did: vta_did.to_string(),
        vta_url: vta_url.map(str::to_string),
    };
    let json = serde_json::to_vec(&bundle)?;
    Ok(BASE64.encode(json))
}

/// Drain `VtaEvent`s emitted by the SDK and render each as a single
/// line on stderr. Intentionally minimal — the daemon/server/control
/// wizards are non-TUI, so the operator just sees a checklist scroll
/// past as the round-trip progresses.
pub(super) async fn drain_provision_events_to_stderr(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<vta_sdk::provision_client::VtaEvent>,
) {
    while let Some(event) = rx.recv().await {
        render_event_to_stderr(event);
    }
}

/// Render a single `VtaEvent` as a one-line stderr update. Shared by
/// [`drain_provision_events_to_stderr`] (the `run_provision` path, which
/// drains every event including the terminal ones) and
/// [`online_provision_flight`] (which handles `Connected`/`Failed` itself
/// for control flow and forwards the rest here for UX parity).
pub(super) fn render_event_to_stderr(event: vta_sdk::provision_client::VtaEvent) {
    use vta_sdk::provision_client::{DiagStatus, VtaEvent};

    match event {
        VtaEvent::CheckStart(check) => {
            eprintln!("  [..] {}", check.label());
        }
        VtaEvent::CheckDone(check, status) => match status {
            DiagStatus::Pending | DiagStatus::Running => {}
            DiagStatus::Ok(detail) => eprintln!("  [OK] {}  {detail}", check.label()),
            DiagStatus::Skipped(detail) => eprintln!("  [--] {}  {detail}", check.label()),
            DiagStatus::Failed(detail) => eprintln!("  [!!] {}  {detail}", check.label()),
            // `#[non_exhaustive]` since vta-sdk 0.74: a status this build
            // does not know is shown without a detail.
            _ => eprintln!("  [??] {}", check.label()),
        },
        VtaEvent::Resolved(_)
        | VtaEvent::AttemptCompleted { .. }
        | VtaEvent::PreflightDone { .. } => {
            // These are inputs to interactive UIs (recovery prompts,
            // did-hosting-server pickers) that the non-TUI wizards don't
            // surface. The runner uses 0/1-server auto-pick anyway.
        }
        VtaEvent::Connected { protocol, .. } => {
            eprintln!();
            eprintln!("  Connected via {}", protocol.label());
        }
        VtaEvent::Failed(reason) => {
            eprintln!();
            eprintln!("  ✗ {reason}");
        }
        // `#[non_exhaustive]` since vta-sdk 0.74. Like the UI-only events
        // above, an event this wizard does not know has nothing to show.
        _ => {}
    }
}
