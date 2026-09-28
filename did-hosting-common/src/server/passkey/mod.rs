//! Passkeys (WebAuthn): credentials, enrolment invites and ceremony state.

pub mod invite;
pub mod routes;
pub mod store;

use url::Url;
use webauthn_rs::prelude::*;

use crate::server::error::AppError;

/// Build a `Webauthn` instance from the server's `public_url` configuration.
///
/// The relying party ID is the hostname from the URL and the origin is the
/// full scheme+host (e.g. `https://example.com`).
pub fn build_webauthn(public_url: &str) -> Result<Webauthn, AppError> {
    let url = Url::parse(public_url)
        .map_err(|e| AppError::Config(format!("invalid public_url '{public_url}': {e}")))?;

    let rp_id = url
        .domain()
        .ok_or_else(|| AppError::Config("public_url has no domain".into()))?
        .to_string();

    let builder = WebauthnBuilder::new(&rp_id, &url)
        .map_err(|e| AppError::Config(format!("failed to build WebauthnBuilder: {e}")))?;

    let webauthn = builder
        .rp_name("DID Hosting Server")
        .build()
        .map_err(|e| AppError::Config(format!("failed to build Webauthn: {e}")))?;

    Ok(webauthn)
}

/// The operator's `invite` subcommand: issue a login (`session`) invite from
/// the command line, with store access standing in for an administrator's
/// signed `auth/passkey/enroll/invite` — the bootstrap for the first admin.
///
/// Prints the invite URL and the claim code separately, for delivery over
/// two different channels. Neither is stored or logged.
pub async fn run_cli_invite(
    sessions_ks: &crate::server::store::KeyspaceHandle,
    public_url: &str,
    ttl_secs: u64,
    did: &str,
    role: &str,
) -> Result<(), AppError> {
    let did = crate::server::acl::validate_did_format(did)?;
    role.parse::<crate::server::acl::Role>()?;
    if store::get_passkey_user_by_did(sessions_ks, &did)
        .await?
        .is_some_and(|u| !u.credentials.is_empty())
    {
        return Err(AppError::Conflict(format!(
            "{did} already has a login passkey; it adds another from its own session"
        )));
    }
    let issued = invite::issue(
        sessions_ks,
        invite::InviteRequest {
            subject: did.clone(),
            purpose: invite::Purpose::Session,
            role: Some(role.to_string()),
            device_label: None,
            issued_by: "operator (CLI)".into(),
            ttl_secs,
        },
    )
    .await?;
    let url = format!(
        "{}/enroll?token={}",
        public_url.trim_end_matches('/'),
        issued.token
    );
    eprintln!();
    eprintln!("  Enrollment invite created.");
    eprintln!();
    eprintln!("  DID:     {did}");
    eprintln!("  Role:    {role}");
    eprintln!(
        "  Expires: in {}m (epoch {})",
        ttl_secs.div_ceil(60),
        issued.invite.expires_at
    );
    eprintln!();
    eprintln!("  Send these two over DIFFERENT channels (e.g. the link by email,");
    eprintln!("  the code by chat or phone). Either one alone redeems nothing.");
    eprintln!();
    eprintln!("  Enrollment URL:");
    eprintln!("  {url}");
    eprintln!();
    eprintln!("  Claim code:");
    eprintln!("  {}", issued.claim_code);
    eprintln!();
    Ok(())
}
