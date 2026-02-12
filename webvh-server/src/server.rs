use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;

use webauthn_rs::prelude::Webauthn;

use crate::auth::jwt::JwtKeys;
use crate::auth::session::cleanup_expired_sessions;
use crate::config::{AppConfig, AuthConfig};
use crate::error::AppError;
use crate::passkey;
use crate::routes;
use crate::routes::did_manage::cleanup_empty_dids;
use crate::store::{KeyspaceHandle, Store};
use tokio::net::TcpListener;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{Level, debug, info, warn};

#[derive(Clone)]
pub struct AppState {
    pub sessions_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    pub dids_ks: KeyspaceHandle,
    pub stats_ks: KeyspaceHandle,
    pub config: Arc<AppConfig>,
    pub did_resolver: Option<DIDCacheClient>,
    pub secrets_resolver: Option<Arc<ThreadedSecretsResolver>>,
    pub jwt_keys: Option<Arc<JwtKeys>>,
    pub webauthn: Option<Arc<Webauthn>>,
}

pub async fn run(config: AppConfig, store: Store) -> Result<(), AppError> {
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = TcpListener::bind(&addr).await.map_err(AppError::Io)?;

    // Open keyspace handles
    let sessions_ks = store.keyspace("sessions")?;
    let acl_ks = store.keyspace("acl")?;
    let dids_ks = store.keyspace("dids")?;
    let stats_ks = store.keyspace("stats")?;

    // Initialize DIDComm auth infrastructure (requires server_did)
    let (did_resolver, secrets_resolver) = init_didcomm_auth(&config).await;

    // Initialize JWT keys independently — needed by both DIDComm and passkey auth
    let jwt_keys = init_jwt_keys(&config);

    // Initialize passkey/WebAuthn if public_url is configured
    let webauthn = config.public_url.as_ref().and_then(|url| {
        match passkey::build_webauthn(url) {
            Ok(w) => {
                info!("passkey auth enabled (rp_origin={})", url);
                Some(Arc::new(w))
            }
            Err(e) => {
                warn!("passkey auth disabled: {e}");
                None
            }
        }
    });

    let auth_config = config.auth.clone();
    let upload_body_limit = config.limits.upload_body_limit;

    let state = AppState {
        sessions_ks,
        acl_ks,
        dids_ks,
        stats_ks,
        config: Arc::new(config),
        did_resolver,
        secrets_resolver,
        jwt_keys,
        webauthn,
    };

    // Spawn session cleanup background task when auth is configured
    if state.jwt_keys.is_some() {
        tokio::spawn(session_cleanup_loop(
            state.sessions_ks.clone(),
            auth_config.clone(),
        ));
    }

    // Spawn DID cleanup background task (always active)
    tokio::spawn(did_cleanup_loop(
        state.dids_ks.clone(),
        state.stats_ks.clone(),
        auth_config,
    ));

    let app = routes::router(upload_body_limit)
        .with_state(state)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(
                    DefaultOnResponse::new()
                        .level(Level::INFO)
                        .latency_unit(tower_http::LatencyUnit::Millis),
                ),
        );

    info!("server listening addr={addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(AppError::Io)?;

    info!("server shut down");
    Ok(())
}

/// Initialize JWT keys from config. Works independently of DIDComm setup,
/// so passkey auth can issue tokens even without server_did.
fn init_jwt_keys(config: &AppConfig) -> Option<Arc<JwtKeys>> {
    match &config.auth.jwt_signing_key {
        Some(b64) => match decode_jwt_key(b64) {
            Ok(k) => {
                debug!("JWT signing key loaded");
                Some(Arc::new(k))
            }
            Err(e) => {
                warn!("failed to load JWT signing key: {e} — auth endpoints will not work");
                None
            }
        },
        None => {
            warn!("auth.jwt_signing_key not configured — auth endpoints will not work");
            None
        }
    }
}

/// Initialize DID resolver and secrets resolver for DIDComm authentication.
///
/// Returns `None` values if the server DID is not configured (server still starts
/// but DIDComm auth endpoints will not work).
async fn init_didcomm_auth(
    config: &AppConfig,
) -> (
    Option<DIDCacheClient>,
    Option<Arc<ThreadedSecretsResolver>>,
) {
    let server_did = match &config.server_did {
        Some(did) => did.clone(),
        None => {
            warn!("server_did not configured — DIDComm auth endpoints will not work");
            return (None, None);
        }
    };

    // 1. DID resolver (local mode)
    let did_resolver = match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
        Ok(r) => r,
        Err(e) => {
            warn!("failed to create DID resolver: {e} — DIDComm auth endpoints will not work");
            return (None, None);
        }
    };

    // 2. Secrets resolver with server's Ed25519 + X25519 secrets
    let (secrets_resolver, _handle) = ThreadedSecretsResolver::new(None).await;

    // Load and insert server signing key (Ed25519)
    if let Some(ref signing_key_b64) = config.signing_key {
        match decode_ed25519_key(signing_key_b64) {
            Ok(private_bytes) => {
                let kid = format!("{server_did}#key-0");
                let secret =
                    affinidi_tdk::secrets_resolver::secrets::Secret::generate_ed25519(
                        Some(&kid),
                        Some(&private_bytes),
                    );
                secrets_resolver.insert(secret).await;
                debug!(kid = %kid, "server signing secret loaded");
            }
            Err(e) => warn!("failed to decode signing_key: {e}"),
        }
    }

    // Load and insert server key-agreement key (X25519)
    if let Some(ref ka_key_b64) = config.key_agreement_key {
        match decode_x25519_key(ka_key_b64) {
            Ok(private_bytes) => {
                let kid = format!("{server_did}#key-1");
                match affinidi_tdk::secrets_resolver::secrets::Secret::generate_x25519(
                    Some(&kid),
                    Some(&private_bytes),
                ) {
                    Ok(secret) => {
                        secrets_resolver.insert(secret).await;
                        debug!(kid = %kid, "server key-agreement secret loaded");
                    }
                    Err(e) => warn!("failed to create X25519 secret: {e}"),
                }
            }
            Err(e) => warn!("failed to decode key_agreement_key: {e}"),
        }
    }

    info!("DIDComm auth initialized for DID {server_did}");

    (
        Some(did_resolver),
        Some(Arc::new(secrets_resolver)),
    )
}

/// Decode a base64url-no-pad 32-byte Ed25519 private key.
fn decode_ed25519_key(b64: &str) -> Result<[u8; 32], AppError> {
    let bytes = BASE64
        .decode(b64)
        .map_err(|e| AppError::Config(format!("invalid signing_key base64: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| AppError::Config("signing_key must be exactly 32 bytes".into()))
}

/// Decode a base64url-no-pad 32-byte X25519 private key.
fn decode_x25519_key(b64: &str) -> Result<[u8; 32], AppError> {
    let bytes = BASE64
        .decode(b64)
        .map_err(|e| AppError::Config(format!("invalid key_agreement_key base64: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| AppError::Config("key_agreement_key must be exactly 32 bytes".into()))
}

/// Decode a base64url-no-pad JWT signing key and construct `JwtKeys`.
fn decode_jwt_key(b64: &str) -> Result<JwtKeys, AppError> {
    let bytes = BASE64
        .decode(b64)
        .map_err(|e| AppError::Config(format!("invalid jwt_signing_key base64: {e}")))?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AppError::Config("jwt_signing_key must be exactly 32 bytes".into()))?;
    let keys = JwtKeys::from_ed25519_bytes(&key_bytes)?;
    debug!("JWT signing key decoded successfully");
    Ok(keys)
}

async fn did_cleanup_loop(
    dids_ks: KeyspaceHandle,
    stats_ks: KeyspaceHandle,
    auth_config: AuthConfig,
) {
    let ttl_seconds = auth_config.cleanup_ttl_minutes * 60;
    let interval = Duration::from_secs(ttl_seconds.max(60));
    loop {
        tokio::time::sleep(interval).await;
        match cleanup_empty_dids(&dids_ks, &stats_ks, ttl_seconds).await {
            Ok(0) => {}
            Ok(n) => info!(count = n, "cleaned up empty DID records"),
            Err(e) => warn!("DID cleanup error: {e}"),
        }
    }
}

async fn session_cleanup_loop(sessions_ks: KeyspaceHandle, auth_config: AuthConfig) {
    let interval = Duration::from_secs(auth_config.session_cleanup_interval);
    loop {
        tokio::time::sleep(interval).await;
        if let Err(e) = cleanup_expired_sessions(&sessions_ks, auth_config.challenge_ttl).await {
            warn!("session cleanup error: {e}");
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => info!("received SIGINT"),
        () = terminate => info!("received SIGTERM"),
    }
}
