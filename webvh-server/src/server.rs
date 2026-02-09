use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;

use crate::auth::jwt::JwtKeys;
use crate::auth::session::cleanup_expired_sessions;
use crate::config::{AppConfig, AuthConfig};
use crate::error::AppError;
use crate::routes;
use crate::store::{KeyspaceHandle, Store};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing::{debug, info, warn};

#[derive(Clone)]
pub struct AppState {
    pub sessions_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    pub dids_ks: KeyspaceHandle,
    pub stats_ks: KeyspaceHandle,
    pub config: Arc<RwLock<AppConfig>>,
    pub did_resolver: Option<DIDCacheClient>,
    pub secrets_resolver: Option<Arc<ThreadedSecretsResolver>>,
    pub jwt_keys: Option<Arc<JwtKeys>>,
}

pub async fn run(config: AppConfig, store: Store) -> Result<(), AppError> {
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = TcpListener::bind(&addr).await.map_err(AppError::Io)?;

    // Open keyspace handles
    let sessions_ks = store.keyspace("sessions")?;
    let acl_ks = store.keyspace("acl")?;
    let dids_ks = store.keyspace("dids")?;
    let stats_ks = store.keyspace("stats")?;

    // Initialize auth infrastructure
    let (did_resolver, secrets_resolver, jwt_keys) = init_auth(&config).await;

    let auth_config = config.auth.clone();

    let state = AppState {
        sessions_ks,
        acl_ks,
        dids_ks,
        stats_ks,
        config: Arc::new(RwLock::new(config)),
        did_resolver,
        secrets_resolver,
        jwt_keys,
    };

    // Spawn session cleanup background task when auth is configured
    if state.jwt_keys.is_some() {
        tokio::spawn(session_cleanup_loop(state.sessions_ks.clone(), auth_config));
    }

    let app = routes::router()
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    info!("server listening addr={addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(AppError::Io)?;

    info!("server shut down");
    Ok(())
}

/// Initialize DID resolver, secrets resolver, and JWT keys for authentication.
///
/// Returns `None` values if the server DID is not configured (server still starts
/// but auth endpoints will not work).
async fn init_auth(
    config: &AppConfig,
) -> (
    Option<DIDCacheClient>,
    Option<Arc<ThreadedSecretsResolver>>,
    Option<Arc<JwtKeys>>,
) {
    let server_did = match &config.server_did {
        Some(did) => did.clone(),
        None => {
            warn!("server_did not configured — auth endpoints will not work");
            return (None, None, None);
        }
    };

    // 1. DID resolver (local mode)
    let did_resolver = match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
        Ok(r) => r,
        Err(e) => {
            warn!("failed to create DID resolver: {e} — auth endpoints will not work");
            return (None, None, None);
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

    // 3. JWT signing key
    let jwt_keys = match &config.auth.jwt_signing_key {
        Some(b64) => match decode_jwt_key(b64) {
            Ok(k) => k,
            Err(e) => {
                warn!("failed to load JWT signing key: {e} — auth endpoints will not work");
                return (Some(did_resolver), Some(Arc::new(secrets_resolver)), None);
            }
        },
        None => {
            warn!("auth.jwt_signing_key not configured — auth endpoints will not work");
            return (Some(did_resolver), Some(Arc::new(secrets_resolver)), None);
        }
    };

    info!("auth initialized for DID {server_did}");

    (
        Some(did_resolver),
        Some(Arc::new(secrets_resolver)),
        Some(Arc::new(jwt_keys)),
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
