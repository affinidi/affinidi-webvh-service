use std::sync::Arc;

use crate::config::AppConfig;
use crate::error::AppError;
use crate::routes;
use crate::store::{KeyspaceHandle, Store};
use tokio::sync::watch;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{Level, error, info};

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub dids_ks: KeyspaceHandle,
    pub config: Arc<AppConfig>,
}

pub async fn run(config: AppConfig, store: Store) -> Result<(), AppError> {
    let dids_ks = store.keyspace("dids")?;

    let std_listener = {
        let addr = format!("{}:{}", config.server.host, config.server.port);
        let listener = std::net::TcpListener::bind(&addr).map_err(AppError::Io)?;
        listener.set_nonblocking(true).map_err(AppError::Io)?;
        info!("watcher listening addr={addr}");
        listener
    };

    let state = AppState {
        store: store.clone(),
        dids_ks,
        config: Arc::new(config),
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // REST thread
    let rest_state = state.clone();
    let mut rest_shutdown = shutdown_rx.clone();
    let rest_handle = std::thread::Builder::new()
        .name("watcher-rest".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build REST runtime");

            rt.block_on(async {
                info!("REST thread started");

                let listener = tokio::net::TcpListener::from_std(std_listener)
                    .expect("failed to convert TcpListener");

                let app = routes::router()
                    .with_state(rest_state)
                    .layer(
                        TraceLayer::new_for_http()
                            .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                            .on_response(
                                DefaultOnResponse::new()
                                    .level(Level::INFO)
                                    .latency_unit(tower_http::LatencyUnit::Millis),
                            ),
                    );

                axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        let _ = rest_shutdown.changed().await;
                    })
                    .await
                    .expect("axum serve failed");

                info!("REST thread shutting down");
            });
        })
        .map_err(|e| AppError::Internal(format!("failed to spawn REST thread: {e}")))?;

    // Storage thread (just persists on shutdown)
    let mut storage_shutdown = shutdown_rx.clone();
    let storage_handle = std::thread::Builder::new()
        .name("watcher-storage".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build storage runtime");

            rt.block_on(async {
                info!("storage thread started");
                let _ = storage_shutdown.changed().await;
                info!("storage thread shutting down");

                if let Err(e) = store.persist().await {
                    error!("failed to persist store on shutdown: {e}");
                } else {
                    info!("store persisted");
                }
            });
        })
        .map_err(|e| AppError::Internal(format!("failed to spawn storage thread: {e}")))?;

    // Wait for shutdown signal
    shutdown_signal().await;

    let _ = shutdown_tx.send(true);

    let mut any_panic = false;

    match tokio::task::spawn_blocking(move || rest_handle.join()).await {
        Ok(Ok(())) => info!("REST thread stopped"),
        Ok(Err(_)) => { error!("REST thread panicked"); any_panic = true; }
        Err(e) => { error!("failed to join REST thread: {e}"); any_panic = true; }
    }

    match tokio::task::spawn_blocking(move || storage_handle.join()).await {
        Ok(Ok(())) => info!("storage thread stopped"),
        Ok(Err(_)) => { error!("storage thread panicked"); any_panic = true; }
        Err(e) => { error!("failed to join storage thread: {e}"); any_panic = true; }
    }

    if any_panic {
        return Err(AppError::Internal("one or more threads panicked".into()));
    }

    info!("watcher shut down");
    Ok(())
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
