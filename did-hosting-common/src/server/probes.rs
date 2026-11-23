//! Kubernetes-style liveness and readiness probes, `GET /livez` and
//! `GET /readyz`, served by every binary that runs an HTTP listener (edge,
//! control plane, witness, watcher, daemon).
//!
//! The two answer different questions, and the difference is what an
//! orchestrator does with a failure:
//!
//! - **`/livez`**: is the process alive? It answers from the HTTP server
//!   itself and checks nothing else, so storage trouble or an unreachable
//!   control plane or mediator never gets a healthy process restarted. A
//!   restart would cure neither, and on an edge it would reset the
//!   replication staleness clock, hiding the fault.
//! - **`/readyz`**: can this instance take traffic right now? `503` while it
//!   cannot, so a load balancer stops routing to it until it can. Every
//!   binary checks its store; a binary that serves DIDs can add a check of
//!   its own ([`ReadinessProbe::with_serving_check`]): the edge's is the same
//!   own-DID and replication condition its `/api/health` reports.
//!
//! Readiness deliberately does not cover the mediator. Messaging has its own
//! reconnect supervisor, and resolution and the HTTPS Trust Task binding are
//! served without it, so draining the instance would turn a degraded
//! transport into an outage.
//!
//! Both routes are unauthenticated, so neither body says more than
//! `/api/health` already does: a status word, and for readiness which check
//! failed. Never the cause, which can name paths and hosts. That goes to the
//! log, at `warn`.
//!
//! Probes come every few seconds and from anyone who can reach the port, so
//! [`ReadinessProbe`] runs its checks at most once per [`PROBE_CACHE`] and
//! answers every caller in between from that result. The checks never write:
//! see [`KeyspaceHandle::probe`].

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Serialize;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::warn;

use crate::server::store::KeyspaceHandle;

/// How long one round of checks answers for. Bounds the store work an
/// unauthenticated caller can cause to one round per this interval.
pub const PROBE_CACHE: Duration = Duration::from_secs(1);

/// Longest one round of checks may take, all checks together, before what is
/// still running counts as a failure. A stalled disk or store then gets the
/// instance drained, rather than holding the probe open past the
/// orchestrator's own timeout (Kubernetes defaults to 1 s).
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(800);

/// A binary's own readiness condition beyond its store: `Err` carries the
/// reason, for the log only.
pub type ServingCheck =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>> + Send + Sync>;

/// `/livez` body.
#[derive(Debug, Serialize)]
pub struct LiveResponse {
    status: &'static str,
}

/// `GET /livez`. Always `200 {"status":"ok"}` while the server answers.
pub async fn livez() -> Json<LiveResponse> {
    Json(LiveResponse { status: "ok" })
}

/// One readiness check's result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CheckState {
    Ok,
    Unavailable,
}

/// `/readyz` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadyResponse {
    /// `ready` or `notReady`.
    pub status: &'static str,
    /// Every store the binary needs.
    pub storage: CheckState,
    /// The binary's own condition, when it has one
    /// ([`ReadinessProbe::with_serving_check`]); absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serving: Option<CheckState>,
}

impl ReadyResponse {
    fn new(storage: CheckState, serving: Option<CheckState>) -> Self {
        let ready = storage == CheckState::Ok && serving != Some(CheckState::Unavailable);
        Self {
            status: if ready { "ready" } else { "notReady" },
            storage,
            serving,
        }
    }

    pub fn is_ready(&self) -> bool {
        self.status == "ready"
    }
}

impl IntoResponse for ReadyResponse {
    fn into_response(self) -> Response {
        let code = if self.is_ready() {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        (code, Json(self)).into_response()
    }
}

/// Runs the readiness checks for `GET /readyz`, at most once per
/// [`PROBE_CACHE`]. Cheap to clone; clones share the cache.
#[derive(Clone)]
pub struct ReadinessProbe {
    stores: Arc<[KeyspaceHandle]>,
    serving: Option<ServingCheck>,
    last: Arc<Mutex<Option<(Instant, ReadyResponse)>>>,
}

impl ReadinessProbe {
    /// A probe over the store `ks` belongs to. Pass a keyspace the binary
    /// serves from: on a network backend the check is a read in it, and on
    /// fjall it is store-wide.
    pub fn new(ks: KeyspaceHandle) -> Self {
        Self::over(vec![ks])
    }

    /// A probe over several stores, one keyspace of each, all of which must
    /// be ready (the daemon's main store and its witness store).
    pub fn over(stores: Vec<KeyspaceHandle>) -> Self {
        Self {
            stores: stores.into(),
            serving: None,
            last: Arc::new(Mutex::new(None)),
        }
    }

    /// Add the binary's own condition, run after the stores pass (it can
    /// read them) and within the same [`PROBE_TIMEOUT`]. Its result is the
    /// body's `serving` field.
    pub fn with_serving_check(mut self, check: ServingCheck) -> Self {
        self.serving = Some(check);
        self
    }

    /// The current readiness. Concurrent callers wait on one round of
    /// checks rather than each running their own.
    pub async fn check(&self) -> ReadyResponse {
        let mut last = self.last.lock().await;
        if let Some((at, answer)) = *last
            && at.elapsed() < PROBE_CACHE
        {
            return answer;
        }
        let deadline = Instant::now() + PROBE_TIMEOUT;
        let storage = self.check_stores(deadline).await;
        let serving = match &self.serving {
            None => None,
            // Nothing is served without the store, and the check would only
            // fail reading it.
            Some(_) if storage != CheckState::Ok => Some(CheckState::Unavailable),
            Some(check) => Some(match tokio::time::timeout_at(deadline, check()).await {
                Ok(Ok(())) => CheckState::Ok,
                Ok(Err(reason)) => {
                    warn!(reason = %reason, "readiness: not serving correctly");
                    CheckState::Unavailable
                }
                Err(_) => {
                    warn!(
                        timeout_ms = PROBE_TIMEOUT.as_millis() as u64,
                        "readiness: serving check timed out"
                    );
                    CheckState::Unavailable
                }
            }),
        };
        let answer = ReadyResponse::new(storage, serving);
        *last = Some((Instant::now(), answer));
        answer
    }

    async fn check_stores(&self, deadline: Instant) -> CheckState {
        for store in self.stores.iter() {
            match tokio::time::timeout_at(deadline, store.probe()).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    warn!(error = %e, "readiness: store check failed");
                    return CheckState::Unavailable;
                }
                Err(_) => {
                    warn!(
                        timeout_ms = PROBE_TIMEOUT.as_millis() as u64,
                        "readiness: store check timed out"
                    );
                    return CheckState::Unavailable;
                }
            }
        }
        CheckState::Ok
    }
}

/// `GET /livez` and `GET /readyz` over `probe`. Each binary merges this into
/// its app beside `/api/health`, after its layers, so the probes sit outside
/// authentication, rate limiting and request tracing as `/api/health` does.
pub fn router<S>(probe: ReadinessProbe) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new().route("/livez", get(livez)).route(
        "/readyz",
        get(move || {
            let probe = probe.clone();
            async move { probe.check().await }
        }),
    )
}

#[cfg(test)]
mod body_tests {
    use super::*;

    #[test]
    fn ready_body_is_camel_case_and_omits_an_absent_serving_check() {
        let body = serde_json::to_value(ReadyResponse::new(CheckState::Unavailable, None)).unwrap();
        assert_eq!(
            body,
            serde_json::json!({"status": "notReady", "storage": "unavailable"})
        );
        let body = serde_json::to_value(ReadyResponse::new(
            CheckState::Ok,
            Some(CheckState::Unavailable),
        ))
        .unwrap();
        assert_eq!(
            body,
            serde_json::json!({"status": "notReady", "storage": "ok", "serving": "unavailable"})
        );
        assert!(ReadyResponse::new(CheckState::Ok, Some(CheckState::Ok)).is_ready());
    }
}

#[cfg(all(test, feature = "store-fjall"))]
mod tests {
    use super::*;
    use crate::server::config::StoreConfig;
    use crate::server::store::{KS_DIDS, Store};
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// A keyspace of a store opened in `dir`. The handle keeps the
    /// database open after the [`Store`] is dropped.
    async fn store_in(dir: &std::path::Path) -> KeyspaceHandle {
        Store::open(&StoreConfig {
            data_dir: dir.to_path_buf(),
            ..StoreConfig::default()
        })
        .await
        .expect("open store")
        .keyspace(KS_DIDS)
        .expect("keyspace")
    }

    async fn get(app: Router, path: &str) -> (StatusCode, serde_json::Value) {
        let resp = app
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).expect("JSON body"))
    }

    #[tokio::test]
    async fn livez_is_ok() {
        assert_eq!(livez().await.0.status, "ok");
    }

    #[tokio::test]
    async fn readyz_is_ready_over_a_working_store() {
        let dir = tempfile::tempdir().unwrap();
        let probe = ReadinessProbe::new(store_in(dir.path()).await);
        let answer = probe.check().await;
        assert!(answer.is_ready());
        assert_eq!(answer.status, "ready");
        assert_eq!(answer.storage, CheckState::Ok);
        assert_eq!(answer.serving, None);
        assert_eq!(answer.into_response().status(), StatusCode::OK);
    }

    /// The case the probe exists for: the volume under an open database goes
    /// away (a detached PVC, a deleted data directory). The open database
    /// would go on answering from memory; readiness must not. `/livez` stays
    /// `200` throughout.
    #[tokio::test]
    async fn readyz_is_not_ready_once_the_data_directory_is_gone() {
        let parent = tempfile::tempdir().unwrap();
        let data = parent.path().join("data");
        let probe = ReadinessProbe::new(store_in(&data).await);
        let app = router::<()>(probe.clone());
        assert_eq!(get(app.clone(), "/readyz").await.0, StatusCode::OK);

        std::fs::remove_dir_all(&data).unwrap();
        tokio::time::sleep(PROBE_CACHE).await;

        let answer = probe.check().await;
        assert!(!answer.is_ready());
        assert_eq!(answer.status, "notReady");
        assert_eq!(answer.storage, CheckState::Unavailable);
        let (status, body) = get(app.clone(), "/readyz").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body,
            serde_json::json!({"status": "notReady", "storage": "unavailable"}),
            "the body names the failed check and nothing about its cause"
        );
        assert_eq!(
            get(app, "/livez").await,
            (StatusCode::OK, serde_json::json!({"status": "ok"}))
        );
    }

    /// Any of several stores failing makes the instance not ready (the
    /// daemon's witness store beside its main one).
    #[tokio::test]
    async fn readyz_needs_every_store() {
        let parent = tempfile::tempdir().unwrap();
        let (a, b) = (parent.path().join("a"), parent.path().join("b"));
        let probe = ReadinessProbe::over(vec![store_in(&a).await, store_in(&b).await]);
        assert!(probe.check().await.is_ready());
        std::fs::remove_dir_all(&b).unwrap();
        tokio::time::sleep(PROBE_CACHE).await;
        assert_eq!(probe.check().await.storage, CheckState::Unavailable);
    }

    #[tokio::test]
    async fn readyz_answers_from_cache_within_the_window() {
        let parent = tempfile::tempdir().unwrap();
        let data = parent.path().join("data");
        let probe = ReadinessProbe::new(store_in(&data).await);
        assert!(probe.check().await.is_ready());
        std::fs::remove_dir_all(&data).unwrap();
        // Still inside the window: the cached answer stands.
        assert!(probe.check().await.is_ready());
    }

    #[tokio::test]
    async fn a_failing_serving_check_is_not_ready_over_a_working_store() {
        let dir = tempfile::tempdir().unwrap();
        let probe = ReadinessProbe::new(store_in(dir.path()).await)
            .with_serving_check(Arc::new(|| Box::pin(async { Err("stale".to_string()) })));
        let answer = probe.check().await;
        assert!(!answer.is_ready());
        assert_eq!(answer.storage, CheckState::Ok);
        assert_eq!(answer.serving, Some(CheckState::Unavailable));
    }

    /// A check that hangs counts as a failure once [`PROBE_TIMEOUT`] passes,
    /// so the probe answers within the orchestrator's own timeout.
    #[tokio::test]
    async fn a_hung_serving_check_times_out_as_not_ready() {
        let dir = tempfile::tempdir().unwrap();
        let probe =
            ReadinessProbe::new(store_in(dir.path()).await).with_serving_check(Arc::new(|| {
                Box::pin(async { std::future::pending::<Result<(), String>>().await })
            }));
        let started = std::time::Instant::now();
        let answer = probe.check().await;
        assert!(started.elapsed() < PROBE_TIMEOUT + Duration::from_millis(500));
        assert_eq!(answer.serving, Some(CheckState::Unavailable));
        assert!(!answer.is_ready());
    }

    #[tokio::test]
    async fn the_serving_check_is_skipped_without_storage() {
        let parent = tempfile::tempdir().unwrap();
        let data = parent.path().join("data");
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran2 = ran.clone();
        let probe =
            ReadinessProbe::new(store_in(&data).await).with_serving_check(Arc::new(move || {
                ran2.store(true, std::sync::atomic::Ordering::SeqCst);
                Box::pin(async { Ok(()) })
            }));
        std::fs::remove_dir_all(&data).unwrap();
        let answer = probe.check().await;
        assert_eq!(answer.storage, CheckState::Unavailable);
        assert_eq!(answer.serving, Some(CheckState::Unavailable));
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    }
}
