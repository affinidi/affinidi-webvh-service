//! OpenAPI 3.1 spec for the edge's HTTP surface (issue #47, item #5).
//!
//! Behind the off-by-default `openapi` feature. An edge serves public DID
//! resolution, the unauthenticated health probe, and `POST /api/trust-tasks` —
//! the HTTPS binding of its Trust Task listener. It has no management API:
//! every write is a Trust Task signed by its control plane.
//!
//! [`ApiDoc::openapi`] yields the spec programmatically; the committed
//! `docs/openapi.json` snapshot is regenerated and drift-checked by the
//! `openapi_snapshot_in_sync` test below.

use utoipa::OpenApi;

use crate::routes::{did_public, health, trust_tasks};
use crate::routes::{resolve_agent_name, resolve_web, resolve_webvh};

/// Paths the edge serves through its DID-serving fallback
/// (`did_public::serve_public`) or a second route onto a documented handler.
/// Each is a real path of the router; utoipa needs one function per path, so
/// these document them without being handlers.
mod fallback_paths {
    /// `GET /{mnemonic}/did-witness.json`.
    #[utoipa::path(
        get,
        path = "/{mnemonic}/did-witness.json",
        tag = "resolve",
        params(("mnemonic" = String, Path, description = "Slot path of a hosted did:webvh")),
        responses(
            (status = 200, description = "The slot's did:webvh witness proofs", content_type = "application/json"),
            (status = 404, description = "No DID, or no witness file, hosted at this path"),
            (status = 429, description = "This address's resolution rate exceeds `[server.resolve_rate_limit]`; see `Retry-After`", content_type = "application/json"),
        ),
    )]
    #[allow(dead_code)]
    pub fn did_witness() {}

    /// `GET /{mnemonic}/did.json`.
    #[utoipa::path(
        get,
        path = "/{mnemonic}/did.json",
        tag = "resolve",
        params(("mnemonic" = String, Path, description = "Slot path of a hosted DID")),
        responses(
            (status = 200, description = "The slot's did:web document (a did:web record, or the did:web form of a did:webvh)", content_type = "application/did+json"),
            (status = 404, description = "No DID hosted at this path"),
            (status = 429, description = "This address's resolution rate exceeds `[server.resolve_rate_limit]`; see `Retry-After`", content_type = "application/json"),
        ),
    )]
    #[allow(dead_code)]
    pub fn did_json() {}

    /// `GET /@{name}/{context}` — the agent-name redirect with a context tail.
    #[utoipa::path(
        get,
        path = "/@{name}/{context}",
        tag = "resolve",
        params(
            ("name" = String, Path, description = "An agent name bound to a hosted DID"),
            ("context" = String, Path, description = "Any further path; accepted and ignored for the redirect target"),
        ),
        responses(
            (status = 302, description = "Redirect; `Location` is the DID the name is bound to"),
            (status = 404, description = "No such name, or `features.agent_names` is off"),
            (status = 429, description = "This address's resolution rate exceeds `[server.resolve_rate_limit]`; see `Retry-After`", content_type = "application/json"),
        ),
    )]
    #[allow(dead_code)]
    pub fn agent_name_context() {}
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Affinidi DID Hosting — edge HTTP surface",
        description = "HTTP surface of the did-hosting-server edge node: public, \
            unauthenticated DID resolution, a liveness probe, and the HTTPS binding of the \
            Trust Task listener. The edge is written to only by its control plane's signed \
            Trust Tasks, which arrive over TSP, DIDComm or this binding alike.",
        version = env!("CARGO_PKG_VERSION"),
        license(name = "Apache-2.0"),
    ),
    paths(
        trust_tasks::receive,
        health::health,
        did_public::serve_public,
        resolve_webvh::serve_root_did_log,
        resolve_webvh::serve_root_witness,
        resolve_web::serve_root_did_web,
        resolve_agent_name::serve_community,
        resolve_agent_name::serve,
        fallback_paths::did_witness,
        fallback_paths::did_json,
        fallback_paths::agent_name_context,
    ),
    tags(
        (name = "trust-tasks", description = "The HTTPS binding of the Trust Task listener"),
        (name = "resolve", description = "Public, unauthenticated DID resolution"),
        (name = "system", description = "Health / diagnostics"),
    ),
)]
pub struct ApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    /// Path to the committed snapshot, relative to this crate.
    fn snapshot_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/openapi.json")
    }

    /// Keeps `docs/openapi.json` in lockstep with the annotations. Regenerate
    /// after changing any `#[utoipa::path]` with:
    /// `UPDATE_OPENAPI=1 cargo test -p did-hosting-server --features openapi openapi_snapshot`
    #[test]
    fn openapi_snapshot_in_sync() {
        let generated = ApiDoc::openapi()
            .to_pretty_json()
            .expect("serialize openapi");
        let path = snapshot_path();

        if std::env::var_os("UPDATE_OPENAPI").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, format!("{generated}\n")).unwrap();
            return;
        }

        let committed = std::fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!(
                "missing {}. Generate it with: \
                 UPDATE_OPENAPI=1 cargo test -p did-hosting-server --features openapi openapi_snapshot",
                path.display()
            )
        });
        assert_eq!(
            committed.trim_end(),
            generated.trim_end(),
            "docs/openapi.json is out of date — regenerate with \
             UPDATE_OPENAPI=1 cargo test -p did-hosting-server --features openapi openapi_snapshot"
        );
    }
}
