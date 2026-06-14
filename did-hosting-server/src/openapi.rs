//! OpenAPI 3.1 spec for the HTTP upload/resolve API (issue #47, item #5).
//!
//! Behind the off-by-default `openapi` feature. The spec covers the routes a
//! black-box / E2E fuzzer cares about: the authenticated `PUT /api/dids/...`
//! upload path and the public resolve routes, plus the surrounding
//! introspection surface.
//!
//! [`ApiDoc::openapi`] yields the spec programmatically; the committed
//! `docs/openapi.json` snapshot is regenerated and drift-checked by the
//! `openapi_snapshot_in_sync` test below.

use utoipa::OpenApi;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};

use crate::routes::resolve_webvh;
use crate::routes::{did_manage, did_public, health};

/// Registers the `bearer` (JWT) HTTP security scheme referenced by the
/// authenticated endpoints.
struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}

/// The aggregated OpenAPI document for the server's HTTP API.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Affinidi DID Hosting — upload/resolve API",
        description = "HTTP surface of the did-hosting-server edge node: authenticated \
            upload/introspection of did:webvh slots and public, unauthenticated DID \
            resolution. DID lifecycle management (create/rollback/recover) happens over \
            DIDComm on the control plane and is not part of this spec.",
        version = env!("CARGO_PKG_VERSION"),
        license(name = "Apache-2.0"),
    ),
    paths(
        did_manage::upload_did,
        did_manage::upload_witness,
        did_manage::get_did,
        did_manage::get_did_log,
        did_manage::list_dids,
        did_manage::delete_did,
        health::health,
        did_public::serve_public,
        resolve_webvh::serve_root_did_log,
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "dids", description = "Authenticated DID slot management + content sync"),
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
