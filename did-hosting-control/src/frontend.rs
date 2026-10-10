use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

/// The bundle lives *inside this crate* rather than at `../did-hosting-ui/dist`
/// so it travels in the published `.crate` tarball — `cargo package` only
/// collects files under the package root, and a folder the derive cannot see is
/// a compile error. `build.rs` populates it from the `did-hosting-ui` workspace
/// when that sibling is present, and leaves the pre-bundled copy alone
/// otherwise (published crate, no Node required). See `build.rs::build_ui`.
#[derive(Embed)]
#[folder = "ui-dist"]
struct Assets;

pub async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    // Try exact file first
    if let Some(file) = Assets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        if mime.essence_str() == "text/html" {
            return html(file.data);
        }
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, mime.as_ref())],
            file.data,
        )
            .into_response();
    }

    // An extension means a genuine 404, and so does anything under `api/`:
    // the API is `POST /api/trust-tasks` and the few routes beside it, and an
    // API client that asks for anything else must be told there is nothing
    // there, not handed the console's HTML.
    if path.contains('.') || path == "api" || path.starts_with("api/") {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Otherwise, serve index.html for client-side routing
    match Assets::get("index.html") {
        Some(file) => html(file.data),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The console's HTML. It is a single-page app, so every page, the login page
/// that shows the sign-in trigger link included, is this document: never
/// cached, no referrer, never framed (VTI-LNK-082, contract C2, base design
/// 13 item 6).
fn html(body: std::borrow::Cow<'static, [u8]>) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html"),
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::CONTENT_SECURITY_POLICY, "frame-ancestors 'none'"),
        ],
        body,
    )
        .into_response()
}
