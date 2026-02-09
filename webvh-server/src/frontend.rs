use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "../webvh-ui/dist"]
struct Assets;

/// Serves embedded SPA assets. Paths with a file extension are looked up
/// directly (returning 404 if missing). Paths without an extension serve
/// `index.html` to support client-side routing.
pub async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    // Try serving the exact file first
    if let Some(file) = Assets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, mime.as_ref())],
            file.data,
        )
            .into_response();
    }

    // If the path looks like a file (has an extension), it's a genuine 404
    if path.contains('.') {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Otherwise, serve index.html for client-side routing
    match Assets::get("index.html") {
        Some(file) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html")],
            file.data,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
