//! The embedded management UI: serves the exported `ui-dist` bundle, with SPA
//! fallback to `index.html` and cache headers per asset kind.

use std::borrow::Cow;

use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
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

/// How long a content-hashed asset may be cached: a year, the conventional
/// "forever" — its name changes whenever its bytes do.
const IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// Un-hashed assets (a favicon, say) keep their name across releases, so a
/// cache must ask before reusing one; the ETag makes asking cheap.
const REVALIDATE: &str = "no-cache";

/// Whether `path` names a file in the embedded bundle, the console's HTML
/// aside. The daemon serves these from memory without charging the public
/// resolution rate limit, which exists to bound store reads.
pub fn is_embedded_asset(path: &str) -> bool {
    let path = path.trim_start_matches('/');
    !path.is_empty() && !path.ends_with(".html") && Assets::get(path).is_some()
}

/// Whether `path`'s name carries a hash of its content. Expo's web export
/// writes every JS and CSS bundle under `_expo/static/` with the content hash
/// in its name; images and fonts under `assets/` carry an `.<hex hash>.`
/// segment.
fn is_content_hashed(path: &str) -> bool {
    if path.starts_with("_expo/static/") {
        return true;
    }
    path.starts_with("assets/")
        && path.rsplit('/').next().is_some_and(|name| {
            name.split('.')
                .any(|part| part.len() >= 16 && part.bytes().all(|b| b.is_ascii_hexdigit()))
        })
}

/// A strong entity tag from a file's SHA-256.
fn entity_tag(sha256: &[u8; 32]) -> String {
    let hex: String = sha256.iter().map(|b| format!("{b:02x}")).collect();
    format!("\"{hex}\"")
}

/// Whether an `If-None-Match` header names `etag` (or is `*`), by the weak
/// comparison RFC 9110 §13.1.2 prescribes for it.
fn none_match(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .any(|tag| tag == "*" || tag.trim_start_matches("W/") == etag)
}

/// A non-HTML asset: a strong ETag, `304` when the client holds it already,
/// and a cache lifetime by whether its name is content-hashed.
fn asset(path: &str, data: Cow<'static, [u8]>, sha256: &[u8; 32], headers: &HeaderMap) -> Response {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let etag = entity_tag(sha256);
    let cache_control = if is_content_hashed(path) {
        IMMUTABLE
    } else {
        REVALIDATE
    };
    let etag_value = HeaderValue::from_str(&etag).expect("hex is a valid header value");
    let cache_value = HeaderValue::from_static(cache_control);
    if none_match(headers, &etag) {
        return (
            StatusCode::NOT_MODIFIED,
            [
                (header::ETAG, etag_value),
                (header::CACHE_CONTROL, cache_value),
            ],
        )
            .into_response();
    }
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_str(mime.as_ref())
                    .unwrap_or(HeaderValue::from_static("application/octet-stream")),
            ),
            (header::ETAG, etag_value),
            (header::CACHE_CONTROL, cache_value),
        ],
        data,
    )
        .into_response()
}

/// The console: an embedded file by its path, else `index.html` for
/// client-side routing.
pub async fn static_handler(uri: Uri, headers: HeaderMap) -> Response {
    serve(&uri, &headers)
}

/// The console's response body once [`static_service`] has compressed it.
pub type CompressedBody = tower_http::compression::CompressionBody<axum::body::Body>;

/// [`static_handler`] as a service, compressed (gzip or brotli, as the client
/// accepts) — what the control plane and the daemon mount for the console.
pub fn static_service() -> impl tower::Service<
    axum::extract::Request,
    Response = axum::http::Response<CompressedBody>,
    Error = std::convert::Infallible,
    Future = impl Send,
> + Clone
+ Send
+ Sync
+ 'static {
    tower::ServiceBuilder::new()
        .layer(tower_http::compression::CompressionLayer::new())
        .service_fn(|request: axum::extract::Request| async move {
            Ok::<_, std::convert::Infallible>(serve(request.uri(), request.headers()))
        })
}

/// [`static_handler`], for a caller that has already taken the request apart
/// (the daemon's combined fallback).
pub fn serve(uri: &Uri, headers: &HeaderMap) -> Response {
    let path = uri.path().trim_start_matches('/');

    // Try exact file first
    if let Some(file) = Assets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        if mime.essence_str() == "text/html" {
            return html(file.data);
        }
        return asset(path, file.data, &file.metadata.sha256_hash(), headers);
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
fn html(body: Cow<'static, [u8]>) -> Response {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every console page, `/enroll` included (it is served `index.html` by
    /// the client-side-routing fallback), goes out with no referrer, so an
    /// invite link's address never reaches another site.
    #[test]
    fn console_pages_are_sent_with_no_referrer() {
        let response = html(Cow::Borrowed(b"<html></html>".as_slice()));
        assert_eq!(
            response
                .headers()
                .get(header::REFERRER_POLICY)
                .and_then(|v| v.to_str().ok()),
            Some("no-referrer")
        );
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
    }
    fn get<B>(response: &axum::http::Response<B>, name: header::HeaderName) -> Option<&str> {
        response.headers().get(name).and_then(|v| v.to_str().ok())
    }

    /// A content-hashed bundle is cached for a year as immutable; an
    /// un-hashed file must be revalidated. Both carry a strong ETag.
    #[test]
    fn hashed_assets_are_immutable_and_others_revalidate() {
        let sha = [0xab; 32];
        let data = || Cow::Borrowed(b"console.log(1)".as_slice());
        let hashed = asset(
            "_expo/static/js/web/entry-0123456789abcdef0123456789abcdef.js",
            data(),
            &sha,
            &HeaderMap::new(),
        );
        assert_eq!(hashed.status(), StatusCode::OK);
        assert_eq!(get(&hashed, header::CACHE_CONTROL), Some(IMMUTABLE));
        let etag = get(&hashed, header::ETAG).unwrap().to_string();
        assert_eq!(etag, format!("\"{}\"", "ab".repeat(32)));
        assert!(
            get(&hashed, header::CONTENT_TYPE)
                .unwrap()
                .contains("javascript")
        );

        let image = asset(
            "assets/node_modules/x/icon.0123456789abcdef0123456789abcdef.png",
            data(),
            &sha,
            &HeaderMap::new(),
        );
        assert_eq!(get(&image, header::CACHE_CONTROL), Some(IMMUTABLE));

        let favicon = asset("favicon.ico", data(), &sha, &HeaderMap::new());
        assert_eq!(get(&favicon, header::CACHE_CONTROL), Some(REVALIDATE));
        assert_eq!(get(&favicon, header::ETAG), Some(etag.as_str()));
        let plain = asset("assets/logo.png", data(), &sha, &HeaderMap::new());
        assert_eq!(get(&plain, header::CACHE_CONTROL), Some(REVALIDATE));
    }

    /// A client holding the current bytes is answered `304`, with no body; a
    /// stale or foreign tag gets the file.
    #[tokio::test]
    async fn a_matching_if_none_match_is_answered_not_modified() {
        use http_body_util::BodyExt;
        let sha = [0x01; 32];
        let etag = entity_tag(&sha);
        let data = || Cow::Borrowed(b"body".as_slice());
        for tag in [
            etag.clone(),
            format!("W/{etag}"),
            format!("\"x\", {etag}"),
            "*".into(),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::IF_NONE_MATCH, HeaderValue::from_str(&tag).unwrap());
            let response = asset("_expo/static/a-0123456789abcdef.js", data(), &sha, &headers);
            assert_eq!(response.status(), StatusCode::NOT_MODIFIED, "{tag}");
            assert_eq!(get(&response, header::ETAG), Some(etag.as_str()));
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert!(body.is_empty());
        }
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("\"stale\""));
        let response = asset("_expo/static/a-0123456789abcdef.js", data(), &sha, &headers);
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Through the mounted service, a bundled script is compressed for a
    /// client that accepts it, cached as immutable, and answered `304` for
    /// its own ETag. Skipped when no UI bundle was built into this binary.
    #[tokio::test]
    async fn the_mounted_service_compresses_and_validates_bundle_files() {
        use tower::ServiceExt;
        let Some(path) =
            Assets::iter().find(|p| p.starts_with("_expo/static/") && p.ends_with(".js"))
        else {
            return;
        };
        let request = |tag: Option<&str>| {
            let mut r = axum::http::Request::get(format!("/{path}"))
                .header(header::ACCEPT_ENCODING, "gzip");
            if let Some(tag) = tag {
                r = r.header(header::IF_NONE_MATCH, tag);
            }
            r.body(axum::body::Body::empty()).unwrap()
        };
        assert!(is_embedded_asset(&format!("/{path}")));
        let response = static_service().oneshot(request(None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(get(&response, header::CACHE_CONTROL), Some(IMMUTABLE));
        assert_eq!(get(&response, header::CONTENT_ENCODING), Some("gzip"));
        let etag = get(&response, header::ETAG).unwrap().to_string();
        let response = static_service()
            .oneshot(request(Some(&etag)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    }

    /// Paths outside the bundle, and the console's HTML, are not exempt assets.
    #[test]
    fn only_bundle_files_are_embedded_assets() {
        assert!(!is_embedded_asset("/"));
        assert!(!is_embedded_asset("/index.html"));
        assert!(!is_embedded_asset("/alice/did.jsonl"));
        assert!(!is_embedded_asset("/_expo/static/js/web/not-there.js"));
    }
}
