//! DID method abstraction — one contract every supported `did:*`
//! method implements.
//!
//! Per `docs/multi-method-hosting-spec.md` §6. The hosting service was
//! historically webvh-only; this module makes it method-agnostic so
//! `did:web`, `did:webvh`, and future HTTPS-delivered methods can be
//! served from the same infrastructure.
//!
//! ## Design
//!
//! - [`DidMethod`] — the trait. Object-safe (`&self`) so the dispatcher
//!   in [`method_by_name`] can hand out `&'static dyn DidMethod`
//!   without per-call match arms scattered across the codebase. Method
//!   impls are zero-size unit structs (`Web`, `Webvh`) — `&self` is a
//!   no-op at runtime.
//!
//! - [`ParsedDid`] — the parsed identifier (method, optional SCID,
//!   domain, path). All callers downstream of the dispatcher work in
//!   this shape, not raw strings.
//!
//! - [`MethodError`] — narrow error type for parser / validator paths.
//!   Distinct from `crate::server::error::AppError` so the trait
//!   doesn't drag in server-side concerns.
//!
//! ## Feature gating
//!
//! [`method_by_name`] resolves the per-method `&'static dyn DidMethod`
//! at compile time via `#[cfg(feature = "method-...")]`. Disabling a
//! method's feature removes its arm from the dispatcher (and its
//! resolution route from the router — see T25). The default workspace
//! build enables `method-webvh` + `method-web`. `method-webs` is
//! implemented but **off by default**: it pulls the KERI stack, which
//! an operator hosting no `did:webs` DIDs should not carry.
//! `method-webplus` is still a scaffolded stub.
//!
//! ## Picking a method for an incoming publication
//!
//! [`method_by_name`] answers "is this method compiled in", which is
//! what a request naming a method needs. The management API's request
//! body carries content rather than a method name, so it uses
//! [`detect_method`] instead — the payload's own shape decides, and a
//! caller cannot mislabel a payload into the wrong verifier.

pub mod parse;
pub mod publication;
#[cfg(feature = "method-web")]
pub mod web;
#[cfg(feature = "method-webplus")]
pub mod webplus;
#[cfg(feature = "method-webs")]
pub mod webs;
#[cfg(feature = "method-webvh")]
pub mod webvh;

pub use parse::parse_did_method;

/// One DID method's contribution to the hosting service.
///
/// Implementations are zero-size unit structs (`Web`, `Webvh`) so the
/// `&self` parameter is a no-op at runtime — the trait stays object-
/// safe (callable through `&dyn DidMethod`) while reading like
/// associated functions at the call site.
///
/// Required behaviour per impl is documented in
/// `docs/multi-method-hosting-spec.md` §6.1.
pub trait DidMethod: Send + Sync + 'static {
    /// Canonical method name as it appears in `did:{name}:...`.
    /// E.g. `"webvh"`, `"web"`. Lowercase, no punctuation.
    fn name(&self) -> &'static str;

    /// MIME content-type the resolution endpoint returns. E.g.
    /// `"application/jsonl"` for webvh, `"application/did+json"` for web.
    fn content_type(&self) -> &'static str;

    /// File-extension-style suffix used in the resolution URL's final
    /// segment. E.g. `"jsonl"` for webvh, `"json"` for web. The full
    /// resolution URL is constructed by [`Self::resolution_url`].
    fn data_ext(&self) -> &'static str;

    /// Parse a `did:{NAME}:...` identifier into its constituent parts.
    /// Returns `Err` on malformed input or if the identifier names a
    /// different method.
    fn parse_identifier(&self, did: &str) -> Result<ParsedDid, MethodError>;

    /// Build the canonical resolution URL given a domain and mnemonic.
    fn resolution_url(&self, domain: &str, mnemonic: &str) -> String;

    /// Validate stored bytes are a well-formed document of this method.
    /// Called on register, publish, and (defensively) on resolve.
    fn validate(&self, data: &[u8]) -> Result<(), MethodError>;

    /// Apply an update to existing stored data.
    ///
    /// For webvh: appends a log entry to the existing jsonl.
    /// For web: replaces the document outright (`existing` is ignored).
    ///
    /// Returns the new stored bytes.
    fn apply_update(
        &self,
        existing: Option<&[u8]>,
        new_data: &[u8],
    ) -> Result<Vec<u8>, MethodError>;
}

/// Parsed DID identifier, method-tagged.
///
/// Constructed by [`DidMethod::parse_identifier`] and carried through
/// every downstream operation (validation, storage, resolution).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDid {
    /// `&'static str` because it's always one of the registered method
    /// names from `method_by_name` (or a future addition there). Never
    /// caller-supplied.
    pub method: &'static str,

    /// Self-Certifying IDentifier — webvh has it, web doesn't.
    /// `None` for methods that don't use SCIDs.
    pub scid: Option<String>,

    /// Hostname portion of the DID. Normalised: lowercase + IDNA
    /// per T15 (multi-domain).
    pub domain: String,

    /// Path portion of the DID. Multi-segment paths are joined with
    /// `:` in the DID identifier and with `/` in the resolution URL;
    /// stored here in the `:` form for round-trip with the original
    /// identifier.
    ///
    /// Empty string for "no path" (resolves at `/.well-known/...`).
    pub path: String,
}

/// Errors at the method-abstraction layer.
///
/// Deliberately narrow — concrete error types for the specific failure
/// modes a method impl can produce. Higher-level callers map these
/// into `crate::server::error::AppError::Validation` (or similar) at
/// the trait boundary.
#[derive(Debug, thiserror::Error)]
pub enum MethodError {
    /// The identifier wasn't parseable as a `did:{method}:...` URL.
    /// Carries the offending string so debug logs and 400 responses
    /// can echo the bad input.
    #[error("malformed DID identifier: {0}")]
    Malformed(String),

    /// The identifier was well-formed but named a different method
    /// than the one being asked to parse it. E.g. handing
    /// `did:web:example.com:user` to `Webvh::parse_identifier`.
    #[error("DID method mismatch: expected {expected}, found {found}")]
    MethodMismatch {
        expected: &'static str,
        found: String,
    },

    /// Stored bytes failed method-specific validation (bad JSON, wrong
    /// `id` field, broken jsonl chain, …). Carries a human-readable
    /// reason for diagnostics.
    #[error("validation failed: {0}")]
    Validation(String),
}

/// Look up a method impl by its canonical name.
///
/// Returns `Some(&'static dyn DidMethod)` if the named method is
/// compiled into the binary (gated by `#[cfg(feature = "method-...")]`).
/// Returns `None` for unknown names AND for known methods whose feature
/// is disabled — callers can't tell the difference and shouldn't need
/// to. Both cases route to the same 400 response upstream.
///
/// In T10 this dispatcher is intentionally empty. T11 adds the webvh
/// arm; T24 adds the web arm.
#[allow(clippy::needless_return)] // future arms make this expression-form
pub fn method_by_name(name: &str) -> Option<&'static dyn DidMethod> {
    // Static refs to zero-size unit-struct impls. `dyn DidMethod`
    // dispatch is via `&self`, so a single static instance per method
    // is enough — there's no per-call state.
    #[cfg(feature = "method-webvh")]
    static WEBVH: webvh::Webvh = webvh::Webvh;
    #[cfg(feature = "method-web")]
    static WEB: web::Web = web::Web;
    #[cfg(feature = "method-webs")]
    static WEBS: webs::Webs = webs::Webs;

    match name {
        #[cfg(feature = "method-webvh")]
        "webvh" => Some(&WEBVH),
        #[cfg(feature = "method-web")]
        "web" => Some(&WEB),
        #[cfg(feature = "method-webs")]
        "webs" => Some(&WEBS),
        _ => None,
    }
}

/// Enabled methods, in declaration order. Used by the daemon's startup
/// log, by `/api/config`, and by the UI's method-selector dropdown
/// (which renders the same order).
///
/// Compile-time-constructed via const-fn-style match arms — disabling a
/// feature removes its entry without runtime cost.
pub fn enabled_methods() -> &'static [&'static str] {
    // The compiler concatenates `#[cfg]`-gated array entries at compile
    // time, so disabling a feature literally removes its element from
    // the slice.
    &[
        #[cfg(feature = "method-webvh")]
        "webvh",
        #[cfg(feature = "method-web")]
        "web",
        #[cfg(feature = "method-webs")]
        "webs",
    ]
}

/// Infer which method a submitted publication belongs to, from the
/// bytes alone.
///
/// The management API's request body carries the content, not the
/// method, and the method has to be known before anything can verify
/// it. Rather than trust a caller-supplied label — which could name one
/// method for a payload that is really another, and so pick a verifier
/// that waves it through — the shape of the payload decides.
///
/// The three enabled methods are distinguishable without ambiguity:
///
/// - **webvh** — line-delimited JSON whose first entry carries
///   `versionId`. No other method's artifact has that field.
/// - **webs** — a CESR stream containing an inception event. Note the
///   check is *not* "does it parse": the CESR parser reads a bare JSON
///   object as a message, so a webvh log line parses as a stream too.
///   Requiring the inception event is what separates them, and
///   `webs::Webs::validate` owns that rule.
/// - **web** — a single JSON object whose `id` is a `did:web:` DID.
///
/// Order matters: webvh is checked first because it is the cheapest and
/// most specific test, and because its log lines would otherwise reach
/// the webs check, which has to reject them on a subtler ground.
///
/// Returns `None` when nothing matches, or when the matching method is
/// not compiled in — callers map both to the same rejection, since a
/// payload for a disabled method is exactly as unhostable as an
/// unrecognised one.
pub fn detect_method(data: &[u8]) -> Option<&'static str> {
    let text = std::str::from_utf8(data).ok();

    // ---- webvh: jsonl whose first entry has `versionId` ----
    #[cfg(feature = "method-webvh")]
    if let Some(text) = text
        && let Some(line) = text.lines().find(|l| !l.trim().is_empty())
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(line)
        && v.get("versionId").is_some()
    {
        return Some("webvh");
    }

    // ---- webs: a CESR stream carrying an inception event ----
    #[cfg(feature = "method-webs")]
    if webs::Webs.validate(data).is_ok() {
        return Some("webs");
    }

    // ---- web: one JSON object with a did:web `id` ----
    #[cfg(feature = "method-web")]
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data)
        && v.get("id")
            .and_then(|i| i.as_str())
            .is_some_and(|id| id.starts_with("did:web:"))
    {
        return Some("web");
    }

    let _ = text;
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test-only no-op impl proves the trait is object-safe — i.e.
    /// you can construct a `&'static dyn DidMethod` from a zero-size
    /// unit struct. The real impls (`Web`, `Webvh`) ship in T11/T24.
    struct NoopMethod;
    impl DidMethod for NoopMethod {
        fn name(&self) -> &'static str {
            "noop"
        }
        fn content_type(&self) -> &'static str {
            "application/octet-stream"
        }
        fn data_ext(&self) -> &'static str {
            "bin"
        }
        fn parse_identifier(&self, _did: &str) -> Result<ParsedDid, MethodError> {
            Err(MethodError::Malformed("noop test impl".into()))
        }
        fn resolution_url(&self, domain: &str, mnemonic: &str) -> String {
            format!("https://{domain}/{mnemonic}/data.bin")
        }
        fn validate(&self, _data: &[u8]) -> Result<(), MethodError> {
            Ok(())
        }
        fn apply_update(
            &self,
            _existing: Option<&[u8]>,
            new_data: &[u8],
        ) -> Result<Vec<u8>, MethodError> {
            Ok(new_data.to_vec())
        }
    }

    static NOOP: NoopMethod = NoopMethod;

    #[test]
    fn trait_is_object_safe() {
        let m: &'static dyn DidMethod = &NOOP;
        assert_eq!(m.name(), "noop");
        assert_eq!(m.content_type(), "application/octet-stream");
        assert_eq!(m.data_ext(), "bin");
    }

    #[test]
    fn resolution_url_composes_method_specific_path() {
        let url = NOOP.resolution_url("example.com", "tenant/user1");
        assert_eq!(url, "https://example.com/tenant/user1/data.bin");
    }

    #[test]
    fn parse_identifier_can_surface_malformed() {
        let err = NOOP
            .parse_identifier("not-a-did")
            .expect_err("noop impl rejects everything");
        assert!(matches!(err, MethodError::Malformed(_)));
    }

    #[cfg(feature = "method-webvh")]
    #[test]
    fn dispatcher_routes_webvh() {
        let m = method_by_name("webvh").expect("webvh feature enabled in default build");
        assert_eq!(m.name(), "webvh");
    }

    #[test]
    fn dispatcher_returns_none_for_unknown() {
        assert!(method_by_name("anything-not-a-method").is_none());
    }

    #[cfg(feature = "method-web")]
    #[test]
    fn dispatcher_routes_web() {
        let m = method_by_name("web").expect("web feature enabled in default build");
        assert_eq!(m.name(), "web");
        assert_eq!(m.content_type(), "application/did+json");
    }

    #[cfg(not(feature = "method-web"))]
    #[test]
    fn dispatcher_returns_none_for_web_when_feature_off() {
        assert!(method_by_name("web").is_none());
    }

    #[cfg(feature = "method-webvh")]
    #[test]
    fn enabled_methods_contains_webvh() {
        assert!(enabled_methods().contains(&"webvh"));
    }

    #[cfg(feature = "method-web")]
    #[test]
    fn enabled_methods_contains_web() {
        assert!(enabled_methods().contains(&"web"));
    }

    #[cfg(not(any(feature = "method-webvh", feature = "method-web")))]
    #[test]
    fn enabled_methods_is_empty_when_no_method_feature() {
        assert!(enabled_methods().is_empty());
    }

    #[test]
    fn parsed_did_round_trips_through_debug() {
        let p = ParsedDid {
            method: "noop",
            scid: Some("Q1Hh3jBb2".into()),
            domain: "example.com".into(),
            path: "tenant:user1".into(),
        };
        let dbg = format!("{p:?}");
        assert!(dbg.contains("noop"));
        assert!(dbg.contains("example.com"));
        assert!(dbg.contains("tenant:user1"));
    }

    #[test]
    fn method_error_method_mismatch_carries_both_sides() {
        let err = MethodError::MethodMismatch {
            expected: "web",
            found: "webvh".to_string(),
        };
        let s = err.to_string();
        assert!(s.contains("web"));
        assert!(s.contains("webvh"));
    }
}

#[cfg(test)]
mod detect_tests {
    use super::*;

    #[cfg(feature = "method-webs")]
    const KERI: &[u8] = include_bytes!("../../tests/fixtures/ENro7uf0.keri.cesr");

    const WEBVH_LOG: &[u8] = br#"{"versionId":"1-QmABC","versionTime":"2025-01-01T00:00:00Z","state":{"id":"did:webvh:QmABC:example.com:user1"}}"#;
    const WEB_DOC: &[u8] = br#"{"id":"did:web:example.com:user1","verificationMethod":[]}"#;

    #[cfg(feature = "method-webvh")]
    #[test]
    fn detects_webvh_from_a_log_line() {
        assert_eq!(detect_method(WEBVH_LOG), Some("webvh"));
    }

    #[cfg(feature = "method-web")]
    #[test]
    fn detects_web_from_a_document() {
        assert_eq!(detect_method(WEB_DOC), Some("web"));
    }

    #[cfg(feature = "method-webs")]
    #[test]
    fn detects_webs_from_a_cesr_stream() {
        assert_eq!(detect_method(KERI), Some("webs"));
    }

    /// The ambiguity that motivates the ordering: a webvh log line is
    /// also a parseable CESR stream. If webs were checked first — or if
    /// its check were "does it parse" rather than "does it carry an
    /// inception event" — every webvh publish would be routed to the
    /// KERI verifier and rejected.
    #[cfg(all(feature = "method-webvh", feature = "method-webs"))]
    #[test]
    fn a_webvh_log_is_never_mistaken_for_a_cesr_stream() {
        assert_eq!(detect_method(WEBVH_LOG), Some("webvh"));
        assert!(
            webs::Webs.validate(WEBVH_LOG).is_err(),
            "a webvh log line must not pass the webs stream check",
        );
    }

    /// The converse: a CESR stream must not be read as a did:web
    /// document. Its first message is a JSON object, but it has no
    /// `id`, so the web arm cannot claim it either.
    #[cfg(all(feature = "method-webs", feature = "method-web"))]
    #[test]
    fn a_cesr_stream_is_never_mistaken_for_a_web_document() {
        assert_eq!(detect_method(KERI), Some("webs"));
    }

    #[test]
    fn returns_none_for_unrecognised_bytes() {
        assert_eq!(detect_method(b""), None);
        assert_eq!(detect_method(b"not anything"), None);
        // Valid JSON, but no method claims it.
        assert_eq!(detect_method(br#"{"hello":"world"}"#), None);
        // A DID document for a method this service does not host.
        assert_eq!(detect_method(br#"{"id":"did:key:z6Mk"}"#), None);
    }
}
