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
//! build enables `method-webvh` + `method-web`; `method-webs` /
//! `method-webplus` are scaffolded for future work.
//!
//! ## T10 scope
//!
//! This commit ships **the trait + dispatcher skeleton** with no per-
//! method impls. `method_by_name` returns `None` for every name; the
//! dispatcher is wired so T11 (webvh impl) and T24 (web impl) drop in
//! as small additions.

pub mod parse;

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
    match name {
        // T11 will add:
        //   #[cfg(feature = "method-webvh")]
        //   "webvh" => Some(&methods::webvh::Webvh),
        //
        // T24 will add:
        //   #[cfg(feature = "method-web")]
        //   "web" => Some(&methods::web::Web),
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
    &[
        // T11: `#[cfg(feature = "method-webvh")] "webvh"`
        // T24: `#[cfg(feature = "method-web")] "web"`
    ]
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

    #[test]
    fn dispatcher_is_empty_in_t10() {
        // Nothing is registered yet; T11 (webvh) + T24 (web) populate.
        assert!(method_by_name("webvh").is_none());
        assert!(method_by_name("web").is_none());
        assert!(method_by_name("anything").is_none());
    }

    #[test]
    fn enabled_methods_is_empty_in_t10() {
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
