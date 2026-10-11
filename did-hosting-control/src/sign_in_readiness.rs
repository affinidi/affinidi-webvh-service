//! Self-check: does this server's own DID document advertise what wallet
//! sign-in (`auth/oob/*`, contract C4) needs?
//!
//! A wallet reading a sign-in trigger link resolves the service DID and looks
//! for these services on it:
//!
//! - `#sign-in-portal`, `SignInPortal`, `"<origin>/login"` (whose origin it
//!   compares with the page the link came from) — **required**;
//! - `#trust-tasks`, `TrustTaskHTTPS`, `"<origin>/api"` (where it sends the
//!   `auth/oob/*` tasks) — **required**;
//! - `#webvh-hosting`, `WebVHHosting`, `{ "uri": "<public_url>" }` —
//!   **recommended**. The wallet uses it only to decide whether to offer a
//!   server it does not know yet the "Use <host> to host your DIDs?" join; a
//!   person whose wallet already knows the server signs in without it. So a
//!   missing or wrong `WebVHHosting` never stops the login page offering
//!   wallet sign-in. This is consistent with CLAUDE.md's rule that a
//!   mediator-configured node advertises only its messaging transports, not
//!   `WebVHHosting`: such a node signs in fine, and simply won't be offered
//!   the wallet join.
//!
//! A server DID minted from a template that lacks the required ones serves
//! everything else perfectly well, and the wallet only says "This code can't
//! be used" (the `did:webvh:…:webvh.storm.ws` case). So at startup a background task
//! resolves the server's own DID with the service's resolver, checks the
//! latest document, and logs one warning naming what is missing or wrong, the exact
//! JSON to add (built with the same `did_hosting_common::did::add_*` helpers
//! a self-managed daemon uses) and the command that publishes the fix. It
//! re-checks every [`RECHECK_INTERVAL`], so a fix is picked up without a
//! restart.
//!
//! The result is also served, read-only and unauthenticated, at
//! `GET /api/sign-in/readiness` ([`readiness_endpoint`]): the login page
//! reads it to decide whether to offer wallet sign-in. It names only the
//! service types that are missing or wrong (required and recommended apart), which anyone can already read
//! from the public DID document. A failed resolution is reported as
//! `unknown`, never as missing, and the page then still offers the sign-in:
//! a transient failure must not hide it.
//!
//! Kept apart from [`crate::oob`] on purpose: the check is about the
//! published document, not the sign-in state machine.

use std::sync::RwLock;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use axum::Json;
use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use did_hosting_common::did::{
    SERVICE_TYPE_SIGN_IN_PORTAL, add_sign_in_portal_service, add_trust_task_https_service,
    add_webvh_hosting_service, is_https_or_loopback,
};
use serde_json::{Value, json};
use tracing::{info, warn};

use crate::server::AppState;

/// How often a known result is re-checked.
pub const RECHECK_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// How soon a failed resolution is retried.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(60);
/// The delay before the first check, so the listener that may itself serve
/// the DID (the daemon) is up first.
const FIRST_CHECK_DELAY: Duration = Duration::from_secs(5);

/// A service wallet sign-in reads on the server's DID document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignInService {
    SignInPortal,
    TrustTaskHttps,
    WebVhHosting,
}

impl SignInService {
    /// In the order the warning and the login page list them.
    pub const ALL: [SignInService; 3] = [
        SignInService::SignInPortal,
        SignInService::TrustTaskHttps,
        SignInService::WebVhHosting,
    ];

    /// The service `type`.
    pub fn type_name(self) -> &'static str {
        match self {
            SignInService::SignInPortal => SERVICE_TYPE_SIGN_IN_PORTAL,
            SignInService::TrustTaskHttps => "TrustTaskHTTPS",
            SignInService::WebVhHosting => "WebVHHosting",
        }
    }

    /// Whether sign-in fails without it. `WebVHHosting` is only recommended:
    /// it decides whether a wallet that does not know this server offers to
    /// add it, nothing more.
    pub fn is_required(self) -> bool {
        !matches!(self, SignInService::WebVhHosting)
    }

    /// The `id` fragment the `add_*` helpers give it.
    fn fragment(self) -> &'static str {
        match self {
            SignInService::SignInPortal => "#sign-in-portal",
            SignInService::TrustTaskHttps => "#trust-tasks",
            SignInService::WebVhHosting => "#webvh-hosting",
        }
    }
}

/// What is wrong with one service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Defect {
    /// No service of this type, and none with its `id` either.
    Missing,
    /// A service with the expected `id`, but another `type`.
    WrongType { found: String },
    /// A service of this type whose endpoint is not the one sign-in needs.
    WrongEndpoint { found: String, expected: String },
}

/// One service that is missing or wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    pub service: SignInService,
    pub defect: Defect,
}

/// The outcome of a check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Readiness {
    /// The document resolved; these services are missing or wrong (empty
    /// when all is well). Sign-in is set up unless one of them is required.
    Checked(Vec<Problem>),
    /// The check could not run (resolution failed, no resolver, no public
    /// URL). Not the same as missing: the sign-in is still offered.
    Unknown(String),
}

impl Readiness {
    /// The required services that are missing or wrong.
    pub fn missing_required(&self) -> Vec<&Problem> {
        self.problems()
            .filter(|p| p.service.is_required())
            .collect()
    }

    /// The recommended services that are missing or wrong.
    pub fn missing_recommended(&self) -> Vec<&Problem> {
        self.problems()
            .filter(|p| !p.service.is_required())
            .collect()
    }

    /// Whether the login page should offer wallet sign-in: yes unless a
    /// required service is known to be missing or wrong.
    pub fn offers_sign_in(&self) -> bool {
        self.missing_required().is_empty()
    }

    fn problems(&self) -> impl Iterator<Item = &Problem> {
        match self {
            Readiness::Checked(p) => p.iter(),
            Readiness::Unknown(_) => [].iter(),
        }
    }
}

/// The public origin (`scheme://host[:port]`) of `url`, as a browser writes
/// it; `None` unless it is an `http`/`https` URL with a host.
fn origin_of(url: &str) -> Option<String> {
    let u = url::Url::parse(url).ok()?;
    if !matches!(u.scheme(), "http" | "https") {
        return None;
    }
    let origin = u.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

/// The endpoints sign-in expects, derived from `public_url` exactly as setup
/// derives them (`setup_recipe::apply`).
struct Expected {
    public_url: String,
    origin: String,
}

impl Expected {
    fn new(public_url: &str) -> Option<Self> {
        let origin = origin_of(public_url)?;
        Some(Self {
            public_url: public_url.trim_end_matches('/').to_string(),
            origin,
        })
    }

    fn endpoint(&self, service: SignInService) -> String {
        match service {
            SignInService::SignInPortal => format!("{}/login", self.origin),
            SignInService::TrustTaskHttps => format!("{}/api", self.origin),
            SignInService::WebVhHosting => self.public_url.clone(),
        }
    }

    /// Whether `endpoint` (a string, or an object's `uri`) is acceptable for
    /// `service`.
    fn accepts(&self, service: SignInService, endpoint: &Value) -> bool {
        let uri = match (service, endpoint) {
            // `WebVHHosting` is an object carrying `uri` (what a VTA's
            // `servers add` reads), never a bare string.
            (SignInService::WebVhHosting, Value::Object(m)) => m.get("uri"),
            (SignInService::WebVhHosting, _) => None,
            (_, Value::String(_)) => Some(endpoint),
            (_, Value::Object(m)) => m.get("uri"),
            _ => None,
        };
        let Some(uri) = uri.and_then(Value::as_str) else {
            return false;
        };
        if !is_https_or_loopback(uri) {
            return false;
        }
        match service {
            // The base the caller composes `<base>/trust-tasks` from.
            SignInService::TrustTaskHttps => {
                uri.trim_end_matches('/') == self.endpoint(SignInService::TrustTaskHttps)
            }
            // A wallet refuses a portal on another origin (`wrong-origin`).
            SignInService::SignInPortal | SignInService::WebVhHosting => {
                origin_of(uri).as_deref() == Some(self.origin.as_str())
            }
        }
    }
}

/// The `type` of a service as a list (a string or an array of strings).
fn types_of(service: &Value) -> Vec<&str> {
    match service.get("type") {
        Some(Value::String(t)) => vec![t.as_str()],
        Some(Value::Array(ts)) => ts.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

/// Check `doc`, the server's own resolved DID document, against what wallet
/// sign-in needs at `public_url`.
pub fn check_document(doc: &Value, public_url: &str) -> Readiness {
    let Some(expected) = Expected::new(public_url) else {
        return Readiness::Unknown("public_url is not an http(s) URL".into());
    };
    let services: &[Value] = doc
        .get("service")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();

    let mut problems = Vec::new();
    for required in SignInService::ALL {
        let of_type: Vec<&Value> = services
            .iter()
            .filter(|s| types_of(s).contains(&required.type_name()))
            .collect();
        let endpoint_of = |s: &Value| s.get("serviceEndpoint").cloned().unwrap_or(Value::Null);
        if of_type
            .iter()
            .any(|s| expected.accepts(required, &endpoint_of(s)))
        {
            continue;
        }
        let defect = if let Some(first) = of_type.first() {
            let found = endpoint_of(first);
            Defect::WrongEndpoint {
                found: found
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| found.to_string()),
                expected: expected.endpoint(required),
            }
        } else if let Some(same_id) = services.iter().find(|s| {
            s.get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| id.ends_with(required.fragment()))
        }) {
            Defect::WrongType {
                found: types_of(same_id).join(", "),
            }
        } else {
            Defect::Missing
        };
        problems.push(Problem {
            service: required,
            defect,
        });
    }

    Readiness::Checked(problems)
}

/// The exact service entry to publish for `service`, built with the same
/// helper setup uses, so it cannot drift from what a self-managed daemon
/// writes.
pub fn fix_entry(server_did: &str, public_url: &str, service: SignInService) -> Option<Value> {
    let expected = Expected::new(public_url)?;
    let mut doc = json!({ "id": server_did });
    let endpoint = expected.endpoint(service);
    match service {
        SignInService::SignInPortal => add_sign_in_portal_service(&mut doc, &endpoint),
        SignInService::TrustTaskHttps => add_trust_task_https_service(&mut doc, &endpoint),
        SignInService::WebVhHosting => add_webvh_hosting_service(&mut doc, &endpoint),
    }
    doc["service"].as_array()?.first().cloned()
}

/// One problem, in words.
fn describe(p: &Problem) -> String {
    let name = p.service.type_name();
    match &p.defect {
        Defect::Missing => format!("{name} missing"),
        Defect::WrongType { found } => format!(
            "the {} service has type {found:?}, not {name}",
            p.service.fragment()
        ),
        Defect::WrongEndpoint { found, expected } => {
            format!("{name} points at {found:?}, it must be {expected:?}")
        }
    }
}

/// The one warning logged when the DID lacks something: what is missing or
/// wrong and what that costs, the JSON to add, and the command that
/// publishes it. Empty `problems` → `None`.
pub fn warning_text(server_did: &str, public_url: &str, problems: &[Problem]) -> Option<String> {
    if problems.is_empty() {
        return None;
    }
    let (required, recommended): (Vec<&Problem>, Vec<&Problem>) =
        problems.iter().partition(|p| p.service.is_required());
    let list = |ps: &[&Problem]| {
        ps.iter()
            .map(|p| describe(p))
            .collect::<Vec<_>>()
            .join("; ")
    };
    let mut what = Vec::new();
    if !required.is_empty() {
        what.push(format!(
            "Wallet sign-in is not set up: the server DID {server_did} does not list the \
             services wallets need ({}). Wallets will show \"This code can't be used\" until \
             it does.",
            list(&required)
        ));
    }
    if !recommended.is_empty() {
        what.push(format!(
            "Wallets that don't already know this server won't offer to add it ({}). Sign-in \
             itself works.",
            list(&recommended)
        ));
    }
    let entries: Vec<Value> = problems
        .iter()
        .filter_map(|p| fix_entry(server_did, public_url, p.service))
        .collect();
    let json = serde_json::to_string_pretty(&entries).unwrap_or_default();
    Some(format!(
        "{} Add (or replace, by id) these entries in the DID document's \"service\" array of \
         {server_did}:\n{json}\nthen publish the new log entry with:\n  \
         pnm did-mgmt dids edit --did {server_did}\n(the VTA publishes it to this host). This is \
         re-checked every {} minutes; no restart is needed.",
        what.join(" "),
        RECHECK_INTERVAL.as_secs() / 60,
    ))
}

/// Resolve the server's own DID afresh and check it.
pub async fn check(resolver: &DIDCacheClient, server_did: &str, public_url: &str) -> Readiness {
    // Drop any cached copy: the point is to see the latest published
    // document, so a fix shows up on the next check.
    resolver.remove(server_did).await;
    match resolver.resolve(server_did).await {
        Ok(resolved) => match serde_json::to_value(&resolved.doc) {
            Ok(doc) => check_document(&doc, public_url),
            Err(e) => Readiness::Unknown(format!("could not read the DID document: {e}")),
        },
        Err(e) => Readiness::Unknown(format!("could not resolve {server_did}: {e}")),
    }
}

/// The latest result, for the server DID it was computed for.
struct Snapshot {
    server_did: String,
    readiness: Readiness,
}

static LATEST: RwLock<Option<Snapshot>> = RwLock::new(None);

fn record(server_did: &str, readiness: Readiness) {
    if let Ok(mut latest) = LATEST.write() {
        *latest = Some(Snapshot {
            server_did: server_did.to_string(),
            readiness,
        });
    }
}

/// The latest result for `server_did`, `Unknown` before the first check.
pub fn latest(server_did: Option<&str>) -> Readiness {
    let not_yet = || Readiness::Unknown("not checked yet".into());
    let Some(did) = server_did else {
        return not_yet();
    };
    match LATEST.read() {
        Ok(latest) => match latest.as_ref() {
            Some(s) if s.server_did == did => s.readiness.clone(),
            _ => not_yet(),
        },
        Err(_) => not_yet(),
    }
}

/// Log a result, once per change: a repeat of the same result says nothing.
fn log_transition(server_did: &str, public_url: &str, previous: &Readiness, now: &Readiness) {
    if previous == now {
        return;
    }
    match now {
        Readiness::Checked(problems) => match warning_text(server_did, public_url, problems) {
            Some(text) => warn!("{text}"),
            None => {
                if matches!(previous, Readiness::Checked(p) if !p.is_empty()) {
                    info!("wallet sign-in: the server DID now lists the services it needs");
                }
            }
        },
        Readiness::Unknown(reason) => {
            if !matches!(previous, Readiness::Unknown(_)) {
                info!(
                    "wallet sign-in self-check could not run ({reason}); retrying in {}s",
                    RETRY_INTERVAL.as_secs()
                );
            }
        }
    }
}

/// Start the self-check in the background. Never blocks startup and never
/// fails it: a deployment without a server DID, public URL or resolver has
/// nothing to check (and `auth/oob/*` already answers 503 for the first two).
pub fn spawn(state: &AppState) {
    let (Some(server_did), Some(public_url), Some(resolver)) = (
        state.config.server_did.clone(),
        state.config.public_url.clone(),
        state.did_resolver.clone(),
    ) else {
        return;
    };
    tokio::spawn(async move {
        tokio::time::sleep(FIRST_CHECK_DELAY).await;
        let mut previous = Readiness::Unknown(String::new());
        loop {
            let now = check(&resolver, &server_did, &public_url).await;
            log_transition(&server_did, &public_url, &previous, &now);
            let wait = if matches!(now, Readiness::Unknown(_)) {
                RETRY_INTERVAL
            } else {
                RECHECK_INTERVAL
            };
            record(&server_did, now.clone());
            previous = now;
            tokio::time::sleep(wait).await;
        }
    });
}

/// The public body of `GET /api/sign-in/readiness`: the state; for
/// `not-set-up` the required service types that are missing or wrong
/// (`missingServices`); and, in either checked state, the recommended ones
/// (`missingRecommended`), when there are any. Nothing else.
pub fn response_body(readiness: &Readiness) -> Value {
    let names = |ps: Vec<&Problem>| -> Vec<&'static str> {
        ps.iter().map(|p| p.service.type_name()).collect()
    };
    let mut body = match readiness {
        Readiness::Unknown(_) => return json!({ "walletSignIn": "unknown" }),
        Readiness::Checked(_) if readiness.offers_sign_in() => json!({ "walletSignIn": "ready" }),
        Readiness::Checked(_) => json!({
            "walletSignIn": "not-set-up",
            "missingServices": names(readiness.missing_required()),
        }),
    };
    let recommended = names(readiness.missing_recommended());
    if !recommended.is_empty() {
        body["missingRecommended"] = json!(recommended);
    }
    body
}

/// `GET /api/sign-in/readiness`: the latest self-check result. Reads the
/// cache only; it never triggers a resolution.
pub async fn readiness_endpoint(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(response_body(&latest(state.config.server_did.as_deref()))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:webvh:QmSNo2TJRq5xiiYhHZNrTqoaq8bivffWq4PZXjQQAzvNtr:webvh.storm.ws";
    const URL: &str = "https://webvh.storm.ws";

    fn entry(service: SignInService) -> Value {
        fix_entry(DID, URL, service).unwrap()
    }

    fn doc_with(services: Vec<Value>) -> Value {
        json!({ "id": DID, "service": services })
    }

    fn complete() -> Vec<Value> {
        SignInService::ALL.iter().map(|s| entry(*s)).collect()
    }

    /// Every problem a check found (required and recommended).
    fn problems(r: Readiness) -> Vec<Problem> {
        match r {
            Readiness::Checked(p) => p,
            other => panic!("expected Checked, got {other:?}"),
        }
    }

    const READY: Readiness = Readiness::Checked(Vec::new());

    #[test]
    fn all_present_is_ready() {
        assert_eq!(check_document(&doc_with(complete()), URL), READY);
        // With other services around them, and a trailing slash on public_url.
        let mut services = complete();
        services.insert(
            0,
            json!({"id": format!("{DID}#didcomm"), "type": "DIDCommMessaging", "serviceEndpoint": "x"}),
        );
        assert_eq!(
            check_document(&doc_with(services), "https://webvh.storm.ws/"),
            READY
        );
    }

    #[test]
    fn the_resolver_shape_is_accepted() {
        // `affinidi-did-common` serialises `type` as an array.
        let mut services = complete();
        for s in &mut services {
            let t = s["type"].clone();
            s["type"] = json!([t]);
        }
        assert_eq!(check_document(&doc_with(services), URL), READY);
    }

    #[test]
    fn no_services_lists_all_three_in_order() {
        let problems = problems(check_document(&json!({ "id": DID }), URL));
        let names: Vec<_> = problems.iter().map(|p| p.service.type_name()).collect();
        assert_eq!(names, ["SignInPortal", "TrustTaskHTTPS", "WebVHHosting"]);
        assert!(problems.iter().all(|p| p.defect == Defect::Missing));
    }

    #[test]
    fn each_missing_service_is_named_alone() {
        for missing in SignInService::ALL {
            let services = complete()
                .into_iter()
                .filter(|s| s["type"] != missing.type_name())
                .collect();
            let r = check_document(&doc_with(services), URL);
            assert_eq!(r.offers_sign_in(), !missing.is_required(), "{missing:?}");
            assert_eq!(
                problems(r),
                vec![Problem {
                    service: missing,
                    defect: Defect::Missing
                }]
            );
        }
    }

    fn with_endpoint(service: SignInService, endpoint: Value) -> Vec<Value> {
        complete()
            .into_iter()
            .map(|mut s| {
                if s["type"] == service.type_name() {
                    s["serviceEndpoint"] = endpoint.clone();
                }
                s
            })
            .collect()
    }

    #[test]
    fn a_trust_task_base_other_than_origin_api_is_wrong() {
        for bad in [
            json!("https://webvh.storm.ws"),
            json!("https://webvh.storm.ws/api/trust-tasks"),
            json!("https://other.example/api"),
            json!("http://webvh.storm.ws/api"),
        ] {
            let problems = problems(check_document(
                &doc_with(with_endpoint(SignInService::TrustTaskHttps, bad.clone())),
                URL,
            ));
            assert_eq!(problems.len(), 1, "{bad}");
            assert_eq!(problems[0].service, SignInService::TrustTaskHttps);
            assert!(matches!(
                &problems[0].defect,
                Defect::WrongEndpoint { expected, .. } if expected == "https://webvh.storm.ws/api"
            ));
        }
        // A trailing slash on the base is the same base.
        assert_eq!(
            check_document(
                &doc_with(with_endpoint(
                    SignInService::TrustTaskHttps,
                    json!("https://webvh.storm.ws/api/")
                )),
                URL
            ),
            READY
        );
    }

    #[test]
    fn a_portal_off_the_public_origin_or_not_https_is_wrong() {
        for bad in [
            json!("https://elsewhere.example/login"),
            json!("http://webvh.storm.ws/login"),
            json!("https://webvh.storm.ws:8443/login"),
            json!({"not": "a url"}),
        ] {
            let problems = problems(check_document(
                &doc_with(with_endpoint(SignInService::SignInPortal, bad.clone())),
                URL,
            ));
            assert_eq!(problems.len(), 1, "{bad}");
            assert_eq!(problems[0].service, SignInService::SignInPortal);
            assert!(matches!(problems[0].defect, Defect::WrongEndpoint { .. }));
        }
    }

    #[test]
    fn webvh_hosting_needs_an_object_with_a_uri_on_the_origin() {
        for bad in [
            json!("https://webvh.storm.ws"),
            json!({"uri": "https://elsewhere.example"}),
        ] {
            let r = check_document(
                &doc_with(with_endpoint(SignInService::WebVhHosting, bad.clone())),
                URL,
            );
            // Recommended only: sign-in is still offered.
            assert!(r.offers_sign_in(), "{bad}");
            let problems = problems(r);
            assert_eq!(problems.len(), 1, "{bad}");
            assert_eq!(problems[0].service, SignInService::WebVhHosting);
        }
    }

    #[test]
    fn the_right_id_with_the_wrong_type_is_named() {
        let services = complete()
            .into_iter()
            .map(|mut s| {
                if s["type"] == "SignInPortal" {
                    s["type"] = json!("LinkedDomains");
                }
                s
            })
            .collect();
        let problems = problems(check_document(&doc_with(services), URL));
        assert_eq!(
            problems,
            vec![Problem {
                service: SignInService::SignInPortal,
                defect: Defect::WrongType {
                    found: "LinkedDomains".into()
                }
            }]
        );
    }

    #[test]
    fn fix_entries_are_what_setup_writes() {
        assert_eq!(
            entry(SignInService::WebVhHosting),
            json!({"id": format!("{DID}#webvh-hosting"), "type": "WebVHHosting",
                   "serviceEndpoint": {"uri": URL}})
        );
        assert_eq!(
            entry(SignInService::TrustTaskHttps),
            json!({"id": format!("{DID}#trust-tasks"), "type": "TrustTaskHTTPS",
                   "serviceEndpoint": "https://webvh.storm.ws/api"})
        );
        assert_eq!(
            entry(SignInService::SignInPortal),
            json!({"id": format!("{DID}#sign-in-portal"), "type": "SignInPortal",
                   "serviceEndpoint": "https://webvh.storm.ws/login"})
        );
    }

    #[test]
    fn the_warning_has_the_json_and_the_command() {
        let problems = problems(check_document(&json!({ "id": DID }), URL));
        let text = warning_text(DID, URL, &problems).unwrap();
        assert!(text.contains("Wallet sign-in is not set up"));
        assert!(text.contains("SignInPortal missing"));
        assert!(text.contains("TrustTaskHTTPS missing"));
        assert!(text.contains("This code can't be used"));
        assert!(text.contains(
            "Wallets that don't already know this server won't offer to add it \
             (WebVHHosting missing)"
        ));
        let entries: Vec<Value> = problems.iter().map(|p| entry(p.service)).collect();
        assert!(text.contains(&serde_json::to_string_pretty(&entries).unwrap()));
        assert!(text.contains(&format!("pnm did-mgmt dids edit --did {DID}")));
    }

    #[test]
    fn the_warning_lists_only_what_is_wrong() {
        let problems = vec![Problem {
            service: SignInService::TrustTaskHttps,
            defect: Defect::WrongEndpoint {
                found: "https://webvh.storm.ws".into(),
                expected: "https://webvh.storm.ws/api".into(),
            },
        }];
        let text = warning_text(DID, URL, &problems).unwrap();
        assert!(text.contains("TrustTaskHTTPS points at \"https://webvh.storm.ws\""));
        assert!(text.contains("#trust-tasks"));
        assert!(!text.contains("#sign-in-portal"));
        assert!(!text.contains("#webvh-hosting"));
        assert!(!text.contains("won't offer to add it"));
        // Nothing wrong, nothing to warn about.
        assert_eq!(warning_text(DID, URL, &[]), None);
    }

    #[test]
    fn a_missing_webvh_hosting_alone_warns_softly_and_keeps_sign_in() {
        let services = complete()
            .into_iter()
            .filter(|s| s["type"] != "WebVHHosting")
            .collect();
        let r = check_document(&doc_with(services), URL);
        assert!(r.offers_sign_in());
        let text = warning_text(DID, URL, &problems(r)).unwrap();
        assert!(text.starts_with(
            "Wallets that don't already know this server won't offer to add it \
             (WebVHHosting missing)."
        ));
        assert!(!text.contains("This code can't be used"));
        assert!(text.contains(
            &serde_json::to_string_pretty(&[entry(SignInService::WebVhHosting)]).unwrap()
        ));
        assert!(text.contains(&format!("pnm did-mgmt dids edit --did {DID}")));
    }

    #[test]
    fn unknown_is_not_missing_and_still_offers_sign_in() {
        let unknown = Readiness::Unknown("resolver timed out".into());
        assert!(unknown.offers_sign_in());
        assert_eq!(
            response_body(&unknown),
            json!({ "walletSignIn": "unknown" })
        );
        // A public URL the check cannot use is unknown too, not missing.
        assert!(matches!(
            check_document(&json!({ "id": DID }), "not a url"),
            Readiness::Unknown(_)
        ));
        // Before the first check, and for another DID, the answer is unknown.
        assert!(matches!(latest(None), Readiness::Unknown(_)));
        assert!(matches!(
            latest(Some("did:example:never-checked")),
            Readiness::Unknown(_)
        ));
    }

    #[test]
    fn the_endpoint_separates_required_from_recommended() {
        // Only WebVHHosting present: the two required ones block.
        let r = check_document(&doc_with(vec![entry(SignInService::WebVhHosting)]), URL);
        assert!(!r.offers_sign_in());
        assert_eq!(
            response_body(&r),
            json!({ "walletSignIn": "not-set-up",
                    "missingServices": ["SignInPortal", "TrustTaskHTTPS"] })
        );
        // Nothing at all: both lists.
        assert_eq!(
            response_body(&check_document(&json!({ "id": DID }), URL)),
            json!({ "walletSignIn": "not-set-up",
                    "missingServices": ["SignInPortal", "TrustTaskHTTPS"],
                    "missingRecommended": ["WebVHHosting"] })
        );
        // Only WebVHHosting missing: ready, with the recommendation.
        let services = complete()
            .into_iter()
            .filter(|s| s["type"] != "WebVHHosting")
            .collect();
        assert_eq!(
            response_body(&check_document(&doc_with(services), URL)),
            json!({ "walletSignIn": "ready", "missingRecommended": ["WebVHHosting"] })
        );
        assert_eq!(response_body(&READY), json!({ "walletSignIn": "ready" }));
    }

    #[test]
    fn a_change_is_recorded_per_did() {
        let did = "did:example:recorded-per-did";
        record(did, READY);
        assert_eq!(latest(Some(did)), READY);
    }
}
