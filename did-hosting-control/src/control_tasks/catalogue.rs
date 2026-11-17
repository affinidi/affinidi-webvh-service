//! `docs/trust-tasks.md`, generated from the tables the control plane routes
//! on, with a drift test.
//!
//! Every row comes from a list the gate itself reads — [`super::TASKS`], the
//! ACL family's [`ACL_TASK_URIS`], the auth family's dispatcher and the
//! infrastructure family's [`crate::messaging::infra::INFRA_TASK_URIS`] —
//! and its proof rule from [`crate::messaging::proof_rule`], the function the
//! gate calls. Only the *standing* column is written here by hand
//! ([`STANDING`]), because it lives in each handler's body; the test fails
//! when a served task has no entry, or an entry names a task nobody serves.
//!
//! Regenerate with:
//!
//! ```text
//! UPDATE_TRUST_TASKS=1 cargo test -p did-hosting-control --lib trust_task_catalogue
//! ```

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::PathBuf;

use did_hosting_common::server::trust_tasks::{ACL_TASK_URIS, ProofRule};

/// Who may send each task, as its handler decides it. Keyed on the Type URI
/// (the generated `TYPE_URI` strings, spelled out so the catalogue reads as a
/// table). "member" means any ACL entry other than `metricsReader`, which
/// `Cx::auth` refuses on every general task.
const STANDING: &[(&str, &str)] = &[
    // DID slots.
    (
        "did-management/did/check-name/0.1",
        "member (a reservation is owned by the caller)",
    ),
    (
        "did-management/did/register/0.1",
        "member; owner or admin to update an existing slot; or a self-registering `did:webs` (`[[hosting.webs_self_register]]`)",
    ),
    ("did-management/did/info/0.1", "slot owner or admin"),
    (
        "did-management/did/list/0.2",
        "member (own slots); admin to list another owner's",
    ),
    (
        "did-management/did/delete/0.1",
        "slot owner or admin; an `aal2` session over HTTPS when one is presented",
    ),
    (
        "did-management/did/change-owner/0.1",
        "slot owner or admin (the recipient accepts an owner's offer)",
    ),
    (
        "did-management/did/set-state/0.1",
        "slot owner or admin (an administrator's suspension only an administrator lifts)",
    ),
    ("did-management/did/rollback/0.1", "slot owner or admin"),
    ("did-management/did/log/0.1", "slot owner or admin"),
    ("webvh/witness/publish/0.1", "slot owner or admin"),
    // Agent names.
    (
        "did-management/agent-name/update/0.1",
        "owner of the DID, or admin (with a new signed log)",
    ),
    (
        "did-management/agent-name/remove/0.1",
        "owner of the DID holding the name, or admin (with a new signed log)",
    ),
    ("did-management/agent-name/list/0.1", "member"),
    ("did-management/agent-name/check/0.1", "member"),
    ("did-management/agent-name/resolve/0.1", "member"),
    // Domains.
    (
        "did-management/me/domains/0.1",
        "member (the caller's own domains)",
    ),
    ("did-management/domain/list/0.1", "admin"),
    ("did-management/domain/create/0.1", "admin"),
    ("did-management/domain/update/0.1", "admin"),
    ("did-management/domain/set-state/0.1", "admin"),
    ("did-management/domain/set-default/0.1", "admin"),
    ("did-management/domain/purge/0.1", "admin"),
    ("did-management/domain/assign/0.1", "admin"),
    ("did-management/domain/unassign/0.1", "admin"),
    // The fleet.
    ("did-management/registry/list/0.2", "admin"),
    ("did-management/registry/get/0.2", "admin"),
    ("did-management/registry/check/0.2", "admin"),
    ("did-management/registry/admin-register/0.2", "admin"),
    ("did-management/registry/deregister/0.1", "admin"),
    (
        "did-management/registry/purge-domain/0.1",
        "admin; an `aal2` session over HTTPS when one is presented",
    ),
    // The service.
    (
        "did-management/server/info/0.1",
        "anyone (unsigned allowed)",
    ),
    ("did-management/server/config/0.1", "admin"),
    (
        "did-management/server/metrics/0.1",
        "admin or `metricsReader` (gauges: admin only)",
    ),
    (
        "did-management/stats/get/0.1",
        "slot owner or admin (whole-service totals: admin)",
    ),
    (
        "did-management/stats/set-resolution/0.1",
        "slot owner (up to `coarse`) or admin",
    ),
    (
        "did-management/stats/timeseries/0.2",
        "slot owner or admin (domain series: admin)",
    ),
    ("did-management/identity/list/0.1", "admin"),
    (
        "did-management/identity/retire/0.1",
        "admin; an `aal2` session over HTTPS when one is presented",
    ),
    // Sessions and step-up.
    ("auth/step-up/start/0.2", "the session's subject"),
    (
        "auth/step-up/approve-response/0.7",
        "the approver named in the step-up request (an ACL member)",
    ),
    ("auth/revoke-session/0.2", "the session's subject"),
    ("auth/passkey/login/start/0.2", "anyone (unsigned allowed)"),
    (
        "auth/passkey/login/finish/0.2",
        "the `did:key` the login ceremony is bound to; the passkey's subject must be in the ACL",
    ),
    // Passkey enrolment and management.
    (
        "auth/passkey/enroll/invite/0.3",
        "admin, with an `aal2` session or a request signed by the admin's own DID key",
    ),
    (
        "auth/passkey/enroll/redeem/start/0.1",
        "the invite token and claim code (unsigned allowed)",
    ),
    (
        "auth/passkey/enroll/redeem/finish/0.1",
        "the invite token and claim code (unsigned allowed)",
    ),
    ("auth/passkey/enroll/start/0.2", "member, for themselves"),
    ("auth/passkey/enroll/finish/0.2", "member, for themselves"),
    (
        "auth/passkey/enroll/invite/list/0.1",
        "member (own invites); admin (all)",
    ),
    ("auth/passkey/enroll/invite/update/0.1", "admin"),
    ("auth/passkey/enroll/invite/revoke/0.1", "admin"),
    ("auth/passkey/list/0.1", "member (own passkeys)"),
    ("auth/passkey/admin-list/0.1", "admin"),
    (
        "auth/passkey/revoke/start/0.2",
        "member (own passkeys); admin (anyone's)",
    ),
    (
        "auth/passkey/revoke/finish/0.2",
        "member (own passkeys); admin (anyone's)",
    ),
    // Wallet sign-in (bound keys: the exchange decides which key may act).
    (
        "auth/oob/request/0.2",
        "the browser's starter key `K_b` (HTTPS only)",
    ),
    (
        "auth/oob/claim/0.2",
        "the wallet's lock key `K_a` (HTTPS only)",
    ),
    (
        "auth/oob/prove/0.3",
        "`K_a`, carrying the member's `identify` (HTTPS only)",
    ),
    (
        "auth/oob/respond/0.3",
        "`K_a`, carrying the member's `grant` (HTTPS only)",
    ),
    ("auth/oob/redeem/0.2", "`K_b` (HTTPS only)"),
    ("auth/oob/cancel/0.1", "`K_a` or `K_b` (HTTPS only)"),
    // ACL and discovery.
    ("acl/grant/0.2", "admin"),
    ("acl/revoke/0.2", "admin, or the subject revoking itself"),
    ("acl/change-role/0.2", "admin"),
    ("acl/show/0.2", "admin, or the subject looking itself up"),
    ("acl/list/0.3", "admin"),
    ("trust-task-discovery/0.4", "anyone (unsigned allowed)"),
    // Console sign-in (SIOPv2-style challenge / response).
    ("auth/challenge/0.1", "anyone (unsigned allowed)"),
    (
        "auth/authenticate/0.3",
        "an ACL member answering its challenge",
    ),
    (
        "auth/refresh/0.2",
        "the holder of the session's refresh token and bound key",
    ),
    // Infrastructure (edges and watchers).
    (
        "did-management/server/register/0.2",
        "an edge with the `service` role",
    ),
    (
        "did-management/server/health/0.1#response",
        "a registered edge (`service`)",
    ),
    (
        "did-management/server/stats-sync/0.1",
        "a registered edge (`service`)",
    ),
    (
        "webvh/sync/update/0.2#response",
        "the edge or watcher the update was sent to",
    ),
    (
        "webvh/sync/batch/0.1#response",
        "the edge or watcher the batch was sent to",
    ),
    (
        "webvh/sync/delete/0.2#response",
        "the edge or watcher the delete was sent to",
    ),
    (
        "did-management/replica/domain/assign/0.1#response",
        "the edge the op was sent to (`service`)",
    ),
    (
        "did-management/replica/domain/unassign/0.1#response",
        "the edge the op was sent to (`service`)",
    ),
    (
        "did-management/replica/domain/purge/0.1#response",
        "the edge the op was sent to (`service`)",
    ),
    (
        "did-management/replica/domain/upsert/0.1#response",
        "the edge the op was sent to (`service`)",
    ),
];

const SPEC_PREFIX: &str = "https://trusttasks.org/spec/";

/// The registry slug, version and fragment of a Type URI.
fn split(uri: &str) -> (String, String, String) {
    let rest = uri.strip_prefix(SPEC_PREFIX).unwrap_or(uri);
    let (path, fragment) = match rest.split_once('#') {
        Some((p, f)) => (p, format!("#{f}")),
        None => (rest, String::new()),
    };
    let (slug, version) = path.rsplit_once('/').unwrap_or((path, ""));
    (slug.to_owned(), version.to_owned(), fragment)
}

fn rule_name(rule: ProofRule) -> String {
    match rule {
        ProofRule::Optional => "Optional".into(),
        ProofRule::Authentication => "Authentication".into(),
        ProofRule::AssertionMethod => "AssertionMethod".into(),
        ProofRule::SessionKey => "SessionKey".into(),
        ProofRule::BoundKey(purposes) => format!("BoundKey({})", purposes.join(", ")),
        other => format!("{other:?}"),
    }
}

fn standing(uri: &str) -> Option<&'static str> {
    let key = uri.strip_prefix(SPEC_PREFIX).unwrap_or(uri);
    STANDING.iter().find(|(k, _)| *k == key).map(|(_, s)| *s)
}

/// The catalogue's sections: a heading, a sentence, and the Type URIs.
fn sections() -> Vec<(&'static str, &'static str, Vec<String>)> {
    let mut auth = crate::trust_tasks_auth::task_uris();
    auth.sort();
    vec![
        (
            "Management, sign-in and the service (`control_tasks!`)",
            "The rows of the control plane's Trust Task table \
             (`did-hosting-control/src/control_tasks/mod.rs`), in table order.",
            super::TASKS
                .iter()
                .map(|(uri, _)| (*uri).to_owned())
                .collect(),
        ),
        (
            "ACL and discovery",
            "Served by the shared framework pipeline \
             (`did_hosting_common::server::trust_tasks::ACL_TASK_URIS`).",
            ACL_TASK_URIS.iter().map(|u| (*u).to_owned()).collect(),
        ),
        (
            "Console sign-in",
            "The challenge / response sign-in the management UI uses \
             (`did-hosting-control/src/trust_tasks_auth.rs`). Each handler checks \
             its own proof against the challenge it issued.",
            auth,
        ),
        (
            "Infrastructure (from edges and watchers)",
            "What an edge or watcher sends the control plane \
             (`did-hosting-control/src/messaging/infra/mod.rs`): its registration, \
             health and stats, and the signed acknowledgements that settle the \
             control plane's outbox rows. Operators never send these.",
            crate::messaging::infra::INFRA_TASK_URIS
                .iter()
                .map(|u| (*u).to_owned())
                .collect(),
        ),
    ]
}

/// Render `docs/trust-tasks.md`.
pub(crate) fn render() -> String {
    let mut out = String::new();
    out.push_str(
        "# Trust Task catalogue\n\n\
         > **Status:** current — generated from the control plane's routing tables; \
         do not edit by hand.\n\n\
         <!-- Regenerate: UPDATE_TRUST_TASKS=1 cargo test -p did-hosting-control --lib \
         trust_task_catalogue (see did-hosting-control/src/control_tasks/catalogue.rs). -->\n\n\
         Every management operation on a control plane (standalone `did-hosting-control`, \
         or the one inside `did-hosting-daemon`) is a signed Trust Task, sent over TSP, \
         DIDComm or `POST /api/trust-tasks`; all three reach the same dispatch. This page \
         lists every task the control plane serves, the proof the gate requires before \
         the task runs, and the standing its handler then requires of the proven signer. \
         To send one yourself, see [Sending Trust Tasks](sending-trust-tasks.md).\n\n\
         Type URIs are `https://trusttasks.org/spec/<slug>/<version>`; the payload and \
         response schemas are the vendored bundles in \
         [`did-hosting-common/trust-tasks/`](../did-hosting-common/trust-tasks/), pinned by \
         `did-hosting-common/trust-tasks.lock`.\n\n\
         **Proof rules** (`ProofRule`, enforced by the gate before any handler runs):\n\n\
         | Rule | Meaning |\n\
         | ---- | ------- |\n\
         | `Optional` | May be sent unsigned; a proof that is present must verify. |\n\
         | `Authentication` | Signed by the issuer for `authentication`, addressed here, fresh, not a replay. |\n\
         | `AssertionMethod` | A human approver's decision: signed for `assertionMethod`. |\n\
         | `SessionKey` | Signed by the `did:key` a passkey login ceremony is bound to. |\n\
         | `BoundKey(…)` | Wallet sign-in: signed by a fresh key the exchange itself binds; HTTPS only. |\n\n\
         **Standing**: \"member\" is any ACL entry except `metricsReader`; \"admin\" is the \
         `admin` role. A destructive task sent with a browser session below `aal2` is \
         refused `step_up_required`; a document authorised by its signer's own key (no \
         session) is not.\n",
    );
    for (heading, blurb, uris) in sections() {
        let _ = write!(
            out,
            "\n## {heading}\n\n{blurb}\n\n\
             | Task | Version | Proof rule | Standing |\n\
             | ---- | ------- | ---------- | -------- |\n"
        );
        for uri in uris {
            let (slug, version, fragment) = split(&uri);
            let rule = rule_name(crate::messaging::proof_rule(&uri));
            let standing = standing(&uri).unwrap_or("**missing**");
            let _ = writeln!(
                out,
                "| `{slug}`{fragment} | {version} | `{rule}` | {standing} |"
            );
        }
    }
    out
}

fn doc_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("docs/trust-tasks.md")
}

#[test]
fn trust_task_catalogue_in_sync() {
    let served: BTreeSet<String> = sections()
        .into_iter()
        .flat_map(|(_, _, uris)| uris)
        .map(|u| u.strip_prefix(SPEC_PREFIX).unwrap_or(&u).to_owned())
        .collect();
    let documented: BTreeSet<String> = STANDING.iter().map(|(k, _)| (*k).to_owned()).collect();
    let missing: Vec<_> = served.difference(&documented).collect();
    let stale: Vec<_> = documented.difference(&served).collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "STANDING in control_tasks/catalogue.rs is out of step with the served tasks.\n\
         served but no standing: {missing:?}\nstanding for a task nobody serves: {stale:?}"
    );

    let rendered = render();
    let path = doc_path();
    if std::env::var_os("UPDATE_TRUST_TASKS").is_some() {
        std::fs::write(&path, &rendered).expect("write docs/trust-tasks.md");
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == rendered,
        "docs/trust-tasks.md is out of date. Regenerate it with \
         `UPDATE_TRUST_TASKS=1 cargo test -p did-hosting-control --lib trust_task_catalogue`"
    );
}
