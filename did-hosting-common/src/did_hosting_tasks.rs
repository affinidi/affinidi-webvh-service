//! Canonical Trust-Task URLs for every webvh-service operation.
//!
//! One `LazyLock<TrustTask>` per registered task — grep `TASK_` to
//! enumerate the full wire surface. Each URL is exact-match routed both
//! on REST (via the `Trust-Task:` header — see
//! [`crate::server::trust_task::TrustTaskRouter`]) and on DIDComm (via
//! the message `type` field — see
//! [`crate::server::trust_task::didcomm`]).
//!
//! ## Namespace
//!
//! Per `docs/multi-method-hosting-spec.md` §3:
//!
//! - `https://trusttasks.org/did-hosting/...` — method-agnostic ops:
//!   auth, DID provisioning lifecycle, hosting infrastructure
//!   (server-register, health, stats), domain management.
//! - `https://trusttasks.org/webvh/...` — webvh-protocol-specific ops:
//!   witness publish/confirm, sync update/delete. Future `did:webs` or
//!   `did:webplus` operations would register at `webs/...` /
//!   `webplus/...` paths.
//!
//! ## Versioning
//!
//! `{maj}.{min}` only per the canonical Trust-Tasks spec — no patch
//! component. Bumping requires registering a NEW const at a new URL;
//! the old URL keeps routing to its handler until removed in a future
//! release. The router does NOT do version-family matching — `1.0` and
//! `1.1` are completely separate identifiers.
//!
//! ## Cross-crate consistency
//!
//! T9 (the parity harness) and T51 (the client-crate URL invariant
//! test) will assert that every const here matches the client crate's
//! same-named const byte-for-byte. Edit both in lockstep.

use std::sync::LazyLock;

use crate::server::trust_task::TrustTask;

// ---------------------------------------------------------------------------
// Method-agnostic ops — `trusttasks.org/did-hosting/...`
// ---------------------------------------------------------------------------

/// `did-hosting/auth/authenticate/1.0` — alias of MSG_AUTHENTICATE.
pub static TASK_AUTH_AUTHENTICATE_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/auth/authenticate/1.0").expect("static")
});

/// `did-hosting/auth/authenticate-response/1.0` — alias of MSG_AUTH_RESPONSE.
pub static TASK_AUTH_AUTHENTICATE_RESPONSE_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/auth/authenticate-response/1.0")
        .expect("static")
});

/// `did-hosting/auth/step-up-passkey-start/1.0` — request a WebAuthn
/// assertion challenge to elevate the current session to aal2.
pub static TASK_AUTH_STEP_UP_PASSKEY_START_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/auth/step-up-passkey-start/1.0")
        .expect("static")
});

/// `did-hosting/auth/step-up-passkey-finish/1.0` — submit the assertion and
/// elevate the session to aal2.
pub static TASK_AUTH_STEP_UP_PASSKEY_FINISH_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/auth/step-up-passkey-finish/1.0")
        .expect("static")
});

/// `did-hosting/auth/step-up-check/1.0` — demo sensitive op gated on aal2.
pub static TASK_AUTH_STEP_UP_CHECK_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/auth/step-up-check/1.0").expect("static")
});

// -- DID provisioning lifecycle --------------------------------------------

pub static TASK_DID_REQUEST_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/did/request/1.0").expect("static")
});

pub static TASK_DID_OFFER_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/did/offer/1.0").expect("static")
});

pub static TASK_DID_PUBLISH_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/did/publish/1.0").expect("static")
});

pub static TASK_DID_CONFIRM_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/did/confirm/1.0").expect("static")
});

pub static TASK_DID_REGISTER_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/did/register/1.0").expect("static")
});

pub static TASK_DID_REGISTER_CONFIRM_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/did/register-confirm/1.0").expect("static")
});

pub static TASK_DID_INFO_REQUEST_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/did/info-request/1.0").expect("static")
});

pub static TASK_DID_INFO_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/did/info/1.0").expect("static")
});

pub static TASK_DID_LIST_REQUEST_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/did/list-request/1.0").expect("static")
});

pub static TASK_DID_LIST_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/did/list/1.0").expect("static")
});

pub static TASK_DID_DELETE_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/did/delete/1.0").expect("static")
});

pub static TASK_DID_DELETE_CONFIRM_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/did/delete-confirm/1.0").expect("static")
});

pub static TASK_DID_CHANGE_OWNER_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/did/change-owner/1.0").expect("static")
});

pub static TASK_DID_CHANGE_OWNER_CONFIRM_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/did/change-owner-confirm/1.0")
        .expect("static")
});

pub static TASK_DID_PROBLEM_REPORT_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/did/problem-report/1.0").expect("static")
});

// -- Hosting infrastructure (server registration, health, stats) ------------

pub static TASK_SERVER_REGISTER_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/server/register/1.0").expect("static")
});

pub static TASK_SERVER_REGISTER_ACK_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/server/register-ack/1.0").expect("static")
});

pub static TASK_SERVER_HEALTH_PING_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/server/health-ping/1.0").expect("static")
});

pub static TASK_SERVER_HEALTH_PONG_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/server/health-pong/1.0").expect("static")
});

pub static TASK_SERVER_STATS_SYNC_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/server/stats-sync/1.0").expect("static")
});

pub static TASK_SERVER_STATS_ACK_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/server/stats-ack/1.0").expect("static")
});

// -- Domain management (new in multi-domain release) -----------------------
//
// Wired by T17 (REST endpoints) and T33 (Trust-Task dispatch). Listed
// here as the source of truth so handlers don't string-literal the URL.

pub static TASK_DOMAIN_LIST_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/domain/list/1.0").expect("static")
});

pub static TASK_DOMAIN_CREATE_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/domain/create/1.0").expect("static")
});

pub static TASK_DOMAIN_UPDATE_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/domain/update/1.0").expect("static")
});

pub static TASK_DOMAIN_DISABLE_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/domain/disable/1.0").expect("static")
});

pub static TASK_DOMAIN_SET_DEFAULT_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/domain/set-default/1.0").expect("static")
});

pub static TASK_DOMAIN_PURGE_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/domain/purge/1.0").expect("static")
});

pub static TASK_DOMAIN_ASSIGN_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/domain/assign/1.0").expect("static")
});

pub static TASK_DOMAIN_UNASSIGN_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/domain/unassign/1.0").expect("static")
});

pub static TASK_ME_DOMAINS_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/me/domains/1.0").expect("static")
});

// -- T8b: REST-only operations that don't have a DIDComm equivalent ---------
//
// The DIDComm protocol carries auth challenges, DID lifecycle, server
// registration etc. The REST surface also exposes admin / observability
// endpoints (passkey enrolment, ACL CRUD, stats, time-series, registry
// management) that have no DIDComm twin. Registering Trust-Task URLs for
// them gates the wire shape uniformly: every authed REST call carries
// (or can carry, in permissive mode during the v0.7→v0.8 migration) a
// canonical task identifier.

// Auth — REST-specific (the DIDComm-paired `authenticate` is above).
pub static TASK_AUTH_CHALLENGE_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/auth/challenge/1.0").expect("static")
});
pub static TASK_AUTH_REFRESH_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/auth/refresh/1.0").expect("static")
});
pub static TASK_AUTH_PASSKEY_ENROLL_START_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/auth/passkey-enroll-start/1.0")
        .expect("static")
});
pub static TASK_AUTH_PASSKEY_ENROLL_FINISH_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/auth/passkey-enroll-finish/1.0")
        .expect("static")
});
pub static TASK_AUTH_PASSKEY_LOGIN_START_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/auth/passkey-login-start/1.0")
        .expect("static")
});
pub static TASK_AUTH_PASSKEY_LOGIN_FINISH_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/auth/passkey-login-finish/1.0")
        .expect("static")
});
pub static TASK_AUTH_PASSKEY_INVITE_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/auth/passkey-invite/1.0").expect("static")
});

// ACL admin operations.
pub static TASK_ACL_LIST_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/acl/list/1.0").expect("static")
});
pub static TASK_ACL_CREATE_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/acl/create/1.0").expect("static")
});
pub static TASK_ACL_UPDATE_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/acl/update/1.0").expect("static")
});
pub static TASK_ACL_DELETE_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/acl/delete/1.0").expect("static")
});

// DID management — REST-specific helpers (the DIDComm-paired ones are
// above).
pub static TASK_DID_CHECK_NAME_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/did/check-name/1.0").expect("static")
});
pub static TASK_DID_LOG_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/did/log/1.0").expect("static")
});
pub static TASK_DID_DISABLE_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/did/disable/1.0").expect("static")
});
pub static TASK_DID_ENABLE_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/did/enable/1.0").expect("static")
});
pub static TASK_DID_ROLLBACK_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/did/rollback/1.0").expect("static")
});
pub static TASK_DID_RAW_LOG_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/did/raw-log/1.0").expect("static")
});

// Observability / config.
pub static TASK_STATS_SERVER_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/stats/server/1.0").expect("static")
});
pub static TASK_STATS_DID_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/stats/did/1.0").expect("static")
});
pub static TASK_TIMESERIES_SERVER_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/timeseries/server/1.0").expect("static")
});
pub static TASK_TIMESERIES_DID_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/timeseries/did/1.0").expect("static")
});
pub static TASK_SERVICES_OVERVIEW_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/services/overview/1.0").expect("static")
});
pub static TASK_CONFIG_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/config/1.0").expect("static")
});

// Registry admin operations. Distinct from `TASK_SERVER_REGISTER_1_0`,
// which is the *server's* self-registration; these are the *admin's*
// CRUD over the registry table.
pub static TASK_REGISTRY_LIST_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/registry/list/1.0").expect("static")
});
pub static TASK_REGISTRY_ADMIN_REGISTER_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/registry/admin-register/1.0")
        .expect("static")
});
pub static TASK_REGISTRY_GET_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/registry/get/1.0").expect("static")
});
pub static TASK_REGISTRY_DEREGISTER_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/registry/deregister/1.0").expect("static")
});
pub static TASK_REGISTRY_HEALTH_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/registry/health/1.0").expect("static")
});

// ---------------------------------------------------------------------------
// webvh-protocol-specific ops — `trusttasks.org/webvh/...`
// ---------------------------------------------------------------------------
//
// Witness + sync are protocol features of did:webvh's append-only log.
// did:web has no analog (single did.json, no log, no witness signature).
// Future per-method protocol ops live under `webs/...` / `webplus/...`.

pub static TASK_WEBVH_WITNESS_PUBLISH_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/webvh/did/witness-publish/1.0").expect("static")
});

pub static TASK_WEBVH_WITNESS_CONFIRM_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/webvh/did/witness-confirm/1.0").expect("static")
});

pub static TASK_WEBVH_SYNC_UPDATE_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/webvh/did/sync-update/1.0").expect("static")
});

pub static TASK_WEBVH_SYNC_UPDATE_ACK_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/webvh/did/sync-update-ack/1.0").expect("static")
});

pub static TASK_WEBVH_SYNC_DELETE_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/webvh/did/sync-delete/1.0").expect("static")
});

pub static TASK_WEBVH_SYNC_DELETE_ACK_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/webvh/did/sync-delete-ack/1.0").expect("static")
});

#[cfg(test)]
mod tests {
    use super::*;

    /// Every registered URL must validate as a `TrustTask`. A broken URL
    /// in a `LazyLock::expect` would only surface on first access; this
    /// test forces every const to deref so the assertion runs at test
    /// time instead of in production.
    #[test]
    fn every_registered_url_validates() {
        // List every const here. Adding a new TASK_* without adding it to
        // this list is the kind of drift the cross-crate invariant
        // test (T9) will catch; for now this list is the local proof.
        let all: &[&LazyLock<TrustTask>] = &[
            &TASK_AUTH_AUTHENTICATE_1_0,
            &TASK_AUTH_AUTHENTICATE_RESPONSE_1_0,
            &TASK_DID_REQUEST_1_0,
            &TASK_DID_OFFER_1_0,
            &TASK_DID_PUBLISH_1_0,
            &TASK_DID_CONFIRM_1_0,
            &TASK_DID_REGISTER_1_0,
            &TASK_DID_REGISTER_CONFIRM_1_0,
            &TASK_DID_INFO_REQUEST_1_0,
            &TASK_DID_INFO_1_0,
            &TASK_DID_LIST_REQUEST_1_0,
            &TASK_DID_LIST_1_0,
            &TASK_DID_DELETE_1_0,
            &TASK_DID_DELETE_CONFIRM_1_0,
            &TASK_DID_CHANGE_OWNER_1_0,
            &TASK_DID_CHANGE_OWNER_CONFIRM_1_0,
            &TASK_DID_PROBLEM_REPORT_1_0,
            &TASK_SERVER_REGISTER_1_0,
            &TASK_SERVER_REGISTER_ACK_1_0,
            &TASK_SERVER_HEALTH_PING_1_0,
            &TASK_SERVER_HEALTH_PONG_1_0,
            &TASK_SERVER_STATS_SYNC_1_0,
            &TASK_SERVER_STATS_ACK_1_0,
            &TASK_DOMAIN_LIST_1_0,
            &TASK_DOMAIN_CREATE_1_0,
            &TASK_DOMAIN_UPDATE_1_0,
            &TASK_DOMAIN_DISABLE_1_0,
            &TASK_DOMAIN_SET_DEFAULT_1_0,
            &TASK_DOMAIN_PURGE_1_0,
            &TASK_DOMAIN_ASSIGN_1_0,
            &TASK_DOMAIN_UNASSIGN_1_0,
            &TASK_ME_DOMAINS_1_0,
            &TASK_WEBVH_WITNESS_PUBLISH_1_0,
            &TASK_WEBVH_WITNESS_CONFIRM_1_0,
            &TASK_WEBVH_SYNC_UPDATE_1_0,
            &TASK_WEBVH_SYNC_UPDATE_ACK_1_0,
            &TASK_WEBVH_SYNC_DELETE_1_0,
            &TASK_WEBVH_SYNC_DELETE_ACK_1_0,
            // T8b: REST-specific.
            &TASK_AUTH_CHALLENGE_1_0,
            &TASK_AUTH_REFRESH_1_0,
            &TASK_AUTH_PASSKEY_ENROLL_START_1_0,
            &TASK_AUTH_PASSKEY_ENROLL_FINISH_1_0,
            &TASK_AUTH_PASSKEY_LOGIN_START_1_0,
            &TASK_AUTH_PASSKEY_LOGIN_FINISH_1_0,
            &TASK_AUTH_PASSKEY_INVITE_1_0,
            &TASK_ACL_LIST_1_0,
            &TASK_ACL_CREATE_1_0,
            &TASK_ACL_UPDATE_1_0,
            &TASK_ACL_DELETE_1_0,
            &TASK_DID_CHECK_NAME_1_0,
            &TASK_DID_LOG_1_0,
            &TASK_DID_DISABLE_1_0,
            &TASK_DID_ENABLE_1_0,
            &TASK_DID_ROLLBACK_1_0,
            &TASK_DID_RAW_LOG_1_0,
            &TASK_STATS_SERVER_1_0,
            &TASK_STATS_DID_1_0,
            &TASK_TIMESERIES_SERVER_1_0,
            &TASK_TIMESERIES_DID_1_0,
            &TASK_SERVICES_OVERVIEW_1_0,
            &TASK_CONFIG_1_0,
            &TASK_REGISTRY_LIST_1_0,
            &TASK_REGISTRY_ADMIN_REGISTER_1_0,
            &TASK_REGISTRY_GET_1_0,
            &TASK_REGISTRY_DEREGISTER_1_0,
            &TASK_REGISTRY_HEALTH_1_0,
        ];
        for lock in all {
            let _t = lock.as_str(); // force deref; expect() inside LazyLock
            assert!(
                lock.as_str().starts_with("https://trusttasks.org/"),
                "URL must be under trusttasks.org: {}",
                lock.as_str()
            );
        }
    }

    #[test]
    fn method_agnostic_urls_under_did_hosting() {
        for url in [
            TASK_DID_REQUEST_1_0.as_str(),
            TASK_DOMAIN_LIST_1_0.as_str(),
            TASK_SERVER_REGISTER_1_0.as_str(),
        ] {
            assert!(
                url.starts_with("https://trusttasks.org/did-hosting/"),
                "expected /did-hosting/ namespace: {url}"
            );
        }
    }

    #[test]
    fn webvh_specific_urls_under_webvh() {
        for url in [
            TASK_WEBVH_WITNESS_PUBLISH_1_0.as_str(),
            TASK_WEBVH_SYNC_UPDATE_1_0.as_str(),
        ] {
            assert!(
                url.starts_with("https://trusttasks.org/webvh/"),
                "expected /webvh/ namespace: {url}"
            );
        }
    }

    #[test]
    fn every_url_ends_in_a_maj_min_version() {
        let all: &[&LazyLock<TrustTask>] = &[
            &TASK_AUTH_AUTHENTICATE_1_0,
            &TASK_DID_REQUEST_1_0,
            &TASK_DOMAIN_LIST_1_0,
            &TASK_WEBVH_SYNC_UPDATE_1_0,
        ];
        for lock in all {
            let url = lock.as_str();
            let tail = url.rsplit('/').next().unwrap();
            // Must look like {digit}.{digit} — no patch component per
            // the canonical Trust-Tasks spec.
            let parts: Vec<&str> = tail.split('.').collect();
            assert_eq!(parts.len(), 2, "version must be maj.min only: {url}");
            assert!(
                parts[0].chars().all(|c| c.is_ascii_digit())
                    && parts[1].chars().all(|c| c.is_ascii_digit()),
                "version components must be digits: {url}"
            );
        }
    }
}
