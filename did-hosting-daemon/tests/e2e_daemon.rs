//! Daemon-mode end-to-end smoke: the real `did-hosting-daemon` binary,
//! spawned as a subprocess and driven entirely over its public HTTPS Trust
//! Task API — no in-process `AppState` construction, unlike
//! `tests/e2e_distributed.rs`.
//!
//! Setup is the real, non-interactive setup path
//! (`did-hosting-daemon setup --from <recipe> --non-interactive`): self-managed
//! identity (no VTA), `[admin] mode = "did"` seeds the ACL, and
//! `[secrets] backend = "plaintext"` (with `confirm_plaintext = true`) so the
//! daemon needs no keyring. The daemon then runs on a free loopback port and
//! is driven exactly as an operator's tooling would drive it:
//! `POST /api/trust-tasks` for domain/DID management, `POST
//! /witness/api/trust-tasks` for the embedded witness (its own store —
//! `[witness_store]`, separate from `[store]` — but the *same* DID as the
//! control plane and server; see `CLAUDE.md`'s "did-hosting-daemon" section),
//! and a plain `GET` for resolution. Because the witness's store is separate,
//! `[admin] mode = "did"` (which seeds only the main store's ACL) doesn't
//! reach it either — this test seeds that ACL entry directly, the same way
//! it would for a standalone witness.
//!
//! **DIDComm/TSP are not covered here.** Driving them would need the daemon's
//! mediator-facing identity registered with the test mediator *before* the
//! daemon starts, but a self-managed daemon mints that identity itself at
//! setup time from a freshly generated signing key — there is no test seam to
//! predict the resulting `did:webvh` (or inject a known one) ahead of spawning
//! the process. `tests/e2e_distributed.rs` covers TSP and DIDComm instead,
//! against an in-process control plane whose identity this test suite *does*
//! control. HTTPS is covered fully here.
//!
//! Same known gap as `e2e_distributed.rs`: a webvh log naming an active
//! witness can never pass `did/register`'s validation (no proof can exist for
//! a not-yet-published version) — see that file's comment for the full
//! explanation. This test registers an unwitnessed DID and separately proves
//! the embedded witness's own `key/create` + `sign` operations work.

use std::time::Duration;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use serde_json::json;
use trust_tasks_rs::Payload;
use trust_tasks_rs::specs::did_management::did;

use vta_sdk::provision_client::EphemeralSetupKey;

use did_hosting_common::WitnessClient;
use did_hosting_common::did_ops::extract_did_id;
use did_hosting_common::server::trust_tasks::TransportBoundVerifier;
use did_hosting_common::server::trust_tasks::send::{
    build_signed_request, post_trust_task_https_verified,
};

#[path = "support/mod.rs"]
mod support;
use support::{build_did_log, did_key_signer, ok, wait_until};

const SETTLE_TIMEOUT: Duration = Duration::from_secs(20);

async fn reserve_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

/// Everything needed to talk to a running daemon over HTTPS: its base URL,
/// its own DID (shared by the control plane, the embedded server and the
/// embedded witness — one identity, per `CLAUDE.md`), and an admin requester.
struct Daemon {
    base_url: String,
    daemon_did: String,
    admin_did: String,
    admin_signer: affinidi_tdk::secrets_resolver::secrets::Secret,
    did_resolver: DIDCacheClient,
    /// The written `config.toml` — carries `server_did` + bind address, which
    /// the `fetch-metrics` subcommand reads to find the daemon.
    config_path: std::path::PathBuf,
    _dir: tempfile::TempDir,
    child: tokio::process::Child,
}

impl Daemon {
    /// Non-interactively set up a self-managed daemon in a fresh temp dir,
    /// then spawn it and wait until it serves its own root DID.
    async fn spawn() -> Self {
        Self::spawn_with_acl(&[]).await
    }

    /// Like [`Self::spawn`], but also seeds `extra_main_acl` (DID + role) into
    /// the main store's ACL before the daemon starts — the same window and
    /// mechanism the witness-ACL seed below uses, since the service routes no
    /// online `acl/grant` task. Used to grant a MetricsReader whose did:key is
    /// minted by the test.
    async fn spawn_with_acl(
        extra_main_acl: &[(String, did_hosting_common::server::acl::Role)],
    ) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let port = reserve_port().await;
        // `localhost`, not `127.0.0.1`: first-boot domain seeding refuses an
        // IP-literal host ("domain names must be DNS hostnames"), and
        // `localhost` resolves to the loopback interface the server binds to
        // just as well.
        let base_url = format!("http://localhost:{port}");
        let config_path = dir.path().join("config.toml");
        let data_dir = dir.path().join("data");
        let (admin_did, admin_signer) = did_key_signer(200);

        let recipe_path = dir.path().join("recipe.toml");
        let recipe = format!(
            r#"
[deployment]
service = "daemon"
vta_mode = "self-managed"

[output]
config_path = {config_path:?}

[server]
host = "127.0.0.1"
port = {port}
data_dir = {data_dir:?}

[identity]
public_url = "{base_url}"

[secrets]
backend = "plaintext"
confirm_plaintext = true

[admin]
mode = "did"
did = "{admin_did}"

[daemon]
enable_watcher = false
"#,
        );
        std::fs::write(&recipe_path, recipe).expect("write recipe");

        let bin = env!("CARGO_BIN_EXE_did-hosting-daemon");
        let status = tokio::process::Command::new(bin)
            .args(["setup", "--from"])
            .arg(&recipe_path)
            .arg("--non-interactive")
            .kill_on_drop(true)
            .status()
            .await
            .expect("run did-hosting-daemon setup");
        assert!(
            status.success(),
            "did-hosting-daemon setup --from {recipe_path:?} failed"
        );

        // The witness runs on its own store (`[witness_store]`, separate
        // from `[store]` — see `DaemonConfig`), so `[admin] mode = "did"`
        // (which seeds only the main store's ACL, the same ground
        // `did-hosting-daemon add-acl` covers) never reaches it. There is no
        // CLI/recipe path that does, so this seeds it directly, the same way
        // `tests/e2e_distributed.rs` seeds a standalone witness's ACL.
        {
            use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
            use did_hosting_common::server::config::StoreConfig;
            use did_hosting_common::server::domain::DomainScope;
            use did_hosting_common::server::store::{KS_ACL, Store};

            let witness_store_config = StoreConfig {
                data_dir: data_dir.join("witness"),
                ..StoreConfig::default()
            };
            let witness_store = Store::open(&witness_store_config)
                .await
                .expect("open witness store");
            store_acl_entry(
                &witness_store
                    .keyspace(KS_ACL)
                    .expect("witness acl keyspace"),
                &AclEntry {
                    did: admin_did.clone(),
                    role: Role::Admin,
                    label: Some("e2e admin".into()),
                    created_at: 1,
                    max_total_size: None,
                    max_did_count: None,
                    domains: DomainScope::All,
                },
            )
            .await
            .expect("seed witness ACL");
            // Dropped before the daemon starts: fjall locks the directory,
            // and the daemon must be the only opener of it.
        }

        // Seed any caller-supplied entries into the *main* store's ACL, in the
        // same post-setup / pre-spawn window (the store is unlocked once the
        // setup subprocess exits, and must be dropped before the daemon opens
        // it). There is no online `acl/grant` task to do this over the wire.
        if !extra_main_acl.is_empty() {
            use did_hosting_common::server::acl::{AclEntry, store_acl_entry};
            use did_hosting_common::server::config::StoreConfig;
            use did_hosting_common::server::domain::DomainScope;
            use did_hosting_common::server::store::{KS_ACL, Store};

            // Setup roots the main store at `<server.data_dir>/store` (and the
            // witness at `<server.data_dir>/witness`); seed the former.
            let main_store = Store::open(&StoreConfig {
                data_dir: data_dir.join("store"),
                ..StoreConfig::default()
            })
            .await
            .expect("open main store");
            let acl_ks = main_store.keyspace(KS_ACL).expect("main acl keyspace");
            for (did, role) in extra_main_acl {
                store_acl_entry(
                    &acl_ks,
                    &AclEntry {
                        did: did.clone(),
                        role: role.clone(),
                        label: Some("e2e extra".into()),
                        created_at: 1,
                        max_total_size: None,
                        max_did_count: None,
                        domains: DomainScope::All,
                    },
                )
                .await
                .expect("seed main ACL entry");
            }
        }

        let child = tokio::process::Command::new(bin)
            .arg("--config")
            .arg(&config_path)
            .env("RUST_LOG", "warn")
            .kill_on_drop(true)
            .spawn()
            .expect("spawn did-hosting-daemon");

        // `AllowPrivate`: the daemon's own DID really is hosted on `localhost`
        // here, which the resolver's default `PublicOnly` policy refuses as
        // an SSRF guard a same-machine test has no use for.
        let did_resolver = DIDCacheClient::new(
            DIDCacheConfigBuilder::default()
                .with_host_policy(affinidi_did_web::HostPolicy::AllowPrivate)
                .build(),
        )
        .await
        .expect("did resolver");
        let http = reqwest::Client::new();

        wait_until(
            || async {
                http.get(format!("{base_url}/api/health"))
                    .send()
                    .await
                    .is_ok_and(|r| r.status().is_success())
            },
            SETTLE_TIMEOUT,
            "the daemon answers its own health check",
        )
        .await;

        // The root DID is servable the moment the daemon is up — self-managed
        // setup imports its log directly, no further runtime bootstrap step —
        // and no domain exists yet, so the resolve-side host check is still
        // permissive (see `did_hosting_common::server::domain::safety`).
        let root_log = wait_until_ok(&http, &format!("{base_url}/.well-known/did.jsonl")).await;
        let daemon_did = extract_did_id(&root_log).expect("root DID log has a state.id");

        Self {
            base_url,
            daemon_did,
            admin_did,
            admin_signer,
            did_resolver,
            config_path,
            _dir: dir,
            child,
        }
    }

    async fn call(
        &self,
        type_uri: &str,
        payload: serde_json::Value,
    ) -> trust_tasks_rs::TrustTask<serde_json::Value> {
        let doc = build_signed_request(
            type_uri,
            &self.admin_did,
            &self.daemon_did,
            payload,
            &self.admin_signer,
        )
        .await
        .unwrap_or_else(|e| panic!("build request {type_uri}: {e}"));
        let url = format!("{}/api/trust-tasks", self.base_url);
        // The daemon's reply is signed by its `localhost` did:webvh, so the
        // deactivation check needs the resolver's `AllowPrivate` too.
        let verifier = TransportBoundVerifier::with_did_cache_and_host_policy(
            self.did_resolver.clone(),
            didwebvh_rs::host_policy::HostPolicy::AllowPrivate,
        );
        post_trust_task_https_verified(&self.admin_did, &self.daemon_did, &url, &doc, &verifier)
            .await
            .unwrap_or_else(|e| panic!("https send {type_uri}: {e}"))
    }

    async fn get_log(&self, mnemonic: &str) -> reqwest::Response {
        reqwest::Client::new()
            .get(format!("{}/{mnemonic}/did.jsonl", self.base_url))
            .send()
            .await
            .expect("GET the daemon")
    }

    async fn teardown(mut self) {
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
    }
}

/// Poll `url` until it answers 200, returning the body.
async fn wait_until_ok(http: &reqwest::Client, url: &str) -> String {
    let deadline = tokio::time::Instant::now() + SETTLE_TIMEOUT;
    loop {
        if let Ok(resp) = http.get(url).send().await
            && resp.status().is_success()
        {
            return resp.text().await.expect("body");
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for {url} to answer 200");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The full lifecycle over HTTPS against a real daemon process: register a
/// DID, confirm it serves, disable it and confirm it refuses, then delete it
/// — plus a standalone proof that the embedded witness signs correctly (see
/// this file's module docs for why it isn't threaded through `did/register`).
#[tokio::test]
async fn daemon_lifecycle_over_https() {
    let daemon = Daemon::spawn().await;
    let mnemonic = "e2e-daemon";

    // The daemon mounts the control plane's public sign-in self-check that
    // the login page reads; before or without a check it answers a state,
    // never an error.
    let readiness: serde_json::Value = reqwest::Client::new()
        .get(format!("{}/api/sign-in/readiness", daemon.base_url))
        .send()
        .await
        .expect("GET /api/sign-in/readiness")
        .json()
        .await
        .expect("readiness is JSON");
    assert!(
        matches!(
            readiness["walletSignIn"].as_str(),
            Some("ready" | "unknown" | "not-set-up")
        ),
        "unexpected readiness {readiness}"
    );
    let (_did_signer_did, did_signer) = did_key_signer(210);

    // The daemon's own encoded host — the same string `did/register`
    // validates the log's identifier against (`did_hosting_url`, which the
    // recipe set equal to `public_url`).
    let host = did_hosting_common::did::encode_host(&daemon.base_url).expect("encode host");

    // did/register — a plain (unwitnessed) webvh log.
    let (jsonl, _version_id) = build_did_log(&host, mnemonic, &did_signer, None, &[]).await;
    let reply = daemon
        .call(
            did::register::v0_1::Payload::TYPE_URI,
            json!({ "path": mnemonic, "method": "webvh", "didData": jsonl }),
        )
        .await;
    ok(&reply, did::register::v0_1::Payload::TYPE_URI);

    // The daemon serves what was registered.
    wait_until(
        || async { daemon.get_log(mnemonic).await.status().is_success() },
        SETTLE_TIMEOUT,
        "the daemon serves the freshly registered DID",
    )
    .await;
    let served = daemon.get_log(mnemonic).await.text().await.expect("body");
    assert_eq!(
        served.trim(),
        jsonl.trim(),
        "the daemon serves exactly what was registered"
    );

    // The embedded witness — same shared identity, `/witness/api/trust-tasks`
    // — signs a (separate, unregistered) witnessed log correctly.
    let witness_client = WitnessClient::new(
        &format!("{}/witness", daemon.base_url),
        &daemon.daemon_did,
        &daemon.admin_did,
        daemon.admin_signer.clone(),
        daemon.did_resolver.clone(),
    )
    .with_host_policy(didwebvh_rs::host_policy::HostPolicy::AllowPrivate);
    let key = witness_client
        .create_key(Some("e2e"))
        .await
        .unwrap_or_else(|e| panic!("witness key/create: {e}"));
    let witness_key_did = key.key.did.to_string();
    let witness_id = key.key.witness_id.to_string();
    let (witnessed_jsonl, witnessed_version_id) = build_did_log(
        &host,
        &format!("{mnemonic}-witnessed"),
        &did_signer,
        Some(&witness_key_did),
        &[],
    )
    .await;
    let signed = witness_client
        .sign(&witness_id, &witnessed_version_id, &witnessed_jsonl)
        .await
        .unwrap_or_else(|e| panic!("witness sign: {e}"));
    assert_eq!(signed.version_id.to_string(), witnessed_version_id);

    // did/set-state suspended — the daemon refuses resolution.
    let reply = daemon
        .call(
            did::set_state::v0_1::Payload::TYPE_URI,
            json!({ "mnemonic": mnemonic, "state": "suspended" }),
        )
        .await;
    ok(&reply, did::set_state::v0_1::Payload::TYPE_URI);
    wait_until(
        || async { daemon.get_log(mnemonic).await.status() == reqwest::StatusCode::NOT_FOUND },
        SETTLE_TIMEOUT,
        "the daemon refuses a disabled DID",
    )
    .await;

    // did/delete — the daemon refuses resolution at once, with no
    // cache-staleness window. `serve_content` used to check the
    // disabled/deleted flag only when a record existed; `did/delete` removes
    // the record outright (unlike `disable`, which only flips a flag on it),
    // so that check was skipped entirely and a request fell straight through
    // to the still-warm `AppState::did_cache` entry from the `get_log` calls
    // above — a DID that was ever successfully resolved kept serving its
    // last content for up to the cache's TTL after being deleted. Fixed by
    // having `serve_content` treat a missing record as not found before ever
    // consulting the cache, so this `get_log` needs no `wait_until`: the
    // refusal is immediate, proven against a deliberately warm cache.
    let reply = daemon
        .call(
            did::delete::v0_1::Payload::TYPE_URI,
            json!({ "mnemonic": mnemonic }),
        )
        .await;
    ok(&reply, did::delete::v0_1::Payload::TYPE_URI);
    assert_eq!(
        daemon.get_log(mnemonic).await.status(),
        reqwest::StatusCode::NOT_FOUND,
        "a deleted DID must stop resolving immediately, not after the cache's TTL"
    );

    daemon.teardown().await;
}

/// `fetch-metrics` with a key that is not in the ACL must fail with the ACL
/// refusal (`permissionDenied`), not an empty successful scrape and not a
/// signature/proof error.
///
/// The refusal is an *unsigned* framework `trust-task-error`, so this drives the
/// whole chain the maintainer asked after: the daemon's `Cx::metrics_read` ACL
/// gate, the unsigned-error recognition in `post_trust_task_https_verified`, and
/// the subcommand surfacing that code rather than exiting 0 with `[]`. Runs the
/// real `did-hosting-daemon fetch-metrics` subprocess against the live daemon,
/// signing with a freshly minted did:key that was never granted.
#[tokio::test]
async fn fetch_metrics_denied_for_an_ungranted_key() {
    let daemon = Daemon::spawn().await;

    // A did:key the daemon has never seen, persisted in the same key-file format
    // `setup --setup-key-out` writes and `fetch-metrics --key` reads.
    let key_dir = tempfile::tempdir().expect("key temp dir");
    let key_path = key_dir.path().join("ungranted-key.json");
    EphemeralSetupKey::generate()
        .expect("generate an ungranted did:key")
        .persist_to(&key_path)
        .expect("persist the ungranted key");

    let bin = env!("CARGO_BIN_EXE_did-hosting-daemon");
    let out = tokio::process::Command::new(bin)
        .args(["fetch-metrics", "--config"])
        .arg(&daemon.config_path)
        .arg("--key")
        .arg(&key_path)
        .output()
        .await
        .expect("run did-hosting-daemon fetch-metrics");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "an ungranted key must be refused, not a successful scrape. stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stderr.contains("permissionDenied"),
        "the operator should see the ACL refusal code, not a signature/proof error. stderr={stderr:?}"
    );

    daemon.teardown().await;
}

/// `fetch-metrics` with a key granted `MetricsReader` succeeds: it signs,
/// verifies the daemon's signed reply, confirms the reply is the metrics
/// `#response`, and prints the counters as a JSON array (exit 0).
///
/// Counters are only populated when the daemon is built with the `metrics`
/// feature; without it the snapshot's `counters` array is present but empty.
/// So this asserts the whole success path — valid output, clean exit — rather
/// than a specific counter value: stdout must parse as a JSON array.
#[tokio::test]
async fn fetch_metrics_succeeds_for_a_granted_key() {
    // Mint the MetricsReader did:key first so its DID can be granted before the
    // daemon starts, and persist it in the format `fetch-metrics --key` reads.
    let key_dir = tempfile::tempdir().expect("key temp dir");
    let key_path = key_dir.path().join("metrics-reader-key.json");
    let key = EphemeralSetupKey::generate().expect("generate a MetricsReader did:key");
    let reader_did = key.did.clone();
    key.persist_to(&key_path)
        .expect("persist the MetricsReader key");

    let daemon = Daemon::spawn_with_acl(&[(
        reader_did,
        did_hosting_common::server::acl::Role::MetricsReader,
    )])
    .await;

    let bin = env!("CARGO_BIN_EXE_did-hosting-daemon");
    let out = tokio::process::Command::new(bin)
        .args(["fetch-metrics", "--config"])
        .arg(&daemon.config_path)
        .arg("--key")
        .arg(&key_path)
        .output()
        .await
        .expect("run did-hosting-daemon fetch-metrics");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "a granted MetricsReader key must scrape successfully. stdout={stdout:?} stderr={stderr:?}"
    );
    // The last stdout line is the counters JSON (the daemon prints a banner to
    // stderr, not stdout). It must be a JSON array — possibly empty when the
    // daemon was built without the `metrics` feature.
    let last = stdout.lines().last().unwrap_or_default();
    let parsed: serde_json::Value = serde_json::from_str(last)
        .unwrap_or_else(|e| panic!("counters output is not JSON: {e}; stdout={stdout:?}"));
    assert!(
        parsed.is_array(),
        "counters output must be a JSON array, got {parsed:?}"
    );

    daemon.teardown().await;
}
