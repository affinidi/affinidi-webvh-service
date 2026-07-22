//! End-to-end smoke test for the agent-name lifecycle against a **running**
//! control plane: bind → park → resume → remove, asserting the observable
//! outcome (`/@name` redirect status + the registry's `enabled` flag) at every
//! step.
//!
//! This is the one thing the unit/integration suites can't cover — they drive
//! an in-process `AppState`; this drives real HTTP against a live daemon, signs
//! real `did.jsonl` versions with `didwebvh-rs`, and checks that a resolver
//! would actually see the right thing.
//!
//! ## What it exercises
//!
//! - **bind** — a DID is created with `alsoKnownAs` claiming `@name` from its
//!   first version, so the control plane's publish-time reconciliation
//!   registers it (the same path the UI uses). Asserts `/@name` → 302 and the
//!   registry shows the name `enabled: true`.
//! - **park** (`disable`) — a signed new version drops the claim; asserts
//!   `/@name` → 404 but the registry keeps the name `enabled: false` (still
//!   reserved).
//! - **resume** (`enable`) — a signed new version re-claims it; asserts 302 and
//!   `enabled: true` again.
//! - **remove** — a signed new version drops it and releases the reservation;
//!   asserts 404, the name gone from the registry, and `check` reporting it
//!   free again.
//!
//! Plus: `/api/server-info` advertises `agentNames`, `check` distinguishes
//! taken / free / reserved, and `/@unknown` 404s.
//!
//! ## Running it
//!
//! Point it at a **daemon** (control + edge on one origin) or pass both URLs:
//!
//! ```sh
//! cargo run -p did-hosting-server --example agent_name_smoke -- \
//!   --control-url http://localhost:8534 \
//!   --webvh-did did:webvh:…:localhost%3A8534 \
//!   # --hosting-url http://localhost:8530   # only if the edge is a separate origin
//! ```
//!
//! The generated `did:key` must be in the control plane's ACL as an owner
//! before it can register (the tool prints the DID and pauses so you can add
//! it, mirroring `examples/client.rs`). `agent_names` must be enabled on the
//! deployment (it is by default).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use did_hosting_common::WebVHClient;
use did_hosting_common::did::{
    DidDocumentOptions, build_did_document, encode_host, generate_ed25519_identity,
};
use didwebvh_rs::DIDWebVHState;
use didwebvh_rs::parameters::Parameters;
use serde_json::{Value, json};

#[derive(Parser)]
#[command(about = "Smoke-test the agent-name lifecycle against a running control plane")]
struct Cli {
    /// Control-plane base URL — auth, `/api/dids`, `/api/agent-names`,
    /// `/api/server-info`. In daemon mode this is also the hosting origin.
    #[arg(long)]
    control_url: String,

    /// Hosting/edge base URL where `did.jsonl` and `/@name` are served.
    /// Defaults to `--control-url` (daemon mode, one origin).
    #[arg(long)]
    hosting_url: Option<String>,

    /// The DID-hosting service's own DID — the DIDComm `to` of the signed
    /// authenticate message (same as `examples/client.rs`).
    #[arg(long)]
    webvh_did: String,

    /// Local part of the agent name to test. Defaults to a unique `smoke…`.
    #[arg(long)]
    name: Option<String>,
}

/// Serialize the current log chain back to `did.jsonl` wire form.
fn to_jsonl(state: &DIDWebVHState) -> Result<String> {
    let lines: Vec<String> = state
        .log_entries()
        .iter()
        .map(|e| serde_json::to_string(&e.log_entry))
        .collect::<std::result::Result<_, _>>()
        .context("serialize log entry")?;
    Ok(lines.join("\n"))
}

/// GET `/@name` on the hosting origin without following the redirect, and
/// return the status. 302 = served; 404 = not served (parked / removed /
/// unknown) — the two the whole feature turns on.
async fn probe_redirect(probe: &reqwest::Client, hosting: &str, name: &str) -> Result<u16> {
    let resp = probe
        .get(format!("{hosting}/@{name}"))
        .send()
        .await
        .with_context(|| format!("GET {hosting}/@{name}"))?;
    Ok(resp.status().as_u16())
}

/// Whether the DID's registry currently lists `name`, and if so its `enabled`
/// flag. `None` = absent from the registry entirely.
async fn registry_state(client: &WebVHClient, mnemonic: &str, name: &str) -> Result<Option<bool>> {
    let detail = client
        .get_did_detail(mnemonic)
        .await
        .context("GET /api/dids/{mnemonic}")?;
    let Some(names) = detail.get("agentNames").and_then(|v| v.as_array()) else {
        return Ok(None);
    };
    Ok(names.iter().find_map(|e| {
        (e.get("name").and_then(|v| v.as_str()) == Some(name))
            .then(|| e.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false))
    }))
}

fn pass(step: &str) {
    println!("  \u{2713} {step}");
}

/// Assert or abort — a smoke test wants the *first* wrong thing to stop the run
/// with the step named, not a wall of cascading failures.
fn check(cond: bool, step: &str) -> Result<()> {
    if cond {
        pass(step);
        Ok(())
    } else {
        bail!("FAILED: {step}");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let control_url = cli.control_url.trim_end_matches('/').to_string();
    let hosting = cli
        .hosting_url
        .clone()
        .unwrap_or_else(|| control_url.clone())
        .trim_end_matches('/')
        .to_string();

    // The name's authority is the DID's *decoded* host (`localhost:8534`), the
    // same value the control plane derives from the DID and compares
    // `alsoKnownAs` against — so the claim resolves. Match the VTA: always
    // `https://`, authority only.
    let authority = hosting
        .strip_prefix("https://")
        .or_else(|| hosting.strip_prefix("http://"))
        .unwrap_or(&hosting)
        .to_string();

    let name = cli.name.clone().unwrap_or_else(|| {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        format!("smoke{n:x}")
    });
    let aka = format!("https://{authority}/@{name}");

    let probe = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build no-redirect client")?;

    println!("\n=== Agent-name smoke test ===");
    println!("  control : {control_url}");
    println!("  hosting : {hosting}");
    println!("  name    : @{name}");

    // ------------------------------------------------------------------
    // Identity + ACL gate (mirrors examples/client.rs)
    // ------------------------------------------------------------------
    let (my_did, secret) = generate_ed25519_identity().context("generate did:key")?;
    println!("\nOwner DID: {my_did}");
    println!("Ensure this DID is an owner in the control-plane ACL, then press Enter…");
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;

    let mut client = WebVHClient::new(&control_url);
    if let Some(h) = &cli.hosting_url {
        client = client.with_hosting_url(h.clone());
    }
    client
        .authenticate(&my_did, &secret, &cli.webvh_did)
        .await
        .context("authenticate")?;

    // ------------------------------------------------------------------
    // Pre-flight: feature advertised, name free
    // ------------------------------------------------------------------
    println!("\n[pre-flight]");
    let info: Value = reqwest::get(format!("{control_url}/api/server-info"))
        .await
        .context("GET /api/server-info")?
        .json()
        .await
        .context("parse server-info")?;
    check(
        info.get("agentNames").and_then(|v| v.as_bool()) == Some(true),
        "server-info advertises agentNames: true",
    )?;
    let avail = client.check_agent_name(&name, Some(&authority)).await?;
    check(
        avail.get("available").and_then(|v| v.as_bool()) == Some(true),
        "check: name is free before binding",
    )?;
    check(
        probe_redirect(&probe, &hosting, &name).await? == 404,
        "GET /@name 404s before binding",
    )?;

    // ------------------------------------------------------------------
    // BIND — create a DID claiming @name from v1; publish reconciles it in
    // ------------------------------------------------------------------
    println!("\n[bind]");
    let uri = client.request_uri(None).await.context("request_uri")?;
    let mnemonic = uri.mnemonic;

    let host_enc = encode_host(&hosting).context("encode host")?;
    let pubkey_mb = secret
        .get_public_keymultibase()
        .map_err(|e| anyhow::anyhow!("public key multibase: {e}"))?;

    let mut doc = build_did_document(
        &host_enc,
        &mnemonic,
        &pubkey_mb,
        &DidDocumentOptions::default(),
    );
    doc["alsoKnownAs"] = json!([aka]);

    // Match `create_log_entry`: the update key is this secret; its id must
    // carry the multibase after '#'.
    let mut signing_key = secret.clone();
    if !signing_key.id.contains('#') {
        signing_key.id = format!("did:key:{pubkey_mb}#{pubkey_mb}");
    }

    let mut state = DIDWebVHState::default();
    let params = Parameters {
        update_keys: Some(Arc::new(vec![pubkey_mb.clone().into()])),
        ..Default::default()
    };
    state
        .create_log_entry(None, &doc, &params, &signing_key)
        .await
        .map_err(|e| anyhow::anyhow!("create log entry: {e}"))?;

    // The library substituted the real SCID into its stored entry; our local
    // `doc` still carries the `{SCID}` placeholder, so build a base document
    // with the real SCID for every later update.
    let scid = state.scid().to_string();
    let base_doc: Value =
        serde_json::from_str(&serde_json::to_string(&doc)?.replace("{SCID}", &scid))
            .context("substitute SCID into base document")?;
    let with_name = base_doc.clone();
    let without_name = {
        let mut d = base_doc.clone();
        d.as_object_mut().unwrap().remove("alsoKnownAs");
        d
    };

    client
        .upload_did(&mnemonic, &to_jsonl(&state)?)
        .await
        .context("publish v1 (bind)")?;

    check(
        probe_redirect(&probe, &hosting, &name).await? == 302,
        "GET /@name → 302 after bind",
    )?;
    check(
        registry_state(&client, &mnemonic, &name).await? == Some(true),
        "registry lists @name enabled after bind",
    )?;
    let avail = client.check_agent_name(&name, Some(&authority)).await?;
    check(
        avail.get("available").and_then(|v| v.as_bool()) == Some(false),
        "check: name reads as taken after bind",
    )?;

    // Each mutation is a new signed version. Space them past a whole second so
    // two back-to-back `versionTime`s can't collide.
    let settle = || tokio::time::sleep(Duration::from_millis(1100));

    // ------------------------------------------------------------------
    // PARK — drop the claim, keep the reservation
    // ------------------------------------------------------------------
    println!("\n[park]");
    settle().await;
    state
        .update_document(without_name.clone(), &signing_key)
        .await
        .map_err(|e| anyhow::anyhow!("sign park version: {e}"))?;
    client
        .agent_name_op("disable", &mnemonic, &name, &to_jsonl(&state)?)
        .await
        .context("POST /api/agent-names/disable")?;
    check(
        probe_redirect(&probe, &hosting, &name).await? == 404,
        "GET /@name → 404 after park",
    )?;
    check(
        registry_state(&client, &mnemonic, &name).await? == Some(false),
        "registry keeps @name reserved (enabled: false) after park",
    )?;

    // ------------------------------------------------------------------
    // RESUME — re-claim it
    // ------------------------------------------------------------------
    println!("\n[resume]");
    settle().await;
    state
        .update_document(with_name.clone(), &signing_key)
        .await
        .map_err(|e| anyhow::anyhow!("sign resume version: {e}"))?;
    client
        .agent_name_op("enable", &mnemonic, &name, &to_jsonl(&state)?)
        .await
        .context("POST /api/agent-names/enable")?;
    check(
        probe_redirect(&probe, &hosting, &name).await? == 302,
        "GET /@name → 302 after resume",
    )?;
    check(
        registry_state(&client, &mnemonic, &name).await? == Some(true),
        "registry lists @name enabled after resume",
    )?;

    // ------------------------------------------------------------------
    // REMOVE — drop the claim and release the reservation
    // ------------------------------------------------------------------
    println!("\n[remove]");
    settle().await;
    state
        .update_document(without_name.clone(), &signing_key)
        .await
        .map_err(|e| anyhow::anyhow!("sign remove version: {e}"))?;
    client
        .agent_name_op("remove", &mnemonic, &name, &to_jsonl(&state)?)
        .await
        .context("POST /api/agent-names/remove")?;
    check(
        probe_redirect(&probe, &hosting, &name).await? == 404,
        "GET /@name → 404 after remove",
    )?;
    check(
        registry_state(&client, &mnemonic, &name).await?.is_none(),
        "registry no longer lists @name after remove",
    )?;
    let avail = client.check_agent_name(&name, Some(&authority)).await?;
    check(
        avail.get("available").and_then(|v| v.as_bool()) == Some(true),
        "check: name is free again after remove",
    )?;

    // ------------------------------------------------------------------
    // Cleanup
    // ------------------------------------------------------------------
    println!("\n[cleanup]");
    client.delete_did(&mnemonic).await.context("delete DID")?;
    pass("test DID deleted");

    println!("\n=== all checks passed — bind → park → resume → remove verified live ===\n");
    Ok(())
}
