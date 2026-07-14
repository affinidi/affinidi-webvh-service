//! CLI for the service's own identity generations — the **offline** operator
//! surface.
//!
//! # Offline, and why that matters
//!
//! These commands open the store directly, and the embedded store takes an
//! exclusive lock, so they cannot run against a live service. That is not merely
//! a limitation to work around: even if the lock allowed it, deleting a record
//! on disk would not reach into a *running* process's secrets resolver — which is
//! where a compromised key actually still lives. Writing to disk while the
//! service kept decrypting with its in-memory copy would be a kill switch that
//! looks like it fired and didn't.
//!
//! So the split is deliberate:
//!
//! - **Live service** → `POST /api/identity/generations/{id}/retire` (or the UI
//!   button). Runs in-process; the key is gone from the resolver before the
//!   response is written.
//! - **Stopped service** → these commands. They remove the record and the key
//!   material from disk, so the generation is never loaded again on next boot.
//!
//! A running service also reconciles against the store on each expiry sweep, so
//! if a shared-store deployment does manage to delete a record out of band, the
//! running process drops the key within one sweep interval rather than honouring
//! it forever.

use crate::server::config::{SecretsConfig, StoreConfig};
use crate::server::error::AppError;
use crate::server::identity::{IdentityGeneration, load_generations};
use crate::server::secret_store::create_secret_store;
use crate::server::store::{KS_IDENTITY, Store};

type CliResult = Result<(), Box<dyn std::error::Error>>;

/// Read the persisted generations, current first.
async fn load(store_config: &StoreConfig) -> Result<(Store, Vec<IdentityGeneration>), AppError> {
    let store = Store::open(store_config).await?;
    let ks = store.keyspace(KS_IDENTITY)?;
    let now = crate::server::auth::session::now_epoch();
    let generations = load_generations(&ks, now).await?;
    Ok((store, generations))
}

/// `identity-list` — show which key material this service still honours.
pub async fn run_list_generations(store_config: &StoreConfig) -> CliResult {
    let (_store, generations) = load(store_config).await?;

    if generations.is_empty() {
        eprintln!();
        eprintln!("  No identity generations recorded.");
        eprintln!("  (The service records one the first time it resolves its own DID.)");
        eprintln!();
        return Ok(());
    }

    let now = crate::server::auth::session::now_epoch();
    let current_id = generations.first().map(|g| g.id);

    eprintln!();
    for g in &generations {
        let is_current = Some(g.id) == current_id;
        eprintln!(
            "  Generation {}{}",
            g.id,
            if is_current { "  (current)" } else { "" }
        );
        eprintln!("    key agreement : {}", g.ka_kid);
        eprintln!("    signing       : {}", g.signing_kid);
        if let Some(ref m) = g.mediator_did {
            eprintln!("    mediator      : {m}");
        }
        eprintln!(
            "    transports    : {}",
            match (g.protocols.didcomm, g.protocols.tsp) {
                (true, true) => "DIDComm + TSP",
                (true, false) => "DIDComm",
                (false, true) => "TSP",
                (false, false) => "none",
            }
        );
        match g.expires_at {
            Some(expires) => {
                let remaining = expires.saturating_sub(now);
                eprintln!(
                    "    retired       : still honoured for {}m {}s",
                    remaining / 60,
                    remaining % 60
                );
            }
            None if is_current => {}
            None => eprintln!("    retired       : no expiry recorded"),
        }
        eprintln!();
    }

    if generations.len() > 1 {
        eprintln!(
            "  Superseded generations stay decryptable so peers holding a cached DID document"
        );
        eprintln!("  can still reach this service. To stop honouring one immediately (a key");
        eprintln!("  compromise), use `identity-retire-now --generation <id>`.");
        eprintln!();
    }

    Ok(())
}

/// `identity-retire-now` — stop honouring a superseded generation, offline.
///
/// Removes the generation record and its private key material. On next boot the
/// generation is not loaded, so messages addressed to its key-agreement key no
/// longer decrypt.
///
/// Refuses the **current** generation: dropping the key the service is actively
/// using would leave it unable to decrypt anything at all. Publish a new DID
/// document first — that makes the old generation superseded, and then it can be
/// retired.
pub async fn run_retire_generation(
    store_config: &StoreConfig,
    secrets_config: &SecretsConfig,
    config_path: &std::path::Path,
    generation_id: u64,
) -> CliResult {
    let (store, generations) = load(store_config).await?;

    let Some(target) = generations.iter().find(|g| g.id == generation_id) else {
        return Err(format!(
            "no live identity generation with id {generation_id} \
             (run `identity-list` to see what there is)"
        )
        .into());
    };

    if generations.first().map(|g| g.id) == Some(generation_id) {
        return Err(
            "refusing to retire the current generation — it is the key this service is \
             actively using, and dropping it would leave the service unable to decrypt \
             anything. Publish a new DID document first; that supersedes this generation, \
             and then it can be retired."
                .into(),
        );
    }

    // Key material first. If a later step fails, we have still stopped the key
    // from being loaded — the direction to fail in.
    let secret_store = create_secret_store(secrets_config, config_path)?;
    if let Some(mut secrets) = secret_store.get().await? {
        let before = secrets.retired.len();
        secrets.retired.retain(|r| r.ka_kid != target.ka_kid);
        if secrets.retired.len() != before {
            secret_store.set(&secrets).await?;
        }
    }

    let ks = store.keyspace(KS_IDENTITY)?;
    ks.remove(format!("identity:gen:{generation_id:020}"))
        .await?;
    store.persist().await?;

    eprintln!();
    eprintln!("  Retired identity generation {generation_id}.");
    eprintln!("    key agreement : {}", target.ka_kid);
    eprintln!();
    eprintln!("  Messages still addressed to that key-agreement key will no longer decrypt.");
    eprintln!("  Peers whose cached DID document still names it cannot reach this service");
    eprintln!("  until their cache expires — which is the point, if the key was compromised.");
    eprintln!();
    eprintln!("  If the service is running, restart it (or wait one sweep interval) for the");
    eprintln!("  change to take effect in the live process.");
    eprintln!();

    Ok(())
}
