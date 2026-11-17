//! The user-facing CLI wrappers each service's `setup offline-request` /
//! `offline-open` subcommands call.

use super::*;

// ---------------------------------------------------------------------------
// CLI wrappers
//
// Thin, user-facing wrappers around the primitives above. Each service's
// `main.rs` gets a pair of subcommands by delegating here rather than
// re-printing the same operator instructions in three places.
// ---------------------------------------------------------------------------

/// How the `run_offline_open_cli` handler should describe the final
/// "feed these keys into your secret store" step. Kept small and
/// type-driven so each service picks the shape that matches its own CLI.
#[derive(Debug, Clone, Copy)]
pub enum OfflineOpenNextStep<'a> {
    /// Service already has an `import-secrets` subcommand that takes
    /// `--signing-key` and `--ka-key` multibase flags (e.g. did-hosting-server,
    /// webvh-witness). The instruction tells the operator to run it with
    /// the keys from the secrets JSON.
    ImportSecrets {
        /// The binary name to put in the suggested command line.
        binary: &'a str,
    },
    /// Service has no import-secrets subcommand yet; point at its
    /// interactive setup wizard (e.g. did-hosting-control).
    Setup {
        /// The binary name to put in the suggested command line.
        binary: &'a str,
    },
}

/// CLI-facing wrapper around [`write_offline_bootstrap_request`]. Writes
/// the VP-framed bootstrap request for `ask`, persists the ephemeral seed
/// to `seed_path` (chmod 0600 on Unix), and prints step-by-step operator
/// instructions. Build `ask` with [`build_webvh_provision_ask`] so the CLI
/// packages the DID identically to the wizard. `binary` names the calling
/// executable for the printed `vta-open` follow-up.
///
/// Note: this is the **standalone-CLI** entry point (`vta-request`) for
/// operators managing files explicitly. The wizard's `setup-offline-prepare`
/// flow uses `SecretStore::set_bootstrap_seed` instead — no seed file.
pub async fn run_offline_request_cli(
    out: &Path,
    seed_path: &Path,
    binary: &str,
    ask: &vta_sdk::provision_client::ProvisionAsk,
) -> Result<(), Box<dyn std::error::Error>> {
    let context_id = ask.context.as_str();
    let info = write_offline_bootstrap_request(out, ask).await?;

    write_secret_file_0600(seed_path, &info.seed)?;

    eprintln!();
    eprintln!("  Offline bootstrap request ready.");
    eprintln!();
    eprintln!("  Request file:   {}", info.request_path.display());
    eprintln!("  Seed (secret):  {}", seed_path.display());
    eprintln!();
    eprintln!("  Consumer DID:   {}", info.client_did);
    eprintln!("  Nonce:          {}", info.nonce);
    eprintln!();
    eprintln!("  Next steps:");
    eprintln!(
        "    1. Ferry {} to your VTA admin.",
        info.request_path.display()
    );
    eprintln!("    2. Ask them to create the VTA context with this DID as admin");
    eprintln!("       (skip if the context already exists), via either:");
    eprintln!(
        "         pnm contexts create --context {} \\\n           --admin {}",
        context_id, info.client_did
    );
    eprintln!("       or, on the VTA host directly:");
    eprintln!(
        "         vta contexts create --id {} \\\n           --admin-did {} --admin-expires 1h",
        context_id, info.client_did
    );
    eprintln!("    3. Ask them to seal the response:");
    eprintln!(
        "         vta bootstrap provision-integration --request <request-file> \\\n           --out <bundle-file>"
    );
    eprintln!("    4. They send back an ASCII-armored sealed bundle + SHA-256 digest.");
    eprintln!("    5. Run:");
    eprintln!("         {binary} vta-open --bundle <bundle> --expect-digest <hex>");
    eprintln!();
    eprintln!("  KEEP THE SEED FILE. Losing it means you cannot open the response.");
    eprintln!();

    Ok(())
}

/// CLI-facing wrapper around [`open_offline_bootstrap_response`]. Opens
/// the armored bundle and writes three artifacts:
///
/// 1. `did_doc_out` — pretty-printed DID document JSON.
/// 2. `did_log_out` — signed DID log JSONL (only when the template
///    emitted a `WebvhLog` output).
/// 3. `secrets_out` — minted private keys + VTA trust material JSON,
///    chmod-0600 on Unix.
///
/// Prints the minted DID + VTA metadata and a per-service "next steps"
/// block picked from `next`.
pub fn run_offline_open_cli(
    bundle: &Path,
    expect_digest: &str,
    seed_path: &Path,
    did_doc_out: &Path,
    did_log_out: &Path,
    secrets_out: &Path,
    next: OfflineOpenNextStep<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let armor =
        std::fs::read_to_string(bundle).map_err(|e| format!("read {}: {e}", bundle.display()))?;

    let seed_bytes = std::fs::read(seed_path).map_err(|e| {
        format!(
            "failed to read ephemeral seed at {}: {e}",
            seed_path.display()
        )
    })?;
    let seed: [u8; 32] = seed_bytes.as_slice().try_into().map_err(|_| {
        format!(
            "ephemeral seed at {} has {} bytes (expected 32)",
            seed_path.display(),
            seed_bytes.len()
        )
    })?;

    let result = open_offline_bootstrap_response(&armor, expect_digest, &seed)?;

    let did_doc_json = serde_json::to_string_pretty(&result.did_document)?;
    std::fs::write(did_doc_out, &did_doc_json)?;

    if let Some(ref log) = result.log_entry {
        std::fs::write(did_log_out, log)?;
    }

    let secrets_payload = serde_json::json!({
        "did": result.did,
        "signing_key_multibase": result.signing_key_multibase,
        "key_agreement_multibase": result.key_agreement_multibase,
        "admin_did": result.admin_did,
        "admin_signing_key_multibase": result.admin_signing_key_multibase,
        "vta_did": result.vta_did,
        "vta_url": result.vta_url,
        "authorization_vc": result.authorization_vc,
    });
    write_secret_file_0600(
        secrets_out,
        serde_json::to_string_pretty(&secrets_payload)?.as_bytes(),
    )?;

    eprintln!();
    eprintln!("  Sealed response opened.");
    eprintln!();
    eprintln!("  DID:            {}", result.did);
    eprintln!("  VTA DID:        {}", result.vta_did);
    if let Some(ref url) = result.vta_url {
        eprintln!("  VTA URL:        {url}");
    }
    eprintln!();
    eprintln!("  Wrote {}", did_doc_out.display());
    if result.log_entry.is_some() {
        eprintln!("  Wrote {}", did_log_out.display());
    } else {
        eprintln!("  No WebvhLog output in the sealed response — did_log_out not written.");
    }
    eprintln!("  Wrote {} (0600)", secrets_out.display());
    eprintln!();
    eprintln!("  Next steps:");
    eprintln!("    1. Publish the DID document at <hosting-url>/<path>/did.jsonl using");
    eprintln!(
        "       `did-hosting-server bootstrap-did --did-log {}` on the hosting server.",
        did_log_out.display()
    );
    match next {
        OfflineOpenNextStep::ImportSecrets { binary } => {
            eprintln!("    2. Persist the keys via `{binary} import-secrets --signing-key");
            eprintln!("       <signing_key_multibase> --ka-key <key_agreement_multibase>`,");
            eprintln!("       using the values from {}.", secrets_out.display());
        }
        OfflineOpenNextStep::Setup { binary } => {
            eprintln!("    2. Run `{binary} setup` and, when the wizard asks for keys,");
            eprintln!("       feed in the `signing_key_multibase` and `key_agreement_multibase`");
            eprintln!("       values from {}.", secrets_out.display());
            eprintln!("       (A dedicated `import-secrets` subcommand for {binary} is");
            eprintln!("       planned; for now the setup wizard is the supported entry point.)");
        }
    }
    eprintln!();

    Ok(())
}
