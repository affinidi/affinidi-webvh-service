use anyhow::{Context, Result, bail};
use clap::Parser;
use did_hosting_common::WebVHClient;
use did_hosting_common::did::generate_ed25519_identity;
use std::io::{self, Write};
use tracing::info;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(about = "Create a did:webvh DID and publish it through a DID Hosting control plane")]
struct Cli {
    /// Base URL of the control plane (e.g. http://localhost:8532)
    #[arg(long)]
    server_url: String,

    /// DID of the DID Hosting service: every signed request is addressed to
    /// it, and every reply must be signed by it.
    #[arg(long)]
    webvh_did: String,

    /// Optional custom path (e.g. "my-org"). If omitted, a random path is generated.
    #[arg(long)]
    path: Option<String>,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let server_url = cli.server_url.trim_end_matches('/');

    // ------------------------------------------------------------------
    // Step 1: Generate a did:key identity
    // ------------------------------------------------------------------
    let (my_did, my_secret) = generate_ed25519_identity().context("failed to generate did:key")?;

    println!("\n=== Step 1: Identity Generated ===");
    println!("  DID: {my_did}");
    println!(
        "\nEnsure this DID is in the server ACL (e.g. `did-hosting-control add-acl --did <did>`)."
    );
    print!("Press Enter to continue...");
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;

    // ------------------------------------------------------------------
    // Step 2: Sign requests as this identity
    // ------------------------------------------------------------------
    println!("=== Step 2: Signing requests as {my_did} ===");

    let mut client = WebVHClient::new(server_url);
    client
        .sign_as(&my_did, &my_secret, &cli.webvh_did)
        .await
        .context("could not set up the signing identity")?;

    // ------------------------------------------------------------------
    // Step 3: (Optional) Check name availability
    // ------------------------------------------------------------------
    if let Some(ref path) = cli.path {
        println!("\n=== Step 3: Checking name availability ===");
        let check = client
            .check_name(path)
            .await
            .context("failed to check name")?;
        if !check.available {
            bail!("path '{}' is not available", path);
        }
        println!("  Path '{path}' is available!");
    }

    // ------------------------------------------------------------------
    // Step 4: Create DID (request URI + build doc + upload)
    // ------------------------------------------------------------------
    println!("\n=== Step 4: Creating DID ===");

    let result = client
        .create_did(&my_secret, cli.path.as_deref())
        .await
        .context("failed to create DID")?;

    info!(mnemonic = %result.mnemonic, scid = %result.scid, "DID created and uploaded");

    // ------------------------------------------------------------------
    // Step 5: Verify resolution
    // ------------------------------------------------------------------
    println!("\n=== Step 5: Verifying Resolution ===");

    let resolved = client
        .resolve_did(&result.mnemonic)
        .await
        .context("failed to resolve DID")?;

    println!("  Resolved DID log:\n{resolved}");

    // ------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------
    println!("\n=== DID Created and Hosted Successfully! ===");
    println!("  Mnemonic:   {}", result.mnemonic);
    println!("  SCID:       {}", result.scid);
    println!("  DID URL:    {}", result.did_url);
    println!("  DID:        {}", result.did);
    println!("  Public Key: {}", result.public_key_multibase);

    Ok(())
}
