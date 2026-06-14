//! Seed-corpus generator for the `did.jsonl` fuzz targets (issue #47, item #1).
//!
//! `verify_did_log_proofs` validates the SCID / entry-hash chain, so random or
//! single-entry input dies before reaching the chain-walk logic. This tool
//! builds a handful of **valid multi-entry** did:webvh logs (genesis + updates,
//! with/without pre-rotation, with witnesses, and a deactivated tail) and
//! writes them as seed-corpus fixtures the fuzzer mutates from.
//!
//! Each fixture is self-checked against the real
//! `did_hosting_common::did_ops` functions before it is written, and the tool
//! prints what each one exercises. Note that a *witness-configured* chain does
//! not fully pass `verify_did_log_proofs` here — that function does not load
//! the separate witness-proof file (see its doc comment), so witnessed
//! fixtures are still valuable seeds but only fully pass `validate_did_jsonl`.
//!
//! Run:
//! ```sh
//! cargo run -p did-hosting-common --example gen_corpus            # -> ./fuzz/corpus
//! cargo run -p did-hosting-common --example gen_corpus -- /tmp/out
//! ```
//! The generator is non-deterministic only in the keys and `versionTime`
//! stamps; re-running refreshes the corpus as the format evolves.

use std::sync::Arc;

use chrono::{DateTime, Duration, FixedOffset, TimeZone, Utc};
use didwebvh_rs::parameters::Parameters;
use didwebvh_rs::witness::{Witness, Witnesses};
use didwebvh_rs::{DIDWebVHState, Multibase};
use serde_json::{Value, json};

use did_hosting_common::Secret;
use did_hosting_common::did::generate_ed25519_identity;
use did_hosting_common::did_ops::{validate_did_jsonl, verify_did_log_proofs};

const DOMAIN: &str = "fuzz.example.com";

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() -> AnyResult<()> {
    let out_root = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "fuzz/corpus".to_string());

    // Per-target seed directories. `validate_did_id_matches_request` takes a
    // (did_id, path, base_url) tuple rather than a did.jsonl, so it is seeded
    // separately below.
    let jsonl_targets = ["validate_did_jsonl", "verify_did_log_proofs"];

    let mut fixtures: Vec<(&str, String, bool)> = Vec::new();

    // 1. Simple multi-entry chain, no pre-rotation: one update key signs every
    //    entry. The cleanest seed for the chain-walk — fully passes both gates.
    fixtures.push(("chain_simple", build_simple_chain(3).await?, true));

    // 2. Pre-rotation chain: each entry pre-commits next_key_hashes and the
    //    next entry reveals + rotates to them. Exercises key-authorisation.
    fixtures.push(("chain_prerotation", build_prerotation_chain().await?, true));

    // 3. Witness-configured chain: witnesses declared in parameters. Fully
    //    passes the structural gate; rich seed for the proof gate.
    fixtures.push(("chain_witnessed", build_witnessed_chain().await?, false));

    // 4. Deactivated tail: a valid chain terminated by a deactivation entry.
    fixtures.push(("chain_deactivated", build_deactivated_chain().await?, true));

    for (name, jsonl, expect_proofs_ok) in &fixtures {
        // Self-check against the real validators so we never commit a fixture
        // that doesn't do what we claim.
        let structural = validate_did_jsonl(jsonl);
        let proofs = verify_did_log_proofs(jsonl);
        let entries = jsonl.lines().filter(|l| !l.trim().is_empty()).count();
        println!(
            "{name}: {entries} entries | validate_did_jsonl={} | verify_did_log_proofs={}",
            ok(&structural),
            ok(&proofs),
        );
        if let Err(e) = &structural {
            return Err(format!("fixture {name} failed structural validation: {e}").into());
        }
        if *expect_proofs_ok && let Err(e) = &proofs {
            return Err(format!(
                "fixture {name} was expected to pass verify_did_log_proofs but failed: {e}"
            )
            .into());
        }

        // Witnessed chain only seeds the structural target (it doesn't fully
        // pass the proof gate); everything else seeds both jsonl targets.
        let targets: &[&str] = if *expect_proofs_ok {
            &jsonl_targets
        } else {
            &jsonl_targets[..1]
        };
        for target in targets {
            let dir = format!("{out_root}/{target}");
            std::fs::create_dir_all(&dir)?;
            std::fs::write(format!("{dir}/{name}.jsonl"), jsonl)?;
        }
    }

    // Seed `validate_did_id_matches_request`. Its fuzz target consumes an
    // Arbitrary (String, String, String); seeding it with raw bytes is of
    // limited value, but we drop a couple of human-readable seeds containing
    // realistic did:webvh identifiers + paths to bias early exploration.
    let id_dir = format!("{out_root}/validate_did_id_matches_request");
    std::fs::create_dir_all(&id_dir)?;
    for (i, seed) in [
        format!("did:webvh:QmSCID:{DOMAIN}\x00tenant/alice\x00https://{DOMAIN}"),
        format!("did:webvh:QmSCID:{DOMAIN}:tenant:alice\x00tenant/alice\x00https://{DOMAIN}"),
    ]
    .iter()
    .enumerate()
    {
        std::fs::write(format!("{id_dir}/seed_{i}.bin"), seed)?;
    }

    println!(
        "\nWrote {} did.jsonl fixtures under {out_root}/",
        fixtures.len()
    );
    Ok(())
}

fn ok<T, E: std::fmt::Display>(r: &Result<T, E>) -> String {
    match r {
        Ok(_) => "OK".to_string(),
        Err(e) => format!("ERR({e})"),
    }
}

/// A minimal DID document template. `create_log_entry` substitutes `{SCID}`.
fn did_document() -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": format!("did:webvh:{{SCID}}:{DOMAIN}"),
    })
}

/// didwebvh-rs requires the signing key's verification method to be
/// `did:key:<mb>#<mb>`. Mirror what `did_ops`/`did` does on the publish path.
fn signer(secret: &Secret) -> AnyResult<Secret> {
    let mb = secret.get_public_keymultibase()?;
    let mut s = secret.clone();
    if !s.id.contains('#') {
        s.id = format!("did:key:{mb}#{mb}");
    }
    Ok(s)
}

fn ts(day: i64) -> DateTime<FixedOffset> {
    (Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap() + Duration::days(day)).fixed_offset()
}

fn to_jsonl(state: &DIDWebVHState) -> AnyResult<String> {
    let lines = state
        .log_entries()
        .iter()
        .map(|e| serde_json::to_string(&e.log_entry))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(lines.join("\n"))
}

fn mb(secret: &Secret) -> AnyResult<Multibase> {
    Ok(Multibase::new(secret.get_public_keymultibase()?))
}

fn mb_hash(secret: &Secret) -> AnyResult<Multibase> {
    Ok(Multibase::new(secret.get_public_keymultibase_hash()?))
}

/// `count` entries, no pre-rotation: a single update key signs all of them.
async fn build_simple_chain(count: usize) -> AnyResult<String> {
    let (_, key) = generate_ed25519_identity()?;
    let mut state = DIDWebVHState::default();

    let genesis = Parameters::new()
        .with_update_keys(vec![key.get_public_keymultibase()?])
        .build();
    state
        .create_log_entry(Some(ts(0)), &did_document(), &genesis, &signer(&key)?)
        .await?;

    for i in 1..count {
        let old = state.log_entries().last().unwrap();
        let doc = old.get_state().clone();
        let mut params = old.validated_parameters.clone();
        params.update_keys = Some(Arc::new(vec![mb(&key)?]));
        state
            .create_log_entry(Some(ts(i as i64)), &doc, &params, &signer(&key)?)
            .await?;
    }
    to_jsonl(&state)
}

/// Genesis pre-commits the next update keys; the second entry reveals and
/// rotates to them, signing with one of the freshly-revealed keys.
async fn build_prerotation_chain() -> AnyResult<String> {
    let (_, g) = generate_ed25519_identity()?;
    let (_, a) = generate_ed25519_identity()?;
    let (_, b) = generate_ed25519_identity()?;

    let mut state = DIDWebVHState::default();
    let genesis = Parameters::new()
        .with_update_keys(vec![g.get_public_keymultibase()?])
        .with_next_key_hashes(vec![
            a.get_public_keymultibase_hash()?,
            b.get_public_keymultibase_hash()?,
        ])
        .build();
    state
        .create_log_entry(Some(ts(0)), &did_document(), &genesis, &signer(&g)?)
        .await?;

    // Update: reveal a/b as the new update keys, pre-commit fresh next hashes,
    // and sign with `a` (whose hash was committed in genesis).
    let (_, c) = generate_ed25519_identity()?;
    let (_, d) = generate_ed25519_identity()?;
    let old = state.log_entries().last().unwrap();
    let doc = old.get_state().clone();
    let mut params = old.validated_parameters.clone();
    params.update_keys = Some(Arc::new(vec![mb(&a)?, mb(&b)?]));
    params.next_key_hashes = Some(Arc::new(vec![mb_hash(&c)?, mb_hash(&d)?]));
    state
        .create_log_entry(Some(ts(1)), &doc, &params, &signer(&a)?)
        .await?;

    to_jsonl(&state)
}

/// A 2-entry chain with witnesses declared in the genesis parameters.
async fn build_witnessed_chain() -> AnyResult<String> {
    let (_, key) = generate_ed25519_identity()?;
    let (w_did, _) = generate_ed25519_identity()?;

    let mut state = DIDWebVHState::default();
    let genesis = Parameters::new()
        .with_update_keys(vec![key.get_public_keymultibase()?])
        .with_witnesses(Witnesses::Value {
            threshold: 1,
            witnesses: vec![Witness {
                id: Multibase::new(w_did),
            }],
        })
        .build();
    state
        .create_log_entry(Some(ts(0)), &did_document(), &genesis, &signer(&key)?)
        .await?;

    let old = state.log_entries().last().unwrap();
    let doc = old.get_state().clone();
    let mut params = old.validated_parameters.clone();
    params.update_keys = Some(Arc::new(vec![mb(&key)?]));
    state
        .create_log_entry(Some(ts(1)), &doc, &params, &signer(&key)?)
        .await?;

    to_jsonl(&state)
}

/// A simple chain terminated with a deactivation entry.
async fn build_deactivated_chain() -> AnyResult<String> {
    let (_, key) = generate_ed25519_identity()?;
    let mut state = DIDWebVHState::default();

    let genesis = Parameters::new()
        .with_update_keys(vec![key.get_public_keymultibase()?])
        .build();
    state
        .create_log_entry(Some(ts(0)), &did_document(), &genesis, &signer(&key)?)
        .await?;

    // One ordinary update so the deactivation lands on a multi-entry chain.
    let old = state.log_entries().last().unwrap();
    let doc = old.get_state().clone();
    let mut params = old.validated_parameters.clone();
    params.update_keys = Some(Arc::new(vec![mb(&key)?]));
    state
        .create_log_entry(Some(ts(1)), &doc, &params, &signer(&key)?)
        .await?;

    state.deactivate(&signer(&key)?).await?;
    to_jsonl(&state)
}
