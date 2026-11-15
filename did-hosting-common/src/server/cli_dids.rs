//! Offline DID commands shared by `did-hosting-server` and
//! `did-hosting-daemon` (stop the service first; they open its store).

use super::config::StoreConfig;
use super::store::{KS_DIDS, Store};
use crate::did_ops::{DidRecord, content_log_key, content_witness_key, did_key};

/// `dump-did` — print the DID log (`did.jsonl`) stored at `mnemonic` to
/// stdout, and with `witness` its witness proofs after it (the separator on
/// stderr, so stdout stays the two documents).
pub async fn run_dump_did(
    store_config: &StoreConfig,
    mnemonic: &str,
    witness: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = Store::open(store_config).await?;
    let dids_ks = store.keyspace(KS_DIDS)?;

    let _: DidRecord = dids_ks
        .get(did_key(mnemonic))
        .await?
        .ok_or(format!("DID not found at path '{mnemonic}'"))?;

    let log_bytes = dids_ks
        .get_raw(content_log_key(mnemonic))
        .await?
        .ok_or(format!("no log content for path '{mnemonic}'"))?;
    let log = String::from_utf8(log_bytes)
        .map_err(|_| format!("invalid UTF-8 in log content for '{mnemonic}'"))?;
    print!("{log}");

    if witness {
        if let Some(witness_bytes) = dids_ks.get_raw(content_witness_key(mnemonic)).await? {
            let witness_str = String::from_utf8(witness_bytes)
                .map_err(|_| format!("invalid UTF-8 in witness content for '{mnemonic}'"))?;
            eprintln!("--- did-witness.json ---");
            print!("{witness_str}");
        } else {
            eprintln!("(no witness content)");
        }
    }

    Ok(())
}
