use crate::error::AppError;
use crate::store::KeyspaceHandle;
use bip39::Language;
use rand::random_range;

/// Generate a random 2-word BIP-39 mnemonic (e.g., "apple-banana").
fn random_mnemonic() -> String {
    let wordlist = Language::English.word_list();
    let w1 = wordlist[random_range(0..wordlist.len())];
    let w2 = wordlist[random_range(0..wordlist.len())];
    format!("{w1}-{w2}")
}

/// Generate a unique 2-word BIP-39 mnemonic that doesn't collide with
/// existing entries in the store. Retries up to 100 times.
pub async fn generate_unique_mnemonic(dids_ks: &KeyspaceHandle) -> Result<String, AppError> {
    for _ in 0..100 {
        let mnemonic = random_mnemonic();
        let key = format!("did:{mnemonic}");
        if !dids_ks.contains_key(key).await? {
            return Ok(mnemonic);
        }
    }

    Err(AppError::Internal(
        "failed to generate unique mnemonic after 100 attempts".into(),
    ))
}
