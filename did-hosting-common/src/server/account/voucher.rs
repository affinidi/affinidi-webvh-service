//! The single-use record of each `DidHostingVoucher` that admitted a guest
//! account.
//!
//! A voucher is accepted once, keyed on its (`issuer`, `id`), and the record
//! is kept until the voucher's `validUntil` — after which the voucher is
//! refused as expired anyway, so the record has nothing left to prevent.

use sha2::{Digest, Sha256};

use crate::server::error::AppError;
use crate::server::store::KeyspaceHandle;

/// The prefix every record is stored under.
pub const VOUCHER_PREFIX: &str = "acct_voucher:";

/// The record's key: a digest, so an issuer-chosen `id` of any shape makes a
/// bounded key.
fn voucher_key(issuer: &str, id: &str) -> String {
    let mut h = Sha256::new();
    h.update(crate::scid::identity(issuer).as_bytes());
    h.update([0u8]);
    h.update(id.as_bytes());
    format!("{VOUCHER_PREFIX}{}", hex::encode(h.finalize()))
}

/// Whether the voucher (`issuer`, `id`) has been accepted before.
pub async fn is_used(ks: &KeyspaceHandle, issuer: &str, id: &str) -> Result<bool, AppError> {
    ks.contains_key(voucher_key(issuer, id)).await
}

/// Record the voucher (`issuer`, `id`) as accepted, until `valid_until`
/// (epoch seconds).
pub async fn record_used(
    ks: &KeyspaceHandle,
    issuer: &str,
    id: &str,
    valid_until: u64,
) -> Result<(), AppError> {
    ks.insert_raw(voucher_key(issuer, id), valid_until.to_be_bytes().to_vec())
        .await
}

/// Delete the records of vouchers whose `validUntil` is before `now`.
/// Returns how many were deleted.
pub async fn sweep_expired(ks: &KeyspaceHandle, now: u64) -> Result<usize, AppError> {
    let mut removed = 0;
    for (key, value) in ks.prefix_iter_raw(VOUCHER_PREFIX).await? {
        let until = <[u8; 8]>::try_from(value.as_slice())
            .map(u64::from_be_bytes)
            .unwrap_or(0);
        if until < now {
            ks.remove(key).await?;
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(all(test, feature = "store-fjall"))]
mod tests {
    use super::*;
    use crate::server::account::test_ks;

    #[tokio::test]
    async fn a_voucher_is_used_once_per_issuer_and_swept_after_it_lapses() {
        let (ks, _dir) = test_ks().await;
        assert!(!is_used(&ks, "did:example:vtc", "v1").await.unwrap());
        record_used(&ks, "did:example:vtc", "v1", 100)
            .await
            .unwrap();
        assert!(is_used(&ks, "did:example:vtc", "v1").await.unwrap());
        // Another issuer's `v1` is another voucher.
        assert!(!is_used(&ks, "did:example:other", "v1").await.unwrap());
        assert_eq!(sweep_expired(&ks, 50).await.unwrap(), 0);
        assert_eq!(sweep_expired(&ks, 101).await.unwrap(), 1);
        assert!(!is_used(&ks, "did:example:vtc", "v1").await.unwrap());
    }
}
