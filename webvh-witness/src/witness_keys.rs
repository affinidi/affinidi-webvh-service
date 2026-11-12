//! How a witness identity's signing key is kept: sealed to a key-encryption
//! key that lives in the secret store.
//!
//! A witness identity's record in the data store (`KS_WITNESSES`) carries its
//! Ed25519 private key only as an HPKE ciphertext (`sealed_private_key`),
//! sealed to the witness key-encryption key (an X25519 key). That key is held
//! in the configured secret store, in an entry of its own
//! ([`create_witness_kek_store`](did_hosting_common::server::secret_store::create_witness_kek_store)),
//! with the protection the operator chose for the service's own keys. Reading
//! the data store, or a backup or snapshot of it, yields no usable signing
//! key.
//!
//! Why seal into the record rather than keep each key in the secret store:
//!
//! - **One write per identity, in the data store.** Creating an identity is
//!   a single record insert; deleting one removes its key with it. Nothing
//!   reads, modifies and writes back a shared secret-store entry, so writers
//!   in different processes cannot lose each other's keys, and no entry grows
//!   with the number of identities (the cloud backends cap an entry at 25–64
//!   KB).
//! - **Older releases never touch it.** The key-encryption key is written
//!   once, to an entry no release rewrites as part of the service envelope,
//!   so a rollback, an older CLI or an older replica cannot drop it.
//! - **No network on the signing path.** The key-encryption key is read once,
//!   when the witness starts (or a CLI command runs), and kept in memory; a
//!   signature opens the sealed key from the record already read.
//!
//! The seal is `vta_sdk::sealed_transfer::hpke` (DHKEM-X25519, HKDF-SHA256,
//! ChaCha20-Poly1305), the envelope this workspace already uses for VTA
//! bootstrap bundles. The additional authenticated data names this purpose
//! and the identity's `witness_id`, so a sealed key moved onto another record
//! does not open.
//!
//! Releases before this one kept the private key in clear in the record
//! (`private_key_multibase`); [`migrate_record_keys`] seals such keys when the
//! witness starts.

use std::time::Duration;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use did_hosting_common::server::secret_store::WitnessKekStore;
use serde_json::Value;
use tracing::{info, warn};
use vta_sdk::sealed_transfer::hpke;

use crate::error::AppError;
use crate::store::{KeyspaceHandle, Store};

/// The member the record held the private key in, in clear, before keys were
/// sealed.
pub const LEGACY_KEY_MEMBER: &str = "private_key_multibase";
/// The member the record holds the sealed private key in.
pub const SEALED_KEY_MEMBER: &str = "sealed_private_key";

/// The key-encryption key's public key (multibase), as recorded in the data
/// store when it was created: what every sealed record is sealed to.
pub const KEK_PUBLIC_KEY: &str = "kek:public";
/// Claimed (atomically incremented) by the one process that creates the
/// key-encryption key.
pub const KEK_CLAIM_KEY: &str = "kek:claim";

/// How long a process that lost the creation claim waits for the winner's key
/// to appear in the secret store.
const KEK_CLAIM_WAIT: Duration = Duration::from_secs(30);

/// Records rewritten per batch during migration: well inside every backend's
/// transaction bound (DynamoDB's is 100 writes).
pub const MIGRATION_BATCH: usize = 50;

const AAD_PREFIX: &[u8] = b"webvh-witness-signing-key/v1\0";

/// The witness key-encryption key, in memory. Opens and seals identities'
/// signing keys; never written anywhere by this type.
pub struct WitnessKeys {
    kek: Secret,
    public: [u8; 32],
}

impl WitnessKeys {
    /// Wrap an X25519 key-encryption key.
    pub fn from_secret(kek: Secret) -> Result<Self, AppError> {
        let public: [u8; 32] = kek
            .get_public_bytes()
            .try_into()
            .map_err(|_| AppError::Internal("the key-encryption key is not X25519".into()))?;
        if kek.get_private_bytes().len() != 32 {
            return Err(AppError::Internal(
                "the key-encryption key is not X25519".into(),
            ));
        }
        Ok(Self { kek, public })
    }

    /// A fresh key-encryption key (tests, and first creation).
    pub fn generate() -> Result<Self, AppError> {
        let kek = Secret::generate_x25519(None, None)
            .map_err(|e| AppError::Internal(format!("cannot generate a key: {e}")))?;
        Self::from_secret(kek)
    }

    /// The public key, multibase: what the data store records.
    pub fn public_multibase(&self) -> String {
        multibase::encode(multibase::Base::Base58Btc, self.public)
    }

    /// Seal `private_key` (multibase) for the identity `witness_id`.
    pub fn seal(&self, witness_id: &str, private_key: &str) -> Result<String, AppError> {
        let sealed = hpke::seal(&self.public, private_key.as_bytes(), &aad(witness_id))
            .map_err(|e| AppError::Internal(format!("cannot seal a witness signing key: {e}")))?;
        let mut bytes = sealed.kem_encap.to_vec();
        bytes.extend_from_slice(&sealed.aead_ciphertext);
        Ok(multibase::encode(multibase::Base::Base64Url, bytes))
    }

    /// Open `witness_id`'s sealed key and rebuild its signing secret, refusing
    /// one that does not open or whose public half is not `witness_id`.
    pub fn open(&self, did: &str, witness_id: &str, sealed: &str) -> Result<Secret, AppError> {
        let unreadable = || {
            AppError::Internal(format!(
                "the sealed signing key of witness {witness_id} does not open with this \
                 witness's key-encryption key"
            ))
        };
        let (_, bytes) = multibase::decode(sealed).map_err(|_| unreadable())?;
        if bytes.len() <= 32 {
            return Err(unreadable());
        }
        let sealed = hpke::HpkeSealed {
            kem_encap: bytes[..32].try_into().map_err(|_| unreadable())?,
            aead_ciphertext: bytes[32..].to_vec(),
        };
        let mut secret_bytes: [u8; 32] = self
            .kek
            .get_private_bytes()
            .try_into()
            .map_err(|_| unreadable())?;
        let opened = hpke::open(&secret_bytes, &sealed, &aad(witness_id));
        secret_bytes.iter_mut().for_each(|b| *b = 0);
        let mut plain = opened.map_err(|_| unreadable())?;
        let result = std::str::from_utf8(&plain)
            .map_err(|_| unreadable())
            .and_then(|private| signing_secret(did, witness_id, private));
        plain.iter_mut().for_each(|b| *b = 0);
        result
    }
}

fn aad(witness_id: &str) -> Vec<u8> {
    let mut aad = AAD_PREFIX.to_vec();
    aad.extend_from_slice(witness_id.as_bytes());
    aad
}

/// Rebuild `witness_id`'s signing secret from its multibase private key,
/// refusing a key whose public half is not `witness_id`.
pub fn signing_secret(did: &str, witness_id: &str, private_key: &str) -> Result<Secret, AppError> {
    let kid = format!("{did}#{witness_id}");
    let secret = Secret::from_multibase(private_key, Some(&kid)).map_err(|_| {
        AppError::Internal(format!(
            "the signing key of witness {witness_id} cannot be read"
        ))
    })?;
    let public = secret.get_public_keymultibase().map_err(|_| {
        AppError::Internal(format!(
            "the signing key of witness {witness_id} has no public key"
        ))
    })?;
    if public != witness_id {
        return Err(AppError::Internal(format!(
            "the signing key held for witness {witness_id} belongs to another identity"
        )));
    }
    Ok(secret)
}

/// The witness key-encryption key: read from the secret store, or created
/// there if this deployment has none yet.
///
/// The data store records the key's public half when it is created
/// ([`KEK_PUBLIC_KEY`]). A key in the secret store that is not the recorded
/// one, or no key where one is recorded (a secret store replaced or not
/// restored), refuses: identities sealed to the recorded key could not sign,
/// and a new key would hide that.
///
/// Creation is claimed through the data store's atomic counter
/// ([`KEK_CLAIM_KEY`]), so two processes starting together on one store do not
/// each write a different key; the one that loses waits for the winner's.
pub async fn load_or_create(
    kek_store: &WitnessKekStore,
    witnesses_ks: &KeyspaceHandle,
) -> Result<WitnessKeys, AppError> {
    load_or_create_waiting(kek_store, witnesses_ks, KEK_CLAIM_WAIT).await
}

async fn load_or_create_waiting(
    kek_store: &WitnessKekStore,
    witnesses_ks: &KeyspaceHandle,
    claim_wait: Duration,
) -> Result<WitnessKeys, AppError> {
    let recorded: Option<String> = witnesses_ks.get(KEK_PUBLIC_KEY).await?;
    if let Some(kek) = kek_store.get().await? {
        let keys = WitnessKeys::from_secret(kek)?;
        return accept(keys, recorded, kek_store, witnesses_ks).await;
    }
    if let Some(recorded) = recorded {
        return Err(AppError::Config(format!(
            "the witness key-encryption key is missing from the secret store ({}), but this \
             data store's witness identities are sealed to {recorded}. Restore that entry from \
             the secret store (or its backup) this witness used before; until then no identity \
             can sign.",
            kek_store.location()
        )));
    }

    if witnesses_ks.incr_raw(KEK_CLAIM_KEY).await? == 1 {
        let keys = WitnessKeys::generate()?;
        kek_store.set(&keys.kek).await?;
        let read = kek_store.get().await?.ok_or_else(|| {
            AppError::SecretStore(format!(
                "the witness key-encryption key written to {} did not read back",
                kek_store.location()
            ))
        })?;
        if read.get_public_bytes() != keys.public {
            return Err(AppError::SecretStore(format!(
                "the witness key-encryption key in {} changed while it was being created; \
                 another process wrote it. Start again.",
                kek_store.location()
            )));
        }
        witnesses_ks
            .insert(KEK_PUBLIC_KEY, &keys.public_multibase())
            .await?;
        info!(
            location = kek_store.location(),
            "created the witness key-encryption key"
        );
        return Ok(keys);
    }

    // Another process holds the claim: wait for its key.
    let deadline = tokio::time::Instant::now() + claim_wait;
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if let Some(kek) = kek_store.get().await? {
            let recorded: Option<String> = witnesses_ks.get(KEK_PUBLIC_KEY).await?;
            return accept(
                WitnessKeys::from_secret(kek)?,
                recorded,
                kek_store,
                witnesses_ks,
            )
            .await;
        }
    }
    Err(AppError::Config(format!(
        "another process claimed the creation of the witness key-encryption key, but none \
         appeared in {} within {}s. If no other witness process is starting, the claim was \
         left by one that stopped part-way: run `webvh-witness reset-witness-kek-claim` and \
         start again.",
        kek_store.location(),
        claim_wait.as_secs()
    )))
}

async fn accept(
    keys: WitnessKeys,
    recorded: Option<String>,
    kek_store: &WitnessKekStore,
    witnesses_ks: &KeyspaceHandle,
) -> Result<WitnessKeys, AppError> {
    let public = keys.public_multibase();
    match recorded {
        Some(r) if r == public => Ok(keys),
        Some(r) => Err(AppError::Config(format!(
            "the witness key-encryption key in the secret store ({}) is {public}, but this \
             data store's witness identities are sealed to {r}. Point [secrets] at the entry \
             this witness used before, or restore it; until then no identity can sign.",
            kek_store.location()
        ))),
        None => {
            // Created by a process that stopped before recording it.
            witnesses_ks.insert(KEK_PUBLIC_KEY, &public).await?;
            Ok(keys)
        }
    }
}

/// Remove a creation claim left by a process that stopped part-way, so the
/// next start can create the key-encryption key. Refused once a key has been
/// recorded: the claim is then settled.
pub async fn reset_kek_claim(witnesses_ks: &KeyspaceHandle) -> Result<bool, AppError> {
    if witnesses_ks.get::<String>(KEK_PUBLIC_KEY).await?.is_some() {
        return Err(AppError::Config(
            "a witness key-encryption key is recorded for this data store; its creation \
             claim is settled and is not reset"
                .into(),
        ));
    }
    let had = witnesses_ks.get_raw(KEK_CLAIM_KEY).await?.is_some();
    witnesses_ks.remove(KEK_CLAIM_KEY).await?;
    Ok(had)
}

/// What [`migrate_record_keys`] found and did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MigrationReport {
    /// Identities whose clear key was sealed.
    pub sealed: Vec<String>,
    /// Identities with no key at all, or a sealed key that does not open:
    /// they cannot sign.
    pub unusable: Vec<String>,
}

/// Seal every private key a record still holds in clear, and check the rest.
///
/// Runs when the witness starts, before it serves anything. For each record
/// with a clear key ([`LEGACY_KEY_MEMBER`]): the key must belong to the record
/// (its public half is the `witness_id`), else startup is refused and nothing
/// is written. Then, a batch at a time ([`MIGRATION_BATCH`]), each record is
/// **read again** and only the clear member is replaced by the sealed one; a
/// record that is gone, or already sealed, by then is left alone. Each record
/// is one write, so a crash leaves every identity either clear or sealed,
/// never without a key, and the next start carries on.
///
/// Why seal at startup rather than refuse to start: the clear copy is in the
/// data store, and in each new backup or snapshot, for as long as it stays.
/// Sealing it changes no key, so no DID's witness list needs updating, and it
/// needs no operator step. Copies already made are not reached; see the
/// README.
///
/// No key material is logged or returned; only witness ids.
pub async fn migrate_record_keys(
    store: &Store,
    witnesses_ks: &KeyspaceHandle,
    keys: &WitnessKeys,
) -> Result<MigrationReport, AppError> {
    let mut report = MigrationReport::default();
    let mut to_seal: Vec<(Vec<u8>, String)> = Vec::new();

    for (key, value) in witnesses_ks.prefix_iter_raw("witness:").await? {
        let record: Value = serde_json::from_slice(&value)?;
        let witness_id = str_member(&record, "witness_id");
        let did = str_member(&record, "did");
        if let Some(clear) = record.get(LEGACY_KEY_MEMBER) {
            signing_secret(&did, &witness_id, clear.as_str().unwrap_or_default()).map_err(|e| {
                AppError::Internal(format!(
                    "witness signing-key migration: {e}. Startup is refused; nothing was \
                     changed."
                ))
            })?;
            to_seal.push((key, witness_id));
        } else {
            let sealed = str_member(&record, SEALED_KEY_MEMBER);
            if sealed.is_empty() || keys.open(&did, &witness_id, &sealed).is_err() {
                report.unusable.push(witness_id);
            }
        }
    }

    for chunk in to_seal.chunks(MIGRATION_BATCH) {
        let mut batch = store.batch();
        let mut in_batch = Vec::new();
        for (key, witness_id) in chunk {
            // Re-read: the record may have changed since the scan.
            let Some(value) = witnesses_ks.get_raw(key.clone()).await? else {
                continue;
            };
            let mut record: Value = serde_json::from_slice(&value)?;
            let Some(obj) = record.as_object_mut() else {
                continue;
            };
            let Some(clear) = obj.remove(LEGACY_KEY_MEMBER) else {
                continue;
            };
            let sealed = keys.seal(witness_id, clear.as_str().unwrap_or_default())?;
            obj.insert(SEALED_KEY_MEMBER.into(), Value::String(sealed));
            batch.insert_raw(witnesses_ks, key.clone(), serde_json::to_vec(&record)?);
            in_batch.push(witness_id.clone());
        }
        if !in_batch.is_empty() {
            batch.commit().await?;
            report.sealed.extend(in_batch);
        }
    }
    if !report.sealed.is_empty() {
        store.persist().await?;
        info!(
            count = report.sealed.len(),
            witness_ids = ?report.sealed,
            "sealed witness signing keys held in clear in the data store"
        );
    }
    Ok(report)
}

fn str_member(record: &Value, member: &str) -> String {
    record
        .get(member)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Load (or create) the key-encryption key, seal any clear keys, and warn
/// about identities that cannot sign. What the witness — standalone or
/// embedded in the daemon — runs before serving.
pub async fn prepare(
    store: &Store,
    witnesses_ks: &KeyspaceHandle,
    kek_store: &WitnessKekStore,
) -> Result<WitnessKeys, AppError> {
    let keys = load_or_create(kek_store, witnesses_ks).await?;
    let report = migrate_record_keys(store, witnesses_ks, &keys).await?;
    if !report.unusable.is_empty() {
        warn!(
            witness_ids = ?report.unusable,
            "these witness identities have no signing key this witness can open and cannot \
             sign; delete them, or restore the key-encryption key they were sealed to"
        );
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) async fn temp_store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let config = did_hosting_common::server::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..Default::default()
        };
        (Store::open(&config).await.unwrap(), dir)
    }

    fn kek_store(dir: &tempfile::TempDir) -> WitnessKekStore {
        let secrets = crate::config::SecretsConfig {
            backend: Some(crate::secret_store::SecretBackend::Plaintext),
            confirm_plaintext: true,
            ..Default::default()
        };
        did_hosting_common::server::secret_store::create_witness_kek_store(
            &secrets,
            &dir.path().join("w.toml"),
        )
        .unwrap()
    }

    /// A record as releases before this one wrote it: the key in clear.
    async fn legacy_record(ks: &KeyspaceHandle) -> (String, String) {
        let secret = Secret::generate_ed25519(None, None);
        let private = secret.get_private_keymultibase().unwrap();
        let public = secret.get_public_keymultibase().unwrap();
        let record = json!({
            "witness_id": public,
            "did": format!("did:key:{public}"),
            "vta_key_id": null,
            "private_key_multibase": private,
            "public_key_multibase": public,
            "label": "old",
            "created_at": 1_700_000_000u64,
            "proofs_signed": 7u64,
        });
        ks.insert_raw(
            format!("witness:{public}"),
            serde_json::to_vec(&record).unwrap(),
        )
        .await
        .unwrap();
        (public, private)
    }

    async fn raw(ks: &KeyspaceHandle, id: &str) -> String {
        String::from_utf8(ks.get_raw(format!("witness:{id}")).await.unwrap().unwrap()).unwrap()
    }

    #[test]
    fn a_sealed_key_opens_only_for_its_own_identity_and_key() {
        let keys = WitnessKeys::generate().unwrap();
        let s = Secret::generate_ed25519(None, None);
        let id = s.get_public_keymultibase().unwrap();
        let private = s.get_private_keymultibase().unwrap();
        let did = format!("did:key:{id}");
        let sealed = keys.seal(&id, &private).unwrap();
        assert!(!sealed.contains(&private));
        let opened = keys.open(&did, &id, &sealed).unwrap();
        assert_eq!(opened.get_public_keymultibase().unwrap(), id);

        // Moved onto another identity's record: does not open.
        let other = Secret::generate_ed25519(None, None)
            .get_public_keymultibase()
            .unwrap();
        assert!(
            keys.open(&format!("did:key:{other}"), &other, &sealed)
                .is_err()
        );
        // Another key-encryption key: does not open.
        let err = WitnessKeys::generate()
            .unwrap()
            .open(&did, &id, &sealed)
            .unwrap_err();
        assert!(!err.to_string().contains(&private));
        // A sealed key that is not the identity's: refused after opening.
        let foreign = Secret::generate_ed25519(None, None)
            .get_private_keymultibase()
            .unwrap();
        let wrong = keys.seal(&id, &foreign).unwrap();
        assert!(
            keys.open(&did, &id, &wrong)
                .unwrap_err()
                .to_string()
                .contains("belongs to another identity")
        );
        assert!(keys.open(&did, &id, "zgarbage").is_err());
    }

    /// The key-encryption key is created once, recorded, and found again.
    #[tokio::test]
    async fn the_key_encryption_key_is_created_once_and_reloaded() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        let secrets_dir = tempfile::tempdir().unwrap();
        let first = load_or_create(&kek_store(&secrets_dir), &ks).await.unwrap();
        let again = load_or_create(&kek_store(&secrets_dir), &ks).await.unwrap();
        assert_eq!(first.public_multibase(), again.public_multibase());
        assert_eq!(
            ks.get::<String>(KEK_PUBLIC_KEY).await.unwrap(),
            Some(first.public_multibase())
        );
        // The claim is settled: it cannot be reset.
        assert!(reset_kek_claim(&ks).await.is_err());
    }

    /// A secret store without the recorded key, or with another one, refuses
    /// rather than sealing new identities to a key the old ones are not under.
    #[tokio::test]
    async fn a_missing_or_different_key_encryption_key_refuses() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        let secrets_dir = tempfile::tempdir().unwrap();
        let first = load_or_create(&kek_store(&secrets_dir), &ks).await.unwrap();

        let empty_dir = tempfile::tempdir().unwrap();
        let err = load_or_create(&kek_store(&empty_dir), &ks)
            .await
            .err()
            .expect("missing key refused");
        assert!(err.to_string().contains("missing"), "{err}");
        assert!(kek_store(&empty_dir).get().await.unwrap().is_none());

        kek_store(&empty_dir)
            .set(&Secret::generate_x25519(None, None).unwrap())
            .await
            .unwrap();
        let err = load_or_create(&kek_store(&empty_dir), &ks)
            .await
            .err()
            .expect("another key refused");
        assert!(err.to_string().contains(&first.public_multibase()), "{err}");
    }

    /// A claim held by a process that never wrote its key is waited on and
    /// then reported with the way out, which works.
    #[tokio::test]
    async fn a_stale_creation_claim_is_reported_and_can_be_reset() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        ks.incr_raw(KEK_CLAIM_KEY).await.unwrap();
        let secrets_dir = tempfile::tempdir().unwrap();
        let err = load_or_create_waiting(&kek_store(&secrets_dir), &ks, Duration::from_secs(2))
            .await
            .err()
            .expect("waited out");
        assert!(err.to_string().contains("reset-witness-kek-claim"), "{err}");
        assert!(reset_kek_claim(&ks).await.unwrap());
        assert!(load_or_create(&kek_store(&secrets_dir), &ks).await.is_ok());
    }

    #[tokio::test]
    async fn clear_keys_are_sealed_and_still_sign() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        let keys = WitnessKeys::generate().unwrap();
        let (a, a_key) = legacy_record(&ks).await;
        let (b, b_key) = legacy_record(&ks).await;
        let fresh = crate::witness_ops::create_witness(&ks, &keys, None)
            .await
            .unwrap();

        let report = migrate_record_keys(&store, &ks, &keys).await.unwrap();
        let mut sealed = report.sealed.clone();
        sealed.sort();
        let mut expect = vec![a.clone(), b.clone()];
        expect.sort();
        assert_eq!(sealed, expect);
        assert!(report.unusable.is_empty());

        for (id, key) in [(&a, &a_key), (&b, &b_key)] {
            let text = raw(&ks, id).await;
            assert!(!text.contains(key.as_str()), "{text}");
            assert!(!text.contains(LEGACY_KEY_MEMBER), "{text}");
            let record = crate::witness_ops::get_witness(&ks, id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(record.proofs_signed, 7);
            assert_eq!(record.label.as_deref(), Some("old"));
            let opened = keys
                .open(&record.did, id, &record.sealed_private_key)
                .unwrap();
            assert_eq!(&opened.get_private_keymultibase().unwrap(), key);
        }

        use crate::signing::WitnessSigner;
        let record = crate::witness_ops::get_witness(&ks, &a)
            .await
            .unwrap()
            .unwrap();
        let proof = crate::signing::LocalSigner::new(std::sync::Arc::new(keys))
            .sign_proof(&record, "1-Qm")
            .await
            .unwrap();
        assert!(proof.verification_method.ends_with(&a));

        let keys = WitnessKeys::generate().unwrap();
        // Run again with another key-encryption key: nothing in clear is
        // left, and every sealed record is reported as not opening.
        let again = migrate_record_keys(&store, &ks, &keys).await.unwrap();
        assert!(again.sealed.is_empty());
        assert_eq!(again.unusable.len(), 3);
        let _ = fresh;
    }

    /// More records than one batch holds: all are sealed.
    #[tokio::test]
    async fn more_records_than_one_batch_are_all_sealed() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        let keys = WitnessKeys::generate().unwrap();
        let mut ids = Vec::new();
        for _ in 0..(MIGRATION_BATCH * 2 + 7) {
            ids.push(legacy_record(&ks).await.0);
        }
        let report = migrate_record_keys(&store, &ks, &keys).await.unwrap();
        assert_eq!(report.sealed.len(), ids.len());
        for id in &ids {
            assert!(!raw(&ks, id).await.contains(LEGACY_KEY_MEMBER));
        }
    }

    #[tokio::test]
    async fn a_record_key_that_is_not_the_identitys_refuses_startup() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        let keys = WitnessKeys::generate().unwrap();
        let (a, _) = legacy_record(&ks).await;
        let (b, b_key) = legacy_record(&ks).await;
        let mut record: Value = serde_json::from_str(&raw(&ks, &a).await).unwrap();
        let foreign = Secret::generate_ed25519(None, None)
            .get_private_keymultibase()
            .unwrap();
        record[LEGACY_KEY_MEMBER] = json!(foreign);
        ks.insert_raw(format!("witness:{a}"), serde_json::to_vec(&record).unwrap())
            .await
            .unwrap();

        let err = migrate_record_keys(&store, &ks, &keys).await.unwrap_err();
        assert!(!err.to_string().contains(&foreign));
        assert!(raw(&ks, &a).await.contains(&foreign));
        // Nothing at all was written, the valid record included.
        assert!(raw(&ks, &b).await.contains(&b_key));
    }

    #[tokio::test]
    async fn an_identity_with_no_key_is_reported() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        let keys = WitnessKeys::generate().unwrap();
        let record = crate::witness_ops::create_witness(&ks, &keys, None)
            .await
            .unwrap();
        let mut value: Value = serde_json::from_str(&raw(&ks, &record.witness_id).await).unwrap();
        value.as_object_mut().unwrap().remove(SEALED_KEY_MEMBER);
        ks.insert_raw(
            format!("witness:{}", record.witness_id),
            serde_json::to_vec(&value).unwrap(),
        )
        .await
        .unwrap();
        let report = migrate_record_keys(&store, &ks, &keys).await.unwrap();
        assert_eq!(report.unusable, vec![record.witness_id]);
    }
}
