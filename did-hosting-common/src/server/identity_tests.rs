//! Tests for [`super`].

// The tests that open a store are fjall-only (a fresh temp-dir store
// each); what only they use is unused on other backends.
#![cfg_attr(not(feature = "store-fjall"), allow(unused_imports, dead_code))]
use super::*;
use crate::server::config::StoreConfig;
use std::sync::Mutex as StdMutex;

const DID: &str = "did:webvh:example:alpha";

#[cfg(feature = "store-fjall")]
async fn fjall_store() -> Store {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = StoreConfig {
        data_dir: dir.path().to_path_buf(),
        ..StoreConfig::default()
    };
    std::mem::forget(dir);
    Store::open(&cfg).await.expect("open fjall")
}

/// In-memory `SecretStore`. Mirrors the real backends' whole-blob `set`
/// semantics, which is what the retired-key handling has to survive.
struct MockSecretStore(StdMutex<Option<ServerSecrets>>);

impl MockSecretStore {
    fn new(secrets: ServerSecrets) -> Self {
        Self(StdMutex::new(Some(secrets)))
    }
    fn snapshot(&self) -> ServerSecrets {
        self.0.lock().unwrap().clone().expect("secrets present")
    }
}

impl SecretStore for MockSecretStore {
    fn get(
        &self,
    ) -> super::super::secret_store::BoxFuture<'_, Result<Option<ServerSecrets>, AppError>> {
        let v = self.0.lock().unwrap().clone();
        Box::pin(async move { Ok(v) })
    }
    fn set(
        &self,
        secrets: &ServerSecrets,
    ) -> super::super::secret_store::BoxFuture<'_, Result<(), AppError>> {
        *self.0.lock().unwrap() = Some(secrets.clone());
        Box::pin(async move { Ok(()) })
    }
    fn get_bootstrap_seed(
        &self,
    ) -> super::super::secret_store::BoxFuture<'_, Result<Option<[u8; 32]>, AppError>> {
        Box::pin(async move { Ok(None) })
    }
    fn set_bootstrap_seed(
        &self,
        _seed: &[u8; 32],
    ) -> super::super::secret_store::BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move { Ok(()) })
    }
    fn clear_bootstrap_seed(
        &self,
    ) -> super::super::secret_store::BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move { Ok(()) })
    }
}

/// A generation plus a freshly generated key pair for it.
fn keyed_generation(id: u64, tag: &str) -> (IdentityGeneration, Secret, Secret) {
    let signing_kid = format!("{DID}#z6Mk{tag}");
    let ka_kid = format!("{DID}#z6LS{tag}");
    let signing = Secret::generate_ed25519(Some(&signing_kid), None);
    let ka = Secret::generate_x25519(Some(&ka_kid), None).expect("x25519");

    let mut g = generation(id, &ka_kid);
    g.signing_kid = signing_kid;
    (g, signing, ka)
}

/// Build a `ServiceIdentity` directly, bypassing `load_identity` (which
/// would need a resolvable DID).
async fn identity_with(
    generations: Vec<IdentityGeneration>,
    secrets: Vec<Secret>,
) -> Arc<ServiceIdentity> {
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .expect("local DID cache");
    let (secrets_resolver, _handle) = ThreadedSecretsResolver::new(None).await;
    for s in &secrets {
        secrets_resolver.insert(s.clone()).await;
    }
    Arc::new(ServiceIdentity {
        did: DID.to_string(),
        did_resolver,
        secrets_resolver: Arc::new(secrets_resolver),
        scid_floors: None,
        live: RwLock::new(LiveSet {
            generations,
            secrets,
        }),
        rotation: tokio::sync::Mutex::new(()),
    })
}

fn server_secrets(signing: &Secret, ka: &Secret, retired: Vec<RetiredKeys>) -> ServerSecrets {
    ServerSecrets {
        signing_key: signing.get_private_keymultibase().unwrap(),
        key_agreement_key: ka.get_private_keymultibase().unwrap(),
        jwt_signing_key: Secret::generate_ed25519(None, None)
            .get_private_keymultibase()
            .unwrap(),
        vta_credential: None,
        retired,
    }
}

fn generation(id: u64, ka_kid: &str) -> IdentityGeneration {
    IdentityGeneration {
        id,
        did: "did:webvh:example:alpha".into(),
        signing_kid: "did:webvh:example:alpha#key-0".into(),
        ka_kid: ka_kid.into(),
        ka_public_multibase: None,
        mediator_did: Some("did:web:mediator.example".into()),
        protocols: ProtocolSet {
            didcomm: true,
            tsp: false,
        },
        created_at: 100,
        retired_at: None,
        expires_at: None,
    }
}

#[test]
fn protocol_union_carries_a_retiring_transport() {
    // The case that motivated this: the service restarts TSP-only while a
    // DIDComm generation is still retiring. The listener must carry both.
    let current = ProtocolSet {
        didcomm: false,
        tsp: true,
    };
    let retiring = ProtocolSet {
        didcomm: true,
        tsp: false,
    };
    let union = current.union(retiring);
    assert!(
        union.didcomm,
        "retiring generation's DIDComm must be carried"
    );
    assert!(union.tsp, "current generation's TSP must be carried");
}

#[test]
fn identical_facts_do_not_read_as_a_rotation() {
    // The publish hook fires on every publish of our own DID. If a
    // no-op publish looked like a rotation we would churn generations.
    let a = generation(0, "did:webvh:example:alpha#z6LSold");
    let mut b = generation(7, "did:webvh:example:alpha#z6LSold");
    b.created_at = 999;
    b.retired_at = Some(1000);
    assert!(!a.differs_from(&b), "id and timestamps are not identity");
}

#[test]
fn new_key_material_under_the_same_kid_is_not_reported_as_unchanged() {
    // The silent-breakage case. Our own `build_did_document` uses fixed
    // `#key-0`/`#key-1` fragments, so a key rotation that reuses them changes
    // no kid at all. A diff on kids alone reports "unchanged" — and the
    // service keeps using the OLD private key while the document advertises
    // the NEW public one. Every peer with a fresh document is locked out, and
    // the log says everything is fine.
    let mut old = generation(0, "did:webvh:example:alpha#key-1");
    old.ka_public_multibase = Some("z6LSoldkey".into());

    let mut new = old.clone();
    new.ka_public_multibase = Some("z6LSnewkey".into());

    assert!(
        old.differs_from(&new),
        "new key material must register as a change even when the kid is identical"
    );
    assert!(old.is_same_kid_rotation(&new));
}

#[test]
fn a_same_kid_rotation_cannot_overlap_but_a_fresh_fragment_can() {
    // Why our tooling must emit a NEW fragment. The secrets resolver is keyed
    // by kid and inbound JWEs name their recipient by kid, so two keys cannot
    // both answer to `#key-1`. Rotating onto a fresh fragment is what makes a
    // grace window expressible at all.
    let mut old = generation(0, "did:webvh:example:alpha#key-1");
    old.ka_public_multibase = Some("z6LSoldkey".into());

    let mut same_kid = old.clone();
    same_kid.ka_public_multibase = Some("z6LSnewkey".into());
    assert!(
        same_kid.is_same_kid_rotation(&old),
        "same fragment + new key = no overlap possible"
    );

    let mut fresh_kid = generation(1, "did:webvh:example:alpha#z6LSnewkey");
    fresh_kid.ka_public_multibase = Some("z6LSnewkey".into());
    assert!(old.differs_from(&fresh_kid));
    assert!(
        !old.is_same_kid_rotation(&fresh_kid),
        "a fresh fragment can hold both keys at once — this is the overlapping path"
    );
}

#[test]
fn unknown_key_material_never_trips_the_diff() {
    // Generations persisted before the public key was recorded deserialise
    // with `None`, and a document may not expose `publicKeyMultibase` at all.
    // Unknown must read as "unknown", not "changed" — otherwise every such
    // deployment would spuriously rotate on its first reload after upgrading.
    let old = generation(0, "did:webvh:example:alpha#key-1"); // ka_public_multibase: None
    let mut new = old.clone();
    new.ka_public_multibase = Some("z6LSsomething".into());

    assert!(!old.key_material_differs_from(&new));
    assert!(
        !old.differs_from(&new),
        "unknown must not look like a rotation"
    );
}

#[test]
fn a_changed_key_agreement_kid_reads_as_a_rotation() {
    let a = generation(0, "did:webvh:example:alpha#z6LSold");
    let b = generation(0, "did:webvh:example:alpha#z6LSnew");
    assert!(a.differs_from(&b));
}

#[test]
fn a_changed_mediator_reads_as_a_rotation() {
    let a = generation(0, "did:webvh:example:alpha#z6LSold");
    let mut b = a.clone();
    b.mediator_did = Some("did:web:mediator2.example".into());
    assert!(a.differs_from(&b));
}

#[test]
fn liveness_follows_the_expiry() {
    let mut record = generation(0, "did:webvh:example:alpha#z6LSold");
    assert!(record.is_live(u64::MAX), "current generation never expires");

    record.expires_at = Some(500);
    assert!(record.is_live(499));
    assert!(!record.is_live(500), "expiry is exclusive");
    assert!(!record.is_live(501));
}

#[test]
fn the_mnemonic_gate_identifies_our_own_did() {
    // This gates the whole rotation trigger. Get it wrong and either every
    // publish re-resolves our document, or — worse — a publish of our own
    // DID never rotates and the service silently keeps the stale key.
    assert_eq!(
        mnemonic_from_did("did:webvh:QmSCID:example.com:alice").as_deref(),
        Some("alice")
    );

    // Nested paths come back slash-joined, matching the stored mnemonic.
    assert_eq!(
        mnemonic_from_did("did:webvh:QmSCID:example.com:team:alice").as_deref(),
        Some("team/alice")
    );

    // A `%3A`-encoded port is part of the host, not a path separator.
    assert_eq!(
        mnemonic_from_did("did:webvh:QmSCID:localhost%3A8080:alice").as_deref(),
        Some("alice")
    );

    // THE ROOT DID — the canonical shape for a service that owns its domain,
    // and the one this gate has to get right. `.well-known` is where the
    // document is *stored*, not part of the identifier. Returning `None` here
    // would make the gate reject every publish, and rotation would silently
    // never fire on the most common deployment there is.
    assert_eq!(
        mnemonic_from_did("did:webvh:QmSCID:did.example.com").as_deref(),
        Some(".well-known")
    );
    assert_eq!(
        mnemonic_from_did("did:webvh:QmSCID:localhost%3A8080").as_deref(),
        Some(".well-known"),
        "a root DID with a percent-encoded port is still a root DID"
    );

    // Other methods are not ours.
    assert_eq!(mnemonic_from_did("did:web:example.com:alice"), None);
    assert_eq!(mnemonic_from_did("did:key:z6Mk"), None);
    assert_eq!(mnemonic_from_did("did:webvh:QmSCID"), None, "no host");
}

#[test]
fn the_root_did_round_trips_between_identifier_and_storage_slot() {
    // `build_did_document` and `mnemonic_from_did` are inverses, and the root
    // DID is where they used to disagree: setup stored the document under
    // `.well-known` *and* baked `.well-known` into the identifier, producing
    // a DID no conforming resolver could round-trip.
    use crate::did::{DidDocumentOptions, build_did_document};

    let doc = build_did_document(
        "did.example.com",
        ".well-known",
        "z6MkPubKey",
        &DidDocumentOptions::default(),
    );
    let id = doc["id"].as_str().expect("id");

    assert_eq!(
        id, "did:webvh:{SCID}:did.example.com",
        "`.well-known` is a storage slot, not part of the identifier"
    );

    // ...and back again, to the slot the document is served from.
    let concrete = id.replace("{SCID}", "QmSCID");
    assert_eq!(mnemonic_from_did(&concrete).as_deref(), Some(".well-known"));
}

#[test]
fn generation_keys_sort_in_id_order() {
    // Raw prefix iteration is lexicographic, so the zero-padding is what
    // keeps generation 10 from sorting before generation 9.
    let mut keys = [gen_key(10), gen_key(9), gen_key(100)];
    keys.sort();
    assert_eq!(keys, [gen_key(9), gen_key(10), gen_key(100)]);
}

#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn a_saved_generation_survives_a_restart() {
    // The reason any of this is persisted. `config.toml` describes only the
    // current identity, so a generation's resolved kids have to come back
    // from the store or they are gone.
    let store = fjall_store().await;
    let ks = store.keyspace(KS_IDENTITY).expect("identity keyspace");

    let original = generation(0, "did:webvh:example:alpha#z6LSresolved");
    save_current_generation(&store, &ks, &original)
        .await
        .expect("save");

    // Re-open the keyspace: stands in for a fresh boot reading the store.
    let ks = store.keyspace(KS_IDENTITY).expect("identity keyspace");
    let loaded = load_generations(&ks, 1_000).await.expect("load");

    assert_eq!(loaded, vec![original]);
}

#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn a_retired_generation_stays_live_until_it_expires() {
    // The overlap window itself: a retired generation must keep coming back
    // from the store — and stay in the profile — right up to its expiry,
    // then vanish.
    let store = fjall_store().await;
    let ks = store.keyspace(KS_IDENTITY).expect("identity keyspace");

    let current = generation(1, "did:webvh:example:alpha#z6LSnew");
    let mut retired = generation(0, "did:webvh:example:alpha#z6LSold");
    retired.retired_at = Some(500);
    retired.expires_at = Some(1_000);

    save_current_generation(&store, &ks, &current)
        .await
        .expect("save current");
    ks.insert(gen_key(retired.id), &retired)
        .await
        .expect("save retired");

    // Mid-window: both live, current first.
    let live = load_generations(&ks, 999).await.expect("load");
    assert_eq!(live.len(), 2, "retired generation must still be honoured");
    assert_eq!(live[0].id, 1, "current generation sorts first");
    assert_eq!(live[1].id, 0);

    // Past the window: the retired generation drops out and its key
    // material stops being loaded into the profile.
    let live = load_generations(&ks, 1_000).await.expect("load");
    assert_eq!(live, vec![current], "expired generation must be dropped");
}

// -----------------------------------------------------------------------
// Retirement, expiry, and the kill switch
// -----------------------------------------------------------------------

#[tokio::test]
async fn a_retired_generation_reads_its_key_material_from_the_retired_set() {
    // The restart path. After a rotation, `ServerSecrets.signing_key` /
    // `.key_agreement_key` hold the *new* keys — the outgoing generation's
    // only surviving copy is in `retired`, matched by ka_kid.
    let (new_gen, new_signing, new_ka) = keyed_generation(1, "new");
    let (mut old_gen, old_signing, old_ka) = keyed_generation(0, "old");
    old_gen.retired_at = Some(500);
    old_gen.expires_at = Some(4_100);

    let secrets = server_secrets(
        &new_signing,
        &new_ka,
        vec![RetiredKeys {
            ka_kid: old_gen.ka_kid.clone(),
            key_agreement_key: old_ka.get_private_keymultibase().unwrap(),
            signing_kid: old_gen.signing_kid.clone(),
            signing_key: old_signing.get_private_keymultibase().unwrap(),
        }],
    );

    let current = secrets_for(&new_gen, &secrets);
    assert_eq!(current.len(), 2);
    assert!(current.iter().any(|s| s.id == new_gen.ka_kid));

    let retired = secrets_for(&old_gen, &secrets);
    assert_eq!(retired.len(), 2, "retired generation's keys must come back");
    let ka = retired
        .iter()
        .find(|s| s.id == old_gen.ka_kid)
        .expect("old ka secret");
    assert_eq!(
        ka.get_private_keymultibase().unwrap(),
        old_ka.get_private_keymultibase().unwrap(),
        "must be the *old* private key, not the new one"
    );
}

#[tokio::test]
async fn a_retired_generation_with_no_stored_key_yields_nothing() {
    // Its window cannot be honoured — better to carry no secret than to
    // tag the *new* private key with the old kid, which would decrypt
    // nothing and hide the problem.
    let (_new_gen, new_signing, new_ka) = keyed_generation(1, "new");
    let (mut old_gen, _, _) = keyed_generation(0, "old");
    old_gen.retired_at = Some(500);
    old_gen.expires_at = Some(4_100);

    let secrets = server_secrets(&new_signing, &new_ka, Vec::new());
    assert!(secrets_for(&old_gen, &secrets).is_empty());
}

#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn the_sweep_reaps_an_expired_generation_and_stops_honouring_its_key() {
    let store = fjall_store().await;
    let ks = store.keyspace(KS_IDENTITY).expect("identity keyspace");

    let (new_gen, new_signing, new_ka) = keyed_generation(1, "new");
    let (mut old_gen, old_signing, old_ka) = keyed_generation(0, "old");
    old_gen.retired_at = Some(1);
    old_gen.expires_at = Some(2); // long past

    let retired_entry = RetiredKeys {
        ka_kid: old_gen.ka_kid.clone(),
        key_agreement_key: old_ka.get_private_keymultibase().unwrap(),
        signing_kid: old_gen.signing_kid.clone(),
        signing_key: old_signing.get_private_keymultibase().unwrap(),
    };
    let secret_store =
        MockSecretStore::new(server_secrets(&new_signing, &new_ka, vec![retired_entry]));

    save_current_generation(&store, &ks, &new_gen)
        .await
        .expect("save current");
    ks.insert(gen_key(old_gen.id), &old_gen)
        .await
        .expect("save retired");

    let identity = identity_with(
        vec![new_gen.clone(), old_gen.clone()],
        vec![
            new_signing.clone(),
            new_ka.clone(),
            old_signing.clone(),
            old_ka.clone(),
        ],
    )
    .await;

    // Precondition: the old key is honoured right now.
    assert!(
        identity
            .secrets_resolver
            .get_secret(&old_gen.ka_kid)
            .await
            .is_some()
    );

    let reaped = run_sweep_once(&identity, &store, &secret_store).await;
    assert_eq!(reaped, 1);

    // The old key stops decrypting...
    assert!(
        identity
            .secrets_resolver
            .get_secret(&old_gen.ka_kid)
            .await
            .is_none(),
        "expired key must no longer be honoured"
    );
    // ...the current one still does.
    assert!(
        identity
            .secrets_resolver
            .get_secret(&new_gen.ka_kid)
            .await
            .is_some()
    );

    // And it is gone from both stores, so a restart does not resurrect it.
    assert_eq!(identity.generations(), vec![new_gen]);
    assert!(secret_store.snapshot().retired.is_empty());
    assert!(
        load_generations(&ks, now_epoch())
            .await
            .unwrap()
            .iter()
            .all(|g| g.id != old_gen.id)
    );
}

#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn establishing_generation_zero_re_keys_the_placeholder() {
    // A service that hosts its own DID cannot resolve it at boot — it *is*
    // the thing that serves it — so `load_identity` comes up on guessed
    // `#key-0`/`#key-1` kids. Once HTTP is serving, the first real resolve
    // replaces that placeholder.
    //
    // Found by running a daemon: the placeholder's secrets must be dropped
    // from the resolver, not merely added alongside. A document whose kids
    // are *not* `#key-0`/`#key-1` would otherwise leave a fabricated kid
    // resolving to a real key, while the real kid also resolved — the sort of
    // thing that works right up until it doesn't.
    let store = fjall_store().await;
    let ks = store.keyspace(KS_IDENTITY).expect("identity keyspace");

    let (real, signing, ka) = keyed_generation(0, "real");
    let secret_store = MockSecretStore::new(server_secrets(&signing, &ka, Vec::new()));

    // The boot-time placeholder: right key material, guessed kids.
    let placeholder = IdentityGeneration {
        signing_kid: format!("{DID}#key-0"),
        ka_kid: format!("{DID}#key-1"),
        ..real.clone()
    };
    let placeholder_secrets = vec![
        Secret::from_multibase(
            &signing.get_private_keymultibase().unwrap(),
            Some(&placeholder.signing_kid),
        )
        .unwrap(),
        Secret::from_multibase(
            &ka.get_private_keymultibase().unwrap(),
            Some(&placeholder.ka_kid),
        )
        .unwrap(),
    ];
    let identity = identity_with(vec![placeholder.clone()], placeholder_secrets).await;

    establish_generation(&identity, &store, &ks, &real, &secret_store)
        .await
        .expect("establish");

    // The document's real kids now resolve...
    assert!(
        identity
            .secrets_resolver
            .get_secret(&real.ka_kid)
            .await
            .is_some(),
        "the document's key-agreement kid must resolve after establishing"
    );
    // ...and the guessed ones no longer do.
    assert!(
        identity
            .secrets_resolver
            .get_secret(&placeholder.ka_kid)
            .await
            .is_none(),
        "the guessed placeholder kid must be dropped, not left alongside"
    );

    // Generation 0 — established, not rotated: same id, nothing retired.
    let live = identity.generations();
    assert_eq!(live.len(), 1, "establishing must not retire anything");
    assert_eq!(live[0].id, 0);
    assert!(live[0].retired_at.is_none());
    assert_eq!(live[0].ka_kid, real.ka_kid);

    // And it is persisted, so the next boot skips the placeholder entirely.
    assert_eq!(
        load_generations(&ks, now_epoch()).await.unwrap(),
        vec![real]
    );
}

#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn the_sweep_drops_a_generation_deleted_out_of_band() {
    // What makes the *offline* kill switch actually work. The CLI runs in a
    // separate process, deletes the generation record and its key material
    // from disk, and cannot reach into this process's secrets resolver. If
    // the sweep only checked expiry timestamps, the running service would
    // keep decrypting with the copy in memory — the exact opposite of what
    // someone reaching for a kill switch wants. So the store is authoritative
    // about *which* generations are live, and the sweep reconciles.
    let store = fjall_store().await;
    let ks = store.keyspace(KS_IDENTITY).expect("identity keyspace");

    let (new_gen, new_signing, new_ka) = keyed_generation(1, "new");
    let (mut old_gen, old_signing, old_ka) = keyed_generation(0, "old");
    // Deliberately still well inside its grace window.
    old_gen.retired_at = Some(now_epoch());
    old_gen.expires_at = Some(now_epoch() + 3_600);

    let secret_store = MockSecretStore::new(server_secrets(&new_signing, &new_ka, Vec::new()));

    // Only the current generation is persisted — the retired one's record is
    // absent, as it would be after an offline `identity-retire-now`.
    save_current_generation(&store, &ks, &new_gen)
        .await
        .expect("save current");

    let identity = identity_with(
        vec![new_gen.clone(), old_gen.clone()],
        vec![new_signing, new_ka, old_signing, old_ka],
    )
    .await;

    assert_eq!(run_sweep_once(&identity, &store, &secret_store).await, 1);
    assert!(
        identity
            .secrets_resolver
            .get_secret(&old_gen.ka_kid)
            .await
            .is_none(),
        "a generation the store no longer vouches for must stop decrypting"
    );
    assert_eq!(identity.generations(), vec![new_gen]);
}

#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn the_sweep_never_drops_the_current_generation() {
    // The reconciliation above must not be able to disarm the service. A
    // transient read miss on the current generation's record would otherwise
    // drop the key it is actively using and leave it unable to decrypt
    // anything at all.
    let store = fjall_store().await;
    let (current, signing, ka) = keyed_generation(1, "cur");
    let secret_store = MockSecretStore::new(server_secrets(&signing, &ka, Vec::new()));

    // Nothing at all persisted — the harshest version of a read miss.
    let identity = identity_with(vec![current.clone()], vec![signing, ka]).await;

    assert_eq!(run_sweep_once(&identity, &store, &secret_store).await, 0);
    assert!(
        identity
            .secrets_resolver
            .get_secret(&current.ka_kid)
            .await
            .is_some(),
        "the current generation must survive an empty store"
    );
}

#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn the_sweep_leaves_a_generation_inside_its_window() {
    let store = fjall_store().await;
    let ks = store.keyspace(KS_IDENTITY).expect("identity keyspace");

    let (new_gen, new_signing, new_ka) = keyed_generation(1, "new");
    let (mut old_gen, old_signing, old_ka) = keyed_generation(0, "old");
    old_gen.retired_at = Some(now_epoch());
    old_gen.expires_at = Some(now_epoch() + 3_600); // an hour to run

    let secret_store = MockSecretStore::new(server_secrets(&new_signing, &new_ka, Vec::new()));

    // Both records persisted — the state a real rotation leaves behind. The
    // sweep reconciles against the store, so a retired generation that is
    // genuinely still live has to be *in* it.
    save_current_generation(&store, &ks, &new_gen)
        .await
        .expect("save current");
    ks.insert(gen_key(old_gen.id), &old_gen)
        .await
        .expect("save retired");

    let identity = identity_with(
        vec![new_gen, old_gen.clone()],
        vec![new_signing, new_ka, old_signing, old_ka],
    )
    .await;

    assert_eq!(run_sweep_once(&identity, &store, &secret_store).await, 0);
    assert!(
        identity
            .secrets_resolver
            .get_secret(&old_gen.ka_kid)
            .await
            .is_some(),
        "a generation inside its window must keep decrypting"
    );
}

#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn retire_now_drops_the_key_immediately() {
    // The compromise response: stop honouring the old key at once, and
    // accept that anything still addressed to it fails.
    let store = fjall_store().await;
    let ks = store.keyspace(KS_IDENTITY).expect("identity keyspace");

    let (new_gen, new_signing, new_ka) = keyed_generation(1, "new");
    let (mut old_gen, old_signing, old_ka) = keyed_generation(0, "old");
    old_gen.retired_at = Some(now_epoch());
    old_gen.expires_at = Some(now_epoch() + 3_600);

    let secret_store = MockSecretStore::new(server_secrets(
        &new_signing,
        &new_ka,
        vec![RetiredKeys {
            ka_kid: old_gen.ka_kid.clone(),
            key_agreement_key: old_ka.get_private_keymultibase().unwrap(),
            signing_kid: old_gen.signing_kid.clone(),
            signing_key: old_signing.get_private_keymultibase().unwrap(),
        }],
    ));
    ks.insert(gen_key(old_gen.id), &old_gen).await.unwrap();

    let identity = identity_with(
        vec![new_gen, old_gen.clone()],
        vec![new_signing, new_ka, old_signing, old_ka],
    )
    .await;

    retire_generation_now(&identity, &store, &secret_store, old_gen.id)
        .await
        .expect("retire now");

    assert!(
        identity
            .secrets_resolver
            .get_secret(&old_gen.ka_kid)
            .await
            .is_none(),
        "the compromised key must stop decrypting immediately"
    );
    assert!(secret_store.snapshot().retired.is_empty());
}

#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn retire_now_refuses_to_expire_the_current_generation() {
    // Expiring the current generation would drop the key the service is
    // actively using — it would stop being able to decrypt anything at all.
    let store = fjall_store().await;
    let (current, signing, ka) = keyed_generation(1, "cur");
    let secret_store = MockSecretStore::new(server_secrets(&signing, &ka, Vec::new()));
    let identity = identity_with(vec![current.clone()], vec![signing, ka.clone()]).await;

    let err = retire_generation_now(&identity, &store, &secret_store, current.id)
        .await
        .expect_err("must refuse");
    assert!(
        format!("{err}").contains("current generation"),
        "unexpected error: {err}"
    );
    assert!(
        identity
            .secrets_resolver
            .get_secret(&current.ka_kid)
            .await
            .is_some(),
        "the current key must still be honoured after a refused retire"
    );
}

#[tokio::test]
async fn the_half_rotation_guard_rejects_a_key_the_document_does_not_advertise() {
    // The ordering mistake: the DID was published before the new key was
    // written to the secret store. `Secret::from_multibase(key, Some(kid))`
    // happily tags *any* private key with the new kid, so without comparing
    // derived public keys this guard would be vacuous and we would install a
    // generation that cannot decrypt its own inbound traffic.
    let advertised = Secret::generate_x25519(Some("did:x#ka"), None).expect("x25519");
    let unrelated = Secret::generate_x25519(Some("did:x#ka"), None).expect("x25519");
    let advertised_pk = advertised.get_public_keymultibase().unwrap();

    assert!(secret_matches_document(&advertised, Some(&advertised_pk)));
    assert!(
        !secret_matches_document(&unrelated, Some(&advertised_pk)),
        "a key that is not the private half of the advertised one must be rejected"
    );

    // A document that does not expose publicKeyMultibase cannot disprove
    // the pairing — proceed rather than refuse on something unreadable.
    assert!(secret_matches_document(&unrelated, None));
}

/// The grace period is read from the parsed config; a typo never reaches
/// here (it is refused at load — see
/// `config::tests::rotation_grace_period_is_parsed_at_load`).
#[test]
fn the_grace_period_is_read_from_the_parsed_config() {
    use crate::server::config::{GracePeriod, IdentityConfig};

    let cfg = IdentityConfig::default();
    assert_eq!(cfg.rotation_grace_secs(), 3600, "default is 1h");

    let cfg = IdentityConfig {
        rotation_grace_period: GracePeriod::parse("30m").unwrap(),
        ..Default::default()
    };
    assert_eq!(cfg.rotation_grace_secs(), 1800);

    let cfg = IdentityConfig {
        rotation_grace_period: GracePeriod::parse("0").unwrap(),
        ..Default::default()
    };
    assert_eq!(cfg.rotation_grace_secs(), 0, "0 retires immediately");
}

#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn the_current_generation_sorts_first_even_when_it_is_not_the_newest() {
    // `current()` indexes generations[0], and the listener's mediator and
    // the outbound path both read from it. A recovery that makes an older
    // generation current again must not leave a newer one in that slot.
    let store = fjall_store().await;
    let ks = store.keyspace(KS_IDENTITY).expect("identity keyspace");

    let older = generation(3, "did:webvh:example:alpha#z6LSthree");
    let newer = generation(9, "did:webvh:example:alpha#z6LSnine");
    ks.insert(gen_key(newer.id), &newer).await.expect("save");

    save_current_generation(&store, &ks, &older)
        .await
        .expect("save current");

    let live = load_generations(&ks, 1_000).await.expect("load");
    assert_eq!(
        live[0].id, 3,
        "the *current* generation leads, not the newest"
    );
}

#[test]
fn kids_from_document_extracts_the_did_document_shape() {
    // The exact shape `build_did_document` emits: relationships are arrays
    // of bare kid strings, `publicKeyMultibase` a flat VM property.
    let did = "did:webvh:QmScid:host.example:node";
    let doc = serde_json::json!({
        "id": did,
        "verificationMethod": [
            { "id": format!("{did}#key-0"), "type": "Multikey", "publicKeyMultibase": "z6MkSign" },
            { "id": format!("{did}#key-1"), "type": "Multikey", "publicKeyMultibase": "z6LSAgree" },
        ],
        "authentication": [format!("{did}#key-0")],
        "assertionMethod": [format!("{did}#key-0")],
        "keyAgreement": [format!("{did}#key-1")],
    });

    let got = kids_from_document(did, &doc).expect("has relationships");
    assert_eq!(got.signing_kid, format!("{did}#key-0"));
    assert_eq!(got.ka_kid, format!("{did}#key-1"));
    assert_eq!(got.ka_public_multibase.as_deref(), Some("z6LSAgree"));
}

#[test]
fn kids_from_document_none_without_relationships() {
    // No auth/keyAgreement → None, so the caller falls back to the network.
    let doc = serde_json::json!({ "id": "did:webvh:Q:h:n", "service": [] });
    assert!(kids_from_document("did:webvh:Q:h:n", &doc).is_none());
}

#[test]
fn a_protocols_change_is_metadata_not_a_key_change() {
    // The signal the rotation fix branches on: a protocols change is a real
    // difference (a reload must act on it) but NOT a key change.
    let (mut a, _s, _k) = keyed_generation(1, "x");
    a.protocols = ProtocolSet {
        didcomm: true,
        tsp: false,
    };
    let mut b = a.clone();
    b.protocols = ProtocolSet {
        didcomm: true,
        tsp: true,
    };
    assert!(
        a.differs_from(&b),
        "a protocols change is a real difference"
    );
    assert_eq!(a.signing_kid, b.signing_kid);
    assert_eq!(a.ka_kid, b.ka_kid);
    assert!(
        !a.key_material_differs_from(&b),
        "no key material changed — so it must not retire/rotate"
    );
}

#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn metadata_update_keeps_retired_generation_and_its_key() {
    // The outage this prevents: a protocols/mediator change was treated as a
    // rotation, retiring a generation that shared the current `ka_kid`; when
    // its grace expired it deleted the key the service was still using. A
    // metadata update must leave the retired generation and every key intact.
    let store = fjall_store().await;
    let ks = store.keyspace(KS_IDENTITY).expect("identity keyspace");

    let (current, cur_signing, cur_ka) = keyed_generation(1, "cur");
    let (mut retired, ret_signing, ret_ka) = keyed_generation(0, "ret");
    retired.retired_at = Some(now_epoch());
    retired.expires_at = Some(now_epoch() + 3_600);

    let identity = identity_with(
        vec![current.clone(), retired.clone()],
        vec![cur_signing, cur_ka, ret_signing, ret_ka],
    )
    .await;
    save_current_generation(&store, &ks, &current)
        .await
        .expect("save current");

    // Enable TSP: same id, same kids and keys, only `protocols` change.
    let updated = IdentityGeneration {
        protocols: ProtocolSet {
            didcomm: true,
            tsp: true,
        },
        ..current.clone()
    };
    update_current_generation_in_place(&identity, &store, &ks, &updated)
        .await
        .expect("in-place update");

    let live = identity.generations();
    assert!(
        live.iter()
            .any(|g| g.id == retired.id && g.retired_at.is_some()),
        "the retired generation must survive — its premature retirement is the bug"
    );
    assert!(
        identity
            .secrets_resolver
            .get_secret(&retired.ka_kid)
            .await
            .is_some(),
        "the retired key must still decrypt"
    );
    let cur = live
        .iter()
        .find(|g| g.id == current.id)
        .expect("current present");
    assert!(cur.protocols.tsp, "protocols were updated");
    assert_eq!(
        cur.ka_kid, current.ka_kid,
        "the key-agreement kid is unchanged"
    );
    assert!(
        identity
            .secrets_resolver
            .get_secret(&current.ka_kid)
            .await
            .is_some(),
        "the current key is still usable"
    );
}

#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn the_sweep_never_strips_a_key_a_survivor_still_uses() {
    // Leftover damage from a pre-fix same-`ka_kid` rotation: a retired
    // generation shares the current generation's ka_kid. Expiring it would
    // delete the key the service is still using — the exact mechanism behind
    // the mediator-auth outage. The sweep must keep it and reap nothing.
    let store = fjall_store().await;
    let ks = store.keyspace(KS_IDENTITY).expect("identity keyspace");

    let (current, signing, ka) = keyed_generation(1, "shared");
    let mut retired = current.clone();
    retired.id = 0;
    retired.retired_at = Some(1);
    retired.expires_at = Some(2); // long past its grace window

    let secret_store = MockSecretStore::new(server_secrets(&signing, &ka, Vec::new()));
    save_current_generation(&store, &ks, &current)
        .await
        .expect("save current");
    ks.insert(gen_key(retired.id), &retired)
        .await
        .expect("save retired");

    let identity = identity_with(vec![current.clone(), retired.clone()], vec![signing, ka]).await;

    assert_eq!(
        run_sweep_once(&identity, &store, &secret_store).await,
        0,
        "must not expire a retired generation that shares the current key-agreement kid"
    );
    assert!(
        identity
            .secrets_resolver
            .get_secret(&current.ka_kid)
            .await
            .is_some(),
        "the key the current generation is using must survive the sweep"
    );
}
