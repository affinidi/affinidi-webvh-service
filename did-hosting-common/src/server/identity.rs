//! The service's own DID identity, and the generations of key material it
//! still honours.
//!
//! # Why generations
//!
//! When the service's own DID is updated — keys rotated, a service added or
//! removed — peers do not find out at once. A peer that resolved our DID five
//! minutes ago keeps encrypting to the *old* key-agreement key until its cache
//! expires. Cut over instantly and those messages become undecryptable.
//!
//! So an identity is not a single set of keys but a short list of
//! *generations*: the current one, plus any that have been retired but whose
//! grace period has not yet elapsed. Every live generation's key-agreement
//! secret stays loaded, so a message encrypted to any of them still decrypts.
//!
//! This works because **inbound decryption is kid-driven, not
//! document-driven**: the unpack path reads the `kid` off each JWE recipient
//! header and looks it up in the secrets resolver, never consulting our own DID
//! document (`affinidi-messaging-sdk`, `messages/unpack.rs`). Holding an old
//! secret is sufficient; keeping the old verification method *published* is not
//! required. Outbound needs no equivalent handling — it does not sign at all,
//! and its key-agreement key is chosen from our freshly-resolved document, so
//! it moves to the new key on its own.
//!
//! # Why this is persisted
//!
//! `config.toml` only ever describes the *current* identity. After a rotation
//! it holds the new keys and the new mediator; the retiring generation's kids,
//! mediator and expiry exist nowhere else. A restart mid-window would otherwise
//! come back unable to decrypt traffic still addressed to the old key. Hence
//! [`KS_IDENTITY`]: metadata lives in the store, and the private key material
//! stays in the secret store behind the keyring/KMS boundary.
//!
//! Phase 1 establishes the model and persists generation 0. Retirement, the
//! rotation trigger and the expiry sweep land on top of it.

use std::sync::{Arc, RwLock};

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::secrets_resolver::secrets::Secret;
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::auth::session::now_epoch;
use super::error::AppError;
use super::secret_store::{RetiredKeys, SecretStore, ServerSecrets};
use super::store::{KS_IDENTITY, KeyspaceHandle, Store};

/// Store key holding the current generation's id.
const KEY_CURRENT: &str = "identity:current";

/// Prefix for the per-generation records.
const GEN_PREFIX: &str = "identity:gen:";

/// Zero-padded so the raw prefix iteration comes back in id order.
fn gen_key(id: u64) -> String {
    format!("{GEN_PREFIX}{id:020}")
}

/// The inbound transports a listener carries.
///
/// Note the framework currently reads only `tsp` — `TSP_ONLY` still dispatches
/// inbound DIDComm if any shows up. We track both anyway rather than depend on
/// that, since it reads like an upstream oversight rather than a guarantee.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolSet {
    pub didcomm: bool,
    pub tsp: bool,
}

impl ProtocolSet {
    pub fn union(self, other: Self) -> Self {
        Self {
            didcomm: self.didcomm || other.didcomm,
            tsp: self.tsp || other.tsp,
        }
    }
}

/// One version of the service's own DID identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityGeneration {
    pub id: u64,
    pub did: String,

    /// Resolved from the document's first `authentication` entry.
    ///
    /// Inert for DIDComm — the outbound path does not sign (`sign_by` is
    /// accepted and ignored upstream). Tracked because the webvh log-entry
    /// signing path does use it, and because a rotation that changes it is
    /// still a rotation.
    pub signing_kid: String,

    /// Resolved from the document's first `keyAgreement` entry.
    ///
    /// The load-bearing one: this is the kid inbound JWEs are addressed to,
    /// and the reason a retired generation has to stay loaded.
    pub ka_kid: String,

    /// The `publicKeyMultibase` the document advertised for `ka_kid`.
    ///
    /// Tracked because **a kid alone does not identify a key.** A rotation that
    /// installs new key material under the *same* verification-method fragment
    /// (`#key-1` → `#key-1`) changes nothing about the kid, so a diff on kids
    /// alone reports "unchanged" while the service quietly keeps using the old
    /// private key against a document that now advertises a different public one.
    /// Every peer with a fresh document then fails to reach it, and the log says
    /// everything is fine.
    ///
    /// `Option` for backwards compatibility: generations persisted before this
    /// field existed deserialise with `None`, which reads as "unknown" and does
    /// not spuriously trip the diff.
    #[serde(default)]
    pub ka_public_multibase: Option<String>,

    /// The mediator this generation's listener connects to. Taken from
    /// config, not the document — the document advertises where *peers*
    /// should deliver, which must agree, but the two are set separately.
    pub mediator_did: Option<String>,

    pub protocols: ProtocolSet,
    pub created_at: u64,

    /// Set when the generation stops being current. `None` on the current one.
    #[serde(default)]
    pub retired_at: Option<u64>,

    /// When the grace period elapses and the key material is dropped. `None`
    /// on the current generation — it never expires while it is current.
    #[serde(default)]
    pub expires_at: Option<u64>,
}

impl IdentityGeneration {
    /// Whether this generation's key material must still be honoured.
    pub fn is_live(&self, now: u64) -> bool {
        self.expires_at.is_none_or(|expires| expires > now)
    }

    /// Whether the identity-defining facts differ — i.e. whether observing
    /// `other` means a rotation has happened.
    ///
    /// Deliberately ignores `id` and the timestamps: those are bookkeeping,
    /// not identity. Two generations that agree on all of these are the same
    /// identity and must not trigger a rotation, which is what makes the
    /// publish hook safe to fire on every publish.
    pub fn differs_from(&self, other: &Self) -> bool {
        self.did != other.did
            || self.signing_kid != other.signing_kid
            || self.ka_kid != other.ka_kid
            || self.mediator_did != other.mediator_did
            || self.protocols != other.protocols
            || self.key_material_differs_from(other)
    }

    /// Whether the *key material* behind `ka_kid` changed, as opposed to the kid.
    ///
    /// `None` on either side means "unknown" — a generation persisted before the
    /// public key was recorded, or a document that does not expose
    /// `publicKeyMultibase`. Unknown must not read as "changed", or every such
    /// deployment would rotate on its first reload.
    pub fn key_material_differs_from(&self, other: &Self) -> bool {
        match (&self.ka_public_multibase, &other.ka_public_multibase) {
            (Some(a), Some(b)) => a != b,
            _ => false,
        }
    }

    /// A rotation that reuses the verification-method fragment.
    ///
    /// **No grace window is possible in this case, in principle.** The secrets
    /// resolver is a map keyed by kid, and inbound JWEs name their recipient by
    /// kid — so two keys cannot both answer to `#key-1`. Whichever one we hold,
    /// half the peers fail: keep the old and anyone with a fresh document is
    /// locked out; take the new and anyone with a stale one is.
    ///
    /// The service takes the new key (the document is authoritative, and the
    /// stale half will heal as caches expire) and says loudly what it could not
    /// do. Rotating onto a *fresh* fragment is what makes the overlap work, and
    /// is what our own tooling emits.
    pub fn is_same_kid_rotation(&self, other: &Self) -> bool {
        self.ka_kid == other.ka_kid && self.key_material_differs_from(other)
    }
}

/// The live generations and the key material they answer to.
///
/// Split out from [`ServiceIdentity`] because this is the part a rotation
/// replaces; the resolvers around it survive untouched.
struct LiveSet {
    /// Current generation first, then any live retired ones.
    generations: Vec<IdentityGeneration>,

    /// Key material for every live generation, kid-tagged.
    ///
    /// This is what goes into the listener's `TDKProfile`. It matters that it
    /// is a durable vector rather than something injected into a shared
    /// resolver: on every reconnect the framework re-seeds its resolver from
    /// `ListenerConfig.profile.secrets()`, so anything not in here silently
    /// vanishes on the first reconnect.
    secrets: Vec<Secret>,
}

/// The service's own identity: every live generation, and the resolvers seeded
/// from them.
///
/// Not `Debug` — it holds private key material.
///
/// # Why the interior mutability is here, and not in `AppState`
///
/// A rotation has to change which generations are live. It does **not** have to
/// change the resolvers: `DIDCacheClient` is internally `Arc`'d and identical
/// across generations, and `ThreadedSecretsResolver` exposes `insert` and
/// `remove_secret` on `&self`, so the same instance can gain the new
/// generation's secrets and later drop an expired one's. Putting a lock around
/// just the live set therefore lets every `AppState` keep holding a plain
/// `Option<Arc<ServiceIdentity>>` — no `ArcSwap`, no lock in four state structs,
/// and no risk of a handler observing a half-swapped identity.
pub struct ServiceIdentity {
    pub did: String,
    pub did_resolver: DIDCacheClient,
    pub secrets_resolver: Arc<ThreadedSecretsResolver>,

    /// Guarded because a rotation replaces it wholesale. Reads are short and
    /// never held across an await.
    live: RwLock<LiveSet>,

    /// Serialises rotations against each other.
    ///
    /// The secret store has no compare-and-swap and `set()` overwrites the
    /// whole blob, so two concurrent rotations would clobber one another's
    /// retired key material. Also what makes the publish hook safe to fire on
    /// every publish: a burst coalesces behind this, and the second caller
    /// re-reads the DID document, finds nothing changed, and no-ops.
    rotation: tokio::sync::Mutex<()>,
}

impl ServiceIdentity {
    /// The generation currently advertised by the DID document.
    pub fn current(&self) -> IdentityGeneration {
        // `load_identity` never constructs an empty generation list.
        self.live.read().expect("identity lock").generations[0].clone()
    }

    /// Every live generation, current first.
    pub fn generations(&self) -> Vec<IdentityGeneration> {
        self.live.read().expect("identity lock").generations.clone()
    }

    /// Key material for every live generation — the listener profile's secrets.
    pub fn secrets(&self) -> Vec<Secret> {
        self.live.read().expect("identity lock").secrets.clone()
    }

    /// The union of every live generation's protocols.
    ///
    /// A generation retiring out of DIDComm while the current one is TSP-only
    /// still needs DIDComm carried until it expires.
    pub fn protocols(&self) -> ProtocolSet {
        self.live
            .read()
            .expect("identity lock")
            .generations
            .iter()
            .fold(ProtocolSet::default(), |acc, g| acc.union(g.protocols))
    }

    /// The mediator the live listener connects to.
    pub fn mediator_did(&self) -> Option<String> {
        self.current().mediator_did
    }

    /// Build a `ServiceIdentity` directly, for tests in sibling modules.
    ///
    /// `live` is private to this module, so `identity_drain`'s tests cannot
    /// assemble one themselves. Carries no key material — the drain predicates
    /// only read generations.
    #[cfg(test)]
    pub(crate) async fn for_test(did: &str, generations: Vec<IdentityGeneration>) -> Arc<Self> {
        let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("local DID cache");
        let (secrets_resolver, _handle) = ThreadedSecretsResolver::new(None).await;
        Arc::new(Self {
            did: did.to_string(),
            did_resolver,
            secrets_resolver: Arc::new(secrets_resolver),
            live: RwLock::new(LiveSet {
                generations,
                secrets: Vec::new(),
            }),
            rotation: tokio::sync::Mutex::new(()),
        })
    }
}

/// Extract the mnemonic (the slot the DID is *stored* under) from a `did:webvh`
/// DID string.
///
/// - `did:webvh:{SCID}:{host}:{path:components}` → `path/components`
/// - `did:webvh:{SCID}:{host}` → `.well-known`
///
/// The second case is the root DID, and it is not an edge case — it is the
/// canonical shape for a service that owns its domain. `.well-known` is where
/// its document is *stored* (and served from), but it is not part of the
/// identifier: did:webvh maps the pathless form to `/.well-known/did.jsonl`
/// implicitly. This is the inverse of [`crate::did::build_did_document`].
///
/// Used to answer "is the DID that was just published *our own*?" — the question
/// that gates the rotation trigger. Returning `None` for a root DID would make
/// that gate reject every publish, and rotation would silently never fire on the
/// most common deployment shape there is.
pub fn mnemonic_from_did(did: &str) -> Option<String> {
    let rest = did.strip_prefix("did:webvh:")?;
    // Skip the SCID. What's left is `{host}` or `{host}:{path…}` — the host
    // carries any port `%3A`-encoded, so it never contains a bare colon itself.
    let after_scid = rest.split_once(':')?.1;
    if after_scid.is_empty() {
        return None;
    }

    match after_scid.split_once(':') {
        Some((_host, path)) if !path.is_empty() => Some(path.replace(':', "/")),
        // Pathless (or a trailing colon): the root DID, stored at `.well-known`.
        _ => Some(".well-known".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Resolving our own document
// ---------------------------------------------------------------------------

/// What the DID document currently says about the service's own identity.
///
/// The public keys are carried alongside the kids because they are what makes
/// the half-rotation guard real: `Secret::from_multibase(key, Some(kid))` merely
/// *tags* a private key with a kid, it does not check that the key is the one
/// the document advertises under it. Without comparing derived public keys, a
/// rotation would happily install a generation whose "secret" cannot decrypt
/// anything addressed to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedIdentityDoc {
    pub signing_kid: String,
    pub ka_kid: String,
    /// `publicKeyMultibase` advertised for `ka_kid`, if the document exposes it.
    pub ka_public_multibase: Option<String>,
}

/// Resolve the service's own DID document.
///
/// The single authority on our own kids. Returns `None` when the document
/// cannot be resolved, or carries neither an `authentication` nor a
/// `keyAgreement` relationship — callers must then fall back to a stored
/// generation rather than guess, since a guess persisted as a generation would
/// cement the wrong kids into the store.
pub async fn resolve_identity_doc(
    did: &str,
    did_resolver: &DIDCacheClient,
) -> Option<ResolvedIdentityDoc> {
    let doc = match did_resolver.resolve(did).await {
        Ok(response) => response.doc,
        Err(e) => {
            warn!(did = did, "failed to resolve DID document: {e}");
            return None;
        }
    };

    if doc.authentication.is_empty() && doc.key_agreement.is_empty() {
        warn!(
            did = did,
            "DID document has no authentication or keyAgreement"
        );
        return None;
    }

    let signing_kid = doc
        .authentication
        .first()
        .map_or_else(|| format!("{did}#key-0"), |vr| vr.get_id().to_string());
    let ka_kid = doc
        .key_agreement
        .first()
        .map_or_else(|| format!("{did}#key-1"), |vr| vr.get_id().to_string());

    // `publicKeyMultibase` is a flattened extra property on the verification
    // method, not a typed field.
    let ka_public_multibase = doc
        .verification_method
        .iter()
        .find(|vm| vm.id.as_str() == ka_kid)
        .and_then(|vm| vm.property_set.get("publicKeyMultibase"))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    debug!(
        did = did,
        signing = %signing_kid,
        key_agreement = %ka_kid,
        "resolved own DID document"
    );

    Some(ResolvedIdentityDoc {
        signing_kid,
        ka_kid,
        ka_public_multibase,
    })
}

/// Turn one specific, unfixable-in-place misconfiguration into an actionable
/// message instead of a cryptic resolver error.
///
/// Builds before this was fixed minted the root DID as
/// `did:webvh:<scid>:<host>:.well-known` — with the *storage slot* baked into
/// the identifier. No conforming resolver can round-trip that: it maps the
/// pathless form to `/.well-known/did.jsonl` implicitly, so on the way back it
/// strips the suffix and rejects the document because the `id` inside no longer
/// matches. The document serves fine (HTTP 200); the identifier is what fails.
///
/// It cannot be corrected in place — the SCID is derived from the document, so
/// changing the id means a new DID. Say that plainly rather than let the operator
/// chase a resolution error that looks like a network problem.
fn warn_if_well_known_in_identifier(did: &str) {
    if !did.ends_with(":.well-known") {
        return;
    }
    warn!(
        did = did,
        "this DID carries `.well-known` inside its identifier, which no conforming \
         did:webvh resolver can round-trip — `.well-known` is where the document is \
         *stored*, not part of the DID. A root DID should be `did:webvh:<scid>:<host>`. \
         This was minted by a build predating the fix and cannot be corrected in place \
         (the SCID is bound to the document): the DID must be recreated. Identity \
         rotation cannot function until then."
    );
}

/// Whether `secret` is the private half of the key the document advertises.
///
/// Returns `true` when the document does not expose a `publicKeyMultibase` for
/// the kid — we cannot disprove the pairing, and refusing to rotate on a
/// document we simply cannot introspect would be worse than proceeding. The
/// check exists to catch the *ordering* mistake (publish before writing the
/// key), which does produce a document we can read and a key that plainly does
/// not match.
fn secret_matches_document(secret: &Secret, advertised: Option<&str>) -> bool {
    let Some(advertised) = advertised else {
        return true;
    };
    match secret.get_public_keymultibase() {
        Ok(derived) => derived == advertised,
        Err(e) => {
            warn!("could not derive public key from secret: {e}");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// Read every persisted generation, current first, dropping any whose grace
/// period has elapsed.
///
/// Expired records are left on disk for the sweep to reap — this is a read
/// path, and a boot that crashes between here and the sweep must not silently
/// lose the record.
pub async fn load_generations(
    identity_ks: &KeyspaceHandle,
    now: u64,
) -> Result<Vec<IdentityGeneration>, AppError> {
    let current_id: Option<u64> = identity_ks.get(KEY_CURRENT.as_bytes().to_vec()).await?;

    let mut generations: Vec<IdentityGeneration> = Vec::new();
    for (_key, value) in identity_ks.prefix_iter_raw(GEN_PREFIX.as_bytes()).await? {
        match serde_json::from_slice::<IdentityGeneration>(&value) {
            Ok(record) if record.is_live(now) => generations.push(record),
            Ok(record) => debug!(id = record.id, "identity generation expired — skipping"),
            Err(e) => warn!("skipping unreadable identity generation record: {e}"),
        }
    }

    // Current first; the rest newest-first behind it.
    generations.sort_by_key(|g| std::cmp::Reverse(g.id));
    if let Some(id) = current_id
        && let Some(pos) = generations.iter().position(|g| g.id == id)
    {
        generations.swap(0, pos);
    }

    Ok(generations)
}

/// Persist a generation and mark it current.
pub async fn save_current_generation(
    store: &Store,
    identity_ks: &KeyspaceHandle,
    generation: &IdentityGeneration,
) -> Result<(), AppError> {
    let mut batch = store.batch();
    batch.insert(identity_ks, gen_key(generation.id), generation)?;
    batch.insert(identity_ks, KEY_CURRENT.as_bytes().to_vec(), &generation.id)?;
    batch.commit().await
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Build the `Secret`s for a generation.
///
/// The kids come from the generation record, which is the whole point: the
/// secrets resolver and the listener profile must agree on which kid each key
/// answers to, and the DID document is the only authority on that.
///
/// The *current* generation's key material lives in `ServerSecrets` proper; a
/// retired generation's lives in `ServerSecrets::retired`, matched by
/// `ka_kid`. A retired generation whose key material is absent yields nothing:
/// its window cannot be honoured, and the caller warns rather than silently
/// carrying a generation that cannot decrypt anything.
fn secrets_for(generation: &IdentityGeneration, secrets: &ServerSecrets) -> Vec<Secret> {
    let (signing_key, ka_key) = if generation.retired_at.is_some() {
        match secrets
            .retired
            .iter()
            .find(|r| r.ka_kid == generation.ka_kid)
        {
            Some(retired) => (&retired.signing_key, &retired.key_agreement_key),
            None => {
                warn!(
                    id = generation.id,
                    ka_kid = %generation.ka_kid,
                    "retired generation has no key material in the secret store — \
                     messages still addressed to it cannot be decrypted"
                );
                return Vec::new();
            }
        }
    } else {
        (&secrets.signing_key, &secrets.key_agreement_key)
    };

    let mut out = Vec::new();
    match Secret::from_multibase(signing_key, Some(&generation.signing_kid)) {
        Ok(secret) => out.push(secret),
        Err(e) => warn!("failed to decode signing_key: {e}"),
    }
    match Secret::from_multibase(ka_key, Some(&generation.ka_kid)) {
        Ok(secret) => out.push(secret),
        Err(e) => warn!("failed to decode key_agreement_key: {e}"),
    }

    out
}

/// Load the service's own identity: resolve its DID, reconcile against the
/// persisted generations, and seed the resolvers.
///
/// Replaces `init::init_didcomm_auth`, which seeded the secrets resolver under
/// hardcoded `#key-0` / `#key-1` kids while the listener keyed its profile on
/// the *resolved* verification-method ids. Those agree only for a DID whose
/// document happens to use those fragments; for any other, the REST DIDComm
/// auth path and the listener disagreed. Here there is one source of truth for
/// kids — the document — and both are seeded from it.
///
/// Returns `None` when the service has no DID configured, or when the DID
/// resolver cannot be constructed. Both leave DIDComm disabled, as before.
pub async fn load_identity(
    server_did: Option<&str>,
    mediator_did: Option<&str>,
    protocols: ProtocolSet,
    secrets: &ServerSecrets,
    store: &Store,
) -> Option<Arc<ServiceIdentity>> {
    let did = match server_did {
        Some(did) => did,
        None => {
            warn!("server_did not configured — DIDComm auth endpoints will not work");
            return None;
        }
    };

    let did_resolver = match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
        Ok(resolver) => resolver,
        Err(e) => {
            warn!("failed to create DID resolver: {e} — DIDComm auth endpoints will not work");
            return None;
        }
    };

    let identity_ks = match store.keyspace(KS_IDENTITY) {
        Ok(ks) => ks,
        Err(e) => {
            warn!("failed to open identity keyspace: {e} — DIDComm auth endpoints will not work");
            return None;
        }
    };

    let now = now_epoch();
    let stored = load_generations(&identity_ks, now)
        .await
        .unwrap_or_else(|e| {
            warn!("failed to read identity generations: {e} — treating as empty");
            Vec::new()
        });

    let current = resolve_current_generation(
        did,
        mediator_did,
        protocols,
        &did_resolver,
        stored.first(),
        now,
    )
    .await;

    // Persist only what we actually resolved. `resolve_current_generation`
    // returns `None` when the document is unreachable *and* we have nothing
    // stored to fall back on — a first boot, before the DID is published. In
    // that case fall back to the legacy fragments to get the listener up, but
    // do not write them: a guess persisted as a generation would cement the
    // wrong kids into the store, and the next successful resolve would look
    // like a rotation.
    let (current, persist) = match current {
        Some(generation) => {
            let persist = stored.first() != Some(&generation);
            (generation, persist)
        }
        None => {
            warn!(
                did = did,
                "DID document not resolvable and no stored generation — \
                 falling back to #key-0/#key-1 and not persisting"
            );
            warn_if_well_known_in_identifier(did);
            (
                IdentityGeneration {
                    id: 0,
                    did: did.to_string(),
                    signing_kid: format!("{did}#key-0"),
                    ka_kid: format!("{did}#key-1"),
                    // The kids here are a guess, so the key material behind them
                    // is unknown too. `None` reads as "unknown" and never trips
                    // the diff — the placeholder must not look like a rotation.
                    ka_public_multibase: None,
                    mediator_did: mediator_did.map(str::to_string),
                    protocols,
                    created_at: now,
                    retired_at: None,
                    expires_at: None,
                },
                false,
            )
        }
    };

    if persist && let Err(e) = save_current_generation(store, &identity_ks, &current).await {
        // Not fatal: the in-memory identity is correct and the service can
        // serve. It just means a restart re-derives it from the document.
        warn!("failed to persist identity generation: {e}");
    }

    // Every generation still inside its grace window, current first. A retired
    // generation's key material comes back from `ServerSecrets::retired` — this
    // is the restart path the whole feature exists for.
    let current_id = current.id;
    let mut generations = vec![current];
    generations.extend(
        stored
            .into_iter()
            .filter(|g| g.retired_at.is_some() && g.id != current_id),
    );

    let (secrets_resolver, _handle) = ThreadedSecretsResolver::new(None).await;
    let mut all_secrets = Vec::new();
    for generation in &generations {
        for secret in secrets_for(generation, secrets) {
            secrets_resolver.insert(secret.clone()).await;
            all_secrets.push(secret);
        }
    }

    info!(
        did = did,
        generation = generations[0].id,
        signing_kid = %generations[0].signing_kid,
        ka_kid = %generations[0].ka_kid,
        live_generations = generations.len(),
        "service identity loaded"
    );

    Some(Arc::new(ServiceIdentity {
        did: did.to_string(),
        did_resolver,
        secrets_resolver: Arc::new(secrets_resolver),
        live: RwLock::new(LiveSet {
            generations,
            secrets: all_secrets,
        }),
        rotation: tokio::sync::Mutex::new(()),
    }))
}

/// Determine the current generation from the DID document, falling back to the
/// stored one when the document is unreachable.
///
/// Preferring the store over a guess is the point: once we have successfully
/// resolved the document, its kids are durable truth. A later boot during a
/// resolver outage should reuse them, not fall back to `#key-0`/`#key-1` and
/// silently start failing to decrypt.
async fn resolve_current_generation(
    did: &str,
    mediator_did: Option<&str>,
    protocols: ProtocolSet,
    did_resolver: &DIDCacheClient,
    stored: Option<&IdentityGeneration>,
    now: u64,
) -> Option<IdentityGeneration> {
    let Some(doc) = resolve_identity_doc(did, did_resolver).await else {
        if let Some(stored) = stored {
            warn!(
                did = did,
                generation = stored.id,
                "DID document not resolvable — keeping the stored generation's key IDs"
            );
        }
        return stored.cloned();
    };
    // Carry the existing id forward. Boot reconciles the *current* generation in
    // place; assigning a fresh id and retiring the old one is a rotation, and
    // that only ever happens through `reload_service_identity`, which knows how
    // to preserve the outgoing key material. If boot finds a changed document it
    // means the rotation was missed while the process was down — there is no old
    // key to preserve at that point anyway, since nothing in memory holds it.
    let id = stored.map_or(0, |g| g.id);
    let created_at = stored.map_or(now, |g| g.created_at);

    Some(IdentityGeneration {
        id,
        did: did.to_string(),
        signing_kid: doc.signing_kid,
        ka_kid: doc.ka_kid,
        ka_public_multibase: doc.ka_public_multibase,
        mediator_did: mediator_did.map(str::to_string),
        protocols,
        created_at,
        retired_at: None,
        expires_at: None,
    })
}

// ---------------------------------------------------------------------------
// Rotation
// ---------------------------------------------------------------------------

/// What a reload did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadOutcome {
    /// The document matches the current generation. The common case — the
    /// publish hook fires on every publish of our own DID, and almost all of
    /// them change something other than the identity.
    Unchanged,
    /// Generation 0 was recorded for the first time.
    ///
    /// **Not a rotation.** A service that hosts its own DID cannot resolve it at
    /// boot — it is the thing that serves it — so `load_identity` starts on
    /// guessed `#key-0`/`#key-1` kids and deliberately persists nothing. The
    /// first successful resolve, once the HTTP listener is up, replaces that
    /// guess with the document's real kids and writes generation 0.
    ///
    /// Treating this as a rotation would be actively wrong: it would retire a
    /// generation that never existed, and — for any DID whose document does not
    /// happen to use `#key-0`/`#key-1` — would fire on the first boot of a
    /// service that has never rotated anything.
    Established { generation: u64 },
    /// New key material arrived under the **same** verification-method id, so the
    /// new key was adopted with **no grace period**.
    ///
    /// Not a shortcoming of this code — it is not expressible. A kid identifies
    /// exactly one key: the secrets resolver is keyed by kid and inbound JWEs
    /// name their recipient by kid, so two keys cannot both answer to `#key-1`.
    /// Messages already encrypted to the previous key cannot be decrypted, and
    /// peers holding a stale document cannot reach the service until their cache
    /// expires.
    ///
    /// Rotate onto a *fresh* fragment to get an overlap. This variant exists so
    /// that a rotation which cannot overlap is **loud** rather than silently
    /// reported as "unchanged" — which is what a kid-only diff used to do, while
    /// the service quietly kept using the old private key.
    RotatedWithoutOverlap { generation: u64, ka_kid: String },
    /// The document could not be resolved. The current generation stands.
    Unresolvable,
    /// The document changed, but we hold no private key matching the new
    /// key-agreement kid. **Nothing was rotated.**
    ///
    /// Almost always the ordering mistake: the DID was published before the new
    /// key was written to the secret store. Rotating anyway would install a
    /// generation that cannot decrypt its own inbound traffic — strictly worse
    /// than standing still and shouting.
    Refused { reason: String },
    /// A new generation is current; the previous one is retired and stays
    /// decryptable until `expires_at`.
    Rotated {
        new_generation: u64,
        retired_generation: u64,
        expires_at: u64,
    },
}

/// Re-read the service's own DID document and rotate the identity if it changed.
///
/// Safe to call on every publish of our own DID: it is idempotent, it coalesces
/// (concurrent callers serialise on the rotation lock, and the loser re-reads
/// the document and sees `Unchanged`), and it refuses rather than half-rotates.
///
/// On a rotation the outgoing generation's key material is written into
/// `ServerSecrets::retired` **in the same `set()`** that the store already
/// holds the new keys from — the secret store has no compare-and-swap, so this
/// is the only way the old private key is guaranteed to survive a crash.
///
/// The caller is responsible for rebuilding the listener afterwards (the
/// profile's secrets vector changed); see
/// `didcomm_profile::build_tdk_profile_for_identity`.
pub async fn reload_service_identity(
    identity: &ServiceIdentity,
    store: &Store,
    secret_store: &dyn SecretStore,
    mediator_did: Option<&str>,
    protocols: ProtocolSet,
    grace_secs: u64,
) -> Result<ReloadOutcome, AppError> {
    // Serialise rotations. A burst of publishes coalesces here; whoever loses
    // the race re-resolves below and finds nothing left to do.
    let _guard = identity.rotation.lock().await;

    // Our own document is the one entry in the cache we must never serve stale
    // — the whole point is to notice it changed. The 300s TTL is far too slow.
    identity.did_resolver.remove(&identity.did).await;

    let Some(doc) = resolve_identity_doc(&identity.did, &identity.did_resolver).await else {
        return Ok(ReloadOutcome::Unresolvable);
    };

    let current = identity.current();
    let now = now_epoch();
    let identity_ks = store.keyspace(KS_IDENTITY)?;

    // Has a generation ever actually been recorded?
    //
    // A service that hosts its own DID cannot resolve it at boot — it is the
    // thing that serves it — so `load_identity` comes up on guessed
    // `#key-0`/`#key-1` kids and deliberately persists nothing. The in-memory
    // "current" generation at that point is a placeholder, not history. Rotating
    // away from it would retire a generation that never existed, and for any DID
    // whose document does not happen to use those fragments it would fire on the
    // first boot of a service that has never rotated.
    //
    // So the store, not memory, decides which this is: no record → establish.
    let persisted: Option<u64> = identity_ks.get(KEY_CURRENT.as_bytes().to_vec()).await?;

    let candidate = IdentityGeneration {
        // An establish keeps generation 0; a rotation takes the next id.
        id: if persisted.is_some() {
            current.id + 1
        } else {
            current.id
        },
        did: identity.did.clone(),
        signing_kid: doc.signing_kid.clone(),
        ka_kid: doc.ka_kid.clone(),
        ka_public_multibase: doc.ka_public_multibase.clone(),
        mediator_did: mediator_did.map(str::to_string),
        protocols,
        created_at: now,
        retired_at: None,
        expires_at: None,
    };

    if persisted.is_none() {
        // First real resolve. Replace the placeholder in place — no retirement,
        // no expiry, no old key to preserve, because there was no old identity.
        establish_generation(identity, store, &identity_ks, &candidate, secret_store).await?;
        info!(
            generation = candidate.id,
            signing_kid = %candidate.signing_kid,
            ka_kid = %candidate.ka_kid,
            "service identity established from the DID document"
        );
        return Ok(ReloadOutcome::Established {
            generation: candidate.id,
        });
    }

    if !current.differs_from(&candidate) {
        debug!("identity unchanged");
        return Ok(ReloadOutcome::Unchanged);
    }

    // Re-read the secret store. Our in-memory `ServerSecrets` is stale the
    // moment any CLI writes new key material — and a CLI runs in a *different
    // process*, so the new key can only be here.
    let Some(mut secrets) = secret_store.get().await? else {
        return Ok(ReloadOutcome::Refused {
            reason: "secret store holds no server secrets".into(),
        });
    };

    // Refuse to half-rotate. If the key in the store is not the private half of
    // what the document now advertises, the operator published before writing
    // the key. Installing this generation would leave us unable to decrypt
    // anything addressed to it.
    let new_ka = Secret::from_multibase(&secrets.key_agreement_key, Some(&candidate.ka_kid))
        .map_err(|e| AppError::Config(format!("failed to decode key_agreement_key: {e}")))?;

    if !secret_matches_document(&new_ka, doc.ka_public_multibase.as_deref()) {
        return Ok(ReloadOutcome::Refused {
            reason: format!(
                "the DID document advertises key-agreement key {} but the secret store holds a \
                 different private key — write the new key to the secret store before publishing \
                 the DID (keys, then rotate)",
                candidate.ka_kid
            ),
        });
    }

    // A rotation that reused the verification-method fragment.
    //
    // No overlap is possible here, and not because of any shortcoming in this
    // code: the secrets resolver is keyed by kid and inbound JWEs name their
    // recipient by kid, so two keys cannot both answer to `#key-1`. Whichever we
    // hold, half the peers fail.
    //
    // Take the new key — the document is authoritative, and peers still on the
    // old one heal as their caches expire — and say plainly what could not be
    // done. Rotating onto a *fresh* fragment is what makes the grace window work.
    if current.is_same_kid_rotation(&candidate) {
        establish_generation(identity, store, &identity_ks, &candidate, secret_store).await?;
        warn!(
            ka_kid = %candidate.ka_kid,
            "the DID document rotated its key-agreement key but kept the same \
             verification-method id ({}) — so NO grace period is possible: a kid identifies \
             exactly one key, and messages already encrypted to the previous one cannot be \
             decrypted. Adopted the new key; peers holding a stale document cannot reach this \
             service until their cache expires. Rotate onto a NEW fragment to get an overlap.",
            candidate.ka_kid
        );
        return Ok(ReloadOutcome::RotatedWithoutOverlap {
            generation: candidate.id,
            ka_kid: candidate.ka_kid,
        });
    }

    // Retire the outgoing generation and stash its key material. Its `Secret`s
    // are still in memory from when it was current, which is the only place the
    // old private key still exists once the store has been overwritten.
    let expires_at = now.saturating_add(grace_secs);
    let mut retiring = current.clone();
    retiring.retired_at = Some(now);
    retiring.expires_at = Some(expires_at);

    if grace_secs > 0 {
        match retired_keys_for(identity, &retiring) {
            Some(keys) => {
                secrets.retired.retain(|r| r.ka_kid != keys.ka_kid);
                secrets.retired.push(keys);
            }
            None => warn!(
                id = retiring.id,
                "outgoing generation's key material is not in memory — \
                 it cannot be honoured after a restart"
            ),
        }
    }

    // One write: the new keys are already here, and the outgoing key rides
    // along. A crash after this leaves both recoverable.
    secret_store.set(&secrets).await?;

    let identity_ks = store.keyspace(KS_IDENTITY)?;
    let mut batch = store.batch();
    batch.insert(&identity_ks, gen_key(retiring.id), &retiring)?;
    batch.insert(&identity_ks, gen_key(candidate.id), &candidate)?;
    batch.insert(&identity_ks, KEY_CURRENT.as_bytes().to_vec(), &candidate.id)?;
    batch.commit().await?;

    // Swap the live set. The new generation's secrets go into the *same*
    // secrets resolver — it takes `&self`, so every `AppState` holding a clone
    // of the Arc sees them immediately, with no state to re-thread.
    let new_secrets = secrets_for(&candidate, &secrets);
    for secret in &new_secrets {
        identity.secrets_resolver.insert(secret.clone()).await;
    }

    {
        let mut live = identity.live.write().expect("identity lock");
        let mut generations = vec![candidate.clone()];
        if grace_secs > 0 {
            generations.push(retiring.clone());
            generations.extend(live.generations.iter().skip(1).cloned());
        }

        let mut all = new_secrets;
        if grace_secs > 0 {
            // Everything the old live set held stays: the retiring generation's
            // keys are exactly the ones peers with a stale document are still
            // encrypting to.
            all.extend(live.secrets.iter().cloned());
        }
        live.generations = generations;
        live.secrets = all;
    }

    if grace_secs == 0 {
        // Immediate retirement: drop the old key material now. Correct for a
        // compromised key, and the operator opted into the breakage.
        drop_generation_secrets(identity, &retiring).await;
    }

    info!(
        new_generation = candidate.id,
        retired_generation = retiring.id,
        ka_kid = %candidate.ka_kid,
        expires_at,
        "service identity rotated"
    );

    Ok(ReloadOutcome::Rotated {
        new_generation: candidate.id,
        retired_generation: retiring.id,
        expires_at,
    })
}

/// Record generation 0 for the first time, replacing the boot-time placeholder.
///
/// The placeholder's kids were guessed (`#key-0` / `#key-1`), so the secrets
/// resolver and the listener profile are keyed on fragments the document may not
/// use. Both have to be re-keyed onto the document's real kids — and the stale
/// entries dropped, or an inbound JWE addressed to the real kid would find no
/// secret while a fabricated one lingered.
async fn establish_generation(
    identity: &ServiceIdentity,
    store: &Store,
    identity_ks: &KeyspaceHandle,
    generation: &IdentityGeneration,
    secret_store: &dyn SecretStore,
) -> Result<(), AppError> {
    let Some(secrets) = secret_store.get().await? else {
        return Err(AppError::Config(
            "secret store holds no server secrets".into(),
        ));
    };

    save_current_generation(store, identity_ks, generation).await?;

    // Drop the placeholder's key material before inserting the real thing.
    let placeholder = identity.current();
    identity
        .secrets_resolver
        .remove_secret(&placeholder.ka_kid)
        .await;
    identity
        .secrets_resolver
        .remove_secret(&placeholder.signing_kid)
        .await;

    let new_secrets = secrets_for(generation, &secrets);
    for secret in &new_secrets {
        identity.secrets_resolver.insert(secret.clone()).await;
    }

    let mut live = identity.live.write().expect("identity lock");
    live.generations = vec![generation.clone()];
    live.secrets = new_secrets;

    Ok(())
}

/// Extract a generation's key material from the in-memory live set, so it can
/// be persisted as retired.
///
/// The private key is read back out of the `Secret`s the profile is holding —
/// after the CLI has overwritten `ServerSecrets`, this is the only copy left.
fn retired_keys_for(
    identity: &ServiceIdentity,
    generation: &IdentityGeneration,
) -> Option<RetiredKeys> {
    let live = identity.live.read().expect("identity lock");

    let find = |kid: &str| {
        live.secrets
            .iter()
            .find(|s| s.id == kid)
            .and_then(|s| s.get_private_keymultibase().ok())
    };

    Some(RetiredKeys {
        ka_kid: generation.ka_kid.clone(),
        key_agreement_key: find(&generation.ka_kid)?,
        signing_kid: generation.signing_kid.clone(),
        signing_key: find(&generation.signing_kid)?,
    })
}

/// Remove a generation's key material from the secrets resolver and the live
/// set. After this, inbound messages addressed to its kids no longer decrypt.
async fn drop_generation_secrets(identity: &ServiceIdentity, generation: &IdentityGeneration) {
    identity
        .secrets_resolver
        .remove_secret(&generation.ka_kid)
        .await;
    identity
        .secrets_resolver
        .remove_secret(&generation.signing_kid)
        .await;

    let mut live = identity.live.write().expect("identity lock");
    live.generations.retain(|g| g.id != generation.id);
    live.secrets
        .retain(|s| s.id != generation.ka_kid && s.id != generation.signing_kid);
}

// ---------------------------------------------------------------------------
// Expiry
// ---------------------------------------------------------------------------

/// How often the expiry sweep runs.
///
/// Local and cheap — it compares timestamps against the in-memory live set and
/// reads the store; it touches no network. Not configurable, deliberately:
/// operators wanting prompter retirement should shorten
/// `identity.rotation_grace_period`, not the sweep interval. Mirrors
/// `purge_sweep`.
pub const DEFAULT_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// How often the identity is re-resolved from its DID document.
///
/// Deliberately **five times slower than the expiry sweep**. Re-resolving means
/// invalidating our own DID-cache entry and fetching the document over the
/// network; running that every 60s would mean ~1,400 self-resolves a day per
/// service, for a check that is redundant on control and server (their publish
/// hooks already catch the change the moment it happens).
///
/// Five minutes is comfortably inside any sane grace period — the default is an
/// hour — so nothing is at risk from noticing a rotation a few minutes late. The
/// witness is the one service for which this is the *only* trigger, and even
/// there 5 minutes against a 1-hour window is ample.
pub const DEFAULT_RELOAD_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

/// Retire every generation whose grace period has elapsed, returning how many
/// were reaped.
///
/// Purely local: no DID resolution, no network. That is why it can run on a
/// tight interval — see [`DEFAULT_RELOAD_INTERVAL`] for the part that cannot.
///
/// Also reconciles the in-memory live set against the store: a generation whose
/// record has been **deleted out of band** — by the offline `identity-retire-now`
/// CLI, or by another process sharing the store — is dropped here too. Without
/// this, a CLI retire would remove the record and the key from disk while the
/// running process happily kept decrypting with the copy in its resolver, which
/// is precisely the opposite of what someone reaching for the kill switch wants.
pub async fn run_sweep_once(
    identity: &ServiceIdentity,
    store: &Store,
    secret_store: &dyn SecretStore,
) -> u64 {
    let now = now_epoch();
    let live = identity.generations();

    // Which generations does the store still vouch for?
    let persisted: Vec<u64> = match store.keyspace(KS_IDENTITY) {
        Ok(ks) => match load_generations(&ks, now).await {
            Ok(records) => records.iter().map(|g| g.id).collect(),
            Err(e) => {
                warn!("identity sweep: could not read generations: {e}");
                return 0;
            }
        },
        Err(e) => {
            warn!("identity sweep: could not open the identity keyspace: {e}");
            return 0;
        }
    };

    let current_id = live.first().map(|g| g.id);
    let doomed: Vec<IdentityGeneration> = live
        .into_iter()
        .filter(|g| {
            // Never drop the current generation: it is the key the service is
            // actively using, and losing it would leave us unable to decrypt
            // anything at all. Its store record is rewritten on every rotation,
            // so a transient read miss must not take it out.
            if Some(g.id) == current_id {
                return false;
            }
            !g.is_live(now) || !persisted.contains(&g.id)
        })
        .collect();

    if doomed.is_empty() {
        return 0;
    }

    let mut reaped = 0;
    for generation in &doomed {
        if let Err(e) = expire_generation(identity, store, secret_store, generation).await {
            warn!(id = generation.id, "failed to expire generation: {e}");
            continue;
        }
        info!(
            id = generation.id,
            ka_kid = %generation.ka_kid,
            "identity generation expired — its key material is no longer honoured"
        );
        reaped += 1;
    }

    reaped
}

/// Expire one generation early, regardless of its grace period — the kill
/// switch.
///
/// This is the compromise response. Inbound messages still addressed to the old
/// key-agreement key stop decrypting the moment this returns, and that is the
/// point: a compromised key must stop being honoured immediately, breakage
/// accepted.
pub async fn retire_generation_now(
    identity: &ServiceIdentity,
    store: &Store,
    secret_store: &dyn SecretStore,
    generation_id: u64,
) -> Result<(), AppError> {
    let _guard = identity.rotation.lock().await;

    let generations = identity.generations();
    let Some(generation) = generations.iter().find(|g| g.id == generation_id) else {
        return Err(AppError::validation(
            crate::server::error::ValidationKind::Other,
            format!("no live identity generation with id {generation_id}"),
        ));
    };

    if generation.retired_at.is_none() {
        return Err(AppError::Config(
            "refusing to expire the current generation — rotate to a new one first".into(),
        ));
    }

    expire_generation(identity, store, secret_store, generation).await
}

/// Drop a generation: from the secrets resolver, the live set, the store, and
/// the secret store.
async fn expire_generation(
    identity: &ServiceIdentity,
    store: &Store,
    secret_store: &dyn SecretStore,
    generation: &IdentityGeneration,
) -> Result<(), AppError> {
    // Key material first. If a later step fails we have still stopped honouring
    // the key, which is the direction to fail in.
    drop_generation_secrets(identity, generation).await;

    if let Some(mut secrets) = secret_store.get().await? {
        let before = secrets.retired.len();
        secrets.retired.retain(|r| r.ka_kid != generation.ka_kid);
        if secrets.retired.len() != before {
            secret_store.set(&secrets).await?;
        }
    }

    let identity_ks = store.keyspace(KS_IDENTITY)?;
    identity_ks.remove(gen_key(generation.id)).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::config::StoreConfig;
    use std::sync::Mutex as StdMutex;

    const DID: &str = "did:webvh:example:alpha";

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
        ) -> super::super::secret_store::BoxFuture<'_, Result<Option<ServerSecrets>, AppError>>
        {
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

    #[test]
    fn the_grace_period_parses_and_a_typo_fails_safe() {
        use crate::server::config::IdentityConfig;

        let cfg = IdentityConfig::default();
        assert_eq!(cfg.rotation_grace_secs(), 3600, "default is 1h");

        let cfg = IdentityConfig {
            rotation_grace_period: "30m".into(),
            ..Default::default()
        };
        assert_eq!(cfg.rotation_grace_secs(), 1800);

        let cfg = IdentityConfig {
            rotation_grace_period: "0".into(),
            ..Default::default()
        };
        assert_eq!(cfg.rotation_grace_secs(), 0, "0 retires immediately");

        // A typo must not take the boot down, and must fail *long* — keeping
        // the old key honoured — rather than short.
        let cfg = IdentityConfig {
            rotation_grace_period: "1 fortnight".into(),
            ..Default::default()
        };
        assert_eq!(cfg.rotation_grace_secs(), 3600);
    }

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
}
