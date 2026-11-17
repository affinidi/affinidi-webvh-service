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
use didwebvh_rs::log_entry::LogEntryMethods;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use super::auth::session::now_epoch;
use super::error::AppError;
use super::secret_store::{RetiredKeys, SecretStore, ServerSecrets};
use super::store::{KS_IDENTITY, KeyspaceHandle, Store};

/// How long a resolved DID document is trusted from the cache, in seconds.
///
/// This service's resolver verifies every sender-bound proof, so the TTL bounds
/// how long a key a peer has *removed* from its document keeps being accepted.
/// A peer that *added* a key (rotation) is not held to it: a proof that fails
/// against a cached document is retried once against a fresh resolution (see
/// `TransportBoundVerifier`). Kept short and explicit rather than inherited
/// from the SDK default.
pub const DID_CACHE_TTL_SECS: u32 = 120;

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
    /// Keeps the did:scid floors of the identities this service authorises in
    /// the store, for [`Self::did_resolver`] (VTI-KEY-162). `None` when the
    /// store could not be opened for it, which leaves the in-memory floor only.
    pub scid_floors: Option<Arc<super::scid_floors::ScidFloorKeeper>>,

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

    /// The live secret with key id `kid`, if any — one copy rather than
    /// every live key, for a caller that signs with a single key.
    pub fn secret(&self, kid: &str) -> Option<Secret> {
        self.live
            .read()
            .expect("identity lock")
            .secrets
            .iter()
            .find(|s| s.id == kid)
            .cloned()
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

    /// [`Self::from_signing_secret`] with a freshly generated Ed25519 key named
    /// `{did}#key-1`. For tests that need a service able to sign as `did`
    /// without anything resolving the key.
    pub async fn generated_for(did: &str) -> Result<Arc<Self>, AppError> {
        let mut secret = Secret::generate_ed25519(None, None);
        secret.id = format!("{did}#key-1");
        Self::from_signing_secret(did, secret).await
    }

    /// An identity with one generation whose signing key is `secret` (its `id`
    /// is the signing kid). For tests and tools that need a service able to
    /// sign — e.g. a `did:key` service DID — without a published DID log.
    /// Carries no key-agreement key, so it cannot back a DIDComm listener.
    pub async fn from_signing_secret(did: &str, secret: Secret) -> Result<Arc<Self>, AppError> {
        let did_resolver = DIDCacheClient::new(
            DIDCacheConfigBuilder::default()
                .with_cache_ttl(DID_CACHE_TTL_SECS)
                .build(),
        )
        .await
        .map_err(|e| AppError::Internal(format!("DID cache: {e}")))?;
        let (secrets_resolver, _handle) = ThreadedSecretsResolver::new(None).await;
        let generation = IdentityGeneration {
            id: 0,
            did: did.to_string(),
            signing_kid: secret.id.clone(),
            ka_kid: String::new(),
            ka_public_multibase: None,
            mediator_did: None,
            protocols: ProtocolSet::default(),
            created_at: now_epoch(),
            retired_at: None,
            expires_at: None,
        };
        Ok(Arc::new(Self {
            did: did.to_string(),
            did_resolver,
            secrets_resolver: Arc::new(secrets_resolver),
            scid_floors: None,
            live: RwLock::new(LiveSet {
                generations: vec![generation],
                secrets: vec![secret],
            }),
            rotation: tokio::sync::Mutex::new(()),
        }))
    }

    /// [`Self::from_signing_secret`] plus a key-agreement secret and a
    /// mediator, for integration tests that drive a **real** DIDComm listener
    /// (e.g. against `affinidi-messaging-test-mediator`) rather than resolving
    /// a published DID document.
    ///
    /// `from_signing_secret`'s "carries no key-agreement key" limitation is
    /// exactly what this lifts: `signing_secret.id` and `ka_secret.id` become
    /// the generation's `signing_kid`/`ka_kid` as-is, so callers minting a
    /// `did:peer` (whose secrets already carry the right `#key-N` ids) can
    /// pass them straight through. Both secrets are inserted into the
    /// identity's own `secrets_resolver` — [`load_identity`] does the same for
    /// every live generation's secrets — so a real `DIDCommService` listener
    /// build from this identity can actually unpack inbound messages.
    ///
    /// No document is resolved or trusted here: `ka_public_multibase` is
    /// `None`, `protocols` and `mediator_did` are exactly what the caller
    /// passes, and nothing is persisted. Gated behind `test-support` (like
    /// other test-only crate surface, e.g.
    /// `TransportBoundVerifier::record_deactivation_verdict`) so a downstream
    /// integration test can reach it too.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn for_didcomm_test(
        did: &str,
        signing_secret: Secret,
        ka_secret: Secret,
        mediator_did: &str,
        protocols: ProtocolSet,
    ) -> Result<Arc<Self>, AppError> {
        let did_resolver = DIDCacheClient::new(
            DIDCacheConfigBuilder::default()
                .with_cache_ttl(DID_CACHE_TTL_SECS)
                .build(),
        )
        .await
        .map_err(|e| AppError::Internal(format!("DID cache: {e}")))?;
        let (secrets_resolver, _handle) = ThreadedSecretsResolver::new(None).await;
        secrets_resolver.insert(signing_secret.clone()).await;
        secrets_resolver.insert(ka_secret.clone()).await;
        let generation = IdentityGeneration {
            id: 0,
            did: did.to_string(),
            signing_kid: signing_secret.id.clone(),
            ka_kid: ka_secret.id.clone(),
            ka_public_multibase: None,
            mediator_did: Some(mediator_did.to_string()),
            protocols,
            created_at: now_epoch(),
            retired_at: None,
            expires_at: None,
        };
        Ok(Arc::new(Self {
            did: did.to_string(),
            did_resolver,
            secrets_resolver: Arc::new(secrets_resolver),
            scid_floors: None,
            live: RwLock::new(LiveSet {
                generations: vec![generation],
                secrets: vec![signing_secret, ka_secret],
            }),
            rotation: tokio::sync::Mutex::new(()),
        }))
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
            scid_floors: None,
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

/// Extract the identity's kids from a locally-stored `did.jsonl`, without the
/// network.
///
/// The server hosts its own DID, so its store is authoritative — and at cold
/// boot the public URL (often behind a load balancer that hasn't yet marked
/// this instance healthy) 502s, before the HTTP listener is even up. Reading
/// the validated current document from the local log avoids that round-trip.
/// Mirrors [`resolve_identity_doc`]'s field extraction. Returns `None` when the
/// log doesn't parse or has no auth/keyAgreement, so the caller falls back to
/// the network path.
pub fn resolve_identity_doc_from_log(did: &str, log_content: &str) -> Option<ResolvedIdentityDoc> {
    let state = super::identity_rotate::load_validated_state(log_content).ok()?;
    let current = state.log_entries().last()?.log_entry.get_state();
    let resolved = kids_from_document(did, current)?;
    debug!(
        did = did,
        signing = %resolved.signing_kid,
        key_agreement = %resolved.ka_kid,
        "resolved own DID document from the local log (no network)"
    );
    Some(resolved)
}

/// Pure kid extraction from a DID document JSON — the shape `build_did_document`
/// emits (`authentication`/`keyAgreement` are arrays of bare kid strings, and
/// `publicKeyMultibase` is a flat property on the verification method). Split
/// out so the mapping is unit-tested without a validated log, mirroring
/// [`resolve_identity_doc`]'s extraction. Returns `None` when the document has
/// neither relationship, so the caller falls back to the network path.
fn kids_from_document(did: &str, current: &serde_json::Value) -> Option<ResolvedIdentityDoc> {
    if current.get("authentication").is_none() && current.get("keyAgreement").is_none() {
        return None;
    }
    // Each relationship entry is a bare kid string or an embedded VM object.
    let kid_of = |entry: &serde_json::Value| -> Option<String> {
        entry
            .as_str()
            .map(str::to_string)
            .or_else(|| entry.get("id").and_then(|v| v.as_str()).map(str::to_string))
    };
    let signing_kid = current
        .get("authentication")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(kid_of)
        .unwrap_or_else(|| format!("{did}#key-0"));
    let ka_kid = current
        .get("keyAgreement")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(kid_of)
        .unwrap_or_else(|| format!("{did}#key-1"));
    let ka_public_multibase = current
        .get("verificationMethod")
        .and_then(|v| v.as_array())
        .and_then(|vms| {
            vms.iter()
                .find(|vm| vm.get("id").and_then(|i| i.as_str()) == Some(ka_kid.as_str()))
        })
        .and_then(|vm| vm.get("publicKeyMultibase"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
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
/// The secret kids are the *resolved* verification-method ids, never
/// hard-coded fragments: the document is the one source of truth for kids, so
/// the secrets resolver and the listener's profile always agree.
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

    let did_resolver = match DIDCacheClient::new(
        DIDCacheConfigBuilder::default()
            .with_cache_ttl(DID_CACHE_TTL_SECS)
            .build(),
    )
    .await
    {
        Ok(resolver) => resolver,
        Err(e) => {
            warn!("failed to create DID resolver: {e} — DIDComm auth endpoints will not work");
            return None;
        }
    };

    // Before anything resolves through it: the first resolution of an
    // authorised did:scid must already know the floor it reached last run.
    let scid_floors = match super::scid_floors::ScidFloorKeeper::install(&did_resolver, store).await
    {
        Ok(keeper) => Some(keeper),
        Err(e) => {
            warn!("failed to load did:scid floors: {e} — they will not survive a restart");
            None
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

    // Read our own DID's log from the local store so identity resolution can
    // prefer it over the network. The server hosts this DID; at cold boot the
    // public URL (behind a load balancer) may 502 before the instance is
    // healthy, and resolving over the wire is pointless when the authoritative
    // copy is right here.
    let local_log: Option<String> = match (
        mnemonic_from_did(did),
        store.keyspace(super::store::KS_DIDS),
    ) {
        (Some(mnemonic), Ok(dids_ks)) => dids_ks
            .get_raw(crate::did_ops::content_log_key(&mnemonic))
            .await
            .ok()
            .flatten()
            .and_then(|bytes| String::from_utf8(bytes).ok()),
        _ => None,
    };

    let current = resolve_current_generation(
        did,
        mediator_did,
        protocols,
        &did_resolver,
        local_log.as_deref(),
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

    // Validate that the secret store actually holds the private half of the
    // current generation's key-agreement kid. `reload_service_identity` guards
    // this for a *rotation* (it refuses to half-rotate), but boot performs no
    // rotation and so had no such check. If the document advertises a key this
    // process never received, say so LOUDLY now — otherwise the service quietly
    // runs on a retired key and collapses the moment that key's grace period
    // elapses, ~one grace period after boot, with a cryptic "no usable key
    // agreement key".
    match Secret::from_multibase(&secrets.key_agreement_key, Some(&current.ka_kid)) {
        Ok(ka) if !secret_matches_document(&ka, current.ka_public_multibase.as_deref()) => {
            error!(
                did = did,
                ka_kid = %current.ka_kid,
                "the DID document advertises a key-agreement key whose private half is NOT in \
                 the secret store — this identity cannot decrypt or authenticate, and will fail \
                 once any grace period elapses. Write the matching key to the secret store \
                 (keys, then publish the DID), or re-resolve."
            );
        }
        Err(e) => warn!(
            did = did,
            ka_kid = %current.ka_kid,
            "could not decode the stored key-agreement key to validate it against the \
             document: {e}"
        ),
        _ => {}
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
        scid_floors,
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
    local_log: Option<&str>,
    stored: Option<&IdentityGeneration>,
    now: u64,
) -> Option<IdentityGeneration> {
    // Prefer the locally-hosted log (authoritative, and available before the
    // HTTP listener / load balancer is), then fall back to the network resolve.
    let resolved = match local_log.and_then(|log| resolve_identity_doc_from_log(did, log)) {
        Some(from_log) => Some(from_log),
        None => resolve_identity_doc(did, did_resolver).await,
    };
    let Some(doc) = resolved else {
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
    /// The document's **non-key** attributes changed — `protocols` and/or
    /// `mediator_did` — but the keys did not. **Not a rotation.** The current
    /// generation is updated in place: same id, same keys, no retirement and no
    /// grace window.
    ///
    /// This distinction is load-bearing. Retiring a generation here would start
    /// a grace window on a generation that shares the *current* `ka_kid` (the
    /// key didn't change), and its eventual expiry would delete the key
    /// material the service is still using — leaving it with no usable
    /// key-agreement key. A `protocols`/`mediator` change (e.g. enabling TSP)
    /// carries no new key and no old key to preserve, so there is nothing to
    /// rotate. The caller should still rebuild the listener, since the
    /// transports it carries may have changed.
    MetadataUpdated { generation: u64 },
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

    // Something changed — but is it the *key*, or only metadata? A rotation
    // (retire + grace + eventual key deletion) is only correct when the key
    // material changes. A `protocols`/`mediator_did` change carries no new key
    // and no old key to preserve; retiring the current generation for it would
    // arm a grace window whose expiry later deletes the still-in-use `ka_kid`
    // key, leaving the service with no usable key-agreement key.
    let key_changed = current.signing_kid != candidate.signing_kid
        || current.ka_kid != candidate.ka_kid
        || current.key_material_differs_from(&candidate);
    if !key_changed {
        // Keep the current id — this is the same generation — and update in
        // place, preserving any live retired generations and the key material.
        let updated = IdentityGeneration {
            id: current.id,
            ..candidate.clone()
        };
        update_current_generation_in_place(identity, store, &identity_ks, &updated).await?;
        info!(
            generation = updated.id,
            didcomm = updated.protocols.didcomm,
            tsp = updated.protocols.tsp,
            "identity metadata changed (protocols/mediator) but keys did not — \
             updated in place, no rotation"
        );
        return Ok(ReloadOutcome::MetadataUpdated {
            generation: updated.id,
        });
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
/// Update the current generation's non-key attributes (`protocols`,
/// `mediator_did`) in place.
///
/// Unlike [`establish_generation`], this does **not** touch key material or the
/// live set's retired generations: the kids are unchanged, so the secrets
/// resolver already holds exactly the right keys, and any generation still in
/// its grace window must keep decrypting. Only the current generation's record
/// (store) and its in-memory copy are rewritten.
async fn update_current_generation_in_place(
    identity: &ServiceIdentity,
    store: &Store,
    identity_ks: &KeyspaceHandle,
    updated: &IdentityGeneration,
) -> Result<(), AppError> {
    save_current_generation(store, identity_ks, updated).await?;
    let mut live = identity.live.write().expect("identity lock");
    if let Some(first) = live.generations.first_mut() {
        *first = updated.clone();
    } else {
        live.generations = vec![updated.clone()];
    }
    Ok(())
}

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
    let doomed_ids: Vec<u64> = live
        .iter()
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
        .map(|g| g.id)
        .collect();

    if doomed_ids.is_empty() {
        return 0;
    }

    // Safety net: expiring a generation removes its `ka_kid`'s key material from
    // the resolver. Never expire one whose `ka_kid` is still used by a surviving
    // generation — that would strip the key the survivor (usually the current
    // generation) is still using and leave the service with no usable
    // key-agreement key. Post-fix a retired generation never shares the current
    // `ka_kid`; this catches leftover damage from a server that rotated wrongly
    // before that fix, so that a grace expiry can never disarm it.
    let surviving_ka_kids: std::collections::HashSet<&str> = live
        .iter()
        .filter(|g| !doomed_ids.contains(&g.id))
        .map(|g| g.ka_kid.as_str())
        .collect();
    let mut to_expire: Vec<IdentityGeneration> = Vec::new();
    let mut rescued: Vec<u64> = Vec::new();
    for g in live.iter().filter(|g| doomed_ids.contains(&g.id)) {
        if surviving_ka_kids.contains(g.ka_kid.as_str()) {
            rescued.push(g.id);
        } else {
            to_expire.push(g.clone());
        }
    }
    if !rescued.is_empty() {
        error!(
            ?rescued,
            "identity sweep: NOT expiring generation(s) whose key-agreement key is still used by \
             a surviving generation — expiring them would strip the key in active use and leave \
             no usable key-agreement key. This indicates a same-`ka_kid` rotation that should no \
             longer happen (see reload_service_identity's metadata-vs-key split); the shared key \
             material stays loaded until the drift is resolved."
        );
    }

    let mut reaped = 0;
    for generation in &to_expire {
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
#[path = "identity_tests.rs"]
mod tests;
