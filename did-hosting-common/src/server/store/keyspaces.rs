//! Centralised registry of every named keyspace the workspace opens.
//!
//! Why: keyspace names were previously stringly typed at every call site
//! across `did-hosting-{server, control, daemon}`, `webvh-{witness,
//! watcher}`, and tests. A typo (`"sesions"` instead of `"sessions"`)
//! would silently create a parallel empty keyspace, and the multi-domain
//! work needs to add three new keyspaces — each one would otherwise mean
//! editing dozens of call sites and praying for consistency.
//!
//! The registry constant pattern is:
//! - one `KS_*` const per keyspace, kebab-cased name in a `&'static str`;
//! - every call site uses the const, not the literal;
//! - a workspace lint (`rg 'keyspace\("'` returns no matches outside this
//!   file plus the storage-backend unit tests) is the CI invariant.
//!
//! Adding a new keyspace = add a `KS_*` const here, document it, done.

// ---------------------------------------------------------------------------
// Existing keyspaces (pre-rollout)
// ---------------------------------------------------------------------------

/// `dids:<mnemonic>` — DID records (`DidRecord` after T12; legacy raw
/// bytes pre-migration). Backs every DID resolution and management op.
pub const KS_DIDS: &str = "dids";

/// `acl:<did>` — ACL entries (`AclEntry`). Gates which DIDs are allowed
/// to authenticate and what roles they hold.
pub const KS_ACL: &str = "acl";

/// `session:<id>` + `refresh:<token>` — auth sessions and the reverse
/// refresh-token index. Holds the JWT challenge-response flow's state.
pub const KS_SESSIONS: &str = "sessions";

/// `stats:<mnemonic>` — per-DID resolve/update counters and totals.
pub const KS_STATS: &str = "stats";

/// `ts:<mnemonic>:<epoch>` — time-series buckets for stats / dashboards.
pub const KS_TIMESERIES: &str = "timeseries";

/// `registry:<instance_id>` — control plane's registry of remote
/// `did-hosting-server` instances and `webvh-witness` services.
pub const KS_REGISTRY: &str = "registry";

/// `witnesses:<mnemonic>` — witness proofs the witness service has
/// signed for hosted DIDs.
pub const KS_WITNESSES: &str = "witnesses";

/// `meta:<key>` — runner-internal state (e.g. `migration:applied:{id}`
/// markers from the migration runner in `super::super::migrations`).
/// Reserved for workspace-internal bookkeeping; not part of the wire
/// surface.
pub const KS_META: &str = "meta";

// ---------------------------------------------------------------------------
// New keyspaces (added by the multi-domain rollout)
// ---------------------------------------------------------------------------
//
// Wired up here for forward-reference. Their producers / consumers land
// in later tasks (see `tasks/did-hosting-rollout-todo.md`):
//
// - KS_DOMAINS         → T14 / T15 (`DomainEntry` CRUD)
// - KS_ASSIGNMENTS     → T29 (server-local cached assignments)
// - KS_PENDING_PURGES  → T30 (unassignment grace-period purge sweep)

/// `domains:<name>` — first-class `DomainEntry` records. Used by the
/// multi-domain hosting feature.
pub const KS_DOMAINS: &str = "domains";

/// `assignments:<server_id>:<domain>` — local cache of which domains
/// this server is currently authoritative for. Read on cold start
/// before the control plane is reachable.
pub const KS_ASSIGNMENTS: &str = "assignments";

/// `pending_purges:<server>:<domain>:<scheduled_at>` — pending grace-
/// period purges queued after a `domain/unassign/1.0` Trust Task.
pub const KS_PENDING_PURGES: &str = "pending_purges";

/// `identity:current` → the current generation id; `identity:gen:<id>` →
/// an [`IdentityGeneration`](crate::server::identity::IdentityGeneration).
///
/// Records which version(s) of the service's *own* DID identity are still
/// honoured: the resolved verification-method key IDs, the mediator, the
/// protocol set, and (once a generation is retired) its expiry. Boot
/// reconstructs the live set from here, because `config.toml` only ever
/// describes the *current* identity — a retiring generation's mediator and
/// kids exist nowhere else.
///
/// Metadata only. Private key material stays in the secret store, behind
/// the keyring/KMS boundary; it is never written to a keyspace.
pub const KS_IDENTITY: &str = "identity";

/// `outbox:<target_did>:<enqueue_micros>:<uuid>` — durable outbound
/// DIDComm queue. Every control→server mutation (assign, unassign,
/// purge, domain-upsert, sync-update, sync-delete) is persisted here
/// before delivery is attempted. The outbox worker drains entries in
/// per-target FIFO order; on transient failure the entry stays in the
/// keyspace with an updated retry timestamp, so a server outage
/// doesn't lose mutations and a control restart doesn't drop in-
/// flight work. Receivers must remain idempotent because the
/// delivery guarantee is at-least-once.
pub const KS_OUTBOUND_QUEUE: &str = "outbox";
