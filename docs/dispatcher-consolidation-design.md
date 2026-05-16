# Design note — DIDComm dispatcher consolidation

**Status:** proposed (not yet implemented).
**Closes review findings:** C1 (correctness — `MSG_DID_REGISTER`
unreachable on the HTTP-signed path), H1 (correctness — error-code
drift between dispatchers), M4 (design — encryption-asymmetry
undocumented), SM2 (security — replay window unguarded on the
HTTP-signed path), plus ~7 test-coverage gaps the test-engineer
audit flagged for `did-hosting-control/src/routes/didcomm.rs`.

## Background

`did-hosting-control` exposes the same VTA DID-management protocol over
two transports:

1. **Mediator-routed via the framework.**
   `did-hosting-control/src/messaging.rs::build_control_router` registers a
   handler with `affinidi-messaging-didcomm-service`. Inbound
   messages arrive over a websocket from the configured mediator,
   already encrypted (`MessagePolicy::require_encrypted(true)`) and
   sender-bound (`require_sender_did(true)`). The framework crate
   provides reconnect, deduplication, and lifecycle management.

2. **HTTP-signed via `POST /api/didcomm`.**
   `did-hosting-control/src/routes/didcomm.rs::dispatch` accepts a JWS-
   signed-but-not-encrypted DIDComm envelope over plain HTTPS.
   Used by clients that authenticate over REST and don't have a
   mediator session.

Both dispatchers walk the same `MSG_*` types, call the same
`did_ops::*` business logic, and produce the same wire-level
responses (`MSG_DID_OFFER`, `MSG_DID_CONFIRM`, etc.) — but they're
*two separate `match msg.typ.as_str()` statements* that have drifted.

## Current drift (concrete)

### Missing arm

| Message type | Framework router | HTTP-signed dispatcher |
|--------------|:----------------:|:----------------------:|
| `MSG_DID_REQUEST` | ✅ | ✅ |
| `MSG_DID_PUBLISH` | ✅ | ✅ |
| `MSG_DID_REGISTER` | ✅ | ❌ — falls through to "unknown type" |
| `MSG_WITNESS_PUBLISH` | ✅ | ✅ |
| `MSG_INFO_REQUEST` | ✅ | ✅ |
| `MSG_LIST_REQUEST` | ✅ | ✅ |
| `MSG_DELETE` | ✅ | ✅ |
| `MSG_DID_CHANGE_OWNER` | ✅ | ✅ |
| `MSG_SERVER_REGISTER` | ✅ (registry) | n/a |
| `MSG_HEALTH_PONG` / sync acks | ✅ | n/a |

The HTTP-signed path silently rejects atomic-register attempts.

### Error-code drift

| Wire condition | Framework router | HTTP-signed dispatcher |
|----------------|------------------|------------------------|
| `MSG_DID_PUBLISH` missing `mnemonic` | `e.p.did.validation-error` | `e.p.did.invalid-log` |
| `MSG_WITNESS_PUBLISH` missing `mnemonic` | `e.p.did.validation-error` | `e.p.did.witness-invalid` |
| `MSG_INFO_REQUEST` / `MSG_DELETE` missing `mnemonic` | `e.p.did.validation-error` | `e.p.did.mnemonic-not-found` |
| Unknown message type | `e.p.did.validation-error` | `e.p.did.unknown-type` |

The framework router funnels everything through `AppError` and
`map_app_error_code`'s substring matcher; the HTTP dispatcher
constructs `ProtocolError` directly per arm. SDK consumers cannot
rely on a stable code for a stable wire condition.

### Confidentiality asymmetry

Framework router: messages are encrypted (E2E) before they reach
the dispatcher. HTTP-signed: messages are signed-but-not-encrypted.
Both paths accept `did_log` content (potentially sensitive — VM
keys, service endpoints) and `new_owner` DIDs, but only the
framework path carries them through an encrypted envelope. This is
not documented anywhere; operators reading the code can't tell
which channel to prefer.

### Replay window

`unpack_signed` enforces a 5-minute `created_time` freshness window
but neither dispatcher caches `(sender_did, msg.id)` for replay
prevention. The framework path benefits from mediator-level dedup;
the HTTP-signed path does not. A captured signed envelope can be
replayed within the freshness window — bounded blast radius (state-
changing ops like `MSG_DELETE`, `MSG_DID_CHANGE_OWNER` are still
re-applied), but observable.

## Goals

1. **Single per-message dispatch table** — one place to add a new
   `MSG_*` arm, one place to assert against in tests.
2. **Stable wire-level error codes** that the SDK can branch on,
   replacing both substring-sniffing matchers.
3. **Documented confidentiality asymmetry** so operators know which
   transport to prefer for which payloads.
4. **Shared replay cache** so both transports get the same
   anti-replay guarantees.
5. **No change** to the public DIDComm protocol — message shapes,
   request fields, response codes (post-fix) all stay identical.

## Non-goals

- Removing the HTTP-signed transport. It's load-bearing for
  reverse-proxy / client-tooling cases and there's no plan to
  retire it.
- Introducing E2E encryption to the HTTP-signed path. That's a
  different design (mediator-level routing) and unrelated to the
  drift problem.
- Changing the public `MSG_*` type strings or their body shapes.

## Proposed design

### 1. Single dispatch function

Extract a transport-agnostic dispatcher in
`did-hosting-control/src/messaging/dispatch.rs` (new file):

```rust
pub async fn dispatch(
    auth: &AuthClaims,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), AppError>
```

Body is the union of the current two `match` statements, returning
`AppError` on every failure path (no more bespoke `ProtocolError`).
Every `MSG_*` arm is exercised once.

The framework handler in `messaging.rs::handle_webvh_message` and
the HTTP handler in `routes/didcomm.rs::handle` both call into this
single dispatcher. Each transport keeps its own thin wrapper for
the transport-specific concerns (envelope unpacking, signing the
response).

### 2. Stable error-code mapping

Replace both transports' `map_app_error_code` / `map_app_error`
with one promoted function in
`did-hosting-common/src/server/error.rs::AppError::didcomm_code(&self) -> &'static str`,
backed by the existing `ValidationKind` tag system rather than
substring matches. The `did_ops::*` business logic is updated to
construct tagged validations (`AppError::validation(InvalidLog,
"missing 'did_log' in body")`), eliminating the wording-fragile
sniffer.

After-fix codes for the drift cases above:

| Wire condition | Code |
|----------------|------|
| `MSG_DID_PUBLISH` missing `mnemonic` | `e.p.did.validation-error` (consistent) |
| `MSG_WITNESS_PUBLISH` missing `mnemonic` | `e.p.did.validation-error` |
| `MSG_INFO_REQUEST` / `MSG_DELETE` missing `mnemonic` | `e.p.did.validation-error` |
| Unknown message type | `e.p.did.unknown-type` |

The "more specific code" instinct (`e.p.did.invalid-log` for a
missing-field error on `MSG_DID_PUBLISH`) is wrong — missing fields
are validation errors regardless of the surrounding message type.
Specific codes are reserved for cases where the body is present but
semantically wrong (`e.p.did.invalid-log` should fire on JSONL that
fails to parse, not on a missing JSONL field).

### 3. Replay cache

New `did-hosting-control/src/messaging/replay.rs` module:

```rust
pub struct ReplayCache { /* HashMap<(String, String), Instant> behind a Mutex */ }

impl ReplayCache {
    pub fn check_and_insert(&self, sender: &str, msg_id: &str) -> Result<(), AppError>;
}
```

Bounded by TTL = `unpack_signed`'s freshness window (5 min). Stored
on `AppState` as `Arc<ReplayCache>`. Both transports call
`check_and_insert` immediately after sender verification; rejected
replays surface as `e.p.did.replay-detected` (new code).

Storage cost is bounded by max-throughput × 5min × ~64 bytes;
~30 MB at 100 msg/s. No persistent storage — restart accepts
in-flight messages with the same id, which is acceptable since the
TTL is short.

### 4. Documentation

Module-level rustdoc on `routes/didcomm.rs` calling out the
encryption asymmetry: "this endpoint accepts JWS-signed-but-not-
encrypted DIDComm; for end-to-end encryption use the mediator-routed
channel via your DIDComm SDK." Operators reading the source see
the constraint before they make a routing decision.

The protocol doc gets a corresponding subsection in the "Transport"
section enumerating what each channel guarantees.

## Migration path

The refactor lands as a single PR with three commits:

1. **Add `messaging::dispatch::dispatch()` and migrate
   `messaging.rs::handle_webvh_message` to use it.** Existing
   framework-side tests still pass; no behaviour change.
2. **Migrate `routes/didcomm.rs::dispatch` to call the shared
   dispatcher.** Removes `ProtocolError`. Behaviour change: missing
   `MSG_DID_REGISTER` arm now works; the four error-code drift cases
   converge (test diff exposes the wire-level changes for sign-off).
3. **Add the replay cache.** Both transports gate through it.
   Tests cover: identical (sender, msg.id) pair within window
   rejected, distinct pairs accepted, expiry resumes acceptance.

Each commit independently passes `cargo test --workspace` and
`cargo clippy --workspace --all-targets -- -D warnings`.

## Trade-offs

- **Public-facing error code changes for the HTTP-signed transport.**
  The "drift convergence" in step 2 changes the codes the HTTP path
  emits for the four conditions above. Existing clients that branched
  on `e.p.did.invalid-log` for a missing-mnemonic error will need to
  branch on `e.p.did.validation-error` instead. This is a wire-level
  break; it's the right break (the prior code was wrong) but it
  warrants a CHANGELOG entry under "Changed" and a migration note
  for SDK consumers.

- **Replay-cache memory.** Bounded but unbounded-ish in adversarial
  scenarios; an attacker with a flood of unique `msg.id` values
  forces the map to grow until the TTL clears them. Mitigation:
  cap the cache size at e.g. 100k entries and evict oldest on
  insert, accepting that under flood we degrade to "freshness-only"
  protection (which is what we have today).

- **One more module to maintain.** The single dispatcher is more
  code than two `match` statements aggregated, but every change is
  applied once instead of twice — net win after the second feature
  addition.

## Out of scope (for this design)

- Promoting `Role::Service` from "exists but unused" (review M6) to
  a documented role with named handlers. Orthogonal to dispatcher
  consolidation; track separately.
- `did.jsonl` proof verification (review M2). Touches `did_ops::*`
  not the dispatcher.
- `register_did_atomic` write-race fix (review M1). Per-mnemonic
  mutex / serializing actor; orthogonal.
- Default-rejection of loopback / RFC1918 in
  `validate_registered_url`. Has operator-visible behaviour change;
  separate hardening PR with a config flag.

## Open questions

1. Should the replay cache be persistent (survive restart) or
   in-memory? In-memory is simpler and the 5-min TTL bounds the
   damage of a restart-replay; recommend in-memory unless we see a
   deployment scenario that needs the harder guarantee.
2. `unpack_signed`'s freshness window is currently fixed at 5
   minutes — should the replay TTL track that constant or be
   configurable separately? Recommend tracking it (single source
   of truth in `did-hosting-common/src/server/didcomm_unpack.rs`).
3. The HTTP-signed transport is currently behind no rate limit
   (review SM3 flagged the `auth/challenge` endpoint specifically;
   this is a different but related surface). A `tower-governor`
   layer is out of scope for this design but is the right next step
   once consolidation lands.

## Acceptance criteria

- One `match msg.typ.as_str()` statement in the codebase routing
  `MSG_*` to handlers.
- `MSG_DID_REGISTER` reachable from both transports.
- A unit test asserting that the same `AppError` variant produces
  the same wire-level code regardless of transport.
- A unit test asserting that an identical `(sender, msg.id)` pair
  submitted twice within the freshness window produces
  `e.p.did.replay-detected` on the second attempt.
- `routes/didcomm.rs` module-level doc comment names the encryption
  asymmetry and points operators at the mediator-routed transport
  for sensitive payloads.
- CHANGELOG entry under "Changed" documenting the four error-code
  shifts on the HTTP-signed transport.
