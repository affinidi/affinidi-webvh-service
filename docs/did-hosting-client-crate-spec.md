# Spec: `did-hosting-client` companion crate

Status: Draft — awaiting review
Scope: New workspace member `did-hosting-client/` (published as `did-hosting-client`) inside this repo, shipped in the same release tag as the multi-domain + multi-method + Trust-Tasks work (see `docs/multi-domain-spec.md`, `docs/multi-method-hosting-spec.md`).
Author: glenn.gore@gmail.com
Reference implementation: `verifiable-trust-infrastructure` branch `feat/webvh-rest-auth-hardened` (PR #113). Modules to crib from are itemised in §5.4.

## 1. Objective

Extract the daemon-facing client logic currently duplicated by every `didwebvh-rs` consumer into a reusable companion crate. The host workspace is method-agnostic, but at v0.1 the only protocol-level dep we pull in is `didwebvh-rs` (under feature `method-webvh`); `did:web` needs no per-method protocol crate. The new sibling crate `did-hosting-client` provides:

- The **wire contract** for talking to a `did-hosting-server` / `did-hosting-control` / `did-hosting-daemon` (REST + DIDComm auth message types).
- A batteries-included **`Client` type** that handles challenge/authenticate/refresh, token caching, per-server lock contention, HTTPS enforcement, error mapping, and the multi-domain `domain` + multi-method `method` parameters.
- An interface (`HostingTokenStore`, `ServerLocks`) so integrators can plug in their own token persistence and run their own concurrency primitives.

### Why a separate crate (not a feature on `didwebvh-rs`)

- `didwebvh-rs` has no async runtime, no HTTP client, no DIDComm dep today. Adding all three behind a feature flag still bloats `Cargo.lock` for protocol-only consumers (validators, archive readers).
- A separate crate keeps the protocol surface auditable and lets the client crate iterate without bumping protocol semver.
- Convention: `didwebvh-rs` ↔ `did-hosting-client` mirrors `affinidi-tdk` ↔ `affinidi-tdk-client`, `aws-sdk-core` ↔ `aws-sdk-s3`, etc.

### Why in this workspace

The wire contract is owned by `did-hosting-server` / `did-hosting-control` / `did-hosting-daemon`, which live here. Co-locating the client keeps the wire contract and its consumer in lock-step — when the daemon's routes change, the client crate's CI catches it on the same PR. Tradeoff: client releases are coupled to the webvh-service release cadence. We accept that.

### Why it ships with multi-domain

- The Trust-Tasks transport (per `docs/multi-domain-spec.md`) changes the canonical wire identifiers. A client born pre-multi-domain would need a v0.2 bump for Trust-Tasks; born with the multi-domain release, it ships v0.1 Trust-Tasks-native.
- The `domain` parameter on `register_did_atomic` and friends is part of the multi-domain API surface. Client and daemon land together so integrators upgrade once.

## 2. Non-goals

- **Backwards compatibility with pre-rename daemons.** The client crate v0.1 targets the renamed-and-multi-domain-and-multi-method release. It speaks Trust-Tasks URLs only, under the `did-hosting/...` namespace. Integrators on older `webvh-*` daemons stay on hand-rolled clients until they upgrade.
- **CLI binary.** This is a library crate. A separate CLI may follow.
- **Admin operations** (`POST /api/acl`, `POST /api/control/...`, domain management). v0.1 surface is **DID-owner-shaped operations only**: challenge / authenticate / refresh, publish, delete, register-atomic, request-uri, check-path. Admin client surface (if needed) lands in a follow-on with its own dedicated `AdminClient` type.
- **Token persistence beyond in-memory.** `HostingTokenStore` is a trait so integrators can implement file/SQL/redis backends; the crate ships only `InMemoryTokenStore`.
- **DID document parsing.** Service-entry resolution is generic over a `ServiceEntry` trait so integrators bring their own DID-doc parser; we do not pull in a DID document model. The client likewise does not parse `did_data` per method.
- **Per-method protocol logic.** The client crate has no method-specific validators; the daemon enforces method correctness on the server side. The only method-aware client code is the resolution URL pattern selector in `get_did`.
- **Witness-related calls.** Out of scope for v0.1; webvh's witness upload endpoint exists on the daemon but is a separate flow, and witness is a webvh-specific concept that doesn't generalise.

## 3. Crate layout

Workspace folder name follows the in-repo convention (`webvh-*`), published name follows the `didwebvh-*` family:

```
did-hosting-client/
├── Cargo.toml             # package.name = "did-hosting-client"
├── README.md
└── src/
    ├── lib.rs
    ├── auth/
    │   ├── mod.rs         # HostingSigningIdentity{,Owned}, Trust-Task URL consts for auth
    │   └── message.rs     # build_authenticate_message, build_refresh_message (DIDComm JWS construction)
    ├── transport.rs       # ServiceEntry trait, resolve_server_transport, HTTPS enforcement
    ├── token_store.rs     # HostingTokenStore trait + InMemoryTokenStore + TokenData (ZeroizeOnDrop + redacted Debug)
    ├── locks.rs           # ServerLocks per-server-id async mutex registry
    ├── error.rs           # ClientError (Auth, Forbidden, NotFound, Conflict, Validation, Network, Server, Protocol)
    └── client.rs          # Client (constructor + auth + log publish/delete + atomic register + request-uri + check-path)
```

Crate dependencies (`did-hosting-client/Cargo.toml`):

```toml
[package]
name = "did-hosting-client"
version = "0.1.0"
edition = "2024"
rust-version = "1.94"

[dependencies]
didwebvh-rs = { workspace = true }              # pinned by the workspace
affinidi-tdk = { workspace = true }             # DIDComm v2 signing
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
tokio = { version = "1", features = ["sync", "macros"] }
url = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
zeroize = { version = "1", features = ["derive"] }
thiserror = "2"
tracing = "0.1"
async-trait = "0.1"
dashmap = "6"
ipnetwork = "0.20"  # if needed for loopback detection alongside url::Host
# NOTE: do NOT pull in did-hosting-common — this is a thin client; its only daemon
# dep is didwebvh-rs (protocol types).
```

## 4. Tech stack

- Rust 2024, rust-version 1.94 (matches the workspace).
- `reqwest 0.12` with `rustls-tls` for HTTPS (no openssl dep).
- `tokio` for the async runtime + `Mutex` primitive.
- `affinidi-tdk` for DIDComm v2 signed-message construction (the existing protocol crate already depends on this).
- `zeroize` for `TokenData` defence-in-depth.

No new database backends, no new transport runtimes. Out-of-tree integrators stay free to use a different async runtime by reimplementing the trait surface — we do not lock them into tokio anywhere except `ServerLocks` (which uses `tokio::sync::Mutex`). A follow-on PR may extract the lock primitive behind a trait if demand emerges.

## 5. Wire contract

### 5.1 REST endpoints (authoritative — verified against the daemon source)

All under `{base_url}/api/`:

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/auth/challenge` | none | Body `{ did }` → `{ session_id, data: { challenge } }` |
| `POST` | `/auth/` | none (JWS in body) | Body is a JWS-packed DIDComm message → `{ access_token, refresh_token, expires_in }` |
| `POST` | `/auth/refresh` | none (JWS in body) | Body is a JWS-packed DIDComm refresh message → same token shape |
| `POST` | `/dids` | Bearer | Body `{ path, domain? }` → reserves a path slot (was called "request-uri" in the original draft) |
| `POST` | `/dids/check` | Bearer | Body `{ path, domain? }` → `{ ok, reason? }` — validate before reserve |
| `POST` | `/dids/register` | Bearer | Body `{ method?, path, did_data, force?, domain? }` → atomic claim-and-publish. `did_data` is opaque bytes/JSON whose shape depends on the parsed method (JSONL for webvh, JSON for web). `method` optional and inferred from the embedded DID; explicit value, if present, must match. |
| `PUT` | `/dids/{*mnemonic}` | Bearer | Body = did.jsonl (text/plain) → publish (update) a DID log |
| `DELETE` | `/dids/{*mnemonic}` | Bearer | Delete a DID (owner or admin) |
| `GET` | `/{*mnemonic}/did.jsonl` | none | Returns did.jsonl bytes for webvh resolution. Served by the catch-all `serve_public` handler (`webvh-server/src/routes/did_public.rs:150`), not a prefix-mounted route. |
| `GET` | `/{*mnemonic}/did.json` | none | Returns did.json bytes for did:web resolution. Same catch-all handler dispatches on the `.json` suffix at line 182. |
| `GET` | `/.well-known/did.json` | none | No-path did:web resolution (the `__root` mnemonic case). |

> **Discrepancy with the original gist.** The original spec mentioned `POST /log/atomic`, `GET /request-uri/{did}`, `GET /check-path/{path}`, `POST /log/{did}` for publish. Those names matched an earlier daemon revision. The list above is the **current** daemon (verified at `did-hosting-control/src/routes/mod.rs`). The client crate implements these, not the historical names.

Out of scope for v0.1 (visible in the daemon but client doesn't ship them yet): `/owner/{*mnemonic}` (change owner), `/disable/{*mnemonic}` (disable), `/enable`, `/rollback`, `/raw`, `/stats`, `/timeseries`, `/services/overview`, `/config`. Add in a v0.2+ as integrator demand drives.

### 5.2 Trust-Tasks transport (REST)

Every REST call sets the `Trust-Task:` HTTP header carrying the canonical URL for the operation. Routing on the daemon side is exact-match per `verifiable-trust-infrastructure/vti-common/src/trust_task/`. Constants:

```rust
// did-hosting-client/src/auth/mod.rs (auth-related — public so integrators can match)
pub const TASK_AUTH_CHALLENGE_1_0: &str =
    "https://trusttasks.org/did-hosting/auth/challenge/1.0";
pub const TASK_AUTH_AUTHENTICATE_1_0: &str =
    "https://trusttasks.org/did-hosting/auth/authenticate/1.0";
pub const TASK_AUTH_REFRESH_1_0: &str =
    "https://trusttasks.org/did-hosting/auth/refresh/1.0";

// did-hosting-client/src/client.rs (DID-ops — public for integrator wireshark-equivalence)
pub const TASK_DID_REQUEST_URI_1_0: &str =
    "https://trusttasks.org/did-hosting/did/request-uri/1.0";
pub const TASK_DID_CHECK_PATH_1_0: &str =
    "https://trusttasks.org/did-hosting/did/check-path/1.0";
pub const TASK_DID_REGISTER_ATOMIC_1_0: &str =
    "https://trusttasks.org/did-hosting/did/register-atomic/1.0";
pub const TASK_DID_PUBLISH_1_0: &str =
    "https://trusttasks.org/did-hosting/did/publish/1.0";
pub const TASK_DID_DELETE_1_0: &str =
    "https://trusttasks.org/did-hosting/did/delete/1.0";
pub const TASK_DID_RESOLVE_1_0: &str =
    "https://trusttasks.org/did-hosting/did/resolve/1.0";
```

These constants are mirrored by the daemon (see `docs/multi-domain-spec.md` §5 `did_hosting_tasks.rs`); the client lib is the source of truth for the **same** strings from the client side. A `cargo test --workspace` invariant asserts every client const string-equals the corresponding daemon const (cross-crate test) so drift is caught at CI.

### 5.3 DIDComm JWS body shapes

For `/auth/` and `/auth/refresh`, the request body is the **serialized JWS** of a DIDComm v2 Message, signed EdDSA / Ed25519. The DIDComm `type` field uses the Trust-Task URL directly:

**Authenticate** — `type: https://trusttasks.org/did-hosting/auth/authenticate/1.0`

```json
{
  "id": "<uuid>",
  "type": "https://trusttasks.org/did-hosting/auth/authenticate/1.0",
  "from": "<caller_did>",
  "to": ["<server_did>"],
  "created_time": <unix_seconds>,
  "body": { "session_id": "<uuid>", "challenge": "<base64url-32>" }
}
```

**Refresh** — `type: https://trusttasks.org/did-hosting/auth/refresh/1.0`

```json
{
  "id": "<uuid>",
  "type": "https://trusttasks.org/did-hosting/auth/refresh/1.0",
  "from": "<caller_did>",
  "to": ["<server_did>"],
  "created_time": <unix_seconds>,
  "body": { "refresh_token": "<opaque>" }
}
```

Notes:
- `to: [server_did]` is populated even though current daemons don't verify it — defence-in-depth against cross-daemon replay. The multi-domain release will start verifying it; the client must always set it.
- `created_time` is required; daemon allows 5min past / 60s future skew (`did-hosting-control/src/routes/auth.rs`).

### 5.4 HTTPS rule

`Client::new(base_url, server_did)` rejects any non-`https://` scheme **except** when `url::Url::host()` returns `url::Host::Domain("localhost")` or `url::Host::Ipv4` / `Ipv6` whose `is_loopback()` returns true. Don't roll a string allowlist — the IPv6 `[::1]` form fails it. Error names the bad URL and suggests the fix.

```rust
// did-hosting-client/src/transport.rs
pub fn enforce_transport_security(url: &Url) -> Result<(), ClientError> {
    if url.scheme() == "https" { return Ok(()); }
    let host = url.host().ok_or_else(|| ClientError::Validation(...))?;
    if is_loopback_host(&host) { return Ok(()); }
    Err(ClientError::Validation(format!(
        "non-HTTPS base URL not allowed for non-loopback host: {url} \
         (use https:// in production; localhost or 127.0.0.1 / [::1] for dev)"
    )))
}

fn is_loopback_host(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(s) => *s == "localhost",
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    }
}
```

### 5.5 Reference implementation map

Every module called out below has a working implementation in `verifiable-trust-infrastructure` on branch `feat/webvh-rest-auth-hardened`. Verified file sizes as of writing:

| New `did-hosting-client` module | Crib from | Source LOC |
|---|---|---|
| `auth/message.rs` | `vta-service/src/webvh_auth.rs` (entire file) | 359 |
| `auth/mod.rs` types | `webvh_auth.rs::VtaSigningIdentity{,Owned}` (rename to `HostingSigningIdentity` — drop `Vta` prefix) | (subset of above) |
| `transport.rs` | `vta-service/src/operations/did_webvh/transport.rs` | 307 |
| HTTPS enforcement | `vta-service/src/webvh_client.rs::{enforce_transport_security, is_loopback_host}` | (subset, ~50 LOC) |
| `client.rs` REST methods | `vta-service/src/webvh_client.rs::WebvhClient` | 945 (≈400 of which is auth/HTTPS/types already in scope above) |
| `error.rs` | `webvh_client.rs::map_auth_failure` + the `send` method's status-code matching | (~80 LOC) |
| `token_store.rs` decision ladder | `vta-service/src/operations/did_webvh/auth_cache.rs::ensure_fresh_access_token` (port the logic, swap concrete `WebvhServerStore` for the new trait) | 361 |
| `locks.rs` | `vta-service/src/operations/did_webvh/auth_cache.rs::WebvhAuthLocks` (near-verbatim) | ~30 |

Audit doc reference: `verifiable-trust-infrastructure/docs/05-design-notes/webvh-rest-auth-audit.md`.

## 6. Public API surface

### 6.1 Identity

```rust
// Caller-supplied signing identity. Borrowed form for hot paths; owned form
// (with Zeroizing<[u8; 32]>) for stashing across awaits.
pub struct HostingSigningIdentity<'a> {
    pub did: &'a str,           // base DID, no fragment
    pub signing_kid: &'a str,   // fully-qualified `did#fragment`
    pub private_key: &'a [u8; 32],
}

pub struct HostingSigningIdentityOwned { /* Zeroizing seed inside */ }

impl HostingSigningIdentityOwned {
    pub fn as_ref(&self) -> HostingSigningIdentity<'_>;
}
```

### 6.2 Token store and locks

```rust
#[derive(Clone)]
pub struct TokenData {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: u64,  // unix seconds, absolute
}
// MUST derive ZeroizeOnDrop; MUST hand-roll Debug to redact both tokens.

#[async_trait]
pub trait HostingTokenStore: Send + Sync {
    async fn get(&self, server_id: &str) -> Result<Option<TokenData>, ClientError>;
    async fn put(&self, server_id: &str, tokens: TokenData) -> Result<(), ClientError>;
    async fn clear(&self, server_id: &str) -> Result<(), ClientError>;
}

pub struct InMemoryTokenStore { /* DashMap<String, TokenData> */ }
impl Default for InMemoryTokenStore { ... }
impl HostingTokenStore for InMemoryTokenStore { ... }

pub struct ServerLocks { /* DashMap<String, Arc<TokioMutex<()>>> */ }
impl ServerLocks {
    pub fn new() -> Self;
    pub fn for_server(&self, server_id: &str) -> Arc<TokioMutex<()>>;
}
```

`server_id` is whatever stable identifier the integrator uses to disambiguate daemons (typically the server DID). Both stores key on this string opaquely — they don't parse it.

### 6.3 Transport resolution

```rust
pub trait ServiceEntry {
    fn types(&self) -> &[String];
    fn endpoint_uri(&self) -> Option<String>;
}

pub enum ResolvedTransport {
    DIDComm,
    Rest { url: String },
}

pub fn resolve_server_transport<S: ServiceEntry>(svcs: &[S]) -> Option<ResolvedTransport>;
```

Behaviour (per the reference impl):
- Iterate services; first DIDComm match (`type` contains `DIDCommMessaging`) wins outright.
- Else first `WebVHHosting` (canonical) **or** `WebVHHostingService` (legacy alias accepted on read only) match.
- Strip surrounding `"` and trailing `/` from `endpoint_uri`.
- Returns `None` if nothing matches.

### 6.4 Errors

```rust
#[derive(thiserror::Error, Debug)]
pub enum ClientError {
    #[error("authentication failed: {0}")]      Auth(String),
    #[error("forbidden: {0}")]                  Forbidden(String),
    #[error("not found: {0}")]                  NotFound(String),
    #[error("conflict: {0}")]                   Conflict(String),
    #[error("validation: {0}")]                 Validation(String),
    #[error("network: {0}")]                    Network(String),
    #[error("server error: {0}")]               Server(String),
    #[error("protocol: {0}")]                   Protocol(String),
}
```

Mapping rules in the internal `send` helper:
- 401 → `Auth`
- 403 → `Forbidden`
- 404 → `NotFound`
- 409 → `Conflict`
- Other 4xx → `Validation`
- 5xx → `Server`
- `reqwest::Error` (DNS / TLS / connect / timeout) → `Network`
- Body deserialization failure on a 2xx → `Protocol`

Consumers `match` on the enum; we never collapse into a string.

### 6.5 `Client`

```rust
pub struct Client { /* reqwest::Client, base_url: Url, server_did: String, default_domain: Option<String> */ }

impl Client {
    /// HTTPS enforcement runs here. Fails fast at construction.
    pub fn new(base_url: &str, server_did: &str) -> Result<Self, ClientError>;

    /// Sets a default `domain` forwarded on every call that takes one.
    /// Per-call `Some("…")` overrides; per-call `None` falls back to this default.
    pub fn with_default_domain(self, domain: impl Into<String>) -> Self;

    // ── Auth primitives (usually called via the cached helpers below) ──
    pub async fn challenge(&self, did: &str)
        -> Result<ChallengeResponse, ClientError>;
    pub async fn authenticate(&self, identity: &HostingSigningIdentity<'_>)
        -> Result<TokenData, ClientError>;
    pub async fn refresh(&self, refresh_token: &str)
        -> Result<TokenData, ClientError>;

    // ── Cached-auth helpers ── owns the decision ladder
    pub async fn ensure_token(
        &self,
        server_id: &str,
        identity: &HostingSigningIdentity<'_>,
        store: &dyn HostingTokenStore,
        locks: &ServerLocks,
    ) -> Result<String, ClientError>;

    // ── Domain ops ── each takes &str access_token, sends, and on 401 returns
    // ClientError::Auth so the caller's RMW can invalidate + retry once.
    pub async fn publish_did(
        &self,
        mnemonic: &str,
        did_data: &[u8],                 // bytes per the resolved method (JSONL for webvh, JSON for web)
        method: Option<&str>,            // optional explicit method; otherwise inferred from did_data
        token: &str,
        domain: Option<&str>,
    ) -> Result<(), ClientError>;

    pub async fn delete_did(
        &self,
        mnemonic: &str,
        token: &str,
        domain: Option<&str>,
    ) -> Result<(), ClientError>;

    pub async fn register_did_atomic(
        &self,
        body: &RegisterAtomicBody,       // see §6.5.1 below for full shape
        token: &str,
    ) -> Result<RegisterAtomicResponse, ClientError>;

    pub async fn request_uri(
        &self,
        path: &str,
        token: &str,
        domain: Option<&str>,
    ) -> Result<RequestUriResponse, ClientError>;

    pub async fn check_path(
        &self,
        path: &str,
        token: &str,
        domain: Option<&str>,
    ) -> Result<CheckPathResponse, ClientError>;

    pub async fn get_did(&self, mnemonic: &str, method: &str)
        -> Result<Vec<u8>, ClientError>;  // unauthenticated; method picks the resolution path
}
```

#### 6.5.1 `RegisterAtomicBody`

```rust
#[derive(Debug, Serialize)]
pub struct RegisterAtomicBody {
    /// Optional; if omitted the daemon infers from `did_data`'s embedded
    /// identifier. If present, must match the embedded method or the daemon
    /// rejects with 400.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    pub path: String,
    pub did_data: serde_json::Value,     // shape per method (JSON for web; JSONL string for webvh)

    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default)]
    pub force: bool,
}
```

The `Option<&str> domain` resolution rule per call:
1. Per-call `Some("…")` wins.
2. Else use `default_domain` from `with_default_domain`.
3. Else send no `domain` field — daemon resolves via caller's ACL default (per `docs/multi-domain-spec.md` §3).

The mnemonic is **not** the full DID — it's the multi-segment path portion the daemon's `*mnemonic` route captures (e.g. `did:webvh:<scid>:example.com:tenant:user1` → mnemonic `tenant/user1`). The client crate exposes a helper `webvh_mnemonic_from_did(did: &str) -> Result<&str, ClientError>` since this is easy to get wrong.

### 6.6 Optional convenience wrapper

`AuthedClient` — a thin wrapper that holds `(Client, HostingSigningIdentityOwned, Arc<dyn HostingTokenStore>, Arc<ServerLocks>)` and exposes the same DID-ops methods without the explicit `token: &str`. Internally it calls `ensure_token` + the underlying method, and on `ClientError::Auth` invalidates the cache and retries once. Recommended path for most integrators; keeps the per-call surface available for advanced use cases.

```rust
impl AuthedClient {
    pub async fn publish_did(&self, mnemonic: &str, did_data: &[u8], method: Option<&str>, domain: Option<&str>)
        -> Result<(), ClientError>;
    // ... mirrors Client's DID-ops surface, omitting `token` ...
}
```

## 7. Behaviours that must be preserved

These are the load-bearing details the reference impl already gets right. Do not lose them in the port.

1. **Decision ladder in `ensure_token`**:
   - Read `store.get(server_id)`.
   - If `expires_at - now > 30s`: use the cached access_token.
   - Else try `refresh(refresh_token)`. If `Ok(new)`: persist via `store.put`, return new access.
   - If `refresh` returns `ClientError::Auth`: fall through to full `challenge` → `authenticate`. Persist new tokens. Return access.
   - Hold the per-server `ServerLocks` mutex around the **entire** read-modify-write. Two parallel `ensure_token` calls against the same server must serialise — wiremock test asserts a single authenticate call count.

2. **HTTPS enforcement runs in `Client::new`**, not at first call. Construction fails fast on a misconfigured base URL.

3. **Error mapping** in the internal `send` helper exactly as in §6.4. Don't shortcut to `String`.

4. **`TokenData` is `ZeroizeOnDrop` + redacted `Debug`.** Both are easy to forget; ship them by default. A unit test asserts the `Debug` impl does not contain either token substring.

5. **Transport resolution** accepts both `WebVHHosting` (canonical) and `WebVHHostingService` (legacy alias) on read. Strip surrounding `"` and trailing `/` from `endpoint_uri` before returning.

6. **DIDComm `to: [server_did]`** populated even though current daemons don't verify it — defence-in-depth for cross-daemon replay. Future multi-domain daemons start verifying.

7. **`Trust-Task:` header on every REST request.** Set by the internal request builder, not per-method, so a future contributor can't forget on a new method. The header value is the canonical URL const from §5.2.

8. **`created_time` always populated** in DIDComm bodies; uses current unix seconds. No clock skew on the client side — the server allows the window.

## 8. Domain + method awareness

### 8.1 Domain (multi-domain integration)

Per `docs/multi-domain-spec.md` resolution rule:
- The client never invents a default — `with_default_domain` is opt-in.
- If `domain` is omitted on the wire, the daemon falls back to the caller's ACL default. The client does not second-guess.
- For `register_did_atomic`, the `domain` field on the request body is the source of truth — the embedded `did:{method}:…:<host>:…` host must match the named domain. Daemon rejects on mismatch (per multi-domain spec §3 safety check). The client crate **does not validate this client-side** — let the daemon enforce, and surface its 400 as `ClientError::Validation` so the integrator sees the daemon's exact reason.
- For `publish_did` / `delete_did` / resolution, the domain is determined by the DID's host segment; the explicit `domain` parameter is only used as a sanity check on the request body, optional.

### 8.2 Method (multi-method integration)

Per `docs/multi-method-hosting-spec.md`:
- The client crate does not parse the DID's method itself for routing decisions — the daemon does. The client's only method-aware code path is the resolution helper `get_did(mnemonic, method)`, which picks the correct resolution URL pattern (webvh → `/{mnemonic}/did.jsonl`; web → `/{mnemonic}/did.json` or `/.well-known/did.json` for `__root`).
- For `register_did_atomic` and `publish_did`, the optional `method` argument is forwarded verbatim if present. If omitted, the daemon infers from the embedded identifier in `did_data`. If both are present and disagree, the daemon rejects.
- `did_data` is `Vec<u8>` (publish) / `serde_json::Value` (register-atomic). The client does not validate its shape per method — that's the daemon's contract enforcement boundary.
- The client crate is method-agnostic: enabling more methods on the daemon side requires no client-side update beyond the integrator's own awareness of the new method name string.

## 9. Testing strategy

### 9.1 Unit

- `transport.rs`: stub `ServiceEntry` impls cover DIDComm-wins, legacy-alias-accepted, quote-stripping, trailing-slash-stripping, no-services-returns-None.
- `auth/message.rs`: golden JWS shape — build, deserialize after, assert `from` / `to` / `type` / `body` / `created_time` exact.
- `is_loopback_host`: `127.0.0.1`, `::1`, `localhost`, and a public IP all classified correctly.
- `TokenData::Debug` redaction: assert neither token substring appears in `format!("{tok:?}")`.
- `Client::new` HTTPS enforcement: `http://example.com` rejected, `http://localhost:3000` accepted, `http://[::1]:3000` accepted, `https://example.com` accepted.

### 9.2 Integration (wiremock)

- Challenge / authenticate happy path against a wiremock server: returns access+refresh, verifies JWS body received by mock.
- Refresh happy path.
- Publish returns 401 → caller's RMW invalidates cache, calls `authenticate`, retries publish — total wiremock call count asserted.
- 403 bubbles as `ClientError::Forbidden` without retry.
- Network error (mock down) maps to `ClientError::Network`.
- 5xx mapped to `ClientError::Server`.
- `domain` parameter forwarded correctly on `register_did_atomic`, `request_uri`, `check_path`.

### 9.3 `ensure_token` decision ladder

- Fresh cache (expires_at - now > 30s) → no network call, returns cached.
- Expired access + valid refresh → refresh succeeds, store updated, returns new access.
- Expired access + refresh returns 401 → falls back to authenticate, store updated.
- Both fail → propagates the final error from authenticate.

### 9.4 Concurrency

- Two parallel `ensure_token` calls against the same server_id serialise (single authenticate call observed via wiremock counter).
- Two parallel calls against different server_ids do not serialise (both complete in parallel).

### 9.5 Cross-crate invariant

A `did-hosting-common/tests/` test asserts every `TASK_*` const in `did-hosting-client` matches the equivalent daemon-side const in `did-hosting-common/src/did_hosting_tasks.rs` (multi-domain spec §5). Catches URL drift at workspace build time.

### 9.6 Coverage expectation

≥ 80% line coverage on the client crate. No regression elsewhere.

## 10. Boundaries

**Always:**
- Run `cargo fmt`, `cargo clippy --workspace --all-targets`, full test suite before committing (repo CLAUDE.md).
- DCO sign-off via `-s` on every commit.
- Update both client and daemon `TASK_*` consts in the same PR — the cross-crate invariant test will catch drift, but the right pattern is "edit both in lock-step."
- Surface daemon errors verbatim where possible — the integrator's debugging story depends on the daemon's reason strings reaching them. Don't synthesise replacement messages.
- Treat the wire contract (§5) as a published API — any change requires a `min` bump on the affected Trust-Task URL **and** a client version bump.

**Ask first:**
- Adding any dependency beyond what's listed in §3.
- Changing the `HostingTokenStore` trait surface (integrators implement this; renames are breaking).
- Adding admin operations to the v0.1 surface (out of scope; let demand drive a v0.2 `AdminClient`).
- Adding a default token store backend beyond `InMemoryTokenStore`.

**Never:**
- Pull in `did-hosting-common` as a dep. The client crate must be consumable by integrators who don't use the daemon code at all.
- Take a hard dep on tokio in the public API surface beyond `tokio::sync::Mutex` inside `ServerLocks`. The trait surface stays runtime-agnostic.
- Log token values, even at trace level.
- Cache anything beyond `TokenData` server-side (no DID-doc cache, no resolution cache) — that's the integrator's job and varies wildly.
- Speak v1.0 `MSG_*` URLs. v0.1 of this crate is Trust-Tasks-only.
- Validate the multi-domain `did.host` vs `domain` parameter client-side. Let the daemon enforce; bubble the 400.

## 11. Decision log

| # | Question | Resolution |
|---|---|---|
| C1 | Crate location | Sibling workspace member in this repo (`did-hosting-client/`, published as `did-hosting-client`). |
| C2 | Wire identifiers at v0.1 | Trust-Tasks URLs only, under `trusttasks.org/did-hosting/...`. Targets the renamed-multi-domain-multi-method daemon. |
| C3 | Domain API shape | `Client::with_default_domain(d)` + optional per-call `domain: Option<&str>`. |
| C4 | Method API shape | Optional `method: Option<&str>` per call on publish + register-atomic + get-did. Daemon infers from `did_data` if omitted. Client crate stays method-agnostic; only resolution-URL selector in `get_did` knows about per-method URL patterns. |
| C5 | Release sequencing | Ships in the same tag as the multi-domain + multi-method + repo-rename release. |
| C6 | Admin operations in v0.1? | No. v0.1 = DID-owner-shaped operations. Admin client lands separately. |
| C7 | CLI binary? | No. Library crate only in v0.1. |
| C8 | Token-store backends shipped? | `InMemoryTokenStore` only. Trait surface lets integrators add their own. |
| C9 | Runtime lock-in? | tokio is required for `ServerLocks` (uses `tokio::sync::Mutex`); trait surfaces stay runtime-agnostic. |

No open questions at the time of this draft.

## 12. Risks

- **Reference impl drift while we port.** `verifiable-trust-infrastructure` branch `feat/webvh-rest-auth-hardened` continues to evolve. Mitigation: pin the source commit in the PR description; do the port in one focused session rather than spread over weeks; the audit doc (`webvh-rest-auth-audit.md`) is treated as the canonical statement of intent, not the code itself.
- **Cross-crate URL drift.** Daemon-side `TASK_*` consts (in `did-hosting-common`) and client-side `TASK_*` consts (in `did-hosting-client`) can drift. Mitigation: the cross-crate invariant test in §9.5 catches this at workspace build.
- **Integrator misuse of `with_default_domain`.** An integrator who sets the default and forgets they did so may publish to the wrong domain when reusing the same `Client` across tenants. Mitigation: `with_default_domain` is opt-in; the README example uses per-call `Some("…")` for multi-tenant flows.
- **Token store contention under high parallelism.** `ServerLocks` is per-server-id, so two heavy tenants on different servers don't serialise. Two tenants on the **same** server serialise their auth ladders; that's by design (single in-flight authenticate per server). Mitigation: documented in the rustdoc on `ServerLocks::for_server`.
- **`reqwest` rustls-only TLS choice.** Some integrators expect openssl-native-tls. Mitigation: documented; integrators who need native-tls fork or wait for a feature flag (out of scope for v0.1).

## 13. References

- `docs/multi-domain-spec.md` — companion spec; Trust-Tasks transport and multi-domain semantics live there.
- `verifiable-trust-infrastructure` branch `feat/webvh-rest-auth-hardened`:
  - `vta-service/src/webvh_auth.rs`
  - `vta-service/src/webvh_client.rs`
  - `vta-service/src/operations/did_webvh/transport.rs`
  - `vta-service/src/operations/did_webvh/auth_cache.rs`
  - `docs/05-design-notes/webvh-rest-auth-audit.md`
- `did-hosting-control/src/routes/mod.rs` — authoritative daemon route map (this repo).
- `did-hosting-control/src/routes/auth.rs` — challenge / authenticate / refresh implementation.
- `verifiable-trust-infrastructure/vti-common/src/trust_task/` — canonical Trust-Task Rust types.
- RFC 7515 — JSON Web Signature, used by the DIDComm v2 signed-message envelope.
