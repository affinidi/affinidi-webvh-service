# Spec: Multi-Method DID Hosting + Repo Rename

Status: Draft — awaiting review
Scope: Repository rename + multi-DID-method support. Ships in the same release tag as `docs/multi-domain-spec.md` and `docs/webvh-client-crate-spec.md`.
Author: glenn.gore@gmail.com

This spec sits **alongside** the multi-domain and client specs. Read those first for context — this one focuses on what's different when you stop being webvh-only.

## 1. Objective

Generalise the hosting service from "webvh-specific" to "any DID method that delivers via HTTPS". The default build supports `did:webvh` and `did:web`. `did:webs` and `did:webplus` are mentioned as future targets with scaffolded compile-time feature flags, but no implementation in this release.

Concretely:

- **Repo rename**: `affinidi-webvh-service` → `did-hosting-service`. Method-agnostic crates rename to `did-hosting-*`. Method-specific crates keep their method prefix.
- **Method abstraction**: a `DidMethod` trait carries identifier parsing, resolution URL pattern, storage shape, validation, and lifecycle semantics. Per-method impls live behind Cargo features.
- **Compile-time gating**: `--features method-webvh,method-web` is the default. `method-webs` / `method-webplus` exist as feature flags compiled out by default; their impls are stubs.
- **No management-API URL changes**: routes stay; request body field names generalise (`did_log` → `did_data`).
- **Per-method resolution endpoints**: webvh — `GET /{*mnemonic}/did.jsonl` already dispatched via the catch-all at `webvh-server/src/routes/did_public.rs:150` (suffix-stripping fallback, not a prefix-mounted route). web — `GET /{*mnemonic}/did.json` is **already partially implemented** at `did_public.rs:182` via `serve_did_web()`; this release formalises that handler through the `DidMethod` trait. `GET /.well-known/did.json` lands for the no-path did:web case.
- **UX**: method selector on DID create flow, method column / badge in lists, conditional per-method actions on the detail view.

### Why

The hosting infrastructure (ACL, auth, domains, control plane, sync, UI shell, audit log) is method-agnostic. Coupling it to one DID method means standing up parallel hosting for every method an operator wants to support. Lifting the method into an abstraction lets one deployment serve `did:web` and `did:webvh` from the same domains, same ACL, same control plane, same UI.

The rename is mechanically painful but cheap to delay-cost: the longer we wait, the more `webvh-*` names leak into integrators' code, docs, terraform, monitoring dashboards, etc. Bundling with the multi-domain + Trust-Tasks + client-crate release means one big-bang migration for operators rather than three or four.

## 2. Non-goals

- **Shipping `did:webs` or `did:webplus`.** The feature flags exist and the trait surface accommodates them, but the per-method modules are stubs that fail to build with a clear "not implemented in this release" message if enabled.
- **DID portability across methods.** A `did:web:example.com:user1` and a `did:webvh:scid:example.com:user1` are *different DIDs* even at the same domain/path — there is no "convert my did:web to did:webvh" tool.
- **Resolution gateway for *external* DIDs.** This service hosts DIDs registered through it; it does not become a generic DID resolver that fetches arbitrary `did:web:other.example.com` documents from other operators.
- **Method-specific witness/watcher generalisation.** Witness and watcher remain webvh-protocol features. `did:web` has no witness concept — UI hides those actions for did:web DIDs but we do not invent a method-neutral witness abstraction.
- **`did:web` log of history.** `did:web` has no on-chain log; updates overwrite. We do not synthesise a log to mimic webvh.
- **Renaming `didwebvh-rs`.** That's an external dependency we consume; renaming it is out of scope for this repo.

## 3. Resolved decisions

| Question | Decision |
|---|---|
| Repo name | `did-hosting-service`. |
| Crate naming | Method-agnostic crates → `did-hosting-common`, `did-hosting-server`, `did-hosting-control`, `did-hosting-daemon`, `did-hosting-client` (was `webvh-client/`), `did-hosting-ui`. Method-specific crates keep their method prefix: `webvh-witness`, `webvh-watcher`. (When a future method needs analogous tooling it gets `{method}-witness` etc.) |
| Workspace folder names | Match crate names. `webvh-common/` → `did-hosting-common/`. Single `git mv` per crate, plus a workspace-wide `Cargo.toml` rewrite. |
| Default-enabled methods | `method-webvh` + `method-web`. |
| Off-by-default methods (scaffolded) | `method-webs`, `method-webplus`. Stub modules; enabling them gives a clear compile error pointing at the missing impl. |
| Storage model | **Single `dids` keyspace** with method-tagged value: `DidRecord { method: String, domain: String, path: String, content_type: String, data: Vec<u8>, version: u64, created_at, updated_at }`. Per-method validators run on read/write. (Composite-keyed multi-keyspace was considered and rejected — would have multiplied backup paths and iteration code.) |
| Trust-Tasks URL namespace | **Generic ops** under `https://trusttasks.org/did-hosting/{path}/{maj}.{min}`. **Method-specific ops** under `https://trusttasks.org/webvh/{path}/{maj}.{min}` (and `webs/`, `webplus/` if/when enabled). `affinidi/` org segment is **dropped** per user direction; the workspace's namespace label sits directly under `trusttasks.org/`. |
| Management API URLs | Unchanged. `POST /api/dids/register` etc. stay; body shapes generalise to `did_data: Value`. |
| Method detection | Parsed from the DID identifier embedded in the request payload (or from the path for resolution). Method is **never** taken from a body field that contradicts the embedded DID. Mismatch → 400. |
| Per-method resolution endpoints | Single suffix-stripping catch-all (`serve_public` at `webvh-server/src/routes/did_public.rs:150`) dispatches based on the path's trailing segment. webvh: `/{*mnemonic}/did.jsonl` already routed (line 154). web: `/{*mnemonic}/did.json` already routed via `serve_did_web` (line 182). The catch-all is gated **internally** by the `#[cfg(feature = "method-*")]` flags on the per-suffix arms — disabling a method removes its arm, the catch-all itself remains. `GET /.well-known/did.json` lands as an additional explicit route for the no-path did:web case. |
| `did:web` no-path edge case | `did:web:example.com` (no path) resolves at `/.well-known/did.json` on that domain. Registration uses a sentinel mnemonic `__root` internally to avoid empty-string keys in storage. |
| Method coexistence on a path | Permitted. `did:web:example.com:user1` and `did:webvh:scid:example.com:user1` are distinct records (different methods → different composite key path). UI surfaces both with method badges. |
| Migration story | One-shot rename + data migration: existing webvh DIDs get `method: "webvh"` written into their `DidRecord` on first boot. Backup format gains a `method` field. Old binaries cannot read new stores; release notes call this out loudly. |
| Operator-facing artifact names | Old binaries (`webvh-server`, `webvh-daemon`, etc.) get re-published as `did-hosting-server`, `did-hosting-daemon`, etc. No compat shim — operators upgrade by replacing binaries. Container images get new image names; docs land a migration guide. |
| Default `Cargo.toml` `[features]` | Workspace's `did-hosting-daemon` defaults to `["method-webvh", "method-web"]`. Standalone services match. |
| UI method awareness | `/api/config` exposes `enabled_methods: ["webvh", "web"]`. UI renders method selector / badges / conditional actions from this. |
| `webvh-witness` / `webvh-watcher` keep names | Confirmed. They're webvh-protocol concepts. Renaming them would be dishonest. |

## 4. Tech stack

- Rust 2024, rust-version 1.94 (unchanged).
- No new runtime deps for the method abstraction itself — it's a Rust trait surface with per-method modules.
- For `did:web`: requires the `id` field of the stored did.json to be parsed; reuse `serde_json::Value` (already in tree).
- The existing `didwebvh-rs` workspace dep stays where it is, consumed only when `method-webvh` is enabled.

No new database backends. No new external network deps.

## 5. Project structure

### 5.1 Rename map (mechanical)

```
affinidi-webvh-service/                  → did-hosting-service/
├── webvh-common/                        → did-hosting-common/
├── webvh-server/                        → did-hosting-server/
├── webvh-control/                       → did-hosting-control/
├── webvh-daemon/                        → did-hosting-daemon/
├── webvh-client/  (new in client spec)  → did-hosting-client/
├── webvh-ui/                            → did-hosting-ui/
├── webvh-witness/                       → webvh-witness/      (unchanged — webvh-protocol-specific)
├── webvh-watcher/                       → webvh-watcher/      (unchanged — webvh-protocol-specific)
└── docs/                                → docs/               (unchanged path)
```

Binary names follow crate names. Config files, env-var prefixes (`WEBVH_CONFIG_PATH` → `DID_HOSTING_CONFIG_PATH`), and CLI subcommands all rename in lock-step.

### 5.2 New / changed modules

```
did-hosting-common/src/
  method/                                NEW — method abstraction lives here
    mod.rs                               trait DidMethod, registry, dispatcher
    parse.rs                             parse_did_method(&str) -> Option<&str>; identifier validation
    web.rs           #[cfg(feature = "method-web")]    impl DidMethod for Web
    webvh.rs         #[cfg(feature = "method-webvh")]  impl DidMethod for Webvh
    webs.rs          #[cfg(feature = "method-webs")]   stub
    webplus.rs       #[cfg(feature = "method-webplus")] stub
  server/
    store/dids.rs                        NEW — DidRecord type + method-tagged read/write
    domain.rs                            unchanged from multi-domain spec
    acl.rs                               unchanged
  webvh_tasks.rs                         renamed → did_hosting_tasks.rs; URL consts re-namespaced

did-hosting-server/src/
  did_ops.rs                             dispatches on DidMethod for create/publish/delete/resolve
  routes/
    resolve.rs                           method-aware dispatcher; method-specific sub-modules:
      resolve_webvh.rs                   #[cfg(feature = "method-webvh")]
      resolve_web.rs                     #[cfg(feature = "method-web")]   serves /{*path}/did.json + /.well-known/did.json
    dids.rs                              register / publish / delete branch on parsed method
  config.rs                              enabled_methods is derived from features at compile time

did-hosting-control/src/
  did_ops.rs                             same generalisation
  routes/dids.rs                         same; admin "create DID" gains optional `method` field
  routes/config.rs                       /api/config exposes enabled_methods

did-hosting-daemon/src/
  main.rs                                wires all enabled methods' resolution routes
  setup.rs                               wizard asks "which methods?" with sensible defaults

did-hosting-ui/                          method selector on create flow, method column in list,
                                         method badge on detail view, conditional witness/rollback
                                         buttons (only shown for webvh DIDs)
```

### 5.3 Cargo features

`did-hosting-common/Cargo.toml`:

```toml
[features]
default = ["method-webvh", "method-web"]
method-webvh = ["dep:didwebvh-rs"]
method-web = []
method-webs = []           # stub — fails compile with clear message if enabled
method-webplus = []        # stub — fails compile with clear message if enabled
```

The other crates re-export feature flags so the daemon's `default` chains down to the common crate's `default`.

Build matrix in CI:
- `cargo build --workspace` (default features, both webvh+web)
- `cargo build --workspace --no-default-features --features method-webvh`
- `cargo build --workspace --no-default-features --features method-web`
- `cargo build --workspace --features method-webvh,method-web,method-webs` (should fail with the stub's compile error)

## 6. The `DidMethod` trait

The contract every method impl satisfies. Designed so a contributor can add `did:webs` by implementing this trait + the per-method routes + a feature flag — no patches to common code.

```rust
// did-hosting-common/src/method/mod.rs

/// One DID method's contribution to the hosting service.
pub trait DidMethod: Send + Sync + 'static {
    /// Canonical method name as it appears in `did:{name}:...`.
    /// E.g. "webvh", "web".
    const NAME: &'static str;

    /// MIME content-type the resolution endpoint returns.
    const CONTENT_TYPE: &'static str;

    /// Storage extension used when persisting raw bytes.
    /// E.g. "jsonl" for webvh, "json" for web.
    const DATA_EXT: &'static str;

    /// Parse a `did:{NAME}:...` identifier into its constituent parts.
    /// Returns Err on malformed input or method mismatch.
    fn parse_identifier(did: &str) -> Result<ParsedDid, MethodError>;

    /// Build the canonical resolution URL given a domain and mnemonic.
    /// E.g. webvh → "https://{domain}/{mnemonic}/did.jsonl"
    ///      web   → "https://{domain}/{mnemonic}/did.json"
    fn resolution_url(domain: &str, mnemonic: &str) -> String;

    /// Validate stored bytes are a well-formed document of this method.
    /// Called on register, publish, and (defensively) on resolve.
    fn validate(data: &[u8]) -> Result<(), MethodError>;

    /// Apply an update to existing stored data. For webvh, this appends
    /// a log entry to the existing jsonl. For web, this replaces the
    /// document outright. Returns the new stored bytes.
    fn apply_update(existing: Option<&[u8]>, new_data: &[u8])
        -> Result<Vec<u8>, MethodError>;
}

pub struct ParsedDid {
    pub method: &'static str,   // NAME
    pub scid: Option<String>,   // webvh has it; web doesn't
    pub domain: String,
    pub path: String,           // multi-segment, joined with ':' in the DID, '/' in URL
}

pub enum MethodError { Malformed, MethodMismatch, Validation(String), … }
```

The dispatcher:

```rust
pub fn method_by_name(name: &str) -> Option<&'static dyn DidMethod> {
    match name {
        #[cfg(feature = "method-webvh")]
        "webvh" => Some(&methods::webvh::Webvh),
        #[cfg(feature = "method-web")]
        "web" => Some(&methods::web::Web),
        _ => None,
    }
}

pub fn enabled_methods() -> &'static [&'static str] {
    // Compile-time concatenated slice of enabled NAMEs.
    &[
        #[cfg(feature = "method-webvh")] "webvh",
        #[cfg(feature = "method-web")] "web",
    ]
}
```

The route registration follows the same pattern: each method's module exposes a function that returns its routes; `did-hosting-server::server` calls each one behind a `#[cfg(feature = "...")]`.

### 6.1 Method-specific details

**`did:web`** (`did-hosting-common/src/method/web.rs`):
- `NAME = "web"`, `CONTENT_TYPE = "application/did+json"`, `DATA_EXT = "json"`.
- `parse_identifier` accepts `did:web:{domain}[:{path}]`; `scid` is always `None`.
- `resolution_url(domain, mnemonic)`:
  - `mnemonic == "__root"` → `https://{domain}/.well-known/did.json`
  - else → `https://{domain}/{mnemonic}/did.json` (with `/` between mnemonic segments)
- `validate(bytes)`: parse as JSON, assert `id` field is a `did:web:…` string matching the storage key's domain/path.
- `apply_update(existing, new)`: ignore `existing`; return `new` (overwrites).

**`did:webvh`** (`did-hosting-common/src/method/webvh.rs`):
- `NAME = "webvh"`, `CONTENT_TYPE = "application/jsonl"`, `DATA_EXT = "jsonl"`.
- `parse_identifier`: existing webvh parser; returns `scid: Some(...)`.
- `resolution_url(domain, mnemonic)` → `https://{domain}/{mnemonic}/did.jsonl`.
- `validate(bytes)`: parse line-by-line, run existing log validation chain.
- `apply_update(existing, new)`: append `new` line to `existing` (with the existing webvh log-validation step).

## 7. Routing

### 7.1 Resolution

```
/* All three handled by a single suffix-stripping catch-all
   (`serve_public` at webvh-server/src/routes/did_public.rs:150).
   Per-suffix arms are individually #[cfg]-gated. */

GET /{*mnemonic}/did.jsonl       → webvh arm  [feature = "method-webvh"]   (already at did_public.rs:154)
GET /{*mnemonic}/did.json        → web arm    [feature = "method-web"]     (already at did_public.rs:182)
GET /.well-known/did.json        → web arm    [feature = "method-web"]     (new — no-path did:web)
```

The `GET /{*path}/did.json` catch-all needs to coexist with the existing API surface under `/api/`. Both methods get registered behind their `#[cfg]` gates. The router merges in priority order: `/api/...` and `/.well-known/...` first (specific), `/{*path}/did.json` last (catch-all). Existing routes are unaffected.

When both features are off (degenerate config), no resolution routes are mounted — daemon still runs, just hosts nothing. Useful for control-only deployments.

### 7.2 Management API (unchanged URLs, generalised bodies)

| Method | Path | Body changes |
|---|---|---|
| `POST` | `/api/dids` | Accepts `{ method?: "web"\|"webvh", path, domain? }`. If omitted, method defaults to system default (webvh in mixed deployments for backwards compat). |
| `POST` | `/api/dids/check` | Same shape; checks per-method availability. |
| `POST` | `/api/dids/register` | `{ method?: "web"\|"webvh", path, domain?, did_data: <opaque bytes / Value>, force? }`. Old `did_log: String` field accepted as an alias when `method = "webvh"` for backwards compat through one minor release. |
| `PUT` | `/api/dids/{*mnemonic}` | Body shape per method, content-type-discriminated: `application/jsonl` → webvh, `application/json` → web. |
| `DELETE` | `/api/dids/{*mnemonic}` | Method derived from stored record. No body. |

Method is derived first from `did_data`'s embedded identifier (`state.id` or `id`), second from an explicit `method` field, third from system default. Mismatch between (1) and (2) → 400.

## 8. UX

- **DID list view** gains a `Method` column with a coloured badge (e.g. webvh = teal, web = neutral). Sortable + filterable.
- **DID create flow** opens with a method selector at the top of the dialog (radio group, ordered by `enabled_methods()` from `/api/config`). Selecting a method changes the form below — webvh shows the SCID-generation flow, web shows a simpler "upload did.json" form.
- **DID detail view** shows the method badge. Webvh-specific actions (witness publish, rollback, raw-log) are conditionally rendered only when the record's method is `webvh`. For web, the only available actions are publish-update (replace doc), delete, change-owner.
- **Setup wizard** (one-shot for `did-hosting-daemon`) asks the operator which methods they want enabled. Mentions feature-flag rebuild is required to change later. Sensible default (both webvh + web on).
- **Migration banner** (post-rename-upgrade) on the dashboard explaining "this deployment now supports did:web in addition to did:webvh; existing DIDs are unchanged."

## 9. Implementation phases

The work ships as **one tagged release** alongside multi-domain and the client crate. Phase numbers extend the multi-domain phasing.

### 9.1 Phase R — Repo rename (mechanical)

Rename folders, update `Cargo.toml` workspace member list, rewrite `pub use` paths, fix `env!` macro references, rewrite test fixture paths, regenerate `Cargo.lock`. No behavior change.

Acceptance:
- `cargo build --workspace --all-features` succeeds.
- Full test suite passes.
- Env-var renames documented in CHANGELOG with compat note.

### 9.2 Phase M1 — Method abstraction (no new method enabled)

Introduce the `DidMethod` trait, the dispatcher, and the `methods/webvh.rs` impl that wraps existing webvh logic. Storage gains `DidRecord { method, ... }` with `method = "webvh"` for all existing entries via the migration in §10. Routes still hardcoded to webvh — no `method-web` yet.

Acceptance:
- All existing webvh tests pass behind the trait surface.
- The `dids` keyspace stores `DidRecord`s with `method = "webvh"` after migration.
- `cargo build --no-default-features --features method-webvh` produces the same binary surface as default builds today.

### 9.3 Phase M2 — `did:web` method

**Audit first**, then formalise. T23 audit findings (commit history; landed alongside this commit): the existing `serve_did_web()` at `did-hosting-server/src/routes/did_public.rs:76` is **not** a standalone did:web handler — it's a **did:webvh → did:web bridge**. It reads the same `content_log_key(mnemonic)` jsonl that did:webvh resolution uses, then extracts a did:web-shaped snapshot via `did_ops::extract_did_web_document` matched against the document's `alsoKnownAs`. It exists so a tenant who hosts did:webvh can also expose a did:web view for cross-compatibility with older resolvers.

T24's `methods/web.rs` (this release) is a **separate**, standalone did:web — overwrite semantics, no jsonl backing, independent storage. Both paths must coexist:

- **Tenant has did:webvh AND wants a did:web view** → existing bridge (`serve_did_web`).
- **Tenant only wants did:web** (no log, simpler storage) → T24's `methods/web.rs` via the trait-routed path that lands with T25.

The dispatch decision at request time will be made by T25's per-method route registration based on the stored `DidRecord`'s method tag (T12). Until T25 ships, the existing bridge keeps serving `*/did.json` requests; the trait-routed path is a separate write surface (`Web::apply_update`) with its own future read path. **Decision: wrap, don't remove.**

Acceptance:
- Audit recorded inline at `did_public.rs:71-104` rustdoc + this spec section.
- New DID created via `POST /api/dids/register` with `method = "web"` resolves at `/{path}/did.json`.
- No-path did:web (`__root` mnemonic) resolves at `/.well-known/did.json`.
- Method-mismatch between `did_data.id` and `method` field rejects with 400.
- Existing did:webvh-bridged did:web call paths unchanged in observable behaviour.

### 9.4 Phase M3 — UX (method-aware)

Method column / badge / selector / conditional actions per §8. Setup wizard updated.

Acceptance:
- Manual checklist run: create a did:web and a did:webvh under the same domain, both appear in the list with correct badges, did:web detail view does **not** show witness/rollback buttons.

### 9.5 Phase M4 — Stub feature flags + CI matrix

Add `methods/webs.rs` and `methods/webplus.rs` as stubs with `compile_error!("method-webs is not implemented; see docs/multi-method-hosting-spec.md")`. Wire the build matrix into CI to assert non-default feature combinations build (or fail with the expected stub message).

Acceptance:
- CI passes the matrix.
- An external contributor who runs `cargo build --features method-webs` sees the clear error pointing to the spec.

## 10. Data migration

One-shot migration runs on first boot at the new version. Triggers when the `dids` keyspace's values do not yet have a `method` field (legacy webvh-only shape).

1. Read every legacy `did_log` value.
2. Wrap in `DidRecord { method: "webvh", domain: <derived>, path: <derived>, data: <bytes>, ... }`.
3. Write back to the same key.

Migration is idempotent (skip if the value already deserialises as `DidRecord`). Backup format (`webvh-server/src/backup.rs`) gains a `method` field on each record — restores cleanly into the new code; old backups read with `method = "webvh"` default.

The composition with the multi-domain migration (multi-domain spec §6.5) runs in order: multi-domain migration first (assigns `domain`), then multi-method migration (tags `method`). Both are idempotent and audited.

## 11. Code style

```rust
// did-hosting-common/src/method/web.rs
use super::{DidMethod, MethodError, ParsedDid};

pub struct Web;

impl DidMethod for Web {
    const NAME: &'static str = "web";
    const CONTENT_TYPE: &'static str = "application/did+json";
    const DATA_EXT: &'static str = "json";

    fn parse_identifier(did: &str) -> Result<ParsedDid, MethodError> {
        let rest = did.strip_prefix("did:web:").ok_or(MethodError::MethodMismatch)?;
        let mut parts = rest.split(':');
        let domain = parts.next().ok_or(MethodError::Malformed)?.to_string();
        let path = parts.collect::<Vec<_>>().join(":");
        Ok(ParsedDid { method: Self::NAME, scid: None, domain, path })
    }

    fn resolution_url(domain: &str, mnemonic: &str) -> String {
        if mnemonic == "__root" {
            format!("https://{domain}/.well-known/did.json")
        } else {
            format!("https://{domain}/{}/did.json", mnemonic.replace(':', "/"))
        }
    }

    fn validate(data: &[u8]) -> Result<(), MethodError> {
        let v: serde_json::Value = serde_json::from_slice(data)
            .map_err(|e| MethodError::Validation(format!("json: {e}")))?;
        let id = v.get("id").and_then(|x| x.as_str())
            .ok_or_else(|| MethodError::Validation("missing id".into()))?;
        if !id.starts_with("did:web:") {
            return Err(MethodError::Validation("id is not did:web".into()));
        }
        Ok(())
    }

    fn apply_update(_existing: Option<&[u8]>, new_data: &[u8])
        -> Result<Vec<u8>, MethodError> {
        Self::validate(new_data)?;
        Ok(new_data.to_vec())
    }
}
```

Style notes:
- **One method = one file = one struct.** No inheritance trickery.
- **Const associated items** (NAME, CONTENT_TYPE, DATA_EXT) keep the metadata immediately visible at the top of the impl.
- **`Result<_, MethodError>` everywhere** — no anyhow at the trait boundary.
- **No method-cross-pollination.** Webvh's impl never imports from `web.rs` and vice versa.

## 12. Testing strategy

- **Unit**: each `DidMethod` impl has its own test module covering parse / resolution_url / validate / apply_update with table-driven cases.
- **Integration**: `did-hosting-server/tests/multi_method.rs` creates one did:webvh and one did:web under the same domain, asserts independent resolution paths and isolated state.
- **Edge case tests**: did:web no-path (`__root`), did:web with multi-segment path, did:web id-mismatch between identifier and document.
- **Migration test**: write a legacy `did_log` shape into the store, run the migration, assert `DidRecord { method: "webvh", ... }` shape on re-read.
- **CI build matrix**: see §9.5.
- **Coverage**: ≥ 80% per method module.
- **Manual**: dev-browser checklist covering all method-aware UI flows.

## 13. Boundaries

**Always:**
- Gate every method-specific module with `#[cfg(feature = "method-{name}")]` so disabling a method actually removes its code from the binary.
- When generalising existing webvh code into the trait abstraction, keep behaviour byte-identical — every webvh test must still pass.
- Run the full CI matrix locally before merging changes that touch any `methods/` module.
- DCO sign + `cargo fmt` + `cargo clippy --workspace --all-targets --all-features`.

**Ask first:**
- Adding a runtime DID method registry (currently compile-time only).
- Changing the `DidMethod` trait surface once shipped — it becomes a soft public API for future contributors adding methods.
- Generalising witness or watcher to method-neutral (out of scope this release).

**Never:**
- Mix method storage in the same `DidRecord` (no records with `method = "webvh"` carrying did.json bytes).
- Synthesise a fake webvh log entry for did:web overwrites.
- Auto-convert a DID across methods.
- Reuse a mnemonic across methods at the same domain *with the assumption they're the same DID* — they are not.

## 14. Risks

- **Rename blast radius.** Operators upgrading from `webvh-*` binaries to `did-hosting-*` binaries do a config + binary + env-var swap simultaneously. Mitigation: detailed migration guide; one-shot config-rewrite CLI subcommand (`did-hosting-daemon migrate-from-webvh-config /path/to/old.toml`) that ingests the old config and produces the new shape.
- **Compile-time gating mistake.** Disabling `method-webvh` should remove all webvh-resolution routes; a missing `#[cfg]` somewhere causes runtime errors instead of clean removal. Mitigation: CI matrix explicitly builds `--no-default-features --features method-web` and runs smoke tests; absence of webvh routes verified in test.
- **Resolution route shadowing.** `GET /{*path}/did.json` is a catch-all; if registered ahead of `/api/...` it'd shadow management routes. Mitigation: router build order codified in `did-hosting-server::server.rs` with an inline comment + a test that asserts `/api/health` still resolves with both methods enabled.
- **Storage migration ordering.** Multi-domain migration (assigns `domain`) and multi-method migration (tags `method`) both run on first boot at new version. Order matters because the multi-method migration needs `domain` populated to derive the `DidRecord`. Mitigation: explicit ordering in the migration runner; idempotent so reruns are safe.
- **External-contributor surface.** The `DidMethod` trait becomes a public extension point. Bad designs here are expensive to undo. Mitigation: explicit "internal beta" stance in the README — trait surface may change in pre-1.0 releases.

## 15. Cross-spec edits required

This spec triggers small follow-up edits to the two existing specs in this release:

- **`docs/multi-domain-spec.md`**: rename Trust-Task URLs from `trusttasks.org/affinidi/webvh/{path}/1.0` to `trusttasks.org/did-hosting/{path}/1.0` (method-agnostic ops) and `trusttasks.org/webvh/{path}/1.0` (webvh-specific). Update §5 project structure to use the new crate names. Update §11 references.
- **`docs/webvh-client-crate-spec.md`**: rename the spec doc to `did-hosting-client-crate-spec.md`; rename the published crate to `did-hosting-client`; update `did_log` → `did_data`; add a `method: Option<&str>` field to `RegisterAtomicBody` (and document the default-to-system-default fallback); update all Trust-Task URL consts.

I'll do both in the same PR that lands this spec — they're trivial mechanical edits given this spec is the source of truth for the new naming.

## 16. References

- `docs/multi-domain-spec.md` — domain dimension; ships in the same release tag.
- `docs/webvh-client-crate-spec.md` — client crate; renaming and method-awareness folded in via §15 edits.
- W3C DID specification §3 — DID method semantics.
- did:web specification: https://w3c-ccg.github.io/did-method-web/
- did:webvh specification: https://identity.foundation/didwebvh/
- `verifiable-trust-infrastructure/vti-common/src/trust_task/` — canonical Trust-Task primitive.
- `https://trusttasks.org/` — ToIP DTGWG Trust Tasks registry.
