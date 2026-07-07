# Design — fit-for-purpose typed DID-management Trust Tasks (`did-hosting/*/1.0`)

**Status:** proposed. Supersedes the idea of adopting the upstream
`trust-tasks-rs` `spec/did-management/*/0.1` payloads directly.

## Problem

Today the DID-management ops (`check-name`, `publish`, `register`, `info`,
`list`, `delete`, `change-owner`, `witness/publish`) are dispatched by the
hand-rolled `dispatch_did_op` (`did-hosting-control/src/messaging.rs`): a
`match msg.typ.as_str()` over ad-hoc JSON bodies (`{ did_log, mnemonic,
path, … }`). They reach the trust-task transports (TSP, DIDComm envelope,
HTTPS) only via `bridge_did_management`, which synthesises a `Message` and
delegates to that match. They do **not** run the framework's typed §7.2
pipeline (typed payload validation, `ProofPolicy`, `ResolvedParties`) that
the ACL ops enjoy.

Adopting the upstream `trust-tasks-rs` `did_management` spec payloads is
**not** the answer: those are record-centric (`did_data` = a full DID
*record*: `version_count`, `updated_at`, `did_id`, …) with **no
first-class field for the `did.jsonl` log** a publish/register actually
carries, and they demand host-assigned fields on a client *request*. They
model "here is a record", not "here is a signed log to publish".

## Approach — define our own, versioned, additive

Give the **already-defined** webvh-owned Type URIs in
`did_hosting_tasks.rs` (`https://trusttasks.org/did-hosting/did/*/1.0`)
proper **typed `Payload` structs** that carry what the ops need, dispatch
them through the framework's typed pipeline, and deprecate the legacy
`MSG_*` / `spec/did-management/*/0.1` path over time.

- **Additive, not breaking.** The `1.0` URIs are new on the wire; the
  existing `MSG_*` path keeps working unchanged until clients opt in.
- **Fit-for-purpose.** Payloads carry the real operational data as typed
  fields — no `ext`-bag smuggling, no spurious required record fields.

### Payload catalogue (request → `#response`)

Each is a Rust struct implementing `trust_tasks_rs::Payload` (a `TYPE_URI`
const + `serde`), living in a new
`did-hosting-common/src/server/trust_tasks/did_hosting/` module. Fields
below are the *fit-for-purpose* request shapes, derived from what each
`dispatch_did_op` arm reads today.

| Op | Request URI | Request fields | Response URI | Response fields |
|----|-------------|----------------|--------------|-----------------|
| check-name | `…/did/request/1.0` | `path?`, `reserve: bool`, `force: bool` | `…/did/offer/1.0` | `available: bool`, `reserved: bool`, `mnemonic?` |
| publish | `…/did/publish/1.0` | `mnemonic`, `did_log` (JSONL) | `…/did/confirm/1.0` | `did_id`, `version_count` |
| register | `…/did/register/1.0` | `path?`, `did_log`, `force: bool`, `witness?` | `…/did/register-confirm/1.0` | `mnemonic`, `did_id` |
| info | `…/did/info-request/1.0` | `mnemonic` | `…/did/info/1.0` | the `DidRecord` projection |
| list | `…/did/list-request/1.0` | `filter?` | `…/did/list/1.0` | `dids: [DidRecord]` |
| delete | `…/did/delete/1.0` | `mnemonic` | `…/did/delete-confirm/1.0` | `mnemonic` |
| change-owner | `…/did/change-owner/1.0` | `mnemonic`, `new_owner` | `…/did/change-owner-confirm/1.0` | `mnemonic`, `new_owner` |
| witness-publish | `…/webvh/witness/publish/1.0` | `mnemonic`, `did_log`, `witness` | (confirm) | `did_id` |

(Exact fields to be finalised against each `dispatch_did_op` arm — this is
a faithful re-typing of the *current* bodies, which are already
fit-for-purpose, not a redesign.)

### Dispatch

The framework `dispatch_inbound` (common) is hardwired to the ACL
`TypedInbound` + `TrustTaskContext`. DID-management handlers need the
control plane's `AppState`, so add a **control-side** typed dispatcher
mirroring the common one:

- `did-hosting-control/src/trust_tasks_did/` — a `Dispatcher<DidMgmtInbound>`
  registering the `1.0` payloads, and per-op async handlers that call
  `trust_tasks_rs::consume_inbound` (§7.2 items 4–8: identity, recipient,
  proof policy) then delegate to the **existing** `did_ops::*` business
  logic (no logic rewrite — the ops are unchanged; only the request/
  response shaping becomes typed).
- Handlers build the typed `#response` payload from the `did_ops` result.

### Routing (unified entry, deprecation)

`messaging::dispatch_trust_task_doc` gains a third arm:

1. Framework ACL/discovery URI → `dispatch_inbound` (unchanged).
2. **`did-hosting/*/1.0` URI → the new control-side typed dispatcher.**
3. Legacy `MSG_*` / `spec/did-management/*/0.1` → `bridge_did_management`
   → `dispatch_did_op`, now **deprecated** (a `tracing::warn!` once per
   op with a "migrate to did-hosting/*/1.0" pointer).

All transports (TSP, DIDComm envelope, HTTPS) get the typed path for free
because they already route through `dispatch_trust_task_doc`.

### Deprecation timeline

1. Ship the `1.0` typed path (this design). Both paths live.
2. Migrate first-party clients (`did-hosting-client`, the UI/wallet) to
   emit `1.0`.
3. Add deprecation warnings on the legacy path (done in step 1, logged).
4. After a release cycle, remove `dispatch_did_op` + the `MSG_*` aliases.

## Testing

- **Parity harness:** for each op, a test asserting the `1.0` typed
  handler produces the same effect + equivalent response as the existing
  `dispatch_did_op` arm for the same logical input (the existing
  `dispatch_did_op_*` tests are the oracle).
- Round-trip each typed payload through `serde` (pins the wire shape).
- End-to-end: a `1.0` op over TSP + over the DIDComm envelope + over
  HTTPS `/api/trust-tasks`, asserting typed dispatch (not the bridge).

## Effort & sequencing

~8 ops × (request struct + response struct + handler + registration +
parity test). Land **one op at a time** behind the routing arm so each is
independently reviewable and the tree stays green:

1. Infrastructure: the `did_hosting` payload module + control-side
   `Dispatcher<DidMgmtInbound>` + the routing arm, with **check-name**
   (simplest) as the first op.
2. **publish** + **register** (the fit-for-purpose motivation — they carry
   `did_log`).
3. info / list / delete / change-owner / witness-publish.
4. Client + UI migration; legacy-path deprecation warnings.

## Files

- New: `did-hosting-common/src/server/trust_tasks/did_hosting/{mod,request,publish,…}.rs`
  (typed payloads), `did-hosting-control/src/trust_tasks_did/{mod,handlers}.rs`
  (dispatcher + handlers).
- Edit: `did-hosting-control/src/messaging.rs` (`dispatch_trust_task_doc`
  routing arm + deprecation warn), `did_hosting_tasks.rs` (any missing
  `1.0` URI constants), `did-hosting-client` (emit `1.0`).
