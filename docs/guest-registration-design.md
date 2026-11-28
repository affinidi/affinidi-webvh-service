# Self-registration — design

Status: **implemented** on `feat/guest-self-registration` (2026-11-27), against the
`did-management/account/*` specs of trustoverip/dtgwg-trust-tasks-tf#1405.

Task names below are short for the `did-management/account/*` family, drafted
in dtgwg-trust-tasks-tf on branch `feat/did-management-account` (with
`did-management/server/info/0.2` and `did-management/_shared/0.4`). The specs
are the authority on wire shapes; this document is the authority on how this
service implements them.

## Problem

A VTA with no prior relationship to a hosting service — typically one embedded
in openvtc, never reachable from the internet — needs to publish its own
`did:webvh` (presented as `did:scid:vh:1`) on a third-party host, with no
operator ACL step per VTA.

Today that fails twice over:

1. **Identity.** The VTA mints its DID serverless
   (`verifiable-trust-infrastructure/vta-service/src/setup/from_toml.rs`,
   `server_id: None`) and signs its requests as that DID. The DID is not
   served anywhere yet, so the control plane cannot resolve the signer.
2. **Authorisation.** The signer is not in the ACL, and every DID-management
   task requires an ACL entry.

Solving (1) alone is not enough: minting a self-certifying DID costs nothing,
so proving *who* is asking says nothing about whether they should get space.
This design solves (1) with self-certification and (2) with gated admission, a
restricted role, and automatic expiry.

## Decisions

| # | Question | Decision |
|---|---|---|
| D1 | Admission modes in v1 | **invite** (operator-issued token + claim code) and **vtc** (VTC-signed voucher). No open mode. |
| D2 | VTC link | **Offline signed voucher.** The VTC signs; the host verifies. No shared secrets, no VTC↔host round-trip. |
| D3 | Liveness | **Owner-signed activity *or* a recent resolution.** The VTA's client sends an automatic renewal, so no human has to act. |
| D4 | During the disable grace period | **Stop resolving** (404, the existing disabled-slot behaviour), and **warn the VTA** before and at decommission. |
| D5 | Role | **Ordinary `Owner`** (revised from a separate `Guest` role, at the VTA side's request). The account record marks it self-registered, and its domain's **terms** set it apart: path prefixes, no agent names, per-domain quotas (the service's ordinary limits where none are stated), and the inactivity lifecycle. |
| D6 | Where the terms live | **Runtime state per domain** (`account::policy`), managed with `did-management/account/policy/{list,set}`: open/closed, trusted authorising parties (DID plus label), prefixes, quotas, lifecycle. `[[hosting.guest_register]]` only seeds them at first start. |
| D7 | Referral | Optional `referral` (`via` DID, `label`) on register and on an invite: attribution, verified only when the admitting voucher or invite supports it. |

### First client: the VTA embedded in openvtc (agreed with the VTA side)

- **Signs as `did:scid:vh:1`** (`default_did_method = "scid"`), with its
  `authentication` key (`#key-0`). Its genesis document lists the
  `did:scid` alias in `alsoKnownAs`, so §1 step 3 admits it, and the ACL entry
  is the bare `did:scid`. No identity merge is needed.
- **Uses invites in v1.** openvtc's quick-start runs before the user belongs to
  any VTC, so no voucher is available at setup. The voucher stays in the spec
  for a later flow in which a VTC invitation starts onboarding.
- **Genesis** is a single entry, `portable: true`, minted with a path read from
  `server/info` beforehand.
- **Lifecycle:** it sends `account/renew` at every startup and daily while
  running (it runs only while the openvtc TUI is open), handles
  `account/expiry-notice` inbound over `#tsp` / `#vta-didcomm`, and calls
  `account/status` at startup. 90 idle days plus 30 days' grace is accepted.

## 1. Self-certifying first registration (`did:webvh`)

A `did:webvh` log *is* self-certifying: the SCID is the hash of the genesis
entry, which contains the DID (domain and path), its `updateKeys`, and the
document; every later entry is signed by the previous `updateKeys`. A log that
verifies from genesis therefore fixes who controls the DID it names. (The doc
comment in `webs_self_register.rs` saying otherwise is too strong and is
corrected as part of this work.)

The check mirrors `did:webs` self-registration (`webs_self_register.rs`):

1. The request carries the full `did.jsonl`. It verifies in full with the same
   code the write path uses (`verify_for_publish` / `verify_history`).
2. The **current** entry's `id` equals the DID the slot builds from
   `{domain, path}`. (Not the genesis entry: a `portable` DID may have moved.)
3. `issuer` is that DID, **or** its `did:scid:vh:1` alias (`scid::scid_alias`)
   **and** the verified document lists that alias in `alsoKnownAs`
   (`ScidAliasStatus::Listed`). A caller registers only itself.
4. The request is sender-bound as every privileged document is
   (`verify_sender_bound`: recipient, freshness, replay), with
   `proofPurpose: authentication` and the key under the **document's
   `authentication`** relationship — never an `updateKey`. The document is the
   one the verified log implies, served by a single-identifier resolver (the
   `OneDocument` pattern), so nothing is resolved over the network.

**Identity forms.** `did:webvh` and `did:scid:vh:1` are distinct identities
verified by the same log (VTI-KEY-164); only `?src=` is dropped from a
`did:scid` (VTI-KEY-160, `scid::identity`). The ACL entry is granted to the form
that signed, without `src`. Signing later as the other form is a different
identity. Collapsing the two is a VTI key-identity decision, not this
service's.

**Shared code.** The method-neutral parts of `webs_self_register.rs` —
admission, the one-document resolver, reserve → commit → grant — move to a
`self_register` module with two log verifiers (KERI KEL, webvh log). One gate,
not two diverging copies. The webvh path does not need `method-webs`.

## 2. Admission

### Task

New row `account/register/0.1` (spec in dtgwg-trust-tasks-tf), `ProofRule`
verified as in §1. Payload (all `deny_unknown_fields`):

```text
domain, path, didLog,             // the slot and its full did.jsonl
admission: { invite: { token, claimCode } }
         | { voucher: <DidHostingVoucher> }
```

It is a separate task rather than a new field on `did/register`, because
account creation and the first publish commit together, and `did/register`'s
contract with `webvh_client` stays untouched.

### Invite (D1)

An admin issues `account/invite/issue/0.1` (plus `list`, `revoke`): a single-use
token and claim code, stored hashed, with a TTL and a bound domain, path prefix
and quota. Storage and hashing generalise `passkey::invite` (a new purpose);
never store or log either secret.

### VTC voucher (D2)

A Data Integrity–signed credential:

```text
type:       DidHostingVoucher
issuer:     <VTC DID>             // must be in the domain's trusted_vtcs
subject:    <VTA DID identity>    // either form, without ?src=
audience:   <this control plane's DID>
id:         <unique, single-use>
validUntil: <short — hours to days>
optional:   domain, quota tier
proof:      proofPurpose assertionMethod  // an attestation, so assertionMethod
```

The VTA mints its DID (serverless), asks its VTC for a voucher naming that DID,
then registers. The voucher is bound to the subject, so a stolen voucher is
useless to anyone else. Its `id` is recorded until `validUntil`, so it cannot
be reused.

Open question: also accept the VTC's existing **membership credential** as the
voucher ("any member of VTC X gets a guest slot")? Simpler for the VTC, but
then revocation status has to be checked.

### Order of checks (cheapest first)

Each step runs only if the previous one passed, so a stranger without a valid
admission costs a hash lookup, not a log verification or a network resolution.

1. The domain's stored terms are open to this evidence; path matches its rules.
2. Request size cap.
3. Per-source and global rate limiters (`rate_limit.rs`). On TSP/DIDComm a
   source can be a fresh `did:key` per request, so only the global bucket bounds
   the total.
4. Domain's `maxRegistrations` not reached (`reserve`, one registration per domain at a
   time, as for webs).
5. Admission:
   - invite → hash lookup, unexpired, unrevoked, matches domain/path;
   - voucher → issuer in `trusted_vtcs`, `audience` is us, unexpired, `id`
     unused, `subject` is the request's `issuer` identity; then the signature,
     against the VTC's DID document (a configured, cached DID — bounded
     resolution, not a stranger's).
6. Log verification (§1 steps 1–3).
7. Sender-bound proof against the log-implied document (§1 step 4). Replay is
   recorded in the `unlisted_signers` sign-in partition.
8. `register_did_atomic` commits (refuses a slot owned by anyone else; never
   `force`).
9. Only after the commit: consume the invite / record the voucher `id`, and
   grant the owner's ACL entry. A failed commit consumes nothing.

### Terms (D6)

Each domain's terms are a `SelfRegistrationPolicy`, stored by the control plane
under `acct_policy:{domain}` and changed by an administrator with
`account/policy/set` (which replaces them whole, and takes effect at once):

| Member | Meaning |
|---|---|
| `enabled` | Open to new registrations. `false` closes the domain; existing accounts carry on. |
| `admissions` | `invite`, `voucher`. |
| `trustedIssuers` | The authorising parties whose vouchers admit: `{ did, label? }`. Labels are never published. |
| `pathPrefixes` | Every DID a self-registered account holds sits under one (whole `/` segments). |
| `maxRegistrations` | Self-registered accounts on the domain. |
| `maxDidCount`, `maxTotalSizeBytes` | Optional; absent = the service's ordinary per-account limits. |
| `inactivityDays`, `graceDays` | The lifecycle; `inactivityDays: 0` = never expire. |
| `maxPendingInvites` | Pending invites at once. |

The configuration seeds them, once, for a domain with none:

```toml
[[hosting.guest_register]]
domain = "example.com"
path_prefixes = ["g"]
admissions = ["invite", "voucher"]          # default ["invite"]
trusted_voucher_issuers = ["did:webvh:…"]   # required exactly when "voucher" is admitted
max_registrations = 1000
# max_did_count, max_total_size: unset = the service's ordinary limits
inactivity_days = 90
grace_days = 30
max_pending_invites = 1000
```

## 3. The account (D5)

A self-registered account is an **ordinary owner's ACL entry** plus an
`AccountRecord` (`account:{subject}` in the ACL keyspace): how it was admitted,
its referral, when its holder was last active, and its lifecycle state. While
the record exists the account is held to its domain's terms:

- every DID it holds sits under the path prefixes (`check-name` must name a
  path: an auto-assigned one could not be checked first);
- no agent names — a publish whose document claims one is refused;
- no `did/change-owner`;
- the terms' quotas on its ACL entry (the service's ordinary limits where the
  terms state none);
- the inactivity lifecycle (§4).

No role carries any of this, so no `check_acl` caller needed changing.

An administrator lifts the terms from one account with `account/exempt`
(`AccountRecord.exempt`): path prefixes, the agent-name and transfer bars and the
lifecycle stop applying, and DIDs the lifecycle disabled are restored.
`exempt: false` applies them again and restarts the inactivity period. Quotas
stay on the ACL entry (`acl/update`).

## 4. Liveness and expiry (D3, D4)

### What keeps an account alive

`last_alive = max(last_active_at, last_resolved_at of its DIDs)`

- **`last_active_at`** — any owner-signed task, including `account/renew/0.1`,
  which `webvh_client` sends automatically (e.g. daily). This is the reliable
  signal: no human needs to act. Written at most once a day to avoid a store
  write per request.
- **`last_resolved_at`** — already merged per DID on the control plane from
  edges' stats syncs (in-process in the daemon). This is the secondary signal:
  a DID that verifiers keep resolving stays up even if its VTA is offline.

Known limits of resolutions as a signal:

- Anyone, including crawlers, can resolve a DID, so a dead DID that is crawled
  never expires. Acceptable in v1 because admission is gated (a squatter cannot
  mint slots freely) and the guest cap bounds the total.
- A CDN in front of the edges hides resolutions. That is why renewal, not
  resolution, is the primary signal.
- A disabled DID returns 404, so resolutions of it are **not** counted:
  only owner activity brings it back.

### Lifecycle

```text
Active ──(idle_days − warn days)──▶ Warned ──(idle_days)──▶ Disabled ──(disable_grace_days)──▶ Purged
  ▲                                   │                        │
  └──── owner activity / resolution ──┘                        │
  ▲                                                            │
  └──────────────── owner-signed renew only ───────────────────┘
```

- **Disabled** sets the record's `disabled` flag with a new reason, *expired*,
  separate from `disabled_by_admin`, so the owner's renewal can clear it (an
  admin suspension still needs an admin). Edges already return 404 for a
  disabled slot and replication already syncs the flag.
- **Purged** deletes the account's DIDs with the ordinary `did/delete` path
  (which syncs the deletion to the edges), then the ACL entry, the holder's
  sessions and the account record. A purged VTA is a stranger again and
  registers anew with fresh admission. There is no path cool-off: a
  `did:webvh` names its SCID, so whoever takes the path next mints a different
  DID; the old one cannot be impersonated.

### Decommission warnings

New task `account/expiry-notice/0.1`, **sent by the control plane to the
owner's DID**, signed for `authentication`:

| When | Notice |
|---|---|
| each `warn_before_days` before disable | `stage: disablePending`, `disableAt` |
| at disable | `stage: disabled`, `purgeAt` |
| one day before purge | `stage: purgePending`, `purgeAt` |

- Sent directly by the sweep (`send_trust_task`, `resolve_send_binding`), so it
  reaches an embedded VTA through its mediator (`#tsp` / `#vta-didcomm`), with
  no fallback to this service's own mediator for a document that advertises
  nothing. A send the transport did not take is tried again on the next
  (hourly) tick. Not through the outbox: the outbox settles a row only on a
  Service-role acknowledgement, and a notice needs none. An owner whose
  document advertises no transport is unroutable: logged, never an error.
  Warning days are fixed at 14 and 3 (not configurable).
- Stages sent are recorded on the account, so a restart does not send them
  twice.
- Pull side for a VTA that was offline: `account/status/0.1` returns the state,
  `disableAt` and `purgeAt`. `account/renew/0.1` returns the same.

### Where it runs

A `PeriodicTask` named `account-lifecycle` in the control plane's
`background_tasks`, named in `server::tasks`. The daemon runs it through the
same `spawn_workers` (it is not in `DAEMON_SKIPPED_TASKS`), and `parity_tests`
covers it.

## 5. Discovery

A client must know a host's guest rules **before** minting, because the path
is baked into the SCID. The rules are not advertised in any DID document
(node documents advertise transports only). The client already holds the
control plane's URL (the operator picks the host), so:

- trust-task discovery lists `account/register/0.1`;
- the unauthenticated `server/info` (served by the control plane, never an
  edge) moves to `server/info/0.2`, whose `selfRegistration` array gives each
  open domain's `admissions`, `trustedVoucherIssuers`, `pathPrefixes`,
  `maxDidCount`, `maxTotalSizeBytes`, `inactivityDays` and `graceDays`.

openvtc filters its host picker on this.

## 6. Cross-repo work

- **dtgwg-trust-tasks-tf:** *drafted* (branch `feat/did-management-account`,
  not yet a PR): `did-management/account/{register,renew,status,expiry-notice}`
  and `account/invite/{issue,list,revoke}` at 0.1, `server/info/0.2` (its
  `selfRegistration` member), and the `HostingAccount` / `AccountInvite` shared
  shapes; the `DidHostingVoucher` is a `$def` of `account/register`.
- **verifiable-trust-infrastructure (`webvh_client` / VTA):** registration call
  after the serverless mint; automatic renewal; handling the inbound expiry
  notice (verify the host's signature); a status call.
- **VTC:** issuing vouchers.

## 7. Open questions

1. Accept a VTC membership credential as the voucher? (§2)
2. Should self-registered `did:webs` identities also get an account record, and so the terms and lifecycle? (§3)
3. ~~Paths: operator prefix, or SCID-derived only?~~ Operator prefixes (`pathPrefixes`).
4. ~~Default `idle_days` / `disable_grace_days`.~~ 90 / 30, accepted by the
   first client.
