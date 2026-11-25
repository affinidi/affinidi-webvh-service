# Changelog

## Unreleased

Entries for the next release are kept in [`changelog.d/`](changelog.d/README.md) until it is released.

## 0.12.0 (release/0.12)

### Breaking — `did-hosting-common` lock-guard and invite signatures

Rust callers of `did-hosting-common` must update for the two changes below:

- `PathLocks::guard` returns `did_hosting_common::server::path_locks::PathGuard`
  instead of `tokio::sync::OwnedMutexGuard<()>`. Code that only holds the
  guard and drops it needs no change; code that names the type does.
- `passkey::invite::issue`, `passkey::invite::redeem` and
  `passkey::run_cli_invite` take a final `std::time::Duration` argument, the
  longest wait for a claim-code hashing slot. Pass
  `config.auth.claim_code_hash_wait()`.

This change is for the next release and will not be backported.

### Breaking — `did-hosting-common` `ServerConfig` has a `client_ipv6_prefix` field

Rust callers that build `did_hosting_common::server::config::ServerConfig`
with a struct literal must set `client_ipv6_prefix`; use
`did_hosting_common::server::config::default_client_ipv6_prefix()` or
`..ServerConfig::default()`. Build a service's `ClientIps` with
`ClientIps::from_server_config(&config.server)` so the setting applies;
`ClientIps::new` still works and counts an IPv6 client by its /64.
Configuration files need no change.

### Breaking — the daemon refuses a witness store that reaches the control plane's data

With the witness enabled, `did-hosting-daemon` now refuses to start when
`[witness_store]` reaches the same data as `[store]`. The embedded witness keeps
its ACL in its store, so it would otherwise share the control plane's ACL, and
with `service` entries now allowed to request witness signatures, every
control-plane `service` entry (each registered edge) could have it sign. The
check is made by trying it: at startup the daemon writes a random value under
a reserved key (`store-probe:…`, outside the `acl:` entries) in `[store]`'s ACL
keyspace, looks for it through `[witness_store]`, and removes it. Any spelling
of the same Redis server and database, DynamoDB table prefix and region,
Firestore database or Cosmos DB database is therefore caught. On DynamoDB both
prefixes default to `webvh`, so a `[witness_store]` without its own
`dynamodb_table_prefix` is refused. The default layout (separate fjall
directories) is unaffected.

To move a deployment that shares one store, keeping its witness identities
(and, with sealed witness keys, the recorded key-encryption key and the sealed
keys, which live in the same keyspace):

1. Stop the daemon and run `did-hosting-daemon backup -o witness.json`. The
   backup includes the `witnesses` keyspace; it does not include the ACL.
2. Give `[witness_store]` its own location (for example
   `dynamodb_table_prefix = "webvh-witness"`).
3. Restore into it: run `did-hosting-daemon restore -i witness.json` with a
   copy of the config whose `[store]` section is the new `[witness_store]`.
   This also writes the backup's other keyspaces there; the witness does not
   read them.
4. Re-create the witness's ACL with `did-hosting-daemon add-acl --witness
   --did <DID> --role admin|service`, giving `service` to callers that only
   request signatures.

If that is not possible, the fallback is to create new witness identities in
the new store and have DIDs that list the old identities move to them.

### Breaking — proof-verification failures carry their kind as a value

Whether a refused proof was a signer that could not be resolved (retryable),
a deactivated signer or a bad proof was decided by searching the error message
for fixed phrases. That message includes the signer's DID, which the sender
chooses. The verifier now reports the kind as a value, taken from where it was
decided, and nothing decides it from text.

Rust callers of `did-hosting-common`:

- `trust_tasks::is_unreachable` and `trust_tasks::unreachable_error` are
  removed. Use `TransportBoundVerifier::check_operational` /
  `check_approval`, which return a `VerifyFailure { kind, error }`
  (`VerifyFailureKind::{Unreachable, Deactivated, Invalid}`), and
  `BoundError::unreachable(detail)` to report a signer you gave up waiting on.
- `BoundError` has a new `Unreachable(VerificationError)` variant, which is
  what `is_transient` now reports. An unreachable signer is no longer a
  `BoundError::Proof`, and its message reads "proof could not be checked: …".
- `verify_operational`, `verify_approval` and `ProofVerifier::verify` keep
  their signatures.
- A caller-supplied resolver (`TransportBoundVerifier::with_resolver`)
  cannot report a kind, so its failures count as bad proofs, whatever their
  message says.

No wire shapes change. Which failures are retryable is unchanged for the
service's own verifier.

### Breaking — unused items removed from `did-hosting-common` and `did-hosting-control`

Rust callers:

- `ServerSecrets`, `RetiredKeys` and `StoredSecrets` implement `Drop`
  (`ZeroizeOnDrop`), so a field can no longer be moved out of one; use
  `clone()` or `std::mem::take`.
- `did-hosting-control`'s `AppState::signing_key_bytes` is removed. It was a
  second, unused copy of the signing seed; sign with
  `signing::control_signing_secret`.
- `didcomm_unpack::{unpack_signed, require_addressed_to, REPLAY_WINDOW_SECS}`
  are removed. Nothing called them since the REST sign-in path was retired.
- `server::acl::{CreateAclRequest, UpdateAclRequest, AclEntryResponse,
  AclListResponse}` are removed, left over from the retired ACL REST routes.
- `SpecAclEntry::into_local` takes the creation time to record, and ignores
  an inbound `createdAt`, as it already did for the other provenance members.
- New: `ServiceIdentity::secret(kid)`,
  `auth::session::{refresh_token_digest, refresh_hash_of_stored}`.

### Breaking — `did_hosting_server::routes::trust_tasks::receive` takes the body unread

Rust callers that invoke the handler directly: it now takes
`Extension<trust_tasks::BodyLimit>` (after `ConnectInfo`) and an
`axum::body::Body` instead of `Bytes`, and reads the body itself after its
rate limit. Mounted through `routes::router*`, nothing changes.

### Breaking — `did-hosting-common` storage backends implement `compare_and_swap_raw`

`KeyspaceOps` has a new required method, `compare_and_swap_raw(key,
expected, new)`, exposed as `KeyspaceHandle::compare_and_swap_raw`: it
writes only if the key holds `expected` (`None`: is absent), atomically
across processes on Redis (a Lua script), DynamoDB (a conditional
`PutItem`), Cosmos DB (create, or `If-Match` replace) and Firestore (a
transaction). An out-of-tree `KeyspaceOps` implementation must add it.
`webvh_witness::witness_ops::sign_witness_proof` no longer takes the mark to
record; call `read_witnessed_mark` and `advance_witnessed_mark` first.

### Breaking — a wallet step-up in the console no longer hands the wallet the session's tokens

The console used to step a wallet session up by giving the wallet browser
extension the session's access token and refresh token
(`window.vtaWallet.stepUpVta`); the wallet then opened the step-up, sent its
decision and renewed the session itself. Now the console keeps both tokens:

1. The console opens the step-up itself: `auth/step-up/start/0.2`, signed by
   the session key bound at login. The control plane answers with its signed
   `auth/step-up/approve-request/0.5`, a single-use challenge bound to this
   session and its subject that lapses on its own (300 seconds).
2. The wallet is handed that approve-request and the service DID, nothing
   else (`window.vtaWallet.approveSessionStepUp({ rpDid, approveRequest })`).
   It verifies the request, asks the user, and returns its
   `auth/step-up/approve-response/0.7`, signed as the subject
   (`assertionMethod`); a session key may never sign an approval.
3. The console checks that the decision answers this challenge for this
   session, and sends it as signed.
4. The console renews the session with `auth/refresh/0.2`, signed by the
   session key with the refresh token it holds, so the new tokens carry
   `aal2`.

The control plane is unchanged: it already accepted a session-key-signed
`auth/step-up/start` for the session's own subject, and an approval only by
the subject's own key.

Behaviour change (R3.6): a wallet that offers only `stepUpVta` can no longer
step a console session up. The console says the action needs a stepped-up
session, and never falls back to handing the tokens over. A passkey session is
unaffected (it is `aal2` from login).

### Breaking — Cosmos DB keeps every keyspace in one container, so a batch is atomic

The `store-cosmosdb` backend kept one container per keyspace and applied a
batch one write at a time, so a failure part-way through left half a change
(a DID record without its log or its name index, a domain re-enabled with its
purge still queued). Every keyspace now lives in one container,
`store.cosmosdb_container` (`<PREFIX>_STORE_COSMOSDB_CONTAINER`, default `kv`,
partitioned on `/pk`), created with its database if missing, and a batch is
one Cosmos DB transactional batch: it lands whole or not at all. A batch over
the transactional batch's bound (100 writes, 2 MB) is refused as a size quota,
writing nothing, as on DynamoDB and Firestore.

On first start, each keyspace still in a container of its own is copied into
the shared container, once. Start one upgraded replica alone so the copy
finishes before others write; the old containers are left for you to delete.
Everything now shares one logical partition, which Cosmos DB caps at 20 GB.

### Breaking — config files refuse unknown keys, and boolean environment variables refuse values they do not recognise

Every binary's config file is now parsed strictly: a key a section does not
define is a startup error that names it, instead of being dropped while the
default applies. This covers the top level of each binary's config and the
`[server]`, `[store]`, `[fjall]`, `[auth]`, `[secrets]`, `[hosting]`,
`[features]`, `[log]`, `[identity]` and `[vta]` sections, the server's
`[limits]`, `[stats]` and `[replication]`, the control plane's `[registry]`
(and `[[registry.instances]]` / `[[registry.watchers]]`) and `[trust_tasks]`,
the watcher's `[sync]` and the daemon's `[enable]`. A misspelling such as
`[store] redis_ur = …` or `[auth] acess_token_expiry = 300` used to be
ignored; it now stops the service. Before upgrading, run `<binary> health`
against each config: it reports the offending key. One config file shared by
two different binaries no longer loads; give each its own.

Boolean environment overrides (`<PREFIX>_FEATURES_DIDCOMM`, `_TSP`,
`_AGENT_NAMES`, `_HTTP_LISTENER`, `_SECRETS_VAULT_SKIP_VERIFY`,
`_HOSTING_SCID_ALSO_KNOWN_AS`, `_STORE_DYNAMODB_AUTO_CREATE`) accept `1`/`true`/`yes`/`on` and
`0`/`false`/`no`/`off` in any case. Anything else is a startup error naming
the variable; before, `=yes` or `=on` turned the feature off.

`[features] deployment_mode` accepts only `"standalone"` or `"daemon"` (the
values it always had), and `[[registry.instances]] service_type` only
`"server"`, `"witness"` or `"watcher"`; an unknown service type was skipped
at seed time with a warning and is now a startup error.

### Breaking — `[hosting]` grace periods are checked when the config loads

`[hosting] unassigned_purge_grace` and `disable_purge_grace` are parsed when
the config is loaded, by every binary. A value that is not a duration (an
integer with an optional unit `s`, `m`, `h` or `d`) stops the service at
startup with a message naming the key and the accepted units. Before, an edge
silently fell back to 2 hours at unassign time (so `"1w"` purged a domain's
DIDs two hours after an unassign), and the control plane failed "disable
domain" with an internal error weeks later.

### Breaking — CLI defaults renamed: the backup file and the VTA context

`backup` writes `did-hosting-backup.json` by default (was
`webvh-backup.json`), and the default VTA context id for `setup
--setup-key-out --context`, `vta-request --context` and the setup wizards'
context prompt is `did-hosting` (was `webvh`). Pass `--output` / `--context`
(or answer the prompt) to keep the old names; an existing context keeps
working when named explicitly.

### Breaking — `did-hosting-daemon backup` / `restore` cover the whole daemon, in a format of their own

The daemon used the edge's backup, which loaded the daemon's config file as
an edge config (so with `[store]` omitted it backed up an empty
`data/did-hosting-server` directory), carried only the edge's keyspaces, and
never opened `[witness_store]`. A restore therefore brought DIDs back without
the ACL, login and step-up passkeys, identity generations, did:scid floors or
outbound queue, lost the witness's ACL and keys, and rewrote `config.toml`
through the edge's config type, dropping `[enable]`, `[witness_store]`,
`[registry]`, `[stats_flush]`, `[geoip]` and `did_hosting_url`.

A daemon backup is now a `did-hosting-daemon` document: both stores, with an
explicit keyspace list for each (every keyspace except the TSP relationship
state, which the next handshake re-establishes), and the configuration file
carried and restored byte for byte. DID logs are still checked against their
own history and the target store's before anything is written. A backup an
earlier daemon wrote is in the edge's format and is refused by
`did-hosting-daemon restore`; take a fresh backup after upgrading.

A backup never carries live sign-in sessions or refresh tokens (users sign in
again after a restore), and both binaries now write the backup file readable
by its owner only (`0600`). It still holds the ACL, passkey credentials and
the configuration unencrypted, so keep it as you keep the service's secrets.

### Breaking — stats sync and health pings follow their pinned Trust Task specifications

`server/stats-sync/0.1` and `server/health/0.1` now carry the payloads their
pinned specifications define, on both ends (#449). An edge sends `instanceId`
and `perMnemonic`, with its sequence number and each entry's latest-event times
under `ext."vnd.affinidi.webvh"`. The control plane answers with `instanceId`
and `accepted` (how many entries it counted). A health ping names the
`instanceId` it probes. The pong answers `instanceId`, `ok` and `observedAt`,
with the edge's version and DID count under the same namespace. A control
plane refuses a sync that sends `buckets` rather than dropping them.

**Upgrade the control plane before its edges.** For this release only, a
control plane still reads the old sync and pong shapes, and an edge still
answers the old empty ping. A control plane from before this release refuses
the new shapes: an upgraded edge's stats would not be counted, and its
instance would age to `Unreachable`. The old shapes stop being read in 0.13.
`did_hosting_common::{StatsSyncAck, StatsSyncStatus}` are removed. Build and
read these payloads with `did_hosting_common::server::trust_tasks::infra`.

### Breaking — a malformed `server.trusted_proxy_cidrs` entry stops the service at startup

An entry that is neither an address nor a CIDR range was logged and dropped,
so a typo silently stopped `Forwarded` / `X-Forwarded-Host` being honoured
from that proxy. The list is now parsed when the config is loaded, like
`trusted_proxies`: a bad entry, or a range covering every address
(`0.0.0.0/0`, `::/0`), is refused, naming the key and the entry. Bare
addresses (`10.0.0.1`) are accepted as one-address ranges.

### Breaking — an invalid `identity.rotation_grace_period` stops the service at startup

A value that was not a duration was logged and treated as `1h`, so a typo in
the compromised-key setting (`"0"`) kept the old key honoured for an hour. It
is now parsed when the config is loaded, like the `[hosting]` grace periods,
and a bad value is refused, naming the key.

### Breaking — `trust-task-discovery` is answered in 0.4 only

The service speaks the latest version of each task it serves, and
`trust-tasks-rs` 0.39 supersedes `trust-task-discovery/0.3` with 0.4. A
discoverer asking in 0.3 is now refused `unsupportedType` and may retry in
0.4. The 0.4 answer lists the same Type URIs; it states no acceptance
window.

### Breaking — `did-hosting-common` invite issuer type

Rust callers of `did-hosting-common` must update for the changes below:

- `passkey::invite::Invite::issued_by`, `passkey::invite::InviteRequest::issued_by`
  and `passkey::store::CeremonyOrigin::Invite::issued_by` are now
  `passkey::invite::Issuer` instead of `String`. Build one with
  `Issuer::administrator(did)`, which refuses anything that is not a DID, or
  `Issuer::operator()`. The stored form is unchanged, so invites and ceremonies
  already on disk still read.
- `passkey::invite::Invite` has a new public field, `amended_by: Vec<String>`.
- `passkey::issue_cli_invite` is new. It is the validating half of
  `run_cli_invite` and returns the issued invite instead of printing it.

### Changed — a passkey login start discloses no subject and leaves no rows behind

`auth/passkey/login/start/0.2` is answered to anyone, unsigned. With no
`subject` it read every login passkey enrolled here, returned all their
credential ids as `allowCredentials`, and stored a snapshot of them under the
new `authId`. Those rows were never removed unless the login finished, and
the start answered `subjectNotRecognized` and `noCredentials` differently, so
it also said which DIDs had a passkey.

- **No subject named:** the start opens a discoverable-credential ceremony
  with no `allowCredentials`; the browser offers the passkeys it holds for
  this service. Finish looks the credential up by id, requires the returned
  user handle to be that credential's user (an assertion without one is
  `assertionInvalid`), and verifies against that one subject's credentials.
  The ceremony row holds only its challenge, whatever the number of passkeys.
- **A subject named:** the start lists that subject's credentials, as
  before, so a passkey enrolled as non-discoverable keeps signing in. For a
  subject with no login passkey it lists decoy credential ids instead of
  answering `subjectNotRecognized` / `noCredentials`: one or two ids derived
  from a service key (made on first use, kept as `pk_login_decoy_key`) and
  the subject, the same on every start for that subject and shaped as the
  console's own enrolments are. Nothing answers them.
- A login that named its subject fails in exactly one way at finish
  (`assertionInvalid`, "the assertion did not verify"), whether the
  credential is unknown, not listed, another subject's, or a decoy list's,
  or the assertion does not verify, so its outcome does not say whether the
  subject is enrolled. An unnamed login still says `credentialUnknown`.
- The counter update after a successful login is made under the subject's
  credentials guard on a fresh read, so a login racing a revocation or an
  enrolment neither restores the revoked credential nor drops the new one.
- Only a request carrying the named subject's own bearer session is told
  `subjectNotRecognized` or `noCredentials`.
- Each source may open 30 login ceremonies a minute: the client address on
  HTTPS (refused as `unavailable` with `retryAfter`), the authenticated
  sender on DIDComm and TSP (refused as `rateLimited`). A DIDComm or TSP
  start with no authenticated sender is refused (`permissionDenied`). A
  messaging sender can mint a fresh `did:key` per request, so there the limit
  is per identity rather than per party; what each start leaves is one small,
  swept row.
- The session sweep now removes expired login ceremonies (`pk_task_meta:`
  and any `pk_auth:` state row an older build wrote), passkey revocation
  ceremonies (`pk_revoke:`), step-up challenges (`stepup-task:`) and DID
  ownership offers (`did_xfer:`). A login ceremony opened by the previous
  build can still be finished.
- New login passkeys are requested with `residentKey: preferred`, so an
  authenticator that can store a discoverable credential does. Step-up
  passkeys are unchanged.
- The console's passkey sign-in takes an optional DID; naming it lists that
  DID's credentials, for a security key the browser does not offer by itself.
- `webauthn-rs` gains its `conditional-ui` feature (no new dependency).
- Behaviour changes (R3.6):
  - An anonymous login start never answers `noCredentials` or
    `subjectNotRecognized`. Unnamed, it opens a ceremony with no list;
    naming an unknown subject, it lists decoys.
  - A passkey enrolled as non-discoverable (some hardware security keys,
    registered under the earlier `residentKey: discouraged`) signs in only
    when the start names its subject — in the console, by entering the DID
    beside "Login with Passkey".
  - A discoverable-flow assertion with no user handle is refused.
  - A named login's failures are all `assertionInvalid` (a named login with
    an unknown credential used to be `credentialUnknown`).
  - Residual signal: decoys are always one or two ids of 16, 20 or 32 bytes.
    A named subject whose real list has three or more credentials, ids of
    other lengths, or `transports` (recorded when a browser reports them at
    enrolment) is distinguishable from an unknown one. Real lists cannot be
    trimmed without breaking those credentials' sign-in, so this is left as
    is; a subject's count and id lengths are what they disclose.
  - The 31st login start a minute from one source is refused, and a
    DIDComm/TSP start with no sender is refused.
  - Checked consumers: the console's `passkeyLoginStart` (updated here to
    pass an optional subject) handles options with or without
    `allowCredentials`. No client in verifiable-trust-infrastructure calls
    this service's passkey login (its own `vta-service` and `vtc-service`
    have their own).

### Changed — enrolling a passkey that grants `aal2` needs a stepped-up session or the caller's own key

A passkey login is minted at `aal2`. `auth/passkey/enroll/{start,finish}/0.2`
let any authenticated subject add a login passkey, and asked for user
verification only when one was already held, so a session at `aal1` (signed
by its browser session key) could enrol a first passkey and sign in again at
`aal2`. An administrator's session at `aal1` could do the same through an
invite (`auth/passkey/enroll/invite/0.3`) naming itself. And enrolment
accepted a credential id already bound to another subject, repointing that
credential's index so its holder could no longer sign in with it.

- Enrolling a subject's first login passkey needs a session already at
  `aal2`, or a request signed by the subject's own DID key (the factor a
  `didSigned` step-up rests on). The check runs at start and again at finish,
  against the credentials held then.
- Issuing any enrolment invite needs the same of the administrator: an `aal2`
  session or its own DID key's signature, whoever the invite names.
- Both refusals are `permissionDenied` with message `step_up_required`. The
  console treats that, like a declared `stepUpRequired`, as a request to step
  up and retry, for invites and for domain purges.
- Every enrolment finish (redeem, self-enrolment, either purpose) refuses a
  credential id already bound to any subject in either credential store
  (`attestationInvalid`), as WebAuthn §7.1 requires; enrolments of the same id
  are serialised.
- Adding a further passkey is unchanged (user verification over an existing
  one).
- Behaviour changes (R3.6):
  - A session at `aal1` signed by its session key can no longer start or
    finish a first login passkey enrolment, or issue an invite. A passkey
    session is `aal2` already; a wallet session steps up first.
  - Re-enrolling a credential already bound anywhere is refused.
  - Checked consumers: the console enrols through invites (it steps up when
    asked); no client in verifiable-trust-infrastructure calls this service's
    `enroll/*` tasks.

### Changed — `did/change-owner` moves a slot only when its recipient accepts

`did/change-owner/0.1` moved a slot to any DID with an ACL entry, at the
owner's word alone. The recipient never agreed, its quota and domain scope
were not applied, and the "not in the ACL" error told the owner whether a
DID had an entry.

- An administrator's request moves the slot at once, as before.
- An owner's request now only offers it. The record is returned unchanged,
  with `ext["vnd.affinidi.webvh"].ownerTransfer = { status: "offered",
  newOwner, expiresAt }`. The offer lasts 72 hours. A new offer replaces the
  last; naming the current owner withdraws it; deleting the slot removes it.
  Nothing about the recipient is looked up when an offer is made, so an offer
  answers the same for any DID.
- The recipient accepts by sending the same request naming itself as
  `newOwner`. It needs the live offer from the slot's current owner, made
  since the slot was registered; anyone else still gets `notOwner`.
- Before a slot moves (an administrator's transfer or an acceptance), the
  recipient must have an ACL entry with a role that owns DIDs (`owner` or
  `admin`), a domain scope that covers the slot, and room for it in its DID
  count and total size quotas. Otherwise the request is refused as
  `targetNotAuthorized`, naming the check that failed (only an administrator,
  or the recipient about itself, can reach it).
- The recipient's quota check and the move are one critical section per
  owner, and so are the quota checks and commits of `did/register`, create,
  publish and the agent-name verbs (the publish paths re-check the size quota
  under the owner's lock and hold it through their commit), so two writes for
  the same owner cannot both take its last slot or byte. Lock order: slot,
  then owner, then agent names.
- `did_ops::change_did_owner` takes the request's `domain` and returns
  `OwnerChange { record, offer }`, or `OwnerChangeError`.
- The console's ownership card offers a DID (owners) or transfers it
  (administrators), and the DID list has "Accept a DID".
- Behaviour changes (R3.6):
  - A non-administrator's `did/change-owner` no longer moves the slot. A
    caller that read `record.owner` from the reply to confirm a move now sees
    the old owner and an `ownerTransfer` offer.
  - A transfer to a DID outside the ACL is no longer refused at once when an
    owner sends it. It is recorded as an offer that can never be accepted.
    An administrator's transfer to one is refused as `targetNotAuthorized`
    (it was `malformedRequest`).
  - A transfer to a `service` or `metrics-reader` entry, or to a recipient
    over its quota or outside its domain scope, is refused, administrators
    included.
  - Checked consumers: the console (updated here). verifiable-trust-
    infrastructure defines the Type URI constant in `vta-sdk` but sends no
    `did/change-owner`.

### Changed — tiered, bounded statistics; charts read by key

Every DID now keeps a coarse series (hourly for 7 days, daily for 30) inside
its `stats:` row, and only busy DIDs keep a 5-minute series, in a ring of 288
rows (`t5:{mnemonic}:{slot}`) that is overwritten in place. Nothing grows
without bound and nothing needs a sweep. Charts read rows by key instead of
scanning the time-series keyspace, which on DynamoDB was a full-table Scan
per chart (one per DID for a domain chart). A DID's row is written at most
once per 5 minutes, when its bucket closes, rather than every 10 seconds.

- **`[stats]`** (env `CONTROL_STATS_*`, `DAEMON_STATS_*`): `mode` (`auto`,
  `fine`, `coarse`), `promote_per_hour` (60), `demote_per_hour` (20),
  `max_fine_dids` (1,000).
- **A per-DID override**, `auto`, `fine`, `coarse` or `off`. Only an admin
  may set `fine`; an owner may set the others for their own DID. Set it with
  the new `did-management/stats/set-resolution/0.1` Trust Task, which also
  reports the tier that applies and why, or offline with the new `stats-set`
  command. `stats-show` reports a DID's tier.
- **The chart's `bucketSeconds` now varies**: a DID without 5-minute detail
  is charted hourly (daily over 30 days). The UI uses the value it is sent.
- **Migration is automatic.** At startup the legacy `ts:` rows are folded into
  the new rows, a flush's worth at a time. Only the last 31 days are
  migrated, as no chart shows older, so memory is bounded by a month of
  history rather than the deployment's age. fjall and DynamoDB read them a
  page of 1,000 keys at a time (DynamoDB as a paged `Scan`), and a failed
  read is retried from where it stopped. Redis, Firestore and Cosmos DB read
  them whole, and after a failed read wait 5 minutes before reading again.
  Charts read the legacy rows until it completes. It can run again safely,
  and picks up rows an older version wrote after a rollback. Legacy rows are
  kept for 30 days, then deleted; `stats-purge-legacy` deletes them at once.
- Removing a DID deletes its statistics rows: an explicit delete, and on the
  daemon also the empty-slot cleanup and the domain purge sweep.
- Displayed totals include counts not yet written.
- A flush tick (the paced flush, then the migration step) starts no writes
  after its 10-second interval; under a slow store, what is left waits for
  the next tick instead of delaying it.

See `docs/stats-tiers.md`.

### Changed — a peer's advertised Trust Task HTTPS endpoint must be public `https`

When a peer's DID document advertises `TrustTaskHTTPS` (and no TSP or DIDComm
service), the control plane's pushes and health pings, and an edge's
registration, stats and replication sends, `POST` to that endpoint. The URL is
the peer's to name, so it is now held to an outbound policy (via
`affinidi-net-guard`): `https` to a public host only. An endpoint on loopback,
a private, link-local or carrier-grade NAT range, or a special-use name
(`localhost`, `*.internal`, single-label names) is treated as not advertised:
the send falls back to the configured mediator, or fails as unroutable. What
the name resolves to is checked again when the request connects. Redirects
are not followed, timeouts are finite and the reply is capped at 1 MiB, as
before. A non-2xx reply body is sanitised and truncated before it reaches a
log line or an outbox error.

- **Behaviour change:** a peer that advertises `TrustTaskHTTPS` at
  `http://localhost:…`, `http://127.0.0.1:…` or a private address is no
  longer sent to. Advertise a public `https` endpoint, or a TSP / DIDComm
  service.
- URLs an operator configures (`WebVHClient`'s server URL, `WitnessClient`'s
  witness URL) are unaffected.
- Setup (interactive and recipe) and the control plane's sign-in self-check
  now note when this node's own advertised `TrustTaskHTTPS` endpoint is one
  other nodes will not send to.
- There is no setting yet to admit private address ranges; a deployment whose
  nodes reach each other only over a private network uses TSP/DIDComm through
  a mediator.
- A peer whose endpoint is refused is warned about once per process; repeats
  are logged at debug.

### Changed — outbound HTTPS Trust Tasks share one client and one verifier

An HTTPS send built a new HTTP client, and a new reply verifier, for every
request. Each service now verifies HTTPS replies with the verifier it checks
inbound documents with, so DID-status verdicts are reused and forced
re-resolutions of a peer's DID are rate-limited across calls (at most one per
DID per 30 s) on these paths too. Replies get a forced-refresh allowance of
their own (`TransportBoundVerifier::for_replies`), so inbound documents cannot
use up the re-resolution a just-rotated peer's reply needs. `WitnessClient` and `WebVHClient` build
their verifier once per client. HTTP clients are built once per process, so
connections are reused.

- **API:** `send_trust_task` and `send_trust_task_with_retry` take a
  `send::Peers` (DID cache and verifier) in place of `Option<&DIDCacheClient>`.
  `post_trust_task_https` still builds a verifier per call and is meant for
  one-off callers; long-lived callers use `post_trust_task_https_verified`.

### Changed — rate limits run on `affinidi-rate-limit`

Every per-address and per-source rate limit (resolution, each Trust Task
listener, the challenge, invite redemption, wallet sign-in, and the
per-address and service-wide large-document budgets), and the rule for which
address a request comes from, now use the `affinidi-rate-limit` crate the mediator and the DID resolver cache use. Each limit is still stated
as requests per window, with the same numbers, but is now a token bucket: a
client may spend its allowance at once and regains one request every
`window / max`, so `Retry-After` is the time to its next request rather than
to the end of the window, and there is no double burst across a window
boundary. Refusals are logged once per client per window. Idle clients are
swept every minute, and at most 250,000 are tracked per limit (previously
10,000, with the map cleared when full). The `429` keeps its shape. Its `message`
changes: the resolution limit sends the crate's generic text, and the other
limits share one template naming their numbers, replacing the challenge's and
redemption's own wording. The large-document budget keeps its own penalty (an
address whose claimed issuer did not verify pays double for its next large
document) on top of the crate's buckets, and tracks at most 10,000 addresses.

Four refusals change. A chain from a trusted proxy that cannot be read (a
malformed entry, more than 64 entries, or a header that is not visible ASCII)
is refused with `400` instead of being charged to the proxy's address, which
handed its sender a second budget and hid a misbehaving proxy; the first such
chain from a proxy each minute is logged as a warning naming it. The `400`
carries the same body everywhere a request is charged to an address — `{
"error": "invalid_forwarded_for", "limiter": "<limiter>", "message": "..." }`
with `x-rate-limit-source: did-host` — except `POST /api/trust-tasks` on the
control plane, which refuses it, like everything else it refuses, with a
`trust-task-error` document (`malformedRequest`).
`server.trusted_proxies` refuses a range covering every address (`0.0.0.0/0`,
`::/0`) at startup. A resolution request with no peer address, a wiring
fault, is refused with `403` instead of `500`. And when a limit already
tracks 250,000 clients that are still within their budget, a new client is
refused with `429` and `Retry-After: 60` until room frees up, rather than the
limit forgetting everyone.

### Changed — `auth/step-up/approve-response` moves to 0.7

The VTA and the VTC moved every step-up answer to
`auth/step-up/approve-response/0.7` and stopped serving 0.6
(OpenVTC/verifiable-trust-infrastructure#2346), and the browser wallet
cuts over with them (OpenVTC/vta-browser-plugin#412). Its lock holds one
version per slug, so after that change the wallet sends only 0.7, and a
control plane still on 0.6 refuses every `stepUpVta` approval. The control
plane now serves 0.7 only; 0.6 is no longer accepted. Merge together with
the wallet's change.

The payload is unchanged. 0.7 relaxes the specification's proof
requirement and spells the `assertionInvalid` `details.reason` values in
lowerCamelCase. The control plane still requires an `assertionMethod`
proof (a relying party may be stricter than the specification) and emits
no `details.reason`, so neither change alters what it does. The UI's
generated types follow the lock.

### Changed — a claim-code check waits a bounded time for a hashing slot

Passkey invite claim codes are checked with Argon2 in a small fixed number of
concurrent slots. A check that found every slot busy used to wait for as long
as it took. It now waits at most `auth.claim_code_hash_wait_ms` (default
5000 ms, at most 60000; env `*_AUTH_CLAIM_CODE_HASH_WAIT_MS`) and is then
answered `unavailable` with a retry time (`RateLimited`, limiter
`claim-code-hashing`). The same bound applies to a redemption waiting behind
another attempt on the same invite. A refused check counts no wrong code
against the invite. A slot is now held until its hash finishes, even if the
caller has gone away; before this, a cancelled request freed its slot while
its hash was still running. Issuing an invite has its own two slots, so
redemption attempts cannot hold up an administrator issuing one. A config
file with a wait above 60000 ms is refused at load.

### Changed — per-address limits count an IPv6 client by its /64, and proven callers keep a share of the large-document budget

Every per-address limit counted an IPv6 client by its full address, so one
host could draw a fresh allowance from each address in its block. Only the
resolution limit counted a /64. Now every one does: the Trust Task listener
limit on the edge, witness and watcher, `POST /api/auth/challenge`, passkey
invite redemption and login start over HTTPS, wallet sign-in (`auth/oob/*`)
and its open-poll cap, the sign-in replay quota per source, and the
large-document budget per address.

- New `[server] client_ipv6_prefix` (default `64`, `1` to `128`) sets the
  network an IPv6 client is counted by, for those limits and for
  `[server.resolve_rate_limit]`. A value outside the range stops the service
  at startup. IPv4 clients are counted by their address, as before.
- The large-document budget across all addresses (60 a minute) is split. An
  address whose large `did/register` verified as the issuer it claimed in the
  last hour draws on 40 of those that no other address can spend. Every other
  address shares the remaining 20, and a proven address falls back to them
  once its own 40 are spent. A claim that does not verify ends the address's
  proven standing.
- The forced re-resolution of a signer's DID is limited per DID with any
  path, query and fragment removed. Before, only a `did:scid`'s lone `?src=`
  was removed, so a `src` with further parameters, or another query, counted
  as a different DID.

Behaviour change (R3.6): no wire shapes change. Clients in one IPv6 /64
now share one allowance on each of the limits above, so several hosts behind
one /64 (or a deployment that hands out addresses from one) can be refused
sooner; set `client_ipv6_prefix = 128` to count each address alone. A
caller's first large document, before it has verified once, and every large
document from a new address, competes for the 20-a-minute share. Log lines
for a limited IPv6 client name its network, not its address.

### Changed — a witness caller can be allowed to request signatures and nothing else

On a witness, `webvh/witness/sign` required an `admin` ACL entry, and an
`admin` can also create and delete witness identities and administer the
witness's ACL. So a control plane, VTA or edge that only needs proofs had to
hold a credential that could delete every witness identity and grant access
to others. `webvh/witness/sign` now also accepts a `service` entry, and
nothing else on the witness does: `key/create`, `key/list` and `key/delete`
still require `admin`, and the ACL tasks still require `admin` (any member
may show or revoke its own entry, as before). An `owner` or `metricsReader`
entry still can do nothing on a witness.

Existing entries and how they move:

- An `admin` entry keeps every permission it had; nothing stops working.
  To narrow a caller that only requests signatures, change its role to
  `service`: `acl/change-role` (`fromRole: admin`, `toRole: service`) from
  another admin, or `webvh-witness remove-acl --did <DID>` then
  `webvh-witness add-acl --did <DID> --role service`. The last `admin`
  cannot be demoted.
- An existing `service` entry on a witness, which could do nothing there
  before, can now request signatures.
- On a witness, a `service` entry now states `keys: {"scope": "all"}` in
  `acl/show` and `acl/list`, since it may have the witness sign with any of
  its identities. An `acl/grant` of a `service` entry to a witness must say
  `keys: {"scope": "all"}`; one saying `none` is refused (`taskFailed`,
  `details.reason: notSupportedByMaintainer`).
  Other services are unchanged: they sign nothing for their members.
- `webvh-witness add-acl` now requires `--role`, and accepts only `admin`
  or `service`. It defaulted to `owner`, which can do nothing on a witness.
- `did-hosting-daemon add-acl --witness` and `list-acl --witness` write and
  read the embedded witness's ACL, which had no CLI before.

### Changed — refresh tokens are stored as SHA-256 digests

The session row and the refresh index key held each refresh token as issued.
They now hold `sha256:` and the token's SHA-256, so reading the sessions
keyspace (a Redis, DynamoDB or Cosmos backend, or a backup) does not yield a
token that redeems. The settlement marker a refresh checks is keyed the same
way.

Sessions written by an earlier release keep working: a token of the shape
those releases issued is also looked up under its old key, and a stored digest
is never accepted in place of a token. The session sweep now also removes
refresh index entries no session issues any more (the session has gone, or a
later sign-in replaced the token without retiring it).

### Changed — service keys are wiped from memory when dropped

`ServerSecrets`, `RetiredKeys` and `StoredSecrets` are zeroized on drop, as is
the serialised envelope, the JWT key's DER encoding and a key a rotation
replaces. Signing a Trust Task copies only the signing key rather than every
live key.

### Changed — the edge and the daemon serve HTTP under connection and time limits

The public listener of `did-hosting-server` and `did-hosting-daemon` now runs
on the shared bounded listener the witness and watcher already use. It
limits connections to 256 at once and 32 per address (IPv4 address or IPv6
/64; `server.trusted_proxies` exempt), allows 20 s for request headers, and
closes a connection after 60 s idle. The edge's `POST /api/trust-tasks` reads
its body after the per-address limit rather than before, bounded in size as
before and now in time (30 s; `408` past it, `413` over the size).

Behaviour change (R3.6): a client past these limits is disconnected or refused
where it was served before.

### Changed — a registration acknowledgement is logged only when it verifies

An edge logged "registration acknowledged by control plane" at `info`, with
the `instanceId` from the document, for any `server/register` response that
reached it, including one posted to its HTTPS listener by anyone. The
acknowledgement is now checked as the control plane's, as every control-plane
document is. An unverified one is logged at `debug` without its contents.

### Changed — `server.trusted_proxies` and `server.trusted_proxy_cidrs` are documented together

The two lists answer different questions: which client sent a request
(`trusted_proxies`) and which host it addresses (`trusted_proxy_cidrs`).
Behind a reverse proxy, list the proxy in both. The edge and the daemon now
warn at startup when only one of them is set.

### Changed — the console signs out in every tab, and takes the invite token out of the address bar

- Signing out (or a session ending on a `401`) in one tab now signs out every
  other tab of the console that holds the same session, through a
  `BroadcastChannel`. Before, another tab kept its in-memory token and session
  key until its next request was refused.
- The enrolment page reads the invite token once, then removes it from the
  address bar and the current history entry (`history.replaceState`), so it
  is not left on screen, in history or in a bookmark. The page also asks the
  browser to send no `Referer` (`<meta name="referrer">`), in addition to the
  `Referrer-Policy: no-referrer` the control plane and daemon already send.
- The comment on where the console keeps its tokens now says what protects
  them. IndexedDB is not a boundary against a script on the origin; the
  non-extractable session key is, together with the control plane requiring a
  proof on every task that acts.
- The UI's npm `overrides` use caret ranges at the locked majors (`minimatch
  ^11.0.4`, `postcss ^8.5.10`, `@xmldom/xmldom ^0.9.12`, `uuid ^11.1.1`, `ws
  ^8.20.1`, `shell-quote ^1.8.4`, `glob ^14.0.2`) instead of open-ended `>=`
  ranges, so a lockfile regeneration cannot jump a major. The lockfile is
  unchanged.

### Changed — enrolment invite links carry the token in the fragment

Invite links (`auth/passkey/enroll/invite` responses and the operator CLI)
are now `{base}/enroll#token=…` instead of `{base}/enroll?token=…`. A browser
never sends the fragment, so the token no longer reaches the web host's
request line, its access logs or a `Referer`. The claim code is still sent
separately, as before.

Behaviour change (R3.6): the link format changes. The enrolment page reads
the fragment first and still accepts `?token=`, so links issued before this
release keep working until they expire. A client that parses the invite
`url` itself should read the token from the fragment, or use the response's
`invite.token` member.

### Changed — the control plane's HTTPS listener is bounded like the edge's

The control plane served `axum::serve` with no header or idle timeout and no
connection cap. It now uses the shared listener limits the edge, witness and
daemon use (256 connections, 32 per address or IPv6 /64, 20 s for request
headers, 60 s idle; `server.trusted_proxies` exempt from the per-address
cap). `POST /api/trust-tasks` reads its body within 30 s (`408` otherwise),
on the control plane and in the daemon.

### Changed — infrastructure messages from edges are typed and checked against the registry

- `server/stats-sync` is parsed as a closed type; an unknown member refuses
  the sync (`e.p.stats.malformed`). A delta whose resolve or update count is
  over 1,000,000,000 is skipped, and the stats totals saturate instead of
  wrapping.
- `replica/domain/*` acknowledgements that are not their task's response
  type are ignored.
- Two server DIDs can map to one registry id (`did:web:h:a_b`,
  `did:web:h:a:b`). A registration under an id another DID registered is
  refused (`e.p.registration.conflict`), and a health pong, domain
  acknowledgement or replication record from the other DID no longer
  updates that instance.
- A server's `servedDomains` claim at registration is kept only for a domain
  the control plane assigned to that server (its latest recorded domain
  operation is an assign). A server with no recorded domain operation keeps
  only domains the registry already listed for it.

### Changed — refusal texts no longer carry internal detail

A proof that does not verify is refused `proofInvalid` with the kind of
failure (malformed, unsupported cryptosuite, key not the issuer's, bad
signature), not the verifier's own message; the message is logged. A
registration the store cannot write is refused with a fixed text, and asks
for a retry when the store is throttled.

### Changed — deleting a DID, retiring an identity generation, purging a domain on an edge and granting an administrator need a stepped-up session

A request that presents a console session (a bearer token on
`POST /api/trust-tasks`) now needs that session at `aal2` for:

- `did-management/did/delete/0.1`;
- `did-management/identity/retire/0.1`;
- `did-management/registry/purge-domain/0.1`;
- `acl/grant/0.2` of an `admin` or `service` entry, and `acl/change-role/0.2`
  to either role. Grants and role changes to `owner` or `metricsReader` are
  unchanged.

Below `aal2` the request is refused before anything is written, with the
same refusal `domain/purge` already gave: `permissionDenied` with the message
`step_up_required`. The ACL tasks ask it of an administrator only; anyone else
gets the task's own refusal.

The console routes each of these calls through its step-up path: on that
refusal it steps a wallet session up through the wallet and sends the request
once more. A passkey session is `aal2` from login and sees no change.

Behaviour change (R3.6): a console wallet session now prompts for a step-up
the first time it deletes a DID, retires a generation, purges a domain on one
edge, or makes someone an administrator or service account. A client that
sends these tasks with an `aal1` bearer session must step it up first. A
request with no bearer session — a VTA sending signed Trust Tasks over
DIDComm, TSP or HTTPS — is authorised by its own proof as before.

### Changed — edge-facing refusals are typed

- A refused `server/stats-sync` or `server/register` now reaches the edge with
  a distinct standard code: `permissionDenied` (not authorised),
  `identityMismatch` (the payload names another server), `taskFailed` with
  `details.limit` (too many deltas), `malformedRequest`, or `internalError` /
  `unavailable` for a failure of the control plane's own (a registration that
  could not be stored was reported as `permissionDenied`).
- The health pong a control plane reads is closed: a pong carrying a member it
  does not read marks nothing active.
- An edge picks `historyRewrite`, `deactivated` or `invalidLog` for a refused
  sync from the kind the check carried rather than its wording, so a
  `did:webs` fork is now `historyRewrite` (was `invalidLog`). An edge also
  refuses to sync a log of a method whose history it does not check (a
  `did:web` document) instead of storing it unchecked.
- An unrouted bare DIDComm message is answered with the standard DIDComm
  `report-problem/2.0` message instead of the unpinned
  `did-management/did/problem-report/0.1`.

### Changed — the console is keyboard- and screen-reader-usable, and meets WCAG AA contrast

Buttons, pickers, inputs and dialogs are shared primitives with roles, names,
state (`checked`, `expanded`, `busy`, `disabled`), a visible focus ring, and
Enter/Space activation; inputs are labelled, page and card titles are
headings, forms submit on Enter, and status is spelled out rather than shown by
colour alone. Tertiary text and filled buttons now meet the 4.5:1 contrast
ratio.

### Changed — the console caches and shares its reads

Screens read through one small cache that deduplicates requests, shows held
data while it refreshes, polls only while the page is visible, ignores a late
answer for a view the operator has moved off (a quick usage-chart range switch
no longer shows the previous range), and refreshes what a change touched.
Editing an ACL entry sends only what changed. The settings page no longer
re-renders every second for every viewer.

### Changed — the console confirms destructive actions in its own dialog, and removing an owner says what happens to their DIDs

Every destructive action in the management console — deleting a DID, rolling
back its last entry, purging or deleting a domain, purging a domain on one
server, retiring an identity generation, revoking a passkey or an invite —
now asks in an in-app dialog with a title, an explicitly labelled action and
focus on Cancel, instead of the browser's `confirm()` (which a browser can
silently suppress). Deleting a DID and purging or deleting a domain also need
the name typed first.

Removing an access entry is one dialog with three choices: remove access only,
remove access and delete the DIDs the account owns (listed, and confirmed by
typing), or cancel. Deleting shows each DID's progress; if any fails, the
access entry is kept and the failures are listed with a retry. Success and
failure notices appear as in-app messages rather than `alert()`.

### Changed — the console keeps your place and your work when you sign in or your session ends

One route guard now covers every page: a reload shows a splash while the
saved session is restored (no more flash of "Please log in"), a signed-out
visitor is sent to the sign-in page and brought back to the page they asked
for (`/login?next=…`, honoured only for a path on the console's own origin),
and a session that expires mid-task shows a "Session expired — sign in again"
banner over the page, with sign-in in a dialog, so whatever was typed on the
page is still there afterwards.

### Changed — console forms validate inline and the console explains itself

- Creating a DID checks the path against the control plane's own rules as you
  type and keeps Create disabled while the path is invalid, taken or still
  being checked; success says what to do next. "Create root DID" reserves the
  root of the selected domain and explains what it is.
- The access form checks the DID or agent name and the quota numbers inline,
  and each role has a one-line description. Creating a domain checks the host
  name the way the control plane will.
- A small "?" explains protocol terms (witness, watcher, portable,
  pre-rotation, TTL, alsoKnownAs, step-up passkeys, domain scope).
- Copy says "control plane" rather than "the daemon", names
  `did-hosting-server` correctly, and uses one verb, "Sign in", throughout.
  The older wallet sign-ins are described in plain language with a
  "What is this?" disclosure.
- When a session needs a step-up the browser cannot provide, the message says
  exactly what to do.

### Changed — the DID page offers document editing only when it can be published, and shows parameters read-only

Without a wallet that can relay to the DID's agent, the document editor is not
offered (it could not sign anything) and the page says how updates are made
instead; the "Copy to Upload" button, which discarded the edit, is gone. The
parameters card is read-only, with a "Copy parameters JSON" action.

### Changed — the Access page and the dashboard fit an owner's account

The Access nav item and page are administrator-only, as the control plane
already enforced. An owner's dashboard shows their DIDs per domain.

### Changed — `health` exits non-zero on a failed check

`did-hosting-server`, `did-hosting-control`, `did-hosting-daemon`,
`webvh-witness` and `webvh-watcher` `health` now exit 1 when any check fails,
or when the config cannot be loaded (before, it always exited 0), so
`health && deploy` and container probes can act on it. `--strict` also fails
on warnings (a store held by the running service, plaintext secrets, a
non-2xx reachability probe). The run ends with a summary line. Colour is used
only when stderr is a terminal and `NO_COLOR` is unset. The store check names
the backend's own location (the data directory for fjall; the server without
credentials for Redis; table prefix and region for DynamoDB; project and
database for Firestore; database and region for Cosmos DB).

### Changed — CLI listings go to stdout; `add-acl` persists before it reports

`list-acl`, `tsp-relationship-list` and `identity-list` print their listings on
stdout (diagnostics stay on stderr), so `list-acl | grep did:` works.
`add-acl` flushes the store before reporting success, as `remove-acl` already
did.

### Changed — `features.rest_api` is now `features.http_listener`

The flag runs the HTTP listener (the UI, `POST /api/trust-tasks`,
`/api/health`), not a REST API, so it is renamed `http_listener` (env
`<PREFIX>_FEATURES_HTTP_LISTENER`). `rest_api` and `<PREFIX>_FEATURES_REST_API`
are still accepted; when both env names are set, `_HTTP_LISTENER` wins. Read by
the control plane, witness and watcher; the edge always serves HTTP.

### Changed — setup wizards check URLs, DIDs and the listen host as they are entered

URL prompts require an `http://` or `https://` URL with a host, DID prompts
(VTA, mediator, control plane, admin, watcher sources) require the
`did:<method>:<id>` shape, and the listen host must be an IP address; a bad
answer is re-asked with the reason instead of failing later at provisioning or
first boot. When the VTA DID cannot be resolved, the wizard says so instead of
silently offering no mediator.

### Changed — `--path` and `--mnemonic` both name a DID slot

`stats-show`, `stats-set`, `bootstrap-did`, `load-did`, `dump-did`,
`recreate-did`, `recover-did` and `remove-did` accept either `--path` or
`--mnemonic`. Messages that suggest a command now name the binary that is
running (`did-hosting-daemon remove-did …` from the daemon).

### Changed — the control plane queues replication with the change that causes it, as references

A DID publish, register, delete, rollback, suspension, witness upload or
agent-name change now writes its sync rows for every server and watcher in the
**same store transaction** as the change. A crash between the two can no longer
lose the push, and a slot's rows reach each server in commit order (a publish
quickly followed by a delete no longer risks the delete arriving first).

Outbox rows no longer carry the `did.jsonl`: a row names the slot (or the
domain), and the worker reads it when it sends. Rows are a few hundred bytes
whatever the log's size, so a resync batch can no longer exceed DynamoDB's
400 KB item limit; a resend carries the newest state, and a slot deleted before
its row is sent goes out as a delete. A slot or domain already queued for a
server is not queued again — an edge that registers while its queue is still
draining no longer has the same delta appended each time — and an
acknowledgement of a state a later change superseded re-arms the row rather
than settling it.

Delivery is cheaper and fairer: the worker reads only the head of each queue,
finds the row an acknowledgement answers through an index, services targets
concurrently, and locks per target rather than globally. The replication
gauges read a count and the head rather than the whole queue. A registration
queues domain rows before DID rows, and pages through the DID records.

Rows queued by an earlier version are re-keyed when the worker starts and drain
as before.

### Changed — unacknowledged sends back off, and are counted apart from failures

A send the mediator accepted but the target never acknowledged was re-sent every
minute, so an offline edge exhausted its budget in about 50 minutes and
collected a copy a minute. The wait now doubles from one minute to an hour,
with jitter, for up to 24 sends (about 19 hours); hard delivery failures keep
their own budget (50, about 3.5 hours). An acknowledgement of any of the last
16 copies sent settles the row. New counters on `server/metrics`:
`webvh_outbox_enqueue_failures_total`, `webvh_outbox_delivery_failures_total`,
`webvh_outbox_unacked_resends_total`, `webvh_outbox_dropped_total` and
`webvh_outbox_record_failures_total`.

An assign a server acknowledged is no longer re-sent on every registration
while the server still reports serving the domain; it is re-sent to one that
registers without it.

### Changed — `did/list` pages from the store, and quota checks stop scanning

`did/list` no longer reads, parses and sorts every record for each page. On
fjall and Redis a page starts at its cursor in the owner index, a new
per-domain index (`domain:{domain}:{mnemonic}`) or the records, and stops
when it is full. On DynamoDB, Cosmos DB and Firestore, whose pages are not in
key order, a page is still one walk of the records, but holds only the page
in memory; the order and the cursor are the same on every backend. Pages stay
in mnemonic order.

The `vnd.affinidi.webvh` request extension of `did/list` takes `search`
(1–200 characters, matched without case against the mnemonic, the DID and its
agent names) and `agentName` (with `domain`: the slot holding that name, from
the name index). A searched page reads at most 5,000 rows and may come back
short, or empty, with a `nextCursor`; keep paging while one is present. An
unknown member of the extension is refused. The same extension's `domain` on
`stats/get` (without `mnemonic`) answers the per-domain aggregate: every slot
on the domain for an administrator, the caller's own slots otherwise.

Each owner's slot count and stored bytes are kept in a `usage:{owner}` row
written in the same batch as the record, so the count and size quotas read one
row instead of every slot the owner holds. Both new kinds of row are built for
an existing store by the `m03_index_did_records` migration, which the control
plane and the daemon run at their first boot after upgrade; a control plane
that cannot run it does not start. Control-plane replicas sharing one store
should be upgraded together: a replica on the previous version writes records
without updating these rows.

### Changed — boot and periodic work no longer hold whole keyspaces in memory

The boot-time integrity check, the session cleanup, the domain purge and the
storage migrations walk the store a page at a time, and the DID counts (the
stats seed and the hourly recount) count keys without reading values. The
stats seed retries a failed store read with backoff and logs it, rather than
silently starting the totals at zero, and the statistics collector no longer
fails every later resolve after a panic while it held its lock.

### Changed — a hosting server answers resolution from memory, with ETags, `304` and compression

- A standalone edge now keeps the resolution gate cache (each DID's record and
  the domains) the daemon already kept: every change an edge serves arrives as
  a control-plane directive it applies in-process, and each one — sync update
  and delete, domain upsert, assign, unassign and purge, the reconcile repair,
  the empty-slot cleanup — clears what it changed through one helper. A warm
  resolve reads nothing from the store. The record is read once per request
  however many method dispatchers look at it.
- Resolved content is held as shared bytes (a hit no longer copies the
  document) with a strong `ETag` computed when it is cached; a matching
  `If-None-Match` is answered `304 Not Modified`. Responses are gzip- or
  brotli-compressed for clients that accept it; the compressed form carries
  the tag weakened (`W/`), which still revalidates.
- The content cache is bounded: `limits.content_cache_bytes` (default 256 MiB),
  dropping the oldest entries past it.
- The HTTP runtime's worker threads default to one per available core instead
  of four; `limits.http_worker_threads` sets them.
- A cold resolve verifies the log on a blocking thread, and a `did:webs`
  `did.json` is derived once per key event log (memoised in memory on the
  stream's SHA-256, so it can never serve a document from before a rotation).

### Changed — an edge applies syncs per slot, verifies before locking, and keeps compact high-water marks

- Sync updates verify the log's chain on a blocking thread before any lock is
  taken, then lock only the slot (and the DID's identity) for the
  read-check-write, so syncs of different slots run in parallel. Re-sending
  exactly what the edge holds is answered `unchanged` without re-verifying it.
- The high-water mark kept for each DID (the tombstone that stops a deleted
  DID's history being rolled back) is now its entries' version ids rather than
  a second copy of the whole log; a `did:webs` mark still keeps its key event
  log. Rows in the old format are read as before and rewritten at boot.
- Registration, the reconcile loop, the empty-slot cleanup and the boot count
  page through the store instead of reading every DID record at once, and the
  health ping reports the in-memory DID count; the per-DID boot log line is
  now `debug`.

### Changed — the console pages and searches the DID list on the server

The DID list no longer reads every DID before it shows any. It asks
`did/list` for 50 at a time, filtered to the pinned domain and to the search
box by the control plane (name, DID or agent name), with **Load more** for
the next page; sorting applies to the DIDs loaded. The dashboard's
pinned-domain cards read that domain's totals with one `stats/get` instead of
listing every DID (the update count is now the real number of updates), and
granting access by agent name looks the one name up instead of listing every
DID. A DID's page reads its log once per load rather than twice, and the
usage chart (with its charting library, most of the console's script) loads
only on the pages that show it.

### Changed — the watcher verifies syncs in parallel and stores a compact high-water mark

A watcher verifies a synced log's chain on a blocking thread before it takes
any lock, and serialises only the read-check-write, per slot and per DID,
instead of every sync behind one process-wide lock. A re-send of exactly the
log it already mirrors is not re-verified. The high-water mark it keeps per DID
is now its entry count, last `versionId`, a SHA-256 over its entries and
whether it deactivated the DID, not a second copy of the log; rows an earlier
release stored as full logs are rewritten at startup. The mark still survives a
delete, as the DID's anti-rollback tombstone.

### Changed — watcher resolution answers conditional requests

Watcher resolution reads the store once per request (disabled slots are
tracked in memory) and sends a strong `ETag`, answering a matching
`If-None-Match` with `304 Not Modified`.

### Changed — the witness signs without a process-wide lock

`webvh/witness/sign` verifies the log off the async workers, and serialises
only requests for the same witness identity and DID while the witnessed mark
moves; signing happens after the lock is released. The mark's
compare-and-swap is unchanged.

### Changed — the management console's assets are cacheable and compressed

The control plane and the daemon send content-hashed console bundles
(`_expo/static/…`, hashed `assets/…`) with `Cache-Control: public,
max-age=31536000, immutable`, other files with `no-cache`, and every non-HTML
file with a strong `ETag` (answering `If-None-Match` with `304`); the console's
HTML stays `no-store`. Console responses are gzip- or brotli-compressed when
the client accepts it. In the daemon, files of the console's bundle are no
longer charged to the public resolution rate limit.

### Changed — `did-hosting-control` refuses to build with no storage backend, or with more than one

Its build script used to print a warning and carry on, leaving a binary that
could not open a store (none selected) or picked one by accident of cfg
ordering (several). It now fails the build with the same message as
`did-hosting-server`, `webvh-witness` and `webvh-watcher`: enable exactly one
of `store-fjall`, `store-redis`, `store-dynamodb`, `store-firestore` or
`store-cosmosdb`.

### Changed — release builds use one codegen unit and strip symbols

`[profile.release]` adds `codegen-units = 1` and `strip = "symbols"`
alongside the existing `opt-level = "s"` and `lto = true`. Release binaries
are smaller and a little faster to run, slower to build, and a panic
backtrace from one shows addresses rather than function names; build with
`CARGO_PROFILE_RELEASE_STRIP=none` when you need them. `opt-level` stays at
`"s"`: `3` measured no faster on webvh log verification and made the binary
about 27% larger.

### Changed — building the management UI requires the Node.js version in `did-hosting-ui/package.json`

The `ui` feature's build script (`did-hosting-control/build.rs`, used by the
control plane and the daemon) now reads its Node.js floor from `engines.node`
in `did-hosting-ui/package.json` (currently `>=24.3.0`) instead of its own
`20`, so the two can no longer disagree. A build that rebuilds the UI on an
older Node now stops with a message naming the required version; build with
`--no-default-features` (see the crate READMEs) to skip the UI.

### Changed — shipped setup recipes run as documented

`examples/did-hosting-server-build.toml` sets a placeholder
`[identity].control_did` (replace it with your control plane's DID), so it is
no longer refused as shipped, and the new
`examples/did-hosting-daemon-self-managed.toml` sets up a VTA-less daemon on
`localhost` with no edits. CI loads and validates every recipe in `examples/`.

### Changed — documentation reorganised

`docs/README.md` indexes the documentation; every page carries a status line,
superseded designs and plans moved to `docs/archive/`, and new pages cover
configuration, deployment, backup and upgrade, metrics, troubleshooting, the
architecture and trust model, and a glossary. A `docs` CI job checks status
lines, relative links (lychee, offline) and retired names.

### Changed — a fjall store flushes its writes in the background, holding at most 8 MiB in memory by default

Every service that opens a local fjall store (control, server, witness,
watcher, and the daemon's two stores) now runs a background flusher. fjall
3.1 records `max_write_buffer_size` but does not enforce it, so before this
change buffered writes stayed in memory, and in the journal replayed at
startup, until fjall flushed on its own schedule. The flusher seals the
memtables once the unflushed bytes across all keyspaces reach
`[fjall].write_buffer` (env `STORAGE_FJALL_WRITE_BUFFER`; default **8 MiB**,
previously effectively unbounded), and flushes anything older than five
minutes however small, which also keeps the journal short. Memory use and
flush behaviour change for every fjall deployment; raise
`[fjall].write_buffer` if a write-heavy service now flushes more often than
you want. (#340)

### Changed — background work is supervised, and shutdown is ordered and bounded

`did-hosting-server`, `did-hosting-control` and `did-hosting-daemon` now run
their background work under a supervisor. A task that stops on its own while
the service is running is logged at `error`: the restartable ones (the
outbox, the purge and identity sweeps, the registry health check, the edge's
registration, reconcile and stats-sync loops) are restarted with backoff
(1 s, doubling to 60 s); the critical ones (the HTTP listener and the storage
thread or task, which persists the store) shut the service down with a
non-zero exit so the orchestrator restarts it. Before this a dead worker was
noticed only at shutdown, and the service kept answering `/api/health` while
replication, identity expiry or the statistics flush had stopped.

Shutdown runs in stages, each given at most 30 seconds: the workers, then the
messaging service (awaited — "DIDComm service stopped" is now logged only
once it has), then HTTP, then work requests handed off (an edge's resync),
then the storage thread's last flush and the store's persist — which
therefore runs after the outbox worker has stopped. The daemon's HTTP server
had no deadline, so one stalled connection could hold up `SIGTERM`
indefinitely; it now has the edge's 30 s.

An edge (and the control plane, and the daemon) now retries starting its
messaging service with backoff instead of giving up after one warning, so an
edge whose mediator is briefly unreachable at boot still comes to reconcile
with its control plane.

### Changed — the daemon's `/health` reports the real check

`GET /health` on `did-hosting-daemon` answered `ok` unconditionally. It now
answers `200` only while the daemon's own DID is served from its store, and
`503` with `"status": "degraded"` otherwise — the check the standalone
services' `/api/health` makes. Its body gains a `version` field.

### Changed — `did_hosting_control::server::AppState` is built by `AppState::build`

For crates embedding the control plane: `AppState` drops the unused
`http_client` field and gains `background` (the tracker of work handed off by
a request, awaited at shutdown). Build one with `AppState::build(config,
store, secrets, identity, AppStateOverrides { .. })` — the recipe the
standalone control plane, the daemon and `test_support` all use — and run
its boot steps with `server::startup`, rather than writing the literal.

### Changed — the control plane no longer records `trust_task_capable` for a server

Every health ping has been a signed trust task for some time, so the registry flag
that once chose between a trust-task ping and the legacy `MSG_HEALTH_PING` was stored
but never read. It is gone from the registry record, and edges no longer send the
`trust_task_capable` registration hint (a control plane that receives it from an older
edge ignores it, as it does any unknown hint).

### Changed — one did.jsonl parser for every did:webvh path

Validation, the publish and serve verifiers, witnessing and identity rotation now
share a single parse of a `did.jsonl` instead of five copies, and a publish no longer
parses every entry twice before checking signatures. Each line is read under the
method version of the entry before it, and a malformed `versionId` is refused by plain
validation too, as every verifier already did.

### Changed — the management UI package is named `did-hosting-ui`

The UI's `package.json` name and Expo slug were still `webvh-ui`.

### Changed — dependency generation: TDK 0.45, trust-tasks 0.39, vta-sdk 0.90

`affinidi-tdk` 0.45, `affinidi-messaging-sdk` 0.47 (`-didcomm-service`
0.32), `trust-tasks-*` 0.39, `vta-sdk` 0.90, `vti-common` 0.66, `vti-secrets`
0.39 and `affinidi-crypto` 0.3, the generation `vta-sdk` 0.90 is built
against, so the shipped graph holds one copy of each. The test mediator moves
to 0.52 with them.

### Changed — the service binaries return freed memory to the OS

`did-hosting-server`, `did-hosting-control`, `did-hosting-daemon`,
`webvh-witness` and `webvh-watcher` now use jemalloc as their global
allocator. With glibc malloc, memory freed after a burst of requests stayed
resident, so RSS ratcheted up to its high-water mark and never came down —
which looks like a leak on a memory graph. jemalloc (with
`background_thread:true`, `dirty_decay_ms:5000`, `muzzy_decay_ms:5000`,
exported as `_rjem_malloc_conf` because tikv-jemalloc-sys prefixes jemalloc's
symbols) returns freed pages to the OS, so RSS tracks the live heap.

It is behind a new default-on `jemalloc` feature on each of those crates and
installed only by the binaries (`main.rs`), never the libraries, so a program
embedding them keeps its own allocator. Build with `--no-default-features` (and
the features you need) to use the system allocator; MSVC targets always do.

### Changed — an invite that would be refused is refused before the passkey is made

`auth/passkey/enroll/redeem/start` now refuses an invite whose issuer or
amending administrator has lost administrator standing, and one that would pair
a passkey with a metrics reader, with `permissionDenied`. Before, these were
refused only at `redeem/finish`, after the invitee had created a passkey on
their authenticator, and the invite was spent. A start refused this way leaves
the invite in place. The finish still checks both. It now reads the role to
grant from the invite as it stands at the finish, not as it was when the
ceremony opened.

### Changed — the workspace moves to the affinidi-tdk 0.49 generation, and `didwebvh-rs` is no longer pinned exactly

Every crate moves to the Affinidi TDK generation built on
`affinidi-data-integrity` 0.9 and `affinidi-secrets-resolver` 0.6, together:
`affinidi-tdk` 0.49, `affinidi-did-common` 0.5,
`affinidi-did-resolver-cache-sdk` 0.9, `affinidi-did-webs` 0.14,
`affinidi-messaging-sdk` 0.50, `affinidi-messaging-didcomm-service` 0.38,
`affinidi-tsp` 0.5, `vta-sdk` 0.92, `vti-common` 0.68, `vti-secrets` 0.41,
the `trust-tasks-*` crates 0.41 and `agent-names` 0.2 (#486).

- `didwebvh-rs` is required as `0.8.3`. Since didwebvh-rs 0.8.3, which
  accepts the newer generation, an unlocked build (`cargo install` without
  `--locked`) gave it different `affinidi-data-integrity` and
  `affinidi-secrets-resolver` copies from the rest of the service, and the
  binaries failed to compile. An exact `=0.8.2` pin worked around that while
  `vta-sdk` and `vti-common` were still on the old generation. With the whole
  workspace on the new one, the pin is gone and unlocked builds compile
  again. Locked builds were never affected.
- `jsonwebtoken` moves from 10 to 12, the version `trust-tasks-https` and
  `vti-common` now use, so the service ships one copy instead of two. It is
  built with the `aws_lc_rs` backend, as they build it, instead of
  `rust_crypto`. Session tokens are still EdDSA, signed and verified only by
  this service. The `rsa` and `crypto-bigint` 0.5 advisories that
  jsonwebtoken 10 brought in no longer apply, and their `deny.toml` ignores
  are gone.
- `did-hosting-control` and `did-hosting-server` no longer declare the storage
  and cloud-secret backend crates themselves. Their `store-*` and `*-secrets`
  features turn on the same `did-hosting-common` features as before, which
  bring those crates in. No feature was renamed or removed.

The `acl/*` Trust Task versions do not change: `acl/{grant,show,change-role,revoke}`
stay at 0.2 and `acl/list` at 0.3. The next versions make a per-entry
`purposes` scope required, which this service does not implement yet.

No configuration, stored data or wire format changes.

### Changed — the workspace moves to the affinidi-tdk 0.50 generation, and the graph holds one trust-tasks copy

Every Affinidi / VTI crate moves together: `affinidi-tdk` 0.50,
`affinidi-messaging-sdk` 0.51, `affinidi-messaging-didcomm-service` 0.39,
`vta-sdk` 0.94, `vti-common` 0.70, `vti-secrets` 0.43, the `trust-tasks-*`
crates 0.41.2, `trust-tasks-build` 0.2.2 and the test mediator 0.56 (dev).
No source change was needed.

- The messaging stack is now on trust-tasks 0.41, so `trust-tasks-rs` and
  `trust-tasks-proof` 0.40 leave the dependency graph. `cargo tree -d` lists
  no duplicate `affinidi-*`, `trust-tasks-*`, `vta-*` or `vti-*` crate, and
  the `deny.toml` skips for the 0.40 copies, `trust-tasks-build` 0.1 and
  `pem` are gone.
- `fuzz/Cargo.lock` is refreshed the same way.

No configuration, stored data or wire format changes.

### Fixed — a DID an administrator suspended stays suspended until an administrator resumes it

`did/set-state` stored only whether a slot was suspended, not who
suspended it, and a re-register wrote every slot back as active. So a slot
an administrator suspended was resumed by its owner sending
`did/set-state active`, by the owner re-registering it, or by the owner
force re-creating the path. The record now notes an administrator's
suspension (`disabled_by_admin`, absent on older records, which read as
not suspended by an administrator). While it is set, the owner's `active`
is refused with `permissionDenied`, and a re-register or forced re-create
keeps the slot suspended. An administrator's `active` clears it.

Behaviour change: a re-register (`did/register` of an existing slot) and a
forced re-create no longer resume a suspended slot, whoever suspended it;
the slot is resumed with `did/set-state active`. An owner can still
suspend and resume a slot it suspended itself. An owner can no longer
delete a slot an administrator suspended (`permissionDenied`): the delete
is final, so a later re-register would start the slot afresh. An
administrator can still delete it.

Upgrade note: a binary from before this change does not know the marker
and drops it when it rewrites a record. After a downgrade, or while
replicas of mixed versions share a store, re-apply administrator
suspensions once every replica runs this version.

### Fixed — the large-document cost of an address decays, and a `did:scid` issuer's `?src=` is not a mismatch

A large `did/register` (over 64 KiB) whose claimed issuer does not verify
doubles its address's cost for the next one. That raised cost never went down
until the process restarted, so after three such documents an address could
send no large document at all: a shared egress address, or a load balancer
missing from `trusted_proxies`, stayed shut out after one sender's failures.
The raised cost now halves every 15 minutes and on each large document from
the address that does verify, and is forgotten once back to 1. The penalty
table keeps its 10,000-address bound and, when full, makes room by dropping
the penalties that have decayed.

The claimed issuer was also compared with the verified one as raw strings, but
the verifier reports a `did:scid` issuer without its `?src=` locator. An owner
signing as `did:scid:vh:1:…?src=…` was charged a penalty on every large
document it sent, although it verified. The two are now compared as
identities, without the locator.

Behaviour change (R3.6): no wire shape changes; an address is refused large
documents for less time than before, and a `did:scid` issuer with `?src=` that
verifies is no longer held to a raised cost.

### Fixed — a `did:webs` slot can be read, suspended, transferred and deleted

A `did:webs` slot's path ends in its AID, which is mixed case. Only
`did/register` accepted that path; `did/info`, `did/log`, `did/set-state`,
`did/change-owner`, `did/delete`, `did/rollback`, `agent-name/list` and
`webvh/witness/publish` checked it against the lowercase-only grammar and
refused it as an invalid path, so a registered `did:webs` could not be
inspected, suspended, transferred or removed. Each of these now takes the
path's grammar from the stored record, as a publish already did: the AID
grammar applies only to a slot recorded as `did:webs`, never because of
anything in the request.

What each does with a `did:webs` slot:

- `did/info` returns the record and no `logSummary`: that summary is read from
  a `did:webvh` log line.
- `did/log` returns one entry, the document the key event log implies now
  (re-verified, as on resolution), and with `raw` the stored `keri.cesr`.
  Earlier establishment events are not listed. Without `method-webs` it
  returns no entries.
- `did/set-state`, `did/change-owner` and `did/delete` work as for any slot.
- `did/rollback` is refused: it truncates a `did:webvh` log by line, and a
  `did:webs` key event log is only ever extended by its controller.
- `webvh/witness/publish` is refused with `invalidWitness`: a `did:webs`
  slot's witness receipts are part of its key event log.

`did/rollback` now applies to `did:webvh` slots only. On a `did:web` slot it
split the stored `did.json` by line: a pretty-printed document was left as
invalid JSON with no `did_id`, and pushed to every edge. It is refused for
every method but `did:webvh`, and the slot is left as it was.

`did/log` answers a path that is not a valid slot path with `notFound`, as it
answers a slot the caller may not read, so the answer does not depend on
whether a `did:webs` slot is recorded at an AID-shaped path.

Behaviour change (R3.6): no wire shape changes. Requests naming a `did:webs`
slot that were refused as an invalid path now succeed, or (rollback, witness
publish) are refused for the method instead. `did/rollback` on a `did:web` (or
any other non-`did:webvh`) slot is refused. `did/log` with a malformed path
returns `did-management/did/log:notFound` instead of a validation error.

### Fixed — outbound HTTP clients keep their timeouts and redirect policy

The client `did-hosting-common` uses to resolve a DID log from a hosting URL
and to send a Trust Task over HTTPS has a 30-second total timeout, a
10-second connect timeout, and refuses redirects. If that client could not be
built (the TLS backend or the platform certificate verifier failed to
initialise), it was silently replaced by a default client with no timeouts
that follows redirects. The failure is now returned to the caller as an error
instead: `WebVHClient::resolve_did` returns `WebVHError::Http`, and a Trust
Task HTTPS send fails like any other transport error. The client is now
public as `did_hosting_common::outbound_client`.

Two other clients now follow the same policy:

- `did-hosting-daemon setup` authenticates to a VTA's REST URL, taken from
  the VTA's DID document, with this client. Before, it used a default client
  with no timeouts that followed redirects.
- The health check's reachability probe (`check_url_reachable`) adds a
  5-second connect timeout to its 5-second total timeout and no longer
  follows redirects, so a 3xx is reported as that status. If its client
  cannot be built, the check fails with the reason instead of panicking.

Behaviour change: on a host whose TLS setup cannot initialise, these calls now
fail instead of running without timeouts or redirect refusal. The health
check reports a redirecting URL as reachable with its 3xx status, as it
already does for other non-success statuses, instead of following it.

### Fixed — a watcher slot stays with the source that first synced it

On a watcher with more than one source, a second source could change or
delete a slot another source held for the same DID. A slot now belongs to the
source that first synced it until that source deletes it. An update from
another source is refused `webvh/sync/update:notAuthorized` (in a batch, that
entry is refused with the same code). A delete from another source leaves the
slot in place and is answered `absent`, as before. Both are logged as
warnings.

The first sync wins, so two settings bound it:

- `[[sync.sources]]` lists a source with the `domains` it may sync DIDs for.
  A DID on any other host is refused `notAuthorized`. A source with no
  `domains`, and every source in `source_dids`, may sync any host, as before.
- A slot whose holder is no longer a configured source is released. The next
  configured source to sync it holds it, still held to the DID's high-water
  log, and the release is logged with the old holder. Removing a source is
  how an operator moves its slots to another.

Behaviour change: before, a second source could extend a DID held by another
source; now only the holding source can. A slot stored by an earlier release
belongs to the source its record names, which is the source that last wrote
it; no migration is needed. Operators with more than one source should check
which source holds each DID. A watcher with a single source is unaffected.

The holder check and the write are serialised per process only, and the store
has no conditional write: run one watcher process per store.

### Fixed — the daemon sends the standard response headers

`did-hosting-daemon` now sets the same response headers as the standalone
control plane, server, witness and watcher: `Content-Security-Policy`
(`default-src 'self'`, …), `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
`Strict-Transport-Security`, and `Cache-Control: no-store` on any response whose
handler sets no `Cache-Control` of its own. They cover the management console and
its assets, `POST /api/trust-tasks`, the embedded witness and watcher, and DID
resolution, which keeps its configured `[server.resolve_cache]` value.
`/health` is unchanged. Before this the daemon sent only the console's own HTML
headers, so Trust Task replies and error responses could be cached. Operators
whose reverse proxy already adds these headers will now see them twice and may
want to drop one copy.

### Fixed — dashboard polling no longer keeps an idle console signed in

The console's dashboard refreshed itself every five seconds, and each refresh
counted as activity, so a console left open on the dashboard never reached
`auth.admin_idle_timeout`. Requests the console sends on a timer now carry
`X-Background-Request: 1`. The control plane authenticates and answers them
as before, but does not record them as session activity. The dashboard refresh
and the pending-approval log check on a DID's page are marked this way, as are
the agent-name and DID reloads they trigger, and both polls pause while the
browser tab is hidden. A request without the header counts as
activity, as before.

### Fixed — signers outside the ACL get their own replay cache and bounded DID resolution

The control plane recorded every signed Trust Task document in one shared
replay cache, including those on the tasks that take a proof from a signer the
ACL does not list (`server/info`, discovery, the `auth/*` family, passkey login
and invite redemption). Such a signer (a fresh `did:key`, say) costs nothing to
create, so that traffic could fill the cache, which then refused every signed
request as `unavailable` until its records aged out. Verifying those proofs,
and a proxied login's delegation evidence, could also resolve any DID the
document named, twice.

- Replay records are now partitioned. Open reads (`server/info`, capability
  discovery, an `auth/oob/*` version this service does not serve) are not
  recorded at all. The shared cache holds only ACL members' and configured
  watchers' records. Sign-in rows from any other signer go to a separate cache
  (100,000 records, 1,000 per signer), and each source (client address on
  HTTPS, sender on DIDComm and TSP) may add at most 120 records a minute. A
  `did:webs` self-registration goes to a third, small cache. A document
  recorded in any of them is refused as a replay in all of them.
- Verifying a proof from a signer the ACL does not list runs the key-free
  checks (recipient, freshness, issuer/sender) first. If the DID must be
  resolved over the network (anything but a `did:key`), at most 16 resolutions
  run at once and 300 per minute across all such signers, each within 10 s,
  with no forced re-resolution retry. Past those limits the document is refused
  as `unavailable` with a `retryAfter`; a timeout is reported as an unreachable
  signer (retryable). The delegate of a proxied login whose principal is an ACL
  member, and whose delegation evidence that principal signed verifies, is
  verified as a member is.
- A proxied `auth/authenticate/0.3` is refused (`permissionDenied`) when its
  principal has no ACL entry, before its delegation evidence is checked. A
  `siopIdToken` must claim the principal as `iss` before it is resolved. Both
  evidence checks are bounded at 10 s.
- For every signer: a proof whose signer DID could not be resolved at all is no
  longer resolved a second time. The forced-refresh limiter is keyed on the
  DID's identity, so a `did:scid`'s `?src=` variants share one allowance, and
  tracks at most 4,096 DIDs.
- Behaviour changes (R3.6):
  - Signers outside the ACL, members' own sign-in keys included (a passkey
    login's browser key, a session key on `auth/refresh`, a proxied login's
    delegate, invite redemption), share the sign-in cache and per-source
    quota. When they are spent, those requests get `unavailable` (retryable)
    even though the shared cache has room. Members' own signed operational
    requests are not affected.
  - A non-`did:key` delegate whose mandate does not verify, and any other
    non-`did:key` signer outside the ACL, competes for the shared resolution
    slots and rate.
  - A signed open read can be resent; it is answered again rather than refused
    as `idConflict`.
  - A proxied login for a principal outside the ACL is now refused before its
    evidence is checked (it was refused later, at the ACL check, before).
  - A signer DID whose resolution fails, including a `did:webvh` whose log
    cannot be read to establish deactivation, used to get a forced fresh
    resolution within the same request. It now gets a retryable `unavailable`,
    and the retry resolves it afresh.
  - The new bounds are constants, not configuration.

### Fixed — `did:webs` registers over `did/register/0.1`

The `did/register/0.1` Trust Task refused every method but webvh ("this host
registers webvh only over this task"), and the REST `POST /api/dids/register`
that took `method: "webs"` has since been removed, so a host built with
`method-webs` had no way left to accept a `did:webs` publication. The task now
takes `method: "webs"` with the `keri.cesr` stream as `didData` and a `domain`,
on a host built with `method-webs`, through the same `register_did_atomic`
that verifies the log and builds the identifier from the slot. A host built
without it refuses `webs` by name, naming the feature. This is how a VTA
publishes the `did:webs` DIDs it creates.

### Fixed — agent names are reserved per name, and released when their DID is deleted

The check that an agent name is free and the write that binds it were held
under the claiming DID's own lock only, so two DIDs claiming the same free name
at once (`agent-name/update`, a plain publish, or `did/register`) could both
succeed, leaving both records listing the name and the index pointing at
whichever wrote last. Each name now has its own lock, taken after the DID's lock
and held from the check to the commit, so exactly one claim wins and the other
is refused as taken.

- `agent-name/remove` retires the name's index entry only while it points at
  the DID removing it; it no longer deletes another DID's entry.
- `did/delete` releases the deleted DID's agent names (active and parked),
  again only entries that point at that DID. Previously they stayed indexed
  against a DID that no longer existed. The names are removed in a second
  write right after the record, so a DID with many names stays deletable on
  stores that cap one transactional write (DynamoDB: 100 items).
- A domain purge likewise removes only the index entries that still point at
  each purged DID, after the record; in the daemon it now takes the control
  plane's DID and name locks while it deletes.
- The DID and name locks are released as soon as a publish or agent-name
  change commits, before the check for a rotation of the service's own DID.
- **Behaviour change:** an index entry that points at a DID which no longer
  exists, or whose record no longer lists the name, no longer holds the name.
  `agent-name/check` reports such a name available and it can be claimed.
- **Upgrading:** agent names left indexed by DIDs deleted before this release
  become claimable again by any DID on their domain.

### Fixed — error text with multi-byte characters is truncated safely

The control plane's outbox cut a failed delivery's error text at a fixed byte
offset; text with a multi-byte character across that offset (an edge's own
error message, or one of this service's messages containing `—`) stopped the
outbox worker. User-facing error messages capped in `did-hosting-common` had the
same problem. Both now cut on a character boundary.

### Fixed — the Redis store URL is logged without credentials

Opening the Redis store logged `redis_url` as configured, including any
username, password or query parameters. The log line now shows the scheme,
host, port and database only.

### Fixed — no warning per DID change when no edge is registered

"DID sync: no active servers in registry" (and its delete counterpart) was
logged at warn on every DID change whenever no edge was active, which for a
daemon is always. With no edge registered it is now logged at debug. With
edges registered but none active, so the change reaches none of them, it is
a warning at most once every 5 minutes.

### Fixed — per-key write locks are released when no longer in use

`PathLocks` (the per-slot, per-name and ACL write locks) kept one entry for
every key ever locked, for the life of the process, including keys that named
no stored record. An entry is now removed as soon as no task holds or waits
for its key, so the lock table stays as small as the set of keys in use.
Same-key callers still serialise exactly as before.

### Fixed — the HTTPS listener classifies a passkey ceremony without a full parse

`POST /api/trust-tasks` decides whether a request opens an invite redemption
or a passkey login (to apply its per-address limit) before the per-type size
limit runs. It used to parse every body, up to the route's largest limit, as
a whole Trust Task document to decide. It now looks only at the body's length
first (a body over those ceremonies' 64 KiB limit cannot be one and is refused
later by the size limit, before any parse), and otherwise reads only the
top-level `type`. A body over 64 KiB that is refused before dispatch is
answered with an unrouted error document instead of one addressed to it. A
redemption or login body that names the ceremony's `type` but is otherwise
malformed now counts against the per-address limit.

### Fixed — sessions and invites end with the passkey or ACL entry they rest on

Revoking a passkey left the sessions it had signed in, and the elevation
it had granted, in place until they expired. Removing a subject's ACL
entry (`acl/revoke` with `revocation.kind: entry`) left its sessions, and
the enrolment invites issued for it, in place, and redeeming such an
invite recreated the entry. Now:

- `auth/passkey/revoke/finish` ends the subject's sessions a login passkey
  signed in (when the revoked passkey is a login passkey) and returns
  sessions a passkey elevated to `aal1`. A session does not record which
  passkey established it, so this covers every such session of the
  subject, except that a passkey session the revocation was made from is
  kept (an elevation on it is still dropped).
- Removing an ACL entry, by `acl/revoke` or by the operator's
  `acl remove`, ends every session of its subject and withdraws the
  invites issued for it or by it. Narrowing an entry's act scope does
  neither. An invite redemption waits for a removal in progress, so it
  cannot recreate the entry in between. The subject's passkeys are kept:
  login checks the ACL, so they work again only if the subject is granted
  an entry again, and then they do. `acl remove` from the command line
  does not take the running control plane's removal lock, so on a store a
  running control plane shares (DynamoDB, Redis and the other networked
  backends) prefer `acl/revoke`.
- A refresh in flight while its session is ended or demoted does not undo
  that: the refresh re-applies it to the rotated session (an ended
  session's refresh is refused).
- `auth/passkey/enroll/redeem/finish` refuses (`permissionDenied`) an
  invite whose issuer no longer holds administrator standing, checked
  under the ACL write lock; the invite is spent.

Behaviour change: a subject signed in with a passkey is signed out when
one of its login passkeys is revoked from another session, and a removed
member is signed out at once rather than when its session expires.

### Fixed — a `mandateCredential` is checked as a decision and must name its own end

A proxied `auth/authenticate/0.3` backed by `delegationEvidence` of kind
`mandateCredential` verified the mandate's proof with the general proof
check, which does not refuse a principal whose `did:webvh` is
deactivated, and accepted a mandate with no `expiresAt`, which then let the
delegate sign in as the principal with no end. The mandate is now verified
as every other decision is (`TransportBoundVerifier::verify_approval`: an
`assertionMethod` proof by a key under the principal's own
`assertionMethod`, never a session delegate, from a principal that has not
deactivated its DID). It must carry `issuedAt` (not in the future) and
`expiresAt` (after it, and not past), at most 30 days apart, and the
session it backs, and that session's refresh token, end no later than the
mandate's `expiresAt`. So does its first access token, and the session
row's `not_after` is set to the mandate's end, which `auth/refresh` clamps
to and the bearer check now refuses past.

Behaviour change: a mandate without `issuedAt` or `expiresAt`, or valid for
more than 30 days, is refused (`delegationNotRecognized`). A session whose
mandate ends before its refresh token would is not refreshed; the delegate
signs in again with its mandate. A bearer session past its `not_after`
is refused (`unauthorized`); only these mandate-backed sessions set it.
`siopIdToken` evidence is unchanged.

### Fixed — the witness and watcher listeners bound slow connections and read a body only after admission

The witness's and the watcher's HTTP listeners had no header, body or idle
timeout and accepted connections without bound, and `POST /api/trust-tasks`
read the whole body (up to 1 MiB) before its per-address rate limit ran. A
client that sent a request slowly, or not at all, kept its connection, and
the limiter never saw a request whose body did not finish.

Both now serve through a shared listener (`did_hosting_common::server::listener`):

- at most 256 connections are served at once; more wait in the backlog for a
  free slot;
- at most 32 of them come from one IPv4 address or one IPv6 /64; more are
  closed as soon as they are accepted. Addresses in `server.trusted_proxies`
  are exempt, since every client behind a proxy shares its address;
- a request's headers must arrive within 20 seconds of its first byte, and a
  new connection must send its first request within the same time; sending a
  byte at a time does not extend it;
- a connection waiting for its next request, or not reading its response, is
  closed after 60 seconds;
- a connection that opens with the HTTP/2 preface is held to the 20-second
  header deadline, renewed only when the service writes to it, never by the
  peer's bytes alone.

`POST /api/trust-tasks` now checks the sender's address before it reads the
body, so a refused address gets its `429` without its body being read. An
admitted body is read up to 1 MiB, as before, and within 30 seconds: one
declared or sent over the limit is answered `413`, one that stops arriving
`408`, both with `Connection: close`. An over-size body was already refused
with `413`; a body that stopped arriving was waited for without limit.

The daemon's embedded witness gets the same order (rate limit, then body)
and the same body bound and timeout; the daemon's own listener is unchanged.
Both READMEs now say a reverse proxy is still expected in front.

For library users: `webvh_witness::routes::trust_tasks::receive` and
`webvh_watcher::routes::trust_tasks::receive` now take the request body as
`axum::body::Body` rather than `Bytes`, and each crate's `AppState` has a
`body_read_timeout`.

### Fixed — witness signing keys are sealed, with the key in the secret store

A witness identity's Ed25519 private key was serialised in clear into its
record in the data store (`witness:{id}` in the `witnesses` keyspace), so
anyone able to read that store, a backup of it, or a disk snapshot could sign
witness proofs as that identity. The record now holds the key only sealed
(HPKE, the envelope already used for VTA bootstrap bundles) to a witness
key-encryption key, and the additional authenticated data names the
identity, so a sealed key moved onto another record does not open. The
key-encryption key is held in the configured secret store in an entry of its
own (`<name>-witness-kek`, or the keyring account
`witness_key_encryption_key`; see `webvh-witness/README.md`). It is written
once, when the witness first starts, and never rewritten, so no release that
writes the service's own entry can drop it, and nothing reads, modifies and
writes back a shared secret. Its creation is claimed through the data
store's atomic counter, so two witnesses starting together on one store make
one key. The data store records its public half; a witness whose secret store
holds no key or another key, while its identities are sealed to the recorded
one, refuses to start and names the entry to restore.

The key-encryption key is read when the witness starts (bounded at 15 s) and
held in memory, so signing reads nothing from the secret store. The signer
checks that the key it opens is the one the identity's id names.

On the first start after upgrading, the witness (standalone, or embedded in
the daemon) seals every key still held in clear in a record, re-reading each
record just before rewriting it, 50 at a time. It logs the witness ids
sealed, never key material. Startup is refused, naming the identity and
changing nothing, if a record's key does not belong to it. Keys are not
changed, so no DID's witness list needs updating. Identities whose key
cannot be opened are named in a startup warning.

The service's own secret-store entry also now keeps any member this release
does not know when it rewrites the entry, instead of dropping it.

Behaviour changes:

- The witness needs permission to create and read a second secret-store
  entry on the cloud, Vault and Kubernetes backends.
- A backup of the data store (including the server's `backup` command)
  holds no usable witness key; back up the key-encryption key's entry too.
  `setup` re-run with another backend, and `export-sealed` /
  `import-sealed`, do not carry it.
- New CLI commands `webvh-witness reset-witness-kek-claim` and
  `did-hosting-daemon reset-witness-kek-claim`, for a first start that
  stopped part-way. A first write the secret store refuses releases the
  claim itself.
- In a rolling upgrade, replicas still on an earlier release cannot sign for
  identities the upgraded ones have sealed until they are upgraded too.
- Moving back to an earlier release after the upgrade does not work: it
  cannot read a sealed record. Nothing is lost; upgrading again works.

Records written before this change remain in earlier backups, snapshots,
and any history the storage backend keeps (point-in-time recovery, for
example), with the keys in clear, and restoring one brings them back until
the witness next starts. Where those copies may have been readable by
others, consider creating new witness identities and having DID controllers
move their witness lists to them; that cannot be done by the service alone.

### Fixed — a `did:webs` update must extend the hosted key event log

An update to a hosted `did:webs` slot, whether a control-plane publish or a
sync an edge applies, was checked only for the same AID and a sequence number
no lower than the hosted one. A log with a different event at the hosted
sequence number, or a longer log that diverged before it, was accepted and
replaced the hosted one. Both verify on their own, so the service could serve
a document from a history that contradicts the one it had already served.

The update's key events for the AID must now begin with every event the hosted
log holds, at the same sequence number with the same SAID, with one exception:
KERI's superseding recovery, where a rotation replaces the interaction events
after the last establishment event. Any other divergence is refused, including
a rotation superseding a rotation, and a shorter log is refused as a rewind.
Events are compared by SAID, so republishing the same events, re-serialized or
with witness receipts added, is still accepted. An edge applies the same check
against the high-water log it keeps after a delete.

A stored log that cannot be parsed still does not block an update, so a
corrupt slot can be repaired; the skipped check is now logged. One that parses
but no longer verifies is compared by its events. Only the AID's own key event
log is held to its history: a delegator's log in the same stream is verified
but not compared with the hosted one.

Behaviour change (R3.6): no wire changes. A `did:webs` publish or sync that
diverges from the hosted log other than by superseding recovery is refused
(`did/publish` and `sync/update` refuse it as they refuse a rewind) instead of
being accepted. Only builds with `method-webs` are affected.

### Fixed — a server's own CLI holds a DID log to the history it has served

A synced log must verify and strictly extend every history the server has
served for that DID: the log it holds, and the high-water mark it keeps after
a delete. The server's own subcommands that write a log skipped those checks.
`load-did` and `bootstrap-did --did-log` checked only the log's structure, so
`remove-did` followed by `load-did` could put an older version of a DID back.
`restore` wrote a backup's logs and high-water marks over the store's
unchecked, so restoring an older backup rolled both back.

Every path that writes a log now goes through the same history check and
records the high-water marks: `load-did`, `bootstrap-did` (with or without
`--did-log`), `recreate-did`, and setup's import of the server's own DID, on
both `did-hosting-server` and `did-hosting-daemon`. `load-did` and
`bootstrap-did --did-log` also verify the log's chain and, for a witnessed
DID, its witness proofs. A new DID in a slot is still allowed, as `sync/update`
allows it.

`restore` checks the whole backup before writing anything, `config.toml`
included. It works through the backup's logs, so none is restored unchecked.
Each restored `did:webvh` log, or `did:webs` log in a build with
`method-webs`, must have a record naming the DID the log establishes, must
verify, must extend the backup's own high-water mark, and must extend what the
store holds for that DID and slot. A backup's high-water mark is kept only if
it extends the store's, and a mark the store holds further is left in place.
If any check fails, the restore is refused and nothing is written. The data
goes into the store the backup's config names, after the usual environment
overrides. An interrupted restore can be run again.

`setup`'s replacement of the server's own DID (`--force-reprovision`) now
verifies the new DID before removing the old one, and swaps them in one batch.

Records these commands create are now tagged with the host their identifier
names, as a synced record is, so a purge of that domain selects them. Before,
the domain was empty and a purge skipped them.

Behaviour change (R3.6): no wire changes. `load-did` and `bootstrap-did
--did-log` refuse a log that does not verify, one that lacks the witness
proofs its parameters require, and an older version of a DID the store has
served. `restore` refuses a backup that would roll a DID back, so restore
into an empty data directory to start from a backup's state. It also refuses
an inconsistent backup (a log with no record, a record naming another DID, a
log that does not verify, or a log behind the backup's own high-water mark)
into any store, and no longer writes `config.toml` before that check.

### Fixed — an edge's HTTPS binding sends no document for a directive it did not verify, and says when to retry

On DIDComm and TSP an edge sends nothing back for a document that does not
verify as its control plane's. Its HTTPS binding (`POST /api/trust-tasks`)
answered such a document `403` with an unsigned `permissionDenied` error
document. It also did so for a document it could not check just now (the
control plane's DID could not be resolved, or the replay cache was full), so a
sender saw a refusal that looked final for a condition the edge expects to
clear.

The HTTPS binding now answers:

- a document that does not verify, or takes no reply: `403` with an empty
  body, no error document;
- a document that could not be checked just now: `503` with `Retry-After`
  (the replay cache's own hint, otherwise 30 seconds) and an empty body.

A health ping that could not be checked is treated the same way. On DIDComm
and TSP nothing changes: neither case is answered, and the control plane
re-sends what it is not answered. Nothing about a deferred document is
recorded, so the same document is applied once it can be checked.

Behaviour change (R3.6): the edge's HTTPS binding no longer returns a body
with `403`, and returns `503` with `Retry-After` where it returned `403`. The
control plane's outbox already treated both as unsettled and kept the
directive queued; only a signed refusal settles one. `docs/openapi.json` is
regenerated.

### Fixed — secrets envelope writes in one process no longer overwrite each other

Writing the service keys (`set`, as a rotation does), writing the offline
bootstrap seed and clearing it each read the whole secrets envelope, changed
one member and wrote it back, with nothing ordering them. Two of them at
once could write back an envelope read before the other's change. A rotation
could then be undone by a seed write that started earlier, leaving the
service unable to sign as its published DID.

Updates of one envelope entry in a process now take turns, wherever the
store was built. Each backend read and write an update makes is bounded at
20 s. An update that waits more than 60 s for its turn fails rather than
queueing indefinitely. Nothing is written after a failed or timed-out read.

Behaviour change (R3.6): a secrets write against a backend that does not
answer now fails after 20 s (a wait for a turn after 60 s) instead of waiting
on it indefinitely. The backends offer no compare-and-swap, so writers in
separate processes (the setup CLI and a running service on one entry) are
still not ordered against each other.

### Fixed — a rollback keeps the agent-name registry in step with the document it restores

`did/rollback` rewrote the log, the DID, its services and version count but
left the agent-name registry as it was, so the registry could list names the
restored document no longer claims, or miss names it does. A rollback now
reconciles the registry exactly as a publish does: names the restored entry
claims are registered, names it no longer claims are released, parked names
stay parked.

Behaviour change (R3.6): a rollback to an entry that claims a name another DID
now holds, or a reserved name, is refused (`agent-name` taken / reserved) and
changes nothing. A name changes holder only through an explicit `remove` by
its holder.

### Fixed — DID resolution answers only `GET` and `HEAD`

A `POST`, `PUT`, `DELETE` or other method to a DID path (`/{path}/did.jsonl`,
`did.json`, `did-witness.json`, `keri.cesr`) returned the document and counted
as a resolution. It is now `405 Method Not Allowed` with `Allow: GET, HEAD`, on
the edge, the daemon and the watcher.

### Fixed — an agent name on a disabled domain no longer redirects

`GET /@{name}` skipped the domain check the DID's own documents pass, so a
name on a disabled domain still redirected to a DID that answered `503`. It
now answers as the DID's documents do.

### Fixed — per-request warnings are rate-limited

The warnings for a `Forwarded` / `X-Forwarded-Host` header from a peer outside
`server.trusted_proxy_cidrs`, for resolution with no domain configured, and
for a request with no resolvable host are now written at most once a minute,
with a count of those held back. The rest go to `debug`. Any client could
trigger them on every request.

### Fixed — witness replicas sharing a store keep to one history of each DID

`webvh/witness/sign` checked that a log extends the furthest entry the
identity had already witnessed for the DID, then recorded the new entry,
under a lock held only within one process. Two witness replicas sharing a
Redis, DynamoDB, Firestore or Cosmos DB store could each pass the check
against the same mark for two different histories of one DID and both sign.

The mark is now moved by an atomic compare-and-swap in the store, from
exactly the value the check read, before the proof is signed. A replica
whose swap loses re-reads the mark and checks again, so it refuses a log
that does not extend what the other replica witnessed. A request that keeps
losing the swap is answered `unavailable` with `retryAfter`. The
`proofsSigned` counter is updated the same way, so a concurrent change to
the identity's record is no longer overwritten.

### Fixed — a republish of the same did:webvh must extend the stored log

`did/register` and `did/publish` used the stored log only to count its
entries. A log for the same DID (same SCID) that was shorter than the stored
one, or diverged from it, was stored, while every edge refused it
(`verify_history`) and kept serving the previous log. The control plane now
refuses it with the same rule: the stored entries, unchanged, then any new
ones. A different DID in the slot is still a replacement, not compared.

### Fixed — an admin takeover releases the previous holder's parked agent names

A forced takeover (`did/register` with `force`) carried every agent name of
the previous record to the new owner, parked names included. Parked names
the new document does not claim are now released with their index entries;
names the new document claims are registered as before.

### Fixed — a witness publishing again replaces its proof

`webvh/witness/publish` appended each proof to the version's entry in
`did-witness.json`, so a witness that published twice was stored twice. A
proof from a witness that already has one for the version now replaces it.

### Fixed — a control plane or daemon picks up a rotation of its own DID as soon as it is registered

Publishing a new version of the control plane's (or daemon's) own DID through
`did/register` did not reload the service identity; the change was only noticed
by the 5-minute backstop reload, so for up to 5 minutes the served document
advertised keys the listener had not loaded. `did/register` now triggers the
reload as soon as the new version is committed.

### Fixed — a daemon restarted mid-rotation keeps draining its old mediator

After a mediator change, a daemon restarted inside the grace window did not
reconnect to the old mediator, so messages peers still delivered there were
lost. The daemon now resumes those drains at startup, through the same
post-listener step the standalone control plane uses.

### Fixed — a node keeps TSP and its TSP relationships when its identity changes

When a witness's identity changed (a key rotation, a transport or mediator
change, or its first resolution at boot), its listener was rebuilt without TSP,
so TSP frames sent to it were dropped and acknowledged until a restart. On every
node the rebuilt listener also lost the transports reconciled from its own DID
document and its persistent TSP relationship store. Each node now builds its
listener through one function at boot and on every rebuild. A witness with only
TSP enabled now also starts its listener.

### Fixed — a watcher notices its own DID rotating

The watcher loaded its identity once and never re-read it, so after its keys
rotated it kept signing replies with a key its document no longer carried and
every sync looked unacknowledged until a restart. Like the witness, it now
re-resolves its own DID every 5 minutes, rotates onto the new keys, expires
superseded generations, and drains an old mediator after a mediator change.

### Fixed — health pongs and acknowledgements no longer log an ERROR on the control plane

Over DIDComm, every health pong, sync or domain acknowledgement and inbound
`trust-task-error` was logged at ERROR as a "should not happen" suppressed
reply. A document that is itself an answer now ends the exchange quietly; only
the SPEC §8.1 suppression, which no transport here can reach, is still logged
as an invariant break. The request log's quiet list (health and stats) now
matches the type of the document inside a trust-task envelope, so those
exchanges no longer add an INFO line each.

### Fixed — an ACL entry granted over `acl/grant` is one that can authorise

The `acl/grant` Trust Task now validates its subject as every other ACL write
does (trimmed, no control characters, at most 2048 bytes), and the ACL check
and the auth challenge accept DIDs up to the same 2048 bytes instead of 512,
so an administrator can no longer create an entry the witness or control plane
then refuses to authorise. The control plane no longer verifies an ACL task's
proof a second time after its proof gate has.

### Fixed — the console checks session renewal and proxied wallet sign-in replies, and reads JWT claims as base64url

Renewing a session (`auth/refresh`) and the VTA-proxied wallet sign-in
(`auth/authenticate/0.3`) were sent with a raw `fetch` and their replies used
unchecked; both now go through the console's Trust Task client, so a reply must
be the control plane's signed answer to that request before its tokens are
kept. The access token's claims are decoded in one place, as base64url with
padding restored, so a claim whose encoding contains `-` or `_` no longer hides
the admin navigation or stops renewal.

### Fixed — copying in the console says when it failed

Every copy button (invite link and claim code, DIDs, agent names) now reports
"Copy failed — select and copy manually" when the browser refuses the
clipboard — on a plain-HTTP deployment, or with the permission denied — and
shows the value as selectable text, instead of failing silently.

### Fixed — `did/register` enforces the caller's `domain` for did:webvh

A `did/register` request naming a `domain` that is not the host of the
did:webvh it publishes is now refused as `did-management:unknown_domain`
before anything is written, as `did/publish` already did. The parameter was
previously accepted and ignored. An omitted domain behaves as before.

### Fixed — `did/register` no longer wipes a did:webvh slot's domain

Registering or re-registering a did:webvh through `did/register` recorded an
empty domain, erasing the one a reserved slot or an earlier publish had set
and hiding the DID from per-domain listings. The record now carries the DID's
host, as every other write path does.

### Fixed — a node picks up TSP on an identity rotation without a restart

The control plane, hosting server, witness and watcher now always start their
messaging service with a TSP handler. Before, a node that booted without TSP
could not dispatch inbound TSP even after a rotation rebuilt its listener for a
DID document that began advertising `TSPTransport`; it needed a restart.

### Fixed — Cosmos DB prefix scans find every key

A prefix scan matched the base64 of the prefix against the base64 of each
key, which only works for prefixes a multiple of 3 bytes long. `did:`,
`acl:` and `session:` scans returned nothing or only part of their rows, so
DID listing, the DID count, domain purges and ACL listing were empty or short
on Cosmos DB.

### Fixed — DynamoDB creates a missing table only when it is missing, and waits for it

A table was created on any `DescribeTable` failure (throttling, `AccessDenied`,
the network), used before it was `ACTIVE`, and never ensured for a keyspace
whose first write was a batch. Now only a missing table is created, a table
someone else is creating counts as created, every table waits until it is
`ACTIVE`, and a batch ensures each table it writes. New tables are on-demand
(`PAY_PER_REQUEST`) instead of 5 provisioned read and write units; set
`store.dynamodb_billing_mode` (`<PREFIX>_STORE_DYNAMODB_BILLING_MODE`) to
`provisioned:<read>:<write>` for provisioned tables, and
`store.dynamodb_auto_create = false`
(`<PREFIX>_STORE_DYNAMODB_AUTO_CREATE=false`) to refuse a missing table
instead of creating it.

### Fixed — Redis prefix scans read only their keyspace, once each

A prefix scan walked every key in the database with `SCAN MATCH`, treated
`*`, `?` and `[` in a prefix as wildcards, could return a row twice, and read
every value in one `MGET`. Each keyspace now keeps a sorted-set index
(`__index__:<keyspace>`), written in the same transaction as its rows, and a
scan, a page or a count reads only that range of it, in chunks. A database
written by an earlier release is indexed once when the store opens. Upgrade
every replica sharing the database together: one still on the old release
writes rows the index does not list.

### Fixed — failed loads in the console no longer look like empty data

The DID list, dashboard, access control, invites, settings, servers and
domains pages show a failed read as an error with a Retry button instead of
"no DIDs", "no invites" or nothing at all. A DID path that does not exist (or
is not yours) shows "DID not found" with no delete or rollback buttons. Panels
that refresh on a timer say when they were last updated and that refreshing is
failing. Rejection codes (`permissionDenied`, `notFound`, `unavailable`,
`stepUpRequired`, …), cancelled passkey prompts and unverifiable replies are
described in plain words, in one place.

### Fixed — the witness's default port is 8531 everywhere

The witness setup wizard offered 8102 and the setup recipe 8534; both now use
8531, the port the witness's config defaults to.

### Fixed — configured registry instances no longer duplicate on every restart

Each `[[registry.instances]]` entry is now kept under a stable id derived from
its type and URL and updated in place, so restarts no longer add a dead record
per configured instance; the duplicates earlier versions left are removed on
start. Every change to an instance record (registration, health status, pong,
acknowledgement, transport and badge observations, `served_domains`) now goes
through one locked read-modify-write, so concurrent writers no longer drop each
other's changes.

### Fixed — a standalone edge runs the purge it acknowledged

An edge answered `replica/domain/unassign` (and a domain disable) with a
scheduled purge time, but only the daemon ran the sweep that carries it out,
so an unassigned domain's DIDs stayed on the edge and kept resolving. The
edge's storage thread now runs the sweep every minute and drops its
resolution cache when it purges anything.

### Fixed — an edge's own DID stays out of the control plane's reach

A self-hosted `did:webvh` edge imports its own DID at setup. It reported that
slot at registration, so the control plane queued a `sync/delete` for it, and
the reconcile counted it as extra for ever, holding `/api/health` at 503. The
edge's own DID is no longer reported, never counts as extra, and a
`sync/delete` of it is refused.

### Fixed — an edge no longer drops an agent name another DID has taken over

When a name moved from one DID to another and the edge applied the new
holder's update first, the old holder's later update (or deletion) removed the
name's index entry anyway, and `/@name` 404'd with nothing to repair it. An
index entry is now removed only while it still names the slot being updated
or deleted, and a re-sync of an unchanged log writes back any of its own
entries that went missing.

### Fixed — migrations that defer records stay pending, and never overwrite a concurrent write

The migration runner marked a migration applied even when it had deferred
records (M-01 without a default domain, M-02 with an unreadable log), so they
were never retried. `Migration::run` now reports `Complete` or
`Deferred(n)`, and only a complete run is marked. M-01 and M-02 also walk the
records in pages and write each one with a compare-and-swap on a fresh read
that changes their one field alone, so a publish another replica commits
during a rolling upgrade is not overwritten with a stale record.

### Fixed — `DAEMON_STORE_*`, `DAEMON_SECRETS_*`, `DAEMON_AUTH_*` and `DAEMON_FEATURES_*` are honoured

The daemon read only a fixed handful of variables, so the store, secret
backend, auth and feature overrides documented for every prefix were ignored
under `DAEMON_`. It now applies the shared overrides, and
`DAEMON_WITNESS_STORE_*` configures `[witness_store]`.

### Fixed — a degraded instance no longer reads as healthy again without a pong

The registry health sweep stamped `last_health_check` whenever it changed an
instance's status, and so did `registry/check`. The next sweep then read a
degraded instance as freshly checked and marked it `Active` again, though it
had not answered. Now only a health pong that reports the edge healthy records
a check. The sweep and `registry/check` re-derive the status from that check,
so they can degrade an instance but never revive it.

### Fixed — `did/rollback` reports `invalidTargetVersion` from a typed error

The `invalidTargetVersion` code was chosen by matching the start of the error
message. It now comes from a `ValidationKind::InvalidTargetVersion` error kind,
so rewording the message can no longer change the code.

### Fixed — a Redis store opens when a scan batch has no rows to index

The one-time index build at open sent an empty pipeline for a `SCAN` batch
that held no row of a known keyspace, which Redis refuses, so the store
failed to open on a database holding only other keys (#470). Such a batch is
now skipped.

### Fixed — `did-hosting-daemon` builds without the `ui` feature

`cargo build -p did-hosting-daemon --no-default-features --features
<store>,did-methods` failed to compile (a missing `IntoResponse` import on the
no-UI fallback route). CI now builds the daemon once per storage backend
without default features, so a broken feature passthrough is caught.

### Fixed — the daemon's embedded watcher serves the DIDs in the daemon's store

`GET /watcher/.well-known/did.jsonl` (and every other hosted DID under
`/watcher`) answered `500`: the watcher read the daemon's slot records as its
own record type, which they are not. It now reads only whether a slot is
disabled or deleted, so a hosted DID is served and an unknown, disabled or
deleted one is `404`.

### Fixed — `did-hosting-control setup` tells operators to grant edges the `service` role

The wizard's ACL step said to add each edge with `--role admin`, which
`server/register` refuses. It now says `--role service`, and its admin entry
is offered for operator DIDs only.

### Fixed — a key-role `did:webs`, such as a VTA's own identity, can register itself

`affinidi-did-webs` moves from 0.7 to 0.13. 0.7 read no key-role designation
and no KERI 2.0 designation, so the document the control plane derives from a
submitted `keri.cesr` lacked the keys such an identifier signs with. A VTA's
own `did:webs` (VTI-KEY-173: distinct attestation, operational and messaging
keys) signs its self-registration with its designated `operational` key,
which that document did not list under `authentication`, so its first-boot
`did/register` was refused as `proofInvalid`. It is now accepted, and the key
state's own key does not stand in for the operational one.

Behaviour change (R3.6): no wire changes. Under 0.13 a `did:webs` is valid
only on a domain its own designated aliases name: a key event log published on
a domain it does not designate is refused instead of being served there. An
identifier that designates no key agreement key now resolves with the X25519
key converted from its signing key in `keyAgreement`, as the reference
resolver's does. Only builds with `method-webs` are affected.

### Fixed — a `did:webs` in the ACL is verified by resolving it

A `did:webs` that self-registration made an Owner (a VTA whose own identity
is a `did:webs`, publishing here) was refused on every request after the
first. Its later requests take the ordinary sender-bound path, which
resolves the issuer, and the DID resolver every service builds was compiled
without `did:webs` support, so the signer was reported unreachable. The
resolver now resolves `did:webs` (`affinidi-did-resolver-cache-sdk` with
`did-webs`) on every binary, whether or not it is built with `method-webs`:
that feature decides what this host serves, not whom it accepts requests
from.

`affinidi-did-webs` moves to 0.13.9, which fixes the resolver's comparison of
a service's `type`: a `did.json` carrying `["X"]` where the key event log
designates `"X"` (as every `did.json` this host serves does) failed
resolution with `DocumentMismatch`, so no `did:webs` designating a service
could be resolved, here or by any other client of the same resolver.

Behaviour change (R3.6): resolving a `did:webs` signer fetches its
`keri.cesr` and `did.json` from the identifier's host, under the same host
policy as `did:web` (public hosts only by default). No configuration
changes.

### Fixed — the console stops renewing a session the control plane has ended

When `auth/refresh` was refused for good (the session reached its absolute
lifetime, idled out, or was revoked or unknown), the console swallowed the
refusal and sent the same refresh token again on every request, background
polls included, until the access token ran out. It now ends the session on the
first such refusal: the tokens and session key are cleared, the other tabs
holding the session are told, and the "Session expired — sign in again" prompt
shows. Network errors, 5xx responses and `unavailable` are still retried, with
a backoff that doubles up to a minute.

The control plane now answers a store failure during the refresh pre-checks as
retryable `unavailable`, not `permissionDenied`, so a non-retryable refusal
always means the session is over. The idle-timeout refusal is still
`permissionDenied`; nothing else changes on the wire.

### Fixed — normal session expiry is no longer logged as a warning

A refresh refused because the session reached its absolute lifetime or idled
out, and a bearer request refused because its session reached its end, are
now logged at `info`, and an idle refusal is logged once, not twice. WARN is
kept for refusals worth an operator's attention, such as a wrong or missing
session-key proof or an unknown, replayed or superseded refresh token.

### Fixed — an operator's CLI invite enrolls the first administrator again

Since invites began to be honored only while their issuer is still an
administrator, an invite made with the operator's `invite` subcommand was
refused at the last step of enrollment with "the administrator who issued this
invite no longer holds that standing": its recorded issuer is the operator, not
an ACL entry, so the lookup never found one. A fresh deployment could not enroll
its first administrator's passkey. A CLI invite carries the operator's
authority, which is store access rather than an ACL entry, so its redemption no
longer looks the operator up in the ACL. This applies to every CLI invite,
whatever its role, not only the first administrator's. Invites issued by an
administrator are checked as before. A refused invite is spent; issue a new one
after upgrading.

### Fixed — an administrator who changes an invite is answerable for it

An administrator who changes an outstanding invite's role or expiry
(`auth/passkey/enroll/invite/update`) is now recorded on the invite. From then
on the invite is honored only while that administrator, as well as its issuer,
is still an administrator, and it is withdrawn when their ACL entry is removed.
Before, a change left no record, so an administrator could raise an operator's
CLI invite to `admin` and the invite stayed redeemable after they were removed.
It also stayed redeemable if they changed an invite another administrator issued.

### Fixed — the CLI no longer issues an invite that cannot be redeemed

The `invite` subcommand refuses `--role metricsReader`, as
`auth/passkey/enroll/invite` already did. Before, it printed an invite that was
always refused at the finish. `remove-acl --did <did>` now also withdraws the
invites issued for a DID that has no ACL entry, so an operator can take back a
CLI invite.

### Fixed — Editing a did:webs DID from the UI no longer fails with "SCID … not found"

The DID detail page sent every delegated edit as `vta/webvh/dids/update`. A VTA keeps its did:webs DIDs in a separate store, so it answered `not found`, and the page then suggested the DID had been orphaned. Edits to a did:webs DID now go through `vta/webs/dids/update/0.1`. That task can change only the DID aliases in `alsoKnownAs`, so the page explains and stops any other document change, as well as agent-name bind, park and resume, before asking the agent.

### Added — a `did:webs` can register itself, proved by its own key event log

A `did:webs` does not exist until a host publishes it, so a node whose own
identity is a `did:webs` had no DID to authenticate to this host with before
its first publication. With `method-webs`, a `did/register/0.1` from a
`did:webs` outside the ACL is now accepted on a domain whose operator enables
it, when the request is signed by a current signing key of the identifier as
the submitted `keri.cesr` establishes it (not by resolving it: it does not
exist yet), and `issuer` is the `did:webs:{domain}:{path}:{AID}` the slot
builds. The new slot is owned by the identifier, which is then given an
`Owner` ACL entry scoped to that domain and one slot, so later publications
take the ordinary owner path.

- **`[[hosting.webs_self_register]]`**: `domain`, and optional
  `path_prefixes` and `max_registrations` (default 100, the most
  self-registered identifiers the domain holds at once). Off by default;
  ignored without `method-webs`.
- Webs only: a self-registration of any other method, with `force`, at a slot
  someone else owns, outside the prefixes, or signed by any key but the log's
  is refused. Rate-limited per source (10 a minute) and across all sources (30
  a minute) before the log is verified, and audited with its source
  (`did.webs.self_registered`).

See `docs/did-webs-hosting.md` ("Self-registration").

### Added — a budget for the statistics flush

The control plane and the daemon flush per-DID statistics every 10 seconds:
at most 200 rows, each a read and a write, all at once. On a small DynamoDB
table that burst could take most of the capacity.
`[stats_flush] max_rows_per_second` (env
`CONTROL_STATS_FLUSH_MAX_ROWS_PER_SECOND`, `DAEMON_STATS_FLUSH_MAX_ROWS_PER_SECOND`)
now sets the rate, from 1 to 10,000, and the flush is paced at it across the
interval instead of written in one burst. The default, 20, keeps today's
volume. Rows past the budget wait for the next flush; as before, time-series
buckets older than an hour and rows past the collector's caps are dropped
with a warning, so a budget below the rows produced loses series data.
Shutdown stops the pacing, and the final flush writes the rest.

### Added — store conformance suite, run against every backend

The `KeyspaceOps` contract (round trips, byte-exact prefix scans, paging,
atomic batches across keyspaces, `take`, `incr` and compare-and-swap under
contention, the per-item limit) is one suite every backend runs: fjall in its
unit tests, Redis, DynamoDB Local and Cosmos DB (its SDK's in-memory
emulator) on every PR, and the Firestore emulator nightly. Every backend now
pages prefix scans, lists keys without their values (`prefix_keys_raw`),
counts them (`prefix_count`), and reports its per-item limit
(`Store::max_item_bytes`).

### Added — suspend and resume a DID, set its statistics detail, and edit a domain's label from the console

The DID page gains Suspend / Resume (`did/set-state`) and a statistics-detail
picker (`stats/set-resolution`); the domains page can add or change a domain's
label (`domain/update`).

### Added — `docs/cli-reference.md` and `did-hosting-daemon dump-did`

A complete CLI reference for every binary, generated from the CLI definitions
and kept current by a test. The daemon gains `dump-did`, which the server
already had.

### Added — `send-trust-task`: send any signed Trust Task from the command line

`did-hosting-control send-trust-task` and `did-hosting-daemon send-trust-task`
sign one Trust Task with a `did:key` file (the format `setup --setup-key-out`
writes), `POST` it to the running service's `/api/trust-tasks`, verify that the
reply is signed by the service's own DID, and print the response payload as
JSON. `--type` takes a full Type URI or its `<slug>/<version>` short form
(`identity/list/0.1`); `--payload` / `--payload-file` give the request payload.
The signer is authorised like any other client, by its proof and its ACL entry.
Runbooks that used to `curl` removed REST routes (`identity/retire`,
`domain/assign`, `registry/purge-domain`, …) now use it; see
`docs/sending-trust-tasks.md`. `fetch-metrics` is now this command with a fixed
type.

### Added — a generated Trust Task catalogue

`docs/trust-tasks.md` lists every Trust Task the control plane serves, with its
version, the proof rule the gate enforces and the standing its handler
requires. It is generated from the routing tables and checked by a drift test
(`UPDATE_TRUST_TASKS=1 cargo test -p did-hosting-control --lib
trust_task_catalogue` regenerates it).

### Added — the daemon has every subcommand the standalone binaries have

`did-hosting-daemon` gains `export-sealed`, `import-sealed`, `vta-request` and
`vta-open`. The subcommands the binaries share are now defined once and
shared by all three, so they behave the same everywhere:

- `import-secrets` and `import-sealed` take an optional `--jwt-key` on every
  binary, and `import-sealed` on `did-hosting-control` now keeps the retired
  key material of superseded identity generations, as the other binaries
  already did.
- `vta-request` takes `--public-url` (`--did-hosting-url` remains an alias),
  an optional `--mediator-did` and `--transport` on every binary; on
  `did-hosting-control` `--mediator-did` is no longer required (without it
  the request is for an HTTP-only DID). `--label` defaults to the binary's
  name.
- `vta-open`'s output files default to `<service>-did.json`,
  `<service>-did.jsonl` and `<service>-secrets.json`, where `<service>` is
  `server`, `control` or `daemon`.
- `remove-did` and `recreate-did` on `did-hosting-server` now remove the
  slot's domain index row and usage counter with it, and `recreate-did`
  removes the owner index entry of the record's actual owner, as the daemon's
  did.

### Added — a self-registered `did:webs` may hold more than its own DID

`[[hosting.webs_self_register]]` takes `max_dids_per_identifier` (default 1,
at least 1): how many DIDs each identifier that registers itself on the domain
may hold, its own included — the `max_did_count` of the `Owner` entry
self-registration grants. With the old fixed limit of one, a VTA whose own
`did:webs` registered itself could publish nothing else on the host: a
community's DID it provisions was refused with `DID count limit reached (1)`.
It applies to entries granted from then on; an entry already granted keeps its
limit until an administrator changes it. See `docs/did-webs-hosting.md`
("Self-registration").

### Added — `/livez` and `/readyz` probes on every HTTP listener

Every binary that runs an HTTP listener (edge, control plane, witness,
watcher, daemon) now serves Kubernetes-style probes at the root,
unauthenticated and outside the rate limits like `/api/health`, which is
unchanged.

- **`GET /livez`** checks nothing beyond the HTTP server answering: always
  `200 {"status":"ok"}`, so storage or control-plane trouble never gets a
  process restarted.
- **`GET /readyz`** answers `200 {"status":"ready","storage":"ok"}`, or `503`
  with `"status":"notReady"` and the failed check `"unavailable"`.
  `storage` covers every store the binary serves from (the daemon's main and
  witness stores): on fjall, that the data directory still holds the database
  (an open database goes on answering from memory after its volume is gone)
  and that fjall has not been poisoned by an I/O error; on the network
  backends, one point read. It never writes. The edge adds `serving`, the
  condition its `/api/health` reports (its own DID served locally, within the
  replication staleness bound); the daemon adds `serving` for its own DID
  when its server is on. Mediator connectivity is not part of readiness.
- The checks run at most once a second, shared by concurrent probes, and
  give up after 800 ms (not ready). The body never carries the cause, which
  is logged at `warn`.

See `docs/deployment.md` ("Health checks", and "Containers and Kubernetes"
for a probe example).

### Removed — the "Show flow visualization (demo)" option on the login page

The VTA-proxied sign-in under "Using an older wallet?" no longer offers a
flow visualization. The checkbox, its stored preference
(`didhosting:proxyLoginViz` in `localStorage`, no longer read), the modal
that showed the decoded sign-in token and the code that decoded it for
display are gone. The proxied sign-in itself is unchanged and goes straight to
the dashboard.

### Removed — the console's native (iOS / Android) targets

The management console is web-only: the `android` / `ios` scripts, the native
blocks in `app.json` and the unused `App.tsx` are gone, and the app declares
its dark appearance. Under 700px wide the navigation folds into a menu and the
DID list shows cards instead of a sideways-scrolling table.

### Removed — `did-hosting-daemon migrate-from-webvh-config`

The subcommand was a stub: it printed instructions, ignored `--force` and
wrote nothing. There is no configuration file content to migrate (the rename
from `webvh-*` changed binary names and environment variable prefixes, not
config keys), so it is removed rather than finished.

### Deprecated — edge settings nothing reads

`did-hosting-server` accepts several settings it never reads: `features.http_listener`
(an edge always binds its HTTP listener), `[limits] default_max_total_size` and
`default_max_did_count` (per-account quotas are the control plane's, never an edge's,
along with their `DID_HOSTING_LIMITS_DEFAULT_MAX_*` environment overrides), and every
`[auth]` key except `cleanup_ttl_minutes`. They still load, but the server now logs a
warning naming each one set to a non-default value, and the two `[limits]` keys are no
longer written back. Remove them from edge configs; a later release will refuse them.

### Security — `url` 2.5.9 for RUSTSEC-2026-0592

The lockfiles now take `url` 2.5.9 (and `form_urlencoded` 1.2.3), which fixes
a stack overflow in `Url::origin()` on nested `blob:` URLs.

### Security — `url` 2.5.9 (RUSTSEC-2026-0592)

- The lockfiles move `url` from 2.5.8 to 2.5.9. In 2.5.8 `Url::origin()`
  recursed once per nested `blob:` prefix, so a crafted URL could overflow
  the stack and abort the process (GHSA-hrj5-67jp-wqp9).

## 0.11.0 (release/0.11)

### Fixed — the plaintext-secrets warning is logged once

A service on the plaintext secrets backend logged its "secrets are stored in
a PLAINTEXT file" warning every minute, because the identity sweep rebuilds
the secret store on each run. It is now logged once per file per process, at
the first build.

### Security — UI build dependencies (15 npm advisories)

All 15 open advisories in `did-hosting-ui`'s lockfile came in through Expo's
build tooling (`@expo/cli`, `@expo/config`, `@expo/fingerprint`), not the
UI's own code. In-range updates (Expo 58.0.22) cleared 14: `node-forge`
1.4.0 → 1.4.2 (GHSA-7wch-p9px-956x, GHSA-jc66-7q78-782g, GHSA-8hrf-8g6f-7xwp,
GHSA-hqq3-7jhf-c5jx, GHSA-5x38-2vff-x55p and six lower), `minimatch`
10.2.6 → 11.0.4 under the existing override (GHSA-g3hv-75wg-m249), and
`zod` 3 (GHSA-mrhx-c7xc-m3w5) and `deepmerge` (GHSA-gcqx-w48m-w2h4, no fixed
release), which current Expo no longer uses. `glob` has no fixed 13.x, so a
new `>=14.0.2` override moves it to 14 (GHSA-3g3m-2fjr-6pw4); 14 only adds
options and follows minimatch 11. `npm audit` reports none.

### Fixed — DynamoDB writes that change several items are atomic

A write batch on DynamoDB was sent 100 items at a time, one transaction per
chunk: a batch over 100 items could land part-way, and a chunk over 4 MB
(possible in `backup restore`, 1,000 entries at a time) was rejected by
DynamoDB, so the restore failed. A batch is now one transaction. One over
DynamoDB's bound (100 writes, 4 MB) is refused before anything is written,
as `taskFailed` with the size in its message, like an over-size item. A
batch naming one item twice now sends only that item's last operation,
since DynamoDB refuses a transaction that touches an item twice.
`backup restore` loads in as many transactions as it needs, each within both
bounds, and is not atomic, as before.

### Fixed — Firestore writes that change several items are atomic

A write batch on Firestore was committed 500 writes at a time, so a batch
over 500 could land part-way, and a commit is one request of at most
10 MiB, which a few base64-encoded logs together can pass. A batch is now
one commit. One over 500 writes or about 10 MB is refused before anything
is written, as `taskFailed` with the size in its message. `backup restore`
splits on both bounds.

### Changed — the daemon resolves a cached DID without reading the store

Every resolve read the DID's record and scanned the domains keyspace before
serving, even with the log cached: on DynamoDB, two reads and a scan per
resolve. A daemon running its control plane now caches the record and the
domains next to the log (its gate cache), so a warm resolve of `did.jsonl`,
`did-witness.json`, a did:web `did.json` or a did:webs DID reads nothing from
the store. Its control plane clears them after each commit that changes a
DID (agent-name changes included) or a domain, so disabling or deleting a
DID, or disabling a domain, still takes effect on the next resolve. On a
cache miss the daemon reads strongly consistent (the domains scan too), and
a miss that raced a change does not cache what it read, so a just-published
log or a disable is never hidden behind a cached copy. This assumes one
daemon per store. A write made from another process (an admin command
against a running daemon's store), or one the store applied but reported as
failed, is picked up within five minutes, the caches' TTL. A daemon with its
control plane off keeps no gate cache: its changes come from elsewhere.

Standalone edges keep reading the record on every resolve, since another
replica sharing their store could change it without telling them; they drop
the separate read of the matched domain, which the scan already returned. A
sync now clears every cached file for its DID, so an edge's witness file no
longer stays stale until the TTL, and edges evict expired cache entries each
minute (they never did).

### Added — the did:scid alias of existing DIDs: state, and listing or removing it

A did:webvh log and its `did:scid:vh:1:<scid>` form are one subject only while
the document lists `did:scid:vh:1:<scid>?src=<location>` in `alsoKnownAs`
(VTI-KEY-164). New DIDs got it at creation; existing ones now can too.

- `did/info` reports the latest document's alias under
  `record.ext["vnd.affinidi.webvh"].scidAlias` — the DID URL for the log's
  current location and whether it is `listed`, `notListed`, or `stale`
  (listed for an old location). Derived on the server, from the log.
- The DID page has a **did:scid Alias** card showing that state. For a DID an
  agent holds, with the wallet's task relay present, it asks the agent to list
  or remove the alias (`vta/webvh/dids/update/1.1`, `scidAlsoKnownAs`) through
  the same approval ceremony as agent-name changes, warning that the entry
  rotates the update key. Without the relay it is read-only and points at the
  controller (pnm or the browser-plugin console).
- `identity-scid-alias list|remove` (control, server, daemon; service stopped)
  lists or removes the alias on the service's own DID — the only log this
  service signs. A stale `src` is replaced, removal drops every entry of the
  SCID, and a request that would change nothing is refused. The update key
  does not rotate.

### Fixed — overload asks the client to retry, instead of looking like a fault

When the store was over capacity, callers could not tell it from a server
fault or a revoked grant, so they did not back off. Overload now answers the
way this service's rate limits already do (and as a VTA answers its own
operation budgets):

- A throttled DynamoDB request (after the SDK's own retries) was a 500
  `internalError`. Over HTTP it is now **429** with `x-rate-limit-source:
  did-host`, `Retry-After`, and `{ "error": "rate_limited", "limiter":
  "store-throughput", ... }`; as a Trust Task refusal, `unavailable` with
  `retryAfter`, on the control plane and the witness. An edge reports it to
  its control plane as retryable, as it now does any rate limit (one used to
  be reported final).
- A Trust Task refused as `unavailable` before it wrote anything did not
  run, and sending the same signed document again is now a retry: the
  control plane and the witness forget its id rather than refusing the
  resend as a replay. One refused after it attempted a write may have
  applied part of it, so its id is kept and a retry must be a new document.
- A failed lookup of the sender's ACL entry was refused as if the sender had
  no grant: `permissionDenied` "caller is not present in the maintainer's
  ACL" at the control plane's dispatch gate, in its tasks and in `acl/*`; "not
  authorised on this witness" at the witness; a final "unauthorized" for an
  edge's registration and stats sync; and, for a document over 64 KiB,
  `malformedRequest` "too large". Each now answers `unavailable` with a retry
  time when the store is throttled, else `internalError`; only an answer
  from the ACL is a refusal. An edge's acknowledgements and health pongs
  whose sender's role cannot be read are not recorded (an op stays queued and
  is re-sent; a pong waits for the next ping).
- The witness no longer puts internal error text in an `internalError`.
- A full replay cache answered `unavailable` with no retry time. It now
  suggests a minute, when its oldest records start to expire, plus up to 30
  seconds at random, so callers refused together don't all retry at once and
  fill it again; a retry can still be refused if the cache is still full.
- The control plane's `POST /api/trust-tasks` sets `Retry-After`, rounded
  up, on a refusal that carries `retryAfter`.
- The `check-name` reservation and agent-name tasks no longer take a failed
  read for "no default domain" (which could store a DID without one) or for
  "this DID has no names"; the failure is reported.

Not changed: sign-in (`auth/challenge`, `auth/authenticate`, `auth/refresh`,
`auth/oob/*`) still refuses a store failure the generic way, since the shared
sign-in library does not pass the store's error through. Only the DynamoDB
backend recognises its throttling; other backends' store errors are still
`internalError`.

### Fixed — on DynamoDB, the control plane no longer acts on a stale DID read

The control plane (standalone or in the daemon) now reads its DID keyspace
with strongly consistent reads on DynamoDB. Its reads decide writes: who owns
a slot, whether a path is free, which log to push to edges. An eventually
consistent read can miss a write that just committed, so a register right
after another owner's could take over that owner's slot, and an edge push
right after a write could find nothing and skip the edge. The daemon's
expired-DID cleanup, which re-reads a record before deleting it, reads the
same way, so it can no longer delete a DID published a moment before. Prefix
scans (listings, quota counts) stay eventually consistent.

Cost: these reads now use twice the read units. They are management traffic
plus two reads per `/api/health` probe. DID resolution, on edges and in the
daemon's embedded server, keeps eventually consistent reads and costs the
same. Other backends are unchanged.

### Fixed — a DID log over the store's item size limit is refused, not a 500

DynamoDB stores at most 400 KB per item and Firestore 1 MiB per document,
and a DID's whole log is one item, while `did/register` accepts logs up to
1 MiB. A larger log failed at the store as an internal error (`500`): the
caller could not tell why, and an edge or watcher receiving it by sync
retried it forever.

- The DynamoDB and Firestore backends now check each item against their
  limit before they write anything, so a refused batch leaves nothing
  half-written. `did/register` (HTTPS, DIDComm and TSP alike) answers
  `taskFailed` (HTTPS `422`) with the size and the limit in its message; the
  backend is logged, not told to the caller. The witness file is checked the
  same way.
- An edge or watcher refuses such a sync as `taskFailed` rather than
  retrying it, alone or in a `sync/batch` (where an edge used to report it as
  `invalidLog`), and keeps serving the version it had. The control plane
  logs a warning for each entry an edge refuses in a batch. Give edges a
  store whose limit is at least the control plane's.
- The DID keeps its last version. A DynamoDB-backed log holds about
  400 KB (about 170 updates of 2.3 KB entries); Firestore about 750 KB,
  because the log is stored base64-encoded. Fjall, Redis and Cosmos DB hold
  any log `did/register` accepts. A DID at its limit takes no further entry,
  a deactivation or key rotation included. The server README states the
  limits.

### Fixed — DID tasks no longer report a write that succeeded as failed

`did/check-name` (with `reserve`), `did/register` and `did/set-state` wrote
the record, then read it back to build their answer. On an eventually
consistent store (DynamoDB without `ConsistentRead`) that read could miss
the write, and the caller got an internal error (`record … missing after
reservation` / `… after write`) for a slot that was reserved or a DID that
was stored. A reservation retried after that error found the slot taken
(`available: false`). All three now answer from the record they wrote,
with no read-back.

### Added — wallet sign-in locations from a local GeoIP database

The control plane (standalone or in the daemon) now fills in
`requester.location` for `auth/oob` sign-in requests, which the wallet shows
its approver (`Vienna, AT`). It was always `unknown`. The lookup follows the
VTC's: a local MaxMind DB (`.mmdb`) file only, never a third-party call;
non-public addresses are never looked up; the address is neither logged nor
stored. Point `[geoip] database` (or `CONTROL_GEOIP_DATABASE` /
`DAEMON_GEOIP_DATABASE`) at a DB-IP City Lite or MaxMind GeoLite2 City file.
A missing or bad file is a warning, not a startup failure, and a replaced
file is re-read within a minute. Without the table nothing changes. See
`docs/geoip.md`.

`[[geoip.networks]]` names your own ranges (`cidr`, `location`), such as an
office LAN or VPN that no public database can place. They are checked before
the database, the most specific range wins, and a bad entry stops startup.

### Changed — `trusted_proxies` takes CIDR ranges and follows the VTC's rules

`[server] trusted_proxies`, on every service, now accepts CIDR ranges
(`"10.0.0.0/16"`) as well as single addresses, like the VTC's
`trust_xff_cidrs`. An entry that is neither used to be dropped silently,
leaving that proxy untrusted; it now stops startup with the entry named.

Client-address resolution from `X-Forwarded-For` now matches the VTC:
- every header line is read, as one chain;
- `addr:port`, `[v6]` and IPv4-mapped entries are accepted;
- a malformed entry reached before the client, a chain of more than 64
  entries, or a chain trusted end to end falls back to the TCP peer. The last
  case used to return the leftmost entry, which the client controls.

The control plane's duplicate of this function is gone; every service uses
the one in `did-hosting-common`.

### Fixed — false "corrupted entry" warnings at startup

The store integrity check reported every agent-name index entry
(`name:{domain}:{name}`) as invalid JSON. Those entries, and an edge's
`hw:` high-water logs, hold raw bytes by design and are now skipped. No
data was affected.

### Security — rustls 0.21 removed from the AWS backends

The DynamoDB store and AWS secret backends no longer build the AWS SDK's
legacy HTTPS client, which used rustls 0.21 (GHSA-c8m5-c952-6cm4,
GHSA-w44r-93j7-qv28, GHSA-h2v8-394m-p7vv). They now use the SDK's current
client on rustls 0.23.46, so the lockfile carries a single rustls.

### Changed — trust-tasks 0.36

The workspace moves to trust-tasks-rs 0.36, with vta-sdk 0.75, vti-common
0.51, vti-secrets 0.24, affinidi-tdk 0.36, affinidi-messaging-sdk 0.44,
affinidi-messaging-didcomm-service 0.29 and the test mediator 0.48. The UI's
`@openvtc/trust-tasks` runtime moves to 0.28.1.

Error documents are now `trust-task-error/0.6`, on every path, routed or not.
0.6 extends 0.5 with two codes, `unsupportedExtension` and `indeterminate`;
a consumer that accepts later minors (SPEC §5.2), as the UI does, needs no
change. No pinned task version changed.

### Changed — BREAKING: every Trust Task moves to its latest version

Old versions are no longer served. A peer that still sends one gets
`unsupportedType`. Ship this together with the matching VTA, wallet and
browser-extension releases.

- **acl:**
  - `grant`, `revoke`, `change-role` and `show` move to 0.2. Entries use
    AclEntry 0.2 and state their authority explicitly:
    - the domains an entry may act on are its `act` scope;
    - `keys` and `capabilities` are stated, never implied.
  - The webvh `ext` namespace carries only `quota` and `defaultDomain`. The
    old `ext…domains` member is refused.
  - Domains are dropped with `revoke` narrowing (`{kind:"act"}`); `grant`
    can no longer narrow an entry.
  - `list` moves to 0.3: `limit`/`nextCursor` paging, and
    `context`+`direction` filters.
  - `trust-task-discovery` moves to 0.3.
- **auth/oob** (wallet sign-in):
  - `request`, `claim` and `redeem` move to 0.2; `prove`, `respond` and
    `grant` move to 0.3.
  - Deadlines and session ends are RFC 3339 strings: `claimClosesAt`,
    `decisionClosesAt`, `sessionEndsAt`.
  - The prove/respond 0.1↔0.2 fallback is gone.
- **auth:**
  - Only `authenticate` 0.3 and `refresh` 0.2 are served. Refreshing a
    key-bound session now requires the bound key's proof.
  - `step-up/start` moves to 0.2; it embeds `approve-request` 0.5, which uses
    `accepts` and `ttlSeconds`.
  - `step-up/approve-response` moves to 0.6. `approverSigned` evidence is
    refused with `noGate`.
  - `passkey/enroll/invite` moves to 0.3 (`ttlSeconds`).
- **did-management:**
  - `did/list` moves to 0.2: paging by an opaque, signed cursor, and no
    `total`. The cursor key lives in the store, so cursors survive restarts
    and work across replicas.
  - `registry/*` moves to 0.2 (`lastHealthCheckAt`, `observedAt`) and
    `stats/timeseries` to 0.2 (`startsAt`).
  - `server/register` moves to 0.2 and conforms to its schema. The edge's
    hints travel under `ext["com.affinidi.did-hosting"]`.
- **Peers that must move with this release:**
  - The VTA's `webvh_host` sends `did/list/0.1`.
  - The wallet sends `auth/oob` claim 0.1 / prove 0.2 / respond 0.1.
  - The browser extension sends `authenticate/0.2`, `refresh/0.1` and
    `step-up/start/0.1`.
  - The mobile approver reads `approve-request` only up to 0.2.

### Changed — Trust Task types are generated, not prebuilt

- `trust-tasks-rs` 0.35 deprecates its prebuilt spec modules. Every task this
  service speaks is now pinned in `did-hosting-common/trust-tasks.lock`, with
  the bundles vendored under `did-hosting-common/trust-tasks/`.
  - The Rust types are generated by `trust-tasks-build` into
    `did_hosting_common::tasks`.
  - The UI generates its TypeScript types from the same lock
    (`npm run gen:tasks`).
  - CI runs `trust-tasks check`.
- Dependencies:
  - `trust-tasks-*` 0.35
  - `vta-sdk` 0.74, `vti-common` 0.50, `vti-secrets` 0.23
  - `affinidi-tdk` 0.33, `affinidi-messaging-sdk` 0.41, `affinidi-tsp` 0.3
  - `-didcomm-service` 0.26, test-mediator 0.46
  - UI: `@openvtc/trust-tasks` 0.28

### Security — TLS certificate trust (RUSTSEC-2026-0382, RUSTSEC-2026-0383)

- **`rustls-webpki` 0.103.16 and `webpki-root-certs` 1.0.10.** Earlier
  versions could accept certificate chains through distrusted emSign
  intermediates whose private keys are now public. Lockfile only; the fuzz
  workspace's lock is updated too.

### Changed — dependencies

- Workspace-wide `cargo update`: `tokio` 1.54, `trust-tasks-*` 0.32.10, and
  the AWS SDK moves forward (`aws-sdk-dynamodb` 1.131,
  `aws-sdk-secretsmanager` 1.120). `firestore` 0.61, `serde_json_canonicalizer`
  0.4 (canonical output unchanged; duplicate object keys are now an error).
- **The `aws-smithy-types < 1.7` pin is gone.** `aws-smithy-json` 0.63.1
  compiles against the newer line, so the workspace no longer needs to hold
  the AWS subtree back. `vti-secrets` 0.21 now bounds it below 1.9 itself,
  which is what keeps `aws-config` at 1.12.

### Fixed — the server's documented env overrides work

- **`did-hosting-server` reads the shared env overrides under `DID_HOSTING_`**
  as its README documents (`DID_HOSTING_SERVER_HOST`, `_SERVER_PORT`,
  `_LOG_LEVEL`, `_STORE_*`, `_AUTH_*`, `_SECRETS_*`, `_FEATURES_*`, …). They
  were read only under an undocumented `WEBVH_` prefix, so the documented
  names were silently ignored. `WEBVH_` still works but is deprecated; when
  both are set, `DID_HOSTING_` wins.

### Added — configurable, compact replay caches

Each service's anti-replay cache for signed Trust Tasks held at most 5,000
records per signer and 50,000 in all, about 0.4 KB each, and refused new
requests at either bound. One signer was therefore limited to about 14
signed requests a second: a VTA creating DIDs on the control plane or
daemon, a VTA witnessing them, and the control plane's sync to each edge
server and watcher.

- **Compact records.** A record is now a 128-bit keyed hash of
  `(signer, id)`, about 32 bytes, filed by the document's signed `issuedAt`
  in one-minute buckets that are dropped whole as they leave the freshness
  window. A document whose `issuedAt` is missing or outside the window is
  refused as stale.
- **Higher defaults.** 1,000,000 records in all (about 32 MB) and 250,000
  per signer (about 600 signed requests a second).
- **A reserve for quiet signers.** The last 10% of the global bound is kept
  for signers holding fewer than 100 records, so several busy signers
  together cannot lock out the rest.
- **Configurable.** A `[replay]` table (`max_entries`,
  `max_entries_per_signer`) on every binary, or
  `{CONTROL,DAEMON,DID_HOSTING,WATCHER,WITNESS}_REPLAY_*` (the edge also
  reads the deprecated `WEBVH_REPLAY_*`). The daemon applies its table to
  the embedded control plane, witness and watcher, each with its own cache.
  A zero bound, a per-signer bound above the global one, or more than
  10,000,000 records is refused at startup, including for a cache built in
  code. Setup leaves the table out unless it differs from the defaults, so
  later defaults apply. Wallet sign-in (`auth/oob/*`) keeps its own replay
  record and is not affected.
- The edge's cache is now part of its state rather than process-wide, so
  each edge in one process has its own bounds.

### Added — per-client rate limit on DID resolution

Public DID resolution had no rate limit, so one client could use up a
metered store's read capacity for every other client.

- **`[server.resolve_rate_limit]`** (`max_per_window`, `window_secs`, default
  10) caps the resolution requests one client may make per fixed window on
  the server, watcher and daemon; past it the client gets `429 Too Many
  Requests` with `Retry-After`, and one warning per client per window is
  logged. It is off by default. Each setting has a
  `{DID_HOSTING,WATCHER,DAEMON}_SERVER_RESOLVE_RATE_LIMIT_*` env override; a
  zero limit or a window outside 1 to 3,600 seconds is refused at startup.
- A client is its address, an IPv6 client its /64, so rotating addresses
  inside one block does not escape the limit. The budget is per process. In
  the daemon one budget covers the server's and watcher's resolution and the
  root fallback, which also serves the UI.
- The shared per-address limiter (resolution, the Trust Task listeners and
  wallet sign-in) now drops addresses whose window has ended when it reaches
  10,000 tracked addresses, and clears all counts only if
  more than 7,500 are still live, so a flood does not rescan the map on
  every request.

### Added — `trusted_proxies` from the environment

- `{CONTROL,DID_HOSTING,WATCHER,WITNESS,DAEMON}_SERVER_TRUSTED_PROXIES` sets
  `server.trusted_proxies` as a comma-separated list of addresses or CIDR
  ranges (empty clears it), so a deployment can set it without rewriting the
  config file. A bad entry is refused at startup.
- The service warns at startup when the resolution limit is on with no
  trusted proxies: behind a load balancer every client would share one
  budget.

### Added — configurable caching for DID resolution

- **`[server.resolve_cache]`** sets the `Cache-Control` sent with every
  successful resolve (`did.jsonl`, `did-witness.json`, `did.json`,
  `keri.cesr`, the `/@name` redirect) on the server, watcher and daemon:
  `max_age_secs` (default 300, as before; `0` sends `no-cache`),
  `shared_max_age_secs` (`s-maxage`) and `stale_while_revalidate_secs`.
  Each has a `{DID_HOSTING,WATCHER,DAEMON}_SERVER_RESOLVE_CACHE_*` env
  override. Durations past one year are refused at startup. Errors keep
  `no-store`.

### Fixed

- **did:web `did.json` is cacheable.** It carried no `Cache-Control`, so the
  global default stamped it `no-store`; it now follows `[server.resolve_cache]`
  like the other resolve paths.
- **The DID count no longer reads every DID record every 10 seconds.** The
  control plane and the daemon recounted hosted DIDs from the store on every
  stats flush, so an idle service's read load grew with the number of DIDs it
  hosted. Creates, deletes, empty-DID cleanups and domain purges now keep the
  count, and the control plane, daemon and edge recount hourly to correct
  paths that bypass them (an edge's synced DIDs, an offline `remove`).
- **Empty-DID cleanup no longer deletes a slot published into mid-pass.** It
  deleted from a snapshot of the records; in the daemon a DID published into
  an expired reserved slot after the scan could be removed. Each record is
  now re-read and re-checked under the slot's path lock before it is deleted,
  and one failed delete no longer ends the pass.
- **A failed stats flush no longer loses that window's statistics.** The
  control plane and the daemon wrote every stats and time-series row of a
  flush in one transaction, and dropped the drained counts when any read or
  write failed, as under store throttling. Each row is now its own write,
  eight at a time; the first failure ends the flush and the unwritten rows
  are retried on the next one. A write that reports failure is read back
  first, so one the store applied before timing out is not counted twice.
  On DynamoDB, plain writes use half the write units of a transaction, at
  the cost of one request per row. A flush writes at most 200 rows, so its
  load on the store is spread across flushes: the server-wide series goes
  first, then per-DID totals and per-DID buckets alternately, so neither
  starves the other under load. Time-series buckets that cannot be written
  within an hour are dropped with a warning. The flush at shutdown writes
  for at most 15 seconds, so the store is still persisted inside a
  container's termination grace period, and logs an error saying how many
  rows it could not write.
- **Pending statistics are capped.** At most 100,000 DIDs' totals and
  200,000 per-DID time-series buckets wait to be written, whether they
  came from local events, a peer's stats sync or a failed flush. Past the
  caps the per-DID figures are dropped, with a warning at most every five
  minutes; the server-wide totals and series still count them.
- **A server's stats sync can no longer write rows outside its DIDs'
  series.** The control plane used each synced delta's path verbatim in
  its `stats:` and `ts:` keys, so a path of `_all` added to the server-wide
  series. A delta is now counted only if its path has a hosted path's
  shape, or is hosted here (for paths stored before the current path
  rules), and never contains `:` or is `_all`; skipped deltas are logged
  with a sample of their paths.
- **No service keeps every time-series bucket in memory any more.** The
  collector's per-DID 5-minute buckets were never drained, so they grew for
  as long as the process ran. The control plane and the daemon now write
  them, which also puts each local event in the bucket of the time it
  happened rather than the time it was flushed. A synced edge delta is
  filed under the edge's latest event time (or the time it arrived, if
  that is implausible), not the arrival time. An edge no longer keeps
  buckets at all, since it only syncs per-DID totals.
- **An edge keeps its statistics when a stats sync fails to send.** It
  drained them before sending and discarded them on failure; they are now
  retried on the next sync. A sync carries at most 10,000 DIDs, the most
  the control plane accepts, and the rest wait for the next one, so a
  backlog after an outage drains instead of being refused every time.

### Added — did:scid identities

A `did:scid:vh:1` DID is verified by the same did:webvh log as its did:webvh
form, but is a DID in its own right: `did:scid:vh:1:<scid>`, with
`?src=<host>/<path>` only a locator for the log (VTI-KEY-160 to VTI-KEY-166
of the VTI specification). Hosted logs are always did:webvh logs and are
served exactly as before; a did:scid resolver fetches the same `did.jsonl`.

- **Callers may present a did:scid.** An owner, ACL subject or proof signer
  is recorded and compared as the bare did:scid DID: ACL and ownership keys,
  validated DIDs, the dispatch caller and session subjects drop the `src`
  locator, and issuer, sender, recipient and verification-method bindings
  compare by DID, ignoring it. A proof whose `verificationMethod` carries
  `src` is resolved through it and dereferenced by DID and fragment. A
  did:scid signer whose did:webvh log is deactivated signs nothing. The
  did:webvh and did:scid forms remain distinct identities.
- **Self-created DIDs list their did:scid alias.** A DID this service mints
  for itself (server bootstrap, daemon setup, self-managed recipe,
  `WebVHClient::create_did`) lists `did:scid:vh:1:<scid>?src=…` in
  `alsoKnownAs`, linking the two forms. `hosting.scid_also_known_as = false`
  (env `<PREFIX>_HOSTING_SCID_ALSO_KNOWN_AS`, recipe
  `identity.scid_also_known_as`) leaves it out. An existing DID keeps what it
  published. `DidDocumentOptions` gains `omit_scid_alias`, so a struct literal
  of it no longer compiles without it.
- **The console shows did:scid.** The DID detail page lists a hosted DID's
  did:scid alias with a Copy button; the DID table, domain matching and the
  sign-in contact rule understand did:scid (a contact must carry `src`,
  VTI-LNK-119).

## 0.10.0 (release/0.10)

### Fixed — wallet sign-in works with the current browser wallet

- **`auth/oob/prove` and `respond` are served at 0.2** beside 0.1. The wallet
  now tries `prove/0.2` first and falls back to 0.1 only on `unsupportedType`;
  this service refused the unserved type as `permissionDenied` instead, so
  every wallet sign-in failed. 0.2's step 2 offers no `signingScope` (this
  service delegates no signing), and a 0.2 grant that claims one is refused as
  `contextMismatch`. A `respond` must carry the `grant` of its own version.
- **An unserved `auth/oob/*` version answers `unsupportedType`** rather than
  the ACL refusal, so a later wallet version falls back too.
- `secrets.backend = "encrypted_file"` (new in vti-secrets) is refused as
  unsupported at startup rather than half-configured.

### Changed — fewer clicks to sign in with a wallet

- **The landing page goes straight to Login** when signed out, and Login shows
  the sign-in code at once: no "Login" or "Show sign-in code" click. An
  unclaimed code is renewed when its claim window closes; a hidden tab opens
  no request until it is visible again, and a code hidden with its tab shows
  again when the tab does.
- **The number is handed to a wallet on this device (contract C11):** while a
  request is claimed, the element showing the number carries
  `data-oob-request-id` and `data-oob-match-number`. The browser plugin reads
  them on the page where the code was clicked and types the number in; a
  phone wallet reads it off the screen as before.

### Changed — dependencies and the management UI

- vta-sdk 0.72 / vti-common 0.48 / vti-secrets 0.21, trust-tasks 0.32,
  affinidi-tdk 0.27, affinidi-messaging-sdk 0.37, `-didcomm-service` 0.22,
  bip39 3, utoipa 6, firestore 0.59, azure_data_cosmos 1.0; the UI on Expo SDK
  58 / react-native 0.88.
- **Usage chart:** the tooltip shows each series' rate per second beside its
  count (one decimal below 10/s, `<0.1/s` for a trickle).
- **All DIDs** is a compact table: search by name, DID, method, domain or
  agent name, and sort by any column (name, DID, versions, created, updated,
  resolves). Each DID has a QR code. The DID is shown compactly (method, SCID
  head, slot; full on hover), the method and "You" badges appear only when
  the list mixes them, and Updated reads "—" for a DID never updated. The
  name and DID columns size to the longest entry; the others share the rest.
- The "Self-contained daemon" note shows an em dash instead of `—`.

### Fixed — multi-row writes are atomic, and the witness's memory is durable

- **A batch is all or nothing on Fjall.** An operation whose keyspace could
  not be opened was logged and dropped while the rest of the batch committed;
  the batch now fails and writes nothing. `take`/`incr` (refresh-token
  rotation, the invite wrong-code lockout) now exclude every handle to a
  keyspace, not only callers sharing one handle.
- **A live domain is never purged.** Re-enabling or re-assigning a domain and
  cancelling its pending purge are one write, as are disabling or unassigning
  it and scheduling the purge (and a replicated `replica/domain/upsert`). A
  crash between the two used to leave a ripe purge queued against a live
  domain, or a domain disabled with no purge coming. Both purge sweeps also
  re-check, just before deleting, that the row is unchanged and the domain is
  still disabled or unassigned; a leftover row for a live domain is cleared
  instead of acted on.
- **The witness records what it signed before the proof leaves.** The proof
  counter and the anti-equivocation mark are one write, fsynced before
  `webvh/witness/sign` answers, so a power loss can no longer make the witness
  forget an entry it vouched for and sign a fork of it.
- **DID writes on the control plane hold the per-path lock.** `did/create`
  (two creates of a free path both succeeded), `did/delete`,
  `did/set-disabled` (wrote back a stale record) and rollback now read and
  write under it; a force-replace is a single write.
- **An edge's reconcile repair** takes `sync_lock` and re-reads the record, so
  it cannot revert a sync applied while the listing was fetched.
- **Sessions:** an activity touch updates `last_seen` on the current row only,
  so it can no longer resurrect a rotated-away session or undo a passkey
  demotion; session rows, their indexes and refresh indexes change together;
  step-up retires the previous refresh token.
- **Passkey invite redemption** that confers a role holds the ACL write lock,
  so an administrator's concurrent grant is not overwritten.
- Removing a witness identity with its marks, setting the default domain,
  invite indexes and empty-DID cleanup are each one write.

## 0.9.0 (release/0.9)

### Breaking — the control plane has no REST management surface

- **Kept:** `POST /api/trust-tasks` (the HTTPS binding of the one Trust Task
  dispatch), `GET /api/health`, the console's static fallback, and the browser
  sign-in with no Trust Task form: `POST /api/auth/challenge`,
  `POST /api/auth/` (a SIOPv2 `id_token` minted by the holder's VTA) and
  `POST /api/auth/refresh` (refresh token plus the browser's bound session
  key). The daemon inherits the same router.
- **Removed:** every REST management route — `/api/dids*`, `/api/witness/*`,
  `/api/log/*`, `/api/raw/*`, `/api/owner/*`, `/api/disable/*`,
  `/api/enable/*`, `/api/rollback/*`, `/api/agent-names/*`, `/api/domains*`,
  `/api/me/domains`, `/api/acl*`, `/api/stats*`, `/api/timeseries*`,
  `/api/services/overview`, `/api/config`, `/api/server-info`,
  `/api/control/registry*`, `/api/control/register-service`,
  `/api/control/stats`, `/api/identity/generations*`,
  `/api/auth/step-up/vta/{start,finish}`, the demo `/api/auth/step-up/check`,
  `POST /api/task-consent/request` (and its DIDComm decision handler), the
  `/api/proxy/{server,witness}/*` pass-through, and the Prometheus `/metrics`
  endpoint. Each has a Trust Task (`server/metrics/0.1` for the metrics); the
  proxy and task-consent had no caller. The console's SPA fallback no longer
  answers any `/api/*` path.
- **Removed:** the permissive `Trust-Task:` header routing (`TrustTaskRouter`),
  the house `trusttasks.org/did-hosting/*/1.0` URIs, the undocumented
  `spec/did-hosting/*/1.0` arms (`trust_tasks_did`), the DIDComm-JWS dialect of
  `POST /api/auth/` and `/api/auth/refresh`, `ControlClient`, the
  `did-hosting-client` crate (REST-only, unpublished, no caller) and the
  `prometheus` dependency. `WebVHClient` now signs Trust Tasks
  (`sign_as` replaces `authenticate`).

### Breaking — secrets use `vti-secrets`, with no insecure default

- **One implementation.** Every secrets backend (keyring, AWS, GCP, Azure,
  Vault, Kubernetes, plaintext) is now the published `vti-secrets` crate the
  VTA and VTC use. The local copies are gone. The service's keys and
  offline-bootstrap seed are one JSON envelope, stored as the backend's
  payload. Existing stored secrets are not read: recreate the deployment.
- **`secrets.backend`** names the backend (`keyring`, `aws`, `gcp`, `azure`,
  `vault`, `kubernetes`, `plaintext`). Setup writes it. When unset, the
  backend whose selector field is set is used, and failing that the keyring.
- **No keychain, no start.** A host where the OS keyring cannot be opened (a
  headless Linux box with no Secret Service), or a binary built without any
  secure backend, is refused at setup and start with the list of secure
  backends. Nothing falls back to plaintext, and a backend selected on a
  binary built without its feature is an error.
- **Plaintext is tests only.** It needs `backend = "plaintext"` and
  `confirm_plaintext = true`, in the recipe and in `config.toml`. The keys go
  to `<config>.secrets.plaintext` beside the config at `0600`, not into
  `config.toml`. `[secrets.plaintext]`, `plaintext_mode` and
  `plaintext_bootstrap_seed` are removed. The interactive wizard no longer
  offers plaintext.

### Breaking — passkey enrolment is Trust Tasks, with hashed invites

- **Served** on TSP, DIDComm and `POST /api/trust-tasks`:
  `auth/passkey/enroll/invite/0.2`, `auth/passkey/enroll/redeem/start/0.1`,
  `auth/passkey/enroll/redeem/finish/0.1` and
  `auth/passkey/enroll/{start,finish}/0.2`. WebAuthn's own ceremony data rides
  inside the payloads; the browser ceremony is the one non-Trust-Task step.
- **Invites are two secrets, stored hashed.** An invite is a 256-bit token for
  the URL and a 60-bit claim code for a second channel, each returned once.
  The store keeps a SHA-256 of the token (its lookup key) and a salted
  Argon2id digest of the code, compared in constant time. Five wrong codes
  delete the invite; redemption is also rate-limited per source (client IP on
  HTTPS, sender on TSP/DIDComm). Invites expire (default 1 h, capped by
  `auth.passkey_enrollment_ttl`) and are consumed exactly once, atomically
  with binding the credential. An unknown token, a wrong code and an expired
  invite get the same refusal.
- **Step-up-only passkeys** (`purpose: stepUp`) are held in a new keyspace,
  `passkey_step_up`, which the login ceremony never reads: one can never sign
  anyone in, and a login passkey never stands in for one.
- **User verification is bound to the ceremony.** Enrolling a further passkey
  of a purpose the subject already holds requires a user-verified assertion
  from one of them, over a challenge distinct from the registration one and
  stored only in the ceremony record. The first finish takes the record, so a
  replayed finish, or an assertion made for another ceremony, is refused.
- **Removed:** the REST routes `/api/auth/passkey/enroll/{start,finish}`,
  `/api/auth/passkey/login/{start,finish}`,
  `/api/auth/step-up/passkey/{start,finish}`, `/api/auth/passkey/invite`,
  `/api/auth/passkey/invites` and `/api/auth/passkey/invite/{invite_id}`. The
  console already signed in with `auth/passkey/login/*/0.2`, and a session
  step-up by passkey is `auth/passkey/login/*` with `purpose: stepUp`.
- **No migration.** Invites in the old plaintext `enroll:` rows are not read;
  issue new ones. The `invite` CLI now prints the URL and the claim code
  separately.
- **Console.** The enrolment page asks for the claim code, shows whose passkey
  it will be and what it may do before creating it, and redeems over Trust
  Tasks; the ACL page issues sign-in or step-up invites and shows the link and
  the code apart, once.

### Breaking — the watcher is Trust Tasks only, with its own DID

- **Its own DID.** webvh-watcher is provisioned from a VTA context like the
  other services (`setup`, interactive or `--from <recipe>` in any VTA mode).
  Its keys and context credential live in the secrets backend.
- **One listener.** It serves `webvh/sync/update/0.2`, `webvh/sync/delete/0.2`
  and `webvh/sync/batch/0.1` on TSP, DIDComm and `POST /api/trust-tasks`.
  - Only a document signed by one of `sync.source_dids` is applied. A document
    that does not verify gets no reply. A verified one from any other DID gets
    a signed `notAuthorized` and takes no room in the replay cache.
  - Logs are verified as an edge verifies them: the chain and witness proofs,
    the slot, `versionCount`, and strict extension of the held log and a
    per-DID high-water mark that a delete keeps.
- **Removed:** `/api/sync/did`, `/api/sync/delete`, `push_tokens`,
  `sync.sources`, `sync.reconcile_interval`, and the REST sync wire types. The
  recipe's `[watcher]` section is now just `source_dids`. The daemon's
  `watcher_sync` is gone, and its embedded watcher serves resolution only.
- **Control plane fan-out.** A new `[[registry.watchers]]` maps watcher URLs
  to DIDs. A published DID is queued for every mapped watcher its log's
  `watchers` parameter names, and a deleted one for every mapped watcher. It
  goes through the outbox, with the same delivery, retry and signed
  acknowledgement as edges. A mapped watcher's DID may acknowledge those
  syncs and nothing else.

### Breaking — the witness is Trust Tasks only

webvh-witness serves `webvh/witness/key/create|list|delete/0.1`,
`webvh/witness/sign/0.1` and `acl/*` as Trust Tasks, on TSP and DIDComm (its
mediator connection) and `POST /api/trust-tasks`, through one dispatch.

- **Removed:** `/api/auth/*`, `/api/witnesses*`, `/api/proof/*`, `/api/acl*`,
  the `/api/didcomm` 501 stub, the witness's JWT sessions and its `[auth]`
  settings. `/api/health` is unchanged.
- **Every request is authorised on its own proof** — `proofPurpose:
  authentication`, bound to the in-band issuer, addressed to the witness,
  fresh, and not a replay. A document that does not verify gets no reply; a
  verified one from a DID the witness does not authorise gets a signed
  `permissionDenied`, and takes no room in the replay cache. Every reply is
  signed.
- **`witness/sign` verifies before it signs.** It carries the log, and the
  witness refuses an entry whose chain does not verify (`invalidLog`), that is
  not the last (`versionNotLast`), of a deactivated DID (`deactivated`), or
  whose witness parameter does not name it (`notListed`).
- **`WitnessClient`** is a Trust Task client over HTTPS; it verifies every
  reply against the witness DID. The `--witness-*` bootstrap in
  `did-hosting-server` and `did-hosting-daemon` sends `witness/sign` with the
  log, signed by the new DID, and stores a well-formed `did-witness.json`.
- In the daemon, the embedded witness is reached at
  `POST /witness/api/trust-tasks`.

### Changed — the VTA / Trust Tasks / messaging dependency set moves together

- `vta-sdk` 0.56 → 0.58, `vti-common` 0.29 → 0.31, `vti-secrets` 0.4.8 → 0.5,
  the six `trust-tasks-*` crates 0.24 → 0.25, `affinidi-tdk` 0.20 → 0.21,
  `affinidi-messaging-sdk` 0.30 → 0.31, `affinidi-messaging-didcomm-service`
  0.15 → 0.16, `didwebvh-rs` 0.6 → 0.7, and the dev-only
  `affinidi-messaging-test-mediator` 0.14 → 0.15.
- `didwebvh-rs` 0.7 resolves **public hosts only** by default
  (`HostPolicy::PublicOnly`), and the verifier's `did:webvh` deactivation check
  reads the signer's log through it. Production behaviour is unchanged: every
  service's DID cache is already `PublicOnly`. A caller whose resolver allows
  private hosts (local development against `localhost`) now says so to the
  verifier too: `TransportBoundVerifier::with_did_cache_and_host_policy`,
  `WitnessClient::with_host_policy`, and `post_trust_task_https_verified` for
  the raw HTTPS send. Otherwise every reply from a privately hosted
  `did:webvh` peer is refused as unreachable.
- Fixes an unlocked `cargo install` failing with E0631 on `from_vti` in
  `server::secret_store`. `vti-secrets` 0.4.9 re-pinned onto `vti-common` 0.30,
  so a resolve that ignored `Cargo.lock` held two `vti-common` copies.
  `--locked` is still the recommended way to install.

### Added — a self-check that the server DID lists what wallet sign-in needs

- Wallet sign-in (`auth/oob/*`, contract C4) needs the server's own DID to
  list `SignInPortal` (`<origin>/login`) and `TrustTaskHTTPS`
  (`<origin>/api`). A DID minted from a template without them left wallets
  saying only "This code can't be used". `WebVHHosting`
  (`{ "uri": "<public_url>" }`) is recommended, not required: without it a
  wallet that does not already know the server won't offer to add it, but
  sign-in works (so a mediator-configured node, which does not advertise it,
  simply isn't offered the wallet join).
- At startup the control plane (and the daemon) resolves its own DID in the
  background and, if any are missing or wrong, logs one warning with the exact
  JSON entries to add and `pnm did-mgmt dids edit --did <server_did>`. It
  re-checks every 5 minutes (every minute while resolution fails), so a fix is
  picked up without a restart. Startup never waits on it.
- New unauthenticated `GET /api/sign-in/readiness` returns
  `{"walletSignIn": "ready" | "not-set-up" | "unknown"}`, the missing required
  services (`missingServices`) when not set up, and the missing recommended
  ones (`missingRecommended`). The login page reads it: when not set up it
  says which services the DID lacks and opens the older logins; a missing
  `WebVHHosting`, or a failed or pending check, keeps wallet sign-in offered.

### Fixed — an already-deleted message no longer logs a deletion-handler warning

Takes affinidi-messaging-sdk 0.30.1 (and, through the lock, mediator-common
0.17.1 / mediator 0.33.1). A mediator on its Fjall or in-memory store answers
the redundant delete of a redelivered message with `NOT_FOUND: message_hash
(…)`, which SDK 0.30.0 did not recognise as "already gone", so each one logged
`WARN deletion_handler: the mediator refused some ids … deleted=0 failed=1`. In
a hosting service they recur every 30 seconds, in step with the messaging
service's offline-sync status request.
0.30.1 recognises it; mediator 0.33.1 also stops sending it.

### Added — offline commands to list, reset and delete TSP relationships

`did-hosting-daemon`, `did-hosting-control` and `did-hosting-server` gain
`tsp-relationship-list`, `tsp-relationship-reset --peer <did>` and
`tsp-relationship-delete --peer <did> | --all [--yes]`. Relationship state is
per endpoint and persisted, so neither restarting the service nor wiping the
mediator clears it; making two nodes meet as strangers again means clearing
both halves, and until now there was no way to clear this one. Reset puts our
half back to `None` (what the SDK does after a reply timeout) so the next send
re-invites; delete removes the whole record. `--all` covers half-formed
relationships the store cannot enumerate, and only reports without `--yes`.
The commands open the store directly, so stop the service first. Shared as
`server::cli_tsp`.

The keyspace behind the durable relationship store now implements
`scan_prefix`. It did not, and the trait's default yields nothing, so the SDK's
enumerating operations (`established_relationships`, `evict_idle`) would have
seen an empty store. Nothing here called them before; `tsp-relationship-list`
does.

### Fixed — a wallet proxy login no longer raises an approval popup per request

The console signs every Trust Task it sends. A proxy login (the VTA mints the
persona's `id_token`) bound no session key, so each call was signed through
the wallet's `signTrustTask` — which asks the human every time, by design —
and a page load fired several at once: an endless stack of approval windows.
The proxy login now binds a fresh session key the way a holder login does,
sending it as `session_pubkey_b58btc` beside the `id_token` on `POST
/api/auth/`, and the console signs with it: one approval, at sign-in. The
route already bound a key it was given; a test now pins that it does.

- **Every route that binds a session key now decodes it.** `/api/auth/` and
  the REST passkey `login/finish` accepted anything starting `z6Mk`, so a
  value that only looked like an Ed25519 multikey was stored and every proof
  it later signed refused. Both now apply the decode `auth/authenticate/0.2`
  uses for `sessionKey`, shared as
  `server::auth::session::is_ed25519_multikey`. The passkey route's log line
  also sliced the refused value by byte, which panicked on a non-ASCII one.
- **A lost session key ends the session.** A wallet session whose key this
  browser no longer holds used to fall back to the wallet's `signTrustTask`
  silently — changing what each request rested on without saying so, and
  bringing back the popup per request. Every login now binds a key, so the
  console treats a wallet session like a passkey one: sign in again. The
  `asDid` principal hint that fallback read is gone with it.

### Added — wallet logins bind a session key (`auth/authenticate/0.2`)

The control plane serves `auth/authenticate/0.2` (trustoverip/dtgwg-trust-tasks-tf#675)
in place of 0.1. An authenticate document may name a `sessionKey`, a `did:key`
the subject's own proof covers, and the control plane binds it to the new
session, as a passkey login binds its browser key.

- **What it can do.** The HTTPS binding accepts that key's `authentication`
  proofs as the subject, only alongside that session's own bearer token. The
  key stops working when the session expires, is revoked or logs out. Its
  `acr` is the login's, so anything that needs a step-up still does.
- **What it can't do.** It never approves a step-up. Approvals must be signed
  by the subject's own key, on the Trust Task and REST paths, and the verifier
  refuses a delegated `assertionMethod` proof outright. This also closes a gap
  where a passkey session's key could approve its own step-up, because a
  `did:key` document lists its key under `assertionMethod`. It also never
  signs `auth/authenticate` or `auth/refresh`, so it cannot mint or extend a
  session.
- **Key types.** A key that is not Ed25519 is refused with
  `auth/authenticate:sessionKeyUnsupported`, before the challenge is spent.
- **Subject's own key.** A session with a bound key still accepts the
  subject's own proofs, so a wallet can still sign its step-up approval and
  its refresh.
- **Logout.** New `auth/revoke-session/0.2` ends one of the caller's own
  sessions. The console's sign-out now calls it, signed with the session key,
  so logout ends the session server-side, not only in the browser. A session
  key may end only its own session. A session that is gone, or not the
  caller's to end, answers `revokedCount: 0`, so a retried logout succeeds.
- **Console.** A wallet login generates a non-extractable session key and
  passes it as `sessionKey`. Later calls are signed with it instead of
  prompting the wallet. Step-up still goes through the wallet.

### Added — optional Fjall memory settings

Three optional settings — `STORAGE_FJALL_BLOCK_CACHE`,
`STORAGE_FJALL_WRITE_BUFFER`, `STORAGE_FJALL_MAX_JOURNAL` (env vars, or a
`[fjall]` config-file table) — cap the embedded fjall store's block
cache, buffered writes, and startup journal replay so they stay inside a
pod's Kubernetes memory `limit`. Same three names across every binary
(did-hosting-server, did-hosting-control, webvh-witness, webvh-watcher,
did-hosting-daemon); an env var overrides the file. All optional and
unset leaves fjall's own defaults unchanged. Only the `store-fjall`
backend reads them. See `docs/bootstrap_startup.md` for the full table
and pod-sizing guidance.

### Added — the control plane is served as Trust Tasks on every transport

Every control-plane task that only REST served, and every new specification
from trustoverip/dtgwg-trust-tasks-tf#661 the control plane owns, is a row of
the one table, reachable over TSP, DIDComm and HTTPS `POST /api/trust-tasks`:
`did/{set-state,rollback,log}`, `agent-name/resolve`,
`domain/{list,create,update,set-state,set-default,purge,assign,unassign}`,
`registry/{list,get,check,admin-register,deregister,purge-domain}`,
`stats/{get,timeseries}`, `server/{info,config,metrics}`,
`identity/{list,retire}`, `auth/step-up/start/0.1`,
`auth/step-up/approve-response/0.5`, `auth/passkey/login/{start,finish}/0.2`
and `auth/passkey/enroll/invite/{list,update,revoke}`. The REST routes stay
until their callers move.

- **Each task's proof is checked against the key relationship it names.**
  `server/info` and `auth/passkey/login/start` accept a request with no proof
  (a proof that is present is still verified). Operational requests need
  `proofPurpose: authentication`; an approver's `approve-response` needs
  `assertionMethod`, and each is refused under the other. A passkey login is
  signed by the `did:key` its session is then bound to.
- **`POST /api/trust-tasks` no longer requires a bearer session.** The
  document's proof is the authorisation, as on the other transports; a bearer
  session, when presented, must match the proof and contributes its assurance
  level (a domain purge needs `aal2`).
- **Step-up moves to `approve-request/0.3` / `approve-response/0.5`.**
  `auth/step-up/start` binds a challenge to the caller's own session and
  answers a signed `approve-request/0.3`; the subject's `approve-response`
  elevates the session; `auth/refresh` then mints tokens at the session's
  current level.
- **Invites are addressed by `inviteId` and never disclose their token after
  issue** — on REST too: `GET /api/auth/passkey/invites` no longer returns
  tokens or enrollment URLs, and `PUT`/`DELETE /api/auth/passkey/invite/{id}`
  take the invite id. The UI follows.
- **`agent-name/resolve` answers only for DIDs the caller may read**, on REST
  too, so it cannot be used to test whether a DID is hosted.
- **`did/rollback`** takes a `targetVersion`.

### Changed (breaking) — DID management answers in its specifications' shapes

The control plane's DID-management Trust Tasks are served from one table keyed
on the generated `trust-tasks` 0.23.5 Type URIs (`control_tasks`), with the
generated request and response types end to end. The hand-built `MSG_*` JSON
bridge (`bridge_did_management` / `dispatch_did_op`) is gone.

- **Every reply matches its schema.** `did/list` answers `{records, total}`
  (paged by `limit`/`offset`, filtered by `domain`), `did/register`,
  `did/delete`, `did/change-owner` and the `agent-name/*` verbs answer
  `{record}` in the shared `DidRecord` shape, `me/domains` answers the shared
  `DomainEntry` shape. Host-specific members the closed schemas do not define
  (a record's agent names; a domain's scheme, branding, witnesses, watchers,
  quota) travel under the `vnd.affinidi.webvh` extension namespace.
- **Errors are `trust-task-error` documents** with the code the task's
  specification declares (`did-management/did/info:notFound`,
  `…/change-owner:notOwner`, `did-management:unknownDomain`, …), not
  `did/problem-report` replies, which that specification reserves for the
  host's asynchronous reports.
- **Requests are held to their schemas.** An unknown payload member —
  including the snake_case aliases (`new_owner`, `did_log`) — is refused with
  `malformedRequest`. A non-admin naming another `owner` on `did/list` is
  refused (`did-management/did/list:forbidden`) rather than silently shown
  their own slots; `domain` on `did/info`, `did/change-owner` and
  `did/register` is now checked against the slot instead of dropped.
- **Sync moves to `webvh/sync/update/0.2` and `webvh/sync/delete/0.2`.** The
  control plane sends camelCase exactly as schema'd (0.1's implementations
  sent snake_case its schema never allowed), and the slot's `disabled` state
  travels with its content: a disabled DID stops resolving on every edge, and
  resumes on an update carrying `false`. Edges read the generated types, answer
  `applied` or `unchanged`, drop held witness proofs when an update carries
  none, refuse under the declared `invalidLog` / `historyRewrite` /
  `deactivated` codes, report per-entry outcomes for `webvh/sync/batch/0.1`,
  answer `sync/delete` with `deleted` or `absent`, and remove a deleted slot's
  agent-name index. Control planes and edges must be upgraded together.
- **A proof that is present is verified**, on every task, including those that
  do not require one.

### Changed (breaking) — privileged messages must carry a proof bound to their sender

Every message that changes state or discloses more than public data is now
authorised on a Data Integrity proof carried in the document itself, never on
the messaging transport's report of who sent it. A document is acted on only
when it carries a `proof` whose `verificationMethod` is controlled by its
in-band `issuer`, the `issuer` is the expected peer (exact match), it is
addressed to the receiving service (`recipient`), and its `issuedAt` is inside
the freshness window. Replay protection is keyed on `(proven issuer, document
id)`. See `did_hosting_common::server::trust_tasks::bound`.

- **Operational proofs use `authentication`.** These are a service's own
  messages, not attestations (VTI key roles, VTI-KEY-106/107): the proof must
  carry `proofPurpose: authentication` and its `verificationMethod` must be
  listed under the signer's `authentication` relationship. `assertionMethod`
  proofs are refused on these paths (it stays reserved for credentials), and
  every sender this repo controls now signs with `authentication`.
- **Key rotation does not open a rejection window.** A proof that fails against
  a cached DID document is retried once against a freshly resolved one before
  it is refused (at most one forced refresh per DID per 30s). The service's
  DID cache TTL is now explicit: 120s (`DID_CACHE_TTL_SECS`).
- **Replies are signed too.** Every non-error trust-task reply the control
  plane emits — on DIDComm, TSP and HTTPS alike, including
  `auth/challenge#response` and `auth/authenticate#response` — is stamped
  `issuer` = the control plane, `recipient` = the requester, a fresh
  `issuedAt`, and signed with its operational key (`authentication`). Edges
  sign their acks and pongs the same way. `trust-task-error` documents stay
  unsigned. There is no unsigned mode: a control plane (standalone or in the
  daemon) with no `server_did`, no loaded identity, or no signing key for its
  current generation **refuses to start**, and should the key ever be missing
  at request time every trust task is refused with `internalError`.
- **Approval requests are operational too.** The `task-consent/request` and
  `auth/step-up/approve-request` documents the control plane sends are signed
  with `proofPurpose: authentication`. Only the human approver's own decision
  / approve-response is an `assertionMethod` attestation.
- **Approver decisions must be attestations.** A `task-consent/decision` and an
  `auth/step-up/approve-response` must carry `proofPurpose: assertionMethod`
  with the key listed under the signer's `assertionMethod` relationship, and a
  deactivated `did:webvh` signer is refused (`verify_approval`). The consent
  decision's `#response` is now a signed trust-task document in the trust-task
  envelope.
- **Edges do not answer documents that fail verification.** A control-plane op
  or health ping that is not signed by the configured control plane gets no
  reply at all — neither a signed refusal nor an unsigned one.
- **Transient failures are retryable.** A signer whose DID cannot be resolved
  (or whose deactivation status cannot be read) is refused as `unavailable`
  with an error that names the unreachable DID; an edge's storage or I/O
  failure applying an op is `internalError`. Both are retryable, so the control
  plane keeps the op queued rather than settling it. A `sync/batch` with an
  entry that failed transiently is retried whole.
- **Registration re-sends what an edge missed.** The delta re-sync compares the
  DID identity (`did_id`, reported by the edge in `preloaded_dids`) as well as
  the version count, so a DID deleted and re-created at the same slot reaches
  an edge that missed the delete. Domain `assign` / `unassign` / `purge` ops are
  recorded per server and re-sent on each registration until acknowledged
  (an assignment is kept as the desired state).
- **The edge's own REST publish (`PUT /api/dids/{mnemonic}`) is held to the
  sync history rule**: it must extend the held log and the per-DID high-water
  mark, and records the high-water mark itself.
- **Deactivation verdicts follow the DID cache.** An edge builds its proof
  verifier once (it used to build one per message, so nothing was remembered);
  a verdict is reused while the DID cache serves the same document, and the
  verdict map is bounded.
- **Edges keep a high-water mark per DID and per slot that a delete does not
  clear.** A DID re-created after `sync/delete` must extend everything the edge
  ever served for it, so a delete-then-resync cannot roll a DID back to before a
  rotation or bring back a deactivated one. A slot never changes method; a new
  DID (new SCID) may reuse a deleted slot.
- **Edges bind each synced DID to its slot and host** (the log's identifier must
  resolve at that mnemonic on the edge's public URL or an assigned domain),
  verify `did:webs` updates as continuations of the held and high-water logs,
  and verify witness proofs — a witnessed DID without its proofs is refused.
- **The outbox removes an entry only on the target's signed acknowledgement**
  of the exact document sent (or its signed, non-retryable refusal), re-signing
  on every retry and re-sending after 60s without an ack; one op in flight per
  server. Edges re-register at startup, on every mediator reconnect and every
  10 minutes; each registration re-syncs the delta, queues deletes the edge
  missed, and replicates every domain record.
- **Pre-authorisation filtering.** A privileged document from a sender with no
  ACL entry is refused before any signature or DID-resolution work and never
  reaches the replay cache. The replay cache refuses (retryable `unavailable`)
  instead of evicting at its bounds, caps each signer, and expires in O(1).
- **Other hardening.** The task-consent decision requires `recipient`, a fresh
  `issuedAt` and is replay-checked; REST DIDComm-JWS sign-in and refresh require
  a key listed under `authentication`; `POST /api/control/stats` takes a signed
  stats-sync document instead of a bearer token; proofs from a deactivated
  `did:webvh` signer are refused.
- **`TransportBoundVerifier` requires an in-band `issuer`, always.** A proof
  with no `issuer` used to verify as a bare signature, with the issuer then
  filled from the transport's sender; it is now refused. The one delegated shape
  kept is the passkey session key, accepted only on `POST /api/trust-tasks`, and
  only as the exact JWT-bound key acting for the JWT subject
  (`with_session_delegate`).
- **Control plane → edge (sync, domain ops, health ping).** The outbox and the
  health loop send signed Trust Task documents (TSP frame or DIDComm
  trust-task envelope, chosen from the edge's DID document). Edges apply
  `sync/update`, `sync/batch`, `sync/delete` and `domain/{assign,unassign,
  purge,upsert}` only when signed by the configured `control_did` and addressed
  to their own DID. The bare `MSG_SYNC_*` / `MSG_DOMAIN_*` / `MSG_HEALTH_PING`
  DIDComm routes and the serialised-`Message`-over-TSP form are removed.
  `domain/upsert` moves to `https://trusttasks.org/spec/did-management/domain/upsert/0.1`
  (queued entries under the old URI are delivered under the new one).
- **Edges verify the DID logs they are asked to serve.** A `sync/update` is
  applied only if the log's proof chain verifies (entry hashes, update-key
  authorisation, pre-rotation), it establishes the DID the push names, and it
  strictly extends the log already held: a shorter or diverging log is refused
  as a rollback or fork, and a deactivated DID accepts no further entries.
- **Edge → control plane (registration, stats, health pong, sync and domain
  acks).** Sent as signed trust tasks; the bare `MSG_SERVER_REGISTER`,
  `MSG_STATS_SYNC`, `MSG_HEALTH_PONG` and ack routes are removed. Registration,
  stats, pongs and domain acks additionally require the signer to hold the
  `Service` role (pongs previously had no ACL check).
- **DID management, ACL and auth trust tasks (DIDComm envelope, TSP, HTTPS).**
  Every trust task except `trust-task-discovery` and `auth/challenge` must be
  signed by its issuer, and the issuer must be the transport's sender. This
  includes the typed `did-hosting/*/1.0` ops and the ACL reads (`acl/list`,
  `acl/show`), which previously went through unsigned.
- **Removed the non-Trust-Task DID-management transports.** The bare DIDComm
  `MSG_DID_*`, `MSG_AGENT_NAME_*`, `MSG_ME_DOMAINS` routes and the HTTP-signed
  `POST /api/didcomm` endpoint are gone; the same operations are reachable as
  signed documents in the trust-task envelope, over TSP, or on
  `POST /api/trust-tasks`. A peer still sending a bare type gets a
  problem report naming it.
- **`MSG_AUTHENTICATE` over DIDComm requires a signed challenge.** The bare
  route that issued a session to the reported sender is removed; sign-in over
  DIDComm/TSP is the `auth/challenge/0.1` → `auth/authenticate/0.1` trust-task
  pair, whose authenticate document must be signed by the authenticating DID.
- **`trust_tasks.enforce_proofs = false` is refused at startup.** There is no
  longer a mode in which proofs are ignored.
- **Web UI.** Every trust-task envelope except discovery is signed and names
  the session's subject DID as `issuer`.

**Upgrade the whole fleet together.** A control plane and its edges on either
side of this change cannot talk to each other. Clients that must change:
the VTA's DID-management client over DIDComm/TSP
(`verifiable-trust-infrastructure` `vta-service/src/webvh_didcomm.rs`) must sign
each document with the VTA DID as `issuer`; the browser extension's DIDComm
sign-in (`pnm-browser-plugin` `packages/core/src/rp-login/didcomm.ts`) must use
the challenge → signed-authenticate trust tasks instead of a bare
`MSG_AUTHENTICATE`, and its `signTrustTask` (used for wallet-signed admin UI
envelopes) must sign with `proofPurpose: authentication`. REST API callers (bearer JWT from the signed REST sign-in)
are unaffected.

### Fixed — the daemon's control plane checks signer status like the standalone one

The daemon's embedded control plane built its Trust Task proof verifier over the
bare DID cache resolver, so — unlike the standalone control plane — it did not
refuse a proof from a deactivated `did:webvh` signer, did not retry once against
a fresh DID document after the signer rotated its key, and reported an
unreachable signer as a bad proof rather than as retryable (`unavailable`). The
relationship check (`authentication` / `assertionMethod`) already ran.

Every service now builds its verifier with one shared constructor,
`did_hosting_common::server::trust_tasks::build_verifier`: the standalone
control plane, the standalone server, and both halves of the daemon. A
deactivated signer's refusal is now final everywhere: it no longer spends the
signer's forced re-resolution, since a `did:webvh` deactivation cannot be
undone. The
`did-hosting-common` `test-support` feature (dev-only) exposes
`TransportBoundVerifier::record_deactivation_verdict` for tests.

### Changed — the 0.27 messaging line, with the authcrypt sender bound to its key

- **Moved to the 0.27 messaging line.** `affinidi-tdk` 0.16 → **0.17**,
  `affinidi-messaging-sdk` 0.26.27 → **0.27.2**,
  `affinidi-messaging-didcomm-service` 0.11 → **0.12.1**,
  `affinidi-messaging-didcomm` → **0.15.9** (floor), `vta-sdk` 0.50 → **0.52**
  with `vti-common` 0.23.1 → **0.25** (all four declarations), `trust-tasks-*`
  0.21 → **0.22**; dev-graph `affinidi-messaging-test-mediator` 0.9 →
  **0.10.2** (mediator 0.29.5). One copy of each of `affinidi-messaging-sdk`,
  `affinidi-tdk`, `trust-tasks-rs`, `vta-sdk` and `vti-common`.
- **The authcrypt sender is the key that encrypted the message.** In didcomm
  0.15.9 / SDK 0.27.2 / didcomm-service 0.12.1 the sender is resolved only from
  the `skid` the envelope names, and an envelope whose `apu` disagrees with it
  is refused; `HandlerContext::sender_did` is the verified signer or authcrypt
  sender, never the plaintext `from`.
- **Signed sign-in verifies the JWS against the resolved key *as* the key of
  its `kid`.** `didcomm_unpack::unpack_signed` calls `unpack_bound` with a
  `SignerKey`, so the reported `signer_kid` is the key id the signature was
  checked against (the key-only `unpack` is deprecated in didcomm 0.15.9).

### Fixed — stats sync uses TSP when the control plane advertises it

- **Stats sync was the last control↔server exchange hard-coded to DIDComm.**
  A server now sends its periodic per-DID deltas as a
  `.../server/stats-sync/0.1` trust task when the control plane's DID document
  advertises `TSPTransport`, so `send_trust_task` carries it (and the ack) over
  TSP; otherwise it keeps sending the legacy `MSG_STATS_SYNC` DIDComm message.
  The control plane gains the matching `trust_tasks_infra` arm, and the server
  owns the `#response` ack. **Upgrade the control plane first** — one that
  advertises TSP but predates this arm drops the trust task, losing those
  deltas.
- **A stats sync must report under its own DID.** The DIDComm and trust-task
  routes now reject a `server_did` that differs from the transport-proven
  sender (`e.p.stats.sender_mismatch`), as the REST route already did against
  its JWT. `server_did` keys the replay window, so a foreign one could advance
  another server's sequence and have its genuine deltas skipped as stale.

### Changed — messaging-stack refresh for the TSP relationship fixes

- **Took the latest TSP fixes on the 0.26 messaging line.**
  `affinidi-messaging-sdk` 0.26.10 → **0.26.27**: two endpoints that
  re-establish a TSP relationship at the same time (fresh environment, or both
  restarting) no longer fail with `invalid transition: SendInvite in state
  InviteReceived` (0.26.12); a reply-registration race is closed (0.26.19); and
  a TSP send retries when its connection is closed under it (0.26.26).
  `vta-sdk` 0.43 → **0.50** with `vti-common` 0.19.3 → **0.23.1** (the lockstep
  pair, all four `vti-common` declarations), `trust-tasks-*` 0.21.2/0.21.3 →
  **0.21.21**; dev-graph `affinidi-messaging-test-mediator` 0.9.1 → 0.9.17
  (mediator 0.26.2 → 0.28.36). One copy of each of `affinidi-messaging-sdk`,
  `affinidi-tdk`, `trust-tasks-rs`, `vta-sdk` and `vti-common`.
- **Two mechanical source changes for vti-common 0.23.** `AuthError` is now
  `#[non_exhaustive]` with three new variants: `SessionIdleTimeout` and
  `WrongRecipient` map to `AppError::Authentication`, `MissingRecipient` to
  `AppError::Validation`, and a wildcard arm fails closed as `Authentication`.
  `AuthenticateInput` gained a required `audience`; all five sign-in paths pass
  `AudienceBinding::Transport`, because each has already bound the document to
  this service before the canonical handler runs (`require_addressed_to` on the
  signed-DIDComm paths, the id_token `aud` check on SIOPv2, and authcrypt/TSP
  plus the framework's `recipient` check on the auth trust tasks).
- **Not yet on sdk 0.27 / `-didcomm-service` 0.12.** Those move the messaging
  SDK to 0.27 and trust-tasks to 0.22, but the newest published `vta-sdk`
  (0.50.0) still requires sdk ^0.26 / trust-tasks ^0.21 / affinidi-tdk ^0.16,
  so taking them now would put a second copy of each in the shipped graph. The
  move follows the next `vta-sdk` release (verifiable-trust-infrastructure main
  is already on sdk 0.27 / tdk 0.17 / trust-tasks 0.22).

### Added — TSP relationship persistence & self-healing (Rev 3 §7.2.2)

- **Nodes now persist their TSP relationships and re-establish them on connect,
  so an edge stops silently dropping the control plane's pushes after a
  restart.** Under Rev 3 §7.2.2 a receiver drops any application (sync/health)
  frame from a VID it holds no relationship with; the SDK's default relationship
  store is in-memory, so a restart forgot every peer and the node went quiet
  until a re-handshake that nothing triggered. Two halves fix it, on top of the
  answering arm shipped earlier:
  - **Durable store.** Both the control plane and the edge server inject a
    persistent relationship store (`server::tsp_relationship_store`, a
    backend-agnostic `RelationshipKv` over any configured `StorageBackend` —
    fjall, DynamoDB, Firestore, CosmosDB — under the new `KS_TSP_RELATIONSHIPS`
    keyspace) into their TSP listener, so a formed relationship survives a
    restart.
  - **Edge re-invite at connect.** The edge calls the facade's
    `tsp_ensure_relationship` with its control plane on the initial connection
    and every reconnection (idempotent — it skips when the relationship already
    admits application messages), repairing a control-plane restart or a
    never-completed handshake on the edge's next connect. The control plane
    persists its half and answers, so it does not re-invite.

  Requires `affinidi-messaging-didcomm-service` **0.11** (adds
  `ListenerConfig::with_relationship_store` and
  `DIDCommService::tsp_ensure_relationship`; no SDK bump — stays on 0.26.5). See
  `docs/tsp-transport.md`.

### Changed — dependency refresh (TSP rev3)

- **Upgraded the Affinidi / Trust-Tasks stack to the TSP rev3 line.** The
  driver is `affinidi-tsp` 0.1 → **0.2**, the Trust Spanning Protocol rev3
  release, which brings the post-quantum ML-DSA envelope suite underneath the
  transport. It moves as one coordinated family bump: `affinidi-tdk`
  0.14 → 0.16, `affinidi-messaging-didcomm-service` 0.8 → 0.10 (SDK
  0.24 → 0.26), `vta-sdk` 0.38 → 0.41, `vti-common` 0.18.5 → 0.18.9, and all
  five `trust-tasks-*` lines 0.20 → 0.21. Dev-graph `affinidi-messaging-test-mediator`
  0.7 → 0.9 to match. No workspace source change was required — this service
  speaks trust-tasks documents, not TSP envelope internals — and the framework
  still emits `trust-task-error/0.5`. `cargo tree -d` shows no duplicate of the
  family in the normal, build or dev graphs.
- **Refreshed the remaining crates within their existing semver ranges**
  (AWS SDK, `affinidi-did-resolver-*`, `clap`, `jiff`, `reqwest` subtree, …).
  The deliberate holds are unchanged: our `jsonwebtoken` stays at 10,
  `aws-smithy-types` stays below 1.7 (1.6.4), and `base64` at 0.23.

### Added — `did:webs` hosting

- **The service can host `did:webs` DIDs**, behind the new `method-webs`
  feature: registration and publish on the control plane, control-plane→edge
  sync, and resolution of both artifacts. **Off by default on every binary** —
  it pulls the KERI stack, and an operator hosting no `did:webs` DIDs should not
  carry it. On the daemon, `--features method-webs` turns on both halves at
  once; standalone deployments enable it on `did-hosting-control` *and*
  `did-hosting-server`. See `docs/did-webs-hosting.md`.

  Verification is the point of it. `affinidi-did-webs` (taken without its
  `create` feature — the hosting service never holds KERI keys) verifies every
  key event's SAID, the digest chain, controller signatures, pre-rotation
  commitments, delegation seals, witness receipts, and the designated-aliases
  attestation that `alsoKnownAs` comes from. Two further rules are this
  service's own: a stream may only be published to the slot whose final path
  segment is the AID that stream establishes, and an update may not rewind or
  fork the hosted log.

  Two things did not fit the shape `docs/multi-method-hosting-spec.md`
  anticipated, and both are deliberate:

  - **`did:webs` publishes two artifacts, and `DidMethod` carries one.** Rather
    than widen a trait the spec marks "ask first", the CESR stream is stored
    under the existing `content:{mnemonic}:log` key and `did.json` is **derived
    on every read**. The only document this service may serve is the one the log
    implies, so a stored copy could only ever be right or stale — and stale here
    means serving a document from before a key rotation.
  - **A `did:webs` slot ends in a mixed-case AID**, which the shared
    lowercase-only path grammar rejects outright. New `validate_webs_mnemonic`
    exempts the trailing AID only; leading path segments keep the strict rule,
    which exists so two slots cannot differ only by case.

- **`POST /api/dids/register` accepts `method: "webs"`** with the `keri.cesr`
  stream as `did_data` (a string). `method` must be explicit for this method: a
  key event log has no `id` field to derive it from. `did:web` registration is
  still refused, unchanged.

### Changed

- **`register_did_atomic` takes a `domain` argument.** A `did:webs` key event log
  establishes an AID, not a DID — the host and path come from where it is
  published — so the identifier is constructed from the slot and the log is then
  required to establish exactly that AID. webvh reads its own host out of the
  log and ignores the argument. Existing non-REST callers pass `None`.
- **`reconcile_agent_names` takes the extracted name list** rather than the raw
  log. The Layer-1 rule (a node cannot serve a name the DID does not claim) is
  unchanged — it is enforced one step earlier, so each method can say where its
  current document lives without a second copy of the `alsoKnownAs` rule.
- **Edges verify a synced `did:webs` log for themselves** instead of trusting the
  control plane's push. The webvh sync path is unchanged (structural only), for
  the reason it always was: the control plane has already walked that chain, and
  an edge re-running it would reject logs an older `didwebvh-rs` accepted.

### Fixed — rate-limit refusals are `429`, and say who refused

- **Every refusal from this service's own limiters is now a `429`** carrying
  `x-rate-limit-source: did-host`, `Retry-After` in seconds, and a JSON body
  `{ "error": "rate_limited", "limiter": "<name>", "message": "…",
  "retryAfterSecs": N }` — the contract the VTA, VTC and mediator also emit, and
  that `vta_sdk::rate_limit` reads. They all answered `400` before, which no
  client can tell apart from a malformed request: nothing backed off, and an
  operator could not see which service in the path had refused.

  The limiters, by `limiter` name:

  - `auth-challenge-per-ip` — control plane (and daemon) `POST
    /api/auth/challenge`, 30 per IP per 60 s. `Retry-After` is the time left in
    the window.
  - `auth-challenge-pending-per-did` — the per-DID cap on pending challenges: the
    control plane's own tracker, and the canonical handler's cap on
    `did-hosting-server` and `webvh-witness`.
  - `auth-challenge-pending-global` — the control plane's global pending cap.

  For the canonical per-DID cap on `did-hosting-server` and `webvh-witness`,
  `Retry-After` is `challenge_ttl + session_cleanup_interval` (630 s by
  default): a slot frees when its challenge authenticates, or when the sweep
  removes it after expiry. The control plane's caps compute the exact moment
  instead (see the next section).

- **New `AppError::RateLimited { limiter, message, retry_after_secs }`** in
  `did-hosting-common`, and `AuthError::PendingChallengeLimitReached` now
  converts to it rather than to `Validation`.
- **`did-hosting-client` gains `ClientError::RateLimited { limit_source,
  retry_after_secs, body }`**, read from `x-rate-limit-source` and
  `Retry-After`, and counted by `is_retryable()`. A 429 used to fall through to
  `Protocol("unexpected status")`; the challenge limit, as a `400`, read as
  `Validation`. A 429 without the header is reported with `limit_source: None`
  — a proxy or load balancer, not the host.

  DID resolution (`did.jsonl`, `did.json`, `keri.cesr`) has no limiter, so is
  unchanged. The per-IP limiter has no Trust Task counterpart; the control
  plane's pending caps now do (next section).

### Fixed — abandoned auth challenges no longer lock out the control plane

- **An auth challenge nobody redeems now gives its slot back when it expires.**
  The control plane's `PendingChallengeTracker` released a slot only when its
  challenge authenticated. A challenge that expired unused, one issued to a DID
  with no ACL entry (answered without persisting anything, so nothing could
  ever redeem it), or one authenticated over a different binding than it was
  issued on held its slot until restart. Ten abandoned challenges locked a DID
  out of `POST /api/auth/challenge` for good, and ~10,000 across any DIDs locked
  out every login to the control plane (and daemon) — an unauthenticated denial
  of service, whose `Retry-After` promised a retry that would never succeed.

  The tracker now holds the set of live challenges, each expiring with
  `challenge_ttl` — the same bound the authenticate handler enforces — so a
  missed release can over-count for at most one TTL. A successful authenticate
  releases exactly its own challenge by session id (a second release is a
  no-op); a failed one leaves the challenge redeemable and keeps its slot. At
  boot the tracker is seeded from the still-redeemable `ChallengeSent` rows in
  the session store, so the caps hold across a restart. `Retry-After` on
  `auth-challenge-pending-per-did` / `auth-challenge-pending-global` is now the
  moment the oldest counted challenge expires (≤ `challenge_ttl`, 30 s by
  default), not 630 s.

  `did-hosting-server` and `webvh-witness` were not affected: their per-DID cap
  counts `ChallengeSent` rows in the store, which the session sweep removes.

- **`auth/challenge/0.1` over DIDComm, TSP and the HTTPS `/trust-tasks` route
  is held to the same per-DID and global caps** as `POST /api/auth/challenge`.
  It called the canonical handler with its per-DID cap disabled and bypassed
  the tracker, so challenges over those bindings were unbounded. The Trust Task
  framework defines no rate-limit code, so a refusal answers `permissionDenied`
  — the arm's existing mapping for every challenge failure — with the limiter
  and retry hint in the operator log.

- **`PendingChallengeTracker` API**: `try_issue(did, per_did_cap)` returns a
  `Reservation` to `bind` to the issued session id or `cancel`;
  `release(did)` is replaced by `release_session(session_id)`; new
  `for_auth_config`, `with_clock`, `seed_from_sessions`. Counts are `usize`,
  and the methods are synchronous.

### Changed — pending-challenge caps are operator-configurable

- **The control plane's pending-challenge caps can now be tuned.** Both the
  global cap (default 10,000) and the per-DID cap (default 10) are now
  `[auth]` config fields — `max_global_pending_challenges` and
  `max_pending_challenges_per_did` — overridable by env
  (`*_AUTH_MAX_GLOBAL_PENDING_CHALLENGES`,
  `*_AUTH_MAX_PENDING_CHALLENGES_PER_DID`). Defaults are unchanged, so
  behaviour is identical unless an operator sets them; a zero cap is refused at
  config load. This is defence-in-depth on already-bounded code, letting large
  or small deployments size the caps to their footprint.

- **The bounded-memory and locking guarantees are now documented in-code.**
  `pending_challenges.rs` states explicitly that every internal structure is
  capped at the global cap (memory cannot grow without limit; refusal at the
  cap is fail-closed, and the per-IP limiter throttles fill rate — CWE-400),
  and that its `std::sync::Mutex` guard is never held across an `.await` (which
  would fail to compile as a non-`Send` future — CWE-667). No behaviour change;
  the rationale now lives beside the code.

### Changed — dependencies

- **Trust Tasks 0.18 → 0.19, `affinidi-tdk` 0.12 → 0.13, `vta-sdk` 0.34 → 0.35,
  `vti-common` 0.18.0 → 0.18.2, `affinidi-messaging-didcomm-service` 0.6 → 0.7,
  `affinidi-messaging-sdk` 0.22 → 0.23.** No source change in this workspace:
  0.19.0's breaking changes are confined to the `rooms/*` family
  (`rooms/owner/issue-authority` 0.2 makes `validUntil` REQUIRED;
  `rooms/keys/present` 0.2 drops `audience`/`nonce`), and we consume no
  `rooms/*` payload.

  The compiler-invisible check was run rather than assumed: the framework still
  emits `trust-task-error/0.5` at 0.19.4, and the hand-written copy in
  `server::trust_tasks::framework_error_type_uri()` still agrees.

  The dev graph needed its own bump again — `affinidi-messaging-test-mediator`
  0.5 → 0.6 (mediator 0.23) — making it four consecutive moves of this family
  where the dev-dep had to move in the same commit. `cargo tree -d -e
  normal,build` and `-e normal,build,dev` both list none of `vta-sdk`,
  `vti-common`, `affinidi-tdk` or `trust-tasks-rs`.

- **Held at trust-tasks 0.19, deliberately.** 0.20.1 is published, but
  `vta-sdk` 0.35 — the newest — still pins `trust-tasks-rs ^0.19.4`, and
  `vti-common` 0.18.2 with it. Moving our five manifest lines to 0.20 alone
  would duplicate `trust-tasks-rs`, `affinidi-tdk` (0.13 vs 0.14) and
  `affinidi-messaging-sdk` (0.23 vs 0.24). The 0.20 step is gated on
  verifiable-trust-infrastructure publishing a vta-sdk/vti-common pair on
  `^0.20`.

- **`firestore` 0.53 → 0.54**, and in-range refreshes across the lock
  (`reqwest` 0.13.5, `redis` 1.7, `uuid` 1.26.1, `gcloud-sdk` 0.32). `fuzz/Cargo.lock`
  regenerated to match — it records `did-hosting-common`'s dependency set and
  the nightly Fuzz job gates on `cargo fetch --locked`.

- **`jsonwebtoken` stays at 10.** `trust-tasks-https` is still on `^10` at
  0.19.4, so the 10/11 split with `vti-common` persists and our declaration only
  picks which copy we compile against. We cross neither crate's JWT surface.

- **Trust Tasks 0.9 → 0.17, `affinidi-tdk` 0.8 → 0.10, `vta-sdk` 0.25 → 0.31,
  `vti-common` 0.12 → 0.15, `affinidi-messaging-didcomm-service` 0.3 → 0.5.**
  The whole `trust-tasks-*` family moves as one, for the reason the workspace
  manifest gives: `trust-tasks-rs`'s core types cross the public API of
  `-https` / `-didcomm` / `-proof` / `-tsp`.

  Two breaking changes reach source. Generated payload types are
  `#[non_exhaustive]`, so every `acl/*` and `trust-task-discovery` request and
  response literal is built through its generated builder and the constrained
  string newtypes (`AclEntryLabel`, `PayloadReason`, …) are parsed rather than
  `.into()`-ed. And `consume_inbound` now takes a required `ConsumeChecks` —
  SPEC §7.2 item 4 (freshness) and item 11 (duplicate execution), promoted from
  framework default to caller argument.

  `ConsumeChecks::not_consequential()` is passed, which is exactly what the shim
  has always done: 0.9 kept no duplicate-execution record at all, so the bump
  changes no behaviour. **It is not the right long-term answer for the ACL
  writes** (`acl/grant`, `acl/revoke`, `acl/change-role`), which are
  consequential by §2 — a mediator redelivery of one grant document would
  execute twice. A real `ReplayGuard` needs storage behind it and a decision
  about which processes share a VID (control plane, server and daemon all
  consume), so it is its own change rather than a dependency bump. The call site
  says so, and `ConsumeOutcome::Duplicate` is already handled (§7.2: a duplicate
  is not a failure, so it must never fold into `Rejected`) — unreachable until a
  guard is wired, written out so that wiring one is a single edit.

  The framework error document is still `trust-task-error/0.5` under 0.17;
  `unrouted_and_routed_errors_agree_on_the_type_uri` covers it.

- **`affinidi-messaging-test-mediator` 0.2 → 0.4, to close a dev-graph split.**
  Not cosmetic, and not separable from the bump above: the test-mediator carries
  its own `trust-tasks-rs` and `affinidi-tdk`, and at `^0.2` it dragged
  `affinidi-tdk` 0.8 and `trust-tasks-rs` 0.11 back into the dev graph the
  moment the shipped graph reached 0.17. `cargo tree -d -e normal,build,dev`
  listed both twice. 0.4.0 (mediator 0.20, trust-tasks-rs 0.17) collapses them,
  and the graph is back to one copy each of `vta-sdk`, `vti-common`,
  `affinidi-tdk` and `trust-tasks-rs` across normal, build *and* dev.

  This is the second time this dev-dep has split the graph on a trust-tasks
  move. It is now noted in both manifests as a crate that must be bumped in the
  same commit as the family, rather than left to float.

- **`firestore` 0.50 → 0.53** (and `gcloud-sdk` 0.30 → 0.31 behind it). 0.53
  makes the `db::support` traits private, so the extension methods the
  `store-firestore` backend called on `FirestoreDb` — `update_obj`,
  `get_obj_if_exists`, `delete_by_id`, `stream_list_obj` — are no longer in
  scope at any path. The four call sites move to the fluent builders, which is
  the API the crate now intends and the one `FirestoreBatch` in the same file
  already used. Behaviour is unchanged: same upsert semantics, same
  page-size-10 000 listing, same document IDs.

- **`deny.toml`: MPL-2.0 exception for `option-ext`.** New in the graph via
  `vta-sdk` 0.31, which picked up `dirs 6` for its config-path lookup
  (`dirs → dirs-sys → option-ext`). Transitive only, unmodified upstream, and
  file-level copyleft — the same shape as the `webauthn-rs` entries beside it.

- **Workspace-wide `cargo update`.** Lockfile only — no manifest edits, so every
  semver range is unchanged and the documented lockstep pins hold: `vta-sdk`
  stays on 0.25 (0.28 available) and `vti-common` on 0.12 (0.13 available),
  because moving either requires the matching bump of the other.

  Clears **RUSTSEC-2026-0258** for the copy we control (`h2` 0.4.15 → 0.4.18,
  above the advisory's stated fix of ≥ 0.4.16). A second copy, `h2` 0.3.27,
  arrives via the AWS SDK's hyper 0.14 and has no patched 0.3.x; it is ignored
  in `deny.toml` with a justification, alongside the three `rustls-webpki`
  entries that share the same root cause. All four clear when the AWS SDK moves
  to hyper 1.x.

  Also drops the stale `RUSTSEC-2025-0134` ignore — the update removed
  `rustls-pemfile` from the lock entirely.

  Note for anyone tracing the graph: `affinidi-messaging-didcomm-service` 0.3.27
  now pulls `trust-tasks-rs` 0.11.4 alongside our direct 0.9. The workspace
  manifest warns that a graph mixing trust-tasks majors does not type-check — it
  does here, so the two never meet at our API boundary, but the duplication is
  worth knowing about.

- **`clippy::result_large_err` allowed where the `Err` type is upstream.** Rust
  1.98.0 began firing it on seven functions returning
  `trust_tasks_rs::TrustTask<ErrorPayload>` (752–832 bytes). The type is
  upstream and cannot be shrunk here; boxing at our boundary would rewrite every
  handler signature and call site to save one move on a path already about to
  serialise the error onto the wire. Scoped to the `trust_tasks::handlers`
  module and to `authorize`, so it reads as "these return an upstream error
  type" rather than a workspace-wide opt-out.

- **Trust Tasks 0.6 → 0.9, and `vta-sdk` 0.24 → 0.25.** The whole
  `trust-tasks-*` family moves together, as it must — `trust-tasks-rs`'s core
  types cross the public API of `-https` / `-didcomm` / `-proof` / `-tsp`, so a
  graph mixing majors does not type-check.

  Three breaking releases sit in the range. **0.7.0** made `StandardCode`
  `#[non_exhaustive]` (nothing here matches on it, and it is the last time a new
  framework error code will break a downstream `match`). **0.8.0** added
  `StandardCode::Cancelled` and `trust-task-control/0.1`, additive in Rust.
  **0.9.0** gave `consume_inbound` a REQUIRED `PayloadPolicy` argument
  (SPEC §7.2 item 2) and replaced `ValidatedPayload::SCHEMA_JSON` with
  `Payload::PAYLOAD_SCHEMA`, which we never used.

  We reach `consume_inbound` through exactly one shim —
  `did_hosting_common::server::trust_tasks::run_pipeline` — so the policy is
  decided there once, for all ~28 call sites, rather than threaded through each.
  It is `PayloadPolicy::<NoValidator>::AcceptUnvalidated`, which is what this
  code has always done, now stated rather than implied: the codegen `Payload`
  structs carry `deny_unknown_fields` plus newtypes that reject `minLength` and
  pattern violations at deserialise time. That is the same reasoning the
  workspace `Cargo.toml` already gives for leaving the `validate` feature off.

  **No document is accepted or refused differently by this release.** Moving to
  `Validate` would be a behaviour change — it can begin refusing documents a
  peer sends today — and belongs in its own release with its own rollout.

### Changed — UI toolchain

- **Node floor 20 → 24.3, `vitest` 4 → 5.** Node 20 reached end-of-life in
  April 2026; `vitest` 5 requires `^22.12 || ^24 || >=26`, so the runner could
  not move until the floor did. 24 is the active LTS (maintained to April 2028).

  The floor is `>=24.3.0`, not `>=24`, because React Native 0.86 declares
  `^24.3.0` — Node 24.0–24.2 are genuinely too old for the tree. CI's
  `node-version: "24"` resolves to the latest 24.x, which satisfies it; it must
  not be pinned to an exact 24.0.x. `engines.node`, the CI `node-version` and
  the README prerequisite move together.

  In-range npm updates cleared 9 of 12 reported advisories. The remaining three
  are moderate, inside `expo-router`'s transitive `query-string`, and need a
  breaking change to clear.

### Changed — wire

- **Framework error documents are now `trust-task-error/0.5`, up from `0.3`.**
  Not a choice: `0.4` added the `idConflict` standard code and `0.5` added
  `cancelled` (SPEC §8.3), and neither validates against the older payload
  schema's `code` enum or its extended-code pattern, so a document carrying one
  would not validate as `0.3`.

  Per SPEC §5.2 forward-minor compatibility a consumer pinned to `0.3` SHOULD
  accept `0.5`. Consumers that enumerate error versions rather than matching
  `trust-task-error/0.x` are the ones to check.

  `framework_error_type_uri()` is the workspace's single hand-written copy of
  that version — it exists because `trust-tasks-rs` keeps
  `trust_task_error_type_uri()` `pub(crate)`, and the unrouted paths (body never
  parsed, so no request document to reject from) have nowhere else to get it.
  `unrouted_and_routed_errors_agree_on_the_type_uri` caught the drift, as it was
  written to. Two assertions in `did-hosting-control`'s messaging tests that
  named `0.3` literally now read the constant instead, so they follow the
  emitter on the next bump rather than stranding a version behind.

  **Worth remembering for the next bump:** a hand-written spec version is
  invisible to the compiler. Grep for `trust-task-error/0.` before trusting a
  green build.

### Fixed — dependency graph

- **The tolerated dev-graph split has collapsed.** `cargo tree -d -e
  normal,build,dev` previously showed two `vta-sdk` (0.21.9 + 0.24.0) and three
  `trust-tasks-rs` (0.2.60, 0.4.1, 0.6.1), reached through
  `affinidi-messaging-test-mediator` → `affinidi-messaging-mediator`. The
  messaging stack has now republished on the current line (mediator 0.18.18,
  test-mediator 0.2.51, both on trust-tasks-rs 0.9), so both the shipped **and**
  dev graphs carry exactly one of `trust-tasks-rs`, `vta-sdk`, `vti-common` and
  `affinidi-tdk`. The `Cargo.toml` note that predicted this has been updated to
  record it.

### Changed — wire

- **The task-consent `payloadDigest` is now a `digestMultibase`, not bare
  hex.** `routes::task_consent::wire_digest` emits
  `multibase(base58btc, 0x12 0x20 || sha256(…))` — the encoding W3C VCDM
  2.0 defines, `did:webvh` already uses for its SCIDs, and the Trust
  Tasks registry moved `payloadDigest` onto in `trust-tasks-rs` 0.4. The
  pre-image is unchanged: same domain tag, same length-prefixed task type
  and JCS-canonical payload, same challenge salt. Only the encoding moved.

  **This is a coordinated cross-repo change and had to happen.** The
  published `task-consent/request/0.1` schema types the member as
  `DigestMultibase` (`^[zumbfF][A-Za-z0-9+/=_-]+$`, ≥16 chars), which a
  hex digest satisfies only by accident — and only when it happens to
  start with one of `b`/`f`/`F`/`u`/`m`/`z`. The VTA's half is
  OpenVTC/verifiable-trust-infrastructure#911, which converted
  `vta_policy::consent` to the identical encoding *and* made
  `vta-mobile-core` **parse** the incoming digest as `DigestMultibase`
  rather than pass a string through. Against that approver our hex value
  now fails at the device — which is the good failure. The bad one, had
  the parse not been added, is an approval the operator gives and accepts
  and which then silently never takes effect, because the executor can
  never match it.

  The digest is only ever *echoed* by the approver, never recomputed, so
  the two services keep their own domain tags
  (`did-hosting/task-consent/v1\0` here, `vta/task-consent/v1\0` there) —
  a digest minted by one can't be replayed as the other's. Only the
  encoding has to agree.

  Nothing to migrate: in-flight pendings live in an in-memory map behind
  `CONSENT_TIMEOUT` and do not survive the restart that deploys this.

  Covered by a new `digest_is_multibase_multihash_not_hex` test asserting
  the *structure* — base58btc, the `0x12 0x20` multihash prefix in-band,
  34 bytes, and the published pattern — rather than a character count,
  since base58 is not byte-aligned and a leading-zero digest encodes
  shorter.

- **The operator's match code now derives from the digest bytes, not the
  encoding** (`digestPrefix`, moved to `did-hosting-ui/lib/digest-code.ts`).

  This is the other half of the change above, and skipping it would have
  broken the check outright. The code is the six characters the operator
  compares between this screen and the approver's device, under a hint
  that reads *"if the codes differ, deny it"*. It used to be the digest's
  first six characters, which was `hex(digest)[..6]` while the wire
  carried hex. Left alone, the encoding change would have made this
  screen show `zQmcdL` while the approver showed `d449ac` — every code
  mismatching, every legitimate change looking like an attack.

  `digestPrefix` now decodes the multibase, strips the `0x12 0x20`
  multihash prefix, and hex-encodes the leading digest bytes — mirroring
  `vta-mobile-core`'s `match_code_from_digest` exactly. Because the
  digest is still SHA-256, this reproduces the *same* code the screen
  showed before the migration, so the encoding change is invisible here.

  It also keeps the entropy: `payloadDigest` opens `zQm` for every value
  ever produced (base58btc marker plus the sha2-256 multihash prefix), so
  slicing the encoded string would have spent half the code on a constant
  — ~17.6 bits where the operator believes they are comparing ~35, and
  still *looking* like six random characters, which is what would make it
  dangerous rather than merely wasteful.

  Fails closed: anything that is not a base58btc sha2-256 multihash —
  including a stale bare-hex digest — yields `""`, so the operator sees
  no code and denies rather than being shown a plausible prefix of an
  unparseable value.

  Pinned by `lib/__tests__/digest-prefix.test.ts` against the VTA's own
  test vector (`zQmSK9…GYZ` → `3b0c7f`), so a divergence in either
  repo's derivation fails a test instead of silently reaching an
  operator. The function moved to its own import-free module because
  `wallet.ts` imports `react-native`, which the test runner cannot parse;
  `wallet.ts` re-exports it, so callers are unchanged.

### Security

- **The DIDComm trust-task envelope now carries the same anti-replay gate
  as the bare `MSG_*` path** (did-hosting-control 0.8.8). The control
  plane accepts DID-management ops in *two* DIDComm framings: a bare task
  type (`MSG_DID_REGISTER`, `MSG_DELETE`, …) routed to `run_webvh_dispatch`,
  and the `trust_tasks_didcomm::ENVELOPE_TYPE` envelope routed to
  `run_trust_tasks_envelope`. Both reach the same `dispatch_did_op` table —
  the envelope path via `bridge_did_management` — so both reach the same
  state-changing operations. Only the first consulted the replay cache.

  Freshness does not cover this. `created_time` ± the 5-minute window is
  checked during unpack, but a captured envelope re-submitted inside that
  window still verifies; the `(sender, msg.id)` cache is what stops it, and
  `replay.rs` names the operations it exists for — delete, change-owner,
  publish. A client moving its DID-management traffic from bare types onto
  the envelope binding (which is the direction the VTA is going) would have
  silently lost that protection, with no error and no log to show for it.

  `run_trust_tasks_envelope` now gates on the same cache and the same key,
  and rejects with the *same* problem report the bare path emits, so the
  error a client sees does not depend on which framing it used. Ordering
  differs deliberately: the bare path gates after its ACL check, while here
  authorization belongs to the dispatcher and varies by op (framework §7.2
  ops authorize themselves; discovery is intentionally open), so the gate
  runs after the body parses as a Trust Task — malformed bodies never reach
  the cache, and the router's `require_encrypted(true).require_sender_did(true)`
  means every key inserted still belongs to a proven sender.

  No wire change, no new URI, and no behavioural change for first delivery
  of any message.

### Added

- **Signed end-to-end coverage for the approval round trip and
  REQUIRED-proof dispatch** (#147, #149, #150). Closes the test
  deferral left in `did-hosting-control/src/messaging.rs` when
  REQUIRED-proof specs had no signing path: now that both legs sign,
  the tests mint a `task-consent/request/0.1` through the exact
  production builder (control `did:key`), verify it the way a
  conforming approver must (proof + issuer ↔ `verificationMethod`
  binding via `TransportBoundVerifier`), sign the wallet's
  `task-consent/decision/0.1` echoing the verified document's
  `challenge`/`payloadDigest`, and drive it through the inbound
  decision path — asserting the parked request resolves on
  approve/deny and that unsigned, tampered, wrong-holder,
  wrong-key, wrong-digest, wrong-recipient, and stale-challenge
  variants are each refused without consuming the pending entry.
  A signed `acl/grant/0.1` (proof REQUIRED) envelope dispatch is
  covered the same way: a real Data Integrity proof verifies
  end-to-end under `enforce_proofs = true` and lands the entry;
  tampered → `proofInvalid`, proofless → `proofRequired`, nothing
  stored. Test-enabling refactor only: the decision handler's body
  moved into `run_consent_decision` (the established `run_*`
  extraction pattern) so it is drivable without an ATM-backed
  `HandlerContext`; wire behavior is unchanged.

### Added

- **The DID detail page now says when a delegated edit is unlikely to work, and
  what to do when it did not** (did-hosting-ui, `lib/delegation-guard.ts`). Two
  separate confusions, neither of which the obvious ownership gate solves on its
  own:

  - A control-plane admin sees *every* DID on the server (`list_dids` returns
    all of them when the caller is admin and names no owner), and
    "Publish with my agent" was offered on all of them — including DIDs no agent
    of theirs could ever sign for. The page now warns when the DID's owner is
    not the identity the session authenticated as. It **warns rather than
    gates**: the page cannot learn which agent the wallet holds
    (`walletDefaults()` returns only the step-up VTA), so a hard gate would also
    block the legitimate passkey-session-plus-owning-wallet case.

  - An **orphan** — a DID this host still serves after the owning agent deleted
    it — passes any ownership test, because the host record keeps its `owner`.
    (`delete_did_webvh` calls the host first and, if that fails, logs
    "continuing local cleanup but DID is now orphaned on the daemon" and removes
    the local record anyway.) The agent's rejection for this reads
    `did not found: SCID … not found`, which looks like data loss for a DID the
    host is visibly serving. That specific rejection now carries the reason and
    the command that resolves it, rather than the raw error alone.

### Fixed

- **The service no longer emits two versions of the framework error
  document.** Every *routed* rejection goes out through
  `TrustTask::reject_with`, which stamps whatever `trust-tasks-rs` emits —
  `trust-task-error/0.3` since the framework's own 0.3 release. But the four
  **unrouted** paths (a body that never parsed into a Trust Task, so there is
  no request to reject from) each wrote the Type URI out by hand, and each
  wrote `0.1`: `routes::trust_tasks::error_type_uri`,
  `routes::auth::trust_task_malformed`, `messaging::body_parse_error` and the
  TSP transport's parse-failure reply.

  So which version a caller saw depended on whether its request happened to
  parse. That is a trap for exactly the consumer that pins a version, and the
  trap sprang: a client enumerating `0.1`/`0.2` decoded every `0.3` rejection as
  a **success**, because an unrecognised error document falls through to the
  success branch (see the management-UI entry below, and
  OpenVTC/vta-browser-plugin#115).

  `trust-tasks-rs` keeps `trust_task_error_type_uri()` `pub(crate)`, so the
  value cannot be read from the framework. It is now named once for the
  workspace in `did_hosting_common::server::trust_tasks::framework_error_type_uri`,
  and a test compares it against the Type URI a real `reject_with` produces —
  so a framework bump fails a test instead of silently re-splitting the service
  in two. Test assertions that hard-coded `0.1` now assert against that
  function rather than a literal.

- **The management UI now recognises a Trust-Task rejection again**
  (did-hosting-ui). Two independent faults, either of which alone hid the
  server's answer:

  1. The reply-document check was pinned to `trust-task-error/0.1`, and
     `trust-tasks-rs` has emitted `/0.3` since its 0.3 release — it carries the
     §8.2 `inResponseTo` member, which `0.2`'s `additionalProperties: false`
     payload schema cannot admit. The workspace is on 0.4.1, so nothing had sent
     a document that check matched for some time. It now matches the framework
     slug at any `0.x` (SPEC.md §5.2 forward-minor), so the next minor cannot
     break it again; `1.x` is excluded, as that is where the payload shape may
     change.

  2. A rejection arrives as a *document* at a non-2xx status —
     `into_response` maps the code through `status_for_code`
     (`permissionDenied` → 403, `taskFailed` → 422). `request()` threw on the
     status before the body was examined, so the document was discarded no
     matter what version it claimed. Every rejection surfaced as a bare
     `ApiError` carrying serialised JSON as its message, which meant the §8.4
     retry policy — written against `code` / `retryable` / `retryAfter` — could
     never run: nothing was ever a `TrustTaskRejection`. The body is now parsed
     before the failure is classified; anything that is not a framework error
     document is re-thrown untouched. `TrustTaskRejection` also keeps the status
     it arrived at instead of reporting a flat 422.

  The tests missed both because they served error documents at HTTP 200 and
  typed them `/0.1` — a shape no server produces. They now serve rejections at
  their mapped status with the emitted version.

- **`cargo publish` no longer fails on the control plane's UI build**
  (did-hosting-control 0.8.8, did-hosting-ui). Both the build script and
  the rust-embed derive reached `../did-hosting-ui`, a workspace sibling
  that `cargo package` never collects — so verification of the packaged
  crate died in `build.rs` with a misleading `failed to run npm install
  --prefer-offline: No such file or directory`. npm was never looked up:
  `Command::current_dir` was pointed at a path that does not exist inside
  the tarball. `--no-verify` would only have moved the breakage to
  consumers, since `cargo install did-hosting-control` and docs.rs build
  the same tarball.

  `npm run build:web` now exports into `did-hosting-control/ui-dist/`, the
  crate embeds *that*, and the directory is carried into the tarball by an
  explicit `include` list. When the `did-hosting-ui` sibling is absent —
  the published crate, or a lone checkout of this one — `build_ui` returns
  early against the pre-bundled assets, so **building the published crate
  requires neither Node nor npm**; `check_node_version` is now reached only
  when a bundler run is genuinely due. A build with no bundle at all still
  compiles (empty folder, UI routes 404) behind a `cargo:warning` rather
  than failing the derive.

  Publishing this crate now needs `cargo publish --allow-dirty`: cargo
  counts the gitignored bundle as an uncommitted change. Check `git status`
  is otherwise clean first — that flag suppresses the dirty check wholesale,
  not just for `ui-dist`.

- **An approved DID update applied off-tab no longer strands the DID
  detail screen** (did-hosting-ui). Binding an agent name published a
  new version, but the screen kept showing the old one and every route
  forward failed with `concurrent update: … expected 1-…, current is
  2-…`.

  The screen refreshed on mount and after a *successful* publish, and
  nowhere else. A delegated publish that needs approval does not
  succeed inline — it returns `consentRequired` and pins the exact
  re-submit — and the only thing that ever resumed it was the wallet's
  `vtawallet:consentgranted` event. That event fires solely in the tab
  whose wallet relayed the decision, so approving on a paired mobile
  approver let the VTA apply the update server-side with nothing to
  dispatch back to the browser. The tab kept its stale `logEntries`,
  and both exits were dead: "Publish now" replays a payload pinned to
  `expectedVersionId` v1, and a fresh bind composes `alsoKnownAs` from
  the same stale `currentState` — the VTA's dry-run rejects each as a
  concurrent update. A manual browser reload was the only escape, and
  nothing on screen suggested one.

  While an approval is outstanding the screen now re-reads the log
  every five seconds and, once it has moved past the pinned version,
  retires the dead re-submit and reloads. This does not reopen the
  question the "no timer poll" note settled: that rule is about
  *re-submitting*, which reopens the wallet's un-skippable worker-mode
  confirm on each tick, whereas this is an authenticated GET that
  touches no wallet. The notice deliberately does not claim the user's
  change was the one applied — an advancing log proves only that the
  document moved, not who moved it. The decision rule is extracted to
  `lib/pinned-edit.ts` and unit-tested, including that an empty or
  partial read counts as "nothing observed" rather than movement, so a
  failed poll can never discard a live approval.

- **An unrouted DIDComm message now gets a problem-report instead of
  silence** (did-hosting-control 0.8.7). The control plane's fallback
  handler logged an unhandled type and returned nothing, so a caller
  sending a task this router has no arm for learned nothing at all —
  it waited out its full request timeout and then reported a bare
  gateway error naming no task.

  That is what made #144's retirements expensive downstream. A VTA
  still sending the retired `did/publish/0.1` and the
  `agent-name/{set,enable,disable}/0.1` trio burned 30 seconds per
  call and surfaced "bad gateway: request timed out" with nothing to
  grep for; on DIDComm — the transport a client prefers whenever a
  host advertises both — every server-managed publish failed this
  way, while the REST equivalents failed visibly with a 404. The
  retirements themselves were correct; only the silence was the
  problem, and it would have cost the same on the next one.

  The fallback now replies `e.p.msg.unsupported-task` naming the
  refused type, threaded to the request id so the caller's dispatcher
  actually demuxes it — an unthreaded reply would be discarded and
  the caller would wait out the timeout regardless. Loop-safe: an
  inbound problem-report still returns early, before the reply path,
  and the emitted type is itself matched by `is_problem_report`, so a
  peer that cannot route it logs and drops rather than answering
  back. Both properties are pinned by tests.
  request's Data Integrity proof REQUIRED — the approver renders the
  request's prose as the basis of a human decision, so the request must
  be attributable to the relying party by signature, not just by
  transport attribution — but `did-hosting-control` sent both unsigned:

  - `task-consent/request/0.1` now carries an `eddsa-jcs-2022` proof
    (`proofPurpose: assertionMethod`) signed with the control DID's
    assertion key, with `issuer` == the DID of
    `proof.verificationMethod` == the control DID — the same binding
    this service's own `TransportBoundVerifier` enforces on the wallet's
    inbound decision, so the wallet verifies our request exactly the way
    we verify its answer. The module's documented
    "authcrypt-attribution-only request leg" deviation is retired.
  - `POST /api/auth/step-up/vta/start` — previously a bare
    `{subject, sessionId, challenge, reason}` JSON, not a Trust Task at
    all — now mints a full signed `auth/step-up/approve-request/0.2`
    document (issuer = control DID, recipient = the subject DID on the
    self-approve path, payload per the closed spec schema). For the
    coordinated rollout the REST response is a superset: the legacy
    top-level fields are unchanged (deprecated; existing consumers keep
    parsing them) and the signed document rides alongside in a new
    `document` field.

  The signing key comes from the service identity's current generation
  (`signing_kid` + its loaded secret), not the boot-time
  `signing_key_bytes` seed, so the proof's `verificationMethod` tracks
  identity rotation and always names a key the published DID document
  advertises. Signing is hand-rolled on `affinidi-data-integrity` in the
  new `did_hosting_control::signing` module for now; it moves to the
  shared `trust_tasks_proof::affinidi::sign_trust_task` helper once that
  releases. The daemon inherits both changes — it mounts the control
  plane's router and DIDComm listener unchanged.

### Dependencies

- **`vta-sdk` 0.23 → 0.24, with `vti-common` 0.11.40 → 0.12.** The other half
  of the same lockstep pin, and the third time this pair has split the graph.
  `vti-common` 0.11.41 (published 2026-08-16) re-pins onto `vta-sdk` ^0.24
  while the workspace still asked for ^0.23, so any resolution that did not
  come from the committed lockfile pulled *both* copies and failed with three
  E0308s in `did-hosting-control/src/routes/auth.rs` naming two
  identical-looking `AuthenticateResponse` types.

  **No source change was required, in this repo or in the SDK's shape.**
  `vta-sdk` 0.24.0 is a single breaking change — `protocols::join_requests::
  JoinRequestStatusBody::request_id` becomes `Option<Uuid>`, letting an
  applicant poll a join it never learned the id of
  (OpenVTC/verifiable-trust-infrastructure#985). This workspace has no
  reference to join requests at all, so the major moved past us untouched;
  `protocols::auth` — the module the errors pointed at — is byte-identical
  between 0.23.3 and 0.24.0. The errors were never about a changed type. They
  were about two copies of an unchanged one.

  `vti-common` goes to the 0.12 minor rather than a pinned 0.11 patch because
  the 0.11 line now straddles the boundary (0.11.40 pins ^0.23, 0.11.41 pins
  ^0.24); a caret on 0.11.41 would keep floating across a divide the pin
  exists to hold. `cargo tree -d -e normal,build` lists none of `vta-sdk`,
  `vti-common`, `affinidi-tdk` or `trust-tasks-rs`.

  **The operational lesson, which the earlier occurrences did not make
  explicit:** the committed lockfile was correct throughout, so nothing here
  broke — the failure only reproduces in a build that re-resolves. `cargo
  install --path did-hosting-control` does exactly that unless given
  `--locked`. Deploy with `--locked`, or a release built from a clean checkout
  ships whatever crates.io published that morning rather than the pair CI
  tested.

- **The `trust-tasks-*` family 0.4 → 0.6, with `vta-sdk` 0.23.2 and
  `vti-common` 0.11.40.** The registry published
  `vta/webvh/servers/reconcile/0.1` (trustoverip/dtgwg-trust-tasks-tf#210) in
  `trust-tasks-rs` 0.6.1; this brings the workspace onto it, in lockstep with
  OpenVTC/verifiable-trust-infrastructure#979.

  **Six manifest lines were not the whole job.** Moving the five
  `trust-tasks-*` pins and `vta-sdk` left `trust-tasks-rs` duplicated in the
  *shipped* graph, which the rule in `Cargo.toml` forbids: four transitive
  carriers were still on `^0.4` — `vti-common`, `affinidi-messaging-sdk`,
  `affinidi-messaging-didcomm-service` and `trust-tasks-capability-client`.
  All four moved by lockfile alone (their requirements were already wide
  enough), and `cargo tree -d -e normal,build` is what surfaced it. `vti-common`
  0.11.40 only existed because the VTI release landed first; the two repos
  genuinely cannot be reconciled out of order.

  Two source-level consequences of 0.5.0's new `ceremony` envelope member, at
  the four places this workspace builds a `TrustTask` by struct literal. Three
  are unrouted body-parse error builders and pass `None` — nothing parsed, so
  there is no request to carry a ceremony from. The fourth,
  `messaging::tt_reply`, builds a **response** and now carries
  `request.ceremony.clone()`: SPEC §7.1 keeps a reply inside the enactment its
  request belonged to, and `None` there would have silently dropped responses
  out of their ceremony — a latent wire defect the compiler surfaced by
  accident.

  0.6.0's `DigestMultibase` narrowing (to `z`/`u`, with each alphabet enforced)
  needed no change: `routes::task_consent` mints base58btc and has a test
  asserting it. A peer that had chosen `b`/`f`/`m` would parse before this bump
  and fail after.

- **`vta-sdk` 0.21 → 0.23 and `vti-common` 0.11.35 → 0.11.39, moved
  together.** The two share the canonical auth wire types
  (`protocols::auth::{Session, TokenBundle, AuthenticateResponse, …}`), so
  their requirements are one pin in five places, and vti-common 0.11.38
  re-pinned onto vta-sdk ^0.22, 0.11.39 onto ^0.23.

  This had to move because the version requirement is a caret: `cargo update`
  floated vti-common to 0.11.39 on its own, and cargo's answer to "this needs a
  vta-sdk you did not ask for" is not a resolution error — it adds the second
  copy. The result was three `E0308: mismatched types` in `routes/auth.rs`
  naming two identical-looking `AuthenticateResponse` types, which reads as a
  code bug and is not one. CI never saw it (every job passes `--locked`); the
  `Upstream drift` canary, which resolves the way `cargo install` does, went red
  on 2026-08-13, a day before an operator's unlocked build hit the same wall.

  No source changes were needed to absorb it — the workspace compiles, tests and
  clippies clean against 0.23. Two duplicates also collapsed in the shipped
  (normal + build) graph: it now carries one `vta-sdk`, one `vti-common`, one
  `affinidi-tdk` **and** one `trust-tasks-rs`, the last because vta-sdk 0.23
  pins `trust-tasks-rs` ^0.4 where 0.21 pinned ^0.2.

  The **dev** graph still carries vta-sdk 0.21.9 and trust-tasks-rs 0.2.60, via
  `affinidi-messaging-test-mediator` → `affinidi-messaging-mediator` 0.18.11,
  which pins vta-sdk ^0.21. Tolerated deliberately: the mediator is a spawned
  test fixture and neither copy crosses into a type-checking context of ours.
  It collapses when the messaging stack republishes on ^0.23.

- **The `trust-tasks-*` family 0.2 → 0.4, moved as one workspace event**
  (`trust-tasks-rs` 0.2.55 → 0.4.1, `-https` / `-didcomm` / `-proof` /
  `-tsp` 0.2.x → 0.4.0). The core types cross the public API of the four
  binding crates, so a graph mixing majors does not type-check — all five
  requirements move together or none do.

  Two framework changes reached our code. **0.3** added `parentThreadId`
  to the document envelope and `inResponseTo` to the error payload, which
  breaks struct-literal construction of `TrustTask` / `ErrorResponse`: the
  three unrouted body-parse error builders (`messaging::body_parse_error`,
  `routes::auth::trust_task_malformed`, `routes::trust_tasks::body_parse_error`)
  pass `None` — nothing parsed, so there is no request to read an enclosing
  exchange from — and `messaging::tt_reply` carries the request's value
  through, since per SPEC §4.9.2 the whole exchange shares one parent.
  0.3 also moved the emitted framework error Type URI to
  `trust-task-error/0.3`, which two envelope-dispatch tests asserted on.
  No wire change we produce: `parentThreadId` is omitted when unset, and
  the error documents we hand-build still declare `trust-task-error/0.1`
  with an unchanged payload shape.

  **0.4** retyped digest-carrying payload members from `String` to the
  validating `DigestMultibase` newtype. It did not reach our *compile* —
  our `task-consent/*` legs are built and read as untyped
  `serde_json::Value` against the descriptors in `did_hosting_tasks.rs`,
  not the codegen payload types — but see the wire change below, which
  it forces.

  The lock now carries **two `trust-tasks-rs` copies** — 0.2.60 for
  `vta-sdk` 0.21.9 / `vti-common` 0.11.35 / `trust-tasks-capability-client`,
  0.4.1 for us and the messaging stack. It compiles because neither
  `vta-sdk` nor `vti-common` exposes a trust-task type across its API to
  us, so the copies never meet in one type-checking context. Collapse it
  when the VTI side republishes on 0.4; dropping back to 0.2 would instead
  split the messaging stack, which is already on ^0.4.

  **0.4.1 is deliberate, not stale.** `trust-tasks-rs` 0.5.0 published
  the same day, adding an optional `ceremony` envelope member (SPEC §4.11)
  — wire-compatible, breaking only struct-literal construction. Nothing
  in the Affinidi ecosystem has picked it up: the whole messaging stack
  still pins ^0.4.0, so taking 0.5 would mean a *third* copy in the lock
  and putting us on a different major from `affinidi-messaging-didcomm-service`,
  the crate we register handlers with. Revisit when the messaging stack moves.

- **The Affinidi messaging stack moved with it** —
  `affinidi-messaging-sdk` 0.18.65 → 0.19.3,
  `affinidi-messaging-didcomm-service` 0.3.21 → 0.3.24,
  `affinidi-messaging-mediator` 0.18.4 → 0.18.11 (via
  `affinidi-messaging-test-mediator` 0.2.45 → 0.2.49),
  `affinidi-tdk` 0.8.4 → 0.8.5, `affinidi-tsp` and `affinidi-messaging-didcomm`
  to their latest patches. Those three messaging crates are what pin
  `trust-tasks-rs` ^0.4 on the ecosystem side, so this half is not
  separable from the one above.

- **`vti-common` 0.11.33 → 0.11.35 and `vta-sdk` 0.21.4 → 0.21.9**, moved
  together as the lockstep note in the workspace manifest requires — the
  workspace `vta-sdk` requirement plus all four `vti-common` declarations
  (`did-hosting-{common,control,server}`, `webvh-witness`). Verified with
  `cargo tree -d -e normal,build,dev`: no duplicate `vta-sdk`,
  `vti-common` or `affinidi-tdk`; `trust-tasks-rs` is the one expected
  duplicate, for the reason above.

- **`ed25519-dalek` 2 → 3 and `sha2` 0.10 → 0.11**, taken to *join* the
  copy the Affinidi stack already uses rather than because they are latest.
  All of `affinidi-crypto`, `-data-integrity`, `-messaging-didcomm`,
  `-tsp`, `vta-sdk` and `vti-common` were already on dalek 3, leaving our
  five crates as the only first-party holdouts on 2.x; `didwebvh-rs`,
  `vta-sdk` and `vti-common` are likewise on sha2 0.11. Both boundaries
  are byte-level on our side (JWT keys go to `jsonwebtoken` as DER/raw
  bytes via `JwtKeys::from_ed25519_bytes`; sha2 is used once, for the
  task-consent wire digest), so no signing or verification code changed.
  The only `ed25519-dalek` 2 left in the lock is `jsonwebtoken`'s own,
  which never crosses our API.

- **Deliberately *not* taken: `jsonwebtoken` 11 and `base64` 0.23.**
  Both are the latest published, and both would have added a duplicate
  rather than replaced one. `trust-tasks-https`'s `jwt` feature and
  `vti-common` pin `jsonwebtoken` ^10, so 11 keeps 10 in the graph *and*
  splits us from the JWT surface we hand tokens to — and 11 still depends
  on `ed25519-dalek` ^2, so it buys nothing on that front either. Every
  Affinidi crate is on `base64` 0.22, so 0.23 would be a third copy (the
  AWS SDK already drags in 0.21) for a crate that is pure encoding and
  crosses no API. The reasoning is recorded next to each requirement in
  the workspace manifest so the next refresh doesn't relitigate it.

- **Admin UI: in-range dependency refresh** — `expo` 57.0.9 → 57.0.11,
  `expo-router` 57.0.9 → 57.0.11, `expo-constants` 57.0.8 → 57.0.9,
  `expo-linking` 57.0.4 → 57.0.5, `react-native-safe-area-context` 5.8.0
  → 5.8.1. Lockfile only; no `package.json` range changed.
  `npm run typecheck` and `npm test` pass.

  `npm audit` reports 14 high-severity advisories, all in the Metro /
  Expo *build* toolchain (`image-size`, `nanoid`, `metro*`,
  `@react-native/*`) and none in shipped runtime code. They are not a
  regression from this change — they were published after the SDK 57
  bump — and `npm audit fix --force` "resolves" them by downgrading
  `expo` 57 → 53 and `react-native` 0.86 → 0.72, which is a far larger
  regression than the advisories. Left for the upstream Expo release
  that carries the fixed Metro. `react-native-screens` 4.27.0 is
  available but out of the declared `~4.26` range; not taken here.

- **`vta-sdk` 0.20 → 0.21 and `vti-common` 0.11.30 → 0.11.33, moved
  together.** `vti-common` 0.11.33 re-pins onto `vta-sdk` ^0.21, so
  refreshing the lockfile alone would have resolved *two* `vta-sdk`
  copies — the exact failure the lockstep note in the workspace
  manifest warns about. Bumped as one change across the workspace
  `vta-sdk` requirement and all four `vti-common` declarations
  (`did-hosting-{common,control,server}`, `webvh-witness`); verified
  with `cargo tree -d -e normal,build,dev`, which reports no duplicate
  `vta-sdk`, `vti-common`, `affinidi-tdk` or `trust-tasks-*`. The dev
  graph moved with it: `affinidi-messaging-mediator` 0.17.13 → 0.18.4
  (via `affinidi-messaging-test-mediator` 0.2.45), which is the
  mediator floor that keeps the dev half on `vta-sdk` ^0.21.

- **`firestore` 0.49 → 0.50** — required, not cosmetic. `firestore`
  0.49 no longer compiles against the current `gcloud-sdk` (a new
  `concurrency_mode` field on `transaction_options::ReadWrite`), so
  the `store-firestore` backend was broken by the lockfile refresh
  until the major bump. **`azure_data_cosmos` 0.36 → 0.37** alongside
  it (`store-cosmosdb`).

- Lockfile refreshed to the latest compatible releases across the rest
  of the graph — `affinidi-*`, `trust-tasks-*`, `aws-*`,
  `google-cloud-*`, `tokio`, `kube`, `redis`, `toml`, `uuid`,
  `thiserror`. The `vta-sdk` 0.21 move dropped the whole `ssi-*` /
  `json-ld` subtree and the old `proc-macro-error` generation, so
  three now-unmatched advisory ignores (RUSTSEC-2024-0370,
  RUSTSEC-2026-0173, RUSTSEC-2026-0215) and three dead licence
  exceptions (`bitmaps`, `im`, `sized-chunks`) came out of
  `deny.toml`. No first-party code changed; the full suite,
  `cargo clippy --workspace --all-targets` and `cargo deny check` are
  clean, and each storage backend still builds on its own.

- **Admin UI: Expo SDK 56 → 57** (`expo` 57.0.9, `expo-router` 57.0.9,
  `react-native` 0.85.3 → 0.86.2, `react`/`react-dom` 19.2.8,
  `react-native-screens` 4.26, `react-native-safe-area-context` 5.8),
  plus **TypeScript 6 → 7** and `recharts` 3.10. SDK 57 requires
  `expo-status-bar` to be listed as a config plugin, which is the one
  `app.json` change. `npm run typecheck`, `npm test` and
  `npm run build:web` all pass, and `npm audit` reports no
  vulnerabilities — no application code needed changing.

## 0.8.6 (2026-07-29)

### Changed

- **`vta-sdk` 0.19 → 0.20 and `vti-common` 0.11.5 → 0.11.30, moved
  together.** The two crates share the canonical SIOPv2 / RFC-6749 auth wire
  types (`vta_sdk::protocols::auth::{Session, TokenBundle,
  AuthenticateResponse, ChallengeResponse, epoch_to_rfc3339}`), so a
  mismatched pair resolves to two `vta-sdk` copies and fails to compile with
  `E0308` on `AuthenticateResponse`. `vti-common` 0.11.30 re-pins onto
  `vta-sdk ^0.20`; both keep `affinidi-tdk ^0.8`. All five declarations —
  the workspace `vta-sdk` pin plus the four `vti-common` entries in
  `did-hosting-{common,control,server}` and `webvh-witness` — moved in one
  step, and `cargo tree -d -e normal,build,dev` lists none of `vta-sdk`,
  `vti-common` or `affinidi-tdk`.

  The lock's `affinidi-messaging-mediator` moved 0.17.9 → 0.17.13 as part of
  this, via the `affinidi-messaging-test-mediator` dev-dependency. Below
  0.17.13 the mediator pins `vta-sdk ^0.19` and so reintroduced a second
  `vta-sdk` copy in the *dev* graph — invisible to a passing build, because
  the two copies never meet in one type-checking context. It is also
  independently required: a mediator below 0.17.13 answers
  `messaging/account/update` with `501 unsupported Trust Task type` and
  cannot serve a VTA on messaging SDK 0.18.65, which this workspace moved to
  in 0.8.5. The integration tests were otherwise running against a mediator
  that no longer represents production.

  **No source changes were needed to compile.** The auth surface this
  service actually consumes did not move: `vti_common::auth::handlers`,
  `auth::backend`, `auth::jwt`, `auth::siop`, `auth::step_up` and
  `vti_common::error` are byte-identical between 0.11.5 and 0.11.30, and
  in `vta_sdk::protocols::auth` only the unused `RevokeSessionResponse`
  changed. `sealed_transfer`, `keys`, `did_secrets`, `credentials`,
  `auth_light` and `didcomm_light` are unchanged, so the sealed-transfer
  bundle bytes and the DID-signed assertion domain tag are wire-identical
  to 0.19 — an offline bundle produced by either version verifies on the
  other.

  Behavioural deltas this service inherits, none of them source-visible:

  - **`VtaClient`'s webvh operations now dispatch Trust Tasks over the
    DIDComm leg** (`rpc_tt` in place of `rpc`, e.g.
    `spec/vta/webvh/servers/list/1.0` instead of the
    `did_management::LIST_WEBVH_SERVERS` protocol message). The REST leg is
    unchanged. This reaches the daemon's setup wizard, which calls
    `list_webvh_servers` / `list_webvh_server_domains` after
    `connect_didcomm`, so the hosting-server picker over DIDComm now
    requires a VTA new enough to route those task URIs. Failure is
    non-fatal — the wizard degrades to serverless with a printed note.
  - **Transport discovery is TSP-aware.** `ResolvedVta` gained
    `tsp_mediator_did`, `VtaEndpoint` gained a `Tsp` variant (and
    `#[non_exhaustive]`), and 0.20 no longer synthesises a REST URL from the
    VTA DID's own domain when it finds no `#vta-rest`. A TSP-only VTA that
    used to arrive looking like a REST one (and fail at the network call)
    is now reported honestly; `connect_setup_client` says so explicitly
    rather than falling through the "neither REST nor DIDComm" arm. A TSP
    leg for the catalogue reads is deliberately not added here.
  - Two extraction rules inside `resolve_vta_endpoint` changed with the
    move to the shared `ServiceCapabilities`: REST discovery now matches on
    the service `type` (`VTARest` / `TRQPRest`) rather than the
    `#vta-rest` id fragment, and the DIDComm mediator is taken from the
    first `DIDCommMessaging` service's first endpoint rather than the first
    `did:`-prefixed URI found across all of them. Both are no-ops for a
    VTA-minted DID document; a hand-written one could resolve differently.
  - `TransportChoice::Auto` now prefers TSP > DIDComm > REST, and
    `challenge_response` no longer leaks an ATM task per login.

- Corrected the stale note on
  `did_hosting_control::routes::auth::canonical_to_local_auth_response`. It
  claimed the helper existed because two `vta-sdk` copies made one type look
  like two, and predicted it would disappear once `vta-sdk` consolidated
  onto a single published version. That consolidation is this release, and
  the helper is still required: `did_hosting_common::AuthenticateResponse`
  is a genuinely separate local type in `types.rs`, kept so the client
  crates have a wire type that does not drag the SDK in.

## 0.8.4 (2026-07-29)

### Changed

- **Clean cutover from the retired `confirm/*` pair to the `task-consent`
  family.** The registry retired `confirm/{request,response}/0.1`
  (supersededBy `task-consent/{request,decision}`, trust-tasks-tf #156):
  a confirm *is* a task-consent with empty `effects`, `minApprovals: 1`,
  and the requester's display text carried in the new explicitly-untrusted
  `note` field. The control plane's live RP→wallet confirmation flow moved
  onto the new family wholesale — the confirm URIs are gone, not aliased.
  - `POST /api/confirm/request` → **`POST /api/task-consent/request`**,
    identified by `spec/task-consent/request/0.1`. Same admin-only auth,
    same request body (`holder_did`, `action`), same `{ "approved": bool }`
    result, same 60-second park-and-wait. The request it now sends is a
    full Trust Task document rather than a bare body: `effects: []` (this
    service has no dry-run for a prose-described admin action, and the
    spec requires an executor without one to leave effects empty),
    `consequences` carrying that fact in the words the wallet renders when
    effects are empty, `minApprovals: 1`, `excludeRequester: false`,
    `expiresAt` matching the park window, and the caller's `action` text
    verbatim in `note`.
  - The inbound `confirm-response/1.0` DIDComm handler is replaced by a
    `spec/task-consent/decision/0.1` handler. **The decision's Data
    Integrity proof is now mandatory and verified** — under the old pair
    the authcrypt envelope alone was the authentication, and the wallet's
    answer carried no signature at all. Per the task-consent spec the
    proof, not the transport session, is the authorization: the handler
    requires it, checks the proof's `verificationMethod` DID, the in-band
    `issuer`, and the authcrypt sender all name the addressed holder,
    binds `recipient` to this control plane, and then verifies the
    signature through the existing `TransportBoundVerifier`. It answers
    with the spec's `#response`
    (`{status: granted|denied, payloadDigest, approvals}`).
  - The decision is bound to the request by **`payloadDigest`**, which the
    old `confirm/response` had no equivalent of: a domain-separated
    SHA-256 over the RFC 8785 (JCS) canonical pending-task payload, the
    task type, and the 128-bit `challenge` as salt. The wallet echoes it
    verbatim and a mismatch is rejected, so an approval can no longer be
    replayed against a different action under the same challenge. The
    gated "task" is identified by the service-local
    `did-hosting/admin-action/1.0` URI (never routed — it exists only to
    be bound into the digest, so a decision minted for an admin-action
    prompt cannot authorize a registered task whose payload canonicalizes
    identically).
  - A failed holder/digest check no longer consumes the pending entry: the
    lookup, the checks and the removal now happen under one lock, so a
    malformed or mis-addressed decision leaves a legitimate in-flight
    consent intact.
  - `action` is validated against the schema's 500-character `note` limit
    and rejected rather than silently truncated.

  **Removed wire identifiers** (no dual-accept — pre-production policy):
  `https://trusttasks.org/spec/confirm/request/0.1`,
  `https://trusttasks.org/wallet/confirm/1.0`,
  `https://trusttasks.org/wallet/confirm-response/1.0`, and the REST route
  `POST /api/confirm/request`. Wallets must move to the task-consent
  family; a stale `{"approved": bool}` answer is now unparseable and
  resolves nothing.

  **Known deviation:** the *request* leg carries no Data Integrity proof,
  though `task-consent/request/0.1` marks one REQUIRED. It rides on
  authcrypt attribution from the control DID instead, mirroring this
  service's existing step-up `approve-request` precedent — the transport
  authenticates the same party the proof would. Signing the request needs
  the control plane's issuer key wired into the route; tracked separately.


## 0.8.3 (2026-07-29)

### Changed

- **Clean cutover to the consolidated `did-management` state-enum tasks
  (#143).** The registry collapsed the state-toggle verb sets into
  declarative state-enum tasks, and this service now speaks only the
  canonical URIs:
  - `did-management/agent-name/update/0.1` (`state: active | parked`)
    replaces `agent-name/{set,enable,disable}/0.1` on the DIDComm dispatch
    table, the Trust-Task envelope, and REST (`POST /api/agent-names/update`
    replaces `/set`, `/enable`, `/disable`). `agent-name/remove` stays its
    own destructive task, now on its canonical
    `did-management/agent-name/remove/0.1` URI. The update/remove payloads
    accept the pre-cutover `didLog` spelling as an alias for the spec's
    `didData`. Parking or re-activating a name that is already in the
    requested state is now an idempotent refresh, not a conflict
    (declarative-state semantics per the spec).
  - `did-management/did/publish/0.1` is retired (spec supersededBy:
    `did/register`): the DIDComm publish route, the typed-envelope publish
    op, and the `did-hosting/did/publish/1.0` REST header are gone.
    `PUT /api/dids/{*mnemonic}` (unchanged handler) is now identified by
    `did-management/did/register/0.1` — a register from the slot's owner is
    an update, which is exactly the operation publish carried.
  - The REST `Trust-Task` surface dropped the legacy `did-hosting/*/1.0`
    identifiers for every operation that has a registry spec, replacing
    them with the canonical `spec/did-management/*` (and
    `spec/webvh/witness/publish/0.1`) URIs; `did/{enable,disable}` and
    `domain/{enable,disable}` endpoints are identified by the new
    `did/set-state/0.1` / `domain/set-state/0.1` tasks.
  - `agent-name/{check,list}/0.1` now have registry specs; `list` responses
    project `createdAt` as RFC3339 per the spec (the store keeps epoch
    seconds).
  - Removed identifiers are listed in the PR body so downstream clients
    (VTA, CLI) can be swept; ops with no registry spec (stats, timeseries,
    config, acl `1.0`, registry list/get/health, did log/raw-log,
    agent-name/resolve, domain/list, step-up-check) keep their
    `did-hosting/*/1.0` identifiers unchanged.


## 0.8.2 (2026-07-15)

### Added

- **Agent names work over DIDComm/TSP, not just REST.** The six agent-name
  verbs shipped REST-only, so a VTA on the DIDComm transport could provision a
  DID and then had to fall back to HTTPS for the one step that gives it a
  human-memorable handle — the exact seam a DIDComm-native agent exists to
  avoid. `agent-name/{set,remove,enable,disable,list,check}/0.1` are now on the
  control plane's DIDComm dispatch table, so they are reachable over the
  mediator-routed transport, the HTTP-signed `POST /api/didcomm` route, and the
  Trust-Task envelope alike. Every arm calls the same `did_ops` function its
  REST twin does and reuses the REST request types and `{record}` projection
  verbatim, so the two transports cannot answer differently; the owner/admin
  checks, the domain-scoping chain (explicit → caller's ACL default → system
  default) and the server fan-out after a mutation are unchanged. `list` is
  net-new to both surfaces: it returns the registry — parked entries included —
  which is the only place a parked name is visible, since parking removes it
  from the document's `alsoKnownAs` by design.

- **Agent names are visible where you actually look for them.** Binding and
  parking already lived in the Agent Names card on the DID detail page, but
  that card sits below the document viewer — too far to reach for the everyday
  act of copying a handle to give someone, and the DIDs list showed no names at
  all. Served names now render as copyable `domain/@name` chips directly
  beneath the DID on both the list and the detail header. Under the DID, not
  above it: a name is an alias, and promoting it over the identifier leaves a
  reader unsure which line is authoritative — doubly so in the list, whose card
  heading is already a friendly label. `GET /api/dids` gained `agentNames`,
  carrying the same registry entries `GET /api/dids/{mnemonic}` serves so the
  list needs no per-DID fetch; parked entries ride along and the views filter
  them out, since a parked name would advertise a redirect that 404s.

- **Batched DID sync to cut the resync mediator-throttle flood.** A control
  plane pushed one `MSG_SYNC_UPDATE` per DID, and each inbound frame draws one
  transport-level TSP reply — so a bulk resync (a server (re)registering with
  many DIDs behind) burst those replies straight past the mediator's rate limit,
  logging `429 Too Many Requests` and dropping frames. Capable servers now
  advertise `sync_batch` at registration; the control plane coalesces the
  initial sync into `MSG_SYNC_BATCH` messages (`body.updates[]`), capped at 50
  DIDs or 512 KB each, collapsing many frames — and their replies — into few.
  The server applies each entry best-effort (a malformed one is skipped, not
  fatal, and re-sent on the next delta) and returns one ack per batch. Servers
  that don't advertise the capability still get one message per DID, so an older
  control plane and an older server interoperate unchanged.

### Added

- **The admin UI has CI.** `did-hosting-ui` is TypeScript that never reached a
  compiler or a test runner on any push — `ci.yml` had no Node job at all, and
  the package had no test script — so a type error or a broken client-side
  policy could only be caught by someone running Expo locally. That matters
  more than it sounds: the UI holds the trust-task client (envelope shapes,
  proof signing, the §8.4 retry policy), which is wire behaviour the Rust suite
  cannot see. A `ui` job now runs `npm ci` (lockfile-pinned, matching the Rust
  jobs' `--locked`), `npm run typecheck`, and `npm test`. Vitest is the runner;
  it needs no Expo/React-Native scaffolding for `lib/`, which has no
  module-scope browser dependencies. First suite covers the retry policy: the
  §8.4 decision table exhaustively, plus `api.listAcl` end-to-end through
  `trustTask` with `fetch` stubbed, so the re-issue path, the attempt bound and
  the give-up path are all exercised against real client code.

### Fixed

- **The Web UI honors the server's `retryable` hint instead of discarding it.**
  `dispatchTrustTask` parsed the `trust-task-error/0.1` payload and threw away
  `retryable` and `retryAfter`, so an error the server had explicitly marked
  transient reached the user as a hard failure with a manual retry as the only
  recourse. The UI now applies the SPEC §8.4 rule (mirroring
  `trust_tasks_rs::ErrorPayload::should_retry_at`): one extra attempt, after
  waiting out a `retryAfter` up to 5s. Because a signed envelope cannot be
  resent bit-for-bit — the rejected `created` would simply be rejected again —
  a retry re-issues under a fresh `id`, which the spec permits and which is the
  only form that can succeed. That makes each retry a *new* task, so the policy
  turns on whether applying a task twice is a no-op: `unavailable` (the spec's
  unambiguous "did not run") is retried on anything, while the ambiguous
  `internalError` is retried only on `acl/list` and `acl/show` (reads) and
  `acl/grant` (idempotent by spec §3 — "re-emitting an identical grant produces
  no state change"). `acl/revoke` and `acl/change-role` are excluded: neither
  corrupts state on a re-issue, but both would report failure for an operation
  that had actually succeeded (`subject_not_present`, `state_mismatch`).

- **Signed UI requests no longer fail on browser-vs-server clock skew.** The Web
  UI stamps a proof's `created` from the *browser's* clock
  (`session-key.ts::signEnvelope`), and the verifier compared it strictly
  against the *server's*, rejecting anything in its future. A browser even
  milliseconds ahead therefore made every signed action — adding an ACL entry,
  say — a race between clock skew and network latency: the request passed when
  it arrived slowly enough for the server's clock to catch up, and failed with
  `proofInvalid` / "Created date is in the future" when it didn't. Same click,
  different outcome, and the rejection carried `retryable: false`, so the UI
  presented it as a dead end. `created` is now stamped 5 seconds in the past.
  Nothing enforces a *maximum* age on `created`, so the backdate costs nothing
  and also protects against verifiers we don't ship. The matching server-side
  fix — a 60s clock-skew allowance, matching our bearer-JWT leeway — arrives
  with `affinidi-data-integrity` 0.7.8 (below), and is what covers signers we
  *don't* ship the UI for: the VTA's `webvh_client` races the control plane's
  clock exactly the same way and gets no benefit from the browser-side
  backdate.

- **Enforce the `?domain=` cross-tenant safety check on publish/delete.** The
  VTA sends `?domain=` on `PUT`/`DELETE /api/dids/{mnemonic}` (and documents a
  `did-management:unknown_domain` rejection), but the control-plane handlers had
  no `Query` extractor, so axum silently dropped it — the advertised
  cross-tenant protection did not exist on the wire. `upload_did`/`delete_did`
  now read the parameter and `did_ops` cross-checks it against the DID's host
  (a DID's host *is* its domain) / the slot's persisted domain, rejecting a
  mismatch with `did-management:unknown_domain` before the log lands. Covers the
  DIDComm trust-task path too (it resolves the domain separately and passes
  none). The standalone `did-hosting-server` direct-publish handler is unchanged
  (the daemon and standalone-control deployments route management through the
  control plane).

- **A metadata-only identity change no longer triggers a key rotation.** The
  service treated any change to a generation's `protocols` or `mediator_did` —
  e.g. enabling TSP (`features.tsp = true`) — as a rotation, because
  `differs_from` compares those fields. With no key change, this took the
  retirement path: it retired the current generation (starting a grace window)
  and installed a "new" generation sharing the **same** `ka_kid`. When that
  retired generation's grace expired, `expire_generation` deleted the key
  material for a kid the current generation was still using — leaving the
  service with `sender has no usable key agreement key` and a permanent mediator
  reconnect loop, ~one grace period after the change.

  A rotation (retire + grace + eventual key deletion) now happens **only when
  the key-agreement key actually changes**. A `protocols`/`mediator_did` change
  updates the current generation in place — same id, same keys, no retirement,
  no grace window — and rebuilds the listener so a transport change takes
  effect. New `ReloadOutcome::MetadataUpdated` and
  `update_current_generation_in_place`; tests cover that the retired generation
  and every key survive an in-place update.

- **Two safety nets around identity key material** (defence-in-depth for the
  above). (1) Boot now validates that the secret store holds the private half of
  the current generation's advertised key-agreement kid — the guard
  `reload_service_identity` applies to a rotation, which boot lacked — and logs
  loudly on a mismatch instead of running on a retired key and collapsing a
  grace period later. (2) The expiry sweep never expires a generation whose
  `ka_kid` is still used by a surviving generation, so a grace expiry can never
  strip the key in active use and leave the service with no usable
  key-agreement key.

- **Registration no longer re-syncs every DID on every boot.** A server
  registering over TSP/DIDComm hit `sync_all_dids_to_server`, a full push of
  every DID, regardless of what the server already had — so a reboot re-synced
  the whole set (and re-triggered the server's own-DID identity-rotation check
  each time). The server now reports what it holds in `preloaded_dids`
  (mnemonic → version), and the control plane pushes only the delta; an older
  server that sends none still gets a full push. This is what lets the edge
  sync scale to thousands of DIDs.
- **The server resolves its own DID from the local store, not the network.** At
  cold boot the identity load resolved the server's own DID over its public URL
  — through a load balancer that hadn't marked the instance healthy yet — and
  logged a spurious `502`/`ERROR` before falling back. It now reads the
  authoritative `did.jsonl` from the local store first
  (`resolve_identity_doc_from_log`), falling back to the network only when the
  local copy is missing.
- **Quieter sync logging.** The per-DID `inbound TSP: server sync/domain
  message` receipt and the duplicate `applied DID sync update … via mediator`
  line drop to `debug`; each applied update logs once at `info`.

### Dependencies

- affinidi-data-integrity 0.7.7 → 0.7.8 — verification now allows a 60s
  clock-skew window on a proof's `created` instead of comparing it strictly
  against the verifier's clock (affinidi/affinidi-tdk-rs#666). This is the
  server-side half of the clock-skew fix above; the lockfile move is the whole
  change, since the `"0.7"` requirement already admitted it.

## 0.8.0 (2026-07-15)

The theme of this release is **transport as a first-class, negotiable property
of every node**. DIDComm, TSP, and HTTPS all carry the same Trust-Task
documents, each node's **DID document is the authoritative source of how to
reach it**, and the transport a message actually travelled on is recorded
rather than assumed.

### Added — Transport-agnostic Trust Tasks (TSP + DIDComm + HTTPS)

- TSP transport alongside DIDComm — everything is a Trust Task (#58), with TSP
  decoupled from DIDComm: TSP-only transport, a three-way transport selection,
  and TSP→DIDComm send fallback (#64).
- Outbound control→server sync push over TSP (#62); server registration and
  health routed as transport-agnostic Trust Tasks (#70).
- HTTPS Trust-Task DID-management parity (#60, #31).
- TSP-only VTA DID template selected for TSP-only nodes (#65).
- The observed control-plane link transport is recorded and surfaced, distinct
  from what a document advertises (#71).

### Added — The DID document is authoritative for transport

- Send-transport selection follows an explicit **document → config → fail**
  precedence; the former blind-DIDComm default is gone (#86).
- The standalone server advertises its own messaging transports on its DID
  (#87), and mediator-configured node DIDs **omit the `WebVHHosting` service**
  entirely — advertising only `TSPTransport` / `DIDCommMessaging` (#88).
- DID-document services surface as badges across the controller UI (#67), with
  resolver-implicit `#whois` / `#files` excluded (#68) and the badge cache
  backfilled on standalone control boot (#69).

### Added — Typed did-hosting DID-management protocol

- Typed `did-hosting/1.0` DID-management Trust-Task protocol — eight operations
  (#61) — accepting canonical spec URIs for did-management, webvh, and
  info/list/change-owner/me-domains (#25, #26, #27), converging on canonical
  URIs only with the alias bridge dropped (#28).
- Trust-Tasks 0.2 specs with 0.1 back-compat; in-band recipient required on
  every envelope (#40, #41).

### Added — Service-identity key rotation

- `identity-rotate-keys` rotates the service's own key-agreement key onto a
  fresh fragment with a working grace period and old-mediator drain (#82, #84).

### Added — Runtime DID management, delegated updates, secret backends

- DID changes are picked up at runtime instead of requiring a restart (#78);
  a DID document can be edited through the user's agent (#77), and the
  delegated DID-update path is wired end-to-end (#79).
- HashiCorp Vault and native Kubernetes Secret store backends (#53).
- Discover-first daemon online setup with a webvh publication choice (#33); a
  VTA-provisioned daemon trusts its provisioning VTA to publish (#55); DID-path
  folding unified through one shared provision-ask builder (#34).

### Fixed

- Identity rotation: importing keys no longer destroys a live rotation's grace
  period (#83), and a kid-reusing rotation is no longer misreported as
  "unchanged" (#81).
- A root DID must not carry `.well-known` in its identifier (#80); the root DID
  registers correctly at the `.well-known` slot (#72).
- Proxy-login / SIOP: camelCase `secretKind` on `vault/list` (#85), runtime RP
  DID resolution (#51), session-key proofs without an in-band issuer (#44),
  canonical camelCase log/owner wire fields (#39), and assorted demo fixes
  (#17, #18, #19, #20, #23).
- `host:port` domains resolve consistently end-to-end (#24); did:webvh host
  authority is percent-decoded before domain validation (#56); `check-name`
  probe/reserve/auto-assign contract implemented (#38).
- CI and advisory maintenance (#43, #48, #49, #54, #73).

### Dependencies

- Aligned to `vti-common` 0.11.5 / `vta-sdk` 0.19 (#74) and refreshed the
  lockfile to the latest compatible releases — `affinidi-messaging-*`,
  `google-cloud-*`, `http-body(-util)`, `rustls`, `redis`, `jsonpath-rust`.

### Versions

- Workspace crates `0.7.0` → `0.8.0`; `did-hosting-client` `0.1.0` → `0.1.1`;
  `did-hosting-ui` `1.0.0` → `1.1.0`.

## 0.7.0 (2026-05-24)

### Added — Trust Tasks framework adoption

- **Trust Tasks ACL surface (`POST /api/trust-tasks`).** New wire
  shape for ACL administration built on the
  [Trust Tasks framework](https://trusttasks.org/) at the registry's
  `acl/*/0.1` family. Six operations live behind one endpoint
  (envelope `type` member discriminates):
  - `acl/grant/0.1` — idempotent insert; role-change attempts rejected
    with `permission_denied` + `details.reason = "role_change_required"`.
  - `acl/revoke/0.1` — full removal **or** scope reduction (`scopes`
    items in `domain:<name>` shape); `last-authority` guard refuses
    revocations that would leave zero Admin entries.
  - `acl/change-role/0.1` — state-checked (`fromRole`/`toRole`);
    rejects concurrent overwrites with `acl/change-role:state_mismatch`.
  - `acl/show/0.1` — single-entry lookup; self-lookup permitted for
    non-Admin callers.
  - `acl/list/0.1` — conjunctive filters (`role`, `scope`,
    `subjectPrefix`) + opaque base64 cursor paging; pageSize ceiling 500.
  - `trust-task-discovery/0.1` — advertises all six types, declares
    `frameworkVersion: "0.1"`, and pins
    `requiredExt: ["vnd.affinidi.webvh"]` on `acl/grant` + `acl/change-role`.
- **DIDComm trust-tasks envelope route.** The control plane's DIDComm
  router accepts inbound messages of type
  `https://trusttasks.org/binding/didcomm/0.1/envelope`. Both
  transports share one async dispatch core (handlers don't care which
  transport delivered the document).
- **`trust-tasks-proof` verifier wired through `AppState`.** When
  `state.trust_tasks_verifier` is configured (a `DIDCacheClient` is
  available) AND the new `trust_tasks.enforce_proofs` config flag is
  `true`, the maintainer verifies a present Data Integrity proof and
  rejects an absent proof on a non-bearer spec with `proof_required`.
- **Vendor extension shape (`ext.vnd.affinidi.webvh`).** webvh-
  specific fields (quota + domain scope) live in the spec's `ext`
  slot under a reverse-DNS namespace. See
  [`docs/trust-tasks-acl-migration.md`](docs/trust-tasks-acl-migration.md)
  for the wire shape.
- **Daemon parity.** `did-hosting-daemon` automatically picks up the
  new HTTPS route AND the new DIDComm envelope handler — the daemon
  builds its routers via the control plane's `routes::router_without_fallback()`
  and `messaging::build_control_router()`, so there is no separate
  wiring to maintain (CLAUDE.md §What the daemon mirrors).
- **`AppState` gains `trust_tasks_verifier: Option<Arc<trust_tasks_proof::affinidi::Verifier>>`.**
  Constructed at startup when `did_resolver` is configured (the
  verifier shares the same DID-resolver cache as the DIDComm path).
- **`AppConfig` gains `trust_tasks: TrustTasksConfig`.** New section
  with a single `enforce_proofs: bool` knob (initial default `false`;
  flipped to `true` later in this release — see *Upstream alignment*
  below).
- **UI ACL surface (`did-hosting-ui`) routes through `/api/trust-tasks`.**
  The four `api.{list,create,update,delete}Acl` methods plus a new
  `api.aclShow` now POST trust-task envelopes. Wire-shape translation
  between the spec's `AclEntry` and the existing TypeScript `AclEntry`
  type is invisible to screen code.
- New [`docs/trust-tasks-acl-migration.md`](docs/trust-tasks-acl-migration.md)
  — client migration guide (old vs. new wire shape, proof policy,
  worked examples for both HTTPS and DIDComm, error-code mapping).
- New [`docs/trust-tasks-registry-gaps.md`](docs/trust-tasks-registry-gaps.md)
  — catalogue of webvh ops not yet in the public Trust Tasks
  registry, grouped by reusability tier with proposed slugs + payload
  sketches per type. ~50 ops across 8 groups, ready to file upstream.

### Deprecated — legacy ACL REST surface

- **`GET/POST /api/acl`, `PUT/DELETE /api/acl/{did}`** — every legacy
  ACL route now emits:
  - `Deprecation: true`
  - `Sunset: Mon, 01 Dec 2026 00:00:00 GMT`
  - `Link: </api/trust-tasks>; rel="successor-version"`
  - Structured `warn`-level log line per call identifying caller +
    successor URL (grep for `legacy_route=`).
  Removal target: **v0.8.0**. See
  [`docs/trust-tasks-acl-migration.md`](docs/trust-tasks-acl-migration.md)
  for migration guidance.

### Hardening (review-driven)

A multi-axis review of the trust-tasks adoption (security,
correctness, tests, documentation) surfaced a set of issues; the
fixes landed before the v0.7.0 cut. The wire shape and the
operator-facing config didn't change — these are correctness +
safety fixes.

- **ACL writes serialise through a single global lock.** Without
  this, two concurrent `acl/revoke` requests targeting the two
  remaining Admins could each pass the last-authority guard (each
  saw the *other* still present) and both commit, emptying the
  Admin set. The new `acl_locks: PathLocks` on `AppState` is a
  separate registry from the existing `path_locks` (which serialises
  DID-mnemonic writes); the three ACL-write handlers (`grant`,
  `change-role`, `revoke`) acquire one fixed key
  (`ACL_WRITE_LOCK_KEY`) so the read-then-write critical section is
  race-free across concurrent admins targeting different subjects.
  `PathLocks` itself is hoisted from `did-hosting-control` into
  `did-hosting-common::server::path_locks` so the dispatcher (in
  the common crate) can construct one.
- **`acl/grant` same-role regrant now persists metadata updates.**
  The UI's `updateAcl` relies on "same-role grant = idempotent
  metadata update" semantics; the previous implementation returned
  the existing entry verbatim, silently dropping label/quota/domain
  changes. The handler now merges the producer's non-role fields
  onto the existing entry, preserves `created_at`, and persists
  only when at least one field actually changed.
- **`acl/change-role` last-authority code re-namespaced.** The
  handler previously raised `acl/revoke:last_authority_protected`
  on the change-role path — cross-slug. Now raises
  `acl/change-role:last_authority_protected` (extended code per
  SPEC.md §8.5) so the slug matches the request's `type` URI.
- **`POST /api/trust-tasks` body is parsed by hand.** Replaces the
  `axum::Json` extractor whose text/plain 400 violated the spec's
  "malformed_request → `trust-task-error/0.1` document" contract.
  Body-shape failures now emit the routed error document with the
  spec-correct code.
- **64 KB body limit** on `/api/trust-tasks` caps an
  authenticated-Owner DoS class. Constant
  `routes::TRUST_TASKS_BODY_LIMIT_BYTES`.
- **`proof` carried with `enforce_proofs = false` is rejected, not
  silently dropped.** A producer who signed the envelope believed
  their signing key was authenticating; only the bearer JWT was. The
  new `(Some(proof), None)` arm of `run_pipeline` returns
  `malformed_request` with an operator-actionable message.
- **`NoVerifier` is now an uninhabited `enum NoVerifier {}`.** The
  previous unit-struct + panic-on-call carried the "bad call" risk
  as a runtime trap; the enum makes `Some(&NoVerifier)`
  uninstantiable.
- **`acl/list` cursor encodes `last_seen` DID** instead of a
  positional offset. Offset-based pagination skipped/repeated
  entries across concurrent deletes; `last_seen` is stable. The
  cursor stays opaque to consumers per spec.
- **`acl/list` `domain:` filter matches `All`-scoped entries.**
  `All` semantically operates on any domain; a "show me everyone
  who can publish to alpha.example" query now correctly includes
  `All`-scoped Admins.
- **`Suppressed` outcome promoted to `error!` log** (was `warn!`).
  The DIDComm gate `require_sender_did(true)` makes this branch
  unreachable in practice; the `should_not_happen=true` field
  surfaces an invariant violation to error dashboards if it ever
  fires.
- **Documentation fixes**: migration doc's worked example now
  distinguishes the caller (admin) from the grant's subject
  (alice); pre-publication crates.io links repointed at the
  upstream GitHub source; orphan doc block on `dispatch_inbound`
  attached.

### Upstream alignment — trust-tasks 0.1.1

The framework consumed our v0.7.0 review feedback in
[PR #33](https://github.com/trustoverip/dtgwg-trust-tasks-tf/pull/33);
v0.7.0 adopts the resulting 0.1.1 surface. Behavioural-equivalent
where the old code was correct, and a strict simplification of the
dispatch core:

- **`run_pipeline` is now a thin shim over
  `trust_tasks_rs::consume_inbound`.** ~110 lines of hand-rolled
  §7.2 pipeline replaced by ~20 lines of adapter. The framework
  owns expiry, recipient enforcement, party resolution, proof
  policy, and audience binding; our shim adapts `ConsumeOutcome` →
  `DispatchOutcome` and re-encodes the typed response as
  `TrustTask<Value>`.
- **`ProofPolicy` replaces `Option<&V>`.** Three explicit variants
  (`Verify(&v)`, `RejectIfPresent`, `AcceptUnverified`) make the
  consumer's posture audit-able at the call site. The control
  plane's `enforce_proofs` toggle maps to `Verify(&verifier)` /
  `RejectIfPresent`.
- **`Payload::IS_PROOF_REQUIRED` enforced authoritatively.**
  Codegen reads each spec's `proofRequirement.requirement` from
  front matter; `consume_inbound` checks the const independently of
  the consumer's `ProofPolicy`. `acl/grant`, `acl/revoke`,
  `acl/change-role` (all REQUIRED) refuse proofless documents
  regardless of policy; `acl/list`, `acl/show`, and
  `trust-task-discovery` (RECOMMENDED / OPTIONAL) accept them.
- **`Payload::extended_code(local)` helper** replaces every hand-
  rolled `TrustTaskCode::Extended { slug, local }` literal across
  `change_role.rs` and `revoke.rs`. Slug is sourced from
  `TYPE_URI` and can't drift.
- **`NoVerifier` uninhabited enum + `verification_error_to_reason`
  helper removed.** Framework handles both. Pipeline is generic in
  `V: ProofVerifier + ?Sized` and the `RejectIfPresent` /
  `AcceptUnverified` variants don't carry a verifier reference.
- **Sanitised wire-rejection diagnostic.** The
  `RejectIfPresent` path now emits the framework-shared
  `PROOF_NOT_ACCEPTED_BY_POLICY` constant ("in-band proof not
  accepted by consumer policy (SPEC §7.2 item 7)") rather than the
  previous verbose form. The verbose operator-actionable form
  ("flip `enforce_proofs = true`") lives in a `tracing::warn!` in
  `dispatch_inbound`. Sanitising the wire prevents an unauth
  probe from enumerating verifier coverage across a fleet.
- **`enforce_proofs` default flipped from `false` to `true`.** With
  the framework enforcing IS_PROOF_REQUIRED authoritatively,
  REQUIRED specs (grant/revoke/change-role) are unreachable
  without a verified proof. The new default produces the
  framework-correct shape for both backend-only callers (CLI,
  service-to-service) and the Web UI (browser-side signing —
  see next entry).

- **Browser-side Data Integrity signing for the Web UI.** Closes
  the "Web UI can't sign in-band" gap that was the original
  reason `enforce_proofs` defaulted to `false`. Ephemeral
  Ed25519 keypair generated via WebCrypto on each `passkey/login/
  finish`; public multikey (base58btc, `z6Mk…`) sent to the
  server and stored on the session record. Every REQUIRED-spec
  envelope carries an `eddsa-jcs-2022` proof whose
  `verificationMethod` is the matching `did:key` —
  `did-hosting-ui/lib/session-key.ts` implements the cryptosuite
  inline (~280 LOC, no npm deps for JCS or base58btc; uses
  WebCrypto `crypto.subtle.sign`). Private key stays as a
  non-extractable `CryptoKey` and never leaves the tab.

  Server side wires the binding in three places:
   * `Session.session_pubkey_b58btc` field carries the bound
     pubkey across requests (stored in the existing sessions
     keyspace).
   * `AuthClaims.session_pubkey_b58btc` surfaces it to
     `dispatch_trust_task`.
   * Pre-check in `dispatch_trust_task` (SECURITY): when the JWT
     carries a session pubkey, the proof's `verificationMethod`
     MUST be the matching `did:key:{pk}#{pk}`. Mismatch →
     `proof_invalid` rejection. Closes the "JWT subject A signs
     with B's session key to forge requests as A" attack — the
     framework's verifier would verify the cryptographic
     signature successfully but wouldn't enforce the JWT-binding
     itself.
   * The framework's `AffinidiVerifier` then does the actual
     signature verification (via the existing
     `CachedDidResolver` which already supports `did:key`).
- **`trust-tasks` family pinned to `0.1.1` on crates.io.** The PR #33
  changes shipped upstream as `trust-tasks-rs` 0.1.1 (published
  2026-05-24); the workspace dep moves to the crates.io pin and the
  transitional `[patch.crates-io]` block has been removed.

### Auth-architecture consolidation with vti-common

did-hosting's `/auth/*` surface now dispatches through the canonical
handlers in `vti_common::auth::handlers`. Closes the structural
follow-ups from the May 2026 cross-system auth security review.

#### Added

- **`did_hosting_common::server::auth::DidHostingSessionStore`** —
  `vti_common::auth::SessionStore` adapter over did-hosting's
  `KeyspaceHandle`. Honours did-hosting's separate storage trait
  (fjall, Redis, DynamoDB backends) while consuming the canonical
  `Session` type from vti-common.
- **`AuthBackend` impls per service**:
  - `did_hosting_control::auth::DidHostingControlAuthBackend`
    (REST SIOPv2; per-DID rate-limiting via the existing O(1)
    `PendingChallengeTracker`, canonical handler's limit disabled
    via `max_pending_challenges_per_did = 0`).
  - `did_hosting_server::auth::DidHostingServerAuthBackend`
    (DIDComm-only; canonical per-DID limit replaces the previous
    O(N) prefix-scan).
  - `webvh_witness::auth::WebvhWitnessAuthBackend`
    (DIDComm-only; canonical per-DID limit replaces the previous
    O(N) prefix-scan).
- **Re-exported `Session` + `SessionState` from vti-common** —
  `did_hosting_common::server::auth::session` now thin-wraps
  `vti_common::auth::session::{Session, SessionState}`. Field
  shape unchanged (the canonical type's `tee_attested` is
  `#[serde(default)]`; did-hosting never sets it). The wire-shape
  `Session` in `did_hosting_common::types` (the OIDC Core §2
  response body) is a distinct type and is unchanged.
- **Trust-Task URI dual-accept** — `did-hosting-server` and
  `webvh-witness` `/auth/` + `/auth/refresh` accept both the
  legacy `affinidi.com/webvh/1.0/...` URIs and the canonical
  `trusttasks.org/spec/auth/{authenticate,refresh}/0.1` URIs.
  Migration-window behaviour; drop the alias one minor release
  after every client upgrades.

#### Changed

- **`From<AuthError> for AppError`** — the canonical handler's
  typed `vti_common::auth::AuthError` variants render through
  did-hosting's existing `IntoResponse` plumbing without
  backend-specific glue.
- **Cross-repo dependency** — `did-hosting-common` (and consumer
  crates) now depend on `vti-common = "0.7"` from crates.io
  (published 2026-05-24 alongside this release).
- **Workspace `vta-sdk` pin** moved to `version = "0.7"` on
  crates.io so the two repos resolve to a single `vta-sdk`
  version (rather than two co-existing copies — the workspace
  pin + the vti-common-internal pin).

#### Removed

- did-hosting-common's local *storage-side* `Session` +
  `SessionState` definitions. Replaced by re-export from
  vti-common. (The wire-shape `Session` in
  `did_hosting_common::types` is unrelated and remains.)
- did-hosting-{control,server,witness}'s in-line `/auth/*` flow
  logic (~250 lines). Each handler is now a thin dispatcher
  around the canonical handler.

#### Note

The full operator-side documentation update — runtime config
keys, `pnm services` topology, the new `trust_xff` flag, the
`step_up_required` body shape — lands in v0.8.0 alongside the
broader did-hosting docs refresh.

### Changed — **BREAKING**

- **Repo and workspace renamed.** `affinidi-webvh-service` →
  `did-hosting-service`. Method-agnostic crates renamed to
  `did-hosting-*`:
  - `affinidi-webvh-common`  → `did-hosting-common`
  - `affinidi-webvh-server`  → `did-hosting-server`
  - `affinidi-webvh-control` → `did-hosting-control`
  - `affinidi-webvh-daemon`  → `did-hosting-daemon`
  Method-specific crates drop the `affinidi-` prefix but keep their
  method name:
  - `affinidi-webvh-witness` → `webvh-witness`
  - `affinidi-webvh-watcher` → `webvh-watcher`
  Binaries follow crate names. Cargo `name`, library names (snake-case),
  binary names, and folder paths all change together. Bumps every
  workspace member's import statement; downstream consumers must
  update their `Cargo.toml` dependency names. See
  `tasks/did-hosting-rollout-plan.md` for the rollout context.
- **Env-var rename: `WEBVH_*` → `DID_HOSTING_*`.** Affects every legacy
  webvh-server env var. The other per-binary prefixes (`DAEMON_*`,
  `CONTROL_*`, `WITNESS_*`, `WATCHER_*`) are unchanged.
- **New CLI subcommand stub: `did-hosting-daemon migrate-from-webvh-config
  --input <FILE> [--output <FILE>] [--force]`.** Operators can script
  against the invocation now; the rewriter implementation lands in a
  follow-up release (see `tasks/did-hosting-rollout-plan.md` WS-7).
- **Multi-domain hosting.** Domains are now first-class objects.
  The daemon stores `DomainEntry { name, label, scheme, status,
  default_domain, branding, witnesses, watchers, quota,
  well_known_enabled }` records in a new `domains` keyspace and
  enforces per-domain isolation on every resolve:
  - **Resolve-side safety** — every `GET /{mnemonic}/did.jsonl`
    (and the did:web / witness siblings) checks the request's
    `Host` against the embedded `did_id`'s host. Mismatch → 404
    (hides off-domain DIDs from cross-domain probes); disabled
    domain → 503 with structured maintenance body
    `{ "status": "disabled", "domain": "<name>", "message": ... }`.
  - **ACL domain scope** — `AclEntry` gains a `domains` field
    (`All` / `Allowed([…])` / `AllowedWithDefault { domains,
    default }`). New `Owner` entries default to
    `AllowedWithDefault`. Existing v0.6 entries deserialise as
    `All` for backwards-compat (run the ACL-lockdown admin tool
    in T42 to migrate).
  - **Request resolution rule** — `POST /api/dids/register`'s
    new `domain` field follows: explicit → ACL default → system
    default → reject. `Allowed([…])` callers without a default
    must declare a domain on every call.
  - **Domain admin surface** — `GET /api/domains` (Admin),
    `GET /api/me/domains` (per-caller scoped), `POST /api/domains`
    (create + optional set-as-default), `PUT /api/domains/{name}`
    (update metadata), `POST /api/domains/{name}/disable`,
    `POST /api/domains/{name}/enable`,
    `POST /api/domains/{name}/set-default`. All Trust-Task-bound
    via `TASK_DOMAIN_*` URLs.
  - **Trusted-proxy CIDR config** — `server.trusted_proxy_cidrs`
    controls which peers can override the `Host` header via
    `Forwarded` / `X-Forwarded-Host`. Outside the CIDR set, the
    daemon always uses the literal `Host`. RFC 7239 parsed.
- **Multi-method DID hosting.** Compile-time feature gates
  `method-webvh` + `method-web` (default) + `method-webs` /
  `method-webplus` (compile-error stubs for future work). Per-
  method resolution routes (`/{mnemonic}/did.jsonl` →
  `resolve_webvh`; `/{mnemonic}/did.json` → `resolve_web`)
  feature-gated; a method-webvh-only build doesn't compile (or
  register) the web routes.
  - `POST /api/dids/register` accepts the new
    `{ path, method?, did_data, domain?, force? }` body shape.
    `method` is optional and inferred from `did_data.id` when
    absent; explicit mismatch → 400.
  - `PUT /api/dids/{mnemonic}` content-type discriminator:
    `application/jsonl` → webvh, `application/did+json` → web.
  - Legacy `did_log: String` field accepted as a backwards-
    compat alias for webvh-only callers; will be removed in a
    future release.
- **Distributed domain assignment + retain-then-purge lifecycle.**
  The control plane is now the source of truth for which domains
  each server hosts.
  - `MSG_SERVER_REGISTER` carries `enabled_methods` +
    `served_domains` + `protocol_version` so the control plane
    can route method-aware requests.
  - `MSG_DOMAIN_ASSIGN { domain }` / `MSG_DOMAIN_UNASSIGN { domain }`
    + admin REST triggers at
    `POST /api/control/registry/{instance_id}/domains/{domain}/{assign,unassign}`.
    Idempotent on the server side.
  - Unassignment schedules a `PendingPurge { domain, scheduled_at,
    grace_seconds, reason, scheduled_by }` row with grace from
    `[hosting] unassigned_purge_grace` (default `"2h"`). The
    background sweep (60s tick) walks ripe entries and purges
    the matching DID records.
  - `MSG_DOMAIN_PURGE` + admin
    `POST /api/control/registry/{instance_id}/domains/{domain}/purge`
    bypass the grace for immediate cleanup
    (audit-log `reason: "admin-immediate"`).
  - Server cold-start fallback chain (T29): persisted
    `KS_ASSIGNMENTS` → `bootstrap_domains` config →
    legacy `public_url` host → empty (warn-log).
- **Trust-Tasks transport.** Every DIDComm message type and
  every authed REST route now has a canonical
  `https://trusttasks.org/did-hosting/...` URL.
  - DIDComm dispatcher accepts both legacy `MSG_*` and canonical
    `TASK_*` as `typ`; `v1_aliases` table provides the bijection.
    Existing clients keep working unchanged.
  - REST routes register through `TrustTaskRouter::route_with_task_permissive`
    — a client that sends the `Trust-Task:` header gets exact-
    match validation (415 on drift), a client that doesn't passes
    through (v0.7 → v0.8 migration window).
- **Companion client library `did-hosting-client`.** New
  workspace member exposing a thin REST + DIDComm client.
  Public surface includes `Client`, `AuthedClient`,
  `HostingSigningIdentity{,Owned}`, `HostingTokenStore` +
  `InMemoryTokenStore`, `ServerLocks`, `ClientError`,
  `ServiceEntry`, and all `TASK_*` URL constants. HTTPS enforced
  at construction (loopback exempt for dev). Decision ladder
  (cached → refresh → reauth) runs under per-server async mutex.
  Cross-crate parity test pins URL constants byte-for-byte
  against the daemon (T51).
- **Web UI catches up to the multi-domain + multi-method surface.**
  - New admin pages: `/domains` (catalog CRUD with create / set-default /
    disable / enable) and `/servers` (registry view with per-instance
    health, enabled methods, served-domain chips, assign / unassign /
    purge-now actions).
  - `DomainProvider` + nav-bar `DomainSwitcher` make a domain the
    active context across the app; admins also see an "All domains"
    pseudo-selection. Non-admin views are filtered through
    `GET /api/me/domains`.
  - ACL page gains a `DomainScope` editor (All / Specific / Specific +
    default) with chip selection and a separate default picker; the
    row read view shows the current scope as chips. Both the new-entry
    form and inline edit write through `createAcl` / `updateAcl`.
  - DID list filters by the active domain and renders per-row method +
    domain badges; DID detail shows the method and domain pulled from
    the new wire fields (T12 / M-01), with a graceful fallback to
    `log.method` on legacy records.
  - Dashboard surfaces the active-domain caption and an admin-only
    migration banner counting owners still on legacy "All" scope —
    deep-links to `/acl` for cleanup. Count is derived locally from
    `listAcl` (no new endpoint).

### Added

- **Non-interactive setup for every service.** Every `setup` subcommand
  on `did-hosting-{daemon,server,control}` + `webvh-{witness,watcher}` accepts a
  declarative `--from <recipe.toml>` recipe — drives the wizard with
  zero TTY interaction. The recipe contains no secrets; cloud creds
  come from the environment and crypto material is generated at setup
  time.
- **Full air-gapped install runs both phases non-interactively.** The
  same recipe file drives `offline-prepare` (writes the sealed-bundle
  request + persists the ephemeral seed in the configured secret
  backend) and `offline-complete` (opens the VTA admin's sealed reply).
  The recipe is the only state file — no separate state TOML needed.
- **`--force-reprovision` flag + reprovision-refusal scan.** Before
  any non-interactive run rotates credentials, the wizard probes the
  configured secret backend for an existing `ServerSecrets` entry. If
  one is present it refuses with exit 4 unless `--force-reprovision`
  is set. Backs up `config.toml` to `config.toml.bak` on overwrite.
- **`uninstall` subcommand** on `did-hosting-{daemon,server,control}` + `webvh-witness`
  — clears managed secrets from the configured backend and removes the
  config file plus companion DID-log files. Prompts for a typed
  `DELETE` confirmation; CI passes `--yes` to skip.
- **Env-var overlay on recipes.** `DAEMON_*` / `DID_HOSTING_*` / `CONTROL_*`
  / `WITNESS_*` / `WATCHER_*` env vars override recipe values at load
  time — one recipe template can ship across dev/staging/prod.
- **Stable exit codes for headless mode.** 0 success, 2 no-transport
  (VTA), 3 post-auth body rejected, 4 reprovision refused, 5 recipe
  parse/validation failed. Matches the mediator-setup wizard.
- **Example recipes** in `examples/` for every service, plus CI smoke
  tests that load + validate each one.

### Security

- **DIDComm `MSG_SERVER_REGISTER` now applies the registry URL allowlist.**
  The REST `POST /api/control/register-service` route already enforced
  `registry.url_allowlist`, but the DIDComm handler did not — any
  Service-role caller could register an attacker-controlled URL,
  including cloud-metadata / loopback / RFC1918 addresses. When an
  admin then hit `/api/proxy/server/{instance_id}/...`, the proxy
  forwarded the admin's bearer token to the registered URL (SSRF +
  token exfil). The allowlist gate is now lifted into a shared
  `registry::validate_registered_url` helper called by both transports.
  Empty allowlists preserve the prior "operator opted out" behaviour;
  any operator running the proxy route should configure one.
- **List-DIDs DID-prefix-collision IDOR closed.** Owner-index keys are
  `owner:{did}:{mnemonic}` and DIDs naturally contain colons. A DID
  that was a string-prefix of another (e.g. `did:web:tenant` vs
  `did:web:tenant:server`) leaked the longer-DID owner's mnemonics,
  did_id, timestamps, and resolve counts via prefix iteration in
  `list_dids`. Fixed by re-checking `record.owner == target_owner`
  after the iteration. Read-only — no write paths were affected.
- **Error sanitisation rebuilt on stable per-variant messages.** The
  prior `IntoResponse for AppError` used substring matches
  (`msg.contains("ACL") || msg.contains("did:")`) to decide whether to
  redact `Forbidden`, leaving brittle gaps (`"not the owner of this
  DID"` leaked through; `"is not in the ACL"` got caught) and ignored
  `Validation` entirely. Replaced with `AppError::user_message()` per
  variant: `Forbidden` always collapses to `"forbidden"`, and
  `Validation`/`Conflict`/`QuotaExceeded` strip ASCII control chars
  and cap at 256 bytes to prevent reflection of caller-supplied
  newlines/control bytes.
- **`now_epoch` and JWT issue path no longer panic on clock skew.** A
  system clock set before 1970 (e.g. a misconfigured embedded host)
  used to panic in `SystemTime::now().duration_since(UNIX_EPOCH).unwrap()`.
  Switched to `unwrap_or_default()` to match `didcomm_unpack`'s
  existing pattern.
- **Stricter DID-format validation on admin write surfaces.** New
  `validate_did_format` helper used by ACL create/update/delete and
  by `change_did_owner::new_owner`. Trims surrounding whitespace,
  rejects empty / oversized (>2048 bytes) / missing-`did:`-prefix /
  contains-control-character. The most common failure mode this
  prevents is silent: a typo with trailing whitespace lands as a
  storage key that no later `check_acl` lookup will match.

### Added

- **DID ownership transfer.** New `PUT /api/owner/{*mnemonic}` REST
  endpoint and `MSG_DID_CHANGE_OWNER` / `MSG_DID_CHANGE_OWNER_CONFIRM`
  DIDComm message types let an admin or the current owner re-assign a
  DID slot to another identity. New owner must already be in the ACL.
  Web UI exposes the transfer flow on the DID detail screen, gated to
  admins or the current owner.
- **Atomic claim-and-publish.** New `POST /api/dids/register` route
  and `register_did_atomic` operation that claims a path and publishes
  the first signed log entry in a single fjall batch — closes the
  resolvability gap between path reservation and first publish that
  the previous two-step `request_uri` + `publish_did` flow exposed.
  Idempotent for same-owner re-publish; admin force-takeover requires
  an explicit `force=true` flag.
- **`force` flag on `MSG_DID_REQUEST` / `POST /api/dids`.** Lets the
  current owner or an admin override the "DID already exists" error
  to claim the slot. Wipes prior log/witness/owner-index in a single
  batch.

### Fixed

- **Stats counter advances on control-plane writes.** Previously
  `total_updates` and `last_updated_at` only moved via stats-sync
  messages from remote `did-hosting-server` instances; in self-hosted /
  daemon deployments where the control plane is authoritative, the
  counters never advanced. Added `record_update` calls to
  `publish_did` and `register_did_atomic` after the storage commit
  succeeds.
- **`force=true` create no longer fans out a stale delete.** All three
  create call sites (REST `request_uri`, framework DIDComm dispatcher,
  signed-HTTP DIDComm dispatcher) used to push `notify_servers_delete`
  on force-replace, which made downstream resolvers serve 404 until
  the operator's follow-up `publish_did` arrived. Removed; the
  publish step's own `notify_servers_did` fans out the new content.
  Operators wanting an atomic ownership-takeover should use
  `register_did_atomic`.
- **`did-hosting-daemon::run_recreate_did`** now removes the owner-index
  entry under the *actual* owner DID rather than the hard-coded
  literal `"system"` (which only worked because `auto_bootstrap_dids`
  happened to use that owner string).

### Changed

- **Bumped `affinidi-messaging-didcomm-service` 0.3.0 → 0.3.1 and
  `affinidi-messaging-sdk` 0.17/0.18 → 0.18.2.** Picks up the
  upstream fix for the orphaned `WebSocketTransport` task bug
  diagnosed during testing: when the mediator's HTTP auth endpoint
  was briefly unreachable at startup, prior versions leaked one
  transport task per failed `Listener::connect()` attempt via a
  self-sustaining `Arc` cycle, producing a duplicate-channel storm
  once the mediator recovered.
- **CLAUDE.md daemon-parity rules clarified.** Restructured into
  three explicit sections: positioning, what the daemon mirrors, and
  what it intentionally does NOT mirror. Calls out registry health-
  check loop, HTTP stats sync, server's own DIDComm listener, and
  outbound ATM as deliberate omissions in the all-in-one model.

### Documentation

- npm `overrides` for `postcss` (≥8.5.10) and `@xmldom/xmldom`
  (≥0.8.13) close 5 dependabot alerts on the UI side.
- `cargo update` plus the SDK upgrade close the high-severity
  `openssl 0.10.79` and `rustls-webpki 0.103.13` advisories on the
  default-features Rust build.

### Follow-ups — security review + domain UX (2026-05-25)

A second pass over the v0.7.0 cut against an external security-patch
series, plus operator-driven UX gaps surfaced once the multi-domain
features were exercised end-to-end. The wire shape and operator-
facing config are unchanged; these are correctness, authz, and
log-hygiene fixes.

#### Security

- **DIDComm `MSG_SERVER_REGISTER` / `MSG_STATS_SYNC` now require the
  `Service` role exactly.** Both control-plane handlers previously
  accepted any sender in the ACL (Owner / Service / Admin). The
  REST equivalents (`POST /api/control/register-service` /
  `POST /api/control/stats`) are gated on `ServiceAuth` (Service-only);
  the DIDComm transports are now aligned. The `handle_server_register`
  case is the higher-impact half: success calls `sync_all_dids_to_server`,
  which pushes every tenant's DID log + witness content to the caller
  and subscribes them to all future updates — an Owner-role DID could
  enumerate the entire fleet's hosted data via a single forged register.
- **`MSG_SYNC_UPDATE` / `MSG_SYNC_DELETE` bound to the configured
  `control_did`, not any Service-role DID.** `did-hosting-server`'s
  sync handlers overwrite or delete arbitrary DIDs by body-supplied
  mnemonic. The previous `Role::Admin | Role::Service` gate let any
  peer server, witness, or stale Service ACL entry wipe or replace
  any hosted DID's log/witness content. New `require_control_plane`
  helper enforces an exact match against `config.control_did`; missing
  `control_did` rejects all sync messages (correct — a server without
  a control plane has no legitimate sender).
- **`GET /api/services/overview` now requires `AdminAuth`.** Previously
  any authenticated `AuthClaims` caller could enumerate the backend
  service registry — internal instance URLs, instance IDs, server
  DIDs, health status, registration timestamps. The equivalent
  `/api/control/registry` routes have always required `AdminAuth`; the
  overview gate is brought in line.
- **Manual `Debug` impls on credential-bearing config types.**
  `StoreConfig` (`redis_url`, `cosmosdb_connection_string`),
  `WatcherEndpoint.token`, `SyncConfig.push_tokens`,
  `SourceConfig.token`, `EnrollStartRequest.token`, and
  `CreateInviteResponse.{token, enrollment_url}` previously
  derived `Debug` and would render the live credential verbatim
  in any startup `tracing::info!(?config, …)` or error-path debug
  format. Each now redacts via `<redacted>` (count-only for the
  `push_tokens` slice). `PlaintextSecrets` already redacted; this
  closes the gap on every related struct.
- **Regression test guards the DIDComm refresh signer-binding.** The
  fix that pins a refresh token to the DIDComm sender DID lives in
  the upstream `vti-common` crate. Added
  `did-hosting-server/tests/refresh_signer_binding.rs` — seeds an
  Alice-owned session, calls `handle_refresh` with a mismatched
  signer, asserts `AppError::Authentication`. Catches a future
  backend swap silently dropping the binding parameter.

#### Fixed — domain assignment surfaces correctly in the UI

- **`POST /api/control/registry/{id}/domains/{domain}/{op}` now returns
  JSON on 202.** All three handlers (`assign`, `unassign`, `purge`)
  previously returned bare `StatusCode::ACCEPTED` with no body. The
  UI's `request()` helper short-circuits 204 only — on any other
  status it validates `application/json` and throws
  `"Expected JSON response but got unknown content type"`. Each
  handler now returns `(StatusCode::ACCEPTED, Json(json!({…})))`
  with the operation, instance ID, and domain so the UI gets a
  structured ack.
- **Control-plane DIDComm router handles `domain/{assign,unassign,purge}-ack`.**
  Servers send these after applying the matching outbound op. The
  router had no entries, so each ack fell through to `handle_fallback`
  and logged `inbound DIDComm: unhandled message type — ignoring`.
  A new `handle_domain_ack` records the ack at info-level (parallel
  to the existing `handle_sync_ack`).
- **`served_domains` populated end-to-end.** The control plane's
  registry view (and the UI's "domains assigned to this server"
  panel) showed nothing after a successful domain assign. Two-part
  fix: `did-hosting-server`'s `register_via_didcomm` no longer
  hardcodes `served_domains: []` (it now lists active local domains
  from `list_domains(&state.store)`), and `handle_domain_ack` mirrors
  each ack into the matching `ServiceInstance.served_domains` so the
  registry updates immediately without waiting for the next server
  boot. Restart-recovery and live-update paths converge on the same
  identity (`sender.replace(':', "_")`, the same derivation
  `handle_server_register` already uses).

#### Added — admin escape hatch for disabled domains

- **`DELETE /api/domains/{name}` (Admin-only) force-deletes a disabled
  domain**, bypassing the `hosting.disable_purge_grace` cooling-off
  window the background sweep otherwise waits out. Refuses when the
  domain is Active (operator must disable first — same two-step safety
  the UI already enforces) or when it's the current default
  (`delete_domain_record` already gates this and surfaces as
  `Conflict`). The pending-purge row is cancelled after the record
  is removed so the next sweep doesn't try to delete a row that's
  already gone. Mounted alongside the existing `PUT /domains/{name}`
  under `TASK_DOMAIN_UPDATE_1_0` (same pattern as `/registry/{id}`
  chaining GET+DELETE under one Trust-Task URI).
- **`?purge_servers=true` adds one-click fleet-wide purge.** When set,
  every registry instance whose `served_domains` lists the domain
  receives a `domain.purge/1.0` (T30) DIDComm message before the
  control-plane record is removed. Fire-and-forget over DIDComm;
  the local delete proceeds without waiting for acks, and
  `handle_domain_ack` drops the domain from `served_domains` as
  servers ack back. Per-instance failures during fanout are logged
  but never block the overall delete — operators can re-run the
  per-server "Purge now" on any that missed.
- **Three buttons on disabled domain cards.** UI gains "Delete now"
  (record-only) and "Purge & delete" (fleet-wide) destructive buttons
  alongside the existing "Enable". Each has a confirm dialog that
  spells out the blast radius. The "Delete now" path is the
  recovery route for legacy disabled domains whose `purge_at` was
  never populated and would otherwise stay stuck forever.

#### Changed

- **Login UI: "Login with VTA Wallet"** replaces "Login with VTI
  Wallet" on the button + install hint + the two extension-missing
  error messages. Aligns the user-facing strings with the rest of
  the codebase (`window.vtaWallet`, etc.).

### Follow-ups — UX polish, branding, and dashboard scoping (2026-05-25)

A third pass over the v0.7.0 cut driven by hands-on operator use of
the new multi-domain features. No wire changes; everything below is
text, layout, or client-side filtering. Same v0.7.0 dated section is
extended because the tag still hasn't moved.

#### Changed — product naming aligned to "DID Hosting"

- **User-facing "WebVH" → "DID Hosting" rename.** Setup-wizard
  headers, CLI `about` strings, the daemon/server/control ASCII-banner
  subtitles, `Cargo.toml` `description` fields, README titles and
  body, the DIDComm DID-management protocol document's prose and
  Mermaid participant labels, the WebAuthn `rp_name` ("DID Hosting
  Server"), and the `OperatorMessages` integration labels passed
  through to the VTA's `pnm contexts create --name "..."` hint all
  say "DID Hosting" now. Kept "WebVH" where it refers to the DID
  method itself (`did:webvh`, WebVH log entries, WebVH spec links),
  code identifiers (`WebVHClient`, `WebVHError`, `WebVHHosting`
  service-type string), wire constants (JWT `aud: "WebVH"`,
  message-type URIs under `https://affinidi.com/webvh/1.0/...`), and
  the `webvh-watcher` / `webvh-witness` crate directories whose
  witness/watcher concepts are themselves method-specific. The
  rebrand is text-only — no API, ABI, or on-disk format changes.
- **UI title "DID Hosting Manager".** Expo manifest `name`
  (`did-hosting-ui/app.json`) updated, which drives the browser tab
  `<title>` rendered from `dist/index.html`.

#### Fixed

- **Duplicate "Mediator DID" prompt during daemon setup.** Both the
  offline-prepare and self-managed flows rendered the prompt twice
  when the operator pasted a long mediator DID. Root cause:
  `dialoguer`'s `Input::interact_text()` re-renders the prompt after
  Enter to drop the bracketed default indicator, and its line-clear
  counts logical newlines rather than terminal-wrapped visual rows
  — so a wrapped input left the original prompt on screen while the
  re-render landed below as if it were a second prompt. Replaced the
  single `Input` (`.default(String::new()) + .allow_empty(true)`)
  with a `Confirm`-then-`Input` pair: the Confirm "Configure a
  DIDComm mediator?" is short enough to never wrap, and the
  follow-up `Mediator DID:` Input has a short label so the re-render
  lines up cleanly. Same shape as the existing online flow's
  mediator selection.
- **Domain switcher now actually scopes the DIDs list.** The
  client-side filter accepted any DID whose `domain` field was
  empty, so tenants whose records pre-date the M-01 migration (or
  whose DIDs were assigned cross-domain) saw the switcher silently
  no-op. Tightened to a strict `d.domain === currentDomain`; the
  list page surfaces an `N unassigned DIDs hidden` hint next to the
  filter caption so a user staring at an unexpectedly short list
  knows there are legacy records to triage (or to switch to "All
  domains").
- **Dashboard stats now react to the domain switcher.** The
  dashboard previously read `/api/stats` and rendered the
  server-wide aggregate regardless of the active domain. When a
  specific domain is pinned the dashboard now derives per-domain
  numbers from the DID list: DIDs in `{domain}`, scoped resolves,
  and scoped updates (sum of `versionCount - 1` clamped to ≥0 — the
  in-memory updates counter isn't broken out per-domain yet).
  "All domains" (admin) keeps the cheap `/api/stats` fast-path.

#### Added — dashboard

- **Domains stat card.** New card between "Total DIDs" and
  "Total Resolves" reading the count from the existing
  `useDomains()` provider. Always shows the total configured count;
  it's a system-level fact rather than a per-view stat.
- **Wider dashboard layout.** `statusRow`, `errorCard`, `section`,
  `migrationBanner`, and the `ServiceOverview` container bumped from
  `maxWidth: 500/800` to `1200` to match `NavBar` and the DID detail
  page. The dashboard was the only screen still rendering inside a
  narrow centered column on wide viewports.

#### Build

- **`cargo update`.** `affinidi-messaging-didcomm` 0.13.2 → 0.13.3,
  `affinidi-messaging-mediator` 0.15.4 → 0.15.5,
  `affinidi-messaging-sdk` 0.18.2 → 0.18.3,
  `windows-native-keyring-store` 1.0.0 → 1.1.0. Drops unused
  transitive deps (`aes 0.9`, `cipher 0.5`, `cpubits 0.1`,
  `inout 0.2`, `vta-sdk 0.6` — workspace already pins 0.7).

### Follow-ups — affinidi-messaging-didcomm 0.15 ecosystem bump (2026-06-03)

A dependency-only pass over the v0.7.0 cut. No wire, API, ABI, or
on-disk format changes; the entire move is version alignment in the
lockfile plus three stale test assertions. Same v0.7.0 dated section
is extended because the tag still hasn't moved.

#### Build

- **`affinidi-messaging-didcomm` 0.14 → 0.15.** The whole Affinidi
  stack has to move in lockstep, otherwise two didcomm versions coexist
  and `Message` / `UnpackMetadata` stop unifying across crate
  boundaries (`did-hosting-control` failed to compile: the DIDComm
  service router operates on `affinidi_tdk`'s re-export while our direct
  dep stayed on 0.14). Only `Cargo.toml` changed (`affinidi-messaging-didcomm
  = "0.15"`); everything else was re-locked under the existing
  `"0.7"`/`"0.3"`/`"0.9"`/`"0.1"` pins:
  - `affinidi-messaging-didcomm-service` 0.3.2 → 0.3.3
  - `affinidi-tdk` 0.7.2 → 0.7.3
  - `affinidi-messaging-sdk` 0.18.4 → 0.18.6
  - `affinidi-did-authentication` 0.3.4 → 0.3.5,
    `affinidi-meeting-place` 0.4.1 → 0.4.2 (both inside the tdk subtree)
  - `trust-tasks-didcomm` 0.1.3 → 0.1.4 (the last crate holding a stray
    didcomm 0.14.0; the lock now carries a single didcomm 0.15.0)
  - dev-deps: `affinidi-messaging-mediator` 0.15.7 → 0.15.12 (drops the
    stale `vta-sdk 0.7.0` + `affinidi-messaging-didcomm 0.13.3` chain),
    `affinidi-messaging-mediator-common` 0.15.1 → 0.15.3,
    `affinidi-messaging-test-mediator` 0.2.3 → 0.2.4

#### Fixed

- **Stale provision-ask template assertions.** Three
  `did-hosting-common::server::vta_setup` tests still expected the
  pre-rename service-named templates (`did-hosting-{control,daemon,server}`)
  after the v0.7.0 repipe to vta-sdk's capability-named builders. Updated
  to the values the production code now emits — `did-host-http-didcomm`,
  `did-host-http`, `did-host-didcomm`. Pre-existing failures, unrelated
  to the didcomm bump.

## 0.6.0 (2026-05-05)

### Security

- **All three refresh handlers (control, server, witness) now require a
  JWS-signed DIDComm envelope and bind the signer to the session DID.**
  did-hosting-control was the last hold-out — it accepted a raw refresh-token
  string in the body. Refresh now requires possession of both the refresh
  token *and* the session-DID's signing key on every service.
- **Offline-bootstrap latent-bug fix.** `open_offline_bootstrap_response`
  used `BTreeMap::iter().next()` to pick "the" DidKeyMaterial entry from
  the sealed payload's secrets map. With admin rollover enabled (the
  production-recommended VTA config), payloads carry two entries —
  integration and admin — and the alphabetical iteration order silently
  picked the wrong one (`did:key:...` admin sorts before `did:webvh:...`
  integration). The open path now matches by `config.did_document.id`
  with a logged forward-compat fallback. New
  `offline_bootstrap_full_webvh_to_vta_roundtrip` integration test
  exercises the full webvh ↔ VTA seal/open path in-process and would
  have caught this regression before publish.
- **Refresh-token rotation TOCTOU closed end-to-end.** Two concurrent
  requests with the same leaked refresh token used to both pass the
  lookup before either deleted the session. The fix is a new
  `KeyspaceOps::take_raw_atomic` primitive — Redis `GETDEL` /
  DynamoDB `DeleteItem` with `ReturnValues=ALL_OLD` / fjall mutex /
  per-keyspace mutex on Firestore + Cosmos DB. All three refresh
  handlers (control, server, witness) now atomically consume the
  refresh-index entry as part of the lookup, so exactly one concurrent
  caller wins — even across multiple webvh replicas backed by Redis
  or DynamoDB. The previous in-process `RefreshClaim` workaround is
  removed.
- **Refresh handlers (server, witness) now bind the JWS signer to the session
  DID.** Previously a leaked refresh token plus any attacker-controlled DID
  could rotate the victim's tokens — the signed envelope only proved
  possession of *some* key. Both handlers now reject when the verified
  signer DID does not equal `session.did`.
- **Empty-`jti` rotation bypass closed.** The extractor used to short-circuit
  the rotation check when `claims.jti.is_empty()`. Any session with a
  `token_id` now requires a non-empty matching `jti`, regardless of how
  the token was minted.
- **Registry / proxy trust chain hardened in did-hosting-control.** The audit
  found a Service-role JWT could register an attacker URL as a backend
  instance, and the proxy would then forward an Admin caller's
  Authorization header to it on the next proxy hit:
  - `RegistryConfig` gains an optional `url_allowlist` for backend hostnames.
  - `did-hosting-control`'s reqwest client is built with `Policy::none()` so
    a malicious backend cannot redirect the proxy onto a third-party host.
  - The proxy strips RFC 7230 §6.1 hop-by-hop headers and `Set-Cookie`
    from upstream responses before forwarding.
- **Watcher `/api/sync/did` body limited to 4 MiB** via a tower-http
  `RequestBodyLimitLayer`, and `validate_did_jsonl` now requires the
  latest entry's `state.id` to start with `did:webvh:`. Closes a leaked-
  push-token DoS / arbitrary-content republish vector.
- **Manual `Debug` redaction extended** to `Session` (refresh_token,
  token_id, challenge), `Enrollment` (invite token), `StoredSecrets`
  (bootstrap_seed), and `SecretsConfig` (plaintext_bootstrap_seed).
- **Multi-signature JWS envelopes are rejected** by `unpack_signed`. The
  threat model assumes single-signer messages; accepting additional
  signatures silently created surprising states.
- **X25519 verification methods rejected** by `resolve_verifying_key` —
  Ed25519 signing keys and X25519 key-agreement keys are both 32 bytes,
  so the previous length check would not catch a kid pointing at the
  wrong key class.
- **Keyring init no longer poisons the process** on transient failures.
  Only the success case is cached; transient failures (dbus not yet up,
  etc.) are allowed to retry on the next constructor call.
- **`write_secret_file_0600` is now atomic-rename safe** — uses a
  sibling tempfile with mode 0600 set before data is written, then
  rename. Re-runs of the offline-bootstrap CLI no longer fail with
  EEXIST when the seed file already exists.
- **DIDComm authentication closed an auth-bypass on every REST `/api/auth/`
  endpoint.** `unpack_signed` now returns the JWS-verified signer DID and
  rejects envelopes whose `from` field disagrees. Previously an attacker
  controlling any DID could mint a JWT for any ACL'd DID on the server,
  control plane, or witness REST surface. The mediator-driven inbound DIDComm
  path was unaffected.
- **Stats-sync endpoint requires Service-role auth** and binds the payload's
  `server_did` to the JWT-authenticated caller. Closes a counter-poisoning
  vector on the public control-plane surface.
- **Watcher sync now runs `validate_did_jsonl`** before storing pushed log
  content. A leaked push token can no longer republish arbitrary JSON
  masquerading as a DID document.
- **Witness `sign_proof` is now Admin-only** and emits an audit log on every
  signed proof. Previously any authenticated caller could request a witness
  proof for any version_id.
- **Reverse proxy in did-hosting-control requires Admin role** rather than any
  authenticated user.
- **Refresh handlers rotate everything.** The control / server / witness
  refresh endpoints now mint a fresh `session_id`, access token and refresh
  token on every refresh; the old session is deleted atomically. The
  `RefreshData` response shape gains `refresh_token` + `refresh_expires_at`
  so callers can drive the next refresh.
- **Private key files are written atomically** with mode 0600 using
  `OpenOptions::create_new`. Closes a TOCTOU window between `fs::write` and
  `set_permissions`.
- **`ServerSecrets`, `WitnessRecord`, `PlaintextSecrets` redact `Debug`** so
  `tracing::debug!(?secrets, …)` no longer leaks key material.
- **`PlaintextSecretStore::set` now persists `vta_credential`** instead of
  silently dropping it. Plaintext-backed deployments could previously lose
  their VTA credential on any wizard-driven config rewrite.
- **HTTP responses carry CSP, Referrer-Policy, HSTS** in addition to the
  existing X-Frame-Options / X-Content-Type-Options / Cache-Control.
- **Invite tokens** are now logged as a token-prefix only (revoke / update
  handlers in the passkey module). The token itself is no longer committed
  to operator log streams.
- **`KeyringSecretStore::try_new`** surfaces backend-registration failure as
  a structured `AppError::SecretStore` instead of warning-then-mystery-error.

### Added
- **did-hosting-daemon**: Self-managed identity mode. The setup wizard now
  offers a fourth choice ("Self-managed — no VTA — daemon manages its
  own DID") that skips every VTA prompt and instead generates the
  daemon's Ed25519 + X25519 keys locally and self-hosts a `did:webvh`
  identifier. Config gains an `[identity] mode = "vta" | "self-managed"`
  field (default `"vta"` for back-compat — existing configs without
  the section continue to load unchanged). Admin enrolment in
  self-managed mode uses passkey-invite only via the existing
  `did-hosting-daemon invite --did <DID> --role admin` CLI; the wizard does
  not seed any admin DID into the ACL. Tenant DID provisioning over
  DIDComm is unchanged — external tenant VTAs can still provision
  DIDs into a self-managed daemon. Daemon-only in v1; standalone
  `did-hosting-server` / `did-hosting-control` / `webvh-witness` setup wizards
  reject the self-managed choice with a clear "daemon-only" error
  pointing at `did-hosting-daemon`. See `docs/self-managed-mode-spec.md`.
- **did-hosting-control**: Web UI for creating enrollment invites. The Access
  Control page now has an "Invite by Link" card that generates an
  enrollment URL for a given DID and role, removing the need to drop to
  the `did-hosting-control invite` CLI to onboard new users. The invitee opens
  the link, registers a passkey, and is added to the ACL automatically.

### Fixed
- **Offline-bootstrap phase 2 fails with "bootstrap seed missing from
  secret store" in plaintext mode.** Phase 1 wrote the seed to
  `[secrets].plaintext_bootstrap_seed` in `config.toml` and serialised
  the wizard's `SecretsConfig` snapshot — captured *before* the seed was
  written — into `setup-offline-state.toml`. Phase 2 reconstructed the
  store from that stale snapshot and reported the seed missing even
  though it was sitting on disk. Affected all four wizards (daemon,
  control, server, witness) when built without a secure secrets backend
  (no `keyring` / `aws-secrets` / `gcp-secrets` / `azure-secrets`
  feature). `PlaintextSecretStore::get_bootstrap_seed` now reads
  directly from the config file rather than caching at construction;
  the file is the source of truth, matching how the cloud and keyring
  backends already worked. Regression tests cover the wizard's exact
  serialise-snapshot-then-reload flow plus the malformed-seed
  operator-edit case.
- **Setup wizards**: the offline-bootstrap "Next steps" output printed
  an incorrect VTA-host CLI hint
  (`vta context provision --context X --admin Y`). The actual command
  is `vta context create --id X` with no `--admin` flag. Updated all
  five wizards (common, server, control, witness, daemon).

### Changed
- **Keyring backend**: migrated from the `keyring` 3.x facade crate to
  `keyring-core` 1.x with platform-specific backend stores
  (`apple-native-keyring-store`, `windows-native-keyring-store`,
  `dbus-secret-service-keyring-store`) selected by target cfg. The
  default credential store is registered once at first
  `KeyringSecretStore::new()` call. No on-disk format changes — entries
  written by the previous build are still readable.
- **vta-sdk integration**: adapted to upstream `ProvisionAsk` builder
  renames — `webvh_hosting_server` → `did_hosting_daemon`, `webvh_service`
  → `did_hosting_server` for witness-style consumers, and a new
  `did_hosting_control(context, host_url, mediator_did)` builder for the
  control plane (now requires `host_url` since the upstream template
  embeds it as the `WebVHHosting` service endpoint). The control-plane
  wizard now collects `did_hosting_url` before the VTA round-trip.
- **did-hosting-ui**: Login page "need access?" section no longer surfaces the
  CLI command — it now instructs users to request an invite link from an
  admin, matching the new web-based flow.
- **MSRV**: raised from 1.91.0 to 1.94.0. Required by the updated
  affinidi-tdk / affinidi-messaging / affinidi-secrets-resolver /
  affinidi-data-integrity stacks, all of which declared 1.94+ in their
  latest releases.
- **Witness proof signing**: migrated to the new async `Signer`-based API
  in affinidi-data-integrity 0.6. The `WitnessSigner` trait is now async
  (returns a `BoxFuture`) — any external signer implementations must be
  updated accordingly.
- **CosmosDB store**: migrated to azure_data_cosmos's required
  `RoutingStrategy` parameter and the now-async `container_client()`.
  Region is configurable via new `store.cosmosdb_region` setting (env:
  `*_STORE_COSMOSDB_REGION`), accepting any Azure region name — display
  form (`"West US 2"`) or normalized (`"westus2"`). Defaults to
  `"eastus"` when unset.

### Tests
- **DIDComm dispatcher coverage** in `did-hosting-control`. Added 22 unit tests
  exercising the wire-level contract: every `dispatch_did_op` arm
  (validation, success, conflict, not-found, cross-owner forbidden), the
  authenticate flow end-to-end with JWT decode-back assertions, and the
  ACL gate at the dispatcher level. Refactored `handle_authenticate` and
  `handle_webvh_message` to delegate to `(String, Value)`-returning
  helpers (`run_authenticate`, `run_webvh_dispatch`) so the wire-level
  responses are testable without an `ATM`-backed `HandlerContext`. Also
  added `affinidi-messaging-test-mediator` (0.2) as a dev-dep for
  in-process embedded mediator tests. Smoke tests validate the
  fixture spawns, provisions distinct DIDs via the new
  `TestMediator::with_users` helper, and supports incremental
  `TestMediatorHandle::add_user` post-spawn — the lighter-weight
  alternative to `TestEnvironment` for handler-level scenarios that
  don't need an ATM-bound profile.
- **JWT crypto provider unification fix.** `JwtKeys::from_ed25519_bytes`
  now idempotently installs `jsonwebtoken::crypto::rust_crypto` as the
  process-level provider before encode/decode. Required because
  workspace-feature unification (e.g. when a dev-dep transitively pulls
  in `aws_lc_rs`) made `jsonwebtoken` 10.x refuse to auto-pick a
  provider and panic on first use. The install is a no-op on subsequent
  calls so it's safe across any thread.

### Build
- **UI build now requires Node.js 20+.** Metro/Expo's loader uses
  `Array.prototype.toReversed()`, which landed in Node 20 — older
  toolchains fail deep inside `expo export` with
  `TypeError: configs.toReversed is not a function`.
  `did-hosting-control/build.rs` now preflights `node --version` and fails
  with an actionable message when Node is missing or too old.
  `did-hosting-ui/package.json` also declares `engines.node >= 20`. README
  prerequisites updated from Node 18+ to Node 20+.

### Dependencies
- affinidi-tdk 0.5 → 0.7
- affinidi-tdk-common 0.4 → 0.6
- affinidi-messaging-didcomm 0.13.1 → 0.13.2
- affinidi-messaging-didcomm-service 0.2 → 0.3
- affinidi-messaging-sdk 0.16 → 0.17
- affinidi-secrets-resolver 0.5.3 → 0.5.5
- affinidi-did-resolver-cache-sdk 0.8.4 → 0.8.6
- affinidi-data-integrity 0.3 → 0.6 (breaking API — see note above)
- vta-sdk 0.4 → 0.5 (template-driven provisioning)
- didwebvh-rs 0.4 → 0.5 (transitive)
- firestore 0.47 → 0.48
- azure_core 0.32 → 0.35
- azure_data_cosmos 0.31 → 0.33 (breaking API)
- azure_security_keyvault_secrets 0.13 → 0.14
- azure_identity 0.34 → 0.35
- redis 1.0 → 1.2 (breaking `AsyncIter::next_item` now returns
  `Option<RedisResult<T>>`)
- aws-sdk-* and aws-config patch bumps
- keyring 3 → keyring-core 1 (see Changed)

## 0.5.0 (2026-04-13)

### Added
- **did-hosting-server**: DIDComm-based server registration with control plane,
  replacing HTTP-based registration. Servers now authenticate and register
  via DIDComm messages over a persistent websocket connection.
- **did-hosting-server**: DIDComm health ping/pong replaces HTTP health checks,
  providing reliable liveness monitoring over the existing DIDComm channel.
- **did-hosting-server**: `list-dids` and `remove-did` CLI commands for managing
  DIDs directly from the server command line.
- **did-hosting-control**: Consolidated VTA provisioning protocol — the control
  plane now handles the full DIDComm VTA flow (did/request, did/publish)
  for all registered servers.
- **did-hosting-control**: Auto-adds its own DID to server ACL on registration,
  enabling seamless DID sync without manual ACL configuration.
- **did-hosting-common**: Shared DIDComm message type constants for health,
  stats, and DID sync protocols.

### Changed
- **did-hosting-server**: Management routes removed from server edge nodes.
  All DID management is now done through the control plane; servers are
  read-only edge nodes that serve DID documents.
- **did-hosting-server**: Single DIDComm connection per service using
  `DIDCommService` v0.2.0, replacing per-operation connections.
- **did-hosting-server**: Setup wizard simplified for read-only edge node role —
  asks only for DID hosting URL instead of full server configuration.
- **did-hosting-server**: DID path derived from URL instead of hardcoded
  `.well-known`, supporting flexible DID hosting configurations.
- **did-hosting-control**: DIDComm service and handlers restructured for
  improved message routing and handler visibility.
- **did-hosting-daemon**: DIDComm config flag now read from `[features]` section.
  HTTP server starts before DIDComm to avoid self-resolution race condition.

### Fixed
- **did-hosting-server**: Always serve HTTP for public DID resolution regardless
  of `rest_api` flag — DID documents must remain publicly accessible.
- **did-hosting-server**: Websocket connection established before sending
  registration message, preventing message loss.
- **did-hosting-control**: DID sync and stats flow now works reliably between
  control plane and registered servers.
- **did-hosting-control**: DIDComm service properly visible to route handlers.
- Improved DIDComm error logging across all services.

### Performance
- Suppressed noisy health-ping/pong and stats-ack request logs to reduce
  log volume in production.

### Dependencies
- `affinidi-messaging-didcomm-service` 0.1 → 0.2

## 0.4.2 (2026-04-13)

### Added
- **did-hosting-daemon**: Full parity with standalone did-hosting-server + did-hosting-control.
  The daemon now includes all lifecycle management that was previously only
  available in standalone mode:
  - Background storage task: session cleanup, DID cleanup, stats flush to
    persistent store, and service health checks
  - Auto-bootstrap of root DID on startup when `public_url` is configured
  - Stats collector seeded from persisted store (stats survive restarts)
  - Registry seeding from static config on startup
  - DIDComm support via new `didcomm` config field — inbound listener for VTA
    integration and outbound ATM for sync push messages
  - Ordered shutdown: DIDComm → HTTP → storage flush → persist
- **did-hosting-daemon**: New CLI commands from did-hosting-server: `bootstrap-did`,
  `recreate-did`, `recover-did`, `load-did`, `import-secrets`, `backup`,
  `restore`
- **did-hosting-daemon**: DID store integrity check on startup

### Fixed
- **did-hosting-daemon**: fjall `Locked` error on startup — server, watcher, and
  control all share the same store path but each opened it independently.
  Stores are now opened once and shared.
- **did-hosting-daemon**: Enrollment invite URLs returned 404 — the control plane
  was nested at `/control` but enrollment URLs pointed to `/enroll`. Control
  plane is now merged at root so URLs work identically in daemon and
  standalone modes.
- **did-hosting-daemon**: DID resolve stats were not recorded — the server's
  stats collector was `None`. Now a shared `Arc<StatsCollector>` is used by
  both server and control plane.
- **did-hosting-daemon**: HTTP client had no timeouts — now uses 30s request /
  10s connect timeouts matching standalone server.
- **did-hosting-control**: Time-series graphs showed zero — `flush_stats_to_store`
  wrote aggregate totals but never wrote time-series bucket entries
  (`ts:{mnemonic}:{epoch}`). Now writes per-DID and server-wide (`_all`)
  5-minute buckets on each flush cycle. This fix applies to both daemon
  and standalone control plane modes.

### Changed
- **did-hosting-server**: `start_didcomm_service` is now `pub` for daemon reuse.
- **did-hosting-control**: `flush_stats_to_store`, `run_health_checks`, and
  `seed_registry` are now `pub` for daemon reuse.

## 0.4.1 (2026-04-13)

### Added
- **did-hosting-daemon**: Restore unified CLI management commands (`add-acl`,
  `list-acl`, `remove-acl`, `invite`) so operators can manage ACLs and create
  passkey enrollment invites directly from the daemon binary without needing to
  run `did-hosting-control` separately.

## 0.4.0 (2026-04-13)

### Added
- **did-hosting-server**: Restore `import-secrets` CLI command for importing server
  secrets from a VTA secrets bundle or individual multibase-encoded keys. This
  is required for cold-start bootstrap scenarios where no VTA service is running.

## 0.3.0 (2026-04-12)

### Changed
- Simplified architecture: removed shared CLI module, VTA-cache layer, and
  background task infrastructure from did-hosting-common
- Each service binary now owns its CLI directly instead of delegating to
  `did-hosting-common::server::cli`
- Switched from local-path `vta-sdk` to crates.io published version (0.3.x)

### Removed
- `did-hosting-common::server::cli` module (CLI logic moved into each binary)
- `did-hosting-common::server::vta_cache` module (VTA key refresh on startup removed)
- `import-secrets` CLI command from did-hosting-server (restored in 0.4.0)

## 0.2.0 (2026-04-08)

### Changed
- Version bump release for crates.io publishing

## 0.1.0 (2026-03-31)

First production-hardened release. Major improvements across all services in
security, performance, scalability, and operational readiness.

### Breaking Changes

- **affinidi-messaging-didcomm 0.13 migration**: `Message.type_` renamed to
  `Message.typ`; `pack_signed` and `unpack_string` replaced with new sync APIs
- **StatsSyncPayload**: Now carries per-DID deltas instead of aggregate totals;
  includes monotonic sequence number for idempotency
- **Stats persistence removed from did-hosting-server**: Stats are in-memory only;
  control plane is the single source of truth
- **DID delete is now soft-delete**: Content preserved for 30-day recovery
  period; hard delete happens via cleanup thread

### New Features

#### did-hosting-common (0.1.0)
- `StatsCollector`: Simplified to per-DID delta tracking with `drain_for_sync()`
  and `record_deltas()` for control plane ingestion
- `ServiceAuth` extractor for service-role-only endpoints
- `Role::Service` ACL role for service accounts
- `DidDocumentOptions`: DID documents now support `keyAgreement` (X25519) and
  `DIDCommMessaging` service endpoints
- `ContentCache`: In-memory TTL cache with Arc-based zero-copy reads
- `didcomm_unpack`: JWS unpacking with DID resolution and message freshness
  validation (5-minute window)
- Prometheus metrics module (behind `metrics` feature flag)
- Session `token_id` (jti) for JWT revocation on refresh
- Store `verify_integrity()` method for startup corruption detection
- `QuotaIndex` for O(1) per-owner DID count and size tracking
- Input bounds validation (DID length, path length)
- Error sanitization — 4xx responses no longer leak internal DIDs/paths

#### did-hosting-server (0.1.0)
- Multi-threaded REST executor (4 Tokio workers)
- DID resolution cache with TTL and write-through invalidation
- Per-DID stats sync to control plane (delta-based, no double-counting)
- Background control plane registration with retry and circuit breaker
- `recreate-did` CLI command for DID regeneration with config update
- `recover-did` CLI command for soft-delete recovery
- DID list pagination (`?limit=N&offset=M`)
- Rate limiting on auth challenge endpoint (10 pending per DID)
- DIDComm mediator discovery from VTA DID document
- Audit logging (`audit=true` field on security-critical events)
- Shutdown timeout (30s) on thread joins
- Store integrity check on startup

#### did-hosting-control (0.1.0)
- Per-DID stats storage with in-memory collector and periodic flush
- Stats sync authentication (ACL validation on incoming payloads)
- Stats idempotency (sequence number deduplication)
- Parallel health checks (tokio::spawn instead of sequential)
- Per-DID stats and timeseries API endpoints
- `ServiceAuth`-protected register-service endpoint
- DID list pagination
- Soft-delete recovery endpoint (`POST /api/recover/{mnemonic}`)

#### webvh-witness (0.1.0)
- Multi-threaded REST executor
- DIDComm API migration (0.13)

#### webvh-watcher (0.1.0)
- HTTP trace logging reduced to DEBUG level

#### did-hosting-daemon (0.1.0)
- Aligned with did-hosting-server AppState changes (cache, signing key)

### Security
- Session fixation prevention via JWT `jti` rotation on refresh
- DIDComm message freshness validation (rejects messages >5 min old)
- Input bounds: DID length capped at 512 bytes
- Auth challenge rate limiting (max 10 pending per DID)
- Stats sync endpoint authenticated against ACL
- Error responses sanitized (no internal DID/path leakage)
- Fjall batch errors logged instead of silently dropped

### Performance
- DID resolution cache reduces store load by ~80% for stable DIDs
- O(1) quota checks via `QuotaIndex` (was O(n) prefix scan)
- Incremental DID count tracking (was O(n) periodic scan)
- Arc-based cache entries avoid cloning large documents
- Empty stats syncs skipped (zero cost when idle)
- DID list pagination prevents unbounded response materialization

### Operations
- Prometheus metrics endpoint (`GET /metrics`, `metrics` feature flag)
- Configuration validation on load (auth TTLs, URL format, DID format)
- Structured audit logging for DID and auth operations
- HTTP trace logging moved to DEBUG level (reduces log noise)
- DID store status logged at startup (count, paths)
- Graceful shutdown with 30s timeout

### Dependencies
- `affinidi-messaging-didcomm` 0.12 → 0.13
- `vta-sdk` switched from local path to crates.io (0.2.x)
- `prometheus` 0.13 (optional, behind `metrics` feature)
