# Troubleshooting

> **Status:** current

Symptoms, what they usually mean, and where to look. Log lines are quoted as
the services emit them; turn up detail with `log.level = "debug"` (or
`<PREFIX>_LOG_LEVEL=debug`), and for transport problems
`RUST_LOG=info,affinidi_messaging_sdk=debug,affinidi_messaging_didcomm_service=debug`.

Start with the offline check, which reads the config, the store and the secrets
backend and exits non-zero when something is wrong:

```bash
did-hosting-daemon --config config.toml health          # or -server / -control / webvh-witness / webvh-watcher
did-hosting-daemon --config config.toml health --strict # also fail on warnings
```

## The service will not start

| Message | Cause and fix |
|---|---|
| A config error naming a key | Configs are parsed strictly: an unknown or misspelt key stops the service. Fix or remove it; `health` names it. One config file cannot be shared by two binaries. |
| `invalid <VARIABLE>` | A boolean env var must be `1`/`true`/`yes`/`on` or `0`/`false`/`no`/`off`; numbers and durations must parse. |
| `control_did is not set. did-hosting-server is an edge that a control plane drives …` | An edge needs `control_did` (or `DID_HOSTING_CONTROL_DID`). For one host with no separate control plane, run `did-hosting-daemon`. |
| `server_did is not configured; the control plane signs every reply …` / `the service identity for … could not be loaded` | The control plane signs every reply and refuses to start without a signing identity. Finish setup, or check the secrets backend is reachable and holds this DID's keys. |
| `trust_tasks.enforce_proofs = false is no longer supported` | Remove the setting. |
| `store locked: …` | Another process holds the fjall data directory — usually the running service. Offline CLI commands (`add-acl`, `list-acl`, `identity-*`, `tsp-relationship-*`, `backup`, `restore`, `load-did`, …) need the service stopped. |
| A `STORAGE_FJALL_*` / `[fjall]` error | A byte size that does not parse, is zero, or is below the floor (1 MiB, or 64 MiB for `max_journal`). See [fjall memory settings](bootstrap_startup.md#fjall-memory-settings-store-fjall-only). |
| A secrets-backend error listing the secure backends | The selected backend is not compiled into this binary, or the OS keyring cannot be opened (common in containers). Build with the backend's feature, or configure a cloud backend. |

## A DID does not resolve

1. **Is it in the store the server reads?** On an edge, an edge's store is a
   cache of the control plane's: a DID the control plane does not publish is
   not served, and anything loaded on an edge directly (`load-did`,
   `bootstrap-did`) is deleted the next time the edge registers (only the edge's
   own DID is exempt). Publish through the control plane.
2. **Is the edge current?** `GET /api/health` answers `503` (`"degraded"`) when
   the edge has not reconciled with its control plane within
   `replication.staleness_bound_secs` (300 s). An edge with no mediator logs
   `no messaging service: this edge cannot reconcile with its control plane`
   and reports degraded once the bound passes. See
   [an edge does not register](#an-edge-does-not-register-or-receive-updates).
3. **Is the domain assigned and enabled?** An unassigned or disabled domain's
   DIDs are purged from the edge after the grace period
   (`hosting.unassigned_purge_grace`, `disable_purge_grace`). Check the
   console's **Domains** and **Servers** pages.
4. **Is the DID suspended?** A DID an administrator suspended (`did/set-state`)
   is not served.
5. **Does the identifier match the document?** A root DID is pathless
   (`did:webvh:<scid>:did.example.com`) and is served at
   `/.well-known/did.jsonl`. A `server_did` ending in `:.well-known` was minted
   by an old build and cannot resolve; the service warns about it at boot. It
   must be recreated.
6. **Is a cache in the way?** Resolution responses carry `Cache-Control` from
   `[server.resolve_cache]`; a CDN or resolver may hold an old copy for that
   long. Resolution is also rate-limited per client address
   (`[server.resolve_rate_limit]`, `429` with `Retry-After`).

## A node's own identity looks wrong

| Log | Means |
|---|---|
| `… falling back to #key-0/#key-1 and not persisting` on a restart | The service never established its identity from its own DID document. Check the document resolves from the host itself. |
| `REFUSED to rotate the service identity …` | The published document and the secret store disagree about a key. The service keeps running on the old identity. See the [rotation runbook](identity-rotation-runbook.md). |
| `identity rotated WITHOUT a grace period` | A rotation reused the verification-method fragment; peers holding the old document cannot reach the service until they re-resolve. |

## A Trust Task is refused

Every privileged message is authorised on its own proof. The refusal names the
reason; the common ones:

| Log or error | Cause and fix |
|---|---|
| `trust task refused: sender has no ACL entry` | The signer's DID is not in the ACL. `add-acl` (offline), the console's **Access** page, or `acl/grant/0.2`. |
| `permissionDenied` … `administrator standing` | The task needs the `admin` role. |
| `a metrics-reader credential is not valid for this task` | A `MetricsReader` key may send only `server/metrics/0.1`. |
| `the service is never its own administrator` | The service's own DID cannot administer it. Sign with an operator key. |
| `trust task refused: not bound to its sender` | The proof's `verificationMethod` is not controlled by the document's `issuer`, the `issuer` is missing, the proof purpose or relationship is wrong, or `recipient` is not this service. A `did:key` signer must use its own verification method (`did:key:<mb>#<mb>`). |
| `issuedAt is outside the freshness window` | Clock skew: a document is accepted from up to 5 minutes old to 60 seconds in the future. Check NTP on both ends. |
| `trust task refused: replay cache` / `… rejected: replay` | The same `(issuer, id)` was seen before. Every send must be a freshly built document with a new `id`; `send-trust-task` and the services' own clients do this. |
| `step_up_required` (`required_acr: aal2`) | A destructive task (`did/delete`, `identity/retire`, `registry/purge-domain`) sent with a browser session below `aal2`. Step up in the console (passkey or wallet approval) and retry. A document signed by an admin's key and sent without a session is not affected. |
| `unsupportedType` | The task, or this version of it, is not served. Only the latest version of each task is; see the [catalogue](trust-tasks.md). |
| An HTTPS `403` with no body, from an edge | The edge refused a document that failed its control-plane check — it never answers one, signed or unsigned. Check the sender is the edge's `control_did`. A `503` with `Retry-After` is transient (the signer's DID could not be resolved yet). |

## An edge does not register or receive updates

On the control plane:

| Log | Fix |
|---|---|
| `server registration rejected: DID not in ACL (requires pre-approval)` | `did-hosting-control add-acl --did <edge-did> --role service`. |
| `server registration rejected: Service role required` | The edge's ACL entry must have the `service` role (not `admin`). |
| `server registration rejected: URL host not in registry.url_allowlist` | Add the edge's public host to `[registry] url_allowlist`, or leave it empty (then only private and loopback literal hosts are refused). |
| `register: dropping served_domains entry — …` | The edge reports a domain the control plane does not know or did not assign to it. Assign it, or ignore. |

On the edge:

| Log | Fix |
|---|---|
| `no control_did configured — skipping registration` | Set `control_did`. |
| `timed out waiting for mediator connection — skipping registration` | The edge cannot reach its mediator, or the mediator refuses it. Check `mediator_did` resolves and the edge's own DID resolves (the mediator authenticates it). |
| `control-plane document rejected: …` | A document claiming to be from the control plane failed verification (replay, freshness, wrong signer). |

The control plane's outbox resends unacknowledged updates with backoff and drops
a row after its retry budget (about 3.5 hours of hard failures, about 19 hours of
unacknowledged sends, or 7 days in all). A dropped row is not lost: the edge's
next registration (every 10 minutes, and on every reconnect) resyncs it. The
admin gauges of `server/metrics/0.1` show, per target,
`did_hosting_replication_pending`, `_lag_seconds`, `_last_ack_age_seconds` and
`_last_reconcile_age_seconds`; the counters include
`webvh_outbox_delivery_failures_total`, `webvh_outbox_unacked_resends_total`
and `webvh_outbox_dropped_total`. See [metrics](metrics.md).

## A request over TSP takes about 30 seconds, then works

The sender held a TSP relationship with this service that this service had lost
its half of. The receiver drops a frame with no relationship **silently** (by
design: it sends no "no relationship" signal back), and the sender only
re-invites after its 30-second reply timeout. Look on the **receiving** side
for:

```
WARN affinidi_messaging_didcomm_service::service::listener: Failed to unpack TSP frame … no relationship
```

A log filter can hide this line; raise `affinidi_messaging_didcomm_service` to
`debug` before concluding it is absent. Each side keeps its own half of every
relationship (the mediator holds none). Inspect and reset this service's half,
with the service stopped:

```bash
did-hosting-daemon --config config.toml tsp-relationship-list
did-hosting-daemon --config config.toml tsp-relationship-reset --peer <peer-did>
```

`tsp-relationship-delete --peer <peer-did>` (or `--all --yes`) removes the
records outright. Clear the peer's half too if the problem persists (a VTA has
`vta tsp-relationships`). An edge re-establishes its relationship with the
control plane on every connect.

## Sign-in problems

| Symptom | Cause and fix |
|---|---|
| The passkey prompt never appears | WebAuthn needs `public_url` set and the console served from that origin over `https` (or `http://localhost`). |
| An invite fails after a few attempts | Five wrong claim codes cancel the invite. Mint a new one: `invite --did <did> --role <role>`, or from the console. |
| A wallet sign-in shows no location | No GeoIP database is configured; see [GeoIP](geoip.md). |
| `429 Too Many Requests` on `POST /api/trust-tasks` | The per-address limit. Behind a reverse proxy, set `server.trusted_proxies` so clients are told apart (see [deployment](deployment.md)). |

## Still stuck

Collect the version (`<binary> --version`), the `health` output, and the log
lines around the failure at `debug`, with keys and tokens redacted, and open an
issue at <https://github.com/affinidi/affinidi-webvh-service/issues>.
