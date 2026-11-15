# Metrics

> **Status:** current — names are from `did_hosting_common::server::metrics` and the `server/metrics` handlers.

No service exposes an unauthenticated scrape endpoint (there is no
Prometheus `/metrics`). Operational numbers are read with the signed
`did-management/server/metrics/0.1` Trust Task, so only a party in the ACL
can read them. Per-DID usage statistics (resolution counts and the usage
chart) are a separate thing: see [stats-tiers.md](stats-tiers.md).

## Who can read what

| Caller (ACL role) | Gets |
| --- | --- |
| `metricsReader` | `counters` only. The role can do nothing else: every other task refuses it. |
| `admin` | `counters` and `gauges` (the replication gauges below). |
| the control plane, asking its edge | the edge's replication gauges and counters (an edge has no ACL; it answers its `control_did` only). |

Grant a scraper its own `did:key` with the `metricsReader` role rather than
using an admin key.

## The `metrics` build feature

The **counters** exist only in a binary built with the `metrics` feature
(`did-hosting-server`, `did-hosting-control` and `did-hosting-daemon` each
have one; it is off by default). Without it the task still answers, with an
empty `counters` array. The replication gauges do not depend on the feature.

```bash
cargo build --locked -p did-hosting-daemon --release --features metrics
```

## Reading counters: `fetch-metrics`

`did-hosting-control fetch-metrics` and `did-hosting-daemon fetch-metrics`
sign a `server/metrics/0.1` request with a `did:key`, post it to the running
service's `POST /api/trust-tasks`, verify that the reply is signed by the
service's own DID, and print the counters as JSON on stdout:

```bash
# 1. Mint a did:key file. `setup --setup-key-out` writes one (and prints a
#    VTA enrolment command you can ignore here); any Ed25519 did:key in the
#    same JSON format works.
did-hosting-daemon setup --setup-key-out metrics-key.json --context metrics

# 2. Grant it the metricsReader role (offline, before or between runs) …
did-hosting-daemon add-acl --did "$(jq -r .did metrics-key.json)" --role metricsReader
#    … or, on a running service, with an acl/grant Trust Task.

# 3. Scrape.
did-hosting-daemon fetch-metrics --key metrics-key.json
# [{"name":"webvh_resolves_total","value":1234.0}, …]
```

`--url` overrides the endpoint (default: `http://<server.host>:<server.port>`
from the config, a wildcard bind dialled as loopback). An ungranted or
revoked key is an error, not an empty array. Feed the output to your
monitoring agent on a timer.

`fetch-metrics` prints counters only. An administrator reads the gauges by
sending the same task with an admin key
([sending-trust-tasks.md](sending-trust-tasks.md)).

## Counters

All monotonic, since process start, per process.

| Name | Counts |
| --- | --- |
| `webvh_resolves_total` | DID resolutions served. |
| `webvh_updates_total` | DID log updates accepted. |
| `webvh_auth_challenges_total` | Sign-in challenges issued. |
| `webvh_auth_successes_total` | Successful sign-ins. |
| `webvh_auth_failures_total` | Failed sign-ins. |
| `webvh_cache_hits_total` | Resolution content-cache hits. |
| `webvh_cache_misses_total` | Resolution content-cache misses. |
| `webvh_stats_syncs_total` | Statistics syncs (edge → control plane). |
| `webvh_outbox_enqueue_failures_total` | Outbox rows that could not be enqueued (the change reaches the target only on its next registration). |
| `webvh_outbox_delivery_failures_total` | Outbox sends that failed hard (transport refused, or could not be built). |
| `webvh_outbox_unacked_resends_total` | Outbox entries re-sent because the target did not acknowledge in time. |
| `webvh_outbox_dropped_total` | Outbox entries dropped past their retry budget. Alert on any increase. |
| `webvh_outbox_record_failures_total` | Times the outbox failed to record a send, failure or settle. |

An edge's reply also carries `did_hosting_replication_repaired_total`:
slots its reconcile repaired (a missed disable fixed on the spot).

## Gauges

### On the control plane (admin only), one set per registered edge

Each carries the label `edge` (the edge's DID).

| Name | Meaning |
| --- | --- |
| `did_hosting_replication_pending` | Outbox entries queued for the edge and not yet acknowledged. |
| `did_hosting_replication_lag_seconds` | Age of the oldest of them (0 when none). |
| `did_hosting_replication_last_ack_age_seconds` | Seconds since the edge last acknowledged anything. |
| `did_hosting_replication_last_reconcile_age_seconds` | Seconds since the edge last started a reconcile against `did/list`. |

### On an edge (read by its control plane)

| Name | Meaning |
| --- | --- |
| `did_hosting_replication_reconcile_age_seconds` | Seconds since the last clean reconcile (or since start). |
| `did_hosting_replication_staleness_bound_seconds` | The configured `[replication] staleness_bound_secs`. |
| `did_hosting_replication_fresh` | `1` while within the bound (`/api/health` is `200`), `0` past it (`503`). |
| `did_hosting_replication_stale_slots` | Slots the last reconcile found behind or missing. |
| `did_hosting_replication_last_reconciled_at` | Unix time of the last clean reconcile, when there has been one. |

## Suggested alerts

- `webvh_outbox_dropped_total` increases: a change was given up on; the
  target recovers on its next registration or reconcile, but find out why.
- `did_hosting_replication_lag_seconds` above a few minutes, or
  `did_hosting_replication_last_ack_age_seconds` growing, for one edge: that
  edge is unreachable or refusing.
- An edge's `/api/health` returning `503` (its `did_hosting_replication_fresh`
  is `0`).
- `webvh_auth_failures_total` rising sharply against
  `webvh_auth_successes_total`.
