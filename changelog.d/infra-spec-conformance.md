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
