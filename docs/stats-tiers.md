# Tiered statistics

The control plane (and the daemon's embedded control plane) keeps per-DID
usage statistics: totals, and a time series for the usage chart. Since this
change every DID keeps a cheap **coarse** series, and only busy DIDs, or DIDs
an admin pins, also keep a **fine** 5-minute series. Every row is bounded and
overwritten in place, so nothing ever needs a sweep, and every read is by key,
so a chart costs the same however long the service has run.

## Why

The previous format wrote one `ts:{mnemonic}:{epoch}` row per DID per
5-minute bucket, re-read and rewritten every 10 seconds, and never deleted.
Charts found their rows by scanning the time-series keyspace, which on
DynamoDB is a full-table Scan, and the per-domain chart scanned once per DID.
Storage and read cost grew with the age of the deployment.

## Rows

| Row | Keyspace | Holds | Bound |
|---|---|---|---|
| `stats:{mnemonic}` | stats | totals, plus `coarse`: hourly points (7 days) and daily points (30 days), sparse | one row per DID |
| `t5:{mnemonic}:{slot}` | timeseries | one 5-minute bucket: `{e, r, u}` (start, resolves, updates) | 288 per fine DID (24 hours) |
| `c:_all` | timeseries | the server-wide coarse series, hourly for 30 days | one row |
| `t5:_all:{slot}` | timeseries | the server-wide fine ring (always kept) | 288 |
| `statspin:{mnemonic}` | stats | a DID's override, when not `auto` | one row per pinned DID |
| `meta:stats-migration` | timeseries | the migration marker | one row |

`slot` is `(epoch / 300) % 288`. A slot write whose bucket is newer than the
one the slot holds replaces it; that is the whole of the ring's upkeep. A
reader treats a slot holding a different bucket from the one it asked for as
empty.

The coarse series is sparse — `[[hour, resolves, updates], …]` — and pruned
to its window on every write. A DID resolved in three hours of the week stores
three points. The `stats:` row stays readable as the old `DidStats` (the
series is under a separate `coarse` key), so older readers and older binaries
still see the totals.

## Writes

The collector keeps 5-minute buckets in memory. The periodic flush (every
10 seconds, paced by `[stats_flush]`) writes only what is **due**: buckets
that have closed, and the totals of the DIDs they belong to. So a DID is
written at most once per 5 minutes however busy it is, and a DID whose only
activity is in the open bucket waits for it to close. The shutdown flush
writes everything, open buckets included; every write adds to what is
stored, so a partial bucket is safe.

For each due DID the flush reads its `stats:` row, adds the totals and the
buckets to the coarse series, decides the tier (below), and writes the row
back with the decision recorded (`fine_since`). If the DID is fine, each
bucket is then written into its ring slot. A slot write that fails is retried
on its own, so the row, already written, never counts a bucket twice.

## Tiers

| Tier | Keeps | Chart |
|---|---|---|
| `fine` | coarse + 5-minute ring | 5-minute points for the last hour and day; hourly for 7 days; daily for 30 |
| `coarse` | coarse | hourly for the last hour, day and 7 days; daily for 30 |
| `off` | totals only | empty |

The response's `bucketSeconds` says which, so the UI's rate maths follows.
The server-wide series is always fine; over 30 days it is charted in 4-hour
steps from its 30-day hourly series. A domain chart sums its DIDs' coarse
series (one row read per DID).

A DID uses its fine ring for a window only if it has been fine since before
the window starts; otherwise that window is charted from the coarse series,
so a newly promoted DID's chart never shows a gap.

### Automatic promotion

With `[stats] mode = "auto"` (the default), each time a DID's row is written:

- **Promote** when the current or previous hour holds at least
  `promote_per_hour` resolves (default 60, about one a minute) and fewer
  than `max_fine_dids` DIDs (default 1,000) are promoted automatically.
- **Demote** when both the last hour and the last 24 hours' average are below
  `demote_per_hour` (default 20). A burst keeps its detail for the day it is
  on the chart.

The promoted set is in memory and rebuilt from the rows (`fine_since`) as
they are written after a restart. `mode = "fine"` gives every DID 5-minute
detail, with no cap; `mode = "coarse"` gives it to none (except pinned DIDs).

```toml
[stats]
mode = "auto"           # auto | fine | coarse
promote_per_hour = 60
demote_per_hour = 20    # must be below promote_per_hour
max_fine_dids = 1000
```

Environment: `CONTROL_STATS_MODE`, `CONTROL_STATS_PROMOTE_PER_HOUR`,
`CONTROL_STATS_DEMOTE_PER_HOUR`, `CONTROL_STATS_MAX_FINE_DIDS` (and the
`DAEMON_STATS_*` equivalents).

### Per-DID override

| Resolution | Effect | Who may set it |
|---|---|---|
| `auto` | the policy above (the default; stored as no row) | owner or admin |
| `fine` | always 5-minute detail, not counted against the cap | **admin only** |
| `coarse` | never promoted | owner or admin |
| `off` | totals only | owner or admin |

`fine` is admin-only because it costs writes and bypasses the cap; an owner
can only ask for less detail about their own DID.

The override is set by `stats_admin::set_stats_resolution` (the authorisation
lives there) and, offline, by the `stats-set` command. A Trust Task for it,
`did-management/did/set-stats-resolution`, needs its spec in the trust-tasks
registry first; until then the CLI is the operator's path. The running
service loads overrides at startup; another control-plane replica sees a
change at its next start.

## Costs

Per DID-hour with activity, on a store where every row is a read and a write:

| | Before | After |
|---|---|---|
| Quiet DID, a few resolves in different 10-second windows | one read + one write per window, for the totals and the bucket each | at most one read + one write per 5 minutes with activity |
| Busy DID | about 720 reads + 720 writes | at most 12 row writes + 12 slot writes, each a read and a write |
| Storage per DID | grows forever | one row; plus 288 small rows when fine |
| Chart read | a full-table Scan (one per DID for a domain) | one `GET`; 12 or 288 `GET`s for a fine window |

On DynamoDB, units follow item size: a write is one unit per KB. A ring slot
and a new DID's row are about 100 bytes, one unit each. A DID's row grows with
its points, to about 3 KB for a DID active in every hour of the week (168
hourly and 30 daily points), so writing it costs up to about three units; the
server-wide `c:_all` row (720 hourly points) is about 13 KB, written once per
5 minutes. A read is one unit per 4 KB, strongly consistent. So for a DID
resolved about once per 5 minutes all week the write units are similar to or
somewhat above the previous format's (two one-unit rows); the saving is for
busier DIDs, and in reads and storage.

## Migration

Automatic, idempotent, and safe to roll back.

1. **Coexistence.** New rows use new keys (`t5:`, `c:_all`) or a new field
   (`coarse`) that older readers ignore. Nothing writes `ts:` any more. Edges
   are unaffected: they keep no time series.
2. **Backfill, once.** At startup, if the marker is missing or incomplete,
   the storage task reads `ts:` once, a page of 1,000 rows at a time in key
   order (a backend that cannot list in key order, a hash-ordered Scan, is
   read whole, and after a failed read waits 5 minutes before reading again),
   and, a flush's worth at a time between flushes, adds each
   series' legacy buckets to its coarse series (and, for a
   series that is fine, the last day's to its ring). Each series records the
   legacy buckets it has taken (`migrated_through`), so a restart part-way, a
   second run, or two replicas overlapping never count a bucket twice. Series
   for DIDs that no longer exist are skipped. Totals are not touched: the old
   format already kept them in the same row. One replica runs it, holding an
   hourly lease (`meta:stats-migration-lease:{hour}`).
3. **Charts during the backfill** are read from the legacy rows; once the
   marker records completion they are read from the new rows.
4. **Legacy rows are kept for 30 days** after completion, then deleted, paced
   and resumably, reading their keys a page at a time. `stats-purge-legacy` deletes them at once.
5. **Rollback.** An older binary rolled back to within the 30 days finds its
   `ts:` rows, missing only what was counted since the upgrade, and its
   rewrites of `stats:` rows drop their `coarse` series. On the next upgrade
   the startup check finds server-wide `ts:` buckets newer than the marker's
   completion and runs the backfill again: rows whose series was dropped are
   rebuilt from the legacy rows, and series that kept theirs take only what
   the older binary wrote. Restoring a backup from before the upgrade is the
   same as a first upgrade.

## CLI

Offline (stop the service first), on both `did-hosting-control` and
`did-hosting-daemon`:

- `stats-show --mnemonic <m>` — the override, recorded tier and totals.
- `stats-set --mnemonic <m> --resolution <auto|fine|coarse|off>`.
- `stats-purge-legacy` — finish the backfill and delete the legacy rows now.

## Limits

- Rows are still a read and a write each. DynamoDB's `ADD` (the store already
  uses it for `incr_raw`) would make them one write and safe for several
  writers; that needs a multi-field increment in the store trait.
- The flush assumes one writer per stats row, as before: two control-plane
  replicas flushing the same DID can lose an update.
- DIDs removed by the domain purge sweep or the empty-slot cleanup leave their
  `stats:` row behind, as before; an explicit delete removes all of a DID's
  statistics rows.
