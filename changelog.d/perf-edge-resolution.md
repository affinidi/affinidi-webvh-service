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
