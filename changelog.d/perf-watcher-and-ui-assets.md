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
