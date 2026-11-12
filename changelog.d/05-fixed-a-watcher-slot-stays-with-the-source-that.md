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
