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
