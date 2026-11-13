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

### Breaking — `did-hosting-common` storage backends implement `compare_and_swap_raw`

`KeyspaceOps` has a new required method, `compare_and_swap_raw(key,
expected, new)`, exposed as `KeyspaceHandle::compare_and_swap_raw`: it
writes only if the key holds `expected` (`None`: is absent), atomically
across processes on Redis (a Lua script), DynamoDB (a conditional
`PutItem`), Cosmos DB (create, or `If-Match` replace) and Firestore (a
transaction). An out-of-tree `KeyspaceOps` implementation must add it.
`webvh_witness::witness_ops::sign_witness_proof` no longer takes the mark to
record; call `read_witnessed_mark` and `advance_witnessed_mark` first.
