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
