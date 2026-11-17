### Deprecated — edge settings nothing reads

`did-hosting-server` accepts several settings it never reads: `features.http_listener`
(an edge always binds its HTTP listener), `[limits] default_max_total_size` and
`default_max_did_count` (per-account quotas are the control plane's, never an edge's,
along with their `DID_HOSTING_LIMITS_DEFAULT_MAX_*` environment overrides), and every
`[auth]` key except `cleanup_ttl_minutes`. They still load, but the server now logs a
warning naming each one set to a non-default value, and the two `[limits]` keys are no
longer written back. Remove them from edge configs; a later release will refuse them.

### Changed — the control plane no longer records `trust_task_capable` for a server

Every health ping has been a signed trust task for some time, so the registry flag
that once chose between a trust-task ping and the legacy `MSG_HEALTH_PING` was stored
but never read. It is gone from the registry record, and edges no longer send the
`trust_task_capable` registration hint (a control plane that receives it from an older
edge ignores it, as it does any unknown hint).

### Changed — one did.jsonl parser for every did:webvh path

Validation, the publish and serve verifiers, witnessing and identity rotation now
share a single parse of a `did.jsonl` instead of five copies, and a publish no longer
parses every entry twice before checking signatures. Each line is read under the
method version of the entry before it, and a malformed `versionId` is refused by plain
validation too, as every verifier already did.

### Changed — the management UI package is named `did-hosting-ui`

The UI's `package.json` name and Expo slug were still `webvh-ui`.
