### Fixed — `did:webs` registers over `did/register/0.1`

The `did/register/0.1` Trust Task refused every method but webvh ("this host
registers webvh only over this task"), and the REST `POST /api/dids/register`
that took `method: "webs"` has since been removed, so a host built with
`method-webs` had no way left to accept a `did:webs` publication. The task now
takes `method: "webs"` with the `keri.cesr` stream as `didData` and a `domain`,
on a host built with `method-webs`, through the same `register_did_atomic`
that verifies the log and builds the identifier from the slot. A host built
without it refuses `webs` by name, naming the feature. This is how a VTA
publishes the `did:webs` DIDs it creates.
