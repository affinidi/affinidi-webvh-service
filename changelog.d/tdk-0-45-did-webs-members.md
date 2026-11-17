### Fixed — a `did:webs` in the ACL is verified by resolving it

A `did:webs` that self-registration made an Owner (a VTA whose own identity
is a `did:webs`, publishing here) was refused on every request after the
first. Its later requests take the ordinary sender-bound path, which
resolves the issuer, and the DID resolver every service builds was compiled
without `did:webs` support, so the signer was reported unreachable. The
resolver now resolves `did:webs` (`affinidi-did-resolver-cache-sdk` with
`did-webs`) on every binary, whether or not it is built with `method-webs`:
that feature decides what this host serves, not whom it accepts requests
from.

`affinidi-did-webs` moves to 0.13.9, which fixes the resolver's comparison of
a service's `type`: a `did.json` carrying `["X"]` where the key event log
designates `"X"` (as every `did.json` this host serves does) failed
resolution with `DocumentMismatch`, so no `did:webs` designating a service
could be resolved, here or by any other client of the same resolver.

Behaviour change (R3.6): resolving a `did:webs` signer fetches its
`keri.cesr` and `did.json` from the identifier's host, under the same host
policy as `did:web` (public hosts only by default). No configuration
changes.

### Breaking — `trust-task-discovery` is answered in 0.4 only

The service speaks the latest version of each task it serves, and
`trust-tasks-rs` 0.39 supersedes `trust-task-discovery/0.3` with 0.4. A
discoverer asking in 0.3 is now refused `unsupportedType` and may retry in
0.4. The 0.4 answer lists the same Type URIs; it states no acceptance
window.

### Changed — dependency generation: TDK 0.45, trust-tasks 0.39, vta-sdk 0.90

`affinidi-tdk` 0.45, `affinidi-messaging-sdk` 0.47 (`-didcomm-service`
0.32), `trust-tasks-*` 0.39, `vta-sdk` 0.90, `vti-common` 0.66, `vti-secrets`
0.39 and `affinidi-crypto` 0.3, the generation `vta-sdk` 0.90 is built
against, so the shipped graph holds one copy of each. The test mediator moves
to 0.52 with them.
