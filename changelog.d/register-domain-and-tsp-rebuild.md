### Fixed — `did/register` enforces the caller's `domain` for did:webvh

A `did/register` request naming a `domain` that is not the host of the
did:webvh it publishes is now refused as `did-management:unknown_domain`
before anything is written, as `did/publish` already did. The parameter was
previously accepted and ignored. An omitted domain behaves as before.

### Fixed — `did/register` no longer wipes a did:webvh slot's domain

Registering or re-registering a did:webvh through `did/register` recorded an
empty domain, erasing the one a reserved slot or an earlier publish had set
and hiding the DID from per-domain listings. The record now carries the DID's
host, as every other write path does.

### Fixed — a node picks up TSP on an identity rotation without a restart

The control plane, hosting server, witness and watcher now always start their
messaging service with a TSP handler. Before, a node that booted without TSP
could not dispatch inbound TSP even after a rotation rebuilt its listener for a
DID document that began advertising `TSPTransport`; it needed a restart.
