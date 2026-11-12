### Added — a `did:webs` can register itself, proved by its own key event log

A `did:webs` does not exist until a host publishes it, so a node whose own
identity is a `did:webs` had no DID to authenticate to this host with before
its first publication. With `method-webs`, a `did/register/0.1` from a
`did:webs` outside the ACL is now accepted on a domain whose operator enables
it, when the request is signed by a current signing key of the identifier as
the submitted `keri.cesr` establishes it (not by resolving it: it does not
exist yet), and `issuer` is the `did:webs:{domain}:{path}:{AID}` the slot
builds. The new slot is owned by the identifier, which is then given an
`Owner` ACL entry scoped to that domain and one slot, so later publications
take the ordinary owner path.

- **`[[hosting.webs_self_register]]`**: `domain`, and optional
  `path_prefixes` and `max_registrations` (default 100, the most
  self-registered identifiers the domain holds at once). Off by default;
  ignored without `method-webs`.
- Webs only: a self-registration of any other method, with `force`, at a slot
  someone else owns, outside the prefixes, or signed by any key but the log's
  is refused. Rate-limited per source (10 a minute) and across all sources (30
  a minute) before the log is verified, and audited with its source
  (`did.webs.self_registered`).

See `docs/did-webs-hosting.md` ("Self-registration").
