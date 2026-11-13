### Fixed — a republish of the same did:webvh must extend the stored log

`did/register` and `did/publish` used the stored log only to count its
entries. A log for the same DID (same SCID) that was shorter than the stored
one, or diverged from it, was stored, while every edge refused it
(`verify_history`) and kept serving the previous log. The control plane now
refuses it with the same rule: the stored entries, unchanged, then any new
ones. A different DID in the slot is still a replacement, not compared.

### Fixed — an admin takeover releases the previous holder's parked agent names

A forced takeover (`did/register` with `force`) carried every agent name of
the previous record to the new owner, parked names included. Parked names
the new document does not claim are now released with their index entries;
names the new document claims are registered as before.

### Fixed — a witness publishing again replaces its proof

`webvh/witness/publish` appended each proof to the version's entry in
`did-witness.json`, so a witness that published twice was stored twice. A
proof from a witness that already has one for the version now replaces it.

### Changed — the control plane's HTTPS listener is bounded like the edge's

The control plane served `axum::serve` with no header or idle timeout and no
connection cap. It now uses the shared listener limits the edge, witness and
daemon use (256 connections, 32 per address or IPv6 /64, 20 s for request
headers, 60 s idle; `server.trusted_proxies` exempt from the per-address
cap). `POST /api/trust-tasks` reads its body within 30 s (`408` otherwise),
on the control plane and in the daemon.

### Changed — infrastructure messages from edges are typed and checked against the registry

- `server/stats-sync` is parsed as a closed type; an unknown member refuses
  the sync (`e.p.stats.malformed`). A delta whose resolve or update count is
  over 1,000,000,000 is skipped, and the stats totals saturate instead of
  wrapping.
- `replica/domain/*` acknowledgements that are not their task's response
  type are ignored.
- Two server DIDs can map to one registry id (`did:web:h:a_b`,
  `did:web:h:a:b`). A registration under an id another DID registered is
  refused (`e.p.registration.conflict`), and a health pong, domain
  acknowledgement or replication record from the other DID no longer
  updates that instance.
- A server's `servedDomains` claim at registration is kept only for a domain
  the control plane assigned to that server (its latest recorded domain
  operation is an assign). A server with no recorded domain operation keeps
  only domains the registry already listed for it.

### Changed — refusal texts no longer carry internal detail

A proof that does not verify is refused `proofInvalid` with the kind of
failure (malformed, unsupported cryptosuite, key not the issuer's, bad
signature), not the verifier's own message; the message is logged. A
registration the store cannot write is refused with a fixed text, and asks
for a retry when the store is throttled.
