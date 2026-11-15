### Breaking — a malformed `server.trusted_proxy_cidrs` entry stops the service at startup

An entry that is neither an address nor a CIDR range was logged and dropped,
so a typo silently stopped `Forwarded` / `X-Forwarded-Host` being honoured
from that proxy. The list is now parsed when the config is loaded, like
`trusted_proxies`: a bad entry, or a range covering every address
(`0.0.0.0/0`, `::/0`), is refused, naming the key and the entry. Bare
addresses (`10.0.0.1`) are accepted as one-address ranges.

### Breaking — an invalid `identity.rotation_grace_period` stops the service at startup

A value that was not a duration was logged and treated as `1h`, so a typo in
the compromised-key setting (`"0"`) kept the old key honoured for an hour. It
is now parsed when the config is loaded, like the `[hosting]` grace periods,
and a bad value is refused, naming the key.

### Fixed — the daemon's embedded watcher serves the DIDs in the daemon's store

`GET /watcher/.well-known/did.jsonl` (and every other hosted DID under
`/watcher`) answered `500`: the watcher read the daemon's slot records as its
own record type, which they are not. It now reads only whether a slot is
disabled or deleted, so a hosted DID is served and an unknown, disabled or
deleted one is `404`.

### Fixed — `did-hosting-control setup` tells operators to grant edges the `service` role

The wizard's ACL step said to add each edge with `--role admin`, which
`server/register` refuses. It now says `--role service`, and its admin entry
is offered for operator DIDs only.
