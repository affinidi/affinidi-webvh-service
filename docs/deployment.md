# Deployment and hardening

> **Status:** current

How to put the DID Hosting binaries on a network: what each one listens on,
what to put in front of it, and the settings that change behind a proxy.
Every key named here is in [configuration.md](configuration.md); how the
pieces relate is in [architecture.md](architecture.md).

## Choose a topology

- **One host: `did-hosting-daemon`.** Control plane, hosting server, witness
  and (optionally) watcher in one process, on one port and one store. This
  is the recommended deployment unless you need edges in several places.
- **Distributed:** one `did-hosting-control` (the authoritative store and
  the console), one or more `did-hosting-server` edges serving resolution,
  optionally a `webvh-witness` and `webvh-watcher`s. Edges are caches: each
  can be wiped and rebuilt from the control plane.

The repository ships no container images, Helm charts or unit files; the
sketches below are starting points.

## Ports

| Binary | Default port | Must be reachable by |
| --- | --- | --- |
| `did-hosting-server` | 8530 | Everyone who resolves DIDs (public), and its control plane if the edge's DID advertises an HTTPS Trust Task endpoint |
| `webvh-witness` | 8531 | The parties that request witness proofs (control plane, VTAs) |
| `did-hosting-control` | 8532 | Operators' browsers (console), VTAs and other publishers, wallets during sign-in |
| `webvh-watcher` | 8533 | Everyone who resolves through it (public), and its source control planes over HTTPS when it advertises that |
| `did-hosting-daemon` | 8534 | All of the above, on one port |

Inter-node traffic normally rides the mediator (TSP or DIDComm), which every
node dials out to; HTTPS is used between nodes only when a node's DID
document advertises a `TrustTaskHTTPS` endpoint, or the node has no mediator.

## TLS termination

**No binary terminates TLS.** Each listens in plain HTTP; put a reverse
proxy or load balancer that terminates TLS in front of every listener that
leaves the host.

- `public_url` (and a DID's host) must be the `https://` origin the proxy
  serves. `did:webvh` and `did:web` resolve over HTTPS only, and the
  control plane's passkey sign-in needs a secure origin (a browser accepts
  `http://localhost` and nothing else in plain HTTP).
- Every response already carries `Strict-Transport-Security`, a
  restrictive `Content-Security-Policy`, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`; the
  proxy should not strip them. Resolution responses set their own
  `Cache-Control` (`[server.resolve_cache]`) and allow any origin (CORS) so
  browser resolvers can read them; everything else is `no-store`.
- Edges and watchers answer resolution with an `ETag` and honour
  `If-None-Match` (`304 Not Modified`), and compress responses (gzip or
  brotli) for clients that accept it; the console's assets are compressed
  and cacheable too. A proxy may pass these through or cache on them, but
  must not rewrite the body of an uncompressed response it then forwards
  with the original strong `ETag`.
- Allow request bodies of at least **1 MiB** on `POST /api/trust-tasks`
  (edge and watcher; a control plane's `did/register` can be as large), and
  do not buffer responses indefinitely.
- Keep the proxy's own connection and rate limits. The built-in limits (at
  most 256 concurrent connections, 32 per IPv4 address or IPv6 /64, a
  20-second header deadline, a 60-second idle timeout, a 30-second body
  deadline on Trust Task posts) are a backstop, not a replacement.

## Two proxy lists

Behind a proxy, two separate `[server]` lists tell a service which peers to
believe, for two different questions. List your proxies in **both**; the
edge and the daemon warn at startup when only one is set.

| Key | Question it answers | Headers it trusts | Read by | Bad entry |
| --- | --- | --- | --- | --- |
| `trusted_proxies` | Who is the **client**? (per-address rate limits, connection caps, GeoIP for wallet sign-in) | `X-Forwarded-For` | every binary | refused at load |
| `trusted_proxy_cidrs` | Which **host** does the request address? (which hosting domain, and so which DIDs, a resolution sees) | `Forwarded` (RFC 7239), `X-Forwarded-Host` | the edge, and the daemon's resolution | refused at load |

Both take addresses or CIDR ranges. List only ranges from which nothing
but the proxy can reach the service: any other peer in the list can name
its own client address or its own host. A range covering every address
(`0.0.0.0/0`, `::/0`) is refused. With neither set (the default), the TCP
peer is the client and the literal `Host` header is the host — correct with
no proxy, or behind a CDN that rewrites neither.

Signs you got it wrong: every client shares one rate-limit budget and
`429`s arrive together (`trusted_proxies` unset behind a balancer); a
multi-domain edge serves the wrong domain's DIDs or 404s them
(`trusted_proxy_cidrs` unset while the proxy rewrites `Host`).

`server.client_ipv6_prefix` (default 64) sets how many bits of an IPv6
client's address identify it in every per-address limit.

## What to expose, per binary

- **Edge (`did-hosting-server`)**: the resolution paths (`/.well-known/*`,
  `/{path}/did.jsonl`, `/did-witness.json`, `/did.json`, `/keri.cesr`,
  `/@…`) publicly; `/api/health` to your load balancer;
  `POST /api/trust-tasks` only if the edge's DID advertises HTTPS for its
  control plane. Nothing else is served.
- **Control plane**: the console (any non-API path),
  `POST /api/trust-tasks`, `POST /api/auth/challenge`,
  `GET /api/sign-in/readiness`, `GET /api/health`. The control plane is the
  single most sensitive endpoint in the system and is deliberately not
  discoverable from the DIDs it manages (see
  [architecture.md](architecture.md#the-control-plane-is-never-advertised)).
  Reach it on its own hostname, and restrict it at the network edge to the
  operators, publishers (VTAs) and wallets that need it where you can.
- **Witness**: `POST /api/trust-tasks` and `/api/health`, to the parties
  that request proofs.
- **Watcher**: its resolution paths publicly; `POST /api/trust-tasks` to
  its sources if it advertises HTTPS; `/api/health`.
- **Daemon**: all of the control plane's and the edge's paths at the root,
  `/witness/api/trust-tasks`, `/watcher/…` when the watcher is enabled, and
  `/health`.

## Health checks

- `GET /api/health` on the edge answers `503` when its own DID is not
  served locally, or when it has not completed a clean reconcile with its
  control plane within `[replication] staleness_bound_secs` (default 300 s):
  point the load balancer at it so a stale edge is drained. A restart resets
  the staleness clock, so also alert on restart loops.
- `GET /api/health` on the control plane, witness and watcher, and `GET
  /health` on the daemon, are liveness probes.
- `<binary> health [--strict]` is an offline diagnostic for an operator or a
  pre-start hook: it exits non-zero when a check fails (`--strict`: also on
  a warning).

## Secrets

Use a real secrets backend in production — the OS keyring on a single host,
or a cloud secret manager, HashiCorp Vault or a Kubernetes `Secret` in a
cluster (build with the matching feature). `backend = "plaintext"` is for
tests and refuses to run without `confirm_plaintext = true`. The witness
(and the daemon's embedded witness) keeps a second entry, its key-encryption
key, beside the service keys; its credentials need permission to create and
read it. Back both up (see [backup-and-upgrade.md](backup-and-upgrade.md)).

## Running under systemd

A sketch for a daemon on one host:

```ini
# /etc/systemd/system/did-hosting-daemon.service
[Unit]
Description=DID Hosting daemon
After=network-online.target
Wants=network-online.target

[Service]
User=did-hosting
Group=did-hosting
WorkingDirectory=/var/lib/did-hosting
ExecStartPre=/usr/local/bin/did-hosting-daemon --config /etc/did-hosting/config.toml health
ExecStart=/usr/local/bin/did-hosting-daemon --config /etc/did-hosting/config.toml
Environment=DAEMON_LOG_FORMAT=json
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/did-hosting
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

The OS-keyring backend needs a Secret Service (or Keychain) reachable by
that user; on a headless server prefer a file-free backend such as Vault, or
run the keyring under the service user's session. The daemon stops cleanly
on `SIGTERM`.

## Containers and Kubernetes

- Bind `0.0.0.0` inside the container and terminate TLS at the ingress;
  list the ingress's pod or node ranges in both proxy lists.
- Size the pod's memory limit with the fjall caps in mind
  (`[fjall]` / `STORAGE_FJALL_*`: block cache, write buffer, journal), or
  use an external store backend.
- Keep `data_dir` (fjall) on a persistent volume. Run **one** process per
  fjall directory; fjall locks it.
- A watcher must be the only watcher process on its store. Witness replicas
  may share an external store (their per-DID marks are compare-and-swapped).
- Probe `/api/health` (or the daemon's `/health`) for readiness and
  liveness.

## Logging

`[log] format = "json"` (or `<PREFIX>_LOG_FORMAT=json`) for log
aggregation; `RUST_LOG` overrides `[log] level` with a full filter. Logs
never carry private keys, invite tokens or claim codes.

## Related

- [configuration.md](configuration.md) — every key and variable.
- [metrics.md](metrics.md) — reading the counters.
- [troubleshooting.md](troubleshooting.md) — symptoms and fixes.
- [geoip.md](geoip.md) — sign-in locations behind a proxy.
