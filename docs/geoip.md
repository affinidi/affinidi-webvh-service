# GeoIP: sign-in locations

When someone signs in to the management UI with their wallet (`auth/oob`),
the wallet shows them where the sign-in request came from — the
`requester.location` of `auth/oob` step 2, for example `Vienna, AT`. The
control plane (standalone, or embedded in `did-hosting-daemon`) works that
out from the requesting browser's address with a **local database file
only**. It never calls a third-party service (base design §12.6), so the
address never leaves the service. This is the same lookup the VTC does
(`verifiable-trust-infrastructure` `docs/03-vtc/geoip.md`), so a wallet sees
the same thing from either.

Without a database every location is `unknown`, which the wallet shows as a
warning rather than as neutral. Configuring one is optional, but recommended.

## What it shows

- `City, CC` — the English city name and the ISO 3166-1 country code
  (`London, GB`, `Frankfurt am Main, DE`).
- The English country name alone (`Sweden`) when the record has no city.
- `unknown` when no database is loaded, the database has no record for the
  address, or the address is not a public one: private (`10/8`,
  `172.16/12`, `192.168/16`), loopback, link-local, carrier-grade NAT
  (`100.64/10`), IPv6 unique-local (`fc00::/7`), documentation, benchmarking,
  multicast and reserved ranges are never looked up in the database — name
  them yourself if you want them shown (see "Naming your own networks").
  Behind a reverse proxy, list the proxy in `[server] trusted_proxies` (see
  "Behind a reverse proxy") so its `X-Forwarded-For` is honoured; otherwise
  every request comes from the proxy's (usually private) address and every
  location is `unknown`.

The result is at most 128 characters, the limit the `auth/oob` schema sets.
Only that coarse result is kept, in the sign-in request while it is open;
the lookup logs and stores nothing about the address.

## Choosing a database

Any MaxMind DB (`.mmdb`) file with the GeoIP2 **City** record layout works.
Two free ones:

| Database | Licence | Notes |
|---|---|---|
| **DB-IP "IP to City Lite"** (recommended) | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — attribution required | Direct download, no account. Updated monthly. |
| MaxMind **GeoLite2 City** | [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula) | Needs a free MaxMind account and licence key. Updated twice weekly. |

### DB-IP City Lite

The file for a month is
`https://download.db-ip.com/free/dbip-city-lite-YYYY-MM.mmdb.gz`
(about 60 MB compressed, 130 MB unpacked):

```sh
sudo mkdir -p /var/lib/did-hosting/geoip
cd /var/lib/did-hosting/geoip
curl -fsSLo dbip-city-lite.mmdb.gz \
  "https://download.db-ip.com/free/dbip-city-lite-$(date -u +%Y-%m).mmdb.gz"
gunzip -f dbip-city-lite.mmdb.gz        # → dbip-city-lite.mmdb
```

**Attribution.** DB-IP Lite is licensed under CC BY 4.0, which requires
crediting DB-IP wherever the data is used. Their requested form is:

> IP Geolocation by [DB-IP](https://db-ip.com)

The service does not display this for you. Carry it wherever you publish
your privacy notice or legal pages.

### MaxMind GeoLite2 City

Sign up at <https://www.maxmind.com/en/geolite2/signup>, create a licence key,
and download `GeoLite2-City.mmdb` — by hand, or with MaxMind's
[`geoipupdate`](https://github.com/maxmind/geoipupdate) tool, which also keeps
it current. Point the service at the `.mmdb` file exactly as below. GeoLite2's
EULA has its own attribution and data-retention terms; read them before use.

## Configuring the service

In the control plane's or daemon's `config.toml`:

```toml
[geoip]
database = "/var/lib/did-hosting/geoip/dbip-city-lite.mmdb"
```

or in the environment, which overrides the file (an empty value turns it
off): `CONTROL_GEOIP_DATABASE` for `did-hosting-control`,
`DAEMON_GEOIP_DATABASE` for `did-hosting-daemon`.

```sh
DAEMON_GEOIP_DATABASE=/var/lib/did-hosting/geoip/dbip-city-lite.mmdb
```

Only the control plane answers wallet sign-in, so an edge server, witness or
watcher has no `[geoip]`. Setup does not write the table.

The file must be readable by the user the service runs as. At startup the
log says `GeoIP database loaded` with the database type and build time. If
the file is missing or is not a valid `.mmdb`, the service logs a **warning**
and starts anyway, with every location `unknown`: a location is advisory,
and sign-in works without it. Leaving `[geoip]` out keeps every location
`unknown`.

The service reads the whole file into memory (about the size of the unpacked
file), and briefly holds two copies while a new version loads.

## Naming your own networks

A public database cannot place an office LAN, a VPN pool or any other private
range, so a sign-in from one shows as `unknown`. Name them instead:

```toml
[[geoip.networks]]
cidr = "10.20.0.0/16"
location = "Sydney office"

[[geoip.networks]]
cidr = "fd00:1::/32"
location = "Corporate VPN"

[[geoip.networks]]
cidr = "203.0.113.10"         # a single address: the office's public egress
location = "Sydney office"
```

- `cidr` is a CIDR range or a single address; `location` is what the wallet
  shows, at most 128 characters.
- These are checked **before** the database, for any address, private or
  public, so a named public address overrides the database's answer.
- When ranges overlap, the most specific (longest prefix) wins, whatever the
  order in the file.
- They work with or without `database`. A bad range or label stops the
  service at startup with the entry named; changes need a restart.

This is specific to the hosting service; the VTC has no equivalent.

## Behind a reverse proxy

The location is only as good as the client address. Behind a load balancer
or reverse proxy, the TCP peer is the proxy, so list your proxies — single
addresses or CIDR ranges, like the VTC's `trust_xff_cidrs`:

```toml
[server]
trusted_proxies = ["10.0.0.0/16", "2001:db8:100::/48"]
```

When a request comes from one of them, the service walks `X-Forwarded-For`
from the right, skips every hop that is itself a trusted proxy, and uses the
first address that isn't. Anything doubtful — no header, a malformed entry,
a chain of more than 64 entries, or one trusted end to end — falls back to
the proxy's own address. List only proxies that append to (or overwrite)
`X-Forwarded-For`, and never a layer-4 (TCP) forwarder, which passes the
client's own header through: that lets anyone choose their address. The
same setting drives every per-address rate limit, on every service.

## Keeping it current

The service checks the file's modification time and size once a minute and
re-reads it when either changes, so a refreshed database is picked up
**without a restart**. If the new file cannot be read — a half-finished
download, say — the service warns and keeps using the version it already has.

Replace the file atomically: write the new one beside it and `mv` it into
place, so the service never reads a partial file. A monthly cron job for DB-IP
(the file for a month appears on its first days; this runs on the 3rd):

```sh
# /etc/cron.d/did-hosting-geoip
15 4 3 * * did-hosting /usr/local/bin/did-hosting-geoip-update
```

```sh
#!/bin/sh
# /usr/local/bin/did-hosting-geoip-update — fetch this month's DB-IP City Lite.
set -eu
dir=/var/lib/did-hosting/geoip
tmp=$(mktemp "$dir/.dbip.XXXXXX")
trap 'rm -f "$tmp" "$tmp.gz"' EXIT
curl -fsSLo "$tmp.gz" \
  "https://download.db-ip.com/free/dbip-city-lite-$(date -u +%Y-%m).mmdb.gz"
gunzip -c "$tmp.gz" > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$dir/dbip-city-lite.mmdb"
```

In Kubernetes, the same script fits a `CronJob` writing to a volume the
service mounts read-only; it picks the new file up within a minute of the `mv`.
