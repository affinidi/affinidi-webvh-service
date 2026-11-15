### Breaking — config files refuse unknown keys, and boolean environment variables refuse values they do not recognise

Every binary's config file is now parsed strictly: a key a section does not
define is a startup error that names it, instead of being dropped while the
default applies. This covers the top level of each binary's config and the
`[server]`, `[store]`, `[fjall]`, `[auth]`, `[secrets]`, `[hosting]`,
`[features]`, `[log]`, `[identity]` and `[vta]` sections, the server's
`[limits]`, `[stats]` and `[replication]`, the control plane's `[registry]`
(and `[[registry.instances]]` / `[[registry.watchers]]`) and `[trust_tasks]`,
the watcher's `[sync]` and the daemon's `[enable]`. A misspelling such as
`[store] redis_ur = …` or `[auth] acess_token_expiry = 300` used to be
ignored; it now stops the service. Before upgrading, run `<binary> health`
against each config: it reports the offending key. One config file shared by
two different binaries no longer loads; give each its own.

Boolean environment overrides (`<PREFIX>_FEATURES_DIDCOMM`, `_TSP`,
`_AGENT_NAMES`, `_HTTP_LISTENER`, `_SECRETS_VAULT_SKIP_VERIFY`,
`_HOSTING_SCID_ALSO_KNOWN_AS`, `_STORE_DYNAMODB_AUTO_CREATE`) accept `1`/`true`/`yes`/`on` and
`0`/`false`/`no`/`off` in any case. Anything else is a startup error naming
the variable; before, `=yes` or `=on` turned the feature off.

`[features] deployment_mode` accepts only `"standalone"` or `"daemon"` (the
values it always had), and `[[registry.instances]] service_type` only
`"server"`, `"witness"` or `"watcher"`; an unknown service type was skipped
at seed time with a warning and is now a startup error.

### Breaking — `[hosting]` grace periods are checked when the config loads

`[hosting] unassigned_purge_grace` and `disable_purge_grace` are parsed when
the config is loaded, by every binary. A value that is not a duration (an
integer with an optional unit `s`, `m`, `h` or `d`) stops the service at
startup with a message naming the key and the accepted units. Before, an edge
silently fell back to 2 hours at unassign time (so `"1w"` purged a domain's
DIDs two hours after an unassign), and the control plane failed "disable
domain" with an internal error weeks later.

### Breaking — CLI defaults renamed: the backup file and the VTA context

`backup` writes `did-hosting-backup.json` by default (was
`webvh-backup.json`), and the default VTA context id for `setup
--setup-key-out --context`, `vta-request --context` and the setup wizards'
context prompt is `did-hosting` (was `webvh`). Pass `--output` / `--context`
(or answer the prompt) to keep the old names; an existing context keeps
working when named explicitly.

### Changed — `health` exits non-zero on a failed check

`did-hosting-server`, `did-hosting-control`, `did-hosting-daemon`,
`webvh-witness` and `webvh-watcher` `health` now exit 1 when any check fails,
or when the config cannot be loaded (before, it always exited 0), so
`health && deploy` and container probes can act on it. `--strict` also fails
on warnings (a store held by the running service, plaintext secrets, a
non-2xx reachability probe). The run ends with a summary line. Colour is used
only when stderr is a terminal and `NO_COLOR` is unset. The store check names
the backend's own location (the data directory for fjall; the server without
credentials for Redis; table prefix and region for DynamoDB; project and
database for Firestore; database and region for Cosmos DB).

### Changed — CLI listings go to stdout; `add-acl` persists before it reports

`list-acl`, `tsp-relationship-list` and `identity-list` print their listings on
stdout (diagnostics stay on stderr), so `list-acl | grep did:` works.
`add-acl` flushes the store before reporting success, as `remove-acl` already
did.

### Changed — `features.rest_api` is now `features.http_listener`

The flag runs the HTTP listener (the UI, `POST /api/trust-tasks`,
`/api/health`), not a REST API, so it is renamed `http_listener` (env
`<PREFIX>_FEATURES_HTTP_LISTENER`). `rest_api` and `<PREFIX>_FEATURES_REST_API`
are still accepted; when both env names are set, `_HTTP_LISTENER` wins. Read by
the control plane, witness and watcher; the edge always serves HTTP.

### Changed — setup wizards check URLs, DIDs and the listen host as they are entered

URL prompts require an `http://` or `https://` URL with a host, DID prompts
(VTA, mediator, control plane, admin, watcher sources) require the
`did:<method>:<id>` shape, and the listen host must be an IP address; a bad
answer is re-asked with the reason instead of failing later at provisioning or
first boot. When the VTA DID cannot be resolved, the wizard says so instead of
silently offering no mediator.

### Changed — `--path` and `--mnemonic` both name a DID slot

`stats-show`, `stats-set`, `bootstrap-did`, `load-did`, `dump-did`,
`recreate-did`, `recover-did` and `remove-did` accept either `--path` or
`--mnemonic`. Messages that suggest a command now name the binary that is
running (`did-hosting-daemon remove-did …` from the daemon).

### Added — `docs/cli-reference.md` and `did-hosting-daemon dump-did`

A complete CLI reference for every binary, generated from the CLI definitions
and kept current by a test. The daemon gains `dump-did`, which the server
already had.

### Fixed — the witness's default port is 8531 everywhere

The witness setup wizard offered 8102 and the setup recipe 8534; both now use
8531, the port the witness's config defaults to.
