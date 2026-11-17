# CLI reference

> **Status:** current — generated from each binary's clap definition.

<!-- Generated from each binary's clap definition. Do not edit by hand: run
     `UPDATE_CLI_REFERENCE=1 cargo test -p <crate> --bin <binary> cli_reference`
     (see did-hosting-common/src/cli_reference.rs). -->

Every subcommand of every binary, with its full `--help`. The global
`-c, --config <PATH>` option is accepted by every subcommand.

<!-- BEGIN did-hosting-server -->
## `did-hosting-server`

```text
DID Hosting Server

Usage: did-hosting-server [OPTIONS] [COMMAND]

Commands:
  setup                    Run interactive setup wizard to generate config.toml
  uninstall                Teardown a server install: clears managed secrets from the configured backend, removes the config file (and `.bak`)
  health                   Run health check diagnostics. Exits non-zero when a check fails (or, with --strict, warns), so it can gate a deploy or a container probe
  backup                   Export server data to a backup file
  restore                  Restore server data from a backup file
  setup-offline-prepare    Step 1/2 of the offline (air-gapped VTA) setup wizard
  setup-offline-complete   Step 2/2 of the offline setup wizard
  identity-list            List the service's own identity generations (key material still honoured)
  identity-rotate-keys     Rotate the service's own key-agreement key
  identity-scid-alias      List or remove the did:scid alias of the service's own DID
  identity-retire-now      Stop honouring a superseded identity generation immediately
  tsp-relationship-list    List this service's established TSP relationships (offline; stop the service first)
  tsp-relationship-reset   Reset our half of a TSP relationship to `None`, so the next send to the peer re-invites (offline). Keeps the cached peer capability
  tsp-relationship-delete  Delete TSP relationship records outright (offline)
  bootstrap-did            Bootstrap a DID for this server (defaults to root .well-known)
  recreate-did             Recreate a DID at a given path (deletes existing, creates new, updates config)
  recover-did              Recover a soft-deleted DID
  load-did                 Load a DID at an arbitrary path (e.g., "services/control")
  dump-did                 Dump the DID log (did.jsonl) for a given path
  list-dids                List all DIDs in the store
  remove-did               Remove a DID and all its data from the store
  import-secrets           Import secrets from a VTA secrets bundle or individual keys
  export-sealed            Export this service's DID + signing/KA keys as an HPKE-sealed migration bundle
  import-sealed            Open a sealed `DidSecrets` migration bundle and import the contained keys as this service's identity. Inverse of `export-sealed` on the sending side
  vta-request              Write an offline VTA bootstrap request (for air-gapped VTAs)
  vta-open                 Open a sealed VTA bootstrap response (primitive — prefer `setup-offline-complete` for a full wizard-driven finish)
  help                     Print this message or the help of the given subcommand(s)

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -h, --help
          Print help

  -V, --version
          Print version
```

### `did-hosting-server setup`

```text
Run interactive setup wizard to generate config.toml.

Headless mode (for CI / scripted setup):

1. Run with `--setup-key-out <path> --context <id>` to mint an ephemeral did:key, persist it (chmod 0600), and print the `pnm contexts create` command. Exits without further prompts. 2. Run again with `--setup-key-file <path>` to drive the rest of the wizard reusing the persisted setup DID.

Usage: did-hosting-server setup [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --setup-key-out <SETUP_KEY_OUT>
          Phase 1: mint an ephemeral did:key, persist to `<path>`, and print the `pnm contexts create` command + exit

      --setup-key-file <SETUP_KEY_FILE>
          Phase 2: reuse the setup DID persisted at `<path>`; skip the interactive "Has the context been created?" confirmation

      --context <CONTEXT>
          Context id for phase 1's PNM command. Defaults to `did-hosting`

          [default: did-hosting]

      --from <FILE>
          Path to a declarative setup recipe TOML. Drives the wizard non-interactively — see `examples/did-hosting-server-build.toml`. For `vta_mode = "online"` also pass `--setup-key-file <path>` (Phase 2). For `offline-complete`, the recipe carries the bundle path + digest

      --force-reprovision
          Refuse to run when an existing setup is detected, unless this flag is set. Without it, the wizard exits 4 to protect issued JWTs and active VTA sessions

      --non-interactive
          Explicit "no TTY available" flag. Requires `--from`. With this set, missing required recipe fields fail fast instead of dropping into prompts (which would hang in CI)

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-server uninstall`

```text
Teardown a server install: clears managed secrets from the configured backend, removes the config file (and `.bak`)

Usage: did-hosting-server uninstall [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --yes
          Skip the typed "DELETE" confirmation prompt. CI use only

  -h, --help
          Print help
```

### `did-hosting-server health`

```text
Run health check diagnostics. Exits non-zero when a check fails (or, with --strict, warns), so it can gate a deploy or a container probe

Usage: did-hosting-server health [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --strict
          Also exit non-zero when a check only warned (a store held by the running service, plaintext secrets, a non-2xx reachability probe)

  -h, --help
          Print help
```

### `did-hosting-server backup`

```text
Export server data to a backup file

Usage: did-hosting-server backup [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -o, --output <OUTPUT>
          Output file path (use "-" for stdout)

          [default: did-hosting-backup.json]

  -h, --help
          Print help
```

### `did-hosting-server restore`

```text
Restore server data from a backup file.

The backup is checked before anything is written, config.toml included. Each did:webvh (or did:webs) log must verify, match its record, and extend both the backup's own high-water mark and what the store already holds for that DID; otherwise nothing is restored. Restore into an empty store to start from the backup's state. The data goes into the store the backup's config names (after the usual environment overrides). If a restore is interrupted, run it again: it is safe to repeat.

Usage: did-hosting-server restore [OPTIONS] --input <INPUT>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -i, --input <INPUT>
          Input backup file path

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-server setup-offline-prepare`

```text
Step 1/2 of the offline (air-gapped VTA) setup wizard.

Runs the interactive prompts, writes the bootstrap-request.json + ephemeral seed, and serialises the operator's answers to a state TOML file. After the VTA admin returns a sealed bundle, run `setup-offline-complete`.

Usage: did-hosting-server setup-offline-prepare [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --request <REQUEST>
          Path for the bootstrap-request.json file

          [default: bootstrap-request.json]

      --state <STATE>
          Path for the pending state file (plain TOML, no secrets).

          The ephemeral bootstrap seed is persisted to the configured secrets backend (keyring / AWS / GCP / plaintext-in-config), not to a file.

          [default: setup-offline-state.toml]

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-server setup-offline-complete`

```text
Step 2/2 of the offline setup wizard.

Opens the sealed bundle with the seed saved during step 1, then persists the DID + keys + config per the choices captured in the state file, and imports the server's own DID into the local store.

Usage: did-hosting-server setup-offline-complete [OPTIONS] --bundle <BUNDLE> --expect-digest <EXPECT_DIGEST>

Options:
      --bundle <BUNDLE>
          Path to the ASCII-armored sealed bundle from the VTA admin

  -c, --config <CONFIG>
          Path to the configuration file

      --expect-digest <EXPECT_DIGEST>
          Expected SHA-256 digest (lowercase hex) of the armored ciphertext; communicated out-of-band

      --state <STATE>
          Path to the state file written by `setup-offline-prepare`

          [default: setup-offline-state.toml]

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-server identity-list`

```text
List the service's own identity generations (key material still honoured)

Usage: did-hosting-server identity-list [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -h, --help
          Print help
```

### `did-hosting-server identity-rotate-keys`

```text
Rotate the service's own key-agreement key.

Publishes a new DID log entry installing a fresh key-agreement key on a NEW verification-method fragment, and keeps the outgoing key honoured for the grace period so peers holding a cached DID document can still reach this service.

The fresh fragment is not cosmetic: a kid identifies exactly one key, so reusing `#key-1` would make any grace period impossible.

The service must be STOPPED (the store is exclusively locked).

Usage: did-hosting-server identity-rotate-keys [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --keys <KEYS>
          Which keys to rotate: "ka" (default), "signing", or "both".

          "ka"      — the encryption key. This is what the grace period covers. "signing" — the DID's updateKeys: the authority to publish updates. Revoked IMMEDIATELY; there is no grace period for it, and for a compromised key that is exactly what you want.

          [default: ka]

      --ka-key <KA_KEY>
          X25519 key-agreement key to install (multibase). Generated if omitted

      --signing-key <SIGNING_KEY>
          Ed25519 signing key to install (multibase). Generated if omitted

      --grace <GRACE>
          How long to keep honouring the outgoing key-agreement key ("1h", "0"). Defaults to `[identity] rotation_grace_period`

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-server identity-scid-alias`

```text
List or remove the did:scid alias of the service's own DID.

Publishes a new DID log entry whose `alsoKnownAs` lists (`list`) or no longer lists (`remove`) `did:scid:vh:1:<scid>?src=<location>` — the listing that makes the DID's did:webvh and did:scid forms one subject (VTI-KEY-164). `list` replaces an alias listed for an older location. Refused when nothing would change. Signed with the current update key, which does not rotate.

The service must be STOPPED (the store is exclusively locked).

Usage: did-hosting-server identity-scid-alias [OPTIONS] <ACTION>

Arguments:
  <ACTION>
          "list" or "remove"

          [possible values: list, remove]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-server identity-retire-now`

```text
Stop honouring a superseded identity generation immediately.

The offline kill switch, for a compromised key. Messages still addressed to that generation's key-agreement key will no longer decrypt.

The service must be stopped (the store is exclusively locked). For a LIVE service use the control plane's `identity/retire/0.1` Trust Task (`send-trust-task`, see docs/sending-trust-tasks.md) or the UI button, which drops the key from the running process immediately.

Usage: did-hosting-server identity-retire-now [OPTIONS] --generation <GENERATION>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --generation <GENERATION>
          Generation id to retire (see `identity-list`)

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-server tsp-relationship-list`

```text
List this service's established TSP relationships (offline; stop the service first).

Each endpoint keeps its own half of every relationship; the mediator holds none, so resetting a peer pairing means clearing both ends.

Usage: did-hosting-server tsp-relationship-list [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-server tsp-relationship-reset`

```text
Reset our half of a TSP relationship to `None`, so the next send to the peer re-invites (offline). Keeps the cached peer capability

Usage: did-hosting-server tsp-relationship-reset [OPTIONS] --peer <PEER>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --peer <PEER>
          The peer's DID (its TSP VID)

      --our <OUR>
          This service's VID for the pair. Needed only for a half-formed relationship, which `tsp-relationship-list` cannot show

  -h, --help
          Print help
```

### `did-hosting-server tsp-relationship-delete`

```text
Delete TSP relationship records outright (offline)

Usage: did-hosting-server tsp-relationship-delete [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --peer <PEER>
          The peer's DID (its TSP VID)

      --our <OUR>
          This service's VID for the pair. Needed only for a half-formed relationship, which `tsp-relationship-list` cannot show

      --all
          Delete every record, established or half-formed

  -y, --yes
          Confirm `--all`. Without it, only reports what would be deleted

  -h, --help
          Print help
```

### `did-hosting-server bootstrap-did`

```text
Bootstrap a DID for this server (defaults to root .well-known)

Usage: did-hosting-server bootstrap-did [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --path <PATH>
          DID path/mnemonic to bootstrap (e.g. "my-org", "services/auth") Defaults to ".well-known" (the root DID for this server)

          [default: .well-known]
          [alias: --mnemonic]

      --did-log <DID_LOG>
          Path to an existing did.jsonl file to import

      --did-witness <DID_WITNESS>
          Path to an existing did-witness.json file to import (requires --did-log)

      --witness-url <WITNESS_URL>
          Witness service URL for requesting a proof (auto-bootstrap only)

      --witness-id <WITNESS_ID>
          Witness ID to use when requesting a proof (auto-bootstrap only)

      --witness-did <WITNESS_DID>
          The witness server's own DID (its `server_did`), required with --witness-url. The sign-in is addressed to it, and the witness server refuses one addressed elsewhere. This is not --witness-id, which names one of the witnesses that server hosts

  -h, --help
          Print help
```

### `did-hosting-server recreate-did`

```text
Recreate a DID at a given path (deletes existing, creates new, updates config)

Usage: did-hosting-server recreate-did [OPTIONS] --path <PATH>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --path <PATH>
          DID path/mnemonic to recreate (e.g. "webvh/server1")

          [alias: --mnemonic]

  -h, --help
          Print help
```

### `did-hosting-server recover-did`

```text
Recover a soft-deleted DID

Usage: did-hosting-server recover-did [OPTIONS] --path <PATH>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --path <PATH>
          DID path/mnemonic to recover (e.g. "webvh/server1")

          [alias: --mnemonic]

  -h, --help
          Print help
```

### `did-hosting-server load-did`

```text
Load a DID at an arbitrary path (e.g., "services/control").

The log must verify (and its witness proofs, if it is witnessed) and must extend every history this store has served for that DID, including one since removed with `remove-did`.

Usage: did-hosting-server load-did [OPTIONS] --path <PATH> --did-log <DID_LOG>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --path <PATH>
          Path to store the DID at (e.g., "services/control")

          [alias: --mnemonic]

      --did-log <DID_LOG>
          Path to the did.jsonl file

      --did-witness <DID_WITNESS>
          Optional did-witness.json file

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-server dump-did`

```text
Dump the DID log (did.jsonl) for a given path

Usage: did-hosting-server dump-did [OPTIONS] --path <PATH>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --path <PATH>
          DID path/mnemonic to dump (e.g. ".well-known", "my-org")

          [alias: --mnemonic]

      --witness
          Also dump the witness proof (did-witness.json)

  -h, --help
          Print help
```

### `did-hosting-server list-dids`

```text
List all DIDs in the store

Usage: did-hosting-server list-dids [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -h, --help
          Print help
```

### `did-hosting-server remove-did`

```text
Remove a DID and all its data from the store

Usage: did-hosting-server remove-did [OPTIONS] --path <PATH>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --path <PATH>
          DID path/mnemonic to remove (e.g. "glenn", ".well-known")

          [alias: --mnemonic]

  -h, --help
          Print help
```

### `did-hosting-server import-secrets`

```text
Import secrets from a VTA secrets bundle or individual keys

Usage: did-hosting-server import-secrets [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --vta-bundle <VTA_BUNDLE>
          Base64url-encoded VTA secrets bundle (from `vta create-did-webvh`)

      --signing-key <SIGNING_KEY>
          Ed25519 signing key (multibase-encoded)

      --ka-key <KA_KEY>
          X25519 key agreement key (multibase-encoded, required with --signing-key)

      --jwt-key <JWT_KEY>
          Ed25519 JWT signing key (multibase-encoded, generated if omitted)

      --vta-credential <VTA_CREDENTIAL>
          VTA credential bundle (base64url-encoded, optional)

      --force
          Overwrite existing secrets without prompting

  -h, --help
          Print help
```

### `did-hosting-server export-sealed`

```text
Export this service's DID + signing/KA keys as an HPKE-sealed migration bundle.

Reads the receiver's `bootstrap-request.json` (same shape that `vta-request` or `setup-offline-prepare` produces), loads the existing identity from the configured secret store, wraps the keys as a `DidSecrets` payload, and seals to the receiver's ephemeral X25519 pubkey. Prints a SHA-256 digest that the receiver MUST verify out-of-band before opening. The receiver opens it with `import-sealed`.

Usage: did-hosting-server export-sealed [OPTIONS] --request <REQUEST>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --request <REQUEST>
          Path to the receiver's bootstrap-request.json

      --out <OUT>
          Path for the ASCII-armored sealed output

          [default: sealed-export.txt]

      --digest-out <DIGEST_OUT>
          Optional file to write the SHA-256 digest to. Always printed to stderr regardless

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-server import-sealed`

```text
Open a sealed `DidSecrets` migration bundle and import the contained keys as this service's identity. Inverse of `export-sealed` on the sending side

Usage: did-hosting-server import-sealed [OPTIONS] --bundle <BUNDLE> --expect-digest <EXPECT_DIGEST>

Options:
      --bundle <BUNDLE>
          Path to the ASCII-armored sealed bundle

  -c, --config <CONFIG>
          Path to the configuration file

      --expect-digest <EXPECT_DIGEST>
          Expected SHA-256 digest of the armored ciphertext (from the operator, out-of-band)

      --seed <SEED>
          Path to the ephemeral seed the receiver saved when generating the bootstrap-request.json

          [default: bootstrap-seed.bin]

      --producer-pubkey <PRODUCER_PUBKEY>
          Optional Ed25519 public key of the producer (multibase- encoded, matches `#key-0` in the producer's DID document). When supplied, the bundle's `DidSigned` assertion is verified against it; omit to fall back to digest-only trust

      --jwt-key <JWT_KEY>
          Ed25519 JWT signing key (multibase-encoded, generated if omitted)

      --force
          Overwrite existing secrets without prompting

  -h, --help
          Print help
```

### `did-hosting-server vta-request`

```text
Write an offline VTA bootstrap request (for air-gapped VTAs).

Generates an ephemeral Ed25519 keypair and writes a JSON request the operator ferries to the VTA admin. Keep the companion seed file safe — it's needed to open the sealed response.

Usage: did-hosting-server vta-request [OPTIONS] --public-url <PUBLIC_URL>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --out <OUT>
          Path for the bootstrap-request.json file

          [default: bootstrap-request.json]

      --seed <SEED>
          Path for the ephemeral seed (keep this secret; chmod 0600 on Unix)

          [default: bootstrap-seed.bin]

      --label <LABEL>
          Operator-visible label identifying this request. Defaults to the binary's name

      --public-url <PUBLIC_URL>
          Public URL where this service serves its DID (e.g. `https://server1.example.com`). It names where the VTA publishes the DID's log and, through its path, the DID path. With `--mediator-did` the DID advertises only its messaging transports (`TSPTransport` / `DIDCommMessaging`), not this URL; only an HTTP-only DID (no mediator) carries a `WebVHHosting` service here

          [alias: --did-hosting-url]

      --context <CONTEXT>
          VTA context the integration will live in. Embedded as `contextHint` in the request so the VTA admin can run `vta bootstrap provision-integration` without `--context`

          [default: did-hosting]

      --mediator-did <MEDIATOR_DID>
          DIDComm mediator DID to advertise on this service's DID. When set, the rendered DID exposes a `TSPTransport` and/or `DIDCommMessaging` service at this mediator (per `--transport`), so peers can reach the service over messaging without out-of-band config — matching the interactive setup. Omit for an HTTP-only DID

      --transport <TRANSPORT>
          Which messaging transport(s) to advertise at `--mediator-did`: `both`, `tsp`, or `didcomm`. Ignored when no mediator is given

          [default: both]

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-server vta-open`

```text
Open a sealed VTA bootstrap response (primitive — prefer `setup-offline-complete` for a full wizard-driven finish).

Reads the armored bundle the operator ferried back, verifies the out-of-band digest, opens the HPKE sealed payload with the ephemeral seed, and emits the DID document + signed DID log, and the minted keys for `import-secrets` (or `setup`).

Usage: did-hosting-server vta-open [OPTIONS] --bundle <BUNDLE> --expect-digest <EXPECT_DIGEST>

Options:
      --bundle <BUNDLE>
          Path to the ASCII-armored sealed bundle

  -c, --config <CONFIG>
          Path to the configuration file

      --expect-digest <EXPECT_DIGEST>
          Expected SHA-256 digest of the armored ciphertext (from the operator, out-of-band)

      --seed <SEED>
          Path to the ephemeral seed saved by `vta-request`

          [default: bootstrap-seed.bin]

      --did-doc-out <DID_DOC_OUT>
          Where to write the rendered DID document as JSON. Defaults to `<service>-did.json` (`server`, `control` or `daemon`)

      --did-log-out <DID_LOG_OUT>
          Where to write the signed DID log (JSONL). Omitted when the template didn't emit a WebvhLog output. Defaults to `<service>-did.jsonl`

      --secrets-out <SECRETS_OUT>
          Where to save the minted private signing + KA key pair plus VTA trust material (authorization VC, pinned VTA DID) as JSON. Defaults to `<service>-secrets.json`

  -h, --help
          Print help (see a summary with '-h')
```
<!-- END did-hosting-server -->

<!-- BEGIN did-hosting-control -->
## `did-hosting-control`

```text
DID Hosting Control Plane — Unified Management

Usage: did-hosting-control [OPTIONS] [COMMAND]

Commands:
  setup                    Run interactive setup wizard to generate config.toml
  uninstall                Teardown a control plane install: clears managed secrets and removes the config file (+ `.bak`, + `control-did.jsonl`)
  health                   Run health check diagnostics. Exits non-zero when a check fails (or, with --strict, warns), so it can gate a deploy or a container probe
  setup-offline-prepare    Step 1/2 of the offline (air-gapped VTA) setup wizard
  setup-offline-complete   Step 2/2 of the offline setup wizard
  add-acl                  Add an ACL entry
  list-acl                 List all ACL entries
  remove-acl               Remove an ACL entry and withdraw its DID's invites
  invite                   Create a passkey enrollment invite
  fetch-metrics            Read this service's counters over the authenticated `server/metrics/0.1` Trust Task and print them as JSON
  send-trust-task          Send one signed Trust Task to the running service and print the response payload as JSON
  stats-show               Show a DID's statistics resolution, recorded tier and totals (offline; stop the service first)
  stats-set                Set a DID's statistics resolution (offline; stop the service first): `auto` (by traffic), `fine` (always 5-minute detail), `coarse` (never promoted) or `off` (totals only). Applied at the next start
  stats-purge-legacy       Finish the move to tiered statistics and delete the legacy time-series rows now, instead of 30 days after the migration (offline; stop the service first). An older version rolled back to afterwards has no time-series history
  identity-list            List the service's own identity generations (key material still honoured)
  identity-rotate-keys     Rotate the service's own key-agreement key
  identity-scid-alias      List or remove the did:scid alias of the service's own DID
  identity-retire-now      Stop honouring a superseded identity generation immediately
  tsp-relationship-list    List this service's established TSP relationships (offline; stop the service first)
  tsp-relationship-reset   Reset our half of a TSP relationship to `None`, so the next send to the peer re-invites (offline). Keeps the cached peer capability
  tsp-relationship-delete  Delete TSP relationship records outright (offline)
  import-secrets           Import secrets from a VTA secrets bundle or individual keys
  export-sealed            Export this service's DID + signing/KA keys as an HPKE-sealed migration bundle
  import-sealed            Open a sealed `DidSecrets` migration bundle and import the contained keys as this service's identity. Inverse of `export-sealed` on the sending side
  vta-request              Write an offline VTA bootstrap request (for air-gapped VTAs)
  vta-open                 Open a sealed VTA bootstrap response (primitive — prefer `setup-offline-complete` for a full wizard-driven finish)
  help                     Print this message or the help of the given subcommand(s)

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -h, --help
          Print help

  -V, --version
          Print version
```

### `did-hosting-control setup`

```text
Run interactive setup wizard to generate config.toml.

Headless mode (for CI / scripted setup):

1. Run with `--setup-key-out <path> --context <id>` to mint an ephemeral did:key, persist it (chmod 0600), and print the `pnm contexts create` command. Exits without further prompts. 2. Run again with `--setup-key-file <path>` to drive the rest of the wizard reusing the persisted setup DID.

Usage: did-hosting-control setup [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --setup-key-out <SETUP_KEY_OUT>
          Phase 1: mint an ephemeral did:key, persist to `<path>`, and print the `pnm contexts create` command + exit

      --setup-key-file <SETUP_KEY_FILE>
          Phase 2: reuse the setup DID persisted at `<path>`; skip the interactive "Has the context been created?" confirmation

      --context <CONTEXT>
          Context id for phase 1's PNM command. Defaults to `did-hosting`

          [default: did-hosting]

      --from <FILE>
          Path to a declarative setup recipe TOML. Drives the wizard non-interactively. See `examples/did-hosting-control-build.toml`

      --force-reprovision
          Refuse to run when an existing setup is detected, unless this flag is set. Exit 4 protects issued JWTs / active VTA sessions

      --non-interactive
          Explicit "no TTY available" flag. Requires `--from`

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-control uninstall`

```text
Teardown a control plane install: clears managed secrets and removes the config file (+ `.bak`, + `control-did.jsonl`)

Usage: did-hosting-control uninstall [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --yes
          Skip the typed "DELETE" confirmation prompt. CI use only

  -h, --help
          Print help
```

### `did-hosting-control health`

```text
Run health check diagnostics. Exits non-zero when a check fails (or, with --strict, warns), so it can gate a deploy or a container probe

Usage: did-hosting-control health [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --strict
          Also exit non-zero when a check only warned (a store held by the running service, plaintext secrets, a non-2xx reachability probe)

  -h, --help
          Print help
```

### `did-hosting-control setup-offline-prepare`

```text
Step 1/2 of the offline (air-gapped VTA) setup wizard.

Runs the interactive prompts, writes the bootstrap-request.json + ephemeral seed, and serialises the operator's answers to a state TOML file. After the VTA admin returns a sealed bundle, run `setup-offline-complete`.

Usage: did-hosting-control setup-offline-prepare [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --request <REQUEST>
          Path for the bootstrap-request.json file

          [default: bootstrap-request.json]

      --state <STATE>
          Path for the pending state file (plain TOML, no secrets).

          The ephemeral bootstrap seed is persisted to the configured secrets backend (keyring / AWS / GCP / plaintext-in-config), not to a file.

          [default: setup-offline-state.toml]

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-control setup-offline-complete`

```text
Step 2/2 of the offline setup wizard.

Opens the sealed bundle with the seed saved during step 1, then persists the DID + keys + config + admin ACL per the choices captured in the state file.

Usage: did-hosting-control setup-offline-complete [OPTIONS] --bundle <BUNDLE> --expect-digest <EXPECT_DIGEST>

Options:
      --bundle <BUNDLE>
          Path to the ASCII-armored sealed bundle from the VTA admin

  -c, --config <CONFIG>
          Path to the configuration file

      --expect-digest <EXPECT_DIGEST>
          Expected SHA-256 digest (lowercase hex) of the armored ciphertext; communicated out-of-band

      --state <STATE>
          Path to the state file written by `setup-offline-prepare`

          [default: setup-offline-state.toml]

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-control add-acl`

```text
Add an ACL entry

Usage: did-hosting-control add-acl [OPTIONS] --did <DID>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --did <DID>
          DID to add to the ACL

      --role <ROLE>
          Role (admin or owner)

          [default: owner]

      --label <LABEL>
          Optional label

      --witness
          did-hosting-daemon only: add the entry to the embedded witness's ACL (`[witness_store]`) instead of the control plane's. The role must then be `admin` or `service` (request witness signatures only). Refused by a binary with no embedded witness

  -h, --help
          Print help
```

### `did-hosting-control list-acl`

```text
List all ACL entries

Usage: did-hosting-control list-acl [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --witness
          did-hosting-daemon only: list the embedded witness's ACL (`[witness_store]`) instead of the control plane's. Refused by a binary with no embedded witness

  -h, --help
          Print help
```

### `did-hosting-control remove-acl`

```text
Remove an ACL entry and withdraw its DID's invites

Withdraws the enrolment invites issued for the DID, or issued or changed by it. With no ACL entry, only withdraws the invites issued for the DID, which is how an operator takes back a CLI invite.

Usage: did-hosting-control remove-acl [OPTIONS] --did <DID>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --did <DID>
          DID to remove from the ACL

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-control invite`

```text
Create a passkey enrollment invite

Usage: did-hosting-control invite [OPTIONS] --did <DID>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --did <DID>
          DID to invite

      --role <ROLE>
          Role (admin or owner)

          [default: owner]

      --ttl-hours <TTL_HOURS>
          Invite lifetime in hours (default: `auth.passkey_enrollment_ttl`)

  -h, --help
          Print help
```

### `did-hosting-control fetch-metrics`

```text
Read this service's counters over the authenticated `server/metrics/0.1` Trust Task and print them as JSON.

The counters live in the running service's process memory and are reachable only through this signed task — there is no unauthenticated scrape endpoint. Signs with the `--key` did:key (granted `MetricsReader` in the ACL) and POSTs to the running service's `POST /api/trust-tasks`. Only `counters` are returned (gauges require Admin and are omitted). Prints the counters as JSON on stdout, ready to pipe into a monitoring agent.

Counter instrumentation is opt-in: the `webvh_*` counters are populated only in a build with the `metrics` feature; against one without it this prints an empty array `[]`. A genuine refusal (an ungranted or revoked key) is reported as an error rather than an empty array.

Usage: did-hosting-control fetch-metrics [OPTIONS] --key <KEY>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --key <KEY>
          Path to the signer's did:key JSON file — the MetricsReader key, same format `setup --setup-key-out` writes

      --url <URL>
          Base URL of the running service. Defaults to `http://<server.host>:<server.port>` from config (a wildcard bind such as `0.0.0.0` / `::` is dialled as loopback)

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-control send-trust-task`

```text
Send one signed Trust Task to the running service and print the response payload as JSON.

Every management operation is a Trust Task (docs/trust-tasks.md lists them). Signs the request with the `--key` did:key, POSTs it to the running service's `POST /api/trust-tasks`, verifies the reply is the service's own signed response, and prints its payload. The key is authorised like any other client: by its proof and its ACL entry (add it with `add-acl`). A refusal is reported as an error with its code.

Usage: did-hosting-control send-trust-task [OPTIONS] --key <KEY> --type <TYPE>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --key <KEY>
          Path to the signer's did:key JSON file — same format `setup --setup-key-out` writes

      --type <TYPE>
          The task: a full Type URI, or `<slug>/<version>` such as `identity/list/0.1` or `did-management/registry/list/0.2`

      --payload <PAYLOAD>
          The request payload as JSON (default `{}`)

      --payload-file <PAYLOAD_FILE>
          Read the request payload from a JSON file

      --url <URL>
          Base URL of the running service. Defaults to `http://<server.host>:<server.port>` from config (a wildcard bind is dialled as loopback)

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-control stats-show`

```text
Show a DID's statistics resolution, recorded tier and totals (offline; stop the service first)

Usage: did-hosting-control stats-show [OPTIONS] --mnemonic <MNEMONIC>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --mnemonic <MNEMONIC>
          The DID's path (mnemonic), e.g. ".well-known" or "my-org"

          [alias: --path]

  -h, --help
          Print help
```

### `did-hosting-control stats-set`

```text
Set a DID's statistics resolution (offline; stop the service first): `auto` (by traffic), `fine` (always 5-minute detail), `coarse` (never promoted) or `off` (totals only). Applied at the next start

Usage: did-hosting-control stats-set [OPTIONS] --mnemonic <MNEMONIC> --resolution <RESOLUTION>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --mnemonic <MNEMONIC>
          The DID's path (mnemonic), e.g. ".well-known" or "my-org"

          [alias: --path]

      --resolution <RESOLUTION>
          auto, fine, coarse or off

          [possible values: auto, fine, coarse, off]

  -h, --help
          Print help
```

### `did-hosting-control stats-purge-legacy`

```text
Finish the move to tiered statistics and delete the legacy time-series rows now, instead of 30 days after the migration (offline; stop the service first). An older version rolled back to afterwards has no time-series history

Usage: did-hosting-control stats-purge-legacy [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -h, --help
          Print help
```

### `did-hosting-control identity-list`

```text
List the service's own identity generations (key material still honoured)

Usage: did-hosting-control identity-list [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -h, --help
          Print help
```

### `did-hosting-control identity-rotate-keys`

```text
Rotate the service's own key-agreement key.

Publishes a new DID log entry installing a fresh key-agreement key on a NEW verification-method fragment, and keeps the outgoing key honoured for the grace period so peers holding a cached DID document can still reach this service.

The fresh fragment is not cosmetic: a kid identifies exactly one key, so reusing `#key-1` would make any grace period impossible.

The service must be STOPPED (the store is exclusively locked).

Usage: did-hosting-control identity-rotate-keys [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --keys <KEYS>
          Which keys to rotate: "ka" (default), "signing", or "both".

          "ka"      — the encryption key. This is what the grace period covers. "signing" — the DID's updateKeys: the authority to publish updates. Revoked IMMEDIATELY; there is no grace period for it, and for a compromised key that is exactly what you want.

          [default: ka]

      --ka-key <KA_KEY>
          X25519 key-agreement key to install (multibase). Generated if omitted

      --signing-key <SIGNING_KEY>
          Ed25519 signing key to install (multibase). Generated if omitted

      --grace <GRACE>
          How long to keep honouring the outgoing key-agreement key ("1h", "0"). Defaults to `[identity] rotation_grace_period`

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-control identity-scid-alias`

```text
List or remove the did:scid alias of the service's own DID.

Publishes a new DID log entry whose `alsoKnownAs` lists (`list`) or no longer lists (`remove`) `did:scid:vh:1:<scid>?src=<location>` — the listing that makes the DID's did:webvh and did:scid forms one subject (VTI-KEY-164). `list` replaces an alias listed for an older location. Refused when nothing would change. Signed with the current update key, which does not rotate.

The service must be STOPPED (the store is exclusively locked).

Usage: did-hosting-control identity-scid-alias [OPTIONS] <ACTION>

Arguments:
  <ACTION>
          "list" or "remove"

          [possible values: list, remove]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-control identity-retire-now`

```text
Stop honouring a superseded identity generation immediately.

The offline kill switch, for a compromised key. Messages still addressed to that generation's key-agreement key will no longer decrypt.

The service must be stopped (the store is exclusively locked). For a LIVE service use the control plane's `identity/retire/0.1` Trust Task (`send-trust-task`, see docs/sending-trust-tasks.md) or the UI button, which drops the key from the running process immediately.

Usage: did-hosting-control identity-retire-now [OPTIONS] --generation <GENERATION>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --generation <GENERATION>
          Generation id to retire (see `identity-list`)

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-control tsp-relationship-list`

```text
List this service's established TSP relationships (offline; stop the service first).

Each endpoint keeps its own half of every relationship; the mediator holds none, so resetting a peer pairing means clearing both ends.

Usage: did-hosting-control tsp-relationship-list [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-control tsp-relationship-reset`

```text
Reset our half of a TSP relationship to `None`, so the next send to the peer re-invites (offline). Keeps the cached peer capability

Usage: did-hosting-control tsp-relationship-reset [OPTIONS] --peer <PEER>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --peer <PEER>
          The peer's DID (its TSP VID)

      --our <OUR>
          This service's VID for the pair. Needed only for a half-formed relationship, which `tsp-relationship-list` cannot show

  -h, --help
          Print help
```

### `did-hosting-control tsp-relationship-delete`

```text
Delete TSP relationship records outright (offline)

Usage: did-hosting-control tsp-relationship-delete [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --peer <PEER>
          The peer's DID (its TSP VID)

      --our <OUR>
          This service's VID for the pair. Needed only for a half-formed relationship, which `tsp-relationship-list` cannot show

      --all
          Delete every record, established or half-formed

  -y, --yes
          Confirm `--all`. Without it, only reports what would be deleted

  -h, --help
          Print help
```

### `did-hosting-control import-secrets`

```text
Import secrets from a VTA secrets bundle or individual keys

Usage: did-hosting-control import-secrets [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --vta-bundle <VTA_BUNDLE>
          Base64url-encoded VTA secrets bundle (from `vta create-did-webvh`)

      --signing-key <SIGNING_KEY>
          Ed25519 signing key (multibase-encoded)

      --ka-key <KA_KEY>
          X25519 key agreement key (multibase-encoded, required with --signing-key)

      --jwt-key <JWT_KEY>
          Ed25519 JWT signing key (multibase-encoded, generated if omitted)

      --vta-credential <VTA_CREDENTIAL>
          VTA credential bundle (base64url-encoded, optional)

      --force
          Overwrite existing secrets without prompting

  -h, --help
          Print help
```

### `did-hosting-control export-sealed`

```text
Export this service's DID + signing/KA keys as an HPKE-sealed migration bundle.

Reads the receiver's `bootstrap-request.json` (same shape that `vta-request` or `setup-offline-prepare` produces), loads the existing identity from the configured secret store, wraps the keys as a `DidSecrets` payload, and seals to the receiver's ephemeral X25519 pubkey. Prints a SHA-256 digest that the receiver MUST verify out-of-band before opening. The receiver opens it with `import-sealed`.

Usage: did-hosting-control export-sealed [OPTIONS] --request <REQUEST>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --request <REQUEST>
          Path to the receiver's bootstrap-request.json

      --out <OUT>
          Path for the ASCII-armored sealed output

          [default: sealed-export.txt]

      --digest-out <DIGEST_OUT>
          Optional file to write the SHA-256 digest to. Always printed to stderr regardless

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-control import-sealed`

```text
Open a sealed `DidSecrets` migration bundle and import the contained keys as this service's identity. Inverse of `export-sealed` on the sending side

Usage: did-hosting-control import-sealed [OPTIONS] --bundle <BUNDLE> --expect-digest <EXPECT_DIGEST>

Options:
      --bundle <BUNDLE>
          Path to the ASCII-armored sealed bundle

  -c, --config <CONFIG>
          Path to the configuration file

      --expect-digest <EXPECT_DIGEST>
          Expected SHA-256 digest of the armored ciphertext (from the operator, out-of-band)

      --seed <SEED>
          Path to the ephemeral seed the receiver saved when generating the bootstrap-request.json

          [default: bootstrap-seed.bin]

      --producer-pubkey <PRODUCER_PUBKEY>
          Optional Ed25519 public key of the producer (multibase- encoded, matches `#key-0` in the producer's DID document). When supplied, the bundle's `DidSigned` assertion is verified against it; omit to fall back to digest-only trust

      --jwt-key <JWT_KEY>
          Ed25519 JWT signing key (multibase-encoded, generated if omitted)

      --force
          Overwrite existing secrets without prompting

  -h, --help
          Print help
```

### `did-hosting-control vta-request`

```text
Write an offline VTA bootstrap request (for air-gapped VTAs).

Generates an ephemeral Ed25519 keypair and writes a JSON request the operator ferries to the VTA admin. Keep the companion seed file safe — it's needed to open the sealed response.

Usage: did-hosting-control vta-request [OPTIONS] --public-url <PUBLIC_URL>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --out <OUT>
          Path for the bootstrap-request.json file

          [default: bootstrap-request.json]

      --seed <SEED>
          Path for the ephemeral seed (keep this secret; chmod 0600 on Unix)

          [default: bootstrap-seed.bin]

      --label <LABEL>
          Operator-visible label identifying this request. Defaults to the binary's name

      --public-url <PUBLIC_URL>
          Public URL where this service serves its DID (e.g. `https://server1.example.com`). It names where the VTA publishes the DID's log and, through its path, the DID path. With `--mediator-did` the DID advertises only its messaging transports (`TSPTransport` / `DIDCommMessaging`), not this URL; only an HTTP-only DID (no mediator) carries a `WebVHHosting` service here

          [alias: --did-hosting-url]

      --context <CONTEXT>
          VTA context the integration will live in. Embedded as `contextHint` in the request so the VTA admin can run `vta bootstrap provision-integration` without `--context`

          [default: did-hosting]

      --mediator-did <MEDIATOR_DID>
          DIDComm mediator DID to advertise on this service's DID. When set, the rendered DID exposes a `TSPTransport` and/or `DIDCommMessaging` service at this mediator (per `--transport`), so peers can reach the service over messaging without out-of-band config — matching the interactive setup. Omit for an HTTP-only DID

      --transport <TRANSPORT>
          Which messaging transport(s) to advertise at `--mediator-did`: `both`, `tsp`, or `didcomm`. Ignored when no mediator is given

          [default: both]

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-control vta-open`

```text
Open a sealed VTA bootstrap response (primitive — prefer `setup-offline-complete` for a full wizard-driven finish).

Reads the armored bundle the operator ferried back, verifies the out-of-band digest, opens the HPKE sealed payload with the ephemeral seed, and emits the DID document + signed DID log, and the minted keys for `import-secrets` (or `setup`).

Usage: did-hosting-control vta-open [OPTIONS] --bundle <BUNDLE> --expect-digest <EXPECT_DIGEST>

Options:
      --bundle <BUNDLE>
          Path to the ASCII-armored sealed bundle

  -c, --config <CONFIG>
          Path to the configuration file

      --expect-digest <EXPECT_DIGEST>
          Expected SHA-256 digest of the armored ciphertext (from the operator, out-of-band)

      --seed <SEED>
          Path to the ephemeral seed saved by `vta-request`

          [default: bootstrap-seed.bin]

      --did-doc-out <DID_DOC_OUT>
          Where to write the rendered DID document as JSON. Defaults to `<service>-did.json` (`server`, `control` or `daemon`)

      --did-log-out <DID_LOG_OUT>
          Where to write the signed DID log (JSONL). Omitted when the template didn't emit a WebvhLog output. Defaults to `<service>-did.jsonl`

      --secrets-out <SECRETS_OUT>
          Where to save the minted private signing + KA key pair plus VTA trust material (authorization VC, pinned VTA DID) as JSON. Defaults to `<service>-secrets.json`

  -h, --help
          Print help (see a summary with '-h')
```
<!-- END did-hosting-control -->

<!-- BEGIN did-hosting-daemon -->
## `did-hosting-daemon`

```text
DID Hosting Daemon — Unified Service

Usage: did-hosting-daemon [OPTIONS] [COMMAND]

Commands:
  setup                    Run interactive setup wizard to generate config.toml
  uninstall                Teardown a daemon install: clears managed secrets and removes the config file (+ `.bak`, + companion DID-log files)
  setup-offline-prepare    Step 1/2 of the offline (air-gapped VTA) setup wizard
  setup-offline-complete   Step 2/2 of the offline setup wizard
  health                   Run health check diagnostics. Exits non-zero when a check fails (or, with --strict, warns), so it can gate a deploy or a container probe
  reset-witness-kek-claim  Clear the embedded witness's key-encryption-key creation claim left by a start that stopped while creating the key (`[witness_store]`). Refused once a key is held or recorded
  backup                   Export the daemon's data to a backup file: both stores (`[store]`, with the ACL, passkeys, identity generations and outbound queue, and `[witness_store]`) and the configuration file, verbatim
  restore                  Restore the daemon's data from a `did-hosting-daemon backup` file
  add-acl                  Add an ACL entry
  list-acl                 List all ACL entries
  remove-acl               Remove an ACL entry and withdraw its DID's invites
  invite                   Create a passkey enrollment invite
  fetch-metrics            Read this service's counters over the authenticated `server/metrics/0.1` Trust Task and print them as JSON
  send-trust-task          Send one signed Trust Task to the running service and print the response payload as JSON
  stats-show               Show a DID's statistics resolution, recorded tier and totals (offline; stop the service first)
  stats-set                Set a DID's statistics resolution (offline; stop the service first): `auto` (by traffic), `fine` (always 5-minute detail), `coarse` (never promoted) or `off` (totals only). Applied at the next start
  stats-purge-legacy       Finish the move to tiered statistics and delete the legacy time-series rows now, instead of 30 days after the migration (offline; stop the service first). An older version rolled back to afterwards has no time-series history
  identity-list            List the service's own identity generations (key material still honoured)
  identity-rotate-keys     Rotate the service's own key-agreement key
  identity-scid-alias      List or remove the did:scid alias of the service's own DID
  identity-retire-now      Stop honouring a superseded identity generation immediately
  tsp-relationship-list    List this service's established TSP relationships (offline; stop the service first)
  tsp-relationship-reset   Reset our half of a TSP relationship to `None`, so the next send to the peer re-invites (offline). Keeps the cached peer capability
  tsp-relationship-delete  Delete TSP relationship records outright (offline)
  bootstrap-did            Bootstrap a DID for this server (defaults to root .well-known)
  recreate-did             Recreate a DID at a given path (deletes existing, creates new, updates config)
  recover-did              Recover a soft-deleted DID
  load-did                 Load a DID at an arbitrary path (e.g., "services/control")
  dump-did                 Dump the DID log (did.jsonl) for a given path
  list-dids                List all DIDs in the store
  remove-did               Remove a DID and all its data from the store
  import-secrets           Import secrets from a VTA secrets bundle or individual keys
  export-sealed            Export this service's DID + signing/KA keys as an HPKE-sealed migration bundle
  import-sealed            Open a sealed `DidSecrets` migration bundle and import the contained keys as this service's identity. Inverse of `export-sealed` on the sending side
  vta-request              Write an offline VTA bootstrap request (for air-gapped VTAs)
  vta-open                 Open a sealed VTA bootstrap response (primitive — prefer `setup-offline-complete` for a full wizard-driven finish)
  help                     Print this message or the help of the given subcommand(s)

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -h, --help
          Print help

  -V, --version
          Print version
```

### `did-hosting-daemon setup`

```text
Run interactive setup wizard to generate config.toml.

Headless mode (for CI / scripted setup):

1. Run with `--setup-key-out <path> --context <id>` to mint an ephemeral did:key, persist it (chmod 0600), and print the `pnm contexts create` command the operator runs to enrol the setup DID in the VTA. Exits without touching anything else. 2. Run again with `--setup-key-file <path>` to drive the rest of the wizard reusing the persisted setup DID — skips the interactive ACL-ready confirmation.

Usage: did-hosting-daemon setup [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --setup-key-out <SETUP_KEY_OUT>
          Phase 1: mint an ephemeral did:key, persist to `<path>`, and print the `pnm contexts create` command + exit

      --setup-key-file <SETUP_KEY_FILE>
          Phase 2: reuse the setup DID persisted at `<path>`; skip the interactive "Has the context been created?" confirmation

      --context <CONTEXT>
          Context id for phase 1's PNM command. Defaults to `did-hosting`

          [default: did-hosting]

      --from <FILE>
          Path to a declarative setup recipe TOML. Drives setup non-interactively. The daemon recipe also supports `vta_mode = "self-managed"` for no-VTA deployments. See `examples/did-hosting-daemon-build.toml`

      --force-reprovision
          Refuse to run when an existing setup is detected, unless set. Exit 4 protects issued JWTs / active VTA sessions

      --non-interactive
          Explicit "no TTY available" flag. Requires `--from`

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-daemon uninstall`

```text
Teardown a daemon install: clears managed secrets and removes the config file (+ `.bak`, + companion DID-log files)

Usage: did-hosting-daemon uninstall [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --yes
          Skip the typed "DELETE" confirmation prompt. CI use only

  -h, --help
          Print help
```

### `did-hosting-daemon setup-offline-prepare`

```text
Step 1/2 of the offline (air-gapped VTA) setup wizard.

The ephemeral bootstrap seed is persisted to the configured secrets backend (keyring / AWS / GCP / plaintext-in-config) — not to a file.

Usage: did-hosting-daemon setup-offline-prepare [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --request <REQUEST>
          Path for the bootstrap-request.json file

          [default: bootstrap-request.json]

      --state <STATE>
          Path for the pending state file (plain TOML, no secrets)

          [default: setup-offline-state.toml]

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-daemon setup-offline-complete`

```text
Step 2/2 of the offline setup wizard

Usage: did-hosting-daemon setup-offline-complete [OPTIONS] --bundle <BUNDLE> --expect-digest <EXPECT_DIGEST>

Options:
      --bundle <BUNDLE>
          Path to the ASCII-armored sealed bundle from the VTA admin

  -c, --config <CONFIG>
          Path to the configuration file

      --expect-digest <EXPECT_DIGEST>
          Expected SHA-256 digest (lowercase hex) of the armored ciphertext; communicated out-of-band

      --state <STATE>
          Path to the state file written by `setup-offline-prepare`

          [default: setup-offline-state.toml]

  -h, --help
          Print help
```

### `did-hosting-daemon health`

```text
Run health check diagnostics. Exits non-zero when a check fails (or, with --strict, warns), so it can gate a deploy or a container probe

Usage: did-hosting-daemon health [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --strict
          Also exit non-zero when a check only warned (a store held by the running service, plaintext secrets, a non-2xx reachability probe)

  -h, --help
          Print help
```

### `did-hosting-daemon reset-witness-kek-claim`

```text
Clear the embedded witness's key-encryption-key creation claim left by a start that stopped while creating the key (`[witness_store]`). Refused once a key is held or recorded

Usage: did-hosting-daemon reset-witness-kek-claim [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -h, --help
          Print help
```

### `did-hosting-daemon backup`

```text
Export the daemon's data to a backup file: both stores (`[store]`, with the ACL, passkeys, identity generations and outbound queue, and `[witness_store]`) and the configuration file, verbatim

Usage: did-hosting-daemon backup [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -o, --output <OUTPUT>
          Output file path (use "-" for stdout)

          [default: did-hosting-backup.json]

  -h, --help
          Print help
```

### `did-hosting-daemon restore`

```text
Restore the daemon's data from a `did-hosting-daemon backup` file.

The backup is checked before anything is written, config.toml included (it is written back verbatim). Each did:webvh (or did:webs) log must verify, match its record, and extend both the backup's own high-water mark and what the store already holds for that DID; otherwise nothing is restored. Restore into an empty store to start from the backup's state. The data goes into the store the backup's config names (after the usual environment overrides). If a restore is interrupted, run it again: it is safe to repeat.

Usage: did-hosting-daemon restore [OPTIONS] --input <INPUT>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -i, --input <INPUT>
          Input backup file path

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-daemon add-acl`

```text
Add an ACL entry

Usage: did-hosting-daemon add-acl [OPTIONS] --did <DID>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --did <DID>
          DID to add to the ACL

      --role <ROLE>
          Role (admin or owner)

          [default: owner]

      --label <LABEL>
          Optional label

      --witness
          did-hosting-daemon only: add the entry to the embedded witness's ACL (`[witness_store]`) instead of the control plane's. The role must then be `admin` or `service` (request witness signatures only). Refused by a binary with no embedded witness

  -h, --help
          Print help
```

### `did-hosting-daemon list-acl`

```text
List all ACL entries

Usage: did-hosting-daemon list-acl [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --witness
          did-hosting-daemon only: list the embedded witness's ACL (`[witness_store]`) instead of the control plane's. Refused by a binary with no embedded witness

  -h, --help
          Print help
```

### `did-hosting-daemon remove-acl`

```text
Remove an ACL entry and withdraw its DID's invites

Withdraws the enrolment invites issued for the DID, or issued or changed by it. With no ACL entry, only withdraws the invites issued for the DID, which is how an operator takes back a CLI invite.

Usage: did-hosting-daemon remove-acl [OPTIONS] --did <DID>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --did <DID>
          DID to remove from the ACL

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-daemon invite`

```text
Create a passkey enrollment invite

Usage: did-hosting-daemon invite [OPTIONS] --did <DID>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --did <DID>
          DID to invite

      --role <ROLE>
          Role (admin or owner)

          [default: owner]

      --ttl-hours <TTL_HOURS>
          Invite lifetime in hours (default: `auth.passkey_enrollment_ttl`)

  -h, --help
          Print help
```

### `did-hosting-daemon fetch-metrics`

```text
Read this service's counters over the authenticated `server/metrics/0.1` Trust Task and print them as JSON.

The counters live in the running service's process memory and are reachable only through this signed task — there is no unauthenticated scrape endpoint. Signs with the `--key` did:key (granted `MetricsReader` in the ACL) and POSTs to the running service's `POST /api/trust-tasks`. Only `counters` are returned (gauges require Admin and are omitted). Prints the counters as JSON on stdout, ready to pipe into a monitoring agent.

Counter instrumentation is opt-in: the `webvh_*` counters are populated only in a build with the `metrics` feature; against one without it this prints an empty array `[]`. A genuine refusal (an ungranted or revoked key) is reported as an error rather than an empty array.

Usage: did-hosting-daemon fetch-metrics [OPTIONS] --key <KEY>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --key <KEY>
          Path to the signer's did:key JSON file — the MetricsReader key, same format `setup --setup-key-out` writes

      --url <URL>
          Base URL of the running service. Defaults to `http://<server.host>:<server.port>` from config (a wildcard bind such as `0.0.0.0` / `::` is dialled as loopback)

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-daemon send-trust-task`

```text
Send one signed Trust Task to the running service and print the response payload as JSON.

Every management operation is a Trust Task (docs/trust-tasks.md lists them). Signs the request with the `--key` did:key, POSTs it to the running service's `POST /api/trust-tasks`, verifies the reply is the service's own signed response, and prints its payload. The key is authorised like any other client: by its proof and its ACL entry (add it with `add-acl`). A refusal is reported as an error with its code.

Usage: did-hosting-daemon send-trust-task [OPTIONS] --key <KEY> --type <TYPE>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --key <KEY>
          Path to the signer's did:key JSON file — same format `setup --setup-key-out` writes

      --type <TYPE>
          The task: a full Type URI, or `<slug>/<version>` such as `identity/list/0.1` or `did-management/registry/list/0.2`

      --payload <PAYLOAD>
          The request payload as JSON (default `{}`)

      --payload-file <PAYLOAD_FILE>
          Read the request payload from a JSON file

      --url <URL>
          Base URL of the running service. Defaults to `http://<server.host>:<server.port>` from config (a wildcard bind is dialled as loopback)

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-daemon stats-show`

```text
Show a DID's statistics resolution, recorded tier and totals (offline; stop the service first)

Usage: did-hosting-daemon stats-show [OPTIONS] --mnemonic <MNEMONIC>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --mnemonic <MNEMONIC>
          The DID's path (mnemonic), e.g. ".well-known" or "my-org"

          [alias: --path]

  -h, --help
          Print help
```

### `did-hosting-daemon stats-set`

```text
Set a DID's statistics resolution (offline; stop the service first): `auto` (by traffic), `fine` (always 5-minute detail), `coarse` (never promoted) or `off` (totals only). Applied at the next start

Usage: did-hosting-daemon stats-set [OPTIONS] --mnemonic <MNEMONIC> --resolution <RESOLUTION>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --mnemonic <MNEMONIC>
          The DID's path (mnemonic), e.g. ".well-known" or "my-org"

          [alias: --path]

      --resolution <RESOLUTION>
          auto, fine, coarse or off

          [possible values: auto, fine, coarse, off]

  -h, --help
          Print help
```

### `did-hosting-daemon stats-purge-legacy`

```text
Finish the move to tiered statistics and delete the legacy time-series rows now, instead of 30 days after the migration (offline; stop the service first). An older version rolled back to afterwards has no time-series history

Usage: did-hosting-daemon stats-purge-legacy [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -h, --help
          Print help
```

### `did-hosting-daemon identity-list`

```text
List the service's own identity generations (key material still honoured)

Usage: did-hosting-daemon identity-list [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -h, --help
          Print help
```

### `did-hosting-daemon identity-rotate-keys`

```text
Rotate the service's own key-agreement key.

Publishes a new DID log entry installing a fresh key-agreement key on a NEW verification-method fragment, and keeps the outgoing key honoured for the grace period so peers holding a cached DID document can still reach this service.

The fresh fragment is not cosmetic: a kid identifies exactly one key, so reusing `#key-1` would make any grace period impossible.

The service must be STOPPED (the store is exclusively locked).

Usage: did-hosting-daemon identity-rotate-keys [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --keys <KEYS>
          Which keys to rotate: "ka" (default), "signing", or "both".

          "ka"      — the encryption key. This is what the grace period covers. "signing" — the DID's updateKeys: the authority to publish updates. Revoked IMMEDIATELY; there is no grace period for it, and for a compromised key that is exactly what you want.

          [default: ka]

      --ka-key <KA_KEY>
          X25519 key-agreement key to install (multibase). Generated if omitted

      --signing-key <SIGNING_KEY>
          Ed25519 signing key to install (multibase). Generated if omitted

      --grace <GRACE>
          How long to keep honouring the outgoing key-agreement key ("1h", "0"). Defaults to `[identity] rotation_grace_period`

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-daemon identity-scid-alias`

```text
List or remove the did:scid alias of the service's own DID.

Publishes a new DID log entry whose `alsoKnownAs` lists (`list`) or no longer lists (`remove`) `did:scid:vh:1:<scid>?src=<location>` — the listing that makes the DID's did:webvh and did:scid forms one subject (VTI-KEY-164). `list` replaces an alias listed for an older location. Refused when nothing would change. Signed with the current update key, which does not rotate.

The service must be STOPPED (the store is exclusively locked).

Usage: did-hosting-daemon identity-scid-alias [OPTIONS] <ACTION>

Arguments:
  <ACTION>
          "list" or "remove"

          [possible values: list, remove]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-daemon identity-retire-now`

```text
Stop honouring a superseded identity generation immediately.

The offline kill switch, for a compromised key. Messages still addressed to that generation's key-agreement key will no longer decrypt.

The service must be stopped (the store is exclusively locked). For a LIVE service use the control plane's `identity/retire/0.1` Trust Task (`send-trust-task`, see docs/sending-trust-tasks.md) or the UI button, which drops the key from the running process immediately.

Usage: did-hosting-daemon identity-retire-now [OPTIONS] --generation <GENERATION>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --generation <GENERATION>
          Generation id to retire (see `identity-list`)

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-daemon tsp-relationship-list`

```text
List this service's established TSP relationships (offline; stop the service first).

Each endpoint keeps its own half of every relationship; the mediator holds none, so resetting a peer pairing means clearing both ends.

Usage: did-hosting-daemon tsp-relationship-list [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-daemon tsp-relationship-reset`

```text
Reset our half of a TSP relationship to `None`, so the next send to the peer re-invites (offline). Keeps the cached peer capability

Usage: did-hosting-daemon tsp-relationship-reset [OPTIONS] --peer <PEER>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --peer <PEER>
          The peer's DID (its TSP VID)

      --our <OUR>
          This service's VID for the pair. Needed only for a half-formed relationship, which `tsp-relationship-list` cannot show

  -h, --help
          Print help
```

### `did-hosting-daemon tsp-relationship-delete`

```text
Delete TSP relationship records outright (offline)

Usage: did-hosting-daemon tsp-relationship-delete [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --peer <PEER>
          The peer's DID (its TSP VID)

      --our <OUR>
          This service's VID for the pair. Needed only for a half-formed relationship, which `tsp-relationship-list` cannot show

      --all
          Delete every record, established or half-formed

  -y, --yes
          Confirm `--all`. Without it, only reports what would be deleted

  -h, --help
          Print help
```

### `did-hosting-daemon bootstrap-did`

```text
Bootstrap a DID for this server (defaults to root .well-known)

Usage: did-hosting-daemon bootstrap-did [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --path <PATH>
          DID path/mnemonic to bootstrap (e.g. "my-org", "services/auth") Defaults to ".well-known" (the root DID for this server)

          [default: .well-known]
          [alias: --mnemonic]

      --did-log <DID_LOG>
          Path to an existing did.jsonl file to import

      --did-witness <DID_WITNESS>
          Path to an existing did-witness.json file to import (requires --did-log)

      --witness-url <WITNESS_URL>
          Witness service URL for requesting a proof (auto-bootstrap only)

      --witness-id <WITNESS_ID>
          Witness ID to use when requesting a proof (auto-bootstrap only)

      --witness-did <WITNESS_DID>
          The witness server's own DID (its `server_did`), required with --witness-url. The sign-in is addressed to it, and the witness server refuses one addressed elsewhere. This is not --witness-id, which names one of the witnesses that server hosts

  -h, --help
          Print help
```

### `did-hosting-daemon recreate-did`

```text
Recreate a DID at a given path (deletes existing, creates new, updates config)

Usage: did-hosting-daemon recreate-did [OPTIONS] --path <PATH>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --path <PATH>
          DID path/mnemonic to recreate (e.g. "webvh/server1")

          [alias: --mnemonic]

  -h, --help
          Print help
```

### `did-hosting-daemon recover-did`

```text
Recover a soft-deleted DID

Usage: did-hosting-daemon recover-did [OPTIONS] --path <PATH>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --path <PATH>
          DID path/mnemonic to recover (e.g. "webvh/server1")

          [alias: --mnemonic]

  -h, --help
          Print help
```

### `did-hosting-daemon load-did`

```text
Load a DID at an arbitrary path (e.g., "services/control").

The log must verify (and its witness proofs, if it is witnessed) and must extend every history this store has served for that DID, including one since removed with `remove-did`.

Usage: did-hosting-daemon load-did [OPTIONS] --path <PATH> --did-log <DID_LOG>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --path <PATH>
          Path to store the DID at (e.g., "services/control")

          [alias: --mnemonic]

      --did-log <DID_LOG>
          Path to the did.jsonl file

      --did-witness <DID_WITNESS>
          Optional did-witness.json file

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-daemon dump-did`

```text
Dump the DID log (did.jsonl) for a given path

Usage: did-hosting-daemon dump-did [OPTIONS] --path <PATH>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --path <PATH>
          DID path/mnemonic to dump (e.g. ".well-known", "my-org")

          [alias: --mnemonic]

      --witness
          Also dump the witness proof (did-witness.json)

  -h, --help
          Print help
```

### `did-hosting-daemon list-dids`

```text
List all DIDs in the store

Usage: did-hosting-daemon list-dids [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -h, --help
          Print help
```

### `did-hosting-daemon remove-did`

```text
Remove a DID and all its data from the store

Usage: did-hosting-daemon remove-did [OPTIONS] --path <PATH>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --path <PATH>
          DID path/mnemonic to remove (e.g. "glenn", ".well-known")

          [alias: --mnemonic]

  -h, --help
          Print help
```

### `did-hosting-daemon import-secrets`

```text
Import secrets from a VTA secrets bundle or individual keys

Usage: did-hosting-daemon import-secrets [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --vta-bundle <VTA_BUNDLE>
          Base64url-encoded VTA secrets bundle (from `vta create-did-webvh`)

      --signing-key <SIGNING_KEY>
          Ed25519 signing key (multibase-encoded)

      --ka-key <KA_KEY>
          X25519 key agreement key (multibase-encoded, required with --signing-key)

      --jwt-key <JWT_KEY>
          Ed25519 JWT signing key (multibase-encoded, generated if omitted)

      --vta-credential <VTA_CREDENTIAL>
          VTA credential bundle (base64url-encoded, optional)

      --force
          Overwrite existing secrets without prompting

  -h, --help
          Print help
```

### `did-hosting-daemon export-sealed`

```text
Export this service's DID + signing/KA keys as an HPKE-sealed migration bundle.

Reads the receiver's `bootstrap-request.json` (same shape that `vta-request` or `setup-offline-prepare` produces), loads the existing identity from the configured secret store, wraps the keys as a `DidSecrets` payload, and seals to the receiver's ephemeral X25519 pubkey. Prints a SHA-256 digest that the receiver MUST verify out-of-band before opening. The receiver opens it with `import-sealed`.

Usage: did-hosting-daemon export-sealed [OPTIONS] --request <REQUEST>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --request <REQUEST>
          Path to the receiver's bootstrap-request.json

      --out <OUT>
          Path for the ASCII-armored sealed output

          [default: sealed-export.txt]

      --digest-out <DIGEST_OUT>
          Optional file to write the SHA-256 digest to. Always printed to stderr regardless

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-daemon import-sealed`

```text
Open a sealed `DidSecrets` migration bundle and import the contained keys as this service's identity. Inverse of `export-sealed` on the sending side

Usage: did-hosting-daemon import-sealed [OPTIONS] --bundle <BUNDLE> --expect-digest <EXPECT_DIGEST>

Options:
      --bundle <BUNDLE>
          Path to the ASCII-armored sealed bundle

  -c, --config <CONFIG>
          Path to the configuration file

      --expect-digest <EXPECT_DIGEST>
          Expected SHA-256 digest of the armored ciphertext (from the operator, out-of-band)

      --seed <SEED>
          Path to the ephemeral seed the receiver saved when generating the bootstrap-request.json

          [default: bootstrap-seed.bin]

      --producer-pubkey <PRODUCER_PUBKEY>
          Optional Ed25519 public key of the producer (multibase- encoded, matches `#key-0` in the producer's DID document). When supplied, the bundle's `DidSigned` assertion is verified against it; omit to fall back to digest-only trust

      --jwt-key <JWT_KEY>
          Ed25519 JWT signing key (multibase-encoded, generated if omitted)

      --force
          Overwrite existing secrets without prompting

  -h, --help
          Print help
```

### `did-hosting-daemon vta-request`

```text
Write an offline VTA bootstrap request (for air-gapped VTAs).

Generates an ephemeral Ed25519 keypair and writes a JSON request the operator ferries to the VTA admin. Keep the companion seed file safe — it's needed to open the sealed response.

Usage: did-hosting-daemon vta-request [OPTIONS] --public-url <PUBLIC_URL>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --out <OUT>
          Path for the bootstrap-request.json file

          [default: bootstrap-request.json]

      --seed <SEED>
          Path for the ephemeral seed (keep this secret; chmod 0600 on Unix)

          [default: bootstrap-seed.bin]

      --label <LABEL>
          Operator-visible label identifying this request. Defaults to the binary's name

      --public-url <PUBLIC_URL>
          Public URL where this service serves its DID (e.g. `https://server1.example.com`). It names where the VTA publishes the DID's log and, through its path, the DID path. With `--mediator-did` the DID advertises only its messaging transports (`TSPTransport` / `DIDCommMessaging`), not this URL; only an HTTP-only DID (no mediator) carries a `WebVHHosting` service here

          [alias: --did-hosting-url]

      --context <CONTEXT>
          VTA context the integration will live in. Embedded as `contextHint` in the request so the VTA admin can run `vta bootstrap provision-integration` without `--context`

          [default: did-hosting]

      --mediator-did <MEDIATOR_DID>
          DIDComm mediator DID to advertise on this service's DID. When set, the rendered DID exposes a `TSPTransport` and/or `DIDCommMessaging` service at this mediator (per `--transport`), so peers can reach the service over messaging without out-of-band config — matching the interactive setup. Omit for an HTTP-only DID

      --transport <TRANSPORT>
          Which messaging transport(s) to advertise at `--mediator-did`: `both`, `tsp`, or `didcomm`. Ignored when no mediator is given

          [default: both]

  -h, --help
          Print help (see a summary with '-h')
```

### `did-hosting-daemon vta-open`

```text
Open a sealed VTA bootstrap response (primitive — prefer `setup-offline-complete` for a full wizard-driven finish).

Reads the armored bundle the operator ferried back, verifies the out-of-band digest, opens the HPKE sealed payload with the ephemeral seed, and emits the DID document + signed DID log, and the minted keys for `import-secrets` (or `setup`).

Usage: did-hosting-daemon vta-open [OPTIONS] --bundle <BUNDLE> --expect-digest <EXPECT_DIGEST>

Options:
      --bundle <BUNDLE>
          Path to the ASCII-armored sealed bundle

  -c, --config <CONFIG>
          Path to the configuration file

      --expect-digest <EXPECT_DIGEST>
          Expected SHA-256 digest of the armored ciphertext (from the operator, out-of-band)

      --seed <SEED>
          Path to the ephemeral seed saved by `vta-request`

          [default: bootstrap-seed.bin]

      --did-doc-out <DID_DOC_OUT>
          Where to write the rendered DID document as JSON. Defaults to `<service>-did.json` (`server`, `control` or `daemon`)

      --did-log-out <DID_LOG_OUT>
          Where to write the signed DID log (JSONL). Omitted when the template didn't emit a WebvhLog output. Defaults to `<service>-did.jsonl`

      --secrets-out <SECRETS_OUT>
          Where to save the minted private signing + KA key pair plus VTA trust material (authorization VC, pinned VTA DID) as JSON. Defaults to `<service>-secrets.json`

  -h, --help
          Print help (see a summary with '-h')
```
<!-- END did-hosting-daemon -->

<!-- BEGIN webvh-witness -->
## `webvh-witness`

```text
WebVH Witness Node

Usage: webvh-witness [OPTIONS] [COMMAND]

Commands:
  setup                    Run interactive setup wizard to generate config.toml
  uninstall                Teardown a witness install: clears managed secrets and removes the config file (+ `.bak`, + `witness-did.jsonl`)
  health                   Run health check diagnostics. Exits non-zero when a check fails (or, with --strict, warns), so it can gate a deploy or a container probe
  add-acl                  Add an access control entry
  list-acl                 List all access control entries
  remove-acl               Remove an access control entry
  create-witness           Create a new witness identity
  list-witnesses           List all witness identities
  delete-witness           Delete a witness identity
  reset-witness-kek-claim  Clear a key-encryption-key creation claim left by a witness process that stopped while creating it. Refused once a key is recorded
  setup-offline-prepare    Step 1/2 of the offline (air-gapped VTA) setup wizard
  setup-offline-complete   Step 2/2 of the offline setup wizard
  vta-request              Write an offline VTA bootstrap request (for air-gapped VTAs)
  export-sealed            Export this witness's DID + signing/KA keys as an HPKE-sealed migration bundle. See `did-hosting-server export-sealed` for semantics
  import-sealed            Open a sealed `DidSecrets` migration bundle and import the contained keys as this witness's identity
  vta-open                 Open a sealed VTA bootstrap response
  help                     Print this message or the help of the given subcommand(s)

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -h, --help
          Print help

  -V, --version
          Print version
```

### `webvh-witness setup`

```text
Run interactive setup wizard to generate config.toml.

Headless mode (for CI / scripted setup):

1. Run with `--setup-key-out <path> --context <id>` to mint an ephemeral did:key, persist it (chmod 0600), and print the `pnm contexts create` command. Exits without further prompts. 2. Run again with `--setup-key-file <path>` to drive the rest of the wizard reusing the persisted setup DID.

Usage: webvh-witness setup [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --setup-key-out <SETUP_KEY_OUT>
          Phase 1: mint an ephemeral did:key, persist to <path>, and print the `pnm contexts create` command + exit

      --setup-key-file <SETUP_KEY_FILE>
          Phase 2: reuse the setup DID persisted at <path>; skip the interactive "Has the context been created?" confirmation

      --context <CONTEXT>
          Context id for phase 1's PNM command. Defaults to `did-hosting`

          [default: did-hosting]

      --from <FILE>
          Path to a declarative setup recipe TOML

      --force-reprovision
          Refuse to run when an existing setup is detected, unless set

      --non-interactive
          Explicit "no TTY available" flag. Requires `--from`

  -h, --help
          Print help (see a summary with '-h')
```

### `webvh-witness uninstall`

```text
Teardown a witness install: clears managed secrets and removes the config file (+ `.bak`, + `witness-did.jsonl`)

Usage: webvh-witness uninstall [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --yes
          Skip the typed "DELETE" confirmation prompt. CI use only

  -h, --help
          Print help
```

### `webvh-witness health`

```text
Run health check diagnostics. Exits non-zero when a check fails (or, with --strict, warns), so it can gate a deploy or a container probe

Usage: webvh-witness health [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --strict
          Also exit non-zero when a check only warned (a store held by the running service, plaintext secrets, a non-2xx reachability probe)

  -h, --help
          Print help
```

### `webvh-witness add-acl`

```text
Add an access control entry

Usage: webvh-witness add-acl [OPTIONS] --did <DID> --role <ROLE>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --did <DID>
          DID to grant access to

      --role <ROLE>
          Role, required: `admin` (create, list and delete witness identities, administer this ACL, and request signatures) or `service` (request signatures only: for a control plane, VTA or edge that needs proofs). No other role can do anything on a witness, so no other is accepted

          [possible values: admin, service]

  -h, --help
          Print help
```

### `webvh-witness list-acl`

```text
List all access control entries

Usage: webvh-witness list-acl [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -h, --help
          Print help
```

### `webvh-witness remove-acl`

```text
Remove an access control entry

Usage: webvh-witness remove-acl [OPTIONS] --did <DID>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --did <DID>
          DID to remove from the ACL

  -h, --help
          Print help
```

### `webvh-witness create-witness`

```text
Create a new witness identity

Usage: webvh-witness create-witness [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --label <LABEL>
          Optional label for the witness

  -h, --help
          Print help
```

### `webvh-witness list-witnesses`

```text
List all witness identities

Usage: webvh-witness list-witnesses [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -h, --help
          Print help
```

### `webvh-witness delete-witness`

```text
Delete a witness identity

Usage: webvh-witness delete-witness [OPTIONS] --id <ID>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --id <ID>
          Witness ID (multibase public key)

  -h, --help
          Print help
```

### `webvh-witness reset-witness-kek-claim`

```text
Clear a key-encryption-key creation claim left by a witness process that stopped while creating it. Refused once a key is recorded

Usage: webvh-witness reset-witness-kek-claim [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -h, --help
          Print help
```

### `webvh-witness setup-offline-prepare`

```text
Step 1/2 of the offline (air-gapped VTA) setup wizard.

Runs the interactive prompts, writes the bootstrap-request.json + ephemeral seed, and serialises the operator's answers to a state TOML file. After the VTA admin returns a sealed bundle, run `setup-offline-complete`.

Usage: webvh-witness setup-offline-prepare [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --request <REQUEST>
          Path for the bootstrap-request.json file

          [default: bootstrap-request.json]

      --state <STATE>
          Path for the pending state file (plain TOML, no secrets).

          The ephemeral bootstrap seed is persisted to the configured secrets backend (keyring / AWS / GCP / plaintext-in-config), not to a file.

          [default: setup-offline-state.toml]

  -h, --help
          Print help (see a summary with '-h')
```

### `webvh-witness setup-offline-complete`

```text
Step 2/2 of the offline setup wizard.

Opens the sealed bundle with the seed saved during step 1, then persists the DID + keys + config + admin ACL per the choices captured in the state file.

Usage: webvh-witness setup-offline-complete [OPTIONS] --bundle <BUNDLE> --expect-digest <EXPECT_DIGEST>

Options:
      --bundle <BUNDLE>
          Path to the ASCII-armored sealed bundle from the VTA admin

  -c, --config <CONFIG>
          Path to the configuration file

      --expect-digest <EXPECT_DIGEST>
          Expected SHA-256 digest (lowercase hex) of the armored ciphertext; communicated out-of-band

      --state <STATE>
          Path to the state file written by `setup-offline-prepare`

          [default: setup-offline-state.toml]

  -h, --help
          Print help (see a summary with '-h')
```

### `webvh-witness vta-request`

```text
Write an offline VTA bootstrap request (for air-gapped VTAs).

Generates an ephemeral Ed25519 keypair and writes a JSON request the operator ferries to the VTA admin. Keep the companion seed file safe — it's needed to open the sealed response.

Usage: webvh-witness vta-request [OPTIONS] --mediator-did <MEDIATOR_DID>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --out <OUT>
          Path for the bootstrap-request.json file

          [default: bootstrap-request.json]

      --seed <SEED>
          Path for the ephemeral seed (keep this secret; chmod 0600 on Unix)

          [default: bootstrap-seed.bin]

      --label <LABEL>
          Operator-visible label identifying this request

          [default: webvh-witness]

      --mediator-did <MEDIATOR_DID>
          DIDComm mediator DID. Bound to the `did-hosting-server` template's `MEDIATOR_DID` variable so the rendered DID document advertises the right mediator endpoint

      --context <CONTEXT>
          VTA context the integration will live in. Embedded as `contextHint` in the request so the VTA admin can run `vta bootstrap provision-integration` without `--context`

          [default: did-hosting]

  -h, --help
          Print help (see a summary with '-h')
```

### `webvh-witness export-sealed`

```text
Export this witness's DID + signing/KA keys as an HPKE-sealed migration bundle. See `did-hosting-server export-sealed` for semantics

Usage: webvh-witness export-sealed [OPTIONS] --request <REQUEST>

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --request <REQUEST>
          Path to the receiver's bootstrap-request.json

      --out <OUT>
          Path for the ASCII-armored sealed output

          [default: sealed-export.txt]

      --digest-out <DIGEST_OUT>
          Optional file to write the SHA-256 digest to. Always printed to stderr regardless

  -h, --help
          Print help
```

### `webvh-witness import-sealed`

```text
Open a sealed `DidSecrets` migration bundle and import the contained keys as this witness's identity

Usage: webvh-witness import-sealed [OPTIONS] --bundle <BUNDLE> --expect-digest <EXPECT_DIGEST>

Options:
      --bundle <BUNDLE>
          Path to the ASCII-armored sealed bundle

  -c, --config <CONFIG>
          Path to the configuration file

      --expect-digest <EXPECT_DIGEST>
          Expected SHA-256 digest of the armored ciphertext

      --seed <SEED>
          Path to the ephemeral seed the receiver saved when generating the bootstrap-request.json

          [default: bootstrap-seed.bin]

      --producer-pubkey <PRODUCER_PUBKEY>
          Optional Ed25519 public key of the producer (multibase- encoded, matches `#key-0` in the producer's DID document). When supplied, the bundle's `DidSigned` assertion is verified against it; omit to fall back to digest-only trust

      --jwt-key <JWT_KEY>
          Optional Ed25519 JWT signing key (multibase-encoded, auto-generated if omitted)

      --force
          Overwrite existing secrets without prompting

  -h, --help
          Print help
```

### `webvh-witness vta-open`

```text
Open a sealed VTA bootstrap response.

Reads the armored bundle the operator ferried back, verifies the out-of-band digest, opens the HPKE sealed payload with the ephemeral seed, and emits the DID document + signed DID log for import via `did-hosting-server bootstrap-did` on the hosting server.

Usage: webvh-witness vta-open [OPTIONS] --bundle <BUNDLE> --expect-digest <EXPECT_DIGEST>

Options:
      --bundle <BUNDLE>
          Path to the ASCII-armored sealed bundle

  -c, --config <CONFIG>
          Path to the configuration file

      --expect-digest <EXPECT_DIGEST>
          Expected SHA-256 digest of the armored ciphertext (from the operator, out-of-band)

      --seed <SEED>
          Path to the ephemeral seed saved by `vta-request`

          [default: bootstrap-seed.bin]

      --did-doc-out <DID_DOC_OUT>
          Where to write the rendered DID document as JSON

          [default: witness-did.json]

      --did-log-out <DID_LOG_OUT>
          Where to write the signed DID log (JSONL). Omitted when the template didn't emit a WebvhLog output

          [default: witness-did.jsonl]

      --secrets-out <SECRETS_OUT>
          Where to save the minted private signing + KA key pair plus VTA trust material (authorization VC, pinned VTA DID) as JSON. Feed into `webvh-witness setup` to persist via the configured secret backend

          [default: witness-secrets.json]

  -h, --help
          Print help (see a summary with '-h')
```
<!-- END webvh-witness -->

<!-- BEGIN webvh-watcher -->
## `webvh-watcher`

```text
WebVH Watcher — Read-Only DID Mirror

Usage: webvh-watcher [OPTIONS] [COMMAND]

Commands:
  setup   Provision the watcher's DID from a VTA context and write config.toml
  health  Run health check diagnostics. Exits non-zero when a check fails (or, with --strict, warns), so it can gate a deploy or a container probe
  help    Print this message or the help of the given subcommand(s)

Options:
  -c, --config <CONFIG>
          Path to the configuration file

  -h, --help
          Print help

  -V, --version
          Print version
```

### `webvh-watcher setup`

```text
Provision the watcher's DID from a VTA context and write config.toml.

Interactive by default (online VTA). For scripted setup, pass `--from <recipe.toml>`; an online recipe also needs `--setup-key-file`, minted first with `--setup-key-out`.

Usage: webvh-watcher setup [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --from <FILE>
          Path to a declarative setup recipe TOML. Skips every prompt

      --setup-key-out <SETUP_KEY_OUT>
          Mint an ephemeral setup did:key, persist it to <path>, print the `pnm contexts create` command, and exit

      --setup-key-file <SETUP_KEY_FILE>
          Reuse the setup did:key persisted by `--setup-key-out`

      --context <CONTEXT>
          Context id for `--setup-key-out`'s PNM command

          [default: did-hosting]

      --force-reprovision
          Allow overwriting an existing config.toml. The previous file is moved to config.toml.bak

  -h, --help
          Print help (see a summary with '-h')
```

### `webvh-watcher health`

```text
Run health check diagnostics. Exits non-zero when a check fails (or, with --strict, warns), so it can gate a deploy or a container probe

Usage: webvh-watcher health [OPTIONS]

Options:
  -c, --config <CONFIG>
          Path to the configuration file

      --strict
          Also exit non-zero when a check only warned (a store held by the running service, plaintext secrets, a non-2xx reachability probe)

  -h, --help
          Print help
```
<!-- END webvh-watcher -->
