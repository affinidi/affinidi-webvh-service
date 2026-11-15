# Affinidi DID Hosting Service

A collection of services to operate
[WebVH](https://www.w3.org/TR/did-web-vh/) DIDs in production.

> **IMPORTANT:**
> did-hosting-service crates are provided "as is" without any
> warranties or guarantees, and by using this framework, users agree
> to assume all risks associated with its deployment and use
> including implementing security, and privacy measures in their
> applications. Affinidi assumes no liability for any issues arising
> from the use or modification of the project.

Documentation lives in [`docs/`](docs/README.md): start with the
[architecture overview](docs/architecture.md), the
[configuration reference](docs/configuration.md) and the
[setup guide](docs/bootstrap_startup.md).

## Architecture

The workspace contains six crates. The services can run as separate
processes or together in one binary:

```text
Standalone (distributed):                 Daemon (single host):

  owner (VTA / client)                      owner (VTA / client)
        │ signed Trust Tasks                      │ signed Trust Tasks
        ▼                                         ▼
┌─────────────────────┐                  ┌──────────────────────────┐
│ did-hosting-control │  control plane:  │   did-hosting-daemon     │
│       :8532         │  registry, UI,   │        :8534             │
└─────────┬───────────┘  source of record│  /           control +   │
          │ signed sync (outbox,         │              resolution  │
          │ retried until acknowledged)  │  /witness    witness     │
          ├──────────► did-hosting-server│  /watcher    watcher     │
          │             :8530 (edge)     │  (one listener, one      │
          └──────────► webvh-watcher     │   process; no network    │
                        :8533 (mirror)   │   between the parts)     │
                                         └──────────────────────────┘
  webvh-witness :8531 signs did:webvh witness proofs for the parties its
  ACL admits (a control plane, VTA or edge).
```

The control plane holds the authoritative state and pushes it out; edges and
watchers are caches that can be rebuilt from it. See
[docs/architecture.md](docs/architecture.md) for the trust model.

## Components

| Crate | Binary | Description |
| ----- | ------ | ----------- |
| [did-hosting-server](did-hosting-server/) | `did-hosting-server` | Edge: serves DID documents publicly and applies the signed sync updates its control plane sends (over TSP, DIDComm or HTTPS). No management surface |
| [webvh-witness](webvh-witness/) | `webvh-witness` | Witness node — signs did:webvh witness proofs on request |
| [webvh-watcher](webvh-watcher/) | `webvh-watcher` | Read-only DID mirror — the control planes it mirrors push it signed updates, and it serves them publicly for redundancy |
| [did-hosting-control](did-hosting-control/) | `did-hosting-control` | Control plane — DID lifecycle as Trust Tasks over TSP, DIDComm and HTTPS, management UI, service registry, passkey and wallet sign-in |
| [did-hosting-daemon](did-hosting-daemon/) | `did-hosting-daemon` | Unified daemon — control plane, resolution, witness and watcher in one binary (recommended for single-host deployments) |
| [did-hosting-common](did-hosting-common/) | *(library)* | Shared types, Trust Task definitions, client (`WebVHClient`), storage, config, ACL and passkey modules |

## Quick Start

### Requirements

- Rust: the workspace MSRV is `rust-version` in the root
  [`Cargo.toml`](Cargo.toml) (2024 edition).
- Node.js: the version in `engines.node` of
  [`did-hosting-ui/package.json`](did-hosting-ui/package.json). The default
  build of `did-hosting-control` and `did-hosting-daemon` includes the `ui`
  feature, which builds the management UI with npm when the bundle is
  missing or stale. To build without Node, drop the UI:
  `cargo build --locked -p did-hosting-daemon --release --no-default-features --features keyring,store-fjall,did-methods`
  (control: `--no-default-features --features keyring,store-fjall`).

> **Every build and install here passes `--locked`, and that is not
> decoration.** `Cargo.lock` is this workspace's tested dependency set. A
> build that floats past it can pick up a transitive release that was never
> tested here; the optional `aws-secrets` and `store-dynamodb` backends have
> been broken that way before (a breaking `aws-smithy-types` minor release),
> and because they are optional, an ordinary local check never notices.
>
> `cargo build` and `cargo test` honour the lockfile on their own, so `--locked`
> on those turns a silently stale lock into an error. **`cargo install` is the
> trap: it ignores `Cargo.lock` by default** — so a host install must be
> spelled `cargo install --locked --path did-hosting-control`.
>
> See the note beside the AWS dependencies in `did-hosting-common/Cargo.toml`
> for the builds to run after a dependency bump.



### Option 1: Unified daemon (recommended for getting started)

One process serves the control plane, the management UI, public DID
resolution and the witness on a single port (8534 by default). The shipped
self-managed recipe needs no VTA and runs as is against `localhost`:

```bash
git clone https://github.com/affinidi/affinidi-webvh-service.git
cd affinidi-webvh-service
cargo build --locked -p did-hosting-daemon --release

# Generate the daemon's own keys and DID and write config.toml.
./target/release/did-hosting-daemon setup --from examples/did-hosting-daemon-self-managed.toml

# Invite the first administrator (prints a passkey enrolment link).
./target/release/did-hosting-daemon invite --did <your-admin-did> --role admin

./target/release/did-hosting-daemon
```

The daemon supports two identity modes at setup time:

- **VTA-managed** — a parent VTA provisions the daemon's keys and DID
  (`examples/did-hosting-daemon-build.toml`, `vta_mode = "online"`).
- **Self-managed** — the daemon generates its own keys and self-hosts a
  `did:webvh` identifier. No VTA required. Daemon-only.
  See [docs/bootstrap_startup.md](docs/bootstrap_startup.md).

Running `did-hosting-daemon setup` with no `--from` starts the interactive
wizard instead. See [did-hosting-daemon/README.md](did-hosting-daemon/) for
the details.

### Option 2: Standalone services

Run each service as its own process for a distributed deployment. Set up the
control plane first: every edge and watcher is configured with the control
plane's DID, and refuses updates signed by anyone else.

```bash
cargo build --locked --workspace --release

did-hosting-control setup    # control plane: note its DID (server_did in its config.toml)
did-hosting-server setup     # edge: asks for the control plane's DID
webvh-witness setup          # optional: witness proofs
webvh-watcher setup          # optional: read-only mirror

did-hosting-control          # each binary runs from the config.toml setup wrote
did-hosting-server
```

An edge registers itself with its control plane by sending a signed
`server/register` Trust Task; the control plane then keeps it in sync through
its outbox. The walk-through is in
[docs/bootstrap_startup.md](docs/bootstrap_startup.md); every subcommand is in
the [CLI reference](docs/cli-reference.md).

> **Building with `--no-default-features`?** The DID-method
> features (`method-webvh`, `method-web`) are part of the default
> set on `did-hosting-server` (the daemon's equivalent is `did-methods`).
> A minimal build that drops them compiles fine but silently
> 404s every public DID resolution. If you customise features,
> opt the methods back in explicitly — see
> [did-hosting-server/README.md](did-hosting-server/README.md).

### Option 3: Non-interactive / scripted setup

Every `setup` subcommand accepts `--from <recipe.toml>` for CI / scripted
deployments. The recipe is declarative TOML with no secrets — keys are
generated by setup; cloud credentials come from the environment. Each
binary has a recipe in [`examples/`](examples/); CI loads and validates
every one of them.

**Online (VTA reachable from the machine running setup):**

```bash
# Phase 1: mint an ephemeral did:key, print the operator's command, exit.
did-hosting-server setup --setup-key-out setup.key --context did-hosting
# (the VTA operator enrols the printed did:key, e.g. with `pnm`)

# Phase 2: the recipe drives everything else. Set [identity].control_did
# in the recipe to your control plane's DID first.
did-hosting-server setup --from examples/did-hosting-server-build.toml \
                   --setup-key-file setup.key
```

**Air-gapped (no VTA network access — both phases non-interactive):**

```bash
# Phase 1: vta_mode = "offline-prepare" in the recipe.
did-hosting-server setup --from recipe.toml
# → writes bootstrap-request.json + persists ephemeral seed in secret backend.
# (operator ferries the request to the VTA admin and receives sealed bundle)

# Phase 2: flip vta_mode = "offline-complete" + add bundle_path/expect_digest.
did-hosting-server setup --from recipe.toml
# → opens the sealed bundle, finishes setup. No TTY required.
```

**VTA-less daemon (self-managed):**

```bash
did-hosting-daemon setup --from examples/did-hosting-daemon-self-managed.toml
```

Other flags: `--force-reprovision` to rotate an existing install (backs up
`config.toml` first), `--non-interactive` to fail fast on missing fields
instead of prompting, `<binary> uninstall` to tear down. Full reference in
[docs/bootstrap_startup.md](docs/bootstrap_startup.md) and
[docs/cli-reference.md](docs/cli-reference.md).

## Managing DIDs

Every management operation — registering and updating DIDs, domains, the
ACL, the service registry — is a signed [Trust Task](docs/trust-tasks.md)
sent to the control plane (or daemon). There is no REST management API. Use
the management UI, the `WebVHClient` in `did-hosting-common`, or the
`send-trust-task` CLI described in
[docs/sending-trust-tasks.md](docs/sending-trust-tasks.md).

### Example client

The `did-hosting-server` crate includes an example CLI
(`did-hosting-server/examples/client.rs`) that creates a `did:webvh` DID and
publishes it through a running control plane or daemon, using `WebVHClient`
to sign each request as a fresh `did:key`.

```sh
cargo build --locked -p did-hosting-server --example client
```

1. Start `did-hosting-daemon` (port 8534) or `did-hosting-control`
   (port 8532).

2. Run the example against it. `--webvh-did` is the service's own DID —
   `server_did` in its `config.toml`, also printed at the end of `setup`:

   ```sh
   cargo run -p did-hosting-server --example client -- \
     --server-url http://localhost:8534 \
     --webvh-did "$(grep '^server_did' config.toml | cut -d'"' -f2)"
   ```

3. The example generates a `did:key` identity and pauses:

   ```
   === Step 1: Identity Generated ===
     DID: did:key:z6Mk...

   Ensure this DID is in the server ACL (e.g. `did-hosting-control add-acl --did <did>`).
   Press Enter to continue...
   ```

   Add it to the ACL in another terminal — `did-hosting-daemon add-acl --did
   <did>` or `did-hosting-control add-acl --did <did>` (role `owner` by
   default) — then press Enter.

4. The example registers the DID, uploads its log and checks that it
   resolves. On success it prints a summary such as:

   ```
   === DID Created and Hosted Successfully! ===
     Mnemonic:   apple-banana
     SCID:       FHcGtSJ...
     DID URL:    http://localhost:8534/apple-banana/did.jsonl
     DID:        did:webvh:FHcGtSJ...:localhost%3A8534:apple-banana
     Public Key: z6Mk...
   ```

## Support & feedback

If you face any issues or have suggestions, please don't hesitate to contact us
using [this link](https://share.hsforms.com/1i-4HKZRXSsmENzXtPdIG4g8oa2v).

### Reporting technical issues

If you have a technical issue with the Affinidi DID Hosting Service codebase, you can
also create an issue directly in GitHub.

1. Ensure the bug was not already reported by searching on GitHub under
   [Issues](https://github.com/affinidi/affinidi-webvh-service/issues).

2. If you're unable to find an open issue addressing the problem,
   [open a new one](https://github.com/affinidi/affinidi-webvh-service/issues/new).
   Be sure to include a **title and clear description**, as much relevant
   information as possible,
   and a **code sample** or an **executable test case** demonstrating the expected
   behaviour that is not occurring.

## Contributing

Want to contribute? Head over to our [CONTRIBUTING](CONTRIBUTING.md)
guidelines.
