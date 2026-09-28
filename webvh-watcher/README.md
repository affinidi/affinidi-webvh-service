# Affinidi WebVH Watcher

The WebVH Watcher is a read-only DID mirror. The control planes it is
configured to mirror push it signed `webvh/sync/*` Trust Tasks, and it serves
what they push publicly. It provides redundancy and geographic distribution
for DID resolution without managing DIDs.

The watcher has its own DID, with keys in a VTA context, like every other
service here. It verifies every log it mirrors exactly as a hosting server
does, and it applies a sync only when its source signed it.

> **IMPORTANT:**
> did-hosting-service crates are provided "as is" without any
> warranties or guarantees, and by using this framework, users
> agree to assume all risks associated with its deployment and
> use including implementing security, and privacy measures in
> their applications. Affinidi assumes no liability for any
> issues arising from the use or modification of the project.

## Getting Started

### Prerequisites

- Rust 1.94.0+ (2024 Edition)

### 1. Build

```bash
cargo build --locked -p webvh-watcher --release
```

The binary is produced at `target/release/webvh-watcher`.

### 2. Set up

`webvh-watcher setup` provisions the watcher's DID from a VTA context
(interactive, online), or `webvh-watcher setup --from <recipe.toml>` for any
VTA mode — see `examples/webvh-watcher-build.toml`. It writes `config.toml`,
stores the DID's keys in the secrets backend, and writes `watcher-did.jsonl`
for you to publish on a hosting server. The part of `config.toml` that says
whom it mirrors:

```toml
[sync]
# Only a webvh/sync/* Trust Task signed by one of these DIDs is applied.
source_dids = ["did:webvh:control.example.com"]
```

### 3. Configure the control plane

On each control plane the watcher mirrors, map the watcher's URL to its DID:

```toml
[[registry.watchers]]
url = "https://watcher1.example.com"
did = "did:webvh:…:watcher1.example.com"
```

A DID whose log names `https://watcher1.example.com` in its `watchers`
parameter is then pushed there through the control plane's outbox — the same
delivery, retry and acknowledgement as its edges — over the transport the
watcher's DID advertises (TSP, DIDComm, or HTTPS).

### 4. Start the watcher

```bash
webvh-watcher --config config.toml
```

## How It Works

```
control plane ──(signed webvh/sync/update|delete|batch, TSP · DIDComm · HTTPS)──► webvh-watcher

Clients ──(GET /{mnemonic}/did.jsonl)──► webvh-watcher
```

1. A DID is published at the control plane.
2. The control plane queues a signed `webvh/sync/update/0.2` for every
   configured watcher the log names.
3. The watcher verifies the document's proof (`proofPurpose:
   authentication`, bound to its issuer, addressed to the watcher, fresh, not
   a replay) and that the issuer is one of `sync.source_dids`; then it
   verifies the log — its chain and witness proofs, the slot it names, and
   that it strictly extends anything already mirrored for that DID — and
   answers with a signed `#response`, which settles the outbox entry.
4. Clients resolve DIDs from any watcher.

A document that does not verify gets no reply. A verified one from a DID that
is not a source is refused `notAuthorized` (signed), and is not recorded.

## Configuration

The watcher is configured via a TOML file. By default it looks
for `config.toml` in the current directory. You can specify a
different path with the `--config` flag or the
`WATCHER_CONFIG_PATH` environment variable.

### Environment Variable Overrides

| Variable               | Description         |
| ---------------------- | ------------------- |
| `WATCHER_CONFIG_PATH`  | Path to config file |
| `WATCHER_SERVER_HOST`  | Bind host           |
| `WATCHER_SERVER_PORT`  | Bind port           |
| `WATCHER_LOG_LEVEL`    | Log level           |
| `WATCHER_SERVER_DID`   | The watcher's DID   |
| `WATCHER_MEDIATOR_DID` | Its mediator        |
| `WATCHER_SOURCE_DIDS`  | Comma-separated source DIDs |

## CLI Commands

```
webvh-watcher                                  # Run watcher (default)
webvh-watcher setup                            # Interactive online VTA setup
webvh-watcher setup --setup-key-out <path>     # Mint a setup key for a headless online setup
webvh-watcher setup --from <recipe.toml> [--setup-key-file <path>]
webvh-watcher health                           # Diagnostics
```

## API Endpoints

### Public (unauthenticated)

| Method | Path                            | Description         |
| ------ | ------------------------------- | ------------------- |
| `GET`  | `/api/health`                   | Health check        |
| `GET`  | `/{mnemonic}/did.jsonl`         | Resolve DID log     |
| `GET`  | `/{mnemonic}/did-witness.json`  | Resolve witness     |
| `GET`  | `/.well-known/did.jsonl`        | Root DID log        |
| `GET`  | `/.well-known/did-witness.json` | Root witness        |

### Trust Tasks

| Method | Path               | Description |
| ------ | ------------------ | ----------- |
| `POST` | `/api/trust-tasks` | The HTTPS binding of `webvh/sync/update/0.2`, `webvh/sync/delete/0.2`, `webvh/sync/batch/0.1` |

The same documents are accepted over TSP and DIDComm on the watcher's
mediator connection.

## Library Usage

The webvh-watcher crate can be used as a library (e.g., by the
[did-hosting-daemon](../did-hosting-daemon/)). It exposes:

- `webvh_watcher::config::AppConfig` — configuration
- `webvh_watcher::server::AppState` — application state
- `webvh_watcher::routes::router()` — Axum router
- `webvh_watcher::server::run()` — standalone entry point

## Support & feedback

If you face any issues or have suggestions, please don't
hesitate to contact us using
[this link](https://share.hsforms.com/1i-4HKZRXSsmENzXtPdIG4g8oa2v).

### Reporting technical issues

If you have a technical issue with the Affinidi DID Hosting Service
codebase, you can also create an issue directly in GitHub.

1. Ensure the bug was not already reported by searching on
   GitHub under
   [Issues](https://github.com/affinidi/did-hosting-service/issues).

2. If you're unable to find an open issue addressing the
   problem,
   [open a new one](https://github.com/affinidi/did-hosting-service/issues/new).
   Be sure to include a **title and clear description**, as
   much relevant information as possible, and a **code sample**
   or an **executable test case** demonstrating the expected
   behaviour that is not occurring.

## Contributing

Want to contribute? Head over to our
[CONTRIBUTING](https://github.com/affinidi/did-hosting-service/blob/main/CONTRIBUTING.md)
guidelines.
