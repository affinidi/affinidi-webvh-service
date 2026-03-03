# Affinidi WebVH Watcher

The WebVH Watcher is a read-only DID mirror that receives pushed
DID updates from [webvh-server](../webvh-server/) instances and
serves them publicly. It provides redundancy, geographic
distribution, and load balancing for DID resolution without
managing DIDs directly.

The watcher has no authentication, no ACL, and no DID lifecycle
management — it simply stores and serves replicated DID content.

> **IMPORTANT:**
> affinidi-webvh-service crates are provided "as is" without any
> warranties or guarantees, and by using this framework, users
> agree to assume all risks associated with its deployment and
> use including implementing security, and privacy measures in
> their applications. Affinidi assumes no liability for any
> issues arising from the use or modification of the project.

## Getting Started

### Prerequisites

- Rust 1.91.0+ (2024 Edition)

### 1. Build

```bash
cargo build -p affinidi-webvh-watcher --release
```

The binary is produced at `target/release/webvh-watcher`.

### 2. Configure

Create a `config.toml`:

```toml
[server]
host = "0.0.0.0"
port = 8103

[log]
level = "info"

[store]
data_dir = "data/webvh-watcher"

[sync]
# Shared secret tokens that source servers must present when pushing
push_tokens = ["my-shared-secret-token"]

# Optional: source servers to pull from for reconciliation
# [[sync.sources]]
# url = "http://server1:8101"
# token = "pull-token"
```

### 3. Configure the source server

On the webvh-server that will push DID updates, add the watcher
to its `config.toml`:

```toml
[[watchers]]
url = "http://watcher1.example.com:8103"
token = "my-shared-secret-token"
```

The token must match one of the watcher's `sync.push_tokens`.

### 4. Start the watcher

```bash
webvh-watcher --config config.toml
```

## How It Works

```
webvh-server ──(POST /api/sync/did)──► webvh-watcher
             ──(POST /api/sync/delete)──►

Clients ──(GET /{mnemonic}/did.jsonl)──► webvh-watcher
```

1. A DID is published on a webvh-server
2. The server pushes the DID content to all registered watchers
3. The watcher stores the content and serves it at the same
   public paths as the original server
4. Clients can resolve DIDs from any watcher instance

Push failures on the server side are logged but do not block the
primary publish operation.

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

## CLI Commands

```
webvh-watcher                     # Run watcher (default)
webvh-watcher setup               # Interactive config wizard (coming soon)
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

### Sync (token-authenticated)

| Method | Path                | Description              |
| ------ | ------------------- | ------------------------ |
| `POST` | `/api/sync/did`     | Receive pushed DID       |
| `POST` | `/api/sync/delete`  | Receive DID deletion     |

Sync endpoints require a `Bearer` token matching one of the
configured `sync.push_tokens`.

## Library Usage

The webvh-watcher crate can be used as a library (e.g., by the
[webvh-daemon](../webvh-daemon/)). It exposes:

- `affinidi_webvh_watcher::config::AppConfig` — configuration
- `affinidi_webvh_watcher::server::AppState` — application state
- `affinidi_webvh_watcher::routes::router()` — Axum router
- `affinidi_webvh_watcher::server::run()` — standalone entry point

## Support & feedback

If you face any issues or have suggestions, please don't
hesitate to contact us using
[this link](https://share.hsforms.com/1i-4HKZRXSsmENzXtPdIG4g8oa2v).

### Reporting technical issues

If you have a technical issue with the Affinidi WebVH Service
codebase, you can also create an issue directly in GitHub.

1. Ensure the bug was not already reported by searching on
   GitHub under
   [Issues](https://github.com/affinidi/affinidi-webvh-service/issues).

2. If you're unable to find an open issue addressing the
   problem,
   [open a new one](https://github.com/affinidi/affinidi-webvh-service/issues/new).
   Be sure to include a **title and clear description**, as
   much relevant information as possible, and a **code sample**
   or an **executable test case** demonstrating the expected
   behaviour that is not occurring.

## Contributing

Want to contribute? Head over to our
[CONTRIBUTING](https://github.com/affinidi/affinidi-webvh-service/blob/main/CONTRIBUTING.md)
guidelines.
