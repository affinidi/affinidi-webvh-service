# Affinidi WebVH Service

A collection of services to operate
[WebVH](https://www.w3.org/TR/did-web-vh/) DIDs in production.

> **IMPORTANT:**
> affinidi-webvh-service crates are provided "as is" without any
> warranties or guarantees, and by using this framework, users agree
> to assume all risks associated with its deployment and use
> including implementing security, and privacy measures in their
> applications. Affinidi assumes no liability for any issues arising
> from the use or modification of the project.

## Architecture

The workspace contains six crates that can be deployed independently
or combined into a single binary:

```
Standalone mode:                          Daemon mode:

┌──────────────┐                         ┌───────────────────────┐
│ webvh-control│ (UI + proxy + registry) │    webvh-daemon       │
│   :8100      │──────┐                  │       :8100           │
└──────────────┘      │                  │ ┌───────────────────┐ │
                      ├─► webvh-server   │ │ /          server │ │
┌──────────────┐      │     :8101        │ │ /witness   witness│ │
│ webvh-server │◄─────┘                  │ │ /watcher   watcher│ │
│   :8101      │      ├─► webvh-witness  │ │ /control   control│ │
└──────────────┘      │     :8102        │ └───────────────────┘ │
┌──────────────┐      │                  │   (shared listener,   │
│webvh-witness │◄─────┘                  │    separate stores)   │
│   :8102      │      ├─► webvh-watcher  └───────────────────────┘
└──────────────┘      │     :8103
┌──────────────┐      │
│webvh-watcher │◄─────┘
│   :8103      │ (read-only DID mirror)
└──────────────┘
```

## Components

| Crate | Binary | Description |
| ----- | ------ | ----------- |
| [webvh-server](webvh-server/) | `webvh-server` | DID hosting and lifecycle management — create, upload, resolve, delete DIDs with REST API and DIDComm v2 authentication |
| [webvh-witness](webvh-witness/) | `webvh-witness` | Witness node — generates and manages cryptographic witness proofs for DID integrity verification |
| [webvh-watcher](webvh-watcher/) | `webvh-watcher` | Read-only DID mirror — receives pushed DID updates from servers and serves them publicly for redundancy |
| [webvh-control](webvh-control/) | `webvh-control` | Control plane — unified management UI, service registry, reverse proxy to backend services, passkey authentication |
| [webvh-daemon](webvh-daemon/) | `webvh-daemon` | Unified daemon — embeds server + witness + watcher + control plane in a single binary for simple deployments |
| [webvh-common](webvh-common/) | *(library)* | Shared types, traits, auth, ACL, storage, config, and passkey modules used by all services |

## Quick Start

### Requirements

- Rust 1.91.0+ (2024 Edition)
- Node.js 18+ (only if building the management UI)

### Option 1: Unified daemon (recommended for getting started)

The daemon runs all services on a single port:

```bash
git clone https://github.com/affinidi/affinidi-webvh-service.git
cd affinidi-webvh-service
cargo build -p affinidi-webvh-daemon --release
./target/release/webvh-daemon
```

See [webvh-daemon/README.md](webvh-daemon/) for configuration details.

### Option 2: Standalone services

Run each service independently for distributed deployments:

```bash
# Build all services
cargo build --workspace --release

# Run each service with its own config
webvh-server setup && webvh-server
webvh-witness setup && webvh-witness
webvh-control setup && webvh-control
webvh-watcher --config watcher-config.toml
```

See each crate's README for detailed setup instructions.

## Example Client

The `webvh-server` crate includes an example CLI (`webvh-server/examples/client.rs`)
that demonstrates the full flow of programmatically creating a `did:webvh` DID
and uploading it to a running webvh-server. It handles DIDComm v2
authentication, DID document construction, WebVH log entry creation, and
upload.

### Building

```sh
cargo build -p affinidi-webvh-server --example client
```

### Usage

1. Start the webvh-server with DIDComm authentication configured.

2. Run the example, pointing it at the server:

   ```sh
   cargo run -p affinidi-webvh-server --example client -- --server-url http://localhost:8101
   ```

3. The example will generate a `did:key` identity and pause, printing the DID:

   ```
   Generated DID: did:key:z6Mk...
   Ensure this DID is in the server ACL (e.g. via webvh-server invite).
   Press Enter to continue...
   ```

   Add the printed DID to the server's ACL (for example, by running the
   webvh-server `add-acl` command in another terminal), then press Enter.

4. The example will authenticate, create the DID, upload it, and verify
   resolution. On success it prints a summary:

   ```
   DID Created and Hosted Successfully!
     Mnemonic:   apple-banana
     SCID:       FHcGtSJ...
     DID URL:    http://localhost:8101/apple-banana/did.jsonl
     DID:        did:webvh:FHcGtSJ...:localhost%3A8085:apple-banana
     Public Key: z6Mk...
   ```

## Support & feedback

If you face any issues or have suggestions, please don't hesitate to contact us
using [this link](https://share.hsforms.com/1i-4HKZRXSsmENzXtPdIG4g8oa2v).

### Reporting technical issues

If you have a technical issue with the Affinidi WebVH Service codebase, you can
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

Want to contribute?

Head over to our [CONTRIBUTING](https://github.com/affinidi/affinidi-webvh-service/blob/main/CONTRIBUTING.md)
guidelines.
