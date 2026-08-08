# Affinidi DID Hosting Client

`did-hosting-client` is a client library for talking to a
[did-hosting-server](../did-hosting-server/) or
[did-hosting-daemon](../did-hosting-daemon/) over REST + DIDComm v2.
It is the integrator-facing surface: authenticate with a DID, reserve
a path, publish and update `did:webvh` logs, and delete DIDs.

The daemon's wire contract is the source of truth; this crate ships a
thin typed mirror of it. Every REST call carries the canonical
`Trust-Task:` header so the daemon can exact-match the operation.

> **IMPORTANT:**
> did-hosting-service crates are provided "as is" without any
> warranties or guarantees, and by using this framework, users
> agree to assume all risks associated with its deployment and
> use including implementing security, and privacy measures in
> their applications. Affinidi assumes no liability for any
> issues arising from the use or modification of the project.

## Getting Started

### Prerequisites

- Rust 1.95.0+ (2024 Edition)

### Add the dependency

```toml
[dependencies]
did-hosting-client = "0.1"
```

### Usage

`Client` is the raw REST handle — it takes an access token per call.
`AuthedClient` wraps it with a signing identity and runs the
authenticate / refresh ladder for you, which is what most integrators
want:

```rust,no_run
use std::sync::Arc;
use did_hosting_client::{AuthedClient, Client, InMemoryTokenStore, ServerLocks};

# async fn example(identity: /* HostingSigningIdentityOwned */ ()) -> Result<(), Box<dyn std::error::Error>> {
let tokens = Arc::new(InMemoryTokenStore::default());
let client = Client::new("https://hosting.example.com", "did:webvh:...:daemon", tokens)?;

let authed = AuthedClient::new(
    client,
    identity,                 // owned DID + signing key
    Arc::new(ServerLocks::default()),
    "did:webvh:...:daemon",   // the daemon's DID — DIDComm `to`
);

if authed.check_path("alice", None).await? {
    let uri = authed.request_uri("alice", None).await?;
    // ... build the signed did.jsonl for `uri`, then publish it.
}
# Ok(())
# }
```

## What's in scope

- **Authentication** — DIDComm v2 JWS challenge-response, exchanged
  for a Bearer token used on subsequent REST calls. Tokens are
  zeroized on drop and redacted from `Debug`.
- **DID lifecycle** — check path, reserve URI, atomic
  register-and-publish, publish update, delete.
- **Agent names** — the `/@alice` shortcut request/response types and
  the Trust-Task URLs for check / update / remove.
- **Trust-Tasks transport** — canonical task URL constants in
  `trust_tasks`, set as the `Trust-Task:` header on every request.

Out of scope for 0.1: the admin / observability surface (ACL, stats,
time-series, services overview, registry CRUD). The daemon exposes
those, but the integrator-facing client does not ship them yet.

## Design choices

- **No `did-hosting-common` dependency.** Pulling in the daemon's
  internal types would chain in fjall, axum, and the secret-store
  backends. The only daemon-shared crate is `didwebvh-rs` (protocol
  types), which keeps this crate publishable stand-alone.
- **HTTPS-only by default.** Loopback (`127.0.0.1`, `::1`,
  `localhost`) is allowed for development; anything else without TLS
  fails closed.
- **Runtime-agnostic traits.** `ServerLocks` uses
  `tokio::sync::Mutex` internally, but no trait defined here requires
  a specific runtime — `HostingTokenStore` can be implemented against
  any executor.
- **rustls, not OpenSSL.** `reqwest` is pinned to rustls so
  integrators don't need a system OpenSSL.

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
