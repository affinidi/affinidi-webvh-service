# Sending Trust Tasks

> **Status:** current

Every management operation on a control plane — standalone
`did-hosting-control`, or the one inside `did-hosting-daemon` — is a signed
Trust Task. There is no REST management API. This page shows the three ways
to send one; the full list of tasks, with the proof and standing each needs,
is the [Trust Task catalogue](trust-tasks.md).

| Path | Use it for |
| ---- | ---------- |
| The management UI | Day-to-day operation. Every console action is a Trust Task signed in the browser. |
| `send-trust-task` (CLI) | Runbooks, incident response, scripts: one task, from the service host. |
| `WebVHClient` (Rust) | Programs: a VTA or your own tooling publishing DIDs. |

## From the command line: `send-trust-task`

`did-hosting-control` and `did-hosting-daemon` both have the command. It signs
one request with a `did:key` you hold, `POST`s it to the running service's
`/api/trust-tasks`, checks that the reply is signed by the service's own DID,
and prints the response payload as JSON. The full flags are in the
[CLI reference](cli-reference.md).

```text
did-hosting-control [--config config.toml] send-trust-task \
    --key <key.json> --type <task> [--payload <json> | --payload-file <file>] [--url <base>]
```

- `--type` is a full Type URI or its `<slug>/<version>` short form:
  `identity/list/0.1`, `did-management/registry/list/0.2`, `acl/list/0.3`. A
  version this release does not speak is refused before anything is sent.
- `--payload` is the request payload (default `{}`). Its members are the
  task's schema, in the vendored bundle under
  `did-hosting-common/trust-tasks/<slug>/<version>.bundle.json`; an unknown
  member is refused.
- `--url` defaults to `http://<server.host>:<server.port>` from the config
  (a `0.0.0.0` / `::` bind is dialled as loopback). The service's DID
  (`server_did`) comes from the same config.

A refusal is printed as an error with the task's error code, and the command
exits non-zero.

### 1. A key, and its place in the ACL

The signer is authorised like any other client: by its proof and its ACL
entry. Mint a `did:key` file — `setup --setup-key-out` writes one and exits
without touching the service's config (ignore the `pnm` command it prints; it
is for VTA enrolment):

```bash
did-hosting-control setup --setup-key-out admin-key.json
jq -r .did admin-key.json        # the key's DID
```

Then grant it the standing the tasks you want need (most operator tasks need
`admin`). The ACL commands work on the stopped service's store:

```bash
did-hosting-control add-acl --did "$(jq -r .did admin-key.json)" --role admin --label "ops CLI key"
```

On the daemon the commands are the same with `did-hosting-daemon`. Keep the
key file like any other admin credential (it is written `0600`); remove its ACL
entry (`remove-acl`) when you no longer need it.

> **Step-up.** The destructive tasks (`did/delete`, `identity/retire`,
> `registry/purge-domain`, issuing an enrolment invite) require an `aal2`
> session *when the request carries a browser session*. A document authorised
> by its signer's own key, as these are, carries none, so the admin key is
> enough.

### 2. Examples

```bash
# The service's identity generations (key material still honoured).
did-hosting-control send-trust-task --key admin-key.json --type identity/list/0.1

# Stop honouring a superseded generation now (the live kill switch).
did-hosting-control send-trust-task --key admin-key.json \
  --type identity/retire/0.1 --payload '{"generationId": 0}'

# The fleet: registered edges, watchers and witnesses, with their health.
did-hosting-control send-trust-task --key admin-key.json \
  --type registry/list/0.2 --payload '{"serviceType": "server"}'

# Assign a hosting domain to an edge (instanceId from registry/list).
did-hosting-control send-trust-task --key admin-key.json \
  --type domain/assign/0.1 \
  --payload '{"instanceId": "did_webvh_…_edge1.example.com", "domain": "dids.example.com"}'

# Have one edge delete its copy of a domain's DIDs.
did-hosting-control send-trust-task --key admin-key.json \
  --type registry/purge-domain/0.1 \
  --payload '{"instanceId": "did_webvh_…_edge1.example.com", "domain": "old.example.com"}'

# DID slots: the first page of one owner's slots on one domain.
did-hosting-control send-trust-task --key admin-key.json \
  --type did/list/0.2 \
  --payload '{"domain": "dids.example.com", "owner": "did:key:z6Mk…", "limit": 100}'
```

`did/list` pages: pass the reply's `nextCursor` back as `cursor` while one is
present. Its `vnd.affinidi.webvh` extension adds `search` (matched without
case against the mnemonic, the DID and its agent names) and `agentName` (with
`domain`); a searched page may come back short, or empty, with a
`nextCursor`:

```bash
did-hosting-control send-trust-task --key admin-key.json --type did/list/0.2 \
  --payload '{"ext": {"vnd.affinidi.webvh": {"search": "alice"}}}'
```

The output is JSON, so `jq` works on it:

```bash
did-hosting-control send-trust-task --key admin-key.json --type identity/list/0.1 \
  | jq '.generations[] | {generationId, current}'
```

`fetch-metrics` is the same mechanism with the type fixed to
`server/metrics/0.1` and the output narrowed to the counters, for a
`metricsReader` key (see [metrics](metrics.md)).

## From the management UI

The console (served by the control plane at `/`) signs each action as a
Trust Task with a key bound to your sign-in session, and sends it to
`POST /api/trust-tasks`. Destructive actions ask you to step the session up to
`aal2` first (a passkey or your wallet). Use the UI when you can; the CLI is for
when you cannot reach it or need to script.

## From a program: `WebVHClient`

`did_hosting_common::WebVHClient` signs every request as a DID you hold and
verifies every reply. `did-hosting-server/examples/client.rs` is a complete
program that creates and publishes a `did:webvh` with it:

```rust
use did_hosting_common::WebVHClient;

let mut client = WebVHClient::new("https://control.example.com");
client.sign_as(&my_did, &my_secret, &control_plane_did).await?;
let dids = client.list_dids().await?;
```

It has typed methods for the DID lifecycle (`create_did`, `upload_did`,
`list_dids`, `delete_did`, agent names). For anything else, send the task
with `send-trust-task` or build a signed document with
`did_hosting_common::server::trust_tasks::send::build_signed_request`.

## Over TSP or DIDComm

The same documents are accepted over TSP and the DIDComm trust-task envelope
(a VTA usually uses one of these). The control plane's DID document says which
it listens on; see [TSP transport](tsp-transport.md). The authorisation is the
same on every transport: the document's own proof.
