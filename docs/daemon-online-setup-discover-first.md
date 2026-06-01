# Daemon online setup — discover-first publication choice

## Problem

`did-hosting-daemon setup` (online VTA mode) collects the DID path folded into a
Public URL **before** talking to the VTA, then calls the SDK `run_provision`.
When the VTA has a registered webvh hosting server, `run_provision` auto-selects
it (server-managed mode), where the path comes from `WEBVH_PATH` — not the `URL`
var. The folded path is ignored and the hosting server rejects the empty path:

    e.p.did.path-invalid: validation error: [path] path must not be empty

vta-sdk 0.9.1 derives `WEBVH_PATH` from the `URL` for `run_provision`, which fixes
the crash for the serverless contract. But two things remain:

1. `run_provision` **always** auto-picks a registered server — it gives the operator
   no way to choose self-hosting (serverless) vs publishing through a server, and
   bails outright when 2+ servers are registered.
2. `run_provision` gives the operator no say in *where* the daemon's own DID is
   published. Self-hosting (the daemon serves its own `did.jsonl`) is the common and
   simplest deployment, but it is **not** a rule: a hosting service may deliberately
   publish its own DID on **another** hosting service — for redundancy / HA (the DID
   keeps resolving if this node is down) or delegated hosting (a shared, highly
   available hosting tier). Both are valid; the operator must be able to choose.

## Decision (from the owner)

Let the operator **choose** at setup time:

- **Self-host (serverless)** — the daemon publishes its own `did.jsonl` at
  `<public-url>/<did-path>/did.jsonl`. `webvh_server_id = None`. This is the
  documented default model and already works on 0.9.1.
- **Publish via a registered hosting server (server-managed)** — the operator
  picks one of the VTA's registered webvh servers (and, if multi-tenant, a domain),
  and supplies a path. `webvh_server_id = Some(id)`; the DID is hosted on that
  server's domain.

## Reference implementation

`verifiable-trust-infrastructure/vtc-service/src/setup/wizard.rs` already does
exactly this for the `vtc-host` template. We mirror its two helpers:

- `select_webvh_target(resolved, setup_key) -> WebvhTarget { server_id, domain, path }`
  - `connect_setup_client` — REST `challenge_response_light` if the VTA advertises
    REST, else `VtaClient::connect_didcomm`.
  - `prompt_webvh_server(&client)` — `client.list_webvh_servers()` → `Select` with a
    trailing "Serverless — self-host" entry. Empty catalogue / list error → serverless.
  - `prompt_webvh_domain(&client, sid)` — `client.list_webvh_server_domains(sid)` →
    `Select` only when 2+ domains; else `None` (server resolves its default).
  - `prompt_webvh_path(sid)` — free-text path label under the server.
- `drive_provision(vta_did, setup_key, ask)` — replicates `run_provision`'s
  orchestration but bypasses the auto-pick: spawn `run_connection_test`; on
  `PreflightDone` spawn `run_provision_flight(.., None /*server*/, None /*path*/, ..)`
  so the `WEBVH_SERVER`/`WEBVH_DOMAIN`/`WEBVH_PATH` vars **already injected into the
  ask** flow through verbatim. Honours an explicit serverless choice and works with
  2+ registered servers.

The `WEBVH_*` vars are injected into `ask.integration_template_vars` from the
operator's `WebvhTarget` before `drive_provision` (vtc wizard lines ~1096-1112).

## Plan

### did-hosting-common/src/server/vta_setup.rs
- Add `online_provision_flight(vta_did, context_id, setup_key, ask, messages)
  -> OnlineProvisionOutcome` that drives `run_connection_test` → `run_provision_flight`
  (mirror `drive_provision`) and reuses `drain_provision_events_to_stderr` +
  the existing reply→`OnlineProvisionOutcome` flattening.
- Leave `online_provision_setup` (run_provision-based) in place for
  server/control/witness, which keep their current behaviour.

### did-hosting-daemon/src/setup.rs — `run_online_provision`
Reorder to discover-first:
1. Prompt VTA DID + context (move earlier).
2. Mint/load setup key; print the PNM `contexts create` / `acl create` hint; confirm.
3. `resolve_vta(&vta_did)` → mediator + rest_url.
4. Mediator selection (existing 3-way: VTA's / different / none).
5. Always prompt **Public URL** (the daemon's own reachable URL — `public_url`,
   WebAuthn RP, `URL` var).
6. `select_webvh_target` (serverless vs server+domain+path).
   - Serverless: also prompt the local **DID path** (today's `prompt_did_path`);
     `URL = hosting_url_for(public_url, did_path)`. `did_log` imported locally.
   - Server-managed: inject `WEBVH_SERVER`/`WEBVH_DOMAIN`/`WEBVH_PATH`. `URL` = the
     daemon's own public URL (document content / service endpoint).
7. Build the ask (`did_hosting_control` w/ mediator, else `did_hosting_daemon`),
   inject `WEBVH_*` vars, call `online_provision_flight`.
8. Config:
   - Serverless: `public_url` = operator origin; import `did_log` at `did_path` (today).
   - Server-managed: derive the resolution host/path from the **minted DID**; the
     daemon does not self-host this DID.

## Settled

1. **`public_url` is independent of the DID's canonical host.** `public_url` is the
   daemon's own reachable URL (API/UI/WebAuthn RP). The daemon's `did:webvh` encodes a
   single canonical host: in serverless that host *is* `public_url`; in server-managed
   it is the chosen hosting server's domain (redundancy / delegated hosting). The
   config keeps `public_url` = the daemon's own URL regardless, and `server_did`
   records the minted DID (whose host may differ).

2. **Local import.** The VTA returns the `webvh_log` in *both* modes
   (`did_webvh/mod.rs:924` — identical reply shape). Serverless: import it locally and
   self-host (today's behaviour). Server-managed: the canonical host is the remote
   service (that's the point — redundancy/delegated hosting), so the daemon does **not**
   self-import its own DID; it records `server_did` + the minted log only as needed for
   the runtime credential. (A local read-only mirror is a possible future enhancement,
   not v1.)
3. **`did_path` meaning.** Serverless: local hosting sub-path folded into `URL`.
   Server-managed: a label on the remote server (`WEBVH_PATH`), distinct from the
   daemon's own `public_url`. Keep them distinct in `finalize_daemon_setup`.

## Testing
- Unit: `WebvhTarget` var injection; serverless vs server-managed branch selection.
- Live (cannot run from here): full online setup against a VTA with 0 / 1 / 2+
  registered servers, both serverless and server-managed choices.
