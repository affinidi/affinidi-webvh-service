# Bootstrap & Startup Guide

This document explains how to set up a complete WebVH environment with DIDComm-based authentication between services.

## Prerequisites

- PNM CLI installed and configured with access to a VTA (Verifiable Trust Agent)
- Compiled WebVH binaries: `webvh-server`, `webvh-control`
- A public URL where the server will serve DIDs (e.g., `https://did.example.com`)

## Architecture Overview

Services authenticate with each other using DIDComm challenge-response:

- **webvh-server** — hosts DID documents at public URLs
- **webvh-control** — manages service registration, ACLs, and DID sync
- **webvh-witness** — provides witness proofs for DID log entries

Each service has its own DID, created during bootstrap. The server authenticates with the control plane using its DID, replacing the previous bearer-token approach.

## Sequence Diagram

```mermaid
sequenceDiagram
    participant Admin
    participant PNM as PNM CLI
    participant VTA
    participant Server as webvh-server
    participant Control as webvh-control

    rect rgb(230, 240, 255)
        Note over Admin,VTA: Phase 0a — Provision VTA Contexts (PNM CLI)
        loop For each service (webvh-server, webvh-control, webvh-witness)
            Admin->>PNM: pnm contexts provision<br/>--name <service> --did-url <url>
            PNM->>VTA: Create context + DID
            VTA->>PNM: context_id, DID material, secrets
            PNM->>Admin: ContextProvisionBundle (base64url)
        end
    end

    rect rgb(235, 245, 255)
        Note over Admin: Phase 0b — Import Provision Bundles
        Admin->>Admin: webvh-control bootstrap<br/>--control-bundle eyJ...
        Note over Admin: Writes control plane<br/>*.bundle + *.did.jsonl
    end

    rect rgb(240, 248, 255)
        Note over Admin: Phase 1 — Configure Services
        Admin->>Admin: webvh-server setup (import server provision bundle)
        Admin->>Admin: webvh-control setup (import control secrets bundle)
        Admin->>Server: webvh-server load-did --path .well-known<br/>--did-log webvh-server.did.jsonl
        Admin->>Server: webvh-server load-did --path services/control<br/>--did-log webvh-control.did.jsonl
        Admin->>Control: webvh-control add-acl<br/>--did did:webvh:SERVER_SCID:... --role admin
    end

    rect rgb(245, 255, 245)
        Note over Server,Control: Phase 2 — Start Services
        Admin->>Server: Start webvh-server
        Note over Server: Serves /.well-known/did.jsonl (own DID)<br/>Serves /services/control/did.jsonl (control DID)
        Admin->>Control: Start webvh-control
        Note over Control: Configured with own server_did
    end

    rect rgb(255, 248, 240)
        Note over Server,Control: Phase 3 — DIDComm Registration
        Server->>Control: POST /api/auth/challenge {did: server_did}
        Control->>Server: {session_id, challenge}
        Note over Server: Sign DIDComm message with server's Ed25519 key
        Server->>Control: POST /api/auth/ (packed DIDComm message)
        Note over Control: Resolve server DID from server's public URL<br/>Verify signature, check ACL → issue JWT
        Control->>Server: {access_token, refresh_token}
    end

    rect rgb(255, 245, 250)
        Note over Server,Control: Phase 4 — Service Registration + DID Sync
        Server->>Control: POST /api/control/register-service<br/>Bearer JWT<br/>{serviceType, url, preloadedDids: [{mnemonic, didId, versionCount}]}
        Note over Control: Register instance in registry<br/>Check preloaded DIDs against known DIDs
        Control->>Server: {instanceId, didUpdates: [...]}
        Note over Server: Apply any DID updates to local store
    end
```

## Step-by-Step Setup

### Phase 0a: Provision VTA Contexts with PNM

Each WebVH service gets its own VTA context for secret/config isolation. Use the PNM CLI to provision a context with a DID for each service:

```bash
# Provision the webvh-server context
# The --did-url should point to where the server's DID will be published
pnm contexts provision \
  --name webvh-server \
  --did-url https://did.example.com/.well-known

# Provision the webvh-control context
pnm contexts provision \
  --name webvh-control \
  --did-url https://did.example.com/services/control

# (Optional) Provision the webvh-witness context
pnm contexts provision \
  --name webvh-witness \
  --did-url https://did.example.com/services/witness
```

Each command outputs a base64url-encoded **ContextProvisionBundle** containing:
- VTA context credentials (admin DID + credential)
- DID material (DID document, log entry)
- Private keys (signing + key-agreement)

Save the output string from each command — you'll pass them to the setup wizards.

### Phase 0b: Import Control Plane Provision Bundle

Extract the control plane's secrets and DID log from its provision bundle:

```bash
webvh-control bootstrap \
  --control-bundle <base64url output from webvh-control provision> \
  --output-dir ./bootstrap-output
```

This creates:
```
bootstrap-output/
  webvh-control.bundle      # secrets bundle (base64url, for setup wizard)
  webvh-control.did.jsonl   # DID log entry (for load-did)
```

### Phase 1: Configure Services

#### 1a. Import secrets via setup wizards

Run the setup wizard for each service. Each wizard prompts to import a secrets bundle
(from PNM provision or from the bootstrap step):

```bash
webvh-server setup     # import the webvh-server provision bundle when prompted
webvh-control setup    # paste bootstrap-output/webvh-control.bundle when prompted
```

#### 1b. Preload DIDs onto the server

The server needs to host the DID documents for all services:

```bash
# Server's own DID at /.well-known/did.jsonl
webvh-server load-did \
  --path .well-known \
  --did-log bootstrap-output/webvh-server.did.jsonl

# Control plane's DID at /services/control/did.jsonl
webvh-server load-did \
  --path services/control \
  --did-log bootstrap-output/webvh-control.did.jsonl
```

#### 1c. Grant server access to control plane

```bash
webvh-control add-acl --did <server-DID> --role admin
```

Replace `<server-DID>` with the DID printed during the `load-did` step.

#### 1d. Configure control plane URL

Add to the server's `config.toml`:

```toml
control_url = "http://localhost:8532"
```

Or set the environment variable:

```bash
export WEBVH_CONTROL_URL=http://localhost:8532
```

### Phase 2: Start Services

```bash
# Terminal 1
webvh-server

# Terminal 2
webvh-control
```

On startup, the server will:
1. Authenticate with the control plane via DIDComm
2. Register itself, reporting all preloaded DIDs
3. Apply any DID updates received from the control plane

## Daemon Mode (All-in-One)

For development or simple deployments, use `webvh-daemon` which runs all services in a single process:

```toml
# daemon-config.toml
server_did = "did:webvh:..."
public_url = "https://did.example.com"

[server]
host = "0.0.0.0"
port = 8534

[enable]
server = true
control = true
witness = true
watcher = false
```

```bash
webvh-daemon --config daemon-config.toml
```

In daemon mode, inter-service communication happens in-process without network calls.

## Verifying the Setup

### Check server health
```bash
curl http://localhost:8530/api/health
```

### Check DID resolution
```bash
curl http://localhost:8530/.well-known/did.jsonl
curl http://localhost:8530/services/control/did.jsonl
```

### Check control plane registry
```bash
# Requires admin auth token
curl -H "Authorization: Bearer <token>" \
  http://localhost:8532/api/control/registry
```

### Check ACL entries
```bash
webvh-server list-acl
webvh-control list-acl
```

## Environment Variables

### webvh-server
| Variable | Description |
|----------|-------------|
| `WEBVH_SERVER_DID` | Server's DID |
| `WEBVH_PUBLIC_URL` | Public-facing URL |
| `WEBVH_CONTROL_URL` | Control plane URL |
| `WEBVH_CONTROL_DID` | Control plane's DID |

### webvh-control
| Variable | Description |
|----------|-------------|
| `CONTROL_SERVER_DID` | Control plane's DID |
| `CONTROL_PUBLIC_URL` | Public-facing URL |
