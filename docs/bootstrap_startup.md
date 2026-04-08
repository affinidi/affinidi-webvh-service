# Bootstrap & Startup Guide

This document explains how to set up a complete WebVH environment with DIDComm-based authentication between services.

## Prerequisites

- VTA (Verifiable Trust Agent) credentials for each service's context
  - Each service gets its own isolated VTA context
  - Credentials are base64url-encoded strings issued by the VTA operator
- Compiled WebVH binaries: `webvh-server`, `webvh-control`, `webvh-witness`
- A public URL where the server will serve DIDs (e.g., `https://did.example.com`)

## Architecture Overview

Services authenticate with each other using DIDComm challenge-response:

- **webvh-control** — manages service registration, ACLs, and DID sync (set up first)
- **webvh-server** — hosts DID documents at public URLs (set up second)
- **webvh-witness** — provides witness proofs for DID log entries (optional, set up last)

Each service connects to its own VTA context during setup, creates its own DID, retrieves keys, and stores them locally. No external PNM CLI is needed.

## Sequence Diagram

```mermaid
sequenceDiagram
    participant Admin
    participant VTA
    participant Control as webvh-control
    participant Server as webvh-server
    participant Witness as webvh-witness

    rect rgb(230, 240, 255)
        Note over Admin,VTA: Phase 1 — Control Plane Setup (first)
        Admin->>Control: webvh-control setup
        Control->>VTA: Authenticate with VTA credential
        VTA->>Control: Session established
        Control->>VTA: Create control DID
        VTA->>Control: DID + signing key + KA key
        Control->>Admin: Writes control-did.jsonl<br/>Outputs control DID string
    end

    rect rgb(235, 245, 255)
        Note over Admin,Server: Phase 2 — Server Setup
        Admin->>Server: webvh-server setup
        Server->>VTA: Authenticate with VTA credential
        VTA->>Server: Session established
        Server->>VTA: Create server root DID
        VTA->>Server: DID + signing key + KA key + log entry
        Note over Server: Auto-imports root DID at .well-known
        Admin->>Admin: Enter control_url + control_did from Phase 1
    end

    rect rgb(240, 248, 255)
        Note over Admin,Server: Phase 2b — Bootstrap Control DID on Server
        Admin->>Server: webvh-server bootstrap-did<br/>--path services/control<br/>--did-log control-did.jsonl
        Admin->>Control: webvh-control add-acl<br/>--did <server-did> --role admin
    end

    rect rgb(245, 255, 245)
        Note over Admin,Witness: Phase 3 — Witness Setup (optional)
        Admin->>Witness: webvh-witness setup
        Witness->>VTA: Authenticate with VTA credential
        VTA->>Witness: Session established
        Witness->>VTA: Create witness DID
        VTA->>Witness: DID + signing key + KA key + log entry
        Witness->>Admin: Writes witness-did.jsonl
        Admin->>Server: webvh-server bootstrap-did<br/>--path services/witness<br/>--did-log witness-did.jsonl
    end

    rect rgb(255, 248, 240)
        Note over Server,Control: Phase 4 — Start Services
        Admin->>Server: Start webvh-server
        Admin->>Control: Start webvh-control
        Admin->>Witness: Start webvh-witness
        Server->>Control: DIDComm challenge-response auth
        Control->>Server: JWT access token
        Server->>Control: Register service + report preloaded DIDs
    end
```

## Step-by-Step Setup

### Phase 1: Control Plane (set up first — other services need its DID)

```bash
webvh-control setup
```

The wizard prompts for:
1. **VTA credential** — base64url string for the control plane's VTA context
2. **DID hosting URL** — where webvh-server will serve DIDs (e.g., `https://did.example.com`)
3. **DID path** — path on the server (default: `services/control`)
4. **Public URL** — control plane's own URL for WebAuthn (e.g., `http://localhost:8532`)
5. Host, port, log level, data directory, secrets backend
6. **Admin ACL** — enter an existing DID or generate a new `did:key`

Output:
- `config.toml` — control plane configuration
- `control-did.jsonl` — DID log entry to import on the server
- Control DID string (displayed on screen)

**Save the control DID** — you'll need it when setting up the server.

### Phase 2: Server (set up second — hosts all DIDs)

```bash
webvh-server setup
```

The wizard prompts for:
1. **VTA credential** — base64url string for the server's VTA context
2. **Public URL** — where DIDs are served (e.g., `https://did.example.com`)
3. Features (DIDComm, REST API)
4. **Control plane URL** — e.g., `http://localhost:8532` (from Phase 1)
5. **Control plane DID** — paste the DID from Phase 1
6. Host, port, log level, data directory, secrets backend
7. **Admin ACL** — enter an existing DID or generate a new `did:key`

The wizard automatically creates the root DID and imports it at `.well-known`.

### Phase 2b: Bootstrap Control DID on Server

Import the control plane's DID log entry onto the server:

```bash
webvh-server bootstrap-did \
  --path services/control \
  --did-log control-did.jsonl
```

Grant the server admin access to the control plane:

```bash
webvh-control add-acl --did <server-DID> --role admin
```

Replace `<server-DID>` with the DID printed during server setup.

### Phase 3: Witness (optional — set up after server)

```bash
webvh-witness setup
```

The wizard prompts for:
1. **VTA credential** — base64url string for the witness's VTA context
2. **DID hosting URL** — the server's public URL
3. **DID path** — path on the server (default: `services/witness`)
4. Features, host, port, log level, data directory, secrets backend
5. **Admin ACL**

Import the witness DID on the server:

```bash
webvh-server bootstrap-did \
  --path services/witness \
  --did-log witness-did.jsonl
```

### Phase 4: Start Services

```bash
# Terminal 1
webvh-server --config config.toml

# Terminal 2
webvh-control --config config.toml

# Terminal 3 (if witness is configured)
webvh-witness --config config.toml
```

On startup, the server will:
1. Authenticate with the control plane via DIDComm challenge-response
2. Register itself, reporting all preloaded DIDs
3. Apply any DID updates received from the control plane

## Daemon Mode (All-in-One)

For development or simple deployments, use `webvh-daemon` which runs all services in a single process:

```toml
# daemon-config.toml
server_did = "did:webvh:..."
public_url = "https://did.example.com"
did_hosting_url = "https://did.example.com"

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

## Cold-Start Bootstrap (No Running Services)

When bootstrapping a new environment from scratch — no DID resolution, no DIDComm, no running VTA or mediator — use this offline flow. DIDs are created locally on the VTA and loaded manually into each service.

### Prerequisites

- VTA binary (`vta`) with setup completed (`vta setup`)
- Compiled `webvh-server` and `mediator-setup-vta` binaries
- A `config.toml` for the webvh-server (can be minimal — just `public_url`, `[server]`, `[store]`, `[secrets]`)
- A `mediator.toml` for the mediator

### Step 1: Create DIDs on the VTA (offline)

```bash
# Create the webvh-server's DID
vta create-did-webvh --context ctx1 --label server
# → saves did-server.jsonl, optionally exports secrets bundle

# Create the mediator's DID
vta create-did-webvh --context mediator --label mediator
# → saves did-mediator.jsonl, optionally exports secrets bundle
```

When prompted, export the secrets bundle for each DID. Copy the base64url output — you'll need it in the next steps.

### Step 2: Set up the WebVH Server (offline)

```bash
# Import the server's signing/KA keys from the VTA bundle
webvh-server import-secrets --config config.toml \
  --vta-bundle <server-secrets-bundle>

# Load all DIDs into the server's store
webvh-server load-did --path .well-known --did-log did-server.jsonl
webvh-server load-did --path <vta-path> --did-log did-vta.jsonl
webvh-server load-did --path <mediator-path> --did-log did-mediator.jsonl
```

### Step 3: Start the WebVH Server

```bash
webvh-server --config config.toml
```

All DIDs are now resolvable via HTTP. The server starts with DIDComm in degraded mode (mediator not yet available).

### Step 4: Set up the Mediator (offline)

```bash
mediator-setup-vta --import-bundle --config conf/mediator.toml
```

When prompted:
1. Paste the **mediator secrets bundle** (from step 1)
2. Paste the **VTA credential** (from `vta setup`)
3. Choose a storage backend (string/AWS/keyring)
4. Enter the context ID (e.g., `mediator`)

This pre-seeds the VTA secret cache so the mediator can start without a running VTA.

### Step 5: Start the Mediator

```bash
mediator
```

The mediator tries to reach the VTA, falls back to the cached secrets, and starts. Its DID is already resolvable via the webvh-server.

### Step 6: Start the VTA

```bash
vta --config config.toml
```

All three services can now resolve each other. DIDComm is fully operational.

### Cold-Start Summary

| Step | Action | Network? | Services Running |
|------|--------|----------|------------------|
| 1 | `vta create-did-webvh` (×2) | No | None |
| 2 | `webvh-server import-secrets` + `load-did` (×3) | No | None |
| 3 | Start webvh-server | No | WebVH |
| 4 | `mediator-setup-vta --import-bundle` | No | WebVH |
| 5 | Start mediator | Yes (DID resolution) | WebVH, Mediator |
| 6 | Start VTA | Yes (DID resolution) | All |

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
| `WEBVH_VTA_URL` | VTA REST URL |
| `WEBVH_VTA_DID` | VTA DID for DIDComm |
| `WEBVH_VTA_CONTEXT_ID` | VTA context ID |

### webvh-control
| Variable | Description |
|----------|-------------|
| `CONTROL_SERVER_DID` | Control plane's DID |
| `CONTROL_PUBLIC_URL` | Public-facing URL |
| `CONTROL_DID_HOSTING_URL` | DID hosting URL (where DIDs are publicly served) |
| `CONTROL_VTA_URL` | VTA REST URL |
| `CONTROL_VTA_DID` | VTA DID for DIDComm |
| `CONTROL_VTA_CONTEXT_ID` | VTA context ID |

### webvh-witness
| Variable | Description |
|----------|-------------|
| `WITNESS_SERVER_DID` | Witness's DID |
| `WITNESS_VTA_URL` | VTA REST URL |
| `WITNESS_VTA_DID` | VTA DID for DIDComm |
| `WITNESS_VTA_CONTEXT_ID` | VTA context ID |
