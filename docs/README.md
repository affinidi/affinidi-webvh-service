# Documentation

> **Status:** current — the index of this directory.

Every page here starts with a status line: **current** (describes the code on
`main`), **historical** (kept for its reasoning; superseded, and moved to
[`archive/`](#archive)) or **proposal** (not built yet). CI checks the status
lines, the links between pages, and that current pages do not name retired
routes or binaries (`scripts/check-docs.py`, `lychee.toml`).

## Start here

| Page | What it covers |
| ---- | -------------- |
| [Architecture and trust model](architecture.md) | The services, who is authoritative, how nodes reach each other, and why every privileged message is authorised on its own proof. |
| [Glossary](glossary.md) | Slot, mnemonic, path, edge, control plane, owner, agent name, generation, … |
| [Bootstrap and startup](bootstrap_startup.md) | Setting up a daemon or a distributed deployment, interactive or from a recipe. |

## Operating

| Page | What it covers |
| ---- | -------------- |
| [Configuration reference](configuration.md) | Every config section and key, environment overrides, store and secrets backends. |
| [Deployment and hardening](deployment.md) | TLS termination, reverse proxies, `trusted_proxies` vs `trusted_proxy_cidrs`, ports, service units. |
| [Backup and upgrade](backup-and-upgrade.md) | What to back up for each binary, restore, and upgrading between releases. |
| [Rollback](rollback.md) | Stepping a deployment back to an earlier release (N / N-1). |
| [Metrics](metrics.md) | The counters and gauges, and reading them with `fetch-metrics`. |
| [Troubleshooting](troubleshooting.md) | Symptoms, log lines and fixes. |
| [Identity rotation runbook](identity-rotation-runbook.md) | Rotating a service's own DID keys on a live deployment. |
| [GeoIP](geoip.md) | Sign-in locations from a local database. |

## Managing DIDs

| Page | What it covers |
| ---- | -------------- |
| [Sending Trust Tasks](sending-trust-tasks.md) | The UI, the `send-trust-task` CLI and `WebVHClient`. |
| [Trust Task catalogue](trust-tasks.md) | Every task the control plane serves, its proof rule and required standing (generated). |
| [CLI reference](cli-reference.md) | Every subcommand of every binary (generated). |
| [Hosting `did:webs`](did-webs-hosting.md) | The opt-in `did:webs` method and where it differs. |
| [`openapi.json`](openapi.json) | The public HTTP surface of an edge: DID resolution and health (generated). |

## Design

| Page | What it covers |
| ---- | -------------- |
| [TSP transport](tsp-transport.md) | TSP and DIDComm, the send-binding preference, the outbox, one dispatch for every transport. |
| [Identity rotation design](identity-rotation-design.md) | How a service rotates its own DID keys. |
| [Tiered statistics](stats-tiers.md) | The coarse / fine per-DID series and their bounds. |

## Archive

Superseded designs, specs and plans, kept for their reasoning. Each says what
replaced it.

- [DIDComm DID-management protocol](archive/didcomm-did-management-protocol.md)
- [Typed DID-management Trust Tasks, v1 design](archive/did-hosting-trust-tasks-v1-design.md)
- [Dispatcher consolidation](archive/dispatcher-consolidation-design.md)
- [Multi-domain hosting spec](archive/multi-domain-spec.md)
- [Multi-method hosting spec](archive/multi-method-hosting-spec.md)
- [Self-managed mode spec](archive/self-managed-mode-spec.md)
- [Daemon online setup: discover first](archive/daemon-online-setup-discover-first.md)
- [Trust Tasks ACL client migration (0.7 → 0.8)](archive/trust-tasks-acl-migration.md)
- [Trust Tasks registry gaps](archive/trust-tasks-registry-gaps.md)
- [Migration guide 0.6 → 0.7](archive/migrations/v0.6.0-to-v0.7.0.md)
- Completed implementation plans: [0.7 rollout plan](archive/tasks/did-hosting-rollout-plan.md),
  [0.7 rollout tasks](archive/tasks/did-hosting-rollout-todo.md),
  [self-managed plan](archive/tasks/plan.md),
  [self-managed tasks](archive/tasks/todo.md),
  [self-managed runtime audit](archive/tasks/runtime-audit-T3.md)

Contributor rules (daemon parity, proof rules, the source of record) are in
[CLAUDE.md](../CLAUDE.md) and [CONTRIBUTING.md](../CONTRIBUTING.md); release
mechanics in [RELEASES.md](../RELEASES.md).
