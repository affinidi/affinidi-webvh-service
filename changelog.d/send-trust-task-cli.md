### Added — `send-trust-task`: send any signed Trust Task from the command line

`did-hosting-control send-trust-task` and `did-hosting-daemon send-trust-task`
sign one Trust Task with a `did:key` file (the format `setup --setup-key-out`
writes), `POST` it to the running service's `/api/trust-tasks`, verify that the
reply is signed by the service's own DID, and print the response payload as
JSON. `--type` takes a full Type URI or its `<slug>/<version>` short form
(`identity/list/0.1`); `--payload` / `--payload-file` give the request payload.
The signer is authorised like any other client, by its proof and its ACL entry.
Runbooks that used to `curl` removed REST routes (`identity/retire`,
`domain/assign`, `registry/purge-domain`, …) now use it; see
`docs/sending-trust-tasks.md`. `fetch-metrics` is now this command with a fixed
type.

### Added — a generated Trust Task catalogue

`docs/trust-tasks.md` lists every Trust Task the control plane serves, with its
version, the proof rule the gate enforces and the standing its handler
requires. It is generated from the routing tables and checked by a drift test
(`UPDATE_TRUST_TASKS=1 cargo test -p did-hosting-control --lib
trust_task_catalogue` regenerates it).
