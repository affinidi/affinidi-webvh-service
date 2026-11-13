### Changed — deleting a DID, retiring an identity generation, purging a domain on an edge and granting an administrator need a stepped-up session

A request that presents a console session (a bearer token on
`POST /api/trust-tasks`) now needs that session at `aal2` for:

- `did-management/did/delete/0.1`;
- `did-management/identity/retire/0.1`;
- `did-management/registry/purge-domain/0.1`;
- `acl/grant/0.2` of an `admin` or `service` entry, and `acl/change-role/0.2`
  to either role. Grants and role changes to `owner` or `metricsReader` are
  unchanged.

Below `aal2` the request is refused before anything is written, with the
same refusal `domain/purge` already gave: `permissionDenied` with the message
`step_up_required`. The ACL tasks ask it of an administrator only; anyone else
gets the task's own refusal.

The console routes each of these calls through its step-up path: on that
refusal it steps a wallet session up through the wallet and sends the request
once more. A passkey session is `aal2` from login and sees no change.

Behaviour change (R3.6): a console wallet session now prompts for a step-up
the first time it deletes a DID, retires a generation, purges a domain on one
edge, or makes someone an administrator or service account. A client that
sends these tasks with an `aal1` bearer session must step it up first. A
request with no bearer session — a VTA sending signed Trust Tasks over
DIDComm, TSP or HTTPS — is authorised by its own proof as before.
