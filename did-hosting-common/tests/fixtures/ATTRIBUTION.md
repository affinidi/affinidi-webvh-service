# Test fixtures

`ENro7uf0.keri.cesr` and `ENro7uf0.did.json` are the artifacts published for

    did:webs:did-webs-service%3a7676:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe

reproduced verbatim from the Apache-2.0 licensed
[hyperledger-labs/did-webs-resolver](https://github.com/hyperledger-labs/did-webs-resolver)
reference implementation, at
`volume/dkr/examples/ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe/`.

They reach this repository via `affinidi-did-webs`, which uses the same bytes
as its own conformance vectors.

## Why they are copied here rather than generated

Every other byte the `method-webs` tests run against, this workspace could
produce itself — and a fixture we generated would only prove we agree with
ourselves. These came out of keripy, so they are the only ones that can catch
this service and the wider KERI ecosystem disagreeing about what a valid
`did:webs` publication looks like.

They are used **unmodified**. Tests that need a bad stream (a tampered event, a
rewound log, a document publishing keys the log never authorised) derive it
from these at runtime, so the on-disk copy stays a faithful conformance vector.
