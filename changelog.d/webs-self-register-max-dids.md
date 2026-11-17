### Added — a self-registered `did:webs` may hold more than its own DID

`[[hosting.webs_self_register]]` takes `max_dids_per_identifier` (default 1,
at least 1): how many DIDs each identifier that registers itself on the domain
may hold, its own included — the `max_did_count` of the `Owner` entry
self-registration grants. With the old fixed limit of one, a VTA whose own
`did:webs` registered itself could publish nothing else on the host: a
community's DID it provisions was refused with `DID count limit reached (1)`.
It applies to entries granted from then on; an entry already granted keeps its
limit until an administrator changes it. See `docs/did-webs-hosting.md`
("Self-registration").
