### Added — self-registration: a VTA with no relationship to the host can register its own DID

A party with no account can register one through
`did-management/account/register/0.1`. It submits its own self-certifying
`did:webvh` log; the request's proof is checked against the document that
log implies, so a DID that does not resolve yet can register itself. It
also presents admission evidence: both halves of an operator invite
(`did-management/account/invite/{issue,list,revoke}/0.1`), or a
`DidHostingVoucher` signed by an authorising party the domain trusts.
`did:scid` registrants are admitted where the document lists the alias.
An optional `referral` records how the registrant came here. It is
verified only when the admitting voucher or invite supports it.

The registrant becomes an ordinary owner. While its account lasts it is
held to its domain's terms:
- its DIDs sit under the domain's path prefixes;
- it holds no agent names;
- the terms' quotas apply, or the service's ordinary limits where the terms
  state none;
- it expires when unused.

The holder's signed tasks (`did-management/account/renew/0.1`, sent by its
software) and resolutions of its DIDs keep it alive. After
`inactivityDays` (default 90) its DIDs are disabled. After `graceDays`
(default 30) they, the account and its ACL entry are deleted. The holder is
sent a signed `did-management/account/expiry-notice/0.1` before and at each
step, and can ask with `did-management/account/status/0.1`.

An administrator can exempt one account from its terms, or hold it to them
again, with `did-management/account/exempt/0.1`.

Each domain's terms are runtime state, managed by administrators with
`did-management/account/policy/{list,set}/0.1`:
- open or closed;
- the trusted authorising parties, with labels;
- path prefixes, quotas and lifecycle.

`[[hosting.guest_register]]` only seeds a domain's terms at first start.
`did-management/server/info/0.2` publishes the open domains' terms, so a
registrant can read the path rules before it mints its DID.

### Changed — `did-management/server/info` is served at 0.2

The public `server/info` read moves to 0.2, which extends 0.1 with the open
domains' self-registration terms (`selfRegistration`). 0.1 is no longer
served: a client still sending it is refused `unsupportedType` and should
send 0.2, whose response is a superset. The management UI and
`did_hosting_common::client` send 0.2.
