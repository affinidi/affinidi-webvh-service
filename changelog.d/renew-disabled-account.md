### Fixed — a request signed by a DID this host serves is verified against the host's own log

A signer whose `did:webvh` this host holds (or its listed `did:scid` alias)
was verified by resolving its DID over the network, back to this host. Three
cases broke:

- **A self-registered account disabled for inactivity could never be
  restored.** Disabling it makes its DID answer 404, so its
  `account/renew` was refused as `unavailable`. Its `account/status` (an
  offline holder's backstop) failed the same way.
- **An owner whose own identity DID was disabled** was locked out of every
  task, though its authority is its ACL entry's.
- **A host that cannot reach its own public URL** (behind NAT or a proxy, or
  on a private address) refused such signers on every request.

These signers are now verified against the document the stored log implies:
only its servable, witnessed part, as a resolver would see it. A deactivated
log authenticates no one. Approvals (`assertionMethod`) keep their own path.
