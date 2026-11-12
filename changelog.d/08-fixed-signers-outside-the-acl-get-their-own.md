### Fixed — signers outside the ACL get their own replay cache and bounded DID resolution

The control plane recorded every signed Trust Task document in one shared
replay cache, including those on the tasks that take a proof from a signer the
ACL does not list (`server/info`, discovery, the `auth/*` family, passkey login
and invite redemption). Such a signer (a fresh `did:key`, say) costs nothing to
create, so that traffic could fill the cache, which then refused every signed
request as `unavailable` until its records aged out. Verifying those proofs,
and a proxied login's delegation evidence, could also resolve any DID the
document named, twice.

- Replay records are now partitioned. Open reads (`server/info`, capability
  discovery, an `auth/oob/*` version this service does not serve) are not
  recorded at all. The shared cache holds only ACL members' and configured
  watchers' records. Sign-in rows from any other signer go to a separate cache
  (100,000 records, 1,000 per signer), and each source (client address on
  HTTPS, sender on DIDComm and TSP) may add at most 120 records a minute. A
  `did:webs` self-registration goes to a third, small cache. A document
  recorded in any of them is refused as a replay in all of them.
- Verifying a proof from a signer the ACL does not list runs the key-free
  checks (recipient, freshness, issuer/sender) first. If the DID must be
  resolved over the network (anything but a `did:key`), at most 16 resolutions
  run at once and 300 per minute across all such signers, each within 10 s,
  with no forced re-resolution retry. Past those limits the document is refused
  as `unavailable` with a `retryAfter`; a timeout is reported as an unreachable
  signer (retryable). The delegate of a proxied login whose principal is an ACL
  member, and whose delegation evidence that principal signed verifies, is
  verified as a member is.
- A proxied `auth/authenticate/0.3` is refused (`permissionDenied`) when its
  principal has no ACL entry, before its delegation evidence is checked. A
  `siopIdToken` must claim the principal as `iss` before it is resolved. Both
  evidence checks are bounded at 10 s.
- For every signer: a proof whose signer DID could not be resolved at all is no
  longer resolved a second time. The forced-refresh limiter is keyed on the
  DID's identity, so a `did:scid`'s `?src=` variants share one allowance, and
  tracks at most 4,096 DIDs.
- Behaviour changes (R3.6):
  - Signers outside the ACL, members' own sign-in keys included (a passkey
    login's browser key, a session key on `auth/refresh`, a proxied login's
    delegate, invite redemption), share the sign-in cache and per-source
    quota. When they are spent, those requests get `unavailable` (retryable)
    even though the shared cache has room. Members' own signed operational
    requests are not affected.
  - A non-`did:key` delegate whose mandate does not verify, and any other
    non-`did:key` signer outside the ACL, competes for the shared resolution
    slots and rate.
  - A signed open read can be resent; it is answered again rather than refused
    as `idConflict`.
  - A proxied login for a principal outside the ACL is now refused before its
    evidence is checked (it was refused later, at the ACL check, before).
  - A signer DID whose resolution fails, including a `did:webvh` whose log
    cannot be read to establish deactivation, used to get a forced fresh
    resolution within the same request. It now gets a retryable `unavailable`,
    and the retry resolves it afresh.
  - The new bounds are constants, not configuration.
