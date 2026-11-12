### Fixed — the large-document cost of an address decays, and a `did:scid` issuer's `?src=` is not a mismatch

A large `did/register` (over 64 KiB) whose claimed issuer does not verify
doubles its address's cost for the next one. That raised cost never went down
until the process restarted, so after three such documents an address could
send no large document at all: a shared egress address, or a load balancer
missing from `trusted_proxies`, stayed shut out after one sender's failures.
The raised cost now halves every 15 minutes and on each large document from
the address that does verify, and is forgotten once back to 1. The penalty
table keeps its 10,000-address bound and, when full, makes room by dropping
the penalties that have decayed.

The claimed issuer was also compared with the verified one as raw strings, but
the verifier reports a `did:scid` issuer without its `?src=` locator. An owner
signing as `did:scid:vh:1:…?src=…` was charged a penalty on every large
document it sent, although it verified. The two are now compared as
identities, without the locator.

Behaviour change (R3.6): no wire shape changes; an address is refused large
documents for less time than before, and a `did:scid` issuer with `?src=` that
verifies is no longer held to a raised cost.
