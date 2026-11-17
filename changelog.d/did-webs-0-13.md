### Fixed — a key-role `did:webs`, such as a VTA's own identity, can register itself

`affinidi-did-webs` moves from 0.7 to 0.13. 0.7 read no key-role designation
and no KERI 2.0 designation, so the document the control plane derives from a
submitted `keri.cesr` lacked the keys such an identifier signs with. A VTA's
own `did:webs` (VTI-KEY-173: distinct attestation, operational and messaging
keys) signs its self-registration with its designated `operational` key,
which that document did not list under `authentication`, so its first-boot
`did/register` was refused as `proofInvalid`. It is now accepted, and the key
state's own key does not stand in for the operational one.

Behaviour change (R3.6): no wire changes. Under 0.13 a `did:webs` is valid
only on a domain its own designated aliases name: a key event log published on
a domain it does not designate is refused instead of being served there. An
identifier that designates no key agreement key now resolves with the X25519
key converted from its signing key in `keyAgreement`, as the reference
resolver's does. Only builds with `method-webs` are affected.
