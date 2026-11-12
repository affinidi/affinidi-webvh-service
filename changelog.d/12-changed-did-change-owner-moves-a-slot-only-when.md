### Changed — `did/change-owner` moves a slot only when its recipient accepts

`did/change-owner/0.1` moved a slot to any DID with an ACL entry, at the
owner's word alone. The recipient never agreed, its quota and domain scope
were not applied, and the "not in the ACL" error told the owner whether a
DID had an entry.

- An administrator's request moves the slot at once, as before.
- An owner's request now only offers it. The record is returned unchanged,
  with `ext["vnd.affinidi.webvh"].ownerTransfer = { status: "offered",
  newOwner, expiresAt }`. The offer lasts 72 hours. A new offer replaces the
  last; naming the current owner withdraws it; deleting the slot removes it.
  Nothing about the recipient is looked up when an offer is made, so an offer
  answers the same for any DID.
- The recipient accepts by sending the same request naming itself as
  `newOwner`. It needs the live offer from the slot's current owner, made
  since the slot was registered; anyone else still gets `notOwner`.
- Before a slot moves (an administrator's transfer or an acceptance), the
  recipient must have an ACL entry with a role that owns DIDs (`owner` or
  `admin`), a domain scope that covers the slot, and room for it in its DID
  count and total size quotas. Otherwise the request is refused as
  `targetNotAuthorized`, naming the check that failed (only an administrator,
  or the recipient about itself, can reach it).
- The recipient's quota check and the move are one critical section per
  owner, and so are the quota checks and commits of `did/register`, create,
  publish and the agent-name verbs (the publish paths re-check the size quota
  under the owner's lock and hold it through their commit), so two writes for
  the same owner cannot both take its last slot or byte. Lock order: slot,
  then owner, then agent names.
- `did_ops::change_did_owner` takes the request's `domain` and returns
  `OwnerChange { record, offer }`, or `OwnerChangeError`.
- The console's ownership card offers a DID (owners) or transfers it
  (administrators), and the DID list has "Accept a DID".
- Behaviour changes (R3.6):
  - A non-administrator's `did/change-owner` no longer moves the slot. A
    caller that read `record.owner` from the reply to confirm a move now sees
    the old owner and an `ownerTransfer` offer.
  - A transfer to a DID outside the ACL is no longer refused at once when an
    owner sends it. It is recorded as an offer that can never be accepted.
    An administrator's transfer to one is refused as `targetNotAuthorized`
    (it was `malformedRequest`).
  - A transfer to a `service` or `metrics-reader` entry, or to a recipient
    over its quota or outside its domain scope, is refused, administrators
    included.
  - Checked consumers: the console (updated here). verifiable-trust-
    infrastructure defines the Type URI constant in `vta-sdk` but sends no
    `did/change-owner`.
