### Fixed — a DID an administrator suspended stays suspended until an administrator resumes it

`did/set-state` stored only whether a slot was suspended, not who
suspended it, and a re-register wrote every slot back as active. So a slot
an administrator suspended was resumed by its owner sending
`did/set-state active`, by the owner re-registering it, or by the owner
force re-creating the path. The record now notes an administrator's
suspension (`disabled_by_admin`, absent on older records, which read as
not suspended by an administrator). While it is set, the owner's `active`
is refused with `permissionDenied`, and a re-register or forced re-create
keeps the slot suspended. An administrator's `active` clears it.

Behaviour change: a re-register (`did/register` of an existing slot) and a
forced re-create no longer resume a suspended slot, whoever suspended it;
the slot is resumed with `did/set-state active`. An owner can still
suspend and resume a slot it suspended itself. An owner can no longer
delete a slot an administrator suspended (`permissionDenied`): the delete
is final, so a later re-register would start the slot afresh. An
administrator can still delete it.

Upgrade note: a binary from before this change does not know the marker
and drops it when it rewrites a record. After a downgrade, or while
replicas of mixed versions share a store, re-apply administrator
suspensions once every replica runs this version.
