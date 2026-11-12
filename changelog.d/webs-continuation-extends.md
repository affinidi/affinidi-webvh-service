### Fixed — a `did:webs` update must extend the hosted key event log

An update to a hosted `did:webs` slot, whether a control-plane publish or a
sync an edge applies, was checked only for the same AID and a sequence number
no lower than the hosted one. A log with a different event at the hosted
sequence number, or a longer log that diverged before it, was accepted and
replaced the hosted one. Both verify on their own, so the service could serve
a document from a history that contradicts the one it had already served.

The update's key events for the AID must now begin with every event the hosted
log holds, at the same sequence number with the same SAID, with one exception:
KERI's superseding recovery, where a rotation replaces the interaction events
after the last establishment event. Any other divergence is refused, including
a rotation superseding a rotation, and a shorter log is refused as a rewind.
Events are compared by SAID, so republishing the same events, re-serialized or
with witness receipts added, is still accepted. An edge applies the same check
against the high-water log it keeps after a delete.

A stored log that cannot be parsed still does not block an update, so a
corrupt slot can be repaired; the skipped check is now logged. One that parses
but no longer verifies is compared by its events. Only the AID's own key event
log is held to its history: a delegator's log in the same stream is verified
but not compared with the hosted one.

Behaviour change (R3.6): no wire changes. A `did:webs` publish or sync that
diverges from the hosted log other than by superseding recovery is refused
(`did/publish` and `sync/update` refuse it as they refuse a rewind) instead of
being accepted. Only builds with `method-webs` are affected.
