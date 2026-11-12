### Fixed — a `did:webs` slot can be read, suspended, transferred and deleted

A `did:webs` slot's path ends in its AID, which is mixed case. Only
`did/register` accepted that path; `did/info`, `did/log`, `did/set-state`,
`did/change-owner`, `did/delete`, `did/rollback`, `agent-name/list` and
`webvh/witness/publish` checked it against the lowercase-only grammar and
refused it as an invalid path, so a registered `did:webs` could not be
inspected, suspended, transferred or removed. Each of these now takes the
path's grammar from the stored record, as a publish already did: the AID
grammar applies only to a slot recorded as `did:webs`, never because of
anything in the request.

What each does with a `did:webs` slot:

- `did/info` returns the record and no `logSummary`: that summary is read from
  a `did:webvh` log line.
- `did/log` returns one entry, the document the key event log implies now
  (re-verified, as on resolution), and with `raw` the stored `keri.cesr`.
  Earlier establishment events are not listed. Without `method-webs` it
  returns no entries.
- `did/set-state`, `did/change-owner` and `did/delete` work as for any slot.
- `did/rollback` is refused: it truncates a `did:webvh` log by line, and a
  `did:webs` key event log is only ever extended by its controller.
- `webvh/witness/publish` is refused with `invalidWitness`: a `did:webs`
  slot's witness receipts are part of its key event log.

`did/rollback` now applies to `did:webvh` slots only. On a `did:web` slot it
split the stored `did.json` by line: a pretty-printed document was left as
invalid JSON with no `did_id`, and pushed to every edge. It is refused for
every method but `did:webvh`, and the slot is left as it was.

`did/log` answers a path that is not a valid slot path with `notFound`, as it
answers a slot the caller may not read, so the answer does not depend on
whether a `did:webs` slot is recorded at an AID-shaped path.

Behaviour change (R3.6): no wire shape changes. Requests naming a `did:webs`
slot that were refused as an invalid path now succeed, or (rollback, witness
publish) are refused for the method instead. `did/rollback` on a `did:web` (or
any other non-`did:webvh`) slot is refused. `did/log` with a malformed path
returns `did-management/did/log:notFound` instead of a validation error.
