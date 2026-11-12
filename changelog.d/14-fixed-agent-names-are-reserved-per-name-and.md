### Fixed — agent names are reserved per name, and released when their DID is deleted

The check that an agent name is free and the write that binds it were held
under the claiming DID's own lock only, so two DIDs claiming the same free name
at once (`agent-name/update`, a plain publish, or `did/register`) could both
succeed, leaving both records listing the name and the index pointing at
whichever wrote last. Each name now has its own lock, taken after the DID's lock
and held from the check to the commit, so exactly one claim wins and the other
is refused as taken.

- `agent-name/remove` retires the name's index entry only while it points at
  the DID removing it; it no longer deletes another DID's entry.
- `did/delete` releases the deleted DID's agent names (active and parked),
  again only entries that point at that DID. Previously they stayed indexed
  against a DID that no longer existed. The names are removed in a second
  write right after the record, so a DID with many names stays deletable on
  stores that cap one transactional write (DynamoDB: 100 items).
- A domain purge likewise removes only the index entries that still point at
  each purged DID, after the record; in the daemon it now takes the control
  plane's DID and name locks while it deletes.
- The DID and name locks are released as soon as a publish or agent-name
  change commits, before the check for a rotation of the service's own DID.
- **Behaviour change:** an index entry that points at a DID which no longer
  exists, or whose record no longer lists the name, no longer holds the name.
  `agent-name/check` reports such a name available and it can be claimed.
- **Upgrading:** agent names left indexed by DIDs deleted before this release
  become claimable again by any DID on their domain.
