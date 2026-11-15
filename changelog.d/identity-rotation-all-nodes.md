### Fixed — a control plane or daemon picks up a rotation of its own DID as soon as it is registered

Publishing a new version of the control plane's (or daemon's) own DID through
`did/register` did not reload the service identity; the change was only noticed
by the 5-minute backstop reload, so for up to 5 minutes the served document
advertised keys the listener had not loaded. `did/register` now triggers the
reload as soon as the new version is committed.

### Fixed — a daemon restarted mid-rotation keeps draining its old mediator

After a mediator change, a daemon restarted inside the grace window did not
reconnect to the old mediator, so messages peers still delivered there were
lost. The daemon now resumes those drains at startup, through the same
post-listener step the standalone control plane uses.

### Fixed — a node keeps TSP and its TSP relationships when its identity changes

When a witness's identity changed (a key rotation, a transport or mediator
change, or its first resolution at boot), its listener was rebuilt without TSP,
so TSP frames sent to it were dropped and acknowledged until a restart. On every
node the rebuilt listener also lost the transports reconciled from its own DID
document and its persistent TSP relationship store. Each node now builds its
listener through one function at boot and on every rebuild. A witness with only
TSP enabled now also starts its listener.

### Fixed — a watcher notices its own DID rotating

The watcher loaded its identity once and never re-read it, so after its keys
rotated it kept signing replies with a key its document no longer carried and
every sync looked unacknowledged until a restart. Like the witness, it now
re-resolves its own DID every 5 minutes, rotates onto the new keys, expires
superseded generations, and drains an old mediator after a mediator change.
