### Changed — the control plane queues replication with the change that causes it, as references

A DID publish, register, delete, rollback, suspension, witness upload or
agent-name change now writes its sync rows for every server and watcher in the
**same store transaction** as the change. A crash between the two can no longer
lose the push, and a slot's rows reach each server in commit order (a publish
quickly followed by a delete no longer risks the delete arriving first).

Outbox rows no longer carry the `did.jsonl`: a row names the slot (or the
domain), and the worker reads it when it sends. Rows are a few hundred bytes
whatever the log's size, so a resync batch can no longer exceed DynamoDB's
400 KB item limit; a resend carries the newest state, and a slot deleted before
its row is sent goes out as a delete. A slot or domain already queued for a
server is not queued again — an edge that registers while its queue is still
draining no longer has the same delta appended each time — and an
acknowledgement of a state a later change superseded re-arms the row rather
than settling it.

Delivery is cheaper and fairer: the worker reads only the head of each queue,
finds the row an acknowledgement answers through an index, services targets
concurrently, and locks per target rather than globally. The replication
gauges read a count and the head rather than the whole queue. A registration
queues domain rows before DID rows, and pages through the DID records.

Rows queued by an earlier version are re-keyed when the worker starts and drain
as before.

### Changed — unacknowledged sends back off, and are counted apart from failures

A send the mediator accepted but the target never acknowledged was re-sent every
minute, so an offline edge exhausted its budget in about 50 minutes and
collected a copy a minute. The wait now doubles from one minute to an hour,
with jitter, for up to 24 sends (about 19 hours); hard delivery failures keep
their own budget (50, about 3.5 hours). An acknowledgement of any of the last
16 copies sent settles the row. New counters on `server/metrics`:
`webvh_outbox_enqueue_failures_total`, `webvh_outbox_delivery_failures_total`,
`webvh_outbox_unacked_resends_total`, `webvh_outbox_dropped_total` and
`webvh_outbox_record_failures_total`.

An assign a server acknowledged is no longer re-sent on every registration
while the server still reports serving the domain; it is re-sent to one that
registers without it.

### Fixed — configured registry instances no longer duplicate on every restart

Each `[[registry.instances]]` entry is now kept under a stable id derived from
its type and URL and updated in place, so restarts no longer add a dead record
per configured instance; the duplicates earlier versions left are removed on
start. Every change to an instance record (registration, health status, pong,
acknowledgement, transport and badge observations, `served_domains`) now goes
through one locked read-modify-write, so concurrent writers no longer drop each
other's changes.
