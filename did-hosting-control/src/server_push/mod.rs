//! Durable push of control-plane mutations to registered server
//! instances via the [`crate::outbox`] queue.
//!
//! Every `send_*` / `notify_servers_*` / `fanout_*` function in this
//! module persists outbound DIDComm messages to the outbox keyspace
//! and signals the outbox worker. The worker is responsible for
//! actual delivery + retry; the helpers here only build bodies and
//! enqueue. Returning Ok means "enqueued durably", NOT "the recipient
//! has acknowledged".
//!
//! See [`crate::outbox`] for delivery semantics, backoff, and poison-
//! pill behaviour. Recipients of every control→server message type
//! handled here are idempotent — the at-least-once delivery
//! guarantee is safe.

mod domains;
mod resync;
mod staging;
mod targets;
mod watchers;

pub use domains::{
    DomainIntent, DomainOp, domain_intents, fanout_domain_upsert, resend_domain_intents,
    resend_domain_intents_for, send_domain_assign, send_domain_purge, send_domain_unassign,
    send_domain_upsert, settle_domain_intent, sync_all_domains_now,
};
pub use resync::{
    ReportedDid, edge_is_current, parse_reported, resync_server, sync_all_dids_now,
    sync_all_dids_to_server,
};
pub(crate) use staging::{DidChange, stage_did_sync, sync_update_body};
pub use staging::{notify_servers_delete, notify_servers_did};
pub use watchers::{is_configured_watcher, watcher_dids_for, watchers_named};
