//! Per-spec ACL handlers + the framework-defined trust-task-discovery
//! handler.
//!
//! Each submodule owns one Type URI under
//! `https://trusttasks.org/spec/acl/<slug>/0.1`. The dispatcher (see
//! [`super::dispatch_inbound`]) routes typed inbound documents to
//! [`grant::handle`], [`revoke::handle`], etc.

pub mod change_role;
pub mod discovery;
pub mod grant;
pub mod list;
pub mod revoke;
pub mod show;
