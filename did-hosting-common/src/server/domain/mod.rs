//! First-class domain objects.
//!
//! Per `docs/multi-domain-spec.md` §3. Domains are runtime-managed
//! entities (not config-file static): an admin adds / disables /
//! re-points a domain via the management API or DIDComm and the
//! daemon picks the change up live. This module is the type surface;
//! CRUD + normalisation lives in T15.
//!
//! ## Storage layout
//!
//! `domains:{name}` — one `DomainEntry` per row in the `domains`
//! keyspace (`KS_DOMAINS`). `meta:default_domain` carries the
//! current default (single-key pointer). See
//! `super::store::keyspaces` for the const names.
//!
//! ## What's here vs. what's in `super::acl`
//!
//! `DomainScope` is the per-ACL-entry visibility rule (which domains
//! a caller's ACL entry is allowed to operate on). It conceptually
//! belongs to the ACL but is defined here because both the domain
//! module (when adding a new domain, we may want to validate ACL
//! references) and the ACL module need to see it; keeping the type
//! definition with the domain module avoids a cycle.

pub mod scope;
pub mod types;

pub use scope::DomainScope;
pub use types::{
    DomainBranding, DomainEntry, DomainQuota, DomainStatus, DomainUrlScheme,
};
