//! `did:webs` — **NOT IMPLEMENTED IN THIS RELEASE**.
//!
//! Per `docs/multi-method-hosting-spec.md` §1 and §2, `did:webs` is
//! a scaffolded compile-time target — the feature flag exists so the
//! `DidMethod` trait surface can be exercised against a future
//! method without restructuring, but no impl ships in this release.
//!
//! Enabling `--features method-webs` produces this compile error on
//! purpose. A future release will replace this stub with a real
//! impl following the pattern in `super::webvh`.

#![cfg(feature = "method-webs")]

compile_error!(
    "method-webs is not implemented in this release. \
     See docs/multi-method-hosting-spec.md §1 for the planned scope \
     and §6 for the DidMethod trait the impl will satisfy. To build \
     without it, drop --features method-webs."
);
