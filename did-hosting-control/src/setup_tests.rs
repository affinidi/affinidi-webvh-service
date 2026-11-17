//! Tests for the control plane's setup wizard.

use super::*;

/// The wizard grants an edge the role `server/register` requires
/// (`service`), never `admin`, which registration refuses.
#[test]
fn acl_guidance_grants_edges_the_service_role() {
    let grant = format!("add-acl --did <edge-did> --role {}", Role::Service);
    assert!(
        ACL_BOOTSTRAP_GUIDANCE.contains(&grant),
        "{ACL_BOOTSTRAP_GUIDANCE}"
    );
    assert!(
        !ACL_BOOTSTRAP_GUIDANCE.contains("--role admin"),
        "{ACL_BOOTSTRAP_GUIDANCE}"
    );
}
