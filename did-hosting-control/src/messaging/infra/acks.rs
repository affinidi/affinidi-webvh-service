//! Acknowledgements from edges: DID sync acks and domain assign/unassign/purge
//! acks, which settle the outbox and the domain intents.

use super::*;

// ---------------------------------------------------------------------------
// Sync / domain acknowledgements (server → control plane)
// ---------------------------------------------------------------------------

/// A server acknowledged a `sync/*` push. Informational: logged, nothing else.
pub(crate) fn do_sync_ack(signer: &str, type_uri: &str, body: &Value) {
    let status = body
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let mnemonic = body
        .get("mnemonic")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    info!(
        signer,
        mnemonic, status, type_uri, "DID sync: server acknowledged"
    );
    // A `sync/batch` ack carries a result per entry. A refused entry settles
    // with the batch, and that server keeps serving the version it had (for
    // example, a log over its store's item limit), so it is worth an operator's
    // attention.
    for result in body
        .get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|r| r.get("status").and_then(Value::as_str) == Some("refused"))
    {
        let field = |name| {
            result
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        };
        let (mnemonic, code) = (field("mnemonic"), field("code"));
        warn!(
            signer,
            mnemonic,
            code,
            "DID sync: server refused an entry and keeps serving its previous version"
        );
    }
}

/// A server acknowledged a `domain/{assign,unassign,purge}` push.
///
/// Mirrors the server's view of `served_domains` into the registry so the UI
/// reflects the change without waiting for the next registration:
/// `applied` on an assign ack adds the domain, anything
/// else removes it. `signer` is the ack's proven issuer and must hold the
/// Service role — otherwise any DID could rewrite a server's `served_domains`
/// (dropping a domain hides it from the next purge fan-out).
pub(crate) async fn do_domain_ack(state: &AppState, signer: &str, type_uri: &str, body: &Value) {
    let status = body
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let Some(domain) = body.get("domain").and_then(|v| v.as_str()) else {
        return;
    };
    let op = match type_uri {
        MSG_REPLICA_DOMAIN_ASSIGN_ACK => "assign",
        MSG_REPLICA_DOMAIN_UNASSIGN_ACK => "unassign",
        _ => "purge",
    };
    // The acknowledgement must be its task's response type (R3.2): a body
    // that is not is acted on in no way.
    {
        use did_hosting_common::tasks::did_management::replica::domain::{
            assign::v0_1 as assign, purge::v0_1 as purge, unassign::v0_1 as unassign,
        };
        let conforms = match op {
            "assign" => serde_json::from_value::<assign::Response>(body.clone()).is_ok(),
            "unassign" => serde_json::from_value::<unassign::Response>(body.clone()).is_ok(),
            _ => serde_json::from_value::<purge::Response>(body.clone()).is_ok(),
        };
        if !conforms {
            warn!(
                signer,
                domain, op, "domain ack ignored: not a {op} response this service reads"
            );
            return;
        }
    }
    info!(
        signer,
        domain, status, op, "server acknowledged domain {op}"
    );

    match check_acl(&state.acl_ks, signer).await {
        Ok(did_hosting_common::server::acl::Role::Service) => {}
        Ok(other) => {
            warn!(did = signer, role = %other, domain, op, "domain ack rejected: Service role required");
            return;
        }
        Err(e) if did_hosting_common::server::acl::is_acl_refusal(&e) => {
            warn!(
                did = signer,
                domain, op, "domain ack rejected: DID not in ACL"
            );
            return;
        }
        // Not settled: the control plane re-sends the op, and the server
        // acknowledges it again.
        Err(e) => {
            warn!(did = signer, domain, op, error = %e, "domain ack ignored: ACL lookup failed");
            return;
        }
    }
    // An acknowledged unassign or purge no longer needs re-sending on the next
    // registration (see `server_push::resend_domain_intents`).
    let settled = match op {
        "assign" => crate::server_push::DomainOp::Assign,
        "unassign" => crate::server_push::DomainOp::Unassign,
        _ => crate::server_push::DomainOp::Purge,
    };
    // `replica/domain/assign/0.1` answers only `applied`.
    let add = op == "assign" && status == "applied";
    crate::server_push::settle_domain_intent(state, signer, domain, settled, add).await;

    let instance_id = crate::registry::instance_id_for(signer);
    // Under the instance's lock, so a concurrent registration or status sweep
    // cannot drop this change to `served_domains` (which the purge fan-out
    // reads).
    let mut found = false;
    let updated =
        crate::registry::update_instance_for_did(&state.registry_ks, signer, |instance| {
            found = true;
            if add {
                if instance.served_domains.iter().any(|d| d == domain) {
                    return false;
                }
                instance.served_domains.push(domain.to_string());
                instance.served_domains.sort();
                true
            } else {
                let before = instance.served_domains.len();
                instance.served_domains.retain(|d| d != domain);
                instance.served_domains.len() != before
            }
        })
        .await;
    match updated.map(|_| found) {
        Ok(true) => {}
        Ok(false) => {
            // Ack arrived before registration, or the registry was wiped; the
            // next register cycle reconciles.
            warn!(
                instance_id,
                "domain ack received for unregistered server — skipping registry update"
            );
        }
        Err(e) => {
            warn!(instance_id, error = %e, "failed to load instance for ack reconciliation");
        }
    }
}
