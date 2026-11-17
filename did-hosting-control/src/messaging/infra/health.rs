//! `server/health` pongs: an edge's answer to the control plane's ping,
//! recorded on its registry entry.

use super::*;

// ---------------------------------------------------------------------------
// Health pong handler (server → control plane)
// ---------------------------------------------------------------------------

/// Transport-agnostic core of health-pong handling, for the
/// `.../server/health/0.1#response` trust task over DIDComm or TSP.
///
/// `signer` is the pong's proven issuer. Only a Service-role DID may mark an
/// instance Active: the registry's liveness view decides which servers the
/// dashboard reports healthy, so it must not be writable by any DID that can
/// reach the mediator.
///
/// A pong is terminal: it never produces a reply.
pub(crate) async fn do_health_pong(state: &AppState, signer: &str, body: &Value) {
    use crate::registry::{self, ServiceStatus};

    match is_service(state, signer).await {
        Ok(true) => {}
        Ok(false) => {
            warn!(did = signer, "health pong ignored: Service role required");
            return;
        }
        Err(e) => {
            warn!(did = signer, error = %e, "health pong ignored: ACL lookup failed");
            return;
        }
    }

    // Typed and closed (R3.2): a pong this service does not read in full
    // marks nothing active.
    // The pinned `server/health/0.1#response`, or for one release the pong
    // edges sent before #449.
    let pong = match did_hosting_common::server::trust_tasks::infra::read_health_reply(body) {
        Ok(pong) => pong,
        Err(e) => {
            warn!(did = signer, error = %e, "health pong ignored: not a pong this service reads");
            return;
        }
    };
    let version = pong.version.as_deref().unwrap_or("unknown");
    debug!(signer, ok = pong.ok, version, did_count = ?pong.did_count, "health pong received from server");

    // Find the instance the signer registered and mark it active. Another
    // DID whose registry id collides with it is not that instance.
    let instance_id = registry::instance_id_for(signer);
    if let Some(named) = pong.instance_id.as_deref()
        && named != instance_id
    {
        warn!(
            did = signer,
            named, instance_id, "health pong ignored: names another instance"
        );
        return;
    }
    // Only a successful check improves the status: an edge reporting itself
    // unhealthy is left to age out like one that did not answer.
    if !pong.ok {
        warn!(
            did = signer,
            instance_id, "health pong reports the edge unhealthy"
        );
        return;
    }
    let now = crate::auth::session::now_epoch();
    let updated = registry::update_instance_for_did(&state.registry_ks, signer, |instance| {
        instance.status = ServiceStatus::Active;
        instance.last_health_check = Some(now);
        true
    })
    .await;
    if let Err(e) = updated {
        warn!(instance_id, error = %e, "failed to update instance status from health pong");
    }
}
