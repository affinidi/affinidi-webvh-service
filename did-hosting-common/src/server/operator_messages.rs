//! `OperatorMessages` implementations for the four webvh setup binaries.
//!
//! These are passed to `vta_sdk::provision_client::run_provision` (and the
//! headless `run_phase1_init` / `run_phase2_connect`) so the SDK's runners
//! and CLI driver render the right integration label and `pnm contexts
//! create` command for each binary.

use vta_sdk::provision_client::OperatorMessages;

/// Messages for the `did-hosting-daemon` binary (unified server + control + witness).
pub struct WebvhDaemonMessages;

impl OperatorMessages for WebvhDaemonMessages {
    fn integration_label(&self) -> &str {
        "DID Hosting daemon"
    }

    fn integration_label_lower(&self) -> &str {
        "did hosting daemon"
    }

    fn pnm_admin_command_hint(&self, context_id: &str, setup_did: &str) -> String {
        format!(
            "pnm contexts create --id {context_id} --name \"DID Hosting daemon\" \\\n  \
             --admin-did {setup_did} --admin-expires 1h"
        )
    }
}

/// Messages for the `did-hosting-server` binary (standalone DID hosting server).
pub struct WebvhServerMessages;

impl OperatorMessages for WebvhServerMessages {
    fn integration_label(&self) -> &str {
        "DID Hosting server"
    }

    fn integration_label_lower(&self) -> &str {
        "did hosting server"
    }

    fn pnm_admin_command_hint(&self, context_id: &str, setup_did: &str) -> String {
        format!(
            "pnm contexts create --id {context_id} --name \"DID Hosting server\" \\\n  \
             --admin-did {setup_did} --admin-expires 1h"
        )
    }
}

/// Messages for the `did-hosting-control` binary (standalone management plane).
pub struct WebvhControlMessages;

impl OperatorMessages for WebvhControlMessages {
    fn integration_label(&self) -> &str {
        "DID Hosting control plane"
    }

    fn integration_label_lower(&self) -> &str {
        "did hosting control plane"
    }

    fn pnm_admin_command_hint(&self, context_id: &str, setup_did: &str) -> String {
        format!(
            "pnm contexts create --id {context_id} --name \"DID Hosting control plane\" \\\n  \
             --admin-did {setup_did} --admin-expires 1h"
        )
    }
}

/// Messages for the `webvh-witness` binary (standalone witness service).
pub struct WebvhWitnessMessages;

impl OperatorMessages for WebvhWitnessMessages {
    fn integration_label(&self) -> &str {
        "WebVH witness"
    }

    fn integration_label_lower(&self) -> &str {
        "webvh witness"
    }

    fn pnm_admin_command_hint(&self, context_id: &str, setup_did: &str) -> String {
        format!(
            "pnm contexts create --id {context_id} --name \"WebVH witness\" \\\n  \
             --admin-did {setup_did} --admin-expires 1h"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_distinct_per_binary() {
        let labels = [
            WebvhDaemonMessages.integration_label(),
            WebvhServerMessages.integration_label(),
            WebvhControlMessages.integration_label(),
            WebvhWitnessMessages.integration_label(),
        ];
        for (i, a) in labels.iter().enumerate() {
            for b in labels.iter().skip(i + 1) {
                assert_ne!(a, b, "duplicate label: {a}");
            }
        }
    }

    #[test]
    fn pnm_command_includes_context_did_and_label() {
        let cmd = WebvhDaemonMessages
            .pnm_admin_command_hint("prod-webvh", "did:key:z6MkExampleDaemonKey");
        assert!(cmd.contains("--id prod-webvh"));
        assert!(cmd.contains("--admin-did did:key:z6MkExampleDaemonKey"));
        assert!(cmd.contains("--name \"DID Hosting daemon\""));
        assert!(cmd.contains("--admin-expires 1h"));
    }

    #[test]
    fn server_command_uses_hosting_server_label() {
        let cmd = WebvhServerMessages
            .pnm_admin_command_hint("prod-webvh", "did:key:z6MkExampleServerKey");
        assert!(cmd.contains("--name \"DID Hosting server\""));
    }

    #[test]
    fn control_command_uses_control_plane_label() {
        let cmd = WebvhControlMessages
            .pnm_admin_command_hint("prod-webvh", "did:key:z6MkExampleControlKey");
        assert!(cmd.contains("--name \"DID Hosting control plane\""));
    }

    #[test]
    fn witness_command_uses_witness_label() {
        let cmd = WebvhWitnessMessages
            .pnm_admin_command_hint("prod-webvh", "did:key:z6MkExampleWitnessKey");
        assert!(cmd.contains("--name \"WebVH witness\""));
    }
}
