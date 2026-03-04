//! Control plane registration — announces this server to the control plane.

use serde_json::json;
use tracing::{info, warn};

/// Register this server instance with the control plane.
///
/// Posts a service registration request using a shared bearer token.
/// Failures are logged as warnings — registration is never fatal.
pub async fn register_with_control(
    http_client: &reqwest::Client,
    control_url: &str,
    control_token: &str,
    public_url: &str,
    label: Option<&str>,
) {
    let url = format!("{control_url}/api/control/register-service");
    let body = json!({
        "serviceType": "server",
        "url": public_url,
        "label": label,
    });

    match http_client
        .post(&url)
        .bearer_auth(control_token)
        .json(&body)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            info!(control_url = %control_url, "registered with control plane");
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(
                control_url = %control_url,
                status = %status,
                body = %body,
                "control plane registration failed"
            );
        }
        Err(e) => {
            warn!(
                control_url = %control_url,
                error = %e,
                "failed to connect to control plane for registration"
            );
        }
    }
}
