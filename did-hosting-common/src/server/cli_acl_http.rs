//! Live-API variants of the `add-acl` / `list-acl` / `remove-acl` CLI commands.
//!
//! When `--url` and `--token` are passed, the CLI calls the running service's
//! authenticated REST API instead of opening the store directly. This works
//! while the service is running, even for backends with an exclusive store lock
//! (fjall).
//!
//! API contract (matches the control plane's `/api/acl` routes):
//!
//! ```text
//! GET    /api/acl        -> 200 { entries: [...] }
//! POST   /api/acl        -> 201 { did, role, ... }
//! DELETE /api/acl/{did}  -> 204
//! ```
//!
//! The bearer token must be a valid admin JWT.

use reqwest::Client;
use serde::Serialize;
use serde_json::Value;

const MAX_DID_LEN: usize = 2048;
const MAX_LABEL_LEN: usize = 256;

type CliResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Serialize)]
struct CreateAclBody<'a> {
    did: &'a str,
    role: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_total_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_did_count: Option<u64>,
}

fn has_control_chars(s: &str) -> bool {
    s.chars().any(char::is_control)
}

fn validate_url(url: &str) -> Result<(), String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or("url must start with http:// or https://")?;
    if rest.is_empty() || rest.starts_with('/') || has_control_chars(url) || url.contains(' ') {
        return Err("url is not a valid http(s) URL".into());
    }
    Ok(())
}

fn validate_token(token: &str) -> Result<(), String> {
    if token.trim().is_empty() {
        return Err("token must not be empty".into());
    }
    if has_control_chars(token) {
        return Err("token contains control characters".into());
    }
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return Err("token does not look like a JWT (expected header.payload.signature)".into());
    }
    Ok(())
}

fn validate_did(did: &str) -> Result<(), String> {
    if !did.starts_with("did:") {
        return Err("DID must start with 'did:'".into());
    }
    if did.len() > MAX_DID_LEN {
        return Err(format!("DID is too long (max {MAX_DID_LEN} chars)"));
    }
    if has_control_chars(did) {
        return Err("DID contains control characters".into());
    }
    Ok(())
}

fn validate_role(role: &str) -> Result<(), String> {
    match role {
        "admin" | "owner" | "service" => Ok(()),
        _ => Err("invalid role: use admin | owner | service".into()),
    }
}

fn validate_label(label: Option<&str>) -> Result<(), String> {
    match label {
        Some(l) if l.len() > MAX_LABEL_LEN => {
            Err(format!("label is too long (max {MAX_LABEL_LEN} chars)"))
        }
        Some(l) if has_control_chars(l) => Err("label contains control characters".into()),
        _ => Ok(()),
    }
}

/// Percent-encode a string for use as a single URL path segment.
fn percent_encode_path(input: &str) -> String {
    input
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=@".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn acl_endpoint(url: &str) -> String {
    format!("{}/api/acl", url.trim_end_matches('/'))
}

async fn api_error(resp: reqwest::Response) -> Box<dyn std::error::Error> {
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    format!("API returned {status}: {body}").into()
}

/// Create an ACL entry via the live REST API.
pub async fn api_add_acl(
    url: &str,
    token: &str,
    did: String,
    role: String,
    label: Option<String>,
    max_total_size: Option<u64>,
    max_did_count: Option<u64>,
) -> CliResult {
    validate_url(url)?;
    validate_token(token)?;
    validate_did(&did)?;
    validate_role(&role)?;
    validate_label(label.as_deref())?;

    let body = CreateAclBody {
        did: &did,
        role: &role,
        label: label.as_deref(),
        max_total_size,
        max_did_count,
    };
    let resp = Client::new()
        .post(acl_endpoint(url))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(api_error(resp).await);
    }
    eprintln!();
    eprintln!("  ACL entry created via live API!");
    eprintln!();
    eprintln!("  DID:  {did}");
    eprintln!("  Role: {role}");
    if let Some(size) = max_total_size {
        eprintln!("  Max total size: {size} bytes");
    }
    if let Some(count) = max_did_count {
        eprintln!("  Max DID count:  {count}");
    }
    eprintln!();
    Ok(())
}

/// List ACL entries via the live REST API.
pub async fn api_list_acl(url: &str, token: &str) -> CliResult {
    validate_url(url)?;
    validate_token(token)?;

    let resp = Client::new()
        .get(acl_endpoint(url))
        .bearer_auth(token)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(api_error(resp).await);
    }

    let data: Value = resp.json().await?;
    let entries = data
        .get("entries")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    if entries.is_empty() {
        eprintln!("  No ACL entries.");
        return Ok(());
    }

    let field = |e: &Value, k: &str| e.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    eprintln!();
    eprintln!("  {:<15} {:<60} LABEL", "ROLE", "DID");
    eprintln!("  {}", "-".repeat(90));
    for e in entries {
        eprintln!(
            "  {:<15} {:<60} {}",
            field(e, "role"),
            field(e, "did"),
            field(e, "label")
        );
    }
    eprintln!();
    eprintln!("  Total: {} entry(s)", entries.len());
    eprintln!();
    Ok(())
}

/// Remove an ACL entry via the live REST API.
pub async fn api_remove_acl(url: &str, token: &str, did: &str) -> CliResult {
    validate_url(url)?;
    validate_token(token)?;
    validate_did(did)?;

    let endpoint = format!("{}/{}", acl_endpoint(url), percent_encode_path(did));
    let resp = Client::new()
        .delete(endpoint)
        .bearer_auth(token)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(api_error(resp).await);
    }
    eprintln!();
    eprintln!("  ACL entry removed via live API.");
    eprintln!("  DID: {did}");
    eprintln!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "aaa.bbb.ccc";

    #[test]
    fn colon_in_did_is_encoded() {
        assert_eq!(percent_encode_path("did:key:z6Mk"), "did%3Akey%3Az6Mk");
    }

    #[test]
    fn unreserved_chars_are_not_encoded() {
        assert_eq!(percent_encode_path("abc123-._~"), "abc123-._~");
    }

    #[test]
    fn endpoint_strips_trailing_slash() {
        assert_eq!(acl_endpoint("http://h:1/"), "http://h:1/api/acl");
    }

    #[test]
    fn url_validation() {
        assert!(validate_url("http://localhost:8534").is_ok());
        assert!(validate_url("https://x.example").is_ok());
        assert!(validate_url("ftp://x").is_err());
        assert!(validate_url("http://").is_err());
        assert!(validate_url("http://a b").is_err());
    }

    #[test]
    fn token_validation() {
        assert!(validate_token(TOKEN).is_ok());
        assert!(validate_token("").is_err());
        assert!(validate_token("a.b").is_err());
        assert!(validate_token("a..c").is_err());
        assert!(validate_token("a.b.c\n").is_err());
    }

    #[test]
    fn did_role_label_validation() {
        assert!(validate_did("did:key:z6Mk").is_ok());
        assert!(validate_did("key:z6Mk").is_err());
        assert!(validate_role("admin").is_ok());
        assert!(validate_role("root").is_err());
        assert!(validate_label(Some("ok")).is_ok());
        assert!(validate_label(Some(&"x".repeat(MAX_LABEL_LEN + 1))).is_err());
        assert!(validate_label(Some("a\nb")).is_err());
        assert!(validate_label(None).is_ok());
    }

    #[test]
    fn create_body_omits_unset_optionals() {
        let body = CreateAclBody {
            did: "did:key:z",
            role: "admin",
            label: None,
            max_total_size: None,
            max_did_count: Some(3),
        };
        let v = serde_json::to_value(&body).unwrap();
        assert_eq!(v["max_did_count"], 3);
        assert!(v.get("label").is_none());
        assert!(v.get("max_total_size").is_none());
    }
}
