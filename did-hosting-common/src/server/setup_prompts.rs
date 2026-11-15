//! Shared `dialoguer` prompt helpers used by every binary's setup wizard.
//!
//! Why this module exists: the four binary wizards (server, control,
//! daemon, witness) previously duplicated the same prompt patterns inline
//! — listen host/port, log format, public URL — and across two setup
//! modes each (online + offline) in some cases. A typo or default-value
//! drift between binaries was easy to introduce and hard to spot.
//!
//! Helpers here are intentionally minimal — they wrap a single dialoguer
//! call each, take an explicit default value so the call site documents
//! the per-binary default, and return the parsed/validated result. No
//! behaviour change vs. the inline form; the value is consolidation.
//!
//! The setup wizards for the offline-bootstrap secret store live in
//! `super::secret_store::wizard` and are not affected — different
//! prompt surface entirely.

use dialoguer::{Input, Select};

use super::config::{LogFormat, TransportSelection};

/// Prompt for a long, free-form value (DIDs, URLs) that can exceed the
/// terminal width.
///
/// `dialoguer::Input::interact_text()` renders the prompt and the typed
/// value inline and redraws the line on submit, but its render-height
/// tracker counts only `\n` characters (`dialoguer`'s `theme/render.rs`),
/// so it cannot see that a long value wrapped onto a second physical row on
/// a narrow terminal. Its post-submit `clear_last_lines` then under-counts,
/// the wrapped first row is never erased, and the redraw leaves a duplicate
/// — the doubled `Mediator DID` line operators hit when the value is wider
/// than the window. We sidestep the redraw entirely: print the label and
/// read the line in cooked mode, letting the terminal wrap the echo
/// naturally with nothing to clear. The on-screen form (`prompt: value`)
/// matches `dialoguer`'s default `SimpleTheme`.
///
/// `allow_empty` controls whether an empty submission returns `""` (used by
/// "leave empty to skip" prompts) or re-prompts. EOF returns whatever was
/// read so a non-interactive stream can't spin forever. The result is
/// trimmed.
pub fn prompt_long_value(prompt: &str, allow_empty: bool) -> dialoguer::Result<String> {
    use std::io::{BufRead, Write};

    let mut stderr = std::io::stderr();
    loop {
        write!(stderr, "{prompt}: ")?;
        stderr.flush()?;

        let mut line = String::new();
        let read = std::io::stdin().lock().read_line(&mut line)?;
        let value = line.trim().to_string();

        // Re-prompt only on a deliberate empty Enter (read > 0); on EOF
        // (read == 0) fall through with the empty value to avoid a spin.
        if value.is_empty() && !allow_empty && read != 0 {
            continue;
        }
        return Ok(value);
    }
}

/// [`prompt_long_value`], re-prompting with the reason until `check` accepts
/// the value. With `allow_empty`, an empty submission returns `""` without
/// being checked. At end of input an unacceptable value is an error rather
/// than a silent acceptance.
pub fn prompt_long_validated(
    prompt: &str,
    allow_empty: bool,
    check: impl Fn(&str) -> Result<String, String>,
) -> dialoguer::Result<String> {
    loop {
        let value = prompt_long_value(prompt, allow_empty)?;
        if value.is_empty() && allow_empty {
            return Ok(value);
        }
        match check(&value) {
            Ok(accepted) => return Ok(accepted),
            Err(reason) if value.is_empty() => {
                // EOF with nothing read: nothing more will come.
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, reason).into());
            }
            Err(reason) => eprintln!("  {reason}"),
        }
    }
}

/// Accept an absolute `http`/`https` URL with a host, returned without its
/// trailing slash so downstream code can `format!("{}/path")` without
/// double-slashing.
pub fn validate_url(value: &str) -> Result<String, String> {
    let value = value.trim();
    let url = url::Url::parse(value).map_err(|e| {
        format!("`{value}` is not a URL ({e}); enter it with its scheme, e.g. https://example.com")
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "`{value}` uses `{}`; the URL must start with https:// (or http://)",
            url.scheme()
        ));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(format!("`{value}` has no host"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(format!("`{value}` must not carry a query or fragment"));
    }
    Ok(value.trim_end_matches('/').to_string())
}

/// Accept a DID: `did:<method>:<method-specific-id>`, the method lowercase
/// letters and digits, no whitespace anywhere.
pub fn validate_did(value: &str) -> Result<String, String> {
    let value = value.trim();
    let shape = || {
        format!("`{value}` is not a DID; expected did:<method>:<id>, e.g. did:webvh:…:example.com")
    };
    if value.chars().any(char::is_whitespace) {
        return Err(format!("`{value}` contains whitespace; a DID has none"));
    }
    let rest = value.strip_prefix("did:").ok_or_else(shape)?;
    let (method, id) = rest.split_once(':').ok_or_else(shape)?;
    if method.is_empty()
        || !method
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        || id.is_empty()
    {
        return Err(shape());
    }
    Ok(value.to_string())
}

/// Accept a listen address: an IPv4 or IPv6 address (`0.0.0.0`, `127.0.0.1`,
/// `::`), not a hostname.
pub fn validate_listen_host(value: &str) -> Result<String, String> {
    let value = value.trim();
    value
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.to_string())
        .map_err(|_| {
            format!(
                "`{value}` is not an IP address; enter one, e.g. 0.0.0.0 (every interface) \
                 or 127.0.0.1"
            )
        })
}

/// Prompt for an `http`/`https` URL (see [`validate_url`]), re-prompting
/// with the reason until one parses.
///
/// `prompt_text` lets the caller phrase the question for its binary
/// (e.g. "Server URL", "DID hosting URL"). With `allow_empty`, an empty
/// answer returns `""` (a "leave empty to skip" prompt).
pub fn prompt_url(prompt_text: &str, allow_empty: bool) -> dialoguer::Result<String> {
    prompt_long_validated(prompt_text, allow_empty, validate_url)
}

/// Prompt for a DID (see [`validate_did`]), re-prompting with the reason
/// until one has the `did:<method>:` shape. With `allow_empty`, an empty
/// answer returns `""`.
pub fn prompt_did(prompt_text: &str, allow_empty: bool) -> dialoguer::Result<String> {
    prompt_long_validated(prompt_text, allow_empty, validate_did)
}

/// Prompt for the bind / listen host, an IP address. Default is almost
/// always `0.0.0.0` (any interface); pass that in to keep the call site's
/// intent visible.
pub fn prompt_listen_host(default: &str) -> dialoguer::Result<String> {
    let host: String = Input::new()
        .with_prompt("Listen host")
        .default(default.to_string())
        .validate_with(|v: &String| validate_listen_host(v).map(|_| ()))
        .interact_text()?;
    Ok(validate_listen_host(&host).unwrap_or(host))
}

/// Prompt for the bind / listen port. Default differs per binary
/// (server=8530, daemon=8534, witness=8531, …); pass the binary's choice.
pub fn prompt_listen_port(default: u16) -> dialoguer::Result<u16> {
    Input::new()
        .with_prompt("Listen port")
        .default(default)
        .interact_text()
}

/// Prompt for the log output format (`text` or `json`). Default is `text`.
pub fn prompt_log_format() -> dialoguer::Result<LogFormat> {
    let options = ["text", "json"];
    let idx = Select::new()
        .with_prompt("Log format")
        .items(options)
        .default(0)
        .interact()?;
    Ok(match idx {
        1 => LogFormat::Json,
        _ => LogFormat::Text,
    })
}

/// Prompt for which messaging transport(s) the node advertises and its
/// mediator listener carries. TSP and DIDComm share the mediator socket,
/// so callers only invoke this when a mediator has been configured — with
/// no mediator the node is HTTP-only. Defaults to `Both` (a node that
/// speaks both is reachable by every peer; TSP is preferred when a peer
/// advertises both).
pub fn prompt_transport_selection() -> dialoguer::Result<TransportSelection> {
    let options = [
        "Both DIDComm and TSP (recommended)",
        "DIDComm only",
        "TSP only",
    ];
    let idx = Select::new()
        .with_prompt("Messaging transport")
        .items(options)
        .default(0)
        .interact()?;
    Ok(match idx {
        1 => TransportSelection::Didcomm,
        2 => TransportSelection::Tsp,
        _ => TransportSelection::Both,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_need_an_http_scheme_and_a_host() {
        assert_eq!(
            validate_url(" https://server1.example.com/ ").unwrap(),
            "https://server1.example.com"
        );
        assert_eq!(
            validate_url("http://localhost:8530/dids/a").unwrap(),
            "http://localhost:8530/dids/a"
        );
        for bad in [
            "server1.example.com",
            "ftp://example.com",
            "https://",
            "https://example.com/?x=1",
            "not a url",
        ] {
            assert!(validate_url(bad).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn dids_need_the_did_method_shape() {
        assert_eq!(
            validate_did("did:webvh:abc:example.com").unwrap(),
            "did:webvh:abc:example.com"
        );
        assert!(validate_did("did:key:z6Mk").is_ok());
        for bad in [
            "webvh:abc",
            "did:",
            "did:webvh",
            "did:webvh:",
            "did:WebVH:abc",
            "did:webvh:abc example.com",
            "https://example.com",
        ] {
            assert!(validate_did(bad).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn listen_hosts_are_ip_addresses() {
        assert_eq!(validate_listen_host("0.0.0.0").unwrap(), "0.0.0.0");
        assert_eq!(validate_listen_host(" :: ").unwrap(), "::");
        assert!(validate_listen_host("localhost").is_err());
        assert!(validate_listen_host("example.com").is_err());
    }
}
