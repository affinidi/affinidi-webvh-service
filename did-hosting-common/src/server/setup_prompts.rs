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

use super::config::LogFormat;

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

/// Prompt for a public URL.
///
/// `prompt_text` lets the caller phrase the question for its binary
/// (e.g. "Server URL", "DID hosting URL"). The trailing slash is
/// stripped before returning so downstream code can `format!("{}/path")`
/// without double-slashing.
pub fn prompt_public_url(prompt_text: &str) -> dialoguer::Result<String> {
    let url = prompt_long_value(prompt_text, false)?;
    Ok(url.trim_end_matches('/').to_string())
}

/// Prompt for the bind / listen host. Default is almost always `0.0.0.0`
/// (any interface); pass that in to keep the call site's intent visible.
pub fn prompt_listen_host(default: &str) -> dialoguer::Result<String> {
    Input::new()
        .with_prompt("Listen host")
        .default(default.to_string())
        .interact_text()
}

/// Prompt for the bind / listen port. Default differs per binary
/// (server=8530, daemon=8534, witness=8102, …); pass the binary's choice.
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
