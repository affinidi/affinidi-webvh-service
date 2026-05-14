//! Exit codes for non-interactive setup runs.
//!
//! Scripts and CI pipelines branch on these — keep them stable. They
//! mirror the mediator-setup wizard's documented exit codes so operators
//! who run both have one set to remember.

/// Setup completed successfully.
pub const EXIT_OK: i32 = 0;

/// Generic argument / recipe parse error caught before any side effects.
/// Use `clap`'s default exit code (2) for `--help` / bad args; this is for
/// recipes that *parse* but fail downstream validation.
pub const EXIT_RECIPE_INVALID: i32 = 5;

/// The VTA refused the post-auth request body. Operator must inspect the
/// VTA's error and re-run. Matches the mediator wizard's exit 3.
pub const EXIT_VTA_POST_AUTH: i32 = 3;

/// No VTA transport worked (every advertised transport failed pre-auth).
/// Matches the mediator wizard's exit 2.
pub const EXIT_VTA_NO_TRANSPORT: i32 = 2;

/// Existing setup detected — `--force-reprovision` not given. The wizard
/// refuses to silently rotate live keys.
pub const EXIT_REPROVISION_REFUSED: i32 = 4;
