//! Declarative setup recipes for the webvh services.
//!
//! A *recipe* is a TOML file that captures every input the interactive
//! setup wizards prompt for. It lets operators drive `webvh-daemon`,
//! `webvh-server`, `webvh-control`, `webvh-witness` (and the simpler
//! `webvh-watcher`) through CI / scripts without a TTY.
//!
//! The recipe is **declarative** — it contains no secret material; cloud
//! credentials and VTA bundles are supplied separately at runtime
//! (env vars, file paths, the `--setup-key-file` ephemeral did:key, etc.).
//! Safe to commit to version control.
//!
//! ## Three non-interactive entry points
//!
//! 1. **`--from <recipe.toml>`** — load every field from the recipe.
//! 2. **`--non-interactive`** with CLI flags — build a recipe in-memory
//!    from `clap` args, then dispatch the same way.
//! 3. **Phase 1 / Phase 2 VTA enrolment** (`--setup-key-out` /
//!    `--setup-key-file`) — pre-existing; the recipe loader cooperates
//!    by accepting a pre-loaded ephemeral key for online mode.
//!
//! See `examples/webvh-*-build.toml` and `docs/bootstrap_startup.md`.

pub mod apply;
pub mod exit_codes;
pub mod load;
pub mod reprovision;
pub mod schema;

pub use apply::*;
pub use exit_codes::*;
pub use load::*;
pub use reprovision::*;
pub use schema::*;
