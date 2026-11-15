### Changed — building the management UI requires the Node.js version in `did-hosting-ui/package.json`

The `ui` feature's build script (`did-hosting-control/build.rs`, used by the
control plane and the daemon) now reads its Node.js floor from `engines.node`
in `did-hosting-ui/package.json` (currently `>=24.3.0`) instead of its own
`20`, so the two can no longer disagree. A build that rebuilds the UI on an
older Node now stops with a message naming the required version; build with
`--no-default-features` (see the crate READMEs) to skip the UI.

### Changed — shipped setup recipes run as documented

`examples/did-hosting-server-build.toml` sets a placeholder
`[identity].control_did` (replace it with your control plane's DID), so it is
no longer refused as shipped, and the new
`examples/did-hosting-daemon-self-managed.toml` sets up a VTA-less daemon on
`localhost` with no edits. CI loads and validates every recipe in `examples/`.

### Changed — documentation reorganised

`docs/README.md` indexes the documentation; every page carries a status line,
superseded designs and plans moved to `docs/archive/`, and new pages cover
configuration, deployment, backup and upgrade, metrics, troubleshooting, the
architecture and trust model, and a glossary. A `docs` CI job checks status
lines, relative links (lychee, offline) and retired names.
