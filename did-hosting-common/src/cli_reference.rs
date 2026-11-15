//! `docs/cli-reference.md`, generated from each binary's clap definition.
//!
//! Every binary carries a test made by [`cli_reference_test!`](crate::cli_reference_test!): it renders
//! the binary's `--help` and every subcommand's long help, and fails when the
//! binary's section of `docs/cli-reference.md` differs — so the reference
//! cannot drift from the CLI, and the test doubles as a `--help` snapshot.
//! To regenerate after changing a CLI:
//!
//! ```text
//! UPDATE_CLI_REFERENCE=1 cargo test -p <crate> --bin <binary> cli_reference
//! ```
//!
//! This module holds the string handling; the clap rendering lives in the
//! macro, which expands in the binary crate (whose `clap` it uses), so this
//! crate takes no `clap` dependency.

use std::path::Path;

/// The environment variable that makes the test rewrite the reference
/// instead of comparing against it.
pub const UPDATE_VAR: &str = "UPDATE_CLI_REFERENCE";

const HEADER: &str = "# CLI reference\n\n\
> **Status:** current — generated from each binary's clap definition.\n\n\
<!-- Generated from each binary's clap definition. Do not edit by hand: run\n     \
`UPDATE_CLI_REFERENCE=1 cargo test -p <crate> --bin <binary> cli_reference`\n     \
(see did-hosting-common/src/cli_reference.rs). -->\n\n\
Every subcommand of every binary, with its full `--help`. The global\n\
`-c, --config <PATH>` option is accepted by every subcommand.\n";

fn begin(bin: &str) -> String {
    format!("<!-- BEGIN {bin} -->\n")
}

fn end(bin: &str) -> String {
    format!("<!-- END {bin} -->\n")
}

/// The section of the reference for `bin`, from its rendered top-level help
/// and `(subcommand, long help)` pairs.
pub fn section(bin: &str, top_help: &str, subcommands: &[(String, String)]) -> String {
    let mut out = String::new();
    out.push_str(&begin(bin));
    out.push_str(&format!("## `{bin}`\n\n```text\n{}\n```\n", tidy(top_help)));
    for (name, help) in subcommands {
        out.push_str(&format!(
            "\n### `{bin} {name}`\n\n```text\n{}\n```\n",
            tidy(help)
        ));
    }
    out.push_str(&end(bin));
    out
}

/// Help text without trailing whitespace on any line.
fn tidy(help: &str) -> String {
    help.trim_end()
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
}

/// `doc` with `bin`'s section replaced by `section` (or appended, in a
/// document that has none yet).
pub fn splice(doc: &str, bin: &str, section: &str) -> String {
    let doc = if doc.trim().is_empty() { HEADER } else { doc };
    let (b, e) = (begin(bin), end(bin));
    match (doc.find(&b), doc.find(&e)) {
        (Some(start), Some(stop)) if stop > start => {
            format!("{}{section}{}", &doc[..start], &doc[stop + e.len()..])
        }
        _ => format!(
            "{}\n{section}",
            doc.trim_end_matches('\n').to_string() + "\n"
        ),
    }
}

/// `bin`'s section as it stands in `doc`, if present.
pub fn current_section<'a>(doc: &'a str, bin: &str) -> Option<&'a str> {
    let (b, e) = (begin(bin), end(bin));
    let start = doc.find(&b)?;
    let stop = doc.find(&e)?;
    (stop > start).then(|| &doc[start..stop + e.len()])
}

/// Compare `bin`'s section of the reference at `path` with `expected`, or
/// rewrite it when [`UPDATE_VAR`] is set. Panics with the regeneration
/// command when they differ.
pub fn check_or_update(path: &Path, crate_name: &str, bin: &str, expected: &str) {
    let doc = std::fs::read_to_string(path).unwrap_or_default();
    if std::env::var_os(UPDATE_VAR).is_some() {
        std::fs::write(path, splice(&doc, bin, expected))
            .unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
        return;
    }
    if current_section(&doc, bin) != Some(expected) {
        panic!(
            "{} is out of date for `{bin}` (its CLI changed). Regenerate it with\n  \
             {UPDATE_VAR}=1 cargo test -p {crate_name} --bin {bin} cli_reference\n\
             and commit the result.",
            path.display()
        );
    }
}

/// A test, in a binary crate, that keeps `docs/cli-reference.md` in step
/// with the binary's clap `Cli` (see the module docs).
///
/// `cli_reference_test!(Cli, "did-hosting-server")`.
#[macro_export]
macro_rules! cli_reference_test {
    ($cli:ty, $bin:literal) => {
        #[test]
        fn cli_reference_is_current() {
            let mut cmd = <$cli as ::clap::CommandFactory>::command()
                .term_width(100)
                .max_term_width(100);
            cmd.build();
            let top = cmd.render_long_help().to_string();
            let subs: Vec<(String, String)> = cmd
                .get_subcommands_mut()
                .filter(|s| s.get_name() != "help")
                .map(|s| (s.get_name().to_string(), s.render_long_help().to_string()))
                .collect();
            let expected = $crate::cli_reference::section($bin, &top, &subs);
            let path = ::std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("docs")
                .join("cli-reference.md");
            $crate::cli_reference::check_or_update(&path, env!("CARGO_PKG_NAME"), $bin, &expected);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_section_is_spliced_in_place_and_others_kept() {
        let a1 = section("a", "A help", &[("x".into(), "X help".into())]);
        let b = section("b", "B help", &[]);
        let doc = splice(&splice("", "a", &a1), "b", &b);
        assert!(doc.starts_with("# CLI reference"));
        assert_eq!(current_section(&doc, "a"), Some(a1.as_str()));
        assert_eq!(current_section(&doc, "b"), Some(b.as_str()));
        assert!(a1.contains("### `a x`"));

        let a2 = section("a", "A help v2", &[]);
        let doc2 = splice(&doc, "a", &a2);
        assert_eq!(current_section(&doc2, "a"), Some(a2.as_str()));
        assert_eq!(current_section(&doc2, "b"), Some(b.as_str()));
        assert_eq!(splice(&doc2, "a", &a2), doc2, "idempotent");
    }
}
