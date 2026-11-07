# vss: notes for agents

A Cargo workspace (virtual manifest at the root, one `Cargo.lock` and
`target/` for all crates):

- `vssb/`: the embeddable sandbox library. Read `vssb/AGENTS.md`.
- `vssr/`: the command-line front end built on it (policy files,
  detection, audit log). Read `vssr/AGENTS.md`.

Read the AGENTS.md of each crate you work in. Run `cargo test` from the
root to test every crate.

## Depending on systemd

Use systemd only where there is no real alternative, and add a fallback
wherever one is reasonably possible (for example, a kernel mechanism
that enforces the same limit without a systemd scope). Each of these
choices is the user's: whether a feature depends on systemd, and which
fallback it gets, if any. Ask before deciding; don't settle it in code
or in a design note on your own.
