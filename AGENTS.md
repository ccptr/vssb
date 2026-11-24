# vss: notes for agents

A Cargo workspace (virtual manifest at the root, one `Cargo.lock` and
`target/` for all crates):

- `vssl/`: the embeddable sandbox library. Read `vssl/AGENTS.md`.
- `dbus-proxy/`: the filtering D-Bus proxy library. Read `dbus-proxy/AGENTS.md`.
- `vssr/`: the command-line front end built on both (policy files,
  detection, audit log). Read `vssr/AGENTS.md`.
- `packaging/arch/`: PKGBUILDs for vssr. `vssr-git` follows `main`;
  `vssr` is pinned to a vss and an ossteam commit (no release is tagged
  yet). To move it, set `_commit`, `_ossteam_commit` and `pkgver`, then
  run `updpkgsums`; the vss commit must be on GitHub.

Read the AGENTS.md of each crate you work in. Run `cargo test` from the
root to test every crate.

## Depending on systemd

Use systemd only where there is no real alternative, and add a fallback
wherever one is reasonably possible (for example, a kernel mechanism
that enforces the same limit without a systemd scope). Each of these
choices is the user's: whether a feature depends on systemd, and which
fallback it gets, if any. Ask before deciding; don't settle it in code
or in a design note on your own.
