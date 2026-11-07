# vss: notes for agents

A Cargo workspace (virtual manifest at the root, one `Cargo.lock` and
`target/` for all crates):

- `vssb/`: the embeddable sandbox library. Read `vssb/AGENTS.md`.

Read the AGENTS.md of each crate you work in. Run `cargo test` from the
root to test every crate.
