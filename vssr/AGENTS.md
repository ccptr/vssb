# vssr: notes for agents

Rootless Linux sandbox for running agents unattended. See README.md for
the user-facing design.

vssr is the front end; the sandbox itself is
[vssb](../vssb) (the sibling crate in this workspace), which builds
the namespaces, mounts, Landlock, seccomp and cgroup scope. Changes to
how the sandbox is built, and their tests, go there; vssr turns policy
into a `vssb::Sandbox` and `vssb::Command`. The D-Bus filter is
[vssd](../vssd), likewise: vssr turns `[dbus]` into a `vssd::Policy` and
its events into audit events.

## Layout

- `src/main.rs`: CLI, policy overrides, supervisor (creates the run
  directory, sweeping killed runs' ones, the Wayland security context
  and the D-Bus filter, spawns the sandbox, serves the HTTP proxy,
  forwards signals from a signalfd, timeout, audit events), all on one
  thread apart from the two proxies'.
- `src/policy.rs`: TOML policy and its resolution into a `Plan` (mount
  list as `vssb::Mount`s sorted parent-first, env, net, limits), and
  `Plan::sandbox`/`Plan::command`, which map it onto vssb.
  `DEFAULT_POLICY` is the single source of the defaults; the system view
  comes from vssb (`Sandbox::system` + `resolved_mounts`).
- `src/detect.rs`: detectors that read the project's build files (Cargo)
  for directories to expose; `policy.rs` decides what is mounted.
- `src/audit.rs` (JSON-lines log, fed by `vssb::proxy` events too),
  `src/check.rs` (`vssb::probe`), `src/util.rs`.
- `examples/`: policy files, and `wayland-context.rs`, the prototype of
  gui.md's Wayland decision gate (run it against a headless compositor
  only).

## Invariants

- vssr is a general-purpose sandbox. It knows nothing about particular
  agents or harnesses; knowledge about one goes in a policy file
  (`examples/`, later built-in profiles), as data. Detectors key on the
  project's contents (build tools), never on the command.
- Detected rules only add binds under `detect.within` (ro),
  `detect.within_rw` (rw) or inside the working directory's git
  repository (`detect.project`, never its root or `.git`, never a
  repository at or above `$HOME`). They never override an explicit
  entry and never reach under a `deny`: build files are repository
  content the sandboxed program may have edited.
- Symlinks are resolved in `policy.rs`, before vssb sees a path: a host
  symlink exposed at its own place becomes a `Symlink` entry, and no
  symlink is followed under a writable directory (`Plan::writable`).
  Symlinks are judged by their canonical location (`util::resolve_guarded`),
  never by how a path is spelt.
- Bind and socket sources reach vssb canonical and marked `no_symlinks`,
  so a symlink planted after the check is an error, not a new destination.
  A socket entry always mounts the socket itself, never a symlink to it.
- The audit log is opened without following a symlink the sandbox could
  have planted (`resolve_guarded` on its directory, then `openat2` and
  `O_NOFOLLOW`), and only as a regular file. Missing directories on the
  way are made with `mkdirat` from the pinned parent, never by path.
  `--audit-fd` takes a descriptor the caller passed in instead, so no path
  is involved; vssr writes to a close-on-exec copy.
- `--pass-fd` hands the program copies of the caller's descriptors; the
  audit descriptor is never one of them (the program could forge events).
- vssr's own messages go through `Audit::say` (an event, and stderr unless
  quiet), never straight to stderr once the log is open.
- The forwarded signals are blocked before the sandbox or any proxy
  thread starts, so only the signalfd receives them.
- Sockets in the run directory are bound through a descriptor of the
  directory opened without following symlinks (`/proc/self/fd/N/bus` for
  the D-Bus filter's; vssb does the same for the Wayland one), never by a
  path from the host's environment.
- A run holds `flock` on its run directory until it ends; creating a run
  directory and sweeping unlocked (killed runs') ones happen under the
  lock of `$XDG_RUNTIME_DIR/vssr`, so a new directory is never swept.
- vssb's own invariants (fork safety of the child, mount-point lookup,
  seccomp last) are listed in its AGENTS.md.

## Testing

`cargo test`, then `tests/integration.sh` (end-to-end; needs network for
the proxy tests and a systemd user manager for the limit tests; the
Wayland tests need `VSSR_TEST_WAYLAND` naming a headless compositor, and
the script unsets `WAYLAND_DISPLAY` so nothing else reaches the live
session; the D-Bus tests start their own bus, and make only a read-only
call to the session bus). The D-Bus filter's own tests are vssd's. Add an
integration test for every new guarantee; guarantees of the sandbox
itself also get one in vssb's `tests/sandbox.rs`.

## Design notes

`docs/design/` holds proposals that aren't implemented yet; check there
before designing something new. `ergonomics.md`: project policies,
profiles, permission requests, isolated runs, harness integration (the
main note). `gui.md`: GUI applications (Wayland security contexts,
filtered D-Bus, audio, GPU). `embedding.md`: audit of embedding vssb
(in process) or vssr (as a helper binary) in another program, and the
gaps for game launchers.
