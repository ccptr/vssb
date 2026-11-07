# vssb: notes for agents

Embeddable rootless Linux sandbox: vssr's core as a library. See
README.md for the design and the guarantees towards the host program.

## Layout

- `src/config.rs`: the public description (`Sandbox`, `Mount`, `Command`,
  `Stdio`, `Limits`, `Cgroup`). Plain data, no syscalls.
- `src/prepare.rs`: resolves the mounts and builds `Prepared` (everything
  the child needs) and `Parent` (what the caller keeps). All allocation
  happens here.
- `src/spawn.rs`: `spawn` (clone, id maps, cgroup, deciding how each
  limit is enforced, go, status) and `Child`.
- `src/cpus.rs`: picks the CPUs for pinning (the cpus fallback).
- `src/child.rs`: init (PID 1) and the program's process.
- `src/mounts.rs`, `src/landlock.rs`: child-side filesystem view and
  Landlock (raw syscalls; the parent works out the rights).
- `src/seccomp.rs`: hand-assembled BPF. `src/report.rs`: fixed-size
  failure records from the child and their messages. `src/cgroup.rs`:
  systemd scope over D-Bus (`ossteam-dbus`, from the ossteam checkout
  next to this one; a blocking call, no subprocess). `src/proxy.rs`:
  filtering HTTP proxy.

## Invariants

- **The child is a fork of a multi-threaded process.** Everything that
  runs after `clone_pidfd` returns 0 (`child.rs`, `mounts.rs`,
  `landlock::apply`, `seccomp::install`, `sys.rs`) may only make raw
  syscalls or thin libc wrappers that take no locks. No allocation, no
  `format!`, no std I/O or `std::fs`, no panicking indexing, no libc
  `fork`, `signal` or `sigaction` (glibc's takes a lock). Prepare what it
  needs in `prepare.rs`, and report failures with a `Report`.
  `spawning_while_other_threads_hold_libc_locks` catches regressions of
  this kind.
- Init closes all other descriptors first thing. Keep anything the child
  needs in `Prepared::keep_fds`.
- No process-wide state in the library: no threads (except in `proxy`),
  no signal handlers, no re-exec, no `waitpid(-1)` in the parent. (The
  only static is `cpus.rs`'s rotation counter, which touches nothing of
  the host's.)
- Limits use systemd (or a given cgroup) where nothing else will do, and
  fall back where reasonably possible, each with a method setting and an
  `Enforcement` entry. Which features depend on systemd and which
  fallbacks they get is the user's decision (see the root AGENTS.md).
- Mount points, and bind sources (in the child, before `open_tree`), are
  opened with `openat2(RESOLVE_NO_SYMLINKS)`, a symlink as the final
  component is refused too, and vssb never creates entries (mount points
  or symlinks) inside a bind mount (that would write to the host).
- Descriptors vssb opens are kept off 0-2 (`prepare::above_stdio`), so a
  caller with stdio closed doesn't hand them to the program as stdio.
- In the program's process, seccomp is installed last, right before exec.
- seccomp jumps are 8-bit: keep the final ALLOW reachable, and keep
  `seccomp::tests` passing.
- The core knows nothing about particular programs. Front-end concerns
  (policy files, detection, audit format) belong in vssr.

## Testing

`cargo test`. Add an end-to-end test in `tests/sandbox.rs` for every new
guarantee. Tests run in parallel threads on purpose.
