# Design note: embedding vssb and vssr in another program

Status: audit, 2026-11-06, of the workspace at commit f636985. It
replaces the audit of 2026-11-05 (vssr at 038e9e7), written before vssb
existed, which found in-process use unworkable. Example host: a new
Steam-like game client that launches each game in a sandbox. GUI support
is covered in [gui.md](gui.md).

## Verdict

- **As a library inside the client process: workable.** That is what
  [vssb](../../../vssb) is for. It can be called from any thread of a
  multi-threaded host, takes over no process-wide state, and gives the
  host typed errors, a pidfd and per-run cleanup. What's missing for a
  general host is a C API (it is Rust only) and a policy layer above
  `Sandbox`, if the host wants vssr's policy files.
- **As a helper binary the client runs (`vssr run`): workable, with
  small changes.** Exit codes, signals, timeouts and the audit stream
  work. What's missing is in vssr's CLI, not in the sandbox: vssb can
  already pass descriptors and join a given cgroup, but vssr has no flags
  for them, and its plan and `check` output are for people only.
- **For games specifically: not ready.** The sandbox has no 32-bit
  syscalls, no GPU, no `/sys`, no display or audio sockets, no input
  devices and no filtered UDP, and container runtimes like the Steam
  Linux Runtime can't run inside it. `gui.md` covers part of this
  (Wayland, D-Bus, GPU, audio); none of it is implemented yet.
- **License: MPL-2.0.** A closed-source client can link vssb, statically
  or not. Changes to vssb's own files stay under the MPL.

## 1. In-process embedding (linking vssb)

What a host gets (details and the test for each in vssb's README):

- `Sandbox::spawn` from any thread, from many at once. The child of the
  fork-like `clone3` makes only raw syscalls, so locks held by other
  threads can't deadlock it.
- No threads (except the optional `proxy`), no signal handlers, no
  change to the process's signal mask, no re-execution of the host.
- The sandbox is a clone child without an exit signal: the host's
  `waitpid(-1)` can't reap it, and `Child::pidfd` fits a poll loop or an
  async runtime.
- It dies with the host process (init watches a control socket), not
  with the spawning thread, and dropping a `Child` kills and reaps it.
- Nothing is read from the host process: environment, working directory
  and paths are explicit.
- Init closes every descriptor except the ones passed with
  `Command::pass_fd`, so other threads' sockets don't leak in.
- Limits through a systemd user scope over D-Bus, or
  `Cgroup::Join(dir)` for a host that manages its own cgroups.
  `Child::freeze`, `signal`, `terminate(grace)`.
- `probe()` to test what the kernel supports before offering a
  sandboxed launch, and `Error` variants that tell setup failures,
  missing kernel support and exec failures apart.
- Startup: about 4.5 ms from `vssr run` to exit for `true` (release
  build, Linux 7.2), about 10 ms with a systemd scope for limits, and
  about 5 ms with the proxy.

Gaps for a host:

| Gap | Where | Why it matters |
|---|---|---|
| Rust only: no C ABI, no `cdylib` | `vssb/src/lib.rs` | A C or C++ client needs a small FFI crate (opaque `Sandbox`, `Command` and `Child` handles, the pidfd, errors as codes and strings). |
| Limits run `busctl` as an ordinary child | `vssb/src/cgroup.rs:80` | `std::process` waits for that pid alone, so a host that reaps with `waitpid(-1)` can take its status first. With `strict` (the default) the spawn then fails; without it, the game runs without limits. `Cgroup::Join` avoids it; a D-Bus call without a subprocess would fix it. |
| No policy layer in the library | `vssr/src/policy.rs` | vssr's `Policy` → `Plan` lives in the binary crate and reads `$HOME` and the working directory itself (`policy.rs:327`). A host that wants vssr's policy files would need it split out with explicit inputs. A host with its own configuration builds a `Sandbox` directly and needs none of it. |
| AppArmor on Ubuntu 24.04+ | vssb README | Unprivileged user namespaces need a profile for the binary that creates them, so in-process use puts the whole client under that profile. A helper binary keeps the profile small. |
| Forking without exec during a spawn | vssb README | The forked copy keeps the control socket open, so `spawn` waits until it exits or execs (`std::process` has the same property). |

## 2. Subprocess embedding (the client runs `vssr run …`)

What already works:

- Standard input, output and error pass through. The exit status is the
  program's own, or 128+N for signal N, or 124 (timeout), 125 (setup),
  126 or 127 (exec) for vssr's own failures.
- When the client sends SIGTERM, INT, HUP, QUIT, USR1 or USR2 to vssr,
  it reaches the game. If vssr is killed,
  the sandbox dies with it. The timeout sends SIGTERM, waits
  `kill_grace`, then sends SIGKILL.
- `VSSR_ID` chooses the sandbox id, which ties audit events to the
  client's own launch id.
- `--audit-log /proc/self/fd/3` streams JSON-lines events to a pipe the
  client holds: `setup_failed`, `start` (with the host pid), `net`,
  `net_close`, `signal`, `timeout`, `exit`. `start` is written once the
  program has been exec'd, so it serves as a ready event; a setup
  failure writes `setup_failed` instead, so it can't be mistaken for a
  game that exits with 125.
- Several sandboxes can run at once, each in its own namespaces.

Gaps, roughly by importance:

1. **No way to pass file descriptors in.** vssb has
   `Command::pass_fd`, vssr has no flag. A client usually wants to hand
   the game a pre-connected IPC socket. Suggestion: `--pass-fd N[:M]`.
   That is cleaner than exposing sockets by path, and it doesn't
   conflict with the Landlock rule against connecting to sockets.
2. **No machine-readable plan or check.** `--dry-run` and `vssr check`
   print text meant for people, and `Plan` doesn't derive `Serialize`.
   Suggestion: `--json` on both (`check` maps onto `vssb::probe`).
3. **No way to join the client's cgroup.** vssb has `Cgroup::Join`,
   vssr always uses a systemd user scope. Suggestion: `--cgroup PATH`
   (it also avoids the `busctl` subprocess).
4. **stderr noise.** "vssr: blocked …", detection notes and warnings are
   mixed into the game's stderr. `audit.quiet` silences only the
   blocked-request lines. Suggestion: a flag that sends all of vssr's
   messages to the event stream.
5. **Policy only from a file or flags.** `-p /proc/self/fd/N` works but
   isn't documented. Document it or add `--policy-fd`.
6. **Defaults meant for an agent in a project.** The default policy
   runs the `cargo` detector on the working directory and refuses a
   working directory that contains `$HOME`. Game policies should set
   `detect.enable = []`, and the client should always pass `-p`.

## 3. Fit for games (what blocks a Steam-like client)

These are properties of the sandbox, so they apply to both routes.

| Need | Today | Where | Notes |
|---|---|---|---|
| 32-bit programs (old games, 32-bit Wine/Proton parts, 32-bit helpers) | **Killed**: any syscall not from the native architecture returns `KILL_PROCESS` | `vssb/src/seccomp.rs:206-208` | Not configurable. A fix needs a second branch with the i386 syscall numbers (they differ from x86_64), within the 8-bit jump limit. |
| Wine/Proton running 16/32-bit code | `modify_ldt` denied | `vssb/src/seccomp.rs:73` | Can be allowed (`Sandbox::seccomp_allow`, or `seccomp.allow` in a vssr policy). |
| Steam Linux Runtime / pressure-vessel (bubblewrap) | Nested user namespaces and the whole mount family are denied | `vssb/src/seccomp.rs:65-66`, `:228-229` | Allowing them removes much of what seccomp adds. Running the runtime's containers would mean vssb becomes the container runtime, or the runtime sandboxes and vssb doesn't. |
| GPU (Mesa, Vulkan, NVIDIA) | `/dev` holds only null, zero, full, random, urandom, tty, a private devpts and `/dev/shm`; `/sys` isn't mounted | `vssb/src/mounts.rs:181`, `vssb/src/config.rs:231-235` | gui.md plans render nodes (`gpu = true`). Vulkan and Mesa also need parts of `/sys` (`/sys/dev/char`, `/sys/class/drm`, PCI ids), which no note covers yet. |
| Wayland / X11 / audio | `/run`, `/tmp` and `/var/tmp` are fresh tmpfs, so there are no `XDG_RUNTIME_DIR` sockets and no `/tmp/.X11-unix`. Binding a socket read-only doesn't help, since Landlock ABI 9 blocks connecting to it | `vssb/src/prepare.rs:165`, `vssb/src/landlock.rs:59` | Planned in gui.md (security-context Wayland, private Xwayland, `fs.sockets`, PipeWire). Games add a latency need: fullscreen and direct scan-out through the compositor. |
| Controllers and hotplug | No `/dev/input`, `/dev/hidraw*`, `/dev/uinput`. Netlink is limited to ROUTE and SOCK_DIAG, so udev monitors (`NETLINK_KOBJECT_UEVENT`) are refused | `vssb/src/seccomp.rs:251-265`, `vssb/src/mounts.rs:181` | `uinput` is input injection (an escape, like a Wayland virtual keyboard). The client should own the devices and hand the game per-device fds, which `pass_fd` now allows. |
| Multiplayer networking (UDP, arbitrary ports) | `Net::None` (loopback plus listeners such as the HTTP(S) proxy) or `Net::Host` (unfiltered UDP; Landlock filters TCP ports only) | `vssb/src/config.rs:110-118`, `vssb/src/proxy.rs` | No filtered middle ground. Options: a userspace UDP relay on a listener, like the proxy, or a veth with nftables (needs privileges). |
| Client ↔ game IPC (Steamworks-style) | Private `/dev/shm`. Abstract unix sockets and signals are scoped by Landlock and by the separate network namespace | `vssb/src/landlock.rs:36-37`, `vssb/src/config.rs:23-25` | Design it as an fd passed in (`pass_fd`) rather than shared memory or a well-known socket. |
| Crash reports (breakpad, crashpad) | `ptrace` denied | `vssb/src/seccomp.rs:62` | Can be allowed; better done from outside, by the client. |
| Kernel-level anti-cheat | Not possible in any user-namespace sandbox | n/a | Treat as unsupported. |
| Platform | Linux 6.x with unprivileged user namespaces; x86_64 or aarch64 | vssb README | Ubuntu 24.04+ needs an AppArmor profile (see section 1). Not verified here: whether SteamOS kernels enable Landlock (with `strict`, the default, vssb refuses to run without it). |

Things that already fit a game launcher well: a read-only install
directory, read-write save and prefix directories, a tmpfs home, memory,
CPU and pid limits, the timeout, cleanup that kills everything the game
left behind, freezing a paused game, and the audit trail.

## 4. Suggested order of work

1. **Integration contract for `vssr run`** (small; useful to every
   embedder, not only games): `--pass-fd`, `--cgroup`, `--json` for
   `check` and `--dry-run`, a flag that sends all of vssr's messages to
   the event stream, and documenting `-p /proc/self/fd/N` and `start` as
   the ready event. One integration test per guarantee, as AGENTS.md
   asks.
2. **Limits without a subprocess**: create the scope over D-Bus from
   vssb itself instead of running `busctl`, so a host's `waitpid(-1)`
   can't interfere.
3. **A C API** (`vssb-ffi`), if a client not written in Rust is meant
   to link it.
4. **Split `Policy` → `Plan` into a library**, with explicit inputs
   (cwd, home, uid/gid, environment), only if hosts want vssr's policy
   format.
5. **GUI layer from gui.md** (its own order of work), plus a read-only
   `/sys` subset next to `gpu`.
6. **Game-specific items**: an i386 branch in the seccomp filter,
   opt-in uevent netlink, per-device fds from the client, and a UDP
   policy.

This audit comes from reading the code; only the startup times were
measured.
