# Design note: embedding vssr

Status: audit, 2026-11-05, at commit 038e9e7. Example host: a new
Steam-like game client that launches each game in a vssr sandbox. GUI
support is covered in [gui.md](gui.md).

Update, 2026-11-06: the in-process route (section 1) now exists as
[vssb](../../../vssb), and vssr is rebuilt on it. That removed every
blocker in section 1's table: there's no `systemd-run` re-exec, no
leaked threads, no `PDEATHSIG`, the timeout ends with the run, and a
`setup_failed` audit event closes gap 2 of section 2 in part (there's no
`ready` event yet). File and line references below are to the code as it
was audited.

## Verdict

- **As a library inside the client process: not workable, by design.**
  vssr takes over process-wide state (it forks with a raw `clone`,
  changes the signal mask, starts threads that never end, re-executes
  itself), and it can only be called safely from a single-threaded
  process. A game client is heavily multi-threaded.
- **As a helper binary the client runs: workable, with small changes.**
  vssr is one binary with documented exit codes. It forwards signals,
  supports timeouts, and kills the sandbox if it dies. It writes an
  audit log in JSON lines, and the caller can choose the sandbox id.
  What's missing is a machine-readable way to configure it and get
  status back, and a way to hand it file descriptors.
- **For games specifically: not ready.** The sandbox has no 32-bit
  syscalls, no GPU, no `/sys`, no display or audio sockets, no input
  devices and no filtered UDP. Container runtimes like the Steam Linux
  Runtime can't run inside it either. `docs/design/gui.md` covers part
  of this (Wayland, D-Bus, GPU, audio), but none of it is implemented
  yet.
- **There is no license.** The repository has no LICENSE file and
  `Cargo.toml` has no `license` field, so nobody else can legally embed
  it yet.

## 1. In-process embedding (linking vssr as a library)

| Blocker | Where | Why it matters to a host |
|---|---|---|
| No library target; the run logic lives in `main.rs` and all modules are private | `src/main.rs` | Nothing to link against. |
| `clone` without `CLONE_VM` (works like `fork`), then Rust code with allocation, `anyhow` and `std::fs` in the child | `src/main.rs:345`, `src/mounts.rs` | In a multi-threaded host, a lock (for example malloc's) held by another thread at fork time stays locked in the child, so the child can deadlock. The AGENTS.md invariant ("single-threaded when it calls `clone`") rules this out. |
| Resource limits re-run the **whole process** under `systemd-run` with `current_exe()` and the original `argv` | `src/main.rs:284-286` | The host process would be replaced. |
| Blocks SIGTERM/INT/HUP/QUIT/USR1/USR2 on the calling thread and runs a `sigwait` thread that loops forever | `src/main.rs:325`, `:393` | Takes the host's signals, and each run leaks a thread. |
| The timeout thread sleeps for the full timeout even when the program has already exited | `src/main.rs:408` | Later it prints "timeout" and writes a timeout event for a run that has already finished. One thread leaks per run. |
| The proxy's accept loop never ends | `src/proxy.rs:183` | Each run leaks a thread and a listening socket (which keeps the sandbox's network namespace alive). |
| `PR_SET_PDEATHSIG` is set in the child | `src/child.rs:51` | This fires when the **thread** that cloned it exits, not the process. Called from a worker thread, the sandbox dies when that thread ends. |
| `waitpid(pid)` on its own child | `src/main.rs` (supervise) | A host that reaps with `waitpid(-1)` (GLib child watches, many launchers) can take the exit status first. |
| Inputs come from the process: `current_dir`, `$HOME`, `getuid`, and the process environment for `env.pass` | `src/main.rs:157`, `src/policy.rs:348`, `:716` | A host can't build a plan for another directory or environment without changing its own. |
| Output goes through `eprintln!`/`println!`; errors are `anyhow` strings plus `i32` codes | various | No typed errors, no callbacks. |

Parts that could be reused: `Policy` and its sections are plain `pub`
structs with `Default`, so they can be built in code. `Plan` is plain
data. `seccomp::build` and `proxy::NetPolicy` are pure functions.
Splitting these into a library is cheap. Doing the same for the
executor isn't, and shouldn't be done: keep execution in a separate
process.

## 2. Subprocess embedding (the client runs `vssr run …`)

What already works:

- Standard input, output and error are passed through. The exit status
  is the program's own, or 128+N for signal N, or 124–127 for vssr's own
  failures.
- When the client sends SIGTERM to vssr, it reaches the game. If vssr is
  killed, `PDEATHSIG` takes the sandbox down. Signals go through a
  pidfd, so a reused pid can never be hit. The timeout sends SIGTERM,
  waits a grace period, then sends SIGKILL.
- The caller can set `VSSR_ID` to choose the sandbox id
  (`src/main.rs`, `run`), which ties audit events to the client's own
  launch id.
- `--audit-log` takes any path, so `--audit-log /proc/self/fd/3` streams
  events to a pipe the client holds (`start` with the host pid, `net`,
  `signal`, `timeout`, `exit`).
- Startup takes about 10 ms. Several sandboxes can run at once, each in
  its own namespaces (the proxy port is per network namespace).

Gaps, roughly by importance:

1. **No way to pass file descriptors in.** PID 1 closes everything above
   the control socket (`src/child.rs`, `setup`), and the agent marks
   every fd ≥ 3 close-on-exec. A client usually wants to hand the game
   a pre-connected IPC socket. Suggestion: `--pass-fd N[:M]`. That is
   cleaner than exposing sockets by path, and it doesn't conflict with
   the Landlock rule against connecting to sockets.
2. **A setup failure looks like a normal exit.** Setup failures exit
   with 125 and write no audit event (`start_child` returns early), so a
   game that exits with 125 itself can't be told apart. Suggestion: a
   `setup_failed` event with the reason, and a `ready` event once the
   program has been exec'd.
3. **No machine-readable plan or check.** `--dry-run` and `vssr check`
   print text meant for people. `Plan` doesn't derive `Serialize`.
   Suggestion: `--json` on both, so the client can test what the kernel
   supports (user namespaces, Landlock ABI, systemd) before it offers a
   sandboxed launch.
4. **Policy only from a file or flags.** It works with
   `-p /proc/self/fd/N`, but it should be documented, or
   `--policy-fd` added.
5. **stderr noise.** "vssr: blocked …", detection notes and warnings
   are mixed into the game's stderr. `audit.quiet` silences only the
   blocked-request lines. Suggestion: a flag that sends all of vssr's
   messages to the event fd.
6. **cgroups go only through `systemd-run`.** A client that manages its
   own cgroups (a delegated subtree) or wants its own scope names can't
   plug in. Suggestion: `--cgroup PATH`, to join a cgroup the caller
   already prepared.
7. **Defaults meant for an agent in a project.** The default policy
   runs the `cargo` detector on the working directory and refuses a
   working directory that contains `$HOME`. Game policies should set
   `detect.enable = []`; the client should always pass `-p`.

## 3. Fit for games (what blocks a Steam-like client)

| Need | Today | Where | Notes |
|---|---|---|---|
| 32-bit programs (old games, 32-bit Wine/Proton parts, 32-bit helpers) | **Killed**: any syscall not from the native architecture returns `KILL_PROCESS` | `src/seccomp.rs:197-200` | Not configurable. A fix needs a second branch with the i386 syscall numbers (they differ from x86_64). |
| Wine/Proton running 16/32-bit code | `modify_ldt` denied | `src/seccomp.rs:71` | Can already be allowed with `seccomp.allow = ["modify_ldt"]`. |
| Steam Linux Runtime / pressure-vessel (bubblewrap) | Nested user namespaces and the whole mount family are denied | `src/seccomp.rs:63`, `:220-221` | Allowing them removes much of what seccomp adds. Running the runtime's containers would mean vssr becomes the container runtime, or the runtime sandboxes and vssr doesn't. |
| GPU (Mesa, Vulkan, NVIDIA) | `/dev` holds only null, zero, full, random, urandom and tty; `/sys` isn't mounted at all | `src/mounts.rs:202`, `src/policy.rs` `system_mounts` | gui.md plans render nodes (`gpu = true`). Vulkan and Mesa also need parts of `/sys` (`/sys/dev/char`, `/sys/class/drm`, PCI ids), which no note covers yet. |
| Wayland / X11 / audio | `/run` and `/tmp` are fresh tmpfs, so there's no `XDG_RUNTIME_DIR` sockets and no `/tmp/.X11-unix`. Binding a socket read-only doesn't help, since Landlock ABI 9 blocks connecting to it | `src/policy.rs:706`, `src/lsm.rs` | Planned in gui.md (security-context Wayland, private Xwayland, `fs.sockets`, PipeWire). Games add a latency need: fullscreen and direct scan-out through the compositor. |
| Controllers and hotplug | No `/dev/input`, `/dev/hidraw*`, `/dev/uinput`. Netlink is limited to ROUTE and SOCK_DIAG, so udev monitors (`NETLINK_KOBJECT_UEVENT`) get `EPROTONOSUPPORT` | `src/seccomp.rs:256`, `src/mounts.rs:202` | `uinput` is input injection (an escape, like a Wayland virtual keyboard). The client should own the devices and hand the game per-device fds (see gap 1 in section 2). |
| Multiplayer networking (UDP, arbitrary ports) | Proxy mode carries only HTTP(S) and CONNECT. The only choices are `host` (unfiltered UDP; Landlock filters TCP ports only) or `none` | `src/proxy.rs`, `src/lsm.rs` | No filtered middle ground. Options: a userspace UDP relay in the supervisor (like the proxy), or a veth with nftables (needs privileges). |
| Client ↔ game IPC (Steamworks-style) | Private `/dev/shm`. Abstract unix sockets and signals are scoped by Landlock and by the separate network namespace | `src/lsm.rs:39`, `src/mounts.rs` (`build_dev`) | A new client controls its own IPC, so design it as an fd passed in (gap 1) rather than shared memory or a well-known socket. |
| Crash reports (breakpad, crashpad) | `ptrace` denied | `src/seccomp.rs:60` | Can be allowed per policy; better done from outside, by the client. |
| Kernel-level anti-cheat | Not possible in any user-namespace sandbox | n/a | Treat as unsupported. |
| Platform | Linux 6.x with unprivileged user namespaces; x86_64 or aarch64 | README | On Ubuntu 24.04+, vssr needs its own AppArmor profile, as Steam has for its bubblewrap. Not verified here: whether SteamOS kernels enable Landlock (with `strict = true`, vssr refuses to run without it). |

Things that already fit a game launcher well: a read-only install
directory, read-write save and prefix directories, a tmpfs home, memory,
CPU and pid limits, the timeout, cleanup that kills everything the game
left behind, and the audit trail.

## 4. Suggested order of work

1. **License**, if anyone else is meant to embed it.
2. **Integration contract for subprocess use** (small; useful to every
   embedder, not only games): `--pass-fd`, `ready` and `setup_failed`
   events, `--json` for `check` and `--dry-run`, `--policy-fd`, a flag
   that sends all of vssr's messages to the event stream. One
   integration test per guarantee, as AGENTS.md asks.
3. **Split out a library crate** for `Policy` → `Plan`, with explicit
   inputs (cwd, home, uid/gid, environment) instead of reading the
   process. Keep `clone` and everything after it in the binary.
4. **GUI layer from gui.md** (its own order of work), plus a read-only
   `/sys` subset next to `gpu`.
5. **Game-specific items**: an i386 branch in the seccomp filter,
   opt-in uevent netlink, per-device fds from the client, and a UDP
   policy.
6. Fix the thread and fd leaks in section 1 only if in-process use ever
   becomes a goal. They're harmless in the CLI, since the process exits.

This audit comes from reading the code and design notes; nothing was
compiled or run for it.
