# vssb

The sandbox core of [vssr](../vssr) as a library you can embed: run a
program in a rootless Linux sandbox (namespaces, Landlock, seccomp, cgroup
limits) from inside another program, such as a game launcher, an agent
harness or a build tool. It needs no root, no daemon and no helper binary.
Its only dependency is `libc`.

```rust
use vssb::{Command, Limits, Mount, Sandbox, Stdio};

let mut sb = Sandbox::new();
sb.system(true)                                  // ro /usr, /etc…; fresh /tmp, /proc, /dev
  .mount(Mount::ro("/srv/game"))
  .mount(Mount::rw("/home/me/.local/share/game/saves"))
  .limits(Limits { memory: Some(4 << 30), ..Default::default() });

let mut cmd = Command::new("/srv/game/bin/game");
cmd.cwd("/srv/game").env("PATH", "/usr/bin:/bin").stdout(Stdio::Piped);
let mut child = sb.spawn(cmd)?;                  // returns once the program is exec'd
let status = child.wait()?;
```

`examples/run.rs` is a small command-line front end to try it:
`cargo run --example run -- --ro /data -- ls /data`.

## What a sandbox enforces

The same layers as vssr:

| Layer | Mechanism | What it does |
|---|---|---|
| Filesystem view | mount namespace, new root on tmpfs | Only listed paths exist: read-only, writable, an empty tmpfs or hidden. `/proc`, `/dev` and `/tmp` are fresh. |
| Filesystem rights | Landlock (ABI 1–9) | A second, independent check of the read/write/exec split. With ABI 9+, host unix sockets exposed read-only can't be connected to. |
| Processes | PID, IPC, UTS, cgroup namespaces | The program sees only its own processes; everything it started is killed when it exits. |
| Network | network namespace | `Net::None`: loopback only, plus listeners handed to the host (for the filtering `proxy`). `Net::Host`: the host network, optionally limited to TCP ports by Landlock. |
| Syscalls | seccomp BPF | No nested namespaces, mount, ptrace, bpf, io_uring, perf, keyrings, kernel modules, raw sockets or TIOCSTI. |
| Privileges | no_new_privs, empty capability sets | setuid binaries don't escalate; even uid 0 inside has no capabilities. |
| Resources | cgroup v2, rlimits | Memory, CPU and pids through a systemd user scope or a cgroup you give it. Open files, file size and the rest through rlimits. |

## What makes it embeddable

vssr is a CLI, so it could take over its process. A library can't. These
are the guarantees towards the host, each with an integration test in
`tests/sandbox.rs`:

- **Spawn from any thread, from many at once.** The sandbox starts with a
  fork-like `clone3`. A fork of a multi-threaded process inherits any
  lock another thread held at that moment, so the child code makes only
  raw syscalls, with no allocation, no locks and no libc `fork` or
  `sigaction`. The parent prepares everything it needs (strings, pointer
  arrays, the BPF program, Landlock rights, descriptors) before clone.
  Failures come back as fixed-size records that the parent turns into an
  `Error`.
- **No process-wide state.** No threads, no signal handlers, no changes
  to the host's signal mask (it blocks signals on the calling thread only
  for the moment of clone), and no re-execution of the host. Limits come
  from asking the systemd user manager over D-Bus (`busctl`) to move the
  waiting child into a new scope, rather than re-running the host under
  `systemd-run`.
- **Your `waitpid(-1)` can't steal it.** The sandbox is a "clone child"
  (no exit signal): it sends no SIGCHLD and only `__WALL` waits see it.
  `Child` waits on its pidfd, which can also go into your poll loop or
  async runtime (`Child::pidfd`).
- **It dies with your process, not with a thread.** Init holds one end of
  a control socket. When your process (or the `Child`) goes away, init
  kills everything in the sandbox. `PR_SET_PDEATHSIG` would fire when the
  spawning *thread* exits, so it isn't used.
- **No leaked descriptors.** Init closes every descriptor except its own
  as its first step, so other threads' sockets and pipes don't stay open
  in it. The program gets stdio and the descriptors you pass
  (`Command::pass_fd`), nothing else.
- **Explicit inputs.** Nothing is read from the host process: no
  environment (the program's environment starts empty), no current
  directory, no `$HOME`. Paths must be absolute.

## API in brief

- `Sandbox`: a reusable description.
  - `system(true)` adds the usual system view.
  - `mount(Mount::ro/rw/ro_at/rw_at/tmpfs/deny/symlink/proc/dev)`, with
    `.noexec()`, `.optional()` and `.size()`. When two entries share a
    destination, the later one wins.
  - Network: `net(Net::None | Net::Host)`, `listen_tcp(port)`,
    `tcp_connect(ports)`, `tcp_bind(ports)`.
  - Syscalls: `seccomp_allow(name)`, `seccomp_deny(name)`.
  - Resources: `rlimit(Resource, n)`, `limits(Limits)`,
    `cgroup(Cgroup::Auto | Inherit | SystemdUserScope | Join(dir))`.
  - Ids and the rest: `uid`, `gid`, `hostname`, `strict`.
  - `resolved_mounts()` shows the final view.
- `Command`: one program.
  - `args`, `env` (explicit), `cwd`.
  - `stdin`/`stdout`/`stderr(Stdio::Inherit | Null | Piped | Fd(fd))`,
    `pass_fd(target, fd)`.
  - `keep_session(true)` for interactive use: the program keeps the
    caller's terminal.
  - `id(name)` names the systemd scope.
- `Child`:
  - Waiting: `wait`, `try_wait`, `wait_timeout`, `pidfd`.
  - Stopping: `signal` (forwarded to the program by init), `kill` (the
    whole sandbox), `terminate(grace)` (SIGTERM, then SIGKILL).
  - `freeze(bool)` uses the cgroup freezer.
  - `take_listeners`, `cgroup`, and the `stdin`/`stdout`/`stderr` pipes.
  - Dropping a `Child` kills and reaps the sandbox.
- `ExitStatus`: the program's own status, which init reports. If the
  sandbox was killed, it's the signal that killed it.
- `Error`: `Config`, `Unsupported` (the kernel lacks something strict mode
  needs), `Io`, `Setup` (a step inside the sandbox failed, with the path
  involved), `Exec`. `shell_code()` gives 125/126/127.
- `probe()`: user namespaces, Landlock ABI, seccomp, systemd user manager.
- `seccomp::Filter`: the filter on its own, to inspect it.
- `proxy` (feature, on by default): the filtering HTTP(S) proxy, served
  on a listener from `listen_tcp`. It reports allow, deny and close events
  through a callback and stops cleanly. It is the only part that starts
  threads.

## Not here (they are in vssr)

Policy files, path expansion (`~`, `$PWD`), Cargo dependency detection, the
audit log format and the CLI are front-end concerns, and live in
[vssr](../vssr), which is built on this crate: it maps its `Plan` onto
`Sandbox` + `Command`, and serves `proxy::serve` with a callback that
writes the events to its audit log.

## Requirements and limits

- Linux 6.x (`clone3`, `open_tree`/`move_mount`/`mount_setattr`,
  `openat2`, pidfds, Landlock), x86_64 or aarch64.
- Unprivileged user namespaces. Ubuntu 24.04+ restricts them through
  AppArmor and needs a profile for the host binary.
- For `Limits`: a systemd user manager and `busctl`, or a cgroup v2
  directory you can write to (`Cgroup::Join`).
- `Child::signal` forwards SIGHUP, INT, QUIT, USR1, USR2, ALRM, TERM, CONT,
  TSTP and WINCH. Pausing the whole sandbox needs `freeze`.
- If your process forks without exec while a spawn is in flight, the
  forked copy keeps the control socket open, so `spawn` waits until that
  copy exits or execs. `std::process` has the same property.
- The security notes in vssr's README apply unchanged: writable
  directories are an exit, the proxy filters by name, the kernel is shared.

## Tests

```sh
cargo test     # unit tests, plus end-to-end tests of every guarantee above
```

The end-to-end tests need `sh`, `bash`, `python3` and `curl` on the host,
and run sandboxes on many threads at once. The limit and freeze tests are
skipped without a systemd user manager. They don't need internet access.
