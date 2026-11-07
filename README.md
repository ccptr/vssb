# vss

Rootless Linux sandboxing for running AI agents, builds and other
untrusted programs unattended: namespaces, Landlock, seccomp and cgroup
limits, with no root, no daemon and no setuid helper.

This workspace holds two crates:

- [**vssr**](vssr): the command-line sandbox. Policy files (TOML), a
  filtering HTTP(S) proxy with allow-listed hosts, detection of the
  project's build dependencies, and a JSON-lines audit log.
- [**vssb**](vssb): the sandbox itself as a library, for embedding in
  another program (a game launcher, an agent harness, a build tool). It is
  safe to start from any thread and leaves no process-wide state behind.
  vssr is built on it.

```sh
cd ~/p/some-repo
vssr run -- make test                                  # cwd writable, no network
vssr run --allow api.anthropic.com --allow '*.github.com' -- ./agent.sh
vssr check                                             # what the kernel supports
```

```rust
use vssb::{Command, Mount, Sandbox};

let mut sb = Sandbox::new();
sb.system(true).mount(Mount::ro("/srv/data"));
let mut cmd = Command::new("/usr/bin/ls");
cmd.args(["/srv/data"]);
let status = sb.spawn(cmd)?.wait()?;
```

Each crate's README covers its design, guarantees and security notes in
full.

## Conveniences in vssr

- **Works without a policy file.** The built-in policy makes the current
  directory writable, replaces `~` with an empty tmpfs, gives a read-only
  system view and no network. `vssr policy` prints it with comments, as a
  starting point for your own.
- **Detects build dependencies.** At start, vssr reads the project's
  `Cargo.toml` files and finds the directories the build will read outside
  the working directory: path dependencies (transitive ones too),
  `[patch]` and `[replace]` paths, workspace members and the workspace
  roots of dependencies. Ones elsewhere in the same git repository are
  exposed read-only on their own. Ones outside it are exposed only under
  directories you list (`--detect-within ~/p`). Anything left out is
  reported along with the option that would allow it. Run from a workspace
  member, vssr says to run from the workspace root instead, since cargo
  writes `Cargo.lock` and `target/` there.
- **Shows its work.** `--dry-run` prints the resolved plan, with the
  reason for each detected mount. `vssr check` adds what the kernel
  supports. Both take `--json`.
- **Proxy settings that clients pick up.** With `--allow HOST`, the
  sandbox gets `HTTP(S)_PROXY`, `ALL_PROXY`, `NO_PROXY` and
  `NODE_USE_ENV_PROXY=1`. curl, git, pip, npm, cargo, Python `requests`
  and Node's `fetch` then go through the filtering proxy with no setup.
  Patterns like `*.github.com` and `host:port` work.
- **Paths as you'd write them.** `~`, `$VAR` and `$PWD` are expanded.
  `SRC:DEST` mounts a path elsewhere, and a `?` prefix makes it optional.
  Entries nest in any combination: a read-only `.git` or a hidden `.env`
  inside a writable checkout. Host symlinks such as `/bin -> usr/bin` are
  recreated as symlinks.
- **Behaves like the command.** The exit status is the program's own (or
  128+N for signal N), with the shell's 124–127 for timeout, setup
  failure, not executable and not found. Signals are passed on, `--tty`
  keeps the terminal for interactive tools, and `--timeout` sends
  SIGTERM, then SIGKILL after a grace period. Startup takes about 10 ms.
- **Easy to drive from another program.** `--audit-fd` streams JSON
  events (a `start` event once the program runs, then connections,
  signals and `exit`) to a descriptor you pass in. `-p /proc/self/fd/N`
  reads the policy from a pipe, `--pass-fd` hands the program a
  descriptor such as a pre-connected socket, and `--cgroup` uses a cgroup
  you prepared.

## Requirements

- Linux 6.x on x86_64 or aarch64, with unprivileged user namespaces
  (Ubuntu 24.04+ restricts them through AppArmor and needs a profile).
- For a memory limit: a systemd user manager, or a cgroup v2 directory you
  can write to. CPU and process limits fall back to CPU pinning and the
  PID namespace's size without one.

## Building

vssb depends on `ossteam-dbus` from the ossteam repository, which must be
checked out next to this one (`../ossteam`). Then, from this directory:

```sh
cargo build --release      # the binary is target/release/vssr
```

## Tests

```sh
cargo test                 # every crate: unit tests and vssb's end-to-end tests
vssr/tests/integration.sh  # vssr end to end
```

The integration script runs `target/debug/vssr` (or the binary given as
its argument), so build first. It needs network access for the proxy tests
(`VSSR_TEST_OFFLINE=1` skips them). Tests of limits through a systemd
scope are skipped without a systemd user manager.

## Documentation

- [`vssr/README.md`](vssr/README.md): the command line, policy files,
  audit events and security notes.
- [`vssb/README.md`](vssb/README.md): the library API and what makes it
  embeddable.
- [`vssr/docs/design/`](vssr/docs/design): proposals not implemented yet
  (ergonomics, GUI applications, embedding).
- [`docs/audits/`](docs/audits): security audits of the workspace.

## License

Mozilla Public License 2.0 ([`LICENSE`](LICENSE)). vssb links
`ossteam-dbus`, which is LGPL-2.1-or-later for now; see vssb's README for
what that means for static linking.
