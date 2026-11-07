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
