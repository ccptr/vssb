# vssr

A general-purpose Linux sandbox for running AI agents, builds or any
other untrusted program unattended, with fine-grained control over what
they can see, change, reach and spend. It knows nothing about any
particular agent or harness: anything that runs as a command runs in it,
and agent-specific setup lives in policy files. One binary, no root, no
daemon, about 10 ms of startup overhead.

```sh
cd ~/p/some-repo
vssr run -- make test                                  # cwd writable, no network
vssr run --allow api.anthropic.com --allow '*.github.com' -- ./agent.sh
vssr run -p examples/claude-code.toml -- claude -p "fix the failing tests" --dangerously-skip-permissions
```

## What the sandbox enforces

| Layer | Mechanism | What it does |
|---|---|---|
| Filesystem view | mount namespace, new root on tmpfs | Only paths the policy lists exist. Each is read-only, read-write, an empty tmpfs or hidden. `/proc`, `/dev` and `/tmp` are fresh and private. |
| Filesystem rights | Landlock (ABI 1–9) | A second, independent check of the same read/write/exec split. With ABI 9+, host unix sockets exposed read-only (say, a `--ro /run/user/1000` that includes the systemd or docker socket) can't be connected to. |
| Processes | PID, IPC, UTS, cgroup namespaces | The agent sees only its own processes; everything it started is killed when it exits, and the whole sandbox dies if vssr dies. |
| Network | network namespace + filtering proxy | `none`: loopback only. `proxy`: HTTP(S) only to allow-listed hosts and ports, via a proxy running outside the sandbox, with private/LAN addresses blocked. `host`: the host network, optionally limited to TCP ports by Landlock. |
| Syscalls | seccomp BPF | No nested namespaces, mount, ptrace, bpf, io_uring, perf, keyrings, kernel modules, raw/packet sockets or terminal injection (TIOCSTI). |
| Privileges | no_new_privs, empty capability sets | setuid binaries don't escalate; even uid 0 inside has no capabilities. |
| Resources | cgroup v2 via a systemd user scope, rlimits | Memory, CPU, process count, open files, file size; wall-clock timeout with SIGTERM then SIGKILL. |
| Audit | JSON lines | Start (or why setup failed), every allowed/denied connection with byte counts, signals, timeout, exit. |

Run `vssr check` to see what your kernel supports and how a policy
resolves.

## Requirements

- Linux 6.x (uses `open_tree`/`move_mount`/`mount_setattr`, `openat2`,
  Landlock). Tested on 7.2 with Landlock ABI 10.
- Unprivileged user namespaces enabled (the default on most distributions;
  Ubuntu 24.04+ restricts them through AppArmor and needs a profile).
- x86_64 or aarch64.
- For memory/CPU/pid limits: `busctl` and a systemd user manager.

The sandbox itself is built by [vssb](../vssb), the library crate next to
vssr in this workspace. Build with `cargo build --release` from the
workspace root; the binary is `target/release/vssr` there.

## Command line

```
vssr run [OPTIONS] -- COMMAND [ARGS...]
  -p, --policy FILE      policy file (TOML); default: the built-in policy
      --ro PATH          expose read-only     (SRC or SRC:DEST, '?' prefix = optional)
      --rw PATH          expose read-write
      --tmpfs PATH       empty tmpfs
      --deny PATH        hide a path
      --net none|proxy|host
      --allow HOST       allow through the proxy (implies --net proxy)
      --timeout 30m      --memory 4G   --cpus 2   --pids 512
  -e, --env NAME[=VAL]   pass or set an environment variable
      --cwd DIR          working directory inside
      --audit-log FILE   JSON-lines audit log
      --tty              keep the terminal (interactive use)
      --detect-within DIR  expose detected build dependencies under DIR (read-only)
      --detect-within-rw DIR  the same, read-write
      --detect-project off|ro|rw  detected dependencies in the same git repository (default ro)
      --no-detect        don't read the project's build files for extra rules
      --no-strict        run even if Landlock or limits can't be enforced
      --dry-run          print the resolved plan and exit
vssr check [same options]  kernel support + resolved plan
vssr policy                print the built-in default policy
```

Command-line options override the policy file.

Exit status is the command's own exit status, or 128+N if it died from
signal N. vssr itself uses 124 for a timeout, 125 when the sandbox could
not be set up, 126 when the command can't be executed and 127 when it is
not found.

## Policy files

`vssr policy` prints the defaults with comments. Every key is optional.

```toml
command = ["claude", "-p", "…"]     # used when no command is given

[sandbox]
hostname = "vssr"
cwd = "$PWD"            # working directory inside (default: where vssr ran)
strict = true           # refuse to run if Landlock or limits can't be enforced
tty = false             # keep the controlling terminal
timeout = "2h"          # wall-clock limit
kill_grace = "10s"      # SIGTERM → SIGKILL delay on timeout
uid = 1000              # ids inside (default: yours)
gid = 1000

[fs]
system = true           # ro /usr /etc /opt /bin /sbin /lib*; fresh /proc /dev /tmp /var/tmp /run
ro     = ["~/.gitconfig", "/srv/data:/data"]   # SRC or SRC:DEST
rw     = ["$PWD"]
tmpfs  = ["~"]
deny   = ["$PWD/.env", "~/.ssh"]
noexec = ["/tmp"]       # must name one of the entries above exactly
tmpfs_size = "2G"

[net]
mode = "proxy"          # none | proxy | host
allow = ["api.anthropic.com", "*.github.com", "example.org:8443", "db.internal:*", "10.0.0.5:5432"]
deny = ["gist.github.com"]
allow_private = false   # let allowed names resolve to loopback/LAN addresses
proxy_port = 3128
tcp_connect = [443]     # Landlock: only these TCP ports may be connected to
tcp_bind = []           # Landlock: only these TCP ports may be bound

[env]
pass = ["PATH", "TERM", "LANG", "LC_*", "HOME", "ANTHROPIC_API_KEY"]
set = { CI = "1" }

[limits]
memory = "8G"           # cgroup memory.max (swap disabled)
cpus = 4                # cgroup cpu.max, in cores
pids = 4096             # cgroup pids.max
nofile = 8192           # RLIMIT_NOFILE
fsize = "20G"           # RLIMIT_FSIZE

[detect]
enable = ["cargo"]      # detectors run at start (the default); [] turns them off
within = ["~/p"]        # detected directories outside the project are exposed only under these
within_rw = []          # the same, read-write
project = "ro"          # detected directories elsewhere in the same git repository: off | ro | rw

[seccomp]
allow = ["ptrace"]      # take syscalls off the default deny list
deny = ["kcmp", "nr:999"]

[audit]
log = "~/.local/state/vssr/audit.jsonl"
quiet = false           # don't print blocked requests to stderr
```

**Paths.** `~`, `$VAR` and `${VAR}` are expanded; `$PWD` is the directory
vssr started in. When two entries name the same path, `deny` beats `rw`
beats `ro` beats `tmpfs`, and command-line entries beat the policy file.
Nested entries work in any combination, e.g. a read-only `.git` inside a
writable checkout, or a hidden `.env` inside it. A path that is a symlink
on the host is recreated as a symlink (so `/bin -> usr/bin` keeps working).

**Network patterns.** `host` allows ports 80 and 443; `host:port` and
`host:*` widen that. `*.example.com` matches subdomains, not
`example.com` itself. `*` matches every host. Deny rules apply to all ports
unless they name one. In proxy mode the sandbox gets `HTTP_PROXY`,
`HTTPS_PROXY`, `ALL_PROXY` (and lower-case versions), `NO_PROXY` and
`NODE_USE_ENV_PROXY=1`, which covers curl, git, pip, npm, cargo, Python
`requests` and Node's `fetch`. There is no DNS inside; clients resolve
through the proxy.

**Detected rules.** At start, vssr reads the project's build files and
finds directories outside the working directory that the build will
read. The `cargo` detector follows path dependencies (direct and
transitive, including those of workspace members), `[patch]` and
`[replace]` paths, and the workspace roots of dependencies. Each one is
exposed at its host path:

- read-only under a `detect.within` directory, read-write under a
  `detect.within_rw` one (the deepest matching directory decides, so a
  read-only `~/p/vendor` inside a writable `~/p` works);
- inside the same git repository as the working directory (the nearest
  directory at or above it with a `.git`), as `detect.project` says:
  read-only by default, `rw` to make them writable, `off` to need
  `within` like anything else. This never covers the repository root
  itself or anything under its `.git`, and a repository at or above
  `$HOME` (dotfiles) doesn't count. It only widens what `within` grants.

Anything else is reported with the line that would allow it. An explicit
entry for the same path, or a read-only one above it, always wins, and
nothing under a `deny` entry is exposed. `--dry-run` shows each detected mount with the reason.
If the working directory is a member of a workspace above it, vssr says
to run from the workspace root instead, since cargo writes `Cargo.lock`
and `target/` there.

Build files are repository content, and the sandboxed program may have
edited them in an earlier run: anything under `detect.within` can be
made readable by naming it in a `Cargo.toml`, and anything under
`within_rw` (or in the repository, with `project = "rw"`) writable, which
makes it an exit like any writable directory (see below). Keep these
lists to directories you'd be fine exposing that way, and `deny` secrets
inside them. Symlinks under `within_rw` directories aren't followed for
explicit entries either, since an earlier run may have planted them. Detected paths are canonicalised before the
check, so symlinks in the project can't point outside `within`.

## Examples

- [`examples/claude-code.toml`](examples/claude-code.toml): Claude Code on
  the current repository, with API and package-registry access only, and
  its own state directory instead of your real `~/.claude`.
- [`examples/untrusted-build.toml`](examples/untrusted-build.toml):
  read-only source, writable `build/`, no network.

Agent-specific policies are plain data, so supporting another harness
means writing a policy file: its state directory, the API hosts it needs,
the environment variables to pass, and the flags that turn off its own
sandbox if it builds one (see the last points below).

## Security notes and limits

Think about what you expose, not only what you block.

- **Writable directories are an exit.** Whatever the agent writes into a
  `rw` path can run later outside the sandbox: git hooks in `.git/hooks`,
  `.envrc`, editor tasks, build scripts, `~/.bashrc`. Expose the smallest
  directory that works; consider `ro = ["$PWD/.git"]` and committing
  yourself, and never expose your real `~/.claude`, `~/.config` or shell
  rc files read-write.
- **The proxy filters by name.** A CONNECT tunnel to an allowed host can
  carry anything, and CDNs that serve many domains from one address allow
  domain fronting. Allow-listing `github.com` allows pushing to any
  repository the agent has credentials for. Credentials you pass in can be
  sent to any allowed host.
- **Supplementary groups stay.** Without root, vssr can't drop your
  supplementary groups; they show up as `nobody` inside. They only matter
  for files the policy exposes.
- **/etc is visible** read-only in the default system view. Add `deny`
  entries for anything sensitive in it, or set `system = false` and list
  what you need.
- **The kernel is shared.** Like containers, this relies on the kernel for
  isolation; seccomp trims the attack surface, but a kernel exploit
  reachable from the remaining syscalls escapes. For hostile code, use a VM.
- Programs that build their own sandbox (Chromium, Electron, Firefox)
  need to be told not to (`--no-sandbox`), because nested user namespaces
  are blocked.
- Landlock rights are inherited down the directory tree, so when a
  read-only directory is mounted inside a writable one, vssr withholds the
  unix-socket-connect right from the writable one too. Programs that
  create and use their own sockets there fail with EACCES; use a different
  directory (the default `/tmp` is fine unless you mount something
  read-only under it).
- `--tty` keeps your terminal attached so interactive tools work.
  TIOCSTI is blocked, but the agent can still print escape sequences to
  your terminal; prefer non-tty mode for unattended runs.

## How it works

`vssr run` (the supervisor) resolves the policy into a plan: it expands
paths, runs the detectors, resolves symlinks and checks the writable
directories, and merges everything into one mount list. It hands that
list, with the rest of the plan, to [vssb](../vssb), which does the
sandboxing:

1. vssb `clone`s a child into new user, mount, PID, network, IPC and UTS
   namespaces and writes its uid/gid maps. With limits, it asks the
   systemd user manager over D-Bus (`busctl`) for a transient scope
   (`vssb-<id>.scope`) holding the child, then the child enters a new
   cgroup namespace rooted there;
2. the child, PID 1 of the new namespace, clones every bind source with
   `open_tree`, makes it read-only, nosuid and nodev while still
   detached, mounts a tmpfs as the new root, attaches everything under it
   parent-first (finding each mount point with
   `openat2(RESOLVE_NO_SYMLINKS)`), and `pivot_root`s into it;
3. it sets the hostname, brings up loopback and, in proxy mode, listens
   on `127.0.0.1:3128` and hands that socket to the supervisor, so the
   proxy runs outside the sandbox but accepts connections from inside;
4. it forks the program, which drops capabilities, sets no_new_privs,
   applies Landlock and seccomp, and execs the command;
5. it forwards signals to the program and reaps zombies; when the program
   exits it kills everything else in the namespace and reports the
   program's status. If the supervisor dies, PID 1 notices its control
   socket closing and kills the sandbox.

Meanwhile the supervisor serves the proxy with the policy's rules, passes
SIGTERM, SIGINT, SIGHUP, SIGQUIT, SIGUSR1 and SIGUSR2 on to the program,
enforces the timeout (SIGTERM, then SIGKILL after `kill_grace`) and
writes the audit log.

## Tests

```sh
cargo test                  # unit tests: policy, proxy rules, seccomp assembly
tests/integration.sh        # end-to-end checks of the guarantees above
```

The integration tests need internet access for the proxy tests
(`VSSR_TEST_OFFLINE=1` skips them) and a systemd user manager for the
limit tests.
