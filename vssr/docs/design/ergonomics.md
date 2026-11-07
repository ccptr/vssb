# Design note: ergonomics of running agents in a project

Status: proposal, 2026-11-05. Implemented so far: runtime detection of
Cargo path dependencies (2.1).

Related notes: [GUI applications](gui.md) (Wayland, D-Bus, audio and GPU
for host-installed apps, as an opt-in layer).

## Principle: general-purpose, any harness

vssr is a general-purpose sandbox, not an agent tool. Everything below
must work for any command: any agent harness, a build, a test runner, an
untrusted script. Concretely:

- The core has no knowledge of particular agents. What a harness needs
  (state directory, API hosts, environment, flags that disable its own
  sandbox, where it reads instructions) is data in a profile.
- Detectors key on the project's contents (build tools), never on the
  command being run.
- Interfaces offered to the program inside (environment variables,
  `/run/vssr/`, `vssr.internal`) are plain files, variables and HTTP, so
  any harness or script can use them without a vssr library.

## Problem

vssr enforces a good boundary, but using it day to day is clumsy:

- Every run names a policy file (`-p /path/to/claude-code.toml`), and a
  policy file is all or nothing: adding Rust toolchain access to the
  Claude example means copying the whole file.
- Nothing knows which project needs what. Toolchains, package caches and
  registries are written out by hand for each project.
- When the agent hits a wall (a 403 from the proxy, a missing path), the
  run fails and the user finds out afterwards, by reading stderr or the
  audit log and editing the policy by hand.
- The agent doesn't know it is sandboxed, so it retries blocked requests
  or works around them in odd ways.
- The useful setup, a writable checkout, is also the main way out: a
  writable `.git` (hooks, `core.fsmonitor`, `core.hooksPath`, filter
  drivers), `.envrc`, build scripts and editor tasks all run later on the
  host.

## Goals

- `cd project && vssr run -- claude …` does the right thing, with a policy
  the user approved for that project.
- Common needs (toolchains, caches, registries) are one line, not twenty.
- A blocked request turns into a one-command fix, not a debugging session.
- A mode where nothing the agent writes can run on the host; only data
  comes out.

## Non-goals

- Live prompts for filesystem access (see 3.4 for why).
- Wrapping single tool calls of a harness that itself runs outside the
  sandbox (see 5.4).
- Injecting credentials in the proxy. It would need TLS interception and
  a CA inside the sandbox; worth its own note.

## Threat-model rule for everything below

**Nothing that widens a policy may be writable from inside a sandbox, or
be taken from repository contents without the user approving it.** A
cloned repository is attacker-controlled input, and an agent that can
edit the policy for its next run has no boundary at all. Every proposal
below is checked against this rule.

---

## 1. Where a project's policy comes from

### 1.1 Profiles that compose

A policy file may build on others:

```toml
extends = ["claude-code", "rust"]
```

- Names resolve to built-in profiles (compiled in, like `DEFAULT_POLICY`)
  or to `~/.config/vssr/profiles/NAME.toml`; a path containing `/` is
  taken as a file.
- Merging: layers apply in order, then the file itself, then the command
  line. Lists append (`fs.*`, `net.allow`, `net.deny`, `env.pass`,
  `seccomp.*`); tables merge by key (`env.set`); scalars override. A
  later layer narrows with the existing tools: `deny` beats `rw`, and
  `net.deny` beats `net.allow`.
- Implementation: every config struct in `policy.rs` uses
  `#[serde(default)]`, so after deserializing, "not set" and "set to the
  default" look the same. Merge the layers as raw `toml::Value` tables
  first, then deserialize the result once. Cycles in `extends` are an
  error.
- The built-in default policy becomes the implicit first layer, which
  keeps today's behaviour for files without `extends`.

`-p NAME` accepts a profile name as well as a path, so
`vssr run -p claude -- …` works from any directory.

### 1.2 Project policies found automatically

When no `-p` is given, vssr looks for a project policy before falling
back to the built-in default:

1. **User-owned, outside the repository** (primary):
   `~/.config/vssr/projects/<key>.toml`, where `<key>` derives from the
   canonical path of the project root (the git top level, or the current
   directory). Match by path, not by git remote: the remote URL lives in
   `.git/config`, which an earlier run with a writable `.git` could have
   changed to borrow another project's policy.
2. **Supplied by the repository** (`.vssr.toml` at the project root):
   treated as a request. On first use, or when its content changes, vssr
   prints it as a diff against the profile it extends and refuses to run
   until the user approves it (`vssr trust`). Approval stores the file's
   SHA-256 in `~/.config/vssr/trusted/` next to the project key, like
   `direnv allow`. An approved file is used exactly as approved.

If both exist, the user-owned file wins and the repository file is
ignored, with a note on stderr.

### 1.3 Policy files are never writable inside

At plan time, vssr collects every file that contributed to the policy
(the `extends` chain, the project file, the trust store) and:

- adds a read-only entry for any of them that falls under a writable
  path, so `$PWD/.vssr.toml` stays read-only inside;
- refuses to run if `~/.config/vssr` (or any policy source) would be
  writable, with an error naming the entry that exposes it.

This also closes the hole that exists today when someone runs
`-p ./policy.toml` from inside the writable directory.

### 1.4 Showing where each grant came from

`vssr check` and `--dry-run` print the source of each mount, allowed host
and environment variable:

```
filesystem:
  rw     /home/dev/p/foo                     (claude-code)
  ro     /home/dev/.rustup                   (rust)
  deny   /home/dev/p/foo/.env                (projects/foo.toml)
network:  proxy — api.anthropic.com (claude-code), index.crates.io (rust), …
```

Carry the origin through `FsOverrides` and `NetPolicy` as a label next to
each entry. With layered policies this is the main debugging tool.

### 1.5 `vssr init`

Writes `~/.config/vssr/projects/<key>.toml` for the current project: it
`extends` the chosen agent profile and the toolchain presets found in
the tree (2.1), and the user can edit it afterwards. `vssr edit` opens it
in `$EDITOR`.

---

## 2. Granting from the project's contents

### 2.1 Detected rules and toolchain presets

**Implemented: runtime detection** (`src/detect.rs`, `[detect]` in the
policy). At start, detectors read the project's build files and report
host directories the build will read; `Plan::build` exposes each one
read-only at its host path, but only when:

- no explicit entry covers it already (an entry for that very path, or a
  visible bind above it, wins);
- it isn't under a `deny` entry or a remapped mount;
- its canonical path is under one of `detect.within` (read-only) or
  `detect.within_rw` (read-write), the deepest matching directory
  deciding; or it is inside the working directory's git repository, which
  `detect.project` (`off`, `ro` by default, `rw`) grants without any
  `within` entry. The project rule never covers the repository root or
  its `.git`, ignores repositories at or above `$HOME`, and only widens.
  Otherwise vssr prints what it found and the line that would allow it.

The `cargo` detector follows path dependencies (all dependency tables,
`target.*` included, direct and transitive), `[workspace.dependencies]`,
workspace members (with `*`/`?` globs), `[patch]` and `[replace]`, and
the workspace root of each dependency. A workspace root above the working
directory is reported, not exposed: cargo writes `Cargo.lock` and
`target/` there, so the fix is to run from the root.

This revises the earlier position that detection never grants at run
time. The bound is `within`: the user names the directories that build
files may pull in, accepting that anything below them can be named by an
edited `Cargo.toml`. The defaults (detection on, `within` empty,
`project = "ro"`) expose dependencies from the same repository read-only
and only report the rest.

Next detectors in the same shape: `package.json` `file:`/`link:`
dependencies, `go.mod` `replace … => ../dir`, `pyproject.toml` path
dependencies (uv, Poetry), `.cargo/config.toml` `paths`.

**Proposed: toolchain presets.** Built-in profiles per ecosystem,
suggested by marker files:

| Marker | Profile | Grants (sketch) |
|---|---|---|
| `Cargo.toml` | `rust` | `~/.rustup` ro, `$CARGO_HOME` cache (2.2), `index.crates.io`, `static.crates.io` |
| `package.json` | `node` | npm cache (2.2), `registry.npmjs.org` |
| `pyproject.toml`, `requirements*.txt` | `python` | pip/uv cache (2.2), `pypi.org`, `files.pythonhosted.org` |
| `go.mod` | `go` | module cache (2.2), `proxy.golang.org`, `sum.golang.org` |

Presets, unlike detected paths, carry network access and writable caches,
so marker files only feed `vssr init` and a hint on stderr ("this looks
like a Rust project; `extends = ["rust"]` adds …"); they aren't applied at
run time.

Profiles read environment variables for their paths (`$CARGO_HOME`,
falling back to `~/.cargo`), since layouts vary (`CARGO_HOME` here is
`~/.local/share/cargo`).

### 2.2 Overlay mounts for caches

Caches have to be writable, but a writable host cache is a way out
(cargo build scripts, npm `postinstall`, poisoned wheels used later by the
host). A new entry type fixes this:

```toml
[fs]
overlay = ["$CARGO_HOME", "~/.npm"]   # SRC or SRC:DEST
```

- The lower layer is the host directory (read-only); the upper and work
  directories live in `~/.local/share/vssr/overlay/<project-key>/<n>/`,
  so writes persist between runs of the same project but never reach the
  host cache, and projects don't share writes.
- Unprivileged overlayfs works in a user namespace since Linux 5.11, with
  the `userxattr` option. The upper directory must be on a filesystem with
  user xattrs (ext4, btrfs, xfs; tmpfs since 6.6).
- Keep the `open_tree` invariant: pass the layers to `fsconfig` as file
  descriptors (`FSCONFIG_SET_FD` with `lowerdir+`, `upperdir`, `workdir`)
  that were opened before the new root covers `/tmp`. **Check the minimum
  kernel version for fd-based layers**; if it's later than the README's
  "Linux 6.x", fall back to `/proc/self/fd/N` paths or raise the
  requirement.
- Precedence: `overlay` ranks with `ro` (it is a read-only view of the
  host plus private writes); `deny` and `rw` beat it.
- `vssr overlay rm [--project]` discards the upper layers.

Overlay is also the building block for isolated runs (4).

---

## 3. Permission requests at run time

### 3.1 Summary of blocked requests at exit (unattended)

The proxy already decides and logs every connection. The supervisor keeps
a count per (host, port, reason) and, at exit, unless `audit.quiet`:

```
vssr: blocked during this run:
  pypi.org:443           ×3  not in the allow list
  sentry.io:443          ×1  not in the allow list
  10.0.0.5:5432          ×1  resolves to a private or loopback address
vssr: to allow: vssr allow pypi.org sentry.io
```

The same data goes into the audit log as one `summary` event, so it
survives a harness that swallows stderr.

### 3.2 `vssr allow` and `vssr suggest`

- `vssr allow HOST…` adds hosts to the project's user-owned policy
  (creating it as in 1.5 if needed). Use `toml_edit` so comments and
  layout survive; that is a new dependency.
- `vssr suggest [RUN-ID]` reads the audit log for that run (default: the
  last run in this project) and prints a policy diff; `--apply` writes it.
  This needs an audit log, so the built-in default should turn
  `audit.log` on (`~/.local/state/vssr/audit.jsonl`).
- Private-address denials are suggested as `allow_private = true` only
  with a warning, never applied without `--apply`.

### 3.3 Interactive network approval (`--tty` runs)

For a blocked request, the proxy holds the client connection and asks:

```
vssr: claude wants pypi.org:443  [o]nce  [r]un  [p]roject  [d]eny (default in 30 s)
```

- Ask on the supervisor's controlling terminal when the run uses `--tty`;
  otherwise on a control socket for `vssr approve` from another terminal,
  with an optional desktop notification.
- "Run" adds the host to the in-memory `NetPolicy` for the rest of the
  run; "project" also does 3.2's `vssr allow`.
- Ask once per (host, port); while a prompt is open, later connections to
  the same host wait for the same answer. Without an answer in time, deny.
- The proxy runs outside the sandbox and already owns the decision, so
  this changes no boundary. The prompt shows only the host and port, which
  the proxy parsed itself; never text from the agent unless it has been
  cleaned (3.5).
- Terminal sharing: the agent and the prompt share the tty in `--tty`
  mode. Pausing output while prompting is hard to get right, so the
  control-socket path may be the better default even for interactive
  runs. Open question.

### 3.4 Why not filesystem prompts

- Landlock rules are fixed once the agent calls `landlock_restrict_self`.
  A path granted later is only reachable if it falls under a directory
  that was already allowed at start, with rights no wider than that
  directory's.
- Mounting into the running sandbox needs a helper process: a
  multithreaded process can't `setns` into a user or mount namespace, and
  the supervisor has threads by then (the proxy). The helper would also
  have to create mount points, and vssr never creates directories inside
  a bind mount.
- Paths the policy doesn't list don't exist inside (ENOENT), so vssr can't
  even see the request. Only `deny` entries (mode 000, EACCES) are
  recognisable, and those are also invisible to the supervisor.

The workable flow is: fail, record, suggest, rerun. With the agent's state
in a sandbox-only directory, `claude --continue` makes a rerun cheap. The
agent can also ask for paths through 3.5, which gives the user the record
the kernel doesn't.

Possible later: Landlock audit (ABI 7) reports denials through the kernel
audit subsystem, but reading it needs privileges vssr doesn't have.

### 3.5 Letting the agent ask: `vssr.internal`

The proxy answers requests for a reserved host, `vssr.internal`, itself
instead of forwarding them. The proxy environment variables already route
clients to it, so no new socket plumbing is needed:

- `GET http://vssr.internal/policy`: the plan as text (`Plan::describe()`)
  and JSON.
- `POST http://vssr.internal/request` with
  `{"net": ["pypi.org"], "path": ["~/.m2"], "why": "…"}`: queued for the
  user. Shown live through 3.3's prompt where possible, otherwise listed
  in the exit summary and in the audit log.
- A small `vssr-request` script inside the sandbox (or documented `curl`
  calls) wraps this.

In `net.mode = "none"` the proxy listener still runs, allowing only
`vssr.internal`, so requests work without network access. In `host` mode
there is no proxy; requests aren't available (or the listener runs on
another loopback port; open question).

Requests are agent-controlled text: strip control characters and escape
sequences, cap the length, and rate-limit before showing or logging them.

---

## 4. Getting work out safely: isolated runs

```sh
vssr run --isolate -- claude -p "fix the failing tests"
```

1. The project directory is an overlay (2.2): the host checkout is the
   read-only lower layer, and `~/.local/share/vssr/runs/<id>/` holds the
   upper layer. The agent sees the whole tree, including `target/` and
   `node_modules/`, without copying anything, and everything it writes
   (`.git` included) stays in the upper layer.
2. The agent works and commits as usual. Hooks from the host's `.git`
   still run, but inside the sandbox.
3. When the agent exits, vssr runs `git bundle create run.bundle --all`
   inside the sandbox (same policy, no network), writing to a vssr-owned
   directory outside the overlay.
4. On the host, vssr runs
   `git fetch run.bundle 'refs/heads/*:refs/remotes/vssr-<id>/*'`. A
   bundle is a pack plus a ref list: no config, hooks or attributes from
   the agent's repository are used on the host. Ref names are
   agent-controlled; fetching into a per-run namespace keeps them from
   touching local branches.
5. vssr prints `git log main..vssr-<id>/HEAD` and keeps the run directory
   until `vssr runs rm <id>`.

Also:

- Several agents can work on one checkout at once, each in its own upper
  layer.
- Uncommitted work is recoverable from the upper layer; `vssr runs diff
  <id>` shows it.
- Residual risk: the host's git parses an agent-made pack; a bug in
  `index-pack` would be reachable. Much smaller than running agent-written
  hooks.
- Changes to the host checkout while an isolated run is active give
  undefined results in the overlay. vssr should say so at start, and could
  record `HEAD` and warn at exit if it moved.
- Without git (no `.git` at the root), steps 3 to 5 are skipped and the
  upper layer is the result.

---

## 5. Integration with harnesses (as profile data)

### 5.1 Tell the model it's sandboxed

- Keep `VSSR_SANDBOX=1` (set today) and add `VSSR_ID=<id>`.
- Write a short `/run/vssr/sandbox.md` (vssr's own tmpfs, regenerated
  each run): reachable hosts, writable paths, how to use `vssr-request`,
  and that blocked requests won't start working by retrying.
- Each harness profile says how its harness picks the file up. For
  Claude Code, the sandbox-only state directory's `CLAUDE.md` holds one
  line, `@/run/vssr/sandbox.md`; other harnesses use their own
  instruction files or a system-prompt flag. vssr itself only writes the
  file; it never edits a harness's files.

### 5.2 Agent profiles

Built-in `claude-code` (and later `codex`, `gemini`, `opencode`, …)
profiles carry, for each harness: the state directory mapping, API hosts,
environment, and the flags that turn off the harness's own sandbox where
it can't nest. Claude Code's built-in sandbox uses bubblewrap, which needs
nested user namespaces, and vssr blocks those.

### 5.3 A short command

Today a command on the command line replaces the profile's `command`. Add
a form that appends:

```sh
vssr with claude -p "fix the failing tests"
# = profile "claude", command = profile.command + ["-p", "fix the failing tests"]
vssr with rust-build cargo test
```

The subcommand is generic (a profile name, then arguments), so it serves
agents and plain tools alike. The `vssr run -- …` behaviour stays as it
is. The name is an open question.

### 5.4 Not proposed: per-tool-call wrapping

A PreToolUse hook that runs each Bash call through vssr, with the harness
outside, leaves the harness's own file edits unsandboxed, and Claude Code
already has a sandbox for single commands. vssr's value is boxing the
whole agent.

---

## Order of work

1. Profiles with `extends`, user-owned project policies, policy files
   kept read-only inside, provenance in `check` (1.1–1.4).
2. Exit summary, `vssr allow`, `vssr suggest`, audit log on by default
   (3.1, 3.2).
3. `VSSR` variables, `/run/vssr/sandbox.md`, the `claude-code` profile's
   instruction import (5.1, 5.2).
4. Overlay entries (2.2), then `--isolate` (4).
5. `vssr.internal` and interactive approval (3.5, 3.3).
6. `vssr init`, toolchain presets, `vssr with` (1.5, 2.1, 5.3), and more
   detectors (2.1).

## Tests to add (`tests/integration.sh`)

- A policy file under a writable path is read-only inside; a policy that
  would make `~/.config/vssr` writable is refused.
- A repository `.vssr.toml` is ignored until trusted, and again after it
  changes.
- `extends` merge order and precedence match the rules in 1.1 (unit tests
  in `policy.rs`).
- Writes to an overlay entry are visible inside and absent from the lower
  directory afterwards; a second run of the same project sees them.
- In an isolated run, a `.git/hooks` file or `.envrc` written by the agent
  never appears in the host checkout; the host receives only refs from
  the bundle, under `vssr-<id>/`.
- The exit summary lists a blocked host; `vssr suggest --apply` adds it,
  and the next run reaches it.
- `vssr.internal` answers in `none` mode; request text with escape
  sequences is shown cleaned.

## Open questions

- Removing an inherited list entry (say, a host from `claude-code`) other
  than through `deny`: is a `remove` syntax worth it?
- Project key: canonical path only, or path plus inode of the root so a
  recreated directory doesn't inherit the old policy?
- Prompt location for 3.3: shared tty, control socket, or both.
- `vssr.internal` in `host` network mode.
- Whether `--isolate` should be the default for agent profiles once it is
  stable.
