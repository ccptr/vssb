# Design note: GUI applications

Status: proposal, 2026-11-05. Nothing here is implemented yet. Part of
the general-purpose direction in [ergonomics.md](ergonomics.md).

## Problem

Rootless sandboxing of GUI applications that are installed on the host
(by the distribution's package manager, or built locally) has few good
options:

- **Flatpak** only sandboxes applications built for it, on its own
  runtimes: a large download, and a repackaging step for every app.
- **firejail** handles host applications, but it is setuid root, which
  is a large attack surface in itself.
- **bubblewrap** is a primitive: each wrapper is written by hand, and
  getting the Wayland, D-Bus and audio sockets right is left to the
  author.

vssr already reuses the host's `/usr` read-only, so it needs no runtime
and no repackaging. What it lacks is a safe way to hand a GUI app the
few sockets it needs.

## Principle

GUI support is an opt-in layer. It must not weaken anything the headless
sandbox guarantees, and the core stays generic: what a particular app
needs (app id, directories, environment, D-Bus names) is profile data.
Each socket below is off by default, narrowed before it is exposed, and
covered by an integration test.

## Threat model: what the raw sockets give away

Passing the session's sockets through unchanged is not a sandbox:

- **Wayland.** Compositors offer privileged protocols to ordinary
  clients. On this machine (Hyprland 0.57.1, checked with `wayland-info`
  on 2026-11-05) every client gets:
  - screen capture: `zwlr_screencopy_manager_v1`,
    `ext_image_copy_capture_manager_v1`;
  - reading the clipboard at any time: `zwlr_data_control_manager_v1`,
    `ext_data_control_manager_v1`;
  - input injection: `zwp_virtual_keyboard_manager_v1`,
    `zwlr_virtual_pointer_manager_v1`.

  Virtual-keyboard access means a sandboxed app can type commands into a
  terminal outside the sandbox: a complete escape.
- **X11.** Any client can log keys, read other windows and inject input.
- **D-Bus session bus.** `org.freedesktop.systemd1` `StartTransientUnit`
  runs any command on the host, as do many other services. A complete
  escape.
- **PipeWire.** The raw socket gives access to every stream, including
  microphone capture and screen-capture streams.
- **GPU render nodes.** Not an escape by themselves, but they add the
  kernel GPU driver to the attack surface.

## Proposed policy surface

```toml
[gui]
app_id = "org.example.App"   # reported to the compositor (and portals, see 7)
wayland = true               # a security-context socket; refused if the compositor lacks it
insecure_wayland = false     # allow running when privileged protocols stay visible (see 1)
x11 = false                  # a private Xwayland inside the sandbox (see 4)
gpu = false                  # /dev/dri render nodes
audio = false                # the PipeWire socket: all streams, including capture

[dbus]
talk = ["org.freedesktop.Notifications", "org.freedesktop.portal.*"]
own = ["org.example.App"]
# see = [], call = [], broadcast = []   # passed to xdg-dbus-proxy as is

[fs]
sockets = ["$XDG_RUNTIME_DIR/some.sock"]   # unix sockets the program may connect to (see 2)
```

## 1. Wayland through a security context

`wp_security_context_manager_v1` (wayland-protocols, staging) lets a
sandbox engine create a dedicated listening socket whose clients the
compositor can tell apart and restrict. Flatpak uses it.

Sequence, all in the supervisor before `clone`:

1. Create a unix socket at `$XDG_RUNTIME_DIR/vssr/<id>/wayland-0` on the
   host, `bind` and `listen`, and create a pipe.
2. Connect to the session's compositor, bind
   `wp_security_context_manager_v1`, call
   `create_listener(listen_fd, close_fd)` with the read end of the pipe,
   then `set_sandbox_engine("vssr")`, `set_app_id(app_id)`,
   `set_instance_id(id)` and `commit`. Close the connection.
3. Keep the pipe's write end open for the life of the sandbox. When the
   supervisor exits, the compositor sees the hang-up and stops accepting
   on the socket.
4. Bind only that socket into the sandbox as
   `$XDG_RUNTIME_DIR/wayland-0` and set `WAYLAND_DISPLAY=wayland-0`. The
   session's own `wayland-1` is never visible.

The protocol exchange is small (a registry bind, one request passing two
fds, three setters, commit), so it can be hand-written like the seccomp
assembler, with no Wayland library. It is synchronous and starts no
threads, so the invariant about `clone` still holds.

**Decision gate.** The protocol only tags clients; restricting them is up
to the compositor. Before building more, a prototype must connect
through such a socket and list the globals it sees:

- If Hyprland still offers screencopy, data control or virtual input
  there, vssr refuses `wayland = true` on that compositor unless
  `insecure_wayland = true`, and says which protocols leak.
- wlroots compositors (sway) reportedly hide privileged protocols from
  security-context clients; verify on the headless sway used for tests.
- Hyprland also has a permission system for screen capture and virtual
  input in its configuration (to verify). That would be a host-wide
  setting the user configures, not something vssr can rely on.

The check runs at every start: vssr lists the globals through the new
socket and refuses (or warns, with `insecure_wayland`) if a privileged
one appears. That check is also the main integration test.

## 2. Connecting to specific sockets (`fs.sockets`)

With Landlock ABI 9+, vssr keeps the sandbox from connecting to host unix
sockets exposed read-only, which is what blocks a stray `docker.sock`
today. A new entry type binds one socket file and grants the right to
connect to exactly that file:

- valid only for socket files (checked with `fstat` on the `open_tree`
  clone), never directories;
- used internally for the Wayland and D-Bus sockets above;
- generic: headless runs can use it too (an `ssh-agent` socket, a
  build-cache daemon), with a warning in the README that each socket is
  a capability handed to the program.

## 3. D-Bus only through a filter

The sandbox never sees the session bus. vssr starts `xdg-dbus-proxy` (a
standalone binary, packaged separately from Flatpak's runtimes;
installed here) outside the sandbox:

```
xdg-dbus-proxy "$DBUS_SESSION_BUS_ADDRESS" $XDG_RUNTIME_DIR/vssr/<id>/bus \
    --filter --talk=… --own=… --fd=N
```

- Started before `clone` (fork and exec, no threads), with
  `PR_SET_PDEATHSIG` so it dies with the supervisor; vssr waits for the
  ready byte on `--fd` before going on.
- The policy's `[dbus]` lists map onto `--talk`, `--own`, `--see`,
  `--call` and `--broadcast` one to one.
- Inside: the socket at `$XDG_RUNTIME_DIR/bus`, and
  `DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus`.
- No system bus by default. The accessibility bus is off
  (`NO_AT_BRIDGE=1`) unless the profile asks for it.
- Profiles should prefer portals (`org.freedesktop.portal.*`) over
  talking to services directly.

## 4. X11 only through a private Xwayland

No access to the session's X server. For apps that need X11, the
sandbox runs its own X server as an ordinary Wayland client through the
security-context socket: `xwayland-satellite` (rootless windows; not
installed here) or a rootful `Xwayland` in one window. It runs inside the
sandbox, so it is sandboxed too, and its X socket exists only there.
X11 apps in one sandbox can still snoop on each other, but not on
anything outside.

## 5. Audio and GPU

- `audio = true` binds `pipewire-0` (via `fs.sockets`) with a warning at
  start: the app can capture the microphone and any stream. To
  investigate: whether PipeWire can serve a separate socket with
  restricted permissions (as it does for Flatpak clients through its
  access module), so playback works without capture.
- `gpu = true` adds `/dev/dri/renderD*` (and the NVIDIA device nodes when
  present) to the device list built in `mounts.rs`. Render nodes only;
  never the primary (`card*`) nodes.

## 6. Per-app state and desktop plumbing

- A persistent home per app: `~/.local/share/vssr/apps/<app_id>` mapped
  to `~`, read-write, so settings survive without touching the real
  home. Read-only extras from the profile: fonts (`~/.local/share/fonts`,
  fontconfig), themes, `~/.config/gtk-3.0`.
- A private `XDG_RUNTIME_DIR` inside (a tmpfs at `/run/user/<uid>`),
  holding only the sockets above.
- Environment the profile sets: `GDK_BACKEND=wayland`,
  `QT_QPA_PLATFORM=wayland`, `GSETTINGS_BACKEND=keyfile` (dconf would
  need its D-Bus service), and so on.
- `vssr desktop install PROFILE` writes
  `~/.local/share/applications/vssr-<app>.desktop`, copying the
  original's name and icon, with `Exec=vssr run -p PROFILE -- …`.
- Apps that build their own sandbox (Chromium, Electron) still need
  `--no-sandbox`; their profiles say so.

## 7. Portals

As far as I know, xdg-desktop-portal recognises only Flatpak and Snap
sandboxes. Everything else is a host app, so:

- a file chooser returns host paths, which the sandboxed app can't open
  unless the policy exposes them; profiles expose `~/Downloads` and
  similar directories up front;
- the document portal (`/run/user/<uid>/doc`) isn't used.

To explore (unverified):

- **App id for host apps.** Recent portals derive a host app's id from
  its systemd unit name (`app-<id>-….scope`). vssr already runs limited
  sandboxes in a transient user scope; naming it
  `app-vssr.<app_id>-<id>.scope` would give portals and permission
  stores a stable id.
- **Flatpak-compatible sandbox info.** Portals recognise a Flatpak by
  reading `/.flatpak-info` through `/proc/<pid>/root`. vssr's root is a
  tmpfs that becomes read-only after setup, so it could carry such a
  file. Portals would then treat the app as sandboxed, and the document
  portal's FUSE mount could be bound in to pass picked files through.
  This depends on portal internals (other checks, instance directories)
  that may change, so it needs a careful look first; it uses a file
  format, not anyone's branding.

## Order of work

0. **Prototype the decision gate (1):** a security-context listener plus
   a global listing, against Hyprland and headless sway. About a day; it
   decides whether the rest is worth building on this compositor.
1. `fs.sockets` with the Landlock connect right (2); useful headless too.
2. Wayland through a security context, with the check at every start (1).
3. `xdg-dbus-proxy` and `[dbus]` (3).
4. Per-app home, environment, `XDG_RUNTIME_DIR`, fonts and themes; two
   or three example profiles in `examples/` (6).
5. `gpu` and `audio` (5).
6. Private Xwayland (4).
7. Portal exploration (7), then `vssr desktop install` (6).

## Tests to add

Run against the headless sway (socket `wayland-2`, see the agent notes),
never the live Hyprland session, and not while Counter-Strike 2 is
running:

- A client inside sees no screencopy, data-control or virtual-input
  globals; vssr refuses to start where the compositor would leak them.
- The session's own Wayland socket and the session bus are unreachable
  inside.
- Through the D-Bus proxy, `org.freedesktop.systemd1` can't be called;
  an allowed name can.
- Only sockets listed in `fs.sockets` can be connected to; another
  socket in the same directory can't.
- The security-context socket stops accepting once the sandbox exits.
- `x11 = true` gives a working X server inside, and no X socket from the
  host is visible.

## Open questions

- Does Hyprland filter globals for security-context clients, and if not,
  is its permission configuration enough to recommend?
- Restricted PipeWire access without Flatpak's identification.
- Whether the Flatpak-compatible info file (7) is robust enough to
  support, or too tied to portal internals.
- One sandbox per app instance, or a long-lived sandbox per app that
  later launches join (single-instance apps expect the latter).
