# dbus-proxy

A filtering D-Bus proxy, as a library: it gives a sandboxed program a
session bus that reaches only the names its policy allows, and reports
every message it stops. vssr uses it for `--dbus`; any program that
sandboxes another can embed it.

```rust
let mut policy = dbus_proxy::Policy::new();
policy.talk("org.freedesktop.Notifications")?.own("org.example.App")?;
let address = std::env::var("DBUS_SESSION_BUS_ADDRESS")?;
dbus_proxy::probe(&address)?;                       // fail now if there is no bus
let listener = UnixListener::bind(&socket)?;  // where the program finds it
let proxy = dbus_proxy::serve(listener, &address, policy, |e| eprintln!("{e}"))?;
// run the program with DBUS_SESSION_BUS_ADDRESS=unix:path=<socket>
drop(proxy);                                  // closes every connection
```

`examples/proxy.rs` runs it by hand with xdg-dbus-proxy's arguments
(`cargo run -p dbus-proxy --example proxy -- "$DBUS_SESSION_BUS_ADDRESS" /tmp/bus --talk=…`).

## The policy

The model is xdg-dbus-proxy's, so rules written for Flatpak mean the same:

- Each name gets a level: `see` < `talk` < `own`. A name with no level is
  hidden: calls to it fail with `ServiceUnknown` (or `NameHasNoOwner`) as
  if nothing owned it, and `ListNames`, `NameHasOwner`, `GetNameOwner` and
  `NameOwnerChanged` don't show it.
- `see`: listed, its owner can be looked up and followed, no calls.
- `talk`: any call, and every signal it broadcasts reaches the program.
- `own`: `talk`, and the program may own the name.
- `call NAME RULE` and `broadcast NAME RULE` make the name talkable for
  the calls, or the broadcasts, the rule matches. RULE is
  `[METHOD][@PATH]`: METHOD is `*`, `org.example.Iface.*` or
  `org.example.Iface.Method`, PATH is `/obj/path` or `/obj/path/*` (it and
  below). A call rule needs an interface on the call to match.
- `org.example.*` covers `org.example` and every name below it.

`Policy::add` takes xdg-dbus-proxy's own arguments (`--talk=NAME`,
`--call=NAME=RULE` and so on).

Programs call services by their unique names (`:1.42`), so the proxy
follows which unique name owns each well-known name the policy covers:
right after the program's `Hello` it takes a snapshot (`ListNames`, then
`GetNameOwner` for each covered name, after adding a match for
`NameOwnerChanged`), and the program's own messages wait until it is
complete. A unique name then has the highest level of the names it owns.
The program may also call itself, and may see (not call) any unique name
that sent it something.

The bus's own methods: `Hello`, `GetId`, `AddMatch` (not with
`eavesdrop`), `RemoveMatch`, `ListNames` and `ListActivatableNames`
(filtered replies) and `Introspect` pass. `RequestName`, `ReleaseName`
and `ListQueuedOwners` need `own` on the name; `NameHasOwner`,
`GetNameOwner` and the `GetConnection*` credential methods need `see`;
`StartServiceByName` needs `talk`. About a hidden name they answer as
xdg-dbus-proxy does: `NameHasOwner` false, `GetNameOwner`
`NameHasNoOwner`, the others `ServiceUnknown`. Everything else
(`BecomeMonitor`, `UpdateActivationEnvironment`, `ReloadConfig`, the
bus's `Peer` and `Properties` interfaces, `Debug.Stats`, `Containers1`,
anything newer) is refused.

Coming in: replies only to the program's calls in flight; broadcasts only
from senders the policy lets through; messages the bus addresses to the
program (calls from any connection, unicast signals), and nothing
addressed to anyone else. Going out: replies only to calls the program
received, each once; broadcast signals freely (the bus stamps the sender,
so they can't be forged).

## How it differs from xdg-dbus-proxy

- **It logs in for the program.** The proxy logs in to the bus as itself
  and accepts the program's `EXTERNAL` login whatever uid it claims, once
  the socket's peer credentials say it runs as the caller's user. So a
  program running as root (or another uid) in its user namespace still
  gets a bus; xdg-dbus-proxy passes the login through, and the bus
  refuses the uid. `ANONYMOUS` and other mechanisms are refused.
- **It reports what it stops**, as `Event::Deny` with the message's
  destination, interface, member, path, the name a bus method was about,
  and the reason. Connections opening (with their unique name) and
  closing are events too.
- **It runs in the caller**, one thread to accept and one per connection,
  with no helper binary.
- **It is stricter** about headers (below), refuses method calls with no
  destination and `ReloadConfig`, refuses any match rule that mentions
  `eavesdrop` (xdg-dbus-proxy looks for `eavesdrop=`), and drops messages
  that carry descriptors towards a program that didn't negotiate them.
- **A unique name's level follows what it owns now.** xdg-dbus-proxy
  keeps the level a service's unique name earned from a well-known name
  after the service gives that name up (it stays visible, callable, and
  its broadcasts keep arriving); here it goes with the name.
- No `--sloppy-names` and no `--log` (events replace it).

## Messages

Every header is parsed whole and checked at least as strictly as
dbus-daemon checks it before the filter looks at it: byte order, version,
lengths, zero padding, no field given twice, each known field's type and
syntax (object paths, interface, member, error and bus names, signatures),
the fields each message type requires, and unknown fields skipped by
their full type. A message that fails closes the connection, so the
filter never reads a header differently from the bus. Both byte orders
are read; the proxy's own messages are little-endian.

The proxy numbers every message it sends to the bus (the program's too),
so its own calls never collide with the program's, and gives replies the
program's serial back. Descriptors travel with their messages
(`SCM_RIGHTS`) both ways.

## Limits

Messages up to 32 MiB (the specification allows 128 MiB; big data goes in
a descriptor), 64 connections at a time (more wait in the backlog), 16384
calls in flight each way (more are answered with `LimitsExceeded`), and a
side that stops reading: 8 MiB queued for it pauses the other side, 128
MiB drops the connection. Each login may take 10 seconds.

## Security notes

- The filter decides who the program may talk to, not what a service does
  for it. `org.freedesktop.systemd1` and `org.freedesktop.Flatpak` start
  any command on the host for a caller, and so would a terminal emulator's
  or an IDE's service; vssr warns about the first two. Prefer portals,
  which check their callers.
- The proxy itself has the caller's full access to the bus. Its only
  `unsafe` code is the system calls (`recvmsg`/`sendmsg` with descriptors,
  `poll`, `pipe2`, `getsockopt`).
- Any connection on the bus may call the program, as on any bus.
- `NameOwnerChanged` for the names it may see can reach the program
  without its asking (the proxy's own match rule is on its connection).

## Tests

`cargo test -p dbus-proxy`: unit tests of the wire format, the policy, the login
and the filter (as a state machine, message by message), and
`tests/proxy.rs`, which starts a private `dbus-daemon` with
`dbus-test-tool` services and runs GDBus (`gdbus`, and Python's GIO for
descriptors and broadcasts, `tests/peer.py`), sd-bus (`busctl`) and
libdbus (`dbus-send`, `dbus-monitor`) clients through the proxy. Tests
whose tools are missing say so and pass.

### Against xdg-dbus-proxy

```sh
cargo test -p dbus-proxy --lib differential -- --ignored --nocapture
DIFF_SEED=… DIFF_ROUND=… cargo test …     # replay one round
```

`src/differential.rs` builds two identical worlds per round, each a
private `dbus-daemon` with the same four services, one behind
xdg-dbus-proxy and one behind this proxy, with the same random policy
(xdg-dbus-proxy's arguments). It then plays the same random actions in
both: calls (to well-known and unique names, the program itself, names
that don't exist, with and without interfaces and flags), every bus
method, match rules (eavesdropping ones too), the program's broadcasts,
unicast signals and stray replies; the services' broadcasts, calls to
the program (answered once or twice), calls between services, and names
changing owner. After each action it compares what the program got
(reply or error name, bodies that don't depend on the bus, signals,
calls) and what each service got from it. A round stops at its first
difference. The two kinds above, where this proxy is the stricter, are
counted as known; any other difference fails with the policy and the
actions that led to it (`DIFF_ROUNDS`, default 40, from `DIFF_FROM`, 0,
and `DIFF_ACTIONS`, 25; it needs `xdg-dbus-proxy`). A round takes about
two seconds.

On 2026-11-07 and 08, 3900 rounds (seeds 1, 7, 11 and 2026) found two
differences, both since fixed: this proxy let the bus's `Peer` and
`Properties` methods through, which xdg-dbus-proxy refuses, and it
answered bus methods about hidden names with other errors. Every other
difference was one of the two known kinds. Nothing reached a service,
or the program, through this proxy that didn't through xdg-dbus-proxy.
