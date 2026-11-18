# dbus-proxy: notes for agents

Filtering D-Bus proxy, as a library (vssr's `--dbus`). See README.md for
the policy model, what passes, and how it differs from xdg-dbus-proxy.

## Layout

- `src/lib.rs`: the public API (`serve`, `probe`, `Proxy`, `Event`,
  `Denied`, `Reason`) and the accept loop.
- `src/policy.rs`: `Policy` (levels, `.*` names, call and broadcast
  rules), xdg-dbus-proxy's semantics.
- `src/filter.rs`: the filter for one connection, with no I/O: messages
  in from either side, messages and events out. Owner tracking, the
  snapshot after `Hello`, calls in flight, bus methods.
- `src/wire.rs`: header parsing and checking, leading string arguments,
  serial rewriting, building the messages the filter makes up.
- `src/names.rs`: name syntax. `src/auth.rs`: both logins and bus
  addresses. `src/conn.rs`: one connection's sockets (`poll`, `recvmsg`
  with descriptors, queues).
- `src/differential.rs`: the differential test against xdg-dbus-proxy
  (an ignored test).
- `examples/proxy.rs`: the proxy by hand. `tests/proxy.rs`, `tests/peer.py`:
  end to end on a private bus.

## Invariants

- Nothing reaches the other side without going through the filter, and
  the filter only sees messages `wire::Message::parse` accepted. Keep the
  header checks at least as strict as dbus-daemon's: a field the filter
  reads one way and the bus another is an escape. When in doubt, refuse
  (the connection closes).
- Default deny: an unknown bus method, message type or case is refused,
  never passed.
- The program's messages wait (unread) until the owner snapshot is
  complete; unique-name decisions depend on it.
- Replies are matched to calls in flight by our serial (towards the
  program) and by (caller, serial) (from the program), each used once.
- Library rules: no process-wide state (threads only: one to accept, one
  per connection; no signal handlers, no `fork`), every thread stops and
  is joined when `Proxy` drops, and the crate knows nothing about vssr
  (no policy files, no audit format).

## Testing

`cargo test -p dbus-proxy`. Every filter rule gets a case in `filter::tests`;
anything that depends on a real client library or bus gets one in
`tests/proxy.rs`. After a change to the filter, run the differential
test against xdg-dbus-proxy (README, "Against xdg-dbus-proxy") for a few
thousand rounds; a new difference is either a bug or, when it is
deliberate and this proxy is the stricter, an entry in `known` and the
README. Tests use only their private `dbus-daemon`, never the
session bus; try the session bus by hand only read-only (the example
proxy with `--see`, then `ListNames` or a property read).

`stopping_closes_connections` is flaky: on 2026-11-18 it failed once at
"still accepting" in a full `cargo test`, then passed 40 times alone
and 20 times with all of `tests/proxy.rs`. The likely cause, not
confirmed: the proxy has closed its listener by the time `Proxy` drops
(the accept thread owns it and is joined), but a child that another
test in the same binary is starting (`dbus-daemon`, `dbus-test-tool`,
`python3`) holds a copy of the listening socket between fork and exec,
so the connect still succeeds. If it fails again, rerun it alone before
suspecting the proxy's shutdown.
