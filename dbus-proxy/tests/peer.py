#!/usr/bin/env python3
"""A peer for dbus-proxy's end-to-end tests, on GDBus (python3-gi).

  peer.py service NAME   owns NAME on $DBUS_SESSION_BUS_ADDRESS and serves
                         org.dbusproxy.Peer at /org/dbusproxy/Peer; prints "ready"
  peer.py client BUS     through $DBUS_SESSION_BUS_ADDRESS (the proxy):
                         passes descriptors both ways and checks which
                         broadcasts arrive; BUS is the real bus, for a
                         stray broadcast the proxy must hold back
"""

import os
import sys

from gi.repository import Gio, GLib

IFACE = """
<node><interface name="org.dbusproxy.Peer">
  <method name="Take"><arg type="h" direction="in"/></method>
  <method name="Pipe"><arg type="h" direction="out"/></method>
  <method name="Emit"/>
  <signal name="Changed"/>
</interface></node>
"""


def service(name):
    conn = Gio.DBusConnection.new_for_address_sync(
        os.environ["DBUS_SESSION_BUS_ADDRESS"],
        Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,
        None,
        None,
    )
    info = Gio.DBusNodeInfo.new_for_xml(IFACE).interfaces[0]

    def call(conn, sender, path, iface, method, params, inv):
        fds = inv.get_message().get_unix_fd_list()
        if method == "Take":
            fd = fds.get(params.unpack()[0])
            os.write(fd, b"taken")
            os.close(fd)
            inv.return_value(None)
        elif method == "Pipe":
            r, w = os.pipe()
            os.write(w, b"from-service")
            os.close(w)
            out = Gio.UnixFDList.new()
            idx = out.append(r)
            os.close(r)
            inv.return_value_with_unix_fd_list(GLib.Variant("(h)", (idx,)), out)
        elif method == "Emit":
            conn.emit_signal(None, "/org/dbusproxy/Peer", "org.dbusproxy.Peer", "Changed", None)
            inv.return_value(None)

    conn.register_object("/org/dbusproxy/Peer", info, call, None, None)
    r = conn.call_sync(
        "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "RequestName",
        GLib.Variant("(su)", (name, 4)), None, 0, -1, None,
    )
    assert r.unpack()[0] == 1, r
    print("ready", flush=True)
    GLib.MainLoop().run()


def client(bus):
    conn = Gio.bus_get_sync(Gio.BusType.SESSION, None)
    got = []
    conn.signal_subscribe(None, None, None, None, None, Gio.DBusSignalFlags.NONE,
                          lambda c, s, p, i, m, a: got.append(i + "." + m))

    # A descriptor to the service, and one back from it.
    r, w = os.pipe()
    fds = Gio.UnixFDList.new()
    idx = fds.append(w)
    os.close(w)
    conn.call_with_unix_fd_list_sync("org.dbusproxy.Peer", "/org/dbusproxy/Peer", "org.dbusproxy.Peer", "Take",
                                     GLib.Variant("(h)", (idx,)), None, 0, 5000, fds, None)
    print("take", os.read(r, 100).decode(), flush=True)
    reply, out = conn.call_with_unix_fd_list_sync("org.dbusproxy.Peer", "/org/dbusproxy/Peer", "org.dbusproxy.Peer", "Pipe",
                                                  None, None, 0, 5000, None, None)
    fd = out.get(reply.unpack()[0])
    print("pipe", os.read(fd, 100).decode(), flush=True)

    # A broadcast from a connection the policy doesn't cover; the round
    # trip makes sure the bus has passed it on before the allowed one.
    other = Gio.DBusConnection.new_for_address_sync(
        bus, Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION, None, None)
    other.emit_signal(None, "/x", "org.dbusproxy.Stray", "Signal", None)
    other.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetId",
                    None, None, 0, -1, None)
    conn.call_sync("org.dbusproxy.Peer", "/org/dbusproxy/Peer", "org.dbusproxy.Peer", "Emit", None, None, 0, 5000, None)
    ctx = GLib.MainContext.default()
    deadline = GLib.get_monotonic_time() + 5_000_000
    while "org.dbusproxy.Peer.Changed" not in got and GLib.get_monotonic_time() < deadline:
        ctx.iteration(True)
    while ctx.pending():
        ctx.iteration(False)
    print("signals", " ".join(s for s in got if s.startswith("org.dbusproxy.")), flush=True)


if __name__ == "__main__":
    {"service": service, "client": client}[sys.argv[1]](sys.argv[2])
