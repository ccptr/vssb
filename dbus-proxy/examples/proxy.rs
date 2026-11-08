//! Runs the proxy by hand, with xdg-dbus-proxy's rule syntax:
//!
//! ```sh
//! cargo run -p dbus-proxy --example proxy -- "$DBUS_SESSION_BUS_ADDRESS" /tmp/bus --talk=org.freedesktop.Notifications
//! DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/bus notify-send hi
//! ```
//!
//! Prints every event; stops on end of input (Ctrl-D).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [address, socket, rules @ ..] = args.as_slice() else {
        return Err("usage: proxy ADDRESS SOCKET [--see|--talk|--own=NAME] [--call|--broadcast=NAME=RULE]...".into());
    };
    let mut policy = dbus_proxy::Policy::new();
    for r in rules {
        policy.add(r)?;
    }
    dbus_proxy::probe(address)?;
    let listener = std::os::unix::net::UnixListener::bind(socket)?;
    let proxy = dbus_proxy::serve(listener, address, policy, |e| eprintln!("{e}"))?;
    eprintln!("listening on unix:path={socket}");
    std::io::copy(&mut std::io::stdin(), &mut std::io::sink())?;
    drop(proxy);
    std::fs::remove_file(socket)?;
    Ok(())
}
