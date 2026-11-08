//! End to end: a private dbus-daemon, services on it, and real clients
//! (GDBus, sd-bus's busctl, libdbus's dbus-send and dbus-monitor) behind
//! the proxy. Tests that need a tool that isn't installed say so and
//! pass.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn have(tool: &str) -> bool {
    let ok = Command::new("sh").args(["-c", &format!("command -v {tool}")]).stdout(Stdio::null()).status().is_ok_and(|s| s.success());
    if !ok {
        eprintln!("skipped: {tool} is not installed");
    }
    ok
}

/// Kills its processes when dropped.
struct Procs(Vec<Child>);

impl Drop for Procs {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

struct Bus {
    dir: PathBuf,
    address: String,
    procs: Procs,
}

impl Bus {
    fn start(name: &str) -> Bus {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("dbus-proxy-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("bus");
        let conf = dir.join("bus.conf");
        std::fs::write(
            &conf,
            format!(
                r#"<busconfig>
  <type>session</type>
  <listen>unix:path={}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>"#,
                socket.display()
            ),
        )
        .unwrap();
        let mut daemon = Command::new("dbus-daemon")
            .arg(format!("--config-file={}", conf.display()))
            .args(["--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(daemon.stdout.take().unwrap()).read_line(&mut line).unwrap();
        Bus { dir, address: line.trim().to_string(), procs: Procs(vec![daemon]) }
    }

    /// A `dbus-test-tool echo` owning `name` (empty replies to every call).
    fn echo(&mut self, name: &str) {
        let c = Command::new("dbus-test-tool").args(["echo", &format!("--name={name}")]).env("DBUS_SESSION_BUS_ADDRESS", &self.address).spawn().unwrap();
        self.procs.0.push(c);
        self.wait_for(name);
    }

    fn wait_for(&self, name: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.names(&self.address).iter().any(|n| n == name) {
            assert!(Instant::now() < deadline, "{name} did not appear on the bus");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// `ListNames` on `address`, through busctl.
    fn names(&self, address: &str) -> Vec<String> {
        let o = run(&["busctl", &format!("--address={address}"), "call", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "ListNames"]);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let text = String::from_utf8_lossy(&o.stdout).into_owned();
        text.split('"').skip(1).step_by(2).map(String::from).collect()
    }
}

fn run(argv: &[&str]) -> Output {
    run_env(argv, &[])
}

fn run_env(argv: &[&str], env: &[(&str, &str)]) -> Output {
    let mut c = Command::new(argv[0]);
    c.args(&argv[1..]).stdin(Stdio::null());
    for (k, v) in env {
        c.env(k, v);
    }
    let mut child = c.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    // Nothing here should take long; a hang is a failure, not a stuck test.
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().unwrap()
}

struct Proxied {
    address: String,
    events: Arc<Mutex<Vec<dbus_proxy::Event>>>,
    proxy: Option<dbus_proxy::Proxy>,
}

impl Proxied {
    fn new(bus: &Bus, name: &str, policy: dbus_proxy::Policy) -> Proxied {
        let socket = bus.dir.join(name);
        let listener = UnixListener::bind(&socket).unwrap();
        let events = Arc::new(Mutex::new(vec![]));
        let e = events.clone();
        let proxy = dbus_proxy::serve(listener, &bus.address, policy, move |ev| e.lock().unwrap().push(ev.clone())).unwrap();
        Proxied { address: format!("unix:path={}", socket.display()), events, proxy: Some(proxy) }
    }

    fn denied(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                dbus_proxy::Event::Deny { denied, .. } => Some(denied.to_string()),
                _ => None,
            })
            .collect()
    }
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn policy() -> dbus_proxy::Policy {
    let mut p = dbus_proxy::Policy::new();
    p.talk("org.dbusproxy.Allowed").unwrap().see("org.dbusproxy.Seen").unwrap().own("org.dbusproxy.Mine.*").unwrap();
    p
}

fn tools() -> bool {
    ["dbus-daemon", "dbus-test-tool", "busctl", "gdbus", "dbus-send"].iter().all(|t| have(t))
}

#[test]
fn talk_see_hide_and_own() {
    if !tools() {
        return;
    }
    let mut bus = Bus::start("names");
    for n in ["org.dbusproxy.Allowed", "org.dbusproxy.Other", "org.dbusproxy.Seen"] {
        bus.echo(n);
    }
    let p = Proxied::new(&bus, "proxy", policy());
    let a = p.address.as_str();

    // GDBus, libdbus and sd-bus all log in and make calls through it.
    let o = run(&["gdbus", "call", "-a", a, "-d", "org.dbusproxy.Allowed", "-o", "/", "-m", "org.dbusproxy.Allowed.Hi"]);
    assert!(o.status.success(), "gdbus: {}", stderr(&o));
    let o = run(&["dbus-send", &format!("--bus={a}"), "--print-reply", "--dest=org.dbusproxy.Allowed", "/", "org.dbusproxy.Allowed.Hi"]);
    assert!(o.status.success(), "dbus-send: {}", stderr(&o));
    let o = run(&["busctl", &format!("--address={a}"), "call", "org.dbusproxy.Allowed", "/", "org.dbusproxy.Allowed", "Hi"]);
    assert!(o.status.success(), "busctl: {}", stderr(&o));

    // Hidden: as if nothing owned it. Seen: there, but not callable.
    let o = run(&["dbus-send", &format!("--bus={a}"), "--print-reply", "--dest=org.dbusproxy.Other", "/", "org.dbusproxy.Other.Hi"]);
    assert!(!o.status.success() && stderr(&o).contains("ServiceUnknown"), "{}", stderr(&o));
    let o = run(&["busctl", &format!("--address={a}"), "call", "org.dbusproxy.Seen", "/", "org.dbusproxy.Seen", "Hi"]);
    assert!(!o.status.success() && (stderr(&o).contains("Access denied") || stderr(&o).contains("AccessDenied")), "{}", stderr(&o));

    let names = bus.names(a);
    assert!(names.iter().any(|n| n == "org.dbusproxy.Allowed") && names.iter().any(|n| n == "org.dbusproxy.Seen"), "{names:?}");
    assert!(!names.iter().any(|n| n == "org.dbusproxy.Other"), "{names:?}");
    // The program sees the unique names of the visible ones, not the others'.
    let uniques: Vec<&String> = names.iter().filter(|n| n.starts_with(':')).collect();
    assert_eq!(uniques.len(), 3, "the two services and itself: {names:?}");

    // Calls by unique name follow the owner.
    let owner = |name: &str| {
        let o = run(&["busctl", &format!("--address={}", bus.address), "call", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner", "s", name]);
        String::from_utf8_lossy(&o.stdout).split('"').nth(1).unwrap().to_string()
    };
    let o = run(&["gdbus", "call", "-a", a, "-d", &owner("org.dbusproxy.Allowed"), "-o", "/", "-m", "org.dbusproxy.Allowed.Hi"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let o = run(&["gdbus", "call", "-a", a, "-d", &owner("org.dbusproxy.Other"), "-o", "/", "-m", "org.dbusproxy.Other.Hi"]);
    assert!(!o.status.success() && stderr(&o).contains("NameHasNoOwner"), "{}", stderr(&o));

    // Owning: a name under org.dbusproxy.Mine.* yes, anything else no.
    let own = |name: &str| run_env(&["dbus-test-tool", "black-hole", &format!("--name={name}")], &[("DBUS_SESSION_BUS_ADDRESS", a)]);
    let mut mine = Command::new("dbus-test-tool").args(["echo", "--name=org.dbusproxy.Mine.App"]).env("DBUS_SESSION_BUS_ADDRESS", a).spawn().unwrap();
    bus.wait_for("org.dbusproxy.Mine.App");
    // And other programs on the bus reach it, under that name.
    let o = run(&["busctl", &format!("--address={}", bus.address), "call", "org.dbusproxy.Mine.App", "/", "org.dbusproxy.X", "Hi"]);
    assert!(o.status.success(), "calling the program's name: {}", stderr(&o));
    let _ = mine.kill();
    let _ = mine.wait();
    let o = own("org.dbusproxy.Allowed2");
    assert!(!o.status.success() && stderr(&o).contains("failed to take bus name"), "{}", stderr(&o));

    let denied = p.denied();
    for want in [
        "call org.dbusproxy.Other.Hi to org.dbusproxy.Other at /: name not visible",
        "call org.dbusproxy.Seen.Hi to org.dbusproxy.Seen at /: not allowed",
        "call org.freedesktop.DBus.RequestName(org.dbusproxy.Allowed2) to org.freedesktop.DBus at /org/freedesktop/DBus: may not own the name",
    ] {
        assert!(denied.iter().any(|d| d == want), "{want:?} not in {denied:#?}");
    }
}

#[test]
fn no_eavesdropping() {
    if !tools() || !have("dbus-monitor") {
        return;
    }
    let bus = Bus::start("monitor");
    let p = Proxied::new(&bus, "proxy", policy());
    let o = run(&["timeout", "3", "dbus-monitor", "--address", &p.address]);
    // dbus-monitor tries BecomeMonitor, then eavesdropping match rules.
    assert!(!o.status.success(), "dbus-monitor ran: {}", String::from_utf8_lossy(&o.stdout));
    let denied = p.denied();
    assert!(denied.iter().any(|d| d.contains("BecomeMonitor") && d.ends_with("bus method not offered")), "{denied:#?}");
    assert!(denied.iter().any(|d| d.contains("AddMatch") && d.ends_with("eavesdropping")), "{denied:#?}");
}

#[test]
fn descriptors_and_broadcasts() {
    if !tools() || !have("python3") || run(&["python3", "-c", "from gi.repository import Gio"]).status.code() != Some(0) {
        eprintln!("skipped: needs python3-gi");
        return;
    }
    let peer = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/peer.py");
    let mut bus = Bus::start("fds");
    let mut svc = Command::new("python3")
        .arg(&peer)
        .args(["service", "org.dbusproxy.Peer"])
        .env("DBUS_SESSION_BUS_ADDRESS", &bus.address)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(svc.stdout.take().unwrap()).read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "ready");
    bus.procs.0.push(svc);
    let mut p = dbus_proxy::Policy::new();
    p.talk("org.dbusproxy.Peer").unwrap();
    let p = Proxied::new(&bus, "proxy", p);
    let o = run_env(&["python3", peer.to_str().unwrap(), "client", &bus.address], &[("DBUS_SESSION_BUS_ADDRESS", &p.address)]);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{out}{}", stderr(&o));
    assert_eq!(out, "take taken\npipe from-service\nsignals org.dbusproxy.Peer.Changed\n");
}

#[test]
fn stopping_closes_connections() {
    if !have("dbus-daemon") {
        return;
    }
    let bus = Bus::start("stop");
    let mut p = Proxied::new(&bus, "proxy", policy());
    let path = p.address.strip_prefix("unix:path=").unwrap().to_string();
    // One logged in, one stuck before logging in.
    let mut logged = UnixStream::connect(&path).unwrap();
    logged.write_all(b"\0AUTH EXTERNAL 30\r\n").unwrap();
    let mut buf = [0u8; 64];
    let n = logged.read(&mut buf).unwrap();
    assert!(buf[..n].starts_with(b"OK "), "{:?}", String::from_utf8_lossy(&buf[..n]));
    let mut stuck = UnixStream::connect(&path).unwrap();
    let t = Instant::now();
    drop(p.proxy.take());
    assert!(t.elapsed() < Duration::from_secs(2), "stopping took {:?}", t.elapsed());
    stuck.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    assert_eq!(stuck.read(&mut buf).unwrap_or(0), 0);
    assert_eq!(logged.read(&mut buf).unwrap_or(0), 0);
    assert!(UnixStream::connect(&path).is_err(), "still accepting");
}

#[test]
fn probe() {
    if !have("dbus-daemon") {
        return;
    }
    let bus = Bus::start("probe");
    dbus_proxy::probe(&bus.address).unwrap();
    assert!(dbus_proxy::probe(&format!("unix:path={}", bus.dir.join("nothing").display())).is_err());
    assert!(dbus_proxy::probe("tcp:host=localhost,port=1").is_err());
}
