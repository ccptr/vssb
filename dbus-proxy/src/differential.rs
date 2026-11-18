//! Differential testing against xdg-dbus-proxy: the same policy and the
//! same traffic through both proxies, each in front of its own private
//! dbus-daemon with the same services, and what comes out compared.
//!
//! ```sh
//! cargo test -p dbus-proxy --lib differential -- --ignored --nocapture
//! DIFF_SEED=… DIFF_ROUND=… cargo test …   # replay one round
//! ```
//!
//! `DIFF_ROUNDS` (40) rounds of `DIFF_ACTIONS` (25) actions each, from
//! round `DIFF_FROM` (0); `DIFF_PROGRESS=1` prints each round's number. Each
//! round draws a policy (xdg-dbus-proxy's arguments, which the policy also
//! takes) and a sequence of actions: calls and bus methods from the
//! program, match rules, its broadcasts, unicast signals and stray
//! replies; broadcasts, calls to the program and owner changes from the
//! services. What is compared is what the program gets (replies, with
//! deterministic bodies; signals; calls) and what each service gets from
//! it. A round stops at its first difference; the documented ones (see
//! `known`) are counted, the rest fail the test.

use crate::filter::BUS;
use crate::wire::{self, Body, Field, Kind, Message, NO_AUTO_START, NO_REPLY_EXPECTED};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BUS_PATH: &str = "/org/freedesktop/DBus";
const REPLY_WAIT: Duration = Duration::from_millis(1500);

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<T: Copy>(&mut self, v: &[T]) -> T {
        v[self.below(v.len())]
    }

    fn chance(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
}

// --- what the actions draw from ---

/// Services: P0 owns the first two, P1 the next two, P2 one, P3 none.
const OWNED: [&[&str]; 4] = [&["org.test.A", "org.test.A.Sub"], &["org.test.B", "org.other.C"], &["org.other.C.D"], &[]];
/// Names that start unowned.
const FREE: [&str; 3] = ["org.test", "org.free", "org.test.Z"];
const PATTERNS: [&str; 13] = [
    "org.test.A",
    "org.test.A.Sub",
    "org.test.B",
    "org.other.C",
    "org.other.C.D",
    "org.test",
    "org.free",
    "org.test.Z",
    "org.test.*",
    "org.test.A.*",
    "org.other.*",
    "org.free.*",
    "org.other.C.D.*",
];
const METHODS: [&str; 7] = ["*", "org.test.I.*", "org.test.I.M", "org.test.J.N", "org.freedesktop.DBus.Properties.Get", "org.test.I.N", ""];
const RULE_PATHS: [&str; 6] = ["", "@/a", "@/a/*", "@/*", "@/", "@/a/b"];
const IFACES: [Option<&str>; 4] = [Some("org.test.I"), Some("org.test.J"), Some("org.freedesktop.DBus.Properties"), None];
const MEMBERS: [&str; 3] = ["M", "N", "Get"];
const PATHS: [&str; 5] = ["/", "/a", "/a/b", "/ab", "/c"];
const MATCHES: [&str; 13] = [
    "eavesdrop =true",
    "type='method_call', eavesdrop = 'true'",
    " eavesdrop='true',type='method_call'",
    "type='method_call',\teavesdrop\t=true",
    "type='signal'",
    "type='signal',eavesdrop=true",
    "eavesdrop=true",
    "type='method_call'",
    "type='method_call',eavesdrop='true'",
    "sender='org.test.A'",
    "arg0='eavesdrop'",
    "type='signal',sender='org.freedesktop.DBus',member='NameOwnerChanged'",
    "type='error',eavesdrop=true",
];

fn gen_policy(r: &mut Rng) -> Vec<String> {
    let mut v = vec![];
    for _ in 0..r.below(6) {
        let name = r.pick(&PATTERNS);
        let arg = match r.below(5) {
            0 => format!("--see={name}"),
            1 => format!("--talk={name}"),
            2 => format!("--own={name}"),
            k => {
                let rule = format!("{}{}", r.pick(&METHODS), r.pick(&RULE_PATHS));
                if rule.is_empty() {
                    continue;
                }
                format!("--{}={name}={rule}", if k == 3 { "call" } else { "broadcast" })
            }
        };
        v.push(arg);
    }
    v
}

#[derive(Debug, Clone, Copy)]
enum Dest {
    Name(&'static str),
    Peer(usize),
    Myself,
    NoSuchUnique,
}

#[derive(Debug, Clone, Copy)]
enum Arg {
    None,
    Name(Dest),
    Str(&'static str),
}

#[derive(Debug, Clone, Copy)]
enum Action {
    Call { dest: Dest, path: &'static str, iface: Option<&'static str>, member: &'static str, no_reply: bool, no_auto: bool },
    Bus { iface: &'static str, member: &'static str, arg: Arg },
    Emit { path: &'static str, iface: &'static str, member: &'static str },
    Unicast { dest: Dest, path: &'static str, iface: &'static str, member: &'static str },
    StrayReply { peer: usize, serial: u32 },
    PeerEmit { peer: usize, path: &'static str, iface: &'static str, member: &'static str },
    PeerCall { peer: usize, twice: bool },
    PeerOwn { peer: usize, name: &'static str, release: bool },
    /// A service calls another; nothing of it may reach the program.
    PeerToPeer { from: usize, to: usize },
}

fn gen_dest(r: &mut Rng) -> Dest {
    match r.below(10) {
        0..=4 => Dest::Name(r.pick(&PATTERNS[..8])),
        5 => Dest::Name("org.nonexistent.X"),
        6 | 7 => Dest::Peer(r.below(4)),
        8 => Dest::Myself,
        _ => Dest::NoSuchUnique,
    }
}

const BUS_METHODS: [(&str, &str, u8); 24] = [
    // (interface, member, argument: 0 none, 1 a name, 2 a match rule)
    (BUS, "RequestName", 1),
    (BUS, "ReleaseName", 1),
    (BUS, "NameHasOwner", 1),
    (BUS, "GetNameOwner", 1),
    (BUS, "ListQueuedOwners", 1),
    (BUS, "StartServiceByName", 1),
    (BUS, "GetConnectionUnixUser", 1),
    (BUS, "GetConnectionUnixProcessID", 1),
    (BUS, "GetConnectionCredentials", 1),
    (BUS, "ListNames", 0),
    (BUS, "ListActivatableNames", 0),
    (BUS, "GetId", 0),
    (BUS, "AddMatch", 2),
    (BUS, "RemoveMatch", 2),
    (BUS, "UpdateActivationEnvironment", 0),
    (BUS, "ReloadConfig", 0),
    (BUS, "Hello", 0),
    (BUS, "NoSuchMethod", 0),
    ("org.freedesktop.DBus.Introspectable", "Introspect", 0),
    ("org.freedesktop.DBus.Peer", "Ping", 0),
    ("org.freedesktop.DBus.Peer", "GetMachineId", 0),
    ("org.freedesktop.DBus.Properties", "Get", 0),
    ("org.freedesktop.DBus.Monitoring", "BecomeMonitor", 0),
    ("org.freedesktop.DBus.Debug.Stats", "GetStats", 0),
];

fn gen_action(r: &mut Rng) -> Action {
    let sig = |r: &mut Rng| (r.pick(&PATHS), r.pick(&IFACES).unwrap_or("org.test.I"), r.pick(&MEMBERS));
    match r.below(20) {
        0..=6 => Action::Call {
            dest: gen_dest(r),
            path: r.pick(&PATHS),
            iface: r.pick(&IFACES),
            member: r.pick(&MEMBERS),
            no_reply: r.chance(10),
            no_auto: r.chance(20),
        },
        7..=11 => {
            let (iface, member, kind) = r.pick(&BUS_METHODS);
            let arg = match kind {
                1 if r.chance(15) => Arg::Name(Dest::Name(r.pick(&FREE))),
                1 => Arg::Name(gen_dest(r)),
                2 => Arg::Str(r.pick(&MATCHES)),
                _ => Arg::None,
            };
            Action::Bus { iface, member, arg }
        }
        12 => {
            let (path, iface, member) = sig(r);
            Action::Emit { path, iface, member }
        }
        13 => {
            let (path, iface, member) = sig(r);
            Action::Unicast { dest: gen_dest(r), path, iface, member }
        }
        14 => Action::StrayReply { peer: r.below(4), serial: 1 + r.below(8) as u32 },
        15 | 16 => {
            let (path, iface, member) = sig(r);
            Action::PeerEmit { peer: r.below(4), path, iface, member }
        }
        17 => Action::PeerCall { peer: r.below(4), twice: r.chance(30) },
        18 if r.chance(50) => Action::PeerToPeer { from: r.below(4), to: r.below(4) },
        _ => {
            let names: Vec<&'static str> = PATTERNS[..8].to_vec();
            Action::PeerOwn { peer: r.below(4), name: r.pick(&names), release: r.chance(40) }
        }
    }
}

// --- raw connections ---

fn hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

struct Raw {
    s: UnixStream,
    buf: Vec<u8>,
    serial: u32,
    unique: String,
    inbox: Vec<Message>,
    /// A service: answers every call with an empty reply.
    peer: bool,
    closed: bool,
}

impl Raw {
    fn connect(path: &Path, peer: bool) -> Raw {
        let deadline = Instant::now() + Duration::from_secs(5);
        let s = loop {
            match UnixStream::connect(path) {
                Ok(s) => break s,
                Err(e) if Instant::now() < deadline => {
                    let _ = e;
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("connecting to {}: {e}", path.display()),
            }
        };
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let uid = unsafe { libc::geteuid() }.to_string();
        (&s).write_all(format!("\0AUTH EXTERNAL {}\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n", hex(&uid)).as_bytes()).unwrap();
        let mut got = vec![];
        let mut b = [1u8];
        while got.windows(2).filter(|w| w == b"\r\n").count() < 2 {
            assert_eq!((&s).read(&mut b).unwrap(), 1, "closed during the login");
            got.push(b[0]);
        }
        assert!(got.starts_with(b"OK "), "{}", String::from_utf8_lossy(&got));
        s.set_nonblocking(true).unwrap();
        let mut r = Raw { s, buf: vec![], serial: 0, unique: String::new(), inbox: vec![], peer, closed: false };
        let hello = r.call(BUS, BUS_PATH, Some(BUS), "Hello", "", &Body::default(), 0);
        r.unique = r.wait(hello).and_then(|m| m.arg0().map(String::from)).expect("Hello");
        r
    }

    fn send(&mut self, kind: Kind, flags: u8, fields: &[Field], sig: &str, body: &Body) -> u32 {
        self.serial += 1;
        let m = wire::build(kind, flags, self.serial, fields, sig, body).unwrap();
        let mut rest = &m.data[..];
        let deadline = Instant::now() + Duration::from_secs(10);
        while !rest.is_empty() && !self.closed {
            match (&self.s).write(rest) {
                Ok(n) => rest = &rest[n..],
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Take in what the other side is sending meanwhile (left
                    // for read() to handle), so neither waits for the other.
                    let mut chunk = [0u8; 65536];
                    if let Ok(n) = (&self.s).read(&mut chunk) {
                        self.buf.extend_from_slice(&chunk[..n]);
                    }
                    assert!(Instant::now() < deadline, "stuck sending to {}", self.unique);
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(_) => self.closed = true,
            }
        }
        self.serial
    }

    #[allow(clippy::too_many_arguments)]
    fn call(&mut self, dest: &str, path: &str, iface: Option<&str>, member: &str, sig: &str, body: &Body, flags: u8) -> u32 {
        let mut f = vec![Field::Path(path), Field::Member(member), Field::Destination(dest)];
        if let Some(i) = iface {
            f.push(Field::Interface(i));
        }
        self.send(Kind::Call, flags, &f, sig, body)
    }

    /// Reads what has arrived; services answer calls as they come.
    fn read(&mut self) {
        let mut chunk = [0u8; 65536];
        loop {
            match (&self.s).read(&mut chunk) {
                Ok(0) => {
                    self.closed = true;
                    break;
                }
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        while self.buf.len() >= 16 {
            let Ok(len) = wire::message_len(&self.buf) else {
                self.closed = true;
                return;
            };
            if self.buf.len() < len {
                break;
            }
            let data: Vec<u8> = self.buf.drain(..len).collect();
            let m = Message::parse(data).expect("the bus or a proxy sent an invalid message");
            if self.peer && m.expects_reply() {
                let sender = m.sender.clone().unwrap_or_default();
                self.send(Kind::Return, NO_REPLY_EXPECTED, &[Field::ReplySerial(m.serial), Field::Destination(&sender)], "", &Body::default());
            }
            self.inbox.push(m);
        }
    }

    fn take_reply(&mut self, serial: u32) -> Option<Message> {
        let i = self.inbox.iter().position(|m| m.reply_serial == Some(serial))?;
        Some(self.inbox.remove(i))
    }

    /// Waits for a reply on this connection alone (setup, where only the
    /// bus answers).
    fn wait(&mut self, serial: u32) -> Option<Message> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && !self.closed {
            self.read();
            if let Some(m) = self.take_reply(serial) {
                return Some(m);
            }
            let mut p = libc::pollfd { fd: self.s.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            unsafe { libc::poll(&mut p, 1, 10) };
        }
        None
    }
}

// --- a world: a bus, its services, a proxy and the program ---

enum Front {
    Xdg(Child),
    Ours(#[allow(dead_code)] crate::Proxy),
}

struct World {
    daemon: Child,
    front: Option<Front>,
    peers: Vec<Raw>,
    client: Raw,
}

impl Drop for World {
    fn drop(&mut self) {
        if let Some(Front::Xdg(c)) = &mut self.front {
            let _ = c.kill();
            let _ = c.wait();
        }
        self.front = None;
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

fn start_daemon(dir: &Path) -> Child {
    let conf = dir.join("bus.conf");
    std::fs::write(
        &conf,
        format!(
            r#"<busconfig><type>session</type><listen>unix:path={}</listen><auth>EXTERNAL</auth>
<policy context="default"><allow send_destination="*" eavesdrop="true"/><allow eavesdrop="true"/><allow own="*"/></policy></busconfig>"#,
            dir.join("bus").display()
        ),
    )
    .unwrap();
    let mut d = Command::new("dbus-daemon")
        .arg(format!("--config-file={}", conf.display()))
        .args(["--nofork", "--print-address=1"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = [0u8; 1];
    let mut out = d.stdout.take().unwrap();
    while out.read(&mut line).unwrap_or(0) == 1 && line[0] != b'\n' {}
    d
}

impl World {
    fn new(xdg: bool, dir: &Path, policy: &[String]) -> World {
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();
        let daemon = start_daemon(dir);
        let bus = dir.join("bus");
        let mut peers = vec![];
        for names in OWNED {
            let mut p = Raw::connect(&bus, true);
            for n in names {
                let mut body = Body::default();
                body.str(n).u32(4);
                let s = p.call(BUS, BUS_PATH, Some(BUS), "RequestName", "su", &body, 0);
                assert_eq!(p.wait(s).and_then(|m| m.arg0_u32()), Some(1), "{n}");
            }
            let mut body = Body::default();
            body.str("type='signal'");
            let s = p.call(BUS, BUS_PATH, Some(BUS), "AddMatch", "s", &body, 0);
            p.wait(s).unwrap();
            peers.push(p);
        }
        let address = format!("unix:path={}", bus.display());
        let socket = dir.join("proxy");
        let front = if xdg {
            let c = Command::new("xdg-dbus-proxy").arg(&address).arg(&socket).arg("--filter").args(policy).stderr(Stdio::null()).spawn().unwrap();
            Front::Xdg(c)
        } else {
            let mut p = crate::Policy::new();
            for a in policy {
                p.add(a).unwrap();
            }
            Front::Ours(crate::serve(UnixListener::bind(&socket).unwrap(), &address, p, |_| {}).unwrap())
        };
        let mut client = Raw::connect(&socket, false);
        let mut body = Body::default();
        body.str("type='signal'");
        let s = client.call(BUS, BUS_PATH, Some(BUS), "AddMatch", "s", &body, 0);
        client.wait(s).unwrap();
        let mut w = World { daemon, front: Some(front), peers, client };
        w.barrier();
        w
    }

    fn conn(&mut self, who: usize) -> &mut Raw {
        if who == 0 { &mut self.client } else { &mut self.peers[who - 1] }
    }

    /// Reads from every connection until `done` holds or time is up.
    fn pump(&mut self, timeout: Duration, mut done: impl FnMut(&World) -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            self.client.read();
            for p in &mut self.peers {
                p.read();
            }
            if done(self) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            let mut fds: Vec<libc::pollfd> = std::iter::once(&self.client)
                .chain(&self.peers)
                .map(|c| libc::pollfd { fd: c.s.as_raw_fd(), events: libc::POLLIN, revents: 0 })
                .collect();
            unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, 10) };
        }
    }

    fn wait_reply(&mut self, who: usize, serial: u32, timeout: Duration) -> Option<Message> {
        self.pump(timeout, |w| {
            let c = if who == 0 { &w.client } else { &w.peers[who - 1] };
            c.closed || c.inbox.iter().any(|m| m.reply_serial == Some(serial))
        });
        self.conn(who).take_reply(serial)
    }

    /// Everything sent so far has arrived wherever it goes: a round trip
    /// to the bus from the program, then from each service.
    fn barrier(&mut self) {
        for who in 0..=self.peers.len() {
            if self.conn(who).closed {
                continue;
            }
            let s = self.conn(who).call(BUS, BUS_PATH, Some(BUS), "GetId", "", &Body::default(), 0);
            self.wait_reply(who, s, Duration::from_secs(3));
        }
    }

    fn resolve(&self, d: Dest) -> String {
        match d {
            Dest::Name(n) => n.into(),
            Dest::Peer(i) => self.peers[i].unique.clone(),
            Dest::Myself => self.client.unique.clone(),
            Dest::NoSuchUnique => ":1.999".into(),
        }
    }

    fn label(&self, s: &str) -> String {
        if s == self.client.unique {
            return "SELF".into();
        }
        if let Some(i) = self.peers.iter().position(|p| p.unique == s) {
            return format!("P{i}");
        }
        if s.starts_with(':') { "U?".into() } else { s.into() }
    }

    fn reply(&mut self, serial: u32, member: &str) -> String {
        let Some(m) = self.wait_reply(0, serial, REPLY_WAIT) else {
            return if self.client.closed { "reply: connection closed".into() } else { "reply: none".into() };
        };
        if m.kind == Kind::Error {
            return format!("reply: error {}", m.error_name.as_deref().unwrap_or("?"));
        }
        // Bodies that differ between two buses anyway.
        // (The proxies' own process ids differ too.)
        let opaque = ["GetId", "Introspect", "GetMachineId", "Get", "GetAll", "GetConnectionCredentials", "GetStats", "GetConnectionUnixProcessID"];
        let body = if opaque.contains(&member) {
            m.signature.clone()
        } else {
            match m.signature.as_str() {
                "s" => self.label(m.arg0().unwrap_or("")),
                "u" | "b" => m.arg0_u32().map(|v| v.to_string()).unwrap_or_default(),
                "as" => {
                    let mut v: Vec<String> = m.string_array().unwrap_or_default().iter().map(|n| self.label(n)).collect();
                    v.sort();
                    v.join(",")
                }
                s => s.to_string(),
            }
        };
        format!("reply: ok {body}")
    }

    fn describe(&self, who: &str, m: &Message) -> String {
        let from = self.label(m.sender.as_deref().unwrap_or(""));
        let to = m.destination.as_deref().map(|d| format!(" to {}", self.label(d))).unwrap_or_default();
        let what = format!("{}.{}", m.interface.as_deref().unwrap_or("-"), m.member.as_deref().unwrap_or("-"));
        let args = m.strings(m.signature.len().min(3)).map(|a| a.iter().map(|s| self.label(s)).collect::<Vec<_>>().join(",")).unwrap_or_default();
        let path = m.path.as_deref().unwrap_or("");
        match m.kind {
            Kind::Return | Kind::Error => format!("{who} got {} {}{to} from {from}", m.kind.name(), m.error_name.as_deref().unwrap_or("")),
            _ => format!("{who} got {} {what} {path}{to} from {from} ({args})", m.kind.name()),
        }
    }

    /// What arrived since the action began, in no particular order.
    fn arrived(&mut self) -> Vec<String> {
        let mut v = vec![];
        for m in &self.client.inbox {
            v.push(self.describe("program", m));
        }
        for (i, p) in self.peers.iter().enumerate() {
            for m in &p.inbox {
                if m.sender.as_deref() == Some(&self.client.unique) {
                    v.push(self.describe(&format!("P{i}"), m));
                }
            }
        }
        if self.client.closed {
            v.push("program's connection closed".into());
        }
        v
    }

    fn run(&mut self, a: &Action) -> Vec<String> {
        self.client.inbox.clear();
        for p in &mut self.peers {
            p.inbox.clear();
        }
        let mut obs = vec![];
        if self.client.closed {
            return vec!["program's connection closed".into()];
        }
        match *a {
            Action::Call { dest, path, iface, member, no_reply, no_auto } => {
                let d = self.resolve(dest);
                let flags = if no_reply { NO_REPLY_EXPECTED } else { 0 } | if no_auto { NO_AUTO_START } else { 0 };
                let s = self.client.call(&d, path, iface, member, "", &Body::default(), flags);
                if !no_reply {
                    obs.push(self.reply(s, member));
                }
            }
            Action::Bus { iface, member, arg } => {
                let mut body = Body::default();
                let sig = match (member, arg) {
                    ("RequestName" | "StartServiceByName", Arg::Name(d)) => {
                        body.str(&self.resolve(d)).u32(if member == "RequestName" { 4 } else { 0 });
                        "su"
                    }
                    (_, Arg::Name(d)) => {
                        body.str(&self.resolve(d));
                        "s"
                    }
                    (_, Arg::Str(s)) => {
                        body.str(s);
                        "s"
                    }
                    ("UpdateActivationEnvironment", _) => {
                        body.u32(0).pad(8);
                        "a{ss}"
                    }
                    ("BecomeMonitor", _) => {
                        body.strs(&[]).u32(0);
                        "asu"
                    }
                    ("Get", _) => {
                        body.str(BUS).str("Features");
                        "ss"
                    }
                    _ => "",
                };
                let s = self.client.call(BUS, BUS_PATH, Some(iface), member, sig, &body, 0);
                obs.push(self.reply(s, member));
            }
            Action::Emit { path, iface, member } => {
                self.client.send(Kind::Signal, 0, &[Field::Path(path), Field::Interface(iface), Field::Member(member)], "", &Body::default());
            }
            Action::Unicast { dest, path, iface, member } => {
                let d = self.resolve(dest);
                let f = [Field::Path(path), Field::Interface(iface), Field::Member(member), Field::Destination(&d)];
                self.client.send(Kind::Signal, 0, &f, "", &Body::default());
            }
            Action::StrayReply { peer, serial } => {
                let d = self.peers[peer].unique.clone();
                self.client.send(Kind::Return, 0, &[Field::ReplySerial(serial), Field::Destination(&d)], "", &Body::default());
            }
            Action::PeerEmit { peer, path, iface, member } => {
                self.peers[peer].send(Kind::Signal, 0, &[Field::Path(path), Field::Interface(iface), Field::Member(member)], "", &Body::default());
            }
            Action::PeerCall { peer, twice } => {
                let me = self.client.unique.clone();
                let from = self.peers[peer].unique.clone();
                let s = self.peers[peer].call(&me, "/x", Some("org.test.I"), "M", "", &Body::default(), 0);
                let got = self.pump(REPLY_WAIT, |w| w.client.inbox.iter().any(|m| m.kind == Kind::Call && m.serial == s && m.sender.as_deref() == Some(&from)));
                obs.push(format!("program got the call: {got}"));
                if got {
                    self.client.inbox.retain(|m| !(m.kind == Kind::Call && m.serial == s));
                    for _ in 0..if twice { 2 } else { 1 } {
                        self.client.send(Kind::Return, 0, &[Field::ReplySerial(s), Field::Destination(&from)], "", &Body::default());
                    }
                }
                let r = self.wait_reply(peer + 1, s, REPLY_WAIT);
                obs.push(format!("service got a reply: {}", r.map(|m| m.kind.name()).unwrap_or("none")));
            }
            Action::PeerToPeer { from, to } => {
                let d = self.peers[to].unique.clone();
                let s = self.peers[from].call(&d, "/p", Some("org.test.Private"), "Secret", "", &Body::default(), 0);
                self.wait_reply(from + 1, s, REPLY_WAIT);
            }
            Action::PeerOwn { peer, name, release } => {
                let mut body = Body::default();
                body.str(name);
                let (member, sig) = if release { ("ReleaseName", "s") } else { ("RequestName", "su") };
                if !release {
                    body.u32(4);
                }
                let s = self.peers[peer].call(BUS, BUS_PATH, Some(BUS), member, sig, &body, 0);
                self.wait_reply(peer + 1, s, Duration::from_secs(3));
            }
        }
        self.barrier();
        obs.extend(self.arrived());
        obs.sort();
        obs
    }
}

/// Differences that are deliberate (each is listed in the README), and
/// only where ours is the stricter: everything we let through,
/// xdg-dbus-proxy does too, apart from our own error replies.
fn known(before: &[Action], a: &Action, xdg: &[String], ours: &[String]) -> Option<&'static str> {
    let member = if let Action::Bus { member, .. } = *a { member } else { "" };
    // A line we may show where xdg-dbus-proxy shows more: an error, a "no
    // owner", or fewer names in a list.
    let less = |l: &String| {
        xdg.contains(l)
            || l.starts_with("reply: error")
            || (member == "NameHasOwner" && l == "reply: ok 0")
            || (member == "ListNames"
                && l.strip_prefix("reply: ok ").is_some_and(|ns| {
                    xdg.iter().filter_map(|x| x.strip_prefix("reply: ok ")).any(|xs| ns.split(',').all(|n| xs.split(',').any(|x| x == n)))
                }))
    };
    if !ours.iter().all(less) {
        return None;
    }
    let released = |p: usize| before.iter().any(|b| matches!(b, Action::PeerOwn { peer, release: true, .. } if *peer == p));
    match *a {
        Action::Bus { member: "AddMatch", arg: Arg::Str(rule), .. } if rule.contains("eavesdrop") => {
            Some("any rule mentioning eavesdrop is refused, not only eavesdrop=")
        }
        // xdg-dbus-proxy keeps a unique name's level after it gives up the
        // name that earned it; ours follows the current owner.
        Action::Call { dest: Dest::Peer(p), .. }
        | Action::Unicast { dest: Dest::Peer(p), .. }
        | Action::PeerEmit { peer: p, .. }
        | Action::Bus { arg: Arg::Name(Dest::Peer(p)), .. }
            if released(p) =>
        {
            Some("a service's unique name loses what its released name gave it")
        }
        Action::Bus { member: "ListNames", .. } if (0..4).any(released) => Some("a service's unique name loses what its released name gave it"),
        _ => None,
    }
}

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

#[test]
#[ignore = "needs dbus-daemon and xdg-dbus-proxy; run with --ignored"]
fn against_xdg_dbus_proxy() {
    let have = |t: &str| Command::new("sh").args(["-c", &format!("command -v {t}")]).stdout(Stdio::null()).status().is_ok_and(|s| s.success());
    assert!(have("dbus-daemon") && have("xdg-dbus-proxy"), "needs dbus-daemon and xdg-dbus-proxy");
    let seed = env("DIFF_SEED", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64 | 1);
    let (rounds, actions) = (env("DIFF_ROUNDS", 40), env("DIFF_ACTIONS", 25) as usize);
    let only = std::env::var("DIFF_ROUND").ok().and_then(|v| v.parse::<u64>().ok());
    eprintln!("DIFF_SEED={seed}");
    let base = std::env::temp_dir().join(format!("dbus-proxy-diff-{}", std::process::id()));
    let (mut found, mut known_seen, mut compared) = (vec![], std::collections::BTreeMap::new(), 0);
    for round in env("DIFF_FROM", 0)..rounds {
        if only.is_some_and(|o| o != round) {
            continue;
        }
        // splitmix64, so neighbouring rounds draw unrelated sequences.
        let mut z = seed.wrapping_add((round + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        let mut r = Rng((z ^ (z >> 31)) | 1);
        let policy = gen_policy(&mut r);
        let acts: Vec<Action> = (0..actions).map(|_| gen_action(&mut r)).collect();
        if std::env::var_os("DIFF_PROGRESS").is_some() {
            eprintln!("round {round}");
        }
        let mut x = World::new(true, &base.join("xdg"), &policy);
        let mut o = World::new(false, &base.join("ours"), &policy);
        for (i, a) in acts.iter().enumerate() {
            let (ox, oo) = (x.run(a), o.run(a));
            compared += 1;
            if ox == oo {
                continue;
            }
            match known(&acts[..i], a, &ox, &oo) {
                Some(why) => *known_seen.entry(why).or_insert(0) += 1,
                None => {
                    let only_x: Vec<&String> = ox.iter().filter(|l| !oo.contains(l)).collect();
                    let only_o: Vec<&String> = oo.iter().filter(|l| !ox.contains(l)).collect();
                    eprintln!("DIFF {a:?} | xdg {only_x:?} | ours {only_o:?} | policy {policy:?}");
                    let steps: Vec<String> = acts[..i].iter().map(|a| format!("    {a:?}")).collect();
                    let report = format!(
                        "round {round} (DIFF_SEED={seed} DIFF_ROUND={round}), action {i}\n  policy: {policy:?}\n  before:\n{}\n  action: {a:?}\n  only xdg-dbus-proxy: {only_x:#?}\n  only ours: {only_o:#?}",
                        steps.join("\n")
                    );
                    eprintln!("\n{report}\n");
                    found.push(report);
                }
            }
            break; // the two may have diverged from here on
        }
    }
    let _ = std::fs::remove_dir_all(&base);
    eprintln!("{compared} actions compared; known differences: {known_seen:?}");
    assert!(found.is_empty(), "{} unexplained differences", found.len());
}
