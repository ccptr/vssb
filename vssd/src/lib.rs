//! A filtering D-Bus proxy: gives a sandboxed program a session bus that
//! reaches only the names its [`Policy`] allows.
//!
//! The caller binds a Unix socket where the program will find its bus,
//! and [`serve`] answers every connection on it with a connection of its
//! own to the real bus, passing on only what the policy allows and
//! reporting each message it stops as an [`Event`]. The rules mean what
//! xdg-dbus-proxy's mean (see [`Policy`]), but the proxy runs in the
//! caller's process (threads, no helper binary), logs in to the bus as
//! the caller rather than passing the program's login through (so the
//! program's uid in its user namespace doesn't matter), and reports what
//! it refuses.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut policy = vssd::Policy::new();
//! policy.talk("org.freedesktop.Notifications")?.own("org.example.App")?;
//! let listener = std::os::unix::net::UnixListener::bind("/run/user/1000/app/bus")?;
//! let address = std::env::var("DBUS_SESSION_BUS_ADDRESS")?;
//! vssd::probe(&address)?;
//! let proxy = vssd::serve(listener, &address, policy, |e| eprintln!("{e}"))?;
//! // ... run the program with DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/app/bus
//! drop(proxy); // stops serving and closes every connection
//! # Ok(()) }
//! ```

mod auth;
mod conn;
mod filter;
mod names;
mod policy;
mod wire;

pub use policy::{Level, Policy, PolicyError};
pub use wire::Kind;

use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Connections served at once; more wait in the listener's backlog.
const MAX_CONNS: usize = 64;

/// Why the proxy stopped a message of the program's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The policy doesn't show the name (it looks as if nothing owns it).
    Hidden,
    /// The name is visible, but the policy doesn't allow this message.
    NotAllowed,
    /// Owning (`RequestName` and the like) a name the policy doesn't let
    /// it own.
    NotOwner,
    /// A match rule that would eavesdrop on other connections.
    Eavesdrop,
    /// A bus method the proxy doesn't offer (`BecomeMonitor`,
    /// `UpdateActivationEnvironment` and anything it doesn't know).
    BusMethod,
    /// A reply to a call the program never got.
    Unrequested,
    /// A call with no destination.
    NoDestination,
    /// Too many calls in flight.
    Limit,
    /// A message with descriptors for a program that can't take them
    /// (this one came from the bus).
    Descriptors,
}

impl Reason {
    pub fn text(self) -> &'static str {
        match self {
            Reason::Hidden => "name not visible",
            Reason::NotAllowed => "not allowed",
            Reason::NotOwner => "may not own the name",
            Reason::Eavesdrop => "eavesdropping",
            Reason::BusMethod => "bus method not offered",
            Reason::Unrequested => "reply to no call",
            Reason::NoDestination => "no destination",
            Reason::Limit => "too many calls in flight",
            Reason::Descriptors => "descriptors not negotiated",
        }
    }
}

/// A message the proxy stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    pub kind: Kind,
    pub destination: Option<String>,
    pub path: Option<String>,
    pub interface: Option<String>,
    pub member: Option<String>,
    /// For bus methods about a name (`RequestName`, `GetNameOwner` and the
    /// like), that name; for `AddMatch`, the rule.
    pub name: Option<String>,
    pub reason: Reason,
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let method = match (&self.interface, &self.member) {
            (Some(i), Some(m)) => format!("{i}.{m}"),
            (None, Some(m)) => m.clone(),
            _ => String::new(),
        };
        write!(f, "{}", self.kind.name())?;
        if !method.is_empty() {
            write!(f, " {method}")?;
        }
        if let Some(n) = &self.name {
            write!(f, "({n})")?;
        }
        if let Some(d) = &self.destination {
            write!(f, " to {d}")?;
        }
        if let Some(p) = &self.path {
            write!(f, " at {p}")?;
        }
        write!(f, ": {}", self.reason.text())
    }
}

/// What the proxy did, for logging and auditing. `conn` numbers the
/// program's connections from 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The program connected and the bus gave it this unique name.
    Connect { conn: u64, unique: String },
    /// The proxy stopped a message of the program's.
    Deny { conn: u64, denied: Denied },
    /// A connection ended; `error` says why when it wasn't a plain close.
    Close { conn: u64, error: Option<String> },
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Connect { conn, unique } => write!(f, "connection {conn}: connected as {unique}"),
            Event::Deny { conn, denied } => write!(f, "connection {conn}: blocked {denied}"),
            Event::Close { conn, error: None } => write!(f, "connection {conn}: closed"),
            Event::Close { conn, error: Some(e) } => write!(f, "connection {conn}: closed: {e}"),
        }
    }
}

type Sink = Arc<dyn Fn(&Event) + Send + Sync>;

pub(crate) struct Shared {
    upstream: String,
    policy: Arc<Policy>,
    events: Sink,
    /// Readable (at end of file) once the proxy stops.
    stop: OwnedFd,
}

/// A running proxy. Dropping it stops it: the listener stops accepting,
/// every connection closes, and its threads are joined. The socket file
/// is the caller's to remove.
pub struct Proxy {
    stop: Option<OwnedFd>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Checks that the bus at `address` is there and takes our login, so a
/// caller can fail early instead of at the program's first connection.
pub fn probe(address: &str) -> io::Result<()> {
    auth::connect(address, -1, Instant::now() + Duration::from_secs(5)).map(drop)
}

/// Serves `listener` with `policy`, connecting each program to the bus at
/// `address` (a D-Bus address: `unix:path=…` or `unix:abstract=…`
/// entries), and reports to `events`. Starts one thread to accept and one
/// per connection.
pub fn serve(listener: UnixListener, address: &str, policy: Policy, events: impl Fn(&Event) + Send + Sync + 'static) -> io::Result<Proxy> {
    let mut p = [0; 2];
    if unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let (stop, stop_w) = unsafe { (OwnedFd::from_raw_fd(p[0]), OwnedFd::from_raw_fd(p[1])) };
    listener.set_nonblocking(true)?;
    let sh = Arc::new(Shared { upstream: address.to_string(), policy: Arc::new(policy), events: Arc::new(events), stop });
    let thread = std::thread::Builder::new().name("vssd".into()).spawn(move || accept_loop(listener, sh))?;
    Ok(Proxy { stop: Some(stop_w), thread: Some(thread) })
}

fn accept_loop(listener: UnixListener, sh: Arc<Shared>) {
    let next = AtomicU64::new(1);
    let mut conns: Vec<JoinHandle<()>> = vec![];
    loop {
        let mut p = [
            libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: sh.stop.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        ];
        // Full: wait for a connection to end (checked every 100 ms).
        let full = conns.len() >= MAX_CONNS;
        let n = unsafe { libc::poll(if full { p[1..].as_mut_ptr() } else { p.as_mut_ptr() }, if full { 1 } else { 2 }, if full { 100 } else { -1 }) };
        if p[1].revents != 0 {
            break;
        }
        let (done, live): (Vec<_>, Vec<_>) = conns.into_iter().partition(|h| h.is_finished());
        conns = live;
        for h in done {
            let _ = h.join();
        }
        if n <= 0 || full {
            continue;
        }
        match listener.accept() {
            Ok((s, _)) => {
                let conn = next.fetch_add(1, Ordering::Relaxed);
                let sh2 = sh.clone();
                let spawned = std::thread::Builder::new()
                    .name(format!("vssd-{conn}"))
                    .stack_size(512 * 1024)
                    .spawn(move || conn::serve(s, conn, &sh2));
                match spawned {
                    Ok(h) => conns.push(h),
                    Err(e) => (sh.events)(&Event::Close { conn, error: Some(format!("starting its thread: {e}")) }),
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::Interrupted => {}
            // EMFILE and the like: don't spin.
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    for h in conns {
        let _ = h.join();
    }
}
