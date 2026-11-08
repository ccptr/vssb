//! The login on both sides, and connecting to the bus.
//!
//! The proxy doesn't pass the program's login through: it logs in to
//! the bus as itself (`EXTERNAL`, our uid) and accepts the program's
//! `EXTERNAL` login whatever uid it claims, once the socket's peer
//! credentials say it runs as our user. So a program whose uid inside a
//! user namespace differs from ours (root in the sandbox, say) still
//! gets a bus.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Instant;

/// Longest login line either side may send.
const MAX_LINE: usize = 16 * 1024;
/// Most commands a program may send before `BEGIN`.
const MAX_COMMANDS: usize = 32;

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "the login took too long")
}

fn stopped() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "the proxy is stopping")
}

/// Waits until `fd` is ready for `events`, the deadline passes (an
/// error), or `stop` becomes readable (an error).
pub(crate) fn wait(fd: RawFd, events: i16, stop: RawFd, deadline: Instant) -> io::Result<()> {
    loop {
        let ms = deadline.saturating_duration_since(Instant::now()).as_millis().min(i32::MAX as u128) as i32;
        if ms == 0 {
            return Err(timed_out());
        }
        let mut p = [libc::pollfd { fd, events, revents: 0 }, libc::pollfd { fd: stop, events: libc::POLLIN, revents: 0 }];
        let n = unsafe { libc::poll(p.as_mut_ptr(), 2, ms) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if p[1].revents != 0 {
            return Err(stopped());
        }
        if p[0].revents != 0 {
            return Ok(());
        }
    }
}

/// Reads and writes the line-based login, without blocking past the
/// deadline.
struct Lines<'a> {
    s: &'a UnixStream,
    buf: Vec<u8>,
    stop: RawFd,
    deadline: Instant,
}

impl Lines<'_> {
    fn fill(&mut self) -> io::Result<()> {
        let mut chunk = [0u8; 4096];
        loop {
            match (&mut &*self.s).read(&mut chunk) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the peer closed the connection")),
                Ok(n) => {
                    self.buf.extend_from_slice(&chunk[..n]);
                    return Ok(());
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => wait(self.s.as_raw_fd(), libc::POLLIN, self.stop, self.deadline)?,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    fn byte(&mut self) -> io::Result<u8> {
        while self.buf.is_empty() {
            self.fill()?;
        }
        Ok(self.buf.remove(0))
    }

    fn line(&mut self) -> io::Result<String> {
        loop {
            if let Some(i) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let line: Vec<u8> = self.buf.drain(..i + 2).take(i).collect();
                return String::from_utf8(line)
                    .ok()
                    .filter(|l| l.bytes().all(|c| (0x20..0x7f).contains(&c)))
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "login line is not printable ASCII"));
            }
            if self.buf.len() > MAX_LINE {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "login line too long"));
            }
            self.fill()?;
        }
    }

    fn send(&mut self, line: &[u8]) -> io::Result<()> {
        let mut rest = line;
        while !rest.is_empty() {
            match (&mut &*self.s).write(rest) {
                Ok(n) => rest = &rest[n..],
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => wait(self.s.as_raw_fd(), libc::POLLOUT, self.stop, self.deadline)?,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

fn hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// A logged-in connection to the bus (before `Hello`).
pub(crate) struct Upstream {
    pub stream: UnixStream,
    pub guid: String,
    pub unix_fds: bool,
}

enum Target {
    Path(PathBuf),
    Abstract(Vec<u8>),
}

fn unescape(v: &str) -> Option<Vec<u8>> {
    let b = v.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            out.push(u8::from_str_radix(std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(out)
}

/// The sockets a bus address names, in order: its `unix:path=` and
/// `unix:abstract=` entries (other transports are skipped).
fn targets(address: &str) -> Vec<Target> {
    use std::os::unix::ffi::OsStringExt;
    let mut v = vec![];
    for entry in address.split(';') {
        let Some(params) = entry.strip_prefix("unix:") else { continue };
        for kv in params.split(',') {
            match kv.split_once('=') {
                Some(("path", p)) => v.extend(unescape(p).map(|p| Target::Path(std::ffi::OsString::from_vec(p).into()))),
                Some(("abstract", a)) => v.extend(unescape(a).map(Target::Abstract)),
                _ => {}
            }
        }
    }
    v
}

fn connect_target(t: &Target) -> io::Result<UnixStream> {
    match t {
        Target::Path(p) => UnixStream::connect(p),
        Target::Abstract(name) => {
            use std::os::linux::net::SocketAddrExt;
            UnixStream::connect_addr(&std::os::unix::net::SocketAddr::from_abstract_name(name)?)
        }
    }
}

/// Connects to the bus at `address` and logs in as ourselves.
pub(crate) fn connect(address: &str, stop: RawFd, deadline: Instant) -> io::Result<Upstream> {
    let mut last = io::Error::new(io::ErrorKind::InvalidInput, format!("no unix: socket in the bus address {address:?}"));
    for t in targets(address) {
        match connect_target(&t) {
            Ok(s) => return login(s, stop, deadline),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn login(stream: UnixStream, stop: RawFd, deadline: Instant) -> io::Result<Upstream> {
    stream.set_nonblocking(true)?;
    let refused = |what: &str, line: &str| io::Error::new(io::ErrorKind::PermissionDenied, format!("the bus answered {what} with {line:?}"));
    let mut l = Lines { s: &stream, buf: vec![], stop, deadline };
    let uid = unsafe { libc::geteuid() }.to_string();
    l.send(format!("\0AUTH EXTERNAL {}\r\n", hex(&uid)).as_bytes())?;
    let ok = l.line()?;
    let guid = match ok.strip_prefix("OK ") {
        Some(g) if !g.is_empty() && g.bytes().all(|c| c.is_ascii_hexdigit()) => g.to_string(),
        _ => return Err(refused("our login", &ok)),
    };
    l.send(b"NEGOTIATE_UNIX_FD\r\n")?;
    let fds = l.line()?;
    let unix_fds = match fds.as_str() {
        "AGREE_UNIX_FD" => true,
        f if f.starts_with("ERROR") => false,
        f => return Err(refused("NEGOTIATE_UNIX_FD", f)),
    };
    l.send(b"BEGIN\r\n")?;
    if !l.buf.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "the bus sent data before Hello"));
    }
    Ok(Upstream { stream, guid, unix_fds })
}

/// The program's login. Returns whether it negotiated descriptor passing,
/// and what it sent after `BEGIN` (the start of its first message).
pub(crate) fn accept(stream: &UnixStream, guid: &str, unix_fds: bool, stop: RawFd, deadline: Instant) -> io::Result<(bool, Vec<u8>)> {
    stream.set_nonblocking(true)?;
    let mut l = Lines { s: stream, buf: vec![], stop, deadline };
    if l.byte()? != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "the program's login did not start with a NUL byte"));
    }
    let ok = format!("OK {guid}\r\n");
    let (mut authed, mut want_data, mut agreed) = (false, false, false);
    // `EXTERNAL` data is the uid the client claims, in hex. Any uid will
    // do (the peer credentials are what counts), but it must be one.
    let uid_ok = |d: &str| unhex(d).is_some_and(|b| !b.is_empty() && b.iter().all(u8::is_ascii_digit));
    for _ in 0..MAX_COMMANDS {
        let line = l.line()?;
        let (cmd, arg) = line.split_once(' ').unwrap_or((&line, ""));
        let reply: &[u8] = match (cmd, authed) {
            ("AUTH", false) => {
                let (mech, data) = arg.split_once(' ').unwrap_or((arg, ""));
                if mech != "EXTERNAL" {
                    b"REJECTED EXTERNAL\r\n"
                } else if data.is_empty() {
                    want_data = true;
                    b"DATA\r\n"
                } else if uid_ok(data) {
                    authed = true;
                    ok.as_bytes()
                } else {
                    b"REJECTED EXTERNAL\r\n"
                }
            }
            ("DATA", false) if want_data => {
                want_data = false;
                if arg.is_empty() || uid_ok(arg) {
                    authed = true;
                    ok.as_bytes()
                } else {
                    b"REJECTED EXTERNAL\r\n"
                }
            }
            ("CANCEL" | "ERROR", false) => {
                want_data = false;
                b"REJECTED EXTERNAL\r\n"
            }
            ("NEGOTIATE_UNIX_FD", true) if unix_fds => {
                agreed = true;
                b"AGREE_UNIX_FD\r\n"
            }
            ("NEGOTIATE_UNIX_FD", true) => b"ERROR \"the bus does not pass descriptors\"\r\n",
            ("BEGIN", true) => return Ok((agreed, std::mem::take(&mut l.buf))),
            ("BEGIN", false) => return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the program sent BEGIN before logging in")),
            _ => b"ERROR \"unknown command\"\r\n",
        };
        l.send(reply)?;
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "too many login commands"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    /// Runs `accept` against a client that sends `input`; returns what the
    /// proxy answered and the result.
    fn serve(input: &[u8], unix_fds: bool) -> (String, io::Result<(bool, Vec<u8>)>) {
        let (a, mut b) = UnixStream::pair().unwrap();
        b.write_all(input).unwrap();
        b.shutdown(std::net::Shutdown::Write).unwrap();
        let r = accept(&a, "0123abcd", unix_fds, -1, soon());
        drop(a);
        let mut out = String::new();
        b.read_to_string(&mut out).unwrap();
        (out, r)
    }

    #[test]
    fn accepts_any_claimed_uid() {
        // Root inside a user namespace: uid 0 ("30").
        let (out, r) = serve(b"\0AUTH EXTERNAL 30\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\nl\x01\x00\x01", true);
        assert_eq!(out, "OK 0123abcd\r\nAGREE_UNIX_FD\r\n");
        assert_eq!(r.unwrap(), (true, b"l\x01\x00\x01".to_vec()));
        // The two-step form, then no descriptors on offer.
        let (out, r) = serve(b"\0AUTH EXTERNAL\r\nDATA\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n", false);
        assert_eq!(out, "DATA\r\nOK 0123abcd\r\nERROR \"the bus does not pass descriptors\"\r\n");
        assert_eq!(r.unwrap(), (false, vec![]));
    }

    #[test]
    fn refuses_other_logins() {
        let (out, r) = serve(b"\0AUTH\r\nAUTH ANONYMOUS\r\nAUTH EXTERNAL 7a7a\r\nBEGIN\r\n", true);
        assert_eq!(out, "REJECTED EXTERNAL\r\nREJECTED EXTERNAL\r\nREJECTED EXTERNAL\r\n");
        assert!(r.is_err());
        assert!(serve(b"AUTH EXTERNAL 30\r\n", true).1.is_err(), "no NUL byte");
        assert!(serve(&[&b"\0"[..], &[b'x'; MAX_LINE + 10]].concat(), true).1.is_err());
        assert!(serve(&[&b"\0"[..], &b"FOO\r\n".repeat(MAX_COMMANDS + 1)].concat(), true).1.is_err());
    }

    #[test]
    fn logs_in_to_a_bus() {
        let (a, b) = UnixStream::pair().unwrap();
        let bus = std::thread::spawn(move || {
            let mut l = Lines { s: &b, buf: vec![], stop: -1, deadline: soon() };
            assert_eq!(l.byte().unwrap(), 0);
            let uid = unsafe { libc::geteuid() }.to_string();
            assert_eq!(l.line().unwrap(), format!("AUTH EXTERNAL {}", hex(&uid)));
            l.send(b"OK 00ff\r\n").unwrap();
            assert_eq!(l.line().unwrap(), "NEGOTIATE_UNIX_FD");
            l.send(b"AGREE_UNIX_FD\r\n").unwrap();
            assert_eq!(l.line().unwrap(), "BEGIN");
        });
        let up = login(a, -1, soon()).unwrap();
        bus.join().unwrap();
        assert_eq!((up.guid.as_str(), up.unix_fds), ("00ff", true));
    }

    #[test]
    fn addresses() {
        let t = targets("tcp:host=x;unix:abstract=/tmp/dbus-%41b,guid=1;unix:path=/run/user/1/bus");
        assert!(matches!(&t[0], Target::Abstract(a) if a == b"/tmp/dbus-Ab"));
        assert!(matches!(&t[1], Target::Path(p) if p == std::path::Path::new("/run/user/1/bus")));
        assert_eq!(t.len(), 2);
        assert!(targets("unix:path=/x%zz").is_empty());
    }
}
