//! One proxied connection: the program's socket and ours to the bus,
//! both non-blocking, served from one thread with `poll`. Messages are
//! read whole (with the descriptors that came with them), go through the
//! [`Filter`], and are queued for the other side.

use crate::filter::{Filter, Out};
use crate::wire::{self, Message};
use crate::{Event, Shared, auth};
use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// How long both logins may take together.
const LOGIN: Duration = Duration::from_secs(10);
/// Queued for a side that isn't reading: above this we stop reading
/// from the other side; far above it the connection is dropped.
const HIGH: usize = 8 << 20;
const MAX_QUEUED: usize = 128 << 20;
/// Descriptors received but not yet claimed by a whole message.
const MAX_LOOSE_FDS: usize = 1024;
const READ: usize = 64 * 1024;
/// Room for the most descriptors one `recvmsg` returns.
const CMSG_WORDS: usize = 160;

fn recv(fd: RawFd, buf: &mut [u8], fds: &mut VecDeque<OwnedFd>) -> io::Result<usize> {
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
    let mut cmsg = [0u64; CMSG_WORDS];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&cmsg) as _;
    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(c) as *const libc::c_int;
                let count = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / std::mem::size_of::<libc::c_int>();
                for i in 0..count {
                    fds.push_back(OwnedFd::from_raw_fd(std::ptr::read_unaligned(data.add(i))));
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::other("descriptors were cut off"));
    }
    Ok(n as usize)
}

fn send(fd: RawFd, data: &[u8], fds: &[OwnedFd]) -> io::Result<usize> {
    let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut _, iov_len: data.len() };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    let mut cmsg = [0u64; CMSG_WORDS];
    if !fds.is_empty() {
        let len = std::mem::size_of_val(fds) as u32;
        unsafe {
            msg.msg_control = cmsg.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(len) as _;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(len) as _;
            let data = libc::CMSG_DATA(c) as *mut libc::c_int;
            for (i, f) in fds.iter().enumerate() {
                std::ptr::write_unaligned(data.add(i), f.as_raw_fd());
            }
        }
    }
    let n = unsafe { libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
    if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
}

/// One end: what came in and isn't a whole message yet, and what waits
/// to go out.
struct Side {
    s: UnixStream,
    buf: Vec<u8>,
    pos: usize,
    fds: VecDeque<OwnedFd>,
    out: VecDeque<Message>,
    /// How much of the first queued message is already sent.
    sent: usize,
    queued: usize,
    eof: bool,
}

impl Side {
    fn new(s: UnixStream, buf: Vec<u8>) -> Side {
        Side { s, buf, pos: 0, fds: VecDeque::new(), out: VecDeque::new(), sent: 0, queued: 0, eof: false }
    }

    fn fd(&self) -> RawFd {
        self.s.as_raw_fd()
    }

    fn read(&mut self) -> Result<(), String> {
        if self.pos > 0 && self.pos * 2 >= self.buf.len() {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        let old = self.buf.len();
        self.buf.resize(old + READ, 0);
        let r = recv(self.fd(), &mut self.buf[old..], &mut self.fds);
        self.buf.truncate(old + *r.as_ref().unwrap_or(&0));
        match r {
            Ok(0) => self.eof = true,
            Ok(_) => {}
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {}
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => self.eof = true,
            Err(e) => return Err(e.to_string()),
        }
        if self.fds.len() > MAX_LOOSE_FDS {
            return Err("too many descriptors without a message".into());
        }
        Ok(())
    }

    fn next(&mut self) -> Result<Option<Message>, String> {
        let avail = &self.buf[self.pos..];
        if avail.len() < 16 {
            return Ok(None);
        }
        let len = wire::message_len(avail).map_err(|e| e.to_string())?;
        if avail.len() < len {
            return Ok(None);
        }
        let data = avail[..len].to_vec();
        self.pos += len;
        let mut m = Message::parse(data).map_err(|e| e.to_string())?;
        let n = m.unix_fds as usize;
        if n > self.fds.len() {
            return Err("a message names more descriptors than came with it".into());
        }
        m.fds = self.fds.drain(..n).collect();
        Ok(Some(m))
    }

    fn push(&mut self, m: Message) -> Result<(), String> {
        self.queued += m.data.len();
        self.out.push_back(m);
        if self.queued > MAX_QUEUED {
            return Err("the other side stopped reading".into());
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), String> {
        while let Some(m) = self.out.front() {
            let r = if self.sent == 0 { send(self.fd(), &m.data, &m.fds) } else { send(self.fd(), &m.data[self.sent..], &[]) };
            match r {
                Ok(n) => {
                    self.sent += n;
                    if self.sent == m.data.len() {
                        self.queued -= m.data.len();
                        self.sent = 0;
                        self.out.pop_front();
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if matches!(e.kind(), io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset) => {
                    self.eof = true;
                    self.out.clear();
                    self.queued = 0;
                    return Ok(());
                }
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(())
    }
}

/// Serves one connection from the program until either side closes or
/// the proxy stops; reports how it ended.
pub(crate) fn serve(client: UnixStream, conn: u64, sh: &Shared) {
    let error = run(client, conn, sh).err();
    (sh.events)(&Event::Close { conn, error });
}

fn peer_uid(s: &UnixStream) -> io::Result<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe { libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut cred as *mut libc::ucred).cast(), &mut len) };
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(cred.uid) }
}

fn run(client: UnixStream, conn: u64, sh: &Shared) -> Result<(), String> {
    let stop = sh.stop.as_raw_fd();
    let uid = peer_uid(&client).map_err(|e| format!("peer credentials: {e}"))?;
    if uid != unsafe { libc::geteuid() } {
        return Err(format!("the program runs as uid {uid}, not as ours"));
    }
    let deadline = Instant::now() + LOGIN;
    let up = auth::connect(&sh.upstream, stop, deadline).map_err(|e| format!("the session bus: {e}"))?;
    let (unix_fds, early) = match auth::accept(&client, &up.guid, up.unix_fds, stop, deadline) {
        Ok(r) => r,
        Err(e) if e.kind() == io::ErrorKind::Interrupted => return Ok(()),
        Err(e) => return Err(format!("the program's login: {e}")),
    };
    let mut filter = Filter::new(sh.policy.clone(), conn, unix_fds);
    let mut c = Side::new(client, early);
    let mut b = Side::new(up.stream, vec![]);
    let mut out = vec![];
    loop {
        // Everything already in, in order, as far as the filter and the
        // other side's queue let it: a message from each side per round.
        loop {
            let mut progress = false;
            if !filter.client_paused()
                && b.queued < HIGH
                && let Some(m) = c.next()?
            {
                filter.on_client(m, &mut out)?;
                progress = true;
            }
            if c.queued < HIGH
                && let Some(m) = b.next()?
            {
                filter.on_bus(m, &mut out)?;
                progress = true;
            }
            for o in out.drain(..) {
                match o {
                    Out::Bus(m) => b.push(m)?,
                    Out::Client(m) => c.push(m)?,
                    Out::Event(e) => (sh.events)(&e),
                }
            }
            if !progress {
                break;
            }
        }
        c.flush()?;
        b.flush()?;
        // A side that closed: deliver what is left for the other, then end.
        if c.eof || b.eof {
            let other = if c.eof { &mut b } else { &mut c };
            if other.out.is_empty() || other.eof {
                return Ok(());
            }
        }
        // A side at end of file isn't polled at all (it would always be
        // ready); the other is only written to.
        let want = |s: &Side, read: bool| {
            let events = if read { libc::POLLIN } else { 0 } | if s.out.is_empty() { 0 } else { libc::POLLOUT };
            libc::pollfd { fd: if s.eof { -1 } else { s.fd() }, events, revents: 0 }
        };
        let read_c = !filter.client_paused() && b.queued < HIGH && !b.eof;
        let read_b = c.queued < HIGH && !c.eof;
        let mut p = [
            want(&c, read_c),
            want(&b, read_b),
            libc::pollfd { fd: stop, events: libc::POLLIN, revents: 0 },
        ];
        if unsafe { libc::poll(p.as_mut_ptr(), 3, -1) } < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e.to_string());
        }
        if p[2].revents != 0 {
            return Ok(());
        }
        for (pf, side) in [(&p[0], &mut c), (&p[1], &mut b)] {
            if pf.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                side.read()?;
            }
        }
    }
}
