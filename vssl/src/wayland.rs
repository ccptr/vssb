//! Wayland through a security context: a listening socket the compositor
//! serves with restrictions for sandboxed clients
//! (`wp_security_context_manager_v1`, as Flatpak uses it).
//!
//! [`Context::create`] runs on the host, before spawning: it binds a new
//! listening socket, hands it to the compositor with the sandbox's metadata,
//! and lists the globals a client connecting through it sees, so the caller
//! can refuse to go on when privileged protocols stay visible
//! ([`Context::escapes`]). Mount [`Context::socket`] into the sandbox with
//! [`Mount::socket_at`](crate::Mount::socket_at), never the session's own
//! socket. Dropping the context makes the compositor stop accepting on the
//! socket (connections already made keep working; they end with the
//! sandbox) and removes it.
//!
//! The protocol exchange is written by hand (no Wayland library), is
//! synchronous and starts no threads.

use crate::error::{Error, Result};
use crate::prepare::above_stdio;
use std::ffi::CString;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Globals that let a client escape or spy on the session: screen capture,
/// the clipboard at any time, input injection, reading other clients'
/// input, and creating security contexts of its own.
pub const ESCAPES: &[&str] = &[
    "zwlr_screencopy_manager_v1",
    "ext_image_copy_capture_manager_v1",
    "zwlr_export_dmabuf_manager_v1",
    "hyprland_toplevel_export_manager_v1",
    "zwlr_data_control_manager_v1",
    "ext_data_control_manager_v1",
    "zwp_virtual_keyboard_manager_v1",
    "zwlr_virtual_pointer_manager_v1",
    "zwp_input_method_manager_v2",
    "hyprland_input_capture_manager_v1",
    "wp_security_context_manager_v1",
];

const MANAGER: &str = "wp_security_context_manager_v1";
const DISPLAY: u32 = 1;
const TIMEOUT: Duration = Duration::from_secs(5);

/// The metadata the compositor gets for the sandbox's clients.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// The sandbox engine's name (e.g. "vssr").
    pub engine: String,
    /// The application's id (e.g. "org.example.App").
    pub app_id: Option<String>,
    /// This sandbox instance's id.
    pub instance_id: Option<String>,
}

/// A security-context listener, alive until dropped.
#[derive(Debug)]
pub struct Context {
    socket: PathBuf,
    dir: OwnedFd,
    name: CString,
    /// The write end of the close-fd: closing it stops the listener.
    close: Option<OwnedFd>,
    globals: Vec<String>,
}

impl Context {
    /// Creates a listener at `socket` (its directory must exist and have no
    /// symlink in its path; the socket itself must not exist) on the
    /// compositor listening at `compositor`, and lists the globals offered
    /// through it. [`Error::Unsupported`] when the compositor has no
    /// security-context support.
    pub fn create(compositor: &Path, socket: &Path, opts: &Options) -> Result<Context> {
        let (Some(parent), Some(name)) = (socket.parent(), socket.file_name()) else {
            return Err(Error::Config(format!("{}: not a socket path", socket.display())));
        };
        if !socket.is_absolute() {
            return Err(Error::Config(format!("{}: the socket path must be absolute", socket.display())));
        }
        let name = CString::new(name.as_bytes()).map_err(|_| Error::Config("socket name contains a NUL byte".into()))?;
        let dir = open_dir(parent).map_err(|e| Error::io(format!("opening {}", parent.display()), e))?;
        let listener = listen(&dir, &name).map_err(|e| Error::io(format!("listening on {}", socket.display()), e))?;
        // From here on, dropping `ctx` removes the socket.
        let mut ctx = Context { socket: socket.to_path_buf(), dir, name, close: None, globals: Vec::new() };
        let (close_r, close_w) = pipe().map_err(|e| Error::io("pipe", e))?;
        ctx.close = Some(close_w);

        let fail = |what: &str, e: String| Error::io(format!("{what} ({})", compositor.display()), io::Error::other(e));
        let mut host = Conn::connect(compositor).map_err(|e| Error::io(format!("connecting to the compositor at {}", compositor.display()), e))?;
        let (reg, globals) = host.registry().map_err(|e| fail("listing the compositor's globals", e))?;
        let Some(&(mgr_name, _)) = globals.iter().find(|(i, _)| i == MANAGER).map(|(_, g)| g) else {
            return Err(Error::Unsupported(format!(
                "the compositor at {} doesn't offer {MANAGER}, so its clients can't be restricted",
                compositor.display()
            )));
        };
        let mgr = host.bind(reg, mgr_name, MANAGER, 1).map_err(|e| fail("binding the security-context manager", e.to_string()))?;
        let sc = host.new_id();
        let req = |host: &Conn, obj: u32, op: u16, args: &[u8], fds: &[RawFd]| {
            host.send(obj, op, args, fds).map_err(|e| fail("creating the security context", e.to_string()))
        };
        req(&host, mgr, 1, &u32_arg(sc), &[listener.as_raw_fd(), close_r.as_raw_fd()])?; // create_listener
        req(&host, sc, 1, &str_arg(&opts.engine), &[])?; // set_sandbox_engine
        if let Some(a) = &opts.app_id {
            req(&host, sc, 2, &str_arg(a), &[])?;
        }
        if let Some(i) = &opts.instance_id {
            req(&host, sc, 3, &str_arg(i), &[])?;
        }
        req(&host, sc, 4, &[], &[])?; // commit
        req(&host, sc, 0, &[], &[])?; // destroy: the listener stays
        req(&host, mgr, 0, &[], &[])?; // destroy
        host.roundtrip(reg, &mut Vec::new()).map_err(|e| fail("creating the security context", e))?;
        // The compositor holds its own copies now.
        drop((listener, close_r, host));

        // What a client connecting through it sees.
        let mut client = Conn::connect(&ctx.proc_path()).map_err(|e| Error::io(format!("connecting through {}", socket.display()), e))?;
        let (_, seen) = client.registry().map_err(|e| fail("listing the globals through the security context", e))?;
        ctx.globals = seen.into_iter().map(|(i, _)| i).collect();
        ctx.globals.sort();
        ctx.globals.dedup();
        Ok(ctx)
    }

    /// The listening socket, for [`Mount::socket_at`](crate::Mount::socket_at).
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// The interfaces offered to a client through the socket, sorted.
    pub fn globals(&self) -> &[String] {
        &self.globals
    }

    /// The [`ESCAPES`] still offered through the socket.
    pub fn escapes(&self) -> Vec<&'static str> {
        ESCAPES.iter().copied().filter(|e| self.globals.iter().any(|g| g == e)).collect()
    }

    /// The socket reached through the pinned directory, never by path.
    fn proc_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.dir.as_raw_fd())).join(std::ffi::OsStr::from_bytes(self.name.as_bytes()))
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        self.close.take();
        unsafe { libc::unlinkat(self.dir.as_raw_fd(), self.name.as_ptr(), 0) };
    }
}

fn open_dir(p: &Path) -> io::Result<OwnedFd> {
    let c = CString::new(p.as_os_str().as_bytes())?;
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_NO_SYMLINKS;
    let fd = unsafe { libc::syscall(libc::SYS_openat2, libc::AT_FDCWD, c.as_ptr(), &how as *const libc::open_how, std::mem::size_of::<libc::open_how>()) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

fn os(r: i32) -> io::Result<i32> {
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(r) }
}

/// A listening unix socket named `name` in `dir`, bound through the pinned
/// directory so no symlink is followed on the way.
fn listen(dir: &OwnedFd, name: &CString) -> io::Result<OwnedFd> {
    let path = format!("/proc/self/fd/{}/", dir.as_raw_fd()).into_bytes();
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let full: Vec<u8> = path.into_iter().chain(name.as_bytes().iter().copied()).collect();
    if full.len() >= addr.sun_path.len() {
        return Err(io::Error::other("socket name too long"));
    }
    for (d, s) in addr.sun_path.iter_mut().zip(&full) {
        *d = *s as libc::c_char;
    }
    let fd = os(unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) })?;
    let fd = above_stdio(unsafe { OwnedFd::from_raw_fd(fd) }).map_err(|e| io::Error::other(e.to_string()))?;
    let len = (std::mem::size_of::<libc::sa_family_t>() + full.len()) as libc::socklen_t;
    os(unsafe { libc::bind(fd.as_raw_fd(), (&addr as *const libc::sockaddr_un).cast(), len) })?;
    os(unsafe { libc::listen(fd.as_raw_fd(), 128) })?;
    Ok(fd)
}

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut p = [0; 2];
    os(unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) })?;
    let (r, w) = unsafe { (OwnedFd::from_raw_fd(p[0]), OwnedFd::from_raw_fd(p[1])) };
    let up = |f| above_stdio(f).map_err(|e| io::Error::other(e.to_string()));
    Ok((up(r)?, up(w)?))
}

fn u32_arg(v: u32) -> Vec<u8> {
    v.to_ne_bytes().to_vec()
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32 + 1).to_ne_bytes());
    out.extend_from_slice(s.as_bytes());
    out.push(0);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

fn str_arg(s: &str) -> Vec<u8> {
    let mut v = Vec::new();
    put_str(&mut v, s);
    v
}

/// Reads wire arguments, failing on a short message instead of panicking.
struct Args<'a> {
    b: &'a [u8],
    at: usize,
}

impl Args<'_> {
    fn u32(&mut self) -> std::result::Result<u32, String> {
        let v = self.b.get(self.at..self.at + 4).ok_or("short message")?;
        self.at += 4;
        Ok(u32::from_ne_bytes(v.try_into().unwrap_or_default()))
    }

    fn string(&mut self) -> std::result::Result<String, String> {
        let len = self.u32()? as usize;
        let s = self.b.get(self.at..self.at + len.saturating_sub(1)).ok_or("short message")?;
        self.at += len.div_ceil(4) * 4;
        Ok(String::from_utf8_lossy(s).into_owned())
    }
}

enum Event {
    Error(String),
    Global { name: u32, interface: String, version: u32 },
    Done { callback: u32 },
    Other,
}

type Globals = Vec<(String, (u32, u32))>;

/// A client connection, enough for the registry and one request with fds.
struct Conn {
    stream: UnixStream,
    next_id: u32,
    buf: Vec<u8>,
}

impl Conn {
    fn connect(path: &Path) -> io::Result<Conn> {
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        Ok(Conn { stream, next_id: 2, buf: Vec::new() })
    }

    fn new_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Sends one request, with `fds` as SCM_RIGHTS.
    fn send(&self, object: u32, opcode: u16, args: &[u8], fds: &[RawFd]) -> io::Result<()> {
        let mut msg = Vec::with_capacity(8 + args.len());
        msg.extend_from_slice(&object.to_ne_bytes());
        msg.extend_from_slice(&(((8 + args.len() as u32) << 16) | opcode as u32).to_ne_bytes());
        msg.extend_from_slice(args);
        let mut iov = libc::iovec { iov_base: msg.as_ptr() as *mut _, iov_len: msg.len() };
        let mut cmsg = vec![0u8; unsafe { libc::CMSG_SPACE((fds.len() * 4) as u32) } as usize];
        let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
        hdr.msg_iov = &mut iov;
        hdr.msg_iovlen = 1;
        if !fds.is_empty() {
            hdr.msg_control = cmsg.as_mut_ptr().cast();
            hdr.msg_controllen = cmsg.len() as _;
            unsafe {
                let c = libc::CMSG_FIRSTHDR(&hdr);
                (*c).cmsg_level = libc::SOL_SOCKET;
                (*c).cmsg_type = libc::SCM_RIGHTS;
                (*c).cmsg_len = libc::CMSG_LEN((fds.len() * 4) as u32) as _;
                std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(c).cast::<RawFd>(), fds.len());
            }
        }
        let n = unsafe { libc::sendmsg(self.stream.as_raw_fd(), &hdr, libc::MSG_NOSIGNAL) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n as usize != msg.len() {
            return Err(io::Error::other("short write to the compositor"));
        }
        Ok(())
    }

    fn event(&mut self, registry: u32) -> std::result::Result<Event, String> {
        loop {
            if self.buf.len() >= 8 {
                let word = |at: usize| u32::from_ne_bytes(self.buf[at..at + 4].try_into().unwrap_or_default());
                let (object, head) = (word(0), word(4));
                let size = (head >> 16) as usize;
                if size < 8 {
                    return Err("malformed message from the compositor".into());
                }
                if self.buf.len() >= size {
                    let m: Vec<u8> = self.buf.drain(..size).collect();
                    let mut a = Args { b: &m, at: 8 };
                    return Ok(match (object, head & 0xffff) {
                        (DISPLAY, 0) => {
                            let (obj, code, msg) = (a.u32()?, a.u32()?, a.string()?);
                            Event::Error(format!("protocol error on object {obj}, code {code}: {msg}"))
                        }
                        (o, 0) if o == registry => Event::Global { name: a.u32()?, interface: a.string()?, version: a.u32()? },
                        (o, 0) if o != DISPLAY => Event::Done { callback: o },
                        _ => Event::Other,
                    });
                }
            }
            let mut chunk = [0u8; 4096];
            let n = self.stream.read(&mut chunk).map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("the compositor closed the connection".into());
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// wl_display.sync, then events until it is done; globals are collected.
    fn roundtrip(&mut self, registry: u32, globals: &mut Globals) -> std::result::Result<(), String> {
        let cb = self.new_id();
        // After a protocol error the compositor hangs up; the error is
        // still there to read, so a failed send isn't the end.
        let _ = self.send(DISPLAY, 0, &u32_arg(cb), &[]);
        loop {
            match self.event(registry)? {
                Event::Error(e) => return Err(e),
                Event::Global { name, interface, version } => globals.push((interface, (name, version))),
                Event::Done { callback } if callback == cb => return Ok(()),
                _ => {}
            }
        }
    }

    fn registry(&mut self) -> std::result::Result<(u32, Globals), String> {
        let reg = self.new_id();
        self.send(DISPLAY, 1, &u32_arg(reg), &[]).map_err(|e| e.to_string())?;
        let mut globals = Vec::new();
        self.roundtrip(reg, &mut globals)?;
        Ok((reg, globals))
    }

    fn bind(&mut self, registry: u32, name: u32, interface: &str, version: u32) -> io::Result<u32> {
        let id = self.new_id();
        let mut a = u32_arg(name);
        put_str(&mut a, interface);
        a.extend_from_slice(&version.to_ne_bytes());
        a.extend_from_slice(&id.to_ne_bytes());
        self.send(registry, 0, &a, &[])?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixListener;

    #[test]
    fn strings_are_padded() {
        assert_eq!(str_arg("abc"), [4, 0, 0, 0, b'a', b'b', b'c', 0]);
        assert_eq!(str_arg("abcd").len(), 12);
        let m = str_arg("wl_seat");
        assert_eq!(Args { b: &m, at: 0 }.string().unwrap(), "wl_seat");
        assert!(Args { b: &m[..6], at: 0 }.string().is_err());
    }

    /// A compositor that answers the registry with `globals` and every sync
    /// with done, and nothing else.
    fn fake_compositor(path: &Path, globals: &'static [&'static str]) -> std::thread::JoinHandle<()> {
        let l = UnixListener::bind(path).unwrap();
        std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut buf = Vec::new();
            loop {
                let mut chunk = [0u8; 512];
                match c.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
                while buf.len() >= 8 {
                    let size = (u32::from_ne_bytes(buf[4..8].try_into().unwrap()) >> 16) as usize;
                    if buf.len() < size {
                        break;
                    }
                    let m: Vec<u8> = buf.drain(..size).collect();
                    let (obj, op) = (u32::from_ne_bytes(m[0..4].try_into().unwrap()), m[4]);
                    let id = u32::from_ne_bytes(m[8..12].try_into().unwrap());
                    let mut out = Vec::new();
                    let mut event = |obj: u32, args: Vec<u8>| {
                        out.extend_from_slice(&obj.to_ne_bytes());
                        out.extend_from_slice(&((8 + args.len() as u32) << 16).to_ne_bytes());
                        out.extend_from_slice(&args);
                    };
                    match (obj, op) {
                        (DISPLAY, 1) => {
                            for (n, g) in globals.iter().enumerate() {
                                let mut a = u32_arg(n as u32 + 1);
                                put_str(&mut a, g);
                                a.extend_from_slice(&1u32.to_ne_bytes());
                                event(id, a);
                            }
                        }
                        (DISPLAY, 0) => event(id, u32_arg(0)),
                        _ => {}
                    }
                    c.write_all(&out).unwrap();
                }
            }
        })
    }

    #[test]
    fn escapes_are_the_privileged_globals_offered() {
        let dir = std::env::temp_dir();
        let ctx = Context {
            socket: dir.join("vssl-none"),
            dir: open_dir(&std::fs::canonicalize(&dir).unwrap()).unwrap(),
            name: c"vssl-wayland-test-none".into(),
            close: None,
            globals: ["wl_compositor", "zwlr_screencopy_manager_v1", "zwp_virtual_keyboard_manager_v1", "ext_idle_notifier_v1"].map(String::from).to_vec(),
        };
        assert_eq!(ctx.escapes(), ["zwlr_screencopy_manager_v1", "zwp_virtual_keyboard_manager_v1"]);
    }

    #[test]
    fn compositors_without_security_contexts_are_unsupported() {
        let dir = std::env::temp_dir().join(format!("vssl-wl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dir = std::fs::canonicalize(&dir).unwrap();
        let server = fake_compositor(&dir.join("compositor"), &["wl_compositor", "wl_shm"]);
        let socket = dir.join("wayland-0");
        let opts = Options { engine: "test".into(), ..Default::default() };
        match Context::create(&dir.join("compositor"), &socket, &opts) {
            Err(Error::Unsupported(m)) => assert!(m.contains(MANAGER), "{m}"),
            r => panic!("{r:?}"),
        }
        assert!(!socket.exists(), "the listening socket is removed again");
        server.join().unwrap();
        // A symlink in the directory's path is refused.
        std::os::unix::fs::symlink(&dir, dir.join("alias")).unwrap();
        assert!(matches!(Context::create(&dir.join("compositor"), &dir.join("alias/wayland-0"), &opts), Err(Error::Io { .. })));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
