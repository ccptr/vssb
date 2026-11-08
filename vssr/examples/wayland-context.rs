//! Prototype for gui.md's decision gate: create a Wayland security-context
//! listener by hand (no Wayland library), connect through it, and compare
//! the globals a sandboxed client sees with what an ordinary client sees.
//!
//! Usage: cargo run -p vssr --example wayland-context -- \
//!     COMPOSITOR_SOCKET LISTEN_PATH [CLIENT ARGS...]
//!
//! Run it against a headless compositor (see gui.md), never the live session:
//! it creates a listener there. CLIENT runs with WAYLAND_DISPLAY set to the
//! listener before the close-fd is closed.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

const DISPLAY: u32 = 1;

#[derive(Debug)]
enum Event {
    Error { object: u32, code: u32, message: String },
    Global { name: u32, interface: String, version: u32 },
    Done { callback: u32 },
    Other,
}

struct Conn {
    stream: UnixStream,
    next_id: u32,
    buf: Vec<u8>,
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_ne_bytes());
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_u32(out, s.len() as u32 + 1);
    out.extend_from_slice(s.as_bytes());
    out.push(0);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

fn get_u32(b: &[u8], at: &mut usize) -> u32 {
    let v = u32::from_ne_bytes(b[*at..*at + 4].try_into().unwrap());
    *at += 4;
    v
}

fn get_str(b: &[u8], at: &mut usize) -> String {
    let len = get_u32(b, at) as usize;
    let s = String::from_utf8_lossy(&b[*at..*at + len.saturating_sub(1)]).into_owned();
    *at += len.div_ceil(4) * 4;
    s
}

impl Conn {
    fn connect(path: &str) -> io::Result<Conn> {
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        Ok(Conn { stream, next_id: 2, buf: Vec::new() })
    }

    fn new_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Sends one request, with `fds` as SCM_RIGHTS.
    fn send(&self, object: u32, opcode: u16, args: &[u8], fds: &[RawFd]) -> io::Result<()> {
        let mut msg = Vec::new();
        put_u32(&mut msg, object);
        put_u32(&mut msg, ((8 + args.len() as u32) << 16) | opcode as u32);
        msg.extend_from_slice(args);
        let mut iov = libc::iovec { iov_base: msg.as_ptr() as *mut _, iov_len: msg.len() };
        let mut cmsg = vec![0u8; unsafe { libc::CMSG_SPACE((fds.len() * 4) as u32) } as usize];
        let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
        hdr.msg_iov = &mut iov;
        hdr.msg_iovlen = 1;
        if !fds.is_empty() {
            hdr.msg_control = cmsg.as_mut_ptr() as *mut _;
            hdr.msg_controllen = cmsg.len();
            unsafe {
                let c = libc::CMSG_FIRSTHDR(&hdr);
                (*c).cmsg_level = libc::SOL_SOCKET;
                (*c).cmsg_type = libc::SCM_RIGHTS;
                (*c).cmsg_len = libc::CMSG_LEN((fds.len() * 4) as u32) as usize;
                std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(c) as *mut RawFd, fds.len());
            }
        }
        let n = unsafe { libc::sendmsg(self.stream.as_raw_fd(), &hdr, libc::MSG_NOSIGNAL) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        assert_eq!(n as usize, msg.len());
        Ok(())
    }

    /// Reads the next event. `registry` is the registry's id, if any.
    fn event(&mut self, registry: u32) -> io::Result<Event> {
        loop {
            if self.buf.len() >= 8 {
                let size = (u32::from_ne_bytes(self.buf[4..8].try_into().unwrap()) >> 16) as usize;
                if self.buf.len() >= size {
                    let m: Vec<u8> = self.buf.drain(..size).collect();
                    let object = u32::from_ne_bytes(m[0..4].try_into().unwrap());
                    let opcode = u32::from_ne_bytes(m[4..8].try_into().unwrap()) & 0xffff;
                    let mut at = 8;
                    return Ok(match (object, opcode) {
                        (DISPLAY, 0) => Event::Error {
                            object: get_u32(&m, &mut at),
                            code: get_u32(&m, &mut at),
                            message: get_str(&m, &mut at),
                        },
                        (o, 0) if o == registry => Event::Global {
                            name: get_u32(&m, &mut at),
                            interface: get_str(&m, &mut at),
                            version: get_u32(&m, &mut at),
                        },
                        (o, 0) if o != DISPLAY => Event::Done { callback: o },
                        _ => Event::Other,
                    });
                }
            }
            let mut chunk = [0u8; 4096];
            let n = self.stream.read(&mut chunk)?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "compositor closed the connection"));
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// wl_display.sync, then reads events until it is done. Globals are
    /// collected; a protocol error is returned as Err.
    fn roundtrip(&mut self, registry: u32, globals: &mut BTreeMap<String, (u32, u32)>) -> Result<(), String> {
        let cb = self.new_id();
        let mut a = Vec::new();
        put_u32(&mut a, cb);
        // If the compositor has already posted an error and hung up, the
        // send fails; the error is still waiting to be read.
        let _ = self.send(DISPLAY, 0, &a, &[]);
        loop {
            match self.event(registry).map_err(|e| e.to_string())? {
                Event::Error { object, code, message } => {
                    return Err(format!("protocol error on object {object}, code {code}: {message}"));
                }
                Event::Global { name, interface, version } => {
                    globals.insert(interface, (name, version));
                }
                Event::Done { callback } if callback == cb => return Ok(()),
                _ => {}
            }
        }
    }

    fn registry(&mut self) -> (u32, BTreeMap<String, (u32, u32)>) {
        let reg = self.new_id();
        let mut a = Vec::new();
        put_u32(&mut a, reg);
        self.send(DISPLAY, 1, &a, &[]).unwrap();
        let mut globals = BTreeMap::new();
        self.roundtrip(reg, &mut globals).unwrap();
        (reg, globals)
    }

    fn bind(&mut self, registry: u32, name: u32, interface: &str, version: u32) -> u32 {
        let id = self.new_id();
        let mut a = Vec::new();
        put_u32(&mut a, name);
        put_str(&mut a, interface);
        put_u32(&mut a, version);
        put_u32(&mut a, id);
        self.send(registry, 0, &a, &[]).unwrap();
        id
    }
}

fn pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

/// Privileged protocols: what gui.md's threat model names, plus the rest
/// that let one client watch or steer others.
const PRIVILEGED: &[&str] = &[
    "zwlr_screencopy_manager_v1",
    "ext_image_copy_capture_manager_v1",
    "zwlr_export_dmabuf_manager_v1",
    "zwlr_data_control_manager_v1",
    "ext_data_control_manager_v1",
    "zwp_virtual_keyboard_manager_v1",
    "zwlr_virtual_pointer_manager_v1",
    "zwp_input_method_manager_v2",
    "zwlr_foreign_toplevel_manager_v1",
    "ext_foreign_toplevel_list_v1",
    "zwlr_gamma_control_manager_v1",
    "zwlr_output_manager_v1",
    "zwlr_output_power_manager_v1",
    "ext_session_lock_manager_v1",
    "zwlr_layer_shell_v1",
    "ext_idle_notifier_v1",
    "ext_workspace_manager_v1",
    "ext_transient_seat_manager_v1",
    "zwp_keyboard_shortcuts_inhibit_manager_v1",
    "wp_security_context_manager_v1",
];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (compositor, listen_path) = (&args[1], &args[2]);

    // 1. What an ordinary client sees.
    let mut host = Conn::connect(compositor).expect("connect to compositor");
    let (host_reg, host_globals) = host.registry();
    println!("ordinary client: {} globals", host_globals.len());

    // 2. Create the listener: socket, pipe, create_listener, metadata, commit.
    let _ = std::fs::remove_file(listen_path);
    let listener = UnixListener::bind(listen_path).expect("bind listen socket");
    let (close_r, close_w) = pipe();
    let (name, version) = host_globals["wp_security_context_manager_v1"];
    let mgr = host.bind(host_reg, name, "wp_security_context_manager_v1", version.min(1));
    let ctx = host.new_id();
    let mut a = Vec::new();
    put_u32(&mut a, ctx);
    host.send(mgr, 1, &a, &[listener.as_raw_fd(), close_r.as_raw_fd()]).unwrap();
    for (op, value) in [(1, "vssr"), (2, "org.example.App"), (3, "proto-1")] {
        let mut a = Vec::new();
        put_str(&mut a, value);
        host.send(ctx, op, &a, &[]).unwrap();
    }
    host.send(ctx, 4, &[], &[]).unwrap(); // commit
    host.send(ctx, 0, &[], &[]).unwrap(); // destroy: the listener stays
    host.send(mgr, 0, &[], &[]).unwrap(); // destroy
    let mut ignore = BTreeMap::new();
    match host.roundtrip(host_reg, &mut ignore) {
        Ok(()) => println!("security context committed (engine vssr, app id org.example.App, instance proto-1)"),
        Err(e) => panic!("create_listener failed: {e}"),
    }
    // The compositor holds its own copies now; the supervisor needs neither.
    drop(listener);
    drop(close_r);
    drop(host);

    // 3. What a client through the listener sees.
    let mut sandboxed = Conn::connect(listen_path).expect("connect through the listener");
    let (sb_reg, sb_globals) = sandboxed.registry();
    println!("sandboxed client: {} globals", sb_globals.len());
    let hidden: Vec<&String> = host_globals.keys().filter(|k| !sb_globals.contains_key(*k)).collect();
    println!("hidden from the sandboxed client ({}):", hidden.len());
    for h in &hidden {
        println!("  {h}");
    }
    let leaked: Vec<&&str> = PRIVILEGED.iter().filter(|p| sb_globals.contains_key(**p)).collect();
    let absent: Vec<&&str> = PRIVILEGED.iter().filter(|p| !host_globals.contains_key(**p)).collect();
    println!("privileged globals still visible: {leaked:?}");
    if !absent.is_empty() {
        println!("(not offered by this compositor at all: {absent:?})");
    }
    let extra: Vec<&String> = sb_globals.keys().filter(|k| !host_globals.contains_key(*k)).collect();
    if !extra.is_empty() {
        println!("only visible to the sandboxed client: {extra:?}");
    }

    // 4. Binding a hidden global by its name must fail too, not just listing.
    if let Some(&(name, version)) = host_globals.get("zwp_virtual_keyboard_manager_v1") {
        let mut probe = Conn::connect(listen_path).unwrap();
        let (reg, _) = probe.registry();
        probe.bind(reg, name, "zwp_virtual_keyboard_manager_v1", version);
        match probe.roundtrip(reg, &mut BTreeMap::new()) {
            Ok(()) => println!("binding hidden zwp_virtual_keyboard_manager_v1 by name: ALLOWED"),
            Err(e) => println!("binding hidden zwp_virtual_keyboard_manager_v1 by name: refused ({e})"),
        }
    }

    // Optionally, a real client through the listener (args after the path).
    if args.len() > 3 {
        let status = std::process::Command::new(&args[3])
            .args(&args[4..])
            .env("WAYLAND_DISPLAY", listen_path)
            .status()
            .expect("run client");
        println!("client {:?} through the listener: {status}", &args[3..]);
    }

    // 5. Closing the write end: no new connections; existing ones?
    drop(close_w);
    std::thread::sleep(Duration::from_millis(200));
    match UnixStream::connect(listen_path) {
        Ok(_) => println!("after closing close_fd: new connection ACCEPTED"),
        Err(e) => println!("after closing close_fd: new connection refused ({e})"),
    }
    match sandboxed.roundtrip(sb_reg, &mut BTreeMap::new()) {
        Ok(()) => println!("after closing close_fd: existing sandboxed connection still works"),
        Err(e) => println!("after closing close_fd: existing sandboxed connection ended ({e})"),
    }
    let _ = std::fs::remove_file(listen_path);
}
