//! Filtering HTTP proxy for a sandbox with [`Net::None`](crate::Net::None).
//! It runs in the caller, on the host network, and accepts connections on
//! a listener that lives in the sandbox's network namespace
//! ([`Sandbox::listen_tcp`](crate::Sandbox::listen_tcp)). It supports
//! CONNECT (HTTPS and anything tunnelled) and plain-HTTP absolute-form
//! requests, decides by host name and port, refuses private addresses, and
//! connects to the address it checked (no DNS rebinding).
//!
//! The proxy is the only part of vssb that starts threads: one to accept,
//! and two per connection. [`ProxyHandle`] stops them all.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use vssb::{proxy, Command, Sandbox};
//! let mut sb = Sandbox::new();
//! sb.system(true).listen_tcp(3128);
//! let mut cmd = Command::new("curl");
//! cmd.args(["-sS", "https://example.com"]).env("HTTPS_PROXY", "http://127.0.0.1:3128");
//! let mut child = sb.spawn(cmd)?;
//! let rules = proxy::NetPolicy::new(&["example.com".into()], &[], false)?;
//! let listener = child.take_listeners().remove(0);
//! let _proxy = proxy::serve(listener, rules, |e| eprintln!("{e:?}"))?;
//! child.wait()?;
//! # Ok(()) }
//! ```

use crate::error::{Error, Result};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const MAX_HEAD: usize = 64 * 1024;
const MAX_CONNS: usize = 512;
const DEFAULT_PORTS: [u16; 2] = [80, 443];

fn bad(msg: String) -> Error {
    Error::Config(msg)
}

#[derive(Debug, Clone, PartialEq)]
enum HostPat {
    Any,
    Exact(String),
    /// "*.example.com" stored as ".example.com": matches subdomains only.
    Suffix(String),
}

#[derive(Debug, Clone, PartialEq)]
struct Pattern {
    host: HostPat,
    /// None: any port.
    ports: Option<Vec<u16>>,
}

/// Which hosts and ports the proxy lets through.
#[derive(Debug, Clone, Default)]
pub struct NetPolicy {
    allow: Vec<Pattern>,
    deny: Vec<Pattern>,
    allow_private: bool,
}

#[derive(Debug, PartialEq)]
pub enum Decision {
    /// Allowed; `explicit_ip` when an allow entry names the IP literal itself.
    Allow { explicit_ip: bool },
    Deny(String),
}

fn parse_pattern(s: &str, default_ports: Option<&[u16]>) -> Result<Pattern> {
    let s = s.trim().to_ascii_lowercase();
    let (host, port) = split_host_port(&s)?;
    let ports = match port {
        Some("*") => None,
        Some(p) => Some(vec![p.parse().map_err(|_| bad(format!("{s:?}: invalid port")))?]),
        None => default_ports.map(|d| d.to_vec()),
    };
    let host = if host == "*" {
        HostPat::Any
    } else if let Some(rest) = host.strip_prefix("*.") {
        validate_host(rest)?;
        HostPat::Suffix(format!(".{rest}"))
    } else {
        validate_host(host)?;
        HostPat::Exact(host.trim_end_matches('.').to_string())
    };
    Ok(Pattern { host, ports })
}

/// Splits "host", "host:port", "[v6]" or "[v6]:port".
fn split_host_port(s: &str) -> Result<(&str, Option<&str>)> {
    if let Some(r) = s.strip_prefix('[') {
        let end = r.find(']').ok_or_else(|| bad(format!("{s:?}: missing ]")))?;
        let rest = &r[end + 1..];
        let port = match rest.strip_prefix(':') {
            Some(p) => Some(p),
            None if rest.is_empty() => None,
            None => return Err(bad(format!("{s:?}: junk after ]"))),
        };
        return Ok((&r[..end], port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Ok((h, Some(p))),
        _ => Ok((s, None)), // a bare IPv6 address, or no port
    }
}

fn validate_host(h: &str) -> Result<()> {
    if h.is_empty() || h.len() > 253 {
        return Err(bad(format!("invalid host {h:?}")));
    }
    if h.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if !h.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_') {
        return Err(bad(format!("invalid host {h:?}")));
    }
    Ok(())
}

impl Pattern {
    fn matches(&self, host: &str, port: u16) -> bool {
        let host_ok = match &self.host {
            HostPat::Any => true,
            HostPat::Exact(h) => h == host,
            HostPat::Suffix(s) => host.ends_with(s.as_str()),
        };
        host_ok && self.ports.as_ref().is_none_or(|p| p.contains(&port))
    }
}

impl NetPolicy {
    /// `allow` and `deny` entries: `host` (ports 80 and 443 for allow
    /// entries, all ports for deny entries), `host:port`, `host:*`,
    /// `*.domain` (subdomains only), `*`, IP literals. Deny wins.
    /// `allow_private` lets allowed names resolve to loopback/LAN addresses.
    pub fn new(allow: &[String], deny: &[String], allow_private: bool) -> Result<NetPolicy> {
        Ok(NetPolicy {
            allow: allow.iter().map(|s| parse_pattern(s, Some(&DEFAULT_PORTS))).collect::<Result<_>>()?,
            deny: deny.iter().map(|s| parse_pattern(s, None)).collect::<Result<_>>()?,
            allow_private,
        })
    }

    pub fn describe(&self) -> String {
        if self.allow.is_empty() {
            return "nothing allowed".into();
        }
        format!(
            "{} allow rule(s), {} deny rule(s), private addresses {}",
            self.allow.len(),
            self.deny.len(),
            if self.allow_private { "allowed" } else { "blocked" }
        )
    }

    pub fn decide(&self, host: &str, port: u16) -> Decision {
        if let Some(d) = self.deny.iter().find(|p| p.matches(host, port)) {
            return Decision::Deny(format!("matches deny rule {:?}", d.host));
        }
        match self.allow.iter().find(|p| p.matches(host, port)) {
            Some(p) => Decision::Allow { explicit_ip: matches!(&p.host, HostPat::Exact(h) if h.parse::<IpAddr>().is_ok()) },
            None => Decision::Deny("not in the allow list".into()),
        }
    }
}

/// Loopback, private, link-local, CGNAT, multicast and other non-public ranges.
pub fn is_non_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_broadcast()
                || a.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                || o[0] >= 240
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_non_public(IpAddr::V4(v4));
            }
            if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
                let v4 = Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
                return is_non_public(IpAddr::V4(v4));
            }
            a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8)
        }
    }
}

/// What the proxy did, for logging and auditing.
#[derive(Debug, Clone)]
pub enum Event {
    Allow { method: String, host: String, port: u16, addr: SocketAddr },
    Deny { method: String, host: String, port: u16, reason: String },
    Error { method: String, host: String, port: u16, reason: String },
    Close { host: String, port: u16, bytes_up: u64, bytes_down: u64, duration: Duration },
}

type Sink = Arc<dyn Fn(&Event) + Send + Sync>;

struct Shared {
    policy: NetPolicy,
    events: Sink,
    stop: AtomicBool,
    next: AtomicU64,
    /// Open sockets (both sides of every connection), to shut down on stop.
    conns: Mutex<HashMap<u64, TcpStream>>,
}

impl Shared {
    fn track(&self, s: &TcpStream) -> Option<u64> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let c = s.try_clone().ok()?;
        let mut m = self.conns.lock().unwrap_or_else(|e| e.into_inner());
        if self.stop.load(Ordering::SeqCst) {
            let _ = c.shutdown(Shutdown::Both);
        }
        m.insert(id, c);
        Some(id)
    }

    fn untrack(&self, id: Option<u64>) {
        if let Some(id) = id {
            self.conns.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
        }
    }
}

/// A running proxy. Dropping it (or [`stop`](ProxyHandle::stop)) closes
/// the listener and every open connection, and waits for the accept thread.
pub struct ProxyHandle {
    shared: Arc<Shared>,
    listener: TcpListener,
    thread: Option<JoinHandle<()>>,
}

impl ProxyHandle {
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        // Wakes the blocked accept() with an error.
        unsafe { libc::shutdown(self.listener.as_raw_fd(), libc::SHUT_RDWR) };
        for c in self.shared.conns.lock().unwrap_or_else(|e| e.into_inner()).values() {
            let _ = c.shutdown(Shutdown::Both);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Serves `listener` (usually from [`Child::take_listeners`](crate::Child::take_listeners))
/// with `policy`, reporting each decision to `events`.
pub fn serve(listener: TcpListener, policy: NetPolicy, events: impl Fn(&Event) + Send + Sync + 'static) -> io::Result<ProxyHandle> {
    listener.set_nonblocking(false)?;
    let shared = Arc::new(Shared { policy, events: Arc::new(events), stop: AtomicBool::new(false), next: AtomicU64::new(0), conns: Mutex::new(HashMap::new()) });
    let l = listener.try_clone()?;
    let sh = shared.clone();
    let thread = std::thread::Builder::new().name("vssb-proxy".into()).spawn(move || accept_loop(l, sh))?;
    Ok(ProxyHandle { shared, listener, thread: Some(thread) })
}

fn accept_loop(listener: TcpListener, sh: Arc<Shared>) {
    let active = Arc::new(AtomicU64::new(0));
    loop {
        let conn = listener.accept();
        if sh.stop.load(Ordering::SeqCst) {
            return;
        }
        let Ok((conn, _)) = conn else {
            // EMFILE and the like: don't spin.
            std::thread::sleep(Duration::from_millis(20));
            continue;
        };
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNS as u64 {
            active.fetch_sub(1, Ordering::SeqCst);
            let mut c = conn;
            let _ = c.write_all(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
            continue;
        }
        let (sh2, act) = (sh.clone(), active.clone());
        let spawned = std::thread::Builder::new().stack_size(256 * 1024).spawn(move || {
            let id = sh2.track(&conn);
            handle(conn, &sh2);
            sh2.untrack(id);
            act.fetch_sub(1, Ordering::SeqCst);
        });
        if spawned.is_err() {
            active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

struct Request {
    method: String,
    host: String,
    port: u16,
    /// For plain HTTP: the rewritten request head to send upstream.
    upstream_head: Option<Vec<u8>>,
}

fn respond(c: &mut TcpStream, status: &str, msg: &str) {
    let body = format!("vssb: {msg}\n");
    let _ = write!(
        c,
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\nX-Vssb-Proxy: blocked\r\n\r\n{body}",
        body.len()
    );
}

fn handle(mut client: TcpStream, sh: &Shared) {
    let emit = |e: Event| (sh.events)(&e);
    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    let mut buf = Vec::with_capacity(4096);
    let head_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEAD {
            return respond(&mut client, "431 Request Header Fields Too Large", "request head too large");
        }
        let mut chunk = [0u8; 8192];
        match client.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let _ = client.set_read_timeout(None);
    let rest = buf[head_end + 4..].to_vec();
    let req = match parse_request(&buf[..head_end]) {
        Ok(r) => r,
        Err(e) => return respond(&mut client, "400 Bad Request", &e.to_string()),
    };
    let (method, host, port) = (req.method.clone(), req.host.clone(), req.port);

    let deny = |client: &mut TcpStream, reason: &str| {
        emit(Event::Deny { method: method.clone(), host: host.clone(), port, reason: reason.into() });
        respond(client, "403 Forbidden", &format!("connection to {host}:{port} blocked by sandbox policy ({reason})"));
    };
    let explicit_ip = match sh.policy.decide(&host, port) {
        Decision::Allow { explicit_ip } => explicit_ip,
        Decision::Deny(reason) => return deny(&mut client, &reason),
    };

    // Resolve once, filter, and connect to the checked address.
    let addrs: Vec<SocketAddr> = match (host.as_str(), port).to_socket_addrs() {
        Ok(a) => a.collect(),
        Err(e) => {
            emit(Event::Error { method: method.clone(), host: host.clone(), port, reason: format!("resolve: {e}") });
            return respond(&mut client, "502 Bad Gateway", &format!("cannot resolve {host}: {e}"));
        }
    };
    let usable: Vec<SocketAddr> = addrs.iter().copied().filter(|a| sh.policy.allow_private || explicit_ip || !is_non_public(a.ip())).collect();
    if usable.is_empty() {
        return deny(&mut client, "resolves to a private or loopback address");
    }
    let mut upstream = None;
    let mut last_err = None;
    for a in &usable {
        match TcpStream::connect_timeout(a, Duration::from_secs(15)) {
            Ok(s) => {
                upstream = Some((s, *a));
                break;
            }
            Err(e) => last_err = Some(e),
        }
    }
    let Some((mut up, addr)) = upstream else {
        let e = last_err.map(|e| e.to_string()).unwrap_or_default();
        emit(Event::Error { method: method.clone(), host: host.clone(), port, reason: format!("connect: {e}") });
        return respond(&mut client, "502 Bad Gateway", &format!("cannot connect to {host}:{port}: {e}"));
    };
    let up_id = sh.track(&up);
    emit(Event::Allow { method: method.clone(), host: host.clone(), port, addr });

    let sent = match &req.upstream_head {
        None => client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n"),
        Some(head) => up.write_all(head),
    };
    if sent.is_ok() && (rest.is_empty() || up.write_all(&rest).is_ok()) {
        let start = Instant::now();
        let (bytes_up, bytes_down) = pump(client, up);
        emit(Event::Close { host, port, bytes_up: bytes_up + rest.len() as u64, bytes_down, duration: start.elapsed() });
    }
    sh.untrack(up_id);
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn parse_request(head: &[u8]) -> Result<Request> {
    let text = std::str::from_utf8(head).map_err(|_| bad("request head is not UTF-8".into()))?;
    let mut lines = text.split("\r\n");
    let line = lines.next().unwrap_or_default();
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(bad("malformed request line".into()));
    };
    if !version.starts_with("HTTP/1.") {
        return Err(bad(format!("unsupported protocol {version:?}")));
    }
    let headers: Vec<&str> = lines.collect();

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_authority(target, None)?;
        return Ok(Request { method: "CONNECT".into(), host, port, upstream_head: None });
    }

    let Some(rest) = target.get(..7).filter(|p| p.eq_ignore_ascii_case("http://")).map(|_| &target[7..]) else {
        return Err(bad(format!("only CONNECT and absolute http:// requests are supported (got {target:?})")));
    };
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_string()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, "/".to_string()),
    };
    if authority.contains('@') {
        return Err(bad("credentials in proxy URLs are not supported".into()));
    }
    let (host, port) = parse_authority(authority, Some(80))?;

    let mut out = format!("{method} {path} {version}\r\n");
    let mut saw_host = false;
    for h in headers {
        let Some((name, value)) = h.split_once(':') else { return Err(bad("malformed header line".into())) };
        match name.trim().to_ascii_lowercase().as_str() {
            "proxy-connection" | "proxy-authorization" | "connection" | "keep-alive" => continue,
            "host" => {
                let (hh, _) = parse_authority(value.trim(), Some(port))?;
                if hh != host {
                    return Err(bad(format!("Host header {hh:?} does not match the request target {host:?}")));
                }
                saw_host = true;
            }
            _ => {}
        }
        out.push_str(h);
        out.push_str("\r\n");
    }
    if !saw_host {
        out.push_str(&format!("Host: {authority}\r\n"));
    }
    // One request per connection, so every request is checked.
    out.push_str("Connection: close\r\n\r\n");
    Ok(Request { method: method.to_string(), host, port, upstream_head: Some(out.into_bytes()) })
}

fn parse_authority(a: &str, default_port: Option<u16>) -> Result<(String, u16)> {
    let lower = a.to_ascii_lowercase();
    let (host, port) = split_host_port(&lower)?;
    let port = match (port, default_port) {
        (Some(p), _) => p.parse().map_err(|_| bad(format!("invalid port in {a:?}")))?,
        (None, Some(d)) => d,
        (None, None) => return Err(bad(format!("{a:?}: CONNECT needs host:port"))),
    };
    let host = host.trim_end_matches('.').to_string();
    validate_host(&host)?;
    if port == 0 {
        return Err(bad("invalid port 0".into()));
    }
    Ok((host, port))
}

/// Copies both ways until both sides are done. Returns (client→upstream, upstream→client) bytes.
fn pump(client: TcpStream, upstream: TcpStream) -> (u64, u64) {
    let (Ok(mut c_read), Ok(mut u_write)) = (client.try_clone(), upstream.try_clone()) else {
        return (0, 0);
    };
    let t = std::thread::Builder::new().stack_size(64 * 1024).spawn(move || {
        let n = io::copy(&mut c_read, &mut u_write).unwrap_or(0);
        let _ = u_write.shutdown(Shutdown::Write);
        n
    });
    let (mut u_read, mut c_write) = (upstream, client);
    let down = io::copy(&mut u_read, &mut c_write).unwrap_or(0);
    // Upstream is finished: close the client fully so the other copy ends too.
    let _ = c_write.shutdown(Shutdown::Both);
    let _ = u_read.shutdown(Shutdown::Both);
    let up = t.ok().and_then(|t| t.join().ok()).unwrap_or(0);
    (up, down)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pol(allow: &[&str], deny: &[&str]) -> NetPolicy {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        NetPolicy::new(&s(allow), &s(deny), false).unwrap()
    }

    #[test]
    fn matching() {
        let p = pol(&["api.anthropic.com", "*.github.com", "example.org:8443", "any.port:*"], &["bad.github.com"]);
        assert_eq!(p.decide("api.anthropic.com", 443), Decision::Allow { explicit_ip: false });
        assert!(matches!(p.decide("api.anthropic.com", 22), Decision::Deny(_)));
        assert!(matches!(p.decide("evil-api.anthropic.com", 443), Decision::Deny(_)));
        assert!(matches!(p.decide("github.com", 443), Decision::Deny(_)));
        assert!(matches!(p.decide("raw.github.com", 80), Decision::Allow { .. }));
        assert!(matches!(p.decide("bad.github.com", 443), Decision::Deny(_)));
        assert!(matches!(p.decide("xgithub.com", 443), Decision::Deny(_)));
        assert!(matches!(p.decide("example.org", 8443), Decision::Allow { .. }));
        assert!(matches!(p.decide("example.org", 443), Decision::Deny(_)));
        assert!(matches!(p.decide("any.port", 5432), Decision::Allow { .. }));
        let ip = pol(&["10.0.0.5:5432"], &[]);
        assert_eq!(ip.decide("10.0.0.5", 5432), Decision::Allow { explicit_ip: true });
    }

    #[test]
    fn private_ranges() {
        for a in ["127.0.0.1", "10.1.2.3", "192.168.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "64:ff9b::a00:1"] {
            assert!(is_non_public(a.parse().unwrap()), "{a}");
        }
        for a in ["1.1.1.1", "140.82.112.3", "2606:4700::1111"] {
            assert!(!is_non_public(a.parse().unwrap()), "{a}");
        }
    }

    #[test]
    fn requests() {
        let r = parse_request(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443").unwrap();
        assert_eq!((r.host.as_str(), r.port), ("api.anthropic.com", 443));
        let r = parse_request(b"GET http://Example.com/a?b HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive").unwrap();
        assert_eq!((r.host.as_str(), r.port), ("example.com", 80));
        let head = String::from_utf8(r.upstream_head.unwrap()).unwrap();
        assert!(head.starts_with("GET /a?b HTTP/1.1\r\n"));
        assert!(!head.contains("Proxy-Connection"));
        assert!(head.ends_with("Connection: close\r\n\r\n"));
        assert!(parse_request(b"GET http://a.com/ HTTP/1.1\r\nHost: b.com").is_err());
        assert!(parse_request(b"GET /relative HTTP/1.1").is_err());
        assert!(parse_request(b"CONNECT [::1]:443 HTTP/1.1").is_ok());
        assert!(parse_request(b"CONNECT host HTTP/1.1").is_err());
    }
}
