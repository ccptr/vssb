//! End-to-end checks of the guarantees. Cargo runs these tests on many
//! threads at once, which also exercises spawning from a multi-threaded
//! host. Needs python3 and sh on the host; the limit tests need a systemd
//! user manager and are skipped without one.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use vssb::{Cgroup, Command, Error, ExitStatus, Limits, Mount, Net, Resource, Sandbox, Stdio};

/// A fresh host directory, removed on drop.
struct Dir(PathBuf);

impl Dir {
    fn new() -> Dir {
        static N: AtomicUsize = AtomicUsize::new(0);
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let p = base.join(format!("vssb-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&p).unwrap();
        Dir(p)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The system view with `dir` writable.
fn sandbox(dir: &Dir) -> Sandbox {
    let mut sb = Sandbox::new();
    sb.system(true).mount(Mount::rw(&dir.0));
    sb
}

fn sh(dir: &Dir, script: &str) -> Command {
    let mut c = Command::new("sh");
    c.args(["-c", script]).cwd(&dir.0).env("PATH", "/usr/bin:/bin").stdout(Stdio::Piped).stderr(Stdio::Piped);
    c
}

/// Runs to completion; returns the status and stdout+stderr.
fn run(sb: &Sandbox, cmd: Command) -> (ExitStatus, String) {
    let mut child = sb.spawn(cmd).expect("spawn");
    let mut out = String::new();
    let mut err = String::new();
    child.stdout.take().unwrap().read_to_string(&mut out).unwrap();
    child.stderr.take().unwrap().read_to_string(&mut err).unwrap();
    let s = child.wait().unwrap();
    (s, out + &err)
}

fn code(sb: &Sandbox, dir: &Dir, script: &str) -> i32 {
    let (s, out) = run(sb, sh(dir, script));
    let c = s.shell_code();
    if c > 128 {
        eprintln!("{script}: {s}: {out}");
    }
    c
}

fn output(sb: &Sandbox, dir: &Dir, script: &str) -> String {
    run(sb, sh(dir, script)).1
}

fn python(dir: &Dir, code: &str) -> Command {
    let mut c = Command::new("python3");
    c.args(["-c", code]).cwd(&dir.0).env("PATH", "/usr/bin:/bin").stdout(Stdio::Piped).stderr(Stdio::Piped);
    c
}

fn alive(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(s) => !s.rsplit(')').next().unwrap_or("").trim_start().starts_with('Z'),
        Err(_) => false,
    }
}

/// Whether any process on the host has `needle` in its command line.
fn host_has_process(needle: &str) -> bool {
    std::fs::read_dir("/proc").unwrap().flatten().any(|e| {
        std::fs::read(e.path().join("cmdline")).map(|c| String::from_utf8_lossy(&c).replace('\0', " ").contains(needle)).unwrap_or(false)
    })
}

fn eventually(mut f: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(5);
    while Instant::now() < end {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

// == basics

#[test]
fn exit_codes_and_signals() {
    let d = Dir::new();
    let sb = sandbox(&d);
    assert_eq!(code(&sb, &d, "exit 42"), 42);
    let (s, _) = run(&sb, sh(&d, "kill -9 $$"));
    assert_eq!(s.signal(), Some(9));
    assert_eq!(s.shell_code(), 137);
}

#[test]
fn exec_errors() {
    let d = Dir::new();
    let sb = sandbox(&d);
    let e = sb.spawn(Command::new("/nonexistent/cmd")).unwrap_err();
    assert!(matches!(e, Error::Exec { .. }), "{e}");
    assert_eq!(e.shell_code(), 127);
    let mut c = Command::new("no-such-program-vssb");
    c.env("PATH", "/usr/bin:/bin");
    assert_eq!(sb.spawn(c).unwrap_err().shell_code(), 127);
    std::fs::write(d.0.join("noexec"), "#!/bin/sh\n").unwrap();
    assert_eq!(sb.spawn(Command::new(d.0.join("noexec"))).unwrap_err().shell_code(), 126);
}

#[test]
fn namespaces() {
    let d = Dir::new();
    let mut sb = sandbox(&d);
    sb.hostname("box");
    assert_eq!(output(&sb, &d, "echo $$").trim(), "2");
    assert_eq!(output(&sb, &d, "cat /proc/sys/kernel/hostname").trim(), "box");
    assert_eq!(output(&sb, &d, "id -u").trim(), unsafe { libc::getuid() }.to_string());
    // PID 1, sh, ls and grep.
    assert_eq!(output(&sb, &d, "ls /proc | grep -c '^[0-9]'").trim(), "4", "host processes are invisible");
    sb.uid(0).gid(0);
    assert_eq!(output(&sb, &d, "id -u").trim(), "0");
    // ...without any capabilities.
    assert!(output(&sb, &d, "grep CapEff /proc/self/status").contains("0000000000000000"));
}

#[test]
fn environment_is_explicit() {
    let d = Dir::new();
    let sb = sandbox(&d);
    let mut c = sh(&d, "env | sort");
    c.env("FOO", "bar");
    let out = run(&sb, c).1;
    let names: Vec<&str> = out.lines().map(|l| l.split('=').next().unwrap()).filter(|n| *n != "PWD" && *n != "SHLVL" && *n != "_").collect();
    assert_eq!(names, ["FOO", "PATH"], "{out}");
}

#[test]
fn sigpipe_has_its_default() {
    let d = Dir::new();
    let sb = sandbox(&d);
    let mut c = Command::new("bash");
    c.args(["-c", "yes | head -1 >/dev/null; echo ${PIPESTATUS[0]}"]).cwd(&d.0).env("PATH", "/usr/bin:/bin").stdout(Stdio::Piped).stderr(Stdio::Piped);
    assert_eq!(run(&sb, c).1.trim(), "141", "yes dies of SIGPIPE");
}

// == filesystem

#[test]
fn filesystem_view() {
    let d = Dir::new();
    let sb = sandbox(&d);
    assert_eq!(code(&sb, &d, "echo hi > out.txt"), 0);
    assert_eq!(std::fs::read_to_string(d.0.join("out.txt")).unwrap(), "hi\n");
    assert_eq!(code(&sb, &d, "touch /usr/vssb-x"), 1);
    assert_eq!(code(&sb, &d, "touch /etc/vssb-x"), 1);
    assert_eq!(code(&sb, &d, "touch /vssb-x"), 1, "the root is read-only");
    let secret = Dir::new();
    std::fs::write(secret.0.join("s"), "x").unwrap();
    assert_ne!(code(&sb, &d, &format!("cat {}/s", secret.0.display())), 0, "unlisted host paths are invisible");
    assert_eq!(code(&sb, &d, "test -z \"$(ls /tmp | grep -v vssb-test)\""), 0, "/tmp is private");
}

#[test]
fn ro_deny_tmpfs() {
    let d = Dir::new();
    std::fs::create_dir_all(d.0.join("data")).unwrap();
    std::fs::write(d.0.join("data/f"), "d").unwrap();
    std::fs::write(d.0.join(".env"), "topsecret").unwrap();
    std::fs::create_dir_all(d.0.join(".git")).unwrap();
    std::fs::write(d.0.join(".git/config"), "cfg").unwrap();
    let mut sb = sandbox(&d);
    sb.mount(Mount::ro(d.0.join("data")))
        .mount(Mount::deny(d.0.join(".env")))
        .mount(Mount::deny(d.0.join(".git")))
        .mount(Mount::tmpfs(d.0.join("scratch")).optional());
    assert_eq!(code(&sb, &d, "cat data/f"), 0);
    assert_eq!(code(&sb, &d, "echo x > data/f"), 1);
    assert_ne!(code(&sb, &d, "cat .env"), 0);
    assert_ne!(code(&sb, &d, "echo x > .env"), 0);
    assert_eq!(std::fs::read_to_string(d.0.join(".env")).unwrap(), "topsecret");
    assert_ne!(code(&sb, &d, "ls .git"), 0);

    let mut sb = sandbox(&d);
    sb.mount(Mount::tmpfs(d.0.join("data")));
    assert_eq!(code(&sb, &d, "test ! -e data/f && touch data/new"), 0);
    assert!(!d.0.join("data/new").exists(), "tmpfs writes stay inside");
}

#[test]
fn mount_points_are_never_created_in_host_directories() {
    let d = Dir::new();
    let mut sb = sandbox(&d);
    sb.mount(Mount::tmpfs(d.0.join("missing/deeper")));
    let e = sb.spawn(sh(&d, "true")).unwrap_err();
    assert!(e.to_string().contains("won't create it"), "{e}");
    assert!(!d.0.join("missing").exists());
    // ...unless optional, in which case it's skipped.
    let mut sb = sandbox(&d);
    sb.mount(Mount::tmpfs(d.0.join("missing/deeper")).optional());
    assert_eq!(code(&sb, &d, "test ! -e missing"), 0);
}

#[test]
fn no_mounting_through_symlinks() {
    let d = Dir::new();
    std::os::unix::fs::symlink("/etc", d.0.join("sneaky")).unwrap();
    let mut sb = sandbox(&d);
    sb.mount(Mount::tmpfs(d.0.join("sneaky/x")));
    let e = sb.spawn(sh(&d, "true")).unwrap_err();
    assert!(e.to_string().contains("symlink"), "{e}");
}

#[test]
fn missing_sources_are_config_errors() {
    let d = Dir::new();
    let mut sb = sandbox(&d);
    sb.mount(Mount::ro("/vssb-surely-missing"));
    assert!(matches!(sb.spawn(sh(&d, "true")), Err(Error::Config(_))));
}

#[test]
fn noexec() {
    let d = Dir::new();
    std::fs::copy("/usr/bin/true", d.0.join("mytrue")).unwrap();
    let mut sb = Sandbox::new();
    sb.system(true).mount(Mount::rw(&d.0).noexec());
    assert_eq!(sb.spawn(Command::new(d.0.join("mytrue"))).unwrap_err().shell_code(), 126);
}

#[test]
fn devices() {
    let d = Dir::new();
    let sb = sandbox(&d);
    assert_eq!(code(&sb, &d, "echo x > /dev/null && head -c1 /dev/urandom >/dev/null"), 0);
    assert_eq!(run(&sb, python(&d, "import pty; pty.openpty()")).0.code(), Some(0));
    assert_eq!(code(&sb, &d, "echo x > /dev/shm/a && cat /dev/shm/a"), 0);
}

#[test]
fn host_unix_sockets_are_unreachable() {
    if vssb::probe().landlock_abi < 9 {
        return;
    }
    let d = Dir::new();
    let sock_dir = Dir::new();
    let path = sock_dir.0.join("s");
    let _l = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let mut sb = sandbox(&d);
    sb.mount(Mount::ro(&sock_dir.0));
    let out = run(&sb, python(&d, &format!("import socket\ns=socket.socket(socket.AF_UNIX)\ntry: s.connect({:?}); print('connected')\nexcept OSError as e: print(e)", path))).1;
    assert!(out.contains("Errno 13") || out.contains("Errno 1"), "{out}");
    // Its own sockets work.
    let out = run(&sb, python(&d, "import socket\np='/tmp/own.sock'; s=socket.socket(socket.AF_UNIX); s.bind(p); s.listen()\nc=socket.socket(socket.AF_UNIX); c.connect(p); print('ok')")).1;
    assert_eq!(out.trim(), "ok");
}

// == syscalls

#[test]
fn seccomp_filter() {
    let d = Dir::new();
    let sb = sandbox(&d);
    assert_ne!(code(&sb, &d, "unshare -r true"), 0, "no nested user namespaces");
    let py = |c: &str| run(&sb, python(&d, c)).1;
    assert!(py("import ctypes,os; l=ctypes.CDLL(None,use_errno=True); l.ptrace(16,1,0,0); print(os.strerror(ctypes.get_errno()))").contains("Operation not permitted"));
    assert!(py("import socket\ntry: socket.socket(socket.AF_PACKET, socket.SOCK_RAW)\nexcept OSError as e: print(e)").contains("Errno 97"));
    assert!(py("import ctypes; l=ctypes.CDLL(None,use_errno=True); p=ctypes.create_string_buffer(120); l.syscall(425,8,p); print('Errno', ctypes.get_errno())").contains("Errno 1"));
    assert_eq!(run(&sb, python(&d, "import threading; t=threading.Thread(target=print); t.start(); t.join()")).0.code(), Some(0), "threads work");
    assert!(output(&sb, &d, "cat /proc/1/environ").contains("Permission denied"), "PID 1 is off limits");
    let mut sb2 = sandbox(&d);
    sb2.seccomp_allow("ptrace");
    let out = run(&sb2, python(&d, "import ctypes,os; l=ctypes.CDLL(None,use_errno=True); l.ptrace(0,0,0,0); print(os.strerror(ctypes.get_errno()))")).1;
    assert!(!out.contains("Operation not permitted"), "{out}");
}

#[test]
fn rlimits() {
    let d = Dir::new();
    let mut sb = sandbox(&d);
    sb.rlimit(Resource::NoFile, 64);
    assert_eq!(output(&sb, &d, "ulimit -n").trim(), "64");
    assert_eq!(output(&sb, &d, "ulimit -c").trim(), "0");
}

// == descriptors

#[test]
fn piped_stdio() {
    let d = Dir::new();
    let sb = sandbox(&d);
    let mut c = Command::new("cat");
    c.env("PATH", "/usr/bin:/bin").stdin(Stdio::Piped).stdout(Stdio::Piped);
    let mut child = sb.spawn(c).unwrap();
    child.stdin.take().unwrap().write_all(b"round trip").unwrap();
    let mut out = String::new();
    child.stdout.take().unwrap().read_to_string(&mut out).unwrap();
    assert_eq!(out, "round trip");
    assert!(child.wait().unwrap().success());
}

#[test]
fn pass_fd() {
    let d = Dir::new();
    let sb = sandbox(&d);
    let mut p = [0; 2];
    assert_eq!(unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    let (r, w) = unsafe { (OwnedFd::from_raw_fd(p[0]), OwnedFd::from_raw_fd(p[1])) };
    let mut c = sh(&d, "echo via-fd >&5; ls /proc/self/fd | tr '\\n' ' '");
    c.pass_fd(5, w);
    let (s, out) = run(&sb, c);
    assert!(s.success());
    let mut got = String::new();
    std::fs::File::from(r).read_to_string(&mut got).unwrap();
    assert_eq!(got, "via-fd\n");
    // Only stdio, the passed fd, and the one ls opened.
    assert_eq!(out.split_whitespace().collect::<Vec<_>>(), ["0", "1", "2", "3", "5"], "{out}");
}

// == lifecycle

#[test]
fn terminate_and_kill() {
    let d = Dir::new();
    let sb = sandbox(&d);
    let mut child = sb.spawn(sh(&d, "trap 'exit 3' TERM; sleep 30 & wait")).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(child.terminate(Duration::from_secs(5)).unwrap().code(), Some(3), "SIGTERM is forwarded");

    let start = Instant::now();
    let mut child = sb.spawn(sh(&d, "trap '' TERM; while :; do sleep 0.1; done")).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let s = child.terminate(Duration::from_millis(500)).unwrap();
    assert_eq!(s.signal(), Some(9), "killed after the grace period");
    assert!(start.elapsed() < Duration::from_secs(4));
}

#[test]
fn wait_timeout() {
    let d = Dir::new();
    let sb = sandbox(&d);
    let mut child = sb.spawn(sh(&d, "sleep 30")).unwrap();
    assert_eq!(child.wait_timeout(Duration::from_millis(200)).unwrap(), None);
    child.kill().unwrap();
    assert!(child.wait_timeout(Duration::from_secs(5)).unwrap().is_some());
}

#[test]
fn leftover_processes_are_killed() {
    let d = Dir::new();
    let sb = sandbox(&d);
    assert_eq!(code(&sb, &d, "sleep 4242.1 & echo started"), 0);
    assert!(eventually(|| !host_has_process("sleep 4242.1")));
}

#[test]
fn dropping_the_child_kills_the_sandbox() {
    let d = Dir::new();
    let sb = sandbox(&d);
    let child = sb.spawn(sh(&d, "sleep 4242.2")).unwrap();
    let pid = child.id();
    drop(child);
    assert!(!alive(pid));
    assert!(eventually(|| !host_has_process("sleep 4242.2")));
}

#[test]
fn the_spawning_thread_may_exit() {
    let d = Dir::new();
    let sb = sandbox(&d);
    let mut child = std::thread::spawn(move || sb.spawn(sh(&d, "sleep 1; echo done")).unwrap()).join().unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(child.try_wait().unwrap(), None, "still running after its thread exited");
    let mut out = String::new();
    child.stdout.take().unwrap().read_to_string(&mut out).unwrap();
    assert_eq!(out, "done\n");
    assert!(child.wait().unwrap().success());
}

#[test]
fn the_hosts_waitpid_cant_reap_it() {
    let d = Dir::new();
    let sb = sandbox(&d);
    let mut child = sb.spawn(sh(&d, "true")).unwrap();
    let mut pfd = libc::pollfd { fd: child.pidfd().as_raw_fd(), events: libc::POLLIN, revents: 0 };
    unsafe { libc::poll(&mut pfd, 1, 5000) };
    // WNOWAIT: don't take other tests' children.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    unsafe { libc::waitid(libc::P_ALL, 0, &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT) };
    assert_ne!(unsafe { info.si_pid() } as u32, child.id());
    assert!(child.wait().unwrap().success());
}

#[test]
fn concurrent_spawns() {
    let d = Dir::new();
    let sb = sandbox(&d);
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..16).map(|i| { let (sb, d) = (&sb, &d); s.spawn(move || code(sb, d, &format!("exit {i}"))) }).collect();
        for (i, h) in hs.into_iter().enumerate() {
            assert_eq!(h.join().unwrap(), i as i32);
        }
    });
}

/// Other threads holding libc locks (sigaction's, malloc's, thread and
/// process creation's) at clone time
/// must not hang the child: it may only make raw syscalls.
#[test]
fn spawning_while_other_threads_hold_libc_locks() {
    let d = Dir::new();
    let sb = sandbox(&d);
    let stop = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|s| {
        for _ in 0..8 {
            s.spawn(|| {
                let mut v: Vec<Vec<u8>> = Vec::new();
                while !stop.load(Ordering::Relaxed) {
                    unsafe { libc::signal(libc::SIGUSR2, libc::SIG_IGN) };
                    std::thread::spawn(|| ()).join().unwrap();
                    let _ = std::process::Command::new("/usr/bin/true").status();
                    v.push(vec![0; 4096]);
                    if v.len() > 64 {
                        v.clear();
                    }
                }
            });
        }
        let start = Instant::now();
        for _ in 0..200 {
            let mut child = sb.spawn(Command::new("/usr/bin/true")).unwrap();
            let s = child.wait_timeout(Duration::from_secs(10)).unwrap();
            assert!(s.is_some_and(|s| s.success()), "{s:?}");
        }
        stop.store(true, Ordering::Relaxed);
        assert!(start.elapsed() < Duration::from_secs(60));
    });
}

/// Run by `sandbox_dies_with_its_host`: starts a sandbox, prints its pid, hangs.
#[test]
#[ignore]
fn helper_spawn_and_hang() {
    if std::env::var_os("VSSB_HELPER").is_none() {
        return;
    }
    let d = Dir::new();
    let child = sandbox(&d).spawn(sh(&d, "sleep 4242.3")).unwrap();
    println!("PID {}", child.id());
    std::io::stdout().flush().unwrap();
    std::thread::sleep(Duration::from_secs(60));
}

#[test]
fn sandbox_dies_with_its_host() {
    let mut helper = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "helper_spawn_and_hang", "--ignored", "--nocapture", "--test-threads=1"])
        .env("VSSB_HELPER", "1")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = helper.stdout.take().unwrap();
    let mut buf = Vec::new();
    let mut b = [0u8; 256];
    let pid: u32 = loop {
        let n = out.read(&mut b).unwrap();
        assert!(n > 0, "helper exited early: {}", String::from_utf8_lossy(&buf));
        buf.extend_from_slice(&b[..n]);
        let s = String::from_utf8_lossy(&buf);
        if let Some((_, rest)) = s.split_once("PID ")
            && let Some((num, _)) = rest.split_once('\n')
            && let Ok(p) = num.trim().parse()
        {
            break p;
        }
    };
    assert!(alive(pid));
    helper.kill().unwrap();
    helper.wait().unwrap();
    assert!(eventually(|| !alive(pid)), "sandbox survived its host");
    assert!(eventually(|| !host_has_process("sleep 4242.3")));
}

// == network

#[test]
fn only_loopback() {
    let d = Dir::new();
    let sb = sandbox(&d);
    let out = run(&sb, python(&d, "import socket; print(*[n for _, n in socket.if_nameindex()])")).1;
    assert_eq!(out.trim(), "lo");
}

#[test]
fn listeners_reach_the_host() {
    let d = Dir::new();
    let mut sb = sandbox(&d);
    sb.listen_tcp(8123);
    let mut child = sb.spawn(python(&d, "import socket; s=socket.create_connection(('127.0.0.1', 8123)); s.sendall(b'hello'); print(s.recv(10).decode())")).unwrap();
    let l = child.take_listeners().remove(0);
    let (mut conn, _) = l.accept().unwrap();
    let mut got = [0u8; 5];
    conn.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"hello");
    conn.write_all(b"back").unwrap();
    drop(conn);
    let mut out = String::new();
    child.stdout.take().unwrap().read_to_string(&mut out).unwrap();
    assert_eq!(out.trim(), "back");
    assert!(child.wait().unwrap().success());
}

#[test]
fn tcp_ports_with_host_network() {
    if vssb::probe().landlock_abi < 4 {
        return;
    }
    let (a, b) = (std::net::TcpListener::bind("127.0.0.1:0").unwrap(), std::net::TcpListener::bind("127.0.0.1:0").unwrap());
    let (pa, pb) = (a.local_addr().unwrap().port(), b.local_addr().unwrap().port());
    let d = Dir::new();
    let mut sb = sandbox(&d);
    sb.net(Net::Host).tcp_connect([pa]);
    let try_port = |p: u16| run(&sb, python(&d, &format!("import socket\ntry: socket.create_connection(('127.0.0.1', {p})); print('ok')\nexcept OSError as e: print(e)"))).1;
    assert_eq!(try_port(pa).trim(), "ok");
    assert!(try_port(pb).contains("Errno 13") || try_port(pb).contains("Permission denied"));
}

#[test]
fn abstract_sockets_are_scoped() {
    if vssb::probe().landlock_abi < 6 {
        return;
    }
    let name = format!("\0vssb-test-{}", std::process::id());
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as u16;
    for (i, b) in name.bytes().enumerate() {
        addr.sun_path[i] = b as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + name.len()) as u32;
    unsafe {
        assert_eq!(libc::bind(fd, (&addr as *const libc::sockaddr_un).cast(), len), 0);
        assert_eq!(libc::listen(fd, 1), 0);
    }
    let d = Dir::new();
    let mut sb = sandbox(&d);
    sb.net(Net::Host);
    let out = run(&sb, python(&d, &format!("import socket\ns=socket.socket(socket.AF_UNIX)\ntry: s.connect({:?}); print('connected')\nexcept OSError as e: print(e)", name))).1;
    unsafe { libc::close(fd) };
    assert!(out.contains("Errno 1"), "{out}");
}

#[cfg(feature = "proxy")]
#[test]
fn proxy_filters_requests() {
    use std::sync::{Arc, Mutex};
    use vssb::proxy;
    // An HTTP server on the host's loopback.
    let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in server.incoming().flatten() {
            let mut c = c;
            let mut b = [0u8; 1024];
            let _ = c.read(&mut b);
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    let d = Dir::new();
    let mut sb = sandbox(&d);
    sb.listen_tcp(3128);
    let script = format!(
        "curl -sS -m 5 -x http://127.0.0.1:3128 http://127.0.0.1:{port}/; echo; curl -sS -m 5 -o /dev/null -w '%{{http_code}}' -x http://127.0.0.1:3128 http://127.0.0.2:{port}/"
    );
    let mut child = sb.spawn(sh(&d, &script)).unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let ev = events.clone();
    let rules = proxy::NetPolicy::new(&[format!("127.0.0.1:{port}")], &[], false).unwrap();
    let handle = proxy::serve(child.take_listeners().remove(0), rules, move |e| ev.lock().unwrap().push(format!("{e:?}"))).unwrap();
    let mut out = String::new();
    child.stdout.take().unwrap().read_to_string(&mut out).unwrap();
    child.wait().unwrap();
    handle.stop();
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines, ["ok", "403"], "{out}");
    let ev = events.lock().unwrap();
    assert!(ev.iter().any(|e| e.starts_with("Allow")) && ev.iter().any(|e| e.starts_with("Deny")), "{ev:?}");
}

// == resource limits

fn limits_available() -> bool {
    vssb::probe().systemd_user
}

#[test]
fn memory_limit() {
    if !limits_available() {
        return;
    }
    let d = Dir::new();
    let mut sb = sandbox(&d);
    sb.limits(Limits { memory: Some(64 << 20), ..Default::default() });
    let (s, _) = run(&sb, python(&d, "b = bytearray(512 << 20); b[::4096] = b'x' * (len(b) // 4096)"));
    assert_eq!(s.signal(), Some(9));
}

#[test]
fn pids_limit_and_cgroup_namespace() {
    if !limits_available() {
        return;
    }
    let d = Dir::new();
    let mut sb = sandbox(&d);
    sb.limits(Limits { pids: Some(16), ..Default::default() });
    let out = output(&sb, &d, "cat /proc/self/cgroup; for i in $(seq 40); do sleep 2 & done 2>&1; wait");
    assert!(out.lines().any(|l| l == "0::/"), "the scope is the cgroup root inside: {out}");
    assert!(out.contains("fork") || out.contains("Resource temporarily unavailable") || out.contains("retry"), "{out}");
}

#[test]
fn freeze_through_the_scope() {
    if !limits_available() {
        return;
    }
    let d = Dir::new();
    let mut sb = sandbox(&d);
    sb.cgroup(Cgroup::SystemdUserScope);
    let mut c = sh(&d, "sleep 0.3; echo done");
    c.id(format!("test-freeze-{}", std::process::id()));
    let mut child = sb.spawn(c).unwrap();
    let cg = child.cgroup().unwrap().to_path_buf();
    assert!(cg.ends_with(format!("vssb-test-freeze-{}.scope", std::process::id())), "{}", cg.display());
    child.freeze(true).unwrap();
    std::thread::sleep(Duration::from_millis(800));
    assert_eq!(child.try_wait().unwrap(), None, "frozen");
    child.freeze(false).unwrap();
    assert!(child.wait().unwrap().success());
}

#[test]
fn probe_reports_support() {
    let s = vssb::probe();
    assert!(s.ready(), "{s:?}");
    assert!(!Path::new(&s.kernel).as_os_str().is_empty());
}
