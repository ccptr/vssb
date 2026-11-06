//! The caller's side: starting a sandbox and the [`Child`] handle.

use crate::cgroup;
use crate::child;
use crate::config::{Command, Sandbox};
use crate::error::{Error, Result};
use crate::prepare::{self, CgroupPlan};
use crate::report::{self, Report};
use crate::sys;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::net::TcpListener;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How the program ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitStatus {
    code: Option<i32>,
    signal: Option<i32>,
}

impl ExitStatus {
    fn from_wait(st: i32) -> ExitStatus {
        if libc::WIFEXITED(st) {
            ExitStatus { code: Some(libc::WEXITSTATUS(st)), signal: None }
        } else {
            ExitStatus { code: None, signal: Some(libc::WTERMSIG(st)) }
        }
    }

    /// The exit code, if the program exited normally.
    pub fn code(&self) -> Option<i32> {
        self.code
    }

    /// The signal that killed it. When the whole sandbox was killed (by
    /// [`Child::kill`] or from outside), this is that signal.
    pub fn signal(&self) -> Option<i32> {
        self.signal
    }

    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// The code, or 128 + the signal, as a shell reports it.
    pub fn shell_code(&self) -> i32 {
        self.code.unwrap_or_else(|| 128 + self.signal.unwrap_or(0))
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.code, self.signal) {
            (Some(c), _) => write!(f, "exit status {c}"),
            (_, Some(s)) => write!(f, "killed by signal {s}"),
            _ => f.write_str("unknown status"),
        }
    }
}

/// A running sandbox. Dropping it kills the sandbox and reaps it; so
/// does the caller's process dying.
#[derive(Debug)]
pub struct Child {
    pid: i32,
    pidfd: OwnedFd,
    ctl: OwnedFd,
    status: Option<ExitStatus>,
    id: String,
    cgroup: Option<PathBuf>,
    listeners: Vec<TcpListener>,
    /// The caller's ends of [`Stdio::Piped`](crate::Stdio::Piped) streams.
    pub stdin: Option<File>,
    pub stdout: Option<File>,
    pub stderr: Option<File>,
}

impl Sandbox {
    /// Starts `cmd` in a new sandbox made from this description. Returns
    /// once the program has been exec'd; setup and exec failures come back
    /// as errors. Safe to call from any thread, and from several at once.
    pub fn spawn(&self, cmd: Command) -> Result<Child> {
        spawn(self, cmd)
    }
}

fn spawn(sb: &Sandbox, cmd: Command) -> Result<Child> {
    let (mut p, mut parent) = prepare::prepare(sb, cmd)?;
    let mut flags = (libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS) as u64;
    if parent.new_net {
        flags |= libc::CLONE_NEWNET as u64;
    }
    let cg = match &parent.cgroup {
        CgroupPlan::Join { fd, .. } => Some(fd.as_raw_fd()),
        _ => None,
    };
    let r = unsafe {
        // Block every signal on this thread across clone, so none of the
        // caller's handlers can run in the child before it resets them.
        let mut all: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut all);
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::pthread_sigmask(libc::SIG_SETMASK, &all, &mut old);
        let r = sys::clone_pidfd(flags, cg);
        if let Ok((0, _)) = r {
            child::pid1(&mut p);
        }
        libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
        r
    };
    drop(std::mem::take(&mut parent.child_side));
    let (pid, pidfd) = r.map_err(|e| {
        let os = io::Error::from_raw_os_error(e);
        match e {
            libc::EPERM | libc::EINVAL | libc::ENOSPC | libc::EUSERS => {
                Error::Unsupported(format!("creating namespaces: {os} (are unprivileged user namespaces enabled? see vssb::probe)"))
            }
            _ => Error::io("clone", os),
        }
    })?;
    drop(p);

    // From here on, returning an error drops `child`, which kills and reaps the sandbox.
    let mut child = Child {
        pid,
        pidfd: unsafe { OwnedFd::from_raw_fd(pidfd) },
        ctl: parent.ctl,
        status: None,
        id: parent.id,
        cgroup: None,
        listeners: Vec::new(),
        stdin: parent.stdin,
        stdout: parent.stdout,
        stderr: parent.stderr,
    };
    write_id_maps(pid, parent.uid, parent.gid)?;
    match &parent.cgroup {
        CgroupPlan::Scope { unit } => child.cgroup = cgroup::enter_scope(pid, unit, &parent.limits, parent.strict)?,
        CgroupPlan::Join { path, .. } => child.cgroup = Some(path.clone()),
        CgroupPlan::None => {}
    }
    sys::send_with_fds(child.ctl.as_raw_fd(), b"G", &[]).map_err(|e| Error::io("starting the sandbox", io::Error::from_raw_os_error(e)))?;

    // EOF means the program was exec'd; a record means a step failed.
    if let Some(rep) = read_report(File::from(parent.status))? {
        let cx = report::Context { dests: &parent.dests, program: &parent.program, listen: &parent.listen };
        return Err(report::to_error(rep, &cx));
    }
    child.listeners = recv_listeners(&child.ctl)?;
    Ok(child)
}

fn write_id_maps(pid: i32, uid: u32, gid: u32) -> Result<()> {
    let proc = PathBuf::from(format!("/proc/{pid}"));
    let (host_uid, host_gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let w = |f: &str, s: String| std::fs::write(proc.join(f), s).map_err(|e| Error::io(format!("writing {f}"), e));
    w("setgroups", "deny".into())?;
    w("uid_map", format!("{uid} {host_uid} 1\n"))?;
    w("gid_map", format!("{gid} {host_gid} 1\n"))
}

fn read_report(mut f: File) -> Result<Option<Report>> {
    let mut buf = [0u8; report::SIZE];
    let mut got = 0;
    while got < buf.len() {
        match f.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::io("reading the sandbox's status", e)),
        }
    }
    match got {
        0 => Ok(None),
        report::SIZE => Ok(Some(Report::from_bytes(&buf))),
        _ => Err(Error::io("reading the sandbox's status", io::Error::from(io::ErrorKind::UnexpectedEof))),
    }
}

fn recv_listeners(ctl: &OwnedFd) -> Result<Vec<TcpListener>> {
    let mut buf = [0u8; 8];
    let mut cbuf = [0u64; 16];
    let mut out = Vec::new();
    unsafe {
        let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&cbuf) as _;
        let n = libc::recvmsg(ctl.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT);
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let count = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / 4;
                let data = libc::CMSG_DATA(c).cast::<i32>();
                for k in 0..count {
                    out.push(TcpListener::from(OwnedFd::from_raw_fd(std::ptr::read_unaligned(data.add(k)))));
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
        if n < 1 || buf[0] != b'L' {
            return Err(Error::Setup { step: "the sandbox exited during setup".into(), source: io::Error::last_os_error() });
        }
    }
    Ok(out)
}

impl Child {
    /// Host pid of the sandbox's init (PID 1 inside).
    pub fn id(&self) -> u32 {
        self.pid as u32
    }

    /// The run's id (as given to [`Command::id`], or random).
    pub fn sandbox_id(&self) -> &str {
        &self.id
    }

    /// A pidfd for the sandbox: it becomes readable when the sandbox
    /// exits, for use with poll/epoll or an async runtime.
    pub fn pidfd(&self) -> BorrowedFd<'_> {
        self.pidfd.as_fd()
    }

    /// The sandbox's cgroup directory, when it has its own.
    pub fn cgroup(&self) -> Option<&Path> {
        self.cgroup.as_deref()
    }

    /// The listening sockets from [`Sandbox::listen_tcp`], in order.
    pub fn take_listeners(&mut self) -> Vec<TcpListener> {
        std::mem::take(&mut self.listeners)
    }

    /// Sends a signal to the program (through PID 1, which forwards
    /// SIGHUP, INT, QUIT, USR1, USR2, ALRM, TERM, CONT, TSTP and WINCH).
    /// SIGKILL kills the whole sandbox.
    pub fn signal(&self, sig: i32) -> io::Result<()> {
        if self.status.is_some() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "the sandbox has already been waited for"));
        }
        let r = unsafe { libc::syscall(libc::SYS_pidfd_send_signal, self.pidfd.as_raw_fd(), sig, std::ptr::null::<libc::siginfo_t>(), 0u32) };
        if r < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    /// Kills every process in the sandbox.
    pub fn kill(&mut self) -> io::Result<()> {
        match self.signal(libc::SIGKILL) {
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(()),
            r => r,
        }
    }

    /// Stops (`true`) or resumes every process in the sandbox, through
    /// its cgroup (needs one: a systemd scope or [`Cgroup::Join`](crate::Cgroup::Join)).
    pub fn freeze(&self, frozen: bool) -> io::Result<()> {
        let dir = self.cgroup.as_ref().ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "the sandbox has no cgroup of its own"))?;
        std::fs::write(dir.join("cgroup.freeze"), if frozen { "1" } else { "0" })
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.waitid(libc::WNOHANG)
    }

    /// Waits for the program to exit (closing `stdin` first, as std does).
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        drop(self.stdin.take());
        loop {
            if let Some(s) = self.waitid(0)? {
                return Ok(s);
            }
        }
    }

    /// Waits at most `timeout`; `None` if the program is still running.
    pub fn wait_timeout(&mut self, timeout: Duration) -> io::Result<Option<ExitStatus>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(s) = self.try_wait()? {
                return Ok(Some(s));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(None);
            }
            let ms = left.as_millis().clamp(1, i32::MAX as u128) as i32;
            let mut pfd = libc::pollfd { fd: self.pidfd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            unsafe { libc::poll(&mut pfd, 1, ms) };
        }
    }

    /// SIGTERM, then SIGKILL for everything if the program hasn't exited
    /// after `grace`.
    pub fn terminate(&mut self, grace: Duration) -> io::Result<ExitStatus> {
        if let Some(s) = self.try_wait()? {
            return Ok(s);
        }
        let _ = self.signal(libc::SIGTERM);
        if let Some(s) = self.wait_timeout(grace)? {
            return Ok(s);
        }
        self.kill()?;
        self.wait()
    }

    fn waitid(&mut self, flags: i32) -> io::Result<Option<ExitStatus>> {
        if let Some(s) = self.status {
            return Ok(Some(s));
        }
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        loop {
            let r = unsafe { libc::waitid(sys::P_PIDFD, self.pidfd.as_raw_fd() as libc::id_t, &mut info, libc::WEXITED | sys::WALL | flags) };
            if r == 0 {
                break;
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
        if unsafe { info.si_pid() } == 0 {
            return Ok(None);
        }
        let st = unsafe { info.si_status() };
        let init = if info.si_code == libc::CLD_EXITED {
            ExitStatus { code: Some(st), signal: None }
        } else {
            ExitStatus { code: None, signal: Some(st) }
        };
        // PID 1 reports the program's own status before it exits.
        let mut buf = [0u8; 8];
        let n = unsafe { libc::recv(self.ctl.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
        let s = if n == 5 && buf[0] == b'X' {
            ExitStatus::from_wait(i32::from_ne_bytes([buf[1], buf[2], buf[3], buf[4]]))
        } else {
            init
        };
        self.status = Some(s);
        Ok(Some(s))
    }
}

impl AsFd for Child {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.pidfd.as_fd()
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if self.status.is_none() {
            let _ = self.kill();
            let _ = self.wait();
        }
    }
}
