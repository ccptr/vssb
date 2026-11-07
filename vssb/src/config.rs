//! The public description of a sandbox and of a command to run in it.
//! Everything here is plain data; nothing touches the system until
//! [`Sandbox::spawn`].

use std::ffi::{OsStr, OsString};
use std::os::fd::{OwnedFd, RawFd};
use std::path::{Path, PathBuf};

/// What to put at a path inside the sandbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MountKind {
    /// A host path (file or directory), read-only or writable.
    Bind { src: PathBuf, writable: bool },
    /// A fresh, empty, writable tmpfs.
    Tmpfs { size: Option<u64> },
    /// Hide whatever would be visible here: an empty mode-000 directory or
    /// file, read-only. Skipped when nothing is there.
    Deny,
    /// A symlink with this target.
    Symlink { target: PathBuf },
    /// A fresh /proc for the sandbox's PID namespace.
    Proc,
    /// A minimal /dev: null, zero, full, random, urandom, tty, a private
    /// devpts and a private /dev/shm.
    Dev { shm_size: Option<u64> },
}

/// One entry of the filesystem view. When two entries name the same
/// `dest`, the later one wins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mount {
    pub dest: PathBuf,
    pub kind: MountKind,
    pub noexec: bool,
    /// Skip silently when the source doesn't exist (or, inside a host
    /// directory, when the mount point is missing).
    pub optional: bool,
    /// Refuse a bind source with a symlink anywhere in its path instead of
    /// resolving it. For callers that resolved the path themselves and
    /// checked where it leads: a symlink planted since then is an error,
    /// not a new destination.
    pub no_symlinks: bool,
}

impl Mount {
    fn new(dest: impl Into<PathBuf>, kind: MountKind) -> Mount {
        Mount { dest: dest.into(), kind, noexec: false, optional: false, no_symlinks: false }
    }

    /// A host path, read-only, at the same place inside.
    pub fn ro(path: impl Into<PathBuf>) -> Mount {
        let p = path.into();
        Mount::ro_at(p.clone(), p)
    }

    /// A host path, read-only, at `dest` inside.
    pub fn ro_at(src: impl Into<PathBuf>, dest: impl Into<PathBuf>) -> Mount {
        Mount::new(dest, MountKind::Bind { src: src.into(), writable: false })
    }

    /// A host path, writable, at the same place inside. Whatever the
    /// sandbox writes there can run later outside it (scripts, hooks…).
    pub fn rw(path: impl Into<PathBuf>) -> Mount {
        let p = path.into();
        Mount::rw_at(p.clone(), p)
    }

    pub fn rw_at(src: impl Into<PathBuf>, dest: impl Into<PathBuf>) -> Mount {
        Mount::new(dest, MountKind::Bind { src: src.into(), writable: true })
    }

    pub fn tmpfs(dest: impl Into<PathBuf>) -> Mount {
        Mount::new(dest, MountKind::Tmpfs { size: None })
    }

    pub fn deny(path: impl Into<PathBuf>) -> Mount {
        Mount { optional: true, ..Mount::new(path, MountKind::Deny) }
    }

    /// A symlink at `dest`. Like mount points, it is only created in
    /// filesystems vssb made, never inside a bind mount (the host's).
    pub fn symlink(dest: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Mount {
        Mount::new(dest, MountKind::Symlink { target: target.into() })
    }

    pub fn proc(dest: impl Into<PathBuf>) -> Mount {
        Mount::new(dest, MountKind::Proc)
    }

    pub fn dev(dest: impl Into<PathBuf>) -> Mount {
        Mount::new(dest, MountKind::Dev { shm_size: None })
    }

    /// Nothing under this mount may be executed.
    pub fn noexec(mut self) -> Mount {
        self.noexec = true;
        self
    }

    pub fn optional(mut self) -> Mount {
        self.optional = true;
        self
    }

    /// Sets the `no_symlinks` field: refuse symlinks in the source path.
    pub fn no_symlinks(mut self) -> Mount {
        self.no_symlinks = true;
        self
    }

    /// Size limit of a tmpfs, or of /dev/shm for a dev mount.
    pub fn size(mut self, bytes: u64) -> Mount {
        match &mut self.kind {
            MountKind::Tmpfs { size } | MountKind::Dev { shm_size: size } => *size = Some(bytes),
            _ => {}
        }
        self
    }
}

/// Network access.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Net {
    /// A private network namespace with only loopback. The host can serve
    /// the sandbox through listeners from [`Sandbox::listen_tcp`].
    #[default]
    None,
    /// The host's network, optionally limited to TCP ports by Landlock
    /// ([`Sandbox::tcp_connect`], [`Sandbox::tcp_bind`]). UDP is unfiltered.
    Host,
}

/// Limits for the whole sandbox. They go through its cgroup when it has
/// one; cpus and pids have fallbacks for when it doesn't (see
/// [`Child::enforcement`](crate::Child::enforcement) for what applied).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Limits {
    /// memory.max in bytes (swap is disabled when set). Needs a cgroup.
    pub memory: Option<u64>,
    /// CPU limit in cores, e.g. 0.5 or 2: a quota (cpu.max) or pinning to
    /// that many CPUs, rounded to the nearest whole number (at least 1).
    /// See [`CpuMethod`].
    pub cpus: Option<f64>,
    /// Processes and threads, init included (so at least 2): pids.max, or
    /// the size of the sandbox's PID namespace. See [`PidsMethod`].
    pub pids: Option<u64>,
    /// How `pids` is enforced.
    pub pids_method: PidsMethod,
    /// How `cpus` is enforced.
    pub cpu_method: CpuMethod,
    /// Which CPUs pinning uses.
    pub cpu_choice: CpuChoice,
}

impl Limits {
    pub fn is_empty(&self) -> bool {
        self.memory.is_none() && self.cpus.is_none() && self.pids.is_none()
    }
}

/// How the `pids` limit is enforced.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PidsMethod {
    /// pids.max in the sandbox's cgroup when it has one; otherwise the
    /// PID namespace.
    #[default]
    Auto,
    /// Only pids.max in the sandbox's cgroup.
    Cgroup,
    /// Only the PID namespace: init sets its `pid_max` and lets pid
    /// numbers wrap before the program starts, so exactly that many fit.
    /// Needs a kernel with a per-namespace `pid_max` (Linux 6.14+).
    PidNamespace,
}

/// How the `cpus` limit is enforced.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CpuMethod {
    /// A quota through the sandbox's cgroup when it has one; otherwise
    /// pinning, forced in strict mode ([`PinForced`](CpuMethod::PinForced)),
    /// plain with strict off ([`Pin`](CpuMethod::Pin)).
    #[default]
    Auto,
    /// Only a quota through the sandbox's cgroup.
    Cgroup,
    /// Pin the sandbox to that many CPUs (`sched_setaffinity`). The
    /// program sees only those, but may widen its own set again, so this
    /// is a hint rather than a limit.
    Pin,
    /// Pin, and deny `sched_setaffinity` to the program (EPERM), so it
    /// can't widen the set. Programs that set their own affinity (Wine's
    /// `SetThreadAffinityMask`, some engines) get an error.
    PinForced,
}

/// Which CPUs pinning picks, within the ones the calling thread may use.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum CpuChoice {
    /// As many physical cores as possible (one hyperthread each before
    /// any second one), rotating from sandbox to sandbox.
    #[default]
    Spread,
    /// As few physical cores as possible (all hyperthreads of a core
    /// before the next core), rotating from sandbox to sandbox.
    Pack,
    /// The first N of these CPU numbers, in this order.
    List(Vec<u32>),
}

/// How [`Child::freeze`](crate::Child::freeze) pauses the sandbox.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FreezeMethod {
    /// The cgroup freezer when the sandbox has a cgroup; otherwise signals.
    #[default]
    Auto,
    /// Only the cgroup freezer (an error without a cgroup).
    Cgroup,
    /// SIGSTOP and SIGCONT to every process in the sandbox. Programs can
    /// tell: a SIGCONT handler runs on resume, and parents see their
    /// children stop and continue (job-control shells react to that).
    /// While paused, forwarded SIGCONT and SIGTSTP are held back.
    Signals,
}

/// How one limit is in effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Via {
    /// Through the sandbox's cgroup.
    Cgroup,
    /// Pinned to these CPUs; `forced` when `sched_setaffinity` is denied.
    Pinned { cpus: Vec<u32>, forced: bool },
    /// Through the size of the sandbox's PID namespace.
    PidNamespace,
    /// Not in effect (only possible with strict mode off).
    NotEnforced,
}

/// How each limit that was set is in effect (`None`: not set).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Enforcement {
    pub memory: Option<Via>,
    pub cpus: Option<Via>,
    pub pids: Option<Via>,
}

/// Where the sandbox's processes live in the cgroup tree.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Cgroup {
    /// A systemd user scope when a limit that goes through a cgroup is
    /// set; otherwise the caller's own cgroup. If no scope can be created
    /// (no systemd user manager), cpus and pids use their fallbacks and
    /// only a memory limit (or [`CpuMethod::Cgroup`]) fails in strict mode.
    #[default]
    Auto,
    /// Always the caller's cgroup. Only limits with a fallback (cpus,
    /// pids) can be set.
    Inherit,
    /// A new transient systemd user scope (`vssb-<id>.scope`), created
    /// over D-Bus with `busctl`, even without limits (for
    /// [`Child::freeze`](crate::Child::freeze) through the cgroup). In
    /// strict mode, failing to create it is an error.
    SystemdUserScope,
    /// An existing cgroup v2 directory the caller prepared (for example
    /// in a delegated subtree). The sandbox starts in it directly
    /// (`CLONE_INTO_CGROUP`); limits, if set, are written to it first.
    Join(PathBuf),
}

/// Resource limits (setrlimit) for the program. The core size is always 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resource {
    NoFile,
    FileSize,
    AddressSpace,
    Data,
    Stack,
    CpuTime,
    Processes,
    MemLock,
}

impl Resource {
    pub(crate) fn raw(self) -> u32 {
        (match self {
            Resource::NoFile => libc::RLIMIT_NOFILE,
            Resource::FileSize => libc::RLIMIT_FSIZE,
            Resource::AddressSpace => libc::RLIMIT_AS,
            Resource::Data => libc::RLIMIT_DATA,
            Resource::Stack => libc::RLIMIT_STACK,
            Resource::CpuTime => libc::RLIMIT_CPU,
            Resource::Processes => libc::RLIMIT_NPROC,
            Resource::MemLock => libc::RLIMIT_MEMLOCK,
        }) as u32
    }
}

/// A sandbox description. Reusable: each [`spawn`](Sandbox::spawn) makes
/// a new, independent sandbox from it.
#[derive(Clone, Debug)]
pub struct Sandbox {
    pub(crate) system: bool,
    pub(crate) mounts: Vec<Mount>,
    pub(crate) hostname: String,
    pub(crate) uid: Option<u32>,
    pub(crate) gid: Option<u32>,
    pub(crate) net: Net,
    pub(crate) listen: Vec<u16>,
    pub(crate) tcp_connect: Option<Vec<u16>>,
    pub(crate) tcp_bind: Option<Vec<u16>>,
    pub(crate) seccomp_allow: Vec<String>,
    pub(crate) seccomp_deny: Vec<String>,
    pub(crate) rlimits: Vec<(Resource, u64)>,
    pub(crate) limits: Limits,
    pub(crate) cgroup: Cgroup,
    pub(crate) freeze: FreezeMethod,
    pub(crate) strict: bool,
}

impl Default for Sandbox {
    fn default() -> Self {
        Sandbox::new()
    }
}

impl Sandbox {
    /// An empty view (nothing is mounted), no network, strict.
    pub fn new() -> Sandbox {
        Sandbox {
            system: false,
            mounts: Vec::new(),
            hostname: "sandbox".into(),
            uid: None,
            gid: None,
            net: Net::None,
            listen: Vec::new(),
            tcp_connect: None,
            tcp_bind: None,
            seccomp_allow: Vec::new(),
            seccomp_deny: Vec::new(),
            rlimits: Vec::new(),
            limits: Limits::default(),
            cgroup: Cgroup::Auto,
            freeze: FreezeMethod::Auto,
            strict: true,
        }
    }

    /// Adds the usual system view under your own entries: read-only /usr,
    /// /etc, /opt, /bin, /sbin, /lib*, /nix/store (host symlinks such as
    /// /bin -> usr/bin are recreated as symlinks), fresh /tmp, /var/tmp
    /// and /run tmpfs, /proc and /dev, and with [`Net::Host`] the target
    /// of /etc/resolv.conf.
    pub fn system(&mut self, on: bool) -> &mut Self {
        self.system = on;
        self
    }

    pub fn mount(&mut self, m: Mount) -> &mut Self {
        self.mounts.push(m);
        self
    }

    pub fn mounts(&mut self, ms: impl IntoIterator<Item = Mount>) -> &mut Self {
        self.mounts.extend(ms);
        self
    }

    pub fn hostname(&mut self, h: impl Into<String>) -> &mut Self {
        self.hostname = h.into();
        self
    }

    /// The uid inside (default: the caller's). It maps to the caller's uid.
    pub fn uid(&mut self, uid: u32) -> &mut Self {
        self.uid = Some(uid);
        self
    }

    pub fn gid(&mut self, gid: u32) -> &mut Self {
        self.gid = Some(gid);
        self
    }

    pub fn net(&mut self, n: Net) -> &mut Self {
        self.net = n;
        self
    }

    /// Listens on 127.0.0.1:`port` inside the sandbox's network namespace.
    /// The listening sockets are handed to the caller
    /// ([`Child::take_listeners`](crate::Child::take_listeners)), so a
    /// service running on the host side (such as [`proxy`](crate::proxy))
    /// accepts connections made from inside. Needs [`Net::None`].
    pub fn listen_tcp(&mut self, port: u16) -> &mut Self {
        self.listen.push(port);
        self
    }

    /// Only these TCP ports may be connected to (Landlock ABI 4+). Ports
    /// of [`listen_tcp`](Sandbox::listen_tcp) are always allowed.
    pub fn tcp_connect(&mut self, ports: impl IntoIterator<Item = u16>) -> &mut Self {
        self.tcp_connect = Some(ports.into_iter().collect());
        self
    }

    /// Only these TCP ports may be bound (Landlock ABI 4+).
    pub fn tcp_bind(&mut self, ports: impl IntoIterator<Item = u16>) -> &mut Self {
        self.tcp_bind = Some(ports.into_iter().collect());
        self
    }

    /// Takes a syscall off the default deny list (see [`seccomp`](crate::seccomp)),
    /// or lifts one of the argument checks ("clone", "unshare", "clone3",
    /// "socket", "ioctl").
    pub fn seccomp_allow(&mut self, name: impl Into<String>) -> &mut Self {
        self.seccomp_allow.push(name.into());
        self
    }

    /// Denies another syscall, by name or as "nr:<number>".
    pub fn seccomp_deny(&mut self, name: impl Into<String>) -> &mut Self {
        self.seccomp_deny.push(name.into());
        self
    }

    pub fn rlimit(&mut self, r: Resource, value: u64) -> &mut Self {
        self.rlimits.push((r, value));
        self
    }

    pub fn limits(&mut self, l: Limits) -> &mut Self {
        self.limits = l;
        self
    }

    pub fn cgroup(&mut self, c: Cgroup) -> &mut Self {
        self.cgroup = c;
        self
    }

    pub fn freeze_method(&mut self, f: FreezeMethod) -> &mut Self {
        self.freeze = f;
        self
    }

    /// When on (the default), refuse to start if Landlock or the requested
    /// limits can't be enforced. When off, run with what is available.
    pub fn strict(&mut self, on: bool) -> &mut Self {
        self.strict = on;
        self
    }

    /// The filesystem view as it will be built: system entries merged in,
    /// paths normalised, sources canonicalised (with `no_symlinks`, only
    /// normalised), missing optional entries dropped, parents before
    /// children.
    pub fn resolved_mounts(&self) -> crate::Result<Vec<Mount>> {
        crate::prepare::resolve_mounts(self)
    }
}

/// Where one of the program's standard streams goes.
#[derive(Debug, Default)]
pub enum Stdio {
    /// The caller's own stream.
    #[default]
    Inherit,
    Null,
    /// A new pipe; the caller's end is in [`Child`](crate::Child)'s
    /// `stdin`/`stdout`/`stderr`.
    Piped,
    /// This descriptor (it is closed in the caller after spawning).
    Fd(OwnedFd),
}

/// A program to run in a sandbox. The environment starts empty: nothing
/// is inherited from the caller unless you pass it.
#[derive(Debug)]
pub struct Command {
    pub(crate) program: OsString,
    pub(crate) args: Vec<OsString>,
    pub(crate) env: Vec<(OsString, OsString)>,
    pub(crate) cwd: PathBuf,
    pub(crate) stdin: Stdio,
    pub(crate) stdout: Stdio,
    pub(crate) stderr: Stdio,
    pub(crate) fds: Vec<(RawFd, OwnedFd)>,
    pub(crate) keep_session: bool,
    pub(crate) id: Option<String>,
}

impl Command {
    /// A program name is looked up in the PATH of the command's own
    /// environment (default `/usr/local/bin:/usr/bin:/bin`), inside the
    /// sandbox.
    pub fn new(program: impl AsRef<OsStr>) -> Command {
        Command {
            program: program.as_ref().to_owned(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: PathBuf::from("/"),
            stdin: Stdio::Inherit,
            stdout: Stdio::Inherit,
            stderr: Stdio::Inherit,
            fds: Vec::new(),
            keep_session: false,
            id: None,
        }
    }

    pub fn arg(&mut self, a: impl AsRef<OsStr>) -> &mut Self {
        self.args.push(a.as_ref().to_owned());
        self
    }

    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args.extend(args.into_iter().map(|a| a.as_ref().to_owned()));
        self
    }

    /// Sets a variable (a later value for the same name wins).
    pub fn env(&mut self, k: impl AsRef<OsStr>, v: impl AsRef<OsStr>) -> &mut Self {
        let k = k.as_ref().to_owned();
        self.env.retain(|(n, _)| *n != k);
        self.env.push((k, v.as_ref().to_owned()));
        self
    }

    pub fn envs<I, K, V>(&mut self, vars: I) -> &mut Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        for (k, v) in vars {
            self.env(k, v);
        }
        self
    }

    /// Working directory inside the sandbox (default `/`). It must be
    /// inside a bind or tmpfs mount.
    pub fn cwd(&mut self, dir: impl AsRef<Path>) -> &mut Self {
        self.cwd = dir.as_ref().to_owned();
        self
    }

    pub fn stdin(&mut self, s: Stdio) -> &mut Self {
        self.stdin = s;
        self
    }

    pub fn stdout(&mut self, s: Stdio) -> &mut Self {
        self.stdout = s;
        self
    }

    pub fn stderr(&mut self, s: Stdio) -> &mut Self {
        self.stderr = s;
        self
    }

    /// Hands `fd` to the program as descriptor `target` (3 or above), for
    /// example a pre-connected socket to the caller.
    pub fn pass_fd(&mut self, target: RawFd, fd: OwnedFd) -> &mut Self {
        self.fds.retain(|(t, _)| *t != target);
        self.fds.push((target, fd));
        self
    }

    /// Stay in the caller's session, so the program keeps the controlling
    /// terminal (interactive use). Terminal-generated SIGINT, SIGQUIT and
    /// SIGTSTP then reach it directly and aren't forwarded a second time.
    pub fn keep_session(&mut self, on: bool) -> &mut Self {
        self.keep_session = on;
        self
    }

    /// An id for this run (letters, digits, '-' and '_'): it names the
    /// systemd scope. Default: random.
    pub fn id(&mut self, id: impl Into<String>) -> &mut Self {
        self.id = Some(id.into());
        self
    }

    pub fn get_program(&self) -> &OsStr {
        &self.program
    }
}
