//! Turns a [`Sandbox`] and a [`Command`] into everything the child needs,
//! ahead of `clone`: C strings, pointer arrays, the seccomp program, the
//! Landlock rights, file descriptors, and room for the child's own
//! bookkeeping. The child then only reads (and writes its own copy of)
//! this memory, so it never has to allocate.

use crate::cgroup;
use crate::config::{Cgroup, Command, CpuMethod, FreezeMethod, Limits, Mount, MountKind, Net, PidsMethod, Sandbox, Stdio};
use crate::cpus;
use crate::error::{Error, Result};
use crate::landlock;
use crate::seccomp::Filter;
use crate::sys::{self, MAX_FDS};
use std::collections::BTreeMap;
use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

/// A mount, ready for the child.
pub(crate) enum POp {
    Bind { src: CString, rw: bool },
    Tmpfs { opts: Vec<(CString, CString)> },
    Deny,
    Symlink { target: CString },
    Proc,
    Dev { shm_opts: Vec<(CString, CString)> },
}

pub(crate) struct PMount {
    pub dest: CString,
    /// Path components of `dest`, for walking it with openat2.
    pub comps: Vec<CString>,
    pub op: POp,
    pub noexec: bool,
    pub optional: bool,
    /// Earlier mounts whose destination is a strict ancestor of this one.
    pub ancestors: Vec<usize>,
    /// Read-only binds of non-files strictly below this one (Landlock).
    pub ro_below: Vec<usize>,
    /// Landlock rights for a rule on `dest` (0: none).
    pub access: u64,
    /// For Dev: its shm directory, which gets its own Landlock rule.
    pub shm: Option<CString>,
}

impl PMount {
    pub fn depth(&self) -> usize {
        self.comps.len()
    }
}

/// Everything the child uses. It holds raw pointers into its own strings,
/// so it stays on the stack of `spawn` and is never moved across threads.
pub(crate) struct Prepared {
    pub mounts: Vec<PMount>,
    pub any_dev: bool,
    // The child's own bookkeeping, preallocated (one slot per mount).
    pub attached: Vec<bool>,
    /// Per mount: 0 not a region, 1 a fresh filesystem vssb may create
    /// mount points in, 2 a host directory (or /proc) it may not.
    pub regions: Vec<u8>,
    pub sources: Vec<i32>,
    pub ro_later: Vec<i32>,

    pub hostname: CString,
    pub new_net: bool,
    pub listen: Vec<u16>,
    pub keep_session: bool,

    /// Descriptors PID 1 keeps (sorted); everything else above 2 is closed.
    pub keep_fds: Vec<i32>,
    /// (source, target) descriptors for the program.
    pub fd_map: Vec<(i32, i32)>,
    pub fd_tmp: Vec<i32>,
    pub fd_base: i32,
    pub ctl: i32,
    pub status_w: i32,

    pub rlimits: Vec<(u32, u64)>,
    pub cwd: CString,
    pub cap_last: u32,
    pub landlock: Option<landlock::Plan>,
    pub seccomp: Vec<libc::sock_filter>,
    /// The same filter, also denying sched_setaffinity (forced pinning).
    pub seccomp_forced: Vec<libc::sock_filter>,
    /// Affinity mask for pinning (empty: none prepared).
    pub cpu_mask: Vec<u64>,
    /// pid_max and ns_last_pid for the PID namespace, as text.
    pub pid_max: [CString; 2],
    pub strict: bool,
    /// Which fallbacks to apply ([`go`] flags), as the parent sent them.
    pub go: u8,
    pub exec_paths: Vec<CString>,
    pub argv: Vec<*const libc::c_char>,
    pub envp: Vec<*const libc::c_char>,
    // Owners of the strings the two pointer arrays point into.
    _argv: Vec<CString>,
    _envp: Vec<CString>,
}

pub(crate) enum CgroupPlan {
    None,
    /// `required`: asked for explicitly, so failing is an error in strict mode.
    Scope { unit: String, required: bool },
    Join { fd: OwnedFd, path: PathBuf },
}

/// Flags in the parent's go message (and, for the first two, in init's
/// reply once it has applied them).
pub(crate) mod go {
    pub const PID_MAX: u8 = 1;
    pub const PIN: u8 = 2;
    pub const FORCED: u8 = 4;
}

/// What the parent keeps for itself.
pub(crate) struct Parent {
    pub ctl: OwnedFd,
    pub status: OwnedFd,
    /// The child's ends; closed in the parent right after clone.
    pub child_side: Vec<OwnedFd>,
    pub stdin: Option<File>,
    pub stdout: Option<File>,
    pub stderr: Option<File>,
    pub cgroup: CgroupPlan,
    pub limits: Limits,
    /// The limits that go through a cgroup when there is one.
    pub cg_limits: Limits,
    /// The CPUs pinning would use.
    pub pin: Option<Vec<u32>>,
    pub freeze: FreezeMethod,
    pub strict: bool,
    pub id: String,
    pub dests: Vec<PathBuf>,
    pub program: String,
    pub listen: Vec<u16>,
    pub uid: u32,
    pub gid: u32,
    pub new_net: bool,
}

fn cstr(s: impl AsRef<OsStr>) -> Result<CString> {
    let s = s.as_ref();
    CString::new(s.as_bytes()).map_err(|_| Error::Config(format!("{s:?} contains a NUL byte")))
}

/// Lexical normalisation of an absolute path ('.' and '..' resolved).
pub(crate) fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::from("/");
    for c in p.components() {
        match c {
            Component::Normal(n) => out.push(n),
            Component::ParentDir => {
                out.pop();
            }
            _ => {}
        }
    }
    out
}

fn system_mounts(host_net: bool) -> Vec<Mount> {
    let mut v = Vec::new();
    let ro = |p: &Path, v: &mut Vec<Mount>| match std::fs::symlink_metadata(p) {
        Ok(md) if md.file_type().is_symlink() => {
            if let Ok(t) = std::fs::read_link(p) {
                v.push(Mount::symlink(p, t).optional());
            }
        }
        Ok(_) => v.push(Mount::ro(p).optional()),
        Err(_) => {}
    };
    for p in ["/usr", "/etc", "/opt", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/nix/store"] {
        ro(Path::new(p), &mut v);
    }
    if host_net {
        // /etc/resolv.conf is often a symlink into /run; expose its target.
        if let Ok(t) = std::fs::canonicalize("/etc/resolv.conf")
            && !t.starts_with("/etc")
            && !t.starts_with("/usr")
        {
            ro(&t, &mut v);
        }
    }
    for p in ["/tmp", "/var/tmp", "/run"] {
        v.push(Mount::tmpfs(p));
    }
    v.push(Mount::proc("/proc"));
    v.push(Mount::dev("/dev"));
    v
}

pub(crate) fn resolve_mounts(sb: &Sandbox) -> Result<Vec<Mount>> {
    let mut entries = Vec::new();
    if sb.system {
        entries.extend(system_mounts(sb.net == Net::Host));
    }
    entries.extend(sb.mounts.iter().cloned());

    let mut map: BTreeMap<PathBuf, Mount> = BTreeMap::new();
    for mut m in entries {
        if !m.dest.is_absolute() {
            return Err(Error::Config(format!("mount destination {} must be absolute", m.dest.display())));
        }
        m.dest = normalize(&m.dest);
        if m.dest == Path::new("/") {
            return Err(Error::Config("'/' can't be mounted over; list the directories to expose instead".into()));
        }
        if let MountKind::Bind { src, .. } = &mut m.kind {
            if !src.is_absolute() {
                return Err(Error::Config(format!("mount source {} must be absolute", src.display())));
            }
            match std::fs::canonicalize(&*src) {
                Ok(c) => *src = c,
                Err(e) if e.kind() == io::ErrorKind::NotFound && m.optional => continue,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    return Err(Error::Config(format!("{}: no such file or directory (mark the mount optional if that's fine)", src.display())));
                }
                Err(e) => return Err(Error::io(src.display().to_string(), e)),
            }
        }
        map.insert(m.dest.clone(), m);
    }
    // Parents before children: by depth, then by path.
    let mut v: Vec<Mount> = map.into_values().collect();
    v.sort_by(|a, b| a.dest.components().count().cmp(&b.dest.components().count()).then_with(|| a.dest.cmp(&b.dest)));
    Ok(v)
}

fn tmpfs_opts(mode: &str, size: Option<u64>) -> Result<Vec<(CString, CString)>> {
    let mut o = vec![(cstr("mode")?, cstr(mode)?)];
    if let Some(s) = size {
        o.push((cstr("size")?, cstr(s.to_string())?));
    }
    Ok(o)
}

fn pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut p = [0; 2];
    if unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(Error::io("pipe", io::Error::last_os_error()));
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(p[0]), OwnedFd::from_raw_fd(p[1])) })
}

fn open_null() -> Result<OwnedFd> {
    let f = File::options().read(true).write(true).open("/dev/null").map_err(|e| Error::io("/dev/null", e))?;
    Ok(f.into())
}

fn random_id() -> String {
    let mut b = [0u8; 6];
    unsafe { libc::getrandom(b.as_mut_ptr().cast(), b.len(), 0) };
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn prepare(sb: &Sandbox, cmd: Command) -> Result<(Prepared, Parent)> {
    let mounts = resolve_mounts(sb)?;

    if !cmd.cwd.is_absolute() {
        return Err(Error::Config(format!("working directory {} must be absolute", cmd.cwd.display())));
    }
    let cwd = normalize(&cmd.cwd);
    // The deepest mount containing the cwd decides (mounts are parent-first).
    let visible = cwd == Path::new("/")
        || mounts
            .iter()
            .rev()
            .find(|m| cwd.starts_with(&m.dest))
            .is_some_and(|m| matches!(m.kind, MountKind::Bind { .. } | MountKind::Tmpfs { .. }));
    if !visible {
        return Err(Error::Config(format!("working directory {} is not visible in the sandbox; mount it or choose another", cwd.display())));
    }

    if sb.net == Net::Host && !sb.listen.is_empty() {
        return Err(Error::Config("listen_tcp needs Net::None (with the host network, listen on the host)".into()));
    }
    if sb.listen.len() > MAX_FDS {
        return Err(Error::Config(format!("at most {MAX_FDS} listeners")));
    }
    if sb.hostname.len() > 64 {
        return Err(Error::Config("hostname longer than 64 bytes".into()));
    }
    if let Some(c) = sb.limits.cpus
        && !(c.is_finite() && c > 0.0)
    {
        return Err(Error::Config("cpus must be positive".into()));
    }
    if sb.limits.pids == Some(0) {
        return Err(Error::Config("pids must be at least 1".into()));
    }

    // Landlock.
    let abi = sys::landlock_abi();
    let connect: Option<Vec<u16>> = sb.tcp_connect.as_ref().map(|c| c.iter().chain(&sb.listen).copied().collect());
    let ports = connect.is_some() || sb.tcp_bind.is_some();
    if sb.strict && abi == 0 {
        return Err(Error::Unsupported("Landlock is not available on this kernel; turn strict mode off to run without it".into()));
    }
    if sb.strict && ports && abi < 4 {
        return Err(Error::Unsupported(format!("this kernel's Landlock cannot restrict TCP ports (needs ABI 4, have {abi})")));
    }
    let ll = landlock::Plan::new(abi, connect.as_deref(), sb.tcp_bind.as_deref());

    let filter = Filter::build(&sb.seccomp_allow, &sb.seccomp_deny)?;

    // Fallbacks for limits without a cgroup, prepared in case they're
    // needed: spawn decides once it knows whether there is a cgroup.
    let l = &sb.limits;
    let pin = match l.cpus {
        Some(c) if l.cpu_method != CpuMethod::Cgroup => Some(cpus::choose(c, &l.cpu_choice)?),
        _ => None,
    };
    let may_force = pin.is_some() && (l.cpu_method == CpuMethod::PinForced || (l.cpu_method == CpuMethod::Auto && sb.strict));
    // Not in the filter's name table; by number.
    let setaffinity = format!("nr:{}", libc::SYS_sched_setaffinity);
    if may_force && sb.seccomp_allow.contains(&setaffinity) {
        return Err(Error::Config(format!("forced pinning denies sched_setaffinity, which seccomp_allow allows ({setaffinity})")));
    }
    let forced_filter = if may_force {
        let mut deny = sb.seccomp_deny.clone();
        deny.push(setaffinity);
        Some(Filter::build(&sb.seccomp_allow, &deny)?)
    } else {
        None
    };
    // pid numbers wrap to 300 (not 1) in every PID namespace, so a pid_max
    // of pids + 299 leaves exactly pids - 1 numbers for the program's
    // tasks once init has made them wrap, as pids.max would with init.
    let pid_max = match l.pids {
        Some(n) if l.pids_method != PidsMethod::Cgroup => Some((n.saturating_add(299)).max(301)),
        _ => None,
    };

    // Mounts.
    let n = mounts.len();
    let mut pms = Vec::with_capacity(n);
    for (i, m) in mounts.iter().enumerate() {
        let comps = m.dest.components().skip(1).map(|c| cstr(c.as_os_str())).collect::<Result<Vec<_>>>()?;
        let op = match &m.kind {
            MountKind::Bind { src, writable } => POp::Bind { src: cstr(src)?, rw: *writable },
            MountKind::Tmpfs { size } => POp::Tmpfs { opts: tmpfs_opts("0755", *size)? },
            MountKind::Deny => POp::Deny,
            MountKind::Symlink { target } => POp::Symlink { target: cstr(target)? },
            MountKind::Proc => POp::Proc,
            MountKind::Dev { shm_size } => POp::Dev { shm_opts: tmpfs_opts("1777", *shm_size)? },
        };
        let below = |j: usize| j != i && mounts[j].dest.starts_with(&m.dest);
        let ancestors = (0..i).filter(|&j| m.dest.starts_with(&mounts[j].dest)).collect();
        let ro_below = match &m.kind {
            MountKind::Bind { writable: true, .. } | MountKind::Tmpfs { .. } => (0..n)
                .filter(|&j| below(j) && matches!(&mounts[j].kind, MountKind::Bind { writable: false, src } if !src.is_file()))
                .collect(),
            _ => Vec::new(),
        };
        let access = ll.as_ref().map_or(0, |p| p.access(&op, m.noexec));
        let shm = match op {
            POp::Dev { .. } => Some(cstr(m.dest.join("shm"))?),
            _ => None,
        };
        pms.push(PMount { dest: cstr(&m.dest)?, comps, op, noexec: m.noexec, optional: m.optional, ancestors, ro_below, access, shm });
    }
    let any_dev = pms.iter().any(|m| matches!(m.op, POp::Dev { .. }));

    // The program: argv, envp, and where to look for it.
    if cmd.program.is_empty() {
        return Err(Error::Config("empty program name".into()));
    }
    let mut argv_s = vec![cstr(&cmd.program)?];
    for a in &cmd.args {
        argv_s.push(cstr(a)?);
    }
    let mut envp_s = Vec::with_capacity(cmd.env.len());
    for (k, v) in &cmd.env {
        if k.is_empty() || k.as_bytes().contains(&b'=') {
            return Err(Error::Config(format!("invalid environment variable name {k:?}")));
        }
        let mut kv = k.clone().into_vec();
        kv.push(b'=');
        kv.extend_from_slice(v.as_bytes());
        envp_s.push(cstr(OsString::from_vec(kv))?);
    }
    let exec_paths = if cmd.program.as_bytes().contains(&b'/') {
        vec![cstr(&cmd.program)?]
    } else {
        let path = cmd.env.iter().find(|(k, _)| k == "PATH").map(|(_, v)| v.clone()).unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into());
        let mut v = Vec::new();
        for dir in path.as_bytes().split(|&b| b == b':') {
            let mut p = if dir.is_empty() { b".".to_vec() } else { dir.to_vec() };
            p.push(b'/');
            p.extend_from_slice(cmd.program.as_bytes());
            v.push(cstr(OsString::from_vec(p))?);
        }
        v
    };
    let mut argv: Vec<*const libc::c_char> = argv_s.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());
    let mut envp: Vec<*const libc::c_char> = envp_s.iter().map(|s| s.as_ptr()).collect();
    envp.push(std::ptr::null());

    // Descriptors.
    let mut sv = [0; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0, sv.as_mut_ptr()) } < 0 {
        return Err(Error::io("socketpair", io::Error::last_os_error()));
    }
    let (ctl, ctl_child) = unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1])) };
    let (status, status_w) = pipe()?;
    let (ctl_raw, status_raw) = (ctl_child.as_raw_fd(), status_w.as_raw_fd());
    let mut child_side = vec![ctl_child, status_w];
    let mut fd_map: Vec<(RawFd, RawFd)> = Vec::new();
    let mut ends: [Option<File>; 3] = [None, None, None];
    for (target, s) in [(0, cmd.stdin), (1, cmd.stdout), (2, cmd.stderr)] {
        let src = match s {
            Stdio::Inherit if unsafe { libc::fcntl(target, libc::F_GETFD) } >= 0 => target,
            Stdio::Inherit | Stdio::Null => {
                let f = open_null()?;
                let raw = f.as_raw_fd();
                child_side.push(f);
                raw
            }
            Stdio::Piped => {
                let (r, w) = pipe()?;
                let (mine, theirs) = if target == 0 { (w, r) } else { (r, w) };
                ends[target as usize] = Some(File::from(mine));
                let raw = theirs.as_raw_fd();
                child_side.push(theirs);
                raw
            }
            Stdio::Fd(f) => {
                let raw = f.as_raw_fd();
                child_side.push(f);
                raw
            }
        };
        fd_map.push((src, target));
    }
    for (target, f) in cmd.fds {
        if target < 3 {
            return Err(Error::Config(format!("pass_fd target {target}: use stdin/stdout/stderr for 0-2")));
        }
        fd_map.push((f.as_raw_fd(), target));
        child_side.push(f);
    }
    let mut keep_fds: Vec<i32> = [ctl_raw, status_raw].into_iter().chain(fd_map.iter().map(|&(s, _)| s)).filter(|&f| f > 2).collect();
    keep_fds.sort_unstable();
    keep_fds.dedup();
    let fd_base = fd_map.iter().map(|&(_, t)| t).max().unwrap_or(2).max(2) + 1;
    let fd_tmp = vec![-1; fd_map.len()];
    let [stdin, stdout, stderr] = ends;

    // Ids, limits and cgroup.
    let id = match cmd.id {
        Some(id) => {
            if id.is_empty() || id.len() > 64 || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return Err(Error::Config(format!("invalid id {id:?} (letters, digits, '-' and '_')")));
            }
            id
        }
        None => random_id(),
    };
    // The limits that go through a cgroup, if there is one.
    let cg_limits = Limits {
        memory: l.memory,
        cpus: l.cpus.filter(|_| matches!(l.cpu_method, CpuMethod::Auto | CpuMethod::Cgroup)),
        pids: l.pids.filter(|_| l.pids_method != PidsMethod::PidNamespace),
        ..Default::default()
    };
    let cgroup = match &sb.cgroup {
        Cgroup::Inherit => {
            let needs = [
                ("a memory limit", l.memory.is_some()),
                ("CpuMethod::Cgroup", l.cpus.is_some() && l.cpu_method == CpuMethod::Cgroup),
                ("PidsMethod::Cgroup", l.pids.is_some() && l.pids_method == PidsMethod::Cgroup),
            ];
            if let Some((what, _)) = needs.iter().find(|(_, n)| *n) {
                return Err(Error::Config(format!("{what} needs a cgroup: use Cgroup::Auto, SystemdUserScope or Join")));
            }
            CgroupPlan::None
        }
        Cgroup::Auto if cg_limits.is_empty() => CgroupPlan::None,
        Cgroup::Auto => CgroupPlan::Scope { unit: format!("vssb-{id}.scope"), required: false },
        Cgroup::SystemdUserScope => CgroupPlan::Scope { unit: format!("vssb-{id}.scope"), required: true },
        Cgroup::Join(path) => {
            cgroup::write_limits(path, &cg_limits);
            let f = File::options()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
                .open(path)
                .map_err(|e| Error::io(format!("opening cgroup {}", path.display()), e))?;
            CgroupPlan::Join { fd: f.into(), path: path.clone() }
        }
    };

    let cap_last = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap").ok().and_then(|s| s.trim().parse().ok()).unwrap_or(63);
    let mut rlimits = vec![(libc::RLIMIT_CORE as u32, 0)];
    rlimits.extend(sb.rlimits.iter().map(|&(r, v)| (r.raw(), v)));

    let p = Prepared {
        any_dev,
        attached: vec![false; n],
        regions: vec![0; n],
        sources: vec![-1; n],
        ro_later: vec![-1; n],
        mounts: pms,
        hostname: cstr(&sb.hostname)?,
        new_net: sb.net == Net::None,
        listen: sb.listen.clone(),
        keep_session: cmd.keep_session,
        keep_fds,
        fd_map,
        fd_tmp,
        fd_base,
        ctl: ctl_raw,
        status_w: status_raw,
        rlimits,
        cwd: cstr(&cwd)?,
        cap_last,
        landlock: ll,
        seccomp: filter.program().to_vec(),
        seccomp_forced: forced_filter.as_ref().map(|f| f.program().to_vec()).unwrap_or_default(),
        cpu_mask: pin.as_deref().map(cpus::mask).unwrap_or_default(),
        pid_max: match pid_max {
            Some(m) => [cstr(m.to_string())?, cstr((m - 1).to_string())?],
            None => [CString::default(), CString::default()],
        },
        strict: sb.strict,
        go: 0,
        exec_paths,
        argv,
        envp,
        _argv: argv_s,
        _envp: envp_s,
    };
    let parent = Parent {
        ctl,
        status,
        child_side,
        stdin,
        stdout,
        stderr,
        cgroup,
        limits: sb.limits.clone(),
        cg_limits,
        pin,
        freeze: sb.freeze,
        strict: sb.strict,
        id,
        dests: mounts.iter().map(|m| m.dest.clone()).collect(),
        program: cmd.program.to_string_lossy().into_owned(),
        listen: sb.listen.clone(),
        uid: sb.uid.unwrap_or_else(|| unsafe { libc::getuid() }),
        gid: sb.gid.unwrap_or_else(|| unsafe { libc::getgid() }),
        new_net: sb.net == Net::None,
    };
    Ok((p, parent))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes() {
        assert_eq!(normalize(Path::new("/a/./b/../c")), PathBuf::from("/a/c"));
        assert_eq!(normalize(Path::new("/../..")), PathBuf::from("/"));
    }

    #[test]
    fn later_entries_win_and_parents_come_first() {
        let tmp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let mut sb = Sandbox::new();
        sb.mount(Mount::tmpfs(tmp.join("sub")))
            .mount(Mount::ro(&tmp))
            .mount(Mount::rw(&tmp))
            .mount(Mount::ro("/vssb-surely-missing").optional());
        let m = sb.resolved_mounts().unwrap();
        assert_eq!(m.len(), 2);
        assert!(matches!(m[0].kind, MountKind::Bind { writable: true, .. }));
        assert!(matches!(m[1].kind, MountKind::Tmpfs { .. }));
    }

    #[test]
    fn rejects_bad_descriptions() {
        let mut sb = Sandbox::new();
        sb.mount(Mount::ro("relative"));
        assert!(sb.resolved_mounts().is_err());
        let mut sb = Sandbox::new();
        sb.mount(Mount::tmpfs("/"));
        assert!(sb.resolved_mounts().is_err());
        let mut sb = Sandbox::new();
        sb.mount(Mount::ro("/vssb-surely-missing"));
        assert!(sb.resolved_mounts().is_err());
        let mut sb = Sandbox::new();
        sb.mount(Mount::tmpfs("/tmp"));
        let mut c = Command::new("true");
        c.cwd("/usr");
        assert!(matches!(prepare(&sb, c), Err(Error::Config(_))));
    }
}
