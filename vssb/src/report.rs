//! Failure reports from the child. The child can't format messages (that
//! would allocate), so it writes a fixed-size record naming the step, the
//! errno and indices into the plan; the parent turns it into an [`Error`].

use crate::error::Error;
use std::io;
use std::path::{Path, PathBuf};

pub(crate) const GO: u32 = 1;
pub(crate) const CGROUP_NS: u32 = 2;
pub(crate) const MOUNT_PRIVATE: u32 = 3;
pub(crate) const OPEN_SOURCE: u32 = 4;
pub(crate) const SET_ATTR: u32 = 5;
pub(crate) const NEW_FS: u32 = 6;
pub(crate) const NEW_ROOT: u32 = 7;
pub(crate) const OPEN_PATH: u32 = 8;
pub(crate) const NOT_CREATABLE: u32 = 9;
pub(crate) const SYMLINK_IN_PATH: u32 = 10;
pub(crate) const NOT_DIR: u32 = 11;
pub(crate) const IS_DIR: u32 = 12;
pub(crate) const CREATE: u32 = 13;
pub(crate) const MOVE_MOUNT: u32 = 14;
pub(crate) const SYMLINK: u32 = 15;
pub(crate) const DEVICES: u32 = 16;
pub(crate) const PIVOT: u32 = 17;
pub(crate) const READ_ONLY: u32 = 18;
pub(crate) const HOSTNAME: u32 = 19;
pub(crate) const LOOPBACK: u32 = 20;
pub(crate) const LISTEN: u32 = 21;
pub(crate) const SEND: u32 = 22;
pub(crate) const FORK: u32 = 23;
pub(crate) const RLIMIT: u32 = 24;
pub(crate) const FDS: u32 = 25;
pub(crate) const CHDIR: u32 = 26;
pub(crate) const CAPS: u32 = 27;
pub(crate) const NO_NEW_PRIVS: u32 = 28;
pub(crate) const LANDLOCK: u32 = 29;
pub(crate) const SECCOMP: u32 = 30;
pub(crate) const EXEC: u32 = 31;
pub(crate) const PID_MAX: u32 = 32;
pub(crate) const PIN: u32 = 33;

/// `a` when a step isn't about one mount.
pub(crate) const NONE: u32 = u32::MAX;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Report {
    pub step: u32,
    pub errno: i32,
    /// Usually a mount index.
    pub a: u32,
    /// Usually a number of path components.
    pub b: u32,
    /// Usually another mount index.
    pub c: u32,
}

pub(crate) const SIZE: usize = std::mem::size_of::<Report>();

impl Report {
    pub fn new(step: u32, errno: i32, a: u32) -> Report {
        Report { step, errno, a, b: 0, c: NONE }
    }

    pub fn with(step: u32, errno: i32, a: u32, b: u32, c: u32) -> Report {
        Report { step, errno, a, b, c }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts((self as *const Report).cast::<u8>(), SIZE) }
    }

    pub fn from_bytes(b: &[u8; SIZE]) -> Report {
        unsafe { std::ptr::read_unaligned(b.as_ptr().cast::<Report>()) }
    }
}

/// What the parent knows to explain a report.
pub(crate) struct Context<'a> {
    pub dests: &'a [PathBuf],
    pub program: &'a str,
    pub listen: &'a [u16],
}

fn prefix(p: &Path, n: u32) -> PathBuf {
    let mut out = PathBuf::from("/");
    for c in p.components().skip(1).take(n as usize) {
        out.push(c);
    }
    out
}

pub(crate) fn to_error(r: Report, cx: &Context) -> Error {
    let os = if r.errno > 0 { io::Error::from_raw_os_error(r.errno) } else { io::Error::other("failed") };
    let dest = |i: u32| cx.dests.get(i as usize).cloned().unwrap_or_else(|| PathBuf::from("(internal)"));
    let d = dest(r.a);
    let shown = d.display();
    let step = match r.step {
        EXEC => return Error::Exec { program: cx.program.to_string(), source: os },
        GO => "waiting for the caller".to_string(),
        PID_MAX => {
            return Error::Unsupported(format!(
                "pids limit: setting the sandbox's pid_max failed ({os}); without a cgroup it needs Linux 6.14+ \
                 (turn strict mode off to run without it)"
            ));
        }
        PIN => "pinning to CPUs (sched_setaffinity)".into(),
        CGROUP_NS => "creating the cgroup namespace".into(),
        MOUNT_PRIVATE => "making mounts private".into(),
        OPEN_SOURCE => format!("cloning the mount source of {shown}"),
        SET_ATTR => format!("setting mount flags for {shown}"),
        NEW_FS if r.a == NONE => "creating an internal filesystem".into(),
        NEW_FS => format!("creating the filesystem for {shown}"),
        NEW_ROOT => "creating the new root".into(),
        OPEN_PATH => format!("looking up {}", prefix(&d, r.b).display()),
        NOT_CREATABLE => {
            let owner = dest(r.c);
            return Error::Setup {
                step: format!(
                    "cannot mount on {shown}: {} does not exist inside {} (a host directory), and vssb won't create it there",
                    prefix(&d, r.b).display(),
                    owner.display()
                ),
                source: os,
            };
        }
        SYMLINK_IN_PATH => format!("{} is a symlink; mount paths can't pass through symlinks (use the real path)", prefix(&d, r.b).display()),
        NOT_DIR => format!("{} is not a directory", prefix(&d, r.b).display()),
        IS_DIR => format!("{shown} is a directory but the source is a file"),
        CREATE => format!("creating mount point {}", prefix(&d, r.b).display()),
        MOVE_MOUNT => format!("mounting on {shown}"),
        SYMLINK => format!("creating symlink {shown}"),
        DEVICES => "populating /dev".into(),
        PIVOT => "switching to the new root".into(),
        READ_ONLY => "making the root read-only".into(),
        HOSTNAME => "setting the hostname".into(),
        LOOPBACK => "bringing up loopback".into(),
        LISTEN => format!("listening on 127.0.0.1:{}", cx.listen.get(r.a as usize).copied().unwrap_or(0)),
        SEND => "handing over listeners".into(),
        FORK => "starting the program's process".into(),
        RLIMIT => format!("setrlimit({})", r.a),
        FDS => "arranging file descriptors".into(),
        CHDIR => "changing to the working directory".into(),
        CAPS => "dropping capabilities".into(),
        NO_NEW_PRIVS => "setting no_new_privs".into(),
        LANDLOCK if r.a == NONE => "applying Landlock".into(),
        LANDLOCK => format!("Landlock rule for {shown}"),
        SECCOMP => "installing the seccomp filter".into(),
        s => format!("step {s}"),
    };
    Error::Setup { step, source: os }
}
