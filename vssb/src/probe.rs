//! What the running kernel and session support.

use crate::sys;

#[derive(Clone, Debug)]
pub struct Support {
    /// Kernel release and architecture.
    pub kernel: String,
    /// Unprivileged user, mount, PID and network namespaces work.
    pub user_namespaces: bool,
    /// Landlock ABI version (0: none). 4+ restricts TCP ports, 6+ scopes
    /// signals and abstract sockets, 9+ guards unix sockets on disk.
    pub landlock_abi: u32,
    pub seccomp: bool,
    /// A systemd user manager is reachable over D-Bus with `busctl`, so
    /// [`Limits`](crate::Limits) can be applied through a scope.
    pub systemd_user: bool,
}

impl Support {
    /// Whether a sandbox with the default (strict) settings can start.
    pub fn ready(&self) -> bool {
        self.user_namespaces && self.seccomp && self.landlock_abi > 0
    }
}

fn userns_works() -> bool {
    let flags = (libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWNET | libc::CLONE_NEWPID) as u64;
    unsafe {
        let mut all: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut all);
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::pthread_sigmask(libc::SIG_SETMASK, &all, &mut old);
        let r = sys::clone_pidfd(flags, None);
        if let Ok((0, _)) = r {
            libc::_exit(0);
        }
        libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
        let Ok((_, pidfd)) = r else { return false };
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let ok = libc::waitid(sys::P_PIDFD, pidfd as libc::id_t, &mut info, libc::WEXITED | sys::WALL) == 0 && info.si_status() == 0;
        libc::close(pidfd);
        ok
    }
}

fn on_path(name: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(name).is_file()))
}

pub fn probe() -> Support {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    unsafe { libc::uname(&mut uts) };
    let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }.to_string_lossy().into_owned();
    let bus = std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some()
        || std::env::var_os("XDG_RUNTIME_DIR").is_some_and(|d| std::path::Path::new(&d).join("bus").exists());
    Support {
        kernel: format!("{release} ({})", std::env::consts::ARCH),
        user_namespaces: userns_works(),
        landlock_abi: sys::landlock_abi(),
        seccomp: unsafe { libc::prctl(libc::PR_GET_SECCOMP) } >= 0,
        systemd_user: bus && on_path("busctl"),
    }
}
