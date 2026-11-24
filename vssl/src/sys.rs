//! Thin wrappers over syscalls. Everything here is allocation-free, so it
//! can be used in the cloned child (see child.rs) as well as the parent.

use std::ffi::CStr;

pub(crate) fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

/// A libc-style return value: the value, or errno when negative.
pub(crate) fn chk(r: i64) -> Result<i64, i32> {
    if r < 0 { Err(errno()) } else { Ok(r) }
}

pub(crate) fn chk_fd(r: i64) -> Result<i32, i32> {
    chk(r).map(|v| v as i32)
}

pub(crate) fn close(fd: i32) {
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
}

pub(crate) fn write_all(fd: i32, mut buf: &[u8]) -> bool {
    while !buf.is_empty() {
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return false;
        }
        buf = buf.get(n as usize..).unwrap_or_default();
    }
    true
}

pub(crate) fn sigset(sigs: &[i32]) -> libc::sigset_t {
    unsafe {
        let mut s: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut s);
        for &sig in sigs {
            libc::sigaddset(&mut s, sig);
        }
        s
    }
}

/// Most file descriptors one control message carries.
pub(crate) const MAX_FDS: usize = 16;

/// Sends `data` with up to [`MAX_FDS`] descriptors (SCM_RIGHTS).
pub(crate) fn send_with_fds(sock: i32, data: &[u8], fds: &[i32]) -> Result<(), i32> {
    unsafe {
        let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut _, iov_len: data.len() };
        let mut cbuf = [0u64; 16];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if !fds.is_empty() {
            let n = fds.len().min(MAX_FDS);
            let bytes = (n * 4) as u32;
            msg.msg_control = cbuf.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(bytes) as _;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(bytes) as _;
            std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(c).cast::<i32>(), n);
        }
        loop {
            if libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL) >= 0 {
                return Ok(());
            }
            if errno() != libc::EINTR {
                return Err(errno());
            }
        }
    }
}

/// Kernel Landlock ABI version (0 when unavailable).
pub(crate) fn landlock_abi() -> u32 {
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    let v = unsafe {
        libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<libc::c_void>(), 0usize, LANDLOCK_CREATE_RULESET_VERSION)
    };
    v.max(0) as u32
}

pub(crate) fn is_dir(fd: i32) -> Result<bool, i32> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    chk(unsafe { libc::fstat(fd, &mut st) } as i64)?;
    Ok(st.st_mode & libc::S_IFMT == libc::S_IFDIR)
}

pub(crate) fn open_path(path: &CStr) -> Result<i32, i32> {
    chk_fd(unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) } as i64)
}

// clone3 and its fork-like fallback.

pub(crate) const CLONE_PIDFD: u64 = 0x1000;
pub(crate) const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

/// Forks (no shared memory, no new stack) with the given namespace flags.
/// The child is a "clone child": it sends no SIGCHLD and only waits with
/// `__WALL`/`__WCLONE` see it, so a host's `waitpid(-1)` can't reap it.
/// Returns 0 in the child, and (pid, pidfd) in the parent.
///
/// # Safety
/// The child runs in a copy of a possibly multi-threaded process: it may
/// only make async-signal-safe calls until it execs or exits.
pub(crate) unsafe fn clone_pidfd(flags: u64, cgroup: Option<i32>) -> Result<(i32, i32), i32> {
    let mut pidfd: i32 = -1;
    let mut args = CloneArgs {
        flags: flags | CLONE_PIDFD | if cgroup.is_some() { CLONE_INTO_CGROUP } else { 0 },
        pidfd: &mut pidfd as *mut i32 as u64,
        exit_signal: 0,
        cgroup: cgroup.unwrap_or(0) as u64,
        ..Default::default()
    };
    let r = unsafe { libc::syscall(libc::SYS_clone3, &mut args as *mut CloneArgs, std::mem::size_of::<CloneArgs>()) };
    if r >= 0 {
        return Ok((r as i32, pidfd));
    }
    // Some seccomp profiles (older container runtimes) return ENOSYS for clone3.
    if errno() == libc::ENOSYS && cgroup.is_none() {
        // The third argument is the parent tid pointer on every architecture.
        let r = unsafe { libc::syscall(libc::SYS_clone, (flags | CLONE_PIDFD) as libc::c_ulong, 0usize, &mut pidfd as *mut i32, 0usize, 0usize) };
        if r >= 0 {
            return Ok((r as i32, pidfd));
        }
    }
    Err(errno())
}

/// fork() without libc's atfork handlers (which take locks).
pub(crate) unsafe fn raw_fork() -> i64 {
    unsafe { libc::syscall(libc::SYS_clone, libc::SIGCHLD as libc::c_ulong, 0usize, 0usize, 0usize, 0usize) }
}

pub(crate) const P_PIDFD: libc::idtype_t = 3;
pub(crate) const WALL: i32 = 0x4000_0000;
