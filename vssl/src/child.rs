//! Code that runs in the cloned child: PID 1 of the new namespaces, which
//! builds the sandbox, starts the program, forwards signals and reaps;
//! and the program's process, which locks itself down and execs.
//!
//! The child is a fork of the caller, which may have many threads. Any
//! lock another thread held at clone time (malloc's, stdio's, the
//! environment's…) stays locked here forever. So until exec this code may
//! only make async-signal-safe calls: raw syscalls and thin libc wrappers
//! over them. No allocation, no `format!`, no std I/O, no panics, no
//! libc `fork`. Everything it needs was prepared by the parent
//! (prepare.rs); failures go back as fixed-size [`Report`]s.

use crate::landlock;
use crate::mounts;
use crate::prepare::{Prepared, go};
use crate::report::{self, Report};
use crate::seccomp;
use crate::sys::{self, chk, close, errno, raw_fork, send_with_fds, sigset, write_all, MAX_FDS, WALL};

pub(crate) const EXIT_SETUP: i32 = 125;

/// Signals PID 1 passes on to the program.
pub(crate) const FORWARDED: [i32; 10] = [
    libc::SIGHUP,
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGUSR1,
    libc::SIGUSR2,
    libc::SIGALRM,
    libc::SIGTERM,
    libc::SIGCONT,
    libc::SIGTSTP,
    libc::SIGWINCH,
];

const SI_KERNEL: i32 = 0x80;

/// The kernel's struct sigaction (not glibc's).
#[repr(C)]
struct KernelSigaction {
    handler: libc::sighandler_t,
    flags: u64,
    restorer: usize,
    mask: u64,
}

fn exit(code: i32) -> ! {
    unsafe { libc::_exit(code) }
}

fn report(fd: i32, r: Report) {
    write_all(fd, r.as_bytes());
}

/// Entry point of the cloned child. All signals are blocked: the parent
/// blocked them around clone, so no handler of the caller's can run here.
pub(crate) fn pid1(p: &mut Prepared) -> ! {
    // Handlers are the caller's code; ignored signals would survive exec.
    // (Raw syscalls: glibc's sigaction takes a lock another thread may hold.)
    let dfl = KernelSigaction { handler: libc::SIG_DFL, flags: 0, restorer: 0, mask: 0 };
    for sig in 1..=64 {
        if sig != libc::SIGKILL && sig != libc::SIGSTOP {
            unsafe { libc::syscall(libc::SYS_rt_sigaction, sig, &dfl as *const KernelSigaction, std::ptr::null::<KernelSigaction>(), 8usize) };
        }
    }
    close_others(&p.keep_fds);

    if let Err(r) = setup(p) {
        report(p.status_w, r);
        exit(EXIT_SETUP);
    }
    let agent = unsafe { raw_fork() };
    if agent < 0 {
        report(p.status_w, Report::new(report::FORK, errno(), report::NONE));
        exit(EXIT_SETUP);
    }
    if agent == 0 {
        let (code, r) = run_program(p);
        report(p.status_w, r);
        exit(code);
    }
    // The program holds the other end until exec; the parent sees EOF then.
    close(p.status_w);
    // The program has its own copies; holding pipe ends here would delay
    // the caller's EOF on them until the whole sandbox exits.
    for &(src, _) in &p.fd_map {
        if src > 2 {
            close(src);
        }
    }
    supervise(p, agent as i32)
}

/// Closes every descriptor above 2 that isn't in `keep` (sorted): other
/// threads of the caller may have had any number of them open.
fn close_others(keep: &[i32]) {
    let mut lo: u32 = 3;
    for &k in keep {
        let k = k as u32;
        if k > lo {
            unsafe { libc::syscall(libc::SYS_close_range, lo, k - 1, 0u32) };
        }
        if k >= lo {
            lo = k + 1;
        }
    }
    unsafe { libc::syscall(libc::SYS_close_range, lo, u32::MAX, 0u32) };
}

fn setup(p: &mut Prepared) -> Result<(), Report> {
    // Wait until the parent has written our id maps (and moved us into a
    // cgroup); it also says which limit fallbacks to apply.
    let mut b = [0u8; 2];
    let n = loop {
        let n = unsafe { libc::recv(p.ctl, b.as_mut_ptr().cast(), 2, 0) };
        if n >= 0 || errno() != libc::EINTR {
            break n;
        }
    };
    if n != 2 || b[0] != b'G' {
        return Err(Report::new(report::GO, 0, report::NONE));
    }
    p.go = b[1];
    // Rooted at the cgroup the parent just put us in.
    chk(unsafe { libc::unshare(libc::CLONE_NEWCGROUP) } as i64).map_err(|e| Report::new(report::CGROUP_NS, e, report::NONE))?;
    let applied = fallbacks(p)?;
    if !p.keep_session {
        // Our own session, so terminal signals reach only the caller.
        unsafe { libc::setsid() };
    }

    mounts::build(p)?;

    let h = p.hostname.as_bytes();
    chk(unsafe { libc::sethostname(h.as_ptr().cast(), h.len()) } as i64).map_err(|e| Report::new(report::HOSTNAME, e, report::NONE))?;
    if p.new_net {
        loopback_up().map_err(|e| Report::new(report::LOOPBACK, e, report::NONE))?;
    }
    let mut fds = [-1i32; MAX_FDS];
    let n = p.listen.len().min(MAX_FDS);
    for (k, (&port, slot)) in p.listen.iter().zip(fds.iter_mut()).enumerate() {
        *slot = listen(port).map_err(|e| Report::new(report::LISTEN, e, k as u32))?;
    }
    send_with_fds(p.ctl, &[b'L', applied], fds.get(..n).unwrap_or_default()).map_err(|e| Report::new(report::SEND, e, report::NONE))?;
    for fd in fds {
        close(fd);
    }
    // Keeps the program from ptracing PID 1 or reading its memory.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
    Ok(())
}

/// Applies the limit fallbacks the parent asked for, before the program's
/// process exists. Returns the ones that took (with strict mode off, a
/// refused one is skipped; with it on, it's an error).
fn fallbacks(p: &Prepared) -> Result<u8, Report> {
    let mut applied = 0;
    if p.go & go::PID_MAX != 0 {
        // pid_max sizes this PID namespace; ns_last_pid = pid_max - 1 makes
        // the next pid wrap, to 300, so every pid the program's tasks get
        // is in 300..pid_max and no more than pid_max - 300 of them fit.
        match write_file(c"/proc/sys/kernel/pid_max", p.pid_max[0].as_bytes())
            .and_then(|()| write_file(c"/proc/sys/kernel/ns_last_pid", p.pid_max[1].as_bytes()))
        {
            Ok(()) => applied |= go::PID_MAX,
            Err(e) if p.strict => return Err(Report::new(report::PID_MAX, e, report::NONE)),
            Err(_) => {}
        }
    }
    if p.go & go::PIN != 0 {
        // Init's own set; the program's process inherits it.
        let m = &p.cpu_mask;
        match chk(unsafe { libc::syscall(libc::SYS_sched_setaffinity, 0, m.len() * 8, m.as_ptr()) }) {
            Ok(_) => applied |= go::PIN,
            Err(e) if p.strict => return Err(Report::new(report::PIN, e, report::NONE)),
            Err(_) => {}
        }
    }
    Ok(applied)
}

fn write_file(path: &core::ffi::CStr, data: &[u8]) -> Result<(), i32> {
    let fd = sys::chk_fd(unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) } as i64)?;
    let ok = write_all(fd, data);
    let e = errno();
    close(fd);
    if ok { Ok(()) } else { Err(e) }
}

fn loopback_up() -> Result<(), i32> {
    #[repr(C)]
    struct IfReq {
        name: [u8; 16],
        flags: libc::c_short,
        _pad: [u8; 22],
    }
    let s = sys::chk_fd(unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) } as i64)?;
    let mut r = IfReq { name: [0; 16], flags: 0, _pad: [0; 22] };
    r.name[0] = b'l';
    r.name[1] = b'o';
    let res = unsafe {
        let mut res = libc::ioctl(s, libc::SIOCGIFFLAGS, &mut r);
        if res == 0 {
            r.flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
            res = libc::ioctl(s, libc::SIOCSIFFLAGS, &r);
        }
        res
    };
    let e = errno();
    close(s);
    if res < 0 { Err(e) } else { Ok(()) }
}

fn listen(port: u16) -> Result<i32, i32> {
    let s = sys::chk_fd(unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) } as i64)?;
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();
    let r = unsafe {
        let r = libc::bind(s, (&addr as *const libc::sockaddr_in).cast(), std::mem::size_of::<libc::sockaddr_in>() as u32);
        if r == 0 { libc::listen(s, 128) } else { r }
    };
    if r < 0 {
        let e = errno();
        close(s);
        return Err(e);
    }
    Ok(s)
}

/// PID 1's loop: forward signals to the program, reap everything, and
/// when the program exits, kill what it left behind and report its status.
/// If the parent goes away (the control socket closes), the sandbox dies.
fn supervise(p: &Prepared, agent: i32) -> ! {
    let mut sigs = [0i32; FORWARDED.len() + 1];
    sigs[..FORWARDED.len()].copy_from_slice(&FORWARDED);
    sigs[FORWARDED.len()] = libc::SIGCHLD;
    let set = sigset(&sigs);
    let sfd = unsafe { libc::signalfd(-1, &set, libc::SFD_CLOEXEC) };
    if sfd < 0 {
        unsafe { libc::kill(-1, libc::SIGKILL) };
        exit(EXIT_SETUP);
    }
    // Paused with signals (FreezeMethod::Signals): forwarded SIGCONT and
    // SIGTSTP wait until the resume, since either would undo or be undone
    // by it (SIGCONT discards pending stop signals). The latest is kept.
    let mut paused = false;
    let mut held = 0;
    loop {
        let mut pfd = [
            libc::pollfd { fd: sfd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: p.ctl, events: libc::POLLIN, revents: 0 },
        ];
        if unsafe { libc::poll(pfd.as_mut_ptr(), 2, -1) } < 0 {
            continue; // EINTR
        }
        if pfd[1].revents != 0 {
            let mut b = [0u8; 16];
            let n = unsafe { libc::recv(p.ctl, b.as_mut_ptr().cast(), b.len(), libc::MSG_DONTWAIT) };
            let gone = n == 0 || (n < 0 && errno() != libc::EAGAIN && errno() != libc::EINTR);
            if gone || pfd[1].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                // The caller is gone: nobody can wait for us any more.
                kill_all_and_reap();
                exit(EXIT_SETUP);
            }
            if n == 2 && b[0] == b'F' {
                let pause = b[1] != 0;
                if pause && !paused {
                    // Every process in the namespace but init; the kernel
                    // also stops children forked while this is delivered.
                    unsafe { libc::kill(-1, libc::SIGSTOP) };
                } else if !pause && paused {
                    unsafe { libc::kill(-1, libc::SIGCONT) };
                    if held != 0 {
                        unsafe { libc::kill(agent, held) };
                        held = 0;
                    }
                }
                paused = pause;
            }
        }
        if pfd[0].revents & libc::POLLIN == 0 {
            continue;
        }
        let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
        let n = unsafe { libc::read(sfd, (&mut info as *mut libc::signalfd_siginfo).cast(), std::mem::size_of::<libc::signalfd_siginfo>()) };
        if n <= 0 {
            continue;
        }
        let sig = info.ssi_signo as i32;
        if sig != libc::SIGCHLD {
            // With the caller's terminal, the program gets these from the
            // terminal itself (sent by the kernel); don't double them.
            let from_tty = info.ssi_code == SI_KERNEL && matches!(sig, libc::SIGINT | libc::SIGQUIT | libc::SIGTSTP);
            if paused && matches!(sig, libc::SIGCONT | libc::SIGTSTP) {
                held = sig;
            } else if !(p.keep_session && from_tty) {
                unsafe { libc::kill(agent, sig) };
            }
            continue;
        }
        let mut done = None;
        loop {
            let mut st = 0;
            let r = unsafe { libc::waitpid(-1, &mut st, libc::WNOHANG | WALL) };
            if r <= 0 {
                break;
            }
            if r == agent {
                done = Some(st);
            }
        }
        if let Some(st) = done {
            // The program is gone: take everything it left behind with it.
            kill_all_and_reap();
            let mut msg = [0u8; 5];
            msg[0] = b'X';
            msg[1..].copy_from_slice(&st.to_ne_bytes());
            let _ = send_with_fds(p.ctl, &msg, &[]);
            exit(shell_code(st));
        }
    }
}

fn kill_all_and_reap() {
    unsafe {
        libc::kill(-1, libc::SIGKILL);
        while libc::waitpid(-1, std::ptr::null_mut(), WALL) > 0 {}
    }
}

fn shell_code(st: i32) -> i32 {
    if libc::WIFEXITED(st) {
        libc::WEXITSTATUS(st)
    } else if libc::WIFSIGNALED(st) {
        128 + libc::WTERMSIG(st)
    } else {
        EXIT_SETUP
    }
}

/// Locks down the program's process and execs it. Returns only on failure.
fn run_program(p: &mut Prepared) -> (i32, Report) {
    let fail = |step: u32, e: i32| (EXIT_SETUP, Report::new(step, e, report::NONE));
    close(p.ctl);

    for &(res, v) in &p.rlimits {
        let r = libc::rlimit { rlim_cur: v, rlim_max: v };
        if unsafe { libc::setrlimit(res as _, &r) } < 0 {
            return (EXIT_SETUP, Report::new(report::RLIMIT, errno(), res));
        }
    }

    // Descriptors: move the status pipe and every source above all
    // targets first, so no target overwrites them; then mark everything
    // close-on-exec and dup each onto its target (dup3 clears the flag).
    let w = unsafe { libc::fcntl(p.status_w, libc::F_DUPFD_CLOEXEC, p.fd_base) };
    if w < 0 {
        return fail(report::FDS, errno());
    }
    close(p.status_w);
    p.status_w = w;
    for (&(src, _), tmp) in p.fd_map.iter().zip(p.fd_tmp.iter_mut()) {
        *tmp = unsafe { libc::fcntl(src, libc::F_DUPFD_CLOEXEC, p.fd_base) };
        if *tmp < 0 {
            return fail(report::FDS, errno());
        }
    }
    unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, libc::CLOSE_RANGE_CLOEXEC as u32) };
    for (&(_, target), &tmp) in p.fd_map.iter().zip(p.fd_tmp.iter()) {
        if unsafe { libc::dup3(tmp, target, 0) } < 0 {
            return fail(report::FDS, errno());
        }
    }

    if unsafe { libc::chdir(p.cwd.as_ptr()) } < 0 {
        return fail(report::CHDIR, errno());
    }
    if let Err(e) = drop_capabilities(p.cap_last) {
        return fail(report::CAPS, e);
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        return fail(report::NO_NEW_PRIVS, errno());
    }
    if let Some(plan) = &p.landlock
        && let Err(r) = landlock::apply(plan, &p.mounts, &p.attached)
    {
        return (EXIT_SETUP, r);
    }
    let empty: u64 = 0;
    unsafe { libc::syscall(libc::SYS_rt_sigprocmask, libc::SIG_SETMASK, &empty as *const u64, std::ptr::null::<u64>(), 8usize) };

    // Last step before exec: from here on the filter applies.
    let filter = if p.go & go::FORCED != 0 { &p.seccomp_forced } else { &p.seccomp };
    if let Err(e) = seccomp::install(filter) {
        return fail(report::SECCOMP, e);
    }
    // execvp's search, without its allocation.
    let mut err = libc::ENOENT;
    let mut eacces = false;
    for path in &p.exec_paths {
        unsafe { libc::execve(path.as_ptr(), p.argv.as_ptr(), p.envp.as_ptr()) };
        match errno() {
            libc::EACCES => eacces = true,
            libc::ENOENT | libc::ENOTDIR => {}
            e => {
                err = e;
                break;
            }
        }
    }
    if eacces && err == libc::ENOENT {
        err = libc::EACCES;
    }
    let code = if err == libc::ENOENT { 127 } else { 126 };
    (code, Report::new(report::EXEC, err, report::NONE))
}

/// Empties the bounding, ambient, inheritable, permitted and effective
/// sets, so even uid 0 inside the sandbox has no capabilities after exec.
fn drop_capabilities(last: u32) -> Result<(), i32> {
    unsafe {
        for cap in 0..=last {
            libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0);
        }
        libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong, 0, 0, 0);
        #[repr(C)]
        struct Header {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        struct Data {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        let hdr = Header { version: 0x2008_0522, pid: 0 }; // _LINUX_CAPABILITY_VERSION_3
        let data = [Data { effective: 0, permitted: 0, inheritable: 0 }, Data { effective: 0, permitted: 0, inheritable: 0 }];
        chk(libc::syscall(libc::SYS_capset, &hdr, data.as_ptr()))?;
    }
    Ok(())
}
