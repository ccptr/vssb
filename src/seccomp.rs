//! Seccomp filter: a deny list of syscalls a sandboxed program has no
//! business making (kernel attack surface, ways around the other layers),
//! plus argument checks for namespace creation, socket families and
//! terminal injection. Built on the host side; installed in the child
//! right before exec.

use crate::error::{Error, Result};
use libc::c_long;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("vssb's seccomp filter supports x86_64 and aarch64 only");

const RET_ALLOW: u32 = 0x7fff_0000;
const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_ERRNO: u32 = 0x0005_0000;

const NS_FLAGS: u32 = (libc::CLONE_NEWNS
    | libc::CLONE_NEWCGROUP
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUSER
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET) as u32;

macro_rules! syscalls {
    ($($name:ident),* $(,)?) => { &[$((stringify!($name), libc::$name)),*] };
}

/// Syscalls known by name, for the deny list and policy entries.
fn known() -> Vec<(&'static str, c_long)> {
    let common: &[(&str, c_long)] = syscalls![
        SYS_ptrace, SYS_process_vm_readv, SYS_process_vm_writev, SYS_pidfd_getfd, SYS_process_madvise,
        SYS_kexec_load, SYS_kexec_file_load, SYS_init_module, SYS_finit_module, SYS_delete_module,
        SYS_bpf, SYS_perf_event_open, SYS_userfaultfd, SYS_add_key, SYS_request_key, SYS_keyctl,
        SYS_mount, SYS_umount2, SYS_pivot_root, SYS_chroot, SYS_move_mount, SYS_open_tree,
        SYS_fsopen, SYS_fsconfig, SYS_fsmount, SYS_fspick, SYS_mount_setattr, SYS_setns,
        SYS_acct, SYS_swapon, SYS_swapoff, SYS_reboot, SYS_syslog, SYS_quotactl, SYS_quotactl_fd,
        SYS_open_by_handle_at, SYS_name_to_handle_at, SYS_io_uring_setup, SYS_io_uring_enter,
        SYS_io_uring_register, SYS_vhangup, SYS_fanotify_init, SYS_lookup_dcookie,
        SYS_settimeofday, SYS_clock_settime, SYS_clock_adjtime, SYS_adjtimex, SYS_sethostname,
        SYS_setdomainname, SYS_personality, SYS_kcmp, SYS_landlock_create_ruleset, SYS_seccomp,
        SYS_clone, SYS_clone3, SYS_unshare, SYS_socket, SYS_ioctl, SYS_execve, SYS_execveat,
        SYS_mbind, SYS_migrate_pages, SYS_move_pages, SYS_set_mempolicy, SYS_nfsservctl,
        SYS_memfd_secret, SYS_mknodat,
    ];
    #[cfg(target_arch = "x86_64")]
    let arch: &[(&str, c_long)] = syscalls![
        SYS_iopl, SYS_ioperm, SYS_uselib, SYS_modify_ldt, SYS__sysctl, SYS_ustat, SYS_sysfs,
        SYS_mknod,
    ];
    #[cfg(target_arch = "aarch64")]
    let arch: &[(&str, c_long)] = &[];
    common.iter().chain(arch).map(|(n, nr)| (n.strip_prefix("SYS_").unwrap_or(n), *nr)).collect()
}

/// Denied outright (EPERM) unless allowed.
pub const DEFAULT_DENY: &[&str] = &[
    "ptrace", "process_vm_readv", "process_vm_writev", "pidfd_getfd", "process_madvise",
    "kexec_load", "kexec_file_load", "init_module", "finit_module", "delete_module",
    "bpf", "perf_event_open", "userfaultfd", "add_key", "request_key", "keyctl",
    "mount", "umount2", "pivot_root", "chroot", "move_mount", "open_tree",
    "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr", "setns",
    "acct", "swapon", "swapoff", "reboot", "syslog", "quotactl", "quotactl_fd",
    "open_by_handle_at", "name_to_handle_at", "io_uring_setup", "io_uring_enter",
    "io_uring_register", "vhangup", "fanotify_init", "lookup_dcookie",
    "settimeofday", "clock_settime", "clock_adjtime", "adjtimex",
    "sethostname", "setdomainname", "nfsservctl",
    // x86_64 only; ignored elsewhere.
    "iopl", "ioperm", "uselib", "modify_ldt", "_sysctl",
];

#[derive(Clone, Copy)]
enum Tgt {
    Next,
    L(usize),
}

enum Ins {
    LdNr,
    LdArch,
    /// Load the low 32 bits of argument n.
    LdArg(u32),
    Jeq(u32, Tgt, Tgt),
    Jge(u32, Tgt, Tgt),
    Jset(u32, Tgt, Tgt),
    Ret(u32),
    Label(usize),
}

struct Asm {
    ins: Vec<Ins>,
    labels: usize,
}

impl Asm {
    fn label(&mut self) -> usize {
        self.labels += 1;
        self.labels
    }

    fn assemble(&self) -> Result<Vec<libc::sock_filter>> {
        // Positions of labels in the final program (labels take no space).
        let mut pos = std::collections::HashMap::new();
        let mut pc = 0usize;
        for i in &self.ins {
            match i {
                Ins::Label(l) => {
                    pos.insert(*l, pc);
                }
                _ => pc += 1,
            }
        }
        let mut out = Vec::with_capacity(pc);
        let off = |pc: usize, t: Tgt| -> Result<u8> {
            match t {
                Tgt::Next => Ok(0),
                Tgt::L(l) => {
                    let d = pos[&l] - (pc + 1);
                    u8::try_from(d).map_err(|_| Error::Config("seccomp jump too long".into()))
                }
            }
        };
        let stmt = |code: u16, k: u32| libc::sock_filter { code, jt: 0, jf: 0, k };
        const LD_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
        for i in &self.ins {
            let pc = out.len();
            let f = match *i {
                Ins::Label(_) => continue,
                Ins::LdNr => stmt(LD_ABS, 0),
                Ins::LdArch => stmt(LD_ABS, 4),
                Ins::LdArg(n) => stmt(LD_ABS, 16 + 8 * n), // little-endian: low half first
                Ins::Ret(k) => stmt((libc::BPF_RET | libc::BPF_K) as u16, k),
                Ins::Jeq(k, t, f) | Ins::Jge(k, t, f) | Ins::Jset(k, t, f) => {
                    let op = match i {
                        Ins::Jeq(..) => libc::BPF_JEQ,
                        Ins::Jge(..) => libc::BPF_JGE,
                        _ => libc::BPF_JSET,
                    };
                    libc::sock_filter { code: (libc::BPF_JMP | op | libc::BPF_K) as u16, jt: off(pc, t)?, jf: off(pc, f)?, k }
                }
            };
            out.push(f);
        }
        Ok(out)
    }
}

/// An assembled BPF program.
#[derive(Clone)]
pub struct Filter {
    prog: Vec<libc::sock_filter>,
    denied: Vec<String>,
}

impl std::fmt::Debug for Filter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Filter").field("instructions", &self.prog.len()).field("denied", &self.denied).finish()
    }
}

fn errno(e: i32) -> u32 {
    RET_ERRNO | (e as u32 & 0xffff)
}

impl Filter {
    /// The default filter, minus `allow`, plus `extra_deny` (names, or
    /// "nr:<number>").
    pub fn build(allow: &[String], extra_deny: &[String]) -> Result<Filter> {
        let known = known();
        let lookup = |name: &str| -> Result<Option<c_long>> {
            if let Some(n) = name.strip_prefix("nr:") {
                return n.parse().map(Some).map_err(|_| Error::Config(format!("seccomp: invalid syscall number {name:?}")));
            }
            Ok(known.iter().find(|(k, _)| *k == name).map(|(_, nr)| *nr))
        };
        for a in allow {
            if lookup(a)?.is_none() && !DEFAULT_DENY.contains(&a.as_str()) {
                return Err(Error::Config(format!("seccomp allow: unknown syscall {a:?}")));
            }
        }
        let allowed = |name: &str| allow.iter().any(|a| a == name);

        let mut plain: Vec<(String, c_long)> = Vec::new();
        for name in DEFAULT_DENY.iter().map(|s| s.to_string()).chain(extra_deny.iter().cloned()) {
            if allowed(&name) {
                continue;
            }
            match lookup(&name)? {
                Some(nr) => {
                    if !plain.iter().any(|(_, n)| *n == nr) {
                        plain.push((name, nr));
                    }
                }
                None if DEFAULT_DENY.contains(&name.as_str()) => {} // not on this arch
                None => return Err(Error::Config(format!("seccomp deny: unknown syscall {name:?} (use \"nr:<number>\")"))),
            }
        }

        let mut a = Asm { ins: vec![], labels: 0 };
        let allow_l = a.label();
        let arch_ok = a.label();
        a.ins.push(Ins::LdArch);
        a.ins.push(Ins::Jeq(AUDIT_ARCH, Tgt::L(arch_ok), Tgt::Next));
        a.ins.push(Ins::Ret(RET_KILL_PROCESS));
        a.ins.push(Ins::Label(arch_ok));
        a.ins.push(Ins::LdNr);
        #[cfg(target_arch = "x86_64")]
        {
            // x32 ABI syscalls carry this bit and would dodge the numbers below.
            let not_x32 = a.label();
            a.ins.push(Ins::Jge(0x4000_0000, Tgt::Next, Tgt::L(not_x32)));
            a.ins.push(Ins::Ret(errno(libc::EPERM)));
            a.ins.push(Ins::Label(not_x32));
        }
        for (_, nr) in &plain {
            let next = a.label();
            a.ins.push(Ins::Jeq(*nr as u32, Tgt::Next, Tgt::L(next)));
            a.ins.push(Ins::Ret(errno(libc::EPERM)));
            a.ins.push(Ins::Label(next));
        }

        // New namespaces: no nested user namespaces and friends.
        let ns_checks: &[(&str, c_long, u32)] = &[
            ("clone", libc::SYS_clone, NS_FLAGS),
            ("unshare", libc::SYS_unshare, NS_FLAGS | libc::CLONE_NEWTIME as u32),
        ];
        for &(name, nr, mask) in ns_checks {
            if allowed(name) {
                continue;
            }
            let next = a.label();
            a.ins.push(Ins::Jeq(nr as u32, Tgt::Next, Tgt::L(next)));
            a.ins.push(Ins::LdArg(0));
            a.ins.push(Ins::Jset(mask, Tgt::Next, Tgt::L(allow_l)));
            a.ins.push(Ins::Ret(errno(libc::EPERM)));
            a.ins.push(Ins::Label(next));
            a.ins.push(Ins::LdNr);
        }
        // clone3 passes flags in memory, which seccomp can't read: make libc fall back to clone.
        if !allowed("clone3") {
            let next = a.label();
            a.ins.push(Ins::Jeq(libc::SYS_clone3 as u32, Tgt::Next, Tgt::L(next)));
            a.ins.push(Ins::Ret(errno(libc::ENOSYS)));
            a.ins.push(Ins::Label(next));
        }

        // Socket families: unix, IPv4, IPv6 and netlink (route and sock_diag only).
        if !allowed("socket") {
            let next = a.label();
            let netlink = a.label();
            a.ins.push(Ins::Jeq(libc::SYS_socket as u32, Tgt::Next, Tgt::L(next)));
            a.ins.push(Ins::LdArg(0));
            for fam in [libc::AF_UNIX, libc::AF_INET, libc::AF_INET6] {
                a.ins.push(Ins::Jeq(fam as u32, Tgt::L(allow_l), Tgt::Next));
            }
            a.ins.push(Ins::Jeq(libc::AF_NETLINK as u32, Tgt::L(netlink), Tgt::Next));
            a.ins.push(Ins::Ret(errno(libc::EAFNOSUPPORT)));
            a.ins.push(Ins::Label(netlink));
            a.ins.push(Ins::LdArg(2));
            a.ins.push(Ins::Jeq(libc::NETLINK_ROUTE as u32, Tgt::L(allow_l), Tgt::Next));
            a.ins.push(Ins::Jeq(libc::NETLINK_SOCK_DIAG as u32, Tgt::L(allow_l), Tgt::Next));
            a.ins.push(Ins::Ret(errno(libc::EPROTONOSUPPORT)));
            a.ins.push(Ins::Label(next));
            a.ins.push(Ins::LdNr);
        }

        // Terminal injection and line-discipline changes.
        if !allowed("ioctl") {
            let next = a.label();
            let deny = a.label();
            a.ins.push(Ins::Jeq(libc::SYS_ioctl as u32, Tgt::Next, Tgt::L(next)));
            a.ins.push(Ins::LdArg(1));
            for cmd in [libc::TIOCSTI, libc::TIOCLINUX, libc::TIOCSETD] {
                a.ins.push(Ins::Jeq(cmd as u32, Tgt::L(deny), Tgt::Next));
            }
            a.ins.push(Ins::Ret(RET_ALLOW));
            a.ins.push(Ins::Label(deny));
            a.ins.push(Ins::Ret(errno(libc::EPERM)));
            a.ins.push(Ins::Label(next));
        }

        a.ins.push(Ins::Label(allow_l));
        a.ins.push(Ins::Ret(RET_ALLOW));

        let prog = a.assemble()?;
        if prog.len() > u16::MAX as usize {
            return Err(Error::Config("seccomp filter too long".into()));
        }
        Ok(Filter { prog, denied: plain.into_iter().map(|(n, _)| n).collect() })
    }

    /// Names of the syscalls denied outright.
    pub fn denied(&self) -> &[String] {
        &self.denied
    }

    /// Number of BPF instructions.
    pub fn len(&self) -> usize {
        self.prog.len()
    }

    pub fn is_empty(&self) -> bool {
        self.prog.is_empty()
    }

    pub(crate) fn program(&self) -> &[libc::sock_filter] {
        &self.prog
    }
}

/// Installs a filter on the calling thread. Allocation-free; needs
/// no_new_privs.
pub(crate) fn install(prog: &[libc::sock_filter]) -> Result<(), i32> {
    let fprog = libc::sock_fprog { len: prog.len() as u16, filter: prog.as_ptr() as *mut _ };
    crate::sys::chk(unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &fprog as *const _) } as i64).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_jumps_fit() {
        let f = Filter::build(&[], &[]).unwrap();
        assert!(f.len() > 50 && f.len() < 4096);
        assert!(f.denied().iter().any(|d| d == "ptrace"));
        let f = Filter::build(&["ptrace".into(), "socket".into()], &["kcmp".into(), "nr:999".into()]).unwrap();
        assert!(!f.denied().iter().any(|d| d == "ptrace"));
        assert!(f.denied().iter().any(|d| d == "kcmp"));
        assert!(Filter::build(&[], &["not_a_syscall".into()]).is_err());
        assert!(Filter::build(&["not_a_syscall".into()], &[]).is_err());
    }

    #[test]
    fn long_deny_lists_still_reach_allow() {
        // Deny entries come before every jump to the final ALLOW, so any
        // number of them keeps those jumps within 8 bits.
        let many: Vec<String> = (1000..1100).map(|n| format!("nr:{n}")).collect();
        assert!(Filter::build(&[], &many).is_ok());
    }
}
