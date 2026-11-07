//! Landlock, with raw syscalls. The parent works out the ruleset and each
//! rule's access rights for the kernel's ABI; the child (after the mount
//! namespace is in place) opens the paths, adds the rules and restricts
//! itself, without allocating.
//!
//! The rules repeat the mount view's read/write/exec split as a second,
//! independent layer, restrict TCP ports when asked, and scope signals and
//! abstract unix sockets to the sandbox.

use crate::prepare::{POp, PMount};
use crate::report::{self, Report};
use crate::sys::{chk, chk_fd, close, is_dir, open_path};
use std::ffi::CStr;

pub(crate) const EXECUTE: u64 = 1 << 0;
pub(crate) const WRITE_FILE: u64 = 1 << 1;
pub(crate) const READ_FILE: u64 = 1 << 2;
pub(crate) const READ_DIR: u64 = 1 << 3;
const REMOVE_DIR: u64 = 1 << 4;
const REMOVE_FILE: u64 = 1 << 5;
const MAKE_CHAR: u64 = 1 << 6;
const MAKE_DIR: u64 = 1 << 7;
const MAKE_REG: u64 = 1 << 8;
const MAKE_SOCK: u64 = 1 << 9;
const MAKE_FIFO: u64 = 1 << 10;
const MAKE_BLOCK: u64 = 1 << 11;
const MAKE_SYM: u64 = 1 << 12;
const REFER: u64 = 1 << 13; // ABI 2
const TRUNCATE: u64 = 1 << 14; // ABI 3
pub(crate) const IOCTL_DEV: u64 = 1 << 15; // ABI 5
pub(crate) const RESOLVE_UNIX: u64 = 1 << 16; // ABI 9

const NET_BIND_TCP: u64 = 1 << 0; // ABI 4
const NET_CONNECT_TCP: u64 = 1 << 1;

const SCOPE_ABSTRACT_UNIX: u64 = 1 << 0; // ABI 6
const SCOPE_SIGNAL: u64 = 1 << 1;

const RULE_PATH_BENEATH: u32 = 1;
const RULE_NET_PORT: u32 = 2;

/// The newest ABI whose rights vssb knows.
const TARGET: u32 = 9;

pub(crate) const READ: u64 = EXECUTE | READ_FILE | READ_DIR;

/// Write rights known at `abi`.
pub(crate) fn write(abi: u32) -> u64 {
    let mut w = WRITE_FILE | REMOVE_DIR | REMOVE_FILE | MAKE_CHAR | MAKE_DIR | MAKE_REG | MAKE_SOCK | MAKE_FIFO | MAKE_BLOCK | MAKE_SYM;
    if abi >= 2 {
        w |= REFER;
    }
    if abi >= 3 {
        w |= TRUNCATE;
    }
    if abi >= 5 {
        w |= IOCTL_DEV;
    }
    if abi >= 9 {
        w |= RESOLVE_UNIX;
    }
    w
}

/// Rights that make sense on a non-directory.
const FILE_ONLY: u64 = READ_FILE | WRITE_FILE | EXECUTE | TRUNCATE | IOCTL_DEV | RESOLVE_UNIX;

#[repr(C)]
struct RulesetAttr {
    fs: u64,
    net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneath {
    allowed_access: u64,
    parent_fd: i32,
}

#[repr(C)]
struct NetPort {
    allowed_access: u64,
    port: u64,
}

/// The ruleset, worked out on the host side.
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    pub fs: u64,
    pub net: u64,
    pub scoped: u64,
    /// Size of the ruleset attribute this kernel understands.
    pub attr_size: usize,
    /// Rights for the Dev mount's shm directory.
    pub shm: u64,
    pub ports: Vec<(u64, u16)>,
}

impl Plan {
    /// `None` when the kernel has no Landlock.
    pub fn new(abi: u32, connect: Option<&[u16]>, bind: Option<&[u16]>) -> Option<Plan> {
        if abi == 0 {
            return None;
        }
        let abi = abi.min(TARGET);
        let fs = READ | write(abi);
        let mut net = 0;
        let mut ports = Vec::new();
        if abi >= 4 {
            if let Some(c) = connect {
                net |= NET_CONNECT_TCP;
                ports.extend(c.iter().map(|&p| (NET_CONNECT_TCP, p)));
            }
            if let Some(b) = bind {
                net |= NET_BIND_TCP;
                ports.extend(b.iter().map(|&p| (NET_BIND_TCP, p)));
            }
        }
        let scoped = if abi >= 6 { SCOPE_ABSTRACT_UNIX | SCOPE_SIGNAL } else { 0 };
        let attr_size = if abi >= 6 { 24 } else if abi >= 4 { 16 } else { 8 };
        Some(Plan { fs, net, scoped, attr_size, shm: (fs & !EXECUTE), ports })
    }

    /// The rights for one mount (0: no rule), before the runtime check for
    /// read-only directories mounted below it.
    pub fn access(&self, op: &POp, noexec: bool) -> u64 {
        let x = if noexec { 0 } else { EXECUTE };
        let rw = (self.fs & !EXECUTE) | x;
        let a = match op {
            POp::Bind { rw: false, .. } => (READ & !EXECUTE) | x,
            POp::Bind { rw: true, .. } | POp::Tmpfs { .. } => rw,
            POp::Proc => READ_FILE | READ_DIR | WRITE_FILE,
            POp::Dev { .. } => READ_FILE | READ_DIR | WRITE_FILE | IOCTL_DEV,
            POp::Deny | POp::Symlink { .. } => 0,
        };
        a & self.fs
    }
}

fn add_path(ruleset: i32, path: &CStr, access: u64) -> Result<(), i32> {
    let fd = open_path(path)?;
    let access = match is_dir(fd) {
        Ok(true) => access,
        Ok(false) => access & FILE_ONLY,
        Err(e) => {
            close(fd);
            return Err(e);
        }
    };
    let mut r = Ok(0);
    if access != 0 {
        let attr = PathBeneath { allowed_access: access, parent_fd: fd };
        r = chk(unsafe { libc::syscall(libc::SYS_landlock_add_rule, ruleset, RULE_PATH_BENEATH, &attr as *const PathBeneath, 0u32) });
    }
    close(fd);
    r.map(|_| ())
}

/// Applies the ruleset to the calling process. Runs in the child after
/// pivot_root, so the paths are the sandbox's own.
pub(crate) fn apply(plan: &Plan, mounts: &[PMount], attached: &[bool]) -> Result<(), Report> {
    let fail = |e: i32, a: u32| Report::new(report::LANDLOCK, e, a);
    let attr = RulesetAttr { fs: plan.fs, net: plan.net, scoped: plan.scoped };
    let rs = chk_fd(unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, &attr as *const RulesetAttr, plan.attr_size, 0u32) })
        .map_err(|e| fail(e, report::NONE))?;
    add_path(rs, c"/", READ_DIR).map_err(|e| fail(e, report::NONE))?;
    for (i, m) in mounts.iter().enumerate() {
        if !attached.get(i).copied().unwrap_or(false) || m.access == 0 {
            continue;
        }
        let mut a = m.access;
        // Rights flow down the tree, through mount points: a read-only
        // directory (or socket) mounted below a writable one would inherit
        // the right to connect to unix sockets there.
        if m.ro_below.iter().any(|&j| attached.get(j).copied().unwrap_or(false)) {
            a &= !RESOLVE_UNIX;
        }
        add_path(rs, &m.dest, a).map_err(|e| fail(e, i as u32))?;
        if let Some(shm) = &m.shm {
            add_path(rs, shm, plan.shm).map_err(|e| fail(e, i as u32))?;
        }
    }
    for &(access, port) in &plan.ports {
        let attr = NetPort { allowed_access: access, port: port as u64 };
        chk(unsafe { libc::syscall(libc::SYS_landlock_add_rule, rs, RULE_NET_PORT, &attr as *const NetPort, 0u32) })
            .map_err(|e| fail(e, report::NONE))?;
    }
    let r = chk(unsafe { libc::syscall(libc::SYS_landlock_restrict_self, rs, 0u32) });
    close(rs);
    r.map(|_| ()).map_err(|e| fail(e, report::NONE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_per_abi() {
        assert_eq!(write(1) & (REFER | TRUNCATE | IOCTL_DEV | RESOLVE_UNIX), 0);
        assert_ne!(write(9) & RESOLVE_UNIX, 0);
        assert_eq!(READ & write(9), 0);
        let p = Plan::new(3, Some(&[443]), None).unwrap();
        assert_eq!(p.net, 0, "no TCP rules before ABI 4");
        assert_eq!(p.attr_size, 8);
        let p = Plan::new(10, Some(&[443]), Some(&[])).unwrap();
        assert_eq!(p.net, NET_CONNECT_TCP | NET_BIND_TCP);
        assert_eq!(p.attr_size, 24);
        assert_eq!(p.fs, READ | write(9), "rights beyond the known ABI are not requested");
        assert!(Plan::new(0, None, None).is_none());
    }
}
