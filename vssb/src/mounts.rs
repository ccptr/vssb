//! Builds the filesystem view inside the new mount namespace. Runs in the
//! cloned child: raw syscalls only, no allocation (see child.rs).
//!
//! Bind sources are cloned (open_tree) and given their final flags
//! (read-only, nosuid, nodev, noexec) while still detached, so they never
//! appear writable. A fresh tmpfs becomes the new root, mounts are attached
//! under it parent-first, and mount points are looked up with
//! openat2(RESOLVE_NO_SYMLINKS) so no symlink can redirect a mount. Mount
//! points are only ever created in filesystems vssb made itself, never
//! inside a bind mount (that would write to the host).

use crate::prepare::{POp, PMount, Prepared};
use crate::report::{self, Report};
use crate::sys::{chk, chk_fd, close, errno, is_dir};
use std::ffi::CStr;

const OPEN_TREE_CLONE: u32 = 1;
const AT_RECURSIVE: u32 = 0x8000;
const MOVE_MOUNT_F_EMPTY_PATH: u32 = 0x4;
const MOVE_MOUNT_T_EMPTY_PATH: u32 = 0x40;
const FSOPEN_CLOEXEC: u32 = 1;
const FSCONFIG_SET_STRING: u32 = 1;
const FSCONFIG_CMD_CREATE: u32 = 6;
const FSMOUNT_CLOEXEC: u32 = 1;
const MOUNT_ATTR_RDONLY: u64 = 0x1;
const MOUNT_ATTR_NOSUID: u64 = 0x2;
const MOUNT_ATTR_NODEV: u64 = 0x4;
const MOUNT_ATTR_NOEXEC: u64 = 0x8;
const RESOLVE_NO_MAGICLINKS: u64 = 0x2;
const RESOLVE_NO_SYMLINKS: u64 = 0x4;
const RESOLVE_BENEATH: u64 = 0x8;

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

type R<T> = Result<T, Report>;

fn open_tree(dfd: i32, path: &CStr, recursive: bool) -> Result<i32, i32> {
    let flags = OPEN_TREE_CLONE | libc::O_CLOEXEC as u32 | if recursive { AT_RECURSIVE } else { 0 };
    chk_fd(unsafe { libc::syscall(libc::SYS_open_tree, dfd, path.as_ptr(), flags) })
}

fn set_attr(fd: i32, set: u64, recursive: bool) -> Result<(), i32> {
    let attr = MountAttr { attr_set: set, attr_clr: 0, propagation: 0, userns_fd: 0 };
    let flags = libc::AT_EMPTY_PATH as u32 | if recursive { AT_RECURSIVE } else { 0 };
    chk(unsafe { libc::syscall(libc::SYS_mount_setattr, fd, c"".as_ptr(), flags, &attr as *const MountAttr, std::mem::size_of::<MountAttr>()) })
        .map(|_| ())
}

fn move_mount(from: i32, to: i32) -> Result<(), i32> {
    chk(unsafe {
        libc::syscall(libc::SYS_move_mount, from, c"".as_ptr(), to, c"".as_ptr(), MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH)
    })
    .map(|_| ())
}

/// Creates a detached filesystem mount (tmpfs, proc, devpts).
fn new_fs<'a>(fstype: &CStr, opts: impl Iterator<Item = (&'a CStr, &'a CStr)>, attrs: u64) -> Result<i32, i32> {
    let fs = chk_fd(unsafe { libc::syscall(libc::SYS_fsopen, fstype.as_ptr(), FSOPEN_CLOEXEC) })?;
    let r = (|| {
        for (k, v) in opts {
            chk(unsafe { libc::syscall(libc::SYS_fsconfig, fs, FSCONFIG_SET_STRING, k.as_ptr(), v.as_ptr(), 0) })?;
        }
        chk(unsafe { libc::syscall(libc::SYS_fsconfig, fs, FSCONFIG_CMD_CREATE, std::ptr::null::<u8>(), std::ptr::null::<u8>(), 0) })?;
        chk_fd(unsafe { libc::syscall(libc::SYS_fsmount, fs, FSMOUNT_CLOEXEC, attrs) })
    })();
    close(fs);
    r
}

fn pairs(v: &[(std::ffi::CString, std::ffi::CString)]) -> impl Iterator<Item = (&CStr, &CStr)> {
    v.iter().map(|(k, v)| (k.as_c_str(), v.as_c_str()))
}

/// Opens one path component under `dir` without following any symlink.
fn open_component(dir: i32, name: &CStr) -> Result<i32, i32> {
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64;
    how.resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_BENEATH;
    chk_fd(unsafe { libc::syscall(libc::SYS_openat2, dir, name.as_ptr(), &how as *const libc::open_how, std::mem::size_of::<libc::open_how>()) })
}

fn file_type(fd: i32) -> Result<u32, i32> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    chk(unsafe { libc::fstat(fd, &mut st) } as i64)?;
    Ok(st.st_mode & libc::S_IFMT)
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Dir,
    File,
    /// Look up only: accept whatever is there.
    Any,
}

/// Whether vssb may create a missing entry below the first `k` components
/// of mount `i`'s path: that depends on the deepest attached mount above
/// it. Returns (creatable, index of that mount or NONE for the root).
fn owner(mounts: &[PMount], regions: &[u8], i: usize, k: usize) -> (bool, u32) {
    let mut best: Option<(usize, usize)> = None;
    if let Some(m) = mounts.get(i) {
        for &j in &m.ancestors {
            let (Some(mj), Some(&r)) = (mounts.get(j), regions.get(j)) else { continue };
            if r != 0 && mj.depth() <= k && best.is_none_or(|(_, d)| mj.depth() > d) {
                best = Some((j, mj.depth()));
            }
        }
    }
    match best {
        None => (true, report::NONE),
        Some((j, _)) => (regions.get(j) == Some(&1), j as u32),
    }
}

/// Walks the first `upto` components of mount `i`'s path from `root`,
/// creating missing directories (and a final empty file for file mounts)
/// where allowed. Returns None when the path is missing and the caller
/// should skip the mount.
#[allow(clippy::too_many_arguments)]
fn ensure(root: i32, mounts: &[PMount], regions: &[u8], i: usize, upto: usize, kind: Kind, create: bool, optional: bool) -> R<Option<i32>> {
    let Some(m) = mounts.get(i) else { return Ok(None) };
    let ix = i as u32;
    let mut cur = chk_fd(unsafe { libc::fcntl(root, libc::F_DUPFD_CLOEXEC, 3) } as i64).map_err(|e| Report::new(report::OPEN_PATH, e, ix))?;
    for (k, name) in m.comps.iter().take(upto).enumerate() {
        let last = k + 1 == upto;
        let want = if last { kind } else { Kind::Dir };
        let depth = (k + 1) as u32;
        let fd = match open_component(cur, name) {
            Ok(fd) => fd,
            Err(libc::ENOENT) => {
                if !create {
                    close(cur);
                    return Ok(None);
                }
                let (creatable, region) = owner(mounts, regions, i, k);
                if !creatable {
                    close(cur);
                    if optional {
                        return Ok(None);
                    }
                    return Err(Report::with(report::NOT_CREATABLE, libc::ENOENT, ix, depth, region));
                }
                let r = if want == Kind::Dir {
                    unsafe { libc::mkdirat(cur, name.as_ptr(), 0o755) }
                } else {
                    let f = unsafe { libc::openat(cur, name.as_ptr(), libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC, 0o644) };
                    close(f);
                    f
                };
                if r < 0 {
                    return Err(Report::with(report::CREATE, errno(), ix, depth, report::NONE));
                }
                open_component(cur, name).map_err(|e| Report::with(report::OPEN_PATH, e, ix, depth, report::NONE))?
            }
            Err(libc::ELOOP) => return Err(Report::with(report::SYMLINK_IN_PATH, libc::ELOOP, ix, depth, report::NONE)),
            Err(e) => return Err(Report::with(report::OPEN_PATH, e, ix, depth, report::NONE)),
        };
        close(cur);
        cur = fd;
        // O_PATH|O_NOFOLLOW opens a final symlink instead of failing.
        let mode = file_type(fd).map_err(|e| Report::with(report::OPEN_PATH, e, ix, depth, report::NONE))?;
        if mode == libc::S_IFLNK {
            return Err(Report::with(report::SYMLINK_IN_PATH, libc::ELOOP, ix, depth, report::NONE));
        }
        let dir = mode == libc::S_IFDIR;
        match want {
            Kind::Dir if !dir => return Err(Report::with(report::NOT_DIR, libc::ENOTDIR, ix, depth, report::NONE)),
            Kind::File if dir => return Err(Report::new(report::IS_DIR, libc::EISDIR, ix)),
            _ => {}
        }
    }
    Ok(Some(cur))
}

const DEV_NAMES: [&CStr; 6] = [c"null", c"zero", c"full", c"random", c"urandom", c"tty"];
const DEV_PATHS: [&CStr; 6] = [c"/dev/null", c"/dev/zero", c"/dev/full", c"/dev/random", c"/dev/urandom", c"/dev/tty"];

/// Builds the view and pivots into it, recording which mounts were
/// attached (optional ones may be skipped).
pub(crate) fn build(p: &mut Prepared) -> R<()> {
    let none = std::ptr::null::<libc::c_char>();
    if unsafe { libc::mount(none, c"/".as_ptr(), none, libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) } < 0 {
        return Err(Report::new(report::MOUNT_PRIVATE, errno(), report::NONE));
    }

    // Clone everything that comes from the host before /tmp gets covered.
    for (i, m) in p.mounts.iter().enumerate() {
        let ix = i as u32;
        let fd = match &m.op {
            POp::Bind { src, rw } => match open_tree(libc::AT_FDCWD, src, true) {
                Ok(fd) => {
                    let mut a = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV;
                    if !rw {
                        a |= MOUNT_ATTR_RDONLY;
                    }
                    if m.noexec {
                        a |= MOUNT_ATTR_NOEXEC;
                    }
                    set_attr(fd, a, true).map_err(|e| Report::new(report::SET_ATTR, e, ix))?;
                    fd
                }
                Err(libc::ENOENT) if m.optional => -1,
                Err(e) => return Err(Report::new(report::OPEN_SOURCE, e, ix)),
            },
            POp::Proc => new_fs(c"proc", std::iter::empty(), MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC)
                .map_err(|e| Report::new(report::NEW_FS, e, ix))?,
            _ => -1,
        };
        if let Some(s) = p.sources.get_mut(i) {
            *s = fd;
        }
    }
    let mut devs = [-1i32; 6];
    if p.any_dev {
        for (d, path) in devs.iter_mut().zip(DEV_PATHS) {
            if let Ok(fd) = open_tree(libc::AT_FDCWD, path, false) {
                set_attr(fd, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC, false).map_err(|e| Report::new(report::DEVICES, e, report::NONE))?;
                *d = fd;
            }
        }
    }
    let internal = |e: i32| Report::new(report::NEW_FS, e, report::NONE);
    // An empty, mode-000 file to bind over denied files.
    let empty = new_fs(c"tmpfs", [(c"mode", c"0755"), (c"size", c"4096")].into_iter(), MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC)
        .map_err(internal)?;
    let f = unsafe { libc::openat(empty, c"empty".as_ptr(), libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC, 0) };
    if f < 0 {
        return Err(internal(errno()));
    }
    close(f);

    // The new root: a tmpfs mounted over /tmp in this namespace only.
    let root = new_fs(c"tmpfs", [(c"mode", c"0755"), (c"size", c"1048576")].into_iter(), MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV)
        .map_err(|e| Report::new(report::NEW_ROOT, e, report::NONE))?;
    let tmp = unsafe { libc::open(c"/tmp".as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if tmp < 0 {
        return Err(Report::new(report::NEW_ROOT, errno(), report::NONE));
    }
    move_mount(root, tmp).map_err(|e| Report::new(report::NEW_ROOT, e, report::NONE))?;
    close(tmp);

    let Prepared { mounts, attached, regions, sources, ro_later, .. } = p;
    for (i, m) in mounts.iter().enumerate() {
        let ix = i as u32;
        let mv = |from: i32, to: i32| {
            let r = move_mount(from, to).map_err(|e| Report::new(report::MOVE_MOUNT, e, ix));
            close(to);
            r
        };
        let depth = m.depth();
        match &m.op {
            POp::Symlink { target } => {
                let Some(dir) = ensure(root, mounts, regions, i, depth - 1, Kind::Dir, true, m.optional)? else { continue };
                let name = m.comps.last().map(|c| c.as_c_str()).unwrap_or(c"");
                let r = unsafe { libc::symlinkat(target.as_ptr(), dir, name.as_ptr()) };
                close(dir);
                if r < 0 {
                    return Err(Report::new(report::SYMLINK, errno(), ix));
                }
            }
            POp::Bind { .. } => {
                let src = sources.get(i).copied().unwrap_or(-1);
                if src < 0 {
                    continue; // optional and missing
                }
                let kind = match is_dir(src) {
                    Ok(true) => Kind::Dir,
                    Ok(false) => Kind::File,
                    Err(e) => return Err(Report::new(report::OPEN_SOURCE, e, ix)),
                };
                let Some(t) = ensure(root, mounts, regions, i, depth, kind, true, m.optional)? else { continue };
                mv(src, t)?;
                regions[i] = 2;
            }
            POp::Tmpfs { opts } => {
                let mut a = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV;
                if m.noexec {
                    a |= MOUNT_ATTR_NOEXEC;
                }
                let fs = new_fs(c"tmpfs", pairs(opts), a).map_err(|e| Report::new(report::NEW_FS, e, ix))?;
                let Some(t) = ensure(root, mounts, regions, i, depth, Kind::Dir, true, m.optional)? else {
                    close(fs);
                    continue;
                };
                mv(fs, t)?;
                close(fs);
                regions[i] = 1;
            }
            POp::Deny => {
                // Hide only what is actually visible at that path.
                let Some(t) = ensure(root, mounts, regions, i, depth, Kind::Any, false, true)? else { continue };
                let dir = is_dir(t).map_err(|e| Report::new(report::OPEN_PATH, e, ix))?;
                if dir {
                    let fs = new_fs(c"tmpfs", [(c"mode", c"0000"), (c"size", c"4096")].into_iter(), MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC)
                        .map_err(|e| Report::new(report::NEW_FS, e, ix))?;
                    mv(fs, t)?;
                    regions[i] = 1;
                    ro_later[i] = fs;
                } else {
                    let f = open_tree(empty, c"empty", false).map_err(|e| Report::new(report::NEW_FS, e, ix))?;
                    set_attr(f, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC, false)
                        .map_err(|e| Report::new(report::SET_ATTR, e, ix))?;
                    mv(f, t)?;
                    close(f);
                }
            }
            POp::Proc => {
                let fs = sources.get(i).copied().unwrap_or(-1);
                let Some(t) = ensure(root, mounts, regions, i, depth, Kind::Dir, true, false)? else { continue };
                mv(fs, t)?;
                regions[i] = 2;
            }
            POp::Dev { shm_opts } => {
                let fs = new_fs(c"tmpfs", [(c"mode", c"0755"), (c"size", c"1048576")].into_iter(), MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC)
                    .map_err(|e| Report::new(report::NEW_FS, e, ix))?;
                let Some(t) = ensure(root, mounts, regions, i, depth, Kind::Dir, true, false)? else {
                    close(fs);
                    continue;
                };
                mv(fs, t)?;
                regions[i] = 1;
                build_dev(fs, &mut devs, shm_opts)?;
                ro_later[i] = fs;
            }
        }
        attached[i] = true;
    }
    close(empty);
    for d in devs {
        close(d);
    }

    // Switch to the new root and drop the host's.
    let pivot = |e: i32| Report::new(report::PIVOT, e, report::NONE);
    let dot = c".".as_ptr();
    chk(unsafe { libc::chdir(c"/tmp".as_ptr()) } as i64).map_err(pivot)?;
    chk(unsafe { libc::syscall(libc::SYS_pivot_root, dot, dot) }).map_err(pivot)?;
    chk(unsafe { libc::umount2(dot, libc::MNT_DETACH) } as i64).map_err(pivot)?;
    chk(unsafe { libc::chdir(c"/".as_ptr()) } as i64).map_err(pivot)?;

    let ro = |e: i32| Report::new(report::READ_ONLY, e, report::NONE);
    set_attr(root, MOUNT_ATTR_RDONLY, false).map_err(ro)?;
    close(root);
    for fd in ro_later.iter_mut() {
        if *fd >= 0 {
            set_attr(*fd, MOUNT_ATTR_RDONLY, false).map_err(ro)?;
            close(*fd);
            *fd = -1;
        }
    }
    for fd in sources.iter_mut() {
        close(*fd); // moved or unused clones
        *fd = -1;
    }
    Ok(())
}

/// Fills a fresh /dev tmpfs (through its mount fd, so no path lookups).
fn build_dev(dev: i32, devs: &mut [i32; 6], shm_opts: &[(std::ffi::CString, std::ffi::CString)]) -> R<()> {
    let fail = |e: i32| Report::new(report::DEVICES, e, report::NONE);
    for (d, name) in devs.iter_mut().zip(DEV_NAMES) {
        if *d < 0 {
            continue;
        }
        let f = unsafe { libc::openat(dev, name.as_ptr(), libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC, 0o644) };
        if f < 0 {
            return Err(fail(errno()));
        }
        close(f);
        let t = open_component(dev, name).map_err(fail)?;
        let r = move_mount(*d, t);
        close(t);
        r.map_err(fail)?;
        close(*d);
        *d = -1;
    }
    let sub = |name: &CStr, fs: i32| -> R<()> {
        if unsafe { libc::mkdirat(dev, name.as_ptr(), 0o755) } < 0 {
            return Err(fail(errno()));
        }
        let t = open_component(dev, name).map_err(fail)?;
        let r = move_mount(fs, t);
        close(t);
        close(fs);
        r.map_err(fail)
    };
    let pts = new_fs(c"devpts", [(c"ptmxmode", c"0666"), (c"mode", c"0620")].into_iter(), MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC).map_err(fail)?;
    sub(c"pts", pts)?;
    let shm = new_fs(c"tmpfs", pairs(shm_opts), MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV).map_err(fail)?;
    sub(c"shm", shm)?;
    for (name, target) in [
        (c"ptmx", c"pts/ptmx"),
        (c"fd", c"/proc/self/fd"),
        (c"stdin", c"/proc/self/fd/0"),
        (c"stdout", c"/proc/self/fd/1"),
        (c"stderr", c"/proc/self/fd/2"),
    ] {
        if unsafe { libc::symlinkat(target.as_ptr(), dev, name.as_ptr()) } < 0 {
            return Err(fail(errno()));
        }
    }
    Ok(())
}
