//! Audit log: one JSON object per line, appended to a file or written to a
//! descriptor the caller passed in. Every event carries the sandbox id so
//! concurrent runs can share one log. vssr's own messages are events too;
//! `say` also prints them to stderr unless the run is quiet.

use crate::util::resolve_guarded_prefix;
use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};
use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

pub struct Audit {
    file: Mutex<Option<File>>,
    pub id: String,
    /// Messages go to the log only, not to stderr.
    pub quiet: bool,
}

impl Audit {
    /// Opens (creates) the log for appending. `writable` are the plan's
    /// writable directories: the log may well be in one, so no symlink
    /// there is followed, and only a regular file is written to.
    pub fn open(path: Option<&Path>, writable: &[PathBuf], id: String, quiet: bool) -> Result<Audit> {
        let file = path.map(|p| open_log(p, writable).with_context(|| format!("audit log {}", p.display()))).transpose()?;
        Ok(Audit { file: Mutex::new(file), id, quiet })
    }

    /// Writes events to `fd`, a descriptor the caller passed in (a pipe,
    /// socket or file). No path is involved, so nothing the sandbox planted
    /// can redirect it. vssr writes to its own copy; the caller's
    /// descriptor is left open (the sandbox's init closes it).
    pub fn from_fd(fd: RawFd, id: String, quiet: bool) -> Result<Audit> {
        let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if fl < 0 {
            return Err(os_err(&format!("descriptor {fd}")));
        }
        if fl & libc::O_PATH != 0 || fl & libc::O_ACCMODE == libc::O_RDONLY {
            bail!("descriptor {fd} is not open for writing");
        }
        let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if copy < 0 {
            return Err(os_err(&format!("copying descriptor {fd}")));
        }
        // Keep it out of helpers vssr runs (busctl). Not for 0-2, which the
        // program inherits as its stdio.
        if fd > 2 {
            let fdfl = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if fdfl >= 0 {
                unsafe { libc::fcntl(fd, libc::F_SETFD, fdfl | libc::FD_CLOEXEC) };
            }
        }
        Ok(Audit { file: Mutex::new(Some(unsafe { File::from_raw_fd(copy) })), id, quiet })
    }

    /// One of vssr's messages: an event, and `text` on stderr unless quiet.
    pub fn say(&self, event: &str, fields: Value, text: &str) {
        self.event(event, fields);
        if !self.quiet {
            eprintln!("vssr: {text}");
        }
    }

    pub fn event(&self, event: &str, fields: Value) {
        let mut guard = self.file.lock().unwrap_or_else(|e| e.into_inner());
        let Some(f) = guard.as_mut() else { return };
        let mut obj = Map::new();
        obj.insert("ts".into(), json!(crate::util::rfc3339(SystemTime::now())));
        obj.insert("sandbox".into(), json!(self.id));
        obj.insert("event".into(), json!(event));
        if let Value::Object(m) = fields {
            obj.extend(m);
        }
        let mut line = Value::Object(obj).to_string();
        line.push('\n');
        // One write per line so concurrent writers with O_APPEND don't interleave.
        let _ = f.write_all(line.as_bytes());
    }
}

fn os_err(what: &str) -> anyhow::Error {
    anyhow::Error::new(std::io::Error::last_os_error()).context(what.to_string())
}

/// openat2 with RESOLVE_NO_SYMLINKS, for a directory.
fn open_dir(dirfd: libc::c_int, path: &[u8]) -> std::io::Result<OwnedFd> {
    let c = CString::new(path)?;
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_NO_SYMLINKS;
    let fd = unsafe { libc::syscall(libc::SYS_openat2, dirfd, c.as_ptr(), &how as *const libc::open_how, std::mem::size_of::<libc::open_how>()) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// Opens the log's directory, creating what is missing. The part that
/// exists is resolved with `resolve_guarded` and pinned; each missing
/// component is then made with `mkdirat` and opened from its parent's
/// descriptor without following a symlink, so a symlink planted on the
/// way (by the sandbox, before or during this) is an error, never a
/// place where directories get created.
fn log_dir(parent: &Path, writable: &[PathBuf]) -> Result<OwnedFd> {
    let (dir, missing) = resolve_guarded_prefix(parent, writable)?;
    if let Some(i) = missing.iter().position(|c| c == "..") {
        bail!("{}: \"..\" after the missing directory {}", parent.display(), dir.join(missing[0..i].iter().collect::<PathBuf>()).display());
    }
    // Pin the checked directory: a symlink swapped in since is an error.
    let mut dfd = open_dir(libc::AT_FDCWD, dir.as_os_str().as_bytes()).with_context(|| format!("opening {}", dir.display()))?;
    let mut at = dir;
    for c in missing {
        at.push(&c);
        let cname = CString::new(c.as_bytes())?;
        if unsafe { libc::mkdirat(dfd.as_raw_fd(), cname.as_ptr(), 0o777) } < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
            return Err(os_err(&format!("creating {}", at.display())));
        }
        dfd = match open_dir(dfd.as_raw_fd(), c.as_bytes()) {
            Ok(fd) => fd,
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
                bail!("{}: refusing to follow the symlink {} (the sandbox may have planted it)", parent.display(), at.display())
            }
            Err(e) => return Err(anyhow::Error::new(e).context(format!("opening {}", at.display()))),
        };
    }
    Ok(dfd)
}

fn open_log(p: &Path, writable: &[PathBuf]) -> Result<File> {
    let (Some(parent), Some(name)) = (p.parent(), p.file_name()) else { bail!("not a file path") };
    let dfd = log_dir(parent, writable)?;
    // O_NOFOLLOW: no symlink as the log; O_NONBLOCK: a FIFO doesn't block the open.
    let cname = CString::new(name.as_bytes())?;
    let flags = libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    let fd = unsafe { libc::openat(dfd.as_raw_fd(), cname.as_ptr(), flags, 0o600 as libc::c_uint) };
    if fd < 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ELOOP) {
            bail!("is a symlink; refusing to follow it (the sandbox may have planted it)");
        }
        return Err(os_err("opening"));
    }
    let f = unsafe { File::from_raw_fd(fd) };
    if !f.metadata()?.file_type().is_file() {
        bail!("not a regular file");
    }
    let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if fl < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, fl & !libc::O_NONBLOCK) } < 0 {
        return Err(os_err("fcntl"));
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(name: &str) -> PathBuf {
        let b = std::fs::canonicalize(std::env::temp_dir()).unwrap().join(format!("vssr-audit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&b);
        std::fs::create_dir_all(b.join("proj")).unwrap();
        b
    }

    fn open_err(p: &Path, writable: &[PathBuf]) -> String {
        format!("{:#}", Audit::open(Some(p), writable, "t".into(), false).err().expect("refused"))
    }

    #[test]
    fn appends_to_a_regular_file() {
        let b = base("ok");
        let log = b.join("proj/logs/a.jsonl");
        for _ in 0..2 {
            let a = Audit::open(Some(&log), &[b.join("proj")], "t".into(), false).unwrap();
            a.event("x", json!({"n": 1}));
        }
        let text = std::fs::read_to_string(&log).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.lines().all(|l| l.contains(r#""event":"x""#)));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&log).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn writes_to_a_passed_descriptor() {
        let mut p = [0; 2];
        assert_eq!(unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let (r, w) = unsafe { (File::from_raw_fd(p[0]), OwnedFd::from_raw_fd(p[1])) };
        let a = Audit::from_fd(w.as_raw_fd(), "t".into(), true).unwrap();
        a.event("x", json!({"n": 1}));
        drop(a);
        // The caller's descriptor stays open; closing it ends the stream.
        assert!(unsafe { libc::fcntl(w.as_raw_fd(), libc::F_GETFD) } >= 0);
        drop(w);
        let text = std::io::read_to_string(r).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains(r#""event":"x""#) && text.contains(r#""sandbox":"t""#));
    }

    #[test]
    fn refuses_descriptors_it_cannot_write() {
        let mut p = [0; 2];
        assert_eq!(unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let (r, w) = unsafe { (OwnedFd::from_raw_fd(p[0]), OwnedFd::from_raw_fd(p[1])) };
        let err = |fd| format!("{:#}", Audit::from_fd(fd, "t".into(), false).err().expect("refused"));
        assert!(err(r.as_raw_fd()).contains("not open for writing"));
        let c = CString::new("/").unwrap();
        let opath = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        assert!(err(opath).contains("not open for writing"));
        unsafe { libc::close(opath) };
        // Above any descriptor limit, so never open (tests run in parallel
        // threads, and a closed number could be reused meanwhile).
        assert!(err(1 << 30).contains("Bad file descriptor"));
        drop(w);
    }

    #[test]
    fn refuses_symlinks_and_fifos() {
        let b = base("bad");
        let w = [b.join("proj")];
        std::fs::write(b.join("sentinel"), "keep\n").unwrap();
        // The log itself a symlink (anywhere: O_NOFOLLOW).
        std::os::unix::fs::symlink(b.join("sentinel"), b.join("proj/log")).unwrap();
        assert!(open_err(&b.join("proj/log"), &w).contains("symlink"));
        assert!(open_err(&b.join("proj/log"), &[]).contains("symlink"));
        // A symlinked directory under a writable one.
        std::fs::create_dir(b.join("elsewhere")).unwrap();
        std::os::unix::fs::symlink(b.join("elsewhere"), b.join("proj/logs")).unwrap();
        assert!(open_err(&b.join("proj/logs/a.jsonl"), &w).contains("refusing to follow the symlink"));
        assert!(open_err(&b.join("proj/logs/new/a.jsonl"), &w).contains("refusing to follow the symlink"));
        assert!(!b.join("elsewhere/a.jsonl").exists() && !b.join("elsewhere/new").exists());
        assert_eq!(std::fs::read_to_string(b.join("sentinel")).unwrap(), "keep\n");
        // A FIFO, without and with a reader: refused, without hanging.
        let fifo = b.join("proj/fifo");
        let c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(open_err(&fifo, &w).contains("No such device"));
        let reader = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) };
        assert!(reader >= 0);
        assert!(open_err(&fifo, &w).contains("not a regular file"));
        unsafe { libc::close(reader) };
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn creates_directories_without_following_symlinks() {
        let b = base("mkdir");
        let w = [b.join("proj")];
        std::fs::create_dir(b.join("outside")).unwrap();
        std::os::unix::fs::symlink(b.join("outside"), b.join("proj/logs")).unwrap();
        // A missing directory, then "..", then the symlink: refused before
        // anything is created.
        let e = open_err(&b.join("proj/missing/../logs/created/a.jsonl"), &w);
        assert!(e.contains("after the missing directory"), "{e}");
        assert!(!b.join("proj/missing").exists());
        // Missing directories are created, and the log in them.
        let log = b.join("proj/new/deeper/a.jsonl");
        Audit::open(Some(&log), &w, "t".into(), false).unwrap().event("x", json!({}));
        assert!(std::fs::read_to_string(&log).unwrap().contains(r#""event":"x""#));
        assert!(std::fs::read_dir(b.join("outside")).unwrap().next().is_none());
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn creating_directories_races_a_planted_symlink() {
        // A thread keeps planting and removing proj/logs -> outside while
        // the log is opened in proj/logs/new: refused or created in the
        // project, never in outside. Both outcomes are required, so the
        // race really ran.
        let b = base("race");
        let w = [b.join("proj")];
        let (outside, logs) = (b.join("outside"), b.join("proj/logs"));
        std::fs::create_dir(&outside).unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let planter = {
            let (stop, outside, logs) = (stop.clone(), outside.clone(), logs.clone());
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    if std::os::unix::fs::symlink(&outside, &logs).is_ok() {
                        let _ = std::fs::remove_file(&logs);
                    }
                }
            })
        };
        let (mut created, mut refused) = (0, 0);
        for i in 0..20000 {
            match Audit::open(Some(&logs.join("new/a.jsonl")), &w, "t".into(), false) {
                Ok(_) => {
                    created += 1;
                    // The real directory; the planter can't remove it.
                    std::fs::remove_dir_all(&logs).unwrap();
                }
                Err(e) => {
                    let e = format!("{e:#}");
                    assert!(e.contains("symlink") || e.contains("No such file"), "{e}");
                    refused += 1;
                }
            }
            assert!(std::fs::read_dir(&outside).unwrap().next().is_none(), "created outside after {i} rounds");
            if created > 20 && refused > 20 && i > 200 {
                break;
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        planter.join().unwrap();
        assert!(created > 0 && refused > 0, "{created} created, {refused} refused");
        std::fs::remove_dir_all(&b).unwrap();
    }
}
