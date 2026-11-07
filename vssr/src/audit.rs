//! Audit log: one JSON object per line, appended to a file. Every event
//! carries the sandbox id so concurrent runs can share one log.

use crate::util::resolve_guarded;
use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};
use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

pub struct Audit {
    file: Mutex<Option<File>>,
    pub id: String,
    /// Print blocked network requests to stderr.
    pub notify: bool,
}

impl Audit {
    /// Opens (creates) the log for appending. `writable` are the plan's
    /// writable directories: the log may well be in one, so no symlink
    /// there is followed, and only a regular file is written to.
    pub fn open(path: Option<&Path>, writable: &[PathBuf], id: String, notify: bool) -> Result<Audit> {
        let file = path.map(|p| open_log(p, writable).with_context(|| format!("audit log {}", p.display()))).transpose()?;
        Ok(Audit { file: Mutex::new(file), id, notify })
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

fn open_log(p: &Path, writable: &[PathBuf]) -> Result<File> {
    let (Some(parent), Some(name)) = (p.parent(), p.file_name()) else { bail!("not a file path") };
    // Resolve the directory first, so missing parts aren't created through
    // a planted symlink.
    let dir = match resolve_guarded(parent, writable)? {
        Some(d) => d,
        None => {
            std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
            resolve_guarded(parent, writable)?.with_context(|| format!("{} disappeared", parent.display()))?
        }
    };
    // Pin the checked directory: a symlink swapped in since is an error.
    let cdir = CString::new(dir.as_os_str().as_bytes())?;
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_NO_SYMLINKS;
    let fd = unsafe { libc::syscall(libc::SYS_openat2, libc::AT_FDCWD, cdir.as_ptr(), &how as *const libc::open_how, std::mem::size_of::<libc::open_how>()) };
    if fd < 0 {
        return Err(os_err(&format!("opening {}", dir.display())));
    }
    let dfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
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
}
