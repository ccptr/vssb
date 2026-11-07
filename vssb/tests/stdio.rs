//! A caller with stdin, stdout and stderr closed. It closes them for the
//! whole process, so it is its own test binary with a single test.

use std::io::Read;
use vssb::{Cgroup, Command, Sandbox, Stdio};

#[test]
fn closed_stdio_gets_dev_null() {
    let mut sb = Sandbox::new();
    sb.system(true).cgroup(Cgroup::Inherit);
    let mut c = Command::new("sh");
    // Each descriptor of the program, then one that keeps the sandbox up.
    c.args(["-c", "for f in /proc/$$/fd/*; do echo \"${f##*/} $(readlink $f)\"; done; exec sleep 30 >/dev/null"])
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::Inherit)
        .stdout(Stdio::Piped)
        .stderr(Stdio::Inherit);

    let saved: Vec<i32> = (0..3).map(|fd| unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 100) }).collect();
    assert!(saved.iter().all(|&s| s >= 0));
    for fd in 0..3 {
        unsafe { libc::close(fd) };
    }
    let r = sb.spawn(c);
    // vssb keeps nothing of its own there.
    let held: Vec<i32> = (0..3).filter(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0).collect();
    for (fd, &s) in saved.iter().enumerate() {
        unsafe {
            libc::dup2(s, fd as i32);
            libc::close(s);
        }
    }

    let mut child = r.expect("spawn");
    assert_eq!(held, [0i32; 0], "descriptors vssb left on 0-2");
    let mut out = String::new();
    child.stdout.take().unwrap().read_to_string(&mut out).unwrap();
    let fds: Vec<(&str, &str)> = out.lines().filter_map(|l| l.split_once(' ')).collect();
    assert!(fds.contains(&("0", "/dev/null")) && fds.contains(&("2", "/dev/null")), "{out}");
    assert!(!out.contains("socket:"), "no control socket in the program: {out}");
    child.kill().unwrap();
    child.wait().unwrap();
}
