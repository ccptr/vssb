//! cgroup placement. An unprivileged process can't move another process
//! into a cgroup it may configure, but the systemd user manager can: after
//! clone, while the child waits, vssb asks it over D-Bus (with `busctl`)
//! for a transient scope holding the child, with the limits as properties.
//! The child then makes that scope the root of its cgroup namespace.

use crate::config::Limits;
use crate::error::{Error, Result};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Writes limits into a cgroup directory the caller prepared.
pub(crate) fn write_limits(dir: &Path, l: &Limits) -> io::Result<()> {
    if let Some(m) = l.memory {
        std::fs::write(dir.join("memory.max"), m.to_string())?;
        // Missing when swap accounting is off; nothing to limit then.
        let _ = std::fs::write(dir.join("memory.swap.max"), "0");
    }
    if let Some(c) = l.cpus {
        let period = 100_000u64;
        let quota = ((c * period as f64).round() as u64).max(1000);
        std::fs::write(dir.join("cpu.max"), format!("{quota} {period}"))?;
    }
    if let Some(p) = l.pids {
        std::fs::write(dir.join("pids.max"), p.to_string())?;
    }
    Ok(())
}

/// The limits that are not in effect in `dir`.
fn missing(dir: &Path, l: &Limits) -> Vec<&'static str> {
    let read = |f: &str| std::fs::read_to_string(dir.join(f)).map(|s| s.trim().to_string()).unwrap_or_default();
    let mut v = Vec::new();
    if l.memory.is_some() && matches!(read("memory.max").as_str(), "" | "max") {
        v.push("memory");
    }
    if l.pids.is_some() && matches!(read("pids.max").as_str(), "" | "max") {
        v.push("pids");
    }
    if l.cpus.is_some() && read("cpu.max").starts_with("max") {
        v.push("cpu");
    }
    v
}

fn cgroup_of(pid: i32) -> Option<String> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    s.lines().find_map(|l| l.strip_prefix("0::")).map(str::to_string)
}

/// Moves `pid` into a new systemd user scope `unit` with the limits set.
/// Returns its cgroup directory, or None when that failed and `strict` is off.
pub(crate) fn enter_scope(pid: i32, unit: &str, l: &Limits, strict: bool) -> Result<Option<PathBuf>> {
    let fail = |msg: String| {
        if strict { Err(Error::Unsupported(format!("{msg} (turn strict mode off to run without limits)"))) } else { Ok(None) }
    };
    let mut props: Vec<String> = Vec::new();
    let mut count = 0;
    let mut prop = |p: &[&str]| {
        props.extend(p.iter().map(|s| s.to_string()));
        count += 1;
    };
    let pid_s = pid.to_string();
    prop(&["PIDs", "au", "1", &pid_s]);
    prop(&["Description", "s", "vssb sandbox"]);
    prop(&["CollectMode", "s", "inactive-or-failed"]);
    if let Some(m) = l.memory {
        prop(&["MemoryMax", "t", &m.to_string()]);
        prop(&["MemorySwapMax", "t", "0"]);
    }
    if let Some(c) = l.cpus {
        let usec = ((c * 1e6).round() as u64).max(10_000);
        prop(&["CPUQuotaPerSecUSec", "t", &usec.to_string()]);
    }
    if let Some(p) = l.pids {
        prop(&["TasksMax", "t", &p.to_string()]);
    }
    let out = Command::new("busctl")
        .args(["--user", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager"])
        .args(["StartTransientUnit", "ssa(sv)a(sa(sv))", unit, "fail", &count.to_string()])
        .args(&props)
        .arg("0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output();
    match out {
        Err(e) => return fail(format!("running busctl to create a systemd user scope: {e}")),
        Ok(o) if !o.status.success() => {
            return fail(format!("creating systemd user scope {unit}: {}", String::from_utf8_lossy(&o.stderr).trim()));
        }
        Ok(_) => {}
    }
    // The job runs asynchronously: wait until the process is in the scope.
    let deadline = Instant::now() + Duration::from_secs(5);
    let suffix = format!("/{unit}");
    let rel = loop {
        if let Some(cg) = cgroup_of(pid)
            && cg.ends_with(&suffix)
        {
            break cg;
        }
        if Instant::now() > deadline {
            return fail(format!("timed out waiting for systemd to move the sandbox into {unit}"));
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    let dir = Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
    let m = missing(&dir, l);
    if !m.is_empty() && strict {
        return Err(Error::Unsupported(format!("cgroup limits not in effect ({}) in {}", m.join(", "), dir.display())));
    }
    Ok(Some(dir))
}
