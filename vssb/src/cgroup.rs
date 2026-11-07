//! cgroup placement. An unprivileged process can't move another process
//! into a cgroup it may configure, but the systemd user manager can: after
//! clone, while the child waits, vssb asks it over D-Bus (with `busctl`)
//! for a transient scope holding the child, with the limits as properties.
//! The child then makes that scope the root of its cgroup namespace.

use crate::config::Limits;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// cpu.max for `cpus` CPUs: (quota, period) in microseconds.
fn cpu_quota(cpus: f64) -> (u64, u64) {
    let period = 100_000u64;
    (((cpus * period as f64).round() as u64).max(1000), period)
}

/// Writes limits into a cgroup directory the caller prepared. Whether
/// they took is checked afterwards with [`in_effect`].
pub(crate) fn write_limits(dir: &Path, l: &Limits) {
    if let Some(m) = l.memory {
        let _ = std::fs::write(dir.join("memory.max"), m.to_string());
        // Missing when swap accounting is off; nothing to limit then.
        let _ = std::fs::write(dir.join("memory.swap.max"), "0");
    }
    if let Some(c) = l.cpus {
        let (quota, period) = cpu_quota(c);
        let _ = std::fs::write(dir.join("cpu.max"), format!("{quota} {period}"));
    }
    if let Some(p) = l.pids {
        let _ = std::fs::write(dir.join("pids.max"), p.to_string());
    }
}

/// Which of the limits set in `l` are in effect in a cgroup.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct InEffect {
    pub memory: bool,
    pub cpus: bool,
    pub pids: bool,
}

/// A limit counts as in effect when the cgroup's value is at most the
/// requested one (a write that failed may have left a larger one).
pub(crate) fn in_effect(dir: &Path, l: &Limits) -> InEffect {
    let read = |f: &str| std::fs::read_to_string(dir.join(f)).map(|s| s.trim().to_string());
    let num = |f: &str| read(f).ok().and_then(|s| s.parse::<u64>().ok());
    // Without swap accounting there is no memory.swap.max, and no swap to limit.
    let no_swap = || match read("memory.swap.max") {
        Ok(s) => s == "0",
        Err(e) => e.kind() == io::ErrorKind::NotFound,
    };
    let cpus = |c: f64| {
        let (quota, period) = cpu_quota(c);
        let s = read("cpu.max").unwrap_or_default();
        let mut it = s.split_whitespace().map(|v| v.parse::<u64>().ok());
        match (it.next().flatten(), it.next().flatten()) {
            // quota'/period' <= quota/period
            (Some(q), Some(p)) if p > 0 => q as u128 * period as u128 <= quota as u128 * p as u128,
            _ => false,
        }
    };
    InEffect {
        memory: l.memory.is_some_and(|m| num("memory.max").is_some_and(|v| v <= m) && no_swap()),
        cpus: l.cpus.is_some_and(cpus),
        pids: l.pids.is_some_and(|n| num("pids.max").is_some_and(|v| v <= n)),
    }
}

fn cgroup_of(pid: i32) -> Option<String> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    s.lines().find_map(|l| l.strip_prefix("0::")).map(str::to_string)
}

/// Moves `pid` into a new systemd user scope `unit` with the limits set.
/// Returns its cgroup directory, or why that failed. Which limits took
/// is checked afterwards with [`in_effect`].
pub(crate) fn enter_scope(pid: i32, unit: &str, l: &Limits) -> Result<PathBuf, String> {
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
        Err(e) => return Err(format!("running busctl to create a systemd user scope: {e}")),
        Ok(o) if !o.status.success() => {
            return Err(format!("creating systemd user scope {unit}: {}", String::from_utf8_lossy(&o.stderr).trim()));
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
            return Err(format!("timed out waiting for systemd to move the sandbox into {unit}"));
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    Ok(Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Controller files in a temporary directory.
    fn check(files: &[(&str, &str)], l: &Limits) -> InEffect {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!("vssb-cgroup-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).unwrap();
        for (f, v) in files {
            std::fs::write(dir.join(f), format!("{v}\n")).unwrap();
        }
        let r = in_effect(&dir, l);
        std::fs::remove_dir_all(&dir).unwrap();
        r
    }

    fn all() -> Limits {
        Limits { memory: Some(64 << 20), cpus: Some(1.0), pids: Some(4), ..Default::default() }
    }

    #[test]
    fn values_at_most_the_request_are_in_effect() {
        let r = check(&[("memory.max", "67108864"), ("memory.swap.max", "0"), ("cpu.max", "100000 100000"), ("pids.max", "4")], &all());
        assert!(r.memory && r.cpus && r.pids, "{r:?}");
        // Smaller ones too (a tighter limit someone else set); same ratio, other period.
        let r = check(&[("memory.max", "4096"), ("cpu.max", "25000 50000"), ("pids.max", "2")], &all());
        assert!(r.memory && r.cpus && r.pids, "no memory.swap.max: no swap accounting; {r:?}");
        let r = check(&[("cpu.max", "50000 50000")], &Limits { cpus: Some(1.0), ..Default::default() });
        assert!(r.cpus);
    }

    #[test]
    fn larger_or_missing_values_are_not() {
        // What a failed write leaves behind.
        let r = check(&[("memory.max", "1073741824"), ("memory.swap.max", "0"), ("cpu.max", "800000 100000"), ("pids.max", "4096")], &all());
        assert!(!r.memory && !r.cpus && !r.pids, "{r:?}");
        let r = check(&[("memory.max", "max"), ("cpu.max", "max 100000"), ("pids.max", "max")], &all());
        assert!(!r.memory && !r.cpus && !r.pids, "{r:?}");
        let r = check(&[], &all());
        assert!(!r.memory && !r.cpus && !r.pids, "{r:?}");
        // Just above the quota.
        let r = check(&[("cpu.max", "100001 100000")], &all());
        assert!(!r.cpus);
        // Swap left on.
        let r = check(&[("memory.max", "67108864"), ("memory.swap.max", "max")], &all());
        assert!(!r.memory);
        let r = check(&[("memory.max", "67108864"), ("memory.swap.max", "1048576")], &all());
        assert!(!r.memory);
    }

    #[test]
    fn unrequested_limits_are_not_in_effect() {
        let r = check(&[("memory.max", "1"), ("cpu.max", "1000 100000"), ("pids.max", "1")], &Limits::default());
        assert!(!r.memory && !r.cpus && !r.pids, "{r:?}");
    }

    #[test]
    fn written_limits_and_systemds_are_in_effect() {
        for c in [0.001, 0.3, 1.0, 1.2345549, 7.5] {
            let (q, p) = cpu_quota(c);
            let l = Limits { cpus: Some(c), ..Default::default() };
            assert!(check(&[("cpu.max", &format!("{q} {p}"))], &l).cpus, "{c}");
            // What systemd writes for enter_scope's CPUQuotaPerSecUSec.
            let usec = ((c * 1e6).round() as u64).max(10_000);
            assert!(check(&[("cpu.max", &format!("{} 100000", (usec * 100_000 / 1_000_000).max(1000)))], &l).cpus, "{c}");
        }
    }
}
