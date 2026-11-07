//! `vssr check`: what the running kernel and session support, then the
//! resolved plan for the given policy and options.

use crate::policy::Plan;
use anyhow::Result;
use vssb::seccomp::Filter;

pub fn run(plan: impl FnOnce() -> Result<Plan>) -> Result<i32> {
    let mut ok = true;
    let mut line = |good: bool, name: &str, detail: String| {
        ok &= good;
        println!("{} {name:<16} {detail}", if good { " ok " } else { "FAIL" });
    };

    let s = vssb::probe();
    line(true, "kernel", s.kernel.clone());
    line(s.user_namespaces, "user namespaces", "unprivileged user, mount, PID and network namespaces".into());

    let abi = s.landlock_abi;
    let detail = match abi {
        0 => "not available (enable the landlock LSM, or run with strict = false)".to_string(),
        1..=3 => format!("ABI {abi}: filesystem rules only; no TCP port rules or scoping"),
        4..=5 => format!("ABI {abi}: filesystem and TCP port rules; no signal/socket scoping"),
        _ => format!("ABI {abi}: filesystem, TCP ports, signal and abstract-socket scoping"),
    };
    line(abi > 0, "landlock", detail);

    let f = Filter::build(&[], &[])?;
    line(s.seccomp, "seccomp", format!("{} syscalls denied by default, {} BPF instructions", f.denied().len(), f.len()));

    let detail = if s.systemd_user {
        "busctl and the systemd user manager are available"
    } else {
        "no systemd user manager reachable with busctl: memory/cpu/pids limits unavailable"
    };
    // Limits are optional, so this never fails the check by itself.
    println!("{} {:<16} {detail}", if s.systemd_user { " ok " } else { " -- " }, "resource limits");

    println!();
    match plan() {
        Ok(p) => print!("{}", p.describe()),
        Err(e) => {
            println!("policy: {e:#}");
            ok = false;
        }
    }
    Ok(if ok { 0 } else { 1 })
}
