//! `vssr check`: what the running kernel and session support, then the
//! resolved plan for the given policy and options.

use crate::policy::Plan;
use anyhow::Result;
use vssb::seccomp::Filter;

pub fn run(json: bool, plan: impl FnOnce() -> Result<Plan>) -> Result<i32> {
    if json {
        return run_json(plan);
    }
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
        "the systemd user manager answers on the user bus"
    } else {
        "no systemd user manager on the user bus: no memory limit (unless --cgroup); cpus pin, pids size the PID namespace"
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

/// `vssr check --json`: the same facts for programs. `ok` is false when the
/// default (strict) settings can't start or the policy doesn't resolve.
fn run_json(plan: impl FnOnce() -> Result<Plan>) -> Result<i32> {
    let s = vssb::probe();
    let f = Filter::build(&[], &[])?;
    let mut ok = s.user_namespaces && s.landlock_abi > 0 && s.seccomp;
    let mut out = serde_json::json!({
        "kernel": s.kernel,
        "user_namespaces": s.user_namespaces,
        "landlock_abi": s.landlock_abi,
        "seccomp": s.seccomp,
        "seccomp_denied": f.denied().len(),
        "systemd_user": s.systemd_user,
    });
    match plan() {
        Ok(p) => out["plan"] = p.to_json(),
        Err(e) => {
            out["policy_error"] = format!("{e:#}").into();
            ok = false;
        }
    }
    out["ok"] = ok.into();
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(if ok { 0 } else { 1 })
}
