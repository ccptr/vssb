//! vssr: a Linux sandbox for running agents unattended, with fine-grained
//! filesystem, network, syscall and resource permissions. Needs no root.
//! The sandbox itself (namespaces, Landlock, seccomp, cgroup scope) is
//! vssb's; vssr adds policy files, detection, the proxy's rules, signal
//! forwarding, the timeout and the audit log.

mod audit;
mod check;
mod detect;
mod policy;
mod util;

use anyhow::{Context, Result, bail};
use audit::Audit;
use clap::{Args, Parser, Subcommand, ValueEnum};
use policy::{FsKind, FsOverrides, NetMode, Plan, Policy};
use serde_json::json;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use vssb::proxy::{self, Event};
use vssb::{Enforcement, Via};

/// vssr's own failure to set up the sandbox (as vssb reports it too).
const EXIT_SETUP: i32 = 125;
const EXIT_TIMEOUT: i32 = 124;

/// Signals vssr passes on to the sandboxed program.
const FORWARDED: [libc::c_int; 6] = [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT, libc::SIGUSR1, libc::SIGUSR2];
/// `ssi_code` of a signal sent by the kernel (the terminal's, for SIGINT
/// and SIGQUIT), not by another process.
const SI_KERNEL: i32 = 0x80;

#[derive(Parser)]
#[command(name = "vssr", version, about = "Run commands in a Linux sandbox with fine-grained permissions")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a command in the sandbox: vssr run [OPTIONS] -- COMMAND [ARGS...]
    Run(RunArgs),
    /// Report what this kernel supports and show the resolved policy
    Check(RunArgs),
    /// Print the built-in default policy (a starting point for your own)
    Policy,
}

#[derive(Clone, Copy, ValueEnum)]
enum ProjectArg {
    Off,
    Ro,
    Rw,
}

#[derive(Clone, Copy, ValueEnum)]
enum NetArg {
    None,
    Proxy,
    Host,
}

#[derive(Args)]
struct RunArgs {
    /// Policy file (TOML). Without one, the built-in default policy is used.
    #[arg(short, long)]
    policy: Option<PathBuf>,
    /// Expose a path read-only (SRC or SRC:DEST; prefix '?' if it may be missing)
    #[arg(long, value_name = "PATH")]
    ro: Vec<String>,
    /// Expose a path read-write
    #[arg(long, value_name = "PATH")]
    rw: Vec<String>,
    /// Mount an empty tmpfs
    #[arg(long, value_name = "PATH")]
    tmpfs: Vec<String>,
    /// Hide a path that would otherwise be visible
    #[arg(long, value_name = "PATH")]
    deny: Vec<String>,
    /// Network mode
    #[arg(long, value_enum)]
    net: Option<NetArg>,
    /// Allow a host through the proxy (HOST, HOST:PORT, *.DOMAIN); implies --net proxy
    #[arg(long, value_name = "HOST")]
    allow: Vec<String>,
    /// Wall-clock limit, e.g. 30m or 2h
    #[arg(long)]
    timeout: Option<String>,
    /// Memory limit, e.g. 4G (needs a cgroup: a systemd user scope)
    #[arg(long)]
    memory: Option<String>,
    /// CPU limit in cores, e.g. 2 or 0.5 (without a cgroup: pinning to that many CPUs)
    #[arg(long)]
    cpus: Option<f64>,
    /// Maximum number of processes and threads
    #[arg(long)]
    pids: Option<u64>,
    /// Pass an environment variable (NAME) or set one (NAME=VALUE)
    #[arg(short, long, value_name = "NAME[=VALUE]")]
    env: Vec<String>,
    /// Working directory inside the sandbox
    #[arg(long)]
    cwd: Option<String>,
    /// Append JSON-lines audit events to this file
    #[arg(long, value_name = "FILE")]
    audit_log: Option<String>,
    /// Write the audit events to this inherited descriptor (a pipe, socket
    /// or file) instead of a log file
    #[arg(long, value_name = "N", conflicts_with = "audit_log")]
    audit_fd: Option<i32>,
    /// Send vssr's own messages only to the audit log, not to stderr
    #[arg(short, long)]
    quiet: bool,
    /// Hand inherited descriptor N to the program as descriptor M (3 or
    /// above; default N), e.g. a pre-connected socket
    #[arg(long, value_name = "N[:M]")]
    pass_fd: Vec<String>,
    /// Start in this existing cgroup v2 directory (e.g. in a delegated
    /// subtree) instead of a systemd user scope; limits are written to it
    #[arg(long, value_name = "DIR")]
    cgroup: Option<PathBuf>,
    /// With --dry-run or check: print JSON for programs
    #[arg(long)]
    json: bool,
    /// Keep the controlling terminal (for interactive use)
    #[arg(long)]
    tty: bool,
    /// Run even if Landlock or resource limits can't be enforced
    #[arg(long)]
    no_strict: bool,
    /// Expose directories the project's build files need (detected at start)
    /// read-only when they are under DIR
    #[arg(long, value_name = "DIR")]
    detect_within: Vec<String>,
    /// The same, read-write
    #[arg(long, value_name = "DIR")]
    detect_within_rw: Vec<String>,
    /// How to expose detected directories elsewhere in the same git repository
    #[arg(long, value_enum, value_name = "MODE")]
    detect_project: Option<ProjectArg>,
    /// Don't read the project's build files for extra rules
    #[arg(long)]
    no_detect: bool,
    /// Print the resolved plan and exit
    #[arg(long)]
    dry_run: bool,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_name = "COMMAND")]
    command: Vec<String>,
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.cmd {
        Cmd::Policy => {
            print!("{}", policy::DEFAULT_POLICY);
            0
        }
        Cmd::Check(args) => match check::run(args.json, || resolve(&args)) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("vssr: {e:#}");
                EXIT_SETUP
            }
        },
        Cmd::Run(args) => match run(args) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("vssr: {e:#}");
                EXIT_SETUP
            }
        },
    };
    std::process::exit(code);
}

/// Loads the policy, applies command-line overrides and resolves the plan.
fn resolve(args: &RunArgs) -> Result<Plan> {
    let cwd = std::env::current_dir().context("current directory")?;
    let cwd = std::fs::canonicalize(&cwd).unwrap_or(cwd);
    let mut p = match &args.policy {
        Some(path) => Policy::load(path)?,
        None => {
            let home = std::env::var("HOME").unwrap_or_default();
            if cwd == Path::new("/") || Path::new(&home).starts_with(&cwd) {
                bail!(
                    "the default policy makes the current directory writable, and {} contains your home directory; \
                     run from a project directory or pass --policy",
                    cwd.display()
                );
            }
            Policy::default_policy()
        }
    };

    let mut fs = FsOverrides::default();
    for (kind, list) in [(FsKind::Tmpfs, &args.tmpfs), (FsKind::Ro, &args.ro), (FsKind::Rw, &args.rw), (FsKind::Deny, &args.deny)] {
        fs.entries.extend(list.iter().map(|s| (kind, s.clone())));
    }
    if let Some(n) = args.net {
        p.net.mode = match n {
            NetArg::None => NetMode::None,
            NetArg::Proxy => NetMode::Proxy,
            NetArg::Host => NetMode::Host,
        };
    }
    if !args.allow.is_empty() {
        if args.net.is_none() && p.net.mode == NetMode::None {
            p.net.mode = NetMode::Proxy;
        }
        p.net.allow.extend(args.allow.iter().cloned());
    }
    if args.timeout.is_some() {
        p.sandbox.timeout = args.timeout.clone();
    }
    if args.memory.is_some() {
        p.limits.memory = args.memory.clone();
    }
    if args.cpus.is_some() {
        p.limits.cpus = args.cpus;
    }
    if args.pids.is_some() {
        p.limits.pids = args.pids;
    }
    for e in &args.env {
        match e.split_once('=') {
            Some((k, v)) => {
                p.env.set.insert(k.to_string(), v.to_string());
            }
            None => p.env.pass.push(e.clone()),
        }
    }
    if args.cwd.is_some() {
        p.sandbox.cwd = args.cwd.clone();
    }
    if args.audit_log.is_some() {
        p.audit.log = args.audit_log.clone();
    }
    if args.audit_fd.is_some() {
        p.audit.log = None;
    }
    if args.quiet {
        p.audit.quiet = true;
    }
    if args.tty {
        p.sandbox.tty = true;
    }
    if args.no_strict {
        p.sandbox.strict = false;
    }
    if args.no_detect {
        p.detect.enable.clear();
    }
    p.detect.within.extend(args.detect_within.iter().cloned());
    p.detect.within_rw.extend(args.detect_within_rw.iter().cloned());
    if let Some(m) = args.detect_project {
        p.detect.project = match m {
            ProjectArg::Off => policy::ProjectMode::Off,
            ProjectArg::Ro => policy::ProjectMode::Ro,
            ProjectArg::Rw => policy::ProjectMode::Rw,
        };
    }
    if !args.command.is_empty() {
        p.command = args.command.clone();
    }
    let mut plan = Plan::build(&p, &fs, &cwd)?;
    plan.cgroup = args.cgroup.as_ref().map(|c| cwd.join(c));
    Ok(plan)
}

/// `--pass-fd N[:M]`: copies of the caller's descriptors, by target.
fn passed_fds(specs: &[String], audit_fd: Option<i32>) -> Result<Vec<(i32, OwnedFd)>> {
    let mut out: Vec<(i32, OwnedFd)> = vec![];
    for spec in specs {
        let parse = |s: &str| s.parse::<i32>().ok().filter(|&n| n >= 0);
        let (n, m) = match spec.split_once(':') {
            Some((n, m)) => (parse(n), parse(m)),
            None => (parse(spec), parse(spec)),
        };
        let (Some(n), Some(m)) = (n, m) else { bail!("--pass-fd {spec}: expected N or N:M (descriptor numbers)") };
        if m < 3 {
            bail!("--pass-fd {spec}: the program's descriptor must be 3 or above (0-2 are its stdio)");
        }
        if out.iter().any(|(t, _)| *t == m) {
            bail!("--pass-fd {spec}: descriptor {m} is already passed");
        }
        if audit_fd == Some(n) {
            bail!("--pass-fd {spec}: {n} is the audit descriptor; the program could write events to it");
        }
        let copy = unsafe { libc::fcntl(n, libc::F_DUPFD_CLOEXEC, 3) };
        if copy < 0 {
            bail!("--pass-fd {spec}: descriptor {n}: {}", std::io::Error::last_os_error());
        }
        // The program gets the copy; keep the original out of helpers vssr runs.
        if n > 2 {
            let fl = unsafe { libc::fcntl(n, libc::F_GETFD) };
            unsafe { libc::fcntl(n, libc::F_SETFD, fl | libc::FD_CLOEXEC) };
        }
        out.push((m, unsafe { OwnedFd::from_raw_fd(copy) }));
    }
    Ok(out)
}

fn run(args: RunArgs) -> Result<i32> {
    let plan = resolve(&args)?;
    if plan.quiet && plan.audit_log.is_none() && args.audit_fd.is_none() {
        bail!("quiet (--quiet, audit.quiet) sends vssr's messages to the audit log, and there is none (--audit-log, --audit-fd)");
    }
    if args.json && !args.dry_run {
        bail!("--json goes with --dry-run (or `vssr check`)");
    }
    if args.dry_run {
        if args.json {
            println!("{}", serde_json::to_string_pretty(&plan.to_json())?);
        } else {
            print!("{}", plan.describe());
        }
        return Ok(0);
    }
    if plan.argv.is_empty() {
        bail!("no command given (vssr run [OPTIONS] -- COMMAND, or `command` in the policy)");
    }
    let fds = passed_fds(&args.pass_fd, args.audit_fd)?;
    let id = std::env::var("VSSR_ID").unwrap_or_else(|_| util::random_id());
    let audit = Arc::new(match args.audit_fd {
        Some(fd) => Audit::from_fd(fd, id.clone(), plan.quiet).context("--audit-fd")?,
        None => Audit::open(plan.audit_log.as_deref(), &plan.writable, id.clone(), plan.quiet)?,
    });
    for n in &plan.notes {
        audit.say("note", json!({"text": n}), n);
    }
    // From here on, failures are events too (and stay off stderr if quiet).
    supervise(&plan, &id, &audit, fds).or_else(|e| {
        let msg = format!("{e:#}");
        audit.say("error", json!({"error": msg, "code": EXIT_SETUP}), &msg);
        Ok(EXIT_SETUP)
    })
}

fn sigset(sigs: &[libc::c_int]) -> libc::sigset_t {
    unsafe {
        let mut s: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut s);
        for &sig in sigs {
            libc::sigaddset(&mut s, sig);
        }
        s
    }
}

/// Starts the sandbox and stays with it until it exits: serves the proxy,
/// forwards signals, enforces the timeout and writes the audit log.
fn supervise(plan: &Plan, id: &str, audit: &Arc<Audit>, fds: Vec<(i32, OwnedFd)>) -> Result<i32> {

    // Forwarded signals arrive on a signalfd. Block them before any thread
    // starts, so the proxy's threads inherit the mask and never take one.
    let fwd = sigset(&FORWARDED);
    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &fwd, std::ptr::null_mut()) };
    let sfd = unsafe { libc::signalfd(-1, &fwd, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
    if sfd < 0 {
        bail!("signalfd: {}", std::io::Error::last_os_error());
    }
    let sfd = unsafe { OwnedFd::from_raw_fd(sfd) };

    let started = Instant::now();
    let mut cmd = plan.command(id);
    for (target, fd) in fds {
        cmd.pass_fd(target, fd);
    }
    let mut child = match plan.sandbox().spawn(cmd) {
        Ok(c) => c,
        Err(e) => {
            let code = e.shell_code();
            audit.say("setup_failed", json!({"command": plan.argv, "code": code, "error": e.to_string()}), &e.to_string());
            if matches!(e, vssb::Error::Unsupported(_)) && !audit.quiet {
                eprintln!("vssr: `vssr check` shows what this system supports; --no-strict runs with what is available");
            }
            return Ok(code);
        }
    };
    let enforced = child.enforcement().clone();
    for (name, via) in [("memory", &enforced.memory), ("cpus", &enforced.cpus), ("pids", &enforced.pids)] {
        if *via == Some(Via::NotEnforced) {
            let text = format!("the {name} limit is not in effect (no cgroup, and no fallback took)");
            audit.say("warning", json!({"limit": name, "text": text}), &format!("warning: {text}"));
        }
    }

    // Stopped (listener and every connection closed) when it goes out of scope.
    let _proxy = match child.take_listeners().pop() {
        Some(l) => {
            let a = audit.clone();
            Some(proxy::serve(l, plan.net.clone(), move |e| net_event(&a, e)).context("starting the proxy")?)
        }
        None if plan.net_mode == NetMode::Proxy => bail!("the sandbox did not hand over the proxy socket"),
        None => None,
    };
    audit.event(
        "start",
        json!({
            "command": plan.argv,
            "cwd": plan.cwd,
            "net": format!("{:?}", plan.net_mode).to_lowercase(),
            "host_pid": child.id(),
            "timeout_s": plan.timeout.map(|t| t.as_secs()),
            "detected": plan.detected,
            "limits": limits_json(&enforced),
            "user": std::env::var("USER").ok(),
        }),
    );

    // Too far off to represent: no deadline.
    let deadline = plan.timeout.and_then(|t| started.checked_add(t));
    let mut timed_out = false;
    let mut kill_at: Option<Instant> = None;
    let status = loop {
        if let Some(s) = child.try_wait().context("waiting for the sandbox")? {
            break s;
        }
        let now = Instant::now();
        if kill_at.is_some_and(|k| now >= k) {
            // Killing PID 1 takes down the whole PID namespace.
            child.kill().context("killing the sandbox")?;
            kill_at = None;
            continue;
        }
        if !timed_out && let Some(d) = deadline && now >= d {
            timed_out = true;
            let t = plan.timeout.unwrap_or_default();
            audit.say("timeout", json!({"after_s": t.as_secs()}), &format!("timeout after {}s, stopping the sandbox", t.as_secs()));
            let _ = child.signal(libc::SIGTERM);
            kill_at = now.checked_add(plan.kill_grace);
            continue;
        }
        let next = if timed_out { kill_at } else { deadline };
        let ms = next.map_or(-1, |n| n.saturating_duration_since(now).as_millis().clamp(1, i32::MAX as u128) as i32);
        let mut pfd = [
            libc::pollfd { fd: child.pidfd().as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: sfd.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        ];
        unsafe { libc::poll(pfd.as_mut_ptr(), 2, ms) };
        if pfd[1].revents & libc::POLLIN != 0 {
            forward_signals(plan, &sfd, &child, audit);
        }
    };

    let code = if timed_out { EXIT_TIMEOUT } else { status.shell_code() };
    audit.event("exit", json!({"code": code, "timed_out": timed_out, "duration_ms": started.elapsed().as_millis() as u64}));
    Ok(code)
}

/// Passes pending signals on to the program (through the sandbox's PID 1).
fn forward_signals(plan: &Plan, sfd: &OwnedFd, child: &vssb::Child, audit: &Audit) {
    loop {
        let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::signalfd_siginfo>();
        let n = unsafe { libc::read(sfd.as_raw_fd(), (&mut info as *mut libc::signalfd_siginfo).cast(), size) };
        if n != size as isize {
            return;
        }
        let sig = info.ssi_signo as i32;
        if !should_forward(plan.tty, sig, info.ssi_code) {
            continue;
        }
        audit.event("signal", json!({"signal": sig}));
        let _ = child.signal(sig);
    }
}

/// With the terminal kept, the program gets the terminal's SIGINT and
/// SIGQUIT itself; don't double those. Ones another process sent go on.
fn should_forward(tty: bool, sig: i32, code: i32) -> bool {
    !(tty && code == SI_KERNEL && matches!(sig, libc::SIGINT | libc::SIGQUIT))
}

/// How each limit that was set is enforced, for the start event.
fn limits_json(e: &Enforcement) -> serde_json::Value {
    let via = |v: &Via| match v {
        Via::Cgroup => json!("cgroup"),
        Via::Pinned { cpus, forced } => json!({"pinned": cpus, "forced": forced}),
        Via::PidNamespace => json!("pid-namespace"),
        Via::NotEnforced => json!("none"),
    };
    let mut m = serde_json::Map::new();
    for (name, v) in [("memory", &e.memory), ("cpus", &e.cpus), ("pids", &e.pids)] {
        if let Some(v) = v {
            m.insert(name.into(), via(v));
        }
    }
    serde_json::Value::Object(m)
}

fn net_event(audit: &Audit, e: &Event) {
    match e {
        Event::Allow { method, host, port, addr } => {
            audit.event("net", json!({"action": "allow", "method": method, "host": host, "port": port, "addr": addr.to_string()}));
        }
        Event::Deny { method, host, port, reason } => {
            audit.say(
                "net",
                json!({"action": "deny", "method": method, "host": host, "port": port, "reason": reason}),
                &format!("blocked {method} {host}:{port} ({reason})"),
            );
        }
        Event::Error { method, host, port, reason } => {
            audit.event("net", json!({"action": "error", "method": method, "host": host, "port": port, "reason": reason}));
        }
        Event::Close { host, port, bytes_up, bytes_down, duration } => {
            let ms = duration.as_millis() as u64;
            audit.event("net_close", json!({"host": host, "port": port, "bytes_up": bytes_up, "bytes_down": bytes_down, "ms": ms}));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_signals_are_not_doubled() {
        const SI_USER: i32 = 0;
        assert!(!should_forward(true, libc::SIGINT, SI_KERNEL));
        assert!(!should_forward(true, libc::SIGQUIT, SI_KERNEL));
        // Sent by another process (kill), or without the terminal: forwarded.
        assert!(should_forward(true, libc::SIGINT, SI_USER));
        assert!(should_forward(true, libc::SIGQUIT, libc::SI_QUEUE));
        assert!(should_forward(true, libc::SIGTERM, SI_KERNEL));
        assert!(should_forward(false, libc::SIGINT, SI_KERNEL));
    }
}
