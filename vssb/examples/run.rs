//! A tiny front-end, to try vssb by hand:
//!
//!   cargo run --example run -- [--ro PATH] [--rw PATH] [--tmpfs PATH] [--deny PATH]
//!       [--host-net] [--memory BYTES] [--pids N] [--cwd DIR] [--tty] -- COMMAND [ARGS...]
//!
//! The system view is on, the current directory is writable and the
//! working directory, and PATH, TERM, LANG and HOME are passed through.

use std::path::PathBuf;
use vssb::{Command, Limits, Mount, Net, Sandbox};

fn main() {
    let mut args = std::env::args().skip(1);
    let mut sb = Sandbox::new();
    sb.system(true);
    let cwd = std::env::current_dir().and_then(std::fs::canonicalize).expect("current directory");
    let mut inside_cwd = cwd.clone();
    let mut limits = Limits::default();
    let mut tty = false;
    sb.mount(Mount::rw(&cwd));
    let path = |a: Option<String>| PathBuf::from(a.expect("missing argument"));
    let mut argv = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--ro" => {
                sb.mount(Mount::ro(path(args.next())));
            }
            "--rw" => {
                sb.mount(Mount::rw(path(args.next())));
            }
            "--tmpfs" => {
                sb.mount(Mount::tmpfs(path(args.next())));
            }
            "--deny" => {
                sb.mount(Mount::deny(path(args.next())));
            }
            "--host-net" => {
                sb.net(Net::Host);
            }
            "--memory" => limits.memory = args.next().and_then(|s| s.parse().ok()),
            "--pids" => limits.pids = args.next().and_then(|s| s.parse().ok()),
            "--cwd" => inside_cwd = path(args.next()),
            "--tty" => tty = true,
            "--" => {
                argv.extend(args.by_ref());
                break;
            }
            _ => {
                argv.push(a);
                argv.extend(args.by_ref());
                break;
            }
        }
    }
    if argv.is_empty() {
        eprintln!("usage: run [OPTIONS] -- COMMAND [ARGS...]");
        std::process::exit(2);
    }
    sb.limits(limits);
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]).cwd(&inside_cwd).keep_session(tty);
    for k in ["PATH", "TERM", "LANG", "HOME"] {
        if let Some(v) = std::env::var_os(k) {
            cmd.env(k, v);
        }
    }
    let code = match sb.spawn(cmd) {
        Ok(mut child) => match child.wait() {
            Ok(s) => s.shell_code(),
            Err(e) => {
                eprintln!("run: wait: {e}");
                125
            }
        },
        Err(e) => {
            eprintln!("run: {e}");
            e.shell_code()
        }
    };
    std::process::exit(code);
}
