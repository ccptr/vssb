//! Policy files (TOML) and their resolution into a concrete [`Plan`],
//! which maps onto a vssl [`Sandbox`] and [`Command`].

use crate::util::{expand, expand_path, parse_duration, parse_size, resolve_guarded};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use vssl::proxy::NetPolicy;
use vssl::{Command, Limits, Mount, MountKind, Net, Resource, Sandbox};

/// The policy used when none is given. `vssr policy` prints it.
pub const DEFAULT_POLICY: &str = r#"# vssr default policy: the current directory is writable, the home
# directory is an empty tmpfs, and there is no network.

[sandbox]
hostname = "vssr"
strict = true          # refuse to run if Landlock or seccomp can't be enforced
# timeout = "2h"       # wall-clock limit; the sandbox is killed after it
# kill_grace = "10s"   # time between SIGTERM and SIGKILL on timeout
# tty = false          # keep the controlling terminal (interactive use)
# cwd = "$PWD"

[fs]
system = true          # read-only /usr, /etc, /opt, /bin…; fresh /proc, /dev, /tmp
rw = ["$PWD"]
tmpfs = ["~"]
ro = []
deny = []
noexec = []
sockets = []           # host unix sockets the program may connect to, e.g. ["$SSH_AUTH_SOCK"];
                       # each one is a capability: whatever the service behind it allows
# tmpfs_size = "2G"

[net]
mode = "none"          # none | proxy | host
# allow = ["api.anthropic.com", "*.github.com"]   # proxy mode only

[env]
pass = ["PATH", "TERM", "COLORTERM", "LANG", "LANGUAGE", "LC_*", "TZ", "USER", "LOGNAME", "HOME", "SHELL"]

[limits]
# memory = "8G"
# cpus = 4
# pids = 4096
# Without a cgroup (no systemd user manager), cpus and pids have fallbacks:
# cpu_method = "auto"    # auto (cgroup quota, else pinning), cgroup, pin, pin-forced
# cpu_choice = "spread"  # CPUs to pin to: spread, pack, or a list such as [0, 2]
# pids_method = "auto"   # auto (cgroup, else the PID namespace), cgroup, pid-namespace
# nofile = 8192
# fsize = "20G"

[detect]
enable = ["cargo"]     # read the project's build files at start (cargo: path dependencies, workspaces)
within = []            # expose detected directories outside the project, read-only, only under these
                       # e.g. ["~/p"]; anything below them can be named by a build file in the project
within_rw = []         # the same, read-write; whatever is written there can run later on the host
                       # (the deepest matching directory of the two lists decides)
project = "ro"         # detected directories elsewhere in the same git repository: off | ro | rw
                       # (never the repository root or its .git; only widens what within* grant)

[seccomp]
allow = []             # remove syscalls from the default deny list, e.g. ["ptrace"]
deny = []              # extra syscalls to deny

[gui]
wayland = false        # a Wayland socket through a security context, which the compositor restricts
# app_id = "org.example.App"   # reported to the compositor
# insecure_wayland = false     # run even if capture, clipboard or input protocols stay visible

[dbus]
session = false        # the session bus, only through vssr's filter (the lists below)
talk = []              # names the program may call, e.g. ["org.freedesktop.Notifications"]; "org.example.*" for a prefix
own = []               # names it may own, e.g. ["org.example.App"]
# see = []             # names it may only see
# call = []            # "NAME=RULE": calls allowed on NAME alone, RULE being [METHOD][@PATH] (as in xdg-dbus-proxy(1))
# broadcast = []       # "NAME=RULE": signals from NAME the program receives

[audit]
# log = "~/.local/state/vssr/audit.jsonl"
quiet = false          # true: vssr's messages go only to the log, not to stderr
"#;

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Policy {
    pub command: Vec<String>,
    pub sandbox: SandboxCfg,
    pub fs: FsCfg,
    pub net: NetCfg,
    pub env: EnvCfg,
    pub limits: LimitsCfg,
    pub detect: DetectCfg,
    pub seccomp: SeccompCfg,
    pub gui: GuiCfg,
    pub dbus: DbusCfg,
    pub audit: AuditCfg,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct SandboxCfg {
    pub hostname: String,
    pub cwd: Option<String>,
    pub strict: bool,
    pub tty: bool,
    pub timeout: Option<String>,
    pub kill_grace: String,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

impl Default for SandboxCfg {
    fn default() -> Self {
        SandboxCfg {
            hostname: "vssr".into(),
            cwd: None,
            strict: true,
            tty: false,
            timeout: None,
            kill_grace: "10s".into(),
            uid: None,
            gid: None,
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct FsCfg {
    pub system: bool,
    pub ro: Vec<String>,
    pub rw: Vec<String>,
    pub tmpfs: Vec<String>,
    pub deny: Vec<String>,
    pub noexec: Vec<String>,
    pub sockets: Vec<String>,
    pub tmpfs_size: Option<String>,
}

impl Default for FsCfg {
    fn default() -> Self {
        FsCfg {
            system: true,
            ro: vec![],
            rw: vec![],
            tmpfs: vec![],
            deny: vec![],
            noexec: vec![],
            sockets: vec![],
            tmpfs_size: None,
        }
    }
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum NetMode {
    #[default]
    None,
    Proxy,
    Host,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct NetCfg {
    pub mode: NetMode,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub allow_private: bool,
    pub proxy_port: u16,
    pub tcp_connect: Option<Vec<u16>>,
    pub tcp_bind: Option<Vec<u16>>,
}

impl Default for NetCfg {
    fn default() -> Self {
        NetCfg {
            mode: NetMode::None,
            allow: vec![],
            deny: vec![],
            allow_private: false,
            proxy_port: 3128,
            tcp_connect: None,
            tcp_bind: None,
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct EnvCfg {
    pub pass: Vec<String>,
    pub set: BTreeMap<String, String>,
}

impl Default for EnvCfg {
    fn default() -> Self {
        let pass = ["PATH", "TERM", "COLORTERM", "LANG", "LANGUAGE", "LC_*", "TZ", "USER", "LOGNAME", "HOME", "SHELL"];
        EnvCfg { pass: pass.iter().map(|s| s.to_string()).collect(), set: BTreeMap::new() }
    }
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsCfg {
    pub memory: Option<String>,
    pub cpus: Option<f64>,
    pub pids: Option<u64>,
    pub cpu_method: CpuMethodCfg,
    pub cpu_choice: CpuChoiceCfg,
    pub pids_method: PidsMethodCfg,
    pub nofile: Option<u64>,
    pub fsize: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CpuMethodCfg {
    #[default]
    Auto,
    Cgroup,
    Pin,
    PinForced,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CpuChoiceName {
    #[default]
    Spread,
    Pack,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum CpuChoiceCfg {
    Name(CpuChoiceName),
    List(Vec<u32>),
}

impl Default for CpuChoiceCfg {
    fn default() -> Self {
        CpuChoiceCfg::Name(CpuChoiceName::Spread)
    }
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PidsMethodCfg {
    #[default]
    Auto,
    Cgroup,
    PidNamespace,
}

/// Rules detected from the project's build files (see `detect.rs`).
#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields, default)]
pub struct DetectCfg {
    pub enable: Vec<String>,
    pub within: Vec<String>,
    pub within_rw: Vec<String>,
    pub project: ProjectMode,
}

/// How detected directories inside the same project (git repository) as
/// the working directory are exposed.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProjectMode {
    Off,
    #[default]
    Ro,
    Rw,
}

/// The git repository the working directory belongs to: the nearest
/// directory at or above it holding `.git`. Your home directory and its
/// ancestors never count, so a dotfiles repository in `~` doesn't make
/// all of it one project.
pub fn project_root(cwd: &Path, home: &Path) -> Option<PathBuf> {
    cwd.ancestors()
        .take_while(|a| !home.starts_with(a))
        .find(|a| std::fs::symlink_metadata(a.join(".git")).is_ok())
        .map(Path::to_path_buf)
}

impl DetectCfg {
    /// The `within` (false) and `within_rw` (true) roots, canonical;
    /// missing directories are left out.
    fn roots(&self, cwd: &Path, home: &Path) -> Result<Vec<(PathBuf, bool)>> {
        let mut out = Vec::new();
        for (list, rw) in [(&self.within, false), (&self.within_rw, true)] {
            for w in list {
                if let Ok(c) = std::fs::canonicalize(expand_path(w, cwd, home)?) {
                    out.push((c, rw));
                }
            }
        }
        Ok(out)
    }
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields, default)]
pub struct SeccompCfg {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

/// GUI applications (see docs/design/gui.md).
#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields, default)]
pub struct GuiCfg {
    /// Reported to the compositor as the sandboxed clients' app id.
    pub app_id: Option<String>,
    /// A Wayland socket through a security context.
    pub wayland: bool,
    /// Run even when the compositor still offers escape protocols there.
    pub insecure_wayland: bool,
}

/// The session bus through dbus-proxy's filter; the lists mean what
/// xdg-dbus-proxy's `--talk`, `--own`, `--see`, `--call` and
/// `--broadcast` mean.
#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields, default)]
pub struct DbusCfg {
    pub session: bool,
    pub talk: Vec<String>,
    pub own: Vec<String>,
    pub see: Vec<String>,
    pub call: Vec<String>,
    pub broadcast: Vec<String>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields, default)]
pub struct AuditCfg {
    pub log: Option<String>,
    /// vssr's own messages go only to the log, not to stderr.
    pub quiet: bool,
}

impl Policy {
    pub fn parse(text: &str, origin: &str) -> Result<Policy> {
        toml::from_str(text).with_context(|| format!("parsing policy {origin}"))
    }

    pub fn load(path: &Path) -> Result<Policy> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading policy {}", path.display()))?;
        Self::parse(&text, &path.display().to_string())
    }

    pub fn default_policy() -> Policy {
        Self::parse(DEFAULT_POLICY, "(built-in)").expect("built-in policy parses")
    }
}

// ---------------------------------------------------------------------------
// Resolved plan

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsKind {
    Ro,
    Rw,
    Tmpfs,
    Deny,
    Socket,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub argv: Vec<String>,
    /// The whole view, system entries included, parents first. Bind and
    /// socket sources are canonical; host symlinks are `Symlink` entries.
    pub mounts: Vec<Mount>,
    pub cwd: PathBuf,
    pub env: Vec<(String, String)>,
    pub hostname: String,
    pub uid: u32,
    pub gid: u32,
    pub host_uid: u32,
    pub host_gid: u32,
    pub tty: bool,
    pub strict: bool,
    pub timeout: Option<Duration>,
    pub kill_grace: Duration,
    pub net_mode: NetMode,
    pub net: NetPolicy,
    /// The proxy's rules as the policy spelt them (for `to_json`).
    pub net_allow: Vec<String>,
    pub net_deny: Vec<String>,
    pub net_allow_private: bool,
    pub proxy_port: u16,
    pub tcp_connect: Option<Vec<u16>>,
    pub tcp_bind: Option<Vec<u16>>,
    pub memory: Option<u64>,
    pub cpus: Option<f64>,
    pub pids: Option<u64>,
    pub cpu_method: vssl::CpuMethod,
    pub cpu_choice: vssl::CpuChoice,
    pub pids_method: vssl::PidsMethod,
    /// An existing cgroup v2 directory to start in (`--cgroup`) instead of
    /// a systemd user scope.
    pub cgroup: Option<PathBuf>,
    pub nofile: Option<u64>,
    pub fsize: Option<u64>,
    pub seccomp_allow: Vec<String>,
    pub seccomp_deny: Vec<String>,
    pub audit_log: Option<PathBuf>,
    pub quiet: bool,
    /// Host directories the sandbox can write now or may have written in
    /// an earlier run, canonical. No symlink under them is followed.
    pub writable: Vec<PathBuf>,
    /// Why each detected mount is there, by inside path.
    pub detected: BTreeMap<PathBuf, String>,
    /// Messages for the user from plan resolution (detection results).
    pub notes: Vec<String>,
    /// Risks the policy takes on knowingly, for the user (`warning` events).
    pub warnings: Vec<String>,
    pub wayland: Option<WaylandPlan>,
    pub dbus: Option<DbusPlan>,
}

/// Wayland through a security context. The socket itself is made at start
/// (`main.rs`), so it isn't among the plan's mounts.
#[derive(Debug, Clone)]
pub struct WaylandPlan {
    /// The session compositor's socket, on the host.
    pub compositor: PathBuf,
    /// The private runtime directory inside (a tmpfs among the mounts),
    /// which holds the socket as `wayland-0`.
    pub runtime_dir: PathBuf,
    pub app_id: Option<String>,
    pub insecure: bool,
}

impl WaylandPlan {
    /// Where the program finds the socket.
    pub fn socket(&self) -> PathBuf {
        self.runtime_dir.join("wayland-0")
    }
}

/// The session's Wayland socket: `$WAYLAND_DISPLAY` (default `wayland-0`),
/// in `$XDG_RUNTIME_DIR` unless it is an absolute path.
fn session_wayland() -> Result<PathBuf> {
    let name = std::env::var("WAYLAND_DISPLAY").unwrap_or_else(|_| "wayland-0".into());
    if Path::new(&name).is_absolute() {
        return Ok(PathBuf::from(name));
    }
    let rt = std::env::var("XDG_RUNTIME_DIR").context("gui.wayland: $XDG_RUNTIME_DIR is not set")?;
    Ok(Path::new(&rt).join(name))
}

/// Makes `/run/user/<uid>` the program's private runtime directory, a
/// tmpfs for the sockets vssr hands over. `what` names the setting.
fn private_runtime_dir(uid: u32, what: &str, mounts: &mut BTreeMap<PathBuf, Mount>) -> Result<PathBuf> {
    let runtime_dir = PathBuf::from(format!("/run/user/{uid}"));
    // The deepest entry at or above it decides: only a fresh tmpfs (or
    // nothing, the sandbox's own root) can hold the private directory.
    let owner = mounts.iter().filter(|(d, _)| runtime_dir.starts_with(d)).max_by_key(|(d, _)| d.components().count());
    if let Some((d, m)) = owner
        && !matches!(m.kind, MountKind::Tmpfs { .. })
    {
        bail!(
            "{what} makes {} the program's private runtime directory, but the policy's entry for {} covers it; \
             expose host sockets with fs.sockets instead",
            runtime_dir.display(),
            d.display()
        );
    }
    mounts.entry(runtime_dir.clone()).or_insert_with(|| Mount::tmpfs(&runtime_dir));
    Ok(runtime_dir)
}

/// Keeps a session socket (`name`, which `what` replaces) out of the view:
/// an fs.sockets entry for it is refused, and it is hidden wherever a bind
/// would show it.
fn hide_session_socket(socket: &Path, name: &str, what: &str, mounts: &mut BTreeMap<PathBuf, Mount>) -> Result<()> {
    let real = std::fs::canonicalize(socket).unwrap_or_else(|_| socket.to_path_buf());
    let mut denies = Vec::new();
    for m in mounts.values() {
        match &m.kind {
            MountKind::Socket { src } if *src == real => {
                bail!("fs.sockets hands over the session's {name} {}, which {what} replaces", real.display())
            }
            MountKind::Bind { src, .. } if real.starts_with(src) && real != *src => {
                if let Ok(rel) = real.strip_prefix(src) {
                    denies.push(m.dest.join(rel));
                }
            }
            _ => {}
        }
    }
    for d in denies {
        mounts.entry(d.clone()).or_insert_with(|| Mount::deny(d));
    }
    Ok(())
}

/// Adds what Wayland needs to the view: a private runtime directory, and
/// the session's own socket hidden wherever a bind would show it.
fn add_wayland(gui: &GuiCfg, uid: u32, compositor: PathBuf, mounts: &mut BTreeMap<PathBuf, Mount>) -> Result<WaylandPlan> {
    let runtime_dir = private_runtime_dir(uid, "gui.wayland", mounts)?;
    hide_session_socket(&compositor, "Wayland socket", "gui.wayland", mounts)?;
    Ok(WaylandPlan { compositor, runtime_dir, app_id: gui.app_id.clone(), insecure: gui.insecure_wayland })
}

/// The session bus through dbus-proxy's filter. The proxy and its socket are
/// set up when the run starts (`main.rs`), so the socket isn't among the
/// mounts.
#[derive(Debug, Clone)]
pub struct DbusPlan {
    /// The session bus's address.
    pub upstream: String,
    /// The private runtime directory inside, which holds the socket as `bus`.
    pub runtime_dir: PathBuf,
    /// The filter, written as xdg-dbus-proxy's arguments (`--talk=…`,
    /// `--own=…` and the rest, in policy order), for the log.
    pub rules: Vec<String>,
    pub policy: dbus_proxy::Policy,
}

impl DbusPlan {
    /// Where the program finds the socket.
    pub fn socket(&self) -> PathBuf {
        self.runtime_dir.join("bus")
    }

    /// `DBUS_SESSION_BUS_ADDRESS` inside.
    pub fn address(&self) -> String {
        format!("unix:path={}", self.socket().display())
    }
}

/// The session bus's address: `$DBUS_SESSION_BUS_ADDRESS`, or the socket
/// systemd and dbus-broker use, `$XDG_RUNTIME_DIR/bus`.
fn session_bus() -> Result<String> {
    if let Ok(a) = std::env::var("DBUS_SESSION_BUS_ADDRESS")
        && !a.is_empty()
    {
        return Ok(a);
    }
    let rt = std::env::var("XDG_RUNTIME_DIR").context("dbus.session: neither $DBUS_SESSION_BUS_ADDRESS nor $XDG_RUNTIME_DIR is set")?;
    Ok(format!("unix:path={}", Path::new(&rt).join("bus").display()))
}

/// The socket paths a D-Bus address names (`unix:path=…` entries,
/// `%XX` escapes decoded). Abstract sockets have none, and Landlock keeps
/// the sandbox from reaching those outside it.
fn bus_socket_paths(address: &str) -> Vec<PathBuf> {
    let unescape = |v: &str| -> Option<Vec<u8>> {
        let b = v.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' {
                let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        Some(out)
    };
    let mut paths = vec![];
    for entry in address.split(';') {
        let Some(params) = entry.strip_prefix("unix:") else { continue };
        for kv in params.split(',') {
            if let Some(v) = kv.strip_prefix("path=")
                && let Some(p) = unescape(v)
            {
                paths.push(PathBuf::from(std::ffi::OsString::from_vec(p)));
            }
        }
    }
    paths
}

/// Services known to run commands on the host for any caller that may
/// talk to them.
const BUS_ESCAPES: [&str; 2] = ["org.freedesktop.systemd1", "org.freedesktop.Flatpak"];

/// Whether a name or prefix in the filter reaches `name`.
fn bus_name_covers(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix(".*") {
        Some(prefix) => name == prefix || name.strip_prefix(prefix).is_some_and(|r| r.starts_with('.')),
        None => pattern == name,
    }
}

/// Adds the session bus to the view (a private runtime directory, the
/// session's own socket hidden) and turns the policy's lists into the
/// proxy's filter.
fn add_dbus(cfg: &DbusCfg, uid: u32, upstream: String, mounts: &mut BTreeMap<PathBuf, Mount>, warnings: &mut Vec<String>) -> Result<DbusPlan> {
    let mut rules = vec![];
    let mut policy = dbus_proxy::Policy::new();
    for (key, list) in [("see", &cfg.see), ("talk", &cfg.talk), ("own", &cfg.own)] {
        for n in list {
            let r = match key {
                "see" => policy.see(n),
                "talk" => policy.talk(n),
                _ => policy.own(n),
            };
            r.map_err(|e| anyhow::anyhow!("dbus.{key} {e}"))?;
            rules.push(format!("--{key}={n}"));
        }
    }
    for (key, list) in [("call", &cfg.call), ("broadcast", &cfg.broadcast)] {
        for r in list {
            let Some((n, rule)) = r.split_once('=') else {
                bail!("dbus.{key} {r:?}: expected NAME=RULE, RULE being [METHOD][@PATH] (such as org.example.App=org.example.App.Open@/org/example/App)");
            };
            let added = if key == "call" { policy.call(n, rule) } else { policy.broadcast(n, rule) };
            added.map_err(|e| anyhow::anyhow!("dbus.{key} {n}: {e}"))?;
            rules.push(format!("--{key}={r}"));
        }
    }
    for esc in BUS_ESCAPES {
        if let Some(n) = cfg.talk.iter().chain(&cfg.own).find(|n| bus_name_covers(n, esc)) {
            let via = if n == esc { String::new() } else { format!(" (through {n})") };
            warnings.push(format!("dbus: the program may talk to {esc}{via}, which can run any command on the host"));
        }
    }
    let runtime_dir = private_runtime_dir(uid, "dbus.session", mounts)?;
    let host_sockets = bus_socket_paths(&upstream);
    for p in &host_sockets {
        hide_session_socket(p, "bus socket", "dbus.session", mounts)?;
    }
    Ok(DbusPlan { upstream, runtime_dir, rules, policy })
}

/// Extra filesystem entries from the command line; they override the policy.
#[derive(Debug, Default, Clone)]
pub struct FsOverrides {
    pub entries: Vec<(FsKind, String)>,
}

impl Plan {
    /// `home` is the user's home directory ([`crate::util::home_dir`]): what
    /// `~` and `$HOME` mean, and where project detection stops.
    pub fn build(policy: &Policy, extra_fs: &FsOverrides, cwd: &Path, home: &Path) -> Result<Plan> {
        let host_uid = unsafe { libc::getuid() };
        let host_gid = unsafe { libc::getgid() };

        // Collect entries in precedence order: later entries win for the same path.
        let mut entries: Vec<(FsKind, String)> = Vec::new();
        let fs = &policy.fs;
        for (kind, list) in [
            (FsKind::Tmpfs, &fs.tmpfs),
            (FsKind::Ro, &fs.ro),
            (FsKind::Rw, &fs.rw),
            (FsKind::Socket, &fs.sockets),
            (FsKind::Deny, &fs.deny),
        ] {
            entries.extend(list.iter().map(|s| (kind, s.clone())));
        }
        entries.extend(extra_fs.entries.iter().cloned());

        let mut mounts: BTreeMap<PathBuf, Mount> = BTreeMap::new();
        if fs.system {
            for m in system_mounts(policy.net.mode)? {
                mounts.insert(m.dest.clone(), m);
            }
        }

        // Writable host directories, canonical: sources under them may have
        // been tampered with by an earlier sandbox run, so no symlinks are
        // followed there. Directories under detect.within_rw may have been
        // written by an earlier run, whether or not this one exposes them.
        let mut writable: Vec<PathBuf> = policy.detect.roots(cwd, home)?.into_iter().filter(|r| r.1).map(|r| r.0).collect();
        let project = project_root(cwd, &std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf()));
        if policy.detect.project == ProjectMode::Rw
            && let Some(p) = &project
            && let Ok(c) = std::fs::canonicalize(p)
        {
            writable.push(c);
        }
        for (kind, spec) in &entries {
            if *kind == FsKind::Rw {
                let (_, src, _) = split_spec(spec, cwd, home)?;
                if let Ok(c) = std::fs::canonicalize(&src) {
                    writable.push(c);
                }
            }
        }

        let tmpfs_size = fs.tmpfs_size.as_deref().map(parse_size).transpose()?;
        for (kind, spec) in &entries {
            let (optional, src, dest) = split_spec(spec, cwd, home)?;
            let m = match kind {
                FsKind::Tmpfs => Mount { dest, kind: MountKind::Tmpfs { size: None }, noexec: false, optional, no_symlinks: false },
                FsKind::Deny => {
                    if src != dest {
                        bail!("{spec:?}: deny entries take a single path");
                    }
                    Mount::deny(dest)
                }
                FsKind::Ro | FsKind::Rw => {
                    match resolve_source(&src, &dest, &writable)? {
                        Some(k) => {
                            let k = match k {
                                MountKind::Bind { src, .. } => MountKind::Bind { src, writable: *kind == FsKind::Rw },
                                other => other,
                            };
                            Mount { dest, kind: k, noexec: false, optional, no_symlinks: false }
                        }
                        None if optional => continue,
                        None => bail!("{}: no such file or directory (prefix the entry with '?' to make it optional)", src.display()),
                    }
                }
                // Always the socket itself, never a symlink to it: the
                // entry grants connecting to what it names.
                FsKind::Socket => match resolve_guarded(&src, &writable)? {
                    Some(src) => {
                        use std::os::unix::fs::FileTypeExt;
                        if !std::fs::metadata(&src).is_ok_and(|m| m.file_type().is_socket()) {
                            bail!("socket entry {}: not a unix socket", src.display());
                        }
                        Mount { dest, kind: MountKind::Socket { src }, noexec: false, optional, no_symlinks: false }
                    }
                    None if optional => continue,
                    None => bail!("{}: no such socket (prefix the entry with '?' to make it optional)", src.display()),
                },
            };
            mounts.insert(m.dest.clone(), m);
        }

        let (detected, notes) = add_detected(&policy.detect, cwd, home, project.as_deref(), &mut mounts)?;

        for spec in &fs.noexec {
            let p = expand_path(spec, cwd, home)?;
            match mounts.get_mut(&p) {
                Some(m) if matches!(m.kind, MountKind::Bind { .. } | MountKind::Tmpfs { .. }) => m.noexec = true,
                _ => bail!("noexec {}: must name a ro, rw or tmpfs entry exactly", p.display()),
            }
        }
        // fs.tmpfs_size applies to every tmpfs (system ones included) and /dev/shm.
        for m in mounts.values_mut() {
            if let MountKind::Tmpfs { size } | MountKind::Dev { shm_size: size } = &mut m.kind {
                *size = size.or(tmpfs_size);
            }
        }

        let uid = policy.sandbox.uid.unwrap_or(host_uid);
        let wayland = if policy.gui.wayland {
            Some(add_wayland(&policy.gui, uid, session_wayland()?, &mut mounts)?)
        } else {
            if policy.gui.insecure_wayland || policy.gui.app_id.is_some() {
                bail!("gui.app_id and gui.insecure_wayland only apply with gui.wayland = true");
            }
            None
        };
        let mut warnings = vec![];
        let d = &policy.dbus;
        let dbus = if d.session {
            Some(add_dbus(d, uid, session_bus()?, &mut mounts, &mut warnings)?)
        } else {
            if [&d.talk, &d.own, &d.see, &d.call, &d.broadcast].iter().any(|l| !l.is_empty()) {
                warnings.push("dbus: the name lists only apply with dbus.session = true; the program gets no bus".into());
            }
            None
        };

        if mounts.keys().any(|d| d == Path::new("/")) {
            bail!("'/' cannot be bound directly; list the directories to expose instead");
        }

        // Parents before children: sort by depth, then by path.
        let mut mounts: Vec<Mount> = mounts.into_values().collect();
        mounts.sort_by(|a, b| {
            let da = a.dest.components().count();
            let db = b.dest.components().count();
            da.cmp(&db).then_with(|| a.dest.cmp(&b.dest))
        });

        let cwd_inside = match &policy.sandbox.cwd {
            Some(c) => expand_path(c, cwd, home)?,
            None => cwd.to_path_buf(),
        };
        // The deepest mount containing the cwd decides (mounts are sorted parent-first).
        let visible = mounts
            .iter()
            .rev()
            .find(|m| cwd_inside.starts_with(&m.dest))
            .is_some_and(|m| matches!(m.kind, MountKind::Bind { .. } | MountKind::Tmpfs { .. }));
        if !visible {
            bail!(
                "working directory {} is not visible in the sandbox; expose it with --rw/--ro or set --cwd",
                cwd_inside.display()
            );
        }

        let net = NetPolicy::new(&policy.net.allow, &policy.net.deny, policy.net.allow_private)?;
        if policy.net.mode != NetMode::Proxy && !policy.net.allow.is_empty() {
            bail!("net.allow only applies to net.mode = \"proxy\" (it is {:?})", policy.net.mode);
        }

        let mut env = build_env(policy, home, cwd)?;
        if let Some(w) = &wayland {
            env.retain(|(k, _)| k != "WAYLAND_DISPLAY" && k != "XDG_RUNTIME_DIR");
            env.push(("WAYLAND_DISPLAY".into(), "wayland-0".into()));
            env.push(("XDG_RUNTIME_DIR".into(), w.runtime_dir.to_string_lossy().into_owned()));
        }
        if let Some(d) = &dbus {
            env.retain(|(k, _)| k != "DBUS_SESSION_BUS_ADDRESS" && k != "XDG_RUNTIME_DIR");
            env.push(("DBUS_SESSION_BUS_ADDRESS".into(), d.address()));
            env.push(("XDG_RUNTIME_DIR".into(), d.runtime_dir.to_string_lossy().into_owned()));
            // The accessibility bus is reached through the session bus, and
            // isn't in the filter unless the policy says so.
            if !env.iter().any(|(k, _)| k == "NO_AT_BRIDGE") {
                env.push(("NO_AT_BRIDGE".into(), "1".into()));
            }
        }
        env.sort();

        let limits = &policy.limits;
        if let Some(c) = limits.cpus
            && !(c.is_finite() && c > 0.0) {
                bail!("limits.cpus must be positive");
            }

        Ok(Plan {
            argv: policy.command.clone(),
            mounts,
            cwd: cwd_inside,
            env,
            hostname: policy.sandbox.hostname.clone(),
            uid,
            gid: policy.sandbox.gid.unwrap_or(host_gid),
            host_uid,
            host_gid,
            tty: policy.sandbox.tty,
            strict: policy.sandbox.strict,
            timeout: policy.sandbox.timeout.as_deref().map(parse_duration).transpose()?,
            kill_grace: parse_duration(&policy.sandbox.kill_grace)?,
            net_mode: policy.net.mode,
            net,
            net_allow: policy.net.allow.clone(),
            net_deny: policy.net.deny.clone(),
            net_allow_private: policy.net.allow_private,
            proxy_port: policy.net.proxy_port,
            tcp_connect: policy.net.tcp_connect.clone(),
            tcp_bind: policy.net.tcp_bind.clone(),
            memory: limits.memory.as_deref().map(parse_size).transpose()?,
            cpus: limits.cpus,
            pids: limits.pids,
            cpu_method: match limits.cpu_method {
                CpuMethodCfg::Auto => vssl::CpuMethod::Auto,
                CpuMethodCfg::Cgroup => vssl::CpuMethod::Cgroup,
                CpuMethodCfg::Pin => vssl::CpuMethod::Pin,
                CpuMethodCfg::PinForced => vssl::CpuMethod::PinForced,
            },
            cpu_choice: match &limits.cpu_choice {
                CpuChoiceCfg::Name(CpuChoiceName::Spread) => vssl::CpuChoice::Spread,
                CpuChoiceCfg::Name(CpuChoiceName::Pack) => vssl::CpuChoice::Pack,
                CpuChoiceCfg::List(l) => vssl::CpuChoice::List(l.clone()),
            },
            pids_method: match limits.pids_method {
                PidsMethodCfg::Auto => vssl::PidsMethod::Auto,
                PidsMethodCfg::Cgroup => vssl::PidsMethod::Cgroup,
                PidsMethodCfg::PidNamespace => vssl::PidsMethod::PidNamespace,
            },
            cgroup: None,
            nofile: limits.nofile,
            fsize: limits.fsize.as_deref().map(parse_size).transpose()?,
            seccomp_allow: policy.seccomp.allow.clone(),
            seccomp_deny: policy.seccomp.deny.clone(),
            // A host path, so '..' is fine here.
            audit_log: policy.audit.log.as_deref().map(|l| expand(l, cwd, home).map(|e| cwd.join(e))).transpose()?,
            quiet: policy.audit.quiet,
            writable,
            detected,
            notes,
            warnings,
            wayland,
            dbus,
        })
    }

    /// The sandbox this plan describes. The view is complete already, so
    /// vssl's own system view stays off. Bind and socket sources are canonical and
    /// checked, so vssl refuses any symlink in them (one planted since).
    pub fn sandbox(&self) -> Sandbox {
        let mut sb = Sandbox::new();
        sb.mounts(self.mounts.iter().map(|m| match m.kind {
            MountKind::Bind { .. } | MountKind::Socket { .. } => m.clone().no_symlinks(),
            _ => m.clone(),
        }))
            .hostname(self.hostname.clone())
            .uid(self.uid)
            .gid(self.gid)
            .strict(self.strict)
            .limits(Limits {
                memory: self.memory,
                cpus: self.cpus,
                pids: self.pids,
                cpu_method: self.cpu_method,
                cpu_choice: self.cpu_choice.clone(),
                pids_method: self.pids_method,
            });
        if let Some(c) = &self.cgroup {
            sb.cgroup(vssl::Cgroup::Join(c.clone()));
        }
        match self.net_mode {
            NetMode::Host => sb.net(Net::Host),
            NetMode::None => sb.net(Net::None),
            // The proxy serves this listener from outside (see main.rs).
            NetMode::Proxy => sb.net(Net::None).listen_tcp(self.proxy_port),
        };
        if let Some(p) = &self.tcp_connect {
            sb.tcp_connect(p.iter().copied());
        }
        if let Some(p) = &self.tcp_bind {
            sb.tcp_bind(p.iter().copied());
        }
        for s in &self.seccomp_allow {
            sb.seccomp_allow(s.clone());
        }
        for s in &self.seccomp_deny {
            sb.seccomp_deny(s.clone());
        }
        if let Some(n) = self.nofile {
            sb.rlimit(Resource::NoFile, n);
        }
        if let Some(n) = self.fsize {
            sb.rlimit(Resource::FileSize, n);
        }
        sb
    }

    /// The command to run, with stdio inherited. `id` names the run (and its
    /// systemd scope).
    pub fn command(&self, id: &str) -> Command {
        let mut c = Command::new(&self.argv[0]);
        c.args(&self.argv[1..])
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .cwd(&self.cwd)
            .keep_session(self.tty)
            .id(id);
        c
    }

    /// The plan for programs (`--dry-run --json`, `vssr check --json`).
    /// Environment variables are listed by name only: their values may be
    /// secrets.
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;
        let mounts: Vec<_> = self
            .mounts
            .iter()
            .map(|m| {
                let mut o = match &m.kind {
                    MountKind::Bind { src, writable } => json!({"kind": if *writable { "rw" } else { "ro" }, "src": src}),
                    MountKind::Socket { src } => json!({"kind": "socket", "src": src}),
                    MountKind::Tmpfs { size } => json!({"kind": "tmpfs", "size": size}),
                    MountKind::Deny => json!({"kind": "deny"}),
                    MountKind::Symlink { target } => json!({"kind": "symlink", "target": target}),
                    MountKind::Proc => json!({"kind": "proc"}),
                    MountKind::Dev { shm_size } => json!({"kind": "dev", "shm_size": shm_size}),
                };
                o["dest"] = json!(m.dest);
                o["noexec"] = json!(m.noexec);
                o["optional"] = json!(m.optional);
                if let Some(w) = self.detected.get(&m.dest) {
                    o["detected"] = json!(w);
                }
                o
            })
            .collect();
        // As policy files spell them: PinForced -> pin-forced.
        let method = |m: &dyn std::fmt::Debug| {
            let mut out = String::new();
            for (i, c) in format!("{m:?}").chars().enumerate() {
                if c.is_uppercase() && i > 0 {
                    out.push('-');
                }
                out.push(c.to_ascii_lowercase());
            }
            out
        };
        json!({
            "command": self.argv,
            "cwd": self.cwd,
            "hostname": self.hostname,
            "uid": self.uid,
            "gid": self.gid,
            "host_uid": self.host_uid,
            "host_gid": self.host_gid,
            "mounts": mounts,
            "net": {
                "mode": format!("{:?}", self.net_mode).to_lowercase(),
                "proxy_port": (self.net_mode == NetMode::Proxy).then_some(self.proxy_port),
                "allow": self.net_allow,
                "deny": self.net_deny,
                "allow_private": self.net_allow_private,
                "tcp_connect": self.tcp_connect,
                "tcp_bind": self.tcp_bind,
            },
            "env": self.env.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            "limits": {
                "memory": self.memory,
                "cpus": self.cpus,
                "cpu_method": method(&self.cpu_method),
                "cpu_choice": match &self.cpu_choice {
                    vssl::CpuChoice::List(l) => json!(l),
                    c => json!(method(c)),
                },
                "pids": self.pids,
                "pids_method": method(&self.pids_method),
                "nofile": self.nofile,
                "fsize": self.fsize,
                "timeout_s": self.timeout.map(|t| t.as_secs_f64()),
                "kill_grace_s": self.kill_grace.as_secs_f64(),
            },
            "cgroup": self.cgroup,
            "seccomp": {"allow": self.seccomp_allow, "deny": self.seccomp_deny},
            "strict": self.strict,
            "tty": self.tty,
            "audit_log": self.audit_log,
            "quiet": self.quiet,
            "gui": {
                "wayland": self.wayland.as_ref().map(|w| json!({
                    "compositor": w.compositor,
                    "socket": w.socket(),
                    "app_id": w.app_id,
                    "insecure": w.insecure,
                })),
            },
            "dbus": {
                "session": self.dbus.as_ref().map(|d| json!({
                    "upstream": d.upstream,
                    "socket": d.socket(),
                    "rules": d.rules,
                })),
            },
            "notes": self.notes,
            "warnings": self.warnings,
        })
    }

    /// Human-readable summary for `vssr check` and `--dry-run`.
    pub fn describe(&self) -> String {
        use std::fmt::Write;
        let mut s = String::new();
        let _ = writeln!(s, "command:  {}", if self.argv.is_empty() { "(none)".into() } else { shell_words(&self.argv) });
        let _ = writeln!(s, "cwd:      {}", self.cwd.display());
        let _ = writeln!(s, "ids:      uid {} gid {} (host {} / {})", self.uid, self.gid, self.host_uid, self.host_gid);
        let _ = writeln!(s, "filesystem:");
        for m in &self.mounts {
            let what = match &m.kind {
                MountKind::Bind { src, writable } => {
                    let mode = if *writable { "rw    " } else { "ro    " };
                    if src == &m.dest { mode.to_string() } else { format!("{mode}<- {} ", src.display()) }
                }
                MountKind::Socket { src } if src == &m.dest => "socket ".into(),
                MountKind::Socket { src } => format!("socket <- {} ", src.display()),
                MountKind::Tmpfs { .. } => "tmpfs ".into(),
                MountKind::Deny => "deny  ".into(),
                MountKind::Symlink { target } => format!("link  -> {} ", target.display()),
                MountKind::Proc => "proc  ".into(),
                MountKind::Dev { .. } => "dev   ".into(),
            };
            let flags = if m.noexec { " (noexec)" } else { "" };
            let why = self.detected.get(&m.dest).map(|w| format!("  (detected: {w})")).unwrap_or_default();
            let _ = writeln!(s, "  {what}{}{flags}{why}", m.dest.display());
        }
        let net = match self.net_mode {
            NetMode::None => "none (loopback only)".to_string(),
            NetMode::Host => "host (shares the host network)".to_string(),
            NetMode::Proxy => format!("proxy on 127.0.0.1:{} — {}", self.proxy_port, self.net.describe()),
        };
        let _ = writeln!(s, "network:  {net}");
        if let Some(p) = &self.tcp_connect {
            let _ = writeln!(s, "          tcp connect ports: {p:?}");
        }
        if let Some(p) = &self.tcp_bind {
            let _ = writeln!(s, "          tcp bind ports: {p:?}");
        }
        if let Some(w) = &self.wayland {
            let app = w.app_id.as_deref().map(|a| format!(", app id {a}")).unwrap_or_default();
            let insecure = if w.insecure { " (insecure_wayland: runs even if escape protocols are visible)" } else { "" };
            let _ = writeln!(s, "wayland:  {} through a security context{app}, as {}{insecure}", w.compositor.display(), w.socket().display());
        }
        if let Some(d) = &self.dbus {
            let rules = if d.rules.is_empty() { "nothing but the bus itself".into() } else { d.rules.join(" ") };
            let _ = writeln!(s, "dbus:     {} through vssr's filter, as {}; allows {rules}", d.upstream, d.socket().display());
        }
        let names: Vec<&str> = self.env.iter().map(|(k, _)| k.as_str()).collect();
        let _ = writeln!(s, "env:      {}", names.join(" "));
        let mut lim = vec![];
        if let Some(m) = self.memory { lim.push(format!("memory {} MiB", m >> 20)); }
        if let Some(c) = self.cpus { lim.push(format!("cpus {c} ({:?}, {:?})", self.cpu_method, self.cpu_choice)); }
        if let Some(p) = self.pids { lim.push(format!("pids {p} ({:?})", self.pids_method)); }
        if let Some(n) = self.nofile { lim.push(format!("nofile {n}")); }
        if let Some(f) = self.fsize { lim.push(format!("fsize {} MiB", f >> 20)); }
        if let Some(t) = self.timeout { lim.push(format!("timeout {}s", t.as_secs())); }
        let _ = writeln!(s, "limits:   {}", if lim.is_empty() { "none".into() } else { lim.join(", ") });
        if let Some(c) = &self.cgroup {
            let _ = writeln!(s, "cgroup:   {}", c.display());
        }
        let _ = writeln!(s, "strict:   {}  tty: {}", self.strict, self.tty);
        for n in &self.notes {
            let _ = writeln!(s, "note:     {n}");
        }
        for w in &self.warnings {
            let _ = writeln!(s, "warning:  {w}");
        }
        s
    }
}

/// Runs the enabled detectors and adds what they found to `mounts`, as
/// binds at the host path. A detected directory is added only when it lies
/// under one of `detect.within` (read-only) or `detect.within_rw`
/// (read-write), the deepest matching root deciding, or inside `project`
/// as `detect.project` says, whichever grants more; when nothing explicit
/// covers it already; and when it isn't under a deny entry. Returns why
/// each added mount is there, and notes about what was skipped.
fn add_detected(
    cfg: &DetectCfg,
    cwd: &Path,
    home: &Path,
    project: Option<&Path>,
    mounts: &mut BTreeMap<PathBuf, Mount>,
) -> Result<(BTreeMap<PathBuf, String>, Vec<String>)> {
    let det = crate::detect::run(&cfg.enable, cwd)?;
    let mut notes = det.notes;
    let roots = cfg.roots(cwd, home)?;
    let mut found = det.found;
    // Parents first, so a dependency inside an added workspace is already covered.
    found.sort_by_key(|f| f.path.components().count());
    let mut added = BTreeMap::new();
    for f in found {
        if added.contains_key(&f.path) {
            continue;
        }
        let shown = f.path.display();
        let within = roots.iter().filter(|(r, _)| f.path.starts_with(r)).max_by_key(|(r, _)| r.components().count()).map(|r| r.1);
        // Inside the project, but never its root or .git: a build file
        // naming those would hand out the hooks and config of the repository.
        let in_project = project.is_some_and(|p| f.path.starts_with(p) && f.path != p && !f.path.starts_with(p.join(".git")));
        let by_project = match cfg.project {
            _ if !in_project => None,
            ProjectMode::Off => None,
            ProjectMode::Ro => Some(false),
            ProjectMode::Rw => Some(true),
        };
        // None < Some(false) < Some(true): the more permissive rule wins.
        let rw = within.max(by_project);
        // The deepest existing entry at or above the path decides.
        let owner = mounts.iter().filter(|(d, _)| f.path.starts_with(d)).max_by_key(|(d, _)| d.components().count());
        match owner {
            Some((d, _)) if *d == f.path => continue, // an entry for this very path wins
            Some((d, m)) => match &m.kind {
                MountKind::Bind { src, writable: visible_rw } if src == d => match rw {
                    // Inside another detected directory with other rights: mount it on top.
                    Some(want) if want != *visible_rw && added.contains_key(d) => {}
                    Some(true) if !visible_rw => {
                        notes.push(format!("{shown} ({}) stays read-only: it is under the read-only entry {}", f.why, d.display()));
                        continue;
                    }
                    _ => continue, // already visible
                },
                MountKind::Tmpfs { .. } => {}
                MountKind::Deny => {
                    notes.push(format!("not exposing {shown} ({}): it is under the deny entry {}", f.why, d.display()));
                    continue;
                }
                _ => {
                    notes.push(format!("not exposing {shown} ({}): {} is mapped to another location", f.why, d.display()));
                    continue;
                }
            },
            None => {}
        }
        let Some(rw) = rw else {
            notes.push(format!(
                "not exposing {shown} ({}): outside detect.within and the project; add a parent directory to \
                 detect.within (--detect-within) or, for read-write, detect.within_rw (--detect-within-rw), or pass --ro {shown}",
                f.why
            ));
            continue;
        };
        let kind = MountKind::Bind { src: f.path.clone(), writable: rw };
        mounts.insert(f.path.clone(), Mount { dest: f.path.clone(), kind, noexec: false, optional: true, no_symlinks: false });
        added.insert(f.path, f.why);
    }
    Ok((added, notes))
}

/// Splits "SRC" or "SRC:DEST" (with an optional leading '?') into its parts.
fn split_spec(spec: &str, cwd: &Path, home: &Path) -> Result<(bool, PathBuf, PathBuf)> {
    let (optional, spec) = match spec.strip_prefix('?') {
        Some(s) => (true, s),
        None => (false, spec),
    };
    let (src, dest) = match spec.split_once(':') {
        Some((s, d)) => (expand_path(s, cwd, home)?, expand_path(d, cwd, home)?),
        None => {
            let p = expand_path(spec, cwd, home)?;
            (p.clone(), p)
        }
    };
    Ok((optional, src, dest))
}

/// Works out how to expose a host path: as a symlink (when the host path is
/// a symlink exposed at the same place, outside the writable directories)
/// or as a bind of its canonical path. Each symlink on the way is judged by
/// where it really lives, whatever the spelling: one under a writable
/// directory is refused.
fn resolve_source(src: &Path, dest: &Path, writable: &[PathBuf]) -> Result<Option<MountKind>> {
    let meta = match std::fs::symlink_metadata(src) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("{}", src.display())),
    };
    if meta.file_type().is_symlink()
        && src == dest
        && let (Some(parent), Some(name)) = (src.parent(), src.file_name())
        && let Some(dir) = resolve_guarded(parent, writable)?
    {
        let at = dir.join(name);
        if !writable.iter().any(|r| at.starts_with(r)) {
            return Ok(Some(MountKind::Symlink { target: std::fs::read_link(src)? }));
        }
    }
    // Refuses a symlink under a writable directory, the last component too.
    Ok(resolve_guarded(src, writable)?.map(|src| MountKind::Bind { src, writable: false }))
}

/// vssl's system view (read-only /usr, /etc…, fresh /tmp, /proc, /dev),
/// resolved, so policy entries and detection can be checked against it.
fn system_mounts(net: NetMode) -> Result<Vec<Mount>> {
    let mut sb = Sandbox::new();
    sb.system(true).net(if net == NetMode::Host { Net::Host } else { Net::None });
    Ok(sb.resolved_mounts()?)
}

fn build_env(policy: &Policy, home: &Path, cwd: &Path) -> Result<Vec<(String, String)>> {
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in std::env::vars() {
        let pass = policy.env.pass.iter().any(|p| match p.strip_suffix('*') {
            Some(prefix) => k.starts_with(prefix),
            None => *p == k,
        });
        // An empty $HOME passed on would hide the home directory set below.
        if pass && !(k == "HOME" && v.is_empty()) {
            env.insert(k, v);
        }
    }
    for (k, v) in &policy.env.set {
        env.insert(k.clone(), expand(v, cwd, home)?);
    }
    env.entry("HOME".into()).or_insert_with(|| home.to_string_lossy().into_owned());
    env.entry("PATH".into()).or_insert_with(|| "/usr/local/bin:/usr/bin:/bin".into());
    if policy.net.mode == NetMode::Proxy {
        let url = format!("http://127.0.0.1:{}", policy.net.proxy_port);
        for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"] {
            env.entry(k.into()).or_insert_with(|| url.clone());
        }
        for k in ["NO_PROXY", "no_proxy"] {
            env.entry(k.into()).or_insert_with(|| "localhost,127.0.0.1,::1".into());
        }
        // Node.js 24+ only honours the proxy variables with this set.
        env.entry("NODE_USE_ENV_PROXY".into()).or_insert_with(|| "1".into());
    }
    env.insert("VSSR_SANDBOX".into(), "1".into());
    Ok(env.into_iter().collect())
}

pub fn shell_words(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if !a.is_empty() && a.chars().all(|c| c.is_ascii_alphanumeric() || "-_./=:,@%+".contains(c)) {
                a.clone()
            } else {
                format!("'{}'", a.replace('\'', r"'\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The home directory the plans in these tests are built for; it needn't exist.
    const HOME: &str = "/home/vssr-test";

    #[test]
    fn default_policy_parses() {
        let p = Policy::default_policy();
        assert!(p.fs.system);
        assert_eq!(p.net.mode, NetMode::None);
        assert_eq!(p.fs.rw, vec!["$PWD"]);
    }

    #[test]
    fn home_is_the_one_given() {
        // `~` in the default policy's tmpfs, and $HOME in an entry: the home
        // passed in, whatever $HOME says (vssr may have found it in passwd).
        let cwd = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let mut o = FsOverrides::default();
        o.entries.push((FsKind::Tmpfs, "$HOME/sub".into()));
        let plan = Plan::build(&Policy::default_policy(), &o, &cwd, Path::new(HOME)).unwrap();
        for d in [HOME, "/home/vssr-test/sub"] {
            assert!(plan.mounts.iter().any(|m| m.dest == Path::new(d) && matches!(m.kind, MountKind::Tmpfs { .. })), "{d}");
        }
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(Policy::parse("[fs]\nrww = []\n", "t").is_err());
    }

    #[test]
    fn later_entries_win_and_children_follow_parents() {
        let dir = std::env::temp_dir();
        let cwd = std::fs::canonicalize(&dir).unwrap();
        let mut p = Policy::default();
        p.fs.system = false;
        p.fs.ro = vec!["$PWD".into()];
        let mut o = FsOverrides::default();
        o.entries.push((FsKind::Rw, "$PWD".into()));
        o.entries.push((FsKind::Tmpfs, "$PWD/vssr-test-sub".into()));
        let plan = Plan::build(&p, &o, &cwd, Path::new(HOME)).unwrap();
        assert_eq!(plan.mounts.len(), 2);
        assert!(matches!(plan.mounts[0].kind, MountKind::Bind { writable: true, .. }));
        assert!(matches!(plan.mounts[1].kind, MountKind::Tmpfs { .. }));
    }

    #[test]
    fn project_roots() {
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap().join(format!("vssr-proj-{}", std::process::id()));
        let (home, repo) = (base.join("home"), base.join("home/p/repo"));
        std::fs::create_dir_all(repo.join("app/src")).unwrap();
        std::fs::create_dir_all(home.join(".git")).unwrap(); // a dotfiles repository
        let found = |cwd: &Path| project_root(cwd, &home);
        assert_eq!(found(&repo.join("app/src")), None);
        std::fs::write(repo.join(".git"), "gitdir: elsewhere").unwrap(); // worktrees use a file
        assert_eq!(found(&repo.join("app/src")), Some(repo.clone()));
        assert_eq!(found(&repo), Some(repo.clone()));
        assert_eq!(found(&home), None);
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn tmpfs_size_reaches_every_tmpfs_and_shm() {
        let mut p = Policy::default();
        p.fs.tmpfs_size = Some("64M".into());
        let plan = Plan::build(&p, &FsOverrides::default(), Path::new("/usr"), Path::new(HOME)).unwrap();
        let sizes: Vec<_> = plan
            .mounts
            .iter()
            .filter_map(|m| match m.kind {
                MountKind::Tmpfs { size } | MountKind::Dev { shm_size: size } => Some(size),
                _ => None,
            })
            .collect();
        assert!(sizes.len() >= 4, "/tmp, /var/tmp, /run and /dev at least");
        assert!(sizes.iter().all(|s| *s == Some(64 << 20)));
    }

    /// base/alias -> real; real/work/planted -> base/sentinel, as an earlier
    /// run with real/work writable could have left it.
    fn alias_fixture(name: &str) -> PathBuf {
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap().join(format!("vssr-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("real/work/sub")).unwrap();
        std::fs::create_dir_all(base.join("sentinel")).unwrap();
        std::os::unix::fs::symlink("real", base.join("alias")).unwrap();
        std::os::unix::fs::symlink(base.join("sentinel"), base.join("real/work/planted")).unwrap();
        base
    }

    fn plan_with(base: &Path, cwd: &str, entries: &[(FsKind, &str)]) -> Result<Plan> {
        let mut p = Policy::default();
        p.fs.system = false;
        let mut o = FsOverrides::default();
        for (k, e) in entries {
            o.entries.push((*k, e.replace("@", &base.to_string_lossy())));
        }
        Plan::build(&p, &o, &base.join(cwd), Path::new(HOME))
    }

    #[test]
    fn writable_aliases_are_one_directory() {
        let base = alias_fixture("alias");
        let refused = |entries: &[(FsKind, &str)]| {
            let e = plan_with(&base, "real/work", entries).unwrap_err().to_string();
            assert!(e.contains("refusing to follow the symlink"), "{entries:?}: {e}");
        };
        // Writable through the alias, exposed through the real path, and the reverse.
        refused(&[(FsKind::Rw, "@/alias/work:@/real/work"), (FsKind::Ro, "@/real/work/planted:/exposed")]);
        refused(&[(FsKind::Rw, "@/real/work"), (FsKind::Ro, "@/alias/work/planted:/exposed")]);
        // Nor does it become a symlink entry when exposed at its own place.
        refused(&[(FsKind::Rw, "@/real/work"), (FsKind::Ro, "@/alias/work/planted")]);
        refused(&[(FsKind::Rw, "@/alias/work:@/real/work"), (FsKind::Ro, "@/real/work/planted")]);
        // A symlink above the writable directory is fine.
        let plan = plan_with(&base, "alias/work", &[(FsKind::Rw, "@/alias/work"), (FsKind::Ro, "@/alias/work/sub")]).unwrap();
        let src = |d: &str| plan.mounts.iter().find(|m| m.dest == base.join(d)).map(|m| m.kind.clone());
        assert_eq!(src("alias/work"), Some(MountKind::Bind { src: base.join("real/work"), writable: true }));
        assert_eq!(src("alias/work/sub"), Some(MountKind::Bind { src: base.join("real/work/sub"), writable: false }));
        assert_eq!(plan.writable, vec![base.join("real/work")]);
        // Outside the writable directories, a symlink at its own place stays one.
        let plan = plan_with(&base, "real/work", &[(FsKind::Rw, "@/real/work/sub:@/real/work"), (FsKind::Ro, "@/alias")]).unwrap();
        assert!(plan.mounts.iter().any(|m| m.dest == base.join("alias") && m.kind == MountKind::Symlink { target: "real".into() }));
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn binds_reach_vssl_without_symlinks() {
        let base = alias_fixture("nosym");
        let plan = plan_with(&base, "real/work", &[(FsKind::Rw, "@/alias/work"), (FsKind::Ro, "@/sentinel"), (FsKind::Tmpfs, "/tmp")]).unwrap();
        let binds: Vec<_> = plan.sandbox().resolved_mounts().unwrap().into_iter().filter(|m| matches!(m.kind, MountKind::Bind { .. })).collect();
        assert_eq!(binds.len(), 2);
        assert!(binds.iter().all(|m| m.no_symlinks));
        // The system view too.
        let plan = Plan::build(&Policy::default(), &FsOverrides::default(), Path::new("/usr"), Path::new(HOME)).unwrap();
        assert!(plan.sandbox().resolved_mounts().unwrap().iter().all(|m| m.no_symlinks == matches!(m.kind, MountKind::Bind { .. } | MountKind::Socket { .. })));
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn socket_entries() {
        let base = alias_fixture("sock");
        let _l = std::os::unix::net::UnixListener::bind(base.join("real/s")).unwrap();
        // Named through a symlink outside the writable directories: the
        // socket itself is mounted, not a symlink entry.
        let plan = plan_with(&base, "real/work", &[(FsKind::Rw, "@/real/work"), (FsKind::Socket, "@/alias/s")]).unwrap();
        let m = plan.mounts.iter().find(|m| m.dest == base.join("alias/s")).unwrap();
        assert_eq!(m.kind, MountKind::Socket { src: base.join("real/s") });
        let e = plan_with(&base, "real/work", &[(FsKind::Rw, "@/real/work"), (FsKind::Socket, "@/real/work/sub")]).unwrap_err();
        assert!(e.to_string().contains("not a unix socket"), "{e}");
        assert!(plan_with(&base, "real/work", &[(FsKind::Rw, "@/real/work"), (FsKind::Socket, "@/missing")]).is_err());
        assert!(plan_with(&base, "real/work", &[(FsKind::Rw, "@/real/work"), (FsKind::Socket, "?@/missing")]).is_ok());
        // A deny entry still wins.
        let plan = plan_with(&base, "real/work", &[(FsKind::Rw, "@/real/work"), (FsKind::Socket, "@/real/s"), (FsKind::Deny, "@/real/s")]).unwrap();
        assert!(plan.mounts.iter().any(|m| m.dest == base.join("real/s") && m.kind == MountKind::Deny));
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn wayland_view() {
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap().join(format!("vssr-wl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("rt")).unwrap();
        let session = base.join("rt/wayland-1");
        let _l = std::os::unix::net::UnixListener::bind(&session).unwrap();
        let gui = GuiCfg { wayland: true, ..Default::default() };
        let view = |entries: &[Mount]| {
            let mut m: BTreeMap<PathBuf, Mount> = entries.iter().map(|e| (e.dest.clone(), e.clone())).collect();
            add_wayland(&gui, 1000, session.clone(), &mut m).map(|w| (w, m))
        };
        // A private runtime directory, on the sandbox's own /run.
        let (w, m) = view(&[Mount::tmpfs("/run")]).unwrap();
        assert_eq!(w.socket(), Path::new("/run/user/1000/wayland-0"));
        assert!(matches!(m[Path::new("/run/user/1000")].kind, MountKind::Tmpfs { .. }));
        // The session's socket is hidden wherever a bind shows it.
        let (_, m) = view(&[Mount::ro_at(base.join("rt"), "/hostrun")]).unwrap();
        assert_eq!(m[Path::new("/hostrun/wayland-1")].kind, MountKind::Deny);
        // A host directory where the private one goes, or the socket itself, is refused.
        assert!(view(&[Mount::ro("/run")]).is_err());
        assert!(view(&[Mount::ro_at(base.join("rt"), "/run/user/1000")]).is_err());
        assert!(view(&[Mount::socket_at(&session, "/s")]).is_err());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn dbus_view() {
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap().join(format!("vssr-bus-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("rt")).unwrap();
        let bus = base.join("rt/bus");
        let _l = std::os::unix::net::UnixListener::bind(&bus).unwrap();
        let upstream = format!("unix:path={},guid=0123", bus.display());
        let view = |cfg: &DbusCfg, entries: &[Mount]| {
            let mut m: BTreeMap<PathBuf, Mount> = entries.iter().map(|e| (e.dest.clone(), e.clone())).collect();
            let mut warnings = vec![];
            add_dbus(cfg, 1000, upstream.clone(), &mut m, &mut warnings).map(|d| (d, m, warnings))
        };
        let cfg = DbusCfg {
            session: true,
            talk: vec!["org.freedesktop.Notifications".into(), "org.freedesktop.portal.*".into()],
            own: vec!["org.example.App".into()],
            call: vec!["org.example.Other=org.example.Other.Open@/org/example/*".into()],
            ..Default::default()
        };
        let (d, m, notes) = view(&cfg, &[Mount::tmpfs("/run"), Mount::ro_at(base.join("rt"), "/hostrun")]).unwrap();
        assert_eq!(d.socket(), Path::new("/run/user/1000/bus"));
        assert_eq!(d.address(), "unix:path=/run/user/1000/bus");
        assert_eq!(
            d.rules,
            [
                "--talk=org.freedesktop.Notifications",
                "--talk=org.freedesktop.portal.*",
                "--own=org.example.App",
                "--call=org.example.Other=org.example.Other.Open@/org/example/*"
            ]
        );
        assert!(notes.is_empty());
        assert!(matches!(m[Path::new("/run/user/1000")].kind, MountKind::Tmpfs { .. }));
        // The session's socket is hidden wherever a bind shows it, and can't be handed over.
        assert_eq!(m[Path::new("/hostrun/bus")].kind, MountKind::Deny);
        assert!(view(&cfg, &[Mount::socket_at(&bus, "/s")]).is_err());
        assert!(view(&cfg, &[Mount::ro("/run")]).is_err());
        // Names are checked, and services that run host commands are pointed out.
        for bad in ["org", "org.*", "org..x", "1org.x", "org.x y", ":1.5", "org.x.**"] {
            assert!(view(&DbusCfg { session: true, talk: vec![bad.into()], ..Default::default() }, &[]).is_err(), "{bad}");
        }
        for bad in ["org.x", "org.x=", "org.x=a b", "org.x=a\n"] {
            assert!(view(&DbusCfg { session: true, call: vec![bad.into()], ..Default::default() }, &[]).is_err(), "{bad}");
        }
        for talk in ["org.freedesktop.systemd1", "org.freedesktop.*"] {
            let (_, _, notes) = view(&DbusCfg { session: true, talk: vec![talk.into()], ..Default::default() }, &[]).unwrap();
            assert!(notes.iter().any(|n| n.contains("org.freedesktop.systemd1")), "{talk}");
        }
        let (_, _, notes) = view(&DbusCfg { session: true, talk: vec!["org.freedesktop.systemd10".into()], ..Default::default() }, &[]).unwrap();
        assert!(notes.is_empty());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn bus_addresses() {
        assert_eq!(bus_socket_paths("unix:path=/run/user/1/bus"), [PathBuf::from("/run/user/1/bus")]);
        assert_eq!(bus_socket_paths("unix:guid=1,path=/a%20b/bus;tcp:host=x"), [PathBuf::from("/a b/bus")]);
        assert_eq!(bus_socket_paths("unix:abstract=/tmp/dbus-x,guid=2"), Vec::<PathBuf>::new());
        assert_eq!(bus_socket_paths("unix:path=/bad%2"), Vec::<PathBuf>::new());
    }

    #[test]
    fn dbus_needs_the_session_not_your_uid() {
        let dir = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let mut p = Policy::default_policy();
        p.dbus.talk = vec!["org.example.App".into()];
        let plan = Plan::build(&p, &FsOverrides::default(), &dir, Path::new(HOME)).unwrap();
        assert!(plan.dbus.is_none());
        assert!(plan.warnings.iter().any(|w| w.contains("dbus.session = true")), "{:?}", plan.warnings);
        // The proxy logs in for the program, so its uid inside doesn't matter.
        p.dbus.session = true;
        let uid = unsafe { libc::getuid() } + 1;
        p.sandbox.uid = Some(uid);
        let plan = Plan::build(&p, &FsOverrides::default(), &dir, Path::new(HOME)).unwrap();
        assert_eq!(plan.dbus.unwrap().socket(), PathBuf::from(format!("/run/user/{uid}/bus")));
    }

    #[test]
    fn invisible_cwd_is_an_error() {
        let mut p = Policy::default();
        p.fs.system = false;
        p.fs.tmpfs = vec!["/tmp".into()];
        assert!(Plan::build(&p, &FsOverrides::default(), Path::new("/usr"), Path::new(HOME)).is_err());
    }
}
