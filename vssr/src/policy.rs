//! Policy files (TOML) and their resolution into a concrete [`Plan`],
//! which maps onto a vssb [`Sandbox`] and [`Command`].

use crate::util::{expand, expand_path, parse_duration, parse_size};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use vssb::proxy::NetPolicy;
use vssb::{Command, Limits, Mount, MountKind, Net, Resource, Sandbox};

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

[audit]
# log = "~/.local/state/vssr/audit.jsonl"
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
    pub nofile: Option<u64>,
    pub fsize: Option<String>,
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
    fn roots(&self, cwd: &Path) -> Result<Vec<(PathBuf, bool)>> {
        let mut out = Vec::new();
        for (list, rw) in [(&self.within, false), (&self.within_rw, true)] {
            for w in list {
                if let Ok(c) = std::fs::canonicalize(expand_path(w, cwd)?) {
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

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields, default)]
pub struct AuditCfg {
    pub log: Option<String>,
    /// Don't print blocked network requests to stderr.
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
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub argv: Vec<String>,
    /// The whole view, system entries included, parents first. Bind
    /// sources are canonical; host symlinks are `Symlink` entries.
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
    pub proxy_port: u16,
    pub tcp_connect: Option<Vec<u16>>,
    pub tcp_bind: Option<Vec<u16>>,
    pub memory: Option<u64>,
    pub cpus: Option<f64>,
    pub pids: Option<u64>,
    pub nofile: Option<u64>,
    pub fsize: Option<u64>,
    pub seccomp_allow: Vec<String>,
    pub seccomp_deny: Vec<String>,
    pub audit_log: Option<PathBuf>,
    pub quiet: bool,
    /// Why each detected mount is there, by inside path.
    pub detected: BTreeMap<PathBuf, String>,
    /// Messages for the user from plan resolution (detection results).
    pub notes: Vec<String>,
}

/// Extra filesystem entries from the command line; they override the policy.
#[derive(Debug, Default, Clone)]
pub struct FsOverrides {
    pub entries: Vec<(FsKind, String)>,
}

impl Plan {
    pub fn build(policy: &Policy, extra_fs: &FsOverrides, cwd: &Path) -> Result<Plan> {
        let home = PathBuf::from(std::env::var("HOME").context("$HOME is not set")?);
        let host_uid = unsafe { libc::getuid() };
        let host_gid = unsafe { libc::getgid() };

        // Collect entries in precedence order: later entries win for the same path.
        let mut entries: Vec<(FsKind, String)> = Vec::new();
        let fs = &policy.fs;
        for (kind, list) in [
            (FsKind::Tmpfs, &fs.tmpfs),
            (FsKind::Ro, &fs.ro),
            (FsKind::Rw, &fs.rw),
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

        // Writable host directories: sources under them may have been
        // tampered with by an earlier sandbox run, so no symlinks are followed there.
        // Directories under detect.within_rw may have been written by an
        // earlier run, whether or not this one exposes them.
        let mut rw_roots: Vec<PathBuf> = policy.detect.roots(cwd)?.into_iter().filter(|r| r.1).map(|r| r.0).collect();
        let project = project_root(cwd, &std::fs::canonicalize(&home).unwrap_or_else(|_| home.clone()));
        if policy.detect.project == ProjectMode::Rw
            && let Some(p) = &project
        {
            rw_roots.push(p.clone());
        }
        for (kind, spec) in &entries {
            if *kind == FsKind::Rw {
                let (_, src, _) = split_spec(spec, cwd)?;
                rw_roots.push(src);
            }
        }

        let tmpfs_size = fs.tmpfs_size.as_deref().map(parse_size).transpose()?;
        for (kind, spec) in &entries {
            let (optional, src, dest) = split_spec(spec, cwd)?;
            let m = match kind {
                FsKind::Tmpfs => Mount { dest, kind: MountKind::Tmpfs { size: None }, noexec: false, optional },
                FsKind::Deny => {
                    if src != dest {
                        bail!("{spec:?}: deny entries take a single path");
                    }
                    Mount::deny(dest)
                }
                FsKind::Ro | FsKind::Rw => {
                    match resolve_source(&src, &dest, &rw_roots)? {
                        Some(k) => {
                            let k = match k {
                                MountKind::Bind { src, .. } => MountKind::Bind { src, writable: *kind == FsKind::Rw },
                                other => other,
                            };
                            Mount { dest, kind: k, noexec: false, optional }
                        }
                        None if optional => continue,
                        None => bail!("{}: no such file or directory (prefix the entry with '?' to make it optional)", src.display()),
                    }
                }
            };
            mounts.insert(m.dest.clone(), m);
        }

        let (detected, notes) = add_detected(&policy.detect, cwd, project.as_deref(), &mut mounts)?;

        for spec in &fs.noexec {
            let p = expand_path(spec, cwd)?;
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
            Some(c) => expand_path(c, cwd)?,
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

        let env = build_env(policy, &home, cwd)?;

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
            uid: policy.sandbox.uid.unwrap_or(host_uid),
            gid: policy.sandbox.gid.unwrap_or(host_gid),
            host_uid,
            host_gid,
            tty: policy.sandbox.tty,
            strict: policy.sandbox.strict,
            timeout: policy.sandbox.timeout.as_deref().map(parse_duration).transpose()?,
            kill_grace: parse_duration(&policy.sandbox.kill_grace)?,
            net_mode: policy.net.mode,
            net,
            proxy_port: policy.net.proxy_port,
            tcp_connect: policy.net.tcp_connect.clone(),
            tcp_bind: policy.net.tcp_bind.clone(),
            memory: limits.memory.as_deref().map(parse_size).transpose()?,
            cpus: limits.cpus,
            pids: limits.pids,
            nofile: limits.nofile,
            fsize: limits.fsize.as_deref().map(parse_size).transpose()?,
            seccomp_allow: policy.seccomp.allow.clone(),
            seccomp_deny: policy.seccomp.deny.clone(),
            // A host path, so '..' is fine here.
            audit_log: policy.audit.log.as_deref().map(|l| expand(l, cwd).map(|e| cwd.join(e))).transpose()?,
            quiet: policy.audit.quiet,
            detected,
            notes,
        })
    }

    pub fn needs_cgroup(&self) -> bool {
        self.memory.is_some() || self.cpus.is_some() || self.pids.is_some()
    }

    /// The sandbox this plan describes. The view is complete already, so
    /// vssb's own system view stays off.
    pub fn sandbox(&self) -> Sandbox {
        let mut sb = Sandbox::new();
        sb.mounts(self.mounts.iter().cloned())
            .hostname(self.hostname.clone())
            .uid(self.uid)
            .gid(self.gid)
            .strict(self.strict)
            .limits(Limits { memory: self.memory, cpus: self.cpus, pids: self.pids });
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
        let names: Vec<&str> = self.env.iter().map(|(k, _)| k.as_str()).collect();
        let _ = writeln!(s, "env:      {}", names.join(" "));
        let mut lim = vec![];
        if let Some(m) = self.memory { lim.push(format!("memory {} MiB", m >> 20)); }
        if let Some(c) = self.cpus { lim.push(format!("cpus {c}")); }
        if let Some(p) = self.pids { lim.push(format!("pids {p}")); }
        if let Some(n) = self.nofile { lim.push(format!("nofile {n}")); }
        if let Some(f) = self.fsize { lim.push(format!("fsize {} MiB", f >> 20)); }
        if let Some(t) = self.timeout { lim.push(format!("timeout {}s", t.as_secs())); }
        let _ = writeln!(s, "limits:   {}", if lim.is_empty() { "none".into() } else { lim.join(", ") });
        let _ = writeln!(s, "strict:   {}  tty: {}", self.strict, self.tty);
        for n in &self.notes {
            let _ = writeln!(s, "note:     {n}");
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
    project: Option<&Path>,
    mounts: &mut BTreeMap<PathBuf, Mount>,
) -> Result<(BTreeMap<PathBuf, String>, Vec<String>)> {
    let det = crate::detect::run(&cfg.enable, cwd)?;
    let mut notes = det.notes;
    let roots = cfg.roots(cwd)?;
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
        mounts.insert(f.path.clone(), Mount { dest: f.path.clone(), kind, noexec: false, optional: true });
        added.insert(f.path, f.why);
    }
    Ok((added, notes))
}

/// Splits "SRC" or "SRC:DEST" (with an optional leading '?') into its parts.
fn split_spec(spec: &str, cwd: &Path) -> Result<(bool, PathBuf, PathBuf)> {
    let (optional, spec) = match spec.strip_prefix('?') {
        Some(s) => (true, s),
        None => (false, spec),
    };
    let (src, dest) = match spec.split_once(':') {
        Some((s, d)) => (expand_path(s, cwd)?, expand_path(d, cwd)?),
        None => {
            let p = expand_path(spec, cwd)?;
            (p.clone(), p)
        }
    };
    Ok((optional, src, dest))
}

/// Works out how to expose a host path: as a symlink (when the host path is
/// a symlink exposed at the same place) or as a bind of its canonical path.
fn resolve_source(src: &Path, dest: &Path, rw_roots: &[PathBuf]) -> Result<Option<MountKind>> {
    let meta = match std::fs::symlink_metadata(src) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("{}", src.display())),
    };
    if meta.file_type().is_symlink() && src == dest {
        let target = std::fs::read_link(src)?;
        if !rw_roots.iter().any(|r| src.starts_with(r) && src != r) {
            return Ok(Some(MountKind::Symlink { target }));
        }
    }
    let canon = match std::fs::canonicalize(src) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("{}", src.display())),
    };
    for root in rw_roots {
        if src.starts_with(root) && src != root && canon != src {
            bail!(
                "{}: refusing to follow a symlink inside the writable directory {} (resolves to {})",
                src.display(),
                root.display(),
                canon.display()
            );
        }
    }
    Ok(Some(MountKind::Bind { src: canon, writable: false }))
}

/// vssb's system view (read-only /usr, /etc…, fresh /tmp, /proc, /dev),
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
        if pass {
            env.insert(k, v);
        }
    }
    for (k, v) in &policy.env.set {
        env.insert(k.clone(), expand(v, cwd)?);
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

    #[test]
    fn default_policy_parses() {
        let p = Policy::default_policy();
        assert!(p.fs.system);
        assert_eq!(p.net.mode, NetMode::None);
        assert_eq!(p.fs.rw, vec!["$PWD"]);
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
        let plan = Plan::build(&p, &o, &cwd).unwrap();
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
        let plan = Plan::build(&p, &FsOverrides::default(), Path::new("/usr")).unwrap();
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

    #[test]
    fn invisible_cwd_is_an_error() {
        let mut p = Policy::default();
        p.fs.system = false;
        p.fs.tmpfs = vec!["/tmp".into()];
        assert!(Plan::build(&p, &FsOverrides::default(), Path::new("/usr")).is_err());
    }
}
