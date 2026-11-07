//! Rules detected at start-up from the project's own build files, such as
//! Cargo path dependencies that live outside the working directory.
//!
//! Detectors only *find* host directories the build will read. Whether
//! they are exposed is decided in `Plan::build`: read-only, never over an
//! explicit entry, and only under the policy's `detect.within` roots,
//! because the build files are repository content that the sandboxed
//! program itself may have edited during an earlier run.
//!
//! Detectors key on what is in the project (build tools), never on which
//! program runs in the sandbox.

use anyhow::{Result, bail};
use std::collections::{BTreeSet, VecDeque};
use std::path::{Component, Path, PathBuf};

/// Detector names accepted in `detect.enable`.
pub const DETECTORS: &[&str] = &["cargo"];

/// A host directory the project needs, with the reason.
#[derive(Debug, Clone)]
pub struct Found {
    /// Canonical host path.
    pub path: PathBuf,
    pub why: String,
}

#[derive(Debug, Default)]
pub struct Detection {
    pub found: Vec<Found>,
    /// Things worth telling the user (skipped entries, parse errors, hints).
    pub notes: Vec<String>,
}

pub fn check_names(names: &[String]) -> Result<()> {
    for n in names {
        if !DETECTORS.contains(&n.as_str()) {
            bail!("detect.enable: unknown detector {n:?} (known: {})", DETECTORS.join(", "));
        }
    }
    Ok(())
}

/// Runs the enabled detectors from the project directory `start`.
pub fn run(names: &[String], start: &Path) -> Result<Detection> {
    check_names(names)?;
    let mut d = Detection::default();
    for n in names {
        if n == "cargo" {
            cargo(start, &mut d);
        }
    }
    Ok(d)
}

// ---------------------------------------------------------------------------
// Cargo

/// Upper bound on manifests read, so a pathological dependency graph can't
/// stall start-up.
const MAX_MANIFESTS: usize = 256;
/// Manifests bigger than this are skipped.
const MAX_MANIFEST_BYTES: u64 = 1 << 20;

const DEP_TABLES: &[&str] = &["dependencies", "dev-dependencies", "dev_dependencies", "build-dependencies", "build_dependencies"];

/// Follows path dependencies (direct and transitive), `[patch]` and
/// `[replace]` paths, workspace members and the workspace roots of
/// dependencies, since cargo reads all of them.
fn cargo(start: &Path, d: &mut Detection) {
    let Ok(start) = std::fs::canonicalize(start) else { return };
    let Some(root) = read_manifest(&start, d) else { return };

    // A workspace root above the working directory can't be fixed by
    // exposing it read-only: cargo writes Cargo.lock and target/ there.
    if let Some(ws) = workspace_root(&start, &root, d)
        && ws != start
    {
        d.notes.push(format!(
            "cargo: {} is the workspace root of {}; cargo needs to write there, so run vssr from {}",
            ws.join("Cargo.toml").display(),
            start.display(),
            ws.display()
        ));
    }

    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([(start.clone(), root)]);
    seen.insert(start.clone());
    while let Some((dir, manifest)) = queue.pop_front() {
        let name = package_name(&manifest, &dir);
        let mut next: Vec<(PathBuf, String)> = Vec::new();
        let mut paths = manifest_paths(&manifest);
        for pat in member_patterns(&manifest) {
            if has_glob(&pat) {
                let matches = expand_glob(&dir, &pat);
                paths.extend(matches.into_iter().map(|m| (m, "workspace member")));
            } else {
                paths.push((pat, "workspace member"));
            }
        }
        for (rel, what) in paths {
            let p = crate::util::normalize(&dir.join(&rel)).unwrap_or_else(|_| dir.join(&rel));
            match std::fs::canonicalize(&p) {
                Ok(c) if c.is_dir() => next.push((c, format!("{what} of {name}"))),
                Ok(_) => d.notes.push(format!("cargo: {what} {rel:?} of {name} is not a directory")),
                Err(_) => d.notes.push(format!("cargo: {what} {rel:?} of {name} does not exist ({})", p.display())),
            }
        }
        if dir != start
            && let Some(ws) = workspace_root(&dir, &manifest, d)
            && ws != dir
        {
            next.push((ws, format!("workspace root of {name}")));
        }
        for (path, why) in next {
            d.found.push(Found { path: path.clone(), why });
            if !seen.insert(path.clone()) {
                continue;
            }
            if seen.len() > MAX_MANIFESTS {
                d.notes.push(format!("cargo: stopped after {MAX_MANIFESTS} manifests"));
                return;
            }
            if path.join("Cargo.toml").is_file()
                && let Some(m) = read_manifest(&path, d)
            {
                queue.push_back((path, m));
            }
        }
    }
}

fn read_manifest(dir: &Path, d: &mut Detection) -> Option<toml::Table> {
    let file = dir.join("Cargo.toml");
    let meta = std::fs::metadata(&file).ok()?;
    if !meta.is_file() {
        return None;
    }
    if meta.len() > MAX_MANIFEST_BYTES {
        d.notes.push(format!("cargo: skipping {} (larger than 1 MiB)", file.display()));
        return None;
    }
    let text = match std::fs::read_to_string(&file) {
        Ok(t) => t,
        Err(e) => {
            d.notes.push(format!("cargo: reading {}: {e}", file.display()));
            return None;
        }
    };
    match text.parse::<toml::Table>() {
        Ok(t) => Some(t),
        Err(e) => {
            let first = e.to_string().lines().next().unwrap_or_default().to_string();
            d.notes.push(format!("cargo: can't parse {}: {first}", file.display()));
            None
        }
    }
}

fn package_name(m: &toml::Table, dir: &Path) -> String {
    m.get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| dir.display().to_string())
}

/// The workspace root cargo would use for the crate in `dir`: the one set
/// with `package.workspace`, else the nearest ancestor whose manifest has
/// a `[workspace]` table. None when the crate is its own root.
fn workspace_root(dir: &Path, m: &toml::Table, d: &mut Detection) -> Option<PathBuf> {
    if m.contains_key("workspace") {
        return None;
    }
    if let Some(ws) = m.get("package").and_then(|p| p.get("workspace")).and_then(|w| w.as_str()) {
        return std::fs::canonicalize(dir.join(ws)).ok();
    }
    for anc in dir.ancestors().skip(1) {
        if anc.join("Cargo.toml").is_file()
            && let Some(t) = read_manifest(anc, d)
            && t.contains_key("workspace")
        {
            return Some(anc.to_path_buf());
        }
    }
    None
}

/// Directory paths a manifest refers to, relative to its directory, each
/// with a short description.
fn manifest_paths(m: &toml::Table) -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    let deps = |t: Option<&toml::Value>, what: &'static str, out: &mut Vec<(String, &'static str)>| {
        let Some(t) = t.and_then(|t| t.as_table()) else { return };
        for v in t.values() {
            if let Some(p) = v.get("path").and_then(|p| p.as_str()) {
                out.push((p.to_string(), what));
            }
        }
    };
    for k in DEP_TABLES {
        deps(m.get(*k), "path dependency", &mut out);
    }
    if let Some(targets) = m.get("target").and_then(|t| t.as_table()) {
        for t in targets.values() {
            for k in DEP_TABLES {
                deps(t.get(*k), "path dependency", &mut out);
            }
        }
    }
    if let Some(ws) = m.get("workspace") {
        deps(ws.get("dependencies"), "workspace path dependency", &mut out);
    }
    if let Some(patch) = m.get("patch").and_then(|t| t.as_table()) {
        for source in patch.values() {
            deps(Some(source), "patch", &mut out);
        }
    }
    deps(m.get("replace"), "replace", &mut out);
    out
}

/// `[workspace] members` patterns.
fn member_patterns(m: &toml::Table) -> Vec<String> {
    m.get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).map(str::to_string).collect())
        .unwrap_or_default()
}

fn has_glob(s: &str) -> bool {
    s.contains(['*', '?', '['])
}

/// Expands a member pattern relative to `dir`, the way cargo does for the
/// common cases: `*` and `?` within one path component. Returns paths
/// relative to `dir`. Character classes (`[...]`) match nothing.
fn expand_glob(dir: &Path, pattern: &str) -> Vec<String> {
    let mut cur = vec![PathBuf::new()];
    for c in Path::new(pattern).components() {
        let mut next = Vec::new();
        match c {
            Component::Normal(n) if has_glob(&n.to_string_lossy()) => {
                let pat = n.to_string_lossy();
                for base in &cur {
                    let Ok(rd) = std::fs::read_dir(dir.join(base)) else { continue };
                    let mut names: Vec<_> = rd.flatten().map(|e| e.file_name()).collect();
                    names.sort();
                    for name in names {
                        let s = name.to_string_lossy();
                        if !s.starts_with('.') && wildcard(&pat, &s) && dir.join(base).join(&name).is_dir() {
                            next.push(base.join(&name));
                        }
                    }
                }
            }
            other => next = cur.iter().map(|b| b.join(other)).collect(),
        }
        cur = next;
    }
    cur.into_iter().map(|p| p.to_string_lossy().into_owned()).collect()
}

/// Matches `*` (any run) and `?` (one character); `[` matches nothing.
fn wildcard(pat: &str, s: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pat.chars().collect(), s.chars().collect());
    let (mut pi, mut ti, mut star, mut mark) = (0, 0, None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || (p[pi] == t[ti] && p[pi] != '*' && p[pi] != '[')) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_dependency_paths() {
        let m: toml::Table = r#"
            [package]
            name = "app"
            [dependencies]
            a = { path = "../a" }
            reg = "1"
            [dev-dependencies.b]
            path = "../b"
            [target.'cfg(unix)'.build-dependencies]
            c = { path = "/abs/c", version = "1" }
            [workspace]
            members = ["crates/*", "tool"]
            dependencies = { d = { path = "../d" } }
            [patch.crates-io]
            e = { path = "../e" }
            [replace]
            "f:1.0.0" = { path = "../f" }
        "#
        .parse()
        .unwrap();
        let paths: Vec<String> = manifest_paths(&m).into_iter().map(|(p, _)| p).collect();
        for want in ["../a", "../b", "/abs/c", "../d", "../e", "../f"] {
            assert!(paths.contains(&want.to_string()), "missing {want} in {paths:?}");
        }
        assert_eq!(paths.len(), 6);
        assert_eq!(member_patterns(&m), vec!["crates/*", "tool"]);
    }

    #[test]
    fn wildcards() {
        assert!(wildcard("*", "abc"));
        assert!(wildcard("a*c", "abbbc"));
        assert!(wildcard("a?c", "abc"));
        assert!(!wildcard("a?c", "abbc"));
        assert!(!wildcard("[ab]", "a"));
        assert!(wildcard("*-cli", "foo-cli"));
    }

    #[test]
    fn expands_member_globs() {
        let dir = std::env::temp_dir().join(format!("vssr-glob-{}", std::process::id()));
        for d in ["crates/a", "crates/b", "crates/.hidden", "other"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        std::fs::write(dir.join("crates/file"), "").unwrap();
        let got = expand_glob(&dir, "crates/*");
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(got, vec!["crates/a", "crates/b"]);
    }

    #[test]
    fn unknown_detectors_are_rejected() {
        assert!(check_names(&["cargo".into()]).is_ok());
        assert!(check_names(&["make".into()]).is_err());
    }
}
