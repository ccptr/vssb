//! Small helpers: parsing of sizes and durations, path expansion, ids and
//! timestamps.

use anyhow::{Context, Result, anyhow, bail};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

/// Parses "90", "90s", "15m", "2h" or "1d".
pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    let (num, mult) = match s.char_indices().last() {
        Some((i, 's')) => (&s[..i], 1),
        Some((i, 'm')) => (&s[..i], 60),
        Some((i, 'h')) => (&s[..i], 3600),
        Some((i, 'd')) => (&s[..i], 86400),
        _ => (s, 1),
    };
    let n: f64 = num.trim().parse().map_err(|_| anyhow!("invalid duration {s:?}"))?;
    if !(n.is_finite() && n > 0.0) {
        bail!("invalid duration {s:?}");
    }
    // n * mult may overflow to infinity; try_from_secs_f64 refuses that too.
    match Duration::try_from_secs_f64(n * mult as f64) {
        Ok(d) if !d.is_zero() => Ok(d),
        Ok(_) => bail!("invalid duration {s:?}: too short"),
        Err(_) => bail!("invalid duration {s:?}: too long"),
    }
}

/// Parses a byte size such as "512M", "4G" or "1048576" (binary units).
pub fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let t = s.trim_end_matches(['b', 'B']).trim_end_matches(['i']);
    let (num, shift) = match t.char_indices().last() {
        Some((i, 'k' | 'K')) => (&t[..i], 10),
        Some((i, 'm' | 'M')) => (&t[..i], 20),
        Some((i, 'g' | 'G')) => (&t[..i], 30),
        Some((i, 't' | 'T')) => (&t[..i], 40),
        _ => (t, 0),
    };
    let n: f64 = num.trim().parse().map_err(|_| anyhow!("invalid size {s:?}"))?;
    if !(n.is_finite() && n >= 0.0) {
        bail!("invalid size {s:?}");
    }
    let bytes = n * (1u64 << shift) as f64;
    // `as` would saturate; 2^64 itself doesn't fit either.
    if bytes >= u64::MAX as f64 {
        bail!("invalid size {s:?}: too large");
    }
    Ok(bytes as u64)
}

/// Expands a leading `~` and `$VAR` / `${VAR}` references. `$PWD` is the
/// directory vssr was started in, whatever the environment says.
pub fn expand(s: &str, cwd: &Path) -> Result<String> {
    let lookup = |name: &str| -> Result<String> {
        if name == "PWD" {
            return Ok(cwd.to_string_lossy().into_owned());
        }
        std::env::var(name).map_err(|_| anyhow!("{s:?}: environment variable ${name} is not set"))
    };
    let mut out = String::new();
    let mut rest = s;
    if rest == "~" || rest.starts_with("~/") {
        out.push_str(&lookup("HOME")?);
        rest = &rest[1..];
    }
    while let Some(i) = rest.find('$') {
        out.push_str(&rest[..i]);
        rest = &rest[i + 1..];
        let (name, after) = if let Some(r) = rest.strip_prefix('{') {
            let end = r.find('}').ok_or_else(|| anyhow!("{s:?}: unterminated ${{"))?;
            (&r[..end], &r[end + 1..])
        } else {
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            (&rest[..end], &rest[end..])
        };
        if name.is_empty() {
            bail!("{s:?}: lone $ (write $$ is not supported; avoid $ in paths)");
        }
        out.push_str(&lookup(name)?);
        rest = after;
    }
    out.push_str(rest);
    Ok(out)
}

/// Expands and normalises a path: relative paths are taken from `cwd`,
/// and `.` and `..` are resolved lexically. The result is what vssr opens
/// (without following symlinks, or after canonicalising it), so it never
/// differs from what was checked.
pub fn expand_path(s: &str, cwd: &Path) -> Result<PathBuf> {
    let e = expand(s, cwd)?;
    let p = Path::new(&e);
    let p = if p.is_absolute() { p.to_path_buf() } else { cwd.join(p) };
    normalize(&p)
}

pub fn normalize(p: &Path) -> Result<PathBuf> {
    let mut out = PathBuf::from("/");
    for c in p.components() {
        match c {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(n) => out.push(n),
            Component::ParentDir => {
                out.pop();
            }
            Component::Prefix(_) => unreachable!(),
        }
    }
    Ok(out)
}

/// Resolves an absolute path like `canonicalize`, but refuses to follow a
/// symlink that lives (canonically) under one of `writable`, canonical
/// directories the sandbox can write: it may have planted it there.
/// Symlinks elsewhere, above a writable directory too, are followed.
/// Returns the canonical path, or None when a component is missing.
pub fn resolve_guarded(p: &Path, writable: &[PathBuf]) -> Result<Option<PathBuf>> {
    let (out, missing) = resolve_guarded_prefix(p, writable)?;
    Ok(missing.is_empty().then_some(out))
}

/// `resolve_guarded` up to the first missing component: returns the
/// canonical part that exists and the components still to resolve from
/// it, in order (none when the whole path exists).
pub fn resolve_guarded_prefix(p: &Path, writable: &[PathBuf]) -> Result<(PathBuf, Vec<OsString>)> {
    if !p.is_absolute() {
        bail!("{}: not an absolute path", p.display());
    }
    // Components still to resolve, the next one last.
    let mut rest: Vec<OsString> = Vec::new();
    let push = |rest: &mut Vec<OsString>, q: &Path| {
        for c in q.components().rev() {
            match c {
                Component::Normal(n) => rest.push(n.to_owned()),
                Component::ParentDir => rest.push("..".into()),
                Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
            }
        }
    };
    push(&mut rest, p);
    let mut out = PathBuf::from("/");
    let mut hops = 0;
    while let Some(c) = rest.pop() {
        if c == ".." {
            out.pop();
            continue;
        }
        let next = out.join(&c);
        let meta = match std::fs::symlink_metadata(&next) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                rest.push(c);
                rest.reverse();
                return Ok((out, rest));
            }
            Err(e) => return Err(e).with_context(|| format!("{}: {}", p.display(), next.display())),
        };
        if !meta.file_type().is_symlink() {
            out = next;
            continue;
        }
        if let Some(root) = writable.iter().find(|r| next.starts_with(r) && next != **r) {
            bail!("{}: refusing to follow the symlink {} inside the writable directory {}", p.display(), next.display(), root.display());
        }
        hops += 1;
        if hops > 40 {
            bail!("{}: too many levels of symbolic links", p.display());
        }
        let target = std::fs::read_link(&next).with_context(|| format!("{}", next.display()))?;
        if target.is_absolute() {
            out = PathBuf::from("/");
        }
        push(&mut rest, &target);
    }
    Ok((out, Vec::new()))
}

pub fn random_id() -> String {
    let mut b = [0u8; 6];
    // getrandom(2) cannot fail for this size once the pool is initialised.
    unsafe { libc::getrandom(b.as_mut_ptr().cast(), b.len(), 0) };
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Formats a time as RFC 3339 in UTC with milliseconds.
pub fn rfc3339(t: std::time::SystemTime) -> String {
    let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as i64;
    let days = secs.div_euclid(86400);
    let sod = secs.rem_euclid(86400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        sod / 3600,
        sod % 3600 / 60,
        sod % 60,
        d.subsec_millis()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_duration("1.5h").unwrap(), Duration::from_secs(5400));
        assert!(parse_duration("-1").is_err());
        assert!(parse_duration("abc").is_err());
        // Too large for a Duration, or overflowing to infinity: errors, not panics.
        assert!(parse_duration("1e300").is_err());
        assert!(parse_duration("1e307d").is_err());
        assert!(parse_duration("1e-300").is_err());
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("4G").unwrap(), 4 << 30);
        assert_eq!(parse_size("512MiB").unwrap(), 512 << 20);
        assert_eq!(parse_size("1.5k").unwrap(), 1536);
        assert!(parse_size("1e300").is_err());
        assert!(parse_size("16777216T").is_err()); // 2^64
        assert_eq!(parse_size("16777215T").unwrap(), 16777215 << 40);
    }

    #[test]
    fn guarded_resolution() {
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap().join(format!("vssr-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (real, out) = (base.join("real"), base.join("out"));
        std::fs::create_dir_all(real.join("w/sub")).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        std::os::unix::fs::symlink("real", base.join("alias")).unwrap();
        std::os::unix::fs::symlink(&out, real.join("w/planted")).unwrap();
        std::os::unix::fs::symlink("sub/../sub", real.join("w/rel")).unwrap();
        std::os::unix::fs::symlink("loop", base.join("loop")).unwrap();
        let none: &[PathBuf] = &[];
        let w = &[real.join("w")];
        // Without writable directories it is canonicalize.
        assert_eq!(resolve_guarded(&base.join("alias/w/planted"), none).unwrap(), Some(out.clone()));
        assert_eq!(resolve_guarded(&base.join("alias/w/rel/../sub"), none).unwrap(), Some(real.join("w/sub")));
        assert_eq!(resolve_guarded(&base.join("alias/w/missing/x"), none).unwrap(), None);
        assert!(resolve_guarded(&base.join("loop"), none).is_err());
        // A symlink above the writable directory is fine, one inside it isn't,
        // however the path is spelt.
        assert_eq!(resolve_guarded(&base.join("alias/w/sub"), w).unwrap(), Some(real.join("w/sub")));
        assert_eq!(resolve_guarded(&base.join("alias/w"), w).unwrap(), Some(real.join("w")));
        for p in ["real/w/planted", "alias/w/planted", "alias/w/rel", "real/w/sub/../planted/x"] {
            let e = resolve_guarded(&base.join(p), w).unwrap_err().to_string();
            assert!(e.contains("refusing to follow the symlink"), "{p}: {e}");
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn expansion() {
        let cwd = Path::new("/work/dir");
        unsafe { std::env::set_var("VSSR_T", "x") };
        assert_eq!(expand("$PWD/a", cwd).unwrap(), "/work/dir/a");
        assert_eq!(expand("/a/${VSSR_T}/b$VSSR_T", cwd).unwrap(), "/a/x/bx");
        assert!(expand("$VSSR_UNSET_VAR", cwd).is_err());
        assert_eq!(expand_path("rel/./p", cwd).unwrap(), PathBuf::from("/work/dir/rel/p"));
        assert_eq!(expand_path("../x/../y", cwd).unwrap(), PathBuf::from("/work/y"));
        assert_eq!(expand_path("/../..", cwd).unwrap(), PathBuf::from("/"));
    }

    #[test]
    fn time_format() {
        let t = std::time::UNIX_EPOCH + Duration::from_millis(1_793_664_000_123);
        assert_eq!(rfc3339(t), "2026-11-03T00:00:00.123Z");
    }
}
