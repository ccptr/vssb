//! Small helpers: parsing of sizes and durations, path expansion, ids and
//! timestamps.

use anyhow::{Result, anyhow, bail};
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
    Ok(Duration::from_secs_f64(n * mult as f64))
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
    Ok((n * (1u64 << shift) as f64) as u64)
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
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("4G").unwrap(), 4 << 30);
        assert_eq!(parse_size("512MiB").unwrap(), 512 << 20);
        assert_eq!(parse_size("1.5k").unwrap(), 1536);
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
