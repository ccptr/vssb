//! Syntax of the names in a D-Bus message, as the specification gives it
//! and dbus-daemon checks it.

const MAX_NAME: usize = 255;

fn elements(s: &str, ok: impl Fn(u8, bool) -> bool) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME
        && s.split('.').count() >= 2
        && s.split('.').all(|e| !e.is_empty() && e.bytes().enumerate().all(|(i, c)| ok(c, i == 0)))
}

/// A unique connection name, such as `:1.42`.
pub fn unique(s: &str) -> bool {
    s.strip_prefix(':').is_some_and(|r| s.len() <= MAX_NAME && elements(r, |c, _| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'))
}

/// A well-known bus name, such as `org.example.App`.
pub fn well_known(s: &str) -> bool {
    elements(s, |c, first| (c.is_ascii_alphabetic() || c == b'_' || c == b'-') || (!first && c.is_ascii_digit()))
}

pub fn bus_name(s: &str) -> bool {
    unique(s) || well_known(s)
}

/// An interface name (also the syntax of error names).
pub fn interface(s: &str) -> bool {
    elements(s, |c, first| (c.is_ascii_alphabetic() || c == b'_') || (!first && c.is_ascii_digit()))
}

pub fn member(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME
        && s.bytes().enumerate().all(|(i, c)| c.is_ascii_alphabetic() || c == b'_' || (i > 0 && c.is_ascii_digit()))
}

pub fn object_path(s: &str) -> bool {
    s == "/"
        || s.strip_prefix('/').is_some_and(|r| {
            r.split('/').all(|e| !e.is_empty() && e.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for ok in [":1.42", ":a.b", ":1.2.3-x_"] {
            assert!(unique(ok) && bus_name(ok), "{ok}");
        }
        for ok in ["org.example.App", "a.b", "org.ex-ample._x9", "org.example.App2"] {
            assert!(well_known(ok) && bus_name(ok), "{ok}");
        }
        for bad in ["", "org", ":1", "org..x", ".org.x", "org.x.", "org.9x", "org.ex mple", "org.é.x", ":", ":1..2"] {
            assert!(!bus_name(bad), "{bad}");
        }
        assert!(!well_known(&format!("org.{}", "x".repeat(252))));
        assert!(well_known(&format!("org.{}", "x".repeat(251))));
        assert!(interface("org.example.Iface_2"));
        for bad in ["org", "org.ex-ample", "org.2x", "org..x"] {
            assert!(!interface(bad), "{bad}");
        }
        assert!(member("Get_2") && member("_x"));
        for bad in ["", "2x", "a.b", "a-b"] {
            assert!(!member(bad), "{bad}");
        }
        for ok in ["/", "/org", "/org/example/App_1", "/0"] {
            assert!(object_path(ok), "{ok}");
        }
        for bad in ["", "org", "//", "/org/", "/org//x", "/org/ex-ample", "/org.x"] {
            assert!(!object_path(bad), "{bad}");
        }
    }
}
