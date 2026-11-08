//! What a program behind the proxy may do on the bus. The model is
//! xdg-dbus-proxy's, so rules written for Flatpak mean the same here:
//!
//! - each name gets a level, `see` < `talk` < `own`, and a name with no
//!   level is hidden (missing from `ListNames`, calls to it fail as if
//!   nothing owned it);
//! - `talk` allows any call to the name and every signal it broadcasts,
//!   `own` adds owning it;
//! - `call` and `broadcast` rules make a name talkable for the calls, or
//!   the broadcasts, they match only.
//!
//! A name ending in `.*` (`org.example.*`) covers `org.example` and every
//! name below it.

use crate::names;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    None,
    See,
    Talk,
    Own,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PolicyError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pattern {
    name: String,
    subtree: bool,
}

impl Pattern {
    fn parse(s: &str) -> Result<Pattern, PolicyError> {
        let (name, subtree) = match s.strip_suffix(".*") {
            Some(base) => (base, true),
            None => (s, false),
        };
        if !names::well_known(name) {
            return Err(PolicyError(format!(
                "{s:?}: not a D-Bus name (such as org.example.App, or org.example.* for it and the names below it)"
            )));
        }
        Ok(Pattern { name: name.into(), subtree })
    }

    fn matches(&self, name: &str) -> bool {
        if self.subtree {
            name.strip_prefix(self.name.as_str()).is_some_and(|r| r.is_empty() || r.starts_with('.'))
        } else {
            name == self.name
        }
    }
}

/// `[METHOD][@PATH]`: METHOD is `*`, `org.example.Iface.*` or
/// `org.example.Iface.Method`; PATH is `/obj/path`, or `/obj/path/*` for it
/// and everything below.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    interface: Option<String>,
    member: Option<String>,
    path: Option<String>,
    path_subtree: bool,
}

impl Rule {
    fn parse(s: &str) -> Result<Rule, PolicyError> {
        let err = |why: &str| {
            PolicyError(format!("{s:?}: {why}; expected [METHOD][@PATH], such as org.example.Iface.Method@/org/example/Obj"))
        };
        if s.is_empty() {
            return Err(err("empty rule (use talk for every call)"));
        }
        let (method, path) = match s.split_once('@') {
            Some((m, p)) => (m, Some(p)),
            None => (s, None),
        };
        let mut rule = Rule { interface: None, member: None, path: None, path_subtree: false };
        if !method.is_empty() && method != "*" {
            let (iface, member) = method.rsplit_once('.').ok_or_else(|| err("METHOD needs an interface"))?;
            if !names::interface(iface) {
                return Err(err("invalid interface"));
            }
            if member != "*" {
                if !names::member(member) {
                    return Err(err("invalid method name"));
                }
                rule.member = Some(member.into());
            }
            rule.interface = Some(iface.into());
        }
        if let Some(p) = path {
            let (base, subtree) = match p.strip_suffix("/*") {
                Some(b) => (if b.is_empty() { "/" } else { b }, true),
                None => (p, false),
            };
            if !names::object_path(base) {
                return Err(err("invalid object path"));
            }
            rule.path = Some(base.into());
            rule.path_subtree = subtree;
        }
        Ok(rule)
    }

    fn matches(&self, path: Option<&str>, interface: Option<&str>, member: Option<&str>) -> bool {
        if let Some(want) = &self.path {
            let Some(path) = path else { return false };
            let ok = if !self.path_subtree {
                path == want
            } else if want == "/" {
                true
            } else {
                path.strip_prefix(want.as_str()).is_some_and(|r| r.is_empty() || r.starts_with('/'))
            };
            if !ok {
                return false;
            }
        }
        (self.interface.is_none() || self.interface.as_deref() == interface)
            && (self.member.is_none() || self.member.as_deref() == member)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Grant {
    Level(Level),
    Call(Rule),
    Broadcast(Rule),
}

/// Which of a name's messages a check is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Traffic {
    /// Calls (and unicast signals) the program sends to the name.
    Call,
    /// Signals the name broadcasts.
    Broadcast,
}

/// The rules for one proxy. An empty policy hides every name but the
/// bus's own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    entries: Vec<(Pattern, Grant)>,
}

impl Policy {
    pub fn new() -> Policy {
        Policy::default()
    }

    fn level(&mut self, name: &str, level: Level) -> Result<&mut Policy, PolicyError> {
        self.entries.push((Pattern::parse(name)?, Grant::Level(level)));
        Ok(self)
    }

    /// The program may see `name` (list it, look up its owner, follow its
    /// owner changing) but not call it.
    pub fn see(&mut self, name: &str) -> Result<&mut Policy, PolicyError> {
        self.level(name, Level::See)
    }

    /// The program may call `name` and gets the signals it broadcasts.
    pub fn talk(&mut self, name: &str) -> Result<&mut Policy, PolicyError> {
        self.level(name, Level::Talk)
    }

    /// The program may own `name`, and talk to it.
    pub fn own(&mut self, name: &str) -> Result<&mut Policy, PolicyError> {
        self.level(name, Level::Own)
    }

    /// The program may make the calls on `name` that `rule` matches.
    pub fn call(&mut self, name: &str, rule: &str) -> Result<&mut Policy, PolicyError> {
        let p = Pattern::parse(name)?;
        self.entries.push((p, Grant::Call(Rule::parse(rule)?)));
        Ok(self)
    }

    /// The program gets the broadcasts from `name` that `rule` matches.
    pub fn broadcast(&mut self, name: &str, rule: &str) -> Result<&mut Policy, PolicyError> {
        let p = Pattern::parse(name)?;
        self.entries.push((p, Grant::Broadcast(Rule::parse(rule)?)));
        Ok(self)
    }

    /// Adds one rule in xdg-dbus-proxy's command-line form: `--see=NAME`,
    /// `--talk=NAME`, `--own=NAME`, `--call=NAME=RULE` or
    /// `--broadcast=NAME=RULE`.
    pub fn add(&mut self, arg: &str) -> Result<&mut Policy, PolicyError> {
        let bad = || PolicyError(format!("{arg:?}: expected --see, --talk or --own=NAME, or --call or --broadcast=NAME=RULE"));
        let (key, value) = arg.strip_prefix("--").and_then(|a| a.split_once('=')).ok_or_else(bad)?;
        let pair = || value.split_once('=').ok_or_else(bad);
        match key {
            "see" => self.see(value),
            "talk" => self.talk(value),
            "own" => self.own(value),
            "call" => pair().and_then(|(n, r)| self.call(n, r)),
            "broadcast" => pair().and_then(|(n, r)| self.broadcast(n, r)),
            _ => Err(bad()),
        }
    }

    fn matching<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Grant> + 'a {
        self.entries.iter().filter(move |(p, _)| p.matches(name)).map(|(_, g)| g)
    }

    /// The level of a well-known name. A call or broadcast rule makes a
    /// name talkable (for what the rule matches).
    pub fn level_of(&self, name: &str) -> Level {
        self.matching(name)
            .map(|g| match g {
                Grant::Level(l) => *l,
                Grant::Call(_) | Grant::Broadcast(_) => Level::Talk,
            })
            .max()
            .unwrap_or(Level::None)
    }

    /// Whether a message to (`Call`) or broadcast from (`Broadcast`) the
    /// well-known `name` is allowed.
    pub(crate) fn allows(&self, name: &str, t: Traffic, path: Option<&str>, interface: Option<&str>, member: Option<&str>) -> bool {
        self.matching(name).any(|g| match (g, t) {
            (Grant::Level(l), _) => *l >= Level::Talk,
            (Grant::Call(r), Traffic::Call) | (Grant::Broadcast(r), Traffic::Broadcast) => r.matches(path, interface, member),
            _ => false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels() {
        let mut p = Policy::new();
        p.see("org.example.Seen").unwrap();
        p.talk("org.example.Talk.*").unwrap();
        p.own("org.example.Talk.Mine").unwrap();
        p.call("org.example.Calls", "org.example.Calls.Open@/org/example/*").unwrap();
        assert_eq!(p.level_of("org.example.Seen"), Level::See);
        assert_eq!(p.level_of("org.example.Seen.Sub"), Level::None);
        assert_eq!(p.level_of("org.example.Talk"), Level::Talk);
        assert_eq!(p.level_of("org.example.Talk.Any.Deeper"), Level::Talk);
        assert_eq!(p.level_of("org.example.TalkMore"), Level::None);
        assert_eq!(p.level_of("org.example.Talk.Mine"), Level::Own);
        assert_eq!(p.level_of("org.example.Calls"), Level::Talk);
        assert_eq!(p.level_of("org.example"), Level::None);

        let call = |n: &str, path: &str, i: &str, m: &str| p.allows(n, Traffic::Call, Some(path), Some(i), Some(m));
        assert!(call("org.example.Talk.X", "/", "a.b", "C"));
        assert!(!call("org.example.Seen", "/", "a.b", "C"));
        assert!(call("org.example.Calls", "/org/example", "org.example.Calls", "Open"));
        assert!(call("org.example.Calls", "/org/example/A/B", "org.example.Calls", "Open"));
        assert!(!call("org.example.Calls", "/org/examples", "org.example.Calls", "Open"));
        assert!(!call("org.example.Calls", "/org/example", "org.example.Calls", "Close"));
        assert!(!p.allows("org.example.Calls", Traffic::Call, Some("/org/example"), None, Some("Open")), "no interface");
        assert!(!p.allows("org.example.Calls", Traffic::Broadcast, Some("/org/example"), Some("org.example.Calls"), Some("Open")));
        assert!(p.allows("org.example.Talk.Mine", Traffic::Broadcast, Some("/"), Some("a.b"), Some("C")));
    }

    #[test]
    fn rules() {
        let r = Rule::parse("*").unwrap();
        assert!(r.matches(None, None, Some("X")));
        let r = Rule::parse("org.example.I.*").unwrap();
        assert!(r.matches(Some("/x"), Some("org.example.I"), Some("Any")));
        assert!(!r.matches(Some("/x"), Some("org.example.J"), Some("Any")));
        let r = Rule::parse("@/a/b").unwrap();
        assert!(r.matches(Some("/a/b"), Some("x.y"), Some("Z")));
        assert!(!r.matches(Some("/a/b/c"), Some("x.y"), Some("Z")));
        let r = Rule::parse("*@/*").unwrap();
        assert!(r.matches(Some("/anything/at/all"), None, Some("Z")));
        for bad in ["", "Open", "org.example.I.Op-en", "x@", "x.y.Z@a", "x.y.Z@/a/", "org..x.Y", "@/a//*"] {
            assert!(Rule::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn names() {
        let mut p = Policy::new();
        for bad in ["org", "org.*", ":1.2", "org.example.*.x", "*", "org.example.", "org.exa mple"] {
            assert!(p.talk(bad).is_err(), "{bad}");
        }
        assert!(p.add("--talk=org.example.A").is_ok());
        assert!(p.add("--call=org.example.B=org.example.B.Get@/").is_ok());
        assert!(p.add("--broadcast=org.example.B=*").is_ok());
        for bad in ["talk=x.y", "--call=org.example.B", "--listen=x.y", "--own"] {
            assert!(p.add(bad).is_err(), "{bad}");
        }
        assert_eq!(p.level_of("org.example.A"), Level::Talk);
    }
}
