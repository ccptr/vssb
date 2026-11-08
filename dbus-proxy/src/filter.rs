//! The filter for one connection, without any I/O: messages go in from
//! either side, and come out as messages for the bus, messages for the
//! program and events.
//!
//! What it keeps track of:
//!
//! - which unique name owns each well-known name the policy covers (from
//!   a `ListNames` and `GetNameOwner` snapshot taken right after `Hello`,
//!   then `NameOwnerChanged`), because programs call services by their
//!   unique name. The program's own messages wait until the snapshot is
//!   complete;
//! - the unique names the program may see: its own (which it may also
//!   call), and those that sent it something;
//! - the calls in flight each way, so that only replies to them pass.
//!
//! The proxy numbers every message it sends to the bus itself, the
//! program's included, so its own calls never collide with the program's;
//! replies get the program's serial back.

use crate::policy::{Level, Policy, Traffic};
use crate::wire::{self, Body, Field, Kind, Message, NO_AUTO_START};
use crate::{Denied, Event, Reason};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

pub(crate) const BUS: &str = "org.freedesktop.DBus";
const BUS_PATH: &str = "/org/freedesktop/DBus";
const NAME_OWNER_CHANGED: &str =
    "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged',path='/org/freedesktop/DBus'";

/// Calls in flight, each way, before the proxy refuses more.
const MAX_PENDING: usize = 16384;

const ACCESS_DENIED: &str = "org.freedesktop.DBus.Error.AccessDenied";
const SERVICE_UNKNOWN: &str = "org.freedesktop.DBus.Error.ServiceUnknown";
const NAME_HAS_NO_OWNER: &str = "org.freedesktop.DBus.Error.NameHasNoOwner";
const LIMITS_EXCEEDED: &str = "org.freedesktop.DBus.Error.LimitsExceeded";

pub(crate) enum Out {
    Bus(Message),
    Client(Message),
    Event(Event),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reply {
    Normal,
    Hello,
    /// `ListNames` or `ListActivatableNames`: the names get filtered.
    Names,
}

enum Pending {
    Client { serial: u32, reply: Reply },
    AddMatch,
    ListNames,
    GetNameOwner(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Nothing yet from the program; its first message must be `Hello`.
    Start,
    /// `Hello` sent, waiting for the reply.
    Hello,
    /// Taking the snapshot of owners; this many replies outstanding.
    Sync(usize),
    Running,
}

enum Verdict {
    Allow,
    /// Visible, but not this message.
    Deny,
    /// Not visible at all.
    Hide,
}

pub(crate) struct Filter {
    policy: Arc<Policy>,
    conn: u64,
    /// The program negotiated descriptor passing.
    unix_fds: bool,
    phase: Phase,
    unique: Option<String>,
    /// Well-known name → its owner, for names the policy shows.
    owner: HashMap<String, String>,
    /// Unique name → the names above it owns.
    owned: HashMap<String, BTreeSet<String>>,
    /// Unique names the program may see (`See`) or call (`Talk`, its own).
    seen: HashMap<String, Level>,
    /// Our serial on the bus → what the reply is for.
    pending: HashMap<u32, Pending>,
    /// Calls to the program it may answer: (caller, serial).
    replies: HashSet<(String, u32)>,
    serial: u32,
    /// Serials of the replies the proxy makes up for the program.
    made_up: u32,
}

type Res = Result<(), String>;

impl Filter {
    pub fn new(policy: Arc<Policy>, conn: u64, unix_fds: bool) -> Filter {
        Filter {
            policy,
            conn,
            unix_fds,
            phase: Phase::Start,
            unique: None,
            owner: HashMap::new(),
            owned: HashMap::new(),
            seen: HashMap::new(),
            pending: HashMap::new(),
            replies: HashSet::new(),
            serial: 0,
            made_up: 0x8000_0000,
        }
    }

    /// While the snapshot of owners is being taken, the program's messages
    /// wait (unread).
    pub fn client_paused(&self) -> bool {
        matches!(self.phase, Phase::Hello | Phase::Sync(_))
    }

    fn next_serial(&mut self) -> u32 {
        self.serial = self.serial.wrapping_add(1).max(1);
        self.serial
    }

    fn level(&self, name: &str) -> Level {
        if name == BUS {
            return Level::Talk;
        }
        if name.starts_with(':') {
            let mut l = self.seen.get(name).copied().unwrap_or(Level::None);
            for n in self.owned.get(name).into_iter().flatten() {
                l = l.max(self.policy.level_of(n));
            }
            return l;
        }
        self.policy.level_of(name)
    }

    fn allows(&self, name: &str, t: Traffic, m: &Message) -> bool {
        let (p, i, mb) = (m.path.as_deref(), m.interface.as_deref(), m.member.as_deref());
        if name.starts_with(':') {
            self.seen.get(name).is_some_and(|l| *l >= Level::Talk)
                || self.owned.get(name).is_some_and(|ns| ns.iter().any(|n| self.policy.allows(n, t, p, i, mb)))
        } else {
            self.policy.allows(name, t, p, i, mb)
        }
    }

    fn verdict(&self, dest: &str, m: &Message) -> Verdict {
        match self.level(dest) {
            Level::None => Verdict::Hide,
            Level::See => Verdict::Deny,
            _ if self.allows(dest, Traffic::Call, m) => Verdict::Allow,
            _ => Verdict::Deny,
        }
    }

    // --- from the program ---

    pub fn on_client(&mut self, m: Message, out: &mut Vec<Out>) -> Res {
        if self.phase == Phase::Start {
            let hello = m.kind == Kind::Call && m.destination.as_deref() == Some(BUS) && m.is(BUS, "Hello");
            if !hello || !m.expects_reply() {
                return Err("the program's first message was not Hello".into());
            }
            self.phase = Phase::Hello;
            return self.forward(m, Reply::Hello, out);
        }
        match m.kind {
            Kind::Return | Kind::Error => {
                let key = (m.destination.clone().unwrap_or_default(), m.reply_serial.unwrap_or_default());
                if self.replies.remove(&key) {
                    self.forward(m, Reply::Normal, out)
                } else {
                    self.refuse(&m, Reason::Unrequested, None, out)
                }
            }
            Kind::Signal => match m.destination.clone() {
                None => self.forward(m, Reply::Normal, out),
                Some(d) => match self.verdict(&d, &m) {
                    Verdict::Allow => self.forward(m, Reply::Normal, out),
                    Verdict::Deny => self.refuse(&m, Reason::NotAllowed, None, out),
                    Verdict::Hide => self.refuse(&m, Reason::Hidden, None, out),
                },
            },
            Kind::Call => {
                let Some(d) = m.destination.clone() else {
                    return self.refuse(&m, Reason::NoDestination, None, out);
                };
                if d == BUS {
                    return self.bus_call(m, out);
                }
                match self.verdict(&d, &m) {
                    Verdict::Allow => self.forward(m, Reply::Normal, out),
                    Verdict::Deny => self.refuse(&m, Reason::NotAllowed, None, out),
                    Verdict::Hide => self.refuse(&m, Reason::Hidden, None, out),
                }
            }
        }
    }

    fn bus_call(&mut self, m: Message, out: &mut Vec<Out>) -> Res {
        let iface = m.interface.as_deref().unwrap_or("");
        let member = m.member.as_deref().unwrap_or("");
        let arg0 = m.arg0().map(str::to_string);
        // Calls about a name: the least level the program needs on it.
        let needs = |l: Level| match &arg0 {
            Some(n) => self.level(n) >= l,
            None => false,
        };
        match (iface, member) {
            (BUS, "Hello" | "GetId" | "RemoveMatch")
            | ("org.freedesktop.DBus.Introspectable", "Introspect")
            | ("org.freedesktop.DBus.Peer", "Ping" | "GetMachineId")
            | ("org.freedesktop.DBus.Properties", "Get" | "GetAll") => self.forward(m, Reply::Normal, out),
            (BUS, "ListNames" | "ListActivatableNames") => self.forward(m, Reply::Names, out),
            (BUS, "AddMatch") => match &arg0 {
                Some(rule) if !rule.contains("eavesdrop") => self.forward(m, Reply::Normal, out),
                _ => self.refuse(&m, Reason::Eavesdrop, arg0.clone(), out),
            },
            (BUS, "RequestName" | "ReleaseName" | "ListQueuedOwners") => {
                if needs(Level::Own) {
                    self.forward(m, Reply::Normal, out)
                } else {
                    self.refuse(&m, Reason::NotOwner, arg0.clone(), out)
                }
            }
            (BUS, "NameHasOwner") => {
                if needs(Level::See) {
                    return self.forward(m, Reply::Normal, out);
                }
                self.event(&m, Reason::Hidden, arg0, out);
                let mut body = Body::default();
                body.bool(false);
                self.answer(&m, Kind::Return, None, "b", &body, out)
            }
            (
                BUS,
                "GetNameOwner"
                | "GetConnectionUnixUser"
                | "GetConnectionUnixProcessID"
                | "GetConnectionCredentials"
                | "GetAdtAuditSessionData"
                | "GetConnectionSELinuxSecurityContext"
                | "GetConnectionAppArmorSecurityContext",
            ) => {
                if needs(Level::See) {
                    return self.forward(m, Reply::Normal, out);
                }
                let name = arg0.clone().unwrap_or_default();
                self.event(&m, Reason::Hidden, arg0, out);
                let text = format!("Could not get owner of name '{name}': no such name");
                self.error(&m, NAME_HAS_NO_OWNER, &text, out)
            }
            (BUS, "StartServiceByName") => {
                if needs(Level::Talk) {
                    self.forward(m, Reply::Normal, out)
                } else if needs(Level::See) {
                    self.refuse(&m, Reason::NotAllowed, arg0.clone(), out)
                } else {
                    self.refuse(&m, Reason::Hidden, arg0.clone(), out)
                }
            }
            _ => self.refuse(&m, Reason::BusMethod, arg0.clone(), out),
        }
    }

    /// Sends a message of the program's on to the bus, renumbered.
    fn forward(&mut self, mut m: Message, reply: Reply, out: &mut Vec<Out>) -> Res {
        if m.expects_reply() {
            if self.pending.len() >= MAX_PENDING {
                self.event(&m, Reason::Limit, None, out);
                return self.error(&m, LIMITS_EXCEEDED, "Too many calls in flight", out);
            }
            let serial = m.serial;
            m.set_serial(self.next_serial());
            self.pending.insert(m.serial, Pending::Client { serial, reply });
        } else {
            m.set_serial(self.next_serial());
        }
        out.push(Out::Bus(m));
        Ok(())
    }

    fn event(&self, m: &Message, reason: Reason, name: Option<String>, out: &mut Vec<Out>) {
        let denied = Denied {
            kind: m.kind,
            destination: m.destination.clone(),
            path: m.path.clone(),
            interface: m.interface.clone(),
            member: m.member.clone(),
            name,
            reason,
        };
        out.push(Out::Event(Event::Deny { conn: self.conn, denied }));
    }

    /// Drops a message of the program's, reporting it, and answers it with
    /// the error the bus would give if it expects an answer.
    fn refuse(&mut self, m: &Message, reason: Reason, name: Option<String>, out: &mut Vec<Out>) -> Res {
        self.event(m, reason, name.clone(), out);
        if !m.expects_reply() {
            return Ok(());
        }
        let what = name.or_else(|| m.destination.clone()).unwrap_or_default();
        let (error, text) = match reason {
            Reason::Hidden if what.starts_with(':') || m.flags & NO_AUTO_START != 0 => {
                (NAME_HAS_NO_OWNER, format!("The name {what} does not exist"))
            }
            Reason::Hidden => (SERVICE_UNKNOWN, format!("The name {what} was not provided by any .service files")),
            _ => (ACCESS_DENIED, format!("The sandbox's D-Bus filter does not allow this ({})", reason.text())),
        };
        self.error(m, error, &text, out)
    }

    fn error(&mut self, m: &Message, name: &str, text: &str, out: &mut Vec<Out>) -> Res {
        if !m.expects_reply() {
            return Ok(());
        }
        let mut body = Body::default();
        body.str(text);
        self.answer(m, Kind::Error, Some(name), "s", &body, out)
    }

    /// A reply to the program's call `m`, made up as if the bus sent it.
    fn answer(&mut self, m: &Message, kind: Kind, error: Option<&str>, sig: &str, body: &Body, out: &mut Vec<Out>) -> Res {
        self.made_up = self.made_up.wrapping_add(1).max(1);
        let mut fields = vec![Field::ReplySerial(m.serial), Field::Sender(BUS)];
        if let Some(u) = &self.unique {
            fields.push(Field::Destination(u));
        }
        if let Some(e) = error {
            fields.push(Field::ErrorName(e));
        }
        let r = wire::build(kind, wire::NO_REPLY_EXPECTED, self.made_up, &fields, sig, body).map_err(|e| e.to_string())?;
        out.push(Out::Client(r));
        Ok(())
    }

    // --- from the bus ---

    pub fn on_bus(&mut self, mut m: Message, out: &mut Vec<Out>) -> Res {
        if let Some(rs) = m.reply_serial {
            // Replies to anything but our calls in flight are dropped.
            let Some(p) = self.pending.remove(&rs) else { return Ok(()) };
            let (serial, reply) = match p {
                Pending::Client { serial, reply } => (serial, reply),
                internal => return self.internal_reply(internal, &m, out),
            };
            if reply == Reply::Hello {
                if m.kind != Kind::Return {
                    return Err("the bus refused Hello".into());
                }
                self.hello(&m, out)?;
            } else if reply == Reply::Names && m.kind == Kind::Return {
                m = self.filter_names(&m)?;
            }
            m.set_reply_serial(serial);
            return self.deliver(m, out);
        }
        match m.destination.as_deref() {
            Some(d) => {
                // Only what the bus routes to us; anything else (as a
                // monitor would get) never reaches the program.
                if !self.is_ours(d) {
                    return Ok(());
                }
                if m.expects_reply()
                    && let Some(s) = &m.sender
                    && self.replies.len() < MAX_PENDING
                {
                    self.replies.insert((s.clone(), m.serial));
                }
                self.deliver(m, out)
            }
            None if m.kind == Kind::Signal => {
                let Some(sender) = m.sender.clone() else { return Ok(()) };
                if sender == BUS {
                    if m.is(BUS, "NameOwnerChanged") && m.signature == "sss" {
                        let Some(args) = m.strings(3) else { return Ok(()) };
                        let (name, old, new) = (args[0].to_string(), args[1].to_string(), args[2].to_string());
                        let show = self.level(&name) >= Level::See;
                        self.owner_changed(&name, &old, &new);
                        return if show { self.deliver(m, out) } else { Ok(()) };
                    }
                    return self.deliver(m, out);
                }
                if self.allows(&sender, Traffic::Broadcast, &m) { self.deliver(m, out) } else { Ok(()) }
            }
            None => Ok(()),
        }
    }

    fn is_ours(&self, dest: &str) -> bool {
        let Some(u) = &self.unique else { return false };
        dest == u || self.owner.get(dest) == Some(u)
    }

    /// Passes a message on to the program; its sender becomes visible.
    fn deliver(&mut self, m: Message, out: &mut Vec<Out>) -> Res {
        if !m.fds.is_empty() && !self.unix_fds {
            // The program can't take descriptors; the bus may not know that.
            self.event(&m, Reason::Descriptors, None, out);
            return Ok(());
        }
        if let Some(s) = &m.sender
            && s.starts_with(':')
        {
            self.seen.entry(s.clone()).or_insert(Level::See);
        }
        out.push(Out::Client(m));
        Ok(())
    }

    fn hello(&mut self, m: &Message, out: &mut Vec<Out>) -> Res {
        let unique = m.arg0().filter(|u| crate::names::unique(u)).ok_or("the bus's reply to Hello has no unique name")?;
        self.unique = Some(unique.to_string());
        self.seen.insert(unique.to_string(), Level::Talk);
        out.push(Out::Event(Event::Connect { conn: self.conn, unique: unique.to_string() }));
        // The match comes first, so no change after the list is missed.
        let mut body = Body::default();
        body.str(NAME_OWNER_CHANGED);
        self.bus_method("AddMatch", "s", &body, Pending::AddMatch, out)?;
        self.bus_method("ListNames", "", &Body::default(), Pending::ListNames, out)?;
        self.phase = Phase::Sync(2);
        Ok(())
    }

    fn bus_method(&mut self, member: &str, sig: &str, body: &Body, p: Pending, out: &mut Vec<Out>) -> Res {
        let serial = self.next_serial();
        let fields = [Field::Path(BUS_PATH), Field::Interface(BUS), Field::Member(member), Field::Destination(BUS)];
        let m = wire::build(Kind::Call, 0, serial, &fields, sig, body).map_err(|e| e.to_string())?;
        self.pending.insert(serial, p);
        out.push(Out::Bus(m));
        Ok(())
    }

    fn internal_reply(&mut self, p: Pending, m: &Message, out: &mut Vec<Out>) -> Res {
        let Phase::Sync(left) = self.phase else { return Ok(()) };
        let mut left = left - 1;
        match p {
            Pending::AddMatch if m.kind != Kind::Return => return Err("the bus refused the filter's match rule".into()),
            Pending::ListNames => {
                let names = m.string_array().ok_or("the bus's ListNames reply is not a list of names")?;
                let wanted: Vec<String> =
                    names.into_iter().filter(|n| !n.starts_with(':') && self.policy.level_of(n) >= Level::See).map(String::from).collect();
                for n in wanted {
                    let mut body = Body::default();
                    body.str(&n);
                    self.bus_method("GetNameOwner", "s", &body, Pending::GetNameOwner(n), out)?;
                    left += 1;
                }
            }
            Pending::GetNameOwner(name) => {
                // An error: the name went away meanwhile.
                if m.kind == Kind::Return
                    && let Some(owner) = m.arg0().filter(|o| crate::names::unique(o))
                {
                    let owner = owner.to_string();
                    self.set_owner(&name, Some(&owner));
                }
            }
            _ => {}
        }
        self.phase = if left == 0 { Phase::Running } else { Phase::Sync(left) };
        Ok(())
    }

    fn set_owner(&mut self, name: &str, new: Option<&str>) {
        if let Some(prev) = self.owner.remove(name)
            && let Some(s) = self.owned.get_mut(&prev)
        {
            s.remove(name);
            if s.is_empty() {
                self.owned.remove(&prev);
            }
        }
        if let Some(n) = new {
            self.owner.insert(name.into(), n.into());
            self.owned.entry(n.into()).or_default().insert(name.into());
        }
    }

    fn owner_changed(&mut self, name: &str, _old: &str, new: &str) {
        if name.starts_with(':') {
            if new.is_empty() {
                self.seen.remove(name);
                self.owned.remove(name);
                self.replies.retain(|(s, _)| s != name);
            }
            return;
        }
        if self.policy.level_of(name) < Level::See {
            return;
        }
        self.set_owner(name, if new.is_empty() { None } else { Some(new) });
    }

    /// A `ListNames` reply with only the names the program may see.
    fn filter_names(&self, m: &Message) -> Result<Message, String> {
        let Some(names) = m.string_array() else { return Err("the bus's ListNames reply is not a list of names".into()) };
        let keep: Vec<&str> = names.into_iter().filter(|n| self.level(n) >= Level::See).collect();
        let mut body = Body::default();
        body.strs(&keep);
        let mut fields = vec![Field::ReplySerial(m.reply_serial.unwrap_or(1))];
        if let Some(d) = &m.destination {
            fields.push(Field::Destination(d));
        }
        if let Some(s) = &m.sender {
            fields.push(Field::Sender(s));
        }
        wire::build(Kind::Return, m.flags, m.serial, &fields, "as", &body).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = ":1.7";

    fn call(serial: u32, dest: &str, iface: &str, member: &str, args: &[&str]) -> Message {
        let mut body = Body::default();
        for a in args {
            body.str(a);
        }
        let sig = "s".repeat(args.len());
        let f = [Field::Path("/x"), Field::Interface(iface), Field::Member(member), Field::Destination(dest)];
        wire::build(Kind::Call, 0, serial, &f, &sig, &body).unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn from(sender: &str, kind: Kind, serial: u32, reply_to: Option<u32>, dest: Option<&str>, iface: &str, member: &str, args: &[&str]) -> Message {
        let mut body = Body::default();
        for a in args {
            body.str(a);
        }
        let mut f = vec![Field::Sender(sender)];
        if let Some(r) = reply_to {
            f.push(Field::ReplySerial(r));
        }
        if let Some(d) = dest {
            f.push(Field::Destination(d));
        }
        if matches!(kind, Kind::Call | Kind::Signal) {
            f.extend([Field::Path("/x"), Field::Interface(iface), Field::Member(member)]);
        }
        if kind == Kind::Error {
            f.push(Field::ErrorName("org.example.Error"));
        }
        wire::build(kind, 0, serial, &f, &"s".repeat(args.len()), &body).unwrap()
    }

    fn names_reply(reply_to: u32, names: &[&str]) -> Message {
        let mut body = Body::default();
        body.strs(names);
        let f = [Field::Sender(BUS), Field::ReplySerial(reply_to), Field::Destination(ME)];
        wire::build(Kind::Return, 0, 99, &f, "as", &body).unwrap()
    }

    struct T {
        f: Filter,
        out: Vec<Out>,
    }

    impl T {
        /// A filter past Hello and the snapshot, in which `owners` own
        /// their names.
        fn new(p: Policy, owners: &[(&str, &str)]) -> T {
            let mut t = T { f: Filter::new(Arc::new(p), 1, true), out: vec![] };
            t.client(call(1, BUS, BUS, "Hello", &[]));
            assert!(t.f.client_paused());
            let hello = t.bus_msgs().pop().unwrap();
            t.bus(from(BUS, Kind::Return, 1, Some(hello.serial), Some(ME), "", "", &[ME]));
            let sync = t.bus_msgs();
            assert_eq!(sync.len(), 2);
            assert_eq!(sync[0].arg0(), Some(NAME_OWNER_CHANGED));
            t.bus(from(BUS, Kind::Return, 2, Some(sync[0].serial), Some(ME), "", "", &[]));
            let mut listed: Vec<&str> = owners.iter().map(|o| o.0).collect();
            listed.extend(["org.example.Hidden", ":1.1"]);
            t.bus(names_reply(sync[1].serial, &listed));
            let lookups = t.bus_msgs();
            for l in &lookups {
                let name = l.arg0().unwrap();
                let owner = owners.iter().find(|o| o.0 == name).map(|o| o.1).unwrap();
                t.bus(from(BUS, Kind::Return, 3, Some(l.serial), Some(ME), "", "", &[owner]));
            }
            assert!(!t.f.client_paused());
            t.out.clear();
            t
        }

        fn client(&mut self, m: Message) {
            self.f.on_client(m, &mut self.out).unwrap();
        }

        fn bus(&mut self, m: Message) {
            self.f.on_bus(m, &mut self.out).unwrap();
        }

        fn bus_msgs(&mut self) -> Vec<Message> {
            let mut v = vec![];
            for o in self.out.drain(..) {
                if let Out::Bus(m) = o {
                    v.push(m);
                }
            }
            v
        }

        fn take(&mut self) -> (Vec<Message>, Vec<Message>, Vec<Event>) {
            let (mut b, mut c, mut e) = (vec![], vec![], vec![]);
            for o in self.out.drain(..) {
                match o {
                    Out::Bus(m) => b.push(m),
                    Out::Client(m) => c.push(m),
                    Out::Event(ev) => e.push(ev),
                }
            }
            (b, c, e)
        }

        /// Sends a call and says what happened: "pass", or the error name.
        fn try_call(&mut self, m: Message) -> String {
            self.client(m);
            let (b, c, _) = self.take();
            match (b.len(), c.first()) {
                (1, None) => "pass".into(),
                (0, Some(r)) if r.kind == Kind::Error => r.error_name.clone().unwrap(),
                (0, Some(r)) => format!("reply {:?}", r.signature),
                _ => "?".into(),
            }
        }
    }

    fn policy() -> Policy {
        let mut p = Policy::new();
        p.talk("org.example.Talk").unwrap();
        p.see("org.example.See").unwrap();
        p.see("org.example.Look").unwrap();
        p.own("org.example.Mine.*").unwrap();
        p.call("org.example.Some", "org.example.Some.Get@/x").unwrap();
        p.broadcast("org.example.See", "org.example.See.Changed").unwrap();
        p
    }

    fn owners() -> Vec<(&'static str, &'static str)> {
        vec![("org.example.Talk", ":1.2"), ("org.example.See", ":1.3"), ("org.example.Some", ":1.4")]
    }

    #[test]
    fn first_message_must_be_hello() {
        let mut f = Filter::new(Arc::new(Policy::new()), 1, true);
        let mut out = vec![];
        assert!(f.on_client(call(1, BUS, BUS, "ListNames", &[]), &mut out).is_err());
    }

    #[test]
    fn calls() {
        let mut t = T::new(policy(), &owners());
        assert_eq!(t.try_call(call(10, "org.example.Talk", "a.b", "C", &[])), "pass");
        assert_eq!(t.try_call(call(11, ":1.2", "a.b", "C", &[])), "pass", "by its unique name");
        assert_eq!(t.try_call(call(12, "org.example.See", "a.b", "C", &[])), ACCESS_DENIED);
        assert_eq!(t.try_call(call(13, ":1.3", "a.b", "C", &[])), ACCESS_DENIED);
        assert_eq!(t.try_call(call(14, "org.example.Hidden", "a.b", "C", &[])), SERVICE_UNKNOWN);
        assert_eq!(t.try_call(call(15, ":1.1", "a.b", "C", &[])), NAME_HAS_NO_OWNER);
        assert_eq!(t.try_call(call(16, "org.example.Some", "org.example.Some", "Get", &[])), "pass");
        assert_eq!(t.try_call(call(17, ":1.4", "org.example.Some", "Get", &[])), "pass");
        assert_eq!(t.try_call(call(18, ":1.4", "org.example.Some", "Set", &[])), ACCESS_DENIED);
        assert_eq!(t.try_call(call(19, ME, "a.b", "C", &[])), "pass", "itself");

        // The error answers the program's serial, from the bus, to it.
        t.client(call(20, "org.example.Hidden", "a.b", "C", &[]));
        let (_, c, e) = t.take();
        assert_eq!((c[0].reply_serial, c[0].sender.as_deref(), c[0].destination.as_deref()), (Some(20), Some(BUS), Some(ME)));
        assert!(matches!(&e[0], Event::Deny { denied, .. } if denied.reason == Reason::Hidden));
    }

    #[test]
    fn replies_come_back_renumbered() {
        let mut t = T::new(policy(), &owners());
        t.client(call(5, "org.example.Talk", "a.b", "C", &[]));
        let sent = t.bus_msgs().pop().unwrap();
        assert_ne!(sent.serial, 5);
        t.bus(from(":1.2", Kind::Return, 40, Some(sent.serial), Some(ME), "", "", &[]));
        let (_, c, _) = t.take();
        assert_eq!(c[0].reply_serial, Some(5));
        // Once only, and nothing the program didn't ask for.
        t.bus(from(":1.2", Kind::Return, 41, Some(sent.serial), Some(ME), "", "", &[]));
        t.bus(from(":1.2", Kind::Error, 42, Some(12345), Some(ME), "", "", &[]));
        assert!(t.take().1.is_empty());
    }

    #[test]
    fn program_answers_only_calls_it_got() {
        let mut t = T::new(policy(), &owners());
        t.bus(from(":1.9", Kind::Call, 8, None, Some(ME), "a.b", "C", &[]));
        let (_, c, _) = t.take();
        assert_eq!(c.len(), 1);
        let reply = |dest: &str, to: u32| from(ME, Kind::Return, 3, Some(to), Some(dest), "", "", &[]);
        t.client(reply(":1.9", 8));
        assert_eq!(t.take().0.len(), 1);
        t.client(reply(":1.9", 8));
        t.client(reply(":1.2", 9));
        let (b, _, e) = t.take();
        assert!(b.is_empty());
        assert_eq!(e.len(), 2);
        // A caller may now be seen, not called.
        assert_eq!(t.try_call(call(30, ":1.9", "a.b", "C", &[])), ACCESS_DENIED);
    }

    #[test]
    fn bus_methods() {
        let mut t = T::new(policy(), &owners());
        let bus = |s: u32, m: &str, args: &[&str]| call(s, BUS, BUS, m, args);
        assert_eq!(t.try_call(bus(1, "RequestName", &["org.example.Mine.App"])), "pass");
        assert_eq!(t.try_call(bus(2, "RequestName", &["org.example.Talk"])), ACCESS_DENIED);
        assert_eq!(t.try_call(bus(3, "GetNameOwner", &["org.example.See"])), "pass");
        assert_eq!(t.try_call(bus(4, "GetNameOwner", &["org.example.Hidden"])), NAME_HAS_NO_OWNER);
        assert_eq!(t.try_call(bus(5, "NameHasOwner", &["org.example.Hidden"])), "reply \"b\"");
        assert_eq!(t.try_call(bus(6, "AddMatch", &["type='signal'"])), "pass");
        assert_eq!(t.try_call(bus(7, "AddMatch", &["type='method_call',eavesdrop=true"])), ACCESS_DENIED);
        assert_eq!(t.try_call(bus(8, "UpdateActivationEnvironment", &[])), ACCESS_DENIED);
        assert_eq!(t.try_call(call(9, BUS, "org.freedesktop.DBus.Monitoring", "BecomeMonitor", &[])), ACCESS_DENIED);
        assert_eq!(t.try_call(bus(10, "StartServiceByName", &["org.example.Look"])), ACCESS_DENIED);
        assert_eq!(t.try_call(bus(11, "StartServiceByName", &["org.example.Gone"])), SERVICE_UNKNOWN);
        assert_eq!(t.try_call(bus(12, "GetConnectionUnixProcessID", &[":1.2"])), "pass");
        assert_eq!(t.try_call(bus(13, "GetConnectionUnixProcessID", &[":1.1"])), NAME_HAS_NO_OWNER);
        assert_eq!(t.try_call(call(14, BUS, "org.freedesktop.DBus.Peer", "Ping", &[])), "pass");
    }

    #[test]
    fn list_names_is_filtered() {
        let mut t = T::new(policy(), &owners());
        t.client(call(3, BUS, BUS, "ListNames", &[]));
        let sent = t.bus_msgs().pop().unwrap();
        t.bus(names_reply(sent.serial, &[BUS, ME, ":1.1", ":1.2", "org.example.Talk", "org.example.Hidden", "org.example.See"]));
        let (_, c, _) = t.take();
        assert_eq!(c[0].reply_serial, Some(3));
        assert_eq!(c[0].string_array().unwrap(), vec![BUS, ME, ":1.2", "org.example.Talk", "org.example.See"]);
    }

    #[test]
    fn owners_are_followed() {
        let mut t = T::new(policy(), &owners());
        let noc = |name: &str, old: &str, new: &str| from(BUS, Kind::Signal, 50, None, None, BUS, "NameOwnerChanged", &[name, old, new]);
        // org.example.Talk moves from :1.2 to :1.5.
        t.bus(noc("org.example.Talk", ":1.2", ""));
        t.bus(noc("org.example.Talk", "", ":1.5"));
        assert_eq!(t.take().1.len(), 2, "visible names' changes reach the program");
        assert_eq!(t.try_call(call(1, ":1.2", "a.b", "C", &[])), NAME_HAS_NO_OWNER);
        assert_eq!(t.try_call(call(2, ":1.5", "a.b", "C", &[])), "pass");
        // A hidden name's change does not reach it, nor does its owner become callable.
        t.bus(noc("org.example.Hidden", "", ":1.6"));
        assert!(t.take().1.is_empty());
        assert_eq!(t.try_call(call(3, ":1.6", "a.b", "C", &[])), NAME_HAS_NO_OWNER);
        // A name under an own wildcard, acquired by the program, routes to it.
        t.bus(noc("org.example.Mine.App", "", ME));
        t.take();
        t.bus(from(":1.6", Kind::Call, 4, None, Some("org.example.Mine.App"), "a.b", "C", &[]));
        assert_eq!(t.take().1.len(), 1);
        // Messages routed to someone else (as eavesdropping would) are dropped.
        t.bus(from(":1.6", Kind::Call, 5, None, Some(":1.2"), "a.b", "C", &[]));
        t.bus(from(":1.6", Kind::Call, 6, None, Some("org.example.Talk"), "a.b", "C", &[]));
        assert!(t.take().1.is_empty());
    }

    #[test]
    fn broadcasts() {
        let mut t = T::new(policy(), &owners());
        let signal = |sender: &str, iface: &str, member: &str| from(sender, Kind::Signal, 60, None, None, iface, member, &[]);
        t.bus(signal(":1.2", "a.b", "Any"));
        t.bus(signal(":1.3", "org.example.See", "Changed"));
        t.bus(signal(":1.3", "org.example.See", "Other"));
        t.bus(signal(":1.1", "a.b", "Any"));
        t.bus(signal(":1.4", "org.example.Some", "Get"));
        let got: Vec<String> = t.take().1.iter().map(|m| m.sender.clone().unwrap() + " " + m.member.as_deref().unwrap()).collect();
        assert_eq!(got, [":1.2 Any", ":1.3 Changed"]);
    }

    #[test]
    fn descriptors_need_negotiating() {
        let mut t = T::new(policy(), &owners());
        t.f.unix_fds = false;
        let mut m = from(":1.2", Kind::Call, 8, None, Some(ME), "a.b", "C", &[]);
        let (r, _w) = std::io::pipe().unwrap();
        m.fds.push(r.into());
        t.bus(m);
        let (_, c, e) = t.take();
        assert!(c.is_empty());
        assert!(matches!(&e[0], Event::Deny { denied, .. } if denied.reason == Reason::Descriptors));
    }
}
