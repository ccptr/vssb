//! The D-Bus message format, as far as the filter needs it: reading and
//! checking a whole header, reading the leading string arguments of a
//! body, rewriting serials in place, and building the few messages the
//! filter makes up itself (always little-endian).
//!
//! Headers are checked at least as strictly as dbus-daemon checks them,
//! so the filter never reads a header differently from the bus: a field
//! given twice, a value of the wrong type, non-zero padding, a bad name
//! or a missing required field makes the message (and the connection)
//! invalid.

use crate::names;
use std::fmt;
use std::os::fd::OwnedFd;

/// The largest message the proxy carries (the specification allows
/// 128 MiB; real messages are far smaller, and big data goes in a
/// descriptor).
pub const MAX_MESSAGE: usize = 32 << 20;
/// The most descriptors one message may carry (`SCM_MAX_FD`).
pub const MAX_FDS: u32 = 253;

pub const NO_REPLY_EXPECTED: u8 = 0x1;
pub const NO_AUTO_START: u8 = 0x2;

const PATH: u8 = 1;
const INTERFACE: u8 = 2;
const MEMBER: u8 = 3;
const ERROR_NAME: u8 = 4;
const REPLY_SERIAL: u8 = 5;
const DESTINATION: u8 = 6;
const SENDER: u8 = 7;
const SIGNATURE: u8 = 8;
const UNIX_FDS: u8 = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Call,
    Return,
    Error,
    Signal,
}

impl Kind {
    fn code(self) -> u8 {
        match self {
            Kind::Call => 1,
            Kind::Return => 2,
            Kind::Error => 3,
            Kind::Signal => 4,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Kind::Call => "call",
            Kind::Return => "return",
            Kind::Error => "error",
            Kind::Signal => "signal",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError(pub &'static str);

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid D-Bus message: {}", self.0)
    }
}

type R<T> = Result<T, WireError>;

fn bad<T>(why: &'static str) -> R<T> {
    Err(WireError(why))
}

fn align(n: usize, a: usize) -> usize {
    n.div_ceil(a) * a
}

fn alignment(t: u8) -> usize {
    match t {
        b'y' | b'g' | b'v' => 1,
        b'n' | b'q' => 2,
        b'x' | b't' | b'd' | b'(' | b'{' => 8,
        _ => 4,
    }
}

const BASIC: &[u8] = b"ybnqiuxtdhsog";

/// The end of the single complete type that starts at `s[i]`.
fn complete_type(s: &[u8], i: usize, arrays: u32, structs: u32) -> R<usize> {
    match s.get(i) {
        None => bad("incomplete signature"),
        Some(c) if BASIC.contains(c) || *c == b'v' => Ok(i + 1),
        Some(b'a') => {
            if arrays >= 32 {
                return bad("arrays nested too deep");
            }
            if s.get(i + 1) == Some(&b'{') {
                if structs >= 32 {
                    return bad("structs nested too deep");
                }
                if !s.get(i + 2).is_some_and(|k| BASIC.contains(k)) {
                    return bad("dict key is not a basic type");
                }
                let end = complete_type(s, i + 3, arrays + 1, structs + 1)?;
                if s.get(end) != Some(&b'}') {
                    return bad("dict entry has more than two types");
                }
                Ok(end + 1)
            } else {
                complete_type(s, i + 1, arrays + 1, structs)
            }
        }
        Some(b'(') => {
            if structs >= 32 {
                return bad("structs nested too deep");
            }
            let mut j = i + 1;
            if s.get(j) == Some(&b')') {
                return bad("empty struct");
            }
            while s.get(j) != Some(&b')') {
                j = complete_type(s, j, arrays, structs + 1)?;
            }
            Ok(j + 1)
        }
        Some(_) => bad("invalid type in signature"),
    }
}

/// Whether `s` is a valid signature (any number of complete types).
pub fn signature_ok(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() > 255 {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        match complete_type(b, i, 0, 0) {
            Ok(j) => i = j,
            Err(_) => return false,
        }
    }
    true
}

fn single_type(s: &str) -> bool {
    !s.is_empty() && complete_type(s.as_bytes(), 0, 0, 0) == Ok(s.len())
}

/// Reads values from `b[p..end]`, as the message's byte order says.
struct Reader<'a> {
    b: &'a [u8],
    p: usize,
    end: usize,
    big: bool,
}

impl<'a> Reader<'a> {
    fn pad(&mut self, a: usize) -> R<()> {
        let q = align(self.p, a);
        if q > self.end {
            return bad("truncated");
        }
        if self.b[self.p..q].iter().any(|&x| x != 0) {
            return bad("non-zero padding");
        }
        self.p = q;
        Ok(())
    }

    fn take(&mut self, n: usize) -> R<&'a [u8]> {
        if n > self.end - self.p {
            return bad("truncated");
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }

    fn u8(&mut self) -> R<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> R<u32> {
        self.pad(4)?;
        let b: [u8; 4] = self.take(4)?.try_into().unwrap_or_default();
        Ok(if self.big { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) })
    }

    fn text(s: &[u8]) -> R<&str> {
        match std::str::from_utf8(s) {
            Ok(t) if !t.contains('\0') => Ok(t),
            Ok(_) => bad("NUL inside a string"),
            Err(_) => bad("string is not UTF-8"),
        }
    }

    fn string(&mut self) -> R<&'a str> {
        let n = self.u32()? as usize;
        let s = self.take(n)?;
        if self.u8()? != 0 {
            return bad("string not NUL-terminated");
        }
        Self::text(s)
    }

    fn signature(&mut self) -> R<&'a str> {
        let n = self.u8()? as usize;
        let s = self.take(n)?;
        if self.u8()? != 0 {
            return bad("signature not NUL-terminated");
        }
        let s = Self::text(s)?;
        if !signature_ok(s) {
            return bad("invalid signature");
        }
        Ok(s)
    }

    /// Skips one value of the complete type at `s[i]` (already checked),
    /// checking it on the way; returns the index after the type.
    fn skip(&mut self, s: &[u8], i: usize, depth: u32) -> R<usize> {
        if depth > 64 {
            return bad("values nested too deep");
        }
        let t = s[i];
        match t {
            b'y' => {
                self.u8()?;
            }
            b'b' => {
                if self.u32()? > 1 {
                    return bad("boolean other than 0 or 1");
                }
            }
            b'n' | b'q' => {
                self.pad(2)?;
                self.take(2)?;
            }
            b'i' | b'u' | b'h' => {
                self.u32()?;
            }
            b'x' | b't' | b'd' => {
                self.pad(8)?;
                self.take(8)?;
            }
            b's' => {
                self.string()?;
            }
            b'o' => {
                if !names::object_path(self.string()?) {
                    return bad("invalid object path");
                }
            }
            b'g' => {
                self.signature()?;
            }
            b'v' => {
                let sig = self.signature()?;
                if !single_type(sig) {
                    return bad("variant signature is not a single type");
                }
                self.skip(sig.as_bytes(), 0, depth + 1)?;
            }
            b'a' => {
                let n = self.u32()? as usize;
                if n > 1 << 26 {
                    return bad("array too long");
                }
                let elem = i + 1;
                let array_end = complete_type(s, i, 0, 0)?;
                self.pad(alignment(s[elem]))?;
                if n > self.end - self.p {
                    return bad("truncated");
                }
                let stop = self.p + n;
                let end = std::mem::replace(&mut self.end, stop);
                while self.p < stop {
                    self.skip(s, elem, depth + 1)?;
                }
                self.end = end;
                return Ok(array_end);
            }
            b'(' | b'{' => {
                self.pad(8)?;
                let close = if t == b'(' { b')' } else { b'}' };
                let mut j = i + 1;
                while s[j] != close {
                    j = self.skip(s, j, depth + 1)?;
                }
                return Ok(j + 1);
            }
            _ => return bad("invalid type in signature"),
        }
        Ok(i + 1)
    }
}

/// The total length of the message whose fixed 16-byte header starts
/// `head`, checked against the limits.
pub fn message_len(head: &[u8]) -> R<usize> {
    if head.len() < 16 {
        return bad("truncated");
    }
    let big = match head[0] {
        b'l' => false,
        b'B' => true,
        _ => return bad("unknown byte order"),
    };
    if head[3] != 1 {
        return bad("unknown protocol version");
    }
    let rd = |at: usize| {
        let b: [u8; 4] = head[at..at + 4].try_into().unwrap_or_default();
        (if big { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) }) as usize
    };
    let (body, fields) = (rd(4), rd(12));
    if body > MAX_MESSAGE || fields > MAX_MESSAGE {
        return bad("message too large");
    }
    let total = align(16 + fields, 8) + body;
    if total > MAX_MESSAGE {
        return bad("message too large");
    }
    Ok(total)
}

/// A whole message: its bytes, its descriptors and its parsed header.
#[derive(Debug)]
pub struct Message {
    pub data: Vec<u8>,
    pub fds: Vec<OwnedFd>,
    big: bool,
    pub kind: Kind,
    pub flags: u8,
    pub serial: u32,
    pub path: Option<String>,
    pub interface: Option<String>,
    pub member: Option<String>,
    pub error_name: Option<String>,
    pub reply_serial: Option<u32>,
    reply_serial_at: usize,
    pub destination: Option<String>,
    pub sender: Option<String>,
    pub signature: String,
    pub unix_fds: u32,
    body: usize,
}

impl Message {
    /// Parses and checks `data`, which holds exactly one message (its
    /// length as [`message_len`] gave it). The descriptors are attached
    /// separately.
    pub fn parse(data: Vec<u8>) -> R<Message> {
        let total = message_len(&data)?;
        if total != data.len() {
            return bad("length does not match the header");
        }
        let big = data[0] == b'B';
        let kind = match data[1] {
            1 => Kind::Call,
            2 => Kind::Return,
            3 => Kind::Error,
            4 => Kind::Signal,
            _ => return bad("unknown message type"),
        };
        let mut r = Reader { b: &data, p: 4, end: 16, big };
        let body_len = r.u32()? as usize;
        let serial = r.u32()?;
        let fields_len = r.u32()? as usize;
        if serial == 0 {
            return bad("serial 0");
        }
        let fields_end = 16 + fields_len;
        let mut m = Message {
            data: vec![],
            fds: vec![],
            big,
            kind,
            flags: data[2],
            serial,
            path: None,
            interface: None,
            member: None,
            error_name: None,
            reply_serial: None,
            reply_serial_at: 0,
            destination: None,
            sender: None,
            signature: String::new(),
            unix_fds: 0,
            body: align(fields_end, 8),
        };
        r.end = fields_end;
        let mut seen = 0u32;
        let mut has_sig = false;
        while r.p < fields_end {
            r.pad(8)?;
            let code = r.u8()?;
            let sig = r.signature()?;
            if !single_type(sig) {
                return bad("header field is not a single type");
            }
            if (1..=9).contains(&code) {
                if seen & (1 << code) != 0 {
                    return bad("header field given twice");
                }
                seen |= 1 << code;
            }
            let want = match code {
                0 => return bad("header field 0"),
                PATH => "o",
                INTERFACE | MEMBER | ERROR_NAME | DESTINATION | SENDER => "s",
                REPLY_SERIAL | UNIX_FDS => "u",
                SIGNATURE => "g",
                _ => {
                    // Unknown fields are ignored, as the bus ignores them.
                    r.skip(sig.as_bytes(), 0, 0)?;
                    continue;
                }
            };
            if sig != want {
                return bad("header field of the wrong type");
            }
            match code {
                REPLY_SERIAL => {
                    r.pad(4)?;
                    m.reply_serial_at = r.p;
                    let v = r.u32()?;
                    if v == 0 {
                        return bad("reply serial 0");
                    }
                    m.reply_serial = Some(v);
                }
                UNIX_FDS => {
                    m.unix_fds = r.u32()?;
                    if m.unix_fds > MAX_FDS {
                        return bad("too many descriptors");
                    }
                }
                SIGNATURE => {
                    m.signature = r.signature()?.to_string();
                    has_sig = true;
                }
                _ => {
                    let v = r.string()?;
                    let (ok, slot) = match code {
                        PATH => (names::object_path(v) && v != "/org/freedesktop/DBus/Local", &mut m.path),
                        INTERFACE => (names::interface(v) && v != "org.freedesktop.DBus.Local", &mut m.interface),
                        MEMBER => (names::member(v), &mut m.member),
                        ERROR_NAME => (names::interface(v), &mut m.error_name),
                        DESTINATION => (names::bus_name(v), &mut m.destination),
                        _ => (names::bus_name(v), &mut m.sender),
                    };
                    if !ok {
                        return bad("invalid name in a header field");
                    }
                    *slot = Some(v.to_string());
                }
            }
        }
        if r.p != fields_end {
            return bad("header fields overrun");
        }
        r.end = m.body;
        r.pad(8)?;
        if m.body + body_len != data.len() {
            return bad("body length");
        }
        if body_len > 0 && !has_sig {
            return bad("body without a signature");
        }
        let ok = match kind {
            Kind::Call => m.path.is_some() && m.member.is_some(),
            Kind::Return => m.reply_serial.is_some(),
            Kind::Error => m.reply_serial.is_some() && m.error_name.is_some(),
            Kind::Signal => m.path.is_some() && m.interface.is_some() && m.member.is_some(),
        };
        if !ok {
            return bad("required header field missing");
        }
        m.data = data;
        Ok(m)
    }

    fn put32(&mut self, at: usize, v: u32) {
        let b = if self.big { v.to_be_bytes() } else { v.to_le_bytes() };
        self.data[at..at + 4].copy_from_slice(&b);
    }

    pub fn set_serial(&mut self, s: u32) {
        self.serial = s;
        self.put32(8, s);
    }

    pub fn set_reply_serial(&mut self, s: u32) {
        if self.reply_serial.is_some() {
            self.reply_serial = Some(s);
            self.put32(self.reply_serial_at, s);
        }
    }

    pub fn expects_reply(&self) -> bool {
        self.kind == Kind::Call && self.flags & NO_REPLY_EXPECTED == 0
    }

    pub fn is(&self, interface: &str, member: &str) -> bool {
        self.interface.as_deref() == Some(interface) && self.member.as_deref() == Some(member)
    }

    fn body(&self) -> Reader<'_> {
        Reader { b: &self.data, p: self.body, end: self.data.len(), big: self.big }
    }

    /// The first `n` arguments, when they are all strings.
    pub fn strings(&self, n: usize) -> Option<Vec<&str>> {
        if self.signature.len() < n || !self.signature.bytes().take(n).all(|c| c == b's') {
            return None;
        }
        let mut r = self.body();
        (0..n).map(|_| r.string().ok()).collect()
    }

    /// The first argument, when it is a `u` or `b`.
    #[cfg(test)]
    pub fn arg0_u32(&self) -> Option<u32> {
        if !matches!(self.signature.as_bytes().first(), Some(b'u' | b'b')) {
            return None;
        }
        self.body().u32().ok()
    }

    pub fn arg0(&self) -> Option<&str> {
        self.strings(1).map(|v| v[0])
    }

    /// The body, when it is a single array of strings.
    pub fn string_array(&self) -> Option<Vec<&str>> {
        if self.signature != "as" {
            return None;
        }
        let mut r = self.body();
        let n = r.u32().ok()? as usize;
        if n > r.end - r.p {
            return None;
        }
        r.end = r.p + n;
        let mut v = vec![];
        while r.p < r.end {
            v.push(r.string().ok()?);
        }
        Some(v)
    }
}

/// A header field value for [`build`].
pub enum Field<'a> {
    Path(&'a str),
    Interface(&'a str),
    Member(&'a str),
    ErrorName(&'a str),
    ReplySerial(u32),
    Destination(&'a str),
    Sender(&'a str),
}

/// A body being encoded (little-endian).
#[derive(Default)]
pub struct Body {
    b: Vec<u8>,
}

impl Body {
    pub fn pad(&mut self, a: usize) {
        self.b.resize(align(self.b.len(), a), 0);
    }

    pub fn u32(&mut self, v: u32) -> &mut Body {
        self.pad(4);
        self.b.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn bool(&mut self, v: bool) -> &mut Body {
        self.u32(v as u32)
    }

    pub fn str(&mut self, s: &str) -> &mut Body {
        self.u32(s.len() as u32);
        self.b.extend_from_slice(s.as_bytes());
        self.b.push(0);
        self
    }

    pub fn strs(&mut self, items: &[&str]) -> &mut Body {
        self.u32(0);
        let at = self.b.len();
        for s in items {
            self.str(s);
        }
        let n = (self.b.len() - at) as u32;
        self.b[at - 4..at].copy_from_slice(&n.to_le_bytes());
        self
    }
}

/// Builds a little-endian message. Fails only if the result would not
/// parse (an invalid name, say), which the caller treats as fatal.
pub fn build(kind: Kind, flags: u8, serial: u32, fields: &[Field], signature: &str, body: &Body) -> R<Message> {
    let mut b = Body::default();
    b.b.extend_from_slice(&[b'l', kind.code(), flags, 1]);
    b.u32(body.b.len() as u32).u32(serial).u32(0);
    let field = |b: &mut Body, code: u8, sig: u8| {
        b.pad(8);
        b.b.extend_from_slice(&[code, 1, sig, 0]);
    };
    for f in fields {
        match *f {
            Field::ReplySerial(v) => {
                field(&mut b, REPLY_SERIAL, b'u');
                b.u32(v);
            }
            Field::Path(s) => {
                field(&mut b, PATH, b'o');
                b.str(s);
            }
            Field::Interface(s) | Field::Member(s) | Field::ErrorName(s) | Field::Destination(s) | Field::Sender(s) => {
                let code = match f {
                    Field::Interface(_) => INTERFACE,
                    Field::Member(_) => MEMBER,
                    Field::ErrorName(_) => ERROR_NAME,
                    Field::Destination(_) => DESTINATION,
                    _ => SENDER,
                };
                field(&mut b, code, b's');
                b.str(s);
            }
        }
    }
    if !signature.is_empty() {
        if signature.len() > 255 {
            return bad("invalid signature");
        }
        field(&mut b, SIGNATURE, b'g');
        b.b.push(signature.len() as u8);
        b.b.extend_from_slice(signature.as_bytes());
        b.b.push(0);
    }
    let fields_len = (b.b.len() - 16) as u32;
    b.b[12..16].copy_from_slice(&fields_len.to_le_bytes());
    b.pad(8);
    b.b.extend_from_slice(&body.b);
    Message::parse(b.b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(fields: &[Field], sig: &str, body: &Body) -> Message {
        build(Kind::Call, 0, 7, fields, sig, body).unwrap()
    }

    #[test]
    fn round_trip() {
        let mut body = Body::default();
        body.str("org.example.App").u32(4);
        let m = call(
            &[
                Field::Path("/org/freedesktop/DBus"),
                Field::Interface("org.freedesktop.DBus"),
                Field::Member("RequestName"),
                Field::Destination("org.freedesktop.DBus"),
            ],
            "su",
            &body,
        );
        assert_eq!(m.kind, Kind::Call);
        assert_eq!(m.serial, 7);
        assert_eq!(m.path.as_deref(), Some("/org/freedesktop/DBus"));
        assert!(m.is("org.freedesktop.DBus", "RequestName"));
        assert_eq!(m.arg0(), Some("org.example.App"));
        assert_eq!(m.strings(2), None, "the second argument is not a string");
        assert_eq!(message_len(&m.data), Ok(m.data.len()));

        let mut body = Body::default();
        body.strs(&["a.b", ":1.2", "org.example.X"]);
        let mut r = build(Kind::Return, 0, 9, &[Field::ReplySerial(7), Field::Destination(":1.2")], "as", &body).unwrap();
        assert_eq!(r.string_array(), Some(vec!["a.b", ":1.2", "org.example.X"]));
        r.set_serial(11);
        r.set_reply_serial(12);
        let r = Message::parse(r.data).unwrap();
        assert_eq!((r.serial, r.reply_serial), (11, Some(12)));
    }

    /// Big-endian messages, as another peer may send them, read the same.
    #[test]
    fn big_endian() {
        let mut d = vec![b'B', 4, 0, 1];
        d.extend_from_slice(&0u32.to_be_bytes());
        d.extend_from_slice(&5u32.to_be_bytes());
        let mut f = vec![];
        let mut field = |code: u8, sig: u8, s: &str| {
            f.resize(align(f.len(), 8), 0);
            f.extend_from_slice(&[code, 1, sig, 0]);
            f.extend_from_slice(&(s.len() as u32).to_be_bytes());
            f.extend_from_slice(s.as_bytes());
            f.push(0);
        };
        field(PATH, b'o', "/a");
        field(INTERFACE, b's', "org.example.I");
        field(MEMBER, b's', "Changed");
        d.extend_from_slice(&(f.len() as u32).to_be_bytes());
        d.extend_from_slice(&f);
        d.resize(align(d.len(), 8), 0);
        let mut m = Message::parse(d).unwrap();
        assert_eq!((m.kind, m.serial, m.member.as_deref()), (Kind::Signal, 5, Some("Changed")));
        m.set_serial(0x01020304);
        assert_eq!(&m.data[8..12], &[1, 2, 3, 4]);
    }

    fn header(fields: &[u8], body: &[u8]) -> Vec<u8> {
        let mut d = vec![b'l', 1, 0, 1];
        d.extend_from_slice(&(body.len() as u32).to_le_bytes());
        d.extend_from_slice(&1u32.to_le_bytes());
        d.extend_from_slice(&(fields.len() as u32).to_le_bytes());
        d.extend_from_slice(fields);
        d.resize(align(d.len(), 8), 0);
        d.extend_from_slice(body);
        d
    }

    fn sfield(code: u8, sig: u8, s: &str) -> Vec<u8> {
        let mut f = vec![code, 1, sig, 0];
        f.extend_from_slice(&(s.len() as u32).to_le_bytes());
        f.extend_from_slice(s.as_bytes());
        f.push(0);
        f
    }

    /// A header field array: padding between the fields, none after.
    fn join(fields: &[&[u8]]) -> Vec<u8> {
        let mut out = vec![];
        for f in fields {
            out.resize(align(out.len(), 8), 0);
            out.extend_from_slice(f);
        }
        out
    }

    #[test]
    fn strict_headers() {
        let path = sfield(PATH, b'o', "/a");
        let member = sfield(MEMBER, b's', "M");
        let ok = join(&[&path, &member]);
        assert!(Message::parse(header(&ok, &[])).is_ok());
        let parse = |f: &[u8]| Message::parse(header(f, &[])).map(|_| ()).map_err(|e| e.0);

        assert_eq!(parse(&join(&[&path, &member, &sfield(MEMBER, b's', "N")])), Err("header field given twice"));
        assert_eq!(parse(&join(&[&path, &sfield(MEMBER, b'o', "/M")])), Err("header field of the wrong type"));
        assert_eq!(parse(&join(&[&path, &sfield(DESTINATION, b's', "not a name"), &member])), Err("invalid name in a header field"));
        assert_eq!(parse(&join(&[&path])), Err("required header field missing"));
        assert!(parse(&join(&[&sfield(PATH, b'o', "/org/freedesktop/DBus/Local"), &member])).is_err());
        // Trailing padding counted in the array is a truncated field.
        let mut trailing = ok.clone();
        trailing.resize(align(trailing.len(), 8), 0);
        assert_eq!(parse(&trailing), Err("truncated"));
        let mut padded = ok.clone();
        padded[12] = 1;
        assert_eq!(parse(&padded), Err("non-zero padding"));

        // An unknown field is skipped, whatever its (valid) type.
        let mut unknown = vec![42, 5, b'a', b'(', b'y', b'i', b')', 0];
        unknown.extend_from_slice(&16u32.to_le_bytes());
        unknown.extend_from_slice(&[0; 4]);
        unknown.extend_from_slice(&[1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0]);
        assert_eq!(parse(&join(&[&unknown, &path, &member])), Ok(()));
        let mut nonzero = unknown.clone();
        nonzero[17] = 9; // padding inside the first struct
        assert_eq!(parse(&join(&[&nonzero, &path, &member])), Err("non-zero padding"));
        let mut dict = vec![43, 5, b'a', b'{', b's', b'y', b'}', 0];
        dict.extend_from_slice(&7u32.to_le_bytes());
        dict.extend_from_slice(&[0; 4]);
        dict.extend_from_slice(&[1, 0, 0, 0, b'k', 0, 5]);
        assert_eq!(parse(&join(&[&dict, &path, &member])), Ok(()));

        // A body needs a signature.
        assert_eq!(Message::parse(header(&ok, &[0; 8])).unwrap_err().0, "body without a signature");
        // Serial 0, and a declared length that doesn't match.
        let mut z = header(&ok, &[]);
        z[8] = 0;
        assert_eq!(Message::parse(z).unwrap_err().0, "serial 0");
        let mut long = header(&ok, &[]);
        long.push(0);
        assert!(Message::parse(long).is_err());
    }

    #[test]
    fn limits() {
        let mut h = header(&[], &[]);
        h[4..8].copy_from_slice(&(MAX_MESSAGE as u32).to_le_bytes());
        assert_eq!(message_len(&h).unwrap_err().0, "message too large");
        h[0] = b'x';
        assert_eq!(message_len(&h).unwrap_err().0, "unknown byte order");
    }

    #[test]
    fn signatures() {
        for ok in ["", "s", "a{sv}", "(ii)a(sa{sv})", "aai", "v", "a{oa{sa{sv}}}"] {
            assert!(signature_ok(ok), "{ok}");
        }
        for bad in ["a", "()", "(i", "a{vs}", "a{s}", "a{sss}", "{sv}", "z"] {
            assert!(!signature_ok(bad), "{bad}");
        }
        assert!(signature_ok(&format!("{}i", "a".repeat(32))));
        assert!(!signature_ok(&format!("{}i", "a".repeat(33))));
        let deep = format!("{}i{}", "(".repeat(33), ")".repeat(33));
        assert!(!signature_ok(&deep));
    }
}
