//! `plistlib` with full value fidelity, for sharingd's AutoUnlock files and
//! the pairing backup: binary (`bplist00`) and XML reading and writing.
//!
//! The writers follow CPython's `plistlib` algorithms (sorted keys, scalar
//! uniquing, size selection, XML indentation and base64 wrapping), so a file
//! written here is byte-identical to `plistlib.dumps(value, fmt=...)`.
use std::collections::{BTreeMap, HashMap};

use base64::Engine;
use chrono::{Datelike, NaiveDate, NaiveDateTime, Timelike};
use mirra_core::{Error, Result};

#[derive(Clone, Debug)]
pub enum Plist {
    /// Binary-only `None` (token 0x00).
    Null,
    Bool(bool),
    Integer(i128),
    Real(f64),
    /// Microseconds since 2001-01-01T00:00:00 (naive, like `datetime`).
    Date(i64),
    Data(Vec<u8>),
    String(String),
    /// Binary-only `plistlib.UID`.
    Uid(u64),
    Array(Vec<Plist>),
    /// Python keeps file order, but every writer sorts keys and dict
    /// equality ignores order, so a sorted map is equivalent.
    Dict(BTreeMap<String, Plist>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Xml,
    Binary,
}

impl Plist {
    pub fn as_dict(&self) -> Option<&BTreeMap<String, Plist>> {
        match self {
            Plist::Dict(map) => Some(map),
            _ => None,
        }
    }
    pub fn as_dict_mut(&mut self) -> Option<&mut BTreeMap<String, Plist>> {
        match self {
            Plist::Dict(map) => Some(map),
            _ => None,
        }
    }
    pub fn get(&self, key: &str) -> Option<&Plist> {
        self.as_dict().and_then(|m| m.get(key))
    }
    pub fn is_data(&self) -> bool {
        matches!(self, Plist::Data(_))
    }

    fn number(&self) -> Option<f64> {
        match self {
            Plist::Bool(b) => Some(f64::from(u8::from(*b))),
            Plist::Integer(i) => Some(*i as f64),
            Plist::Real(f) => Some(*f),
            _ => None,
        }
    }
}

/// Python `==` (numbers compare across bool/int/float; dicts ignore order).
impl PartialEq for Plist {
    fn eq(&self, other: &Self) -> bool {
        use Plist::*;
        match (self, other) {
            (Null, Null) => true,
            (Integer(a), Integer(b)) => a == b,
            (Bool(a), Integer(b)) | (Integer(b), Bool(a)) => i128::from(*a) == *b,
            (Bool(a), Bool(b)) => a == b,
            (Real(_), _) | (_, Real(_)) => match (self.number(), other.number()) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            },
            (Date(a), Date(b)) => a == b,
            (Data(a), Data(b)) => a == b,
            (String(a), String(b)) => a == b,
            (Uid(a), Uid(b)) => a == b,
            (Array(a), Array(b)) => a == b,
            (Dict(a), Dict(b)) => a == b,
            _ => false,
        }
    }
}

fn invalid() -> Error {
    Error::Value("Invalid file".into())
}

/// `plistlib.loads(data)` with format detection; also reports the format
/// (`bplist` prefix = binary, as sharingd.py decides when writing back).
pub fn loads(data: &[u8]) -> Result<(Plist, Format)> {
    if data.starts_with(b"bplist00") {
        return Ok((read_binary(data)?, Format::Binary));
    }
    let text = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    if text.starts_with(b"<?xml") || text.starts_with(b"<plist") {
        return Ok((read_xml(text)?, Format::Xml));
    }
    Err(invalid())
}

/// `plistlib.dumps(value, fmt=format)` (sort_keys=True).
pub fn dumps(value: &Plist, format: Format) -> Result<Vec<u8>> {
    match format {
        Format::Binary => write_binary(value),
        Format::Xml => write_xml(value),
    }
}

// ---------------------------------------------------------------- binary

fn count_to_size(count: u64) -> usize {
    if count < 1 << 8 {
        1
    } else if count < 1 << 16 {
        2
    } else if count < 1 << 32 {
        4
    } else {
        8
    }
}

fn push_uint(out: &mut Vec<u8>, value: u64, size: usize) {
    out.extend_from_slice(&value.to_be_bytes()[8 - size..]);
}

#[derive(Hash, PartialEq, Eq)]
enum ScalarKey {
    Str(String),
    Int(i128),
    Bool(bool),
    Float(u64),
    Date(i64),
    Bytes(Vec<u8>),
    None,
}

fn scalar_key(value: &Plist) -> Option<ScalarKey> {
    Some(match value {
        Plist::String(s) => ScalarKey::Str(s.clone()),
        Plist::Integer(i) => ScalarKey::Int(*i),
        Plist::Bool(b) => ScalarKey::Bool(*b),
        // NaN never equals itself; -0.0 == 0.0 shares one object.
        Plist::Real(f) if f.is_nan() => return None,
        Plist::Real(f) => ScalarKey::Float(if *f == 0.0 { 0 } else { f.to_bits() }),
        Plist::Date(d) => ScalarKey::Date(*d),
        Plist::Data(d) => ScalarKey::Bytes(d.clone()),
        // `None` is a singleton, so its identity entry is shared.
        Plist::Null => ScalarKey::None,
        _ => return None,
    })
}

enum Node<'a> {
    Value(&'a Plist),
    Key(&'a str),
}

struct Writer<'a> {
    objects: Vec<Node<'a>>,
    children: HashMap<usize, Vec<usize>>,
    table: HashMap<ScalarKey, usize>,
}

impl<'a> Writer<'a> {
    fn flatten_key(&mut self, key: &'a str) -> usize {
        let index = ScalarKey::Str(key.to_string());
        if let Some(found) = self.table.get(&index) {
            return *found;
        }
        let reference = self.objects.len();
        self.objects.push(Node::Key(key));
        self.table.insert(index, reference);
        reference
    }

    fn flatten(&mut self, value: &'a Plist) -> usize {
        let key = scalar_key(value);
        if let Some(found) = key.as_ref().and_then(|k| self.table.get(k)) {
            return *found;
        }
        let reference = self.objects.len();
        self.objects.push(Node::Value(value));
        if let Some(key) = key {
            self.table.insert(key, reference);
        }
        match value {
            Plist::Dict(map) => {
                let mut refs: Vec<usize> = map.keys().map(|k| self.flatten_key(k)).collect();
                for item in map.values() {
                    refs.push(self.flatten(item));
                }
                self.children.insert(reference, refs);
            }
            Plist::Array(items) => {
                let refs = items.iter().map(|item| self.flatten(item)).collect();
                self.children.insert(reference, refs);
            }
            _ => {}
        }
        reference
    }
}

fn write_size(out: &mut Vec<u8>, token: u8, size: usize) {
    if size < 15 {
        out.push(token | size as u8);
    } else if size < 1 << 8 {
        out.extend_from_slice(&[token | 0xF, 0x10, size as u8]);
    } else if size < 1 << 16 {
        out.extend_from_slice(&[token | 0xF, 0x11]);
        push_uint(out, size as u64, 2);
    } else if (size as u64) < 1 << 32 {
        out.extend_from_slice(&[token | 0xF, 0x12]);
        push_uint(out, size as u64, 4);
    } else {
        out.extend_from_slice(&[token | 0xF, 0x13]);
        push_uint(out, size as u64, 8);
    }
}

fn write_string_object(out: &mut Vec<u8>, text: &str) {
    if text.is_ascii() {
        write_size(out, 0x50, text.len());
        out.extend_from_slice(text.as_bytes());
    } else {
        let units: Vec<u16> = text.encode_utf16().collect();
        write_size(out, 0x60, units.len());
        for unit in units {
            out.extend_from_slice(&unit.to_be_bytes());
        }
    }
}

fn write_binary(root: &Plist) -> Result<Vec<u8>> {
    let mut writer = Writer { objects: Vec::new(), children: HashMap::new(), table: HashMap::new() };
    let top = writer.flatten(root);
    let count = writer.objects.len();
    let ref_size = count_to_size(count as u64);
    let mut out = b"bplist00".to_vec();
    let mut offsets = vec![0u64; count];
    for (reference, node) in writer.objects.iter().enumerate() {
        offsets[reference] = out.len() as u64;
        let value = match node {
            Node::Key(key) => {
                write_string_object(&mut out, key);
                continue;
            }
            Node::Value(value) => *value,
        };
        match value {
            Plist::Null => out.push(0x00),
            Plist::Bool(false) => out.push(0x08),
            Plist::Bool(true) => out.push(0x09),
            Plist::Integer(i) => {
                let i = *i;
                if i < 0 {
                    let v = i64::try_from(i).map_err(|_| Error::Value(format!("{}", i)))?;
                    out.push(0x13);
                    out.extend_from_slice(&v.to_be_bytes());
                } else if i < 1 << 8 {
                    out.extend_from_slice(&[0x10, i as u8]);
                } else if i < 1 << 16 {
                    out.push(0x11);
                    push_uint(&mut out, i as u64, 2);
                } else if i < 1 << 32 {
                    out.push(0x12);
                    push_uint(&mut out, i as u64, 4);
                } else if i < 1 << 63 {
                    out.push(0x13);
                    push_uint(&mut out, i as u64, 8);
                } else if i < 1 << 64 {
                    out.push(0x14);
                    out.extend_from_slice(&i.to_be_bytes());
                } else {
                    return Err(Error::Value(format!("{}", i)));
                }
            }
            Plist::Real(f) => {
                out.push(0x23);
                out.extend_from_slice(&f.to_be_bytes());
            }
            Plist::Date(micros) => {
                out.push(0x33);
                out.extend_from_slice(&(*micros as f64 / 1e6).to_be_bytes());
            }
            Plist::Data(data) => {
                write_size(&mut out, 0x40, data.len());
                out.extend_from_slice(data);
            }
            Plist::String(text) => write_string_object(&mut out, text),
            Plist::Uid(uid) => {
                let uid = *uid;
                if uid < 1 << 8 {
                    out.extend_from_slice(&[0x80, uid as u8]);
                } else if uid < 1 << 16 {
                    out.push(0x81);
                    push_uint(&mut out, uid, 2);
                } else if uid < 1 << 32 {
                    out.push(0x83);
                    push_uint(&mut out, uid, 4);
                } else {
                    out.push(0x87);
                    push_uint(&mut out, uid, 8);
                }
            }
            Plist::Array(_) | Plist::Dict(_) => {
                let refs = &writer.children[&reference];
                let (token, size) = if matches!(value, Plist::Array(_)) { (0xA0, refs.len()) } else { (0xD0, refs.len() / 2) };
                write_size(&mut out, token, size);
                for r in refs {
                    push_uint(&mut out, *r as u64, ref_size);
                }
            }
        }
    }
    let table_offset = out.len() as u64;
    let offset_size = count_to_size(table_offset);
    for offset in offsets {
        push_uint(&mut out, offset, offset_size);
    }
    out.extend_from_slice(&[0; 6]);
    out.push(offset_size as u8);
    out.push(ref_size as u8);
    out.extend_from_slice(&(count as u64).to_be_bytes());
    out.extend_from_slice(&(top as u64).to_be_bytes());
    out.extend_from_slice(&table_offset.to_be_bytes());
    Ok(out)
}

struct Reader<'a> {
    data: &'a [u8],
    offsets: Vec<u64>,
    ref_size: usize,
    active: Vec<bool>,
}

fn read_uint(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b))
}

impl Reader<'_> {
    fn slice(&self, at: usize, count: usize) -> Result<&[u8]> {
        let end = at.checked_add(count).ok_or_else(invalid)?;
        self.data.get(at..end).ok_or_else(invalid)
    }

    fn size(&self, low: u8, at: &mut usize) -> Result<usize> {
        if low != 0xF {
            return Ok(low as usize);
        }
        let marker = self.slice(*at, 1)?[0] & 0x3;
        let width = 1usize << marker;
        let value = read_uint(self.slice(*at + 1, width)?);
        *at += 1 + width;
        usize::try_from(value).map_err(|_| invalid())
    }

    fn refs(&self, at: usize, count: usize) -> Result<Vec<usize>> {
        let bytes = self.slice(at, count.checked_mul(self.ref_size).ok_or_else(invalid)?)?;
        Ok(bytes.chunks(self.ref_size).map(|c| read_uint(c) as usize).collect())
    }

    fn object(&mut self, reference: usize) -> Result<Plist> {
        let offset = *self.offsets.get(reference).ok_or_else(invalid)? as usize;
        if self.active[reference] {
            return Err(invalid()); // A cycle cannot be represented as a tree.
        }
        let token = self.slice(offset, 1)?[0];
        let (high, low) = (token & 0xF0, token & 0x0F);
        let mut at = offset + 1;
        let value = match token {
            0x00 => Plist::Null,
            0x08 => Plist::Bool(false),
            0x09 => Plist::Bool(true),
            0x0F => Plist::Data(Vec::new()),
            0x22 => Plist::Real(f64::from(f32::from_be_bytes(self.slice(at, 4)?.try_into().unwrap()))),
            0x23 => Plist::Real(f64::from_be_bytes(self.slice(at, 8)?.try_into().unwrap())),
            0x33 => {
                let seconds = f64::from_be_bytes(self.slice(at, 8)?.try_into().unwrap());
                let micros = (seconds * 1e6).round_ties_even();
                if !micros.is_finite() || micros.abs() > 9.0e18 {
                    return Err(invalid());
                }
                Plist::Date(micros as i64)
            }
            _ if high == 0x10 => {
                let width = 1usize << low;
                if width > 16 {
                    return Err(invalid());
                }
                let bytes = self.slice(at, width)?;
                let mut value: i128 = 0;
                for b in bytes {
                    value = (value << 8) | i128::from(*b);
                }
                if low == 3 {
                    value = i128::from(value as u64 as i64);
                }
                Plist::Integer(value)
            }
            _ if high == 0x40 => {
                let size = self.size(low, &mut at)?;
                Plist::Data(self.slice(at, size)?.to_vec())
            }
            _ if high == 0x50 => {
                let size = self.size(low, &mut at)?;
                let bytes = self.slice(at, size)?;
                if !bytes.is_ascii() {
                    return Err(invalid());
                }
                Plist::String(String::from_utf8(bytes.to_vec()).map_err(|_| invalid())?)
            }
            _ if high == 0x60 => {
                let size = self.size(low, &mut at)?;
                let bytes = self.slice(at, size.checked_mul(2).ok_or_else(invalid)?)?;
                let units: Vec<u16> = bytes.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                Plist::String(String::from_utf16(&units).map_err(|_| invalid())?)
            }
            _ if high == 0x80 => Plist::Uid(read_uint(self.slice(at, 1 + low as usize)?)),
            _ if high == 0xA0 => {
                let size = self.size(low, &mut at)?;
                let refs = self.refs(at, size)?;
                self.active[reference] = true;
                let items = refs.into_iter().map(|r| self.object(r)).collect::<Result<Vec<_>>>();
                self.active[reference] = false;
                Plist::Array(items?)
            }
            _ if high == 0xD0 => {
                let size = self.size(low, &mut at)?;
                let keys = self.refs(at, size)?;
                let values = self.refs(at + size * self.ref_size, size)?;
                self.active[reference] = true;
                let mut map = BTreeMap::new();
                let mut result = Ok(());
                for (k, v) in keys.into_iter().zip(values) {
                    let pair = self.object(k).and_then(|key| Ok((key, self.object(v)?)));
                    match pair {
                        Ok((Plist::String(key), value)) => {
                            map.insert(key, value);
                        }
                        Ok(_) => {
                            result = Err(invalid());
                            break;
                        }
                        Err(e) => {
                            result = Err(e);
                            break;
                        }
                    }
                }
                self.active[reference] = false;
                result?;
                Plist::Dict(map)
            }
            _ => return Err(invalid()),
        };
        Ok(value)
    }
}

fn read_binary(data: &[u8]) -> Result<Plist> {
    if data.len() < 40 {
        return Err(invalid());
    }
    let trailer = &data[data.len() - 32..];
    let offset_size = trailer[6] as usize;
    let ref_size = trailer[7] as usize;
    let count = read_uint(&trailer[8..16]);
    let top = read_uint(&trailer[16..24]);
    let table = read_uint(&trailer[24..32]);
    if offset_size == 0 || offset_size > 8 || ref_size == 0 || ref_size > 8 || count > data.len() as u64 || top >= count {
        return Err(invalid());
    }
    let start = table as usize;
    let end = start.checked_add(count as usize * offset_size).ok_or_else(invalid)?;
    let bytes = data.get(start..end).ok_or_else(invalid)?;
    let offsets = bytes.chunks(offset_size).map(read_uint).collect();
    let mut reader = Reader { data, offsets, ref_size, active: vec![false; count as usize] };
    reader.object(top as usize)
}

// ------------------------------------------------------------------- XML

const XML_HEADER: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n";

fn epoch() -> NaiveDateTime {
    NaiveDate::from_ymd_opt(2001, 1, 1).unwrap().and_hms_opt(0, 0, 0).unwrap()
}

fn date_text(micros: i64) -> String {
    let moment = epoch() + chrono::Duration::microseconds(micros);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", moment.year(), moment.month(), moment.day(),
        moment.hour(), moment.minute(), moment.second())
}

fn escape(text: &str) -> Result<String> {
    if text.chars().any(|c| matches!(c as u32, 0..=8 | 11 | 12 | 14..=31)) {
        return Err(Error::Value("strings can't contain control characters; use bytes instead".into()));
    }
    Ok(text.replace("\r\n", "\n").replace('\r', "\n").replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;"))
}

struct XmlWriter {
    out: String,
    level: usize,
}

impl XmlWriter {
    fn line(&mut self, text: &str) {
        if !text.is_empty() {
            self.out.extend(std::iter::repeat_n('\t', self.level));
            self.out.push_str(text);
        }
        self.out.push('\n');
    }

    fn simple(&mut self, element: &str, value: Option<&str>) -> Result<()> {
        match value {
            Some(value) => {
                let escaped = escape(value)?;
                self.line(&format!("<{0}>{1}</{0}>", element, escaped));
            }
            None => self.line(&format!("<{}/>", element)),
        }
        Ok(())
    }

    fn value(&mut self, value: &Plist) -> Result<()> {
        match value {
            Plist::String(s) => self.simple("string", Some(s))?,
            Plist::Bool(true) => self.simple("true", None)?,
            Plist::Bool(false) => self.simple("false", None)?,
            Plist::Integer(i) => {
                if *i < -(1i128 << 63) || *i >= 1i128 << 64 {
                    return Err(Error::Value(format!("{}", i)));
                }
                self.simple("integer", Some(&i.to_string()))?
            }
            Plist::Real(f) => {
                let text = if f.is_nan() {
                    "nan".to_string()
                } else if f.is_infinite() {
                    if *f > 0.0 { "inf".into() } else { "-inf".into() }
                } else {
                    mirra_core::pyfmt::float_repr(*f)
                };
                self.simple("real", Some(&text))?
            }
            Plist::Dict(map) if map.is_empty() => self.simple("dict", None)?,
            Plist::Dict(map) => {
                self.line("<dict>");
                self.level += 1;
                for (key, item) in map {
                    self.simple("key", Some(key))?;
                    self.value(item)?;
                }
                self.level -= 1;
                self.line("</dict>");
            }
            Plist::Data(data) => {
                self.line("<data>");
                let width = 76usize.saturating_sub(8 * self.level).max(16);
                let chunk = (width / 4) * 3;
                for piece in data.chunks(chunk.max(1)) {
                    let encoded = base64::engine::general_purpose::STANDARD.encode(piece);
                    self.line(&encoded);
                }
                self.line("</data>");
            }
            Plist::Date(micros) => self.simple("date", Some(&date_text(*micros)))?,
            Plist::Array(items) if items.is_empty() => self.simple("array", None)?,
            Plist::Array(items) => {
                self.line("<array>");
                self.level += 1;
                for item in items {
                    self.value(item)?;
                }
                self.level -= 1;
                self.line("</array>");
            }
            Plist::Null => return Err(Error::Value("unsupported type: <class 'NoneType'>".into())),
            Plist::Uid(_) => return Err(Error::Value("unsupported type: <class 'plistlib.UID'>".into())),
        }
        Ok(())
    }
}

fn write_xml(value: &Plist) -> Result<Vec<u8>> {
    let mut writer = XmlWriter { out: XML_HEADER.to_string(), level: 0 };
    writer.line("<plist version=\"1.0\">");
    writer.value(value)?;
    writer.line("</plist>");
    Ok(writer.out.into_bytes())
}

enum Frame {
    Dict(BTreeMap<String, Plist>, Option<String>),
    Array(Vec<Plist>),
}

struct XmlReader<'a> {
    s: &'a str,
    i: usize,
    stack: Vec<Frame>,
    root: Option<Plist>,
    /// Key waiting for its value in the innermost dict.
    data: String,
}

fn xml_error(message: &str) -> Error {
    Error::Value(message.into())
}

fn decode_entities(raw: &str) -> Result<String> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find('&') {
        out.push_str(&rest[..start]);
        let end = rest[start..].find(';').ok_or_else(invalid)? + start;
        let name = &rest[start + 1..end];
        let decoded = match name {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ if name.starts_with("#x") || name.starts_with("#X") => {
                char::from_u32(u32::from_str_radix(&name[2..], 16).map_err(|_| invalid())?).ok_or_else(invalid)?
            }
            _ if name.starts_with('#') => char::from_u32(name[1..].parse().map_err(|_| invalid())?).ok_or_else(invalid)?,
            _ => return Err(invalid()),
        };
        out.push(decoded);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Ok(out.replace("\r\n", "\n").replace('\r', "\n"))
}

fn parse_date(text: &str) -> Result<i64> {
    let bytes = text.as_bytes();
    let digits = |at: usize, n: usize| -> Option<u32> {
        let part = bytes.get(at..at + n)?;
        part.iter().all(u8::is_ascii_digit).then(|| std::str::from_utf8(part).ok()?.parse().ok())?
    };
    let mut fields = [0u32, 1, 1, 0, 0, 0];
    fields[0] = digits(0, 4).ok_or_else(invalid)?;
    let mut at = 4;
    for (index, separator) in [(1, b'-'), (2, b'-'), (3, b'T'), (4, b':'), (5, b':')] {
        if bytes.get(at) == Some(&separator) {
            if let Some(value) = digits(at + 1, 2) {
                fields[index] = value;
                at += 3;
                continue;
            }
        }
        break;
    }
    if bytes.get(at) != Some(&b'Z') {
        return Err(invalid());
    }
    let moment = NaiveDate::from_ymd_opt(fields[0] as i32, fields[1], fields[2])
        .and_then(|d| d.and_hms_opt(fields[3], fields[4], fields[5]))
        .ok_or_else(invalid)?;
    (moment - epoch()).num_microseconds().ok_or_else(invalid)
}

fn parse_int(raw: &str) -> Result<i128> {
    let text = crate::util::strip(raw);
    let bad = || Error::Value(format!("invalid literal for int() with base 10: {}", mirra_core::pyfmt::repr_str(raw)));
    let (negative, body) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let (radix, digits) = match body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        Some(hex) if raw.starts_with("0x") || raw.starts_with("0X") => (16, hex),
        _ => (10, body),
    };
    let digits = digits.replace('_', "");
    let value = i128::from_str_radix(&digits, radix).map_err(|_| bad())?;
    Ok(if negative { -value } else { value })
}

impl XmlReader<'_> {
    fn add(&mut self, value: Plist) -> Result<()> {
        match self.stack.last_mut() {
            Some(Frame::Dict(map, key)) => match key.take() {
                Some(k) => {
                    map.insert(k, value);
                }
                None => return Err(xml_error("unexpected element")),
            },
            Some(Frame::Array(items)) => items.push(value),
            None => {
                if self.root.is_some() {
                    return Err(xml_error("unexpected element"));
                }
                self.root = Some(value);
            }
        }
        Ok(())
    }

    fn begin(&mut self, name: &str) -> Result<()> {
        self.data.clear();
        match name {
            "dict" => self.stack.push(Frame::Dict(BTreeMap::new(), None)),
            "array" => self.stack.push(Frame::Array(Vec::new())),
            _ => {}
        }
        Ok(())
    }

    fn end(&mut self, name: &str) -> Result<()> {
        let data = std::mem::take(&mut self.data);
        match name {
            "dict" => match self.stack.pop() {
                Some(Frame::Dict(map, None)) => self.add(Plist::Dict(map))?,
                Some(Frame::Dict(_, Some(_))) => return Err(xml_error("missing value for key")),
                _ => return Err(invalid()),
            },
            "array" => match self.stack.pop() {
                Some(Frame::Array(items)) => self.add(Plist::Array(items))?,
                _ => return Err(invalid()),
            },
            "key" => match self.stack.last_mut() {
                Some(Frame::Dict(_, key @ None)) => *key = Some(data),
                _ => return Err(xml_error("unexpected key")),
            },
            "true" => self.add(Plist::Bool(true))?,
            "false" => self.add(Plist::Bool(false))?,
            "integer" => self.add(Plist::Integer(parse_int(&data)?))?,
            "real" => {
                let value: f64 = crate::util::strip(&data).parse().map_err(|_| Error::Value(format!(
                    "could not convert string to float: {}", mirra_core::pyfmt::repr_str(&data))))?;
                self.add(Plist::Real(value))?
            }
            "string" => self.add(Plist::String(data))?,
            "data" => {
                let clean: String = data.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/').collect();
                let decoded = base64::engine::GeneralPurpose::new(&base64::alphabet::STANDARD,
                    base64::engine::GeneralPurposeConfig::new().with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
                        .with_decode_allow_trailing_bits(true))
                    .decode(clean.as_bytes()).map_err(|_| Error::Value("Incorrect padding".into()))?;
                self.add(Plist::Data(decoded))?
            }
            "date" => self.add(Plist::Date(parse_date(&data)?))?,
            _ => {}
        }
        Ok(())
    }

    fn run(&mut self) -> Result<()> {
        let s = self.s;
        while self.i < s.len() {
            let rest = &s[self.i..];
            if let Some(after) = rest.strip_prefix("<!--") {
                self.i += 4 + after.find("-->").ok_or_else(invalid)? + 3;
            } else if let Some(after) = rest.strip_prefix("<![CDATA[") {
                let end = after.find("]]>").ok_or_else(invalid)?;
                self.data.push_str(&after[..end]);
                self.i += 9 + end + 3;
            } else if rest.starts_with("<?") {
                self.i += rest.find("?>").ok_or_else(invalid)? + 2;
            } else if rest.starts_with("<!") {
                // DOCTYPE without an internal subset (plists never carry one).
                self.i += rest.find('>').ok_or_else(invalid)? + 1;
            } else if let Some(after) = rest.strip_prefix("</") {
                let end = after.find('>').ok_or_else(invalid)?;
                let name = after[..end].trim().to_string();
                self.i += 2 + end + 1;
                self.end(&name)?;
            } else if let Some(after) = rest.strip_prefix('<') {
                let end = after.find('>').ok_or_else(invalid)?;
                let inner = &after[..end];
                let empty = inner.ends_with('/');
                let inner = inner.trim_end_matches('/');
                let name = inner.split(|c: char| c.is_whitespace()).next().unwrap_or("").to_string();
                self.i += 1 + end + 1;
                self.begin(&name)?;
                if empty {
                    self.end(&name)?;
                }
            } else {
                let end = rest.find('<').unwrap_or(rest.len());
                self.data.push_str(&decode_entities(&rest[..end])?);
                self.i += end;
            }
        }
        if !self.stack.is_empty() {
            return Err(invalid());
        }
        Ok(())
    }
}

fn read_xml(data: &[u8]) -> Result<Plist> {
    let text = std::str::from_utf8(data).map_err(|_| invalid())?;
    let mut reader = XmlReader { s: text, i: 0, stack: Vec::new(), root: None, data: String::new() };
    reader.run()?;
    reader.root.ok_or_else(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dict(items: Vec<(&str, Plist)>) -> Plist {
        Plist::Dict(items.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    fn sample() -> Plist {
        dict(vec![
            ("Remote LTKs", dict(vec![("DEVICE-1", dict(vec![
                ("Attested LTK Data", Plist::Data((0..200u8).collect())),
                ("Name", Plist::String("Phone é".into())),
                ("Count", Plist::Integer(70000)),
                ("Negative", Plist::Integer(-3)),
                ("Ratio", Plist::Real(0.5)),
                ("Flag", Plist::Bool(true)),
                ("Created", Plist::Date(784_111_777_000_000)),
                ("Shared", Plist::String("x".into())),
                ("Again", Plist::String("x".into())),
                ("List", Plist::Array(vec![Plist::Integer(1), Plist::Integer(1), Plist::Array(vec![])])),
            ]))])),
            ("Empty", dict(vec![])),
        ])
    }

    #[test]
    fn binary_matches_python_plistlib_bytes() {
        // plistlib.dumps({'a': [1, 'x', True, b'\x00'], 'b': 'x', 'c': {}}, fmt=plistlib.FMT_BINARY)
        let value = dict(vec![
            ("a", Plist::Array(vec![Plist::Integer(1), Plist::String("x".into()), Plist::Bool(true), Plist::Data(vec![0])])),
            ("b", Plist::String("x".into())),
            ("c", dict(vec![])),
        ]);
        let expected: &[u8] = b"bplist00\xd3\x01\x02\x03\x04\x06\x09QaQbQc\xa4\x05\x06\x07\x08\x10\x01Qx\x09A\x00\xd0\x08\x0f\x11\x13\x15\x1a\x1c\x1e\x1f\x21\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x22";
        assert_eq!(dumps(&value, Format::Binary).unwrap(), expected);
        assert_eq!(loads(expected).unwrap(), (value, Format::Binary));
    }

    #[test]
    fn xml_matches_python_plistlib_bytes() {
        // plistlib.dumps({'d': b'\x01' * 60, 'k': 'a&b', 'n': [], 't': False})
        let value = dict(vec![("d", Plist::Data(vec![1; 60])), ("k", Plist::String("a&b".into())),
            ("n", Plist::Array(vec![])), ("t", Plist::Bool(false))]);
        let expected = format!("{}<plist version=\"1.0\">\n<dict>\n\t<key>d</key>\n\t<data>\n\t{}\n\t{}\n\t</data>\n\t<key>k</key>\n\t<string>a&amp;b</string>\n\t<key>n</key>\n\t<array/>\n\t<key>t</key>\n\t<false/>\n</dict>\n</plist>\n",
            XML_HEADER, "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB", "AQEBAQEBAQEB");
        assert_eq!(String::from_utf8(dumps(&value, Format::Xml).unwrap()).unwrap(), expected);
        assert_eq!(loads(expected.as_bytes()).unwrap(), (value, Format::Xml));
    }

    #[test]
    fn round_trips_every_type_in_both_formats() {
        for format in [Format::Binary, Format::Xml] {
            let value = sample();
            let data = dumps(&value, format).unwrap();
            let (parsed, detected) = loads(&data).unwrap();
            assert_eq!(detected, format);
            assert_eq!(parsed, value);
            assert_eq!(dumps(&parsed, format).unwrap(), data);
        }
        // hashlib.sha256(plistlib.dumps(sample, fmt=...)).hexdigest() from CPython.
        assert_eq!(crate::util::sha256_hex(&dumps(&sample(), Format::Binary).unwrap()),
            "93e9a0cbda827fd1a48b5aad4ae4769842bc37a6a554d272a0f1f7213ff1e63d");
        assert_eq!(crate::util::sha256_hex(&dumps(&sample(), Format::Xml).unwrap()),
            "e55fb23a20848dd54c8c391bb6959f9840a724467e1045726916d181120e4608");
        assert!(loads(b"").is_err());
        assert!(loads(b"not a plist").is_err());
        assert!(loads(b"bplist00garbage").is_err());
    }

    #[test]
    fn python_equality_across_numbers_and_key_order() {
        assert_eq!(Plist::Bool(true), Plist::Integer(1));
        assert_eq!(Plist::Real(2.0), Plist::Integer(2));
        assert_ne!(Plist::String("1".into()), Plist::Integer(1));
        assert_ne!(Plist::Data(vec![1]), Plist::String("\u{1}".into()));
    }
}
