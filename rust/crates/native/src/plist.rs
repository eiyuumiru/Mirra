//! Minimal `plistlib` equivalent: XML and binary (`bplist00`) reading, and
//! XML writing byte-compatible with `plistlib.dumps` (sorted keys, tabs).
use base64::Engine;
use mirra_core::{Error, Result};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq)]
pub enum Plist {
    /// Insertion-ordered; a duplicate key replaces the earlier value in place.
    Dict(Vec<(String, Plist)>),
    Array(Vec<Plist>),
    String(String),
    Integer(i128),
    Real(f64),
    Bool(bool),
    Data(Vec<u8>),
    /// ISO text as found in the file (`%Y-%m-%dT%H:%M:%SZ`).
    Date(String),
    /// Binary-plist UID (keyed archives); written back as an integer.
    Uid(u64),
}

impl Plist {
    pub fn dict() -> Self {
        Plist::Dict(Vec::new())
    }

    pub fn get(&self, key: &str) -> Option<&Plist> {
        match self {
            Plist::Dict(items) => items.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Plist> {
        match self {
            Plist::Dict(items) => items.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// `d[key] = value` (no effect on non-dictionaries).
    pub fn insert(&mut self, key: impl Into<String>, value: Plist) {
        if let Plist::Dict(items) = self {
            let key = key.into();
            match items.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = value,
                None => items.push((key, value)),
            }
        }
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Plist::String(s) => Some(s),
            _ => None,
        }
    }

    /// Python `type(x) is int` (booleans excluded).
    pub fn as_int(&self) -> Option<i128> {
        match self {
            Plist::Integer(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<Plist>> {
        match self {
            Plist::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_dict(&self) -> Option<&Vec<(String, Plist)>> {
        match self {
            Plist::Dict(items) => Some(items),
            _ => None,
        }
    }

    pub fn is_dict(&self) -> bool {
        matches!(self, Plist::Dict(_))
    }

    /// Convert JSON (objects, arrays, strings, numbers, booleans) for tests
    /// and callers that build plists from JSON-like data. `null` is refused
    /// by `plistlib` and becomes an empty string here.
    pub fn from_json(value: &Value) -> Plist {
        match value {
            Value::Object(map) => Plist::Dict(map.iter().map(|(k, v)| (k.clone(), Plist::from_json(v))).collect()),
            Value::Array(items) => Plist::Array(items.iter().map(Plist::from_json).collect()),
            Value::String(s) => Plist::String(s.clone()),
            Value::Bool(b) => Plist::Bool(*b),
            Value::Number(n) => match (n.as_i64(), n.as_u64()) {
                (Some(i), _) => Plist::Integer(i as i128),
                (_, Some(u)) => Plist::Integer(u as i128),
                _ => Plist::Real(n.as_f64().unwrap_or(0.0)),
            },
            Value::Null => Plist::String(String::new()),
        }
    }

    /// JSON view (data as base64 text, dates as text).
    pub fn to_json(&self) -> Value {
        match self {
            Plist::Dict(items) => Value::Object(items.iter().map(|(k, v)| (k.clone(), v.to_json())).collect()),
            Plist::Array(items) => Value::Array(items.iter().map(Plist::to_json).collect()),
            Plist::String(s) | Plist::Date(s) => Value::from(s.clone()),
            Plist::Integer(n) => i64::try_from(*n).map(Value::from).unwrap_or_else(|_| Value::from(*n as f64)),
            Plist::Real(f) => Value::from(*f),
            Plist::Bool(b) => Value::from(*b),
            Plist::Data(d) => Value::from(base64::engine::general_purpose::STANDARD.encode(d)),
            Plist::Uid(u) => Value::from(*u),
        }
    }
}

fn invalid(message: &str) -> Error {
    Error::value(message)
}

/// `plistlib.loads(data)`: XML or binary format, detected from the header.
pub fn loads(data: &[u8]) -> Result<Plist> {
    let body = data.strip_prefix(b"\xef\xbb\xbf".as_slice()).unwrap_or(data);
    if body.starts_with(b"<?xml") || body.starts_with(b"<plist") {
        let text = std::str::from_utf8(body).map_err(|_| invalid("not well-formed (invalid token)"))?;
        return XmlParser { text, at: 0 }.document();
    }
    if data.starts_with(b"bplist00") {
        return binary(data);
    }
    Err(invalid("Invalid file"))
}

// ---------------------------------------------------------------- XML reader

struct XmlParser<'a> {
    text: &'a str,
    at: usize,
}

enum Tag<'a> {
    Open(&'a str),
    Empty(&'a str),
    Close(&'a str),
}

impl<'a> XmlParser<'a> {
    fn rest(&self) -> &'a str {
        &self.text[self.at..]
    }

    fn eof() -> Error {
        invalid("no element found")
    }

    fn skip_space(&mut self) {
        let rest = self.rest();
        self.at += rest.len() - rest.trim_start().len();
    }

    /// Skip whitespace, comments, processing instructions and DOCTYPE.
    fn skip_misc(&mut self) -> Result<()> {
        loop {
            self.skip_space();
            let rest = self.rest();
            let end = if rest.starts_with("<?") {
                rest.find("?>").map(|i| i + 2)
            } else if rest.starts_with("<!--") {
                rest.find("-->").map(|i| i + 3)
            } else if rest.starts_with("<!DOCTYPE") {
                rest.find('>').map(|i| i + 1)
            } else {
                return Ok(());
            };
            self.at += end.ok_or_else(Self::eof)?;
        }
    }

    fn tag(&mut self) -> Result<Tag<'a>> {
        self.skip_misc()?;
        let rest = self.rest();
        if rest.is_empty() {
            return Err(Self::eof());
        }
        if !rest.starts_with('<') {
            return Err(invalid("not well-formed (invalid token)"));
        }
        let end = rest.find('>').ok_or_else(Self::eof)?;
        let inner = &rest[1..end];
        self.at += end + 1;
        if let Some(name) = inner.strip_prefix('/') {
            return Ok(Tag::Close(name.trim()));
        }
        let (body, empty) = match inner.strip_suffix('/') {
            Some(body) => (body, true),
            None => (inner, false),
        };
        let name = body.split(|c: char| c.is_whitespace()).next().unwrap_or("");
        if name.is_empty() {
            return Err(invalid("not well-formed (invalid token)"));
        }
        Ok(if empty { Tag::Empty(name) } else { Tag::Open(name) })
    }

    fn document(mut self) -> Result<Plist> {
        let value = match self.tag()? {
            Tag::Open("plist") => {
                let value = self.value()?;
                match self.tag()? {
                    Tag::Close("plist") => value,
                    _ => return Err(invalid("mismatched tag")),
                }
            }
            Tag::Open(name) => self.element(name)?,
            Tag::Empty(name) => self.empty(name)?,
            Tag::Close(_) => return Err(invalid("not well-formed (invalid token)")),
        };
        self.skip_misc()?;
        if !self.rest().is_empty() {
            return Err(invalid("junk after document element"));
        }
        Ok(value)
    }

    fn value(&mut self) -> Result<Plist> {
        match self.tag()? {
            Tag::Open(name) => self.element(name),
            Tag::Empty(name) => self.empty(name),
            Tag::Close(_) => Err(invalid("unexpected element end")),
        }
    }

    fn empty(&self, name: &str) -> Result<Plist> {
        Ok(match name {
            "true" => Plist::Bool(true),
            "false" => Plist::Bool(false),
            "dict" => Plist::dict(),
            "array" => Plist::Array(Vec::new()),
            "string" => Plist::String(String::new()),
            "data" => Plist::Data(Vec::new()),
            "key" => return Err(invalid("missing key value")),
            _ => return Err(invalid("unsupported plist element")),
        })
    }

    /// Text up to the closing tag `name` (entities and CDATA decoded).
    fn text_until(&mut self, name: &str) -> Result<String> {
        let mut out = String::new();
        loop {
            let rest = self.rest();
            if rest.is_empty() {
                return Err(Self::eof());
            }
            if let Some(after) = rest.strip_prefix("<![CDATA[") {
                let end = after.find("]]>").ok_or_else(Self::eof)?;
                out.push_str(&after[..end]);
                self.at += 9 + end + 3;
                continue;
            }
            if rest.starts_with("<!--") {
                let end = rest.find("-->").ok_or_else(Self::eof)?;
                self.at += end + 3;
                continue;
            }
            if rest.starts_with('<') {
                match self.tag()? {
                    Tag::Close(close) if close == name => return Ok(out),
                    _ => return Err(invalid("mismatched tag")),
                }
            }
            let stop = rest.find(['<', '&']).unwrap_or(rest.len());
            out.push_str(&rest[..stop]);
            self.at += stop;
            if self.rest().starts_with('&') {
                let rest = self.rest();
                let end = rest.find(';').ok_or_else(|| invalid("not well-formed (invalid token)"))?;
                let entity = &rest[1..end];
                let c = match entity {
                    "amp" => '&',
                    "lt" => '<',
                    "gt" => '>',
                    "quot" => '"',
                    "apos" => '\'',
                    _ => {
                        let code = if let Some(hex) = entity.strip_prefix("#x").or_else(|| entity.strip_prefix("#X")) {
                            u32::from_str_radix(hex, 16).ok()
                        } else if let Some(decimal) = entity.strip_prefix('#') {
                            decimal.parse::<u32>().ok()
                        } else {
                            None
                        };
                        code.and_then(char::from_u32).ok_or_else(|| invalid("undefined entity"))?
                    }
                };
                out.push(c);
                self.at += end + 1;
            }
        }
    }

    fn element(&mut self, name: &str) -> Result<Plist> {
        match name {
            "dict" => {
                let mut items: Vec<(String, Plist)> = Vec::new();
                loop {
                    match self.tag()? {
                        Tag::Close("dict") => break,
                        Tag::Open("key") => {
                            let key = self.text_until("key")?;
                            let value = self.value()?;
                            match items.iter_mut().find(|(k, _)| *k == key) {
                                Some(slot) => slot.1 = value,
                                None => items.push((key, value)),
                            }
                        }
                        Tag::Empty("key") => {
                            let value = self.value()?;
                            match items.iter_mut().find(|(k, _)| k.is_empty()) {
                                Some(slot) => slot.1 = value,
                                None => items.push((String::new(), value)),
                            }
                        }
                        _ => return Err(invalid("missing key in dictionary")),
                    }
                }
                Ok(Plist::Dict(items))
            }
            "array" => {
                let mut items = Vec::new();
                loop {
                    match self.tag()? {
                        Tag::Close("array") => break,
                        Tag::Open(name) => items.push(self.element(name)?),
                        Tag::Empty(name) => items.push(self.empty(name)?),
                        Tag::Close(_) => return Err(invalid("mismatched tag")),
                    }
                }
                Ok(Plist::Array(items))
            }
            "string" => Ok(Plist::String(self.text_until("string")?)),
            "integer" => {
                let raw = self.text_until("integer")?;
                let raw = raw.trim();
                let parsed = if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
                    i128::from_str_radix(hex, 16)
                } else {
                    raw.parse::<i128>()
                };
                parsed.map(Plist::Integer).map_err(|_| invalid("invalid literal for int()"))
            }
            "real" => {
                let raw = self.text_until("real")?;
                raw.trim().parse::<f64>().map(Plist::Real).map_err(|_| invalid("could not convert string to float"))
            }
            "true" | "false" => {
                let raw = self.text_until(name)?;
                if !raw.trim().is_empty() {
                    return Err(invalid("unexpected text in boolean"));
                }
                Ok(Plist::Bool(name == "true"))
            }
            "data" => {
                let raw = self.text_until("data")?;
                let compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
                base64::engine::general_purpose::STANDARD
                    .decode(compact.as_bytes())
                    .map(Plist::Data)
                    .map_err(|_| invalid("Invalid base64-encoded string"))
            }
            "date" => Ok(Plist::Date(self.text_until("date")?.trim().to_string())),
            "key" => Err(invalid("unexpected key")),
            _ => Err(invalid("unsupported plist element")),
        }
    }
}

// ------------------------------------------------------------- binary reader

fn binary(data: &[u8]) -> Result<Plist> {
    let bad = || invalid("Invalid file");
    if data.len() < 8 + 32 {
        return Err(bad());
    }
    let trailer = &data[data.len() - 32..];
    let offset_size = trailer[6] as usize;
    let ref_size = trailer[7] as usize;
    let be = |bytes: &[u8]| bytes.iter().fold(0u64, |a, b| (a << 8) | *b as u64);
    let count = be(&trailer[8..16]) as usize;
    let top = be(&trailer[16..24]) as usize;
    let table = be(&trailer[24..32]) as usize;
    if !(1..=8).contains(&offset_size) || !(1..=8).contains(&ref_size) || top >= count
        || table.checked_add(count.checked_mul(offset_size).ok_or_else(bad)?).is_none_or(|end| end > data.len() - 32) {
        return Err(bad());
    }
    let offsets: Vec<usize> = (0..count).map(|i| be(&data[table + i * offset_size..table + (i + 1) * offset_size]) as usize).collect();
    let mut reader = Binary { data, offsets, ref_size, active: Vec::new(), nodes: 0 };
    reader.object(top)
}

const MAX_PLIST_DEPTH: usize = 64;
const MAX_PLIST_NODES: usize = 100_000;

struct Binary<'a> {
    data: &'a [u8],
    offsets: Vec<usize>,
    ref_size: usize,
    active: Vec<usize>,
    nodes: usize,
}

impl Binary<'_> {
    fn bytes(&self, at: usize, length: usize) -> Result<&[u8]> {
        at.checked_add(length).and_then(|end| self.data.get(at..end)).ok_or_else(|| invalid("Invalid file"))
    }

    fn uint(&self, at: usize, length: usize) -> Result<u64> {
        Ok(self.bytes(at, length)?.iter().fold(0u64, |a, b| (a << 8) | *b as u64))
    }

    /// Length nibble (`0xF` = following integer object); returns (length, start).
    fn length(&self, at: usize, nibble: u8) -> Result<(usize, usize)> {
        if nibble != 0xF {
            return Ok((nibble as usize, at + 1));
        }
        let marker = *self.bytes(at + 1, 1)?.first().unwrap();
        if marker >> 4 != 1 || (marker & 0xF) > 3 {
            return Err(invalid("Invalid file"));
        }
        let size = 1usize << (marker & 0xF);
        let value = usize::try_from(self.uint(at + 2, size)?).map_err(|_| invalid("Invalid file"))?;
        let start = at.checked_add(2).and_then(|v| v.checked_add(size)).ok_or_else(|| invalid("Invalid file"))?;
        Ok((value, start))
    }

    fn object(&mut self, reference: usize) -> Result<Plist> {
        self.nodes = self.nodes.checked_add(1).ok_or_else(|| invalid("Invalid file"))?;
        if self.nodes > MAX_PLIST_NODES || self.active.len() >= MAX_PLIST_DEPTH {
            return Err(invalid("Invalid file"));
        }
        let at = *self.offsets.get(reference).ok_or_else(|| invalid("Invalid file"))?;
        if self.active.contains(&reference) {
            return Err(invalid("Invalid file"));
        }
        let marker = *self.bytes(at, 1)?.first().unwrap();
        let (kind, nibble) = (marker >> 4, marker & 0xF);
        Ok(match kind {
            0x0 => match marker {
                0x08 => Plist::Bool(false),
                0x09 => Plist::Bool(true),
                _ => return Err(invalid("Invalid file")),
            },
            0x1 => {
                if nibble > 4 {
                    return Err(invalid("Invalid file"));
                }
                let size = 1usize << nibble;
                let raw = self.bytes(at + 1, size)?;
                let value = match size {
                    1 | 2 | 4 => raw.iter().fold(0i128, |a, b| (a << 8) | *b as i128),
                    8 => i64::from_be_bytes(raw.try_into().unwrap()) as i128,
                    16 => i128::from_be_bytes(raw.try_into().unwrap()),
                    _ => return Err(invalid("Invalid file")),
                };
                Plist::Integer(value)
            }
            0x2 => match nibble {
                2 => Plist::Real(f32::from_be_bytes(self.bytes(at + 1, 4)?.try_into().unwrap()) as f64),
                3 => Plist::Real(f64::from_be_bytes(self.bytes(at + 1, 8)?.try_into().unwrap())),
                _ => return Err(invalid("Invalid file")),
            },
            0x3 if marker == 0x33 => {
                let seconds = f64::from_be_bytes(self.bytes(at + 1, 8)?.try_into().unwrap());
                if !seconds.is_finite() || seconds.abs() > 1.0e13 {
                    return Err(invalid("Invalid file"));
                }
                let ts = 978_307_200i64.checked_add(seconds.floor() as i64).ok_or_else(|| invalid("Invalid file"))?;
                let epoch = chrono::DateTime::from_timestamp(ts, 0)
                    .ok_or_else(|| invalid("Invalid file"))?;
                Plist::Date(epoch.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            }
            0x4 => {
                let (length, start) = self.length(at, nibble)?;
                Plist::Data(self.bytes(start, length)?.to_vec())
            }
            0x5 => {
                let (length, start) = self.length(at, nibble)?;
                Plist::String(self.bytes(start, length)?.iter().map(|b| *b as char).collect())
            }
            0x6 => {
                let (length, start) = self.length(at, nibble)?;
                let raw = self.bytes(start, length.checked_mul(2).ok_or_else(|| invalid("Invalid file"))?)?;
                let units: Vec<u16> = raw.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                Plist::String(String::from_utf16(&units).map_err(|_| invalid("Invalid file"))?)
            }
            0x8 => {
                let size = nibble as usize + 1;
                if size > 8 {
                    return Err(invalid("Invalid file"));
                }
                Plist::Uid(self.uint(at + 1, size)?)
            }
            0xA | 0xD => {
                let (length, start) = self.length(at, nibble)?;
                let width = self.ref_size;
                let references = if kind == 0xD {
                    length.checked_mul(2).ok_or_else(|| invalid("Invalid file"))?
                } else {
                    length
                };
                let byte_len = references.checked_mul(width).ok_or_else(|| invalid("Invalid file"))?;
                let raw = self.bytes(start, byte_len)?;
                let mut refs = Vec::with_capacity(references);
                for chunk in raw.chunks(width) {
                    refs.push(chunk.iter().fold(0u64, |a, b| (a << 8) | *b as u64) as usize);
                }
                self.active.push(reference);
                let result = if kind == 0xA {
                    let mut items = Vec::new();
                    for r in refs {
                        items.push(self.object(r)?);
                    }
                    Plist::Array(items)
                } else {
                    let mut dict = Plist::dict();
                    for i in 0..length {
                        let key = match self.object(refs[i])? {
                            Plist::String(key) => key,
                            _ => return Err(invalid("Invalid file")),
                        };
                        let value = self.object(refs[length + i])?;
                        dict.insert(key, value);
                    }
                    dict
                };
                self.active.pop();
                result
            }
            _ => return Err(invalid("Invalid file")),
        })
    }
}

// ---------------------------------------------------------------- XML writer

const HEADER: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n";

fn escape(text: &str) -> Result<String> {
    if text.chars().any(|c| matches!(c as u32, 0..=8 | 11 | 12 | 14..=31)) {
        return Err(Error::value("strings can't contain control characters; use bytes instead"));
    }
    Ok(text.replace("\r\n", "\n").replace('\r', "\n").replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;"))
}

fn line(out: &mut String, level: usize, text: &str) {
    out.extend(std::iter::repeat_n('\t', level));
    out.push_str(text);
    out.push('\n');
}

fn write(out: &mut String, value: &Plist, level: usize) -> Result<()> {
    match value {
        Plist::String(s) => line(out, level, &format!("<string>{}</string>", escape(s)?)),
        Plist::Bool(true) => line(out, level, "<true/>"),
        Plist::Bool(false) => line(out, level, "<false/>"),
        Plist::Integer(n) => {
            if *n < i64::MIN as i128 || *n > u64::MAX as i128 {
                return Err(Error::value("int is too large to convert"));
            }
            line(out, level, &format!("<integer>{}</integer>", n))
        }
        Plist::Uid(n) => line(out, level, &format!("<integer>{}</integer>", n)),
        Plist::Real(f) => line(out, level, &format!("<real>{}</real>", mirra_core::pyfmt::float_repr(*f))),
        Plist::Date(d) => line(out, level, &format!("<date>{}</date>", d)),
        Plist::Data(data) => {
            line(out, level, "<data>");
            let width = 76usize.saturating_sub(8 * level).max(16);
            let chunk = (width / 4) * 3;
            for piece in data.chunks(chunk.max(1)) {
                line(out, level, &base64::engine::general_purpose::STANDARD.encode(piece));
            }
            line(out, level, "</data>");
        }
        Plist::Dict(items) => {
            if items.is_empty() {
                line(out, level, "<dict/>");
            } else {
                line(out, level, "<dict>");
                let mut sorted: Vec<&(String, Plist)> = items.iter().collect();
                sorted.sort_by(|a, b| a.0.cmp(&b.0));
                for (key, item) in sorted {
                    line(out, level + 1, &format!("<key>{}</key>", escape(key)?));
                    write(out, item, level + 1)?;
                }
                line(out, level, "</dict>");
            }
        }
        Plist::Array(items) => {
            if items.is_empty() {
                line(out, level, "<array/>");
            } else {
                line(out, level, "<array>");
                for item in items {
                    write(out, item, level + 1)?;
                }
                line(out, level, "</array>");
            }
        }
    }
    Ok(())
}

/// `plistlib.dumps(value)` (XML, `sort_keys=True`).
pub fn dumps(value: &Plist) -> Result<Vec<u8>> {
    let mut out = String::from(HEADER);
    out.push_str("<plist version=\"1.0\">\n");
    write(&mut out, value, 0)?;
    out.push_str("</plist>\n");
    Ok(out.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn writes_plistlib_format_and_round_trips() {
        let mut value = Plist::from_json(&json!({"e": "a<&>", "a": [], "c": {}, "d": 1.5, "n": 63, "t": true}));
        value.insert("b", Plist::Data(vec![b'x'; 100]));
        let text = String::from_utf8(dumps(&value).unwrap()).unwrap();
        assert_eq!(text, concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
            "<plist version=\"1.0\">\n<dict>\n\t<key>a</key>\n\t<array/>\n\t<key>b</key>\n\t<data>\n",
            "\teHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4\n",
            "\teHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA==\n",
            "\t</data>\n\t<key>c</key>\n\t<dict/>\n\t<key>d</key>\n\t<real>1.5</real>\n",
            "\t<key>e</key>\n\t<string>a&lt;&amp;&gt;</string>\n\t<key>n</key>\n\t<integer>63</integer>\n",
            "\t<key>t</key>\n\t<true/>\n</dict>\n</plist>\n"));
        let parsed = loads(text.as_bytes()).unwrap();
        assert_eq!(parsed.get("b"), Some(&Plist::Data(vec![b'x'; 100])));
        assert_eq!(parsed.get("e").and_then(Plist::as_str), Some("a<&>"));
        assert_eq!(parsed.get("n").and_then(Plist::as_int), Some(63));
    }

    #[test]
    fn rejects_malformed_documents() {
        assert!(loads(b"not a plist").is_err());
        assert!(loads(b"<?xml version=\"1.0\"?><plist><array><dict>").is_err());
        assert!(loads(b"<plist><array><string>x</array></plist>").is_err());
        let empty = loads(b"<?xml version=\"1.0\"?><plist version=\"1.0\"><array/></plist>").unwrap();
        assert_eq!(empty, Plist::Array(vec![]));
        // Crafted binary plist with huge declared array length must fail without OOM.
        let mut crafted = b"bplist00".to_vec();
        crafted.extend_from_slice(&[0xAF, 0x13, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        let table = crafted.len() as u64;
        crafted.push(8); // offset of object 0
        crafted.extend_from_slice(&[0u8; 6]);
        crafted.push(1); // offset_size
        crafted.push(1); // ref_size
        crafted.extend_from_slice(&1u64.to_be_bytes()); // count
        crafted.extend_from_slice(&0u64.to_be_bytes()); // top
        crafted.extend_from_slice(&table.to_be_bytes()); // table
        assert!(loads(&crafted).is_err());
    }

    #[test]
    fn reads_system_launch_agent_and_binary_conversion() {
        // Read-only: Apple's definitions are parsed, never modified.
        let path = std::path::Path::new("/System/Library/LaunchAgents/com.apple.coreservices.uiagent.plist");
        if let Ok(data) = std::fs::read(path) {
            let value = loads(&data).unwrap();
            assert_eq!(value.get("Label").and_then(Plist::as_str), Some("com.apple.coreservices.uiagent"));
            let temp = tempfile::tempdir().unwrap();
            let copy = temp.path().join("binary.plist");
            std::fs::write(&copy, &data).unwrap();
            let converted = std::process::Command::new("/usr/bin/plutil").args(["-convert", "binary1"]).arg(&copy).status();
            if converted.map(|s| s.success()).unwrap_or(false) {
                let binary = std::fs::read(&copy).unwrap();
                assert!(binary.starts_with(b"bplist00"));
                assert_eq!(loads(&binary).unwrap().to_json(), value.to_json());
            }
        }
    }
}
