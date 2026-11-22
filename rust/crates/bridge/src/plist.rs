//! XML property lists as written and read by Python's `plistlib` (the
//! usbmuxd and lockdown protocols use XML plists).
//!
//! Values map to JSON: dict → object, array → array, string → string,
//! integer/real → number, true/false → bool. `<data>` is decoded to its
//! base64 text and `<date>` to its ISO text (Mirra never reads either).
use serde_json::{Map, Number, Value};

use mirra_core::Error;

const HEADER: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n";

/// `plistlib.dumps(value)` (XML, sorted keys).
pub fn dumps(value: &Value) -> Result<Vec<u8>, Error> {
    let mut out = String::from(HEADER);
    write(&mut out, value, 0)?;
    out.push_str("</plist>\n");
    Ok(out.into_bytes())
}

fn escape(text: &str) -> Result<String, Error> {
    if text.chars().any(|c| matches!(c as u32, 0..=8 | 11 | 12 | 14..=31)) {
        return Err(Error::Value("strings can't contain control characters; use bytes instead".into()));
    }
    Ok(text.replace("\r\n", "\n").replace('\r', "\n").replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;"))
}

fn line(out: &mut String, depth: usize, text: &str) {
    out.extend(std::iter::repeat_n('\t', depth));
    out.push_str(text);
    out.push('\n');
}

fn write(out: &mut String, value: &Value, depth: usize) -> Result<(), Error> {
    match value {
        Value::Null => return Err(Error::Value("unsupported type: <class 'NoneType'>".into())),
        Value::Bool(true) => line(out, depth, "<true/>"),
        Value::Bool(false) => line(out, depth, "<false/>"),
        Value::Number(n) if n.is_f64() => {
            line(out, depth, &format!("<real>{}</real>", mirra_core::pyfmt::float_repr(n.as_f64().unwrap_or(0.0))))
        }
        Value::Number(n) => line(out, depth, &format!("<integer>{}</integer>", n)),
        Value::String(s) => line(out, depth, &format!("<string>{}</string>", escape(s)?)),
        Value::Array(items) if items.is_empty() => line(out, depth, "<array/>"),
        Value::Array(items) => {
            line(out, depth, "<array>");
            for item in items {
                write(out, item, depth + 1)?;
            }
            line(out, depth, "</array>");
        }
        Value::Object(map) if map.is_empty() => line(out, depth, "<dict/>"),
        Value::Object(map) => {
            line(out, depth, "<dict>");
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                line(out, depth + 1, &format!("<key>{}</key>", escape(key)?));
                write(out, &map[key], depth + 1)?;
            }
            line(out, depth, "</dict>");
        }
    }
    Ok(())
}

fn invalid() -> Error {
    Error::Value("Invalid file".into())
}

/// `plistlib.loads(data)` for XML property lists.
pub fn loads(data: &[u8]) -> Result<Value, Error> {
    let text = std::str::from_utf8(data).map_err(|_| invalid())?;
    let mut parser = Parser { s: text, i: 0 };
    parser.misc()?;
    let root = parser.open()?;
    if root.name != "plist" || root.empty {
        return Err(invalid());
    }
    parser.misc()?;
    let value = parser.value()?;
    parser.misc()?;
    parser.close("plist")?;
    parser.misc()?;
    if parser.i != parser.s.len() {
        return Err(invalid());
    }
    Ok(value)
}

struct Tag {
    name: String,
    empty: bool,
}

struct Parser<'a> {
    s: &'a str,
    i: usize,
}

impl Parser<'_> {
    fn rest(&self) -> &str {
        &self.s[self.i..]
    }

    fn whitespace(&mut self) {
        let rest = self.rest();
        self.i += rest.len() - rest.trim_start_matches([' ', '\t', '\r', '\n']).len();
    }

    /// Skip whitespace, processing instructions, comments and DOCTYPE.
    fn misc(&mut self) -> Result<(), Error> {
        loop {
            self.whitespace();
            let (start, end) = if self.rest().starts_with("<?") {
                ("<?", "?>")
            } else if self.rest().starts_with("<!--") {
                ("<!--", "-->")
            } else if self.rest().starts_with("<!") {
                ("<!", ">")
            } else {
                return Ok(());
            };
            let found = self.rest()[start.len()..].find(end).ok_or_else(invalid)?;
            self.i += start.len() + found + end.len();
        }
    }

    fn open(&mut self) -> Result<Tag, Error> {
        if !self.rest().starts_with('<') || self.rest().starts_with("</") {
            return Err(invalid());
        }
        let end = self.rest().find('>').ok_or_else(invalid)?;
        let inner = &self.rest()[1..end];
        let (inner, empty) = match inner.strip_suffix('/') {
            Some(stripped) => (stripped, true),
            None => (inner, false),
        };
        let name = inner.split([' ', '\t', '\r', '\n']).next().unwrap_or("").to_string();
        if name.is_empty() {
            return Err(invalid());
        }
        self.i += end + 1;
        Ok(Tag { name, empty })
    }

    fn close(&mut self, name: &str) -> Result<(), Error> {
        let expected = format!("</{}", name);
        if !self.rest().starts_with(&expected) {
            return Err(invalid());
        }
        self.i += expected.len();
        self.whitespace();
        if !self.rest().starts_with('>') {
            return Err(invalid());
        }
        self.i += 1;
        Ok(())
    }

    /// Character data up to the closing tag, with entities decoded.
    fn text(&mut self, name: &str) -> Result<String, Error> {
        let mut out = String::new();
        loop {
            let rest = self.rest();
            let stop = rest.find(['<', '&']).ok_or_else(invalid)?;
            out.push_str(&rest[..stop]);
            self.i += stop;
            if self.rest().starts_with("<!--") {
                let found = self.rest().find("-->").ok_or_else(invalid)?;
                self.i += found + 3;
            } else if self.rest().starts_with("<![CDATA[") {
                let found = self.rest().find("]]>").ok_or_else(invalid)?;
                out.push_str(&self.rest()[9..found]);
                self.i += found + 3;
            } else if self.rest().starts_with('&') {
                let end = self.rest().find(';').ok_or_else(invalid)?;
                let entity = &self.rest()[1..end];
                let c = match entity {
                    "amp" => '&',
                    "lt" => '<',
                    "gt" => '>',
                    "quot" => '"',
                    "apos" => '\'',
                    _ => {
                        let number = if let Some(hex) = entity.strip_prefix("#x") {
                            u32::from_str_radix(hex, 16).ok()
                        } else if let Some(decimal) = entity.strip_prefix('#') {
                            decimal.parse().ok()
                        } else {
                            None
                        };
                        number.and_then(char::from_u32).ok_or_else(invalid)?
                    }
                };
                out.push(c);
                self.i += end + 1;
            } else {
                self.close(name)?;
                return Ok(out);
            }
        }
    }

    fn value(&mut self) -> Result<Value, Error> {
        let tag = self.open()?;
        let name = tag.name.as_str();
        match name {
            "true" | "false" => {
                if !tag.empty {
                    self.misc()?;
                    self.close(name)?;
                }
                Ok(Value::Bool(name == "true"))
            }
            "dict" => {
                let mut map = Map::new();
                if tag.empty {
                    return Ok(Value::Object(map));
                }
                loop {
                    self.misc()?;
                    if self.rest().starts_with("</") {
                        self.close("dict")?;
                        return Ok(Value::Object(map));
                    }
                    let key = self.open()?;
                    if key.name != "key" {
                        return Err(invalid());
                    }
                    let key = if key.empty { String::new() } else { self.text("key")? };
                    self.misc()?;
                    let value = self.value()?;
                    map.insert(key, value);
                }
            }
            "array" => {
                let mut items = Vec::new();
                if tag.empty {
                    return Ok(Value::Array(items));
                }
                loop {
                    self.misc()?;
                    if self.rest().starts_with("</") {
                        self.close("array")?;
                        return Ok(Value::Array(items));
                    }
                    items.push(self.value()?);
                }
            }
            "string" | "integer" | "real" | "data" | "date" => {
                let text = if tag.empty { String::new() } else { self.text(name)? };
                match name {
                    "integer" => {
                        let raw = text.trim();
                        let parsed = if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
                            i64::from_str_radix(hex, 16).ok().map(Number::from)
                        } else {
                            raw.parse::<i64>().ok().map(Number::from).or_else(|| raw.parse::<u64>().ok().map(Number::from))
                        };
                        parsed.map(Value::Number).ok_or_else(|| Error::Value(format!("invalid literal for int() with base 10: {}",
                            mirra_core::pyfmt::repr_str(raw))))
                    }
                    "real" => text.trim().parse::<f64>().ok().and_then(Number::from_f64).map(Value::Number)
                        .ok_or_else(|| Error::Value(format!("could not convert string to float: {}", mirra_core::pyfmt::repr_str(&text)))),
                    "data" => Ok(Value::String(text.split_whitespace().collect())),
                    _ => Ok(Value::String(text)),
                }
            }
            _ => Err(invalid()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn writes_plistlib_xml() {
        let message = json!({"ClientVersionString": "Mirra", "ProgName": "Mirra", "kLibUSBMuxVersion": 3,
            "MessageType": "Connect", "DeviceID": 7, "PortNumber": 52410});
        assert_eq!(String::from_utf8(dumps(&message).unwrap()).unwrap(), "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n\t<key>ClientVersionString</key>\n\t<string>Mirra</string>\n\t<key>DeviceID</key>\n\t<integer>7</integer>\n\t<key>MessageType</key>\n\t<string>Connect</string>\n\t<key>PortNumber</key>\n\t<integer>52410</integer>\n\t<key>ProgName</key>\n\t<string>Mirra</string>\n\t<key>kLibUSBMuxVersion</key>\n\t<integer>3</integer>\n</dict>\n</plist>\n");
        let nested = json!({"a": [], "b": {}, "c": true, "d": "x<&>y", "e": [1, {"f": false}], "g": 1.5});
        let text = dumps(&nested).unwrap();
        assert_eq!(String::from_utf8(text.clone()).unwrap(), "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n\t<key>a</key>\n\t<array/>\n\t<key>b</key>\n\t<dict/>\n\t<key>c</key>\n\t<true/>\n\t<key>d</key>\n\t<string>x&lt;&amp;&gt;y</string>\n\t<key>e</key>\n\t<array>\n\t\t<integer>1</integer>\n\t\t<dict>\n\t\t\t<key>f</key>\n\t\t\t<false/>\n\t\t</dict>\n\t</array>\n\t<key>g</key>\n\t<real>1.5</real>\n</dict>\n</plist>\n");
        assert_eq!(loads(&text).unwrap(), nested);
        assert!(dumps(&json!({"a": null})).is_err());
    }

    #[test]
    fn reads_usbmuxd_style_replies() {
        let reply = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n\t<key>DeviceList</key>\n\t<array>\n\t\t<dict>\n\t\t\t<key>DeviceID</key>\n\t\t\t<integer>3</integer>\n\t\t\t<key>MessageType</key>\n\t\t\t<string>Attached</string>\n\t\t\t<key>Properties</key>\n\t\t\t<dict>\n\t\t\t\t<key>ConnectionType</key>\n\t\t\t\t<string>USB</string>\n\t\t\t\t<key>NetworkAddress</key>\n\t\t\t\t<data>\n\t\t\t\tEAIAAAAA\n\t\t\t\t</data>\n\t\t\t\t<key>SerialNumber</key>\n\t\t\t\t<string>a&amp;b&#x41;</string>\n\t\t\t\t<key>Speed</key><real>4.8e8</real>\n\t\t\t</dict>\n\t\t</dict>\n\t</array>\n<!-- c -->\n</dict>\n</plist>\n";
        let value = loads(reply).unwrap();
        assert_eq!(value["DeviceList"][0]["DeviceID"], 3);
        assert_eq!(value["DeviceList"][0]["Properties"]["SerialNumber"], "a&bA");
        assert_eq!(value["DeviceList"][0]["Properties"]["NetworkAddress"], "EAIAAAAA");
        assert_eq!(value["DeviceList"][0]["Properties"]["Speed"], 4.8e8);
        for bad in [&b"bplist00"[..], b"<plist><dict><key>a</key></dict></plist>", b"<plist><string>x</plist>",
                    b"<plist><integer>x</integer></plist>", b"<plist><dict/></plist>junk"] {
            assert!(loads(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
    }
}
