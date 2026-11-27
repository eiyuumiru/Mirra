//! Byte-compatible equivalents of Python `json.dumps` variants used by Mirra.
//!
//! * [`dumps`]          = `json.dumps(v)` (ensure_ascii, `", "`/`": "`)
//! * [`dumps_unicode`]  = `json.dumps(v, ensure_ascii=False)`
//! * [`dumps_compact`]  = `json.dumps(v, ensure_ascii=False, separators=(',', ':'))`
//! * [`dumps_pretty`]   = `json.dumps(v, indent=2)` (ensure_ascii)
use serde_json::Value;

use crate::pyfmt::float_repr;

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub indent: Option<usize>,
    pub ensure_ascii: bool,
    pub item_separator: &'static str,
    pub key_separator: &'static str,
}

impl Options {
    /// Python defaults: separators depend on whether `indent` is set.
    pub fn python(indent: Option<usize>, ensure_ascii: bool) -> Self {
        Options { indent, ensure_ascii, item_separator: if indent.is_some() { "," } else { ", " }, key_separator: ": " }
    }
}

pub fn dumps(value: &Value) -> String {
    dumps_with(value, &Options::python(None, true))
}

pub fn dumps_unicode(value: &Value) -> String {
    dumps_with(value, &Options::python(None, false))
}

pub fn dumps_compact(value: &Value) -> String {
    dumps_with(value, &Options { indent: None, ensure_ascii: false, item_separator: ",", key_separator: ":" })
}

pub fn dumps_pretty(value: &Value) -> String {
    dumps_with(value, &Options::python(Some(2), true))
}

pub fn dumps_with(value: &Value, options: &Options) -> String {
    let mut out = String::new();
    write_value(&mut out, value, options, 0);
    out
}

fn newline(out: &mut String, options: &Options, level: usize) {
    if let Some(indent) = options.indent {
        out.push('\n');
        out.extend(std::iter::repeat_n(' ', indent * level));
    }
}

fn write_value(out: &mut String, value: &Value, options: &Options, level: usize) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => {
            if number.is_f64() {
                let f = number.as_f64().unwrap();
                if f.is_nan() {
                    out.push_str("NaN")
                } else if f.is_infinite() {
                    out.push_str(if f > 0.0 { "Infinity" } else { "-Infinity" })
                } else {
                    out.push_str(&float_repr(f))
                }
            } else {
                out.push_str(&number.to_string())
            }
        }
        Value::String(text) => write_string(out, text, options.ensure_ascii),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(options.item_separator);
                }
                newline(out, options, level + 1);
                write_value(out, item, options, level + 1);
            }
            newline(out, options, level);
            out.push(']');
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (key, item)) in map.iter().enumerate() {
                if i > 0 {
                    out.push_str(options.item_separator);
                }
                newline(out, options, level + 1);
                write_string(out, key, options.ensure_ascii);
                out.push_str(options.key_separator);
                write_value(out, item, options, level + 1);
            }
            newline(out, options, level);
            out.push('}');
        }
    }
}

/// A JSON string literal exactly as Python's encoder writes it.
pub fn write_string(out: &mut String, text: &str, ensure_ascii: bool) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if ensure_ascii && (c as u32) > 0x7e => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{:04x}", unit));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn formats_like_python() {
        let value = json!({"a": 1, "b": [1, 2.5, "\u{e9}\u{1F600}\n"], "c": {}, "d": [], "e": null, "f": true});
        let escaped = concat!("{\"a\": 1, \"b\": [1, 2.5, \"", "\\", "u00e9", "\\", "ud83d", "\\", "ude00", "\\", "n\"], \"c\": {}, \"d\": [], \"e\": null, \"f\": true}");
        assert_eq!(dumps(&value), escaped);
        assert_eq!(dumps_unicode(&json!({"k": "é\u{7f}"})), "{\"k\": \"é\u{7f}\"}");
        assert_eq!(dumps(&json!({"k": "\u{7f}"})), concat!("{\"k\": \"", "\\", "u007f\"}"));
        assert_eq!(dumps_compact(&json!({"a": [1, {"b": "x"}]})), r#"{"a":[1,{"b":"x"}]}"#);
        assert_eq!(dumps_pretty(&json!({"a": [1, 2], "b": {}, "c": {"d": 1.0}})),
            "{\n  \"a\": [\n    1,\n    2\n  ],\n  \"b\": {},\n  \"c\": {\n    \"d\": 1.0\n  }\n}");
    }
}
