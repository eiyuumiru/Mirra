//! Small Python-semantics helpers (truthiness, `str()`, whitespace).
use std::io;

use serde_json::Value;

/// Python `bool(value)` for a JSON value.
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `type(value) is int` (JSON integers; bools are separate in serde).
pub fn is_int(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Number(n)) if n.is_i64() || n.is_u64())
}

/// `value == number` with Python numeric equality (`2.0 == 2`).
pub fn equals_number(value: Option<&Value>, number: i64) -> bool {
    match value {
        Some(Value::Number(n)) => match n.as_i64() {
            Some(i) => i == number,
            None => n.as_f64() == Some(number as f64),
        },
        _ => false,
    }
}

/// Python `str(value)` for a JSON-decoded value.
pub fn py_str(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "None".into(),
        Some(Value::Bool(true)) => "True".into(),
        Some(Value::Bool(false)) => "False".into(),
        Some(Value::Number(n)) => match n.as_f64() {
            Some(f) if n.is_f64() => mirra_core::pyfmt::float_repr(f),
            _ => n.to_string(),
        },
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// `str.isspace()` for one character.
pub fn is_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

/// `str.strip()` without arguments.
pub fn strip(text: &str) -> &str {
    text.trim_matches(is_space)
}

/// `str.isprintable()` for one character. Approximates the Unicode
/// categories Python excludes (Cc, Cf, Cs, Co, Zl, Zp, Zs other than space);
/// unassigned code points are not detected.
pub fn is_printable(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    if c.is_control() || c.is_whitespace() {
        return false;
    }
    let n = c as u32;
    let format = matches!(n, 0xAD | 0x600..=0x605 | 0x61C | 0x6DD | 0x70F | 0x8E2 | 0x180E | 0x200B..=0x200F
        | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD
        | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F);
    let private = matches!(n, 0xE000..=0xF8FF | 0xF0000..=0xFFFFD | 0x100000..=0x10FFFD);
    let noncharacter = (0xFDD0..=0xFDEF).contains(&n) || n & 0xFFFE == 0xFFFE;
    !(format || private || noncharacter)
}

/// `urllib.parse.quote_plus(text)`.
pub fn quote_plus(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => out.push(byte as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

/// `urllib.parse.urlencode(pairs)` for text values.
pub fn urlencode(pairs: &[(&str, &str)]) -> String {
    pairs.iter().map(|(k, v)| format!("{}={}", quote_plus(k), quote_plus(v))).collect::<Vec<_>>().join("&")
}

/// Whether an I/O error is a socket timeout (`socket.timeout` / `TimeoutError`).
pub fn is_timeout(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
        || matches!(error.raw_os_error(), Some(libc::EAGAIN) | Some(libc::ETIMEDOUT))
}

/// An `io::Error` as the Python exception a socket call raises: timeouts
/// become `TimeoutError('timed out')`.
pub fn socket_error(error: io::Error) -> mirra_core::Error {
    if is_timeout(&error) && error.raw_os_error() != Some(libc::ETIMEDOUT) {
        mirra_core::Error::Timeout("timed out".into())
    } else {
        mirra_core::Error::Os(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn python_semantics() {
        assert!(!truthy(&json!(0)) && !truthy(&json!("")) && !truthy(&json!({})) && truthy(&json!([0])));
        assert!(truthy(&json!(0.5)) && !truthy(&json!(0.0)) && !truthy(&Value::Null));
        assert!(is_int(Some(&json!(3))) && !is_int(Some(&json!(true))) && !is_int(Some(&json!(3.0))));
        assert!(equals_number(Some(&json!(2.0)), 2) && !equals_number(Some(&json!("2")), 2));
        assert_eq!(py_str(Some(&json!(3))), "3");
        assert_eq!(py_str(None), "None");
        assert_eq!(strip(" \t\u{a0}x y\r\n\u{1c}"), "x y");
        assert!(is_printable('é') && !is_printable('\u{200b}') && !is_printable('\n') && !is_printable('\u{a0}'));
        assert_eq!(urlencode(&[("client", "AB-12"), ("name", "Dino’s Mac mini ~_.-+&=")]),
            "client=AB-12&name=Dino%E2%80%99s+Mac+mini+~_.-%2B%26%3D");
    }
}
