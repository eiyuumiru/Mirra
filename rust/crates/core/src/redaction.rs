//! Remove credential material while retaining the actual diagnostic message.
use std::collections::HashSet;
use std::sync::LazyLock;

use regex::{Captures, Regex};
use serde_json::{Map, Value};

pub const REDACTED: &str = "<redacted>";
pub const MAX_TEXT: usize = 8192;
pub const MAX_ITEMS: usize = 128;
pub const MAX_DEPTH: usize = 16;

pub const SENSITIVE_FIELDS: &[&str] = &["password", "passphrase", "private_key", "public_key", "key",
    "certificate", "dcrt", "data", "ltk", "local_ltk", "remote_ltk", "token",
    "_auth", "auth_token", "signature", "proof", "pairing_data", "encrypted_data",
    "payload", "ciphertext", "identity", "serial", "udid"];

const EXTRA_NORMALIZED: &[&str] = &["authtoken", "pairingtoken", "localkey", "remotekey", "keymaterial",
    "devicecertificate", "certificatebody", "signedkey", "encryptedpayload"];

/// `re.sub(r'[^a-z0-9]', '', key.lower())`
pub fn normalize_key(key: &str) -> String {
    key.to_lowercase().chars().filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit()).collect()
}

static SENSITIVE_NORMALIZED: LazyLock<HashSet<String>> = LazyLock::new(|| {
    SENSITIVE_FIELDS.iter().map(|k| normalize_key(k)).chain(EXTRA_NORMALIZED.iter().map(|k| k.to_string())).collect()
});

pub fn is_sensitive_key(key: &str) -> bool {
    SENSITIVE_NORMALIZED.contains(&normalize_key(key))
}

static PEM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)-----BEGIN [^-\r\n]+-----.*?(?:-----END [^-\r\n]+-----|\z)").unwrap()
});
static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(r"(?i)(\b(?:password|passphrase|_auth|auth_token|token|private_key|ltk|local_ltk|remote_ltk|signature|ciphertext)\b\s*[=:]\s*)",
        r#"(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;}]+)"#)).unwrap()
});
static HEX_LITERAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b0x[0-9a-fA-F]{32,}\b").unwrap());
static ANSI: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\x1b\[[0-?]*[ -/]*[@-~]").unwrap());

fn blob_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'+' || c == b'/'
}

/// Python's BLOB pattern, which uses look-around Rust's regex lacks:
/// `(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{48,}={0,2}|[0-9a-fA-F]{32,})(?![A-Za-z0-9+/])`
fn redact_blobs(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        if !blob_char(bytes[i]) || (i > 0 && blob_char(bytes[i - 1])) {
            i += 1;
            continue;
        }
        let mut end = i;
        while end < bytes.len() && blob_char(bytes[end]) {
            end += 1;
        }
        let at = |k: usize| bytes.get(k).copied();
        let not_blob = |k: usize| at(k).is_none_or(|c| !blob_char(c));
        let matched = if end - i >= 48 {
            let equals = (0..2).take_while(|k| at(end + k) == Some(b'=')).count();
            let take = match equals {
                2 if not_blob(end + 2) => 2,
                2 => 1,
                1 if not_blob(end + 1) => 1,
                _ => 0,
            };
            Some(end + take)
        } else if end - i >= 32 && bytes[i..end].iter().all(u8::is_ascii_hexdigit) {
            Some(end)
        } else {
            None
        };
        match matched {
            Some(stop) => {
                out.push_str(&text[copied..i]);
                out.push_str(REDACTED);
                copied = stop;
                i = stop;
            }
            None => i = end,
        }
    }
    out.push_str(&text[copied..]);
    out
}

pub fn redact_text(text: &str) -> String {
    let text = ANSI.replace_all(text, "");
    let text = PEM.replace_all(&text, REDACTED);
    let text = ASSIGNMENT.replace_all(&text, |m: &Captures| format!("{}{}", &m[1], REDACTED));
    let text = HEX_LITERAL.replace_all(&text, REDACTED);
    let text = redact_blobs(&text);
    text.chars().filter(|c| *c == '\n' || *c == '\t' || (*c as u32) >= 32).take(MAX_TEXT).collect()
}

/// `redact_text(bytes)`: UTF-8 text is redacted; otherwise a size placeholder.
pub fn redact_bytes(data: &[u8]) -> String {
    match std::str::from_utf8(data) {
        Ok(text) => redact_text(text),
        Err(_) => format!("<binary output: {} bytes>", data.len()),
    }
}

pub fn redact_value(value: &Value) -> Value {
    redact_value_at(value, 0)
}

fn redact_value_at(value: &Value, depth: usize) -> Value {
    if depth > MAX_DEPTH {
        return Value::from("<nested data omitted>");
    }
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, item) in map.iter().take(MAX_ITEMS) {
                let item = if is_sensitive_key(key) { Value::from(REDACTED) } else { redact_value_at(item, depth + 1) };
                out.insert(key.clone(), item);
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().take(MAX_ITEMS).map(|v| redact_value_at(v, depth + 1)).collect()),
        Value::String(text) => Value::from(redact_text(text)),
        other => other.clone(),
    }
}

/// A JSON line is redacted structurally and re-encoded compactly; any other
/// line is redacted as text.
pub fn redact_line(raw: &[u8]) -> String {
    match serde_json::from_slice::<Value>(raw) {
        Ok(value) => crate::pyjson::dumps_compact(&redact_value(&value)),
        Err(_) => redact_bytes(raw),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redaction_keeps_actual_failure_prose_and_codes() {
        let text = "ssh: connect to host 192.0.2.4 port 22: Connection refused; token=private-token";
        let clean = redact_text(text);
        assert!(clean.contains("192.0.2.4 port 22: Connection refused"));
        assert!(!clean.contains("private-token"));
        assert!(clean.ends_with("token=<redacted>"));
        let line = json!({"status": -536870212, "error": "new_device_failure", "data": "short-secret",
            "reply": {"password": "secret-password", "local_ltk": "short-key"}}).to_string();
        let redacted = redact_line(line.as_bytes());
        let value: Value = serde_json::from_str(&redacted).unwrap();
        assert_eq!(value["status"], -536870212);
        assert_eq!(value["error"], "new_device_failure");
        assert!(!redacted.contains("short-secret") && !redacted.contains("secret-password") && !redacted.contains("short-key"));
        assert_eq!(redacted, r#"{"status":-536870212,"error":"new_device_failure","data":"<redacted>","reply":{"password":"<redacted>","local_ltk":"<redacted>"}}"#);
    }

    #[test]
    fn blobs_pem_ansi_and_limits() {
        let b64 = "A".repeat(48);
        assert_eq!(redact_text(&format!("x {}== y", b64)), "x <redacted> y");
        assert_eq!(redact_text(&format!("{}==A", b64)), "<redacted>=A");
        assert_eq!(redact_text(&format!("{}=A", b64)), "<redacted>=A");
        assert_eq!(redact_text(&"G".repeat(47)), "G".repeat(47));
        assert_eq!(redact_text(&"A".repeat(40)), REDACTED);
        assert_eq!(redact_text(&format!("id {}", "ab".repeat(16))), "id <redacted>");
        assert_eq!(redact_text(&format!("id {}g", "ab".repeat(16))), format!("id {}g", "ab".repeat(16)));
        assert_eq!(redact_text(&format!("v=0x{}", "f".repeat(32))), "v=<redacted>");
        assert_eq!(redact_text("a -----BEGIN KEY-----\nabc\n-----END KEY----- b"), "a <redacted> b");
        assert_eq!(redact_text("a -----BEGIN KEY-----\nabc"), "a <redacted>");
        assert_eq!(redact_text("\x1b[31mred\x1b[0m\x07 ok\tz"), "red ok\tz");
        assert_eq!(redact_text("Password: \"two words\", next"), "Password: <redacted>, next");
        assert_eq!(redact_text(&"x ".repeat(5000)).chars().count(), 8192);
        assert_eq!(redact_bytes(b"\xff\x00"), "<binary output: 2 bytes>");
        assert_eq!(redact_line(b"\xffnot json"), "<binary output: 9 bytes>");
        assert_eq!(redact_line(b"plain token: abc"), "plain token: <redacted>");
    }

    #[test]
    fn value_limits_and_keys() {
        assert_eq!(redact_value(&json!({"Auth-Token": "x", "Device Certificate": "y", "ok": 1.5, "n": null})),
            json!({"Auth-Token": REDACTED, "Device Certificate": REDACTED, "ok": 1.5, "n": null}));
        let mut nested = json!("leaf");
        for _ in 0..20 {
            nested = json!([nested]);
        }
        let mut cursor = &redact_value(&nested);
        let mut depth = 0;
        while let Value::Array(items) = cursor {
            cursor = &items[0];
            depth += 1;
        }
        assert_eq!(depth, 17);
        assert_eq!(cursor, &json!("<nested data omitted>"));
        let long: Vec<i32> = (0..200).collect();
        assert_eq!(redact_value(&json!(long)).as_array().unwrap().len(), 128);
    }
}
