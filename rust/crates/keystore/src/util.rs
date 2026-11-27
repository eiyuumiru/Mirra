//! Python-semantics helpers for JSON values (truthiness, `type(x) is int`,
//! numeric `==`, `str()` and `repr()`), plus small file and process helpers.
use std::io;
use std::path::Path;

use mirra_core::pyfmt::{float_repr, repr_str};
use serde_json::{Map, Value};

/// Python `bool(value)`.
pub fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// The integer of `value` when `type(value) is int` (bools excluded).
pub fn int_of(value: Option<&Value>) -> Option<i128> {
    match value {
        Some(Value::Number(n)) => n.as_i64().map(i128::from).or_else(|| n.as_u64().map(i128::from)),
        _ => None,
    }
}

/// `type(value) is int`.
pub fn is_int(value: Option<&Value>) -> bool {
    int_of(value).is_some()
}

/// Python `value == number` (`True == 1`, `0.0 == 0`).
pub fn py_eq_int(value: Option<&Value>, number: i64) -> bool {
    match value {
        Some(Value::Bool(b)) => i64::from(*b) == number,
        Some(Value::Number(n)) => match int_of(value) {
            Some(i) => i == i128::from(number),
            None => n.as_f64() == Some(number as f64),
        },
        _ => false,
    }
}

/// Python `str(value)` for a JSON-decoded value (`None` when absent).
pub fn py_str(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => s.clone(),
        None => "None".into(),
        Some(other) => py_repr(other),
    }
}

/// Python `repr(value)` for a JSON-decoded value.
pub fn py_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) if n.is_f64() => {
            let f = n.as_f64().unwrap_or(0.0);
            if f.is_nan() {
                "nan".into()
            } else if f.is_infinite() {
                if f > 0.0 { "inf".into() } else { "-inf".into() }
            } else {
                float_repr(f)
            }
        }
        Value::Number(n) => n.to_string(),
        Value::String(s) => repr_str(s),
        Value::Array(items) => format!("[{}]", items.iter().map(py_repr).collect::<Vec<_>>().join(", ")),
        Value::Object(map) => format!("{{{}}}",
            map.iter().map(|(k, v)| format!("{}: {}", repr_str(k), py_repr(v))).collect::<Vec<_>>().join(", ")),
    }
}

/// `str.strip()` without arguments.
pub fn strip(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || ('\x1c'..='\x1f').contains(&c))
}

/// `dict.get(key)` on an optional object.
pub fn get<'a>(map: Option<&'a Map<String, Value>>, key: &str) -> Option<&'a Value> {
    map.and_then(|m| m.get(key))
}

/// Text of a path (lossy), as `str(path)` prints it.
pub fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Lowercase hexadecimal digest text.
pub fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// `hashlib.sha256(data).hexdigest()`.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(data))
}

/// `secrets.token_hex(count)`.
pub fn token_hex(count: usize) -> String {
    let mut buffer = vec![0u8; count];
    unsafe { libc::arc4random_buf(buffer.as_mut_ptr().cast(), buffer.len()) };
    hex(&buffer)
}

/// `time.time()`.
pub fn now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// `Path.mkdir(mode=mode, parents=True, exist_ok=True)`: only the final
/// component receives `mode`; missing parents use the default mode.
pub fn mkdir_parents(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new().mode(mode).create(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            match std::fs::DirBuilder::new().mode(mode).create(path) {
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => Ok(()),
                other => other,
            }
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => Ok(()),
        Err(e) => Err(e),
    }
}

/// `Path.chmod(mode)` (follows symlinks).
pub fn chmod(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// `Path.unlink(missing_ok=True)`.
pub fn unlink_missing_ok(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn python_value_semantics() {
        assert!(py_eq_int(Some(&json!(true)), 1));
        assert!(py_eq_int(Some(&json!(0.0)), 0));
        assert!(!py_eq_int(Some(&json!("0")), 0));
        assert!(!is_int(Some(&json!(false))));
        assert!(is_int(Some(&json!(u64::MAX))));
        assert_eq!(py_str(None), "None");
        assert_eq!(py_str(Some(&json!(-7))), "-7");
        assert_eq!(py_repr(&json!({"injected": false, "environment": {}, "pid": "12", "x": [null, 1.5]})),
            "{'injected': False, 'environment': {}, 'pid': '12', 'x': [None, 1.5]}");
        assert!(!truthy(Some(&json!(""))));
        assert!(truthy(Some(&json!([0]))));
        assert_eq!(token_hex(32).len(), 64);
    }
}
