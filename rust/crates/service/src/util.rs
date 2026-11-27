//! Small Python-semantics helpers shared by the runtime/control modules.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{Local, Timelike};
use mirra_core::processes::Birth;
use mirra_core::sys;
use serde_json::{Map, Value};

use crate::error::{Error, Result};

/// Replaceable `process_birth` (tests).
pub type BirthProbe = Arc<dyn Fn(i32) -> mirra_core::Result<Option<Birth>> + Send + Sync>;

pub fn real_birth() -> BirthProbe {
    Arc::new(mirra_core::processes::process_birth)
}

/// `Path.home()`.
pub fn home() -> PathBuf {
    mirra_core::paths::expanduser(Path::new("~"))
}

/// Python truthiness of a JSON value.
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

/// `mapping[key]` (KeyError when missing).
pub fn get<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a Value> {
    map.get(key).ok_or_else(|| Error::key(key))
}

/// `str` value of `mapping[key]` (KeyError / TypeError).
pub fn get_str<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    get(map, key)?.as_str().ok_or_else(|| Error::type_error(format!("expected str for {}", key)))
}

/// `mapping.get(key, {})` where a non-object is treated as empty.
pub fn object<'a>(map: &'a Map<String, Value>, key: &str) -> &'a Map<String, Value> {
    static EMPTY: std::sync::LazyLock<Map<String, Value>> = std::sync::LazyLock::new(Map::new);
    map.get(key).and_then(Value::as_object).unwrap_or(&EMPTY)
}

/// `type(value) is int` (booleans and floats excluded).
pub fn strict_int(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Number(n)) if !n.is_f64() => n.as_i64(),
        _ => None,
    }
}

/// Python `value == number` for JSON numbers and booleans.
pub fn equals_number(value: Option<&Value>, number: i64) -> bool {
    match value {
        Some(Value::Number(n)) => match n.as_i64() {
            Some(i) => i == number,
            None => n.as_f64() == Some(number as f64),
        },
        Some(Value::Bool(b)) => (*b as i64) == number,
        _ => false,
    }
}

/// Numeric view for Python comparisons (`TypeError` for other values).
pub fn number(value: &Value, name: &str) -> Result<f64> {
    match value {
        Value::Number(n) => Ok(n.as_f64().unwrap_or(0.0)),
        Value::Bool(b) => Ok(*b as i64 as f64),
        _ => Err(Error::type_error(format!("'<' not supported for {}", name))),
    }
}

/// `birth[0]` of a recorded identity (TypeError unless a list starting with an int).
pub fn birth_pid(birth: &Value) -> Result<i32> {
    let first = birth.as_array().and_then(|items| items.first())
        .ok_or_else(|| Error::type_error("Invalid process identity"))?;
    strict_int(Some(first)).and_then(|pid| i32::try_from(pid).ok())
        .ok_or_else(|| Error::type_error("Invalid process identity"))
}

/// `observed == tuple(recorded)` for a process identity.
pub fn birth_matches(observed: &Option<Birth>, recorded: &Value) -> bool {
    let (Some((pid, uid, seconds, micros)), Some(items)) = (observed, recorded.as_array()) else { return false };
    items.len() == 4
        && strict_int(items.first()) == Some(*pid as i64)
        && strict_int(items.get(1)) == Some(*uid as i64)
        && items.get(2).and_then(Value::as_u64) == Some(*seconds) && strict_int(items.get(2)).is_some()
        && items.get(3).and_then(Value::as_u64) == Some(*micros) && strict_int(items.get(3)).is_some()
}

/// `process_birth(birth[0]) == tuple(birth)`.
pub fn alive(probe: &BirthProbe, birth: &Value) -> Result<bool> {
    let pid = birth_pid(birth)?;
    Ok(birth_matches(&probe(pid)?, birth))
}

/// `json.loads(path.read_text())`
pub fn read_json(path: &Path) -> Result<Value> {
    let data = std::fs::read(path).map_err(|e| mirra_core::Error::with_path(e, path))?;
    let text = String::from_utf8(data).map_err(|e| Error::value(e.to_string()))?;
    serde_json::from_str(&text).map_err(|e| Error::value(e.to_string()))
}

/// `json.loads(...)` that must be an object (`message` otherwise).
pub fn read_object(path: &Path, message: &str) -> Result<Map<String, Value>> {
    match read_json(path)? {
        Value::Object(map) => Ok(map),
        _ => Err(Error::value(message)),
    }
}

/// `NativeService.private_file`: a private regular file owned by this user.
pub fn private_file(path: &Path) -> Result<()> {
    let info = sys::lstat(path).map_err(|e| mirra_core::Error::with_path(e, path))?;
    if !sys::private_owned(&info, false) {
        return Err(Error::runtime(format!("Expected a private, user-owned support file: {}", path.display())));
    }
    Ok(())
}

/// `datetime.now().isoformat()` (local, naive).
pub fn local_isoformat() -> String {
    let now = Local::now();
    let micros = now.nanosecond() / 1000 % 1_000_000;
    if micros == 0 {
        now.format("%Y-%m-%dT%H:%M:%S").to_string()
    } else {
        format!("{}.{:06}", now.format("%Y-%m-%dT%H:%M:%S"), micros)
    }
}

/// `shutil.copy2`: contents, permission bits and timestamps.
pub fn copy2(source: &Path, target: &Path) -> Result<()> {
    std::fs::copy(source, target).map_err(|e| mirra_core::Error::with_path(e, source))?;
    let info = std::fs::metadata(source).map_err(|e| mirra_core::Error::with_path(e, source))?;
    if let (Ok(accessed), Ok(modified)) = (info.accessed(), info.modified()) {
        let file = std::fs::OpenOptions::new().write(true).open(target).map_err(|e| mirra_core::Error::with_path(e, target))?;
        let _ = file.set_times(std::fs::FileTimes::new().set_accessed(accessed).set_modified(modified));
    }
    Ok(())
}

/// `Path.chmod(mode)`
pub fn chmod(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| mirra_core::Error::with_path(e, path))?;
    Ok(())
}

/// `str(path)`
pub fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Print `json.dumps(value)` followed by a newline to stdout (Python `print`).
pub fn print_json(value: &Value) {
    let mut line = mirra_core::pyjson::dumps(value);
    line.push('\n');
    let _ = sys::write_all(1, line.as_bytes());
}

/// Recursively sort object keys (`json.dumps(..., sort_keys=True)`).
pub fn sort_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            Value::Object(keys.into_iter().map(|k| (k.clone(), sort_keys(&map[k]))).collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_keys).collect()),
        other => other.clone(),
    }
}

/// Python `str(value)` of a scalar JSON value.
pub fn py_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "None".into(),
        Value::Bool(b) => if *b { "True".into() } else { "False".into() },
        other => other.to_string(),
    }
}

/// `value[:limit]` for a Python `str` (code points).
pub fn truncate_chars(text: &str, limit: usize) -> String {
    match text.char_indices().nth(limit) {
        Some((index, _)) => text[..index].to_string(),
        None => text.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn python_semantics() {
        assert!(!truthy(Some(&json!(0))) && truthy(Some(&json!("x"))) && !truthy(Some(&json!({}))));
        assert!(birth_matches(&Some((4, 501, 10, 2)), &json!([4, 501, 10, 2])));
        assert!(!birth_matches(&Some((4, 501, 10, 2)), &json!([4, 501, 10, 3])));
        assert!(!birth_matches(&None, &json!([4, 501, 10, 2])));
        assert!(birth_pid(&json!("x")).is_err());
        assert!(equals_number(Some(&json!(5.0)), 5) && !equals_number(Some(&json!("5")), 5));
        assert_eq!(truncate_chars("é😀ab", 2), "é😀");
        assert_eq!(mirra_core::pyjson::dumps(&sort_keys(&json!({"b": 1, "a": {"d": 1, "c": 2}}))),
            r#"{"a": {"c": 2, "d": 1}, "b": 1}"#);
    }
}
