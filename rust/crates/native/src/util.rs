//! Small Python-semantics helpers shared by the native modules.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mirra_core::processes::{self, Birth};
use mirra_core::{Error, Result};
use serde_json::Value;

/// `Path.home()`.
pub fn home() -> PathBuf {
    mirra_core::paths::expanduser(Path::new("~"))
}

/// Replaceable `process_birth` (tests).
pub type BirthProbe = Arc<dyn Fn(i32) -> Result<Option<Birth>> + Send + Sync>;

pub fn real_birth() -> BirthProbe {
    Arc::new(processes::process_birth)
}

pub fn own_pid() -> i32 {
    std::process::id() as i32
}

pub fn birth_value(birth: &Option<Birth>) -> Value {
    match birth {
        Some(b) => mirra_core::retention::birth_json(b),
        None => Value::Null,
    }
}

/// Python `value == number` for JSON values (`True == 1`, `1.0 == 1`).
pub fn eq_int(value: Option<&Value>, number: i64) -> bool {
    match value {
        Some(Value::Number(n)) => match n.as_i64() {
            Some(i) => i == number,
            None => n.as_f64() == Some(number as f64),
        },
        Some(Value::Bool(b)) => (*b as i64) == number,
        _ => false,
    }
}

/// Python `type(value) is int`.
pub fn strict_int(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Number(n)) if !n.is_f64() => n.as_i64(),
        _ => None,
    }
}

/// Python `str(value)` for JSON scalars.
pub fn py_str(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "None".into(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(true)) => "True".into(),
        Some(Value::Bool(false)) => "False".into(),
        Some(Value::Number(n)) => match n.as_i64() {
            Some(i) => i.to_string(),
            None => n.as_u64().map(|u| u.to_string()).unwrap_or_else(|| mirra_core::pyfmt::float_repr(n.as_f64().unwrap_or(0.0))),
        },
        Some(other) => mirra_core::pyjson::dumps(other),
    }
}

/// `json.loads(path.read_text())`.
pub fn read_json(path: &Path) -> Result<Value> {
    let data = std::fs::read(path).map_err(|e| Error::with_path(e, path))?;
    serde_json::from_slice(&data).map_err(|e| Error::value(e.to_string()))
}

pub fn object(value: Value, message: &str) -> Result<serde_json::Map<String, Value>> {
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(Error::value(message)),
    }
}

/// `time.monotonic()` as used across processes (macOS: mach absolute time).
pub fn monotonic() -> f64 {
    let mut value = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_UPTIME_RAW, &mut value) };
    value.tv_sec as f64 + value.tv_nsec as f64 / 1e9
}

/// `str.strip()` on launchctl text.
pub fn strip(text: &str) -> String {
    text.trim().to_string()
}

/// Python `str.isdecimal()` for ASCII launchctl values.
pub fn is_decimal(text: &str) -> bool {
    !text.is_empty() && text.chars().all(|c| c.is_ascii_digit())
}

/// `path.touch(mode=0o600, exist_ok=False)`.
pub fn touch_new(path: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
        .map(|_| ()).map_err(|e| Error::with_path(e, path))
}

pub fn chmod(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| Error::with_path(e, path))
}

/// `Path.mkdir(mode=0o700, parents=True, exist_ok=True)`: parents use the
/// default mode, the leaf is created 0700.
pub fn mkdir_private(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            std::fs::create_dir_all(parent).map_err(|e| Error::with_path(e, parent))?;
        }
    }
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => Ok(()),
        Err(e) => Err(Error::with_path(e, path)),
    }
}

pub fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// `platform.machine()` (uname machine, e.g. `x86_64`, `arm64`).
pub fn machine() -> String {
    let mut name: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut name) } != 0 {
        return String::new();
    }
    unsafe { std::ffi::CStr::from_ptr(name.machine.as_ptr()) }.to_string_lossy().into_owned()
}
