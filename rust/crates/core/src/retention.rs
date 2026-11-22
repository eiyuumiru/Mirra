//! Retain recent, explicitly retired runtime directories; preserve uncertain data.
//!
//! No glob of old research output grants deletion authority. Only new directories
//! carrying this module's marker can be retired, and the caller must first verify
//! that their app/agent/worker resources have been released.
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::error::{Error, Result};
use crate::processes::{process_birth, Birth};
use crate::state::write_state;
use crate::sys;

pub const MARKER: &str = ".runtime-retention.json";
pub const KEEP_COMPLETED: usize = 3;

static BACKEND: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\Abackend-[0-9]{6,}\z").unwrap());
static NATIVE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\Anative-[0-9]{8}-[0-9]{6}\z").unwrap());

/// Name pattern for a managed kind (`backend` or `native`).
pub fn pattern(kind: &str) -> Option<&'static Regex> {
    match kind {
        "backend" => Some(&BACKEND),
        "native" => Some(&NATIVE),
        _ => None,
    }
}

fn name_matches(kind: &str, directory: &Path) -> bool {
    let name = directory.file_name().and_then(|n| n.to_str()).unwrap_or("");
    pattern(kind).is_some_and(|p| p.is_match(name))
}

fn owned(path: &Path, directory: bool, private: bool) -> Result<libc::stat> {
    let info = sys::lstat(path).map_err(|e| Error::with_path(e, path))?;
    let kind = if directory { sys::is_dir(info.st_mode) } else { sys::is_reg(info.st_mode) };
    let mask = if private { 0o077 } else { 0o022 };
    if !kind || info.st_uid != sys::getuid() || info.st_mode & mask != 0 {
        return Err(Error::runtime("Runtime retention requires private owned files"));
    }
    Ok(info)
}

/// Python `==` between a JSON value and an integer.
fn equals_int(value: Option<&Value>, number: u64) -> bool {
    match value {
        Some(Value::Number(n)) => match (n.as_u64(), n.as_f64()) {
            (Some(v), _) => v == number,
            (None, Some(f)) => f == number as f64,
            _ => false,
        },
        Some(Value::Bool(b)) => (*b as u64) == number,
        _ => false,
    }
}

fn strict_int(value: &Value) -> Option<i64> {
    match value {
        Value::Number(n) if !n.is_f64() => n.as_i64().or_else(|| n.as_u64().map(|v| v as i64)),
        _ => None,
    }
}

/// Owner birth stored in a marker, as a JSON array.
pub fn birth_json(birth: &Birth) -> Value {
    json!([birth.0, birth.1, birth.2, birth.3])
}

fn read(directory: &Path) -> Result<Map<String, Value>> {
    let info = owned(directory, true, true)?;
    let marker = directory.join(MARKER);
    owned(&marker, false, true)?;
    let text = std::fs::read(&marker).map_err(|e| Error::with_path(e, &marker))?;
    let value: Value = serde_json::from_slice(&text).map_err(|e| Error::value(e.to_string()))?;
    let Value::Object(value) = value else {
        return Err(Error::runtime("Runtime retention marker does not identify this directory"));
    };
    let kind = value.get("kind").and_then(Value::as_str).unwrap_or("");
    if !equals_int(value.get("schema_version"), 1) || pattern(kind).is_none() || !name_matches(kind, directory)
        || !equals_int(value.get("inode"), info.st_ino) || !equals_int(value.get("device"), info.st_dev as u64) {
        return Err(Error::runtime("Runtime retention marker does not identify this directory"));
    }
    let valid = match value.get("owner_birth") {
        Some(Value::Array(birth)) if birth.len() == 4 => {
            let numbers: Vec<Option<i64>> = birth.iter().map(strict_int).collect();
            numbers.iter().all(Option::is_some) && numbers[0].unwrap() > 0 && numbers[1].unwrap() == sys::getuid() as i64
        }
        _ => false,
    };
    if !valid {
        return Err(Error::runtime("Runtime retention owner identity is invalid"));
    }
    Ok(value)
}

/// Mark a fresh managed directory as owned by this process.
pub fn track(directory: &Path, kind: &str) -> Result<()> {
    let info = owned(directory, true, true)?;
    if !name_matches(kind, directory) {
        return Err(Error::value("Unexpected managed runtime directory name"));
    }
    if directory.join(MARKER).exists() {
        return Err(Error::runtime("Runtime directory is already tracked"));
    }
    let Some(birth) = process_birth(std::process::id() as i32)? else {
        return Err(Error::runtime("Cannot identify the runtime owner"));
    };
    write_state(&directory.join(MARKER), &json!({"schema_version": 1, "kind": kind,
        "inode": info.st_ino, "device": info.st_dev, "owner_birth": birth_json(&birth), "retired": false}))?;
    Ok(())
}

/// Called only after verified cleanup; existing research output stays unmarked.
pub fn retire(directory: &Path) -> Result<bool> {
    retire_with(directory, &process_birth)
}

pub fn retire_with(directory: &Path, birth: &dyn Fn(i32) -> Result<Option<Birth>>) -> Result<bool> {
    if !directory.join(MARKER).exists() {
        return Ok(false);
    }
    let mut value = read(directory)?;
    let own = birth(std::process::id() as i32)?.map(|b| birth_json(&b)).unwrap_or_else(|| json!([]));
    if value.get("owner_birth") != Some(&own) {
        return Err(Error::runtime("Only the owning controller can retire its runtime directory"));
    }
    if value.get("retired") != Some(&Value::Bool(true)) {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs_f64();
        value.insert("retired".into(), Value::Bool(true));
        value.insert("retired_at".into(), Value::from(now));
        write_state(&directory.join(MARKER), &Value::Object(value))?;
    }
    Ok(true)
}

// Refuse links, sockets, unexpected ownership and writable public files before any
// deletion. Like os.walk(onerror=None), unreadable directories are skipped.
fn check_tree(directory: &Path) -> Result<()> {
    let Ok(entries) = std::fs::read_dir(directory) else { return Ok(()) };
    let mut directories = Vec::new();
    let mut files = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        // os.walk classifies with is_dir() (follows links); both lists are then
        // checked with lstat, so links fail either way.
        if path.is_dir() { directories.push(path) } else { files.push(path) }
    }
    for path in &directories {
        owned(path, true, true)?;
    }
    for path in &files {
        // Every containing directory is private. launchd may create 0644
        // logs there, which remain inaccessible outside the owned tree.
        owned(path, false, false)?;
    }
    for path in &directories {
        check_tree(path)?;
    }
    Ok(())
}

/// Remove all but the `keep` most recently retired directories of `kind`
/// under `root`. Returns `{"removed": [names], "deferred": n, "keep_completed": keep}`.
pub fn prune(root: &Path, kind: &str, protected: &[PathBuf], keep: usize) -> Result<Value> {
    prune_with(root, kind, protected, keep, &process_birth)
}

pub fn prune_with(root: &Path, kind: &str, protected: &[PathBuf], keep: usize,
    birth: &dyn Fn(i32) -> Result<Option<Birth>>) -> Result<Value> {
    if pattern(kind).is_none() || keep < 1 {
        return Err(Error::value("Invalid runtime retention policy"));
    }
    let protected: Vec<PathBuf> = protected.iter().map(|p| crate::paths::absolute(p)).collect();
    let mut eligible: Vec<(f64, PathBuf)> = Vec::new();
    let mut deferred = 0u64;
    for entry in std::fs::read_dir(root).map_err(|e| Error::with_path(e, root))? {
        let directory = entry.map_err(Error::from)?.path();
        if !name_matches(kind, &directory) || !directory.join(MARKER).exists() {
            continue;
        }
        let examined = (|| -> Result<Option<f64>> {
            let value = read(&directory)?;
            if value.get("kind").and_then(Value::as_str) != Some(kind) || value.get("retired") != Some(&Value::Bool(true)) {
                return Ok(None);
            }
            // Backend directories are retired by a still-live supervisor after
            // its cleanup gate passes. Native supervisors must themselves exit.
            if kind == "native" {
                let owner = value["owner_birth"].as_array().cloned().unwrap_or_default();
                let pid = owner.first().and_then(strict_int).unwrap_or(0) as i32;
                if let Some(current) = birth(pid)? {
                    if birth_json(&current) == Value::Array(owner) {
                        return Ok(None);
                    }
                }
            }
            let retired_at = match value.get("retired_at") {
                Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
                _ => return Err(Error::value("Invalid retirement timestamp")),
            };
            check_tree(&directory)?;
            Ok(Some(retired_at))
        })();
        match examined {
            Ok(Some(retired_at)) => eligible.push((retired_at, directory)),
            Ok(None) => {}
            Err(error) if error.is_os_error() || matches!(error, Error::Value(_) | Error::Runtime(_)) => deferred += 1,
            Err(error) => return Err(error),
        }
    }
    eligible.sort_by(|a, b| {
        b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal).then_with(|| b.1.file_name().cmp(&a.1.file_name()))
    });
    let mut removed = Vec::new();
    for (_, directory) in eligible.iter().skip(keep) {
        if protected.contains(&crate::paths::absolute(directory)) {
            continue;
        }
        // Recheck the same inode immediately before removal.
        match read(directory).and_then(|_| std::fs::remove_dir_all(directory).map_err(Error::from)) {
            Ok(()) => removed.push(directory.file_name().unwrap_or_default().to_string_lossy().into_owned()),
            Err(_) => deferred += 1,
        }
    }
    Ok(json!({"removed": removed, "deferred": deferred, "keep_completed": keep}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn directory(root: &Path, name: &str, kind: &str, retired: bool) -> PathBuf {
        let path = root.join(name);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        track(&path, kind).unwrap();
        write_state(&path.join("fixture.json"), &json!({"fixture": true})).unwrap();
        if retired {
            assert!(retire(&path).unwrap());
        }
        path
    }

    fn names(root: &Path) -> std::collections::BTreeSet<String> {
        std::fs::read_dir(root).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn repeated_attempts_keep_three_completed_and_the_active_one() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        for number in 1..=10 {
            directory(root, &format!("backend-{:06}", number), "backend", true);
        }
        let active = directory(root, "backend-000011", "backend", false);
        let evidence = root.join("backend-000000");
        std::fs::create_dir(&evidence).unwrap();
        std::fs::write(evidence.join("validation.json"), "old research").unwrap();
        let report = prune(root, "backend", &[active], KEEP_COMPLETED).unwrap();
        assert_eq!(report["removed"].as_array().unwrap().len(), 7);
        assert_eq!(report["keep_completed"], 3);
        let expected: std::collections::BTreeSet<String> = ["backend-000000", "backend-000008", "backend-000009", "backend-000010", "backend-000011"]
            .iter().map(|s| s.to_string()).collect();
        assert_eq!(names(root), expected);
    }

    #[test]
    fn live_native_owner_and_uncertain_observation_preserve_directories() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        for number in 0..4 {
            directory(root, &format!("native-20260101-00000{}", number), "native", true);
        }
        assert_eq!(prune(root, "native", &[], 3).unwrap()["removed"], json!([]));
        let failing = |_: i32| -> Result<Option<Birth>> { Err(Error::Os(std::io::Error::other("observation failed"))) };
        let report = prune_with(root, "native", &[], 3, &failing).unwrap();
        assert_eq!(report["removed"], json!([]));
        assert_eq!(report["deferred"], 4);
        let gone = |_: i32| -> Result<Option<Birth>> { Ok(None) };
        assert_eq!(prune_with(root, "native", &[], 3, &gone).unwrap()["removed"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn links_and_replaced_identity_are_preserved() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let linked = directory(root, "backend-000001", "backend", true);
        let outside = root.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("precious"), "preserve").unwrap();
        std::os::unix::fs::symlink(&outside, linked.join("link")).unwrap();
        let replaced = directory(root, "backend-000002", "backend", true);
        let mut value: Value = serde_json::from_slice(&std::fs::read(replaced.join(MARKER)).unwrap()).unwrap();
        value["inode"] = json!(value["inode"].as_u64().unwrap() + 1);
        write_state(&replaced.join(MARKER), &value).unwrap();
        for number in 3..7 {
            directory(root, &format!("backend-{:06}", number), "backend", true);
        }
        let report = prune(root, "backend", &[], 3).unwrap();
        assert_eq!(report["deferred"], 2);
        assert!(linked.exists());
        assert!(replaced.exists());
        assert_eq!(std::fs::read_to_string(outside.join("precious")).unwrap(), "preserve");
    }

    #[test]
    fn launchd_log_permissions_inside_private_tree_do_not_prevent_retention() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let first = directory(root, "backend-000001", "backend", true);
        let log = first.join("launchd.log");
        std::fs::write(&log, "diagnostics").unwrap();
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o644)).unwrap();
        let unsafe_dir = directory(root, "backend-000002", "backend", true);
        std::fs::set_permissions(unsafe_dir.join("fixture.json"), std::fs::Permissions::from_mode(0o666)).unwrap();
        for number in 3..6 {
            directory(root, &format!("backend-{:06}", number), "backend", true);
        }
        let report = prune(root, "backend", &[], 3).unwrap();
        assert_eq!(report["removed"], json!(["backend-000001"]));
        assert_eq!(report["deferred"], 1);
        assert!(unsafe_dir.exists());
    }

    #[test]
    fn cannot_retire_another_controller_or_adopt_unmarked_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let path = directory(root, "backend-000001", "backend", false);
        let gone = |_: i32| -> Result<Option<Birth>> { Ok(None) };
        let error = retire_with(&path, &gone).unwrap_err();
        assert_eq!(error.to_string(), "Only the owning controller can retire its runtime directory");
        let unmarked = root.join("backend-000002");
        std::fs::create_dir(&unmarked).unwrap();
        assert!(!retire(&unmarked).unwrap());
        assert_eq!(track(&path, "backend").unwrap_err().to_string(), "Runtime directory is already tracked");
        assert!(prune(root, "other", &[], 3).is_err());
        assert!(prune(root, "backend", &[], 0).is_err());
    }
}
