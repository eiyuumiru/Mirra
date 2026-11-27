//! The narrow part of `scripts/sharingd.py` the runtime/control layer needs.
//!
//! [`Sharingd`] is the seam used by `NativeService` and the supervisor; its
//! system implementation [`SystemSharingd`] is backed by
//! [`mirra_keystore::SharingdAgent`] (journal validation, restoration under
//! the agent lock and job observation), which shares the journal format with
//! the Python service. [`read_journal`] and [`parse_service`] are kept as
//! standalone helpers with the same validation.
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use mirra_core::launchctl::Reply;
use mirra_core::sys;
use mirra_keystore::sharingd::SharingdContext;
use mirra_keystore::SharingdAgent;
use regex::Regex;
use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::util::{self, strict_int};

pub const ORIGINAL_PLIST: &str = "/System/Library/LaunchAgents/com.apple.sharingd.plist";
pub const PROGRAM: &str = "/usr/libexec/sharingd";

/// sharingd ownership operations used by `NativeService` and the supervisor lease helpers.
pub trait Sharingd: Send + Sync {
    /// `SharingdAgent().read_journal()`
    fn read_journal(&self) -> Result<Option<Map<String, Value>>>;
    /// `SharingdAgent.recover_abandoned(restore_detached=...)`
    fn recover_abandoned(&self, restore_detached: bool) -> Result<Option<Value>>;
    /// `sharingd.service()`: the observed `gui/<uid>/com.apple.sharingd` job.
    fn service(&self) -> Result<Map<String, Value>>;
}

/// `sharingd.is_original(state)`
pub fn is_original(state: &Map<String, Value>) -> bool {
    state.get("program").and_then(Value::as_str) == Some(PROGRAM)
        && state.get("path").and_then(Value::as_str) == Some(ORIGINAL_PLIST)
        && !util::truthy(state.get("injected"))
}

/// Parse `launchctl print` of the sharingd job (`sharingd.service`).
pub fn parse_service(reply: &Reply) -> Result<Map<String, Value>> {
    if reply.code != 0 {
        if reply.stderr.contains("Could not find service") {
            return Ok(Map::new());
        }
        return Err(Error::runtime(format!("Cannot inspect sharingd registration: {}", reply.stderr.trim())));
    }
    let mut values = Map::new();
    values.insert("injected".into(), Value::from(reply.stdout.contains("DYLD_INSERT_LIBRARIES") || reply.stdout.contains("MIRRA_KEYSTORE")));
    let mut environment_values = Map::new();
    let mut environment = false;
    for line in mirra_core::pyfmt::splitlines(&reply.stdout) {
        let line = line.trim();
        if line == "environment = {" {
            environment = true;
        } else if line == "}" {
            environment = false;
        } else if environment {
            if let Some((key, value)) = line.split_once(" => ") {
                if key == "DYLD_INSERT_LIBRARIES" {
                    environment_values.insert(key.into(), Value::from(value));
                }
            }
        }
        if let Some((key, value)) = line.split_once(" = ") {
            if matches!(key, "program" | "path" | "pid" | "state" | "last exit code" | "stdout path" | "stderr path")
                && !values.contains_key(key) {
                values.insert(key.into(), Value::from(value));
            }
        }
    }
    values.insert("environment".into(), Value::Object(environment_values));
    // Python inserts `environment` second; keep that key order.
    let mut ordered = Map::new();
    ordered.insert("injected".into(), values["injected"].clone());
    ordered.insert("environment".into(), values["environment"].clone());
    for (key, value) in values {
        if key != "injected" && key != "environment" {
            ordered.insert(key, value);
        }
    }
    Ok(ordered)
}

static DIGEST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A[0-9a-f]{64}\z").unwrap());
static PID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A[0-9]{1,10}\z").unwrap());

/// Validate the directory or its nearest remaining ancestor; never recreate it.
fn private_directory(directory: &Path) -> Result<bool> {
    let mut parent = directory.to_path_buf();
    let info = loop {
        match sys::lstat(&parent) {
            Ok(info) => break info,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => match parent.parent() {
                Some(up) => parent = up.to_path_buf(),
                None => return Err(mirra_core::Error::with_path(e, &parent).into()),
            },
            Err(e) => return Err(mirra_core::Error::with_path(e, &parent).into()),
        }
    };
    if !sys::private_owned(&info, true) {
        return Err(Error::runtime("sharingd ownership directory is not private"));
    }
    Ok(parent == directory)
}

/// `SharingdAgent.read_journal` for `<home>/Library/Caches/Mirra/sharing.json`.
pub fn read_journal(journal: &Path) -> Result<Option<Map<String, Value>>> {
    let info = match sys::lstat(journal) {
        Ok(info) => info,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
        Err(e) => return Err(mirra_core::Error::with_path(e, journal).into()),
    };
    if !sys::private_owned(&info, false) {
        return Err(Error::runtime("sharingd ownership journal is not a private owned file"));
    }
    let record = util::read_json(journal)?;
    let Value::Object(record) = record else { return Err(Error::runtime("Invalid sharingd ownership journal")) };
    let schema = strict_int(record.get("schema_version"));
    if !matches!(schema, Some(1) | Some(2)) {
        return Err(Error::runtime("Invalid sharingd ownership journal"));
    }
    let birth = record.get("controller_birth");
    let detached = record.get("detached") == Some(&Value::Bool(true));
    if !(detached && matches!(birth, None | Some(Value::Null))) {
        let valid = birth.and_then(Value::as_array).is_some_and(|items| {
            items.len() == 4 && items.iter().all(|v| strict_int(Some(v)).is_some())
                && strict_int(items.first()).unwrap_or(0) > 0
                && strict_int(items.get(1)) == Some(sys::getuid() as i64)
        });
        if !valid {
            return Err(Error::runtime("Invalid sharingd controller identity"));
        }
    }
    let Some(directory) = record.get("directory").and_then(Value::as_str) else {
        return Err(Error::runtime("Invalid sharingd ownership directory"));
    };
    let directory = PathBuf::from(directory);
    if !directory.is_absolute() || mirra_core::paths::resolve(&directory) != directory {
        return Err(Error::runtime("Invalid sharingd ownership directory"));
    }
    private_directory(&directory)?;
    let digest = if schema == Some(1) { "plist_sha256" } else { "config_sha256" };
    if !record.get(digest).and_then(Value::as_str).is_some_and(|d| DIGEST.is_match(d)) {
        return Err(Error::runtime("Invalid sharingd launch configuration digest"));
    }
    if schema == Some(2) {
        if let Some(pid) = record.get("injected_pid").filter(|v| !v.is_null()) {
            let text = match pid {
                Value::String(s) => s.clone(),
                Value::Bool(b) => if *b { "True".into() } else { "False".into() },
                other => other.to_string(),
            };
            if !PID.is_match(&text) {
                return Err(Error::runtime("Invalid sharingd adapter process"));
            }
        }
    }
    Ok(Some(record))
}

/// The real per-user sharingd ownership, through [`SharingdAgent`].
pub struct SystemSharingd {
    pub context: SharingdContext,
}

impl SystemSharingd {
    /// The current user's session with `home` as `Path.home()`.
    pub fn new(home: &Path) -> Self {
        let mut context = SharingdContext::system();
        context.home = home.to_path_buf();
        SystemSharingd { context }
    }

    pub fn journal(&self) -> PathBuf {
        self.context.cache().join("sharing.json")
    }
}

impl Sharingd for SystemSharingd {
    fn read_journal(&self) -> Result<Option<Map<String, Value>>> {
        Ok(SharingdAgent::with_context(None, self.context.clone()).read_journal()?)
    }

    fn recover_abandoned(&self, restore_detached: bool) -> Result<Option<Value>> {
        Ok(SharingdAgent::recover_abandoned_with(restore_detached, self.context.clone())?)
    }

    fn service(&self) -> Result<Map<String, Value>> {
        Ok(self.context.service(None, Duration::from_secs(15))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirra_core::state::write_state;
    use serde_json::json;

    #[test]
    fn parses_the_job_and_recognizes_apple_original() {
        let reply = Reply { code: 0, stderr: String::new(), stdout: format!(
            "gui/501/com.apple.sharingd = {{\n\tpath = {}\n\tprogram = {}\n\tpid = 12\n\tenvironment = {{\n\t\tDYLD_INSERT_LIBRARIES => /x.dylib\n\t}}\n}}\n",
            ORIGINAL_PLIST, PROGRAM) };
        let state = parse_service(&reply).unwrap();
        assert_eq!(state["pid"], "12");
        assert_eq!(state["environment"]["DYLD_INSERT_LIBRARIES"], "/x.dylib");
        assert!(!is_original(&state));
        let reply = Reply { code: 0, stderr: String::new(), stdout: format!("path = {}\nprogram = {}\n", ORIGINAL_PLIST, PROGRAM) };
        assert!(is_original(&parse_service(&reply).unwrap()));
        let missing = Reply { code: 113, stdout: String::new(), stderr: "Could not find service".into() };
        assert!(parse_service(&missing).unwrap().is_empty());
        let failed = Reply { code: 125, stdout: String::new(), stderr: "Domain unavailable\n".into() };
        assert_eq!(parse_service(&failed).unwrap_err().to_string(), "Cannot inspect sharingd registration: Domain unavailable");
    }

    #[test]
    fn journal_is_validated_before_use() {
        let temp = tempfile::tempdir().unwrap();
        let root = mirra_core::paths::resolve(temp.path());
        let journal = root.join("sharing.json");
        assert!(read_journal(&journal).unwrap().is_none());
        let directory = root.join("runtime/native-1/backend-000001");
        let uid = sys::getuid();
        write_state(&journal, &json!({"schema_version": 1, "controller_birth": [45, uid, 90, 1],
            "directory": directory.to_string_lossy(), "plist_sha256": "a".repeat(64)})).unwrap();
        assert!(read_journal(&journal).unwrap().is_some());
        write_state(&journal, &json!({"schema_version": 2, "detached": true, "injected_pid": 77,
            "directory": directory.to_string_lossy(), "config_sha256": "b".repeat(64)})).unwrap();
        assert_eq!(read_journal(&journal).unwrap().unwrap()["injected_pid"], 77);
        write_state(&journal, &json!({"schema_version": 1, "controller_birth": [45, uid + 1, 90, 1],
            "directory": directory.to_string_lossy(), "plist_sha256": "a".repeat(64)})).unwrap();
        assert_eq!(read_journal(&journal).unwrap_err().to_string(), "Invalid sharingd controller identity");
    }

    #[test]
    fn system_implementation_uses_the_keystore_agent() {
        use std::sync::{Arc, Mutex};
        let temp = tempfile::tempdir().unwrap();
        let home = mirra_core::paths::resolve(temp.path());
        let calls = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
        let mut sharingd = SystemSharingd::new(&home);
        let seen = calls.clone();
        sharingd.context.launchctl = Arc::new(move |args: &[String], _| {
            seen.lock().unwrap().push(args.to_vec());
            Ok(Reply { code: 0, stderr: String::new(), stdout: format!("path = {}\nprogram = {}\npid = 9\n", ORIGINAL_PLIST, PROGRAM) })
        });
        assert_eq!(sharingd.journal(), home.join("Library/Caches/Mirra/sharing.json"));
        // Nothing journaled: recovery takes the agent lock and changes nothing.
        assert!(sharingd.read_journal().unwrap().is_none());
        assert!(sharingd.recover_abandoned(true).unwrap().is_none());
        assert!(calls.lock().unwrap().is_empty());
        assert!(home.join("Library/Caches/Mirra/sharingd-agent.lock").exists());
        assert!(is_original(&sharingd.service().unwrap()));
        assert_eq!(calls.lock().unwrap()[0][0], "print");
        // A held agent lock is reported, not waited for.
        let mut holder = SharingdAgent::with_context(None, sharingd.context.clone());
        holder.acquire().unwrap();
        assert_eq!(sharingd.recover_abandoned(true).unwrap_err().type_name(), "BlockingIOError");
    }
}
