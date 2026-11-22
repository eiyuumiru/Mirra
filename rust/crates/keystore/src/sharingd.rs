//! Exclusive, journaled ownership of the temporary sharingd adapter
//! (port of `scripts/sharingd.py`).
//!
//! Apple's sharingd job is never replaced. Mirra sets two variables in
//! launchd's user environment, restarts the job with `kickstart -k` and
//! removes the variables again, so the adapter loads into the new process
//! while launchd keeps every sharingd service name registered. Restoring is
//! another `kickstart -k`.
//!
//! When Mirra stops normally it detaches instead: sharingd keeps running with
//! the adapter and the next start adopts it, so the iPhone does not renew its
//! pairing secret (and ask for its passcode) on each stop/start. Updates,
//! removal and new setups restore Apple's sharingd.
//!
//! The journal (`~/Library/Caches/Mirra/sharing.json`) is shared with the
//! Python service: either implementation adopts or restores the other's
//! session, so its fields and JSON layout are unchanged.
use std::collections::BTreeMap;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use mirra_core::launchctl::Reply;
use mirra_core::paths;
use mirra_core::processes::{self, Birth};
use mirra_core::state::write_state;
use mirra_core::sys;
use mirra_core::{Error, Result};
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::plist::{self, Format, Plist};
use crate::util::{self, py_str, text};

pub const ORIGINAL_PLIST: &str = "/System/Library/LaunchAgents/com.apple.sharingd.plist";
pub const PROGRAM: &str = "/usr/libexec/sharingd";
pub const LABEL: &str = "com.apple.sharingd";
pub const ADAPTER_VARIABLES: [&str; 2] = ["DYLD_INSERT_LIBRARIES", "MIRRA_KEYSTORE_CONFIG"];
pub const RESTART_SECONDS: u64 = 8;
const LAUNCHCTL_TIMEOUT: Duration = Duration::from_secs(15);

/// Runs `launchctl <arguments>` with a timeout.
pub type Launchctl = Arc<dyn Fn(&[String], Duration) -> Result<Reply> + Send + Sync>;
/// `processes.process_birth`.
pub type BirthProbe = Arc<dyn Fn(i32) -> Result<Option<Birth>> + Send + Sync>;

/// The system seams of sharingd ownership: home directory, `launchctl`,
/// process identity and timing. Tests substitute every one of them.
#[derive(Clone)]
pub struct SharingdContext {
    /// `Path.home()`
    pub home: PathBuf,
    pub uid: u32,
    pub launchctl: Launchctl,
    pub process_birth: BirthProbe,
    /// How long a restarted job may take to show its new process.
    pub restart: Duration,
    pub interval: Duration,
}

impl Default for SharingdContext {
    fn default() -> Self {
        Self::system()
    }
}

impl SharingdContext {
    /// The real user session: `$HOME`, `/bin/launchctl`, `proc_pidinfo`.
    pub fn system() -> Self {
        SharingdContext {
            home: paths::expanduser(Path::new("~")),
            uid: sys::getuid(),
            launchctl: Arc::new(mirra_core::launchctl::run::<String>),
            process_birth: Arc::new(processes::process_birth),
            restart: Duration::from_secs(RESTART_SECONDS),
            interval: Duration::from_millis(100),
        }
    }

    pub fn domain(&self) -> String {
        format!("gui/{}", self.uid)
    }
    pub fn target(&self) -> String {
        format!("{}/{}", self.domain(), LABEL)
    }
    /// `~/Library/Sharing/AutoUnlock`
    pub fn auto_unlock(&self) -> PathBuf {
        self.home.join("Library/Sharing/AutoUnlock")
    }
    /// `~/Library/Caches/Mirra`
    pub fn cache(&self) -> PathBuf {
        self.home.join("Library/Caches/Mirra")
    }

    pub fn launchctl(&self, arguments: &[&str]) -> Result<Reply> {
        self.launchctl_timeout(arguments, LAUNCHCTL_TIMEOUT)
    }

    fn launchctl_timeout(&self, arguments: &[&str], timeout: Duration) -> Result<Reply> {
        let arguments: Vec<String> = arguments.iter().map(|a| a.to_string()).collect();
        (self.launchctl)(&arguments, timeout)
    }

    /// `service(target, timeout=)`: the job's registration, `{}` when absent.
    pub fn service(&self, target: Option<&str>, timeout: Duration) -> Result<Map<String, Value>> {
        let target = target.map(str::to_string).unwrap_or_else(|| self.target());
        let reply = self.launchctl_timeout(&["print", &target], timeout)?;
        if reply.code != 0 {
            if reply.stderr.contains("Could not find service") {
                return Ok(Map::new());
            }
            return Err(Error::runtime(format!("Cannot inspect sharingd registration: {}", util::strip(&reply.stderr))));
        }
        Ok(parse_service(&reply.stdout))
    }

    fn current(&self) -> Result<Map<String, Value>> {
        self.service(None, LAUNCHCTL_TIMEOUT)
    }

    /// Adapter variables currently present in launchd's user environment.
    pub fn launchd_variables(&self) -> Result<Map<String, Value>> {
        let mut present = Map::new();
        for name in ADAPTER_VARIABLES {
            let reply = self.launchctl(&["getenv", name])?;
            let value = util::strip(&reply.stdout);
            if reply.code == 0 && !value.is_empty() {
                present.insert(name.into(), Value::from(value));
            }
        }
        Ok(present)
    }

    pub fn clear_launchd_variables(&self) -> Result<()> {
        for name in ADAPTER_VARIABLES {
            self.launchctl(&["unsetenv", name])?;
        }
        if !self.launchd_variables()?.is_empty() {
            return Err(Error::runtime("Cannot remove the sharingd adapter variables from launchd"));
        }
        Ok(())
    }

    /// Wait until the job runs a process other than `previous` (a pid text).
    pub fn wait_for_new_process(&self, previous: Option<&Value>) -> Result<Map<String, Value>> {
        let deadline = Instant::now() + self.restart;
        loop {
            let current = self.current()?;
            let pid = current.get("pid");
            if util::truthy(pid) && pid != previous {
                return Ok(current);
            }
            if Instant::now() > deadline {
                return Ok(current);
            }
            std::thread::sleep(self.interval);
        }
    }
}

/// `sharingd.launchctl(...)` with the real `launchctl`.
pub fn launchctl(arguments: &[&str]) -> Result<Reply> {
    SharingdContext::system().launchctl(arguments)
}

/// `sharingd.service(target=None, timeout=15)` for the real user session.
pub fn service(target: Option<&str>, timeout: Duration) -> Result<Map<String, Value>> {
    SharingdContext::system().service(target, timeout)
}

/// Fields of `launchctl print` output: `injected`, the explicit
/// `DYLD_INSERT_LIBRARIES` of the job's `environment` block, then the first
/// `program`, `path`, `pid`, `state`, `last exit code`, `stdout path` and
/// `stderr path` values, in output order (all values are text).
pub fn parse_service(stdout: &str) -> Map<String, Value> {
    const KEYS: [&str; 7] = ["program", "path", "pid", "state", "last exit code", "stdout path", "stderr path"];
    let mut values = Map::new();
    values.insert("injected".into(), Value::Bool(stdout.contains("DYLD_INSERT_LIBRARIES") || stdout.contains("MIRRA_KEYSTORE")));
    let mut environment = Map::new();
    let mut fields: Vec<(String, Value)> = Vec::new();
    let mut inside = false;
    for line in mirra_core::pyfmt::splitlines(stdout) {
        let line = util::strip(line);
        if line == "environment = {" {
            inside = true;
        } else if line == "}" {
            inside = false;
        } else if inside {
            if let Some((key, value)) = line.split_once(" => ") {
                if key == "DYLD_INSERT_LIBRARIES" {
                    environment.insert(key.into(), Value::from(value));
                }
            }
        }
        if let Some((key, value)) = line.split_once(" = ") {
            if KEYS.contains(&key) && !fields.iter().any(|(k, _)| k == key) {
                fields.push((key.into(), Value::from(value)));
            }
        }
    }
    values.insert("environment".into(), Value::Object(environment));
    values.extend(fields);
    values
}

pub fn is_original(state: &Map<String, Value>) -> bool {
    state.get("program").and_then(Value::as_str) == Some(PROGRAM)
        && state.get("path").and_then(Value::as_str) == Some(ORIGINAL_PLIST)
        && !util::truthy(state.get("injected"))
}

type Dict = BTreeMap<String, Plist>;

fn read_plist(path: &Path) -> Result<(Option<Dict>, Format)> {
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((None, Format::Binary)),
        Err(e) => return Err(Error::with_path(e, path)),
    };
    let format = if data.starts_with(b"bplist") { Format::Binary } else { Format::Xml };
    let (value, _) = plist::loads(&data)?;
    Ok((match value {
        Plist::Dict(map) => Some(map),
        _ => None,
    }, format))
}

fn write_plist(path: &Path, value: Dict, format: Format, mode: u32) -> Result<()> {
    let mut name = std::ffi::OsString::from(".");
    name.push(path.file_name().unwrap_or_default());
    name.push(".mirra");
    let temporary = path.with_file_name(name);
    let data = plist::dumps(&Plist::Dict(value), format)?;
    std::fs::write(&temporary, data).map_err(|e| Error::with_path(e, &temporary))?;
    util::chmod(&temporary, mode).map_err(|e| Error::with_path(e, &temporary))?;
    std::fs::rename(&temporary, path).map_err(|e| Error::with_path(e, &temporary))?;
    Ok(())
}

/// Copy this Mac's iPhone Mirroring pairing entries out of sharingd's files.
///
/// sharingd keeps the iPhone's signed LTK (ltk.plist, "Remote LTKs") and its
/// pairing ID (pairing-records.plist) in plain files. Apple's unmodified
/// sharingd, which runs while Mirra is stopped, removes these entries because
/// the matching local key validates only through the bridge. Only entries
/// with "Attested LTK Data" are copied; entries are added or updated, never
/// removed. Returns the number of saved devices.
pub fn backup_pairing_in(auto_unlock: &Path, backup: &Path) -> Result<usize> {
    let (ltks, _) = read_plist(&auto_unlock.join("ltk.plist"))?;
    let (records, _) = read_plist(&auto_unlock.join("pairing-records.plist"))?;
    let Some(Plist::Dict(remote)) = ltks.as_ref().and_then(|l| l.get("Remote LTKs")) else { return Ok(0) };
    let (saved, _) = read_plist(backup)?;
    let mut saved = saved.unwrap_or_default();
    let mut changed = false;
    for (device, entry) in remote {
        if !matches!(entry.get("Attested LTK Data"), Some(Plist::Data(_))) || !matches!(entry, Plist::Dict(_)) {
            continue;
        }
        let mut value = Dict::new();
        value.insert("ltk".into(), entry.clone());
        if let Some(record @ Plist::Dict(_)) = records.as_ref().and_then(|r| r.get(device)) {
            value.insert("pairing".into(), record.clone());
        }
        let value = Plist::Dict(value);
        if saved.get(device) != Some(&value) {
            saved.insert(device.clone(), value);
            changed = true;
        }
    }
    let count = saved.len();
    if changed {
        if let Some(parent) = backup.parent() {
            util::mkdir_parents(parent, 0o700).map_err(|e| Error::with_path(e, parent))?;
        }
        write_plist(backup, saved, Format::Binary, 0o600)?;
    }
    Ok(count)
}

/// Put back missing pairing entries before sharingd (with the adapter)
/// loads them. Returns the number of restored entries.
pub fn restore_pairing_in(auto_unlock: &Path, backup: &Path) -> Result<usize> {
    let (saved, _) = read_plist(backup)?;
    let Some(saved) = saved.filter(|s| !s.is_empty()) else { return Ok(0) };
    let (ltk_path, record_path) = (auto_unlock.join("ltk.plist"), auto_unlock.join("pairing-records.plist"));
    let (ltks, ltk_format) = read_plist(&ltk_path)?;
    let (records, record_format) = read_plist(&record_path)?;
    let mut ltks = ltks.unwrap_or_default();
    let mut records = records.unwrap_or_default();
    let remote = ltks.entry("Remote LTKs".into()).or_insert_with(|| Plist::Dict(Dict::new()));
    let Some(remote) = remote.as_dict_mut() else { return Ok(0) };
    let mut restored = 0;
    for (device, value) in &saved {
        let Some(Plist::Dict(ltk)) = value.get("ltk") else { continue };
        let current = remote.get(device);
        if !matches!(current.and_then(|c| c.get("Attested LTK Data")), Some(Plist::Data(_))) {
            let mut merged = current.and_then(Plist::as_dict).cloned().unwrap_or_default();
            merged.extend(ltk.iter().map(|(k, v)| (k.clone(), v.clone())));
            remote.insert(device.clone(), Plist::Dict(merged));
            restored += 1;
        }
        if let Some(pairing @ Plist::Dict(_)) = value.get("pairing") {
            if !records.contains_key(device) {
                records.insert(device.clone(), pairing.clone());
                restored += 1;
            }
        }
    }
    if restored > 0 {
        std::fs::create_dir_all(auto_unlock).map_err(|e| Error::with_path(e, auto_unlock))?;
        write_plist(&ltk_path, ltks, ltk_format, 0o644)?;
        write_plist(&record_path, records, record_format, 0o644)?;
    }
    Ok(restored)
}

/// Remove the iPhone Mirroring pairings Mirra created, so the next session
/// pairs from scratch. Only entries with "Attested LTK Data" (keys that live
/// on the bridge) and their pairing records are removed; anything else in
/// sharingd's files is kept. Returns the number of removed devices.
pub fn forget_pairing_in(auto_unlock: &Path) -> Result<usize> {
    let (ltk_path, record_path) = (auto_unlock.join("ltk.plist"), auto_unlock.join("pairing-records.plist"));
    let (ltks, ltk_format) = read_plist(&ltk_path)?;
    let Some(mut ltks) = ltks else { return Ok(0) };
    let Some(remote) = ltks.get_mut("Remote LTKs").and_then(Plist::as_dict_mut) else { return Ok(0) };
    let devices: Vec<String> = remote.iter()
        .filter(|(_, entry)| matches!(entry.get("Attested LTK Data"), Some(Plist::Data(_))))
        .map(|(device, _)| device.clone())
        .collect();
    if devices.is_empty() {
        return Ok(0);
    }
    for device in &devices {
        remote.remove(device);
    }
    write_plist(&ltk_path, ltks, ltk_format, 0o644)?;
    let (records, record_format) = read_plist(&record_path)?;
    if let Some(mut records) = records {
        let before = records.len();
        records.retain(|device, _| !devices.contains(device));
        if records.len() != before {
            write_plist(&record_path, records, record_format, 0o644)?;
        }
    }
    Ok(devices.len())
}

/// `forget_pairing_in` for the current user's AutoUnlock files.
pub fn forget_pairing() -> Result<usize> {
    forget_pairing_in(&SharingdContext::system().auto_unlock())
}

/// `backup_pairing(backup)` for the current user's AutoUnlock files.
pub fn backup_pairing(backup: &Path) -> Result<usize> {
    backup_pairing_in(&SharingdContext::system().auto_unlock(), backup)
}

/// `restore_pairing(backup)` for the current user's AutoUnlock files.
pub fn restore_pairing(backup: &Path) -> Result<usize> {
    restore_pairing_in(&SharingdContext::system().auto_unlock(), backup)
}

/// Validate the directory or its nearest remaining ancestor; never recreate
/// it. `Ok(true)` when the directory itself exists.
fn private_directory(directory: &Path, uid: u32) -> Result<bool> {
    let mut parent = directory.to_path_buf();
    let info = loop {
        match sys::lstat(&parent) {
            Ok(info) => break info,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                parent = match parent.parent() {
                    Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
                    _ => PathBuf::from("."),
                };
            }
            Err(e) => return Err(Error::with_path(e, &parent)),
        }
    };
    if !sys::is_dir(info.st_mode) || info.st_uid != uid || info.st_mode & 0o077 != 0 {
        return Err(Error::runtime("sharingd ownership directory is not private"));
    }
    Ok(parent == directory)
}

static DIGEST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A[0-9a-f]{64}\z").unwrap());
static PID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A[0-9]{1,10}\z").unwrap());

fn birth_value(birth: Birth) -> Value {
    json!([birth.0, birth.1, birth.2, birth.3])
}

fn record_directory(record: &Map<String, Value>) -> PathBuf {
    paths::normalize(Path::new(record.get("directory").and_then(Value::as_str).unwrap_or("")))
}

fn schema(record: &Map<String, Value>) -> i64 {
    if util::py_eq_int(record.get("schema_version"), 2) { 2 } else { 1 }
}

pub struct SharingdAgent {
    pub directory: Option<PathBuf>,
    pub domain: String,
    pub target: String,
    pub cache: PathBuf,
    pub journal: PathBuf,
    lock: Option<File>,
    pub owned: bool,
    pub record: Option<Map<String, Value>>,
    pub restored_pairing: usize,
    pub adopted: bool,
    pub context: SharingdContext,
}

impl SharingdAgent {
    /// `SharingdAgent(directory)` for the real user session.
    pub fn new(directory: Option<&Path>) -> Self {
        Self::with_context(directory, SharingdContext::system())
    }

    pub fn with_context(directory: Option<&Path>, context: SharingdContext) -> Self {
        let cache = context.cache();
        SharingdAgent {
            directory: directory.map(paths::resolve),
            domain: context.domain(),
            target: context.target(),
            journal: cache.join("sharing.json"),
            cache,
            lock: None,
            owned: false,
            record: None,
            restored_pairing: 0,
            adopted: false,
            context,
        }
    }

    fn directory_text(&self) -> String {
        self.directory.as_deref().map(text).unwrap_or_else(|| "None".into())
    }

    /// Take the exclusive (non-blocking) agent lock; `BlockingIOError` when
    /// another controller holds it.
    pub fn acquire(&mut self) -> Result<()> {
        util::mkdir_parents(&self.cache, 0o700).map_err(|e| Error::with_path(e, &self.cache))?;
        let path = self.cache.join("sharingd-agent.lock");
        let lock = std::fs::OpenOptions::new().append(true).create(true).open(&path).map_err(|e| Error::with_path(e, &path))?;
        sys::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB)?;
        self.lock = Some(lock);
        Ok(())
    }

    fn release(&mut self) {
        self.lock = None;
    }

    /// The validated ownership journal, `None` when absent.
    pub fn read_journal(&self) -> Result<Option<Map<String, Value>>> {
        let info = match sys::lstat(&self.journal) {
            Ok(info) => info,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
            Err(e) => return Err(Error::with_path(e, &self.journal)),
        };
        if !sys::is_reg(info.st_mode) || info.st_uid != self.context.uid || info.st_mode & 0o077 != 0 {
            return Err(Error::runtime("sharingd ownership journal is not a private owned file"));
        }
        let data = std::fs::read(&self.journal).map_err(|e| Error::with_path(e, &self.journal))?;
        let text = String::from_utf8(data).map_err(|e| Error::value(e.to_string()))?;
        let record: Value = serde_json::from_str(&text).map_err(|e| Error::value(e.to_string()))?;
        let Value::Object(record) = record else { return Err(Error::runtime("Invalid sharingd ownership journal")) };
        if !(util::py_eq_int(record.get("schema_version"), 1) || util::py_eq_int(record.get("schema_version"), 2)) {
            return Err(Error::runtime("Invalid sharingd ownership journal"));
        }
        let birth = record.get("controller_birth").filter(|b| !b.is_null());
        if record.get("detached") == Some(&Value::Bool(true)) && birth.is_none() {
            // No controller: the adapter stays loaded between sessions.
        } else {
            let valid = match birth {
                Some(Value::Array(items)) if items.len() == 4 && items.iter().all(|n| util::is_int(Some(n))) => {
                    util::int_of(Some(&items[0])).unwrap() > 0
                        && util::int_of(Some(&items[1])).unwrap() == i128::from(self.context.uid)
                }
                _ => false,
            };
            if !valid {
                return Err(Error::runtime("Invalid sharingd controller identity"));
            }
        }
        let Some(Value::String(raw)) = record.get("directory") else {
            return Err(Error::runtime("Invalid sharingd ownership directory"));
        };
        let directory = paths::normalize(Path::new(raw));
        if raw.is_empty() || !directory.is_absolute() || paths::resolve(&directory) != directory {
            return Err(Error::runtime("Invalid sharingd ownership directory"));
        }
        private_directory(&directory, self.context.uid)?;
        let digest = if schema(&record) == 1 { "plist_sha256" } else { "config_sha256" };
        if !record.get(digest).and_then(Value::as_str).is_some_and(|d| DIGEST.is_match(d)) {
            return Err(Error::runtime("Invalid sharingd launch configuration digest"));
        }
        if schema(&record) == 2 {
            if let Some(pid) = record.get("injected_pid").filter(|p| !p.is_null()) {
                if !PID.is_match(&py_str(Some(pid))) {
                    return Err(Error::runtime("Invalid sharingd adapter process"));
                }
            }
        }
        Ok(Some(record))
    }

    fn verify_owned_job(&self, current: &Map<String, Value>, directory: &Path, digest: &str) -> Result<()> {
        let plist = directory.join("sharing.plist");
        match sys::lstat(&plist) {
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                // launchd retains a loaded definition even if its source folder was
                // removed. The private journal and the job's exact adapter/log paths
                // must agree before an abandoned registration may be unloaded.
                let adapter = current.get("environment").and_then(|e| e.get("DYLD_INSERT_LIBRARIES")).and_then(Value::as_str);
                let matches = current.get("injected") == Some(&Value::Bool(true))
                    && adapter == Some(text(&directory.join("keystore.dylib")).as_str())
                    && current.get("stdout path").and_then(Value::as_str) == Some(text(&directory.join("sharingd.stdout.log")).as_str())
                    && current.get("stderr path").and_then(Value::as_str) == Some(text(&directory.join("sharingd.stderr.log")).as_str());
                if !matches {
                    return Err(Error::runtime("Missing sharingd configuration cannot be verified; recovery deferred"));
                }
            }
            Err(e) => return Err(Error::with_path(e, &plist)),
            Ok(info) => {
                let unchanged = sys::is_reg(info.st_mode) && info.st_uid == self.context.uid && info.st_mode & 0o077 == 0
                    && util::sha256_hex(&std::fs::read(&plist).map_err(|e| Error::with_path(e, &plist))?) == digest;
                if !unchanged {
                    return Err(Error::runtime("Owned sharingd configuration changed; recovery deferred"));
                }
            }
        }
        Ok(())
    }

    fn restore(&self, record: &Map<String, Value>) -> Result<Map<String, Value>> {
        if schema(record) == 2 {
            self.restore_environment(record)
        } else {
            self.restore_replaced_job(record)
        }
    }

    fn bootstrap_original(&self) -> Result<()> {
        let reply = self.context.launchctl(&["bootstrap", &self.domain, ORIGINAL_PLIST])?;
        if reply.code != 0 {
            return Err(Error::runtime(format!("Cannot restore original sharingd: {}", util::strip(&reply.stderr))));
        }
        Ok(())
    }

    fn finish_restore(&self, record: &Map<String, Value>, restored: Map<String, Value>, config: bool) -> Result<Map<String, Value>> {
        let directory = record_directory(record);
        if private_directory(&directory, self.context.uid)? {
            if config {
                util::unlink_missing_ok(&directory.join("keystore.json"))?; // Holds the broker credentials.
            }
            write_state(&directory.join("sharingd-last-restore.json"), &Value::Object(restored.clone()))?;
        } else {
            write_state(&self.cache.join("sharingd-last-restore.json"),
                &json!({"directory": text(&directory), "state": restored}))?;
        }
        std::fs::remove_file(&self.journal).map_err(|e| Error::with_path(e, &self.journal))?;
        Ok(restored)
    }

    fn restore_environment(&self, record: &Map<String, Value>) -> Result<Map<String, Value>> {
        self.context.clear_launchd_variables()?;
        let current = self.context.current()?;
        let injected = record.get("injected_pid").filter(|p| !p.is_null());
        if current.is_empty() {
            self.bootstrap_original()?;
        } else if current.get("program").and_then(Value::as_str) != Some(PROGRAM)
            || current.get("path").and_then(Value::as_str) != Some(ORIGINAL_PLIST) {
            return Err(Error::runtime("sharingd ownership changed; refusing to replace another configuration"));
        } else {
            let pid = current.get("pid");
            // Without a recorded adapter process, restart anyway: it is harmless.
            if util::truthy(pid) && (injected.is_none() || py_str(pid) == py_str(injected)) {
                let reply = self.context.launchctl(&["kickstart", "-k", &self.target])?;
                if reply.code != 0 {
                    return Err(Error::runtime(format!("Cannot restart original sharingd: {}", util::strip(&reply.stderr))));
                }
                self.context.wait_for_new_process(pid)?;
            }
        }
        let restored = self.context.current()?;
        if !is_original(&restored) || injected.is_some_and(|i| py_str(restored.get("pid")) == py_str(Some(i))) {
            return Err(Error::runtime("Original sharingd restoration is not verified"));
        }
        self.finish_restore(record, restored, true)
    }

    /// Undo a session started by an earlier Mirra version, which replaced the job.
    fn restore_replaced_job(&self, record: &Map<String, Value>) -> Result<Map<String, Value>> {
        let directory = record_directory(record);
        let plist = text(&directory.join("sharing.plist"));
        let mut current = self.context.current()?;
        if current.get("path").and_then(Value::as_str) == Some(plist.as_str())
            && current.get("program").and_then(Value::as_str) == Some(PROGRAM) {
            self.verify_owned_job(&current, &directory, record.get("plist_sha256").and_then(Value::as_str).unwrap_or(""))?;
            let reply = self.context.launchctl(&["bootout", &self.target])?;
            if reply.code != 0 {
                return Err(Error::runtime(format!("Cannot unload owned sharingd: {}", util::strip(&reply.stderr))));
            }
            current = self.context.current()?;
        } else if !current.is_empty() && !is_original(&current) {
            return Err(Error::runtime("sharingd ownership changed; refusing to replace another configuration"));
        }
        if current.is_empty() {
            self.bootstrap_original()?;
        }
        let restored = self.context.current()?;
        if !is_original(&restored) {
            return Err(Error::runtime("Original sharingd restoration is not verified"));
        }
        self.finish_restore(record, restored, false)
    }

    /// A detached adapter process that is still the job's running sharingd.
    pub fn detached_alive(&self, record: Option<&Map<String, Value>>) -> Result<bool> {
        let Some(record) = record else { return Ok(false) };
        if !util::py_eq_int(record.get("schema_version"), 2) || record.get("detached") != Some(&Value::Bool(true)) {
            return Ok(false);
        }
        let current = self.context.current()?;
        let injected = record.get("injected_pid").filter(|p| !p.is_null());
        Ok(injected.is_some() && current.get("program").and_then(Value::as_str) == Some(PROGRAM)
            && current.get("path").and_then(Value::as_str) == Some(ORIGINAL_PLIST)
            && py_str(current.get("pid")) == py_str(injected))
    }

    fn recover_under_lock(&self, restore_detached: bool) -> Result<Option<Value>> {
        let Some(record) = self.read_journal()? else { return Ok(None) };
        if record.get("detached") == Some(&Value::Bool(true)) {
            if !restore_detached && self.detached_alive(Some(&record))? {
                return Ok(None);
            }
        } else {
            let birth = record["controller_birth"].clone();
            let pid = util::int_of(birth.get(0)).unwrap_or(0) as i32;
            if (self.context.process_birth)(pid)?.map(birth_value) == Some(birth) {
                return Err(Error::runtime("The sharingd restoration controller is still running"));
            }
        }
        let restored = self.restore(&record)?;
        Ok(Some(json!({"directory": record["directory"], "original_restored": is_original(&restored)})))
    }

    /// Restore after a lost controller. A detached adapter stays unless asked.
    /// Returns `{"directory", "original_restored"}` when a journal was handled.
    pub fn recover_abandoned(restore_detached: bool) -> Result<Option<Value>> {
        Self::recover_abandoned_with(restore_detached, SharingdContext::system())
    }

    pub fn recover_abandoned_with(restore_detached: bool, context: SharingdContext) -> Result<Option<Value>> {
        let mut agent = Self::with_context(None, context);
        let result = agent.acquire().and_then(|_| agent.recover_under_lock(restore_detached));
        agent.release();
        result
    }

    /// True while a detached adapter with exactly this digest is still sharingd.
    ///
    /// A support update that ships the same adapter can then leave sharingd
    /// running, so the next start adopts it and the iPhone keeps its pairing
    /// armed instead of asking for its passcode again.
    pub fn detached_matches(adapter_sha256: &str) -> Result<bool> {
        Self::detached_matches_with(adapter_sha256, SharingdContext::system())
    }

    pub fn detached_matches_with(adapter_sha256: &str, context: SharingdContext) -> Result<bool> {
        let mut agent = Self::with_context(None, context);
        let result = (|| {
            agent.acquire()?;
            let record = agent.read_journal()?;
            Ok(agent.detached_alive(record.as_ref())?
                && record.as_ref().and_then(|r| r.get("adapter_sha256")).and_then(Value::as_str) == Some(adapter_sha256))
        })();
        agent.release();
        result
    }

    /// Give sharingd back to Apple (updates, removal and new setups).
    pub fn restore_detached() -> Result<Option<Value>> {
        Self::recover_abandoned(true)
    }

    pub fn restore_detached_with(context: SharingdContext) -> Result<Option<Value>> {
        Self::recover_abandoned_with(true, context)
    }

    fn own_birth(&self) -> Result<Birth> {
        (self.context.process_birth)(std::process::id() as i32)?
            .ok_or_else(|| Error::runtime("Cannot record sharingd controller identity"))
    }

    /// Load `adapter` into Apple's sharingd; `settings` stay in a private
    /// file. With `reuse_detached`, a live detached adapter of the same
    /// digest is adopted instead of restarting sharingd.
    pub fn start(&mut self, adapter: &Path, settings: &Value, pairing_backup: Option<&Path>, reuse_detached: bool) -> Result<()> {
        self.acquire()?;
        match self.start_locked(adapter, settings, pairing_backup, reuse_detached) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.close(false)?;
                Err(error)
            }
        }
    }

    fn start_locked(&mut self, adapter: &Path, settings: &Value, pairing_backup: Option<&Path>, reuse_detached: bool) -> Result<()> {
        let adapter_digest = util::sha256_hex(&std::fs::read(adapter).map_err(|e| Error::with_path(e, adapter))?);
        let record = self.read_journal()?;
        if reuse_detached && self.detached_alive(record.as_ref())?
            && record.as_ref().and_then(|r| r.get("adapter_sha256")).and_then(Value::as_str) == Some(adapter_digest.as_str()) {
            let mut record = record.unwrap();
            let birth = self.own_birth()?;
            record.insert("controller_birth".into(), birth_value(birth));
            record.insert("detached".into(), Value::Bool(false));
            record.insert("directory".into(), Value::from(self.directory_text()));
            write_state(&self.journal, &Value::Object(record.clone()))?;
            self.record = Some(record);
            self.owned = true;
            self.adopted = true;
            return Ok(());
        }
        self.recover_under_lock(true)?;
        let current = self.context.current()?;
        if !is_original(&current) {
            return Err(Error::runtime("sharingd does not have its original configuration"));
        }
        if !self.context.launchd_variables()?.is_empty() {
            return Err(Error::runtime("launchd already carries sharingd adapter variables"));
        }
        let directory = self.directory.clone().ok_or_else(|| Error::runtime("sharingd adapter directory is required"))?;
        util::chmod(&directory, 0o700).map_err(|e| Error::with_path(e, &directory))?;
        let config = directory.join("keystore.json");
        util::unlink_missing_ok(&config).map_err(|e| Error::with_path(e, &config))?;
        let descriptor = sys::open(&config, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW, 0o600)
            .map_err(|e| Error::with_path(e, &config))?;
        sys::write_all(descriptor.as_raw_fd(), mirra_core::pyjson::dumps(settings).as_bytes())?;
        drop(descriptor);
        let birth = self.own_birth()?;
        let config_digest = util::sha256_hex(&std::fs::read(&config).map_err(|e| Error::with_path(e, &config))?);
        let record = json!({"schema_version": 2, "controller_birth": birth_value(birth), "directory": text(&directory),
            "config_sha256": config_digest, "previous_pid": current.get("pid").cloned().unwrap_or(Value::Null),
            "injected_pid": null, "adapter_sha256": adapter_digest});
        write_state(&self.journal, &record)?;
        self.record = record.as_object().cloned();
        self.owned = true; // The journal precedes any change to launchd.
        if let Some(backup) = pairing_backup {
            // Read by the restarted sharingd while it starts.
            self.restored_pairing = restore_pairing_in(&self.context.auto_unlock(), backup)?;
        }
        let library = text(&paths::resolve(adapter));
        let restart = (|| {
            for (name, value) in [("DYLD_INSERT_LIBRARIES", library.as_str()), ("MIRRA_KEYSTORE_CONFIG", &text(&config))] {
                let reply = self.context.launchctl(&["setenv", name, value])?;
                if reply.code != 0 {
                    return Err(Error::runtime(format!("Cannot prepare the sharingd adapter: {}", util::strip(&reply.stderr))));
                }
            }
            let reply = self.context.launchctl(&["kickstart", "-k", &self.target])?;
            if reply.code != 0 {
                return Err(Error::runtime(format!("sharingd restart failed: {}", util::strip(&reply.stderr))));
            }
            // launchd copies the environment when it spawns the new process.
            self.context.wait_for_new_process(current.get("pid"))?;
            Ok(())
        })();
        let cleared = self.context.clear_launchd_variables();
        restart.and(cleared)
    }

    /// Remember the adapter process, so restoration restarts exactly that one.
    pub fn record_injected(&mut self, pid: i64) -> Result<()> {
        let record = self.record.as_mut().ok_or_else(|| Error::runtime("sharingd adapter session is not active"))?;
        record.insert("injected_pid".into(), Value::from(pid));
        write_state(&self.journal, &Value::Object(record.clone()))?;
        Ok(())
    }

    /// End the session: detach (keep the adapter loaded) or restore Apple's
    /// sharingd. Returns the observed registration, `None` when not owned.
    pub fn close(&mut self, detach: bool) -> Result<Option<Map<String, Value>>> {
        let result = self.close_locked(detach);
        self.release();
        result
    }

    fn close_locked(&mut self, detach: bool) -> Result<Option<Map<String, Value>>> {
        if !self.owned {
            return Ok(None);
        }
        let record = self.read_journal()?;
        let unchanged = match &record {
            Some(record) => {
                let birth = record.get("controller_birth").filter(|b| !b.is_null());
                record.get("directory").and_then(Value::as_str) == Some(self.directory_text().as_str())
                    && birth.is_some()
                    && (self.context.process_birth)(std::process::id() as i32)?.map(birth_value).as_ref() == birth
            }
            None => false,
        };
        if !unchanged {
            return Err(Error::runtime("sharingd ownership journal changed during the session"));
        }
        let mut record = record.unwrap();
        if detach && schema(&record) == 2 && record.get("injected_pid").is_some_and(|p| !p.is_null()) {
            record.insert("detached".into(), Value::Bool(true));
            record.insert("controller_birth".into(), Value::Null);
            write_state(&self.journal, &Value::Object(record))?;
            self.owned = false;
            return self.context.current().map(Some);
        }
        let restored = self.restore(&record)?;
        self.owned = false;
        Ok(Some(restored))
    }
}

#[cfg(test)]
pub(crate) mod tests;
