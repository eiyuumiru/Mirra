//! Own one temporary AVConference job, with a separate restoration guardian
//! (port of `scripts/decoder_route.py`). The journal
//! `~/Library/Caches/Mirra/decoder-route.json`, its lock and the stage layout
//! under `/private/var/tmp/AVConference` are shared with the Python service.
use std::fmt;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use mirra_core::launchctl::Reply;
use mirra_core::processes::process_birth;
use mirra_core::state::named_temporary;
use mirra_core::subprocess::{self, RunOptions};
use mirra_core::{sys, Error, Result};
use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::plist::{self, Plist};
use crate::util;

pub const ORIGINAL: &str = "/System/Library/LaunchAgents/com.apple.avconferenced.plist";
pub const PROGRAM: &str = "/usr/libexec/avconferenced";
pub const LABEL: &str = "com.apple.videoconference.camera";
pub const STAGES: &str = "/private/var/tmp/AVConference";
/// Hidden CLI subcommand that runs [`guardian_main`].
pub const GUARDIAN_SUBCOMMAND: &str = "__decoder-guardian";

pub static STAGE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^mirra-decoder-[0-9]{8}-[0-9]{6}-[a-z0-9_]+$").unwrap());

/// AVConference could not be unloaded (`DecoderUnloadError`, a RuntimeError).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecoderUnloadError {
    pub returncode: i32,
    pub stderr: String,
}

impl DecoderUnloadError {
    pub fn new(reply: &Reply) -> Self {
        let stderr: String = reply.stderr.trim().chars().take(2048).collect();
        DecoderUnloadError { returncode: reply.code, stderr }
    }
}

impl fmt::Display for DecoderUnloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AVConference could not be unloaded for this session (launchctl exit {}): {}", self.returncode, self.stderr)
    }
}

#[derive(Debug)]
pub enum RouteError {
    Unload(DecoderUnloadError),
    Other(Error),
}

impl RouteError {
    pub fn type_name(&self) -> String {
        match self {
            RouteError::Unload(_) => "DecoderUnloadError".into(),
            RouteError::Other(e) => e.type_name(),
        }
    }
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouteError::Unload(e) => e.fmt(f),
            RouteError::Other(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for RouteError {}

impl From<Error> for RouteError {
    fn from(e: Error) -> Self {
        RouteError::Other(e)
    }
}
impl From<std::io::Error> for RouteError {
    fn from(e: std::io::Error) -> Self {
        RouteError::Other(e.into())
    }
}
impl From<RouteError> for Error {
    fn from(e: RouteError) -> Self {
        match e {
            RouteError::Unload(u) => Error::Runtime(u.to_string()),
            RouteError::Other(e) => e,
        }
    }
}

/// Shared stage and journal locations (tests use temporary directories).
#[derive(Clone, Debug)]
pub struct RoutePaths {
    pub stages: PathBuf,
    pub cache: PathBuf,
}

impl Default for RoutePaths {
    fn default() -> Self {
        RoutePaths { stages: PathBuf::from(STAGES), cache: util::home().join("Library/Caches/Mirra") }
    }
}

impl RoutePaths {
    pub fn journal(&self) -> PathBuf {
        self.cache.join("decoder-route.json")
    }
    pub fn lock(&self) -> PathBuf {
        self.cache.join("decoder-route.lock")
    }
}

/// `launchctl` runner; arguments exclude the program.
pub type Ctl = Arc<dyn Fn(&[String]) -> Result<Reply> + Send + Sync>;

/// `/bin/launchctl <args>` with stdin from /dev/null and a 12 s timeout.
pub fn ctl() -> Ctl {
    Arc::new(|args| {
        let mut command = vec!["/bin/launchctl".to_string()];
        command.extend(args.iter().cloned());
        subprocess::run(&command, &RunOptions::new().input(Vec::new()).capture().timeout(Duration::from_secs(12))).map(Reply::from)
    })
}

/// `codesign --verify <library>` (replaceable).
pub type Verify = Arc<dyn Fn(&Path) -> Result<()> + Send + Sync>;

/// Replaceable job environment.
#[derive(Clone)]
pub struct JobHooks {
    pub command: Ctl,
    /// Apple's job definition (`ORIGINAL`).
    pub original: PathBuf,
    /// `codesign --verify <library>`.
    pub verify: Verify,
    pub timeout: Duration,
    /// How long another adapter may keep `DYLD_INSERT_LIBRARIES` in the user
    /// domain before Apple's job is registered again.
    pub domain_timeout: Duration,
    pub interval: Duration,
}

impl Default for JobHooks {
    fn default() -> Self {
        JobHooks {
            command: ctl(),
            original: PathBuf::from(ORIGINAL),
            verify: Arc::new(|library| {
                subprocess::run(&["/usr/bin/codesign".to_string(), "--verify".into(), util::text(library)],
                    &RunOptions::new().capture().check().timeout(Duration::from_secs(10))).map(|_| ())
            }),
            timeout: Duration::from_secs(8),
            domain_timeout: Duration::from_secs(20),
            interval: Duration::from_millis(100),
        }
    }
}

/// Path must be a private regular file (or directory) owned by this user.
pub fn private(path: &Path, directory: bool) -> Result<libc::stat> {
    let info = sys::lstat(path).map_err(|e| Error::with_path(e, path))?;
    if !sys::private_owned(&info, directory) {
        return Err(Error::runtime("Decoder route path must be private and owned by this user"));
    }
    Ok(info)
}

/// `json.dump(value)` + newline to a temporary file, fsync, atomic replace.
pub fn write_json(path: &Path, value: &Value) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let (file, temporary) = named_temporary(parent, ".decoder-").map_err(|e| Error::with_path(e, parent))?;
    let mut text = mirra_core::pyjson::dumps(value);
    text.push('\n');
    let written = sys::write_all(file.as_raw_fd(), text.as_bytes()).and_then(|_| sys::fsync(file.as_raw_fd()));
    drop(file);
    let result = written.and_then(|_| std::fs::rename(&temporary, path));
    let _ = std::fs::remove_file(&temporary);
    result.map_err(Error::from)
}

/// `read_json`: private file, parsed.
pub fn read_private_json(path: &Path) -> Result<Value> {
    private(path, false)?;
    util::read_json(path)
}

pub type JobState = Map<String, Value>;

/// Parse `launchctl print`: `{}` when missing; `injected`, `endpoints`
/// (name → active count) and top-level `path`/`program`/`pid`/`state`/
/// `active count` (integers when decimal).
pub fn snapshot(reply: &Reply) -> Result<JobState> {
    static ENDPOINT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^"([^"]+)" = \{$"#).unwrap());
    static ACTIVE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^active = ([0-9]+)$").unwrap());
    if reply.code != 0 {
        if reply.stderr.contains("Could not find service") {
            return Ok(Map::new());
        }
        return Err(Error::runtime("AVConference state could not be inspected"));
    }
    let mut values = Map::new();
    values.insert("injected".into(),
        Value::from(mirra_core::launchctl::job_mentions(&reply.stdout, &["DYLD_INSERT_LIBRARIES", "MIRRA_NO_FLS"])));
    let mut endpoints_map = Map::new();
    let mut endpoints = false;
    let mut depth: i64 = 0;
    let mut endpoint: Option<String> = None;
    for line in mirra_core::pyfmt::splitlines(&reply.stdout) {
        if line.starts_with('\t') && !line.starts_with("\t\t") {
            if let Some((key, value)) = line[1..].split_once(" = ") {
                if matches!(key, "path" | "program" | "pid" | "state" | "active count") {
                    let parsed = if util::is_decimal(value) {
                        value.parse::<i64>().map(Value::from).unwrap_or_else(|_| Value::from(value))
                    } else {
                        Value::from(value)
                    };
                    values.insert(key.into(), parsed);
                }
            }
        }
        let stripped = line.trim();
        if stripped == "endpoints = {" {
            endpoints = true;
            depth = 1;
            continue;
        }
        if endpoints {
            let matched = if depth == 1 { ENDPOINT.captures(stripped) } else { None };
            if let Some(m) = matched {
                endpoint = Some(m[1].to_string());
            } else if let Some(name) = endpoint.clone() {
                if let Some(m) = ACTIVE.captures(stripped) {
                    endpoints_map.insert(name, m[1].parse::<i64>().map(Value::from).unwrap_or(Value::Null));
                    endpoint = None;
                }
            }
            depth += line.matches('{').count() as i64 - line.matches('}').count() as i64;
            if depth <= 0 {
                endpoints = false;
            }
        }
    }
    // Python inserts `endpoints` second and fills it in place.
    let mut ordered = Map::new();
    let injected = values.remove("injected").unwrap();
    ordered.insert("injected".into(), injected);
    ordered.insert("endpoints".into(), Value::Object(endpoints_map));
    ordered.extend(values);
    Ok(ordered)
}

fn field<'a>(value: &'a JobState, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::Bool(true)) => true,
    }
}

pub struct DecoderJob {
    pub stage: PathBuf,
    pub domain: String,
    pub target: String,
    pub plist: PathBuf,
    pub wrapper: PathBuf,
    pub hooks: JobHooks,
}

impl DecoderJob {
    pub fn new(stage: &Path) -> Self {
        Self::with_hooks(stage, JobHooks::default())
    }

    pub fn with_hooks(stage: &Path, hooks: JobHooks) -> Self {
        let domain = mirra_core::launchctl::gui_domain();
        DecoderJob { stage: stage.to_path_buf(), target: format!("{}/{}", domain, LABEL), domain,
            plist: stage.join("job.plist"), wrapper: stage.join("wrapper"), hooks }
    }

    fn command(&self, args: &[&str]) -> Result<Reply> {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        (self.hooks.command)(&args)
    }

    pub fn state(&self) -> Result<JobState> {
        snapshot(&self.command(&["print", &self.target])?)
    }

    /// Apple's job, without injection.
    pub fn original(&self, value: &JobState) -> bool {
        field(value, "path") == Some(util::text(&self.hooks.original).as_str()) && field(value, "program") == Some(PROGRAM)
            && !truthy(value.get("injected"))
    }

    pub fn owned(&self, value: &JobState) -> bool {
        field(value, "path") == Some(util::text(&self.plist).as_str()) && field(value, "program") == Some(util::text(&self.wrapper).as_str())
    }

    pub fn wait_removed(&self, path: &Path) -> Result<JobState> {
        let deadline = Instant::now() + self.hooks.timeout;
        let path = util::text(path);
        loop {
            let value = self.state()?;
            if value.is_empty() || field(&value, "path") != Some(path.as_str()) {
                return Ok(value);
            }
            if Instant::now() >= deadline {
                return Err(Error::runtime("AVConference is still unloading; restoration remains pending"));
            }
            std::thread::sleep(self.hooks.interval);
        }
    }

    pub fn wait_original(&self) -> Result<JobState> {
        let deadline = Instant::now() + self.hooks.timeout;
        loop {
            let value = self.state()?;
            if !value.is_empty() {
                if self.original(&value) {
                    return Ok(value);
                }
                return Err(Error::runtime("AVConference belongs to another configuration"));
            }
            if Instant::now() >= deadline {
                return Err(Error::runtime("Original AVConference registration remains pending"));
            }
            std::thread::sleep(self.hooks.interval);
        }
    }

    pub fn require_idle(&self) -> Result<JobState> {
        let value = self.state()?;
        if !self.original(&value) {
            return Err(Error::runtime("AVConference already has another configuration; stop that session first"));
        }
        if !util::eq_int(value["endpoints"].get("com.apple.videoconference.avconference"), 0) {
            return Err(Error::runtime("AVConference is active; quit iPhone Mirroring and other video calls first"));
        }
        Ok(value)
    }

    /// Stage the hook library, wrapper and job definition (Apple's options
    /// retained). Returns hook/original digests.
    pub fn prepare(&self, library: &Path, policy: &str) -> Result<Value> {
        if policy != "all_h264" && policy != "fls_p3" {
            return Err(Error::value("Unknown decoder compatibility policy"));
        }
        private(&self.stage, true)?;
        let original = &self.hooks.original;
        let mut config = plist::loads(&std::fs::read(original).map_err(|e| Error::with_path(e, original))?)?;
        if config.get("Label").and_then(Plist::as_str) != Some(LABEL) {
            return Err(Error::runtime("Unexpected Apple AVConference service definition"));
        }
        let arguments = match config.get("ProgramArguments") {
            None => vec![PROGRAM.to_string()],
            Some(Plist::Array(items)) => items.iter().map(|i| i.as_str().map(str::to_string)).collect::<Option<Vec<_>>>()
                .ok_or_else(|| Error::runtime("Unexpected Apple AVConference arguments"))?,
            Some(_) => Vec::new(),
        };
        if arguments.first().map(String::as_str) != Some(PROGRAM) {
            return Err(Error::runtime("Unexpected Apple AVConference arguments"));
        }
        (self.hooks.verify)(library)?;
        let copied = self.stage.join("decoder-route.dylib");
        std::fs::copy(library, &copied).map_err(|e| Error::with_path(e, library))?;
        util::chmod(&copied, 0o600)?;
        let wrapper = format!("#!/bin/sh\nexport DYLD_INSERT_LIBRARIES={}\nexec {}\n",
            mirra_core::shlex::quote(&util::text(&copied)), mirra_core::shlex::join(&arguments));
        std::fs::write(&self.wrapper, wrapper).map_err(|e| Error::with_path(e, &self.wrapper))?;
        util::chmod(&self.wrapper, 0o700)?;
        let wrapper_text = util::text(&self.wrapper);
        config.insert("Program", Plist::String(wrapper_text.clone()));
        config.insert("ProgramArguments", Plist::Array(vec![Plist::String(wrapper_text)]));
        config.insert("RunAtLoad", Plist::Bool(true));
        config.insert("EnablePressuredExit", Plist::Bool(false));
        config.insert("Umask", Plist::Integer(0o077));
        config.insert("StandardOutPath", Plist::String(util::text(&self.stage.join("stdout.log"))));
        config.insert("StandardErrorPath", Plist::String(util::text(&self.stage.join("stderr.log"))));
        if config.get("EnvironmentVariables").is_none() {
            config.insert("EnvironmentVariables", Plist::dict());
        }
        let environment = config.get_mut("EnvironmentVariables").unwrap();
        if !environment.is_dict() {
            return Err(Error::runtime("Unexpected Apple AVConference environment"));
        }
        environment.insert("MIRRA_NO_FLS", Plist::String("1".into()));
        environment.insert("MIRRA_DECODER_POLICY", Plist::String(policy.into()));
        for name in ["stdout.log", "stderr.log"] {
            util::touch_new(&self.stage.join(name))?;
        }
        std::fs::write(&self.plist, plist::dumps(&config)?).map_err(|e| Error::with_path(e, &self.plist))?;
        util::chmod(&self.plist, 0o600)?;
        let digest = |data: &[u8]| -> String { Sha256::digest(data).iter().map(|b| format!("{:02x}", b)).collect() };
        let hook = std::fs::read(&copied).map_err(|e| Error::with_path(e, &copied))?;
        let apple = std::fs::read(original).map_err(|e| Error::with_path(e, original))?;
        Ok(json!({"decoder_hook_sha256": digest(&hook), "original_plist_sha256": digest(&apple)}))
    }

    /// Replace Apple's idle job with the staged one; `armed.json` is written
    /// before any mutation so the guardian can always restore.
    pub fn start(&self) -> Result<(), RouteError> {
        let before = self.require_idle()?;
        let was_running = truthy(before.get("pid")) && field(&before, "state") == Some("running");
        write_json(&self.stage.join("armed.json"), &json!({"armed": true, "original_state": before,
            "original_was_running": was_running}))?;
        let reply = self.command(&["bootout", &self.target])?;
        if reply.code != 0 {
            return Err(RouteError::Unload(DecoderUnloadError::new(&reply)));
        }
        if !self.wait_removed(&self.hooks.original)?.is_empty() {
            return Err(Error::runtime("AVConference changed during startup; no replacement attempted").into());
        }
        let plist = util::text(&self.plist);
        let reply = self.command(&["bootstrap", &self.domain, &plist])?;
        if reply.code != 0 {
            return Err(Error::runtime("Mirra AVConference registration failed").into());
        }
        Ok(())
    }

    /// Restore Apple's registration (and its previous running state);
    /// another configuration is preserved.
    pub fn restore(&self) -> Result<JobState> {
        let mut current = self.state()?;
        if !current.is_empty() && self.owned(&current) {
            let reply = self.command(&["bootout", &self.target])?;
            if reply.code != 0 {
                return Err(Error::runtime("The owned decoder route could not be unloaded"));
            }
            current = self.wait_removed(&self.plist)?;
        }
        if !current.is_empty() && !self.original(&current) {
            return Err(Error::runtime("AVConference ownership changed; another configuration was preserved"));
        }
        if current.is_empty() {
            // Apple's job would inherit a transient adapter library.
            mirra_core::launchctl::wait_domain_clear(&|args| self.command(args), self.hooks.domain_timeout, self.hooks.interval)?;
            let original = util::text(&self.hooks.original);
            let reply = self.command(&["bootstrap", &self.domain, &original])?;
            if reply.code != 0 {
                return Err(Error::runtime("Original AVConference could not be registered"));
            }
        }
        current = self.wait_original()?;
        let armed = self.stage.join("armed.json");
        if armed.exists() {
            private(&armed, false)?;
            let previous = util::read_json(&armed)?;
            if truthy(previous.get("original_was_running")) && !truthy(current.get("pid")) {
                // Restore demand state as well as registration. Never kill an
                // already-running original service, or force a hardware decoder.
                let reply = self.command(&["kickstart", &self.target])?;
                if reply.code != 0 {
                    return Err(Error::runtime("Original AVConference could not resume its previous running state"));
                }
                let deadline = Instant::now() + self.hooks.timeout;
                loop {
                    current = self.wait_original()?;
                    if truthy(current.get("pid")) && field(&current, "state") == Some("running") {
                        break;
                    }
                    if Instant::now() >= deadline {
                        return Err(Error::runtime("Original AVConference restart remains pending"));
                    }
                    std::thread::sleep(self.hooks.interval);
                }
            }
        }
        Ok(current)
    }
}

pub fn valid_stage(stage: &Path, paths: &RoutePaths) -> Result<PathBuf> {
    let name = stage.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if stage.parent() != Some(paths.stages.as_path()) || !STAGE_PATTERN.is_match(&name) {
        return Err(Error::runtime("Unrecognized decoder route directory"));
    }
    private(stage, true)?;
    Ok(stage.to_path_buf())
}

/// True unless `birth` (`[pid, uid, sec, usec]`) is observed to have ended;
/// an observation error is not evidence that the owner died.
pub fn owner_alive(birth: &Value) -> Result<bool> {
    owner_alive_with(birth, &process_birth)
}

pub fn owner_alive_with(birth: &Value, probe: &dyn Fn(i32) -> Result<Option<mirra_core::processes::Birth>>) -> Result<bool> {
    let invalid = || Error::runtime("Invalid decoder route owner identity");
    let Some(items) = birth.as_array().filter(|items| items.len() == 4) else { return Err(invalid()) };
    if !util::eq_int(items.get(1), sys::getuid() as i64) {
        return Err(invalid());
    }
    let Some(pid) = util::strict_int(items.first()) else { return Err(invalid()) };
    match probe(pid as i32) {
        Ok(Some(current)) => Ok(mirra_core::retention::birth_json(&current) == *birth
            || (0..4).all(|i| util::eq_int(items.get(i), [current.0 as i64, current.1 as i64, current.2 as i64, current.3 as i64][i]))),
        Ok(None) => Ok(false),
        Err(e) if e.is_os_error() => Ok(true),
        Err(e) => Err(e),
    }
}

/// Exclusive per-stage transaction lock (`with transaction(stage):`).
pub struct Transaction(#[allow(dead_code)] OwnedFd);

pub fn transaction(stage: &Path) -> Result<Transaction> {
    let path = stage.join("transaction.lock");
    let fd = sys::open(&path, libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW, 0o600).map_err(|e| Error::with_path(e, &path))?;
    let info = sys::fstat(fd.as_raw_fd())?;
    if !sys::private_owned(&info, false) {
        return Err(Error::runtime("Decoder transaction lock must be private"));
    }
    sys::flock(fd.as_raw_fd(), libc::LOCK_EX)?;
    Ok(Transaction(fd))
}

/// Remove the journal only when it names `stage`.
pub fn clear_journal(stage: &Path, paths: &RoutePaths) -> Result<()> {
    let journal = paths.journal();
    if journal.exists() {
        let value = read_private_json(&journal)?;
        if value.get("stage").and_then(Value::as_str) == Some(util::text(stage).as_str()) {
            std::fs::remove_file(&journal).map_err(|e| Error::with_path(e, &journal))?;
        }
    }
    Ok(())
}

/// Restore an abandoned stage named by the journal (owner and guardian gone).
pub fn recover_abandoned(paths: &RoutePaths, hooks: &JobHooks) -> Result<Option<JobState>> {
    let journal = paths.journal();
    if !journal.exists() {
        return Ok(None);
    }
    let value = read_private_json(&journal)?;
    let stage = valid_stage(Path::new(value.get("stage").and_then(Value::as_str).ok_or_else(|| Error::runtime("'stage'"))?), paths)?;
    let guardian = value.get("guardian_birth");
    if truthy(guardian) && owner_alive(guardian.unwrap())? {
        return Err(Error::runtime("An earlier decoder session is still restoring AVConference"));
    }
    if owner_alive(value.get("owner_birth").unwrap_or(&Value::Null))? {
        return Err(Error::runtime("Another decoder session is still running"));
    }
    let _transaction = transaction(&stage)?;
    let restored = DecoderJob::with_hooks(&stage, hooks.clone()).restore()?;
    write_json(&stage.join("restored.json"), &json!({"original_avc_restored": true, "state": restored, "recovered": true}))?;
    clear_journal(&stage, paths)?;
    Ok(Some(restored))
}

/// Take the exclusive decoder-route lock (recovering an abandoned session);
/// the returned descriptor holds it.
pub fn acquire() -> Result<OwnedFd> {
    acquire_with(&RoutePaths::default(), &JobHooks::default())
}

pub fn acquire_with(paths: &RoutePaths, hooks: &JobHooks) -> Result<OwnedFd> {
    util::mkdir_private(&paths.cache)?;
    private(&paths.cache, true)?;
    let path = paths.lock();
    let fd = sys::open(&path, libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW, 0o600).map_err(|e| Error::with_path(e, &path))?;
    let info = sys::fstat(fd.as_raw_fd())?;
    if !sys::private_owned(&info, false) {
        return Err(Error::runtime("Decoder route lock must be private"));
    }
    sys::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB)?;
    recover_abandoned(paths, hooks)?;
    Ok(fd)
}

/// Restoration guardian: holds the lock descriptor, waits for `stop.json`,
/// the owner's death or the optional deadline, then restores Apple's job.
/// Returns the process exit status.
pub fn guardian(stage: &Path, descriptor: OwnedFd, paths: &RoutePaths, hooks: &JobHooks) -> Result<i32> {
    guardian_with(stage, descriptor, paths, hooks, Duration::from_millis(200))
}

pub fn guardian_with(stage: &Path, descriptor: OwnedFd, paths: &RoutePaths, hooks: &JobHooks, interval: Duration) -> Result<i32> {
    let stage = valid_stage(stage, paths)?;
    let owner_path = stage.join("owner.json");
    let value = read_private_json(&owner_path)?;
    let expected = private(&paths.lock(), false)?;
    let held = sys::fstat(descriptor.as_raw_fd())?;
    if (held.st_dev, held.st_ino) != (expected.st_dev, expected.st_ino) {
        return Err(Error::runtime("Guardian does not own the decoder route lock"));
    }
    let birth = process_birth(util::own_pid())?;
    write_json(&stage.join("guardian-ready.json"), &json!({"guardian_birth": util::birth_value(&birth)}))?;
    let job = DecoderJob::with_hooks(&stage, hooks.clone());
    let outcome = (|| -> Result<()> {
        // Production sessions follow the supervisor's lifetime. A diagnostic
        // caller can still supply an explicit deadline; there is no fixed TTL.
        let deadline = value.get("deadline_monotonic").and_then(Value::as_f64);
        let null = Value::Null;
        loop {
            let open = deadline.is_none_or(|d| util::monotonic() < d)
                && !stage.join("stop.json").exists()
                && owner_alive(value.get("owner_birth").unwrap_or(&null))?
                && (!truthy(value.get("gui_birth")) || owner_alive(value.get("gui_birth").unwrap())?);
            if !open {
                break;
            }
            std::thread::sleep(interval);
        }
        let _transaction = transaction(&stage)?;
        let state = job.restore()?;
        write_json(&stage.join("restored.json"), &json!({"original_avc_restored": true, "state": state}))?;
        clear_journal(&stage, paths)?;
        Ok(())
    })();
    let code = match outcome {
        Ok(()) => 0,
        Err(error) => {
            write_json(&stage.join("restored.json"), &json!({"original_avc_restored": false,
                "error_type": error.type_name(), "error": error.to_string()}))?;
            1
        }
    };
    drop(descriptor);
    Ok(code)
}

/// argv of the guardian process: `<exe> __decoder-guardian <stage> <fd>`.
pub fn guardian_command(executable: &Path, stage: &Path, descriptor: RawFd) -> Vec<std::ffi::OsString> {
    vec![executable.as_os_str().to_owned(), GUARDIAN_SUBCOMMAND.into(), stage.as_os_str().to_owned(), descriptor.to_string().into()]
}

/// Entry point for `__decoder-guardian <stage> <fd>` (arguments after the
/// subcommand). Uses the production paths; returns the exit status.
pub fn guardian_main(args: &[String]) -> i32 {
    let usage = "This restoration helper is started by Mirra native support.";
    let (Some(stage), Some(fd), 2) = (args.first(), args.get(1).and_then(|v| v.parse::<RawFd>().ok()), args.len()) else {
        eprintln!("{}", usage);
        return 1;
    };
    if fd < 0 || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        eprintln!("{}", usage);
        return 1;
    }
    use std::os::fd::FromRawFd;
    let descriptor = unsafe { OwnedFd::from_raw_fd(fd) };
    match guardian(Path::new(stage), descriptor, &RoutePaths::default(), &JobHooks::default()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{}: {}", error.type_name(), error);
            1
        }
    }
}

/// Delete only our expired, private, restored stage directories.
pub fn prune_stages(paths: &RoutePaths, protected: &[PathBuf], days: u64) -> Result<Vec<String>> {
    let mut removed = Vec::new();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs_f64();
    let cutoff = now - (days * 86400) as f64;
    let entries = std::fs::read_dir(&paths.stages).map_err(|e| Error::with_path(e, &paths.stages))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if protected.contains(&path) || !STAGE_PATTERN.is_match(&name) {
            continue;
        }
        let attempt = (|| -> Result<bool> {
            let info = private(&path, true)?;
            if sys::mtime(&info) >= cutoff {
                return Ok(false);
            }
            let restored = read_private_json(&path.join("restored.json"))?;
            if restored.get("original_avc_restored") != Some(&Value::Bool(true)) {
                return Ok(false);
            }
            std::fs::remove_dir_all(&path)?;
            Ok(true)
        })();
        if let Ok(true) = attempt {
            removed.push(name);
        }
    }
    Ok(removed)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Simulated `launchctl` for one stage (never Apple's service).
    pub struct FakeState {
        pub stage: PathBuf,
        pub original: PathBuf,
        pub current: Option<JobState>,
        pub calls: Vec<Vec<String>>,
        pub fail: Option<&'static str>,
        pub removal_polls: u32,
        pub bootstrap_original_running: bool,
        /// pid of the owned job (decoder tests use this process).
        pub owned_pid: i64,
        /// Write a hook-ready marker for `owned_pid` when the owned job starts.
        pub ready_marker: bool,
        /// When set, the stage is the (single) staged directory found here.
        pub stages: Option<PathBuf>,
    }

    pub type Fake = Arc<Mutex<FakeState>>;

    pub fn job_state(value: Value) -> JobState {
        value.as_object().unwrap().clone()
    }

    impl FakeState {
        pub fn current_stage(&self) -> PathBuf {
            if let Some(stages) = &self.stages {
                if let Ok(entries) = std::fs::read_dir(stages) {
                    for entry in entries.flatten() {
                        if STAGE_PATTERN.is_match(&entry.file_name().to_string_lossy()) {
                            return entry.path();
                        }
                    }
                }
            }
            self.stage.clone()
        }

        pub fn original_state(&self) -> JobState {
            job_state(json!({"path": util::text(&self.original), "program": PROGRAM, "pid": 123, "state": "running", "endpoint": 0}))
        }

        pub fn owned_state(&self) -> JobState {
            let stage = self.current_stage();
            job_state(json!({"path": util::text(&stage.join("job.plist")), "program": util::text(&stage.join("wrapper")),
                "pid": self.owned_pid, "state": "running", "injected": true, "endpoint": 0}))
        }
    }

    fn state_text(value: &JobState) -> String {
        let mut lines = vec!["gui/test = {".to_string()];
        for name in ["path", "program", "pid", "state", "active count"] {
            if let Some(item) = value.get(name) {
                let text = match item { Value::String(s) => s.clone(), other => other.to_string() };
                lines.push(format!("\t{} = {}", name, text));
            }
        }
        if truthy(value.get("injected")) {
            lines.extend(["\t environment = {".into(), "\t\tDYLD_INSERT_LIBRARIES => test".into(), "\t }".into()]);
        }
        lines.extend(["\tendpoints = {".into(), "\t\t\"com.apple.videoconference.avconference\" = {".into(),
            format!("\t\t\tactive = {}", value.get("endpoint").and_then(Value::as_i64).unwrap_or(0)), "\t\t}".into(), "\t}".into(), "}".into()]);
        lines.join("\n")
    }

    fn reply(code: i32, stdout: String, stderr: &str) -> Result<Reply> {
        Ok(Reply { code, stdout, stderr: stderr.into() })
    }

    pub fn fake(stage: &Path, original: &Path) -> Fake {
        let mut state = FakeState { stage: stage.to_path_buf(), original: original.to_path_buf(), current: None, calls: Vec::new(),
            fail: None, removal_polls: 0, bootstrap_original_running: true, owned_pid: 456, ready_marker: false, stages: None };
        state.current = Some(state.original_state());
        Arc::new(Mutex::new(state))
    }

    pub fn fake_ctl(fake: &Fake) -> Ctl {
        let fake = fake.clone();
        Arc::new(move |args| {
            let mut f = fake.lock().unwrap();
            f.calls.push(args.to_vec());
            let original = util::text(&f.original);
            match args[0].as_str() {
                "print" => {
                    if f.fail == Some("query") {
                        return reply(5, String::new(), "Observation denied");
                    }
                    if f.removal_polls > 0 {
                        f.removal_polls -= 1;
                        if f.removal_polls == 0 {
                            f.current = None;
                        }
                    }
                    return match &f.current {
                        None => reply(113, String::new(), "Could not find service"),
                        Some(current) => reply(0, state_text(current), ""),
                    };
                }
                "bootout" => {
                    let is_original = f.current.as_ref().is_some_and(|c| field(c, "path") == Some(original.as_str()));
                    if !f.current_stage().join("armed.json").exists() && is_original {
                        panic!("Job changed before restoration was armed");
                    }
                    if matches!(f.fail, Some("bootout" | "bootout_after_removal" | "bootout_foreign")) {
                        if f.fail == Some("bootout_after_removal") {
                            f.current = None;
                        } else if f.fail == Some("bootout_foreign") {
                            f.current = Some(job_state(json!({"path": "/foreign/job.plist", "program": "/foreign/program"})));
                        }
                        return reply(5, String::new(), "Boot-out failed: fixture rejection");
                    }
                    if f.fail == Some("delayed") {
                        f.removal_polls = 3;
                    } else {
                        f.current = None;
                    }
                    if f.fail == Some("timeout") {
                        f.fail = None;
                        return Err(Error::TimeoutExpired { command: args.to_vec(), timeout: Duration::from_secs(12), stdout: vec![], stderr: vec![] });
                    }
                }
                "bootstrap" => {
                    if args.last().map(String::as_str) == Some(original.as_str()) {
                        let mut state = f.original_state();
                        if !f.bootstrap_original_running {
                            state.remove("pid");
                            state.insert("state".into(), json!("not running"));
                        }
                        f.current = Some(state);
                    } else if f.fail == Some("bootstrap") {
                        return reply(1, String::new(), "Failed");
                    } else {
                        f.current = Some(f.owned_state());
                        if f.ready_marker {
                            use std::io::Write;
                            let mut log = std::fs::OpenOptions::new().append(true).open(f.current_stage().join("stderr.log")).unwrap();
                            writeln!(log, "MIRRA_DECODER_HOOK_READY pid={} version=1", f.owned_pid).unwrap();
                        }
                    }
                }
                "kickstart" => {
                    if f.fail == Some("kickstart") {
                        return reply(1, String::new(), "Failed");
                    }
                    f.current = Some(f.original_state());
                }
                _ => {}
            }
            reply(0, String::new(), "")
        })
    }

    pub fn hooks(fake: &Fake, original: &Path) -> JobHooks {
        JobHooks { command: fake_ctl(fake), original: original.to_path_buf(), verify: Arc::new(|_| Ok(())),
            timeout: Duration::from_secs(8), domain_timeout: Duration::from_secs(8), interval: Duration::from_millis(1) }
    }

    struct Restore {
        _temp: tempfile::TempDir,
        stage: PathBuf,
        fake: Fake,
        job: DecoderJob,
    }

    fn restore_fixture() -> Restore {
        let temp = tempfile::tempdir().unwrap();
        let stage = mirra_core::paths::resolve(temp.path());
        let fake = fake(&stage, Path::new(ORIGINAL));
        let job = DecoderJob::with_hooks(&stage, hooks(&fake, Path::new(ORIGINAL)));
        Restore { _temp: temp, stage, fake, job }
    }

    fn verbs(fake: &Fake) -> Vec<String> {
        fake.lock().unwrap().calls.iter().map(|c| c[0].clone()).filter(|c| c != "getenv").collect()
    }

    #[test]
    fn normal_round_trip() {
        let r = restore_fixture();
        r.job.start().unwrap();
        assert!(r.job.owned(&r.job.state().unwrap()));
        assert!(r.job.original(&r.job.restore().unwrap()));
    }

    #[test]
    fn previously_running_original_is_resumed_without_killing_it() {
        let r = restore_fixture();
        r.fake.lock().unwrap().bootstrap_original_running = false;
        r.job.start().unwrap();
        let restored = r.job.restore().unwrap();
        assert_eq!(restored["state"], "running");
        let calls = r.fake.lock().unwrap().calls.clone();
        assert_eq!(calls.iter().filter(|c| c[0] == "kickstart").count(), 1);
        assert!(calls.iter().all(|c| !c.contains(&"-k".to_string())));
    }

    #[test]
    fn previously_idle_original_stays_idle() {
        let r = restore_fixture();
        {
            let mut f = r.fake.lock().unwrap();
            let current = f.current.as_mut().unwrap();
            current.remove("pid");
            current.insert("state".into(), json!("not running"));
            f.bootstrap_original_running = false;
        }
        r.job.start().unwrap();
        let restored = r.job.restore().unwrap();
        assert!(!restored.contains_key("pid"));
        assert!(!verbs(&r.fake).contains(&"kickstart".to_string()));
    }

    #[test]
    fn failed_original_resume_is_reported() {
        let r = restore_fixture();
        r.fake.lock().unwrap().bootstrap_original_running = false;
        r.job.start().unwrap();
        r.fake.lock().unwrap().fail = Some("kickstart");
        assert!(r.job.restore().unwrap_err().to_string().contains("previous running state"));
    }

    #[test]
    fn bootout_failure_preserves_original() {
        let r = restore_fixture();
        r.fake.lock().unwrap().fail = Some("bootout");
        match r.job.start() {
            Err(RouteError::Unload(e)) => {
                assert_eq!(e.returncode, 5);
                assert_eq!(e.stderr, "Boot-out failed: fixture rejection");
            }
            other => panic!("unexpected {:?}", other),
        }
        assert!(r.job.original(&r.job.restore().unwrap()));
        assert!(!verbs(&r.fake).contains(&"bootstrap".to_string()));
    }

    #[test]
    fn bootout_timeout_after_mutation_restores() {
        let r = restore_fixture();
        r.fake.lock().unwrap().fail = Some("timeout");
        match r.job.start() {
            Err(RouteError::Other(e)) => assert_eq!(e.type_name(), "TimeoutExpired"),
            other => panic!("unexpected {:?}", other),
        }
        assert!(r.job.original(&r.job.restore().unwrap()));
        assert_eq!(verbs(&r.fake).iter().filter(|c| *c == "bootout").count(), 1);
    }

    #[test]
    fn bootstrap_failure_restores() {
        let r = restore_fixture();
        r.fake.lock().unwrap().fail = Some("bootstrap");
        assert!(matches!(r.job.start(), Err(RouteError::Other(Error::Runtime(_)))));
        assert!(r.job.original(&r.job.restore().unwrap()));
    }

    #[test]
    fn waits_for_asynchronous_bootout() {
        let r = restore_fixture();
        r.fake.lock().unwrap().fail = Some("delayed");
        r.job.start().unwrap();
        assert!(r.job.original(&r.job.restore().unwrap()));
    }

    #[test]
    fn foreign_configuration_is_preserved() {
        let r = restore_fixture();
        r.fake.lock().unwrap().current = Some(job_state(json!({"path": "/another/job.plist", "program": "/another/program"})));
        assert!(r.job.restore().is_err());
        assert!(verbs(&r.fake).iter().all(|c| c == "print"));
    }

    #[test]
    fn observation_failure_does_not_mutate() {
        let r = restore_fixture();
        r.fake.lock().unwrap().fail = Some("query");
        assert!(r.job.restore().is_err());
        assert!(verbs(&r.fake).iter().all(|c| c == "print"));
    }

    #[test]
    fn active_conference_does_not_mutate() {
        let r = restore_fixture();
        r.fake.lock().unwrap().current.as_mut().unwrap().insert("endpoint".into(), json!(1));
        assert!(r.job.start().is_err());
        assert!(!r.stage.join("armed.json").exists());
        assert!(verbs(&r.fake).iter().all(|c| c == "print"));
    }

    #[test]
    fn existing_hook_does_not_mutate() {
        let r = restore_fixture();
        r.fake.lock().unwrap().current.as_mut().unwrap().insert("injected".into(), json!(true));
        assert!(r.job.start().is_err());
        assert!(verbs(&r.fake).iter().all(|c| c == "print"));
    }

    #[test]
    fn process_observation_error_is_not_death() {
        let birth = json!([123, sys::getuid(), 1, 1]);
        assert!(owner_alive_with(&birth, &|_| Err(Error::os_message(libc::EIO, "unavailable"))).unwrap());
        assert!(!owner_alive_with(&birth, &|_| Ok(Some((123, sys::getuid(), 2, 1)))).unwrap());
        assert!(owner_alive_with(&birth, &|_| Ok(Some((123, sys::getuid(), 1, 1)))).unwrap());
        assert!(owner_alive_with(&json!([123, sys::getuid() + 1, 1, 1]), &|_| Ok(None)).is_err());
        assert!(owner_alive_with(&json!([1, 2]), &|_| Ok(None)).is_err());
    }

    #[test]
    fn staging_keeps_apple_options() {
        let r = restore_fixture();
        let original = r.stage.join("original.plist");
        let definition = Plist::Dict(vec![
            ("Label".into(), Plist::String(LABEL.into())),
            ("ProgramArguments".into(), Plist::Array(vec![Plist::String(PROGRAM.into()), Plist::String("--option".into())])),
            ("MachServices".into(), Plist::Dict(vec![("private.test.endpoint".into(), Plist::Bool(true))])),
            ("EnvironmentVariables".into(), Plist::Dict(vec![("EXISTING".into(), Plist::String("kept".into()))])),
        ]);
        std::fs::write(&original, plist::dumps(&definition).unwrap()).unwrap();
        let library = r.stage.join("input.dylib");
        std::fs::write(&library, b"local fixture").unwrap();
        util::chmod(&r.stage, 0o700).unwrap();
        let job = DecoderJob::with_hooks(&r.stage, JobHooks { original: original.clone(), ..hooks(&r.fake, &original) });
        let digests = job.prepare(&library, "all_h264").unwrap();
        assert_eq!(digests["decoder_hook_sha256"].as_str().unwrap().len(), 64);
        let staged = plist::loads(&std::fs::read(r.stage.join("job.plist")).unwrap()).unwrap();
        assert_eq!(staged.get("MachServices"), definition.get("MachServices"));
        assert_eq!(staged.get("EnvironmentVariables").unwrap().to_json(),
            json!({"EXISTING": "kept", "MIRRA_NO_FLS": "1", "MIRRA_DECODER_POLICY": "all_h264"}));
        let wrapper = std::fs::read_to_string(r.stage.join("wrapper")).unwrap();
        assert!(wrapper.contains("--option"));
        assert!(wrapper.starts_with("#!/bin/sh\nexport DYLD_INSERT_LIBRARIES="));
        assert!(job.prepare(&library, "other").is_err());
    }

    #[test]
    fn snapshot_reads_top_level_fields_and_endpoint_activity() {
        let text = "gui/501/x = {\n\tactive count = 0\n\tpath = /a.plist\n\tpid = 12\n\tstate = running\n\tprogram = /p\n\t\tpath = /nested\n\tendpoints = {\n\t\t\"com.apple.videoconference.avconference\" = {\n\t\t\tport = 0x1\n\t\t\tactive = 0\n\t\t}\n\t\t\"other\" = {\n\t\t\tactive = 2\n\t\t}\n\t}\n}\n";
        let value = snapshot(&Reply { code: 0, stdout: text.into(), stderr: String::new() }).unwrap();
        assert_eq!(Value::Object(value), json!({"injected": false, "endpoints": {"com.apple.videoconference.avconference": 0, "other": 2},
            "active count": 0, "path": "/a.plist", "pid": 12, "state": "running", "program": "/p"}));
        assert!(snapshot(&Reply { code: 113, stdout: String::new(), stderr: "Could not find service".into() }).unwrap().is_empty());
        assert!(snapshot(&Reply { code: 5, stdout: String::new(), stderr: "denied".into() }).is_err());
    }

    #[test]
    fn guardian_restores_after_owner_killed_and_keeps_lock() {
        let temp = tempfile::tempdir().unwrap();
        let base = mirra_core::paths::resolve(temp.path());
        let paths = RoutePaths { stages: base.join("stages"), cache: base.join("cache") };
        for dir in [&paths.stages, &paths.cache] {
            std::fs::create_dir(dir).unwrap();
            util::chmod(dir, 0o700).unwrap();
        }
        let stage = paths.stages.join("mirra-decoder-20261108-151300-guardtest");
        std::fs::create_dir(&stage).unwrap();
        util::chmod(&stage, 0o700).unwrap();
        let mut owner = std::process::Command::new("/bin/sleep").arg("5").spawn().unwrap();
        let lock = sys::open(&paths.lock(), libc::O_RDWR | libc::O_CREAT, 0o600).unwrap();
        sys::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB).unwrap();
        let fake = fake(&stage, Path::new(ORIGINAL));
        {
            let mut f = fake.lock().unwrap();
            f.current = Some(f.owned_state());
        }
        write_json(&stage.join("armed.json"), &json!({"armed": true})).unwrap();
        write_json(&stage.join("owner.json"), &json!({"owner_birth": util::birth_value(&process_birth(owner.id() as i32).unwrap()),
            "deadline_monotonic": null})).unwrap();
        let job_hooks = hooks(&fake, Path::new(ORIGINAL));
        let (thread_stage, thread_paths) = (stage.clone(), paths.clone());
        let child = std::thread::spawn(move || guardian_with(&thread_stage, lock, &thread_paths, &job_hooks, Duration::from_millis(20)));
        let deadline = Instant::now() + Duration::from_secs(3);
        while !stage.join("guardian-ready.json").exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(stage.join("guardian-ready.json").exists());
        let attempted = sys::open(&paths.lock(), libc::O_RDWR, 0).unwrap();
        let blocked = sys::flock(attempted.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB).unwrap_err();
        assert_eq!(blocked.raw_os_error(), Some(libc::EWOULDBLOCK));
        drop(attempted);
        owner.kill().unwrap();
        owner.wait().unwrap();
        assert_eq!(child.join().unwrap().unwrap(), 0);
        let result = util::read_json(&stage.join("restored.json")).unwrap();
        assert_eq!(result["original_avc_restored"], true);
        assert_eq!(result["state"]["program"], PROGRAM);
        let attempted = sys::open(&paths.lock(), libc::O_RDWR, 0).unwrap();
        // A child spawned by a parallel test can hold a copy until it execs.
        let release_deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match sys::flock(attempted.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) {
                Ok(()) => break,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < release_deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("Decoder route lock was not available after restoration: {error}"),
            }
        }
    }

    #[test]
    fn guardian_argv_and_usage() {
        let argv = guardian_command(Path::new("/pkg/build/mirra-cli"), Path::new("/private/var/tmp/AVConference/mirra-decoder-x"), 7);
        assert_eq!(argv, ["/pkg/build/mirra-cli", "__decoder-guardian", "/private/var/tmp/AVConference/mirra-decoder-x", "7"]);
        assert_eq!(guardian_main(&[]), 1);
        assert_eq!(guardian_main(&["/x".into(), "nan".into()]), 1);
    }

    #[test]
    fn prune_removes_only_expired_restored_stages() {
        let temp = tempfile::tempdir().unwrap();
        let base = mirra_core::paths::resolve(temp.path());
        let paths = RoutePaths { stages: base.clone(), cache: base.join("cache") };
        let make = |name: &str, restored: bool| {
            let stage = base.join(name);
            std::fs::create_dir(&stage).unwrap();
            util::chmod(&stage, 0o700).unwrap();
            write_json(&stage.join("restored.json"), &json!({"original_avc_restored": restored})).unwrap();
            stage
        };
        let old = make("mirra-decoder-20200101-000000-old", true);
        let pending = make("mirra-decoder-20200101-000000-pending", false);
        let other = make("unrelated", true);
        let fresh = make("mirra-decoder-20200101-000000-fresh", true);
        let past = std::time::SystemTime::now() - Duration::from_secs(8 * 86400);
        for dir in [&old, &pending, &other] {
            std::fs::File::open(dir).unwrap().set_modified(past).unwrap();
        }
        assert_eq!(prune_stages(&paths, &[], 7).unwrap(), ["mirra-decoder-20200101-000000-old"]);
        assert!(pending.exists() && other.exists() && fresh.exists() && !old.exists());
    }
}
