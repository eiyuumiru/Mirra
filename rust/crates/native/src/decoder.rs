//! Select the verified decoder route and own it for native support's
//! lifetime (port of `scripts/decoder.py`). State is saved to
//! `<run>/decoder-route.json` with the Python keys; the restoration guardian
//! runs as `<current_exe> __decoder-guardian <stage> <lock-fd>`.
use std::collections::{HashMap, VecDeque};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use mirra_core::activity::{self, FileLog};
use mirra_core::event::Event;
use mirra_core::processes::Birth;
use mirra_core::redaction::{redact_text, redact_value};
use mirra_core::state::write_state;
use mirra_core::subprocess::{self, RunOptions};
use mirra_core::{sys, Error, Result};
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::decoder_route::{self as route, DecoderJob, DecoderUnloadError, JobHooks, RouteError, RoutePaths};
use crate::util::{self, BirthProbe};

/// Intel builds whose AVConference still imports VCPDecompressionSessionCreate
/// from VideoProcessing, so the decoder hook interposes the same call.
pub const INSPECTED_BUILDS: [&str; 2] = ["25G332", "25G342"];
pub const INSPECTED_BUILD: &str = INSPECTED_BUILDS[0];

/// `{'model', 'architecture', 'build'}` of this host.
pub fn host_profile() -> Result<Map<String, Value>> {
    let read = |args: &[&str]| -> Result<String> {
        let reply = subprocess::run(args, &RunOptions::new().capture().check().timeout(Duration::from_secs(5)))?;
        Ok(reply.stdout_text().trim().to_string())
    };
    let mut host = Map::new();
    host.insert("model".into(), Value::from(read(&["/usr/sbin/sysctl", "-n", "hw.model"])?));
    host.insert("architecture".into(), Value::from(util::machine()));
    host.insert("build".into(), Value::from(read(&["/usr/bin/sw_vers", "-buildVersion"])?));
    Ok(host)
}

/// Select by inspected ABI; `auto` filters the actual stream in the hook.
pub fn select_route(mode: &str, host: &Map<String, Value>) -> Result<Map<String, Value>> {
    if !matches!(mode, "auto" | "normal" | "no_fls") {
        return Err(Error::value("Unknown decoder route setting"));
    }
    let compatible = host.get("architecture").and_then(Value::as_str) == Some("x86_64")
        && host.get("build").and_then(Value::as_str).is_some_and(|b| INSPECTED_BUILDS.contains(&b));
    let enabled = mode == "no_fls" || (mode == "auto" && compatible);
    if enabled && !compatible {
        return Err(Error::runtime(format!("The decoder route has been inspected for Intel macOS builds {} only",
            INSPECTED_BUILDS.join(", "))));
    }
    let reason = if mode != "auto" {
        "explicit decoder route"
    } else if enabled {
        "automatic Display P3/FLS compatibility"
    } else {
        "normal decoder for this host"
    };
    let mut value = Map::new();
    value.insert("requested".into(), Value::from(mode));
    value.insert("mode".into(), Value::from(if enabled { "no_fls" } else { "normal" }));
    value.insert("enabled".into(), Value::from(enabled));
    value.insert("policy".into(), Value::from(if mode == "auto" { "fls_p3" } else { "all_h264" }));
    value.insert("host".into(), Value::Object(host.clone()));
    value.insert("reason".into(), Value::from(reason));
    Ok(value)
}

/// `read_json`: private file, parsed.
pub fn read_json(path: &Path) -> Result<Value> {
    route::read_private_json(path)
}

/// The restoration guardian process (`subprocess.Popen` subset).
pub trait GuardianProcess: Send {
    /// Exit status once ended (`Popen.poll()`).
    fn poll(&mut self) -> Option<i32>;
    /// Wait up to `timeout`; `Ok(None)` when it is still running.
    fn wait(&mut self, timeout: Duration) -> Result<Option<i32>>;
}

struct SpawnedGuardian(Child);

impl GuardianProcess for SpawnedGuardian {
    fn poll(&mut self) -> Option<i32> {
        self.0.try_wait().ok().flatten().map(mirra_core::subprocess::return_code)
    }

    fn wait(&mut self, timeout: Duration) -> Result<Option<i32>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Ok(Some(mirra_core::subprocess::return_code(status)));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Starts the guardian for a stage, passing the held lock descriptor.
pub type GuardianSpawner = Box<dyn FnMut(&Path, RawFd) -> Result<Box<dyn GuardianProcess>> + Send>;

/// Spawn `<current_exe> __decoder-guardian <stage> <fd>` in a new session,
/// stdin from /dev/null, stdout/stderr to `<stage>/guardian.log` (created
/// exclusively, 0600), inheriting only the lock descriptor `fd`.
pub fn spawn_guardian_process(stage: &Path, lock: RawFd) -> Result<Box<dyn GuardianProcess>> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = stage.join("guardian.log");
    let output = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)
        .map_err(|e| Error::with_path(e, &path))?;
    util::chmod(&path, 0o600)?;
    let errors = output.try_clone()?;
    let executable = std::env::current_exe()?;
    let argv = route::guardian_command(&executable, stage, lock);
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]).stdin(Stdio::null()).stdout(output).stderr(errors);
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 || libc::fcntl(lock, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().map_err(|e| Error::with_path(e, &executable))?;
    Ok(Box::new(SpawnedGuardian(child)))
}

/// `log_limits.watch_native(path, pid, fd)`.
pub type LogWatch = Arc<dyn Fn(&Path, i32, i32) -> Result<()> + Send + Sync>;
pub type EventSink = Arc<dyn Fn(&Value) + Send + Sync>;

/// Replaceable environment of a [`DecoderRoute`] (tests use fakes).
pub struct RouteHooks {
    pub paths: RoutePaths,
    pub job: JobHooks,
    /// `Path.home()`: `native.log` under `Library/Application Support/Mirra/logs`.
    pub home: PathBuf,
    pub birth: BirthProbe,
    pub spawn: GuardianSpawner,
    /// `lifetime.emit_event`.
    pub event: EventSink,
    pub interval: Duration,
    pub guardian_timeout: Duration,
    pub hook_timeout: Duration,
    pub close_timeout: Duration,
}

impl Default for RouteHooks {
    fn default() -> Self {
        RouteHooks {
            paths: RoutePaths::default(),
            job: JobHooks::default(),
            home: util::home(),
            birth: util::real_birth(),
            spawn: Box::new(spawn_guardian_process),
            event: Arc::new(|value| {
                let _ = mirra_core::lifetime::emit_event(value);
            }),
            interval: Duration::from_millis(100),
            guardian_timeout: Duration::from_secs(12),
            hook_timeout: Duration::from_secs(15),
            close_timeout: Duration::from_secs(40),
        }
    }
}

const MAX_EVENTS: usize = 64;

pub struct DecoderRoute {
    pub root: PathBuf,
    pub directory: PathBuf,
    pub stop: Option<Event>,
    pub decision: Map<String, Value>,
    pub stage: Option<PathBuf>,
    pub job: Option<DecoderJob>,
    pub guardian: Option<Box<dyn GuardianProcess>>,
    pub lock: Option<OwnedFd>,
    pub events: VecDeque<Value>,
    pub event_count: u64,
    pub ready_pids: HashMap<i64, Birth>,
    pub ready: bool,
    /// Hook process id (`null` until observed).
    pub pid: Value,
    pub metadata: Map<String, Value>,
    pub observation: String,
    positions: HashMap<&'static str, u64>,
    log: Arc<FileLog>,
    log_limits: Option<LogWatch>,
    pub hooks: RouteHooks,
}

fn fields(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn truthy(value: Option<&Value>) -> bool {
    !matches!(value, None | Some(Value::Null) | Some(Value::Bool(false)))
        && !matches!(value, Some(Value::Number(n)) if n.as_f64() == Some(0.0))
}

impl DecoderRoute {
    /// `DecoderRoute(root, directory, mode=, stop=, host=, log_limits=)`;
    /// `host` defaults to [`host_profile`].
    pub fn new(root: &Path, directory: &Path, mode: &str, stop: Option<Event>, host: Option<Map<String, Value>>,
        log_limits: Option<LogWatch>) -> Result<Self> {
        Self::with_hooks(root, directory, mode, stop, host, log_limits, RouteHooks::default())
    }

    pub fn with_hooks(root: &Path, directory: &Path, mode: &str, stop: Option<Event>, host: Option<Map<String, Value>>,
        log_limits: Option<LogWatch>, hooks: RouteHooks) -> Result<Self> {
        let host = match host {
            Some(host) => host,
            None => host_profile()?,
        };
        let decision = select_route(mode, &host)?;
        let log = Arc::new(FileLog::new(hooks.home.join("Library/Application Support/Mirra/logs")).with_name("native.log"));
        Ok(DecoderRoute {
            root: root.to_path_buf(), directory: directory.to_path_buf(), stop, decision, stage: None, job: None,
            guardian: None, lock: None, events: VecDeque::new(), event_count: 0, ready_pids: HashMap::new(), ready: false,
            pid: Value::Null, metadata: Map::new(), observation: "starting".into(), positions: HashMap::new(), log,
            log_limits, hooks,
        })
    }

    fn enabled(&self) -> bool {
        self.decision.get("enabled") == Some(&Value::Bool(true))
    }

    /// Activity log (`native.log`) and a `service.log` event line.
    pub fn record(&self, message: &str, level: &str, fields: Map<String, Value>) {
        let fields = Value::Object(fields);
        activity::capture(Some(FileLog::shared_sink(&self.log)), || activity::emit("Decoder", message, level, fields.clone()));
        (self.hooks.event)(&json!({"source": "Decoder", "message": redact_text(message), "level": level,
            "timestamp": activity::utc_timestamp(), "fields": redact_value(&fields)}));
    }

    /// Write `<directory>/decoder-route.json` and return it.
    pub fn save(&self, extra: Map<String, Value>) -> Result<Value> {
        let mut value = self.decision.clone();
        value.insert("ready".into(), Value::from(self.ready));
        value.insert("hook_pid".into(), self.pid.clone());
        value.insert("native_event_count".into(), Value::from(self.event_count));
        value.insert("native_decoder_events".into(), Value::Array(self.events.iter().cloned().collect()));
        value.insert("native_video_observations".into(), self.video_observations());
        value.extend(self.metadata.clone());
        value.extend(extra);
        if let Some(stage) = &self.stage {
            value.insert("stage".into(), Value::from(util::text(stage)));
        }
        let value = Value::Object(value);
        write_state(&self.directory.join("decoder-route.json"), &value)?;
        Ok(value)
    }

    /// Creation is not frame delivery; a fresh hook discards old evidence.
    pub fn video_observations(&self) -> Value {
        let mut result = json!({"scope": "latest_captured_creation", "process_id": null, "session_created": null,
            "creation_status": null, "using_hardware_acceleration": null, "frame_delivery_verified": null,
            "presentation_verified": null});
        for event in self.events.iter().rev() {
            let message = event.get("message").and_then(Value::as_str).unwrap_or("");
            if message.starts_with("MIRRA_DECODER_HOOK_READY ") {
                break;
            }
            if !message.starts_with("MIRRA_DECODER_ROUTE ") {
                continue;
            }
            let status = event.get("status");
            result["process_id"] = event.get("pid").cloned().unwrap_or(Value::Null);
            result["creation_status"] = status.cloned().unwrap_or(Value::Null);
            let created = util::strict_int(event.get("session_created")).or_else(|| match event.get("session_created") {
                Some(Value::Bool(b)) => Some(*b as i64),
                _ => None,
            });
            let status_int = util::strict_int(status);
            if status_int.is_some_and(|s| s != 0) {
                result["session_created"] = Value::from(false);
            } else if util::eq_int(status, 0) && matches!(created, Some(0 | 1)) {
                result["session_created"] = Value::from(created == Some(1));
            }
            if result["session_created"] == Value::Bool(true) && util::eq_int(event.get("hardware_query"), 0)
                && (util::eq_int(event.get("using_hardware"), 0) || util::eq_int(event.get("using_hardware"), 1)) {
                result["using_hardware_acceleration"] = Value::from(util::eq_int(event.get("using_hardware"), 1));
            }
            break;
        }
        result
    }

    pub fn interrupted(&self) -> bool {
        self.stop.as_ref().is_some_and(Event::is_set)
    }

    fn guardian_ended(&mut self) -> bool {
        self.guardian.as_mut().is_none_or(|g| g.poll().is_some())
    }

    fn make_stage(&self) -> Result<PathBuf> {
        use std::os::unix::fs::DirBuilderExt;
        const CHARACTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
        let prefix = format!("mirra-decoder-{}-", chrono::Local::now().format("%Y%m%d-%H%M%S"));
        for _ in 0..10000 {
            let suffix: String = (0..8).map(|_| CHARACTERS[sys::random_below(CHARACTERS.len() as u32) as usize] as char).collect();
            let path = self.hooks.paths.stages.join(format!("{}{}", prefix, suffix));
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(Error::with_path(e, &path)),
            }
        }
        Err(Error::runtime("No usable temporary directory name"))
    }

    /// Prepare and start the selected route; returns the saved state.
    /// `RouteError::Unload` is returned only for an explicit (non-auto) route.
    pub fn start(&mut self) -> Result<Value, RouteError> {
        self.record("Selected decoder route", "info", self.decision.clone());
        if !self.enabled() {
            // Explicit normal mode does not inspect or restart AVConference.
            // A journal from an interrupted diagnostic still needs restoration.
            if self.hooks.paths.journal().exists() {
                self.record("Recovering an earlier decoder session", "info", Map::new());
                drop(route::acquire_with(&self.hooks.paths, &self.hooks.job)?);
                self.record("Earlier decoder session restored", "info", Map::new());
            }
            self.ready = true;
            return Ok(self.save(Map::new())?);
        }
        self.lock = Some(route::acquire_with(&self.hooks.paths, &self.hooks.job)?);
        let stages = self.hooks.paths.stages.clone();
        match std::fs::create_dir(&stages) {
            Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => return Err(Error::with_path(e, &stages).into()),
            _ => {}
        }
        if !sys::lstat(&stages).map(|i| sys::is_dir(i.st_mode)).map_err(|e| Error::with_path(e, &stages))? {
            return Err(Error::runtime("AVConference staging directory is unavailable").into());
        }
        let removed = route::prune_stages(&self.hooks.paths, &[], 7)?;
        if !removed.is_empty() {
            self.record("Removed expired decoder logs", "info", fields(json!({"directories": removed, "retention_days": 7})));
        }
        let stage = self.make_stage()?;
        util::chmod(&stage, 0o700)?;
        self.stage = Some(stage.clone());
        let job = DecoderJob::with_hooks(&stage, self.hooks.job.clone());
        self.job = Some(DecoderJob::with_hooks(&stage, self.hooks.job.clone()));
        job.require_idle()?;
        self.record("Verified that original AVConference is idle", "info", Map::new());
        let policy = self.decision["policy"].as_str().unwrap_or("all_h264").to_string();
        self.metadata = fields(job.prepare(&self.root.join("build/decoder-route.dylib"), &policy)?);
        route::write_json(&stage.join("metadata.json"), &Value::Object(self.metadata.clone()))?;
        let Some(birth) = (self.hooks.birth)(util::own_pid())? else {
            return Err(Error::runtime("Native support process identity could not be verified").into());
        };
        let mut owner = fields(json!({"stage": util::text(&stage), "owner_birth": mirra_core::retention::birth_json(&birth),
            "deadline_monotonic": null, "session": "native support"}));
        route::write_json(&stage.join("owner.json"), &Value::Object(owner.clone()))?;
        route::write_json(&self.hooks.paths.journal(), &Value::Object(owner.clone()))?;
        self.spawn_guardian()?;
        let deadline = Instant::now() + self.hooks.guardian_timeout;
        while !stage.join("guardian-ready.json").exists() {
            if self.interrupted() || self.guardian_ended() || Instant::now() >= deadline {
                return Err(Error::runtime("Restoration guardian could not start; no decoder change made").into());
            }
            std::thread::sleep(self.hooks.interval);
        }
        owner.extend(fields(read_json(&stage.join("guardian-ready.json"))?));
        let guardian_birth = owner.get("guardian_birth").cloned().unwrap_or(Value::Null);
        if !route::owner_alive(&guardian_birth)? {
            return Err(Error::runtime("Restoration guardian identity could not be verified").into());
        }
        route::write_json(&self.hooks.paths.journal(), &Value::Object(owner.clone()))?;
        self.record("Restoration guardian started", "info", fields(json!({"guardian_birth": guardian_birth})));
        let started = (|| -> Result<(), RouteError> {
            let _transaction = route::transaction(&stage)?;
            if self.interrupted() || self.guardian_ended() || stage.join("restored.json").exists() {
                return Err(Error::runtime("Native support stopped before decoder startup").into());
            }
            job.start()
        })();
        match started {
            Ok(()) => {}
            Err(RouteError::Unload(error)) => {
                self.record("AVConference unload failed", "error",
                    fields(json!({"launchctl_exit": error.returncode, "launchctl_stderr": error.stderr})));
                if self.decision.get("requested").and_then(Value::as_str) != Some("auto") {
                    return Err(RouteError::Unload(error));
                }
                return self.use_normal_after_restore(error).map_err(RouteError::from);
            }
            Err(other) => return Err(other),
        }
        self.record("Started AVConference with the decoder route", "info", Map::new());
        let deadline = Instant::now() + self.hooks.hook_timeout;
        loop {
            self.drain_native()?;
            if self.interrupted() || self.guardian_ended() {
                return Err(Error::runtime("Decoder startup interrupted; restoration requested").into());
            }
            let current = job.state()?;
            let pid = current.get("pid").and_then(|p| util::strict_int(Some(p)));
            if job.owned(&current) {
                if let Some(pid) = pid {
                    if let Some(expected) = self.ready_pids.get(&pid).copied() {
                        if (self.hooks.birth)(pid as i32)? == Some(expected) {
                            self.pid = Value::from(pid);
                            break;
                        }
                    }
                }
            }
            if !current.is_empty() && !job.owned(&current) {
                return Err(Error::runtime("AVConference changed during decoder startup").into());
            }
            if Instant::now() >= deadline {
                return Err(Error::runtime("AVConference did not load the decoder hook").into());
            }
            std::thread::sleep(self.hooks.interval);
        }
        if let Some(watch) = &self.log_limits {
            let pid = self.pid.as_i64().unwrap_or(0) as i32;
            for (fd, name) in [(1, "stdout.log"), (2, "stderr.log")] {
                watch(&stage.join(name), pid, fd)?;
            }
        }
        self.ready = true;
        self.observation = "ready".into();
        let mut ready = fields(json!({"pid": self.pid}));
        ready.extend(self.metadata.clone());
        self.record("Decoder route is ready", "info", ready);
        Ok(self.save(Map::new())?)
    }

    /// A nonzero bootout status does not establish whether it changed the
    /// job: complete and verify restoration before accepting a normal route.
    fn use_normal_after_restore(&mut self, error: DecoderUnloadError) -> Result<Value> {
        let restored = self.close()?;
        if restored.get("cleanup_verified") != Some(&Value::Bool(true)) || !truthy(restored.get("original_avc_restored"))
            || self.hooks.paths.journal().exists() || self.interrupted() {
            return Err(Error::runtime("Automatic decoder fallback requires verified AVConference restoration"));
        }
        let fallback = fields(json!({"reason": "avconference_unload_failed", "launchctl_exit": error.returncode,
            "original_avc_restored": true, "stage": self.stage.as_deref().map(util::text)}));
        self.metadata.insert("decoder_fallback".into(), Value::Object(fallback.clone()));
        self.stage = None;
        self.job = None;
        self.guardian = None;
        self.decision.insert("mode".into(), Value::from("normal"));
        self.decision.insert("enabled".into(), Value::from(false));
        self.decision.insert("reason".into(), Value::from("normal decoder after automatic compatibility setup was unavailable"));
        self.ready = true;
        self.observation = "ready".into();
        let mut message = fields(json!({"compatibility_hook_active": false}));
        message.extend(fallback);
        self.record("Continuing with the normal decoder after verified restoration", "warning", message);
        self.save(Map::new())
    }

    fn spawn_guardian(&mut self) -> Result<()> {
        let stage = self.stage.clone().ok_or_else(|| Error::runtime("Decoder stage is unavailable"))?;
        let lock = self.lock.as_ref().map(AsRawFd::as_raw_fd).ok_or_else(|| Error::runtime("Decoder route lock is unavailable"))?;
        self.guardian = Some((self.hooks.spawn)(&stage, lock)?);
        Ok(())
    }

    /// Read new complete lines of the hook's stdout/stderr logs.
    pub fn drain_native(&mut self) -> Result<()> {
        static FIELD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"([a-z_]+)=(-?\d+)").unwrap());
        let Some(stage) = self.stage.clone() else { return Ok(()) };
        let mut changed = false;
        for name in ["stdout.log", "stderr.log"] {
            let path = stage.join(name);
            if !path.exists() {
                continue;
            }
            route::private(&path, false)?;
            let descriptor = sys::open(&path, libc::O_RDONLY | libc::O_NOFOLLOW, 0).map_err(|e| Error::with_path(e, &path))?;
            let size = sys::fstat(descriptor.as_raw_fd())?.st_size.max(0) as u64;
            let mut offset = self.positions.get(name).copied().unwrap_or(0);
            if offset > size {
                offset = 0;
            }
            let raw = sys::pread(descriptor.as_raw_fd(), 65536.min(size.saturating_sub(offset) as usize), offset)?;
            let Some(end) = raw.iter().rposition(|b| *b == b'\n') else { continue };
            let complete = &raw[..end];
            self.positions.insert(name, offset + end as u64 + 1);
            let text = String::from_utf8_lossy(complete).into_owned();
            for line in mirra_core::pyfmt::splitlines(&text) {
                if !line.starts_with("MIRRA_DECODER_ROUTE ") && !line.starts_with("MIRRA_DECODER_HOOK_READY ") {
                    continue;
                }
                let mut parsed = Map::new();
                for capture in FIELD.captures_iter(line) {
                    if let Ok(number) = serde_json::from_str::<Value>(&capture[2]) {
                        parsed.insert(capture[1].to_string(), number);
                    }
                }
                let message: String = line.chars().take(4096).collect();
                let mut event = fields(json!({"message": message}));
                event.extend(parsed.clone().into_iter().filter(|(k, _)| k != "message"));
                self.events.push_back(Value::Object(event));
                if self.events.len() > MAX_EVENTS {
                    self.events.pop_front();
                }
                self.event_count += 1;
                changed = true;
                if line.starts_with("MIRRA_DECODER_HOOK_READY ") && util::eq_int(parsed.get("version"), 1) {
                    if let Some(pid) = util::strict_int(parsed.get("pid")).filter(|p| *p > 0) {
                        if let Some(birth) = (self.hooks.birth)(pid as i32)? {
                            self.ready_pids.insert(pid, birth);
                        }
                    }
                }
                self.record(&message, "info", parsed);
            }
        }
        if changed {
            self.save(Map::new())?;
        }
        Ok(())
    }

    fn availability(&mut self, observation: &str, pid: Value) -> Result<()> {
        let ready = observation == "ready" || observation == "idle";
        if observation == self.observation && pid == self.pid && ready == self.ready {
            return Ok(());
        }
        self.observation = observation.into();
        self.pid = pid.clone();
        self.ready = ready;
        let message = match observation {
            "ready" => "AVConference loaded the decoder route",
            "idle" => "AVConference is idle; decoder support remains registered",
            "starting" => "Waiting for AVConference to load the decoder route",
            _ => "Decoder observation deferred; support remains registered",
        };
        self.record(message, "info", fields(json!({"pid": pid})));
        self.save(fields(json!({"observation": observation})))?;
        Ok(())
    }

    /// Periodic observation. Launchd may leave the service idle or relaunch
    /// it on demand; only a guardian exit or a foreign job is an error.
    pub fn poll(&mut self) -> Result<()> {
        if !self.enabled() {
            return Ok(());
        }
        let restored = self.stage.as_ref().is_some_and(|s| s.join("restored.json").exists());
        if self.guardian_ended() || restored {
            return Err(Error::runtime("The decoder guardian ended before native support stopped"));
        }
        let observed = (|| -> Result<(route::JobState, Value, Option<Birth>)> {
            self.drain_native()?;
            let job = self.job.as_ref().ok_or_else(|| Error::runtime("Decoder job is unavailable"))?;
            let current = job.state()?;
            let pid = current.get("pid").cloned().unwrap_or(Value::Null);
            let birth = match util::strict_int(Some(&pid)).filter(|p| *p > 0) {
                Some(p) => (self.hooks.birth)(p as i32)?,
                None => None,
            };
            Ok((current, pid, birth))
        })();
        let Ok((current, pid, birth)) = observed else { return self.availability("unknown", Value::Null) };
        if current.is_empty() {
            return self.availability("unknown", Value::Null);
        }
        if !self.job.as_ref().unwrap().owned(&current) {
            return Err(Error::runtime("AVConference changed to another configuration"));
        }
        let state = current.get("state").and_then(Value::as_str);
        let known = util::strict_int(Some(&pid)).and_then(|p| self.ready_pids.get(&p).copied());
        if pid.is_null() && matches!(state, Some("not running" | "exited")) {
            self.availability("idle", Value::Null)
        } else if birth.is_none() || known != birth {
            self.availability("starting", pid)
        } else {
            self.availability("ready", pid)
        }
    }

    fn close_body(&mut self, result: &mut Map<String, Value>) -> Result<()> {
        let Some(stage) = self.stage.clone() else {
            result.insert("cleanup_verified".into(), Value::from(true));
            result.insert("avc_change_armed".into(), Value::from(false));
            return Ok(());
        };
        result.insert("avc_change_armed".into(), Value::from(stage.join("armed.json").exists()));
        self.record("Restoring original AVConference", "info", Map::new());
        route::write_json(&stage.join("stop.json"), &json!({"stop": true}))?;
        let timeout = self.hooks.close_timeout;
        if let Some(guardian) = self.guardian.as_mut() {
            if guardian.poll().is_none() && guardian.wait(timeout)?.is_none() {
                // The guardian retains its lock and restoration opportunity.
                result.insert("original_avc_restored".into(), Value::from(false));
                result.insert("restoration_pending".into(), Value::from(true));
                return Ok(());
            }
        }
        let job = self.job.as_ref().ok_or_else(|| Error::runtime("Decoder job is unavailable"))?;
        let restored = stage.join("restored.json");
        if !restored.exists() || !truthy(read_json(&restored)?.get("original_avc_restored")) {
            // Also covers a guardian failure before or during startup.
            let _transaction = route::transaction(&stage)?;
            let current = job.restore()?;
            route::write_json(&restored, &json!({"original_avc_restored": true, "state": current, "recovered_by_supervisor": true}))?;
            route::clear_journal(&stage, &self.hooks.paths)?;
        }
        result.extend(fields(read_json(&restored)?));
        let current = job.state()?;
        if !job.original(&current) {
            return Err(Error::runtime("Original AVConference restoration could not be verified"));
        }
        self.drain_native()?;
        result.insert("cleanup_verified".into(), Value::from(true));
        self.record("Original AVConference restored and verified", "info", Map::new());
        Ok(())
    }

    /// Restore Apple's job (via the guardian, or directly) and report
    /// `{enabled, cleanup_verified, original_avc_restored, ...}`.
    pub fn close(&mut self) -> Result<Value> {
        self.ready = false;
        let mut result = fields(json!({"enabled": self.enabled(), "cleanup_verified": false, "original_avc_restored": null}));
        if let Err(error) = self.close_body(&mut result) {
            result.insert("original_avc_restored".into(), Value::from(false));
            result.insert("error".into(), Value::from(error.to_string()));
            self.record("Decoder restoration remains pending", "error",
                fields(json!({"error_type": error.type_name(), "error": error.to_string()})));
        }
        self.lock = None;
        let result = Value::Object(result);
        self.save(fields(json!({"restoration": result})))?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder_route::tests::{fake, hooks as job_hooks, Fake};
    use crate::plist::{self, Plist};
    use std::sync::Mutex;

    fn host(model: &str, architecture: &str, build: &str) -> Map<String, Value> {
        fields(json!({"architecture": architecture, "build": build, "model": model}))
    }

    fn laptop() -> Map<String, Value> {
        host("MacBookPro16,2", "x86_64", "25G332")
    }

    fn desktop() -> Map<String, Value> {
        host("MacPro7,1", "x86_64", "25G332")
    }

    #[test]
    fn host_selection() {
        let value = select_route("auto", &laptop()).unwrap();
        assert_eq!(value["enabled"], true);
        assert_eq!(value["policy"], "fls_p3");
        assert_eq!(select_route("auto", &desktop()).unwrap()["enabled"], true);
        for h in [host("MacPro7,1", "x86_64", "different"), host("MacPro7,1", "arm64", "25G332")] {
            assert_eq!(select_route("auto", &h).unwrap()["enabled"], false);
        }
        let other = select_route("auto", &host("iMac20,1", "x86_64", "25G342")).unwrap();
        assert_eq!((other["enabled"].clone(), other["policy"].clone()), (json!(true), json!("fls_p3")));
        assert_eq!(select_route("no_fls", &laptop()).unwrap()["policy"], "all_h264");
        assert_eq!(select_route("normal", &desktop()).unwrap()["enabled"], false);
        assert!(matches!(select_route("no_fls", &host("x", "x86_64", "uninspected")), Err(Error::Runtime(_))));
        assert!(matches!(select_route("FLS", &laptop()), Err(Error::Value(_))));
        let selected = select_route("auto", &laptop()).unwrap();
        let keys: Vec<&String> = selected.keys().collect();
        assert_eq!(keys, ["requested", "mode", "enabled", "policy", "host", "reason"]);
    }

    type ExitCode = Arc<Mutex<Option<i32>>>;
    type ExitSlot = Arc<Mutex<Option<ExitCode>>>;

    struct Fixture {
        _temp: tempfile::TempDir,
        root: PathBuf,
        directory: PathBuf,
        paths: RoutePaths,
        fake: Fake,
        guardian_exit: ExitSlot,
        birth_override: Arc<Mutex<Option<Birth>>>,
    }

    struct FakeGuardian {
        exit: Arc<Mutex<Option<i32>>>,
        stage: PathBuf,
        paths: RoutePaths,
        hooks: JobHooks,
        stop_after_restore: Option<Event>,
    }

    impl GuardianProcess for FakeGuardian {
        fn poll(&mut self) -> Option<i32> {
            *self.exit.lock().unwrap()
        }
        fn wait(&mut self, _: Duration) -> Result<Option<i32>> {
            let state = DecoderJob::with_hooks(&self.stage, self.hooks.clone()).restore()?;
            route::write_json(&self.stage.join("restored.json"), &json!({"original_avc_restored": true, "state": state}))?;
            route::clear_journal(&self.stage, &self.paths)?;
            *self.exit.lock().unwrap() = Some(0);
            if let Some(stop) = &self.stop_after_restore {
                stop.set();
            }
            Ok(Some(0))
        }
    }

    fn fixture() -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let root = mirra_core::paths::resolve(temp.path());
        let directory = root.join("run");
        let paths = RoutePaths { stages: root.join("stages"), cache: root.join("cache") };
        for dir in [&directory, &paths.stages, &paths.cache] {
            std::fs::create_dir(dir).unwrap();
            util::chmod(dir, 0o700).unwrap();
        }
        std::fs::create_dir(root.join("build")).unwrap();
        std::fs::write(root.join("build/decoder-route.dylib"), b"simulated fixture").unwrap();
        let original = root.join("original.plist");
        let definition = Plist::Dict(vec![("Label".into(), Plist::String(route::LABEL.into())),
            ("ProgramArguments".into(), Plist::Array(vec![Plist::String(route::PROGRAM.into())]))]);
        std::fs::write(&original, plist::dumps(&definition).unwrap()).unwrap();
        let fake = fake(&root, &original);
        {
            let mut f = fake.lock().unwrap();
            f.stages = Some(paths.stages.clone());
            f.owned_pid = util::own_pid() as i64;
            f.ready_marker = true;
        }
        Fixture { _temp: temp, root, directory, paths, fake, guardian_exit: Arc::new(Mutex::new(None)),
            birth_override: Arc::new(Mutex::new(None)) }
    }

    fn controller(f: &Fixture, mode: &str, failure: Option<&'static str>, stop_after_restore: bool) -> DecoderRoute {
        f.fake.lock().unwrap().fail = failure;
        let original = f.root.join("original.plist");
        let job = job_hooks(&f.fake, &original);
        let stop = Event::new();
        let (exit_slot, paths, spawn_hooks) = (f.guardian_exit.clone(), f.paths.clone(), job.clone());
        let after = if stop_after_restore { Some(stop.clone()) } else { None };
        let spawn: GuardianSpawner = Box::new(move |stage, _lock| {
            let exit = Arc::new(Mutex::new(None));
            *exit_slot.lock().unwrap() = Some(exit.clone());
            route::write_json(&stage.join("guardian-ready.json"),
                &json!({"guardian_birth": util::birth_value(&mirra_core::processes::process_birth(util::own_pid())?)}))?;
            Ok(Box::new(FakeGuardian { exit, stage: stage.to_path_buf(), paths: paths.clone(), hooks: spawn_hooks.clone(),
                stop_after_restore: after.clone() }))
        });
        let birth_override = f.birth_override.clone();
        let hooks = RouteHooks {
            paths: f.paths.clone(), job, home: f.root.clone(),
            birth: Arc::new(move |pid| match *birth_override.lock().unwrap() {
                Some(birth) => Ok(Some(birth)),
                None => mirra_core::processes::process_birth(pid),
            }),
            spawn, event: Arc::new(|_| {}), interval: Duration::from_millis(1),
            ..RouteHooks::default()
        };
        DecoderRoute::with_hooks(&f.root, &f.directory, mode, Some(stop), Some(desktop()), None, hooks).unwrap()
    }

    fn calls(f: &Fixture) -> Vec<Vec<String>> {
        f.fake.lock().unwrap().calls.clone()
    }

    fn set_guardian_exit(f: &Fixture, code: i32) {
        *f.guardian_exit.lock().unwrap().as_ref().unwrap().lock().unwrap() = Some(code);
    }

    #[test]
    fn video_observations_require_session_evidence_and_preserve_unknown_frames() {
        let f = fixture();
        let mut instance = controller(&f, "auto", None, false);
        assert_eq!(instance.video_observations()["session_created"], Value::Null);
        instance.events.push_back(json!({"message": "MIRRA_DECODER_ROUTE ", "status": 0, "using_hardware": 1}));
        assert_eq!(instance.video_observations()["session_created"], Value::Null);
        instance.events.push_back(json!({"message": "MIRRA_DECODER_ROUTE ", "status": 0, "session_created": 1,
            "hardware_query": 0, "using_hardware": 1}));
        let value = instance.video_observations();
        assert_eq!(value["session_created"], true);
        assert_eq!(value["using_hardware_acceleration"], true);
        assert_eq!(value["frame_delivery_verified"], Value::Null);
        assert_eq!(value["presentation_verified"], Value::Null);
        instance.events.push_back(json!({"message": "MIRRA_DECODER_ROUTE ", "status": 0, "session_created": 0}));
        assert_eq!(instance.video_observations()["session_created"], false);
        instance.events.push_back(json!({"message": "MIRRA_DECODER_ROUTE ", "status": -123, "session_created": 1}));
        assert_eq!(instance.video_observations()["session_created"], false);
        instance.events.push_back(json!({"message": "MIRRA_DECODER_HOOK_READY "}));
        assert_eq!(instance.video_observations()["session_created"], Value::Null);
    }

    #[test]
    fn normal_start_and_close_do_not_inspect_or_mutate_avconference() {
        let f = fixture();
        let mut hooks = RouteHooks { paths: f.paths.clone(), home: f.root.clone(), event: Arc::new(|_| {}),
            spawn: Box::new(|_, _| panic!("no guardian")), ..RouteHooks::default() };
        hooks.job.command = Arc::new(|_| panic!("no launchctl"));
        let mut instance = DecoderRoute::with_hooks(&f.root, &f.directory, "normal", None, Some(laptop()), None, hooks).unwrap();
        let state = instance.start().unwrap();
        instance.poll().unwrap();
        let result = instance.close().unwrap();
        assert_eq!(state["ready"], true);
        assert_eq!(result["cleanup_verified"], true);
        assert_eq!(result["original_avc_restored"], Value::Null);
        assert!(!f.paths.lock().exists());
    }

    #[test]
    fn auto_bootout_failure_continues_normal_after_verified_restore() {
        let f = fixture();
        let mut instance = controller(&f, "auto", Some("bootout"), false);
        let state = instance.start().unwrap();
        assert_eq!(state["requested"], "auto");
        assert_eq!(state["mode"], "normal");
        assert_eq!(state["ready"], true);
        assert_eq!(state["enabled"], false);
        assert_eq!(state["decoder_fallback"]["original_avc_restored"], true);
        assert_eq!(state["decoder_fallback"]["launchctl_exit"], 5);
        let saved = read_json(&f.directory.join("decoder-route.json")).unwrap();
        assert_eq!(saved["decoder_fallback"], state["decoder_fallback"]);
        assert!(instance.lock.is_none());
        assert!(!f.paths.journal().exists());
        assert_eq!(calls(&f).iter().filter(|c| c[0] == "bootout").count(), 1);
        assert!(!calls(&f).iter().any(|c| c[0] == "bootstrap"));
        let before = calls(&f).len();
        instance.poll().unwrap();
        assert_eq!(instance.close().unwrap()["cleanup_verified"], true);
        assert_eq!(calls(&f).len(), before);
    }

    #[test]
    fn auto_nonzero_bootout_that_removed_job_restores_before_fallback() {
        let f = fixture();
        let mut instance = controller(&f, "auto", Some("bootout_after_removal"), false);
        let state = instance.start().unwrap();
        assert_eq!(state["mode"], "normal");
        assert_eq!(state["decoder_fallback"]["original_avc_restored"], true);
        let bootstraps: Vec<Vec<String>> = calls(&f).into_iter().filter(|c| c[0] == "bootstrap").collect();
        assert_eq!(bootstraps.len(), 1);
        assert_eq!(bootstraps[0].last().unwrap(), &util::text(&f.root.join("original.plist")));
        instance.close().unwrap();
    }

    #[test]
    fn auto_fallback_refuses_foreign_service_after_rejected_bootout() {
        let f = fixture();
        let mut instance = controller(&f, "auto", Some("bootout_foreign"), false);
        let error = instance.start().unwrap_err();
        assert!(error.to_string().contains("requires verified"), "{}", error);
        assert!(!instance.ready);
        assert!(f.paths.journal().exists());
        assert_eq!(f.fake.lock().unwrap().current.as_ref().unwrap()["path"], "/foreign/job.plist");
        assert!(!calls(&f).iter().any(|c| c[0] == "bootstrap"));
    }

    #[test]
    fn explicit_hook_request_never_falls_back() {
        let f = fixture();
        let mut instance = controller(&f, "no_fls", Some("bootout"), false);
        assert!(matches!(instance.start(), Err(RouteError::Unload(_))));
        assert_eq!(instance.decision["enabled"], true);
        assert!(!instance.ready);
        assert!(!instance.metadata.contains_key("decoder_fallback"));
        instance.close().unwrap();
    }

    #[test]
    fn other_startup_errors_are_not_hidden_by_fallback() {
        let f = fixture();
        let mut instance = controller(&f, "auto", Some("bootstrap"), false);
        assert!(instance.start().unwrap_err().to_string().contains("registration failed"));
        assert!(!instance.metadata.contains_key("decoder_fallback"));
        assert!(!instance.ready);
        instance.close().unwrap();
    }

    #[test]
    fn stop_during_restoration_prevents_fallback_readiness() {
        let f = fixture();
        let mut instance = controller(&f, "auto", Some("bootout"), true);
        assert!(instance.start().unwrap_err().to_string().contains("requires verified"));
        assert!(!instance.ready);
        assert!(!f.paths.journal().exists());
    }

    #[test]
    fn production_session_has_no_test_deadline_and_restores_on_stop() {
        let f = fixture();
        let mut instance = controller(&f, "auto", None, false);
        let state = instance.start().unwrap();
        let stage = instance.stage.clone().unwrap();
        let owner = read_json(&stage.join("owner.json")).unwrap();
        assert_eq!(state["ready"], true);
        assert_eq!(owner["deadline_monotonic"], Value::Null);
        assert!(owner.get("gui_birth").is_none());
        let staged = plist::loads(&std::fs::read(stage.join("job.plist")).unwrap()).unwrap();
        assert_eq!(staged.get("EnvironmentVariables").unwrap().get("MIRRA_DECODER_POLICY").and_then(Plist::as_str), Some("fls_p3"));
        assert!(STAGE_NAME.is_match(&stage.file_name().unwrap().to_string_lossy()));
        instance.poll().unwrap();
        let result = instance.close().unwrap();
        assert_eq!(result["original_avc_restored"], true);
        assert_eq!(result["cleanup_verified"], true);
        assert!(!f.paths.journal().exists());
        assert!(calls(&f).iter().any(|c| c[0] == "bootout"));
        assert!(f.root.join("Library/Application Support/Mirra/logs").is_dir());
    }

    static STAGE_NAME: LazyLock<Regex> = LazyLock::new(|| route::STAGE_PATTERN.clone());

    #[test]
    fn real_markers_are_parsed_and_non_decoder_messages_are_excluded() {
        let f = fixture();
        let mut instance = controller(&f, "auto", None, false);
        instance.start().unwrap();
        let stage = instance.stage.clone().unwrap();
        {
            use std::io::Write;
            let mut log = std::fs::OpenOptions::new().append(true).open(stage.join("stderr.log")).unwrap();
            log.write_all(b"ordinary unrelated message\n").unwrap();
            log.write_all(b"MIRRA_DECODER_ROUTE create=1 removed=1 had_fls=1 colour_primaries=12 status=0 using_hardware=1\n").unwrap();
        }
        instance.poll().unwrap();
        let value = read_json(&f.directory.join("decoder-route.json")).unwrap();
        assert_eq!(value["native_event_count"], 2);
        let events = value["native_decoder_events"].as_array().unwrap();
        assert_eq!(events.last().unwrap()["colour_primaries"], 12);
        assert_eq!(events.last().unwrap()["status"], 0);
        assert!(!mirra_core::pyjson::dumps(&value).contains("ordinary unrelated"));
        instance.close().unwrap();
    }

    #[test]
    fn guardian_death_is_a_failure_and_supervisor_restores() {
        let f = fixture();
        let mut instance = controller(&f, "auto", None, false);
        instance.start().unwrap();
        set_guardian_exit(&f, 1);
        assert!(instance.poll().unwrap_err().to_string().contains("guardian ended"));
        let result = instance.close().unwrap();
        assert_eq!(result["original_avc_restored"], true);
        assert_eq!(result["recovered_by_supervisor"], true);
    }

    #[test]
    fn idle_and_reloaded_decoder_keep_registration_and_bridge_session() {
        let f = fixture();
        let mut instance = controller(&f, "auto", None, false);
        instance.start().unwrap();
        let before = calls(&f).len();
        {
            let mut fake = f.fake.lock().unwrap();
            let current = fake.current.as_mut().unwrap();
            current.remove("pid");
            current.insert("state".into(), json!("not running"));
        }
        instance.poll().unwrap();
        assert!(instance.ready);
        assert_eq!(instance.pid, Value::Null);
        assert_eq!(instance.observation, "idle");
        let pid = util::own_pid() as i64 + 100000;
        *f.birth_override.lock().unwrap() = Some((pid as i32, sys::getuid(), 2000, 1));
        {
            let mut fake = f.fake.lock().unwrap();
            let current = fake.current.as_mut().unwrap();
            current.insert("pid".into(), json!(pid));
            current.insert("state".into(), json!("running"));
        }
        instance.poll().unwrap();
        assert!(!instance.ready);
        assert_eq!(instance.observation, "starting");
        {
            use std::io::Write;
            let mut log = std::fs::OpenOptions::new().append(true).open(instance.stage.as_ref().unwrap().join("stderr.log")).unwrap();
            writeln!(log, "MIRRA_DECODER_HOOK_READY pid={} version=1", pid).unwrap();
        }
        instance.poll().unwrap();
        assert!(instance.ready);
        assert_eq!(instance.pid, json!(pid));
        *f.birth_override.lock().unwrap() = None;
        assert!(calls(&f)[before..].iter().all(|c| c[0] == "print"));
        instance.close().unwrap();
    }

    #[test]
    fn observation_failure_defers_without_unloading_support() {
        let f = fixture();
        let mut instance = controller(&f, "auto", None, false);
        instance.start().unwrap();
        let before = calls(&f).len();
        f.fake.lock().unwrap().fail = Some("query");
        instance.poll().unwrap();
        assert!(!instance.ready);
        assert_eq!(instance.observation, "unknown");
        f.fake.lock().unwrap().fail = None;
        instance.poll().unwrap();
        assert!(instance.ready);
        assert!(calls(&f)[before..].iter().all(|c| c[0] == "print"));
        instance.close().unwrap();
    }

    #[test]
    fn reused_decoder_pid_waits_for_fresh_hook_marker() {
        let f = fixture();
        let mut instance = controller(&f, "auto", None, false);
        instance.start().unwrap();
        let old = instance.ready_pids[&(util::own_pid() as i64)];
        *f.birth_override.lock().unwrap() = Some((old.0, old.1, old.2, old.3 + 1));
        instance.poll().unwrap();
        assert!(!instance.ready);
        assert_eq!(instance.observation, "starting");
        *f.birth_override.lock().unwrap() = None;
        instance.poll().unwrap();
        assert!(instance.ready);
        instance.close().unwrap();
    }

    #[test]
    fn foreign_avconference_is_preserved_and_cleanup_failure_is_reported() {
        let f = fixture();
        let mut instance = controller(&f, "auto", None, false);
        instance.start().unwrap();
        f.fake.lock().unwrap().current = Some(route::tests::job_state(json!({"path": "/foreign/job.plist", "program": "/foreign/program"})));
        let before = calls(&f).len();
        assert!(instance.poll().is_err());
        set_guardian_exit(&f, 1);
        let result = instance.close().unwrap();
        assert_eq!(result["cleanup_verified"], false);
        assert_eq!(result["original_avc_restored"], false);
        assert!(calls(&f)[before..].iter().all(|c| c[0] == "print"));
        assert!(instance.lock.is_none());
    }
}
