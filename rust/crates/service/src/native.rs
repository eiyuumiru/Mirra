//! The native support session run by `mirra-cli run-service`
//! (port of `scripts/native.py`).
//!
//! Apple's installed iPhone Mirroring app is used unchanged; a scoped socket
//! helper binds its UDP sockets, the backend supervisor ([`NativeBackend`])
//! keeps the bridge connected, and with `--launch-services` the
//! LaunchServices agent loads the launch adapter so a normal open of the app
//! receives support. With `--service-state` the session runs under
//! [`mirra_native::startup::run_service`]: failed startups pause instead of
//! being retried by launchd, an already-open app is quit once and reopened
//! when the backend is ready. Files (`result.json`, `native-session-active.json`,
//! `service.json`, ...) and stdout events keep the Python layout.
use std::cell::Cell;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use mirra_core::config::{default_root, load_config, Config};
use mirra_core::event::Event;
use mirra_core::lifetime::{deadline_for, duration_from_arguments, emit_event};
use mirra_core::logs::{open_append, BoundedLogs};
use mirra_core::processes::NativeAppObserver;
use mirra_core::retention::{self, KEEP_COMPLETED};
use mirra_core::state::write_state;
use mirra_core::subprocess::{self, RunOptions};
use mirra_core::{pyjson, sys};
use mirra_native::compatibility::{require_media_profile, supported_apple_app};
use mirra_native::decoder::{DecoderRoute, LogWatch};
use mirra_native::launcher::NativeLaunchAgent;
use mirra_native::sockets::BindHelper;
use mirra_native::startup::{self, SessionError, StartupError};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::cli::{self, Token};
use crate::error::Error;
use crate::signals::StopSignals;
use crate::supervisor::{Backend, NativeBackend};
use crate::util::{self, truthy};

pub const SYSTEM_APP: &str = "/System/Applications/iPhone Mirroring.app";
const PROG: &str = "native";
const USAGE: &str = "[-h] [--config CONFIG] [--seconds SECONDS | --until-stopped] [--launch-services] [--recover-backend] [--manage-usb]";
const HELP: &str = "Experimental session using Apple's installed app and a scoped socket helper.

options:
  -h, --help         show this help message and exit
  --config CONFIG
  --seconds SECONDS  Bounded session: 30..1800 seconds
  --until-stopped    Remove the duration limit; recovery policy is selected separately
  --launch-services  Prepare background support; open Apple's existing app normally from Launchpad or Spotlight
  --recover-backend  Keep native launch support running and retry a failed backend (requires --launch-services)
  --manage-usb       Accepted for SSH-era service definitions; USB now reaches the bridge service through usbmux";

/// `native.py` arguments.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NativeArgs {
    pub config: Option<String>,
    pub seconds: Option<i64>,
    pub until_stopped: bool,
    pub launch_services: bool,
    pub recover_backend: bool,
    pub manage_usb: bool,
    pub service_log: Option<String>,
    pub service_state: Option<String>,
}

/// argparse equivalent; `Err(status)` after printing help or a usage error.
pub fn parse_args(args: &[String]) -> Result<NativeArgs, i32> {
    let mut parsed = NativeArgs::default();
    let mut options = cli::Options::new(args);
    let usage = |message: &str| cli::usage_error(PROG, USAGE, message);
    while let Some(token) = options.next() {
        match token {
            Token::Flag(name, None) if name == "--help" => {
                println!("usage: {} {}\n\n{}", PROG, USAGE, HELP);
                return Err(0);
            }
            Token::Flag(name, None) if name == "--until-stopped" => {
                if parsed.seconds.is_some() {
                    return Err(usage("argument --until-stopped: not allowed with argument --seconds"));
                }
                parsed.until_stopped = true;
            }
            Token::Flag(name, None) if name == "--launch-services" => parsed.launch_services = true,
            Token::Flag(name, None) if name == "--recover-backend" => parsed.recover_backend = true,
            Token::Flag(name, None) if name == "--manage-usb" => parsed.manage_usb = true,
            Token::Flag(name, inline) if name == "--seconds" => {
                let value = options.value("--seconds", inline).map_err(|m| usage(&m))?;
                if parsed.until_stopped {
                    return Err(usage("argument --seconds: not allowed with argument --until-stopped"));
                }
                parsed.seconds = Some(value.trim().parse().map_err(|_| usage(&format!(
                    "argument --seconds: invalid int value: {}", mirra_core::pyfmt::repr_str(&value))))?);
            }
            Token::Flag(name, inline) if matches!(name.as_str(), "--config" | "--service-log" | "--service-state") => {
                let value = Some(options.value(&name, inline).map_err(|m| usage(&m))?);
                match name.as_str() {
                    "--config" => parsed.config = value,
                    "--service-log" => parsed.service_log = value,
                    _ => parsed.service_state = value,
                }
            }
            Token::Flag(name, Some(value)) => return Err(usage(&format!("unrecognized arguments: {}={}", name, value))),
            Token::Flag(name, None) | Token::Positional(name) => return Err(usage(&format!("unrecognized arguments: {}", name))),
        }
    }
    Ok(parsed)
}

pub type Emit = Arc<dyn Fn(&Value) + Send + Sync>;
type Hook<T> = Arc<dyn Fn() -> mirra_core::Result<T> + Send + Sync>;
type PathHook<T> = Arc<dyn Fn(&Path) -> mirra_core::Result<T> + Send + Sync>;
/// `wait_for_mirroring_exit(stop, state_path, quit_app)`
pub type WaitForExit = Arc<dyn Fn(&Event, &Path, &mut dyn FnMut() -> mirra_core::Result<()>) -> Result<bool, SessionError> + Send + Sync>;
/// `require_container(path)`
pub type RequireContainer = Arc<dyn Fn(&Path) -> Result<(), SessionError> + Send + Sync>;
/// `NativeBackend(config, directory, recover=).start()`
pub type StartBackend = Arc<dyn Fn(Config, &Path, bool) -> crate::Result<Box<dyn Backend>> + Send + Sync>;

/// The session's system seams (tests substitute fakes).
#[derive(Clone)]
pub struct NativeHooks {
    /// Package root (`configuration.ROOT`): `build/` adapters and `runtime/`.
    pub root: PathBuf,
    /// `Path.home()` (the Mirroring container).
    pub home: PathBuf,
    pub emit: Emit,
    /// `NativeLaunchAgent.recover_abandoned()`
    pub recover_launch: Hook<Option<Value>>,
    pub mirroring_running: Arc<dyn Fn() -> Result<bool, StartupError> + Send + Sync>,
    /// Info.plist is Apple's 1.x app family (`supported_apple_app`).
    pub supported_app: PathHook<bool>,
    /// `codesign --verify --strict APP` (an error when it fails).
    pub codesign: PathHook<()>,
    /// `require_media_profile(root)`
    pub media_profile: PathHook<Value>,
    pub wait_for_exit: WaitForExit,
    /// `quit_mirroring()`
    pub quit_mirroring: Hook<bool>,
    /// `relaunch_mirroring()`
    pub relaunch: Hook<bool>,
    pub require_container: RequireContainer,
    pub start_backend: StartBackend,
    /// sha256 hex digest of a file.
    pub digest: PathHook<String>,
}

fn sha256_file(path: &Path) -> mirra_core::Result<String> {
    let data = std::fs::read(path).map_err(|e| mirra_core::Error::with_path(e, path))?;
    Ok(Sha256::digest(&data).iter().map(|b| format!("{:02x}", b)).collect())
}

impl NativeHooks {
    pub fn system() -> Self {
        NativeHooks {
            root: default_root(),
            home: util::home(),
            emit: Arc::new(|event| {
                let _ = emit_event(event);
            }),
            recover_launch: Arc::new(|| NativeLaunchAgent::recover_abandoned(None)),
            mirroring_running: Arc::new(startup::mirroring_running),
            supported_app: Arc::new(|app| {
                let path = app.join("Contents/Info.plist");
                let data = std::fs::read(&path).map_err(|e| mirra_core::Error::with_path(e, &path))?;
                Ok(supported_apple_app(&mirra_native::plist::loads(&data)?))
            }),
            codesign: Arc::new(|app| {
                let command = ["codesign".to_string(), "--verify".into(), "--strict".into(), util::text(app)];
                subprocess::run(&command, &RunOptions::new().capture().check()).map(|_| ())
            }),
            media_profile: Arc::new(require_media_profile),
            wait_for_exit: Arc::new(|stop, state, quit| startup::wait_for_mirroring_exit(stop, state, Some(quit))),
            quit_mirroring: Arc::new(|| startup::quit_mirroring(6.0, 3.0)),
            relaunch: Arc::new(startup::relaunch_mirroring),
            require_container: Arc::new(startup::require_container),
            start_backend: Arc::new(|config, directory, recover| {
                Ok(Box::new(NativeBackend::new(config, directory, recover).start()?))
            }),
            digest: Arc::new(sha256_file),
        }
    }
}

impl Default for NativeHooks {
    fn default() -> Self {
        Self::system()
    }
}

/// `parser.error(message)`: usage on stderr, `SystemExit(2)`.
fn usage_error(message: &str) -> SessionError {
    cli::usage_error(PROG, USAGE, message);
    SessionError::Exit(2)
}

fn core_error(error: Error) -> mirra_core::Error {
    match error {
        Error::Core(error) => error,
        other => mirra_core::Error::runtime(other.to_string()),
    }
}

fn elapsed(started: Instant) -> f64 {
    (started.elapsed().as_secs_f64() * 100.0).round() / 100.0
}

/// `tempfile.mkdtemp(prefix=, dir=)` (mode 0700).
fn mkdtemp(directory: &Path, prefix: &str) -> std::io::Result<PathBuf> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let mut template = directory.join(format!("{}XXXXXXXX", prefix)).as_os_str().as_bytes().to_vec();
    template.push(0);
    if unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) }.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    template.pop();
    Ok(PathBuf::from(std::ffi::OsString::from_vec(template)))
}

/// Sets `to` once `from` is set, until dropped (the session's signal
/// handler sets both the requested stop and the session stop).
struct Forward {
    done: Event,
    thread: Option<JoinHandle<()>>,
}

impl Forward {
    fn new(from: &Event, to: &Event) -> Self {
        let (from, to, done) = (from.clone(), to.clone(), Event::new());
        let finished = done.clone();
        let thread = std::thread::Builder::new().name("native-stop".into()).spawn(move || {
            while !finished.is_set() {
                if from.wait(Some(Duration::from_millis(100))) {
                    to.set();
                    return;
                }
            }
        }).ok();
        Forward { done, thread }
    }
}

impl Drop for Forward {
    fn drop(&mut self) {
        self.done.set();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Reopen the app the session quit at startup, once the backend is ready:
/// the copy restored at login predates the launch hooks.
pub fn reopen_when_ready(reopen: &mut bool, ready: bool, launch_services: bool, relaunch: &dyn Fn() -> mirra_core::Result<bool>,
    record: &mut Map<String, Value>, emit: &dyn Fn(&Value)) {
    if !(*reopen && ready && launch_services) {
        return;
    }
    *reopen = false;
    let reopened = relaunch().unwrap_or(false);
    record.insert("mirroring_relaunched".into(), json!(reopened));
    emit(&json!({"NATIVE_MIRRORING_RELAUNCHED": reopened}));
}

/// Serve bind requests from the app until `stop`.
fn serve_bindings(listener: Arc<UnixListener>, helper: Arc<Mutex<BindHelper>>, stop: Event, emit: Emit) -> JoinHandle<()> {
    std::thread::spawn(move || {
        while !stop.is_set() {
            let mut poll = libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            let ready = unsafe { libc::poll(&mut poll, 1, 200) };
            if ready == 0 {
                continue;
            }
            if ready < 0 {
                if sys::errno() == libc::EINTR {
                    continue;
                }
                return;
            }
            let connection = match listener.accept() {
                Ok((connection, _)) => connection,
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => continue,
                Err(_) => return,
            };
            if connection.set_nonblocking(false).is_err() {
                continue;
            }
            let mut helper = helper.lock().unwrap();
            if let Ok(error) = helper.handle(&connection) {
                let mut event = json!({"UDP_BIND": error, "bound_count": helper.bound_count});
                if error != 0 {
                    event["reason"] = json!(helper.last_failure);
                }
                emit(&event);
            }
        }
    })
}

/// The state shared between the session body and its cleanup.
struct Session<'a> {
    args: &'a NativeArgs,
    hooks: &'a NativeHooks,
    config: Config,
    staged: Config,
    run_directory: PathBuf,
    executable: PathBuf,
    staged_adapters: Vec<PathBuf>,
    address: PathBuf,
    actual: PathBuf,
    stop: Event,
    record: Map<String, Value>,
    reopen_app: bool,
    duration: Option<u64>,
    helper: Arc<Mutex<BindHelper>>,
    app_observer: NativeAppObserver,
    log_limits: Arc<Mutex<BoundedLogs>>,
    listener: Option<Arc<UnixListener>>,
    bindings: Option<JoinHandle<()>>,
    backend: Option<Box<dyn Backend>>,
    app: Option<Child>,
    launch_agent: Option<NativeLaunchAgent>,
    decoder: Option<DecoderRoute>,
}

impl Session<'_> {
    fn emit(&self, event: Value) {
        (self.hooks.emit)(&event);
    }

    fn service_state(&self, phase: &str, extra: Option<Value>) -> crate::Result<()> {
        if let Some(path) = &self.args.service_state {
            let mut state = json!({"phase": phase, "directory": util::text(&self.run_directory),
                "supervisor_birth": self.record["supervisor_birth"]});
            if let Some(Value::Object(extra)) = extra {
                state.as_object_mut().unwrap().extend(extra);
            }
            write_state(Path::new(path), &state)?;
        }
        Ok(())
    }

    fn body(&mut self) -> crate::Result<()> {
        if let Some(log) = &self.args.service_log {
            for fd in [1, 2] {
                self.log_limits.lock().unwrap().watch_native(Path::new(log), std::process::id() as i32, fd)?;
            }
        }
        let listener = UnixListener::bind(&self.address).map_err(|e| mirra_core::Error::with_path(e, &self.address))?;
        listener.set_nonblocking(true).map_err(|e| mirra_core::Error::with_path(e, &self.address))?;
        let listener = Arc::new(listener);
        self.listener = Some(listener.clone());
        util::chmod(&self.actual, 0o600)?;
        self.bindings = Some(serve_bindings(listener, self.helper.clone(), self.stop.clone(), self.hooks.emit.clone()));
        let app_log_path = self.run_directory.join("app.log");
        let app_log = open_append(&app_log_path).map_err(|e| mirra_core::Error::with_path(e, &app_log_path))?;
        self.log_limits.lock().unwrap().watch_stream(&app_log_path, &app_log)?;
        self.backend = Some((self.hooks.start_backend)(self.staged.clone(), &self.run_directory, self.args.recover_backend)?);
        if !self.args.recover_backend {
            let deadline = Instant::now() + Duration::from_secs(30 + 3 * self.config.timeout);
            let mut ready = false;
            while !self.stop.is_set() && Instant::now() < deadline {
                let state = self.backend.as_ref().unwrap().snapshot();
                if truthy(state.get("ready")) {
                    ready = true;
                    break;
                }
                if matches!(state.get("phase").and_then(Value::as_str), Some("failed" | "stopped")) {
                    return Err(Error::runtime("Backend ended before readiness; inspect backend-status.json and its attempt log"));
                }
                self.stop.wait(Some(Duration::from_millis(200)));
            }
            if !ready {
                return Err(Error::runtime("Backend readiness interrupted or timed out"));
            }
        }
        let limits = self.log_limits.clone();
        let watch: LogWatch = Arc::new(move |path, pid, fd| limits.lock().unwrap().watch_native(path, pid, fd));
        let mut decoder = DecoderRoute::new(&self.hooks.root, &self.run_directory, &self.config.decoder_route,
            Some(self.stop.clone()), None, Some(watch))?;
        self.record.insert("decoder_route".into(), Value::Object(decoder.decision.clone()));
        let started = decoder.start();
        self.decoder = Some(decoder);
        let route = started.map_err(mirra_core::Error::from)?;
        self.record.insert("decoder_route".into(), route.clone());
        self.emit(json!({"NATIVE_DECODER_READY": true, "mode": route["mode"], "host": route["host"]}));
        let mut environment = Map::new();
        environment.insert("DYLD_INSERT_LIBRARIES".into(), json!(self.staged_adapters[..2].iter()
            .map(|p| util::text(p)).collect::<Vec<_>>().join(":")));
        environment.insert("MIRRA_BIND_SOCKET".into(), json!(util::text(&self.address)));
        if self.args.launch_services {
            self.record.insert("launch_agent_attempted".into(), json!(true));
            let agent = self.launch_agent.insert(NativeLaunchAgent::new(&self.run_directory, environment, Some(self.stop.clone()), None));
            let state = agent.start()?;
            self.record.insert("launch_agent".into(), Value::Object(state.clone()));
            let pid: i32 = util::py_str(state.get("pid").unwrap_or(&Value::Null)).trim().parse()
                .map_err(|_| Error::value("Invalid CoreServicesUIAgent process"))?;
            for (fd, name) in [(1, "native-launch-agent.stdout.log"), (2, "native-launch-agent.stderr.log")] {
                self.log_limits.lock().unwrap().watch_native(&self.run_directory.join(name), pid, fd)?;
            }
            self.record.insert("observed_app_pids".into(), json!([]));
            self.emit(json!({"NATIVE_LAUNCH_SERVICES_READY": true, "run": self.record["run"],
                "backend_ready": self.backend.as_ref().unwrap().snapshot().get("ready").cloned().unwrap_or(Value::Null),
                "action": "Open the original iPhone Mirroring app normally; connection requires backend ready"}));
        } else {
            let mut command = Command::new(&self.executable);
            for (key, value) in &environment {
                command.env(key, value.as_str().unwrap_or(""));
            }
            let app = command.stdout(Stdio::from(app_log.try_clone()?)).stderr(Stdio::from(app_log.try_clone()?))
                .spawn().map_err(|e| mirra_core::Error::with_path(e, &self.executable))?;
            let pid = app.id() as i32;
            self.helper.lock().unwrap().expected_pid = Some(pid);
            self.record.insert("app_pid".into(), json!(pid));
            self.app = Some(app);
            self.emit(json!({"NATIVE_APP_STARTED": pid, "run": self.record["run"]}));
        }
        drop(app_log);
        write_state(&self.run_directory.join("native-session-active.json"), &Value::Object(self.record.clone()))?;
        let decoder = self.record["decoder_route"].clone();
        self.service_state("running", Some(json!({"decoder_route": {"enabled": decoder["enabled"], "ready": decoder["ready"]}})))?;
        let deadline = deadline_for(self.duration);
        while !self.stop.wait(Some(Duration::from_millis(500))) && !deadline.expired() {
            self.decoder.as_mut().unwrap().poll()?;
            if let Some(app) = self.app.as_mut() {
                if let Ok(Some(status)) = app.try_wait() {
                    self.record.insert("app_exit_code".into(), json!(subprocess::return_code(status)));
                    break;
                }
            }
            if self.args.launch_services {
                let found = self.app_observer.poll();
                if !self.app_observer.last_errors.is_empty() {
                    self.emit(json!({"APP_OBSERVATION_DEFERRED": true, "errors": self.app_observer.last_errors}));
                }
                for pid in found {
                    let observed = self.record.get_mut("observed_app_pids").and_then(Value::as_array_mut).unwrap();
                    if !observed.contains(&json!(pid)) {
                        observed.push(json!(pid));
                        self.emit(json!({"NATIVE_NORMAL_LAUNCH_OBSERVED": pid}));
                    }
                }
            }
            let state = self.backend.as_ref().unwrap().snapshot();
            let relaunch = self.hooks.relaunch.clone();
            let emit = self.hooks.emit.clone();
            reopen_when_ready(&mut self.reopen_app, truthy(state.get("ready")), self.args.launch_services,
                &*relaunch, &mut self.record, &*emit);
            if matches!(state.get("phase").and_then(Value::as_str), Some("failed" | "stopped")) {
                self.record.insert("backend_ended_before_stop".into(), json!(true));
                break;
            }
        }
        Ok(())
    }

    /// `stop_process(app, 8)`: only the app may be killed by this launcher.
    fn stop_app(&mut self) {
        let Some(app) = self.app.as_mut() else { return };
        if !matches!(app.try_wait(), Ok(None)) {
            return;
        }
        unsafe { libc::kill(app.id() as i32, libc::SIGTERM) };
        let wait = |app: &mut Child, seconds: u64| {
            let deadline = Instant::now() + Duration::from_secs(seconds);
            while Instant::now() < deadline {
                if !matches!(app.try_wait(), Ok(None)) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            false
        };
        if !wait(app, 8) {
            let _ = app.kill();
            wait(app, 3);
        }
    }

    /// The `finally:` of `run_session`; returns a late filesystem error.
    fn cleanup(&mut self, private: &Path, short: &Path, link: &Path) -> Option<mirra_core::Error> {
        let mut late = None;
        self.stop.set();
        if let Some(agent) = self.launch_agent.as_mut() {
            match agent.close() {
                Ok(restored) => {
                    self.record.insert("launch_agent_restored".into(), restored.map_or(Value::Null, Value::Object));
                }
                Err(error) => {
                    self.record.insert("launch_agent_restore_error".into(), json!(error.to_string()));
                }
            }
            if let Err(error) = self.app_observer.terminate_owned(Duration::from_secs(8)) {
                self.record.insert("app_cleanup_error".into(), json!(error.to_string()));
            }
        }
        self.stop_app();
        if let Some(decoder) = self.decoder.as_mut() {
            match decoder.close() {
                Ok(cleanup) => {
                    self.record.insert("decoder_cleanup".into(), cleanup);
                }
                Err(error) => {
                    self.record.insert("decoder_restore_error".into(), json!(error.to_string()));
                }
            }
        }
        if let Some(backend) = self.backend.as_mut() {
            let cleanup = backend.close();
            self.record.insert("backend_cleanup".into(), Value::Object(cleanup));
        }
        let limits = self.log_limits.lock().unwrap().close();
        self.record.insert("log_limits".into(), limits);
        if let Some(bindings) = self.bindings.take() {
            let _ = bindings.join();
        }
        self.listener = None;
        let mut remove = |result: std::io::Result<()>, path: &Path| {
            if let Err(error) = result {
                late.get_or_insert(mirra_core::Error::with_path(error, path));
            }
        };
        match std::fs::remove_file(&self.actual) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            result => remove(result, &self.actual),
        }
        remove(std::fs::remove_file(link), link);
        remove(std::fs::remove_dir(private), private);
        remove(std::fs::remove_dir(short), short);
        if late.is_none() && !truthy(self.record.get("app_cleanup_error")) {
            if let Some(agent) = self.launch_agent.as_mut() {
                if let Err(error) = agent.release_ownership() {
                    late = Some(error);
                }
            }
        }
        let helper = self.helper.lock().unwrap();
        let before = self.record["executable_sha256_before"].clone();
        let unchanged = (self.hooks.digest)(&self.executable).ok().map(Value::from) == Some(before);
        self.record.insert("helper_bind_count".into(), json!(helper.bound_count));
        self.record.insert("helper_last_failure".into(), json!(helper.last_failure));
        drop(helper);
        self.record.insert("app_observation_error_count".into(), json!(self.app_observer.error_count));
        self.record.insert("executable_unchanged".into(), json!(unchanged));
        self.record.insert("signature_verified_after".into(), json!((self.hooks.codesign)(&self.config.system_app).is_ok()));
        let exit_code = util::object(&self.record, "backend_cleanup").get("exit_code").cloned().unwrap_or(Value::Null);
        self.record.insert("backend_exit_code".into(), exit_code);
        let app_exit = self.app.as_mut().and_then(|app| app.try_wait().ok().flatten()).map(subprocess::return_code);
        self.record.insert("app_exit_code".into(), app_exit.map_or(Value::Null, Value::from));
        let result = self.run_directory.join("result.json");
        if let Err(error) = std::fs::write(&result, format!("{}\n", pyjson::dumps_pretty(&Value::Object(self.record.clone())))) {
            late.get_or_insert(mirra_core::Error::with_path(error, &result));
        }
        if let Err(error) = self.service_state("stopped", None) {
            late.get_or_insert(core_error(error));
        }
        if self.cleanup_verified() {
            if let Err(error) = retention::retire(&self.run_directory) {
                late.get_or_insert(error);
            }
        }
        self.emit(json!({"NATIVE_SESSION_ENDED": true, "run": self.record["run"],
            "executable_unchanged": self.record["executable_unchanged"], "backend_exit_code": self.record["backend_exit_code"]}));
        late
    }

    fn decoder_verified(&self) -> bool {
        self.decoder.is_none() || truthy(util::object(&self.record, "decoder_cleanup").get("cleanup_verified"))
    }

    fn cleanup_verified(&self) -> bool {
        let cleanup = util::object(&self.record, "backend_cleanup");
        truthy(cleanup.get("cleanup_verified")) && !truthy(cleanup.get("cleanup_error"))
            && !truthy(self.record.get("launch_agent_restore_error")) && !truthy(self.record.get("app_cleanup_error"))
            && !truthy(self.record.get("decoder_restore_error")) && self.decoder_verified()
    }

    fn status(&self, failure: bool) -> i32 {
        let failed = failure || truthy(self.record.get("backend_ended_before_stop")) || !self.cleanup_verified()
            || truthy(util::object(&self.record, "log_limits").get("error"));
        i32::from(failed)
    }
}

/// One native session (`run_session`); `requested_stop` is the explicit
/// stop (signals, or the service's stop request).
pub fn run_session(args: &NativeArgs, requested_stop: &Event, hooks: &NativeHooks) -> Result<i32, SessionError> {
    // Cleanup also sets the worker stop event. It must not be mistaken for an
    // explicit user shutdown by the service's failed-startup guard.
    let stop = Event::new();
    if args.recover_backend && !args.launch_services {
        return Err(usage_error("--recover-backend requires --launch-services"));
    }
    let config = load_config(args.config.as_deref().map(Path::new), &hooks.root).map_err(mirra_core::Error::from)?;
    let duration = duration_from_arguments(args.seconds, args.until_stopped, config.seconds as i64).map_err(|m| usage_error(&m))?;
    if config.system_app != Path::new(SYSTEM_APP) {
        return Err(usage_error("The native path currently targets the installed system app"));
    }
    let managed_startup = args.launch_services && args.service_state.is_some();
    let started = Instant::now();
    let reopen_app = Cell::new(false);
    if args.launch_services {
        match (hooks.recover_launch)() {
            Ok(recovered) => {
                if let Some(recovered) = recovered.filter(|v| truthy(Some(v))) {
                    (hooks.emit)(&json!({"ABANDONED_NATIVE_SESSION_RECOVERED": recovered}));
                }
            }
            Err(error) => return Err(usage_error(&error.to_string())),
        }
        if managed_startup {
            (hooks.emit)(&json!({"NATIVE_STARTUP_STAGE": "recovered_launch_agent", "elapsed_seconds": elapsed(started)}));
        }
    }
    if !managed_startup && (hooks.mirroring_running)()? {
        return Err(usage_error("Close the existing Mirroring app before starting a native session"));
    }
    if !(hooks.supported_app)(&config.system_app)? {
        return Err(usage_error("This adapter requires Apple\u{2019}s original iPhone Mirroring 1.x system app"));
    }
    let executable = config.system_app.join("Contents/MacOS/iPhone Mirroring");
    (hooks.codesign)(&config.system_app)?;
    let build = hooks.root.join("build");
    let adapters: Vec<PathBuf> = ["sockets.dylib", "media.dylib", "keystore.dylib"].iter().map(|n| build.join(n)).collect();
    if !adapters.iter().all(|p| p.is_file()) {
        return Err(usage_error("Build the host and native bind adapters first: make build build/sockets.dylib"));
    }
    if args.launch_services && !build.join("launch.dylib").is_file() {
        return Err(usage_error("Build the native LaunchServices adapter first: make build/launch.dylib"));
    }
    let media_profile = (hooks.media_profile)(&hooks.root).map_err(|e| usage_error(&e.to_string()))?;
    // Finish read-only checks while macOS is restoring apps. Only the native
    // session changes wait for an existing system Mirroring app to quit.
    if let (true, Some(state)) = (managed_startup, args.service_state.as_deref()) {
        (hooks.emit)(&json!({"NATIVE_STARTUP_STAGE": "verified_host", "elapsed_seconds": elapsed(started)}));
        // The open copy predates the launch hooks: quit it now and reopen it
        // once the bridge is ready, instead of waiting for the user.
        let mut quit_existing_app = || -> mirra_core::Result<()> {
            if (hooks.quit_mirroring)()? {
                reopen_app.set(true);
                (hooks.emit)(&json!({"NATIVE_MIRRORING_QUIT": true, "relaunch_after_ready": true}));
            }
            Ok(())
        };
        if !(hooks.wait_for_exit)(requested_stop, Path::new(state), &mut quit_existing_app)? {
            return Ok(0);
        }
    }
    let container = hooks.home.join("Library/Containers/com.apple.ScreenContinuity/Data/tmp");
    (hooks.require_container)(&container)?;
    if requested_stop.is_set() {
        return Ok(0);
    }
    unsafe { libc::umask(0o077) };
    let runtime = hooks.root.join("runtime");
    let run_directory = runtime.join(format!("native-{}", chrono::Local::now().format("%Y%m%d-%H%M%S")));
    std::fs::create_dir_all(&runtime).map_err(|e| mirra_core::Error::with_path(e, &runtime))?;
    std::fs::create_dir(&run_directory).map_err(|e| mirra_core::Error::with_path(e, &run_directory))?;
    retention::track(&run_directory, "native")?;
    let retained = retention::prune(&runtime, "native", std::slice::from_ref(&run_directory), KEEP_COMPLETED)?;
    if truthy(retained.get("removed")) || truthy(retained.get("deferred")) {
        (hooks.emit)(&json!({"NATIVE_RETENTION": retained}));
    }
    let mut staged = config.clone();
    staged.runtime_directory = run_directory.clone();
    if let Some(seconds) = duration {
        staged.seconds = seconds;
    }
    let settings = run_directory.join("config.json");
    std::fs::write(&settings, format!("{}\n", pyjson::dumps_pretty(&staged.as_dict())))
        .map_err(|e| mirra_core::Error::with_path(e, &settings))?;
    write_state(&run_directory.join("media-compatibility.json"), &media_profile)?;
    let mut staged_adapters = Vec::new();
    for adapter in &adapters {
        let target = run_directory.join(adapter.file_name().unwrap());
        util::copy2(adapter, &target).map_err(core_error)?;
        util::chmod(&target, 0o600).map_err(core_error)?;
        staged_adapters.push(target);
    }
    let private = match mkdtemp(&container, "mb-") {
        Ok(private) => private,
        Err(e) if matches!(e.raw_os_error(), Some(libc::EACCES | libc::EPERM)) => {
            return Err(StartupError::new("container_access_denied", "macOS denied creation of the Mirroring socket directory").into());
        }
        Err(e) => return Err(mirra_core::Error::with_path(e, &container).into()),
    };
    util::chmod(&private, 0o700).map_err(core_error)?;
    let short = mkdtemp(Path::new("/tmp"), "mb-").map_err(|e| mirra_core::Error::with_path(e, "/tmp"))?;
    util::chmod(&short, 0o700).map_err(core_error)?;
    let link = short.join("c");
    std::os::unix::fs::symlink(&private, &link).map_err(|e| mirra_core::Error::with_path(e, &link))?;
    let helper = Arc::new(Mutex::new(BindHelper::new(&executable, true, None)));
    let app_observer = NativeAppObserver::new(util::text(&executable), util::text(&staged_adapters[0]));
    let limit_stop = stop.clone();
    let log_limits = Arc::new(Mutex::new(BoundedLogs::new(2 * 1024 * 1024, Some(Box::new(move || limit_stop.set())))?));
    let before = (hooks.digest)(&executable)?;
    let birth = mirra_core::processes::process_birth(std::process::id() as i32)?;
    let mut adapter_digests = Map::new();
    for adapter in &staged_adapters {
        adapter_digests.insert(adapter.file_name().unwrap().to_string_lossy().into_owned(), json!((hooks.digest)(adapter)?));
    }
    let record = json!({
        "run": run_directory.file_name().unwrap().to_string_lossy(), "supervisor_pid": std::process::id(),
        "system_app": util::text(&config.system_app), "executable_sha256_before": before,
        "supervisor_birth": birth.as_ref().map_or(Value::Null, retention::birth_json),
        "duration_seconds": duration, "native_mirroring_verified": null, "daily_use_verified": false,
        "automatic_backend_recovery": args.recover_backend, "launch_agent_attempted": false,
        "media_profile": media_profile.get("profile").cloned().unwrap_or(Value::Null),
        "launch_method": if args.launch_services { "ordinary LaunchServices with background support" } else { "custom launch command" },
        "validation_scope": "Lifecycle only; video and input require a separate observation",
        "adapter_sha256": adapter_digests});
    let mut session = Session {
        args, hooks, staged, run_directory, staged_adapters,
        address: link.join("s"), actual: private.join("s"), executable, stop: stop.clone(),
        record: record.as_object().unwrap().clone(), reopen_app: reopen_app.get(), duration,
        helper, app_observer, log_limits, listener: None, bindings: None, backend: None, app: None,
        launch_agent: None, decoder: None, config,
    };
    // The session's signal handler stops the session as well as the service.
    let _forward = Forward::new(requested_stop, &stop);
    let mut failure = false;
    let prepared = session.service_state("preparing", None);
    let outcome = prepared.and_then(|_| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| session.body())) {
            Ok(result) => result,
            Err(_) => Err(Error::runtime("Native session panicked")),
        }
    });
    if let Err(error) = outcome {
        failure = true;
        let message = error.to_string();
        session.record.insert("error".into(), json!(message));
        session.emit(json!({"NATIVE_SESSION_ERROR": message}));
    }
    if let Some(error) = session.cleanup(&private, &short, &link) {
        return Err(error.into());
    }
    Ok(session.status(failure))
}

/// `mirra-cli run-service` (and `native.py`-compatible arguments): returns
/// the exit status. With `--service-state` this process is the login
/// service itself and only returns after an explicit stop.
pub fn native_main(args: Vec<String>) -> i32 {
    let args = match parse_args(&args) {
        Ok(args) => args,
        Err(code) => return code,
    };
    run_native(&args, &NativeHooks::system())
}

pub fn run_native(args: &NativeArgs, hooks: &NativeHooks) -> i32 {
    if let Some(state) = &args.service_state {
        return match startup::run_service(|stop| run_session(args, stop, hooks), Path::new(state), None) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("{}: {}", error.type_name(), error);
                1
            }
        };
    }
    let requested = Event::new();
    let flag = requested.clone();
    let _signals = StopSignals::install_with(move || flag.set());
    match run_session(args, &requested, hooks) {
        Ok(code) => code,
        Err(SessionError::Exit(code)) => code,
        Err(error) => {
            eprintln!("{}: {}", error.type_name(), error);
            1
        }
    }
}

#[cfg(test)]
mod tests;
