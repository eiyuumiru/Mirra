//! Run the accepted XS-backed profile and restore sharingd when the session
//! ends (port of `scripts/backend.py`).
//!
//! The supervisor starts this as `mirra-cli __backend --config PATH
//! --until-stopped --parent-lifeline` with stdin/stdout pipes; argv is the
//! same as `backend.py`'s argparse interface. Its own children, formerly
//! `broker.py` and `sharing.py`, are the hidden subcommands
//! `__broker` / `__sharing` of the same executable, built only through
//! [`crate::cli::child_command`] (replaceable via [`BackendContext::child`]).
//! Their arguments are unchanged. Events are one `json.dumps` line each on
//! stdout; the private files (`session-active.json`, `session-result-RUN.json`,
//! `backend-children.json`, logs) keep their Python names and formats.
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mirra_bridge::certificates::{current_certificate, CurrentCertificate};
use mirra_core::config::{default_root, load_config, Config};
use mirra_core::event::Event;
use mirra_core::health::{wait_for_backend_loss_with, ProcessPoll};
use mirra_core::launchctl::{self, Reply};
use mirra_core::lifetime::{duration_from_arguments, emit_event, watch_parent_pipe};
use mirra_core::logs::{open_append, BoundedLogs};
use mirra_core::state::{named_temporary, write_state};
use mirra_core::subprocess::{self, RunOptions};
use mirra_core::workspace::{self, BrokerWorkspace};
use mirra_core::{pyjson, sys};
use serde_json::{json, Map, Value};

use crate::cli::{self, Token, BROKER_SUBCOMMAND};
use crate::error::{Error, Result};
use crate::readiness::Health;
use crate::signals::StopSignals;
use crate::util;

/// `provisioning.exclusive_write`: publish complete bytes without replacing
/// an existing file, even if the process exits during writing.
pub fn exclusive_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(parent)
            .map_err(|e| mirra_core::Error::with_path(e, parent))?;
    }
    let (file, temporary) = named_temporary(parent, ".write")?;
    let result = sys::write_all(file.as_raw_fd(), data).and_then(|_| sys::fsync(file.as_raw_fd()))
        .and_then(|_| std::fs::hard_link(&temporary, path));
    drop(file);
    let _ = std::fs::remove_file(&temporary);
    result.map_err(|e| mirra_core::Error::with_path(e, path).into())
}

pub type CertificateSource = Arc<dyn Fn(&Config, &Path, &mut dyn FnMut()) -> std::result::Result<CurrentCertificate, mirra_bridge::Error> + Send + Sync>;

/// Everything `backend_main` touches outside its runtime directory.
#[derive(Clone)]
pub struct BackendContext {
    /// Package root (`<root>/runtime/certificate-renewal.json`, default profile).
    pub root: PathBuf,
    /// `Path.home()`: the shared session lock under `Library/Caches/Mirra`.
    pub home: PathBuf,
    /// Child command for `broker` / `sharing` (default [`cli::child_command`]).
    pub child: Arc<dyn Fn(&str) -> Command + Send + Sync>,
    /// Command-line fragments identifying a live broker (`ps -o command=`).
    pub broker_markers: Vec<String>,
    /// One stdout event (`print(json.dumps(event), flush=True)`).
    pub emit: Arc<dyn Fn(&Value) + Send + Sync>,
    pub certificate: CertificateSource,
    pub health: Health,
    /// `launchctl print gui/<uid>/com.apple.sharingd`
    pub sharingd_print: Arc<dyn Fn() -> mirra_core::Result<Reply> + Send + Sync>,
    pub loss_interval: Duration,
}

impl Default for BackendContext {
    fn default() -> Self {
        let root = default_root();
        let executable = cli::current_exe();
        BackendContext {
            broker_markers: vec![util::text(&root.join("scripts/broker.py")), format!("{} {}", executable.display(), BROKER_SUBCOMMAND)],
            root,
            home: util::home(),
            child: Arc::new(cli::child_command),
            emit: Arc::new(|event| { let _ = emit_event(event); }),
            #[allow(clippy::result_large_err)]
            certificate: Arc::new(|config, state, on_renewal| current_certificate(config, state, on_renewal, false)),
            health: Arc::new(mirra_core::health::health),
            sharingd_print: Arc::new(|| {
                let target = format!("{}/com.apple.sharingd", launchctl::gui_domain());
                launchctl::run(&["print", target.as_str()], Duration::from_secs(15))
            }),
            loss_interval: Duration::from_secs(5),
        }
    }
}

/// A child shared between the main loop, the signal handler and the monitor.
pub struct SharedChild {
    child: Mutex<Child>,
    pub pid: i32,
}

impl SharedChild {
    pub(crate) fn new(child: Child) -> Arc<Self> {
        let pid = child.id() as i32;
        Arc::new(SharedChild { child: Mutex::new(child), pid })
    }
    /// `Popen.poll()`
    pub fn poll(&self) -> Option<i32> {
        match self.child.lock().unwrap().try_wait() {
            Ok(Some(status)) => Some(subprocess::return_code(status)),
            _ => None,
        }
    }
    /// `Popen.terminate()` while not yet reaped (never signals a reused pid).
    pub fn terminate(&self) {
        let mut child = self.child.lock().unwrap();
        if let Ok(None) = child.try_wait() {
            unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
        }
    }
    /// `Popen.wait(timeout)`: `None` on expiry.
    pub fn wait(&self, timeout: Duration) -> Option<i32> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(code) = self.poll() {
                return Some(code);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

struct Poller(Arc<SharedChild>);

impl ProcessPoll for Poller {
    fn poll(&mut self) -> Option<i32> {
        self.0.poll()
    }
}

struct Session {
    stopping: AtomicBool,
    controller: Mutex<Option<Arc<SharedChild>>>,
    record: Mutex<Map<String, Value>>,
}

impl Session {
    fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        if let Some(controller) = self.controller.lock().unwrap().as_ref() {
            controller.terminate();
        }
    }
    fn set(&self, key: &str, value: Value) {
        self.record.lock().unwrap().insert(key.into(), value);
    }
    fn get(&self, key: &str) -> Option<Value> {
        self.record.lock().unwrap().get(key).cloned()
    }
}

/// Parsed `backend.py` arguments.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BackendArgs {
    pub seconds: Option<i64>,
    pub until_stopped: bool,
    pub config: Option<String>,
    pub parent_lifeline: bool,
}

const USAGE: &str = "[-h] [--seconds SECONDS | --until-stopped] [--config CONFIG]";

pub fn parse_args(args: &[String]) -> std::result::Result<BackendArgs, i32> {
    let mut parsed = BackendArgs::default();
    let mut options = cli::Options::new(args);
    while let Some(token) = options.next() {
        match token {
            Token::Flag(name, None) if name == "--help" => {
                println!("usage: backend {}\n\nRun the accepted XS-backed profile and restore sharingd when the session ends.", USAGE);
                return Err(0);
            }
            Token::Flag(name, None) if name == "--until-stopped" => {
                if parsed.seconds.is_some() {
                    return Err(cli::usage_error("backend", USAGE, "argument --until-stopped: not allowed with argument --seconds"));
                }
                parsed.until_stopped = true;
            }
            Token::Flag(name, None) if name == "--parent-lifeline" => parsed.parent_lifeline = true,
            Token::Flag(name, inline) if name == "--seconds" => {
                let value = options.value("--seconds", inline).map_err(|m| cli::usage_error("backend", USAGE, &m))?;
                if parsed.until_stopped {
                    return Err(cli::usage_error("backend", USAGE, "argument --seconds: not allowed with argument --until-stopped"));
                }
                parsed.seconds = Some(value.trim().parse().map_err(|_| cli::usage_error("backend", USAGE,
                    &format!("argument --seconds: invalid int value: {}", mirra_core::pyfmt::repr_str(&value))))?);
            }
            Token::Flag(name, inline) if name == "--config" => {
                parsed.config = Some(options.value("--config", inline).map_err(|m| cli::usage_error("backend", USAGE, &m))?);
            }
            Token::Flag(name, _) | Token::Positional(name) => {
                return Err(cli::usage_error("backend", USAGE, &format!("unrecognized arguments: {}", name)));
            }
        }
    }
    Ok(parsed)
}

/// `mirra-cli __backend [--seconds N | --until-stopped] [--config PATH] [--parent-lifeline]`
pub fn backend_main(args: Vec<String>) -> i32 {
    run_backend(&args, &BackendContext::default())
}

/// [`backend_main`] with an explicit context. Returns the exit status.
pub fn run_backend(args: &[String], context: &BackendContext) -> i32 {
    unsafe { libc::umask(0o077) };
    let args = match parse_args(args) {
        Ok(args) => args,
        Err(code) => return code,
    };
    match backend(&args, context) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{}", message);
            1
        }
    }
}

fn config_args(configuration: &Config) -> Vec<String> {
    if configuration.source.is_file() { vec!["--config".into(), util::text(&configuration.source)] } else { Vec::new() }
}

/// Clear FD_CLOEXEC on the lease in the child (`pass_fds=(lease,)`).
fn pass_lease(command: &mut Command, lease: Option<RawFd>) {
    if let Some(lease) = lease {
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(lease, libc::F_GETFD);
                libc::fcntl(lease, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                Ok(())
            });
        }
    }
}

fn backend(args: &BackendArgs, context: &BackendContext) -> std::result::Result<i32, String> {
    let configuration = load_config(args.config.as_deref().map(Path::new), &context.root).map_err(|e| e.to_string())?;
    let duration = match duration_from_arguments(args.seconds, args.until_stopped, configuration.seconds as i64) {
        Ok(duration) => duration,
        Err(message) => return Ok(cli::usage_error("backend", USAGE, &message)),
    };
    let directory = configuration.runtime_directory.clone();
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&directory).map_err(|e| e.to_string())?;
    }
    let config_args = config_args(&configuration);
    // The lock is shared across configured output directories: every session owns
    // the same per-user sharingd job. A stale PID file cannot provide that guarantee.
    let lock_directory = context.home.join("Library/Caches/Mirra");
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&lock_directory).map_err(|e| e.to_string())?;
    }
    let session_lock = std::fs::OpenOptions::new().append(true).create(true).open(lock_directory.join("session.lock"))
        .map_err(|e| e.to_string())?;
    if sys::flock(session_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB).is_err() {
        return Err("Another Mirroring session controller is running".into());
    }
    let state = directory.join("broker-state.json");
    if state.exists() {
        let old = util::read_json(&state).map_err(|e| e.to_string())?;
        let pid = match old.get("pid") { Some(v) => util::py_str(v), None => "0".into() };
        let existing = subprocess::run(&["ps", "-p", pid.as_str(), "-o", "command="], &RunOptions::new().capture().timeout(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        let text = existing.stdout_text();
        if context.broker_markers.iter().any(|marker| text.contains(marker.as_str())) {
            return Err("An existing broker is still live; preserve it".into());
        }
    }
    let run = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let mut broker_workspace = BrokerWorkspace::new(&directory).map_err(|e| e.to_string())?;
    let private = broker_workspace.path.clone();
    let session = Arc::new(Session { stopping: AtomicBool::new(false), controller: Mutex::new(None), record: Mutex::new(Map::new()) });
    let handler = session.clone();
    let _signals = StopSignals::install_with(move || handler.stop());
    if args.parent_lifeline {
        let handler = session.clone();
        watch_parent_pipe(0, move || handler.stop());
    }
    let limit_handler = session.clone();
    let mut log_limits = BoundedLogs::new(2 * 1024 * 1024, Some(Box::new(move || limit_handler.stop()))).map_err(|e| e.to_string())?;
    let watch_stop = Event::new();
    let broker_log = directory.join(format!("broker-kdebug-{}.log", run));
    let control_log = directory.join(format!("controller-kdebug-{}.log", run));
    {
        let mut record = session.record.lock().unwrap();
        for (key, value) in [("wrapper_pid", json!(std::process::id())), ("duration_seconds", json!(duration)), ("run", json!(run)),
            ("wire_platform", json!(3)), ("assert_delay_mode", json!(2)), ("pairing_transport", json!("wifi"))] {
            record.insert(key.into(), value);
        }
    }
    let children = Mutex::new(Map::new());
    let record_child = |name: &str, pid: i32| -> Result<bool> {
        let Some(birth) = mirra_core::processes::process_birth(pid)? else { return Ok(false) };
        let mut children = children.lock().unwrap();
        children.insert(name.into(), mirra_core::retention::birth_json(&birth));
        write_state(&directory.join("backend-children.json"), &Value::Object(children.clone()))?;
        Ok(true)
    };
    let mut broker: Option<Arc<SharedChild>> = None;
    let mut broker_stdin = None;
    let mut controller_stdin = None;
    let emit = context.emit.clone();

    let body = (|| -> std::result::Result<(), String> {
        let renewal = context.root.join("runtime/certificate-renewal.json");
        let on_renewal_emit = emit.clone();
        let (certificate, renewed) = match (context.certificate)(&configuration, &renewal,
            &mut || on_renewal_emit(&json!({"BRIDGE_CERTIFICATE_RENEWAL": true}))) {
            Ok(current) => (current.data, current.renewed),
            Err(mirra_bridge::Error::Certificate(error)) => {
                // A device certificate that is only past its notAfter is not fatal: the
                // iPhone's Secure Enclave still issues and validates attested keys from it
                // (the broker's generate/validate self-check is the real gate), and a
                // jailbroken bridge cannot always mint a fresh BAA certificate on demand,
                // so MobileActivation keeps returning the same expired one. Keep running on
                // the enrolled certificate and let attestation decide. Every other failure
                // (clock, invalid, unavailable, busy) still stops the backend so its status
                // reaches the app. Renewal was already attempted and recorded its cooldown.
                if error.code != "expired" {
                    emit(&json!({"BRIDGE_CERTIFICATE_ERROR": error.code, "retry_at": error.retry_at}));
                    return Err(error.to_string());
                }
                let data = std::fs::read(&configuration.certificate_file)
                    .map_err(|e| mirra_core::Error::with_path(e, &configuration.certificate_file).to_string())?;
                emit(&json!({"BRIDGE_CERTIFICATE_EXPIRED_TOLERATED": true, "retry_at": error.retry_at}));
                (data, false)
            }
            Err(error) => return Err(error.to_string()),
        };
        emit(&json!({"BRIDGE_CERTIFICATE_READY": true}));
        let effective = private.join("certificate.der");
        exclusive_write(&effective, &certificate).map_err(|e| e.to_string())?;
        let mut certificate_args = vec!["--certificate".to_string(), util::text(&effective)];
        if renewed {
            certificate_args.push("--renewed-certificate".into());
        }
        let output = open_append(&broker_log).map_err(|e| e.to_string())?;
        log_limits.watch_stream(&broker_log, &output).map_err(|e| e.to_string())?;
        let mut command = (context.child)("broker");
        command.args(["--socket", &util::text(&private.join("broker.sock")), "--state-file", &util::text(&state), "--parent-lifeline"])
            .args(&config_args).args(&certificate_args)
            .stdin(Stdio::piped()).stdout(output.try_clone().map_err(|e| e.to_string())?).stderr(output.try_clone().map_err(|e| e.to_string())?);
        pass_lease(&mut command, broker_workspace.lease_fd());
        let mut child = command.spawn().map_err(|e| e.to_string())?;
        broker_stdin = child.stdin.take();
        let process = SharedChild::new(child);
        broker = Some(process.clone());
        session.set("broker_pid", json!(process.pid));
        record_child("broker", process.pid).map_err(|e| e.to_string())?;
        let deadline = Instant::now() + Duration::from_secs(13 + 3 * configuration.timeout);
        let socket = private.join("broker.sock");
        loop {
            if Instant::now() >= deadline {
                return Err("USB broker did not become ready".into());
            }
            if session.stopping.load(Ordering::SeqCst) {
                return Err("requested stop".into());
            }
            if process.poll().is_some() {
                return Err("USB broker exited; inspect private broker log".into());
            }
            if let Ok(reply) = (context.health)(&socket, Duration::from_secs(2)) {
                if util::truthy(reply.get("ready")) {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        emit(&json!({"USB_BROKER_READY": true, "run": run}));
        let mut control_output = open_append(&control_log).map_err(|e| e.to_string())?;
        log_limits.watch_stream(&control_log, &control_output).map_err(|e| e.to_string())?;
        let lifetime_args: Vec<String> = match duration {
            None => vec!["--until-stopped".into()],
            Some(seconds) => vec!["--seconds".into(), seconds.to_string()],
        };
        let (reader, writer) = pipe().map_err(|e| e.to_string())?;
        let mut command = (context.child)("sharing");
        command.args(&lifetime_args).arg("--parent-lifeline").args(&config_args)
            .stdin(Stdio::piped()).stdout(Stdio::from(writer.try_clone().map_err(|e| e.to_string())?)).stderr(Stdio::from(writer));
        pass_lease(&mut command, broker_workspace.lease_fd());
        let mut child = command.spawn().map_err(|e| e.to_string())?;
        drop(command);
        controller_stdin = child.stdin.take();
        let controller = SharedChild::new(child);
        *session.controller.lock().unwrap() = Some(controller.clone());
        if session.stopping.load(Ordering::SeqCst) {
            controller.terminate();
        }
        record_child("controller", controller.pid).map_err(|e| e.to_string())?;
        session.set("controller_pid", json!(controller.pid));
        session.set("broker_log", json!(broker_log.file_name().unwrap().to_string_lossy()));
        session.set("controller_log", json!(control_log.file_name().unwrap().to_string_lossy()));
        {
            let (session, broker, stop, health) = (session.clone(), process.clone(), watch_stop.clone(), context.health.clone());
            let (socket, timeout, interval, emit) = (socket.clone(), Duration::from_secs(configuration.timeout + 3), context.loss_interval, emit.clone());
            std::thread::spawn(move || {
                let reason = wait_for_backend_loss_with(&mut Poller(broker), &stop, interval, &mut || health(&socket, timeout));
                if let Some(reason) = reason {
                    if !stop.is_set() {
                        session.set("backend_lost", json!(true));
                        session.set("backend_loss_reason", json!(reason));
                        emit(&json!({"BACKEND_LOST": true, "reason": reason, "action": "restoring sharingd"}));
                        if let Some(controller) = session.controller.lock().unwrap().as_ref() {
                            controller.terminate();
                        }
                    }
                }
            });
        }
        let active = format!("{}\n", pyjson::dumps_pretty(&Value::Object(session.record.lock().unwrap().clone())));
        std::fs::write(directory.join("session-active.json"), active).map_err(|e| e.to_string())?;
        let mut lines = BufReader::new(File::from(reader));
        let mut line = Vec::new();
        loop {
            line.clear();
            match lines.read_until(b'\n', &mut line) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.to_string()),
            }
            control_output.write_all(&line).and_then(|_| control_output.flush()).map_err(|e| e.to_string())?;
            let Ok(Value::Object(event)) = serde_json::from_slice::<Value>(&line) else { continue };
            if let Some(running) = event.get("WORKSPACE_RUNNING") {
                // A recovered backend replaces sharingd's pairing state.
                // Record its lifetime so Connect can reject an app still
                // holding a connection from before that replacement.
                let pid = running.get("state").and_then(|s| s.get("pid"))
                    .ok_or_else(|| Error::key("pid").to_string())?;
                let pid = match pid {
                    Value::Number(n) => n.as_i64(),
                    Value::String(s) => s.trim().parse().ok(),
                    _ => None,
                };
                let Some(pid) = pid else { continue };
                if !record_child("sharingd", pid as i32).map_err(|e| e.to_string())? {
                    return Err("sharingd ended before backend readiness".into());
                }
                emit(&json!({"NATIVE_WORKSPACE_READY": true, "controller_pid": controller.pid, "run": run}));
            } else if let Some(restored) = event.get("ORIGINAL_RESTORED") {
                emit(&json!({"ORIGINAL_RESTORED": restored}));
            } else if event.contains_key("RESTORE_ERROR") {
                emit(&json!({"RESTORE_ERROR": true}));
            }
        }
        match controller.wait(Duration::from_secs(10)) {
            Some(code) => session.set("controller_exit_code", json!(code)),
            None => return Err(format!("Command '{}' timed out after 10 seconds", "sharing")),
        }
        Ok(())
    })();

    // finally:
    watch_stop.set();
    let controller = session.controller.lock().unwrap().clone();
    if let Some(controller) = &controller {
        if controller.poll().is_none() {
            controller.terminate();
            if controller.wait(Duration::from_secs(55)).is_none() {
                session.set("controller_restore_timeout", json!(true));
            }
        }
    }
    if let Some(broker) = &broker {
        if broker.poll().is_none() {
            broker.terminate();
            if broker.wait(Duration::from_secs(25)).is_none() {
                session.set("broker_cleanup_timeout", json!(true));
            }
        }
    }
    broker_workspace.close();
    let reply = (context.sharingd_print)().map_err(|e| e.to_string())?;
    let restored = reply.code == 0
        && reply.stdout.contains("path = /System/Library/LaunchAgents/com.apple.sharingd.plist")
        && reply.stdout.contains("program = /usr/libexec/sharingd")
        && !reply.stdout.contains("DYLD_INSERT_LIBRARIES") && !reply.stdout.contains("MIRRA_KEYSTORE");
    session.set("original_sharingd_restored", json!(restored));
    if restored {
        let cleanup = workspace::cleanup(&directory).unwrap_or_else(|e| json!({"removed": false, "error": e.to_string()}));
        session.set("broker_workspace_cleanup", cleanup);
    }
    session.set("finished", json!(true));
    session.set("log_limits", log_limits.close());
    let result = format!("{}\n", pyjson::dumps_pretty(&Value::Object(session.record.lock().unwrap().clone())));
    std::fs::write(directory.join(format!("session-result-{}.json", run)), result).map_err(|e| e.to_string())?;
    let terminal = broker.as_ref().is_none_or(|b| b.poll().is_some());
    emit(&json!({"SESSION_FINISHED": true, "original_sharingd_restored": restored, "broker_terminal": terminal, "run": run}));
    drop((broker_stdin, controller_stdin, session_lock));
    body?;
    let failed = session.get("controller_exit_code") != Some(json!(0)) || !restored
        || util::truthy(session.get("backend_lost").as_ref()) || util::truthy(session.get("broker_cleanup_timeout").as_ref())
        || util::truthy(session.get("controller_restore_timeout").as_ref())
        || util::truthy(session.get("log_limits").as_ref().and_then(|l| l.get("error")));
    Ok(if failed { 1 } else { 0 })
}

/// A close-on-exec pipe `(reader, writer)`.
pub(crate) fn pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    for fd in fds {
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

#[cfg(test)]
mod tests;
