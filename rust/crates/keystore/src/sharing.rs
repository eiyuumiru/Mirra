//! Temporarily load the Mirra keystore adapter into Apple's sharingd job,
//! then restart it unmodified (port of `scripts/sharing.py`).
//!
//! Stdout carries one JSON event per line, parsed by the backend worker:
//! `WORKSPACE_RUNNING` (with `state.pid`), `PAIRING_BACKUP_FAILED`,
//! `BROKER_FILE_FAILED`, then `SHARINGD_DETACHED` or `ORIGINAL_RESTORED`.
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use mirra_core::config::{default_root, load_config};
use mirra_core::event::Event;
use mirra_core::lifetime::{deadline_for, duration_from_arguments};
use mirra_core::logs::BoundedLogs;
use mirra_core::{pyjson, sys, Error};
use serde_json::{json, Map, Value};

use crate::args::{parse_int, Opt, Parser};
use crate::failure::{key_error, stdout_events, Emit, Failure};
use crate::sharingd::{backup_pairing_in, is_original, SharingdAgent, SharingdContext};
use crate::util::{self, py_repr, py_str, text};

const USAGE: &str = "usage: sharing.py [-h] [--seconds SECONDS | --until-stopped] [--config CONFIG]\n";
pub const MAX_REPLY: u32 = 262144;

fn parser() -> Parser {
    Parser {
        prog: "sharing.py",
        description: "Temporarily load the Mirra keystore adapter into Apple's sharingd job, then restart it unmodified.",
        usage: USAGE,
        options: vec![
            Opt::value("--seconds").group(1).help("Bounded session: 30..1800 seconds"),
            Opt::flag("--until-stopped").group(1).help("Remove the duration limit; recovery policy is selected separately"),
            Opt::value("--config"),
            Opt::flag("--parent-lifeline").suppressed(),
        ],
    }
}

/// Watches a native process's diagnostic descriptor (`BoundedLogs.watch_native`).
pub type WatchNative = Arc<dyn Fn(&BoundedLogs, &Path, i32, i32) -> mirra_core::Result<()> + Send + Sync>;

/// Everything sharing.py takes from its environment, replaceable in tests.
#[derive(Clone)]
pub struct SharingOptions {
    /// `configuration.runtime_directory` (holds broker-state.json and keystore.dylib).
    pub workspace: PathBuf,
    /// `None` = `--until-stopped`.
    pub duration: Option<u64>,
    pub context: SharingdContext,
    pub stop: Event,
    pub emit: Emit,
    pub health_timeout: Duration,
    pub adapter_wait: Duration,
    pub adapter_poll: Duration,
    pub tick: Duration,
    pub log_limit: u64,
    pub watch_native: WatchNative,
}

impl SharingOptions {
    pub fn new(workspace: PathBuf, duration: Option<u64>, stop: Event) -> Self {
        SharingOptions {
            workspace,
            duration,
            context: SharingdContext::system(),
            stop,
            emit: stdout_events(),
            health_timeout: Duration::from_secs(15),
            adapter_wait: Duration::from_secs(8),
            adapter_poll: Duration::from_millis(200),
            tick: Duration::from_secs(1),
            log_limit: 2 * 1024 * 1024,
            watch_native: Arc::new(|logs, path, pid, fd| logs.watch_native(path, pid, fd)),
        }
    }

    fn state_directory(&self) -> PathBuf {
        self.context.home.join("Library/Application Support/Mirra/state")
    }
    fn logs_directory(&self) -> PathBuf {
        self.context.home.join("Library/Application Support/Mirra/logs")
    }
}

/// Entry point of the hidden `sharing` subcommand; `args` are the arguments
/// after the subcommand (`sys.argv[1:]` of sharing.py). Returns the exit status.
pub fn sharing_main(args: Vec<String>) -> i32 {
    let parser = parser();
    let parsed = match parser.parse(&args) {
        Ok(parsed) => parsed,
        Err(status) => return status,
    };
    let seconds = match parsed.value("--seconds").map(|v| parse_int("--seconds", v)).transpose() {
        Ok(seconds) => seconds,
        Err(message) => return parser.error(&message),
    };
    let configuration = match load_config(parsed.value("--config").map(Path::new), &default_root()) {
        Ok(configuration) => configuration,
        Err(error) => return Failure::raised("ConfigError", error.0).report(),
    };
    let duration = match duration_from_arguments(seconds, parsed.flag("--until-stopped"), configuration.seconds as i64) {
        Ok(duration) => duration,
        Err(message) => return parser.error(&message),
    };
    let stop = Event::new();
    let flag = stop.clone();
    if let Err(error) = crate::signals::on_termination(move || flag.set()) {
        return Failure::from(error).report();
    }
    if parsed.flag("--parent-lifeline") {
        let flag = stop.clone();
        mirra_core::lifetime::watch_parent_pipe(0, move || flag.set());
    }
    match run(SharingOptions::new(configuration.runtime_directory.clone(), duration, stop)) {
        Ok(()) => 0,
        Err(failure) => failure.report(),
    }
}

fn field<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a Value, Failure> {
    map.get(key).ok_or_else(|| key_error(key))
}

fn read_exact(stream: &mut UnixStream, count: usize) -> Result<Vec<u8>, Failure> {
    let mut data = vec![0u8; count];
    let mut filled = 0;
    while filled < count {
        match stream.read(&mut data[filled..]) {
            Ok(0) => return Err(Failure::raised("ConnectionError", "broker disconnected")),
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                return Err(Failure::raised("TimeoutError", "timed out"))
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(data)
}

/// One `{"operation": "health"}` request to the broker's unix socket.
pub fn broker_health(socket: &Path, timeout: Duration) -> Result<Map<String, Value>, Failure> {
    let mut connection = UnixStream::connect(socket).map_err(Error::Os)?;
    connection.set_read_timeout(Some(timeout))?;
    connection.set_write_timeout(Some(timeout))?;
    let message = pyjson::dumps(&json!({"operation": "health"}));
    let mut frame = (message.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(message.as_bytes());
    connection.write_all(&frame)?;
    let size = u32::from_be_bytes(read_exact(&mut connection, 4)?.try_into().unwrap());
    if !(1..=MAX_REPLY).contains(&size) {
        return Err(Failure::exit("Invalid broker health response length"));
    }
    let raw = read_exact(&mut connection, size as usize)?;
    match serde_json::from_slice::<Value>(&raw) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Ok(Map::new()),
        Err(e) => Err(Failure::raised("JSONDecodeError", e.to_string())),
    }
}

/// Rewrite the broker file in place: the adapter reads it through a
/// descriptor opened before sharingd's sandbox started, so the inode must
/// not change. Online: `{"online": true, "socket", "tcp_port", "token",
/// "certificate" (base64 DER)}`; offline: `{"online": false}`.
pub fn publish_broker(path: &Path, broker: Option<&Map<String, Value>>) -> Result<(), Failure> {
    let mut value = Map::new();
    value.insert("online".into(), Value::Bool(broker.is_some()));
    if let Some(broker) = broker {
        value.insert("socket".into(), field(broker, "socket")?.clone());
        value.insert("tcp_port".into(), field(broker, "tcp_port")?.clone());
        value.insert("token".into(), field(broker, "auth_token")?.clone());
        let certificate = PathBuf::from(py_str(Some(field(broker, "certificate")?)));
        let data = std::fs::read(&certificate).map_err(|e| Error::with_path(e, &certificate))?;
        value.insert("certificate".into(), Value::from(base64::engine::general_purpose::STANDARD.encode(data)));
    }
    let data = pyjson::dumps(&Value::Object(value));
    let descriptor = sys::open(path, libc::O_WRONLY | libc::O_CREAT | libc::O_NOFOLLOW, 0o600)
        .map_err(|e| Error::with_path(e, path))?;
    let fd = descriptor.as_raw_fd();
    let info = sys::fstat(fd)?;
    if info.st_uid != sys::getuid() || info.st_mode & 0o077 != 0 {
        return Err(Failure::runtime("Mirra broker file must be private"));
    }
    sys::ftruncate(fd, 0)?;
    let mut written = 0;
    let bytes = data.as_bytes();
    while written < bytes.len() {
        let n = unsafe { libc::pwrite(fd, bytes[written..].as_ptr().cast(), bytes.len() - written, written as libc::off_t) };
        if n < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        written += n as usize;
    }
    sys::fsync(fd)?;
    Ok(())
}

fn interrupted(message: &str) -> Failure {
    Failure::raised("InterruptedError", message)
}

/// The sharing.py controller: check the broker, load (or adopt) the
/// adapter, watch sharingd until stopped or the bounded duration ends, then
/// detach (normal stop of a continuous session) or restore Apple's sharingd.
pub fn run(options: SharingOptions) -> Result<(), Failure> {
    let workspace = options.workspace.clone();
    let path = workspace.join("broker-state.json");
    let raw = std::fs::read(&path).map_err(|e| Error::with_path(e, &path))?;
    let broker = match serde_json::from_slice::<Value>(&raw) {
        Ok(Value::Object(map)) => map,
        Ok(_) => return Err(Failure::raised("TypeError", "broker state must be an object")),
        Err(e) => return Err(Failure::raised("JSONDecodeError", e.to_string())),
    };
    let socket = PathBuf::from(py_str(Some(field(&broker, "socket")?)));
    let health = broker_health(&socket, options.health_timeout)?;
    if !util::truthy(health.get("ready")) {
        return Err(Failure::exit("Live USB/SEP broker health check failed"));
    }
    let capable = match health.get("capabilities") {
        Some(Value::Array(items)) => items.contains(&json!("reset_owned_sessions")),
        Some(Value::String(text)) => text.contains("reset_owned_sessions"),
        _ => false,
    };
    if !capable {
        return Err(Failure::exit("Broker/shim protocol mismatch: rebuild and restart support together"));
    }
    let context = &options.context;
    let target = context.target();
    let original_before = context.service(Some(&target), Duration::from_secs(15))?;
    if !is_original(&original_before) {
        return Err(Failure::exit(format!("Unexpected original service state: {}", py_repr(&Value::Object(original_before)))));
    }
    if util::truthy(original_before.get("injected")) {
        return Err(Failure::exit("sharingd already has an injected configuration; restore that session before starting another"));
    }
    util::chmod(&workspace, 0o700).map_err(|e| Error::with_path(e, &workspace))?;
    // Read by the adapter inside sharingd only; never placed in launchd's environment.
    // Survives Mirra stops: Apple's sharingd deletes the pairing key when it runs alone.
    let state_directory = options.state_directory();
    util::mkdir_parents(&state_directory, 0o700).map_err(|e| Error::with_path(e, &state_directory))?;
    let info = sys::stat(&state_directory).map_err(|e| Error::with_path(e, &state_directory))?;
    if info.st_uid != sys::getuid() || info.st_mode & 0o077 != 0 {
        return Err(Failure::exit("Mirra state directory must be private"));
    }
    let pairing_backup = state_directory.join("pairing.plist");
    let broker_file = state_directory.join("broker.json");
    // A detached sharingd outlives this workspace, so its output goes to a stable file.
    let logs = options.logs_directory();
    std::fs::create_dir_all(&logs).map_err(|e| Error::with_path(e, &logs))?;
    util::chmod(&logs, 0o700)?;
    let logs_info = sys::lstat(&logs).map_err(|e| Error::with_path(e, &logs))?;
    if !sys::private_owned(&logs_info, true) {
        return Err(Failure::exit("Mirra log directory must be private"));
    }
    let sharingd_logs = [(1, logs.join("sharingd.stdout.log")), (2, logs.join("sharingd.log"))];
    let settings = json!({
        "attested_ltk_backup": text(&state_directory.join("attested-ltk.plist")),
        "broker_file": text(&broker_file),
        "stdout": text(&sharingd_logs[0].1),
        "stderr": text(&sharingd_logs[1].1),
        "environment": {
            "MIRRA_KEYSTORE_BROKER_SOCKET": field(&broker, "socket")?,
            "MIRRA_KEYSTORE_BROKER_TCP_PORT": py_str(Some(field(&broker, "tcp_port")?)),
            "MIRRA_KEYSTORE_BROKER_TOKEN": field(&broker, "auth_token")?,
            "MIRRA_KEYSTORE_DCRT_PATH": field(&broker, "certificate")?,
            "MIRRA_KEYSTORE_DIAGNOSTIC_ERRORS": "1",
            "MIRRA_ASSERT_DELAY_MODE": "2",
            "MIRRA_PAIRING_TRANSPORT": "wifi",
        },
    });
    for (_, path) in &sharingd_logs {
        sys::open(path, libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND | libc::O_NOFOLLOW, 0o600)
            .map_err(|e| Error::with_path(e, path))?;
    }
    publish_broker(&broker_file, Some(&broker))?;
    let stop = options.stop.clone();
    let flag = stop.clone();
    let mut log_limits = BoundedLogs::new(options.log_limit, Some(Box::new(move || flag.set())))?;
    let mut agent = SharingdAgent::with_context(Some(&workspace), context.clone());
    let reuse = health.get("can_resume_pairing") == Some(&Value::Bool(true));
    let session = Session { options: &options, target: &target, original_before: &original_before,
        sharingd_logs: &sharingd_logs, pairing_backup: &pairing_backup, settings: &settings };
    let outcome = session.run(&mut agent, &log_limits, reuse);
    let failed = outcome.is_err();
    let finished = (|| -> Result<(), Failure> {
        if agent.owned {
            // Before Apple's sharingd runs again and removes the entries.
            if let Err(error) = backup_pairing_in(&context.auto_unlock(), &pairing_backup) {
                if !(error.is_os_error() || matches!(error, Error::Value(_))) {
                    return Err(error.into());
                }
                (options.emit)(&json!({"PAIRING_BACKUP_FAILED": error.to_string()}));
            }
            // The adapter keeps the pairing while offline.
            if let Err(error) = publish_broker(&broker_file, None) {
                (options.emit)(&json!({"BROKER_FILE_FAILED": failure_text(&error)}));
            }
            // Only a normal stop of the long-running service keeps the adapter.
            let detach = stop.is_set() && options.duration.is_none() && !failed && log_limits.error().is_none();
            let state = agent.close(detach)?;
            let key = if detach { "SHARINGD_DETACHED" } else { "ORIGINAL_RESTORED" };
            (options.emit)(&json!({key: state}));
        }
        Ok(())
    })();
    let limits = log_limits.close();
    let report = workspace.join("sharingd-log-limits.json");
    let written = std::fs::write(&report, format!("{}\n", pyjson::dumps_pretty(&limits)))
        .map_err(|e| Failure::from(Error::with_path(e, &report)));
    // A later exception replaces an earlier one, as in Python's finally blocks.
    written?;
    finished?;
    outcome?;
    if log_limits.error().is_some() {
        return Err(Failure::exit("Diagnostic log maintenance failed; original sharingd restoration was attempted"));
    }
    Ok(())
}

/// `str(error)` of an exception.
fn failure_text(failure: &Failure) -> String {
    match failure {
        Failure::Exit(message) | Failure::Raised { message, .. } => message.clone(),
    }
}

struct Session<'a> {
    options: &'a SharingOptions,
    target: &'a str,
    original_before: &'a Map<String, Value>,
    sharingd_logs: &'a [(i32, PathBuf); 2],
    pairing_backup: &'a Path,
    settings: &'a Value,
}

impl Session<'_> {
    fn service(&self) -> Result<Map<String, Value>, Failure> {
        Ok(self.options.context.service(Some(self.target), Duration::from_secs(15))?)
    }

    fn run(&self, agent: &mut SharingdAgent, log_limits: &BoundedLogs, reuse: bool) -> Result<(), Failure> {
        let options = self.options;
        if options.stop.is_set() {
            return Err(interrupted("Parent ended before sharingd startup"));
        }
        agent.start(&options.workspace.join("keystore.dylib"), self.settings, Some(self.pairing_backup), reuse)?;
        let state = if agent.adopted {
            // The adapter from an earlier session is still loaded; it reads the new
            // broker from the broker file, and sharingd keeps the iPhone pairing armed.
            let state = self.service()?;
            let injected = agent.record.as_ref().and_then(|r| r.get("injected_pid"));
            if py_str(state.get("pid")) != py_str(injected) {
                return Err(Failure::runtime("The detached sharingd adapter is no longer running"));
            }
            state
        } else {
            let state = self.wait_for_adapter()?;
            let pid = py_str(state.get("pid"));
            let pid: i64 = util::strip(&pid).parse().map_err(|_| Failure::raised("ValueError",
                format!("invalid literal for int() with base 10: {}", mirra_core::pyfmt::repr_str(&pid))))?;
            agent.record_injected(pid)?;
            state
        };
        let pid_text = py_str(state.get("pid"));
        let pid: i32 = util::strip(&pid_text).parse().ok().filter(|p| *p > 0).ok_or_else(|| Failure::raised("ValueError",
            format!("invalid literal for int() with base 10: {}", mirra_core::pyfmt::repr_str(&pid_text))))?;
        for (fd, path) in self.sharingd_logs {
            (options.watch_native)(log_limits, path, pid, *fd)?;
        }
        let record = json!({"controller_pid": std::process::id(), "job": self.target, "state": state,
            "restored_pairing_entries": agent.restored_pairing, "adopted_sharingd": agent.adopted,
            "original_before": self.original_before, "automatic_restore_seconds": options.duration});
        let path = options.workspace.join("sharing.json");
        std::fs::write(&path, format!("{}\n", pyjson::dumps_pretty(&record))).map_err(|e| Error::with_path(e, &path))?;
        (options.emit)(&json!({"WORKSPACE_RUNNING": record}));
        let deadline = deadline_for(options.duration);
        let mut ticks = 0u64;
        while !options.stop.wait(Some(options.tick)) && !deadline.expired() {
            ticks += 1;
            if ticks.is_multiple_of(10) {
                if let Err(error) = backup_pairing_in(&options.context.auto_unlock(), self.pairing_backup) {
                    if !(error.is_os_error() || matches!(error, Error::Value(_))) {
                        return Err(error.into());
                    }
                    (options.emit)(&json!({"PAIRING_BACKUP_FAILED": error.to_string()}));
                }
            }
            // Apple's job restarts sharingd by itself, but never with the adapter.
            if self.service()?.get("pid") != state.get("pid") {
                return Err(Failure::runtime("sharingd restarted without the Mirra adapter"));
            }
        }
        Ok(())
    }

    fn wait_for_adapter(&self) -> Result<Map<String, Value>, Failure> {
        let options = self.options;
        let deadline = Instant::now() + options.adapter_wait;
        let mut state = Map::new();
        while Instant::now() < deadline {
            if options.stop.is_set() {
                return Err(interrupted("Parent ended during sharingd startup"));
            }
            state = self.service()?;
            if state.get("state").and_then(Value::as_str) == Some("running") && util::truthy(state.get("pid")) {
                let marker = format!("MIRRA_KEYSTORE_SHIM_LOADED pid={} enabled=1", py_str(state.get("pid")));
                let log = &self.sharingd_logs[1].1;
                let text = std::fs::read(log).map_err(|e| Error::with_path(e, log))?;
                if String::from_utf8_lossy(&text).contains(&marker) {
                    return Ok(state);
                }
            }
            std::thread::sleep(options.adapter_poll);
        }
        Err(Failure::runtime(format!("sharingd did not load the adapter: {}", py_repr(&Value::Object(state)))))
    }
}

#[cfg(test)]
mod tests;
