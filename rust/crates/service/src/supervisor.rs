//! Restart backend workers while native app launch support remains available
//! (port of `scripts/supervisor.py`).
//!
//! A worker's terminal exit is the trigger for recovery. A separate gate
//! requires restoration of sharingd, release of the session lock and
//! termination of the previous worker's recorded children before another
//! worker may start. Workers are `mirra-cli __backend --config PATH
//! --until-stopped --parent-lifeline` ([`crate::cli::child_command`]); their
//! stdout/stderr pipe is copied to `backend-NNNNNN/backend.log` and scanned for
//! state events, and `backend-status.json` keeps the Python layout.
//! [`backend_lease`] and [`backend_children_stopped`] live in
//! [`crate::supervisor_lease`].
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mirra_core::config::Config;
use mirra_core::event::Event;
use mirra_core::lifetime::emit_event;
use mirra_core::logs::{open_append, BoundedLogs};
use mirra_core::redaction::redact_text;
use mirra_core::retention::{self, KEEP_COMPLETED};
use mirra_core::state::write_state;
use mirra_core::workspace;
use serde_json::{json, Map, Value};

use crate::backend::{pipe, SharedChild};
use crate::cli;
use crate::error::{Error, Result};
use crate::sharingd::{is_original, Sharingd, SystemSharingd};
use crate::supervisor_lease::{backend_children_stopped, backend_lease};
use crate::util::{self, truthy, BirthProbe};

pub type ChildFactory = Arc<dyn Fn(&str) -> Command + Send + Sync>;
pub type Emit = Arc<dyn Fn(&Value) + Send + Sync>;
/// `recovery_gate(previous)` replacement (tests).
pub type Gate = Arc<dyn Fn(Option<&Path>) -> Result<(bool, Option<String>)> + Send + Sync>;

/// Everything the supervisor touches outside its runtime directory.
#[derive(Clone)]
pub struct SupervisorHooks {
    /// Worker command for `"backend"` (default [`cli::child_command`]).
    pub child: ChildFactory,
    pub sharingd: Arc<dyn Sharingd>,
    /// `Path.home()` (the shared `Library/Caches/Mirra/session.lock`).
    pub home: PathBuf,
    pub birth: BirthProbe,
    /// `lifetime.emit_event`
    pub emit: Emit,
    /// Replaces [`recovery_gate`] when set.
    pub gate: Option<Gate>,
    /// Pause between deferred cleanup observations (2 s).
    pub retry: Duration,
    /// How long a terminated worker may take to restore sharingd (80 s).
    pub worker_stop: Duration,
}

impl SupervisorHooks {
    pub fn system() -> Self {
        let home = util::home();
        SupervisorHooks {
            child: Arc::new(cli::child_command),
            sharingd: Arc::new(SystemSharingd::new(&home)),
            home,
            birth: util::real_birth(),
            emit: Arc::new(|event| {
                let _ = emit_event(event);
            }),
            gate: None,
            retry: Duration::from_secs(2),
            worker_stop: Duration::from_secs(80),
        }
    }
}

impl Default for SupervisorHooks {
    fn default() -> Self {
        Self::system()
    }
}

/// Read-only ownership checks. Any uncertain observation defers recovery
/// (returned as an error, like Python's exceptions).
pub fn recovery_gate(previous: Option<&Path>, sharingd: &dyn Sharingd, birth: &BirthProbe, home: &Path)
    -> Result<(bool, Option<String>)> {
    if !backend_children_stopped(previous, sharingd, birth)? {
        return Ok((false, Some("previous backend child still running".into())));
    }
    let lease = match backend_lease(home) {
        Ok(lease) => lease,
        Err(error) if error.type_name() == "BlockingIOError" => {
            return Ok((false, Some("backend controller still owns sharingd".into())));
        }
        Err(error) => return Err(error),
    };
    let current = sharingd.service()?;
    drop(lease);
    if current.is_empty() {
        return Ok((false, Some("sharingd restoration not yet observable".into())));
    }
    if !is_original(&current) {
        return Ok((false, Some("sharingd is not in its original configuration".into())));
    }
    Ok((true, None))
}

/// `except (OSError, ValueError, RuntimeError, subprocess.SubprocessError)`
fn observed(error: &Error) -> bool {
    matches!(error, Error::Core(_))
}

fn observation_error(error: &Error) -> Value {
    json!({"error_type": error.type_name(), "error": redact_text(&error.to_string()),
        "errno": error.errno().map_or(Value::Null, Value::from)})
}

fn optional(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::from)
}

struct Shared {
    config: Config,
    directory: PathBuf,
    recover: bool,
    stop: Event,
    state: Mutex<Map<String, Value>>,
    process: Mutex<Option<Arc<SharedChild>>>,
    error: Mutex<Option<String>>,
    hooks: SupervisorHooks,
}

/// `supervisor.NativeBackend`
pub struct NativeBackend {
    shared: Arc<Shared>,
    finished: Event,
    started: bool,
}

impl NativeBackend {
    pub fn new(config: Config, directory: &Path, recover: bool) -> Self {
        Self::with_hooks(config, directory, recover, SupervisorHooks::system())
    }

    pub fn with_hooks(config: Config, directory: &Path, recover: bool, hooks: SupervisorHooks) -> Self {
        let state = json!({"phase": "pending", "attempt": 0, "ready": false, "automatic_recovery": recover});
        NativeBackend {
            shared: Arc::new(Shared {
                config,
                directory: directory.to_path_buf(),
                recover,
                stop: Event::new(),
                state: Mutex::new(state.as_object().unwrap().clone()),
                process: Mutex::new(None),
                error: Mutex::new(None),
                hooks,
            }),
            finished: Event::new(),
            started: false,
        }
    }

    /// Start the supervisor thread.
    pub fn start(mut self) -> Result<Self> {
        let (shared, finished) = (self.shared.clone(), self.finished.clone());
        std::thread::Builder::new().name("native-backend-supervisor".into()).spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| shared.run()));
            if outcome.is_err() {
                let message = "Backend supervisor panicked".to_string();
                *shared.error.lock().unwrap() = Some(message.clone());
                let _ = shared.publish("failed", vec![("reason", json!(message))]);
            }
            finished.set();
        })?;
        self.started = true;
        Ok(self)
    }

    pub fn snapshot(&self) -> Map<String, Value> {
        self.shared.snapshot()
    }

    /// The worker currently (or last) started, if any.
    pub fn worker(&self) -> Option<Arc<SharedChild>> {
        self.shared.process.lock().unwrap().clone()
    }

    /// `close(timeout=85)`
    pub fn close(&mut self) -> Map<String, Value> {
        self.close_within(Duration::from_secs(85))
    }

    pub fn close_within(&mut self, timeout: Duration) -> Map<String, Value> {
        let shared = &self.shared;
        shared.stop.set();
        if self.started && !self.finished.wait(Some(timeout)) {
            *shared.error.lock().unwrap() = Some("Backend restoration is still running".into());
        }
        let mut result = shared.snapshot();
        result.insert("cleanup_error".into(), optional(shared.error.lock().unwrap().clone()));
        // Direct observations are authoritative even if a worker lost its final log.
        if self.worker().is_some_and(|process| process.poll().is_none()) {
            result.insert("cleanup_error".into(), json!("Backend worker is still running"));
        }
        let outcome = (|| -> Result<()> {
            if let Some(recovered) = shared.hooks.sharingd.recover_abandoned(false)?.filter(|v| truthy(Some(v))) {
                result.insert("abandoned_sharingd_recovered".into(), recovered);
            }
            let current = result.get("directory").filter(|v| truthy(Some(v))).and_then(Value::as_str)
                .map(|name| shared.directory.join(name));
            let (verified, reason) = shared.gate(current.as_deref())?;
            result.insert("cleanup_verified".into(), json!(verified));
            result.insert("cleanup_reason".into(), optional(reason));
            if let (true, false, Some(current)) = (verified, truthy(result.get("cleanup_error")), current) {
                let cleaned = workspace::cleanup(&current)?;
                let in_use = cleaned.get("reason").and_then(Value::as_str) == Some("lease_in_use");
                result.insert("workspace_cleanup".into(), cleaned);
                if !in_use {
                    retention::retire(&current)?;
                } else {
                    result.insert("cleanup_verified".into(), json!(false));
                    result.insert("cleanup_reason".into(), json!("broker workspace is still in use"));
                }
            }
            Ok(())
        })();
        if let Err(error) = outcome {
            result.insert("cleanup_verified".into(), json!(false));
            result.insert("cleanup_reason".into(), json!("ownership observation deferred"));
            result.insert("cleanup_observation_error".into(), observation_error(&error));
        }
        result
    }
}

/// What the native session needs from a started backend supervisor.
pub trait Backend: Send {
    fn snapshot(&self) -> Map<String, Value>;
    fn close(&mut self) -> Map<String, Value>;
}

impl Backend for NativeBackend {
    fn snapshot(&self) -> Map<String, Value> {
        NativeBackend::snapshot(self)
    }
    fn close(&mut self) -> Map<String, Value> {
        NativeBackend::close(self)
    }
}

impl Shared {
    fn snapshot(&self) -> Map<String, Value> {
        self.state.lock().unwrap().clone()
    }

    fn publish(&self, phase: &str, values: Vec<(&str, Value)>) -> Result<()> {
        let state = {
            let mut state = self.state.lock().unwrap();
            state.insert("phase".into(), json!(phase));
            state.insert("ready".into(), json!(phase == "ready"));
            for (key, value) in values {
                state.insert(key.into(), value);
            }
            state.clone()
        };
        write_state(&self.directory.join("backend-status.json"), &Value::Object(state.clone()))?;
        (self.hooks.emit)(&json!({"NATIVE_BACKEND_STATE": state}));
        Ok(())
    }

    fn gate(&self, previous: Option<&Path>) -> Result<(bool, Option<String>)> {
        match &self.hooks.gate {
            Some(gate) => gate(previous),
            None => recovery_gate(previous, self.hooks.sharingd.as_ref(), &self.hooks.birth, &self.hooks.home),
        }
    }

    fn run(&self) {
        if let Err(error) = self.run_loop() {
            let message = error.to_string();
            *self.error.lock().unwrap() = Some(message.clone());
            let _ = self.publish("failed", vec![("reason", json!(message))]);
        }
        let process = self.process.lock().unwrap().clone();
        if let Some(process) = process {
            if process.poll().is_none() {
                process.terminate();
                // Never kill a restoration worker to make a retry appear ready.
                if process.wait(self.hooks.worker_stop).is_none() {
                    *self.error.lock().unwrap() = Some("Backend restoration worker has not stopped".into());
                }
            }
        }
    }

    fn run_loop(&self) -> Result<()> {
        let mut previous: Option<PathBuf> = None;
        let mut delay = 2u64;
        while !self.stop.is_set() {
            let mut observation = Value::Null;
            let checked = (|| -> Result<(bool, Option<String>)> {
                if let Some(recovered) = self.hooks.sharingd.recover_abandoned(false)?.filter(|v| truthy(Some(v))) {
                    (self.hooks.emit)(&json!({"ABANDONED_SHARINGD_RECOVERED": recovered}));
                }
                self.gate(previous.as_deref())
            })();
            let (allowed, reason) = match checked {
                Ok(checked) => checked,
                Err(error) if observed(&error) => {
                    observation = observation_error(&error);
                    (false, Some("ownership observation deferred".into()))
                }
                Err(error) => return Err(error),
            };
            if !allowed {
                let reason = optional(reason);
                let state = self.snapshot();
                if state.get("reason").unwrap_or(&Value::Null) != &reason
                    || state.get("observation_error").unwrap_or(&Value::Null) != &observation {
                    self.publish("waiting_for_cleanup", vec![("reason", reason.clone()), ("observation_error", observation)])?;
                }
                if !self.recover {
                    return Err(Error::runtime(util::py_str(&reason)));
                }
                self.stop.wait(Some(self.hooks.retry));
                continue;
            }
            if let Some(previous) = &previous {
                // Only a terminal worker and a successful restoration gate
                // authorize release of its temporary certificate and files.
                let cleaned = workspace::cleanup(previous)?;
                if cleaned.get("reason").and_then(Value::as_str) == Some("lease_in_use") {
                    self.publish("waiting_for_cleanup", vec![("reason", json!("previous broker workspace is still in use"))])?;
                    self.stop.wait(Some(self.hooks.retry));
                    continue;
                }
                retention::retire(previous)?;
                let retained = retention::prune(&self.directory, "backend", std::slice::from_ref(previous), KEEP_COMPLETED)?;
                if truthy(retained.get("removed")) || truthy(retained.get("deferred")) {
                    (self.hooks.emit)(&json!({"BACKEND_RETENTION": retained}));
                }
            }
            let attempt = util::strict_int(self.snapshot().get("attempt")).unwrap_or(0) + 1;
            let current = self.directory.join(format!("backend-{:06}", attempt));
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new().mode(0o700).create(&current)
                    .map_err(|e| mirra_core::Error::with_path(e, &current))?;
            }
            retention::track(&current, "backend")?;
            let settings = current.join("config.json");
            let mut staged = self.config.clone();
            staged.runtime_directory = current.clone();
            write_state(&settings, &staged.as_dict())?;
            let adapter = current.join("keystore.dylib");
            util::copy2(&self.directory.join("keystore.dylib"), &adapter)?;
            util::chmod(&adapter, 0o600)?;
            let name = current.file_name().unwrap_or_default().to_string_lossy().into_owned();
            self.publish("starting", vec![("attempt", json!(attempt)), ("directory", json!(name)),
                ("reason", Value::Null), ("worker_pid", Value::Null), ("controller_pid", Value::Null),
                ("worker_birth", Value::Null), ("exit_code", Value::Null), ("retry_seconds", Value::Null),
                ("observation_error", Value::Null)])?;
            let stop = self.stop.clone();
            let mut limits = BoundedLogs::new(2 * 1024 * 1024, Some(Box::new(move || stop.set())))?;
            let ran = self.run_worker(&current, &settings, &limits);
            let report = limits.close();
            write_state(&current.join("backend-log-limits.json"), &report)?;
            let (code, healthy_seconds) = ran?;
            if truthy(report.get("error")) {
                return Err(Error::runtime("Backend diagnostic log maintenance failed"));
            }
            previous = Some(current);
            self.publish("worker_ended", vec![("exit_code", json!(code)), ("worker_pid", Value::Null), ("worker_birth", Value::Null)])?;
            if self.stop.is_set() || !self.recover {
                break;
            }
            if healthy_seconds >= 60.0 {
                delay = 2;
            }
            self.publish("retry_wait", vec![("retry_seconds", json!(delay)), ("reason", json!("backend worker ended"))])?;
            self.stop.wait(Some(Duration::from_secs(delay)));
            delay = (delay * 2).min(30);
        }
        self.publish("stopped", vec![])
    }

    fn run_worker(&self, current: &Path, settings: &Path, limits: &BoundedLogs) -> Result<(i32, f64)> {
        let log = current.join("backend.log");
        let mut output = open_append(&log).map_err(|e| mirra_core::Error::with_path(e, &log))?;
        limits.watch_stream(&log, &output)?;
        let (reader, writer) = pipe()?;
        let mut command = (self.hooks.child)("backend");
        command.arg("--config").arg(settings).args(["--until-stopped", "--parent-lifeline"])
            .stdin(Stdio::piped()).stdout(Stdio::from(writer.try_clone()?)).stderr(Stdio::from(writer));
        let spawned = command.spawn();
        // The parent's copies of the write end must close for EOF to arrive.
        drop(command);
        let mut child = spawned?;
        // The worker's lifeline: held until the worker ends.
        let lifeline = child.stdin.take();
        let process = SharedChild::new(child);
        *self.process.lock().unwrap() = Some(process.clone());
        let birth = (self.hooks.birth)(process.pid)?;
        self.publish("starting", vec![("worker_pid", json!(process.pid)),
            ("worker_birth", birth.as_ref().map_or(Value::Null, retention::birth_json))])?;
        let result = self.read_worker(&process, reader, &mut output);
        drop(lifeline);
        result
    }

    /// Drain the pipe directly; rotated diagnostic files never carry status.
    fn read_worker(&self, process: &SharedChild, reader: OwnedFd, output: &mut File) -> Result<(i32, f64)> {
        let mut buffered: Vec<u8> = Vec::new();
        let mut deadline = Instant::now() + Duration::from_secs(30 + 3 * self.config.timeout);
        let mut ready_at: Option<Instant> = None;
        let mut requested_stop = false;
        let mut reader = Some(reader);
        let mut chunk = vec![0u8; 16384];
        while process.poll().is_none() || reader.is_some() {
            if (self.stop.is_set() || (ready_at.is_none() && Instant::now() > deadline)) && !requested_stop {
                if process.poll().is_none() {
                    process.terminate();
                }
                requested_stop = true;
                let reason = if self.stop.is_set() { "requested stop" } else { "backend readiness deadline" };
                self.publish("stopping_worker", vec![("reason", json!(reason))])?;
            }
            let Some(fd) = reader.as_ref().map(AsRawFd::as_raw_fd) else {
                std::thread::sleep(Duration::from_millis(200));
                continue;
            };
            let mut poll = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
            let ready = unsafe { libc::poll(&mut poll, 1, 200) };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            if ready == 0 {
                continue;
            }
            let count = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), chunk.len()) };
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            if count == 0 {
                reader = None;
                continue;
            }
            let data = &chunk[..count as usize];
            output.write_all(data)?;
            output.flush()?;
            buffered.extend_from_slice(data);
            while let Some(position) = buffered.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = buffered.drain(..=position).collect();
                let Ok(Value::Object(event)) = serde_json::from_slice::<Value>(&line[..line.len() - 1]) else { continue };
                self.handle_event(&event, requested_stop, &mut ready_at, &mut deadline)?;
            }
            if buffered.len() > 65536 {
                buffered.clear(); // Invalid oversized diagnostic line, never a state event.
            }
        }
        let code = loop {
            if let Some(code) = process.wait(Duration::from_secs(3600)) {
                break code;
            }
        };
        Ok((code, ready_at.map_or(0.0, |at| at.elapsed().as_secs_f64())))
    }

    fn handle_event(&self, event: &Map<String, Value>, requested_stop: bool, ready_at: &mut Option<Instant>,
        deadline: &mut Instant) -> Result<()> {
        let issue = event.get("BRIDGE_CERTIFICATE_ERROR").filter(|v| truthy(Some(v)));
        if truthy(event.get("NATIVE_WORKSPACE_READY")) && !requested_stop {
            *ready_at = Some(Instant::now());
            self.publish("ready", vec![("reason", Value::Null),
                ("controller_pid", event.get("controller_pid").cloned().unwrap_or(Value::Null)),
                ("certificate_issue", Value::Null), ("certificate_retry_at", Value::Null)])?;
        } else if event.get("BRIDGE_CERTIFICATE_RENEWAL") == Some(&Value::Bool(true)) && !requested_stop {
            // The existing issuer request may take up to 70s, with a
            // separate download and certificate check.
            *deadline = (*deadline).max(Instant::now() + Duration::from_secs(105));
            self.publish("starting", vec![("certificate_issue", json!("renewing")), ("certificate_retry_at", Value::Null)])?;
        } else if let (Some(issue), false) = (issue.filter(|issue| issue.as_str() != Some("busy")), requested_stop) {
            // A lock collision leaves the last certificate observation intact.
            self.publish("starting", vec![("certificate_issue", issue.clone()),
                ("certificate_retry_at", event.get("retry_at").cloned().unwrap_or(Value::Null))])?;
        } else if event.get("BRIDGE_CERTIFICATE_READY") == Some(&Value::Bool(true)) && !requested_stop {
            self.publish("starting", vec![("certificate_issue", Value::Null), ("certificate_retry_at", Value::Null)])?;
        } else if truthy(event.get("BACKEND_LOST")) {
            self.publish("restoring", vec![("reason", json!("backend health failed"))])?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
