//! Keep failed login-service startup from becoming a privacy-prompt loop
//! (port of `scripts/startup.py`).
use std::fmt;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use mirra_core::event::Event;
use mirra_core::lifetime::emit_event;
use mirra_core::processes::{Birth, NativeAppObserver};
use mirra_core::state::write_state;
use mirra_core::subprocess::{self, Completed, RunOptions};
use mirra_core::{sys, Error, Result};
use serde_json::{json, Map, Value};

use crate::util::{self, birth_value};

pub const MIRRORING_EXECUTABLE: &str = "/System/Applications/iPhone Mirroring.app/Contents/MacOS/iPhone Mirroring";
pub const MIRRORING_BUNDLE: &str = "com.apple.ScreenContinuity";

/// `StartupError(code, message)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartupError {
    pub code: String,
    pub message: String,
}

impl StartupError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        StartupError { code: code.into(), message: message.into() }
    }
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StartupError {}

/// What a session (or a startup step) can raise: `StartupError`, any other
/// exception, or `SystemExit(code)`.
#[derive(Debug)]
pub enum SessionError {
    Startup(StartupError),
    Error(Error),
    Exit(i32),
}

impl SessionError {
    pub fn type_name(&self) -> String {
        match self {
            SessionError::Startup(_) => "StartupError".into(),
            SessionError::Error(e) => e.type_name(),
            SessionError::Exit(_) => "SystemExit".into(),
        }
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::Startup(e) => e.fmt(f),
            SessionError::Error(e) => e.fmt(f),
            SessionError::Exit(code) => write!(f, "{}", code),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<StartupError> for SessionError {
    fn from(e: StartupError) -> Self {
        SessionError::Startup(e)
    }
}
impl From<Error> for SessionError {
    fn from(e: Error) -> Self {
        SessionError::Error(e)
    }
}
impl From<io::Error> for SessionError {
    fn from(e: io::Error) -> Self {
        SessionError::Error(e.into())
    }
}
impl From<crate::decoder_route::RouteError> for SessionError {
    fn from(e: crate::decoder_route::RouteError) -> Self {
        SessionError::Error(e.into())
    }
}

/// Runs `pgrep`-style commands with a timeout (replaceable for tests).
pub type Runner<'a> = &'a dyn Fn(&[String], Duration) -> Result<Completed>;

fn run_command(command: &[String], timeout: Duration) -> Result<Completed> {
    subprocess::run(command, &RunOptions::new().capture().timeout(timeout))
}

fn pgrep() -> Vec<String> {
    vec!["pgrep".into(), "-x".into(), "iPhone Mirroring".into()]
}

/// True when an `iPhone Mirroring` process exists; any failed observation
/// is `mirroring_observation_failed`.
pub fn mirroring_running() -> Result<bool, StartupError> {
    mirroring_running_with(&run_command)
}

pub fn mirroring_running_with(run: Runner) -> Result<bool, StartupError> {
    let failed = || StartupError::new("mirroring_observation_failed", "Could not check whether iPhone Mirroring is open");
    let result = run(&pgrep(), Duration::from_secs(5)).map_err(|_| failed())?;
    if result.code != 0 && result.code != 1 {
        return Err(failed());
    }
    Ok(result.code == 0)
}

/// Hooks for [`quit_mirroring_with`].
pub struct QuitHooks<'a> {
    pub run: Runner<'a>,
    /// `NativeAppObserver.identity` for the system executable.
    pub identity: &'a dyn Fn(i32) -> Result<Option<(i32, u64, u64)>>,
    pub kill: &'a dyn Fn(i32, i32) -> io::Result<()>,
    pub interval: Duration,
}

/// Quit this user's original iPhone Mirroring app; true when one was running
/// and is gone. Only this user's processes running Apple's system executable
/// are signalled (SIGTERM, then SIGKILL).
pub fn quit_mirroring(term_seconds: f64, kill_seconds: f64) -> Result<bool> {
    let observer = NativeAppObserver::new(MIRRORING_EXECUTABLE, "");
    let identity = |pid: i32| observer.identity(pid);
    let kill = |pid: i32, signal: i32| {
        if unsafe { libc::kill(pid, signal) } < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    };
    quit_mirroring_with(term_seconds, kill_seconds,
        &QuitHooks { run: &run_command, identity: &identity, kill: &kill, interval: Duration::from_millis(100) })
}

pub fn quit_mirroring_with(term_seconds: f64, kill_seconds: f64, hooks: &QuitHooks) -> Result<bool> {
    let running = || -> Result<Vec<i32>> {
        let result = (hooks.run)(&pgrep(), Duration::from_secs(5))?;
        if result.code != 0 && result.code != 1 {
            return Err(Error::os_message(libc::EIO, "Could not list iPhone Mirroring processes"));
        }
        let mut pids = Vec::new();
        for value in result.stdout_text().split_whitespace() {
            if !util::is_decimal(value) {
                continue;
            }
            let Ok(pid) = value.parse::<i32>() else { continue };
            if (hooks.identity)(pid)?.is_some() {
                pids.push(pid);
            }
        }
        Ok(pids)
    };
    if running()?.is_empty() {
        return Ok(false);
    }
    for (signal, seconds) in [(libc::SIGTERM, term_seconds), (libc::SIGKILL, kill_seconds)] {
        for pid in running()? {
            match (hooks.kill)(pid, signal) {
                Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
                Err(e) => return Err(e.into()),
                Ok(()) => {}
            }
        }
        let deadline = Instant::now() + Duration::from_secs_f64(seconds);
        while Instant::now() < deadline {
            if running()?.is_empty() {
                return Ok(true);
            }
            std::thread::sleep(hooks.interval);
        }
    }
    Ok(false)
}

/// Reopen the app through LaunchServices so the support launch hooks apply.
pub fn relaunch_mirroring() -> Result<bool> {
    let result = subprocess::run(&["/usr/bin/open", "-b", MIRRORING_BUNDLE],
        &RunOptions::new().capture().timeout(Duration::from_secs(20)))?;
    Ok(result.code == 0)
}

fn read_state(path: &Path) -> Result<Map<String, Value>> {
    util::object(util::read_json(path)?, "Support state must be a JSON object")
}

/// Callback asked once to quit an open app (`quit_app`).
pub type QuitApp<'a> = &'a mut dyn FnMut() -> Result<()>;

/// Wait before session mutations, without retrying failed preparation.
/// With `quit_app`, an open app is asked to quit once instead of waiting for
/// the user; if that fails, the wait continues as before.
pub fn wait_for_mirroring_exit(stop: &Event, state_path: &Path, quit_app: Option<QuitApp>) -> Result<bool, SessionError> {
    let birth = mirra_core::processes::process_birth(util::own_pid())?;
    wait_for_mirroring_exit_with(stop, state_path, quit_app, &mirroring_running, birth)
}

pub fn wait_for_mirroring_exit_with(stop: &Event, state_path: &Path, mut quit_app: Option<QuitApp>,
    observe: &dyn Fn() -> Result<bool, StartupError>, birth: Option<Birth>) -> Result<bool, SessionError> {
    let birth = birth_value(&birth);
    let phase = |value: &str| -> Result<(), SessionError> {
        let mut state = read_state(state_path)?;
        if state.get("supervisor_birth") != Some(&birth) || birth.is_null() || state.contains_key("directory") {
            return Err(Error::runtime("Support state changed owners or session preparation already began").into());
        }
        state.insert("phase".into(), Value::from(value));
        write_state(state_path, &Value::Object(state))?;
        Ok(())
    };
    let mut waiting = false;
    while !stop.is_set() {
        if !observe()? {
            if waiting {
                // Restore the failure latch before any recovery or preparation.
                phase("startup_checks")?;
                let _ = emit_event(&json!({"NATIVE_STARTUP_RESUMED": true}));
            }
            return Ok(!stop.is_set());
        }
        if !waiting {
            phase("waiting_for_mirroring_exit")?;
            let _ = emit_event(&json!({"NATIVE_STARTUP_WAITING": "Quit iPhone Mirroring to continue"}));
            waiting = true;
            if let Some(quit) = quit_app.as_mut() {
                if let Err(error) = quit() {
                    if !(error.is_os_error() || error.is_subprocess_error()) {
                        return Err(error.into());
                    }
                    let _ = emit_event(&json!({"NATIVE_MIRRORING_QUIT_FAILED": error.type_name()}));
                }
                continue;
            }
        }
        stop.wait(Some(Duration::from_millis(500)));
    }
    Ok(false)
}

/// Keep a denied request distinct from a system app that has never created
/// its container: EACCES/EPERM → `container_access_denied`, missing or not a
/// directory → `container_missing`; other errors propagate.
pub fn require_container(path: &Path) -> Result<(), SessionError> {
    let missing = || StartupError::new("container_missing",
        "Open and quit Apple\u{2019}s iPhone Mirroring once to initialize its container");
    match sys::stat(path) {
        Ok(info) if sys::is_dir(info.st_mode) => Ok(()),
        Ok(_) => Err(missing().into()),
        Err(e) => match e.raw_os_error() {
            Some(libc::EACCES) | Some(libc::EPERM) => Err(StartupError::new("container_access_denied",
                "macOS denied access to the iPhone Mirroring temporary directory").into()),
            Some(libc::ENOENT) => Err(missing().into()),
            _ => Err(Error::with_path(e, path).into()),
        },
    }
}

// ----------------------------------------------------------- signal handling

static SIGNAL_PIPE: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_signal(_: libc::c_int) {
    let fd = SIGNAL_PIPE.load(Ordering::SeqCst);
    if fd >= 0 {
        let byte = 1u8;
        unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) };
    }
}

/// SIGINT/SIGTERM set `stop` while installed; previous handlers are restored
/// on drop (`signal.signal(sig, lambda *_: stop.set())`).
struct SignalGuard {
    previous: Vec<(libc::c_int, libc::sigaction)>,
    writer: libc::c_int,
    thread: Option<JoinHandle<()>>,
}

impl SignalGuard {
    fn install(stop: &Event) -> Result<Self> {
        let mut fds = [0; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
        for fd in fds {
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        }
        let (reader, writer) = (fds[0], fds[1]);
        let flag = stop.clone();
        let thread = std::thread::Builder::new().name("service-signals".into()).spawn(move || {
            let mut buffer = [0u8; 16];
            loop {
                let n = unsafe { libc::read(reader, buffer.as_mut_ptr().cast(), buffer.len()) };
                if n < 0 && sys::errno() == libc::EINTR {
                    continue;
                }
                if n <= 0 {
                    break;
                }
                flag.set();
            }
            unsafe { libc::close(reader) };
        })?;
        SIGNAL_PIPE.store(writer, Ordering::SeqCst);
        let mut previous = Vec::new();
        for signal in [libc::SIGINT, libc::SIGTERM] {
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = on_signal as *const () as usize;
                action.sa_flags = libc::SA_RESTART;
                libc::sigemptyset(&mut action.sa_mask);
                let mut old: libc::sigaction = std::mem::zeroed();
                libc::sigaction(signal, &action, &mut old);
                previous.push((signal, old));
            }
        }
        Ok(SignalGuard { previous, writer, thread: Some(thread) })
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        for (signal, old) in &self.previous {
            unsafe { libc::sigaction(*signal, old, std::ptr::null_mut()) };
        }
        SIGNAL_PIPE.store(-1, Ordering::SeqCst);
        unsafe { libc::close(self.writer) };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "panic".into()
    }
}

/// Run one session in this process, then wait for an explicit stop.
///
/// Launchd KeepAlive must not spawn a new requesting process after a denied
/// permission or failed startup. Waiting here performs no container access
/// or retry. Returns 0 after a stop.
pub fn run_service<F>(session: F, state_path: &Path, stop: Option<Event>) -> Result<i32>
where F: FnOnce(&Event) -> Result<i32, SessionError> {
    let stop = stop.unwrap_or_default();
    let birth = birth_value(&mirra_core::processes::process_birth(util::own_pid())?);
    let previous = if state_path.exists() { read_state(state_path)? } else { Map::new() };
    let phase = previous.get("phase").and_then(Value::as_str);
    // Waiting for an app to quit performs no session mutations or privacy
    // requests, so only that pre-preparation wait may resume after abrupt death.
    let interrupted = matches!(phase, Some("startup_checks" | "preparing" | "startup_failed"))
        || (phase == Some("waiting_for_mirroring_exit") && previous.contains_key("directory"));
    let mut state = Map::new();
    state.insert("phase".into(), Value::from("startup_checks"));
    state.insert("supervisor_birth".into(), birth.clone());
    if interrupted {
        if let Some(directory) = previous.get("directory") {
            state.insert("directory".into(), directory.clone());
        }
    }
    write_state(state_path, &Value::Object(state))?;
    let _signals = SignalGuard::install(&stop)?;
    let mut code = "support_startup_failed".to_string();
    let outcome = if interrupted {
        Err(SessionError::Startup(StartupError::new("startup_interrupted",
            "The previous startup ended before completion; automatic retry is paused")))
    } else {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| session(&stop))) {
            Ok(result) => result,
            Err(payload) => Err(SessionError::Error(Error::runtime(format!("panic: {}", panic_text(&*payload))))),
        }
    };
    let message = match outcome {
        Ok(status) => format!("Native support ended with status {}", status),
        Err(SessionError::Startup(error)) => {
            code = error.code.clone();
            error.message
        }
        Err(SessionError::Error(error)) if error.is_os_error() && matches!(error.errno(), Some(libc::EACCES | libc::EPERM)) => {
            code = "support_access_denied".into();
            error.to_string()
        }
        Err(SessionError::Error(Error::Runtime(text))) if text.starts_with("panic: ") => text,
        Err(SessionError::Error(error)) => format!("{}: {}", error.type_name(), error),
        Err(SessionError::Exit(status)) => format!("SystemExit: {}", status),
    };
    // Retain the session directory and its cleanup evidence, if one exists.
    let mut current = read_state(state_path)?;
    if current.get("supervisor_birth") != Some(&birth) || birth.is_null() {
        return Err(Error::runtime("Support state changed owners during startup"));
    }
    if !stop.is_set() {
        current.insert("phase".into(), Value::from("startup_failed"));
        current.insert("startup_failure".into(), Value::from(code.clone()));
        write_state(state_path, &Value::Object(current.clone()))?;
        let _ = emit_event(&json!({"NATIVE_STARTUP_PAUSED": true, "reason": code, "error": message}));
        stop.wait(None);
    }
    // A deliberate stop rearms startup. An abrupt death while checking
    // prerequisites leaves the marker, so launchd's next run pauses first.
    current.insert("phase".into(), Value::from("stopped"));
    if !current.contains_key("directory") {
        current.insert("startup_cleanup_verified".into(), Value::from(true));
    }
    write_state(state_path, &Value::Object(current))?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};

    fn completed(code: i32, stdout: &str) -> Result<Completed> {
        Ok(Completed { args: vec![], code, stdout: stdout.as_bytes().to_vec(), stderr: vec![] })
    }

    fn birth() -> Option<Birth> {
        Some((42, 0, 0, 0))
    }

    fn state_json(birth: i64, extra: Value) -> Value {
        let mut value = json!({"phase": "startup_checks", "supervisor_birth": [birth, 0, 0, 0]});
        for (k, v) in extra.as_object().unwrap() {
            value[k] = v.clone();
        }
        value
    }

    #[test]
    fn process_observation_distinguishes_absent_from_failed() {
        for (code, expected) in [(0, true), (1, false)] {
            let seen = Cell::new(Duration::ZERO);
            let run = |_: &[String], timeout: Duration| { seen.set(timeout); completed(code, "") };
            assert_eq!(mirroring_running_with(&run), Ok(expected));
            assert_eq!(seen.get(), Duration::from_secs(5));
        }
        let failures: Vec<Box<dyn Fn() -> Result<Completed>>> = vec![
            Box::new(|| Err(Error::os_message(libc::EIO, "failed"))),
            Box::new(|| Err(Error::TimeoutExpired { command: vec!["pgrep".into()], timeout: Duration::from_secs(5), stdout: vec![], stderr: vec![] })),
            Box::new(|| completed(2, "")),
        ];
        for failure in failures {
            let run = |_: &[String], _: Duration| failure();
            assert_eq!(mirroring_running_with(&run).unwrap_err().code, "mirroring_observation_failed");
        }
    }

    #[test]
    fn wait_cannot_overwrite_another_owner_or_a_prepared_session() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state.json");
        for data in [state_json(43, json!({})), state_json(42, json!({"directory": "native-example"}))] {
            write_state(&state, &data).unwrap();
            let before = std::fs::read(&state).unwrap();
            let error = wait_for_mirroring_exit_with(&Event::new(), &state, None, &|| Ok(true), birth()).unwrap_err();
            assert!(matches!(error, SessionError::Error(Error::Runtime(_))));
            assert_eq!(std::fs::read(&state).unwrap(), before);
        }
    }

    #[test]
    fn wait_quits_an_open_app_once_and_continues() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state.json");
        write_state(&state, &state_json(42, json!({}))).unwrap();
        let open = Cell::new(true);
        let calls = Cell::new(0);
        let mut quit = || { calls.set(calls.get() + 1); open.set(false); Ok(()) };
        assert!(wait_for_mirroring_exit_with(&Event::new(), &state, Some(&mut quit), &|| Ok(open.get()), birth()).unwrap());
        assert_eq!(calls.get(), 1);
        assert_eq!(util::read_json(&state).unwrap()["phase"], "startup_checks");
    }

    #[test]
    fn failed_quit_falls_back_to_waiting_for_the_user() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state.json");
        write_state(&state, &state_json(42, json!({}))).unwrap();
        let checks = RefCell::new(vec![true, true, false].into_iter());
        let calls = Cell::new(0);
        let mut quit = || { calls.set(calls.get() + 1); Err(Error::os_message(libc::EACCES, "denied")) };
        let observe = || Ok(checks.borrow_mut().next().unwrap());
        assert!(wait_for_mirroring_exit_with(&Event::new(), &state, Some(&mut quit), &observe, birth()).unwrap());
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn stop_before_wait_does_not_observe_app() {
        let stop = Event::new();
        stop.set();
        let observe = || -> Result<bool, StartupError> { panic!("must not observe") };
        assert!(!wait_for_mirroring_exit_with(&stop, Path::new("/nonexistent"), None, &observe, birth()).unwrap());
    }

    #[test]
    fn quit_mirroring_signals_only_verified_apps() {
        let alive = Cell::new(true);
        let kills = RefCell::new(Vec::new());
        let run = |_: &[String], _: Duration| completed(0, "101 202\n");
        let identity = |pid: i32| Ok(if pid == 101 && alive.get() { Some((pid, 1, 2)) } else { None });
        let kill = |pid: i32, signal: i32| { kills.borrow_mut().push((pid, signal)); alive.set(false); Ok(()) };
        let hooks = QuitHooks { run: &run, identity: &identity, kill: &kill, interval: Duration::from_millis(1) };
        assert!(quit_mirroring_with(1.0, 1.0, &hooks).unwrap());
        assert_eq!(*kills.borrow(), vec![(101, libc::SIGTERM)]);
        let none = |_: i32| Ok(None);
        let refuse = |_: i32, _: i32| -> io::Result<()> { panic!("must not signal") };
        let hooks = QuitHooks { run: &run, identity: &none, kill: &refuse, interval: Duration::from_millis(1) };
        assert!(!quit_mirroring_with(6.0, 3.0, &hooks).unwrap());
    }

    #[test]
    fn denied_access_is_distinct_from_missing_container() {
        let temp = tempfile::tempdir().unwrap();
        let locked = temp.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::create_dir(locked.join("tmp")).unwrap();
        util::chmod(&locked, 0o000).unwrap();
        let denied = require_container(&locked.join("tmp"));
        util::chmod(&locked, 0o700).unwrap();
        match denied {
            Err(SessionError::Startup(e)) => assert_eq!(e.code, "container_access_denied"),
            other => panic!("unexpected {:?}", other),
        }
        match require_container(&temp.path().join("missing")) {
            Err(SessionError::Startup(e)) => assert_eq!(e.code, "container_missing"),
            other => panic!("unexpected {:?}", other),
        }
    }

    #[test]
    fn existing_container_and_non_directory() {
        let temp = tempfile::tempdir().unwrap();
        require_container(temp.path()).unwrap();
        let file = temp.path().join("file");
        std::fs::write(&file, "").unwrap();
        match require_container(&file) {
            Err(SessionError::Startup(e)) => assert_eq!(e.code, "container_missing"),
            other => panic!("unexpected {:?}", other),
        }
    }

    // ---- Real child processes: the test binary re-runs `child_entry` with a
    // scenario, so failures retain one PID without rerunning the session and
    // SIGTERM permits a deliberate fresh start.

    const SCENARIO: &str = "MIRRA_STARTUP_TEST_SCENARIO";
    const ROOT: &str = "MIRRA_STARTUP_TEST_ROOT";

    fn child_session(scenario: &str, root: &Path, state: &Path, stop: &Event) -> Result<i32, SessionError> {
        use std::io::Write;
        std::fs::OpenOptions::new().create(true).append(true).open(root.join("calls")).unwrap().write_all(b"attempt\n").unwrap();
        let app = root.join("app-open");
        let waiting = |stop: &Event| -> Result<i32, SessionError> {
            let observe = || Ok(app.exists());
            let birth = mirra_core::processes::process_birth(util::own_pid()).unwrap();
            if !wait_for_mirroring_exit_with(stop, state, None, &observe, birth)? {
                return Ok(0);
            }
            let mut data = read_state(state)?;
            assert_eq!(data["phase"], "startup_checks");
            data.insert("phase".into(), json!("preparing"));
            data.insert("directory".into(), json!("native-example"));
            write_state(state, &Value::Object(data))?;
            stop.wait(None);
            Ok(0)
        };
        let update = |phase: &str| -> Result<(), SessionError> {
            let mut data = read_state(state)?;
            data.insert("phase".into(), json!(phase));
            data.insert("directory".into(), json!("native-example"));
            write_state(state, &Value::Object(data))?;
            Ok(())
        };
        match scenario {
            "startup_error" => Err(StartupError::new("container_access_denied", "denied").into()),
            "permission" => Err(Error::os_message(libc::EACCES, "denied during mkdir").into()),
            "exit" => Err(SessionError::Exit(2)),
            "runtime" => Err(Error::runtime("later startup failed").into()),
            "status" => Ok(1),
            "waiting" => waiting(stop),
            "must_not_run" => Err(Error::runtime("must not run").into()),
            "observation_failure" => {
                let run = |_: &[String], _: Duration| -> Result<Completed> { Err(Error::os_message(libc::EIO, "failed")) };
                let observe = || mirroring_running_with(&run);
                let birth = mirra_core::processes::process_birth(util::own_pid()).unwrap();
                wait_for_mirroring_exit_with(stop, state, None, &observe, birth)?;
                Err(Error::runtime("must not prepare").into())
            }
            "wait_stop" => {
                stop.wait(None);
                Ok(0)
            }
            "managed" => {
                update("stopped")?;
                Ok(1)
            }
            "preparing" => {
                update("preparing")?;
                stop.wait(None);
                Ok(0)
            }
            other => panic!("unknown scenario {}", other),
        }
    }

    #[test]
    fn child_entry() {
        let (Ok(scenario), Ok(root)) = (std::env::var(SCENARIO), std::env::var(ROOT)) else { return };
        let root = PathBuf::from(root);
        let state = root.join("service.json");
        let code = run_service(|stop| child_session(&scenario, &root, &state, stop), &state, None).unwrap();
        std::process::exit(code);
    }

    struct Harness {
        _temp: tempfile::TempDir,
        root: PathBuf,
        state: PathBuf,
        calls: PathBuf,
        children: Vec<Child>,
    }

    impl Harness {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().to_path_buf();
            Harness { state: root.join("service.json"), calls: root.join("calls"), root, _temp: temp, children: Vec::new() }
        }

        fn launch(&mut self, scenario: &str) -> usize {
            let child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "startup::tests::child_entry", "--nocapture", "--test-threads=1"])
                .env(SCENARIO, scenario).env(ROOT, &self.root)
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
                .spawn().unwrap();
            self.children.push(child);
            self.children.len() - 1
        }

        fn pid(&self, child: usize) -> i64 {
            self.children[child].id() as i64
        }

        fn wait_state(&mut self, child: usize, phase: &str) -> Value {
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if let Ok(data) = util::read_json(&self.state) {
                    if data["phase"] == phase && data["supervisor_birth"][0] == self.pid(child) {
                        return data;
                    }
                }
                assert!(self.children[child].try_wait().unwrap().is_none(), "Startup guard exited unexpectedly");
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("Timed out waiting for {}", phase);
        }

        fn signal(&mut self, child: usize, signal: i32) -> Option<i32> {
            unsafe { libc::kill(self.children[child].id() as i32, signal) };
            let status = self.children[child].wait().unwrap();
            status.code()
        }

        fn exits_within(&mut self, child: usize, timeout: Duration) -> bool {
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                if self.children[child].try_wait().unwrap().is_some() {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            false
        }

        fn calls(&self) -> String {
            std::fs::read_to_string(&self.calls).unwrap_or_default()
        }

        fn state(&self) -> Value {
            util::read_json(&self.state).unwrap()
        }

        fn wait_calls(&self) {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !self.calls.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            for child in &mut self.children {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    #[test]
    fn failure_types_do_not_exit_or_retry() {
        for (scenario, reason) in [("startup_error", "container_access_denied"), ("permission", "support_access_denied"),
                                   ("exit", "support_startup_failed"), ("runtime", "support_startup_failed"),
                                   ("status", "support_startup_failed")] {
            let mut h = Harness::new();
            let child = h.launch(scenario);
            let data = h.wait_state(child, "startup_failed");
            assert_eq!(data["startup_failure"], reason);
            assert!(!h.exits_within(child, Duration::from_millis(150)));
            assert_eq!(h.calls(), "attempt\n");
            assert_eq!(h.signal(child, libc::SIGTERM), Some(0));
            let stopped = h.state();
            assert_eq!(stopped["phase"], "stopped");
            assert_eq!(stopped["startup_cleanup_verified"], true);
        }
    }

    #[test]
    fn open_app_wait_continues_in_same_process_after_quit() {
        let mut h = Harness::new();
        std::fs::write(h.root.join("app-open"), "").unwrap();
        let child = h.launch("waiting");
        let waiting = h.wait_state(child, "waiting_for_mirroring_exit");
        assert!(waiting.get("directory").is_none());
        assert!(waiting.get("startup_failure").is_none());
        std::fs::remove_file(h.root.join("app-open")).unwrap();
        let prepared = h.wait_state(child, "preparing");
        assert_eq!(prepared["supervisor_birth"], waiting["supervisor_birth"]);
        assert_eq!(h.calls(), "attempt\n");
        assert_eq!(h.signal(child, libc::SIGTERM), Some(0));
    }

    #[test]
    fn stop_cancels_wait_without_preparing_a_session() {
        let mut h = Harness::new();
        std::fs::write(h.root.join("app-open"), "").unwrap();
        let child = h.launch("waiting");
        h.wait_state(child, "waiting_for_mirroring_exit");
        assert_eq!(h.signal(child, libc::SIGTERM), Some(0));
        let state = h.state();
        assert_eq!(state["phase"], "stopped");
        assert_eq!(state["startup_cleanup_verified"], true);
        assert!(state.get("directory").is_none());
        assert!(state.get("startup_failure").is_none());
    }

    #[test]
    fn killed_app_wait_can_resume_without_rearming_permission_failures() {
        let mut h = Harness::new();
        std::fs::write(h.root.join("app-open"), "").unwrap();
        let first = h.launch("waiting");
        h.wait_state(first, "waiting_for_mirroring_exit");
        h.signal(first, libc::SIGKILL);
        let second = h.launch("waiting");
        h.wait_state(second, "waiting_for_mirroring_exit");
        std::fs::remove_file(h.root.join("app-open")).unwrap();
        h.wait_state(second, "preparing");
        assert_eq!(h.calls(), "attempt\nattempt\n");
        assert_eq!(h.signal(second, libc::SIGTERM), Some(0));
    }

    #[test]
    fn wait_marker_with_existing_preparation_cannot_discard_cleanup_evidence() {
        let mut h = Harness::new();
        write_state(&h.state, &json!({"phase": "waiting_for_mirroring_exit", "directory": "native-example",
            "supervisor_birth": [43]})).unwrap();
        let child = h.launch("must_not_run");
        let state = h.wait_state(child, "startup_failed");
        assert_eq!(state["startup_failure"], "startup_interrupted");
        assert_eq!(state["directory"], "native-example");
        assert!(!h.calls.exists());
    }

    #[test]
    fn process_observation_failure_pauses_instead_of_preparing() {
        let mut h = Harness::new();
        let child = h.launch("observation_failure");
        let state = h.wait_state(child, "startup_failed");
        assert_eq!(state["startup_failure"], "mirroring_observation_failed");
        assert!(state.get("directory").is_none());
        assert!(!h.exits_within(child, Duration::from_millis(150)));
        assert_eq!(h.calls(), "attempt\n");
    }

    #[test]
    fn killed_waiting_process_does_not_reprompt_on_launchd_restart() {
        let mut h = Harness::new();
        let first = h.launch("permission");
        h.wait_state(first, "startup_failed");
        h.signal(first, libc::SIGKILL);
        let second = h.launch("permission");
        let data = h.wait_state(second, "startup_failed");
        assert_eq!(data["startup_failure"], "startup_interrupted");
        assert_eq!(h.calls(), "attempt\n");
        h.signal(second, libc::SIGTERM);
        let third = h.launch("permission");
        h.wait_state(third, "startup_failed");
        assert_eq!(h.calls(), "attempt\nattempt\n");
    }

    #[test]
    fn crash_during_startup_is_latched_before_the_next_attempt() {
        let mut h = Harness::new();
        let first = h.launch("wait_stop");
        h.wait_state(first, "startup_checks");
        h.wait_calls();
        h.signal(first, libc::SIGKILL);
        let second = h.launch("must_not_run");
        h.wait_state(second, "startup_failed");
        assert_eq!(h.calls(), "attempt\n");
    }

    #[test]
    fn managed_session_cleanup_evidence_is_preserved() {
        let mut h = Harness::new();
        let child = h.launch("managed");
        let data = h.wait_state(child, "startup_failed");
        assert_eq!(data["directory"], "native-example");
        h.signal(child, libc::SIGKILL);
        let replacement = h.launch("must_not_run");
        let data = h.wait_state(replacement, "startup_failed");
        assert_eq!(data["directory"], "native-example");
        assert_eq!(h.calls(), "attempt\n");
        h.signal(replacement, libc::SIGTERM);
        assert!(h.state().get("startup_cleanup_verified").is_none());
    }

    #[test]
    fn crash_after_session_preparation_does_not_start_another_session() {
        let mut h = Harness::new();
        let child = h.launch("preparing");
        h.wait_state(child, "preparing");
        h.signal(child, libc::SIGKILL);
        let replacement = h.launch("must_not_run");
        let data = h.wait_state(replacement, "startup_failed");
        assert_eq!(data["startup_failure"], "startup_interrupted");
        assert_eq!(data["directory"], "native-example");
        assert_eq!(h.calls(), "attempt\n");
    }

    #[test]
    fn normal_stop_does_not_report_startup_failure() {
        let mut h = Harness::new();
        let child = h.launch("wait_stop");
        h.wait_state(child, "startup_checks");
        h.wait_calls();
        assert_eq!(h.signal(child, libc::SIGTERM), Some(0));
        let data = h.state();
        assert_eq!(data["phase"], "stopped");
        assert!(data.get("startup_failure").is_none());
    }
}
