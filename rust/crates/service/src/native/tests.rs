use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[test]
fn run_service_arguments_parse_like_argparse() {
    let parsed = parse_args(&strings(&["--config", "/pkg/config.json", "--launch-services", "--recover-backend",
        "--until-stopped", "--service-log", "/base/logs/service.log", "--service-state", "/base/service.json"])).unwrap();
    assert_eq!(parsed, NativeArgs { config: Some("/pkg/config.json".into()), seconds: None, until_stopped: true,
        launch_services: true, recover_backend: true, manage_usb: false,
        service_log: Some("/base/logs/service.log".into()), service_state: Some("/base/service.json".into()) });
    let legacy = parse_args(&strings(&["--manage-usb", "--seconds=60", "--config=/c.json"])).unwrap();
    assert!(legacy.manage_usb);
    assert_eq!(legacy.seconds, Some(60));
    assert_eq!(legacy.config.as_deref(), Some("/c.json"));
    assert_eq!(parse_args(&strings(&["--seconds", "30", "--until-stopped"])), Err(2));
    assert_eq!(parse_args(&strings(&["--seconds", "soon"])), Err(2));
    assert_eq!(parse_args(&strings(&["--bogus"])), Err(2));
    assert_eq!(parse_args(&strings(&["extra"])), Err(2));
    assert_eq!(parse_args(&strings(&["--config"])), Err(2));
}

/// Calls recorded by the fake hooks, in order.
#[derive(Default)]
struct Calls {
    log: Mutex<Vec<String>>,
    events: Mutex<Vec<Value>>,
    relaunches: AtomicUsize,
}

impl Calls {
    fn push(&self, name: &str) {
        self.log.lock().unwrap().push(name.into());
    }
    fn names(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
    fn count(&self, name: &str) -> usize {
        self.names().iter().filter(|n| *n == name).count()
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    calls: Arc<Calls>,
    hooks: NativeHooks,
}

impl Fixture {
    /// A package root with fixture adapters, an empty home and fakes for
    /// every system observation; `wait` decides whether startup continues.
    fn new(wait: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = mirra_core::paths::resolve(temp.path());
        std::fs::write(root.join("config.json"), "{}").unwrap();
        std::fs::create_dir(root.join("build")).unwrap();
        for name in ["sockets.dylib", "media.dylib", "keystore.dylib", "launch.dylib"] {
            std::fs::write(root.join("build").join(name), b"fixture").unwrap();
        }
        let calls = Arc::new(Calls::default());
        let c = calls.clone();
        let hooks = NativeHooks {
            root: root.clone(),
            home: root.clone(),
            emit: { let c = c.clone(); Arc::new(move |event| c.events.lock().unwrap().push(event.clone())) },
            recover_launch: { let c = c.clone(); Arc::new(move || { c.push("recover"); Ok(None) }) },
            mirroring_running: { let c = c.clone(); Arc::new(move || { c.push("running"); Ok(false) }) },
            supported_app: { let c = c.clone(); Arc::new(move |app| { assert_eq!(app, Path::new(SYSTEM_APP)); c.push("app"); Ok(true) }) },
            codesign: Arc::new(|_| Ok(())),
            media_profile: { let c = c.clone(); Arc::new(move |_| { c.push("media"); Ok(json!({"profile": "fixture"})) }) },
            wait_for_exit: { let c = c.clone(); Arc::new(move |_, _, _| { c.push("wait"); Ok(wait) }) },
            quit_mirroring: { let c = c.clone(); Arc::new(move || { c.push("quit"); Ok(false) }) },
            relaunch: { let c = c.clone(); Arc::new(move || { c.relaunches.fetch_add(1, Ordering::SeqCst); Ok(true) }) },
            require_container: { let c = c.clone(); Arc::new(move |path| { c.push("container"); startup::require_container(path) }) },
            start_backend: Arc::new(|_, _, _| Err(Error::runtime("simulated backend startup failure"))),
            digest: Arc::new(|_| Ok("0".repeat(64))),
        };
        Fixture { _temp: temp, root, calls, hooks }
    }

    fn args(&self, launch_services: bool, service_state: bool) -> NativeArgs {
        NativeArgs { config: Some(util::text(&self.root.join("config.json"))), until_stopped: true,
            launch_services, recover_backend: launch_services,
            service_state: service_state.then(|| util::text(&self.root.join("service.json"))), ..Default::default() }
    }

    fn container(&self) -> PathBuf {
        self.root.join("Library/Containers/com.apple.ScreenContinuity/Data/tmp")
    }

    fn events(&self, key: &str) -> Vec<Value> {
        self.calls.events.lock().unwrap().iter().filter(|e| e.get(key).is_some()).cloned().collect()
    }
}

#[test]
fn native_recovers_abandoned_apps_before_waiting_or_preparing() {
    for continued in [false, true] {
        let f = Fixture::new(continued);
        let result = run_session(&f.args(true, true), &Event::new(), &f.hooks);
        if continued {
            // No container exists in the fixture home: startup pauses there.
            match result {
                Err(SessionError::Startup(error)) => assert_eq!(error.code, "container_missing"),
                other => panic!("unexpected {:?}", other),
            }
            assert_eq!(f.calls.names(), ["recover", "app", "media", "wait", "container"]);
        } else {
            assert_eq!(result.unwrap(), 0);
            assert_eq!(f.calls.names(), ["recover", "app", "media", "wait"]);
        }
        // A managed startup never asks whether the app is open: it waits instead.
        assert_eq!(f.calls.count("running"), 0);
        let stages: Vec<Value> = f.events("NATIVE_STARTUP_STAGE").iter().map(|e| e["NATIVE_STARTUP_STAGE"].clone()).collect();
        assert_eq!(stages, [json!("recovered_launch_agent"), json!("verified_host")]);
        assert!(!f.root.join("runtime").exists());
    }
}

#[test]
fn plain_cli_keeps_existing_open_app_guard() {
    let mut f = Fixture::new(true);
    let c = f.calls.clone();
    f.hooks.mirroring_running = Arc::new(move || { c.push("running"); Ok(true) });
    match run_session(&f.args(true, false), &Event::new(), &f.hooks) {
        Err(SessionError::Exit(2)) => {}
        other => panic!("unexpected {:?}", other),
    }
    assert_eq!(f.calls.names(), ["recover", "running"]);
}

#[test]
fn recovery_requires_launch_services_and_the_system_app() {
    let f = Fixture::new(true);
    let mut args = f.args(false, false);
    args.recover_backend = true;
    assert!(matches!(run_session(&args, &Event::new(), &f.hooks), Err(SessionError::Exit(2))));
    std::fs::write(f.root.join("config.json"), r#"{"host": {"system_app": "/Applications/Other.app"}}"#).unwrap();
    assert!(matches!(run_session(&f.args(true, true), &Event::new(), &f.hooks), Err(SessionError::Exit(2))));
    std::fs::write(f.root.join("config.json"), "{}").unwrap();
    std::fs::remove_file(f.root.join("build/launch.dylib")).unwrap();
    assert!(matches!(run_session(&f.args(true, true), &Event::new(), &f.hooks), Err(SessionError::Exit(2))));
    assert_eq!(f.calls.count("wait"), 0);
}

#[test]
fn an_open_app_is_quit_once_and_marked_for_reopening() {
    for quit in [true, false] {
        let mut f = Fixture::new(false);
        let c = f.calls.clone();
        f.hooks.quit_mirroring = Arc::new(move || { c.push("quit"); Ok(quit) });
        let c = f.calls.clone();
        f.hooks.wait_for_exit = Arc::new(move |_, state, quit_app| {
            assert!(state.ends_with("service.json"));
            c.push("wait");
            quit_app()?;
            Ok(false)
        });
        assert_eq!(run_session(&f.args(true, true), &Event::new(), &f.hooks).unwrap(), 0);
        assert_eq!(f.calls.count("quit"), 1);
        let quits = f.events("NATIVE_MIRRORING_QUIT");
        if quit {
            assert_eq!(quits, [json!({"NATIVE_MIRRORING_QUIT": true, "relaunch_after_ready": true})]);
        } else {
            assert!(quits.is_empty());
        }
    }
}

#[test]
fn a_failed_quit_reaches_the_wait_as_an_error() {
    let mut f = Fixture::new(false);
    f.hooks.quit_mirroring = Arc::new(|| Err(mirra_core::Error::os_message(libc::EIO, "Could not list iPhone Mirroring processes")));
    let seen = Arc::new(Mutex::new(None));
    let s = seen.clone();
    f.hooks.wait_for_exit = Arc::new(move |_, _, quit_app| {
        *s.lock().unwrap() = Some(quit_app().unwrap_err().is_os_error());
        Ok(false)
    });
    assert_eq!(run_session(&f.args(true, true), &Event::new(), &f.hooks).unwrap(), 0);
    assert_eq!(*seen.lock().unwrap(), Some(true));
    assert!(f.events("NATIVE_MIRRORING_QUIT").is_empty());
}

#[test]
fn the_quit_app_is_reopened_once_after_backend_readiness() {
    let relaunches = AtomicUsize::new(0);
    let relaunch = || { relaunches.fetch_add(1, Ordering::SeqCst); Ok(true) };
    let events = Mutex::new(Vec::new());
    let emit = |event: &Value| events.lock().unwrap().push(event.clone());
    let mut record = Map::new();
    let mut reopen = false;
    reopen_when_ready(&mut reopen, true, true, &relaunch, &mut record, &emit);
    assert_eq!(relaunches.load(Ordering::SeqCst), 0);
    reopen = true;
    reopen_when_ready(&mut reopen, false, true, &relaunch, &mut record, &emit);
    reopen_when_ready(&mut reopen, true, false, &relaunch, &mut record, &emit);
    assert_eq!(relaunches.load(Ordering::SeqCst), 0);
    assert!(record.is_empty());
    reopen_when_ready(&mut reopen, true, true, &relaunch, &mut record, &emit);
    reopen_when_ready(&mut reopen, true, true, &relaunch, &mut record, &emit);
    assert_eq!(relaunches.load(Ordering::SeqCst), 1);
    assert!(!reopen);
    assert_eq!(record["mirroring_relaunched"], true);
    assert_eq!(*events.lock().unwrap(), [json!({"NATIVE_MIRRORING_RELAUNCHED": true})]);
    // A failed `open` is recorded, never retried.
    let failing = || Err(mirra_core::Error::os_message(libc::EIO, "open failed"));
    let mut reopen = true;
    reopen_when_ready(&mut reopen, true, true, &failing, &mut record, &emit);
    assert!(!reopen);
    assert_eq!(record["mirroring_relaunched"], false);
}

fn prepare_container(f: &Fixture) {
    std::fs::create_dir_all(f.container()).unwrap();
}

#[test]
fn native_cleanup_failure_does_not_look_like_a_requested_stop() {
    let f = Fixture::new(true);
    prepare_container(&f);
    let requested = Event::new();
    let args = f.args(false, true);
    assert_eq!(run_session(&args, &requested, &f.hooks).unwrap(), 1);
    assert!(!requested.is_set());
    assert_eq!(std::fs::read_dir(f.container()).unwrap().count(), 0);
    let state = util::read_json(&f.root.join("service.json")).unwrap();
    assert_eq!(state["phase"], "stopped");
    let run = PathBuf::from(state["directory"].as_str().unwrap());
    assert!(run.file_name().unwrap().to_string_lossy().starts_with("native-"));
    let result = util::read_json(&run.join("result.json")).unwrap();
    assert_eq!(result["error"], "simulated backend startup failure");
    assert_eq!(result["executable_unchanged"], true);
    assert!(result.get("backend_cleanup").is_none());
    assert_eq!(std::fs::read(run.join("keystore.dylib")).unwrap(), b"fixture");
    // Not retired: the backend never verified its cleanup.
    let marker = util::read_json(&run.join(".runtime-retention.json")).unwrap();
    assert_eq!(marker["retired"], false);
    assert_eq!(f.events("NATIVE_SESSION_ERROR").len(), 1);
    assert_eq!(f.events("NATIVE_SESSION_ENDED").len(), 1);
}

struct EndedBackend(Arc<AtomicUsize>);

impl Backend for EndedBackend {
    fn snapshot(&self) -> Map<String, Value> {
        json!({"phase": "failed", "ready": false}).as_object().unwrap().clone()
    }
    fn close(&mut self) -> Map<String, Value> {
        self.0.fetch_add(1, Ordering::SeqCst);
        json!({"phase": "failed", "exit_code": 1, "cleanup_error": null, "cleanup_verified": true}).as_object().unwrap().clone()
    }
}

#[test]
fn a_backend_ending_before_readiness_is_closed_and_reported() {
    let mut f = Fixture::new(true);
    prepare_container(&f);
    let closed = Arc::new(AtomicUsize::new(0));
    let c = closed.clone();
    f.hooks.start_backend = Arc::new(move |config, directory, recover| {
        assert!(!recover);
        assert_eq!(config.runtime_directory, directory);
        Ok(Box::new(EndedBackend(c.clone())))
    });
    assert_eq!(run_session(&f.args(false, true), &Event::new(), &f.hooks).unwrap(), 1);
    assert_eq!(closed.load(Ordering::SeqCst), 1);
    let state = util::read_json(&f.root.join("service.json")).unwrap();
    let result = util::read_json(&PathBuf::from(state["directory"].as_str().unwrap()).join("result.json")).unwrap();
    assert_eq!(result["error"], "Backend ended before readiness; inspect backend-status.json and its attempt log");
    assert_eq!(result["backend_exit_code"], 1);
    assert_eq!(result["backend_cleanup"]["cleanup_verified"], true);
    assert_eq!(std::fs::read_dir(f.container()).unwrap().count(), 0);
}
