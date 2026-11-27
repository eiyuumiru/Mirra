use super::*;
use crate::testing::{original_sharingd, FakeSharingd};
use mirra_core::config::load_config;
use mirra_core::launchctl::Reply;
use mirra_core::sys::getuid;
use mirra_keystore::sharingd::SharingdContext;
use std::sync::atomic::{AtomicUsize, Ordering};

/// sharingd with a scripted job state; counts observations.
#[derive(Default)]
struct CountingSharingd {
    state: Mutex<Map<String, Value>>,
    observed: AtomicUsize,
}

impl Sharingd for CountingSharingd {
    fn read_journal(&self) -> Result<Option<Map<String, Value>>> {
        Ok(None)
    }
    fn recover_abandoned(&self, _: bool) -> Result<Option<Value>> {
        Ok(None)
    }
    fn service(&self) -> Result<Map<String, Value>> {
        self.observed.fetch_add(1, Ordering::SeqCst);
        Ok(self.state.lock().unwrap().clone())
    }
}

fn birth(value: Option<(i32, u32, u64, u64)>) -> BirthProbe {
    Arc::new(move |_| Ok(value))
}

struct Home {
    _temp: tempfile::TempDir,
    root: PathBuf,
}

impl Home {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = mirra_core::paths::resolve(temp.path());
        Home { _temp: temp, root }
    }
}

#[test]
fn live_previous_child_prevents_retry_without_observing_sharingd() {
    let gate = Home::new();
    let identity = (123, getuid(), 50, 6);
    for child in ["broker", "sharingd"] {
        write_state(&gate.root.join("backend-children.json"), &json!({child: [123, getuid(), 50, 6]})).unwrap();
        let sharingd = CountingSharingd::default();
        let (allowed, reason) = recovery_gate(Some(&gate.root), &sharingd, &birth(Some(identity)), &gate.root).unwrap();
        assert!(!allowed);
        assert_eq!(reason.as_deref(), Some("previous backend child still running"));
        assert_eq!(sharingd.observed.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn pid_reuse_does_not_block_a_restored_session() {
    let gate = Home::new();
    write_state(&gate.root.join("backend-children.json"), &json!({"broker": [123, getuid(), 50, 6]})).unwrap();
    let sharingd = CountingSharingd { state: Mutex::new(original_sharingd()), ..Default::default() };
    let reused = birth(Some((123, getuid(), 70, 8)));
    assert_eq!(recovery_gate(Some(&gate.root), &sharingd, &reused, &gate.root).unwrap(), (true, None));
}

#[test]
fn uncertain_child_observation_does_not_authorize_restart() {
    let gate = Home::new();
    write_state(&gate.root.join("backend-children.json"), &json!({"broker": [123, getuid(), 50, 6]})).unwrap();
    let failing: BirthProbe = Arc::new(|_| Err(mirra_core::Error::os_message(libc::EIO, "observation failed")));
    assert!(recovery_gate(Some(&gate.root), &CountingSharingd::default(), &failing, &gate.root).unwrap_err().is_os_error());
}

#[test]
fn custom_or_unobservable_sharingd_defers_retry() {
    let gate = Home::new();
    let mut injected = original_sharingd();
    injected.insert("injected".into(), json!(true));
    let mut moved = original_sharingd();
    moved.insert("path".into(), json!("/tmp/com.apple.sharingd.plist"));
    for (state, expected) in [(Map::new(), "sharingd restoration not yet observable"),
                              (injected, "sharingd is not in its original configuration"),
                              (moved, "sharingd is not in its original configuration")] {
        let sharingd = CountingSharingd { state: Mutex::new(state), ..Default::default() };
        let (allowed, reason) = recovery_gate(None, &sharingd, &birth(None), &gate.root).unwrap();
        assert!(!allowed);
        assert_eq!(reason.as_deref(), Some(expected));
    }
}

#[test]
fn a_held_session_lease_means_the_controller_still_owns_sharingd() {
    let gate = Home::new();
    let _held = backend_lease(&gate.root).unwrap();
    let sharingd = CountingSharingd { state: Mutex::new(original_sharingd()), ..Default::default() };
    assert_eq!(recovery_gate(None, &sharingd, &birth(None), &gate.root).unwrap(),
        (false, Some("backend controller still owns sharingd".into())));
    assert_eq!(sharingd.observed.load(Ordering::SeqCst), 0);
}

/// A runtime directory, profile and recorded events/spawns.
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    run: PathBuf,
    config: Config,
    events: Arc<Mutex<Vec<Value>>>,
    spawns: Arc<AtomicUsize>,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = mirra_core::paths::resolve(temp.path());
        // Like Python's mkdtemp (tempfile's default mode follows the umask).
        util::chmod(&root, 0o700).unwrap();
        let run = root.join("native-test");
        std::fs::create_dir(&run).unwrap();
        util::chmod(&run, 0o700).unwrap();
        std::fs::write(run.join("keystore.dylib"), b"test fixture only").unwrap();
        std::fs::write(root.join("config.json"), "{}").unwrap();
        let config = load_config(Some(&root.join("config.json")), &root).unwrap();
        Fixture { _temp: temp, root, run, config, events: Arc::default(), spawns: Arc::default() }
    }

    /// Workers run `/bin/sh -c SCRIPT sh --config PATH --until-stopped --parent-lifeline`.
    /// `allow` replaces the recovery gate with one that always passes.
    fn hooks(&self, sharingd: Arc<dyn Sharingd>, script: &'static str, allow: bool) -> SupervisorHooks {
        let (events, spawns) = (self.events.clone(), self.spawns.clone());
        SupervisorHooks {
            child: Arc::new(move |name| {
                assert_eq!(name, "backend");
                spawns.fetch_add(1, Ordering::SeqCst);
                let mut command = Command::new("/bin/sh");
                command.args(["-c", script, "sh"]);
                command
            }),
            sharingd,
            home: self.root.clone(),
            birth: util::real_birth(),
            emit: Arc::new(move |event| events.lock().unwrap().push(event.clone())),
            gate: if allow { Some(Arc::new(|_| Ok((true, None)))) } else { None },
            retry: Duration::from_millis(20),
            worker_stop: Duration::from_secs(10),
        }
    }

    fn waiting_events(&self) -> Vec<Value> {
        self.events.lock().unwrap().iter().filter_map(|e| e.get("NATIVE_BACKEND_STATE"))
            .filter(|state| state["phase"] == "waiting_for_cleanup").cloned().collect()
    }
}

fn wait_for(backend: &NativeBackend, predicate: impl Fn(&Map<String, Value>) -> bool, seconds: u64) -> Map<String, Value> {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < deadline {
        let state = backend.snapshot();
        if predicate(&state) {
            return state;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("Backend did not reach expected state: {:?}", backend.snapshot());
}

#[test]
fn recovery_error_is_retained_without_spawning_or_repeating_the_same_event() {
    let f = Fixture::new();
    let sharingd = Arc::new(FakeSharingd {
        recover_error: Some(|| mirra_core::Error::with_path(std::io::Error::from_raw_os_error(libc::ENOENT),
            "/private/missing-runtime").into()),
        ..Default::default()
    });
    let mut backend = NativeBackend::with_hooks(f.config.clone(), &f.run, true, f.hooks(sharingd, "exit 0", false))
        .start().unwrap();
    std::thread::sleep(Duration::from_millis(150));
    let cleanup = backend.close();
    assert_eq!(f.spawns.load(Ordering::SeqCst), 0);
    let waiting = f.waiting_events();
    assert_eq!(waiting.len(), 1, "{:?}", waiting);
    assert_eq!(waiting[0]["attempt"], 0);
    assert_eq!(waiting[0]["reason"], "ownership observation deferred");
    assert_eq!(waiting[0]["observation_error"]["error_type"], "FileNotFoundError");
    assert_eq!(waiting[0]["observation_error"]["errno"], 2);
    assert!(waiting[0]["observation_error"]["error"].as_str().unwrap().contains("missing-runtime"));
    assert_eq!(cleanup["phase"], "stopped");
    assert_eq!(cleanup["cleanup_verified"], false);
    assert_eq!(cleanup["cleanup_reason"], "ownership observation deferred");
    assert_eq!(cleanup["cleanup_observation_error"]["error_type"], "FileNotFoundError");
}

#[test]
fn without_recovery_a_deferred_gate_fails_the_supervisor() {
    let f = Fixture::new();
    let sharingd = Arc::new(FakeSharingd::default());
    // No sharingd job is observable (FakeSharingd state is empty).
    let mut backend = NativeBackend::with_hooks(f.config.clone(), &f.run, false, f.hooks(sharingd, "exit 0", false))
        .start().unwrap();
    let state = wait_for(&backend, |s| s["phase"] == "failed", 5);
    assert_eq!(state["reason"], "sharingd restoration not yet observable");
    let report = backend.close();
    assert_eq!(report["cleanup_error"], "sharingd restoration not yet observable");
    assert_eq!(f.spawns.load(Ordering::SeqCst), 0);
    let persisted = util::read_json(&f.run.join("backend-status.json")).unwrap();
    assert_eq!(persisted["phase"], "failed");
}

#[test]
fn failed_observation_waits_without_starting_a_worker() {
    let f = Fixture::new();
    let mut hooks = f.hooks(Arc::new(FakeSharingd::default()), "exit 0", false);
    hooks.gate = Some(Arc::new(|_| Err(mirra_core::Error::TimeoutExpired { command: vec!["launchctl".into()],
        timeout: Duration::from_secs(5), stdout: vec![], stderr: vec![] }.into())));
    let mut backend = NativeBackend::with_hooks(f.config.clone(), &f.run, true, hooks).start().unwrap();
    let state = wait_for(&backend, |s| s["phase"] == "waiting_for_cleanup", 5);
    assert_eq!(state["observation_error"]["error_type"], "TimeoutExpired");
    assert_eq!(state["observation_error"]["errno"], Value::Null);
    backend.close();
    assert_eq!(f.spawns.load(Ordering::SeqCst), 0);
}

const CERTIFICATE_WORKER: &str = r#"
case "$2" in
  */backend-000001/config.json) echo '{"BRIDGE_CERTIFICATE_ERROR": "expired", "retry_at": 1234}' ;;
  *) echo '{"BRIDGE_CERTIFICATE_ERROR": "busy", "retry_at": null}' ;;
esac
exit 1
"#;

#[test]
fn certificate_lock_collision_preserves_the_expired_observation() {
    let f = Fixture::new();
    let hooks = f.hooks(Arc::new(FakeSharingd::default()), CERTIFICATE_WORKER, true);
    let mut backend = NativeBackend::with_hooks(f.config.clone(), &f.run, true, hooks).start().unwrap();
    let state = wait_for(&backend, |s| s["attempt"] == 2 && s["phase"] == "retry_wait", 10);
    assert_eq!(state["certificate_issue"], "expired");
    assert_eq!(state["certificate_retry_at"], 1234);
    assert_eq!(state["exit_code"], 1);
    backend.close();
}

const RETRYING_WORKER: &str = r#"
[ "$1" = --config ] && [ "$3" = --until-stopped ] && [ "$4" = --parent-lifeline ] || exit 9
echo "{\"NATIVE_WORKSPACE_READY\": true, \"controller_pid\": $$}"
case "$2" in */backend-000001/config.json) sleep 0.1; exit 7 ;; esac
trap 'exit 0' TERM
while true; do sleep 0.05; done
"#;

#[test]
fn terminal_worker_retries_and_new_worker_can_stop() {
    // A real pipe/process exercises readiness delivery and EOF.
    let f = Fixture::new();
    let hooks = f.hooks(Arc::new(FakeSharingd::default()), RETRYING_WORKER, true);
    let mut backend = NativeBackend::with_hooks(f.config.clone(), &f.run, true, hooks).start().unwrap();
    let ready = wait_for(&backend, |s| s["attempt"] == 2 && s["ready"] == true, 10);
    assert!(backend.worker().unwrap().poll().is_none());
    let persisted = util::read_json(&f.run.join("backend-status.json")).unwrap();
    assert_eq!(persisted["worker_pid"], ready["worker_pid"]);
    assert_eq!(ready["worker_birth"][0], ready["worker_pid"]);
    assert_eq!(ready["controller_pid"], ready["worker_pid"]);
    assert!(!std::fs::read_to_string(f.run.join("backend-000001/backend.log")).unwrap().trim().is_empty());
    let staged = util::read_json(&f.run.join("backend-000002/config.json")).unwrap();
    assert_eq!(staged["host"]["runtime_directory"].as_str().map(PathBuf::from), Some(f.run.join("backend-000002")));
    assert_eq!(std::fs::read(f.run.join("backend-000002/keystore.dylib")).unwrap(), b"test fixture only");
    let report = backend.close();
    assert_eq!(report["cleanup_verified"], true, "{:?}", report);
    assert_eq!(report["cleanup_error"], Value::Null);
    assert_eq!(report["exit_code"], 0);
    assert_eq!(report["workspace_cleanup"]["reason"], "untracked");
    assert_eq!(f.spawns.load(Ordering::SeqCst), 2);
    let marker = util::read_json(&f.run.join("backend-000002/.runtime-retention.json")).unwrap();
    assert_eq!(marker["retired"], true);
}

const READY_WORKER: &str = r#"
trap 'exit 0' TERM
echo "{\"NATIVE_WORKSPACE_READY\": true, \"controller_pid\": $$}"
while true; do sleep 0.05; done
"#;

#[test]
fn missing_runtime_is_restored_before_a_real_worker_reaches_readiness() {
    let f = Fixture::new();
    let missing = f.root.join("native-20261111-065931/backend-000001");
    let cache = f.root.join("Library/Caches/Mirra");
    std::fs::create_dir_all(&cache).unwrap();
    util::chmod(&cache, 0o700).unwrap();
    write_state(&cache.join("sharing.json"), &json!({"schema_version": 1,
        "controller_birth": [12345, getuid(), 50, 6], "directory": util::text(&missing),
        "plist_sha256": "a".repeat(64)})).unwrap();
    let missing_text = util::text(&missing);
    let owned = format!("gui/{uid}/com.apple.sharingd = {{\npath = {m}/sharing.plist\nprogram = {p}\n\
        stdout path = {m}/sharingd.stdout.log\nstderr path = {m}/sharingd.stderr.log\nenvironment = {{\n\
        \tDYLD_INSERT_LIBRARIES => {m}/keystore.dylib\n\tMIRRA_KEYSTORE_BROKER_TOKEN => <redacted>\n}}\n}}\n",
        uid = getuid(), m = missing_text, p = crate::sharingd::PROGRAM);
    let original = format!("path = {}\nprogram = {}\n", crate::sharingd::ORIGINAL_PLIST, crate::sharingd::PROGRAM);
    let job = Arc::new(Mutex::new(owned));
    let mutations = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
    let mut context = SharingdContext::system();
    context.home = f.root.clone();
    context.process_birth = Arc::new(|_| Ok(None));
    context.interval = Duration::from_millis(5);
    let (state, seen) = (job.clone(), mutations.clone());
    context.launchctl = Arc::new(move |args: &[String], _| {
        let mut current = state.lock().unwrap();
        if args[0] == "print" {
            return Ok(if current.is_empty() {
                Reply { code: 113, stdout: String::new(), stderr: "Could not find service".into() }
            } else {
                Reply { code: 0, stdout: current.clone(), stderr: String::new() }
            });
        }
        seen.lock().unwrap().push(args.to_vec());
        match args[0].as_str() {
            "bootout" => current.clear(),
            "bootstrap" => {
                assert_eq!(args.last().unwrap(), crate::sharingd::ORIGINAL_PLIST);
                *current = original.clone();
            }
            other => panic!("Unexpected sharingd mutation: {}", other),
        }
        Ok(Reply { code: 0, stdout: String::new(), stderr: String::new() })
    });
    let sharingd = Arc::new(SystemSharingd { context });
    let mut hooks = f.hooks(sharingd, READY_WORKER, false);
    hooks.birth = Arc::new(mirra_core::processes::process_birth);
    let mut backend = NativeBackend::with_hooks(f.config.clone(), &f.run, true, hooks).start().unwrap();
    let ready = wait_for(&backend, |s| s["ready"] == true, 10);
    assert_eq!(ready["attempt"], 1);
    assert!(backend.worker().unwrap().poll().is_none());
    assert!(!cache.join("sharing.json").exists());
    assert!(!missing.exists());
    let commands: Vec<String> = mutations.lock().unwrap().iter().map(|a| a[0].clone()).collect();
    assert_eq!(commands, ["bootout", "bootstrap"]);
    assert!(f.events.lock().unwrap().iter().any(|e| e.get("ABANDONED_SHARINGD_RECOVERED").is_some()));
    let closed = backend.close();
    assert_eq!(closed["cleanup_verified"], true, "{:?}", closed);
    assert_eq!(closed["cleanup_error"], Value::Null);
}

#[test]
fn close_requests_a_single_stop_of_a_silent_worker() {
    let f = Fixture::new();
    let hooks = f.hooks(Arc::new(FakeSharingd::default()), "trap 'exit 3' TERM; while true; do sleep 0.05; done", true);
    let mut backend = NativeBackend::with_hooks(f.config.clone(), &f.run, false, hooks).start().unwrap();
    let state = wait_for(&backend, |s| s["phase"] == "starting" && s["worker_pid"].is_i64(), 5);
    assert_eq!(state["attempt"], 1);
    let report = backend.close();
    assert_eq!(report["phase"], "stopped");
    assert_eq!(report["exit_code"], 3);
    let stopping: Vec<Value> = f.events.lock().unwrap().iter().filter_map(|e| e.get("NATIVE_BACKEND_STATE"))
        .filter(|s| s["phase"] == "stopping_worker").cloned().collect();
    assert_eq!(stopping.len(), 1);
    assert_eq!(stopping[0]["reason"], "requested stop");
}
