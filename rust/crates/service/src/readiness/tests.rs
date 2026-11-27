use super::*;
use crate::installation::{PACKAGE_SCHEMA, SUPPORT_REVISION};
use mirra_core::state::write_state;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::Mutex;

/// A service whose manifest and status are scripted (`Mock(spec=NativeService)`).
pub(crate) struct FakeService {
    pub package: PathBuf,
    pub manifest: Mutex<Result<Object, String>>,
    pub snapshot: Arc<Mutex<Object>>,
    pub status_error: Mutex<Option<String>>,
    pub status_calls: Mutex<usize>,
}

impl SupportService for FakeService {
    fn package(&self) -> PathBuf {
        self.package.clone()
    }
    fn validate_package(&self) -> Result<Object> {
        self.manifest.lock().unwrap().clone().map_err(Error::runtime)
    }
    fn status(&self) -> Result<Object> {
        *self.status_calls.lock().unwrap() += 1;
        if let Some(error) = self.status_error.lock().unwrap().clone() {
            return Err(Error::runtime(error));
        }
        Ok(self.snapshot.lock().unwrap().clone())
    }
    fn start(&self) -> Result<Object> {
        panic!("observation must not start support")
    }
    fn stop(&self) -> Result<Object> {
        panic!("observation must not stop support")
    }
    fn registration(&self) -> Result<Object> {
        Ok(Map::new())
    }
}

struct FakeApps {
    pids: Vec<i32>,
    errors: Vec<String>,
    verified: HashMap<i32, Identity>,
    identity: Option<Identity>,
    on_poll: Option<Box<dyn Fn() + Send>>,
}

impl AppObservation for FakeApps {
    fn poll(&mut self) -> Vec<i32> {
        if let Some(callback) = &self.on_poll {
            callback();
        }
        self.pids.clone()
    }
    fn last_errors(&self) -> Vec<String> {
        self.errors.clone()
    }
    fn verified(&self, pid: i32) -> Option<Identity> {
        self.verified.get(&pid).copied()
    }
    fn identity(&self, pid: i32) -> mirra_core::Result<Option<Identity>> {
        Ok(self.identity.or_else(|| self.verified.get(&pid).copied()))
    }
}

fn object(value: Value) -> Object {
    value.as_object().unwrap().clone()
}

struct Fixture {
    _temp: tempfile::TempDir,
    _workspace: tempfile::TempDir,
    service: Arc<FakeService>,
    run: PathBuf,
    directory: PathBuf,
    backend: Arc<Mutex<Object>>,
    socket: PathBuf,
    births: Arc<Mutex<HashMap<i32, mirra_core::processes::Birth>>>,
    launch: Arc<Mutex<Object>>,
    apps_calls: Arc<Mutex<Vec<(PathBuf, PathBuf)>>>,
    probes: Probes,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = mirra_core::paths::resolve(temp.path());
        let package = root.join("installed/current");
        std::fs::create_dir_all(&package).unwrap();
        write_state(&package.join("config.json"), &json!({"backend": {"transport": "ssh"}})).unwrap();
        let snapshot = object(json!({"installed": true, "registered": true, "login_enabled": true, "supervisor_alive": true,
            "native_launch_support_ready": true, "backend_ready": true, "run": "native-test", "backend_attempt": 1}));
        let service = Arc::new(FakeService { package: package.clone(),
            manifest: Mutex::new(Ok(object(json!({"schema_version": PACKAGE_SCHEMA, "support_revision": SUPPORT_REVISION})))),
            snapshot: Arc::new(Mutex::new(snapshot)), status_error: Mutex::new(None), status_calls: Mutex::new(0) });
        let run = package.join("runtime/native-test");
        let directory = run.join("backend-000001");
        std::fs::create_dir_all(&directory).unwrap();
        let backend = Arc::new(Mutex::new(object(json!({"phase": "ready", "attempt": 1, "directory": "backend-000001",
            "automatic_recovery": true, "ready": true}))));
        let uid = sys::getuid();
        write_state(&directory.join("backend-children.json"), &json!({"broker": [42, uid, 100, 1]})).unwrap();
        let workspace = tempfile::Builder::new().prefix("mirra-").tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(workspace.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let info = sys::stat(workspace.path()).unwrap();
        write_state(&directory.join("broker-workspace.json"), &json!({"schema_version": 1,
            "path": util::text(workspace.path()), "device": info.st_dev, "inode": info.st_ino})).unwrap();
        let socket = workspace.path().join("broker.sock");
        let births = Arc::new(Mutex::new(HashMap::from([(42, (42, uid, 100, 1)), (43, (43, uid, 100, 2))])));
        let launch = Arc::new(Mutex::new(object(json!({"path": util::text(&run.join("native-launch-agent.plist")),
            "program": AGENT, "injected": true, "pid": "43"}))));
        let apps_calls = Arc::new(Mutex::new(Vec::new()));
        let table = births.clone();
        let state = launch.clone();
        let calls = apps_calls.clone();
        let probes = Probes {
            birth: Arc::new(move |pid| Ok(table.lock().unwrap().get(&pid).copied())),
            health: Arc::new(mirra_core::health::health),
            launch_state: Arc::new(move |_| Ok(state.lock().unwrap().clone())),
            apps: Arc::new(move |executable, adapter| {
                calls.lock().unwrap().push((executable.to_path_buf(), adapter.to_path_buf()));
                Box::new(FakeApps { pids: vec![], errors: vec![], verified: HashMap::new(), identity: None, on_poll: None })
            }),
            bridge_update: Arc::new(|_, _| Ok(None)),
            config_root: root.clone(),
        };
        let fixture = Fixture { _temp: temp, _workspace: workspace, service, run, directory, backend, socket, births, launch, apps_calls, probes };
        fixture.write_backend();
        fixture
    }

    fn write_backend(&self) {
        write_state(&self.run.join("backend-status.json"), &Value::Object(self.backend.lock().unwrap().clone())).unwrap();
    }

    /// Serve one health request with `payload`; `after` runs between request and reply.
    fn reply(&self, payload: Value, after: Option<Box<dyn FnOnce() + Send>>) -> std::thread::JoinHandle<()> {
        let listener = UnixListener::bind(&self.socket).unwrap();
        std::fs::set_permissions(&self.socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            let mut request = [0u8; 26];
            connection.read_exact(&mut request).unwrap();
            assert_eq!(&request[4..], br#"{"operation":"health"}"#);
            if let Some(after) = after {
                after();
            }
            let data = payload.to_string().into_bytes();
            connection.write_all(&(data.len() as u32).to_be_bytes()).unwrap();
            connection.write_all(&data).unwrap();
        })
    }

    fn observe(&self) -> Value {
        observe_with(self.service.as_ref(), &self.probes, Duration::from_secs(2))
    }

    fn recovered_backend(&mut self, apps: FakeApps) {
        self.backend.lock().unwrap().insert("attempt".into(), json!(2));
        self.write_backend();
        self.service.snapshot.lock().unwrap().insert("backend_attempt".into(), json!(2));
        let uid = sys::getuid();
        self.births.lock().unwrap().insert(44, (44, uid, 110, 2));
        write_state(&self.directory.join("backend-children.json"), &json!({"broker": [42, uid, 100, 1], "sharingd": [44, uid, 110, 2]})).unwrap();
        let apps = Mutex::new(Some(apps));
        let calls = self.apps_calls.clone();
        self.probes.apps = Arc::new(move |executable, adapter| {
            calls.lock().unwrap().push((executable.to_path_buf(), adapter.to_path_buf()));
            Box::new(apps.lock().unwrap().take().unwrap())
        });
    }
}

fn apps(identity: Option<Identity>) -> FakeApps {
    let mut verified = HashMap::new();
    if let Some(identity) = identity {
        verified.insert(identity.0, identity);
    }
    FakeApps { pids: identity.map(|i| vec![i.0]).unwrap_or_default(), errors: vec![], verified, identity: None, on_poll: None }
}

#[test]
fn live_health_ready_does_not_claim_mirroring_connection() {
    let f = Fixture::new();
    let server = f.reply(json!({"ready": true, "identities": 2, "sessions": 2}), None);
    let result = f.observe();
    server.join().unwrap();
    assert_eq!(result["state"], "ready");
    assert_eq!(result["actions"], json!(["open_mirroring", "refresh", "stop"]));
    assert_eq!(result["mirroring_connection_verified"], Value::Null);
    assert_eq!(result["bridge_transport"], "ssh");
    assert!(f.apps_calls.lock().unwrap().is_empty());
    assert_eq!(result.as_object().unwrap().keys().collect::<Vec<_>>(), ["schema_version", "observed_at", "state", "title",
        "detail", "actions", "bridge_transport", "mirroring_connection_verified"]);
}

#[test]
fn recovery_blocks_an_app_that_predates_the_replacement_sharingd() {
    let mut f = Fixture::new();
    f.recovered_backend(apps(Some((60, 110, 1))));
    let server = f.reply(json!({"ready": true}), None);
    let result = f.observe();
    server.join().unwrap();
    assert_eq!(result["state"], "waiting_for_mirroring_exit");
    assert!(result["detail"].as_str().unwrap().contains("Command-Q"));
    assert!(!pyjson_text(&result).contains(&util::text(&f.run)));
    assert_eq!(*f.apps_calls.lock().unwrap(), [(PathBuf::from("/System/Applications/iPhone Mirroring.app/Contents/MacOS/iPhone Mirroring"),
        f.run.join("sockets.dylib"))]);
}

fn pyjson_text(value: &Value) -> String {
    mirra_core::pyjson::dumps(value)
}

#[test]
fn recovery_allows_a_fresh_app_or_no_owned_app() {
    for identity in [None, Some((60, 110, 3))] {
        let mut f = Fixture::new();
        f.recovered_backend(apps(identity));
        let server = f.reply(json!({"ready": true}), None);
        assert_eq!(f.observe()["state"], "ready");
        server.join().unwrap();
    }
}

#[test]
fn uncertain_or_changing_app_observation_does_not_offer_connect() {
    let mut f = Fixture::new();
    let mut uncertain = apps(None);
    uncertain.errors = vec!["TimeoutExpired".into()];
    f.recovered_backend(uncertain);
    let server = f.reply(json!({"ready": true}), None);
    assert_eq!(f.observe()["state"], "unknown");
    server.join().unwrap();

    let mut f = Fixture::new();
    let mut reused = apps(Some((60, 110, 3)));
    reused.identity = Some((60, 200, 1));
    f.recovered_backend(reused);
    let server = f.reply(json!({"ready": true}), None);
    assert_eq!(f.observe()["state"], "unknown");
    server.join().unwrap();

    // The backend generation is rechecked after the app observation.
    let mut f = Fixture::new();
    let mut advancing = apps(Some((60, 110, 3)));
    let (backend, path) = (f.backend.clone(), f.run.join("backend-status.json"));
    advancing.on_poll = Some(Box::new(move || {
        backend.lock().unwrap().insert("attempt".into(), json!(3));
        write_state(&path, &Value::Object(backend.lock().unwrap().clone())).unwrap();
    }));
    f.recovered_backend(advancing);
    let server = f.reply(json!({"ready": true}), None);
    assert_eq!(f.observe()["state"], "unknown");
    server.join().unwrap();
}

#[test]
fn recovery_requires_a_live_recorded_sharingd_identity() {
    let mut f = Fixture::new();
    f.recovered_backend(apps(None));
    f.births.lock().unwrap().insert(44, (44, sys::getuid(), 200, 1));
    let server = f.reply(json!({"ready": true}), None);
    assert_eq!(f.observe()["state"], "unknown");
    server.join().unwrap();
    assert!(f.apps_calls.lock().unwrap().is_empty());
}

#[test]
fn legacy_package_offers_update_without_reading_status() {
    let f = Fixture::new();
    write_state(&f.service.package.join("config.json"), &json!({
        "backend": {"transport": "ssh", "service": {"token_file": util::text(&f.service.package.join("private/token"))}}
    })).unwrap();
    *f.service.manifest.lock().unwrap() = Ok(object(json!({"schema_version": 4})));
    let result = f.observe();
    assert_eq!(result["state"], "update_available");
    assert_eq!(result["actions"], json!(["install", "guide"]));
    assert_eq!(*f.service.status_calls.lock().unwrap(), 0);
}

#[test]
fn ssh_era_legacy_package_directs_user_to_setup_instead_of_install() {
    let f = Fixture::new();
    *f.service.manifest.lock().unwrap() = Ok(object(json!({"schema_version": 4})));
    let result = f.observe();
    assert_eq!(result["state"], "setup_required");
    assert_eq!(result["actions"], json!(["setup", "guide"]));
    assert_eq!(*f.service.status_calls.lock().unwrap(), 0);
}

#[test]
fn failed_health_observation_never_offers_restart() {
    let f = Fixture::new();
    let result = observe_with(f.service.as_ref(), &f.probes, Duration::from_millis(20));
    assert_eq!(result["state"], "unknown");
    assert_eq!(result["actions"], json!(["refresh", "guide"]));
    assert_eq!(result["bridge_transport"], Value::Null);
}

#[test]
fn explicit_failure_has_recovery_guidance_without_private_error() {
    let f = Fixture::new();
    let server = f.reply(json!({"ready": false, "error": "PRIVATE host=192.0.2.9 token=secret"}), None);
    let result = f.observe();
    server.join().unwrap();
    assert_eq!(result["state"], "recovering");
    let text = pyjson_text(&result);
    assert!(!text.contains("PRIVATE") && !text.contains("192.0.2.9"));
}

#[test]
fn backend_generation_change_invalidates_a_positive_reply() {
    let f = Fixture::new();
    let (backend, path) = (f.backend.clone(), f.run.join("backend-status.json"));
    let server = f.reply(json!({"ready": true}), Some(Box::new(move || {
        backend.lock().unwrap().insert("attempt".into(), json!(2));
        write_state(&path, &Value::Object(backend.lock().unwrap().clone())).unwrap();
    })));
    assert_eq!(f.observe()["state"], "unknown");
    server.join().unwrap();
}

#[test]
fn foreign_workspace_or_dead_broker_is_never_queried() {
    let f = Fixture::new();
    let calls = Arc::new(Mutex::new(0));
    let mut probes = f.probes.clone();
    let counter = calls.clone();
    probes.health = Arc::new(move |_, _| { *counter.lock().unwrap() += 1; Ok(Map::new()) });
    let path = f.directory.join("broker-workspace.json");
    let mut record = util::read_object(&path, "").unwrap();
    record["inode"] = json!(record["inode"].as_i64().unwrap() + 1);
    write_state(&path, &Value::Object(record)).unwrap();
    assert_eq!(observe_with(f.service.as_ref(), &probes, Duration::from_secs(2))["state"], "unknown");
    let f = Fixture::new();
    f.births.lock().unwrap().insert(42, (42, sys::getuid(), 200, 1));
    assert_eq!(observe_with(f.service.as_ref(), &probes, Duration::from_secs(2))["state"], "unknown");
    assert_eq!(*calls.lock().unwrap(), 0);
}

#[test]
fn missing_launch_agent_cannot_report_ready() {
    let f = Fixture::new();
    f.launch.lock().unwrap().insert("pid".into(), Value::Null);
    let server = f.reply(json!({"ready": true}), None);
    assert_eq!(f.observe()["state"], "launch_support_unavailable");
    server.join().unwrap();
}

#[test]
fn stopped_and_stopping_states() {
    let f = Fixture::new();
    f.service.snapshot.lock().unwrap().insert("registered".into(), json!(false));
    let result = f.observe();
    assert_eq!(result["state"], "stopping");
    assert_eq!(result["actions"], json!(["refresh"]));
    f.service.snapshot.lock().unwrap().extend(object(json!({"supervisor_alive": false, "login_enabled": false})));
    let result = f.observe();
    assert_eq!(result["state"], "stopped");
    assert_eq!(result["actions"], json!(["install", "setup", "guide"]));
    f.service.snapshot.lock().unwrap().insert("login_enabled".into(), json!(true));
    assert_eq!(f.observe()["actions"], json!(["start", "setup", "guide"]));
}

#[test]
fn backend_phases_and_certificate_issues() {
    let f = Fixture::new();
    f.service.snapshot.lock().unwrap().insert("backend_ready".into(), json!(false));
    for (changes, state) in [(json!({"phase": "failed"}), "needs_attention"),
        (json!({"phase": "waiting_for_cleanup", "attempt": 0, "ready": false,
            "observation_error": {"error_type": "FileNotFoundError", "error": "/Users/private/runtime token=secret", "errno": 2}}), "restoring"),
        (json!({"phase": "retry_wait"}), "waiting_for_bridge"),
        (json!({"certificate_issue": "renewing"}), "renewing_certificate"),
        (json!({"certificate_issue": "expired"}), "bridge_certificate_expired"),
        (json!({"certificate_issue": "clock"}), "bridge_certificate_unavailable")] {
        let mut backend = object(json!({"phase": "ready", "attempt": 1, "directory": "backend-000001", "automatic_recovery": true}));
        backend.extend(object(changes));
        *f.backend.lock().unwrap() = backend;
        f.write_backend();
        let result = f.observe();
        assert_eq!(result["state"], state);
        let text = pyjson_text(&result);
        assert!(!text.contains("/Users/private") && !text.contains("secret"));
        if state == "needs_attention" {
            assert!(!result["detail"].as_str().unwrap().contains("retry automatically"));
        }
        if state == "bridge_certificate_expired" {
            assert_eq!(result["actions"], json!(["renew", "refresh", "stop"]));
        }
    }
}

#[test]
fn changed_installation_or_unknown_error_does_not_leak() {
    let f = Fixture::new();
    *f.service.manifest.lock().unwrap() = Err("PRIVATE changed file".into());
    let result = f.observe();
    assert_eq!(result["state"], "installation_changed");
    assert_eq!(*f.service.status_calls.lock().unwrap(), 0);
    assert!(!pyjson_text(&result).contains("PRIVATE"));
    let f = Fixture::new();
    *f.service.status_error.lock().unwrap() = Some("/private/key material".into());
    let result = f.observe();
    assert_eq!(result["state"], "unknown");
    assert!(!pyjson_text(&result).contains("/private/key"));
    let missing = FakeService { package: PathBuf::from("/nonexistent/current"), manifest: Mutex::new(Ok(Map::new())),
        snapshot: Arc::new(Mutex::new(Map::new())), status_error: Mutex::new(None), status_calls: Mutex::new(0) };
    let result = observe_with(&missing, &f.probes, Duration::from_secs(2));
    assert_eq!((result["state"].clone(), result["actions"].clone()), (json!("setup_required"), json!(["setup"])));
}

#[test]
fn startup_states_do_not_query_the_backend() {
    let f = Fixture::new();
    *f.service.snapshot.lock().unwrap() = object(json!({"registered": true, "supervisor_alive": true,
        "native_launch_support_ready": false, "backend_ready": false}));
    for code in ["container_access_denied", "container_missing", "startup_interrupted", "support_access_denied",
        "support_startup_failed", "PRIVATE unknown reason"] {
        f.service.snapshot.lock().unwrap().insert("startup_failure".into(), json!(code));
        let result = f.observe();
        assert_eq!(result["state"], "startup_failed");
        assert_eq!(result["actions"], json!(["stop", "refresh", "guide"]));
        assert!(!pyjson_text(&result).contains("PRIVATE"));
    }
    f.service.snapshot.lock().unwrap().remove("startup_failure");
    f.service.snapshot.lock().unwrap().insert("phase".into(), json!("waiting_for_mirroring_exit"));
    let result = f.observe();
    assert_eq!(result["state"], "waiting_for_mirroring_exit");
    assert_eq!(result["actions"], json!(["refresh", "stop"]));
    f.service.snapshot.lock().unwrap().insert("supervisor_alive".into(), json!(false));
    assert_eq!(f.observe()["state"], "starting");
}

#[test]
fn outdated_bridge_takes_precedence_until_backend_is_ready() {
    let mut f = Fixture::new();
    f.probes.bridge_update = Arc::new(|config, _| Ok(update_report(config, Some(0))));
    f.service.snapshot.lock().unwrap().insert("backend_ready".into(), json!(false));
    let result = f.observe();
    assert_eq!(result["state"], "bridge_update_available");
    assert_eq!(result["actions"], json!(["refresh", "guide", "stop"]));
    f.service.snapshot.lock().unwrap().insert("backend_ready".into(), json!(true));
    let server = f.reply(json!({"ready": true}), None);
    let result = f.observe();
    server.join().unwrap();
    assert_eq!(result["state"], "ready");
    assert_eq!(result["bridge_update_detail"],
        "Update the iPhone from a Mac with verified SSH access to this bridge, then check again here.");
    assert_eq!(result["actions"], json!(["open_mirroring", "refresh", "stop"]));
}
