use super::*;
use crate::testing::{original_sharingd, FakeSharingd};
use mirra_core::sys::getuid;
use std::collections::VecDeque;
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;

pub(crate) struct Fixture {
    pub _temp: tempfile::TempDir,
    pub root: PathBuf,
    pub service: NativeService,
    pub launchctl: Arc<Mutex<Vec<Vec<String>>>>,
    pub registered: Arc<Mutex<Option<String>>>,
    pub births: Arc<Mutex<VecDeque<Option<mirra_core::processes::Birth>>>>,
    pub default_birth: Arc<Mutex<Option<mirra_core::processes::Birth>>>,
    pub sleeps: Arc<Mutex<usize>>,
    pub sharingd: Arc<FakeSharingd>,
    pub launch_recoveries: Arc<Mutex<Vec<PathBuf>>>,
}

fn private_write(path: &Path, data: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, data).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

pub(crate) fn fixture(sharingd: FakeSharingd) -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let root = mirra_core::paths::resolve(temp.path());
    let launchctl = Arc::new(Mutex::new(Vec::new()));
    let registered: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let births = Arc::new(Mutex::new(VecDeque::new()));
    let default_birth = Arc::new(Mutex::new(None));
    let sleeps = Arc::new(Mutex::new(0));
    let sharingd = Arc::new(sharingd);
    let launch_recoveries = Arc::new(Mutex::new(Vec::new()));
    let mut hooks = ServiceHooks::system(&root);
    let (calls, job) = (launchctl.clone(), registered.clone());
    hooks.launchctl = Arc::new(move |args| {
        calls.lock().unwrap().push(args.to_vec());
        let mut job = job.lock().unwrap();
        Ok(match args[0].as_str() {
            "print" => match job.as_ref() {
                Some(stdout) => Reply { code: 0, stdout: stdout.clone(), stderr: String::new() },
                None => Reply { code: 113, stdout: String::new(), stderr: "Could not find service \"local.mirra.agent\"".into() },
            },
            "bootout" => {
                *job = None;
                Reply { code: 0, stdout: String::new(), stderr: String::new() }
            }
            _ => Reply { code: 0, stdout: String::new(), stderr: String::new() },
        })
    });
    let (queue, fallback) = (births.clone(), default_birth.clone());
    hooks.birth = Arc::new(move |_| Ok(queue.lock().unwrap().pop_front().unwrap_or(*fallback.lock().unwrap())));
    let counter = sleeps.clone();
    hooks.sleep = Arc::new(move |_| *counter.lock().unwrap() += 1);
    hooks.sharingd = sharingd.clone();
    let recoveries = launch_recoveries.clone();
    hooks.recover_launch = Arc::new(move |runtime| {
        recoveries.lock().unwrap().push(runtime.to_path_buf());
        Ok(None)
    });
    hooks.decoder_journal = root.join("Library/Caches/Mirra/decoder-route.json");
    hooks.acquire_decoder = Arc::new(|| Ok(()));
    hooks.helper = Arc::new(|_| Err(Error::runtime("unexpected app helper")));
    let service = NativeService::with_home(Some(&root.join("installed")), &root, hooks);
    Fixture { _temp: temp, root, service, launchctl, registered, births, default_birth, sleeps, sharingd, launch_recoveries }
}

/// A package laid out like `NativeService.prepare()` leaves it.
pub(crate) fn prepare(service: &NativeService, revision: i64) -> Object {
    std::fs::create_dir_all(&service.base).unwrap();
    std::fs::set_permissions(&service.base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut names: Vec<String> = ["scripts/native.py", "scripts/decoder.py", "scripts/decoder_route.py", "scripts/startup.py",
        "python/bin/python3", "python/manifest.json", "python/licenses/LICENSE.cpython.txt", "private/token", "private/certificate.der"]
        .map(String::from).to_vec();
    names.extend(PACKAGE_ADAPTERS.iter().chain(SUPPORT_TOOLS.iter()).map(|n| format!("build/{}", n)));
    names.extend(BRIDGE_UPDATE_FILES.map(String::from));
    let mut files = Map::new();
    for name in &names {
        let data = format!("fixture {}", name);
        private_write(&service.package.join(name), data.as_bytes());
        files.insert(name.clone(), Value::from(hex(data.as_bytes())));
    }
    let config = json!({"schema_version": 1, "backend": {"transport": "ssh",
        "service": {"token_file": util::text(&service.package.join("private/token"))},
        "certificate_file": util::text(&service.package.join("private/certificate.der"))},
        "host": {"runtime_directory": util::text(&service.package.join("runtime/host"))}});
    write_state(&service.package.join("config.json"), &config).unwrap();
    files.insert("config.json".into(), Value::from(hex(&std::fs::read(service.package.join("config.json")).unwrap())));
    let manifest = json!({"schema_version": PACKAGE_SCHEMA, "support_revision": revision, "product": "Mirra",
        "package": util::text(&service.package), "prepared_at": "2026-11-22T00:00:00", "files": files});
    write_state(&service.package.join("manifest.json"), &manifest).unwrap();
    std::fs::create_dir_all(service.base.join("logs")).unwrap();
    manifest.as_object().unwrap().clone()
}

fn hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{:02x}", b)).collect()
}

pub(crate) fn install_plist(service: &NativeService, definition: &Value) {
    let data = mirra_native::plist::dumps(&mirra_native::plist::Plist::from_json(definition)).unwrap();
    private_write(&service.plist, &data);
}

fn write_manifest(service: &NativeService, manifest: &Object) {
    write_state(&service.package.join("manifest.json"), &Value::Object(manifest.clone())).unwrap();
}

fn registered_job(f: &Fixture) {
    *f.registered.lock().unwrap() = Some(format!("{} = {{\n\tpath = {}\n\tpid = 42\n\tstate = running\n}}\n",
        f.service.target, f.service.plist.display()));
}

#[test]
fn constants_match_the_python_service() {
    assert_eq!((LABEL, SUPPORT_REVISION, CERTIFICATE_LOCK_REVISION, BRIDGE_UPDATE_REVISION, CLI_SUPPORT_REVISION, PACKAGE_SCHEMA),
        ("local.mirra.agent", 54, 45, 47, 40, 5));
    assert_eq!(PACKAGE_ADAPTERS.to_vec(), [&ADAPTERS[..], &DECODER_ADAPTERS[..]].concat());
}

#[test]
fn package_integrity_is_checked_before_use() {
    let f = fixture(FakeSharingd::default());
    let manifest = prepare(&f.service, SUPPORT_REVISION);
    assert_eq!(f.service.validate_package().unwrap(), manifest);
    assert!(!needs_update(&manifest).unwrap());
    std::fs::write(f.service.package.join("scripts/native.py"), "changed").unwrap();
    assert_eq!(f.service.validate_package().unwrap_err().to_string(), "Installed support file changed: scripts/native.py");
    // A changed file is rejected before starting; launchctl is never called.
    assert!(f.service.start().is_err());
    assert!(f.launchctl.lock().unwrap().is_empty());
}

#[test]
fn unknown_contracts_and_paths_are_rejected() {
    let f = fixture(FakeSharingd::default());
    let original = prepare(&f.service, SUPPORT_REVISION);
    for (key, value) in [("schema_version", json!(1)), ("product", json!("Other")), ("package", json!("/elsewhere"))] {
        let mut changed = original.clone();
        changed.insert(key.into(), value);
        write_manifest(&f.service, &changed);
        assert_eq!(f.service.validate_package().unwrap_err().to_string(), "Invalid Mirra package manifest");
    }
    let mut changed = original.clone();
    let digest = changed["files"].as_object_mut().unwrap().shift_remove("scripts/native.py").unwrap();
    changed["files"].as_object_mut().unwrap().insert("scripts/foreign.py".into(), digest.clone());
    write_manifest(&f.service, &changed);
    assert_eq!(f.service.validate_package().unwrap_err().to_string(), "Native support package is missing required files");
    let mut changed = original.clone();
    changed["files"].as_object_mut().unwrap().insert("../outside".into(), digest);
    write_manifest(&f.service, &changed);
    assert_eq!(f.service.validate_package().unwrap_err().to_string(), "Package manifest contains an unexpected path");
    let mut changed = original.clone();
    changed.insert("support_revision".into(), json!(true));
    write_manifest(&f.service, &changed);
    assert_eq!(f.service.validate_package().unwrap_err().to_string(), "Invalid Mirra support revision");
    write_manifest(&f.service, &original);
    std::fs::set_permissions(f.service.package.join("config.json"), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(f.service.validate_package().unwrap_err().to_string().starts_with("Expected a private, user-owned support file"));
}

#[test]
fn legacy_packages_need_an_update() {
    assert!(needs_update(json!({"schema_version": 4}).as_object().unwrap()).unwrap());
    assert!(needs_update(json!({"schema_version": 5, "support_revision": 53}).as_object().unwrap()).unwrap());
    assert!(!needs_update(json!({"schema_version": 5, "support_revision": 54}).as_object().unwrap()).unwrap());
    assert!(needs_update(json!({"schema_version": "5"}).as_object().unwrap()).is_err());
}

#[test]
fn definitions_match_the_installed_python_plist() {
    let f = fixture(FakeSharingd::default());
    let definition = f.service.definition(None);
    assert_eq!(definition["ProgramArguments"], json!([util::text(&f.service.package.join("build/mirra-cli")), "run-service"]));
    assert_eq!(definition["Umask"], 63);
    let legacy = json!({"support_revision": 39});
    let legacy = legacy.as_object().unwrap();
    assert_eq!(f.service.definition(Some(legacy))["ProgramArguments"][0], util::text(&f.service.package.join("python/bin/python3")));
    let previous = f.service.previous_definitions(legacy);
    assert_eq!(previous.len(), 1);
    assert_eq!(previous[0]["ProgramArguments"].as_array().unwrap().last().unwrap(), "--manage-usb");
}

#[test]
fn start_bootstraps_only_the_recognized_definition() {
    let f = fixture(FakeSharingd::default());
    let manifest = prepare(&f.service, SUPPORT_REVISION);
    install_plist(&f.service, &f.service.definition(Some(&manifest)));
    let status = f.service.start().unwrap();
    assert_eq!(f.launchctl.lock().unwrap()[1],
        ["bootstrap", f.service.domain.as_str(), util::text(&f.service.plist).as_str()]);
    assert_eq!(status["installed"], true);
    assert_eq!(status["login_enabled"], true);

    let mut foreign = f.service.definition(Some(&manifest));
    foreign["ProgramArguments"][0] = json!("/another/python");
    install_plist(&f.service, &foreign);
    assert_eq!(f.service.start().unwrap_err().to_string(), "Service plist no longer matches the installed package");
}

#[test]
fn interrupted_upgrade_start_is_delegated_to_python_install() {
    let f = fixture(FakeSharingd::default());
    let mut manifest = prepare(&f.service, SUPPORT_REVISION);
    let mut old = f.service.definition(Some(json!({"support_revision": 39}).as_object().unwrap()));
    old["ProgramArguments"].as_array_mut().unwrap().push(json!("--manage-usb"));
    manifest.insert("previous_definition".into(), old.clone());
    write_manifest(&f.service, &manifest);
    install_plist(&f.service, &old);
    assert!(f.service.start().unwrap_err().is_delegate());
    assert!(f.launchctl.lock().unwrap().is_empty());
}

#[test]
fn foreign_service_registration_is_not_stopped() {
    let f = fixture(FakeSharingd::default());
    *f.registered.lock().unwrap() = Some("path = /someone/else.plist\npid = 42\n".into());
    assert_eq!(f.service.stop().unwrap_err().to_string(), "The service label belongs to another configuration");
    let calls = f.launchctl.lock().unwrap();
    assert_eq!(calls.iter().map(|c| c[0].as_str()).collect::<Vec<_>>(), ["print"]);
}

#[test]
fn status_uses_current_decoder_observation_instead_of_startup_ready() {
    let f = fixture(FakeSharingd::default());
    let run = f.service.package.join("runtime/native-fixture");
    std::fs::create_dir_all(&run).unwrap();
    let birth = (42, getuid(), 100, 1);
    *f.default_birth.lock().unwrap() = Some(birth);
    write_state(&f.service.state, &json!({"phase": "running", "directory": util::text(&run),
        "supervisor_birth": [42, getuid(), 100, 1], "decoder_route": {"enabled": true, "ready": true}})).unwrap();
    assert_eq!(f.service.status().unwrap()["native_launch_support_ready"], false);
    for (value, expected) in [(json!({"ready": true}), true), (json!({"ready": false}), false), (json!([]), false)] {
        write_state(&run.join("decoder-route.json"), &value).unwrap();
        assert_eq!(f.service.status().unwrap()["native_launch_support_ready"], expected);
    }
}

#[test]
fn startup_failure_before_run_directory_can_be_observed() {
    let f = fixture(FakeSharingd::default());
    std::fs::create_dir_all(&f.service.base).unwrap();
    for alive in [true, false] {
        write_state(&f.service.state, &json!({"phase": if alive { "startup_failed" } else { "stopped" },
            "supervisor_birth": [42, getuid(), 100, 1], "startup_failure": "container_access_denied",
            "startup_cleanup_verified": !alive})).unwrap();
        *f.default_birth.lock().unwrap() = alive.then_some((42, getuid(), 100, 1));
        let value = f.service.status().unwrap();
        assert_eq!(value["supervisor_alive"], alive);
        assert_eq!(value["native_launch_support_ready"], false);
        assert_eq!(value["backend_ready"], false);
        assert_eq!(value["last_cleanup_verified"], !alive);
        assert_eq!(value["startup_failure"], "container_access_denied");
        assert_eq!(value.keys().collect::<Vec<_>>(), ["installed", "login_enabled", "registered", "registration",
            "native_launch_support_ready", "backend_ready", "supervisor_alive", "supervisor_birth", "phase",
            "startup_failure", "last_cleanup_verified"]);
    }
}

#[test]
fn cleanup_verification_requires_every_restoration() {
    let f = fixture(FakeSharingd::default());
    let run = f.service.package.join("runtime/native-fixture");
    std::fs::create_dir_all(&run).unwrap();
    write_state(&f.service.state, &json!({"phase": "stopped", "directory": util::text(&run),
        "supervisor_birth": [42, getuid(), 100, 1]})).unwrap();
    let result = json!({"backend_cleanup": {"cleanup_verified": true}, "decoder_route": {"enabled": true, "mode": "no_fls"},
        "decoder_cleanup": {"cleanup_verified": true, "original_avc_restored": true}});
    write_state(&run.join("result.json"), &result).unwrap();
    assert_eq!(f.service.status().unwrap()["last_cleanup_verified"], true);
    for change in [json!({"decoder_cleanup": {"cleanup_verified": false, "original_avc_restored": false}}),
        json!({"backend_cleanup": {"cleanup_verified": false}}), json!({"decoder_route": {"enabled": true, "ready": true}}),
        json!({"launch_agent_attempted": true}), json!({"launch_agent_restore_error": "failed"})] {
        let mut changed = result.clone();
        for (k, v) in change.as_object().unwrap() {
            changed[k] = v.clone();
        }
        write_state(&run.join("result.json"), &changed).unwrap();
        assert_eq!(f.service.status().unwrap()["last_cleanup_verified"], false, "{}", change);
    }
    // Restoration proof for another controller does not count.
    write_state(&run.join("result.json"), &json!({"launch_agent_restored": true, "backend_cleanup": {"cleanup_verified": false},
        "cleanup_recovery": {"backend_cleanup_verified": true, "supervisor_birth": [42, getuid(), 90, 1]}})).unwrap();
    assert_eq!(f.service.status().unwrap()["last_cleanup_verified"], false);
}

#[test]
fn stale_supervisor_state_is_not_readiness() {
    let f = fixture(FakeSharingd::default());
    let run = f.service.package.join("runtime/native-test");
    std::fs::create_dir_all(&run).unwrap();
    write_state(&f.service.state, &json!({"phase": "running", "directory": util::text(&run), "supervisor_birth": [42, getuid(), 100, 3]})).unwrap();
    write_state(&run.join("backend-status.json"), &json!({"phase": "ready", "attempt": 1, "ready": true,
        "worker_birth": [43, getuid(), 100, 4]})).unwrap();
    *f.default_birth.lock().unwrap() = Some((42, getuid(), 200, 4));
    let status = f.service.status().unwrap();
    assert_eq!(status["native_launch_support_ready"], false);
    assert_eq!(status["backend_ready"], false);
}

#[test]
fn stop_waits_for_unregistered_supervisor_before_reporting_cleanup() {
    let f = fixture(FakeSharingd::default());
    prepare(&f.service, SUPPORT_REVISION);
    let run = f.service.package.join("runtime/native-test");
    std::fs::create_dir_all(&run).unwrap();
    let birth = (42, getuid(), 100, 1);
    write_state(&f.service.state, &json!({"phase": "stopped", "directory": util::text(&run), "supervisor_birth": [42, getuid(), 100, 1]})).unwrap();
    write_state(&run.join("result.json"), &json!({"backend_cleanup": {"cleanup_verified": true}, "launch_agent_restored": true})).unwrap();
    f.births.lock().unwrap().extend([Some(birth), Some(birth), None, None]);
    let value = f.service.stop().unwrap();
    assert_eq!(*f.sleeps.lock().unwrap(), 1);
    assert_eq!(value["last_cleanup_verified"], true);
}

#[test]
fn stop_boots_out_its_own_job() {
    let f = fixture(FakeSharingd::default());
    prepare(&f.service, SUPPORT_REVISION);
    registered_job(&f);
    let value = f.service.stop().unwrap();
    let calls = f.launchctl.lock().unwrap();
    assert!(calls.contains(&vec!["bootout".to_string(), f.service.target.clone()]));
    assert_eq!(value["registered"], false);
}

/// The captured Wins state: an older sharingd job outlives its removed runtime.
fn missing_runtime_session(f: &Fixture) -> (PathBuf, PathBuf) {
    prepare(&f.service, SUPPORT_REVISION);
    let run = f.service.package.join("runtime/native-20261111-073111");
    std::fs::create_dir_all(&run).unwrap();
    let missing = run.parent().unwrap().join("native-20261111-065931/backend-000001");
    write_state(&f.service.state, &json!({"phase": "stopped", "directory": util::text(&run), "supervisor_birth": [42, getuid(), 100, 1]})).unwrap();
    write_state(&run.join("result.json"), &json!({"supervisor_birth": [42, getuid(), 100, 1],
        "launch_agent_restored": {"injected": false},
        "backend_cleanup": {"attempt": 0, "cleanup_verified": false, "cleanup_reason": "ownership observation deferred"},
        "decoder_route": {"enabled": true}, "decoder_cleanup": {"cleanup_verified": true, "original_avc_restored": true}})).unwrap();
    let cache = f.root.join("Library/Caches/Mirra");
    std::fs::create_dir_all(&cache).unwrap();
    write_state(&cache.join("sharing.json"), &json!({"schema_version": 1})).unwrap();
    *f.sharingd.journal.lock().unwrap() = Some(json!({"directory": util::text(&missing)}).as_object().unwrap().clone());
    *f.sharingd.recovered.lock().unwrap() = Some(json!({"directory": util::text(&missing), "original_restored": true}));
    *f.sharingd.state.lock().unwrap() = original_sharingd();
    (run, cache)
}

#[test]
fn stop_recovers_missing_runtime_after_the_old_support_process_ends() {
    let f = fixture(FakeSharingd::default());
    let (run, _) = missing_runtime_session(&f);
    let result = f.service.stop().unwrap();
    assert_eq!(result["last_cleanup_verified"], true);
    assert_eq!(*f.sharingd.recover_calls.lock().unwrap(), [true]);
    assert_eq!(*f.launch_recoveries.lock().unwrap(), [f.service.package.join("runtime")]);
    let record = util::read_json(&run.join("result.json")).unwrap();
    assert_eq!(record["backend_cleanup"]["cleanup_verified"], false);
    assert_eq!(record["backend_cleanup"]["cleanup_reason"], "ownership observation deferred");
    assert_eq!(record["cleanup_recovery"]["backend_cleanup_verified"], true);
    assert_eq!(record["cleanup_recovery"]["workspaces"][0]["reason"], "untracked");
    assert_eq!(record["cleanup_recovery"].as_object().unwrap().keys().collect::<Vec<_>>(),
        ["backend_cleanup_verified", "supervisor_birth", "sharingd", "workspaces", "observed_at"]);
}

#[test]
fn recovery_refuses_a_replaced_sharingd_and_live_workspaces() {
    let _serial = crate::testing::SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let f = fixture(FakeSharingd::default());
    let (run, _) = missing_runtime_session(&f);
    *f.sharingd.state.lock().unwrap() = json!({"path": "/another/sharing.plist", "program": "/usr/libexec/sharingd"}).as_object().unwrap().clone();
    assert_eq!(f.service.stop().unwrap_err().to_string(), "Original sharingd restoration is not verified");
    assert_eq!(f.service.status().unwrap()["last_cleanup_verified"], false);

    *f.sharingd.state.lock().unwrap() = original_sharingd();
    let backend = run.join("backend-000001");
    std::fs::create_dir_all(&backend).unwrap();
    std::fs::set_permissions(&backend, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut record = util::read_object(&run.join("result.json"), "").unwrap();
    record["backend_cleanup"]["directory"] = json!("backend-000001");
    write_state(&run.join("result.json"), &Value::Object(record)).unwrap();
    let mut workspace = workspace::BrokerWorkspace::new(&backend).unwrap();
    let error = f.service.stop().unwrap_err().to_string();
    assert_eq!(error, "Previous broker workspace is still in use; cleanup was deferred");
    assert!(workspace.path.exists());
    workspace.close();
    // The proof recorded by the deferred attempt is reused (journal already cleared).
    *f.sharingd.recovered.lock().unwrap() = None;
    assert_eq!(f.service.stop().unwrap()["last_cleanup_verified"], true);
    assert!(!workspace.path.exists());
}

#[test]
fn live_backend_child_prevents_recovery() {
    let f = fixture(FakeSharingd::default());
    let (_, _) = missing_runtime_session(&f);
    let missing = PathBuf::from(f.sharingd.journal.lock().unwrap().as_ref().unwrap()["directory"].as_str().unwrap());
    std::fs::create_dir_all(&missing).unwrap();
    write_state(&missing.join("backend-children.json"), &json!({"broker": [44, getuid(), 100, 2]})).unwrap();
    *f.default_birth.lock().unwrap() = Some((44, getuid(), 100, 2));
    let error = f.service.stop().unwrap_err().to_string();
    assert!(error.contains("backend children are still running") || error.contains("still restoring"), "{}", error);
    assert!(f.sharingd.recover_calls.lock().unwrap().is_empty());
    assert!(f.launch_recoveries.lock().unwrap().is_empty());
}

#[test]
fn sharingd_recovery_runs_in_rust_and_a_failure_keeps_the_report() {
    let f = fixture(FakeSharingd { recover_error: Some(|| Error::runtime("The sharingd restoration controller is still running")),
        ..Default::default() });
    let (run, _) = missing_runtime_session(&f);
    let before = std::fs::read(run.join("result.json")).unwrap();
    let error = f.service.stop().unwrap_err();
    assert!(!error.is_delegate());
    assert_eq!(error.to_string(), "The sharingd restoration controller is still running");
    // Launch support is restored first; the failed sharingd step adds no proof.
    assert_eq!(*f.launch_recoveries.lock().unwrap(), [f.service.package.join("runtime")]);
    assert_eq!(std::fs::read(run.join("result.json")).unwrap(), before);
}

#[test]
fn backend_lease_blocks_recovery() {
    let f = fixture(FakeSharingd::default());
    missing_runtime_session(&f);
    let _held = backend_lease(&f.root).unwrap();
    assert_eq!(f.service.stop().unwrap_err().type_name(), "BlockingIOError");
    assert!(f.sharingd.recover_calls.lock().unwrap().is_empty());
}

#[test]
fn app_managed_registration_is_recognized_through_the_helper() {
    let f = fixture(FakeSharingd::default());
    let mut manifest = prepare(&f.service, 41);
    manifest.insert("managed_app".into(), json!(util::text(&f.root.join("Mirra.app"))));
    write_manifest(&f.service, &manifest);
    assert_eq!(f.service.managed_app(None).unwrap(), Some(f.root.join("Mirra.app")));
    manifest.insert("managed_app".into(), json!("relative.app"));
    assert_eq!(f.service.managed_app(Some(&manifest)).unwrap_err().to_string(), "Invalid installed Mirra app path");
}

/// Cross-check with a package from the Python `prepare()`; set
/// `MIRRA_PYTHON_PACKAGE_ROOT` to the fixture root (`<root>/installed`).
#[test]
fn accepts_a_package_prepared_by_python_when_provided() {
    let Some(root) = std::env::var_os("MIRRA_PYTHON_PACKAGE_ROOT") else { return };
    let root = mirra_core::paths::resolve(Path::new(&root));
    let service = NativeService::with_home(Some(&root.join("installed")), &root, ServiceHooks::system(&root));
    let manifest = service.validate_package().unwrap();
    assert_eq!(manifest["support_revision"], SUPPORT_REVISION);
    assert!(!needs_update(&manifest).unwrap());
    let reviewed = mirra_native::plist::loads(&std::fs::read(service.base.join("service.plist")).unwrap()).unwrap().to_json();
    assert_eq!(reviewed, service.definition(Some(&manifest)));
    service.load_config().unwrap();
}
