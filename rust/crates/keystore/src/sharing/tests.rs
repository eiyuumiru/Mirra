//! The sharing controller end to end: a real broker server over a fake
//! bridge, and a simulated launchd that "loads" the adapter on kickstart.
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::Mutex;

use super::*;
use crate::broker::tests::{fake_bridge, private_directory, start};
use crate::sharingd::tests::{context, Births, FakeLaunchd};

struct World {
    _temporary: tempfile::TempDir,
    home: PathBuf,
    workspace: PathBuf,
    launchd: FakeLaunchd,
}

impl World {
    fn new() -> Self {
        let (temporary, root) = private_directory();
        let home = root.join("home");
        std::fs::create_dir_all(home.join("Library/Application Support/Mirra/logs")).unwrap();
        let workspace = root.join("w");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(workspace.join("keystore.dylib"), b"adapter image").unwrap();
        let launchd = FakeLaunchd::new(Some(FakeLaunchd::original(500)));
        launchd.state().marker_log = Some(home.join("Library/Application Support/Mirra/logs/sharingd.log"));
        World { _temporary: temporary, home, workspace, launchd }
    }

    fn options(&self, duration: Option<u64>, events: &Arc<Mutex<Vec<Value>>>, on_running: Option<Event>) -> SharingOptions {
        let mut options = SharingOptions::new(self.workspace.clone(), duration, Event::new());
        options.context = context(&self.home, &self.launchd, Arc::new(Mutex::new(Births::Dead)));
        let (log, stop, broker_file) = (events.clone(), options.stop.clone(), self.broker_file());
        options.emit = Arc::new(move |event| {
            let mut event = event.clone();
            if event.get("WORKSPACE_RUNNING").is_some() {
                // Observe the online broker file while the session runs.
                event["broker_file"] = Value::from(std::fs::read_to_string(&broker_file).unwrap());
                if let Some(stopper) = &on_running {
                    stopper.set();
                    stop.set();
                }
            }
            log.lock().unwrap().push(event);
        });
        options.adapter_wait = Duration::from_secs(2);
        options.adapter_poll = Duration::from_millis(5);
        options.tick = Duration::from_millis(5);
        options.log_limit = 1024;
        options.watch_native = Arc::new(|_, _, _, _| Ok(()));
        options
    }

    fn broker_file(&self) -> PathBuf {
        self.home.join("Library/Application Support/Mirra/state/broker.json")
    }
    fn journal(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.home.join("Library/Caches/Mirra/sharing.json")).unwrap()).unwrap()
    }
    fn pid(&self) -> u32 {
        self.launchd.state().job.as_ref().unwrap().pid.unwrap()
    }
}

#[test]
fn continuous_session_detaches_then_adopts_then_restores_when_bounded() {
    let world = World::new();
    let running = start(&world.workspace, fake_bridge(true));
    let broker = running.state();

    // 1. Fresh load; a normal stop of the continuous session detaches.
    let events = Arc::new(Mutex::new(Vec::new()));
    run(world.options(None, &events, Some(Event::new()))).unwrap();
    let pid = world.pid();
    let seen = events.lock().unwrap().clone();
    let running_event = &seen[0]["WORKSPACE_RUNNING"];
    assert_eq!(running_event["state"]["pid"], pid.to_string());
    assert_eq!(running_event["adopted_sharingd"], false);
    assert_eq!(running_event["job"], format!("gui/{}/com.apple.sharingd", sys::getuid()));
    assert_eq!(running_event["automatic_restore_seconds"], Value::Null);
    let certificate = base64::engine::general_purpose::STANDARD.encode(b"certificate");
    assert_eq!(seen[0]["broker_file"], format!(r#"{{"online": true, "socket": "{}", "tcp_port": {}, "token": "{}", "certificate": "{}"}}"#,
        broker["socket"].as_str().unwrap(), broker["tcp_port"], broker["auth_token"].as_str().unwrap(), certificate));
    assert_eq!(seen[1]["SHARINGD_DETACHED"]["pid"], pid.to_string());
    assert_eq!(seen.len(), 2);
    assert_eq!(world.journal()["detached"], true);
    assert_eq!(world.journal()["injected_pid"], pid);
    assert_eq!(std::fs::read_to_string(world.broker_file()).unwrap(), r#"{"online": false}"#);
    assert_eq!(std::fs::metadata(world.broker_file()).unwrap().permissions().mode() & 0o777, 0o600);
    let settings = std::fs::read_to_string(world.workspace.join("keystore.json")).unwrap();
    let logs = world.home.join("Library/Application Support/Mirra/logs");
    let state = world.home.join("Library/Application Support/Mirra/state");
    assert_eq!(settings, format!(concat!(r#"{{"attested_ltk_backup": "{}", "broker_file": "{}", "stdout": "{}", "stderr": "{}", "#,
        r#""environment": {{"MIRRA_KEYSTORE_BROKER_SOCKET": "{}", "MIRRA_KEYSTORE_BROKER_TCP_PORT": "{}", "MIRRA_KEYSTORE_BROKER_TOKEN": "{}", "#,
        r#""MIRRA_KEYSTORE_DCRT_PATH": "{}", "MIRRA_KEYSTORE_DIAGNOSTIC_ERRORS": "1", "MIRRA_ASSERT_DELAY_MODE": "2", "MIRRA_PAIRING_TRANSPORT": "wifi"}}}}"#),
        text(&state.join("attested-ltk.plist")), text(&world.broker_file()), text(&logs.join("sharingd.stdout.log")),
        text(&logs.join("sharingd.log")), broker["socket"].as_str().unwrap(), broker["tcp_port"],
        broker["auth_token"].as_str().unwrap(), broker["certificate"].as_str().unwrap()));
    let record: Value = serde_json::from_slice(&std::fs::read(world.workspace.join("sharing.json")).unwrap()).unwrap();
    assert_eq!(record["controller_pid"], std::process::id());
    let limits: Value = serde_json::from_slice(&std::fs::read(world.workspace.join("sharingd-log-limits.json")).unwrap()).unwrap();
    assert_eq!(limits["error"], Value::Null);
    let inode = std::fs::metadata(world.broker_file()).unwrap().ino();

    // 2. The broker resumes pairing, so the next session adopts sharingd.
    let mutations = world.launchd.mutations().len();
    let events = Arc::new(Mutex::new(Vec::new()));
    run(world.options(None, &events, Some(Event::new()))).unwrap();
    let seen = events.lock().unwrap().clone();
    assert_eq!(seen[0]["WORKSPACE_RUNNING"]["adopted_sharingd"], true);
    assert_eq!(world.pid(), pid);
    assert_eq!(world.launchd.mutations().len(), mutations);
    assert!(seen[1].get("SHARINGD_DETACHED").is_some());
    assert_eq!(std::fs::metadata(world.broker_file()).unwrap().ino(), inode);

    // 3. A bounded session restores Apple's sharingd when it ends.
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut options = world.options(Some(30), &events, Some(Event::new()));
    options.tick = Duration::from_millis(1);
    run(options).unwrap();
    let seen = events.lock().unwrap().clone();
    let restored = seen[1]["ORIGINAL_RESTORED"].as_object().unwrap();
    assert!(is_original(restored));
    assert_ne!(restored["pid"], pid.to_string());
    assert!(!world.home.join("Library/Caches/Mirra/sharing.json").exists());
    assert!(!world.workspace.join("keystore.json").exists());
    running.finish().unwrap();
}

#[test]
fn sharingd_restart_without_the_adapter_restores_and_fails() {
    let world = World::new();
    let running = start(&world.workspace, fake_bridge(false));
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut options = world.options(None, &events, None);
    let launchd = world.launchd.clone();
    let emit = options.emit.clone();
    options.emit = Arc::new(move |event| {
        if event.get("WORKSPACE_RUNNING").is_some() {
            // Apple's job relaunches sharingd on its own, without the adapter.
            launchd.state().job.as_mut().unwrap().pid = Some(4242);
        }
        emit(event);
    });
    let error = run(options).unwrap_err();
    assert_eq!(error.to_string(), "RuntimeError: sharingd restarted without the Mirra adapter");
    let seen = events.lock().unwrap().clone();
    assert!(seen.last().unwrap().get("ORIGINAL_RESTORED").is_some());
    assert!(!world.home.join("Library/Caches/Mirra/sharing.json").exists());
    running.finish().unwrap();
}

#[test]
fn adapter_that_never_loads_is_restored() {
    let world = World::new();
    world.launchd.state().marker_log = None;
    let running = start(&world.workspace, fake_bridge(false));
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut options = world.options(None, &events, None);
    options.adapter_wait = Duration::from_millis(50);
    let error = run(options).unwrap_err().to_string();
    assert!(error.starts_with("RuntimeError: sharingd did not load the adapter: {'injected': False, 'environment': {}, 'path': "), "{}", error);
    assert!(events.lock().unwrap().last().unwrap().get("ORIGINAL_RESTORED").is_some());
    running.finish().unwrap();
}

#[test]
fn unhealthy_broker_or_foreign_sharingd_stops_before_any_change() {
    let world = World::new();
    let running = start(&world.workspace, fake_bridge(false));
    *running.backend.poll.lock().unwrap() = Some(0);
    let events = Arc::new(Mutex::new(Vec::new()));
    assert_eq!(run(world.options(None, &events, None)).unwrap_err(), Failure::exit("Live USB/SEP broker health check failed"));
    running.finish().unwrap();

    let running = start(&world.workspace, fake_bridge(false));
    world.launchd.state().job.as_mut().unwrap().path = "/tmp/custom.plist".into();
    let error = run(world.options(None, &events, None)).unwrap_err().to_string();
    assert!(error.starts_with("Unexpected original service state: {'injected': False"), "{}", error);
    assert!(world.launchd.mutations().is_empty());
    assert!(events.lock().unwrap().is_empty());
    assert!(!world.broker_file().exists());
    running.finish().unwrap();
}

#[test]
fn broker_file_is_rewritten_in_place_and_must_stay_private() {
    let (_temporary, root) = private_directory();
    let certificate = root.join("c.der");
    std::fs::write(&certificate, b"\x01\x02").unwrap();
    let broker = json!({"socket": "/s", "tcp_port": 5, "auth_token": "t", "certificate": text(&certificate)});
    let path = root.join("broker.json");
    publish_broker(&path, Some(broker.as_object().unwrap())).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), r#"{"online": true, "socket": "/s", "tcp_port": 5, "token": "t", "certificate": "AQI="}"#);
    let inode = std::fs::metadata(&path).unwrap().ino();
    publish_broker(&path, None).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), r#"{"online": false}"#);
    assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(publish_broker(&path, None).unwrap_err(), Failure::runtime("Mirra broker file must be private"));
    assert_eq!(publish_broker(&root.join("x.json"), Some(json!({}).as_object().unwrap())).unwrap_err().to_string(), "KeyError: 'socket'");
}

#[test]
fn arguments_match_sharing_py() {
    let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(sharing_main(args(&["--seconds", "30", "--until-stopped"])), 2);
    assert_eq!(sharing_main(args(&["--seconds", "thirty"])), 2);
    assert_eq!(sharing_main(args(&["--bogus"])), 2);
}
