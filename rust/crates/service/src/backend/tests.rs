#![allow(clippy::result_large_err)]
use super::*;
use mirra_bridge::CertificateError;

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    config: PathBuf,
    runtime: PathBuf,
    events: Arc<Mutex<Vec<Value>>>,
    context: BackendContext,
}

const SHARING: &str = r#"printf '%s\n' '{"WORKSPACE_RUNNING": {"state": {"pid": '"$$"'}}}' 'not json' '{"ORIGINAL_RESTORED": {"restored": true}}'
sleep 0.3"#;

fn fixture(sharing: &'static str, restored: bool) -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let root = mirra_core::paths::resolve(temp.path());
    let runtime = root.join("runtime/host");
    std::fs::create_dir_all(root.join("private")).unwrap();
    std::fs::write(root.join("private/certificate.der"), b"enrolled certificate").unwrap();
    let config = root.join("config.json");
    write_state(&config, &json!({"backend": {"transport": "ssh", "certificate_file": util::text(&root.join("private/certificate.der"))},
        "host": {"runtime_directory": util::text(&runtime)}})).unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    let context = BackendContext {
        root: root.clone(),
        home: root.clone(),
        child: Arc::new(move |name| {
            let mut command = Command::new("/bin/sh");
            // The broker waits on its lifeline; the controller reports a session.
            command.args(["-c", if name == "broker" { "exec cat >/dev/null" } else { sharing }, name]);
            command
        }),
        broker_markers: vec![],
        emit: Arc::new(move |event| sink.lock().unwrap().push(event.clone())),
        certificate: Arc::new(|_, _, _| Ok(CurrentCertificate { data: b"current".to_vec(), start: 0.0, end: 1.0, renewed: true })),
        health: Arc::new(|_, _| Ok(json!({"ready": true}).as_object().unwrap().clone())),
        sharingd_print: Arc::new(move || Ok(Reply { code: 0, stderr: String::new(), stdout: if restored {
            "path = /System/Library/LaunchAgents/com.apple.sharingd.plist\nprogram = /usr/libexec/sharingd\n".into()
        } else {
            "path = /tmp/sharing.plist\nprogram = /usr/libexec/sharingd\nDYLD_INSERT_LIBRARIES => x\n".into()
        } })),
        loss_interval: Duration::from_millis(50),
    };
    Fixture { _temp: temp, root, config, runtime, events, context }
}

impl Fixture {
    fn run(&self) -> i32 {
        let _serial = crate::testing::SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        run_backend(&["--config".into(), util::text(&self.config), "--until-stopped".into()], &self.context)
    }
    fn keys(&self) -> Vec<String> {
        self.events.lock().unwrap().iter().map(|e| e.as_object().unwrap().keys().next().unwrap().clone()).collect()
    }
    fn result(&self) -> Value {
        let path = std::fs::read_dir(&self.runtime).unwrap().map(|e| e.unwrap().path())
            .find(|p| p.file_name().unwrap().to_str().unwrap().starts_with("session-result-")).unwrap();
        util::read_json(&path).unwrap()
    }
}

#[test]
fn arguments_follow_argparse() {
    let strings = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(parse_args(&strings(&["--config", "/c.json", "--until-stopped", "--parent-lifeline"])).unwrap(),
        BackendArgs { seconds: None, until_stopped: true, config: Some("/c.json".into()), parent_lifeline: true });
    assert_eq!(parse_args(&strings(&["--seconds=60"])).unwrap().seconds, Some(60));
    assert_eq!(parse_args(&strings(&["--seconds", "60", "--until-stopped"])), Err(2));
    assert_eq!(parse_args(&strings(&["--seconds", "x"])), Err(2));
    assert_eq!(parse_args(&strings(&["--bogus"])), Err(2));
    let f = fixture(SHARING, true);
    assert_eq!(run_backend(&strings(&["--config", &util::text(&f.config), "--seconds", "5"]), &f.context), 2);
}

#[test]
fn session_runs_children_and_restores_sharingd() {
    let f = fixture(SHARING, true);
    assert_eq!(f.run(), 0);
    assert_eq!(f.keys(), ["BRIDGE_CERTIFICATE_READY", "USB_BROKER_READY", "NATIVE_WORKSPACE_READY", "ORIGINAL_RESTORED", "SESSION_FINISHED"]);
    let events = f.events.lock().unwrap().clone();
    assert_eq!(events[3], json!({"ORIGINAL_RESTORED": {"restored": true}}));
    let finished = &events[4];
    assert_eq!(finished["original_sharingd_restored"], true);
    assert_eq!(finished["broker_terminal"], true);
    let result = f.result();
    assert_eq!(result["controller_exit_code"], 0);
    assert_eq!(result["finished"], true);
    assert_eq!(result["broker_workspace_cleanup"], json!({"removed": true}));
    assert_eq!(result["pairing_transport"], "wifi");
    assert_eq!(result["duration_seconds"], Value::Null);
    assert_eq!(result.as_object().unwrap().keys().take(9).collect::<Vec<_>>(), ["wrapper_pid", "duration_seconds", "run",
        "wire_platform", "assert_delay_mode", "pairing_transport", "broker_pid", "controller_pid", "broker_log"]);
    let children = util::read_json(&f.runtime.join("backend-children.json")).unwrap();
    assert_eq!(children.as_object().unwrap().keys().collect::<Vec<_>>(), ["broker", "controller", "sharingd"]);
    let log = std::fs::read_to_string(f.runtime.join(result["controller_log"].as_str().unwrap())).unwrap();
    assert!(log.contains("not json"));
    assert!(f.runtime.join("session-active.json").is_file());
}

#[test]
fn expired_certificate_is_tolerated_with_the_enrolled_file() {
    let mut f = fixture(SHARING, true);
    f.context.certificate = Arc::new(|_, _, on_renewal| {
        on_renewal();
        Err(CertificateError::new("expired", "The bridge still has an expired certificate", Some(1234.5)).into())
    });
    assert_eq!(f.run(), 0);
    let events = f.events.lock().unwrap().clone();
    assert_eq!(events[0], json!({"BRIDGE_CERTIFICATE_RENEWAL": true}));
    assert_eq!(events[1], json!({"BRIDGE_CERTIFICATE_EXPIRED_TOLERATED": true, "retry_at": 1234.5}));
    assert_eq!(events[2], json!({"BRIDGE_CERTIFICATE_READY": true}));
}

#[test]
fn other_certificate_errors_stop_before_the_broker() {
    let mut f = fixture(SHARING, true);
    f.context.certificate = Arc::new(|_, _, _| Err(CertificateError::new("clock", "Check the Mac’s clock.", None).into()));
    assert_eq!(f.run(), 1);
    assert_eq!(f.keys(), ["BRIDGE_CERTIFICATE_ERROR", "SESSION_FINISHED"]);
    let events = f.events.lock().unwrap().clone();
    assert_eq!(events[0], json!({"BRIDGE_CERTIFICATE_ERROR": "clock", "retry_at": null}));
    assert_eq!(events[1]["broker_terminal"], true);
    assert!(f.result().get("broker_pid").is_none());
}

#[test]
fn unrestored_sharingd_or_failed_controller_fails_the_session() {
    let f = fixture(SHARING, false);
    assert_eq!(f.run(), 1);
    assert_eq!(f.result()["original_sharingd_restored"], false);
    assert!(f.result().get("broker_workspace_cleanup").is_none());
    let f = fixture("exit 3", true);
    assert_eq!(f.run(), 1);
    assert_eq!(f.result()["controller_exit_code"], 3);
}

#[test]
fn a_held_session_lock_refuses_a_second_controller() {
    let f = fixture(SHARING, true);
    let _lease = crate::supervisor_lease::backend_lease(&f.root).unwrap();
    assert_eq!(f.run(), 1);
    assert!(f.events.lock().unwrap().is_empty());
}

#[test]
fn unready_broker_ends_with_restoration_report() {
    let mut f = fixture(SHARING, true);
    f.context.child = Arc::new(|_| {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 0", "broker"]);
        command
    });
    f.context.health = Arc::new(|_, _| Err(mirra_core::Error::Timeout("timed out".into())));
    assert_eq!(f.run(), 1);
    assert_eq!(f.keys(), ["BRIDGE_CERTIFICATE_READY", "SESSION_FINISHED"]);
}

#[test]
fn exclusive_write_never_replaces_a_file() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("nested/certificate.der");
    exclusive_write(&path, b"one").unwrap();
    assert_eq!(exclusive_write(&path, b"two").unwrap_err().type_name(), "FileExistsError");
    assert_eq!(std::fs::read(&path).unwrap(), b"one");
    assert_eq!(std::fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
}
