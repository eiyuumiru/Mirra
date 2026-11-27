use super::*;
use crate::installation::Object;
use mirra_bridge::CertificateError;
use mirra_core::activity::collector;
use serde_json::Map;
use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Default)]
struct FakeService {
    manifest: Object,
    start_error: Option<fn() -> Error>,
    stop_error: Option<fn() -> Error>,
    calls: Mutex<Vec<&'static str>>,
}

impl SupportService for FakeService {
    fn package(&self) -> PathBuf {
        PathBuf::from("/fixture/current")
    }
    fn validate_package(&self) -> Result<Object> {
        self.calls.lock().unwrap().push("validate");
        Ok(self.manifest.clone())
    }
    fn status(&self) -> Result<Object> {
        Ok(Map::new())
    }
    fn start(&self) -> Result<Object> {
        self.calls.lock().unwrap().push("start");
        self.start_error.map_or(Ok(Map::new()), |e| Err(e()))
    }
    fn stop(&self) -> Result<Object> {
        self.calls.lock().unwrap().push("stop");
        self.stop_error.map_or(Ok(Map::new()), |e| Err(e()))
    }
    fn registration(&self) -> Result<Object> {
        Ok(Map::new())
    }
}

struct FakeEnv {
    service: FakeService,
    report: Value,
    update: Option<Value>,
    renewal: RefCell<Option<std::result::Result<(), mirra_bridge::Error>>>,
    renew_calls: RefCell<Vec<PathBuf>>,
    forget_error: Option<fn() -> Error>,
}

impl FakeEnv {
    fn new(report: Value) -> Self {
        FakeEnv { service: FakeService::default(), report, update: None, renewal: RefCell::new(None), renew_calls: RefCell::new(Vec::new()), forget_error: None }
    }
}

impl ControlEnv for FakeEnv {
    fn service(&self) -> &dyn SupportService {
        &self.service
    }
    fn observe(&self) -> Value {
        self.report.clone()
    }
    fn load_config(&self, path: &Path) -> Result<Config> {
        assert_eq!(path, Path::new("/fixture/current/config.json"));
        let temp = std::env::temp_dir();
        Ok(load_config(None, &temp.join("mirra-control-fixture-root"))?)
    }
    fn bridge_update_report(&self, _: &Config) -> Result<Option<Value>> {
        Ok(self.update.clone())
    }
    fn renew(&self, _: &Config, state: &Path) -> std::result::Result<(), mirra_bridge::Error> {
        self.renew_calls.borrow_mut().push(state.to_path_buf());
        self.renewal.borrow_mut().take().unwrap_or(Ok(()))
    }
    fn restore_sharingd(&self) -> Result<()> {
        self.service.calls.lock().unwrap().push("restore_sharingd");
        Ok(())
    }
    fn forget_bridge(&self, _: &Config) -> Result<()> {
        self.service.calls.lock().unwrap().push("forget_bridge");
        self.forget_error.map_or(Ok(()), |e| Err(e()))
    }
    fn forget_local_pairing(&self) -> Result<Value> {
        self.service.calls.lock().unwrap().push("forget_local_pairing");
        Ok(json!({"keychain_items": 1, "backup_files": 2, "pairing_entries": 1}))
    }
}

fn invoke(action: &str, env: &FakeEnv) -> (ControlDispatch, Option<Value>, Vec<Value>) {
    let (sink, records) = collector();
    let args = ControlArgs { action: action.into(), profile: None };
    let mut printed = None;
    let dispatch = activity::capture(Some(sink), || control(&args, env, &mut |v| printed = Some(v.clone())));
    let records = records.lock().unwrap().clone();
    (dispatch, printed, records)
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[test]
fn arguments_follow_argparse() {
    assert_eq!(parse_args(&strings(&["status"])).unwrap(), ControlArgs { action: "status".into(), profile: None });
    assert_eq!(parse_args(&strings(&["install", "--profile", "/p.json"])).unwrap().profile.as_deref(), Some("/p.json"));
    assert_eq!(parse_args(&strings(&["--profile=/p.json", "install"])).unwrap().action, "install");
    assert_eq!(parse_args(&strings(&["status", "--profile", "/p.json"])), Err(2));
    assert_eq!(parse_args(&strings(&["restart"])), Err(2));
    assert_eq!(parse_args(&strings(&[])), Err(2));
    assert_eq!(parse_args(&strings(&["status", "extra"])), Err(2));
    assert_eq!(parse_args_quiet(&strings(&["--profile", "/p", "install"])).unwrap().action, "install");
    assert!(parse_args_quiet(&strings(&["bogus"])).is_none());
}

#[test]
fn install_is_delegated_without_logging_or_reply() {
    let temp = tempfile::tempdir().unwrap();
    let env = FakeEnv::new(json!({"state": "ready"}));
    assert_eq!(control_dispatch(&strings(&["install", "--profile", "/p.json"]), &env, temp.path()),
        ControlDispatch::DelegateToPython(strings(&["install", "--profile", "/p.json"])));
    assert!(!temp.path().join("Library").exists());
    let (dispatch, printed, records) = invoke("install", &env);
    assert_eq!(dispatch, ControlDispatch::DelegateToPython(strings(&["install"])));
    assert!(printed.is_none() && records.is_empty());
}

#[test]
fn status_replies_with_the_observed_report() {
    let env = FakeEnv::new(json!({"state": "ready", "actions": ["open_mirroring"]}));
    let (dispatch, printed, records) = invoke("status", &env);
    assert_eq!(dispatch, ControlDispatch::Exit(0));
    let reply = printed.unwrap();
    assert_eq!(reply, json!({"ok": true, "report": env.report}));
    assert_eq!(mirra_core::pyjson::dumps(&reply), r#"{"ok": true, "report": {"state": "ready", "actions": ["open_mirroring"]}}"#);
    assert_eq!(records.iter().map(|r| r["message"].as_str().unwrap()).collect::<Vec<_>>(), ["request", "reply"]);
    assert_eq!(records[0]["fields"], json!({"action": "status"}));
    assert_eq!(records[1]["fields"]["result"], reply);
}

#[test]
fn failed_action_returns_one_generic_failure_reply() {
    let mut env = FakeEnv::new(json!({"state": "update_available"}));
    env.service.stop_error = Some(|| Error::runtime("PRIVATE_ACCOUNT_DETAIL"));
    let (dispatch, printed, records) = invoke("stop", &env);
    assert_eq!(dispatch, ControlDispatch::Exit(1));
    let reply = printed.unwrap();
    assert_eq!(reply["ok"], false);
    assert_eq!(reply["report"], env.report);
    assert!(reply["message"].as_str().unwrap().contains("Refresh status"));
    assert!(!mirra_core::pyjson::dumps(&reply).contains("PRIVATE_ACCOUNT_DETAIL"));
    assert_eq!(records.iter().filter(|r| r["message"] == "reply").count(), 1);
    assert_eq!(reply.as_object().unwrap().keys().collect::<Vec<_>>(), ["ok", "message", "report"]);
}

#[test]
fn python_only_work_is_delegated_before_replying() {
    let mut env = FakeEnv::new(json!({"state": "stopped"}));
    env.service.start_error = Some(|| Error::Delegate("interrupted install".into()));
    let (dispatch, printed, _) = invoke("start", &env);
    assert_eq!(dispatch, ControlDispatch::DelegateToPython(strings(&["start"])));
    assert!(printed.is_none());
}

#[test]
fn preflight_reports_the_check_and_its_report() {
    let env = FakeEnv::new(json!({"state": "waiting_for_bridge", "detail": "Keep it reachable."}));
    let (dispatch, printed, _) = invoke("preflight", &env);
    assert_eq!(dispatch, ControlDispatch::Exit(0));
    let reply = printed.unwrap();
    assert_eq!(reply["ok"], true);
    assert_eq!(reply["preflight"]["state"], "blocked");
    assert_eq!(reply["preflight"]["message"], "Keep it reachable.");
    assert_eq!(reply["report"], env.report);
}

#[test]
fn renew_checks_the_installed_profile_and_returns_the_result() {
    let mut env = FakeEnv::new(json!({"state": "waiting_for_bridge"}));
    env.service.manifest = json!({"support_revision": CERTIFICATE_LOCK_REVISION}).as_object().unwrap().clone();
    let (dispatch, printed, _) = invoke("renew", &env);
    assert_eq!(dispatch, ControlDispatch::Exit(0));
    let reply = printed.unwrap();
    assert_eq!(reply["message"], "A valid bridge certificate is available. Mirra will use it the next time background support connects.");
    assert_eq!(*env.renew_calls.borrow(), [PathBuf::from("/fixture/current/runtime/certificate-renewal.json")]);
    let mut env = FakeEnv::new(json!({"state": "ready"}));
    env.service.manifest = json!({"support_revision": CERTIFICATE_LOCK_REVISION}).as_object().unwrap().clone();
    assert_eq!(invoke("renew", &env).1.unwrap()["message"], "A valid bridge certificate is available. Background support is ready.");
}

#[test]
fn renew_reports_an_unchanged_expired_certificate() {
    let mut env = FakeEnv::new(json!({"state": "bridge_certificate_expired"}));
    env.service.manifest = json!({"support_revision": CERTIFICATE_LOCK_REVISION}).as_object().unwrap().clone();
    let message = "The iPhone still returns the same expired certificate after requesting renewal";
    *env.renewal.borrow_mut() = Some(Err(CertificateError::new("expired", message, None).into()));
    let (dispatch, printed, _) = invoke("renew", &env);
    assert_eq!(dispatch, ControlDispatch::Exit(1));
    assert_eq!(printed.unwrap(), json!({"ok": false, "message": message, "report": env.report}));
}

#[test]
fn renew_requires_the_shared_lock_and_a_current_bridge() {
    let mut env = FakeEnv::new(json!({"state": "ready"}));
    env.service.manifest = json!({"support_revision": CERTIFICATE_LOCK_REVISION - 1}).as_object().unwrap().clone();
    let (_, printed, _) = invoke("renew", &env);
    assert!(printed.unwrap()["message"].as_str().unwrap().contains("Update Mirra support"));
    assert!(env.renew_calls.borrow().is_empty());
    let mut env = FakeEnv::new(json!({"state": "ready"}));
    env.service.manifest = json!({"support_revision": CERTIFICATE_LOCK_REVISION}).as_object().unwrap().clone();
    let outdated = json!({"state": "bridge_update_available", "detail": "Update Bridge", "actions": ["update_bridge"]});
    env.update = Some(outdated.clone());
    let (dispatch, printed, _) = invoke("renew", &env);
    assert_eq!(dispatch, ControlDispatch::Exit(1));
    assert_eq!(printed.unwrap(), json!({"ok": false, "message": "Update Bridge", "report": outdated}));
    assert!(env.renew_calls.borrow().is_empty());
}

#[test]
fn dispatch_writes_the_private_control_log() {
    let temp = tempfile::tempdir().unwrap();
    let env = FakeEnv::new(json!({"state": "ready"}));
    assert_eq!(control_dispatch(&strings(&["stop"]), &env, temp.path()), ControlDispatch::Exit(0));
    let logs = temp.path().join("Library/Application Support/Mirra/logs");
    let names: Vec<String> = std::fs::read_dir(&logs).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    assert_eq!(names.len(), 1);
    assert!(names[0].starts_with("control-") && names[0].ends_with(".log"));
    let text = std::fs::read_to_string(logs.join(&names[0])).unwrap();
    let messages: Vec<String> = text.lines().map(|l| serde_json::from_str::<Value>(l).unwrap()["message"].as_str().unwrap().to_string()).collect();
    assert_eq!(messages, ["request", "reply"]);
    // status keeps only errors and stderr.
    assert_eq!(control_dispatch(&strings(&["status"]), &env, temp.path()), ControlDispatch::Exit(0));
    assert_eq!(std::fs::read_to_string(logs.join(&names[0])).unwrap(), text);
}

#[test]
fn reset_forgets_the_pairing_between_stop_and_start() {
    let env = FakeEnv::new(json!({"state": "ready"}));
    assert_eq!(parse_args(&strings(&["reset"])).unwrap().action, "reset");
    let (dispatch, printed, _) = invoke("reset", &env);
    assert_eq!(dispatch, ControlDispatch::Exit(0));
    let printed = printed.unwrap();
    assert_eq!(printed["ok"], json!(true));
    assert_eq!(printed["message"], json!(crate::reset::RESET_MESSAGE));
    assert_eq!(printed["reset"]["keychain_items"], json!(1));
    assert_eq!(*env.service.calls.lock().unwrap(),
        ["validate", "stop", "restore_sharingd", "forget_bridge", "forget_local_pairing", "start"]);
}

#[test]
fn reset_needs_a_current_bridge_and_changes_nothing_otherwise() {
    let mut env = FakeEnv::new(json!({"state": "ready"}));
    env.update = Some(json!({"state": "bridge_update_available", "detail": "Update the bridge first."}));
    let (dispatch, printed, _) = invoke("reset", &env);
    assert_eq!(dispatch, ControlDispatch::Exit(1));
    assert_eq!(printed.unwrap()["message"], json!("Update the bridge first."));
    assert_eq!(*env.service.calls.lock().unwrap(), ["validate"]);
}

#[test]
fn a_failed_reset_still_starts_support_again() {
    let mut env = FakeEnv::new(json!({"state": "ready"}));
    env.forget_error = Some(|| Error::runtime("The bridge did not forget this Mac: unknown_operation"));
    let (dispatch, printed, _) = invoke("reset", &env);
    assert_eq!(dispatch, ControlDispatch::Exit(1));
    assert_eq!(printed.unwrap()["ok"], json!(false));
    assert_eq!(*env.service.calls.lock().unwrap(), ["validate", "stop", "restore_sharingd", "forget_bridge", "start"]);
}
