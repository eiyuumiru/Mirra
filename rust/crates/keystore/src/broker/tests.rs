//! The broker server over a fake bridge session: startup events, published
//! files, the unix/TCP wire protocol and shutdown.
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::time::Instant;

use super::*;
use crate::keystore::tests::{fixture_ltk, Fake};

pub(crate) struct Running {
    pub socket: PathBuf,
    pub state_file: PathBuf,
    pub stop: Event,
    pub events: Arc<Mutex<Vec<Value>>>,
    pub thread: Option<std::thread::JoinHandle<Result<(), Failure>>>,
    pub backend: Arc<Fake>,
}

impl Running {
    pub fn state(&self) -> Map<String, Value> {
        serde_json::from_slice::<Value>(&std::fs::read(&self.state_file).unwrap()).unwrap().as_object().cloned().unwrap()
    }
    pub fn finish(mut self) -> Result<(), Failure> {
        self.stop.set();
        self.thread.take().unwrap().join().unwrap()
    }
    pub fn events(&self) -> Vec<Value> {
        self.events.lock().unwrap().clone()
    }
}

/// A bridge whose saved keys let the broker resume pairing.
pub(crate) fn fake_bridge(resume: bool) -> Fake {
    let ready = json!({"ready": true, "dcrt_bytes": 1234, "client_saved": resume, "restored_identities": u8::from(resume),
        "kept_sessions": u8::from(resume)});
    let fake = Fake::new(ready);
    fake.script(|operation, _| Ok(match operation {
        "identities" => json!({"status": 0, "identities": [{"identity": "saved", "ltk": fixture_ltk(), "key_class": 9, "created": 1}]}),
        "generate" => json!({"status": 0, "identity": "fresh", "ltk": fixture_ltk()}),
        _ => json!({"status": 0}),
    }.as_object().cloned().unwrap()));
    fake
}

pub(crate) fn start(directory: &Path, fake: Fake) -> Running {
    let socket = directory.join("b.sock");
    let state_file = directory.join("broker-state.json");
    let setup = BrokerSetup { socket: socket.clone(), state_file: state_file.clone(), certificate: b"certificate".to_vec(),
        certificate_argument: None, minimum_created_at: None };
    let stop = Event::new();
    let events = Arc::new(Mutex::new(Vec::new()));
    let log = events.clone();
    let emit: Emit = Arc::new(move |event| log.lock().unwrap().push(event.clone()));
    let backend = Arc::new(fake);
    let (endpoint, flag) = (backend.clone() as Arc<dyn Backend>, stop.clone());
    let thread = std::thread::spawn(move || serve(&setup, endpoint, &flag, emit));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !events.lock().unwrap().iter().any(|e| e.get("ready").is_some()) {
        assert!(Instant::now() < deadline, "broker did not become ready");
        if thread.is_finished() {
            panic!("broker ended: {:?}", thread.join().unwrap());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Running { socket, state_file, stop, events, thread: Some(thread), backend }
}

pub(crate) fn private_directory() -> (tempfile::TempDir, PathBuf) {
    let temporary = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(temporary.path()).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    (temporary, root)
}

fn exchange<S: Read + Write>(mut stream: S, request: &[u8]) -> Option<Value> {
    let mut frame = (request.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(request);
    stream.write_all(&frame).unwrap();
    let mut size = [0u8; 4];
    if stream.read_exact(&mut size).is_err() {
        return None;
    }
    let mut data = vec![0u8; u32::from_be_bytes(size) as usize];
    stream.read_exact(&mut data).unwrap();
    Some(serde_json::from_slice(&data).unwrap())
}

fn wait_for_event(running: &Running, predicate: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(event) = running.events().into_iter().find(|e| predicate(e)) {
            return event;
        }
        assert!(Instant::now() < deadline, "missing event; saw {:?}", running.events());
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn startup_publishes_private_files_and_python_event_lines() {
    let (_temporary, root) = private_directory();
    let running = start(&root, fake_bridge(true));
    let events = running.events();
    assert_eq!(pyjson::dumps(&events[0]),
        r#"{"saved_mac": true, "restored_identities": 1, "restore_failures": 0, "kept_sessions": 1}"#);
    let state = running.state();
    let port = state["tcp_port"].as_u64().unwrap();
    assert_eq!(pyjson::dumps(&events[1]), format!(
        r#"{{"ready": true, "socket": "{}", "tcp_port": {}, "dcrt_bytes": 1234, "attested_key_validated": true, "certificate_binding_verified": false}}"#,
        text(&running.socket), port));
    let token = state["auth_token"].as_str().unwrap().to_string();
    assert_eq!(token.len(), 64);
    let certificate = root.join("certificate.der");
    assert_eq!(std::fs::read_to_string(&running.state_file).unwrap(), format!(
        "{{\"pid\": {}, \"socket\": \"{}\", \"directory\": \"{}\", \"tcp_port\": {}, \"auth_token\": \"{}\", \"certificate\": \"{}\"}}\n",
        std::process::id(), text(&running.socket), text(&root), port, token, text(&certificate)));
    for path in [&running.state_file, &running.socket, &certificate] {
        assert_eq!(std::fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777, 0o600, "{:?}", path);
    }
    assert_eq!(std::fs::read(&certificate).unwrap(), b"certificate");
    // Saved keys were adopted, so sharingd may keep its pairing.
    let health = mirra_core::health::health(&running.socket, Duration::from_secs(5)).unwrap();
    assert_eq!(health["ready"], true);
    assert_eq!(health["can_resume_pairing"], true);
    assert_eq!(health["identities"], 2);
    let socket = running.socket.clone();
    running.finish().unwrap();
    assert!(!socket.exists());
}

#[test]
fn unix_and_tcp_requests_follow_the_adapter_wire_protocol() {
    let (_temporary, root) = private_directory();
    let running = start(&root, fake_bridge(false));
    let state = running.state();
    let token = state["auth_token"].as_str().unwrap().to_string();
    let port = state["tcp_port"].as_u64().unwrap() as u16;

    let generated = exchange(UnixStream::connect(&running.socket).unwrap(), br#"{"operation": "generate", "key_class": 9}"#).unwrap();
    assert_eq!(generated["status"], 0);
    let event = wait_for_event(&running, |e| e["operation"] == "generate");
    assert_eq!(pyjson::dumps(&event), format!(r#"{{"operation": "generate", "status": 0, "bytes": {}, "error": null}}"#, generated["bytes"]));

    // TCP requires the token; a wrong one gets no reply at all.
    let tcp = || std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    assert!(exchange(tcp(), br#"{"operation": "health"}"#).is_none());
    assert!(exchange(tcp(), br#"{"operation": "health", "_auth": "wrong"}"#).is_none());
    let request = format!(r#"{{"operation": "health", "_auth": "{}"}}"#, token);
    assert_eq!(exchange(tcp(), request.as_bytes()).unwrap()["ready"], true);
    let request = format!(r#"{{"operation": "validate", "local_ltk": {}, "_auth": "{}"}}"#, generated["data"], token);
    assert_eq!(exchange(tcp(), request.as_bytes()).unwrap()["status"], 0);
    let validate = running.backend.calls.lock().unwrap().iter().rev().find(|c| c.0 == "validate").unwrap().1.clone();
    assert_eq!(validate, json!({"identity": "fresh"}));

    // Oversized frames and non-objects are dropped; malformed JSON is logged.
    let mut stream = UnixStream::connect(&running.socket).unwrap();
    stream.write_all(&(MAX_REQUEST + 1).to_be_bytes()).unwrap();
    let mut buffer = [0u8; 1];
    assert_eq!(stream.read(&mut buffer).unwrap(), 0);
    assert!(exchange(UnixStream::connect(&running.socket).unwrap(), b"[1]").is_none());
    assert!(exchange(UnixStream::connect(&running.socket).unwrap(), b"{bad").is_none());
    let error = wait_for_event(&running, |e| e.get("transport_error").is_some());
    assert!(error["transport_error"].as_str().unwrap().starts_with("JSONDecodeError: "));
    // A client that disconnects mid-frame is reported like Python's readn.
    let mut stream = UnixStream::connect(&running.socket).unwrap();
    stream.write_all(&[0, 0, 0, 9, b'{']).unwrap();
    drop(stream);
    wait_for_event(&running, |e| e["transport_error"] == "ConnectionError: client closed");
    running.finish().unwrap();
}

#[test]
fn endpoint_errors_are_logged_with_transport_details() {
    let (_temporary, root) = private_directory();
    let fake = fake_bridge(false);
    let running = start(&root, fake);
    running.backend.script(|_, _| Err(mirra_bridge::EndpointError::new("Bridge reply timed out", Some("endpoint_reply_timeout"),
        json!({"operation": "get_state", "data": "secret"}).as_object().cloned().unwrap()).into()));
    assert!(exchange(UnixStream::connect(&running.socket).unwrap(), br#"{"operation": "get_state", "data": "x"}"#).is_none());
    let event = wait_for_event(&running, |e| e.get("transport_error").is_some());
    assert_eq!(pyjson::dumps(&event), r#"{"transport_error": "EndpointError: Bridge reply timed out", "transport_failure": {"code": "endpoint_reply_timeout", "operation": "get_state"}}"#);
    running.finish().unwrap();
}

#[test]
fn failed_self_check_closes_the_session_without_publishing() {
    let (_temporary, root) = private_directory();
    for (ready, reply, message) in [
        (json!({"dcrt_bytes": 0}), json!({"status": 0}), "RuntimeError: Backend endpoint has no device certificate"),
        (json!({"dcrt_bytes": 1}), json!({"status": -7, "status_hex": "0xfffffff9"}),
            "RuntimeError: Backend cannot create an attested signing key: 0xfffffff9"),
    ] {
        let fake = Fake::new(ready);
        fake.returns(reply);
        let setup = BrokerSetup { socket: root.join("x.sock"), state_file: root.join("state.json"), certificate: vec![1],
            certificate_argument: None, minimum_created_at: None };
        let result = serve(&setup, Arc::new(fake), &Event::new(), Arc::new(|_| {}));
        assert_eq!(result.unwrap_err().to_string(), message);
        assert!(!root.join("x.sock").exists());
        assert!(!root.join("state.json").exists());
    }
}

#[test]
fn arguments_match_broker_py() {
    let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let parsed = parse_args(&args(&["--socket", "/d//b.sock", "--state-file=/d/s.json", "--certificate", "/d/c.der",
        "--renewed-certificate", "--parent-lifeline"])).unwrap();
    assert_eq!(parsed, BrokerArgs { socket: "/d/b.sock".into(), state_file: "/d/s.json".into(), config: None,
        certificate: Some("/d/c.der".into()), renewed_certificate: true, parent_lifeline: true });
    assert_eq!(parse_args(&args(&["--socket", "/d/b.sock"])), Err(2));
    assert_eq!(broker_main(args(&["--state-file", "/x"])), 2);
}
