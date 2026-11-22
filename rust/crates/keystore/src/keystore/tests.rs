//! Port of tests/test_keystore.py with a scripted fake bridge session.
use std::sync::Mutex;

use base64::Engine;
use mirra_bridge::wire::wrap;

use super::*;

type Script = Box<dyn FnMut(&str, &Value) -> Result<Map<String, Value>> + Send>;

pub(crate) struct Fake {
    pub ready: Map<String, Value>,
    pub timeout: Duration,
    pub calls: Mutex<Vec<(String, Value, Option<Instant>)>>,
    pub script: Mutex<Script>,
    pub failure: Mutex<Option<EndpointError>>,
    pub poll: Mutex<Option<i32>>,
}

impl Fake {
    pub fn new(ready: Value) -> Self {
        Fake { ready: ready.as_object().cloned().unwrap_or_default(), timeout: Duration::from_secs(1),
            calls: Mutex::new(Vec::new()), script: Mutex::new(Box::new(|_, _| Ok(Map::new()))),
            failure: Mutex::new(None), poll: Mutex::new(None) }
    }
    pub fn script(&self, script: impl FnMut(&str, &Value) -> Result<Map<String, Value>> + Send + 'static) {
        *self.script.lock().unwrap() = Box::new(script);
    }
    pub fn returns(&self, reply: Value) {
        self.script(move |_, _| Ok(reply.as_object().cloned().unwrap()));
    }
    pub fn sequence(&self, replies: Vec<Result<Value>>) {
        let mut replies: std::collections::VecDeque<_> = replies.into();
        self.script(move |_, _| replies.pop_front().expect("unexpected call").map(|v| v.as_object().cloned().unwrap()));
    }
    pub fn count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
    pub fn reset_calls(&self) {
        self.calls.lock().unwrap().clear();
    }
}

impl Backend for Fake {
    fn ready(&self) -> &Map<String, Value> {
        &self.ready
    }
    fn timeout(&self) -> Duration {
        self.timeout
    }
    fn call(&self, operation: &str, fields: Value, deadline: Option<Instant>) -> Result<Map<String, Value>> {
        self.calls.lock().unwrap().push((operation.to_string(), fields.clone(), deadline));
        (self.script.lock().unwrap())(operation, &fields)
    }
    fn failure(&self) -> Option<EndpointError> {
        self.failure.lock().unwrap().clone()
    }
    fn poll(&self) -> Option<i32> {
        *self.poll.lock().unwrap()
    }
}

/// tests/test_provisioning.py `fixture_ltk()`: structurally valid test data.
pub(crate) fn fixture_ltk() -> String {
    let mut inner = Vec::new();
    for (tag, size) in [(0x81u8, 1usize), (0x85, 600), (0x86, 32), (0x82, 32), (0x83, 32), (0x84, 32)] {
        inner.extend(wrap(tag, &vec![tag; size]));
    }
    base64::engine::general_purpose::STANDARD.encode(wrap(0x30, &inner))
}

fn object(value: Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap()
}

fn endpoint_error(message: &str) -> Error {
    EndpointError::message(message).into()
}

fn broker() -> AksBroker<Arc<Fake>> {
    let mut broker = AksBroker::new(Arc::new(Fake::new(json!({}))), None);
    broker.identities.insert("owned-local".into(), "private-identity".into());
    broker
}

fn session(broker: &mut AksBroker<Arc<Fake>>) -> Result<Map<String, Value>> {
    broker.execute(&object(json!({"operation": "session_signed", "local_ltk": "owned-local",
        "remote_ltk": "owned-remote", "flags": 2})))
}

fn health(broker: &mut AksBroker<Arc<Fake>>) -> Map<String, Value> {
    broker.execute(&object(json!({"operation": "health"}))).unwrap()
}

#[test]
fn invalid_successful_generation_never_publishes_a_broker_identity() {
    let mut broker = broker();
    broker.endpoint.returns(json!({"status": 0, "error": "keystore_parameters_unavailable", "operation_stage": "aks_params_create"}));
    let result = broker.execute(&object(json!({"operation": "generate", "key_class": 9}))).unwrap();
    assert_eq!(result["status"], UNAVAILABLE);
    assert_eq!(result["backend_operation"]["status"], 0);
    assert_eq!(result["backend_operation"]["operation_stage"], "aks_params_create");
    assert!(broker.classes.is_empty());
    assert!(broker.wire_keys.is_empty());
    assert_eq!(health(&mut broker)["ready"], false);
}

#[test]
fn malformed_generation_and_unsupported_wire_layout_never_publish_keys() {
    for fields in [json!({"status": false}), json!({"identity": ["bad-type"]}), json!({"ltk": 123}), json!({"ltk": "dW5zdXBwb3J0ZWQ="})] {
        let mut broker = broker();
        let mut reply = object(json!({"status": 0, "identity": "private-identity", "ltk": fixture_ltk()}));
        reply.extend(object(fields.clone()));
        broker.endpoint.returns(Value::Object(reply));
        let result = broker.execute(&object(json!({"operation": "generate", "key_class": 9}))).unwrap();
        assert_eq!(result["status"], UNAVAILABLE, "{}", fields);
        assert!(broker.classes.is_empty());
        assert!(broker.wire_keys.is_empty());
        assert!(!result.contains_key("ltk"));
        assert_eq!(health(&mut broker)["ready"], false);
    }
}

#[test]
fn generation_is_cached_per_class_and_reports_the_wire_key() {
    let mut broker = broker();
    broker.endpoint.returns(json!({"status": 0, "identity": "id-9", "ltk": fixture_ltk()}));
    let first = broker.execute(&object(json!({"operation": "generate"}))).unwrap();
    let second = broker.execute(&object(json!({"operation": "generate", "key_class": 9}))).unwrap();
    assert_eq!(first, second);
    assert_eq!(broker.endpoint.count(), 1);
    assert_eq!(broker.endpoint.calls.lock().unwrap()[0].1, json!({"attested": true, "key_class": 9}));
    let wire = first["data"].as_str().unwrap();
    assert_eq!(first["bytes"], base64::engine::general_purpose::STANDARD.decode(wire).unwrap().len());
    assert_eq!(broker.identities[wire], "id-9");
    assert_eq!(broker.identities[&fixture_ltk()], "id-9");
    assert_eq!(broker.execute(&object(json!({"operation": "generate", "key_class": 8}))).unwrap(),
        object(json!({"error": "invalid_key_class"})));
    assert_eq!(broker.execute(&object(json!({"operation": "generate", "key_class": true}))).unwrap(),
        object(json!({"error": "invalid_key_class"})));
    broker.endpoint.returns(json!({"status": -5}));
    assert_eq!(broker.execute(&object(json!({"operation": "generate", "key_class": 10}))).unwrap(), object(json!({"status": -5})));
    assert!(broker.failure.is_none());
}

#[test]
fn handles_remain_distinct_after_thousands_of_reconnects() {
    let mut broker = broker();
    broker.endpoint.script(|op, _| Ok(object(if op == "session_signed" { json!({"status": 0, "session": 7}) } else { json!({"status": 0}) })));
    let mut old: Option<i64> = None;
    for _ in 0..4100 {
        let current = session(&mut broker).unwrap()["session"].as_i64().unwrap();
        if let Some(old) = old {
            assert_eq!(broker.execute(&object(json!({"operation": "token", "session": old}))).unwrap(),
                object(json!({"error": "session_not_owned"})));
        }
        assert_eq!(broker.execute(&object(json!({"operation": "reset", "session": current}))).unwrap()["status"], 0);
        old = Some(current);
    }
    let last = session(&mut broker).unwrap()["session"].as_i64().unwrap();
    broker.endpoint.reset_calls();
    assert!(last > SESSION_BASE + 4096);
    assert_eq!(broker.reset_owned_sessions().unwrap()["reset_count"], 1);
    let calls = broker.endpoint.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1["session"], 7);
    assert!(broker.sessions.is_empty());
}

#[test]
fn reset_failure_keeps_ownership_until_successful_cleanup() {
    let mut broker = broker();
    broker.sessions = Ordered(vec![(SESSION_BASE + 3, 97), (SESSION_BASE + 9000, 204)]);
    broker.endpoint.sequence(vec![Ok(json!({"status": -1})), Ok(json!({"status": 0}))]);
    let result = broker.reset_owned_sessions().unwrap();
    assert_eq!((result["status"].clone(), result["reset_count"].clone(), result["remaining_sessions"].clone()),
        (json!(-1), json!(1), json!(1)));
    assert_eq!(broker.sessions, Ordered(vec![(SESSION_BASE + 3, 97)]));
    assert_eq!(health(&mut broker)["error"], "owned_session_reset_failed");
    assert_eq!(health(&mut broker)["ready"], false);
    broker.endpoint.reset_calls();
    assert_eq!(session(&mut broker).unwrap()["error"], "broker_requires_restart");
    assert_eq!(broker.endpoint.count(), 0);
    broker.endpoint.returns(json!({"status": 0}));
    assert_eq!(broker.reset_owned_sessions().unwrap()["remaining_sessions"], 0);
    // Teardown may retry known handles, but only a fresh broker may serve
    // authentication again after failure; old cached identities stay retired.
    assert_eq!(health(&mut broker)["ready"], false);
}

#[test]
fn single_reset_can_retry_without_losing_ownership() {
    let mut broker = broker();
    broker.sessions = Ordered(vec![(SESSION_BASE + 3, 97)]);
    broker.endpoint.returns(json!({"status": -2}));
    assert_eq!(broker.execute(&object(json!({"operation": "reset", "session": SESSION_BASE + 3}))).unwrap()["status"], -2);
    assert!(broker.sessions.contains(SESSION_BASE + 3));
    broker.endpoint.returns(json!({"status": 0}));
    assert_eq!(broker.reset_owned_sessions().unwrap()["remaining_sessions"], 0);
    assert_eq!(health(&mut broker)["ready"], true);
}

#[test]
fn pairing_sessions_survive_owned_session_cleanup() {
    let mut broker = broker();
    broker.endpoint.script(|op, _| Ok(object(if op == "session_signed" { json!({"status": 0, "session": 40}) } else { json!({"status": 0}) })));
    session(&mut broker).unwrap();
    broker.endpoint.script(|op, _| Ok(object(if op == "session_signed" { json!({"status": 0, "session": 41}) } else { json!({"status": 0}) })));
    broker.execute(&object(json!({"operation": "session_signed", "local_ltk": "owned-local", "flags": 0x41}))).unwrap();
    broker.endpoint.reset_calls();
    let result = broker.reset_owned_sessions().unwrap();
    assert_eq!(result, object(json!({"status": 0, "reset_count": 1, "remaining_sessions": 1})));
    assert_eq!(broker.endpoint.calls.lock().unwrap()[0].1, json!({"session": 40, "data": ""}));
    assert_eq!(broker.sessions, Ordered(vec![(SESSION_BASE + 2, 41)]));
}

#[test]
fn reset_transport_failure_stops_without_guessing_or_forgetting_handles() {
    let mut broker = broker();
    broker.sessions = (1..=16).map(|i| (SESSION_BASE + i, (i + 80) as i128)).collect();
    broker.endpoint.script(|_, _| Err(endpoint_error("offline")));
    let result = broker.reset_owned_sessions().unwrap();
    assert_eq!(result["status"], UNAVAILABLE);
    assert_eq!(result["error"], "owned_session_reset_transport_failed");
    assert_eq!(broker.endpoint.count(), 1);
    assert_eq!(broker.sessions.len(), 16);
    assert_eq!(health(&mut broker)["ready"], false);
}

#[test]
fn validation_failure_returns_explicit_unhealthy_reply() {
    for response in [Ok(json!({"status": -7})), Ok(json!({"status": false})), Ok(json!({})), Err("lost command stream")] {
        let mut broker = broker();
        broker.classes.insert(9, object(json!({"identity": "private-identity"})));
        match response.clone() {
            Ok(reply) => broker.endpoint.returns(reply),
            Err(message) => broker.endpoint.script(move |_, _| Err(endpoint_error(message))),
        }
        assert_eq!(health(&mut broker)["ready"], false, "{:?}", response);
        assert_eq!(health(&mut broker)["ready"], false);
        let calls = broker.endpoint.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        assert_eq!((calls[0].0.as_str(), &calls[0].1), ("validate", &json!({"identity": "private-identity"})));
    }
}

#[test]
fn health_retains_the_first_transport_failure_without_request_material() {
    let mut broker = broker();
    broker.classes.insert(9, object(json!({"identity": "private-identity"})));
    broker.endpoint.script(|_, _| Err(EndpointError::new("private input", Some("endpoint_reply_timeout"),
        object(json!({"operation": "validate", "reply_bytes": 9, "identity": "private-identity",
            "data": "private-key", "stderr": "private-stderr"}))).into()));
    let first = health(&mut broker);
    *broker.endpoint.poll.lock().unwrap() = Some(255);
    let second = health(&mut broker);
    assert_eq!(first, second);
    assert_eq!(Value::Object(first["transport_failure"].as_object().unwrap().clone()),
        json!({"code": "endpoint_reply_timeout", "reply_bytes": 9, "operation": "validate"}));
    assert!(!mirra_core::pyjson::dumps(&Value::Object(first)).contains("private-"));
    assert_eq!(broker.endpoint.count(), 1);
}

#[test]
fn health_uses_the_abandoned_streams_original_error() {
    let mut broker = broker();
    broker.classes.insert(9, object(json!({"identity": "private-identity"})));
    *broker.endpoint.failure.lock().unwrap() = Some(EndpointError::new("Original write failure", Some("endpoint_io_error"),
        object(json!({"stage": "write", "errno": 32}))));
    broker.endpoint.script(|_, _| Err(EndpointError::coded("Session is now unavailable", "endpoint_unavailable").into()));
    let response = health(&mut broker);
    assert_eq!(response["ready"], false);
    assert_eq!(response["transport_failure"]["code"], "endpoint_io_error");
    assert_eq!(broker.endpoint.count(), 0);
}

#[test]
fn health_reply_has_python_field_order() {
    let mut broker = broker();
    broker.can_resume_pairing = true;
    assert_eq!(mirra_core::pyjson::dumps(&Value::Object(health(&mut broker))),
        r#"{"ready": true, "identities": 1, "sessions": 0, "capabilities": ["reset_owned_sessions"], "can_resume_pairing": true}"#);
    *broker.endpoint.poll.lock().unwrap() = Some(0);
    assert_eq!(mirra_core::pyjson::dumps(&Value::Object(health(&mut broker))),
        r#"{"ready": false, "identities": 1, "sessions": 0, "capabilities": ["reset_owned_sessions"], "can_resume_pairing": true, "error": "endpoint_disconnected", "transport_failure": {"code": "endpoint_disconnected"}}"#);
}

#[test]
fn expired_certificate_deadline_retires_the_broker() {
    let mut broker = broker();
    broker.certificate_expires_at = Some(crate::util::now() - 1.0);
    assert_eq!(health(&mut broker)["error"], "bridge_certificate_expired");
    assert_eq!(session(&mut broker).unwrap()["error"], "broker_requires_restart");
    let mut tolerant = self::broker();
    assert!(tolerant.certificate_expires_at.is_none());
    assert_eq!(health(&mut tolerant)["ready"], true);
}

#[test]
fn reset_transport_details_remain_available_during_recovery() {
    let mut broker = broker();
    broker.sessions = Ordered(vec![(SESSION_BASE + 1, 97)]);
    broker.endpoint.script(|_, _| Err(EndpointError::new("Closed stream", Some("endpoint_eof"), object(json!({"exit_code": 255}))).into()));
    let result = broker.reset_owned_sessions().unwrap();
    assert_eq!(result["transport_failure"], json!({"code": "endpoint_eof"}));
    assert_eq!(health(&mut broker)["transport_failure"], result["transport_failure"]);
    assert_eq!(broker.sessions, Ordered(vec![(SESSION_BASE + 1, 97)]));
}

#[test]
fn malformed_reset_status_requires_recovery_and_preserves_handle() {
    let mut broker = broker();
    broker.sessions = Ordered(vec![(SESSION_BASE + 1, 97)]);
    broker.endpoint.returns(json!({"status": false}));
    assert_eq!(broker.reset_owned_sessions().unwrap()["status"], UNAVAILABLE);
    assert_eq!(broker.sessions, Ordered(vec![(SESSION_BASE + 1, 97)]));
    assert_eq!(health(&mut broker)["ready"], false);
}

#[test]
fn invalid_resets_and_empty_cleanup_never_touch_endpoint() {
    let mut broker = broker();
    assert_eq!(broker.reset_owned_sessions().unwrap()["status"], 0);
    for value in [json!(-1), json!(7), json!(SESSION_BASE + 2), json!(true), json!("7"), json!(null)] {
        assert_eq!(broker.execute(&object(json!({"operation": "reset", "session": value}))).unwrap(),
            object(json!({"error": "session_not_owned"})));
    }
    assert_eq!(broker.endpoint.count(), 0);
}

#[test]
fn capacity_and_namespace_are_checked_before_allocating_remote_sessions() {
    let mut broker = broker();
    broker.sessions = (1..=MAX_SESSIONS as i64).map(|i| (SESSION_BASE + i, i as i128)).collect();
    assert_eq!(session(&mut broker).unwrap()["status"], NO_MEMORY);
    broker.sessions.clear();
    broker.counter = SESSION_END - SESSION_BASE - 1;
    assert_eq!(session(&mut broker).unwrap()["error"], "session_namespace_exhausted");
    assert_eq!(broker.endpoint.count(), 0);
    assert_eq!(broker.execute(&object(json!({"operation": "validate", "local_ltk": "unknown"}))).unwrap(),
        object(json!({"error": "local_key_not_owned"})));
}

#[test]
fn endpoint_response_is_not_mutated_and_invalid_handle_is_rejected() {
    let mut broker = broker();
    broker.endpoint.returns(json!({"status": 0, "session": 12}));
    assert_eq!(session(&mut broker).unwrap()["session"], SESSION_BASE + 1);
    let calls = broker.endpoint.calls.lock().unwrap().clone();
    assert_eq!(calls[0].1, json!({"identity": "private-identity", "remote_ltk": "owned-remote",
        "remote_key_class": 9, "flags": 2, "parameters": ""}));
    let error = session(&mut broker).unwrap_err();
    assert_eq!(error.type_name(), "EndpointError");
    assert_eq!(health(&mut broker)["ready"], false);
    assert_eq!(session(&mut broker).unwrap()["error"], "broker_requires_restart");
}

#[test]
fn many_resets_share_one_real_transport_deadline() {
    let mut broker = broker();
    Arc::get_mut(&mut broker.endpoint).unwrap().timeout = Duration::from_millis(140);
    broker.sessions = (1..=16).map(|i| (SESSION_BASE + i, i as i128)).collect();
    broker.endpoint.returns(json!({"status": 0}));
    let start = Instant::now();
    broker.reset_owned_sessions().unwrap();
    let deadlines: Vec<Option<Instant>> = broker.endpoint.calls.lock().unwrap().iter().map(|c| c.2).collect();
    assert_eq!(deadlines.len(), 16);
    let first = deadlines[0].expect("reset passes the overall deadline");
    assert!(deadlines.iter().all(|d| *d == Some(first)));
    assert!(first >= start + Duration::from_millis(140) && first <= Instant::now() + Duration::from_millis(140));
    // The cap applies to slow endpoints too (min(timeout, 10s)).
    let mut slow = self::broker();
    Arc::get_mut(&mut slow.endpoint).unwrap().timeout = Duration::from_secs(60);
    slow.sessions = Ordered(vec![(SESSION_BASE + 1, 1)]);
    let before = Instant::now();
    slow.reset_owned_sessions().unwrap();
    let deadline = slow.endpoint.calls.lock().unwrap()[0].2.unwrap();
    assert!(deadline <= before + Duration::from_secs(11) && deadline >= before + Duration::from_secs(10));
}

#[test]
fn restore_adopts_saved_keys_by_creation_and_certificate_window() {
    let ready = json!({"client_saved": true, "restored_identities": 3});
    let mut broker = AksBroker::new(Arc::new(Fake::new(ready)), None);
    broker.endpoint.returns(json!({"status": 0, "identities": [
        {"identity": "newer", "ltk": fixture_ltk(), "key_class": 9, "created": 200},
        {"identity": "older", "ltk": fixture_ltk(), "key_class": 9, "created": 100},
        {"identity": "bad-class", "ltk": fixture_ltk(), "key_class": 7, "created": 300},
        {"identity": "bad-layout", "ltk": "dW5zdXBwb3J0ZWQ=", "key_class": 10, "created": 300},
        "not an entry",
    ]}));
    assert_eq!(broker.restore(None).unwrap(), 2);
    assert_eq!(broker.classes.get(9).unwrap()["identity"], "newer");
    assert_eq!(broker.identities[&fixture_ltk()], "newer");
    let generated = broker.execute(&object(json!({"operation": "generate"}))).unwrap();
    assert_eq!(broker.identities[generated["data"].as_str().unwrap()], "newer");
    assert_eq!(broker.endpoint.count(), 1); // Only the identities listing.

    let mut renewed = AksBroker::new(Arc::new(Fake::new(json!({"client_saved": true, "restored_identities": 1}))), None);
    renewed.endpoint.returns(json!({"status": 0, "identities": [
        {"identity": "old", "ltk": fixture_ltk(), "key_class": 9, "created": 100}]}));
    assert_eq!(renewed.restore(Some(150.0)).unwrap(), 0);
    let mut unsaved = AksBroker::new(Arc::new(Fake::new(json!({"client_saved": false, "restored_identities": 1}))), None);
    assert_eq!(unsaved.restore(None).unwrap(), 0);
    assert_eq!(unsaved.endpoint.count(), 0);
}

fn attested_endpoint() -> Fake {
    Fake::new(json!({"product_type": "iPhone10,5", "os_version": "16.7.10", "os_build": "20H350",
        "process_architecture": "arm64", "serial": "private-serial", "dcrt_sha256": "private-certificate"}))
}

#[test]
fn native_failure_keeps_exact_status_and_does_not_call_validate() {
    let endpoint = attested_endpoint();
    endpoint.returns(json!({"status": -7, "status_hex": "untrusted-status",
        "operation_stage": "aks_create_signing_key_with_params", "identity": "private-identity", "ltk": "private-key"}));
    let error = verify_attested_key(&endpoint).unwrap_err();
    let error = error.as_endpoint().unwrap();
    assert_eq!(error.code(), Some("bridge_attested_key_unavailable"));
    assert_eq!(error.details["status"], -7);
    assert_eq!(error.details["status_hex"], "0xfffffff9");
    assert_eq!(error.details["operation_stage"], "aks_create_signing_key_with_params");
    assert_eq!(error.details["capabilities"]["product_type"], "iPhone10,5");
    assert!(!mirra_core::pyjson::dumps(&Value::Object(error.details.clone())).contains("private-"));
    let calls = endpoint.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!((calls[0].0.as_str(), &calls[0].1), ("generate", &json!({"attested": true, "key_class": 9})));
}

#[test]
fn malformed_successes_and_parameters_failure_are_rejected() {
    for response in [json!({"status": false, "identity": "id", "ltk": fixture_ltk()}), json!({"status": 0, "identity": "id"}),
        json!({"status": 0, "identity": "id", "ltk": fixture_ltk(), "error": "invalid_signing_key_result"})] {
        let endpoint = attested_endpoint();
        endpoint.returns(response);
        assert!(verify_attested_key(&endpoint).is_err());
        assert_eq!(endpoint.count(), 1);
    }
}

#[test]
fn validation_failure_and_unsupported_wire_format_are_distinct() {
    let endpoint = attested_endpoint();
    let generated = json!({"status": 0, "identity": "private-identity", "ltk": fixture_ltk()});
    endpoint.sequence(vec![Ok(generated.clone()), Ok(json!({"status": -9, "operation_stage": "aks_validate_local_key"}))]);
    let error = verify_attested_key(&endpoint).unwrap_err();
    assert_eq!(error.code(), Some("bridge_attested_key_rejected"));
    assert_eq!(error.as_endpoint().unwrap().details["status"], -9);
    let mut unsupported = generated.clone();
    unsupported["ltk"] = json!("dW5zdXBwb3J0ZWQ=");
    endpoint.sequence(vec![Ok(unsupported), Ok(json!({"status": 0}))]);
    let error = verify_attested_key(&endpoint).unwrap_err();
    assert_eq!(error.code(), Some("bridge_key_layout_unsupported"));
    endpoint.sequence(vec![Ok(generated), Ok(json!({"status": 0}))]);
    assert_eq!(verify_attested_key(&endpoint).unwrap()["original_fields_byte_identical"], true);
}

#[test]
fn operation_details_select_status_and_known_stage_only() {
    assert_eq!(Value::Object(operation_details(&object(json!({"status": -536870212, "operation_stage": "other", "identity": "x"})))),
        json!({"status": -536870212, "status_hex": "0xe00002bc"}));
    assert!(operation_details(&object(json!({"status": true}))).is_empty());
}
