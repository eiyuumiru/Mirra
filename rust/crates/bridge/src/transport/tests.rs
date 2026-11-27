use super::*;
use crate::testing::{self, accept_websocket, fixture, read_json, serve, write_frame, write_text, Stream, TOKEN};
use std::io::Write;
use std::sync::{mpsc, Arc};

const DIGEST: &str = "4b0e8bd5e1c27f9f7b4b36e2b8f1f0dd2c1e3a4d6f6f3a0a1f7c1e1c8b7e0a11";

fn greeting() -> Value {
    json!({"ready": true, "protocol_version": 2, "dcrt_sha256": DIGEST, "dcrt_bytes": 3})
}

fn options() -> EndpointOptions {
    EndpointOptions { timeout: Some(Duration::from_millis(400)), expected_certificate_sha256: Some(DIGEST.into()),
        ..Default::default() }
}

/// A bridge that greets with `hello` and then runs `body`.
fn bridge(hello: Value, body: impl FnOnce(&mut Stream) + Send + 'static) -> (testing::Fixture, std::thread::JoinHandle<()>) {
    let body = Mutex::new(Some(body));
    let (port, server) = serve(TOKEN, 1, move |_, mut stream| {
        accept_websocket(&mut stream);
        write_text(&mut stream, &hello);
        (body.lock().unwrap().take().unwrap())(&mut stream);
    });
    (fixture(port), server)
}

/// Answers each request with `{"operation": op, "status": 0}` until `exit`.
fn echo(stream: &mut Stream) -> Vec<Value> {
    let mut seen = Vec::new();
    while let Some(request) = read_json(stream) {
        write_text(stream, &json!({"operation": request["operation"], "status": 0}));
        let done = request["operation"] == "exit";
        seen.push(request);
        if done {
            break;
        }
    }
    seen
}

#[test]
fn roundtrip_and_graceful_close() {
    let (sent, seen) = mpsc::channel();
    let (f, server) = bridge(greeting(), move |stream| {
        sent.send(echo(stream)).unwrap();
        assert_eq!(testing::read_frame(stream), Some((0x8, 1000u16.to_be_bytes().to_vec())));
    });
    let (sink, records) = activity::collector();
    activity::capture(Some(sink), || {
        let endpoint = Endpoint::open(&f.config, options()).unwrap();
        assert!(endpoint.certificate_binding_verified);
        assert_eq!(endpoint.ready["dcrt_bytes"], 3);
        assert_eq!(endpoint.poll(), None);
        let reply = endpoint.call("validate", json!({"identity": "fixture-identity", "key_class": 9})).unwrap();
        assert_eq!(reply, *json!({"operation": "validate", "status": 0}).as_object().unwrap());
        endpoint.close();
        assert_eq!(endpoint.timeout(), Duration::from_millis(400));
        assert_eq!(endpoint.poll(), Some(0));
        let after = endpoint.call("validate", Value::Null).unwrap_err();
        assert_eq!(after.code(), Some("endpoint_unavailable"));
    });
    let requests = seen.recv().unwrap();
    assert_eq!(requests[0], json!({"operation": "validate", "identity": "fixture-identity", "key_class": 9}));
    assert_eq!(requests[1], json!({"operation": "exit"}));
    server.join().unwrap();
    let records = records.lock().unwrap();
    let messages: Vec<&str> = records.iter().map(|r| r["message"].as_str().unwrap()).collect();
    assert_eq!(messages, ["connecting", "reply", "greeting", "request", "reply", "request", "reply"]);
    assert_eq!(records[0]["fields"], json!({"transport": "ssh", "port": f.config.service_port}));
    assert_eq!(records[3]["fields"]["request_bytes"], 73);
    assert_eq!(records[3]["fields"]["operation"], "validate");
    assert!(!serde_json::to_string(&*records).unwrap().contains("fixture-identity"));
}

#[test]
fn unready_greeting_preserves_known_capability_failure_without_secrets() {
    let hello = json!({"ready": false, "error": "required_keystore_symbols_unavailable",
        "missing_symbols": ["aks_remote_session"], "os_version": "15.8.4", "process_architecture": "arm64",
        "serial": "private-serial", "dcrt": "private-certificate"});
    let (f, server) = bridge(hello, |stream| {
        assert_eq!(testing::read_frame(stream).map(|f| f.0), Some(0x8));
    });
    let (sink, records) = activity::collector();
    let error = activity::capture(Some(sink), || Endpoint::open(&f.config, options()).err().unwrap());
    let endpoint = error.as_endpoint().unwrap();
    assert_eq!(endpoint.code(), Some("required_keystore_symbols_unavailable"));
    assert_eq!(endpoint.details["capabilities"]["missing_symbols"], json!(["aks_remote_session"]));
    assert!(!Value::Object(endpoint.details.clone()).to_string().contains("private-"));
    let last = records.lock().unwrap().last().unwrap().clone();
    assert_eq!(last["message"], "startup failed");
    assert_eq!(last["fields"], json!({"error_type": "EndpointError", "error": "Bridge service did not report ready"}));
    server.join().unwrap();
    let (f, server) = bridge(json!({"ready": false, "error": "something_else"}), |_| {});
    assert_eq!(Endpoint::open(&f.config, options()).err().unwrap().code(), None);
    server.join().unwrap();
}

#[test]
fn mismatched_certificate_and_unknown_protocol_are_rejected() {
    let cases = [
        (json!({"ready": true, "protocol_version": 2, "dcrt_sha256": "a".repeat(64)}), "Local and bridge device certificates do not match"),
        (json!({"ready": true, "protocol_version": 3, "dcrt_sha256": DIGEST}), "Unsupported bridge protocol version; reinstall the bridge service"),
        (json!({"ready": true, "protocol_version": 2}), "Local and bridge device certificates do not match"),
    ];
    for (hello, message) in cases {
        let (f, server) = bridge(hello, |_| {});
        let error = Endpoint::open(&f.config, options()).err().unwrap();
        assert_eq!((error.type_name().as_str(), error.to_string().as_str()), ("EndpointError", message));
        server.join().unwrap();
    }
    // Without an explicit digest the enrolled certificate file is the anchor.
    let digest = crate::wire::hex(&Sha256::digest(b"fixture certificate"));
    let (f, server) = bridge(json!({"ready": true, "protocol_version": 2.0, "dcrt_sha256": digest}), |stream| {
        echo(stream);
    });
    let endpoint = Endpoint::open(&f.config, EndpointOptions { timeout: Some(Duration::from_secs(2)), ..Default::default() }).unwrap();
    assert!(endpoint.certificate_binding_verified);
    drop(endpoint);
    server.join().unwrap();
    let (f, server) = bridge(greeting(), |_| {});
    std::fs::remove_file(&f.config.certificate_file).unwrap();
    let missing = Endpoint::open(&f.config, EndpointOptions::default()).err().unwrap();
    assert_eq!(missing.type_name(), "FileNotFoundError");
    server.join().unwrap();
}

#[test]
fn connection_failures_keep_their_codes() {
    let mut f = fixture(1);
    std::fs::remove_file(&f.config.token_file).unwrap();
    let missing = Endpoint::open(&f.config, options()).err().unwrap();
    assert_eq!((missing.type_name().as_str(), missing.code()), ("BridgeError", Some("bridge_pairing_missing")));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    f.config.service_port = listener.local_addr().unwrap().port();
    drop(listener);
    let refused = Endpoint::open(&f.config, EndpointOptions { token: Some(TOKEN.into()), ..options() }).err().unwrap();
    assert_eq!((refused.type_name().as_str(), refused.code()), ("EndpointError", Some("bridge_refused")));
    for (status, code) in [("503 Busy", "bridge_session_limit"), ("404 Missing", "endpoint_unavailable")] {
        let (port, server) = serve(TOKEN, 1, move |_, mut stream| {
            testing::read_request(&mut stream);
            stream.write_all(format!("HTTP/1.1 {}\r\n\r\n", status).as_bytes()).unwrap();
        });
        let error = Endpoint::open(&fixture(port).config, options()).err().unwrap();
        assert_eq!(error.code(), Some(code));
        server.join().unwrap();
    }
}

#[test]
fn partial_response_times_out_and_poisoned_session_is_not_reused() {
    let (f, server) = bridge(greeting(), |stream| {
        read_json(stream).unwrap();
        stream.write_all(&[0x81, 20, b'{']).unwrap();
        std::thread::sleep(Duration::from_millis(900));
    });
    let endpoint = Endpoint::open(&f.config, options()).unwrap();
    let started = Instant::now();
    let error = endpoint.call("generate", Value::Null).unwrap_err();
    let error = error.as_endpoint().unwrap().clone();
    assert_eq!(error.message, "Bridge reply timed out; restart the Mirroring session");
    assert_eq!(error.code(), Some("endpoint_reply_timeout"));
    assert_eq!(error.details["operation"], "generate");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(endpoint.failure(), Some(error.clone()));
    let again = endpoint.call("validate", Value::Null).unwrap_err();
    assert_eq!(again.to_string(), "Bridge session is unavailable; start a new session");
    assert_eq!(endpoint.failure(), Some(error));
    endpoint.close();
    server.join().unwrap();
}

#[test]
fn invalid_oversized_and_closed_replies_are_rejected() {
    let cases: [(Vec<u8>, &str); 4] = [
        (testing::frame(0x1, b"[]"), "endpoint_invalid_reply"),
        (testing::frame(0x1, b"invalid"), "endpoint_invalid_reply"),
        (testing::frame(0x1, &vec![b'x'; MAX_REPLY + 1]), "endpoint_reply_too_large"),
        (testing::frame(0x8, b""), "endpoint_eof"),
    ];
    for (reply, code) in cases {
        let (f, server) = bridge(greeting(), move |stream| {
            read_json(stream).unwrap();
            // The client stops reading once a frame header is over the limit.
            let _ = stream.write_all(&reply);
            std::thread::sleep(Duration::from_millis(100));
        });
        let endpoint = Endpoint::open(&f.config, options()).unwrap();
        let error = endpoint.call("validate", Value::Null).unwrap_err();
        assert_eq!(error.code(), Some(code));
        assert_eq!(error.as_endpoint().unwrap().details["operation"], "validate");
        if code == "endpoint_invalid_reply" {
            assert!(pyutil::is_int(error.as_endpoint().unwrap().details.get("reply_bytes")));
        }
        drop(endpoint);
        server.join().unwrap();
    }
    let (f, server) = bridge(greeting(), |_| {});
    let endpoint = Endpoint::open(&f.config, options()).unwrap();
    server.join().unwrap();
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(endpoint.poll(), Some(0));
    let gone = endpoint.call("validate", Value::Null).unwrap_err();
    assert_eq!(gone.code(), Some("endpoint_disconnected"));
    assert_eq!(endpoint.failure().unwrap().code(), Some("endpoint_disconnected"));
    let oversized = endpoint.call("setup", json!({"data": "x".repeat(MAX_REPLY)}));
    assert_eq!(oversized.unwrap_err().code(), Some("endpoint_disconnected"));
}

#[test]
fn oversized_requests_raise_value_error() {
    let (f, server) = bridge(greeting(), |stream| {
        echo(stream);
    });
    let endpoint = Endpoint::open(&f.config, options()).unwrap();
    let error = endpoint.call("setup", json!({"data": "x".repeat(MAX_REPLY)})).unwrap_err();
    assert_eq!((error.type_name().as_str(), error.to_string().as_str()), ("ValueError", "Bridge request exceeds the size limit"));
    // A refused request does not poison the session.
    assert_eq!(endpoint.call("validate", Value::Null).unwrap()["status"], 0);
    drop(endpoint);
    server.join().unwrap();
}

#[test]
fn deadline_bounds_a_single_call() {
    let (f, server) = bridge(greeting(), |stream| {
        read_json(stream).unwrap();
        std::thread::sleep(Duration::from_millis(600));
    });
    let endpoint = Endpoint::open(&f.config, EndpointOptions { timeout: Some(Duration::from_secs(5)), ..options() }).unwrap();
    let started = Instant::now();
    let error = endpoint.call_with_deadline("reset", json!({"session": 1}), Some(Instant::now() + Duration::from_millis(150)))
        .unwrap_err();
    assert_eq!(error.code(), Some("endpoint_reply_timeout"));
    assert!(started.elapsed() < Duration::from_millis(500));
    drop(endpoint);
    server.join().unwrap();
}

#[test]
fn close_interrupts_an_inflight_request() {
    let (f, server) = bridge(greeting(), |stream| {
        read_json(stream).unwrap();
        std::thread::sleep(Duration::from_secs(3));
    });
    let endpoint = Arc::new(Endpoint::open(&f.config, EndpointOptions { timeout: Some(Duration::from_secs(20)), ..options() }).unwrap());
    let pending = {
        let endpoint = endpoint.clone();
        std::thread::spawn(move || endpoint.call("validate", Value::Null))
    };
    let deadline = Instant::now() + Duration::from_secs(2);
    while endpoint.poll() == Some(0) || endpoint.socket.try_lock().is_ok() {
        assert!(Instant::now() < deadline, "request did not start");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(endpoint.poll(), None);
    let started = Instant::now();
    endpoint.close();
    let result = pending.join().unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(result.unwrap_err().as_endpoint().is_some());
    server.join().unwrap();
}

#[test]
fn ping_during_session_is_answered() {
    let (f, server) = bridge(greeting(), |stream| {
        let request = read_json(stream).unwrap();
        write_frame(stream, 0x9, b"keepalive");
        assert_eq!(testing::read_frame(stream), Some((0xA, b"keepalive".to_vec())));
        write_text(stream, &json!({"operation": request["operation"], "status": 0}));
        echo(stream);
    });
    let endpoint = Endpoint::open(&f.config, options()).unwrap();
    assert_eq!(endpoint.call("get_state", Value::Null).unwrap()["status"], 0);
    drop(endpoint);
    server.join().unwrap();
}

#[test]
fn transport_details_select_only_safe_facts() {
    let error = EndpointError::new("private input", Some("endpoint_reply_timeout"),
        json!({"reply_bytes": 10, "request_bytes": true, "stage": "reply", "operation": "generate", "errno": 32})
            .as_object().unwrap().clone());
    assert_eq!(Value::Object(transport_details(&error)),
        json!({"code": "endpoint_reply_timeout", "reply_bytes": 10, "stage": "reply", "operation": "generate"}));
    let malformed = EndpointError::new("private input", Some("private-code"),
        json!({"operation": ["private-operation"], "errno": true, "stage": {}}).as_object().unwrap().clone());
    assert_eq!(Value::Object(transport_details(&malformed)), json!({"code": "endpoint_error"}));
    let eof = EndpointError::new("Closed stream", Some("endpoint_eof"), json!({"exit_code": 255}).as_object().unwrap().clone());
    assert_eq!(Value::Object(transport_details(&eof)), json!({"code": "endpoint_eof"}));
}
