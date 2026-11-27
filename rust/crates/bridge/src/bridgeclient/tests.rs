use super::*;
use crate::testing::{self, accept_websocket, fixture, read_frame, read_request, respond, serve, write_frame, TOKEN};
use serde_json::json;
use std::sync::mpsc;

#[test]
fn tokens_follow_crockford_rules() {
    assert_eq!(normalize_token(" abcd-efgh jkmn\tpqrs-tvwx-yzol ").unwrap(), "ABCDEFGHJKMNPQRSTVWXYZ01");
    assert_eq!(normalize_token("0000 1111 iiii llll oooo 2222").unwrap(), "000011111111111100002222");
    for bad in ["", "ABCD", "ABCDEFGHJKMNPQRSTVWXYZ0U", "ABCDEFGHJKMNPQRSTVWXYZ012"] {
        let error = normalize_token(bad).unwrap_err();
        assert_eq!(error.type_name(), "ValueError");
        assert_eq!(error.to_string(), TOKEN_FORMAT);
    }
    assert_eq!(display_token("abcdefghjkmnpqrstvwxyz01").unwrap(), "ABCD-EFGH-JKMN-PQRS-TVWX-YZ01");
    assert_eq!(crate::wire::hex(&pre_shared_key(&"A".repeat(24)).unwrap()),
        "073ac4163c7308ab0b8b94ff3f17fd6eaa23be794162127bffce4622fe79d099");
}

#[test]
fn saved_tokens_report_pairing_missing() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("token");
    let missing = read_token(&path).unwrap_err();
    assert_eq!((missing.code(), missing.type_name().as_str()), (Some("bridge_pairing_missing"), "BridgeError"));
    assert!(missing.to_string().starts_with("Missing bridge pairing token"));
    std::fs::write(&path, "short").unwrap();
    assert_eq!(read_token(&path).unwrap_err().to_string(), "The saved bridge pairing token is invalid; pair again");
    std::fs::write(&path, b"\xff\xfe").unwrap();
    assert_eq!(read_token(&path).unwrap_err().code(), Some("bridge_pairing_missing"));
    std::fs::write(&path, "ABCD-EFGH-JKMN-PQRS-TVWX-YZ01\n").unwrap();
    assert_eq!(read_token(&path).unwrap(), "ABCDEFGHJKMNPQRSTVWXYZ01");
}

#[test]
fn revision_distinguishes_legacy_current_newer_and_invalid() {
    let status = |revision: Option<Value>| {
        let mut value = json!({"service": "mirra-bridge", "protocol_version": 2});
        if let Some(r) = revision {
            value["bridge_revision"] = r;
        }
        value.as_object().unwrap().clone()
    };
    assert_eq!(bridge_revision(&status(None)), Some(0));
    assert_eq!(bridge_revision(&status(Some(json!(BRIDGE_REVISION)))), Some(BRIDGE_REVISION));
    assert_eq!(bridge_revision(&status(Some(json!(BRIDGE_REVISION + 1)))), Some(BRIDGE_REVISION + 1));
    for bad in [json!(true), json!(-1), json!(1.0), json!("1")] {
        assert_eq!(bridge_revision(&status(Some(bad))), None);
    }
    assert_eq!(bridge_revision(json!({"service": "other", "protocol_version": 2}).as_object().unwrap()), None);
    assert_eq!(bridge_revision(json!({"service": "mirra-bridge", "protocol_version": 2.0}).as_object().unwrap()), Some(0));
}

#[test]
fn small_helpers() {
    assert_eq!(session_path(false), "/v1/session");
    let mut f = fixture(1);
    assert_eq!(destination(&f.config), Destination::Network("127.0.0.1".into(), 1));
    f.config.transport = "usb".into();
    f.config.product_type = "iPhone10,5".into();
    assert_eq!(destination(&f.config), Destination::Usb("iPhone10,5".into()));
    f.config.serial = "SERIAL".into();
    assert_eq!(destination(&f.config), Destination::Usb("SERIAL".into()));
    assert!(!has_ssh_access(&f.config));
    for path in [&f.config.user_file, &f.config.identity_file, &f.config.known_hosts_file] {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "x").unwrap();
    }
    assert!(has_ssh_access(&f.config));
    let frame = WebSocket::frame_with_mask(0x1, b"abc", [1, 2, 3, 4]);
    assert_eq!(frame, [0x81, 0x83, 1, 2, 3, 4, b'a' ^ 1, b'b' ^ 2, b'c' ^ 3]);
    assert_eq!(WebSocket::frame_with_mask(0x1, &[0; 126], [0; 4])[..4], [0x81, 0xfe, 0, 126]);
    assert_eq!(WebSocket::frame_with_mask(0x1, &[0; 65536], [0; 4])[..10], [0x81, 0xff, 0, 0, 0, 0, 0, 1, 0, 0]);
}

#[test]
fn http_request_over_tls_psk() {
    let (sent, seen) = mpsc::channel();
    let (port, server) = serve(TOKEN, 2, move |index, mut stream| {
        let request = read_request(&mut stream);
        sent.send(request).unwrap();
        if index == 0 {
            respond(&mut stream, "200 OK", "application/json", br#"{"service": "mirra-bridge", "protocol_version": 2}"#);
        } else {
            respond(&mut stream, "404 Not Found", "text/plain", b"[1]");
        }
    });
    let f = fixture(port);
    let (status, reply) = request_json(&f.config, TOKEN, "POST", "/v1/certificate", Some(&json!({"issue": true, "x": "é"})), None).unwrap();
    assert_eq!(status, 200);
    assert_eq!(bridge_revision(&reply), Some(0));
    let (head, body) = seen.recv().unwrap();
    assert_eq!(head, "POST /v1/certificate HTTP/1.1\r\nHost: mirra-bridge\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 30\r\n\r\n");
    assert_eq!(body, b"{\"issue\": true, \"x\": \"\\u00e9\"}");
    let error = request_json(&f.config, TOKEN, "GET", "/v1/missing", None, None).unwrap_err();
    assert_eq!((error.code(), error.to_string().as_str()), (Some("bridge_protocol_error"), "Bridge reply must be an object"));
    assert_eq!(seen.recv().unwrap().0.lines().next(), Some("GET /v1/missing HTTP/1.1"));
    server.join().unwrap();
}

fn reply_with(raw: &'static [u8]) -> Error {
    let (port, server) = serve(TOKEN, 1, move |_, mut stream| {
        read_request(&mut stream);
        stream.write_all(raw).unwrap();
        let _ = stream.shutdown();
    });
    let f = fixture(port);
    let error = request(&f.config, TOKEN, "GET", "/", None, Some(Duration::from_secs(2))).unwrap_err();
    server.join().unwrap();
    error
}

#[test]
fn malformed_replies_have_stable_codes() {
    let cases: [(&[u8], &str, &str); 6] = [
        (b"HTTP/1.0 200 OK\r\n\r\n", "bridge_protocol_error", "Bridge returned an invalid HTTP response"),
        (b"HTTP/1.1 2x0 OK\r\n\r\n", "bridge_protocol_error", "Bridge returned an invalid HTTP response"),
        (b"HTTP/1.1 200 OK\r\nBroken\r\n\r\n", "bridge_protocol_error", "Bridge returned an invalid HTTP header"),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 2000000\r\n\r\n", "bridge_protocol_error", "Bridge response has an invalid length"),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc", "bridge_closed", "Bridge closed the connection during its reply"),
        (b"", "bridge_closed", "Bridge closed the connection before replying"),
    ];
    for (raw, code, message) in cases {
        let error = reply_with(raw);
        assert_eq!((error.code(), error.to_string().as_str()), (Some(code), message), "{:?}", String::from_utf8_lossy(raw));
    }
    assert_eq!(reply_with(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc").type_name(), "BridgeClosed");
    let mut huge = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
    huge.extend(vec![b'a'; MAX_HEADER + 10]);
    let huge: &'static [u8] = Box::leak(huge.into_boxed_slice());
    assert_eq!(reply_with(huge).to_string(), "Bridge response headers are too large");
    let response = {
        let (port, server) = serve(TOKEN, 1, |_, mut stream| {
            read_request(&mut stream);
            stream.write_all(b"HTTP/1.1 0201 Created\r\n  CONTENT-TYPE :  text/x \r\ncontent-length: 004\r\n\r\nbodyextra").unwrap();
        });
        let reply = request(&fixture(port).config, TOKEN, "GET", "/", None, None).unwrap();
        server.join().unwrap();
        reply
    };
    assert_eq!(response, Response { status: 201, content_type: "text/x".into(), body: b"body".to_vec() });
}

#[test]
fn connection_failures_are_classified() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let refused = request(&fixture(port).config, TOKEN, "GET", "/", None, None).unwrap_err();
    assert_eq!(refused.code(), Some("bridge_refused"));
    assert_eq!(refused.to_string(), "Cannot reach the bridge service: [Errno 61] Connection refused");

    let mut f = fixture(port);
    f.config.ssh_host = "host.invalid".into();
    let unknown = request(&f.config, TOKEN, "GET", "/", None, None).unwrap_err();
    assert_eq!(unknown.code(), Some("bridge_unreachable"));
    assert!(unknown.to_string().starts_with("Cannot reach the bridge service: [Errno "), "{}", unknown);

    let (port, server) = serve(TOKEN, 1, |_, _| {});
    let rejected = request(&fixture(port).config, "ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ", "GET", "/", None, None).unwrap_err();
    assert_eq!(rejected.code(), Some("bridge_token_rejected"));
    assert!(rejected.to_string().starts_with("The bridge rejected the pairing token"));
    server.join().unwrap();

    // A server that accepts TCP but never answers the handshake.
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = silent.local_addr().unwrap().port();
    let holder = std::thread::spawn(move || {
        let connection = silent.accept().unwrap();
        std::thread::sleep(Duration::from_millis(800));
        drop(connection);
    });
    let stalled = request(&fixture(port).config, TOKEN, "GET", "/", None, Some(Duration::from_millis(200))).unwrap_err();
    assert_eq!((stalled.code(), stalled.to_string().as_str()),
        (Some("bridge_unreachable"), "The bridge did not finish the secure handshake"));
    holder.join().unwrap();

    let invalid = request(&fixture(port).config, "bad", "GET", "/", None, None).unwrap_err();
    assert_eq!(invalid.type_name(), "ValueError");
}

#[test]
fn slow_replies_time_out() {
    let (port, server) = serve(TOKEN, 1, |_, mut stream| {
        read_request(&mut stream);
        stream.write_all(b"HTTP/1.1 200 OK\r\n").unwrap();
        std::thread::sleep(Duration::from_millis(700));
    });
    let started = Instant::now();
    let error = request(&fixture(port).config, TOKEN, "GET", "/", None, Some(Duration::from_millis(300))).unwrap_err();
    assert_eq!((error.type_name().as_str(), error.to_string().as_str()), ("BridgeTimeout", "Bridge did not answer in time"));
    assert!(started.elapsed() < Duration::from_millis(650));
    server.join().unwrap();
}

#[test]
fn websocket_handshake_frames_ping_and_close() {
    let (port, server) = serve(TOKEN, 1, |_, mut stream| {
        let head = accept_websocket(&mut stream);
        assert!(head.starts_with("GET /v1/session HTTP/1.1\r\nHost: mirra-bridge\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "));
        assert!(head.ends_with("\r\nSec-WebSocket-Version: 13\r\n\r\n"));
        // Ping and a pong before the reply; the client answers the ping.
        let mut burst = testing::frame(0x9, b"hi");
        burst.extend(testing::frame(0xA, b""));
        burst.extend(testing::frame(0x1, &vec![b'x'; 70000]));
        stream.write_all(&burst).unwrap();
        assert_eq!(read_frame(&mut stream), Some((0xA, b"hi".to_vec())));
        assert_eq!(read_frame(&mut stream), Some((0x1, b"request".to_vec())));
        write_frame(&mut stream, 0x8, &1000u16.to_be_bytes());
        assert_eq!(read_frame(&mut stream), None);
    });
    let f = fixture(port);
    let mut socket = WebSocket::open(&f.config, TOKEN, "/v1/session", Duration::from_secs(5)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    assert_eq!(socket.receive(deadline).unwrap(), vec![b'x'; 70000]);
    socket.send_text(b"request", deadline).unwrap();
    let closed = socket.receive(deadline).unwrap_err();
    assert_eq!(closed.type_name(), "BridgeClosed");
    assert!(socket.is_closed() && socket.disconnected());
    assert_eq!(socket.send_text(b"late", deadline).unwrap_err().code(), Some("bridge_closed"));
    socket.close(None);
    server.join().unwrap();
}

fn upgrade_reply(raw: &'static [u8]) -> Error {
    let (port, server) = serve(TOKEN, 1, move |_, mut stream| {
        read_request(&mut stream);
        stream.write_all(raw).unwrap();
    });
    let result = WebSocket::open(&fixture(port).config, TOKEN, "/v1/session", Duration::from_secs(2));
    server.join().unwrap();
    result.err().unwrap()
}

#[test]
fn websocket_refusals_and_bad_frames() {
    let limit = upgrade_reply(b"HTTP/1.1 503 Busy\r\n\r\n");
    assert_eq!((limit.code(), limit.to_string().as_str()), (Some("bridge_session_limit"), "Bridge refused the session (HTTP 503)"));
    assert_eq!(upgrade_reply(b"HTTP/1.1 404 No\r\n\r\n").code(), Some("bridge_protocol_error"));
    let bad = upgrade_reply(b"HTTP/1.1 101 OK\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: wrong\r\n\r\n");
    assert_eq!(bad.to_string(), "Bridge returned an invalid WebSocket handshake");

    let frames: [(Vec<u8>, &str, &str); 4] = [
        (vec![0x81, 0x80, 0, 0, 0, 0], "bridge_protocol_error", "Bridge sent an invalid WebSocket frame"),
        (vec![0x01, 0x00], "bridge_protocol_error", "Bridge sent an invalid WebSocket frame"),
        (vec![0x82, 0x00], "bridge_protocol_error", "Bridge sent an unsupported WebSocket frame"),
        (vec![0x81, 127, 0, 0, 0, 0, 0, 4, 0, 1], "bridge_message_too_large", "Bridge message exceeds the size limit"),
    ];
    for (raw, code, message) in frames {
        let (port, server) = serve(TOKEN, 1, move |_, mut stream| {
            accept_websocket(&mut stream);
            stream.write_all(&raw).unwrap();
            std::thread::sleep(Duration::from_millis(100));
        });
        let mut socket = WebSocket::open(&fixture(port).config, TOKEN, "/v1/session", Duration::from_secs(2)).unwrap();
        let error = socket.receive(Instant::now() + Duration::from_secs(2)).unwrap_err();
        assert_eq!((error.code(), error.to_string().as_str()), (Some(code), message));
        server.join().unwrap();
    }
}

#[test]
fn disconnected_detects_closure_without_blocking() {
    let (release, wait) = mpsc::channel::<()>();
    let (port, server) = serve(TOKEN, 1, move |_, mut stream| {
        accept_websocket(&mut stream);
        write_frame(&mut stream, 0x9, b"p");
        wait.recv().unwrap();
        assert_eq!(read_frame(&mut stream), Some((0xA, b"p".to_vec())));
        drop(stream);
    });
    let mut socket = WebSocket::open(&fixture(port).config, TOKEN, "/v1/session", Duration::from_secs(2)).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    assert!(!socket.disconnected());
    assert!(!socket.disconnected());
    assert!(started.elapsed() < Duration::from_millis(100));
    release.send(()).unwrap();
    server.join().unwrap();
    std::thread::sleep(Duration::from_millis(50));
    assert!(socket.disconnected());
    assert!(socket.is_closed());
}

#[test]
fn usb_transport_runs_tls_through_usbmuxd() {
    use std::os::unix::net::UnixListener;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("usbmuxd");
    let listener = UnixListener::bind(&path).unwrap();
    let context = testing::server_context(TOKEN);
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let header = usbmux::recvn(&mut stream, 16).unwrap();
            let length = u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
            let message = crate::plist::loads(&usbmux::recvn(&mut stream, length - 16).unwrap()).unwrap();
            let reply = if message["MessageType"] == "ListDevices" {
                json!({"DeviceList": [{"DeviceID": 9, "Properties": {"ConnectionType": "USB", "SerialNumber": "SER"}}]})
            } else {
                assert_eq!(message["DeviceID"], 9);
                assert_eq!(message["PortNumber"], 47821u16.to_be());
                json!({"MessageType": "Result", "Number": 0})
            };
            let body = crate::plist::dumps(&reply).unwrap();
            let mut packet = Vec::new();
            for field in [(16 + body.len()) as u32, 1, 8, 1] {
                packet.extend_from_slice(&field.to_le_bytes());
            }
            packet.extend_from_slice(&body);
            stream.write_all(&packet).unwrap();
            if message["MessageType"] == "Connect" {
                let mut tls = Ssl::new(&context).unwrap().accept(stream).unwrap();
                read_request(&mut tls);
                respond(&mut tls, "200 OK", "application/json", b"{}");
            }
        }
    });
    let mut f = fixture(47821);
    f.config.transport = "usb".into();
    f.config.serial = "SER".into();
    usbmux::SOCKET_OVERRIDE.with(|o| *o.borrow_mut() = Some(path.clone()));
    let (status, value) = request_json(&f.config, TOKEN, "GET", "/v1/status", None, None).unwrap();
    assert_eq!((status, value), (200, Map::new()));
    server.join().unwrap();
    f.config.serial = "OTHER".into();
    let missing = std::thread::spawn({
        let config = f.config.clone();
        move || {
            usbmux::SOCKET_OVERRIDE.with(|o| *o.borrow_mut() = Some(temp.path().join("absent")));
            request(&config, TOKEN, "GET", "/", None, None).unwrap_err()
        }
    }).join().unwrap();
    assert_eq!((missing.code(), missing.to_string().as_str()),
        (Some("bridge_unreachable"), "Cannot reach the bridge service: [Errno 2] No such file or directory"));
}
