use super::*;
use crate::testing::{self, fixture, read_request, respond, serve, TOKEN};
use std::sync::mpsc;

/// A bridge answering POST /v1/certificate with `exports[i]` and GET with `der`.
type Requests = mpsc::Receiver<(String, Vec<u8>)>;

fn bridge(exports: Vec<(&'static str, Value)>, der: Vec<u8>) -> (testing::Fixture, Requests, std::thread::JoinHandle<()>) {
    let (sent, seen) = mpsc::channel();
    let count = exports.len() + 1;
    let exports = std::sync::Mutex::new(exports.into_iter());
    let (port, server) = serve(TOKEN, count, move |_, mut stream| {
        let (head, body) = read_request(&mut stream);
        let is_get = head.starts_with("GET ");
        sent.send((head, body)).unwrap();
        if is_get {
            respond(&mut stream, "200 OK", "application/octet-stream", &der);
        } else if let Some((status, reply)) = exports.lock().unwrap().next() {
            respond(&mut stream, status, "application/json", reply.to_string().as_bytes());
        }
    });
    (fixture(port), seen, server)
}

#[test]
fn exports_downloads_and_checks_the_certificate() {
    let der = testing::certificate(1_700_000_000, 1_900_000_000);
    let digest = hex(&Sha256::digest(&der));
    let (f, seen, server) = bridge(vec![("200 OK", json!({"certificate_exported": true, "sha256": digest,
        "issuance_requested": false}))], der.clone());
    let (sink, records) = activity::collector();
    let (data, issued) = activity::capture(Some(sink), || {
        certificate_from_service(&f.config, TOKEN, true, false, Some("ab")).unwrap()
    });
    assert_eq!((data, issued), (der.clone(), false));
    let (head, body) = seen.recv().unwrap();
    assert!(head.starts_with("POST /v1/certificate HTTP/1.1\r\n"));
    assert_eq!(body, br#"{"issue": true, "replace_expired_sha256": "ab"}"#);
    assert!(seen.recv().unwrap().0.starts_with("GET /v1/certificate HTTP/1.1\r\n"));
    server.join().unwrap();
    let records = records.lock().unwrap();
    let messages: Vec<(&str, &str)> = records.iter()
        .map(|r| (r["source"].as_str().unwrap(), r["message"].as_str().unwrap())).collect();
    assert_eq!(&messages[..3], [("Certificate", "issue begin"), ("Certificate", "issue complete"),
        ("Certificate", "certificate download verified")]);
    assert_eq!(records[2]["fields"]["bytes"], der.len());
    assert_eq!(messages[3], ("Certificate", "$ openssl x509 -inform DER -noout"));
    assert_eq!(records.last().unwrap()["message"], "process exited");
}

#[test]
fn missing_cache_requests_issuance_once() {
    let der = testing::certificate(1_700_000_000, 1_900_000_000);
    let digest = hex(&Sha256::digest(&der));
    let (f, seen, server) = bridge(vec![
        ("409 Conflict", json!({"error": "cached_certificate_unavailable", "error_code": 7, "completed": "no"})),
        ("200 OK", json!({"certificate_exported": 1, "sha256": digest})),
    ], der.clone());
    let (sink, records) = activity::collector();
    let (data, issued) = activity::capture(Some(sink), || {
        certificate_from_service(&f.config, TOKEN, false, true, Some("unused")).unwrap()
    });
    assert_eq!((data, issued), (der, true));
    assert_eq!(seen.recv().unwrap().1, br#"{"issue": false}"#);
    assert_eq!(seen.recv().unwrap().1, br#"{"issue": true, "replace_expired_sha256": "unused"}"#);
    server.join().unwrap();
    let records = records.lock().unwrap();
    let warning = records.iter().find(|r| r["message"] == "cached certificate unavailable").unwrap();
    assert_eq!((warning["level"].as_str(), &warning["fields"]), (Some("warning"), &json!({"error_code": "cached_certificate_unavailable"})));
}

#[test]
fn export_failures_are_remote_setup_errors() {
    let (f, _seen, server) = bridge(vec![("500 Error", json!({"error": "issuer_failed", "error_code": 7, "completed": true,
        "secret": "x"}))], Vec::new());
    let error = certificate_from_service(&f.config, TOKEN, false, true, None).unwrap_err();
    assert_eq!(error.type_name(), "RemoteSetupError");
    assert_eq!(error.to_string(), "The bridge could not export its device certificate: issuer_failed");
    let details = &error.as_endpoint().unwrap().details;
    assert_eq!(Value::Object(details.clone()), json!({"error_code": 7, "completed": true}));
    drop(server);

    let (f, _seen, server) = bridge(vec![("200 OK", json!({"certificate_exported": false, "error": ""}))], Vec::new());
    let error = certificate_from_service(&f.config, TOKEN, true, false, None).unwrap_err();
    assert_eq!(error.to_string(), "The bridge could not export its device certificate: 200");
    assert_eq!(error.code(), Some(""));
    drop(server);

    let der = testing::certificate(1_700_000_000, 1_900_000_000);
    let (f, _seen, server) = bridge(vec![("200 OK", json!({"certificate_exported": true, "sha256": "0".repeat(64)}))], der);
    let mismatch = certificate_from_service(&f.config, TOKEN, true, false, None).unwrap_err();
    assert_eq!((mismatch.type_name().as_str(), mismatch.to_string().as_str()),
        ("RuntimeError", "Downloaded device certificate does not match the export"));
    server.join().unwrap();

    let junk = b"not a certificate".to_vec();
    let digest = hex(&Sha256::digest(&junk));
    let (f, _seen, server) = bridge(vec![("200 OK", json!({"certificate_exported": true, "sha256": digest}))], junk);
    let invalid = certificate_from_service(&f.config, TOKEN, true, false, None).unwrap_err();
    assert_eq!(invalid.type_name(), "CalledProcessError");
    server.join().unwrap();
}
