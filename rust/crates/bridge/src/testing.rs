//! Test doubles: a local TLS-PSK bridge service (HTTP + WebSocket).
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::JoinHandle;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use mirra_core::config::{load_config, Config};
use openssl::ssl::{Ssl, SslContext, SslMethod, SslStream, SslVersion};

use crate::bridgeclient::{pre_shared_key, CIPHER, PSK_IDENTITY, WEBSOCKET_GUID};

pub const TOKEN: &str = "ABCD-EFGH-JKMN-PQRS-TVWX-YZ01";

pub fn server_context(token: &str) -> SslContext {
    let key = pre_shared_key(token).unwrap();
    let mut builder = SslContext::builder(SslMethod::tls_server()).unwrap();
    builder.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    builder.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    builder.set_cipher_list(CIPHER).unwrap();
    builder.set_psk_server_callback(move |_ssl, identity, psk| {
        assert_eq!(identity, Some(PSK_IDENTITY.as_bytes()));
        psk[..32].copy_from_slice(&key);
        Ok(32)
    });
    builder.build()
}

pub type Stream = SslStream<TcpStream>;

/// Accept `connections` TLS-PSK connections on 127.0.0.1 and pass each to
/// `handler(index, stream)`; failed handshakes are passed to `rejected`.
pub fn serve<F>(token: &str, connections: usize, handler: F) -> (u16, JoinHandle<()>)
where F: Fn(usize, Stream) + Send + 'static {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let context = server_context(token);
    let handle = std::thread::spawn(move || {
        for index in 0..connections {
            let (tcp, _) = listener.accept().unwrap();
            if let Ok(stream) = Ssl::new(&context).unwrap().accept(tcp) {
                handler(index, stream);
            }
        }
    });
    (port, handle)
}

pub struct Fixture {
    pub _temp: tempfile::TempDir,
    pub config: Config,
}

/// A profile pointing at `127.0.0.1:port` with a saved token and certificate.
pub fn fixture(port: u16) -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let root = mirra_core::paths::resolve(temp.path());
    let settings = root.join("settings.json");
    std::fs::write(&settings, "{}").unwrap();
    let mut config = load_config(Some(&settings), &root).unwrap();
    config.transport = "ssh".into();
    config.ssh_host = "127.0.0.1".into();
    config.service_port = port;
    config.timeout = 5;
    config.token_file = root.join("token");
    config.certificate_file = root.join("certificate.der");
    std::fs::write(&config.token_file, format!("{}\n", TOKEN)).unwrap();
    std::fs::write(&config.certificate_file, b"fixture certificate").unwrap();
    Fixture { _temp: temp, config }
}

/// Read one HTTP request: (head, body).
pub fn read_request<S: Read>(stream: &mut S) -> (String, Vec<u8>) {
    let mut data = Vec::new();
    let mut byte = [0u8; 1];
    while !data.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).unwrap() == 0 {
            break;
        }
        data.push(byte[0]);
    }
    let head = String::from_utf8(data).unwrap();
    let length = head.lines().find_map(|l| l.strip_prefix("Content-Length: ")).map(|v| v.trim().parse().unwrap()).unwrap_or(0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).unwrap();
    (head, body)
}

pub fn respond<S: Write>(stream: &mut S, status: &str, content_type: &str, body: &[u8]) {
    let mut message = format!("HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status, content_type, body.len()).into_bytes();
    message.extend_from_slice(body);
    stream.write_all(&message).unwrap();
}

/// Complete the server side of the WebSocket upgrade; returns the request head.
pub fn accept_websocket<S: Read + Write>(stream: &mut S) -> String {
    let (head, _) = read_request(stream);
    let key = head.lines().find_map(|l| l.strip_prefix("Sec-WebSocket-Key: ")).unwrap().trim().to_string();
    let mut accept = key.into_bytes();
    accept.extend_from_slice(WEBSOCKET_GUID);
    let accept = B64.encode(openssl::sha::sha1(&accept));
    stream.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        accept).as_bytes()).unwrap();
    head
}

/// Read one masked client frame: Some((opcode, payload)), None at EOF.
pub fn read_frame<S: Read>(stream: &mut S) -> Option<(u8, Vec<u8>)> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).ok()?;
    assert_eq!(head[0] & 0x80, 0x80, "client frames are final");
    assert_eq!(head[1] & 0x80, 0x80, "client frames are masked");
    let mut length = (head[1] & 0x7f) as u64;
    if length == 126 {
        let mut b = [0u8; 2];
        stream.read_exact(&mut b).ok()?;
        length = u16::from_be_bytes(b) as u64;
    } else if length == 127 {
        let mut b = [0u8; 8];
        stream.read_exact(&mut b).ok()?;
        length = u64::from_be_bytes(b);
    }
    let mut mask = [0u8; 4];
    stream.read_exact(&mut mask).ok()?;
    let mut payload = vec![0u8; length as usize];
    stream.read_exact(&mut payload).ok()?;
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= mask[i & 3];
    }
    Some((head[0] & 0x0f, payload))
}

/// One unmasked server frame.
pub fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80 | opcode];
    let size = payload.len();
    if size < 126 {
        out.push(size as u8);
    } else if size <= 0xffff {
        out.push(126);
        out.extend_from_slice(&(size as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(size as u64).to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

pub fn write_frame<S: Write>(stream: &mut S, opcode: u8, payload: &[u8]) {
    stream.write_all(&frame(opcode, payload)).unwrap();
}

pub fn write_text<S: Write>(stream: &mut S, value: &serde_json::Value) {
    write_frame(stream, 0x1, value.to_string().as_bytes());
}

/// Read one client text frame as JSON (answering nothing else).
pub fn read_json<S: Read>(stream: &mut S) -> Option<serde_json::Value> {
    let (opcode, payload) = read_frame(stream)?;
    if opcode != 0x1 {
        return None;
    }
    Some(serde_json::from_slice(&payload).unwrap())
}

/// A self-signed DER certificate with the given validity (epoch seconds).
pub fn certificate(not_before: i64, not_after: i64) -> Vec<u8> {
    use openssl::asn1::Asn1Time;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::{X509Builder, X509NameBuilder};
    let key = PKey::from_ec_key(EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "Mirra test").unwrap();
    let name = name.build();
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder.set_not_before(&Asn1Time::from_unix(not_before).unwrap()).unwrap();
    builder.set_not_after(&Asn1Time::from_unix(not_after).unwrap()).unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    builder.build().to_der().unwrap()
}
