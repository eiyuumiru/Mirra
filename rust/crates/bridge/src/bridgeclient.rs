//! TLS-PSK HTTP and WebSocket client for the bridge service on the phone
//! (port of `scripts/bridgeclient.py`).
//!
//! SSH is used only to install the service. Afterwards the Mac connects to
//! one TCP port on the phone (over Wi-Fi, or through usbmux over USB). TLS 1.2
//! ECDHE-PSK with ChaCha20-Poly1305 both encrypts the connection and proves
//! that each side holds the pairing token: the pre-shared key is derived from
//! it, so a peer without the token cannot finish the handshake. No
//! certificate is involved.
use std::ffi::{CStr, CString};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use mirra_core::config::Config;
use mirra_core::subprocess::{self, RunOptions};
use openssl::ssl::{ErrorCode, HandshakeError, Ssl, SslContext, SslMethod, SslOptions, SslStream, SslVerifyMode, SslVersion};
use regex::Regex;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::error::{BridgeError, Error, Result};
use crate::pyutil::{self, is_printable, is_space, strip};
use crate::usbmux;

pub const DEFAULT_PORT: u16 = 47820;
pub const BRIDGE_REVISION: i64 = 2;
pub const TOKEN_ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
pub const TOKEN_LENGTH: usize = 24;
pub const PSK_IDENTITY: &str = "mirra-bridge-v1";
pub const PSK_CONTEXT: &[u8] = b"mirra-bridge-psk-v1\x00";
pub const CIPHER: &str = "ECDHE-PSK-CHACHA20-POLY1305";
pub const WEBSOCKET_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
pub const MAX_MESSAGE: usize = 262144;
pub const MAX_HEADER: usize = 16384;
pub const MAX_BODY: usize = 1048576 + 65536;

const TOKEN_FORMAT: &str = "The pairing token must contain 24 letters or digits, as shown in the phone’s Settings";

/// `normalize_token(value)`: the 24-symbol token; accepts case,
/// hyphens/spaces and O/I/L typos. Raises `ValueError`.
pub fn normalize_token(value: &str) -> Result<String> {
    let token: String = value.chars().filter(|c| !is_space(*c)).collect::<String>()
        .replace('-', "").to_uppercase().replace('O', "0").replace(['I', 'L'], "1");
    if token.chars().count() != TOKEN_LENGTH || token.chars().any(|c| !TOKEN_ALPHABET.contains(c)) {
        return Err(Error::value(TOKEN_FORMAT));
    }
    Ok(token)
}

/// `display_token(token)`: `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`.
pub fn display_token(token: &str) -> Result<String> {
    let token = normalize_token(token)?;
    Ok(token.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("-"))
}

/// `pre_shared_key(token)` = sha256(PSK_CONTEXT + normalized token).
pub fn pre_shared_key(token: &str) -> Result<[u8; 32]> {
    let token = normalize_token(token)?;
    let mut hasher = Sha256::new();
    hasher.update(PSK_CONTEXT);
    hasher.update(token.as_bytes());
    Ok(hasher.finalize().into())
}

/// `read_token(path)`; failures are `BridgeError(..., 'bridge_pairing_missing')`.
pub fn read_token(path: &Path) -> Result<String> {
    let data = std::fs::read(path).map_err(|_| BridgeError::new(
        "Missing bridge pairing token; run setup again or pair with the token from the phone’s Settings",
        "bridge_pairing_missing"))?;
    let invalid = || BridgeError::new("The saved bridge pairing token is invalid; pair again", "bridge_pairing_missing");
    let text = String::from_utf8(data).map_err(|_| invalid())?;
    normalize_token(&text).map_err(|_| Error::Bridge(invalid()))
}

/// `tls_context(token)`: TLS 1.2 only, ECDHE-PSK-CHACHA20-POLY1305, no
/// certificate verification (authentication comes from the pre-shared key:
/// a server without the token cannot complete the PSK handshake).
pub fn tls_context(token: &str) -> Result<SslContext> {
    let key = pre_shared_key(token)?;
    let unavailable = |_| BridgeError::new(format!("This Python’s TLS library lacks {}", CIPHER), "bridge_tls_unavailable");
    let mut builder = SslContext::builder(SslMethod::tls_client()).map_err(unavailable)?;
    builder.set_verify(SslVerifyMode::NONE);
    builder.set_min_proto_version(Some(SslVersion::TLS1_2)).map_err(unavailable)?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_2)).map_err(unavailable)?;
    builder.set_cipher_list(CIPHER).map_err(unavailable)?;
    // Like CPython's default context: a missing close_notify reads as EOF.
    builder.set_options(SslOptions::IGNORE_UNEXPECTED_EOF | SslOptions::NO_COMPRESSION);
    builder.set_psk_client_callback(move |_ssl, _hint, identity, psk| {
        let name = PSK_IDENTITY.as_bytes();
        if identity.len() <= name.len() || psk.len() < key.len() {
            return Err(openssl::error::ErrorStack::get());
        }
        identity[..name.len()].copy_from_slice(name);
        identity[name.len()] = 0;
        psk[..key.len()].copy_from_slice(&key);
        Ok(key.len())
    });
    Ok(builder.build())
}

/// `client_identity()`: this Mac's hardware UUID and name (cached). The
/// bridge saves this Mac's keys under the UUID and shows the name in the
/// phone's Settings.
pub fn client_identity() -> (String, String) {
    static CLIENT: OnceLock<(String, String)> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let options = RunOptions::new().capture().timeout(Duration::from_secs(5));
        let uuid = subprocess::run(&["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], &options).ok()
            .and_then(|reply| {
                let pattern = Regex::new(r#""IOPlatformUUID" = "([0-9A-Fa-f-]{36})""#).unwrap();
                pattern.captures(&reply.stdout_text()).map(|c| c[1].to_uppercase())
            }).unwrap_or_default();
        let name = subprocess::run(&["/usr/sbin/scutil", "--get", "ComputerName"], &options).ok()
            .map(|reply| strip(&reply.stdout_text()).to_string()).unwrap_or_default();
        let name = if name.is_empty() { hostname() } else { name };
        let name = if name.is_empty() { "Mac".to_string() } else { name };
        let name: String = name.chars().filter(|c| is_printable(*c)).take(64).collect();
        (uuid, if name.is_empty() { "Mac".into() } else { name })
    }).clone()
}

fn hostname() -> String {
    let mut buffer = [0u8; 256];
    // SAFETY: the buffer is writable for its full length.
    if unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) } != 0 {
        return String::new();
    }
    let end = buffer.iter().position(|b| *b == 0).unwrap_or(buffer.len());
    String::from_utf8_lossy(&buffer[..end]).into_owned()
}

/// `session_path(saved)`: a saved session keeps this Mac's keys on the
/// bridge across restarts.
pub fn session_path(saved: bool) -> String {
    let (uuid, name) = if saved { client_identity() } else { (String::new(), String::new()) };
    if uuid.is_empty() {
        return "/v1/session".into();
    }
    format!("/v1/session?{}", pyutil::urlencode(&[("client", &uuid), ("name", &name)]))
}

/// `destination(config)`
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Destination {
    /// `('usb', serial or product_type)`
    Usb(String),
    /// `(ssh_host, service_port)`
    Network(String, u16),
}

pub fn destination(config: &Config) -> Destination {
    if config.transport == "usb" {
        Destination::Usb(if config.serial.is_empty() { config.product_type.clone() } else { config.serial.clone() })
    } else {
        Destination::Network(config.ssh_host.clone(), config.service_port)
    }
}

/// `has_ssh_access(config)`
pub fn has_ssh_access(config: &Config) -> bool {
    [&config.user_file, &config.identity_file, &config.known_hosts_file].iter().all(|p| p.is_file())
}

/// `bridge_revision(status)`: an advertised revision, including known
/// legacy bridges (revision 0); `None` for other services or bad values.
pub fn bridge_revision(status: &Map<String, Value>) -> Option<i64> {
    if status.get("service") != Some(&Value::from("mirra-bridge")) || !pyutil::equals_number(status.get("protocol_version"), 2) {
        return None;
    }
    match status.get("bridge_revision") {
        None => Some(0),
        Some(Value::Number(n)) if !n.is_f64() => n.as_i64().filter(|r| *r >= 0).or_else(|| n.as_u64().map(|_| i64::MAX)),
        Some(_) => None,
    }
}

/// The transport under TLS: TCP (network) or a usbmux stream (USB).
#[derive(Debug)]
pub enum RawSocket {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl RawSocket {
    /// `settimeout(timeout)` for both directions.
    pub fn set_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            RawSocket::Tcp(s) => {
                s.set_read_timeout(timeout)?;
                s.set_write_timeout(timeout)
            }
            RawSocket::Unix(s) => {
                s.set_read_timeout(timeout)?;
                s.set_write_timeout(timeout)
            }
        }
    }
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match self {
            RawSocket::Tcp(s) => s.set_nonblocking(nonblocking),
            RawSocket::Unix(s) => s.set_nonblocking(nonblocking),
        }
    }
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        match self {
            RawSocket::Tcp(s) => s.shutdown(how),
            RawSocket::Unix(s) => s.shutdown(how),
        }
    }
    pub fn try_clone(&self) -> io::Result<RawSocket> {
        Ok(match self {
            RawSocket::Tcp(s) => RawSocket::Tcp(s.try_clone()?),
            RawSocket::Unix(s) => RawSocket::Unix(s.try_clone()?),
        })
    }
}

impl Read for RawSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            RawSocket::Tcp(s) => s.read(buf),
            RawSocket::Unix(s) => s.read(buf),
        }
    }
}

impl Write for RawSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            RawSocket::Tcp(s) => s.write(buf),
            RawSocket::Unix(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// An authenticated, encrypted stream to the bridge service.
pub type TlsStream = SslStream<RawSocket>;

/// `socket.create_connection((host, port), timeout)`: try each resolved
/// address in turn and raise the last failure.
pub fn create_connection(host: &str, port: u16, timeout: Duration) -> mirra_core::Result<TcpStream> {
    let mut last = None;
    for address in getaddrinfo(host, port)? {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => return Ok(stream),
            Err(e) => last = Some(e),
        }
    }
    Err(match last {
        Some(e) if pyutil::is_timeout(&e) && e.raw_os_error().is_none() => mirra_core::Error::Timeout("timed out".into()),
        Some(e) => mirra_core::Error::Os(e),
        None => mirra_core::Error::Os(io::Error::other("getaddrinfo returns an empty list")),
    })
}

fn getaddrinfo(host: &str, port: u16) -> mirra_core::Result<Vec<SocketAddr>> {
    let node = CString::new(host).map_err(|_| mirra_core::Error::Value("embedded null character".into()))?;
    let service = CString::new(port.to_string()).unwrap();
    // SAFETY: zeroed addrinfo is a valid "no hints" value; fields set below.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = libc::AF_UNSPEC;
    hints.ai_socktype = libc::SOCK_STREAM;
    let mut result: *mut libc::addrinfo = std::ptr::null_mut();
    // SAFETY: valid C strings and out pointer; the list is freed below.
    let status = unsafe { libc::getaddrinfo(node.as_ptr(), service.as_ptr(), &hints, &mut result) };
    if status != 0 {
        if status == libc::EAI_SYSTEM {
            return Err(mirra_core::Error::Os(io::Error::last_os_error()));
        }
        // SAFETY: gai_strerror returns a static C string.
        let message = unsafe { CStr::from_ptr(libc::gai_strerror(status)) }.to_string_lossy().into_owned();
        return Err(mirra_core::Error::os_message(status, message));
    }
    let mut addresses = Vec::new();
    let mut cursor = result;
    while !cursor.is_null() {
        // SAFETY: cursor walks the list returned by getaddrinfo.
        let info = unsafe { &*cursor };
        if !info.ai_addr.is_null() {
            match info.ai_family {
                libc::AF_INET => {
                    // SAFETY: AF_INET entries carry a sockaddr_in.
                    let a = unsafe { &*(info.ai_addr as *const libc::sockaddr_in) };
                    let ip = std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
                    addresses.push(SocketAddr::from((ip, u16::from_be(a.sin_port))));
                }
                libc::AF_INET6 => {
                    // SAFETY: AF_INET6 entries carry a sockaddr_in6.
                    let a = unsafe { &*(info.ai_addr as *const libc::sockaddr_in6) };
                    let ip = std::net::Ipv6Addr::from(a.sin6_addr.s6_addr);
                    addresses.push(SocketAddr::V6(std::net::SocketAddrV6::new(ip, u16::from_be(a.sin6_port),
                        a.sin6_flowinfo, a.sin6_scope_id)));
                }
                _ => {}
            }
        }
        cursor = info.ai_next;
    }
    // SAFETY: result came from a successful getaddrinfo.
    unsafe { libc::freeaddrinfo(result) };
    Ok(addresses)
}

fn core_is_timeout(error: &mirra_core::Error) -> bool {
    match error {
        mirra_core::Error::Timeout(_) => true,
        mirra_core::Error::Os(e) | mirra_core::Error::OsPath { error: e, .. } => pyutil::is_timeout(e),
        mirra_core::Error::OsMessage { errno, .. } => *errno == libc::ETIMEDOUT,
        _ => false,
    }
}

fn connect_raw(config: &Config, timeout: Duration) -> mirra_core::Result<RawSocket> {
    if config.transport == "usb" {
        let devices = usbmux::list_devices()?;
        let device = usbmux::select_device(&devices, &config.product_type, &config.serial, None)?;
        let id = device.get("DeviceID").cloned()
            .ok_or_else(|| mirra_core::Error::Value("The selected USB device has no DeviceID".into()))?;
        Ok(RawSocket::Unix(usbmux::connect(&id, config.service_port)?))
    } else {
        Ok(RawSocket::Tcp(create_connection(&config.ssh_host, config.service_port, timeout)?))
    }
}

/// `open_socket(config, token, timeout)`: one authenticated, encrypted
/// stream to the bridge service.
pub fn open_socket(config: &Config, token: &str, timeout: Duration) -> Result<TlsStream> {
    let context = tls_context(token)?;
    let raw = match connect_raw(config, timeout) {
        Ok(raw) => raw,
        Err(error) if core_is_timeout(&error) => {
            return Err(BridgeError::new("The bridge service did not answer; check the phone’s address and jailbreak",
                "bridge_unreachable").into());
        }
        Err(error) if error.is_os_error() || matches!(error, mirra_core::Error::Value(_) | mirra_core::Error::Config(_)) => {
            let code = if error.errno() == Some(libc::ECONNREFUSED) { "bridge_refused" } else { "bridge_unreachable" };
            return Err(BridgeError::new(format!("Cannot reach the bridge service: {}", error), code).into());
        }
        Err(error) => return Err(error.into()),
    };
    raw.set_timeout(Some(timeout))?;
    handshake(&context, raw)
}

/// Client handshake on an already connected socket, with Python's mapping of
/// timeouts, TLS failures (a wrong token) and socket errors.
pub fn handshake(context: &SslContext, raw: RawSocket) -> Result<TlsStream> {
    let unfinished = || BridgeError::new("The bridge did not finish the secure handshake", "bridge_unreachable");
    let rejected = || BridgeError::new(
        "The bridge rejected the pairing token. Pair again with the token shown in the phone’s Settings", "bridge_token_rejected");
    let ssl = Ssl::new(context).map_err(|_| rejected())?;
    match ssl.connect(raw) {
        Ok(stream) => Ok(stream),
        Err(HandshakeError::SetupFailure(_)) => Err(rejected().into()),
        Err(HandshakeError::WouldBlock(_)) => Err(unfinished().into()),
        Err(HandshakeError::Failure(mid)) => {
            let error = mid.error();
            match error.io_error() {
                Some(io) if pyutil::is_timeout(io) && io.raw_os_error() != Some(libc::ETIMEDOUT) => Err(unfinished().into()),
                Some(io) if error.code() == ErrorCode::SYSCALL => {
                    let text = match io.raw_os_error() {
                        Some(n) => mirra_core::Error::Os(io::Error::from_raw_os_error(n)).to_string(),
                        None => io.to_string(),
                    };
                    Err(BridgeError::new(format!("The bridge closed the secure handshake: {}", text), "bridge_unreachable").into())
                }
                _ => Err(rejected().into()),
            }
        }
    }
}

fn remaining(deadline: Instant) -> Option<Duration> {
    deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())
}

/// Map an SSL I/O failure to Python's `OSError`.
fn ssl_io(error: openssl::ssl::Error) -> Error {
    match error.into_io_error() {
        Ok(io) => io.into(),
        Err(error) => Error::Core(mirra_core::Error::Os(io::Error::other(error.to_string()))),
    }
}

/// `_receive(stream, deadline)`: one read of up to 64 KiB; empty at EOF.
fn receive(stream: &mut TlsStream, deadline: Instant) -> Result<Vec<u8>> {
    let Some(left) = remaining(deadline) else { return Err(BridgeError::timeout().into()) };
    stream.get_ref().set_timeout(Some(left))?;
    let mut buffer = vec![0u8; 65536];
    loop {
        match stream.ssl_read(&mut buffer) {
            Ok(n) => {
                buffer.truncate(n);
                return Ok(buffer);
            }
            Err(e) if e.code() == ErrorCode::ZERO_RETURN => return Ok(Vec::new()),
            Err(e) if e.code() == ErrorCode::SYSCALL && e.io_error().is_none() => return Ok(Vec::new()),
            Err(e) if e.code() == ErrorCode::WANT_READ && e.io_error().is_none() => {}
            Err(e) if e.io_error().is_some_and(|io| pyutil::is_timeout(io) && io.raw_os_error() != Some(libc::ETIMEDOUT)) => {
                return Err(BridgeError::timeout().into());
            }
            Err(e) if e.io_error().is_some_and(|io| io.kind() == io::ErrorKind::Interrupted) => {}
            Err(e) => return Err(ssl_io(e)),
        }
    }
}

/// `_send(stream, data, deadline)`
fn send(stream: &mut TlsStream, data: &[u8], deadline: Instant) -> Result<()> {
    let late = || BridgeError::timeout_with("Bridge did not accept the request in time");
    let mut view = data;
    while !view.is_empty() {
        let Some(left) = remaining(deadline) else { return Err(late().into()) };
        stream.get_ref().set_timeout(Some(left))?;
        match stream.ssl_write(view) {
            Ok(count) => view = &view[count..],
            Err(e) if e.code() == ErrorCode::WANT_READ && e.io_error().is_none() => {}
            Err(e) if e.io_error().is_some_and(|io| pyutil::is_timeout(io) && io.raw_os_error() != Some(libc::ETIMEDOUT)) => {
                return Err(late().into());
            }
            Err(e) if e.io_error().is_some_and(|io| io.kind() == io::ErrorKind::Interrupted) => {}
            Err(e) => return Err(ssl_io(e)),
        }
    }
    Ok(())
}

fn protocol(message: &str) -> Error {
    BridgeError::new(message, "bridge_protocol_error").into()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn parse_digits(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(text.bytes().fold(0u64, |acc, b| acc.saturating_mul(10).saturating_add((b - b'0') as u64)))
}

/// `_read_head(stream, buffer, deadline)` → (status, lower-cased headers).
fn read_head(stream: &mut TlsStream, buffer: &mut Vec<u8>, deadline: Instant) -> Result<(u64, Map<String, Value>)> {
    while find(buffer, b"\r\n\r\n").is_none() {
        if buffer.len() > MAX_HEADER {
            return Err(protocol("Bridge response headers are too large"));
        }
        let chunk = receive(stream, deadline)?;
        if chunk.is_empty() {
            return Err(BridgeError::closed_with("Bridge closed the connection before replying").into());
        }
        buffer.extend_from_slice(&chunk);
    }
    let end = find(buffer, b"\r\n\r\n").unwrap();
    let head: String = buffer[..end].iter().map(|b| *b as char).collect();
    buffer.drain(..end + 4);
    let lines: Vec<&str> = head.split("\r\n").collect();
    let parts: Vec<&str> = lines[0].splitn(3, ' ').collect();
    let status = match parts.as_slice() {
        [version, status, ..] if *version == "HTTP/1.1" => parse_digits(status),
        _ => None,
    };
    let Some(status) = status else { return Err(protocol("Bridge returned an invalid HTTP response")) };
    let mut headers = Map::new();
    for line in &lines[1..] {
        let Some((name, value)) = line.split_once(':') else {
            return Err(protocol("Bridge returned an invalid HTTP header"));
        };
        headers.insert(strip(name).to_lowercase(), Value::from(strip(value)));
    }
    Ok((status, headers))
}

fn header<'a>(headers: &'a Map<String, Value>, name: &str) -> &'a str {
    headers.get(name).and_then(Value::as_str).unwrap_or("")
}

/// One HTTP reply: `(status, content type, body)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u64,
    pub content_type: String,
    pub body: Vec<u8>,
}

/// `request(config, token, method, path, payload=None, *, timeout=None)`.
pub fn request(config: &Config, token: &str, method: &str, path: &str, payload: Option<&Value>,
               timeout: Option<Duration>) -> Result<Response> {
    let timeout = timeout.unwrap_or(Duration::from_secs(config.timeout));
    let deadline = Instant::now() + timeout;
    let body = payload.map(|p| mirra_core::pyjson::dumps(p).into_bytes()).unwrap_or_default();
    let mut message = format!("{} {} HTTP/1.1\r\nHost: mirra-bridge\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        method, path, body.len()).into_bytes();
    message.extend_from_slice(&body);
    let mut stream = open_socket(config, token, timeout)?;
    send(&mut stream, &message, deadline)?;
    let mut buffer = Vec::new();
    let (status, headers) = read_head(&mut stream, &mut buffer, deadline)?;
    let length = match parse_digits(header(&headers, "content-length")) {
        Some(n) if n <= MAX_BODY as u64 => n as usize,
        _ => return Err(protocol("Bridge response has an invalid length")),
    };
    while buffer.len() < length {
        let chunk = receive(&mut stream, deadline)?;
        if chunk.is_empty() {
            return Err(BridgeError::closed_with("Bridge closed the connection during its reply").into());
        }
        buffer.extend_from_slice(&chunk);
    }
    buffer.truncate(length);
    Ok(Response { status, content_type: header(&headers, "content-type").to_string(), body: buffer })
}

/// `request_json(...)` → (status, reply object).
pub fn request_json(config: &Config, token: &str, method: &str, path: &str, payload: Option<&Value>,
                    timeout: Option<Duration>) -> Result<(u64, Map<String, Value>)> {
    let response = request(config, token, method, path, payload, timeout)?;
    match serde_json::from_slice::<Value>(&response.body) {
        Ok(Value::Object(map)) => Ok((response.status, map)),
        Ok(_) => Err(protocol("Bridge reply must be an object")),
        Err(_) => Err(protocol("Bridge returned invalid JSON")),
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    openssl::rand::rand_bytes(&mut bytes).expect("system random bytes");
    bytes
}

/// Client side of RFC 6455 for one keystore session (text frames only).
pub struct WebSocket {
    stream: TlsStream,
    buffer: Vec<u8>,
    closed: bool,
}

impl WebSocket {
    pub fn new(stream: TlsStream, buffer: Vec<u8>) -> Self {
        WebSocket { stream, buffer, closed: false }
    }

    /// `WebSocket.open(config, token, path, timeout=)`
    pub fn open(config: &Config, token: &str, path: &str, timeout: Duration) -> Result<WebSocket> {
        let deadline = Instant::now() + timeout;
        let stream = open_socket(config, token, timeout)?;
        Self::upgrade(stream, path, deadline)
    }

    /// The HTTP upgrade on an open stream (closed again on failure).
    pub fn upgrade(mut stream: TlsStream, path: &str, deadline: Instant) -> Result<WebSocket> {
        let key = B64.encode(random::<16>());
        let result = (|| {
            send(&mut stream, format!("GET {} HTTP/1.1\r\nHost: mirra-bridge\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n\r\n",
                path, key).as_bytes(), deadline)?;
            let mut buffer = Vec::new();
            let (status, headers) = read_head(&mut stream, &mut buffer, deadline)?;
            if status != 101 {
                let code = if status == 503 { "bridge_session_limit" } else { "bridge_protocol_error" };
                return Err(BridgeError::new(format!("Bridge refused the session (HTTP {})", status), code).into());
            }
            let mut accept = key.clone().into_bytes();
            accept.extend_from_slice(WEBSOCKET_GUID);
            let expected = B64.encode(openssl::sha::sha1(&accept));
            if header(&headers, "sec-websocket-accept") != expected || header(&headers, "upgrade").to_lowercase() != "websocket" {
                return Err(protocol("Bridge returned an invalid WebSocket handshake"));
            }
            Ok(buffer)
        })();
        match result {
            Ok(buffer) => Ok(WebSocket::new(stream, buffer)),
            Err(error) => {
                let _ = stream.get_ref().shutdown(Shutdown::Both);
                Err(error)
            }
        }
    }

    /// `closed`
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// The underlying socket (to interrupt a blocked call from elsewhere).
    pub fn raw_socket(&self) -> &RawSocket {
        self.stream.get_ref()
    }

    /// `_frame(opcode, payload)`: one masked, final client frame.
    pub fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        Self::frame_with_mask(opcode, payload, random::<4>())
    }

    pub fn frame_with_mask(opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
        let size = payload.len();
        let mut out = vec![0x80 | opcode];
        if size < 126 {
            out.push(0x80 | size as u8);
        } else if size <= 0xffff {
            out.push(0x80 | 126);
            out.extend_from_slice(&(size as u16).to_be_bytes());
        } else {
            out.push(0x80 | 127);
            out.extend_from_slice(&(size as u64).to_be_bytes());
        }
        out.extend_from_slice(&mask);
        out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i & 3]));
        out
    }

    /// `send_text(payload, deadline)`
    pub fn send_text(&mut self, payload: &[u8], deadline: Instant) -> Result<()> {
        if self.closed {
            return Err(BridgeError::closed().into());
        }
        send(&mut self.stream, &Self::frame(0x1, payload), deadline)
    }

    /// `_parse()`: (opcode, payload) for one complete frame, or None.
    fn parse(&mut self) -> Result<Option<(u8, Vec<u8>)>> {
        if self.buffer.len() < 2 {
            return Ok(None);
        }
        let (first, second) = (self.buffer[0], self.buffer[1]);
        if first & 0x70 != 0 || second & 0x80 != 0 || first & 0x80 == 0 {
            return Err(protocol("Bridge sent an invalid WebSocket frame"));
        }
        let (mut length, mut header) = ((second & 0x7f) as u64, 2usize);
        if length == 126 {
            if self.buffer.len() < 4 {
                return Ok(None);
            }
            length = u16::from_be_bytes([self.buffer[2], self.buffer[3]]) as u64;
            header = 4;
        } else if length == 127 {
            if self.buffer.len() < 10 {
                return Ok(None);
            }
            length = u64::from_be_bytes(self.buffer[2..10].try_into().unwrap());
            header = 10;
        }
        if length > MAX_MESSAGE as u64 {
            return Err(BridgeError::new("Bridge message exceeds the size limit", "bridge_message_too_large").into());
        }
        let total = header + length as usize;
        if self.buffer.len() < total {
            return Ok(None);
        }
        let payload = self.buffer[header..total].to_vec();
        self.buffer.drain(..total);
        Ok(Some((first & 0x0f, payload)))
    }

    /// `_handle(frame, deadline)`: the text payload, or None for control frames.
    fn handle(&mut self, frame: (u8, Vec<u8>), deadline: Instant) -> Result<Option<Vec<u8>>> {
        let (opcode, payload) = frame;
        match opcode {
            0x8 => {
                self.closed = true;
                Err(BridgeError::closed().into())
            }
            0x9 => {
                send(&mut self.stream, &Self::frame(0xA, &payload), deadline)?;
                Ok(None)
            }
            0xA => Ok(None),
            0x1 => Ok(Some(payload)),
            _ => Err(protocol("Bridge sent an unsupported WebSocket frame")),
        }
    }

    /// `receive(deadline)`: the next text message.
    pub fn receive(&mut self, deadline: Instant) -> Result<Vec<u8>> {
        loop {
            if let Some(frame) = self.parse()? {
                if let Some(payload) = self.handle(frame, deadline)? {
                    return Ok(payload);
                }
                continue;
            }
            let chunk = receive(&mut self.stream, deadline)?;
            if chunk.is_empty() {
                self.closed = true;
                return Err(BridgeError::closed().into());
            }
            self.buffer.extend_from_slice(&chunk);
        }
    }

    /// Non-blocking check, valid only between requests: the service never
    /// sends unsolicited data frames, so readable input means a closure.
    pub fn disconnected(&mut self) -> bool {
        if self.closed {
            return true;
        }
        if self.stream.get_ref().set_nonblocking(true).is_err() {
            self.closed = true;
            return true;
        }
        let mut buffer = vec![0u8; 65536];
        let read = self.stream.ssl_read(&mut buffer);
        let restored = self.stream.get_ref().set_nonblocking(false);
        let chunk = match read {
            Ok(n) => {
                buffer.truncate(n);
                buffer
            }
            Err(e) if e.code() == ErrorCode::WANT_READ => return restored.is_err(),
            Err(e) if e.io_error().is_some_and(|io| io.kind() == io::ErrorKind::WouldBlock) => return restored.is_err(),
            Err(e) if e.code() == ErrorCode::ZERO_RETURN || (e.code() == ErrorCode::SYSCALL && e.io_error().is_none()) => Vec::new(),
            Err(_) => {
                self.closed = true;
                return true;
            }
        };
        if chunk.is_empty() || restored.is_err() {
            self.closed = true;
            return true;
        }
        self.buffer.extend_from_slice(&chunk);
        loop {
            let outcome = match self.parse() {
                Ok(None) => return false,
                Ok(Some(frame)) => self.handle(frame, Instant::now() + Duration::from_secs(1)),
                Err(error) => Err(error),
            };
            match outcome {
                Ok(None) => {}
                // A pong that cannot be sent also means the session is gone.
                Ok(Some(_)) | Err(_) => {
                    self.closed = true;
                    return true;
                }
            }
        }
    }

    /// `close(deadline=None)`: send a 1000 close frame unless already
    /// closed, then close the connection.
    pub fn close(&mut self, deadline: Option<Instant>) {
        if !self.closed {
            self.closed = true;
            let deadline = deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(1));
            let _ = send(&mut self.stream, &Self::frame(0x8, &1000u16.to_be_bytes()), deadline);
        }
        let _ = self.stream.get_ref().shutdown(Shutdown::Both);
    }
}

#[cfg(test)]
mod tests;
