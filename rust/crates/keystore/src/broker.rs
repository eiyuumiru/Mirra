//! Carry native sharingd AKS requests to an isolated keybag on the
//! configured backend (port of `scripts/broker.py`).
//!
//! Wire protocol (shared with the injected adapter, src/mirroring/keystore.m):
//! each connection carries one request, a 4-byte big-endian length followed
//! by a JSON object, answered the same way. Unix-socket peers must have this
//! user's uid; TCP (127.0.0.1) requests must carry `"_auth": <auth_token>`.
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mirra_bridge::certificates::validity;
use mirra_bridge::transport::{transport_details, Endpoint, EndpointOptions};
use mirra_core::config::{default_root, load_config};
use mirra_core::event::Event;
use mirra_core::{paths, pyjson, sys};
use serde_json::{json, Map, Value};

use crate::args::{Opt, Parser};
use crate::failure::{stdout_events, Emit, Failure};
use crate::keystore::{AksBroker, Backend};
use crate::util::{self, text, truthy};

pub const MAX_REQUEST: u32 = 262144;
const SOCKET_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(200);

const USAGE: &str = "usage: broker.py [-h] --socket SOCKET --state-file STATE_FILE\n                 [--config CONFIG]\n";

fn parser() -> Parser {
    Parser {
        prog: "broker.py",
        description: "Carry native sharingd AKS requests to an isolated keybag on the configured backend.",
        usage: USAGE,
        options: vec![
            Opt::value("--socket").required(),
            Opt::value("--state-file").required(),
            Opt::value("--config"),
            Opt::value("--certificate").suppressed(),
            Opt::flag("--renewed-certificate").suppressed(),
            Opt::flag("--parent-lifeline").suppressed(),
        ],
    }
}

/// Parsed `broker.py` arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerArgs {
    pub socket: PathBuf,
    pub state_file: PathBuf,
    pub config: Option<PathBuf>,
    pub certificate: Option<PathBuf>,
    pub renewed_certificate: bool,
    pub parent_lifeline: bool,
}

/// argparse of `broker.py`; `Err(status)` once help or an error was printed.
pub fn parse_args(args: &[String]) -> Result<BrokerArgs, i32> {
    let parsed = parser().parse(args)?;
    let path = |name: &str| parsed.value(name).map(|v| paths::normalize(Path::new(v)));
    Ok(BrokerArgs {
        socket: path("--socket").unwrap(),
        state_file: path("--state-file").unwrap(),
        config: parsed.value("--config").map(PathBuf::from),
        certificate: path("--certificate"),
        renewed_certificate: parsed.flag("--renewed-certificate"),
        parent_lifeline: parsed.flag("--parent-lifeline"),
    })
}

/// `Path.parent` (`.` for a bare name).
fn parent_of(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Entry point of the hidden `broker` subcommand; `args` are the arguments
/// after the subcommand (`sys.argv[1:]` of broker.py). Returns the exit status.
pub fn broker_main(args: Vec<String>) -> i32 {
    let arguments = match parse_args(&args) {
        Ok(arguments) => arguments,
        Err(status) => return status,
    };
    match run(&arguments) {
        Ok(()) => 0,
        Err(failure) => failure.report(),
    }
}

fn run(arguments: &BrokerArgs) -> Result<(), Failure> {
    let configuration = load_config(arguments.config.as_deref(), &default_root())
        .map_err(|e| Failure::raised("ConfigError", e.0))?;
    use std::os::unix::ffi::OsStrExt;
    if arguments.socket.as_os_str().as_bytes().len() >= 104 || arguments.socket.exists() {
        return Err(Failure::exit("Socket path is too long or already exists"));
    }
    let parent = parent_of(&arguments.socket);
    let info = sys::stat(&parent).map_err(|e| mirra_core::Error::with_path(e, &parent))?;
    if info.st_uid != sys::getuid() || info.st_mode & 0o077 != 0 {
        return Err(Failure::exit("Socket parent must be owned by this user with mode 0700"));
    }
    let source = arguments.certificate.clone().unwrap_or_else(|| configuration.certificate_file.clone());
    let certificate_bytes = std::fs::read(&source).map_err(|e| mirra_core::Error::with_path(e, &source))?;
    let (certificate_start, _certificate_end) = validity(&certificate_bytes)?;
    // A not-yet-valid certificate is a clock problem and is rejected. A
    // certificate that is only past its notAfter is tolerated: the attested-key
    // self-check (and the periodic health validate) is the authority on whether
    // the enclave still honors it, so an expired-but-attesting bridge keeps working.
    if util::now() < certificate_start {
        return Err(Failure::exit("Backend device certificate is not yet valid"));
    }
    let endpoint = Endpoint::open(&configuration, EndpointOptions {
        expected_certificate_sha256: Some(util::sha256_hex(&certificate_bytes)),
        saved: true,
        ..Default::default()
    })?;
    let stop = Event::new();
    let flag = stop.clone();
    crate::signals::on_termination(move || flag.set())?;
    if arguments.parent_lifeline {
        let flag = stop.clone();
        mirra_core::lifetime::watch_parent_pipe(0, move || flag.set());
    }
    let setup = BrokerSetup {
        socket: arguments.socket.clone(),
        state_file: arguments.state_file.clone(),
        certificate: certificate_bytes,
        certificate_argument: arguments.certificate.clone(),
        minimum_created_at: arguments.renewed_certificate.then_some(certificate_start),
    };
    serve(&setup, Arc::new(endpoint), &stop, stdout_events())
}

/// Everything `serve` needs once the bridge session is open.
#[derive(Clone, Debug)]
pub struct BrokerSetup {
    pub socket: PathBuf,
    pub state_file: PathBuf,
    /// The validated device certificate (DER).
    pub certificate: Vec<u8>,
    /// `--certificate`; the certificate is copied next to the socket unless
    /// it already is that file.
    pub certificate_argument: Option<PathBuf>,
    /// `--renewed-certificate`: only adopt keys created under the new certificate.
    pub minimum_created_at: Option<f64>,
}

struct Shared {
    broker: Mutex<AksBroker<Arc<dyn Backend>>>,
    token: String,
    emit: Emit,
}

/// Run the broker over an open session until `stop` is set: self-check,
/// publish the unix socket (0600), TCP port and private state file, then
/// serve requests. Expiry is tolerated (`certificate_expires_at=None`): the
/// periodic health check re-validates an attested key over the wire.
pub fn serve(setup: &BrokerSetup, endpoint: Arc<dyn Backend>, stop: &Event, emit: Emit) -> Result<(), Failure> {
    let mut broker = AksBroker::new(endpoint.clone(), None);
    let started = startup(&mut broker, setup, &emit);
    if let Err(error) = started {
        endpoint.close();
        return Err(error);
    }
    let result = listen(setup, broker, &endpoint, stop, emit);
    endpoint.close();
    result
}

fn startup(broker: &mut AksBroker<Arc<dyn Backend>>, setup: &BrokerSetup, emit: &Emit) -> Result<(), Failure> {
    let ready = broker.endpoint.ready().clone();
    if !truthy(ready.get("dcrt_bytes")) {
        return Err(Failure::runtime("Backend endpoint has no device certificate"));
    }
    let restored = broker.restore(setup.minimum_created_at)?;
    let kept = ready.get("kept_sessions");
    broker.can_resume_pairing = restored > 0 && util::int_of(kept).is_some_and(|k| k > 0);
    emit(&json!({"saved_mac": truthy(ready.get("client_saved")), "restored_identities": restored,
        "restore_failures": ready.get("restore_failures").cloned().unwrap_or(json!(0)),
        "kept_sessions": ready.get("kept_sessions").cloned().unwrap_or(json!(0))}));
    let generated = broker.execute(json!({"operation": "generate", "key_class": 9}).as_object().unwrap())?;
    if !util::py_eq_int(generated.get("status"), 0) {
        let detail = generated.get("status_hex").or(generated.get("error"));
        return Err(Failure::runtime(format!("Backend cannot create an attested signing key: {}", util::py_str(detail))));
    }
    let request = json!({"operation": "validate", "local_ltk": generated.get("data").cloned().unwrap_or(Value::Null)});
    let validated = broker.execute(request.as_object().unwrap())?;
    if !util::py_eq_int(validated.get("status"), 0) {
        return Err(Failure::runtime("Backend could not validate its fresh attested key"));
    }
    Ok(())
}

fn listen(setup: &BrokerSetup, broker: AksBroker<Arc<dyn Backend>>, endpoint: &Arc<dyn Backend>, stop: &Event, emit: Emit)
    -> Result<(), Failure> {
    let unix = UnixListener::bind(&setup.socket).map_err(|e| mirra_core::Error::with_path(e, &setup.socket))?;
    let cleanup = SocketFile(setup.socket.clone());
    util::chmod(&setup.socket, 0o600)?;
    let tcp = TcpListener::bind(("127.0.0.1", 0))?;
    let port = tcp.local_addr()?.port();
    let directory = parent_of(&setup.socket);
    let certificate = directory.join("certificate.der");
    if setup.certificate_argument.as_deref().map(paths::normalize) != Some(paths::normalize(&certificate)) {
        std::fs::write(&certificate, &setup.certificate).map_err(|e| mirra_core::Error::with_path(e, &certificate))?;
        util::chmod(&certificate, 0o600)?;
    }
    let token = util::token_hex(32);
    let state = json!({"pid": std::process::id(), "socket": text(&setup.socket), "directory": text(&directory),
        "tcp_port": port, "auth_token": token, "certificate": text(&certificate)});
    let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600)
        .open(&setup.state_file).map_err(|e| mirra_core::Error::with_path(e, &setup.state_file))?;
    file.write_all(format!("{}\n", pyjson::dumps(&state)).as_bytes())?;
    drop(file);
    util::chmod(&setup.state_file, 0o600)?;
    let shared = Arc::new(Shared { broker: Mutex::new(broker), token, emit: emit.clone() });
    let tcp_thread = {
        let (shared, stop) = (shared.clone(), stop.clone());
        std::thread::Builder::new().name("broker-tcp".into()).spawn(move || {
            accept_loop(tcp.as_raw_fd(), &stop, || tcp.accept().map(|(s, _)| s), move |stream| serve_tcp(stream, &shared))
        })?
    };
    emit(&json!({"ready": true, "socket": text(&setup.socket), "tcp_port": port,
        "dcrt_bytes": endpoint.ready().get("dcrt_bytes").cloned().unwrap_or(Value::Null), "attested_key_validated": true,
        "certificate_binding_verified": endpoint.certificate_binding_verified()}));
    {
        let shared = shared.clone();
        accept_loop(unix.as_raw_fd(), stop, || unix.accept().map(|(s, _)| s), move |stream| serve_unix(stream, &shared));
    }
    stop.set();
    let _ = tcp_thread.join();
    drop(unix);
    drop(cleanup);
    Ok(())
}

/// Unlinks the socket path when the server ends (`unlink(missing_ok=True)`).
struct SocketFile(PathBuf);

impl Drop for SocketFile {
    fn drop(&mut self) {
        let _ = util::unlink_missing_ok(&self.0);
    }
}

/// `serve_forever(poll_interval=0.2)`: accept until `stop`, one thread per
/// connection.
fn accept_loop<S, A, H>(fd: RawFd, stop: &Event, accept: A, handler: H)
where
    S: Send + 'static,
    A: Fn() -> std::io::Result<S>,
    H: Fn(S) + Send + Sync + Clone + 'static,
{
    while !stop.is_set() {
        let mut entry = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        let ready = unsafe { libc::poll(&mut entry, 1, POLL_INTERVAL.as_millis() as i32) };
        if ready <= 0 {
            continue;
        }
        if let Ok(stream) = accept() {
            let handler = handler.clone();
            let _ = std::thread::Builder::new().name("broker-request".into()).spawn(move || handler(stream));
        }
    }
}

fn serve_unix(stream: std::os::unix::net::UnixStream, shared: &Shared) {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 || uid != sys::getuid() {
        return;
    }
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(SOCKET_TIMEOUT));
    let _ = stream.set_write_timeout(Some(SOCKET_TIMEOUT));
    handle(&stream, true, shared);
    let _ = stream.shutdown(Shutdown::Write);
}

fn serve_tcp(stream: std::net::TcpStream, shared: &Shared) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(SOCKET_TIMEOUT));
    let _ = stream.set_write_timeout(Some(SOCKET_TIMEOUT));
    handle(&stream, false, shared);
    let _ = stream.shutdown(Shutdown::Write);
}

/// A handler exception, as broker.py prints it (`Type: message`).
enum Raised {
    Failure(Failure),
    Endpoint(Failure, Map<String, Value>),
}

fn io_failure(error: std::io::Error) -> Raised {
    match error.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => Raised::Failure(Failure::raised("TimeoutError", "timed out")),
        _ => Raised::Failure(mirra_core::Error::Os(error).into()),
    }
}

fn read_exact<S: Read>(mut stream: S, count: usize) -> Result<Vec<u8>, Raised> {
    let mut data = vec![0u8; count];
    let mut filled = 0;
    while filled < count {
        match stream.read(&mut data[filled..]) {
            Ok(0) => return Err(Raised::Failure(Failure::raised("ConnectionError", "client closed"))),
            Ok(n) => filled += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(io_failure(e)),
        }
    }
    Ok(data)
}

/// `secrets.compare_digest(str(value), token)`.
fn authorized(value: Option<Value>, token: &str) -> Result<bool, Raised> {
    let given = match value {
        None => String::new(),
        Some(value) => util::py_str(Some(&value)),
    };
    if !given.is_ascii() {
        return Err(Raised::Failure(Failure::raised("TypeError", "comparing strings with non-ASCII characters is not supported")));
    }
    let (a, b) = (given.as_bytes(), token.as_bytes());
    let mut difference = a.len() ^ b.len();
    for (index, byte) in b.iter().enumerate() {
        difference |= usize::from(a.get(index).copied().unwrap_or(0) ^ byte);
    }
    Ok(difference == 0)
}

fn handle<S>(stream: S, unix: bool, shared: &Shared)
where
    S: Read + Write + Copy,
{
    let outcome = (|| -> Result<(), Raised> {
        let size = u32::from_be_bytes(read_exact(stream, 4)?.try_into().unwrap());
        if size > MAX_REQUEST {
            return Ok(());
        }
        let raw = read_exact(stream, size as usize)?;
        let request: Value = serde_json::from_slice(&raw)
            .map_err(|e| Raised::Failure(Failure::raised("JSONDecodeError", e.to_string())))?;
        let Value::Object(mut request) = request else { return Ok(()) };
        if !unix && !authorized(request.shift_remove("_auth"), &shared.token)? {
            return Ok(());
        }
        let response = {
            let mut broker = shared.broker.lock().unwrap_or_else(|e| e.into_inner());
            broker.execute(&request)
        };
        let response = response.map_err(|error| match error.as_endpoint() {
            Some(endpoint) => Raised::Endpoint(Failure::from(mirra_bridge::Error::Endpoint(endpoint.clone())),
                transport_details(endpoint)),
            None => Raised::Failure(error.into()),
        })?;
        let data = pyjson::dumps(&Value::Object(response.clone()));
        let mut frame = (data.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(data.as_bytes());
        let mut writer = stream;
        writer.write_all(&frame).map_err(io_failure)?;
        let mut event = json!({"operation": request.get("operation").cloned().unwrap_or(Value::Null),
            "status": response.get("status_hex").or(response.get("status")).cloned().unwrap_or(Value::Null),
            "bytes": response.get("bytes").cloned().unwrap_or(Value::Null),
            "error": response.get("error").cloned().unwrap_or(Value::Null)});
        if let Some(details) = response.get("transport_failure").filter(|d| truthy(Some(d))) {
            event["transport_failure"] = details.clone();
        }
        (shared.emit)(&event);
        Ok(())
    })();
    let report = |failure: &Failure| match failure {
        Failure::Raised { type_name, message } => format!("{}: {}", type_name, message),
        Failure::Exit(message) => message.clone(),
    };
    match outcome {
        Ok(()) => {}
        Err(Raised::Failure(failure)) => (shared.emit)(&json!({"transport_error": report(&failure)})),
        Err(Raised::Endpoint(failure, details)) => {
            (shared.emit)(&json!({"transport_error": report(&failure), "transport_failure": details}))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
