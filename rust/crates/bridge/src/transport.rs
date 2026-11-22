//! Bounded JSON transport to one authenticated, stateful bridge session
//! (port of `scripts/transport.py`).
//!
//! The session is one WebSocket on the phone's bridge service, carried by
//! TLS-PSK (see [`crate::bridgeclient`]). Closing it releases every keybag and
//! native session the bridge created for it, so a new connection never
//! inherits state.
use std::net::Shutdown;
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use mirra_core::activity;
use mirra_core::config::Config;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::bridgeclient::{read_token, session_path, RawSocket, WebSocket};
use crate::error::{EndpointError, Error, Result};
use crate::keystore::bridge_capabilities;
use crate::pyutil;
use crate::wire::hex;

pub const MAX_REPLY: usize = 262144;
pub const PROTOCOL_VERSION: i64 = 2;
pub const TRANSPORT_ERRORS: [&str; 8] = ["endpoint_reply_timeout", "endpoint_write_timeout", "endpoint_eof",
    "endpoint_disconnected", "endpoint_unavailable", "endpoint_invalid_reply", "endpoint_reply_too_large",
    "endpoint_io_error"];
pub const ENDPOINT_OPERATIONS: [&str; 13] = ["generate", "validate", "sign_remote", "session_signed", "step",
    "token", "confirm", "setup", "reset", "get_state", "drop", "exit", "forget"];
pub const GREETING_ERRORS: [&str; 3] = ["required_keystore_symbols_unavailable", "keystore_library_unavailable",
    "device_certificate_unavailable"];
pub const CONNECTION_ERRORS: [&str; 6] = ["bridge_pairing_missing", "bridge_tls_unavailable", "bridge_unreachable",
    "bridge_refused", "bridge_token_rejected", "bridge_session_limit"];

/// `transport_details(error)`: select failure facts without copying
/// messages or request data.
pub fn transport_details(error: &EndpointError) -> Map<String, Value> {
    let mut selected = Map::new();
    let code = error.code().filter(|c| TRANSPORT_ERRORS.contains(c)).unwrap_or("endpoint_error");
    selected.insert("code".into(), Value::from(code));
    for name in ["reply_bytes", "request_bytes"] {
        if pyutil::is_int(error.details.get(name)) {
            selected.insert(name.into(), error.details[name].clone());
        }
    }
    if let Some(Value::String(stage)) = error.details.get("stage") {
        if stage == "write" || stage == "reply" {
            selected.insert("stage".into(), Value::from(stage.clone()));
        }
    }
    if let Some(Value::String(operation)) = error.details.get("operation") {
        if ENDPOINT_OPERATIONS.contains(&operation.as_str()) {
            selected.insert("operation".into(), Value::from(operation.clone()));
        }
    }
    selected
}

/// Keyword arguments of `Endpoint(config, ...)`.
#[derive(Clone, Debug, Default)]
pub struct EndpointOptions {
    /// Per-request timeout; `config.timeout` seconds when `None`.
    pub timeout: Option<Duration>,
    /// Required `dcrt_sha256`; the sha256 of `config.certificate_file` when `None`.
    pub expected_certificate_sha256: Option<String>,
    /// Pairing token; read from `config.token_file` when `None` or empty.
    pub token: Option<String>,
    /// Ask the bridge to keep this Mac's keys (the runtime broker only;
    /// setup and diagnostics use throwaway keys).
    pub saved: bool,
}

struct State {
    failed: bool,
    failure: Option<EndpointError>,
    closing: bool,
    closed: bool,
    timeout: Duration,
}

/// One bridge session. Calls are serialized; [`Endpoint::poll`] and
/// [`Endpoint::close`] may run from other threads.
pub struct Endpoint {
    socket: Mutex<Option<WebSocket>>,
    interrupt: Mutex<Option<RawSocket>>,
    state: Mutex<State>,
    /// The bridge greeting.
    pub ready: Map<String, Value>,
    pub certificate_binding_verified: bool,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

fn error(message: &str, code: &str, details: Value) -> EndpointError {
    let details = match details {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    EndpointError::new(message, Some(code), details)
}

impl Endpoint {
    /// `Endpoint(config, timeout=, expected_certificate_sha256=, token=, saved=)`
    pub fn open(config: &Config, options: EndpointOptions) -> Result<Endpoint> {
        let timeout = options.timeout.unwrap_or(Duration::from_secs(config.timeout));
        let mut endpoint = Endpoint {
            socket: Mutex::new(None),
            interrupt: Mutex::new(None),
            state: Mutex::new(State { failed: false, failure: None, closing: false, closed: false, timeout }),
            ready: Map::new(),
            certificate_binding_verified: false,
        };
        match endpoint.start(config, options, timeout) {
            Ok(()) => Ok(endpoint),
            Err(failure) => {
                activity::emit("Endpoint", "startup failed", "error",
                    json!({"error_type": failure.type_name(), "error": failure.to_string()}));
                lock(&endpoint.state).failed = true;
                endpoint.close();
                Err(failure)
            }
        }
    }

    fn start(&mut self, config: &Config, options: EndpointOptions, timeout: Duration) -> Result<()> {
        let token = match options.token.filter(|t| !t.is_empty()) {
            Some(token) => token,
            None => read_token(&config.token_file)?,
        };
        activity::emit("Endpoint", "connecting", "info", json!({"transport": config.transport, "port": config.service_port}));
        let socket = WebSocket::open(config, &token, &session_path(options.saved), timeout).map_err(|e| match e {
            Error::Bridge(bridge) => {
                let code = if CONNECTION_ERRORS.contains(&bridge.code.as_str()) { bridge.code.as_str() } else { "endpoint_unavailable" };
                Error::Endpoint(EndpointError::coded(bridge.message.clone(), code))
            }
            other => other,
        })?;
        *lock(&self.interrupt) = socket.raw_socket().try_clone().ok();
        let socket = self.socket.get_mut().unwrap_or_else(|e| e.into_inner()).insert(socket);
        let ready = read_from(socket, Instant::now() + timeout)?;
        self.ready = ready;
        activity::emit("Endpoint", "greeting", "info", json!({"reply": self.ready}));
        if self.ready.get("ready") != Some(&Value::Bool(true)) {
            let code = self.ready.get("error").and_then(Value::as_str).filter(|c| GREETING_ERRORS.contains(c));
            let mut details = Map::new();
            details.insert("capabilities".into(), Value::Object(bridge_capabilities(&self.ready)));
            return Err(EndpointError::new("Bridge service did not report ready", code, details).into());
        }
        if !pyutil::equals_number(self.ready.get("protocol_version"), PROTOCOL_VERSION) {
            return Err(EndpointError::message("Unsupported bridge protocol version; reinstall the bridge service").into());
        }
        let expected = match options.expected_certificate_sha256 {
            Some(expected) => expected,
            None => {
                let data = std::fs::read(&config.certificate_file)
                    .map_err(|e| mirra_core::Error::with_path(e, &config.certificate_file))?;
                hex(&Sha256::digest(&data))
            }
        };
        if self.ready.get("dcrt_sha256") != Some(&Value::String(expected)) {
            return Err(EndpointError::message("Local and bridge device certificates do not match").into());
        }
        self.certificate_binding_verified = true;
        Ok(())
    }

    /// `timeout` (lowered to at most 2 s once closing).
    pub fn timeout(&self) -> Duration {
        lock(&self.state).timeout
    }

    /// `failure`: the first failure that poisoned this session.
    pub fn failure(&self) -> Option<EndpointError> {
        lock(&self.state).failure.clone()
    }

    /// `poll()`: `None` while the session is connected; `Some(0)` once the
    /// bridge has closed it.
    pub fn poll(&self) -> Option<i32> {
        match self.socket.try_lock() {
            // A request is in flight; its own result reports failures.
            Err(TryLockError::WouldBlock) => None,
            Ok(mut guard) => Self::poll_socket(&mut guard),
            Err(TryLockError::Poisoned(poisoned)) => Self::poll_socket(&mut poisoned.into_inner()),
        }
    }

    fn poll_socket(socket: &mut Option<WebSocket>) -> Option<i32> {
        match socket.as_mut() {
            None => Some(0),
            Some(socket) => socket.disconnected().then_some(0),
        }
    }

    /// `call(operation, **fields)`; `fields` is a JSON object (or null).
    pub fn call(&self, operation: &str, fields: Value) -> Result<Map<String, Value>> {
        self.call_with_deadline(operation, fields, None)
    }

    /// `call(operation, _deadline=deadline, **fields)`
    pub fn call_with_deadline(&self, operation: &str, fields: Value, deadline: Option<Instant>) -> Result<Map<String, Value>> {
        let mut socket = lock(&self.socket);
        self.call_locked(&mut socket, operation, fields, deadline)
    }

    fn call_locked(&self, socket: &mut Option<WebSocket>, operation: &str, fields: Value, limit: Option<Instant>)
        -> Result<Map<String, Value>> {
        let timeout = {
            let state = lock(&self.state);
            if state.failed || (state.closing && operation != "exit") || socket.is_none() {
                return Err(error("Bridge session is unavailable; start a new session", "endpoint_unavailable", Value::Null).into());
            }
            state.timeout
        };
        let socket = socket.as_mut().unwrap();
        if socket.is_closed() {
            let failure = error("Bridge session is unavailable; start a new session", "endpoint_disconnected", Value::Null);
            lock(&self.state).failure.get_or_insert_with(|| failure.clone());
            return Err(failure.into());
        }
        let fields = match fields {
            Value::Object(map) => map,
            _ => Map::new(),
        };
        let mut request = Map::new();
        request.insert("operation".into(), Value::from(operation));
        for (k, v) in &fields {
            request.insert(k.clone(), v.clone());
        }
        let payload = mirra_core::pyjson::dumps(&Value::Object(request)).into_bytes();
        activity::emit("Endpoint", "request", "info",
            json!({"operation": operation, "parameters": fields, "request_bytes": payload.len()}));
        if payload.len() > MAX_REPLY {
            return Err(Error::value("Bridge request exceeds the size limit"));
        }
        let mut deadline = Instant::now() + timeout;
        if let Some(limit) = limit {
            deadline = deadline.min(limit);
        }
        let mut stage = "write";
        let result = match socket.send_text(&payload, deadline) {
            Err(Error::Bridge(b)) if b.is_timeout() => Err(Error::Endpoint(error("Bridge request timed out",
                "endpoint_write_timeout", json!({"request_bytes": payload.len()})))),
            Err(e) => Err(e),
            Ok(()) => {
                stage = "reply";
                read_from(socket, deadline)
            }
        };
        match result {
            Ok(reply) => Ok(reply),
            Err(e) if !(e.is_os_error() || e.is_value_error() || e.as_endpoint().is_some()) => Err(e),
            Err(e) => {
                // A delayed reply can no longer be matched to a future request.
                // Replacing the connection would also lose all keybag state.
                let mut failure = match e.as_endpoint() {
                    Some(endpoint) => EndpointError::new(endpoint.message.clone(), endpoint.code(), endpoint.details.clone()),
                    None => error("Bridge transport I/O failed; start a new session", "endpoint_io_error", json!({"stage": stage})),
                };
                if ENDPOINT_OPERATIONS.contains(&operation) {
                    failure.details.insert("operation".into(), Value::from(operation));
                }
                let mut state = lock(&self.state);
                state.failed = true;
                state.failure.get_or_insert_with(|| failure.clone());
                Err(failure.into())
            }
        }
    }

    /// `close()`: send `exit` when the session is healthy, then close the
    /// WebSocket. A request blocked on a stalled bridge is interrupted
    /// instead of delaying shutdown.
    pub fn close(&self) {
        {
            let mut state = lock(&self.state);
            if state.closed {
                return;
            }
            state.closing = true;
        }
        let mut socket = match self.socket.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                lock(&self.state).failed = true;
                if let Some(raw) = lock(&self.interrupt).as_ref() {
                    let _ = raw.shutdown(Shutdown::Both);
                }
                lock(&self.socket)
            }
        };
        let failed = {
            let mut state = lock(&self.state);
            state.timeout = state.timeout.min(Duration::from_secs(2));
            state.failed
        };
        if socket.is_some() {
            if !failed && !socket.as_ref().unwrap().is_closed() {
                let _ = self.call_locked(&mut socket, "exit", Value::Null, None);
            }
            socket.as_mut().unwrap().close(None);
        }
        lock(&self.interrupt).take();
        lock(&self.state).closed = true;
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.close();
    }
}

/// `Endpoint.read(deadline=)`: one bounded JSON object.
fn read_from(socket: &mut WebSocket, deadline: Instant) -> Result<Map<String, Value>> {
    let raw = match socket.receive(deadline) {
        Ok(raw) => raw,
        Err(Error::Bridge(b)) if b.is_timeout() => {
            return Err(error("Bridge reply timed out; restart the Mirroring session", "endpoint_reply_timeout", Value::Null).into());
        }
        Err(Error::Bridge(b)) if b.is_closed() => {
            return Err(error("Bridge connection closed; check the phone’s network and jailbreak", "endpoint_eof", Value::Null).into());
        }
        Err(Error::Bridge(b)) => {
            let code = if b.code == "bridge_message_too_large" { "endpoint_reply_too_large" } else { "endpoint_invalid_reply" };
            return Err(error(&b.message, code, Value::Null).into());
        }
        Err(other) => return Err(other),
    };
    if raw.len() > MAX_REPLY {
        return Err(error("Bridge reply exceeds the size limit", "endpoint_reply_too_large", json!({"reply_bytes": raw.len()})).into());
    }
    let result = match serde_json::from_slice::<Value>(&raw) {
        Ok(Value::Object(map)) => map,
        Ok(_) => return Err(error("Bridge reply must be an object", "endpoint_invalid_reply", json!({"reply_bytes": raw.len()})).into()),
        Err(_) => return Err(error("Bridge returned invalid JSON", "endpoint_invalid_reply", json!({"reply_bytes": raw.len()})).into()),
    };
    activity::emit("Endpoint", "reply", "info", json!({"reply": result}));
    Ok(result)
}

#[cfg(test)]
mod tests;
