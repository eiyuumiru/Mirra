//! Own backend identities and translate only this broker's session handles
//! (port of `scripts/keystore.py`).
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use mirra_bridge::transport::{transport_details, Endpoint};
use mirra_bridge::wire::platform_ltk;
use mirra_bridge::{EndpointError, Error, Result};
use serde_json::{json, Map, Value};

pub use mirra_bridge::keystore::bridge_capabilities;

use crate::util::{int_of, py_eq_int, truthy};

pub const SESSION_BASE: i64 = 0x6F000000;
pub const SESSION_END: i64 = 0x70000000;
/// The endpoint's isolated-session limit.
pub const MAX_SESSIONS: usize = 16;
/// Leave room inside the shim's 15-second socket timeout.
pub const MAX_RESET_SECONDS: u64 = 10;
/// kIOReturnNoMemory (0xe00002bd)
pub const NO_MEMORY: i64 = -536870211;
/// kIOReturnError (0xe00002bc); `UNAVAIWORKSPACELE` in keystore.py.
pub const UNAVAILABLE: i64 = -536870212;
/// Low flag bits of unlock sessions; others pair.
pub const UNLOCK_SESSION_KINDS: [i128; 3] = [2, 8, 12];

const OPERATION_STAGES: [&str; 9] = ["SecRandomCopyBytes", "aks_create_bag", "aks_create_signing_key",
    "aks_params_create", "aks_params_set_data", "aks_params_set_number", "aks_params_get_der",
    "aks_create_signing_key_with_params", "aks_validate_local_key"];

/// The bridge session the broker drives (`transport.Endpoint`'s interface).
pub trait Backend: Send + Sync {
    /// The bridge greeting (`endpoint.ready`).
    fn ready(&self) -> &Map<String, Value>;
    /// `endpoint.timeout`
    fn timeout(&self) -> Duration;
    /// `endpoint.call(operation, _deadline=deadline, **fields)`
    fn call(&self, operation: &str, fields: Value, deadline: Option<Instant>) -> Result<Map<String, Value>>;
    /// `endpoint.failure`: the first error that abandoned the command stream.
    fn failure(&self) -> Option<EndpointError> {
        None
    }
    /// `endpoint.poll()`: `None` while connected.
    fn poll(&self) -> Option<i32> {
        None
    }
    fn certificate_binding_verified(&self) -> bool {
        false
    }
    fn close(&self) {}
}

impl Backend for Endpoint {
    fn ready(&self) -> &Map<String, Value> {
        &self.ready
    }
    fn timeout(&self) -> Duration {
        Endpoint::timeout(self)
    }
    fn call(&self, operation: &str, fields: Value, deadline: Option<Instant>) -> Result<Map<String, Value>> {
        self.call_with_deadline(operation, fields, deadline)
    }
    fn failure(&self) -> Option<EndpointError> {
        Endpoint::failure(self)
    }
    fn poll(&self) -> Option<i32> {
        Endpoint::poll(self)
    }
    fn certificate_binding_verified(&self) -> bool {
        self.certificate_binding_verified
    }
    fn close(&self) {
        Endpoint::close(self)
    }
}

impl<T: Backend + ?Sized> Backend for Arc<T> {
    fn ready(&self) -> &Map<String, Value> {
        (**self).ready()
    }
    fn timeout(&self) -> Duration {
        (**self).timeout()
    }
    fn call(&self, operation: &str, fields: Value, deadline: Option<Instant>) -> Result<Map<String, Value>> {
        (**self).call(operation, fields, deadline)
    }
    fn failure(&self) -> Option<EndpointError> {
        (**self).failure()
    }
    fn poll(&self) -> Option<i32> {
        (**self).poll()
    }
    fn certificate_binding_verified(&self) -> bool {
        (**self).certificate_binding_verified()
    }
    fn close(&self) {
        (**self).close()
    }
}

/// Preserve native status and stage; never copy an identity or key blob.
pub fn operation_details(report: &Map<String, Value>) -> Map<String, Value> {
    let mut selected = Map::new();
    if let Some(status) = int_of(report.get("status")) {
        selected.insert("status".into(), report["status"].clone());
        selected.insert("status_hex".into(), Value::from(format!("0x{:08x}", (status & 0xffffffff) as u64)));
    }
    if let Some(Value::String(stage)) = report.get("operation_stage") {
        if OPERATION_STAGES.contains(&stage.as_str()) {
            selected.insert("operation_stage".into(), Value::from(stage.clone()));
        }
    }
    selected
}

fn nonempty_string(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::String(s)) if !s.is_empty())
}

pub fn valid_generated_key(report: &Map<String, Value>) -> bool {
    int_of(report.get("status")) == Some(0) && !truthy(report.get("error"))
        && nonempty_string(report.get("identity")) && nonempty_string(report.get("ltk"))
}

fn merged(head: Value, tail: Map<String, Value>) -> Map<String, Value> {
    let mut details = match head {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    details.extend(tail);
    details
}

/// Validate one isolated key with the same checks during setup and diagnosis;
/// returns the wire-layout proof.
pub fn verify_attested_key(endpoint: &dyn Backend) -> Result<Value> {
    let capabilities = Value::Object(bridge_capabilities(endpoint.ready()));
    let generated = endpoint.call("generate", json!({"attested": true, "key_class": 9}), None)?;
    if !valid_generated_key(&generated) {
        let details = merged(json!({"operation": "generate", "capabilities": capabilities}), operation_details(&generated));
        return Err(EndpointError::new("The bridge cannot create the required attested key",
            Some("bridge_attested_key_unavailable"), details).into());
    }
    let validated = endpoint.call("validate", json!({"identity": generated["identity"]}), None)?;
    if int_of(validated.get("status")) != Some(0) || truthy(validated.get("error")) {
        let details = merged(json!({"operation": "validate", "capabilities": capabilities}), operation_details(&validated));
        return Err(EndpointError::new("The bridge rejected its fresh attested key",
            Some("bridge_attested_key_rejected"), details).into());
    }
    match platform_ltk(generated["ltk"].as_str().unwrap_or(""), 3) {
        Ok((_, proof)) => Ok(proof),
        Err(error) => {
            let details = merged(json!({"operation": "wire_layout", "capabilities": capabilities}), Map::new());
            Err(EndpointError::new(error.to_string(), Some("bridge_key_layout_unsupported"), details).into())
        }
    }
}

/// A small insertion-ordered map (Python dict order matters for sessions
/// and for the first class used by health validation).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Ordered<K, V>(pub Vec<(K, V)>);

impl<K: PartialEq + Copy, V> Ordered<K, V> {
    pub fn get(&self, key: K) -> Option<&V> {
        self.0.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }
    pub fn contains(&self, key: K) -> bool {
        self.get(key).is_some()
    }
    pub fn insert(&mut self, key: K, value: V) {
        match self.0.iter_mut().find(|(k, _)| *k == key) {
            Some(entry) => entry.1 = value,
            None => self.0.push((key, value)),
        }
    }
    pub fn remove(&mut self, key: K) -> Option<V> {
        let index = self.0.iter().position(|(k, _)| *k == key)?;
        Some(self.0.remove(index).1)
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn clear(&mut self) {
        self.0.clear()
    }
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.0.iter().map(|(_, v)| v)
    }
}

impl<K, V> FromIterator<(K, V)> for Ordered<K, V> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        Ordered(iter.into_iter().collect())
    }
}

/// Calls are serialized by the socket server, including health and cleanup.
pub struct AksBroker<B: Backend> {
    pub endpoint: B,
    pub certificate_expires_at: Option<f64>,
    pub can_resume_pairing: bool,
    /// Wire or bridge LTK (base64) → bridge identity.
    pub identities: HashMap<String, String>,
    /// key class → generated record (`status`, `identity`, `ltk`, ...).
    pub classes: Ordered<i64, Map<String, Value>>,
    /// virtual handle → real bridge handle.
    pub sessions: Ordered<i64, i128>,
    pub session_flags: HashMap<i64, i128>,
    pub counter: i64,
    pub wire_keys: HashMap<i64, String>,
    pub failure: Option<String>,
    pub transport_failure: Option<Map<String, Value>>,
}

fn status_reply(status: i64, error: &str) -> Map<String, Value> {
    let mut reply = Map::new();
    reply.insert("status".into(), Value::from(status));
    reply.insert("error".into(), Value::from(error));
    reply
}

fn error_reply(error: &str) -> Map<String, Value> {
    let mut reply = Map::new();
    reply.insert("error".into(), Value::from(error));
    reply
}

fn key_class_of(value: Option<&Value>) -> Option<i64> {
    int_of(value).filter(|c| [9, 10, 11].contains(c)).map(|c| c as i64)
}

impl<B: Backend> AksBroker<B> {
    pub fn new(endpoint: B, certificate_expires_at: Option<f64>) -> Self {
        AksBroker { endpoint, certificate_expires_at, can_resume_pairing: false, identities: HashMap::new(),
            classes: Ordered::default(), sessions: Ordered::default(), session_flags: HashMap::new(), counter: 0,
            wire_keys: HashMap::new(), failure: None, transport_failure: None }
    }

    /// Adopt the keys this Mac saved on the bridge.
    ///
    /// sharingd keeps its iPhone Mirroring pairing with these keys, so
    /// recognizing them again avoids pairing anew after a restart.
    pub fn restore(&mut self, minimum_created_at: Option<f64>) -> Result<usize> {
        let ready = self.endpoint.ready();
        if !truthy(ready.get("client_saved")) || !truthy(ready.get("restored_identities")) {
            return Ok(0);
        }
        let response = self.endpoint.call("identities", Value::Null, None)?;
        let entries = match (py_eq_int(response.get("status"), 0), response.get("identities")) {
            (true, Some(Value::Array(entries))) => entries,
            _ => return Ok(0),
        };
        let mut ordered: Vec<&Map<String, Value>> = entries.iter().filter_map(Value::as_object).collect();
        ordered.sort_by_key(|entry| int_of(entry.get("created")).unwrap_or(0));
        let mut restored = 0;
        for entry in ordered {
            if let Some(minimum) = minimum_created_at {
                match int_of(entry.get("created")) {
                    Some(created) if (created as f64) >= minimum => {}
                    _ => continue,
                }
            }
            let Some(key_class) = key_class_of(entry.get("key_class")) else { continue };
            let mut record = Map::new();
            record.insert("status".into(), Value::from(0));
            record.insert("identity".into(), entry.get("identity").cloned().unwrap_or(Value::Null));
            record.insert("ltk".into(), entry.get("ltk").cloned().unwrap_or(Value::Null));
            record.insert("key_class".into(), Value::from(key_class));
            if !valid_generated_key(&record) {
                continue;
            }
            let ltk = record["ltk"].as_str().unwrap_or("").to_string();
            let identity = record["identity"].as_str().unwrap_or("").to_string();
            let Ok((wire, _proof)) = platform_ltk(&ltk, 3) else { continue };
            // The newest key of each class answers later generate requests.
            self.classes.insert(key_class, record);
            self.wire_keys.insert(key_class, wire.clone());
            self.identities.insert(wire, identity.clone());
            self.identities.insert(ltk, identity);
            restored += 1;
        }
        Ok(restored)
    }

    /// `Err` only for a non-endpoint failure, which Python lets escape.
    pub fn reset_owned_sessions(&mut self) -> Result<Map<String, Value>> {
        // One client request, one overall endpoint timeout, at most 16 actual
        // handles. Never guess handles or reset the phone's system keybags.
        let deadline = Instant::now() + self.endpoint.timeout().min(Duration::from_secs(MAX_RESET_SECONDS));
        let mut first_error: i128 = 0;
        let mut count = 0;
        for (virtual_handle, real) in self.sessions.0.clone() {
            // A pairing session holds the iPhone's paired peer on the bridge;
            // resetting it makes the iPhone ignore unlocks until it pairs again.
            if let Some(flags) = self.session_flags.get(&virtual_handle) {
                if !UNLOCK_SESSION_KINDS.contains(&(flags & 0x3f)) {
                    continue;
                }
            }
            let response = match self.endpoint.call("reset", json!({"session": number(real), "data": ""}), Some(deadline)) {
                Ok(response) => response,
                Err(Error::Endpoint(error)) | Err(Error::RemoteSetup(error)) => {
                    self.failure.get_or_insert_with(|| "owned_session_reset_transport_failed".into());
                    let details = self.transport_failure.get_or_insert_with(|| transport_details(&error)).clone();
                    let mut reply = status_reply(UNAVAILABLE, "owned_session_reset_transport_failed");
                    reply.insert("reset_count".into(), Value::from(count));
                    reply.insert("remaining_sessions".into(), Value::from(self.sessions.len()));
                    reply.insert("transport_failure".into(), Value::Object(details));
                    return Ok(reply);
                }
                Err(other) => return Err(other),
            };
            let status = int_of(response.get("status").or(Some(&Value::from(UNAVAILABLE)))).unwrap_or(UNAVAILABLE as i128);
            if status == 0 || response.get("error").and_then(Value::as_str) == Some("session_not_owned") {
                self.sessions.remove(virtual_handle);
                self.session_flags.remove(&virtual_handle);
                count += 1;
            } else if first_error == 0 {
                first_error = status;
            }
        }
        if first_error != 0 {
            self.failure.get_or_insert_with(|| "owned_session_reset_failed".into());
        }
        let mut reply = Map::new();
        reply.insert("status".into(), number(first_error));
        reply.insert("reset_count".into(), Value::from(count));
        reply.insert("remaining_sessions".into(), Value::from(self.sessions.len()));
        Ok(reply)
    }

    fn health(&mut self) -> Result<Map<String, Value>> {
        if let Some(first_error) = self.endpoint.failure() {
            self.failure.get_or_insert_with(|| "endpoint_transport_failed".into());
            self.transport_failure.get_or_insert_with(|| transport_details(&first_error));
        }
        if self.endpoint.poll().is_some() {
            self.failure.get_or_insert_with(|| "endpoint_disconnected".into());
            self.transport_failure.get_or_insert_with(|| {
                let mut details = Map::new();
                details.insert("code".into(), Value::from("endpoint_disconnected"));
                details
            });
        }
        let mut alive = self.failure.is_none();
        if alive {
            if let Some(record) = self.classes.values().next() {
                let identity = record.get("identity").cloned().unwrap_or(Value::Null);
                match self.endpoint.call("validate", json!({"identity": identity}), None) {
                    Ok(reply) => {
                        if int_of(reply.get("status")) != Some(0) {
                            self.failure = Some("identity_validation_failed".into());
                        }
                    }
                    Err(Error::Endpoint(error)) | Err(Error::RemoteSetup(error)) => {
                        // The transport has abandoned this command stream. Report a
                        // confirmed failure, instead of dropping the health reply.
                        self.failure = Some("endpoint_transport_failed".into());
                        self.transport_failure = Some(transport_details(&error));
                    }
                    Err(other) => return Err(other),
                }
                alive = self.failure.is_none();
            }
        }
        let mut response = Map::new();
        response.insert("ready".into(), Value::Bool(alive));
        response.insert("identities".into(), Value::from(self.identities.len()));
        response.insert("sessions".into(), Value::from(self.sessions.len()));
        response.insert("capabilities".into(), json!(["reset_owned_sessions"]));
        response.insert("can_resume_pairing".into(), Value::Bool(self.can_resume_pairing));
        if let Some(failure) = &self.failure {
            response.insert("error".into(), Value::from(failure.clone()));
        }
        if let Some(details) = &self.transport_failure {
            if !details.is_empty() {
                response.insert("transport_failure".into(), Value::Object(details.clone()));
            }
        }
        Ok(response)
    }

    fn generate(&mut self, request: &Map<String, Value>) -> Result<Map<String, Value>> {
        let requested = request.get("key_class").cloned().unwrap_or(Value::from(9));
        let Some(key_class) = key_class_of(Some(&requested)) else { return Ok(error_reply("invalid_key_class")) };
        if !self.classes.contains(key_class) {
            let response = self.endpoint.call("generate", json!({"attested": true, "key_class": key_class}), None)?;
            if int_of(response.get("status")).is_some_and(|s| s != 0) {
                return Ok(response);
            }
            if !valid_generated_key(&response) {
                self.failure = Some("invalid_signing_key_result".into());
                let mut reply = status_reply(UNAVAILABLE, "invalid_signing_key_result");
                reply.insert("backend_operation".into(), Value::Object(operation_details(&response)));
                return Ok(reply);
            }
            let ltk = response["ltk"].as_str().unwrap_or("").to_string();
            let identity = response["identity"].as_str().unwrap_or("").to_string();
            let Ok((wire, _proof)) = platform_ltk(&ltk, 3) else {
                self.failure = Some("unsupported_signing_key_layout".into());
                let mut reply = status_reply(UNAVAILABLE, "unsupported_signing_key_layout");
                reply.insert("backend_operation".into(), Value::Object(operation_details(&response)));
                return Ok(reply);
            };
            self.wire_keys.insert(key_class, wire.clone());
            self.identities.insert(wire, identity.clone());
            self.classes.insert(key_class, response);
            self.identities.insert(ltk, identity);
        }
        let wire = self.wire_keys[&key_class].clone();
        let size = base64::engine::general_purpose::STANDARD.decode(&wire).map(|d| d.len()).unwrap_or(0);
        let mut reply = Map::new();
        reply.insert("status".into(), Value::from(0));
        reply.insert("data".into(), Value::from(wire));
        reply.insert("bytes".into(), Value::from(size));
        Ok(reply)
    }

    fn keyed(&mut self, operation: &str, request: &Map<String, Value>) -> Result<Map<String, Value>> {
        let identity = match request.get("local_ltk") {
            Some(Value::String(ltk)) => self.identities.get(ltk).cloned(),
            _ => None,
        };
        let Some(identity) = identity else { return Ok(error_reply("local_key_not_owned")) };
        if operation == "session_signed" {
            if self.counter >= SESSION_END - SESSION_BASE - 1 {
                return Ok(status_reply(UNAVAILABLE, "session_namespace_exhausted"));
            }
            if self.sessions.len() >= MAX_SESSIONS {
                return Ok(status_reply(NO_MEMORY, "owned_session_limit"));
            }
        }
        let mut fields = Map::new();
        fields.insert("identity".into(), Value::from(identity));
        if operation != "validate" {
            let field = |name: &str, default: Value| request.get(name).cloned().unwrap_or(default);
            fields.insert("remote_ltk".into(), field("remote_ltk", Value::from("")));
            fields.insert("remote_key_class".into(), field("remote_key_class", Value::from(9)));
            fields.insert("flags".into(), field("flags", Value::from(0)));
            fields.insert("parameters".into(), field("parameters", Value::from("")));
        }
        let mut response = self.endpoint.call(operation, Value::Object(fields), None)?;
        if operation == "session_signed" && py_eq_int(response.get("status"), 0) {
            let real = int_of(response.get("session")).filter(|r| *r >= 0);
            let Some(real) = real.filter(|r| !self.sessions.values().any(|v| v == r)) else {
                self.failure = Some("invalid_session_handle".into());
                return Err(EndpointError::message("Backend returned an invalid or duplicate session handle").into());
            };
            self.counter += 1;
            let virtual_handle = SESSION_BASE + self.counter;
            self.sessions.insert(virtual_handle, real);
            self.session_flags.insert(virtual_handle, int_of(request.get("flags").or(Some(&Value::from(0)))).unwrap_or(0));
            response.insert("session".into(), Value::from(virtual_handle));
        }
        Ok(response)
    }

    fn session_operation(&mut self, operation: &str, request: &Map<String, Value>) -> Result<Map<String, Value>> {
        let virtual_handle = int_of(request.get("session")).and_then(|v| i64::try_from(v).ok());
        let Some(virtual_handle) = virtual_handle.filter(|v| self.sessions.contains(*v)) else {
            return Ok(error_reply("session_not_owned"));
        };
        let real = *self.sessions.get(virtual_handle).unwrap();
        let data = request.get("data").cloned().unwrap_or(Value::from(""));
        let response = self.endpoint.call(operation, json!({"session": number(real), "data": data}), None)?;
        if operation == "reset" && (py_eq_int(response.get("status"), 0)
            || response.get("error").and_then(Value::as_str) == Some("session_not_owned")) {
            self.sessions.remove(virtual_handle);
            self.session_flags.remove(&virtual_handle);
        }
        Ok(response)
    }

    /// One broker request. `Err` corresponds to an exception escaping
    /// `AksBroker.execute` (the server then drops the connection).
    pub fn execute(&mut self, request: &Map<String, Value>) -> Result<Map<String, Value>> {
        let operation = request.get("operation").and_then(Value::as_str).unwrap_or("");
        if self.certificate_expires_at.is_some_and(|at| crate::util::now() >= at) {
            self.failure = Some("bridge_certificate_expired".into());
        }
        match operation {
            "health" => return self.health(),
            "reset_owned_sessions" => return self.reset_owned_sessions(),
            _ => {}
        }
        if self.failure.is_some() {
            return Ok(status_reply(UNAVAILABLE, "broker_requires_restart"));
        }
        match operation {
            "generate" => self.generate(request),
            "validate" | "sign_remote" | "session_signed" => self.keyed(operation, request),
            "step" | "token" | "confirm" | "setup" | "reset" => self.session_operation(operation, request),
            "get_state" | "drop" => {
                let data = request.get("data").cloned().unwrap_or(Value::from(""));
                self.endpoint.call(operation, json!({"data": data}), None)
            }
            _ => Ok(error_reply("unknown_operation")),
        }
    }
}

fn number(value: i128) -> Value {
    i64::try_from(value).map(Value::from).or_else(|_| u64::try_from(value).map(Value::from)).unwrap_or(Value::Null)
}

#[cfg(test)]
pub(crate) mod tests;
