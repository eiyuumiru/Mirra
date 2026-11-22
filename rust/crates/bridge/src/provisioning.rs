//! The parts of `scripts/provisioning.py` the background service needs:
//! `RemoteSetupError` and `certificate_from_service`. Setup stays in Python.
use std::time::Duration;

use mirra_core::activity;
use mirra_core::config::Config;
use mirra_core::subprocess::RunOptions;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::bridgeclient::{request, request_json};
use crate::error::{EndpointError, Error, Result};
use crate::pyutil::truthy;
use crate::wire::hex;

/// `RemoteSetupError(message, code=None, details=None)`.
pub fn remote_setup_error(message: impl Into<String>, code: Option<&str>, details: Map<String, Value>) -> Error {
    Error::RemoteSetup(EndpointError::new(message, code, details))
}

fn export(config: &Config, token: &str, issue_now: bool, replace_expired_sha256: Option<&str>) -> Result<Map<String, Value>> {
    let (status, reply) = activity::operation("Certificate", if issue_now { "issue" } else { "export" }, Value::Null, || {
        let mut payload = Map::new();
        payload.insert("issue".into(), Value::Bool(issue_now));
        if let (true, Some(digest)) = (issue_now, replace_expired_sha256) {
            payload.insert("replace_expired_sha256".into(), Value::from(digest));
        }
        request_json(config, token, "POST", "/v1/certificate", Some(&Value::Object(payload)), Some(Duration::from_secs(70)))
    })?;
    if status != 200 || !reply.get("certificate_exported").is_some_and(truthy) {
        let code = reply.get("error").and_then(Value::as_str);
        let mut details = Map::new();
        if let Some(Value::Number(n)) = reply.get("error_code") {
            if n.is_i64() || n.is_u64() {
                details.insert("error_code".into(), Value::Number(n.clone()));
            }
        }
        if let Some(Value::Bool(completed)) = reply.get("completed") {
            details.insert("completed".into(), Value::Bool(*completed));
        }
        let shown = match code {
            Some(code) if !code.is_empty() => code.to_string(),
            _ => status.to_string(),
        };
        return Err(remote_setup_error(format!("The bridge could not export its device certificate: {}", shown), code, details));
    }
    Ok(reply)
}

/// `certificate_from_service(config, token, issue, issue_if_missing, *,
/// replace_expired_sha256=None)`: export (or first request) the DCRT on the
/// phone and download it over HTTPS-PSK → `(DER bytes, issued)`.
pub fn certificate_from_service(config: &Config, token: &str, issue: bool, issue_if_missing: bool,
                                replace_expired_sha256: Option<&str>) -> Result<(Vec<u8>, bool)> {
    let mut issued = issue;
    let exported = match export(config, token, issue, replace_expired_sha256) {
        Ok(reply) => reply,
        Err(Error::RemoteSetup(error))
            if issue_if_missing && !issue && error.code() == Some("cached_certificate_unavailable") => {
            activity::emit("Certificate", "cached certificate unavailable", "warning", json!({"error_code": error.code}));
            issued = true;
            export(config, token, true, replace_expired_sha256)?
        }
        Err(error) => return Err(error),
    };
    if exported.get("issuance_requested") == Some(&Value::Bool(false)) {
        issued = false;
    }
    let response = request(config, token, "GET", "/v1/certificate", None, Some(Duration::from_secs(20)))?;
    let data = response.body;
    let expected = exported.get("sha256");
    if response.status != 200 || data.is_empty() || data.len() > 1048576
        || expected != Some(&Value::String(hex(&Sha256::digest(&data)))) {
        return Err(Error::runtime("Downloaded device certificate does not match the export"));
    }
    activity::emit("Certificate", "certificate download verified", "info",
        json!({"bytes": data.len(), "sha256": expected}));
    let options = RunOptions::new().source("Certificate").input(data.clone()).capture().check().timeout(Duration::from_secs(10));
    activity::run(&["openssl", "x509", "-inform", "DER", "-noout"], &options)?;
    Ok((data, issued))
}

#[cfg(test)]
mod tests;
