//! Use a current certificate from the enrolled bridge without changing its
//! saved profile (port of `scripts/certificates.py`).
use std::ffi::OsString;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::Duration;

use chrono::NaiveDate;
use mirra_core::config::Config;
use mirra_core::state::write_state;
use mirra_core::subprocess::{self, RunOptions};
use mirra_core::sys;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::bridgeclient::{self, Response};
use crate::error::{CertificateError, Error, Result};
use crate::provisioning;
use crate::wire::hex;

pub const RETRY_SECONDS: f64 = 900.0;
/// The issuer answered but kept the same expired certificate (seen on
/// jailbroken bridges whose activation service does not mint a new one).
/// Asking again costs each startup ~12s on the bridge, so wait longer;
/// Renew Now still forces it.
pub const UNCHANGED_RETRY_SECONDS: f64 = 12.0 * 3600.0;

const MONTHS: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];

/// `datetime.strptime(text, '%b %d %H:%M:%S %Y %Z')` as UTC epoch seconds.
fn parse_date(text: &str) -> Option<f64> {
    let fields: Vec<&str> = text.split_whitespace().collect();
    let [month, day, time, year, zone] = fields.as_slice() else { return None };
    let month = MONTHS.iter().position(|m| m.eq_ignore_ascii_case(month))? as u32 + 1;
    let number = |s: &str, max_len: usize| -> Option<u32> {
        (!s.is_empty() && s.len() <= max_len && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse().ok()).flatten()
    };
    let day = number(day, 2)?;
    let clock: Vec<&str> = time.split(':').collect();
    let [hour, minute, second] = clock.as_slice() else { return None };
    let (hour, minute, second) = (number(hour, 2)?, number(minute, 2)?, number(second, 2)?);
    if year.len() != 4 {
        return None;
    }
    let year = number(year, 4)? as i32;
    if !["gmt", "utc"].iter().any(|z| z.eq_ignore_ascii_case(zone)) {
        return None;
    }
    let moment = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, minute, second)?;
    Some(moment.and_utc().timestamp() as f64)
}

/// `validity(data)` → (notBefore, notAfter) in epoch seconds, read with
/// `/usr/bin/openssl x509` exactly as the Python service does.
pub fn validity(data: &[u8]) -> std::result::Result<(f64, f64), CertificateError> {
    if data.is_empty() || data.len() > 1_048_576 {
        return Err(CertificateError::new("invalid", "The bridge certificate has an invalid size", None));
    }
    let invalid = || CertificateError::new("invalid", "Could not check the bridge certificate dates", None);
    let mut environment: Vec<(OsString, OsString)> = std::env::vars_os().filter(|(k, _)| k != "LC_ALL").collect();
    environment.push(("LC_ALL".into(), "C".into()));
    let options = RunOptions::new().input(data.to_vec()).capture().check().timeout(Duration::from_secs(5)).env(environment);
    let result = subprocess::run(&["/usr/bin/openssl", "x509", "-inform", "DER", "-noout", "-startdate", "-enddate"], &options)
        .map_err(|_| invalid())?;
    let text = String::from_utf8(result.stdout).ok().filter(|t| t.is_ascii()).ok_or_else(invalid)?;
    let mut dates = std::collections::HashMap::new();
    for line in mirra_core::pyfmt::splitlines(&text) {
        let (key, value) = line.split_once('=').ok_or_else(invalid)?;
        dates.insert(key.to_string(), value.to_string());
    }
    let start = dates.get("notBefore").and_then(|d| parse_date(d)).ok_or_else(invalid)?;
    let end = dates.get("notAfter").and_then(|d| parse_date(d)).ok_or_else(invalid)?;
    if end <= start {
        return Err(invalid());
    }
    Ok((start, end))
}

/// A usable certificate: bytes, validity window, and whether it differs
/// from the enrolled file (`renewed`).
#[derive(Clone, Debug, PartialEq)]
pub struct CurrentCertificate {
    pub data: Vec<u8>,
    pub start: f64,
    pub end: f64,
    pub renewed: bool,
}

/// The operations `current_certificate` depends on (the Python tests patch
/// exactly these); [`System`] uses the real ones.
pub trait Environment {
    fn now(&self) -> f64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
    }
    fn validity(&self, data: &[u8]) -> std::result::Result<(f64, f64), CertificateError> {
        validity(data)
    }
    fn read_token(&self, path: &Path) -> Result<String> {
        bridgeclient::read_token(path)
    }
    fn request(&self, config: &Config, token: &str, method: &str, path: &str, timeout: Duration) -> Result<Response> {
        bridgeclient::request(config, token, method, path, None, Some(timeout))
    }
    fn certificate_from_service(&self, config: &Config, token: &str, issue: bool, issue_if_missing: bool,
                                replace_expired_sha256: Option<&str>) -> Result<(Vec<u8>, bool)> {
        provisioning::certificate_from_service(config, token, issue, issue_if_missing, replace_expired_sha256)
    }
}

pub struct System;

impl Environment for System {}

/// `current_certificate(config, renewal_state, on_renewal, *, force=False)`.
pub fn current_certificate(config: &Config, renewal_state: &Path, on_renewal: &mut dyn FnMut(), force: bool)
    -> Result<CurrentCertificate> {
    current_certificate_with(&System, config, renewal_state, on_renewal, force)
}

fn private(info: &libc::stat, directory: bool) -> bool {
    let kind = if directory { sys::is_dir(info.st_mode) } else { sys::is_reg(info.st_mode) };
    kind && info.st_uid == sys::getuid() && info.st_mode & 0o077 == 0
}

/// `Path.mkdir(exist_ok=True, mode=0o700)`
fn make_directory(directory: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new().mode(0o700).create(directory) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && directory.is_dir() => Ok(()),
        Err(e) => Err(mirra_core::Error::with_path(e, directory).into()),
    }
}

pub fn current_certificate_with(env: &dyn Environment, config: &Config, renewal_state: &Path,
                                on_renewal: &mut dyn FnMut(), force: bool) -> Result<CurrentCertificate> {
    let installed = std::fs::read(&config.certificate_file)
        .map_err(|e| mirra_core::Error::with_path(e, &config.certificate_file))?;
    let (installed_start, installed_end) = env.validity(&installed)?;
    let now = env.now();
    if installed_start > now {
        return Err(CertificateError::new("clock", "The saved certificate is not yet valid. Check the Mac’s clock.", None).into());
    }
    if installed_end > now {
        return Ok(CurrentCertificate { data: installed, start: installed_start, end: installed_end, renewed: false });
    }

    let directory = match renewal_state.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    make_directory(&directory)?;
    let info = sys::lstat(&directory).map_err(|e| mirra_core::Error::with_path(e, &directory))?;
    if !private(&info, true) {
        return Err(CertificateError::new("invalid", "Certificate renewal requires a private Mirra runtime directory", None).into());
    }
    let lock_path = directory.join("certificate-renewal.lock");
    let descriptor = match sys::open(&lock_path, libc::O_CREAT | libc::O_NOFOLLOW | libc::O_RDWR, 0o600) {
        Ok(fd) => fd,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(CertificateError::new("invalid", "Certificate renewal lock is not a private Mirra file", None).into());
        }
        Err(e) => return Err(mirra_core::Error::with_path(e, &lock_path).into()),
    };
    let info = sys::fstat(descriptor.as_raw_fd())?;
    if !private(&info, false) {
        return Err(CertificateError::new("invalid", "Certificate renewal lock is not a private Mirra file", None).into());
    }
    match sys::flock(descriptor.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EWOULDBLOCK) => {
            return Err(CertificateError::new("busy", "A bridge certificate check or renewal is already in progress.", None).into());
        }
        Err(e) => return Err(e.into()),
    }
    let result = check_bridge(env, config, renewal_state, on_renewal, force);
    drop(descriptor);
    result
}

fn check_bridge(env: &dyn Environment, config: &Config, renewal_state: &Path, on_renewal: &mut dyn FnMut(), force: bool)
    -> Result<CurrentCertificate> {
    // The installed file anchors enrollment. Use replacements only from the
    // same TLS-authenticated bridge, without changing the saved profile.
    let unavailable = |message: &str| -> Error { CertificateError::new("unavailable", message, None).into() };
    let reached = env.read_token(&config.token_file)
        .and_then(|token| env.request(config, &token, "GET", "/v1/certificate", Duration::from_secs(10)).map(|r| (token, r)));
    let (token, response) = match reached {
        Ok(pair) => pair,
        Err(e) if e.is_os_error() => return Err(unavailable("Mirra could not reach the enrolled bridge to check its certificate")),
        Err(e) => return Err(e),
    };
    if response.status != 200 {
        return Err(unavailable("The enrolled bridge did not return its certificate"));
    }
    let data = response.body;
    let (start, end) = env.validity(&data)?;
    let now = env.now();
    if start > now {
        return Err(CertificateError::new("clock", "The bridge certificate is not yet valid. Check the Mac’s clock.", None).into());
    }
    if end > now {
        return Ok(CurrentCertificate { data, start, end, renewed: true });
    }

    match sys::lstat(renewal_state) {
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
        Err(e) => return Err(mirra_core::Error::with_path(e, renewal_state).into()),
        Ok(info) => {
            if !private(&info, false) {
                return Err(CertificateError::new("invalid", "Certificate retry state is not a private Mirra file", None).into());
            }
            let text = std::fs::read(renewal_state).map_err(|e| mirra_core::Error::with_path(e, renewal_state))?;
            let text = String::from_utf8(text).map_err(|e| Error::value(e.to_string()))?;
            let state: Value = serde_json::from_str(&text).map_err(|e| Error::value(e.to_string()))?;
            let Value::Object(state) = state else {
                return Err(CertificateError::new("invalid", "Certificate retry state is invalid", None).into());
            };
            if let Some(Value::Number(retry_at)) = state.get("retry_at") {
                let retry_at = retry_at.as_f64().unwrap_or(f64::NAN);
                if !force && now < retry_at && retry_at <= now + RETRY_SECONDS.max(UNCHANGED_RETRY_SECONDS) {
                    return Err(CertificateError::new("expired", "The bridge still has an expired certificate", Some(retry_at)).into());
                }
            }
        }
    }
    let mut retry_at = now + RETRY_SECONDS;
    // Record the cooldown before asking the issuer, even if the process is interrupted.
    write_state(renewal_state, &json!({"retry_at": retry_at}))?;
    on_renewal();
    let expired = |retry_at: f64| -> Error {
        CertificateError::new("expired", "The bridge could not renew its certificate", Some(retry_at)).into()
    };
    let renewed = env.certificate_from_service(config, &token, true, false, Some(&hex(&Sha256::digest(&data))))
        .and_then(|(data, _)| env.validity(&data).map(|window| (data, window)).map_err(Error::from));
    let (data, (start, end)) = match renewed {
        Ok(renewed) => renewed,
        Err(Error::RemoteSetup(error)) if error.code() == Some("certificate_unchanged") => {
            retry_at = now + UNCHANGED_RETRY_SECONDS;
            write_state(renewal_state, &json!({"retry_at": retry_at}))?;
            return Err(CertificateError::new("expired",
                "The iPhone still returns the same expired certificate after requesting renewal", Some(retry_at)).into());
        }
        Err(Error::RemoteSetup(_)) => return Err(expired(retry_at)),
        Err(e) if e.is_os_error() || e.is_runtime_error() || matches!(&e, Error::Core(c) if c.is_subprocess_error()) => {
            return Err(expired(retry_at));
        }
        Err(e) => return Err(e),
    };
    let current = env.now();
    if !(start <= current && current < end) {
        return Err(CertificateError::new("expired", "The issuer did not return a currently valid certificate", Some(retry_at)).into());
    }
    Ok(CurrentCertificate { data, start, end, renewed: true })
}

#[cfg(test)]
mod tests;
