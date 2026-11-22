use super::*;
use crate::error::BridgeError;
use crate::testing;
use std::cell::{Cell, RefCell};
use std::os::unix::fs::PermissionsExt;

type Issued = (Vec<u8>, bool);
type IssueCall = (String, bool, bool, Option<String>);

/// The Python test's patches: time, validity by content, token, request and issuer.
struct Fake {
    now: Cell<f64>,
    request: RefCell<Result<Response>>,
    issued: RefCell<Option<Result<Issued>>>,
    issue_calls: RefCell<Vec<IssueCall>>,
    requests: Cell<usize>,
}

fn reply(body: &[u8]) -> Result<Response> {
    Ok(Response { status: 200, content_type: String::new(), body: body.to_vec() })
}

impl Fake {
    fn new() -> Self {
        Fake { now: Cell::new(100.0), request: RefCell::new(reply(b"expired")), issued: RefCell::new(None),
            issue_calls: RefCell::new(Vec::new()), requests: Cell::new(0) }
    }
}

impl Environment for Fake {
    fn now(&self) -> f64 {
        self.now.get()
    }
    fn validity(&self, data: &[u8]) -> std::result::Result<(f64, f64), CertificateError> {
        Ok(match data {
            b"installed" => (1.0, 50.0),
            b"expired" => (2.0, 60.0),
            b"valid" => (80.0, 140.0),
            _ => return Err(CertificateError::new("invalid", "Could not check the bridge certificate dates", None)),
        })
    }
    fn read_token(&self, _path: &Path) -> Result<String> {
        Ok("fixture".into())
    }
    fn request(&self, _: &Config, _: &str, method: &str, path: &str, timeout: Duration) -> Result<Response> {
        assert_eq!((method, path, timeout), ("GET", "/v1/certificate", Duration::from_secs(10)));
        self.requests.set(self.requests.get() + 1);
        match &*self.request.borrow() {
            Ok(r) => Ok(r.clone()),
            Err(e) => Err(BridgeError::new(e.to_string(), e.code().unwrap_or("x")).into()),
        }
    }
    fn certificate_from_service(&self, _: &Config, token: &str, issue: bool, issue_if_missing: bool,
                                replace: Option<&str>) -> Result<(Vec<u8>, bool)> {
        self.issue_calls.borrow_mut().push((token.into(), issue, issue_if_missing, replace.map(str::to_string)));
        let taken = self.issued.borrow_mut().take();
        match taken {
            None => Ok((b"valid".to_vec(), true)),
            Some(Ok(value)) => {
                *self.issued.borrow_mut() = Some(Ok(value.clone()));
                Ok(value)
            }
            Some(Err(Error::RemoteSetup(e))) => {
                *self.issued.borrow_mut() = Some(Err(Error::RemoteSetup(e.clone())));
                Err(Error::RemoteSetup(e))
            }
            Some(Err(e)) => Err(e),
        }
    }
}

struct Setup {
    _temp: tempfile::TempDir,
    fixture: testing::Fixture,
    state: std::path::PathBuf,
    fake: Fake,
    started: Cell<usize>,
}

impl Setup {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("runtime");
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let fixture = testing::fixture(1);
        std::fs::write(&fixture.config.certificate_file, b"installed").unwrap();
        Setup { _temp: temp, fixture, state: directory.join("retry.json"), fake: Fake::new(), started: Cell::new(0) }
    }
    fn read(&self, force: bool) -> Result<CurrentCertificate> {
        let mut started = || self.started.set(self.started.get() + 1);
        current_certificate_with(&self.fake, &self.fixture.config, &self.state, &mut started, force)
    }
    fn cooldown(&self, retry_at: f64) {
        std::fs::write(&self.state, format!("{{\"retry_at\": {}}}", retry_at)).unwrap();
        std::fs::set_permissions(&self.state, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn retry_at(&self) -> f64 {
        let state: Value = serde_json::from_str(&std::fs::read_to_string(&self.state).unwrap()).unwrap();
        state["retry_at"].as_f64().unwrap()
    }
}

fn certificate(data: &[u8], start: f64, end: f64, renewed: bool) -> CurrentCertificate {
    CurrentCertificate { data: data.to_vec(), start, end, renewed }
}

fn code(error: &Error) -> (&str, Option<f64>) {
    let e = error.as_certificate().unwrap_or_else(|| panic!("not a CertificateError: {}", error));
    (e.code.as_str(), e.retry_at)
}

#[test]
fn valid_enrollment_requires_no_bridge_request() {
    let s = Setup::new();
    std::fs::write(&s.fixture.config.certificate_file, b"valid").unwrap();
    assert_eq!(s.read(false).unwrap(), certificate(b"valid", 80.0, 140.0, false));
    assert_eq!(s.fake.requests.get(), 0);
    assert!(s.fake.issue_calls.borrow().is_empty());
}

#[test]
fn existing_valid_replacement_is_reused_even_in_cooldown() {
    let s = Setup::new();
    s.cooldown(800.0);
    *s.fake.request.borrow_mut() = reply(b"valid");
    assert_eq!(s.read(false).unwrap(), certificate(b"valid", 80.0, 140.0, true));
    assert!(s.fake.issue_calls.borrow().is_empty());
    assert_eq!(std::fs::read(&s.fixture.config.certificate_file).unwrap(), b"installed");
}

#[test]
fn expired_certificate_is_renewed_using_the_enrolled_bridge() {
    let s = Setup::new();
    assert_eq!(s.read(false).unwrap(), certificate(b"valid", 80.0, 140.0, true));
    assert_eq!(s.started.get(), 1);
    assert_eq!(*s.fake.issue_calls.borrow(), [("fixture".to_string(), true, false,
        Some(hex(&Sha256::digest(b"expired"))))]);
    assert_eq!(s.retry_at(), 100.0 + RETRY_SECONDS);
    assert_eq!(std::fs::metadata(&s.state).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn expired_issuer_reply_is_rejected_and_not_requested_again_during_cooldown() {
    let s = Setup::new();
    *s.fake.issued.borrow_mut() = Some(Ok((b"expired".to_vec(), true)));
    for _ in 0..2 {
        let error = s.read(false).unwrap_err();
        assert_eq!(code(&error), ("expired", Some(100.0 + RETRY_SECONDS)));
    }
    assert_eq!(s.fake.issue_calls.borrow().len(), 1);
    assert_eq!(std::fs::read(&s.fixture.config.certificate_file).unwrap(), b"installed");
}

#[test]
fn manual_renewal_bypasses_and_resets_the_cooldown() {
    let s = Setup::new();
    s.cooldown(800.0);
    let error = s.read(false).unwrap_err();
    assert_eq!(code(&error), ("expired", Some(800.0)));
    assert_eq!(error.to_string(), "The bridge still has an expired certificate");
    assert!(s.fake.issue_calls.borrow().is_empty());
    assert_eq!(s.read(true).unwrap(), certificate(b"valid", 80.0, 140.0, true));
    assert_eq!(s.fake.issue_calls.borrow().len(), 1);
    assert_eq!(s.retry_at(), 100.0 + RETRY_SECONDS);
}

#[test]
fn far_future_or_past_cooldowns_are_ignored() {
    for retry_at in [100.0, 100.0 + UNCHANGED_RETRY_SECONDS + 1.0] {
        let s = Setup::new();
        s.cooldown(retry_at);
        assert!(s.read(false).is_ok());
    }
    let s = Setup::new();
    std::fs::write(&s.state, "[]").unwrap();
    std::fs::set_permissions(&s.state, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(code(&s.read(false).unwrap_err()).0, "invalid");
    std::fs::set_permissions(&s.state, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(s.read(false).unwrap_err().to_string(), "Certificate retry state is not a private Mirra file");
}

#[test]
fn manual_renewal_reuses_a_valid_bridge_certificate() {
    let s = Setup::new();
    *s.fake.request.borrow_mut() = reply(b"valid");
    assert_eq!(s.read(true).unwrap(), certificate(b"valid", 80.0, 140.0, true));
    assert!(s.fake.issue_calls.borrow().is_empty());
}

#[test]
fn auto_and_manual_checks_share_the_same_lock() {
    let s = Setup::new();
    let lock = s.state.parent().unwrap().join("certificate-renewal.lock");
    let file = std::fs::OpenOptions::new().create(true).truncate(false).read(true).write(true).open(&lock).unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
    sys::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB).unwrap();
    for force in [false, true] {
        let error = s.read(force).unwrap_err();
        assert_eq!(code(&error).0, "busy");
        assert_eq!(error.to_string(), "A bridge certificate check or renewal is already in progress.");
    }
    assert_eq!(s.fake.requests.get(), 0);
}

#[test]
fn unchanged_expired_certificate_reports_the_issuer_outcome() {
    let s = Setup::new();
    *s.fake.issued.borrow_mut() = Some(Err(provisioning::remote_setup_error("Fixture", Some("certificate_unchanged"), Default::default())));
    let error = s.read(true).unwrap_err();
    assert!(error.to_string().contains("same expired certificate"));
    assert_eq!(code(&error), ("expired", Some(100.0 + UNCHANGED_RETRY_SECONDS)));
    // The longer cooldown also holds for later automatic checks.
    s.fake.issue_calls.borrow_mut().clear();
    assert!(s.read(false).is_err());
    assert!(s.fake.issue_calls.borrow().is_empty());
}

#[test]
fn other_issuer_failures_keep_the_short_cooldown() {
    let failures: [Error; 4] = [
        provisioning::remote_setup_error("Fixture", Some("issuer_failed"), Default::default()),
        Error::runtime("Downloaded device certificate does not match the export"),
        BridgeError::timeout().into(),
        Error::Core(mirra_core::Error::CalledProcess { code: 1, command: vec!["openssl".into()], stdout: vec![], stderr: vec![] }),
    ];
    for failure in failures {
        let s = Setup::new();
        *s.fake.issued.borrow_mut() = Some(Err(failure));
        let error = s.read(false).unwrap_err();
        assert_eq!(code(&error), ("expired", Some(100.0 + RETRY_SECONDS)));
        assert_eq!(error.to_string(), "The bridge could not renew its certificate");
    }
    let s = Setup::new();
    *s.fake.issued.borrow_mut() = Some(Ok((b"garbage".to_vec(), true)));
    assert_eq!(s.read(false).unwrap_err().to_string(), "The bridge could not renew its certificate");
    let s = Setup::new();
    *s.fake.issued.borrow_mut() = Some(Ok((b"installed".to_vec(), true)));
    assert_eq!(s.read(false).unwrap_err().to_string(), "The issuer did not return a currently valid certificate");
}

#[test]
fn unreachable_bridge_and_bad_replies() {
    let s = Setup::new();
    *s.fake.request.borrow_mut() = Err(BridgeError::new("down", "bridge_unreachable").into());
    let error = s.read(false).unwrap_err();
    assert_eq!(code(&error).0, "unavailable");
    assert_eq!(error.to_string(), "Mirra could not reach the enrolled bridge to check its certificate");
    *s.fake.request.borrow_mut() = Ok(Response { status: 404, content_type: String::new(), body: vec![] });
    assert_eq!(s.read(false).unwrap_err().to_string(), "The enrolled bridge did not return its certificate");
    *s.fake.request.borrow_mut() = reply(b"garbage");
    assert_eq!(code(&s.read(false).unwrap_err()).0, "invalid");
}

#[test]
fn future_certificate_stops_without_asking_for_issuance() {
    let s = Setup::new();
    s.fake.now.set(0.0);
    let error = s.read(false).unwrap_err();
    assert_eq!(code(&error).0, "clock");
    assert!(s.fake.issue_calls.borrow().is_empty());
}

#[test]
fn renewal_directory_must_be_private() {
    let s = Setup::new();
    std::fs::set_permissions(s.state.parent().unwrap(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(s.read(false).unwrap_err().to_string(), "Certificate renewal requires a private Mirra runtime directory");
    let s = Setup::new();
    let lock = s.state.parent().unwrap().join("certificate-renewal.lock");
    std::os::unix::fs::symlink("/tmp/elsewhere", &lock).unwrap();
    assert_eq!(s.read(false).unwrap_err().to_string(), "Certificate renewal lock is not a private Mirra file");
    let s = Setup::new();
    std::fs::remove_file(&s.fixture.config.certificate_file).unwrap();
    assert_eq!(s.read(false).unwrap_err().type_name(), "FileNotFoundError");
}

#[test]
fn validity_reads_dates_with_the_system_openssl() {
    for (start, end) in [(1_700_000_000, 1_700_259_200), (946_684_800, 4_102_444_799), (1_704_067_205, 1_704_153_600)] {
        assert_eq!(validity(&testing::certificate(start, end)).unwrap(), (start as f64, end as f64));
    }
    let reversed = validity(&testing::certificate(1_700_000_000, 1_600_000_000)).unwrap_err();
    assert_eq!((reversed.code.as_str(), reversed.message.as_str()), ("invalid", "Could not check the bridge certificate dates"));
    assert_eq!(validity(b"").unwrap_err().message, "The bridge certificate has an invalid size");
    assert_eq!(validity(&vec![0; 1_048_577]).unwrap_err().message, "The bridge certificate has an invalid size");
    assert_eq!(validity(b"junk").unwrap_err().code, "invalid");
}

#[test]
fn dates_parse_like_strptime() {
    assert_eq!(parse_date("Nov 21 10:26:51 2026 GMT"), Some(1_795_256_811.0));
    assert_eq!(parse_date("Jan  1 00:00:00 2024 GMT"), Some(1_704_067_200.0));
    assert_eq!(parse_date("feb 29 00:00:00 2024 utc"), Some(1_709_164_800.0));
    for bad in ["Feb 30 00:00:00 2024 GMT", "Jan 1 00:00:60 2024 GMT", "Jan 1 00:00:00 24 GMT", "Jan 1 00:00:00 2024 PST", "Jan 1 2024"] {
        assert_eq!(parse_date(bad), None, "{}", bad);
    }
}
