//! Exception classes of the bridge modules.
//!
//! Python hierarchy, which callers rely on when classifying failures:
//! `BridgeError(OSError)` with subclasses `BridgeTimeout`/`BridgeClosed`;
//! `EndpointError(RuntimeError)` with subclass `RemoteSetupError`;
//! `CertificateError(RuntimeError)`. Everything else (OSError, ValueError,
//! RuntimeError, subprocess errors) is carried as a [`mirra_core::Error`].
use std::fmt;

use mirra_core::error::ErrorType;
use serde_json::{Map, Value};

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// `bridgeclient.BridgeError(message, code)`; `BridgeTimeout` and
/// `BridgeClosed` are the codes `bridge_timeout` and `bridge_closed`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeError {
    pub message: String,
    pub code: String,
}

pub const BRIDGE_TIMEOUT: &str = "bridge_timeout";
pub const BRIDGE_CLOSED: &str = "bridge_closed";

impl BridgeError {
    pub fn new(message: impl Into<String>, code: impl Into<String>) -> Self {
        BridgeError { message: message.into(), code: code.into() }
    }
    /// `BridgeTimeout()`
    pub fn timeout() -> Self {
        Self::timeout_with("Bridge did not answer in time")
    }
    /// `BridgeTimeout(message)`
    pub fn timeout_with(message: impl Into<String>) -> Self {
        Self::new(message, BRIDGE_TIMEOUT)
    }
    /// `BridgeClosed()`
    pub fn closed() -> Self {
        Self::closed_with("Bridge closed the connection")
    }
    /// `BridgeClosed(message)`
    pub fn closed_with(message: impl Into<String>) -> Self {
        Self::new(message, BRIDGE_CLOSED)
    }
    /// `isinstance(error, BridgeTimeout)`
    pub fn is_timeout(&self) -> bool {
        self.code == BRIDGE_TIMEOUT
    }
    /// `isinstance(error, BridgeClosed)`
    pub fn is_closed(&self) -> bool {
        self.code == BRIDGE_CLOSED
    }
    pub fn type_name(&self) -> &'static str {
        if self.is_timeout() {
            "BridgeTimeout"
        } else if self.is_closed() {
            "BridgeClosed"
        } else {
            "BridgeError"
        }
    }
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for BridgeError {}

/// `transport.EndpointError(message, code=None, details=None)`.
#[derive(Clone, Debug, PartialEq)]
pub struct EndpointError {
    pub message: String,
    pub code: Option<String>,
    pub details: Map<String, Value>,
}

impl EndpointError {
    pub fn new(message: impl Into<String>, code: Option<&str>, details: Map<String, Value>) -> Self {
        EndpointError { message: message.into(), code: code.map(str::to_string), details }
    }
    /// `EndpointError(message)`
    pub fn message(message: impl Into<String>) -> Self {
        Self::new(message, None, Map::new())
    }
    /// `EndpointError(message, code)`
    pub fn coded(message: impl Into<String>, code: &str) -> Self {
        Self::new(message, Some(code), Map::new())
    }
    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }
}

impl fmt::Display for EndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for EndpointError {}

/// `certificates.CertificateError(code, message, retry_at=None)`.
#[derive(Clone, Debug, PartialEq)]
pub struct CertificateError {
    pub code: String,
    pub message: String,
    pub retry_at: Option<f64>,
}

impl CertificateError {
    pub fn new(code: &str, message: impl Into<String>, retry_at: Option<f64>) -> Self {
        CertificateError { code: code.into(), message: message.into(), retry_at }
    }
}

impl fmt::Display for CertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CertificateError {}

/// Any failure raised by this crate's functions.
#[derive(Debug)]
pub enum Error {
    /// `BridgeError` / `BridgeTimeout` / `BridgeClosed` (OSError subclasses)
    Bridge(BridgeError),
    /// `EndpointError` (RuntimeError subclass)
    Endpoint(EndpointError),
    /// `provisioning.RemoteSetupError` (EndpointError subclass)
    RemoteSetup(EndpointError),
    /// `CertificateError` (RuntimeError subclass)
    Certificate(CertificateError),
    /// Builtin exceptions: OSError family, ValueError, RuntimeError, subprocess errors
    Core(mirra_core::Error),
}

impl Error {
    /// Python `type(error).__name__`.
    pub fn type_name(&self) -> String {
        match self {
            Error::Bridge(e) => e.type_name().into(),
            Error::Endpoint(_) => "EndpointError".into(),
            Error::RemoteSetup(_) => "RemoteSetupError".into(),
            Error::Certificate(_) => "CertificateError".into(),
            Error::Core(e) => e.type_name(),
        }
    }

    /// The `.code` attribute of bridge, endpoint and certificate errors.
    pub fn code(&self) -> Option<&str> {
        match self {
            Error::Bridge(e) => Some(&e.code),
            Error::Endpoint(e) | Error::RemoteSetup(e) => e.code(),
            Error::Certificate(e) => Some(&e.code),
            Error::Core(_) => None,
        }
    }

    /// `isinstance(error, OSError)`.
    pub fn is_os_error(&self) -> bool {
        match self {
            Error::Bridge(_) => true,
            Error::Core(e) => e.is_os_error(),
            _ => false,
        }
    }

    /// `isinstance(error, RuntimeError)` (EndpointError, RemoteSetupError,
    /// CertificateError and plain RuntimeError).
    pub fn is_runtime_error(&self) -> bool {
        match self {
            Error::Endpoint(_) | Error::RemoteSetup(_) | Error::Certificate(_) => true,
            Error::Core(e) => matches!(e, mirra_core::Error::Runtime(_)),
            Error::Bridge(_) => false,
        }
    }

    /// `isinstance(error, ValueError)`.
    pub fn is_value_error(&self) -> bool {
        matches!(self, Error::Core(mirra_core::Error::Value(_) | mirra_core::Error::Config(_)))
    }

    /// `isinstance(error, EndpointError)` (includes RemoteSetupError).
    pub fn as_endpoint(&self) -> Option<&EndpointError> {
        match self {
            Error::Endpoint(e) | Error::RemoteSetup(e) => Some(e),
            _ => None,
        }
    }

    pub fn as_bridge(&self) -> Option<&BridgeError> {
        match self {
            Error::Bridge(e) => Some(e),
            _ => None,
        }
    }

    pub fn as_certificate(&self) -> Option<&CertificateError> {
        match self {
            Error::Certificate(e) => Some(e),
            _ => None,
        }
    }

    pub(crate) fn value(message: impl Into<String>) -> Self {
        Error::Core(mirra_core::Error::Value(message.into()))
    }

    pub(crate) fn runtime(message: impl Into<String>) -> Self {
        Error::Core(mirra_core::Error::Runtime(message.into()))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Bridge(e) => e.fmt(f),
            Error::Endpoint(e) | Error::RemoteSetup(e) => e.fmt(f),
            Error::Certificate(e) => e.fmt(f),
            Error::Core(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

impl ErrorType for Error {
    fn error_type(&self) -> String {
        self.type_name()
    }
}

impl From<BridgeError> for Error {
    fn from(e: BridgeError) -> Self {
        Error::Bridge(e)
    }
}

impl From<EndpointError> for Error {
    fn from(e: EndpointError) -> Self {
        Error::Endpoint(e)
    }
}

impl From<CertificateError> for Error {
    fn from(e: CertificateError) -> Self {
        Error::Certificate(e)
    }
}

impl From<mirra_core::Error> for Error {
    fn from(e: mirra_core::Error) -> Self {
        Error::Core(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Core(mirra_core::Error::Os(e))
    }
}
