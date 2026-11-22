//! Error type of the runtime/control layer.
//!
//! It keeps Python's `type(error).__name__` and `str(error)` for the
//! exception classes the ported scripts catch (`OSError`, `ValueError`,
//! `RuntimeError`, `KeyError`, `TypeError`, `subprocess.SubprocessError`,
//! bridge/certificate errors). [`Error::Delegate`] has no Python
//! counterpart: it marks work that still belongs to the Python
//! setup/installation code (see [`crate::control`]).
use std::fmt;

use mirra_core::error::ErrorType;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum Error {
    /// Builtin exceptions raised by mirra-core (OSError family, ValueError,
    /// RuntimeError, ConfigError, subprocess errors).
    Core(mirra_core::Error),
    /// Bridge, endpoint and certificate errors from mirra-bridge.
    Bridge(Box<mirra_bridge::Error>),
    /// `KeyError(key)`; `str()` is the key's repr.
    Key(String),
    /// `TypeError(message)`
    Type(String),
    /// The operation must be finished by the Python implementation (an
    /// interrupted install, or `control install` itself).
    Delegate(String),
}

impl Error {
    pub fn runtime(message: impl Into<String>) -> Self {
        Error::Core(mirra_core::Error::runtime(message))
    }
    pub fn value(message: impl Into<String>) -> Self {
        Error::Core(mirra_core::Error::value(message))
    }
    pub fn key(key: &str) -> Self {
        Error::Key(mirra_core::pyfmt::repr_str(key))
    }
    pub fn type_error(message: impl Into<String>) -> Self {
        Error::Type(message.into())
    }

    /// Python `type(error).__name__`.
    pub fn type_name(&self) -> String {
        match self {
            Error::Core(e) => e.type_name(),
            Error::Bridge(e) => e.type_name(),
            Error::Key(_) => "KeyError".into(),
            Error::Type(_) => "TypeError".into(),
            Error::Delegate(_) => "DelegateToPython".into(),
        }
    }

    pub fn is_delegate(&self) -> bool {
        matches!(self, Error::Delegate(_))
    }

    /// `isinstance(error, OSError)`.
    pub fn is_os_error(&self) -> bool {
        match self {
            Error::Core(e) => e.is_os_error(),
            Error::Bridge(e) => e.is_os_error(),
            _ => false,
        }
    }

    pub fn errno(&self) -> Option<i32> {
        match self {
            Error::Core(e) => e.errno(),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Core(e) => e.fmt(f),
            Error::Bridge(e) => e.fmt(f),
            Error::Key(m) | Error::Type(m) | Error::Delegate(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {}

impl ErrorType for Error {
    fn error_type(&self) -> String {
        self.type_name()
    }
}

impl From<mirra_core::Error> for Error {
    fn from(e: mirra_core::Error) -> Self {
        Error::Core(e)
    }
}

impl From<mirra_bridge::Error> for Error {
    fn from(e: mirra_bridge::Error) -> Self {
        match e {
            mirra_bridge::Error::Core(core) => Error::Core(core),
            other => Error::Bridge(Box::new(other)),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Core(mirra_core::Error::Os(e))
    }
}

impl From<mirra_core::config::ConfigError> for Error {
    fn from(e: mirra_core::config::ConfigError) -> Self {
        Error::Core(e.into())
    }
}
