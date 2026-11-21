//! Error type mirroring the Python exception classes the scripts rely on.
//!
//! `Display` reproduces Python's `str(error)` and [`Error::type_name`]
//! reproduces `type(error).__name__`, because both surface in logs/replies.
use std::fmt;
use std::io;
use std::time::Duration;

use crate::pyfmt;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum Error {
    /// `OSError` (subclass selected by errno). `str()` = `[Errno N] strerror`.
    Os(io::Error),
    /// `OSError(errno, message)`; `str()` = `[Errno N] message`.
    OsMessage { errno: i32, message: String },
    /// `OSError` with a filename; `str()` = `[Errno N] strerror: 'path'`.
    OsPath { error: io::Error, path: String },
    /// `ValueError`
    Value(String),
    /// `RuntimeError`
    Runtime(String),
    /// `configuration.ConfigError` (a `ValueError`)
    Config(String),
    /// builtin `TimeoutError` (an `OSError`), e.g. socket timeouts
    Timeout(String),
    /// builtin `ConnectionError` (an `OSError`)
    Connection(String),
    /// `subprocess.TimeoutExpired`, carrying the output captured so far
    TimeoutExpired { command: Vec<String>, timeout: Duration, stdout: Vec<u8>, stderr: Vec<u8> },
    /// `subprocess.CalledProcessError`
    CalledProcess { code: i32, command: Vec<String>, stdout: Vec<u8>, stderr: Vec<u8> },
}

impl Error {
    pub fn value(message: impl Into<String>) -> Self {
        Error::Value(message.into())
    }
    pub fn runtime(message: impl Into<String>) -> Self {
        Error::Runtime(message.into())
    }
    pub fn os_message(errno: i32, message: impl Into<String>) -> Self {
        Error::OsMessage { errno, message: message.into() }
    }
    /// `OSError` for the last libc errno with a custom message.
    pub fn last_os(message: impl Into<String>) -> Self {
        Error::os_message(crate::sys::errno(), message)
    }
    pub fn with_path(error: io::Error, path: impl AsRef<std::path::Path>) -> Self {
        Error::OsPath { error, path: path.as_ref().to_string_lossy().into_owned() }
    }

    pub fn errno(&self) -> Option<i32> {
        match self {
            Error::Os(e) | Error::OsPath { error: e, .. } => e.raw_os_error(),
            Error::OsMessage { errno, .. } => Some(*errno),
            _ => None,
        }
    }

    /// `isinstance(error, OSError)` in Python.
    pub fn is_os_error(&self) -> bool {
        matches!(self, Error::Os(_) | Error::OsMessage { .. } | Error::OsPath { .. }
            | Error::Timeout(_) | Error::Connection(_))
    }

    /// `isinstance(error, subprocess.SubprocessError)`.
    pub fn is_subprocess_error(&self) -> bool {
        matches!(self, Error::TimeoutExpired { .. } | Error::CalledProcess { .. })
    }

    /// Python `type(error).__name__`.
    pub fn type_name(&self) -> String {
        match self {
            Error::Os(e) | Error::OsPath { error: e, .. } => match e.raw_os_error() {
                Some(n) => os_error_name(n).to_string(),
                None => match e.kind() {
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "TimeoutError".into(),
                    io::ErrorKind::NotFound => "FileNotFoundError".into(),
                    io::ErrorKind::BrokenPipe => "BrokenPipeError".into(),
                    io::ErrorKind::InvalidData => "ValueError".into(),
                    _ => "OSError".into(),
                },
            },
            Error::OsMessage { errno, .. } => os_error_name(*errno).to_string(),
            Error::Value(_) => "ValueError".into(),
            Error::Runtime(_) => "RuntimeError".into(),
            Error::Config(_) => "ConfigError".into(),
            Error::Timeout(_) => "TimeoutError".into(),
            Error::Connection(_) => "ConnectionError".into(),
            Error::TimeoutExpired { .. } => "TimeoutExpired".into(),
            Error::CalledProcess { .. } => "CalledProcessError".into(),
        }
    }

    /// Captured process output for subprocess errors (empty otherwise).
    pub fn output(&self) -> (&[u8], &[u8]) {
        match self {
            Error::TimeoutExpired { stdout, stderr, .. } | Error::CalledProcess { stdout, stderr, .. } => (stdout, stderr),
            _ => (&[], &[]),
        }
    }
}

/// Python's OSError subclass for an errno value.
pub fn os_error_name(errno: i32) -> &'static str {
    match errno {
        libc::EAGAIN | libc::EALREADY | libc::EINPROGRESS => "BlockingIOError",
        libc::ECHILD => "ChildProcessError",
        libc::EPIPE | libc::ESHUTDOWN => "BrokenPipeError",
        libc::ECONNABORTED => "ConnectionAbortedError",
        libc::ECONNREFUSED => "ConnectionRefusedError",
        libc::ECONNRESET => "ConnectionResetError",
        libc::EEXIST => "FileExistsError",
        libc::ENOENT => "FileNotFoundError",
        libc::EINTR => "InterruptedError",
        libc::EISDIR => "IsADirectoryError",
        libc::ENOTDIR => "NotADirectoryError",
        libc::EACCES | libc::EPERM => "PermissionError",
        libc::ESRCH => "ProcessLookupError",
        libc::ETIMEDOUT => "TimeoutError",
        _ => "OSError",
    }
}

fn strerror(errno: i32) -> String {
    crate::sys::strerror(errno)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Os(e) => match e.raw_os_error() {
                Some(n) => write!(f, "[Errno {}] {}", n, strerror(n)),
                None => write!(f, "{}", e),
            },
            Error::OsPath { error, path } => match error.raw_os_error() {
                Some(n) => write!(f, "[Errno {}] {}: {}", n, strerror(n), pyfmt::repr_str(path)),
                None => write!(f, "{}: {}", error, pyfmt::repr_str(path)),
            },
            Error::OsMessage { errno, message } => write!(f, "[Errno {}] {}", errno, message),
            Error::Value(m) | Error::Runtime(m) | Error::Config(m) | Error::Timeout(m) | Error::Connection(m) => {
                f.write_str(m)
            }
            Error::TimeoutExpired { command, timeout, .. } => write!(
                f,
                "Command '{}' timed out after {} seconds",
                pyfmt::repr_list(command),
                pyfmt::duration_seconds(*timeout)
            ),
            Error::CalledProcess { code, command, .. } => {
                if *code < 0 {
                    match pyfmt::signal_name(-*code) {
                        Some(name) => write!(f, "Command '{}' died with <Signals.{}: {}>.", pyfmt::repr_list(command), name, -*code),
                        None => write!(f, "Command '{}' died with unknown signal {}.", pyfmt::repr_list(command), -*code),
                    }
                } else {
                    write!(f, "Command '{}' returned non-zero exit status {}.", pyfmt::repr_list(command), code)
                }
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Os(error)
    }
}

impl From<crate::config::ConfigError> for Error {
    fn from(error: crate::config::ConfigError) -> Self {
        Error::Config(error.0)
    }
}

/// Errors usable with [`crate::activity::operation`]: Python records
/// `error_type=type(error).__name__` and `error=str(error)`.
pub trait ErrorType: fmt::Display {
    fn error_type(&self) -> String;
}

impl ErrorType for Error {
    fn error_type(&self) -> String {
        self.type_name()
    }
}

impl ErrorType for io::Error {
    fn error_type(&self) -> String {
        Error::Os(io::Error::new(self.kind(), "")).type_name_for(self)
    }
}

impl Error {
    fn type_name_for(&self, original: &io::Error) -> String {
        match original.raw_os_error() {
            Some(n) => os_error_name(n).to_string(),
            None => self.type_name(),
        }
    }
}

impl ErrorType for crate::config::ConfigError {
    fn error_type(&self) -> String {
        "ConfigError".into()
    }
}

impl ErrorType for String {
    fn error_type(&self) -> String {
        "RuntimeError".into()
    }
}
