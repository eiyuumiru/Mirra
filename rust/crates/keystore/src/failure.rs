//! How a command ends unsuccessfully: `SystemExit(message)` (message on
//! stderr, status 1) or an uncaught exception (Python prints a traceback whose
//! last line is `Type: message`; status 1).
use std::sync::Arc;

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    Exit(String),
    Raised { type_name: String, message: String },
}

impl Failure {
    pub fn exit(message: impl Into<String>) -> Self {
        Failure::Exit(message.into())
    }
    pub fn raised(type_name: &str, message: impl Into<String>) -> Self {
        Failure::Raised { type_name: type_name.into(), message: message.into() }
    }
    pub fn runtime(message: impl Into<String>) -> Self {
        Self::raised("RuntimeError", message)
    }
    /// Print to stderr and return the exit status.
    pub fn report(&self) -> i32 {
        match self {
            Failure::Exit(message) => eprintln!("{}", message),
            Failure::Raised { type_name, message } if message.is_empty() => eprintln!("{}", type_name),
            Failure::Raised { type_name, message } => eprintln!("{}: {}", type_name, message),
        }
        1
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Exit(message) => f.write_str(message),
            Failure::Raised { type_name, message } => write!(f, "{}: {}", type_name, message),
        }
    }
}

impl From<mirra_core::Error> for Failure {
    fn from(error: mirra_core::Error) -> Self {
        Failure::Raised { type_name: error.type_name(), message: error.to_string() }
    }
}

impl From<mirra_bridge::Error> for Failure {
    fn from(error: mirra_bridge::Error) -> Self {
        Failure::Raised { type_name: error.type_name(), message: error.to_string() }
    }
}

impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        mirra_core::Error::Os(error).into()
    }
}

impl From<mirra_bridge::CertificateError> for Failure {
    fn from(error: mirra_bridge::CertificateError) -> Self {
        Failure::raised("CertificateError", error.message)
    }
}

/// Writes one stdout event line (`print(json.dumps(event), flush=True)`).
pub type Emit = Arc<dyn Fn(&Value) + Send + Sync>;

/// [`mirra_core::lifetime::emit_event`] on fd 1.
pub fn stdout_events() -> Emit {
    Arc::new(|event| {
        let _ = mirra_core::lifetime::emit_event(event);
    })
}

/// Python `KeyError(key)` text for a missing JSON field.
pub fn key_error(key: &str) -> Failure {
    Failure::raised("KeyError", mirra_core::pyfmt::repr_str(key))
}
