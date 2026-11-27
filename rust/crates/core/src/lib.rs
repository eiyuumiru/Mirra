//! mirra-core: shared foundation for the Mirra background service.
//!
//! Behavioral port of the Python helper modules in `scripts/`: configuration,
//! state, lifetime, redaction, logfiles, activity, logs, processes, retention,
//! workspace and health, plus small Python-compatibility helpers (JSON
//! formatting, shell quoting, path resolution) that later crates rely on.

pub mod activity;
pub mod config;
pub mod error;
pub mod event;
pub mod health;
pub mod launchctl;
pub mod lifetime;
pub mod logfiles;
pub mod logs;
pub mod paths;
pub mod processes;
pub mod pyfmt;
pub mod pyjson;
pub mod redaction;
pub mod retention;
pub mod shlex;
pub mod state;
pub mod subprocess;
pub mod sys;
pub mod workspace;

pub use error::{Error, Result};
