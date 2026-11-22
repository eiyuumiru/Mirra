//! mirra-service: the runtime/control layer of the Mirra background service.
//!
//! Behavioral port of `scripts/backend.py`, `readiness.py`, `control.py`,
//! `preflight.py`, `observe.py`, `diagnostics.py`, `logstream.py` and the
//! runtime subset of `installation.py`, plus `supervisor.py` ([`supervisor`])
//! and the service session `native.py` ([`native`]). Setup, provisioning and package
//! installation stay in Python; see [`control`] and [`observe`] for how
//! those requests are routed.
//!
//! Entry functions take the arguments after the subcommand and return the
//! process exit status:
//!
//! | `mirra-cli` subcommand | entry |
//! |---|---|
//! | `control ARGS`, `setup ARGS` | [`observe::observe_main`] (`["control", ...]` / `["setup", ...]`) |
//! | `__control ARGS` (hidden) | [`control::control_main`] |
//! | `__backend ARGS` (hidden) | [`backend::backend_main`] |
//! | `run-service` | [`native::native_main`] (fixed arguments, in-process) |
//! | `diagnostics ARGS` | [`diagnostics::diagnostics_main`] |
//! | `logstream ARGS` | [`logstream::logstream_main`] |

pub mod backend;
pub mod cli;
pub mod control;
pub mod diagnostics;
pub mod error;
pub mod installation;
pub mod logstream;
pub mod native;
pub mod observe;
pub mod preflight;
pub mod readiness;
pub mod reset;
pub mod sharingd;
pub mod signals;
pub mod supervisor;
pub mod supervisor_lease;
pub mod util;

#[cfg(test)]
pub(crate) mod testing;

pub use backend::backend_main;
pub use control::{control_main, ControlDispatch};
pub use diagnostics::diagnostics_main;
pub use error::{Error, Result};
pub use logstream::logstream_main;
pub use native::native_main;
pub use observe::observe_main;
