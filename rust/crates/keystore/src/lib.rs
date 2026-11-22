//! mirra-keystore: the AKS broker and the sharingd adapter controller.
//!
//! Behavioral port of `scripts/keystore.py` ([`keystore::AksBroker`]),
//! `scripts/broker.py` ([`broker::broker_main`]), `scripts/sharingd.py`
//! ([`sharingd::SharingdAgent`]) and `scripts/sharing.py`
//! ([`sharing::sharing_main`]). Files, socket frames and stdout events keep
//! the Python byte formats, so a Rust service can adopt a sharingd detached
//! by the Python service and vice versa.

// `mirra_bridge::Error` (owned by mirra-bridge) is large; boxing it here would
// only convert at every call into the bridge.
#![allow(clippy::result_large_err)]

pub mod args;
pub mod failure;
pub mod broker;
pub mod keystore;
pub mod plist;
pub mod sharing;
pub mod sharingd;
pub mod signals;
pub mod util;

pub use broker::broker_main;
pub use keystore::{AksBroker, Backend};
pub use sharing::sharing_main;
pub use sharingd::SharingdAgent;
