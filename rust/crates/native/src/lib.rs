//! mirra-native: low-level native-session modules of the background service.
//!
//! Behavioral ports of `scripts/startup.py`, `launcher.py`, `ownership.py`,
//! `sockets.py`, `decoder.py`, `decoder_route.py`, `hardware.py`,
//! `macho.py` and `compatibility.py`, plus a minimal `plistlib` equivalent.
//! Journals, locks and state files use the same paths and JSON keys as the
//! Python service so either implementation can recover the other's session.

pub mod compatibility;
pub mod decoder;
pub mod decoder_route;
pub mod hardware;
pub mod launcher;
pub mod macho;
pub mod ownership;
pub mod plist;
pub mod sockets;
pub mod startup;
mod util;

pub use decoder_route::{guardian_main, GUARDIAN_SUBCOMMAND};
