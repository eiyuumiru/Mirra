//! mirra-bridge: the bridge-communication layer of the background service.
//!
//! Behavioral port of `scripts/bridgeclient.py` (TLS-PSK HTTP + WebSocket
//! client), `usbmux.py`, `wire.py`, `transport.py` (the bounded JSON session),
//! `bridgepaths.py`, `certificates.py`, plus the parts of `provisioning.py`
//! (`RemoteSetupError`, `certificate_from_service`) and `keystore.py`
//! (`bridge_capabilities`) that those modules need.
//!
//! Errors keep Python's `str(error)`, `type(error).__name__` and `.code`
//! values because they reach logs, state files and the app.

pub mod bridgeclient;
pub mod bridgepaths;
pub mod certificates;
pub mod error;
pub mod keystore;
pub mod plist;
pub mod provisioning;
pub(crate) mod pyutil;
pub mod transport;
pub mod usbmux;
pub mod wire;

#[cfg(test)]
pub(crate) mod testing;

pub use error::{BridgeError, CertificateError, EndpointError, Error, Result};
