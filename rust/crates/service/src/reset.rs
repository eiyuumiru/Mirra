//! `control reset`: set iPhone Mirroring up from scratch instead of restoring
//! the saved pairing.
//!
//! Normally Mirra keeps an iPhone Mirroring pairing across restarts in four
//! places, and puts it back on every start:
//! 1. the bridge's record of this Mac (keybags, keys and the kept pairing
//!    sessions in `clients/<UUID>.plist`),
//! 2. sharingd's attested local key in the login keychain (restored by the
//!    adapter from `state/attested-ltk.plist`),
//! 3. the paired iPhone's entries in `~/Library/Sharing/AutoUnlock` (restored
//!    from `state/pairing.plist`),
//! 4. the running sharingd, which the next start adopts.
//!
//! A reset stops support, gives sharingd back to Apple, asks the bridge to
//! forget only this Mac (other Macs sharing the bridge keep their pairing),
//! removes the local copies and starts support again. The next connection
//! then creates new keys and the iPhone asks for its passcode to pair again.
use std::path::{Path, PathBuf};
use std::process::Command;

use mirra_bridge::transport::{Endpoint, EndpointOptions};
use mirra_core::config::Config;
use serde_json::{json, Value};

use crate::control::ControlEnv;
use crate::error::{Error, Result};

/// The keychain account of sharingd's attested iPhone Mirroring key.
pub const ATTESTED_ACCOUNT: &str = "com.apple.continuity.auto-unlock.attested";
/// `security` exit status for errSecItemNotFound.
const ITEM_NOT_FOUND: i32 = 44;
/// More copies than this would mean `security` is not making progress.
const MAX_KEYCHAIN_ITEMS: usize = 16;
pub const RESET_MESSAGE: &str = "iPhone Mirroring was reset. Open iPhone Mirroring and choose Connect; \
    the iPhone asks for its passcode once to pair this Mac again.";

/// Mirra's local copies of the pairing, under `~/Library/Application Support/Mirra/state`.
pub fn state_files(home: &Path) -> [PathBuf; 2] {
    let state = home.join("Library/Application Support/Mirra/state");
    [state.join("attested-ltk.plist"), state.join("pairing.plist")]
}

/// Run the reset against `env`. Support is started again even when a step
/// fails, so a half-finished reset never leaves it stopped.
pub fn reset_mirroring(env: &dyn ControlEnv) -> Result<Value> {
    let service = env.service();
    service.validate_package()?;
    let config = env.load_config(&service.package().join("config.json"))?;
    // The bridge must know `forget`; nothing is changed before that is known.
    if let Some(update) = env.bridge_update_report(&config)? {
        return Ok(json!({"ok": false, "message": update["detail"], "report": update}));
    }
    service.stop()?;
    let outcome = (|| -> Result<Value> {
        env.restore_sharingd()?;
        env.forget_bridge(&config)?;
        env.forget_local_pairing()
    })();
    let started = service.start();
    let details = outcome?;
    started?;
    Ok(json!({"ok": true, "message": RESET_MESSAGE, "reset": details, "report": env.observe()}))
}

/// Give sharingd back to Apple, so the next start creates a new process.
pub fn restore_sharingd() -> Result<()> {
    mirra_keystore::sharingd::SharingdAgent::restore_detached()?;
    Ok(())
}

/// Ask the bridge to drop this Mac's saved keys, sessions and record.
pub fn forget_bridge(config: &Config) -> Result<()> {
    let endpoint = Endpoint::open(config, EndpointOptions { saved: true, ..Default::default() })?;
    let reply = endpoint.call("forget", json!({}))?;
    if reply.get("status") == Some(&json!(0)) && reply.get("forgotten") == Some(&Value::Bool(true)) {
        return Ok(());
    }
    let code = reply.get("error").and_then(Value::as_str).unwrap_or("unexpected_reply");
    Err(Error::runtime(format!("The bridge did not forget this Mac: {}", code)))
}

/// Delete every copy of sharingd's attested key from the login keychain.
pub fn delete_attested_keys(security: &mut dyn FnMut() -> std::io::Result<i32>) -> Result<usize> {
    for deleted in 0..=MAX_KEYCHAIN_ITEMS {
        match security()? {
            0 => continue,
            ITEM_NOT_FOUND => return Ok(deleted),
            status => return Err(Error::runtime(format!("security could not delete the attested key (exit {})", status))),
        }
    }
    Err(Error::runtime("security kept finding attested keys"))
}

fn security_delete() -> std::io::Result<i32> {
    let output = Command::new("/usr/bin/security")
        .args(["delete-generic-password", "-a", ATTESTED_ACCOUNT])
        .output()?;
    Ok(output.status.code().unwrap_or(-1))
}

/// Remove the local copies: keychain key, Mirra's backups, AutoUnlock entries.
pub fn forget_local_pairing(home: &Path) -> Result<Value> {
    let keychain = delete_attested_keys(&mut security_delete)?;
    let mut files = 0;
    for path in state_files(home) {
        match std::fs::remove_file(&path) {
            Ok(()) => files += 1,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let pairings = mirra_keystore::sharingd::forget_pairing()?;
    Ok(json!({"keychain_items": keychain, "backup_files": files, "pairing_entries": pairings}))
}

#[cfg(test)]
mod tests;
