//! Test fakes (compiled only for tests).
use std::sync::Mutex;

use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::sharingd::Sharingd;

/// sharingd with a scripted journal, job state and recovery result.
#[derive(Default)]
pub struct FakeSharingd {
    pub journal: Mutex<Option<Map<String, Value>>>,
    pub state: Mutex<Map<String, Value>>,
    pub recovered: Mutex<Option<Value>>,
    pub recover_calls: Mutex<Vec<bool>>,
    /// Recovery fails with this error (journal kept, no call recorded).
    pub recover_error: Option<fn() -> Error>,
}

impl Sharingd for FakeSharingd {
    fn read_journal(&self) -> Result<Option<Map<String, Value>>> {
        Ok(self.journal.lock().unwrap().clone())
    }
    fn recover_abandoned(&self, restore_detached: bool) -> Result<Option<Value>> {
        if let Some(error) = self.recover_error {
            return Err(error());
        }
        self.recover_calls.lock().unwrap().push(restore_detached);
        *self.journal.lock().unwrap() = None;
        Ok(self.recovered.lock().unwrap().clone())
    }
    fn service(&self) -> Result<Map<String, Value>> {
        Ok(self.state.lock().unwrap().clone())
    }
}

/// The Apple sharingd job as `launchctl print` reports it.
pub fn original_sharingd() -> Map<String, Value> {
    serde_json::json!({"path": crate::sharingd::ORIGINAL_PLIST, "program": crate::sharingd::PROGRAM, "injected": false})
        .as_object().unwrap().clone()
}

/// Serializes tests that fork children while broker leases are open: a fork
/// briefly duplicates every descriptor, including another test's lease.
pub static SERIAL: Mutex<()> = Mutex::new(());
