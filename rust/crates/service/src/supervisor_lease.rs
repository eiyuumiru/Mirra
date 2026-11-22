//! `backend_lease`, `backend_children_stopped` and `detached_sharingd_pid`
//! from `scripts/supervisor.py`, shared by `NativeService.stop` and the
//! supervisor port.
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;

use mirra_core::sys;
use serde_json::Value;

use crate::error::{Error, Result};
use crate::sharingd::Sharingd;
use crate::util::{self, strict_int, BirthProbe};

/// The held `~/Library/Caches/Mirra/session.lock`; released on drop.
#[derive(Debug)]
pub struct BackendLease {
    _lock: File,
}

/// `with backend_lease():` — exclude backend startup while inspecting or
/// replacing its runtime. A held lock is `BlockingIOError` (EWOULDBLOCK).
pub fn backend_lease(home: &Path) -> Result<BackendLease> {
    let directory = home.join("Library/Caches/Mirra");
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&directory)
            .map_err(|e| mirra_core::Error::with_path(e, &directory))?;
    }
    let path = directory.join("session.lock");
    let lock = std::fs::OpenOptions::new().append(true).create(true).open(&path)
        .map_err(|e| mirra_core::Error::with_path(e, &path))?;
    sys::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB)?;
    Ok(BackendLease { _lock: lock })
}

/// The injected pid of a detached sharingd adapter, if the journal records one.
pub fn detached_sharingd_pid(sharingd: &dyn Sharingd) -> Option<i64> {
    let record = match sharingd.read_journal() {
        Ok(Some(record)) => record,
        _ => return None,
    };
    if record.get("detached") == Some(&Value::Bool(true)) {
        return strict_int(record.get("injected_pid"));
    }
    None
}

/// Require recorded child identities to have ended before reusing their paths.
pub fn backend_children_stopped(previous: Option<&Path>, sharingd: &dyn Sharingd, birth: &BirthProbe) -> Result<bool> {
    let Some(previous) = previous else { return Ok(true) };
    let path = previous.join("backend-children.json");
    if !path.exists() {
        return Ok(true);
    }
    let record = util::read_json(&path)?;
    let Value::Object(record) = record else {
        return Err(Error::type_error("backend-children.json must be an object"));
    };
    let detached = detached_sharingd_pid(sharingd);
    for (name, identity) in &record {
        if !identity.as_array().is_some_and(|items| items.len() == 4) {
            return Err(Error::value("Invalid backend child identity"));
        }
        // A detached sharingd intentionally outlives its session; the
        // adapter is already mapped and logs to a stable file.
        if name == "sharingd" && detached.is_some() && strict_int(identity.get(0)) == detached {
            continue;
        }
        if util::alive(birth, identity)? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeSharingd;
    use mirra_core::state::write_state;
    use serde_json::json;
    use std::sync::Arc;

    #[test]
    fn lease_is_exclusive() {
        let temp = tempfile::tempdir().unwrap();
        let held = backend_lease(temp.path()).unwrap();
        let error = backend_lease(temp.path()).unwrap_err();
        assert_eq!(error.type_name(), "BlockingIOError");
        drop(held);
        backend_lease(temp.path()).unwrap();
    }

    #[test]
    fn live_children_block_reuse_except_a_detached_sharingd() {
        let temp = tempfile::tempdir().unwrap();
        let uid = sys::getuid();
        write_state(&temp.path().join("backend-children.json"),
            &json!({"broker": [40, uid, 1, 1], "sharingd": [41, uid, 1, 2]})).unwrap();
        let sharingd = FakeSharingd::default();
        let only_sharingd: BirthProbe = Arc::new(move |pid| Ok((pid == 41).then_some((41, uid, 1, 2))));
        assert!(!backend_children_stopped(Some(temp.path()), &sharingd, &only_sharingd).unwrap());
        *sharingd.journal.lock().unwrap() = Some(json!({"detached": true, "injected_pid": 41}).as_object().unwrap().clone());
        assert!(backend_children_stopped(Some(temp.path()), &sharingd, &only_sharingd).unwrap());
        assert!(backend_children_stopped(None, &sharingd, &only_sharingd).unwrap());
        write_state(&temp.path().join("backend-children.json"), &json!({"broker": [40]})).unwrap();
        assert_eq!(backend_children_stopped(Some(temp.path()), &sharingd, &only_sharingd).unwrap_err().to_string(),
            "Invalid backend child identity");
    }
}
