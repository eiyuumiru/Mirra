//! Private broker sockets/certificates with a lease inherited by their users.
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::state::write_state;
use crate::sys;

pub const RECORD: &str = "broker-workspace.json";
pub const LEASE: &str = ".lease";
pub const FILES: [&str; 3] = [LEASE, "broker.sock", "certificate.der"];

pub struct BrokerWorkspace {
    pub path: PathBuf,
    lease: Option<OwnedFd>,
}

impl BrokerWorkspace {
    /// Create `/tmp/mirra-XXXXXXXX` (0700) holding an exclusively locked
    /// lease, and record it in `<runtime>/broker-workspace.json`.
    pub fn new(runtime: &Path) -> Result<Self> {
        let template = CString::new("/tmp/mirra-XXXXXXXX").unwrap();
        let mut buffer = template.into_bytes_with_nul();
        if unsafe { libc::mkdtemp(buffer.as_mut_ptr().cast()) }.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        let path = PathBuf::from(CStr::from_bytes_with_nul(&buffer).unwrap().to_str().unwrap());
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        let lease_path = path.join(LEASE);
        let lease = sys::open(&lease_path, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, 0o600)
            .map_err(|e| Error::with_path(e, &lease_path))?;
        sys::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB)?;
        let info = sys::stat(&path)?;
        write_state(&runtime.join(RECORD), &json!({"schema_version": 1,
            "path": path.to_string_lossy(), "device": info.st_dev, "inode": info.st_ino}))?;
        Ok(BrokerWorkspace { path, lease: Some(lease) })
    }

    /// The lease descriptor (close-on-exec; children inheriting it must clear
    /// FD_CLOEXEC, like Python's `pass_fds`). `None` once closed.
    pub fn lease_fd(&self) -> Option<RawFd> {
        self.lease.as_ref().map(AsRawFd::as_raw_fd)
    }

    /// Do not LOCK_UN: children share the lease's open-file description.
    pub fn close(&mut self) {
        self.lease = None;
    }
}

fn unexpected(message: &str) -> Error {
    Error::runtime(message)
}

/// Remove the recorded workspace unless its lease is still held. Returns
/// `{"removed": true}` or `{"removed": false, "reason": "untracked"|"already_absent"|"lease_in_use"}`.
/// Caller first restores sharingd; a live lease always prevents removal.
pub fn cleanup(runtime: &Path) -> Result<Value> {
    let record = runtime.join(RECORD);
    if !record.exists() {
        return Ok(json!({"removed": false, "reason": "untracked"}));
    }
    let info = sys::lstat(&record).map_err(|e| Error::with_path(e, &record))?;
    if !sys::private_owned(&info, false) {
        return Err(unexpected("Broker workspace record is not a private owned file"));
    }
    let data = std::fs::read(&record).map_err(|e| Error::with_path(e, &record))?;
    let value: Value = serde_json::from_slice(&data).map_err(|e| Error::value(e.to_string()))?;
    let path = PathBuf::from(value.get("path").and_then(Value::as_str).unwrap_or(""));
    let parent = path.parent().map(Path::to_path_buf).filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| PathBuf::from("."));
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if value.get("schema_version") != Some(&json!(1)) || crate::paths::resolve(&parent) != crate::paths::resolve(Path::new("/tmp"))
        || !name.starts_with("mirra-") {
        return Err(unexpected("Unexpected broker workspace path"));
    }
    if !path.exists() {
        return Ok(json!({"removed": false, "reason": "already_absent"}));
    }
    let info = sys::lstat(&path).map_err(|e| Error::with_path(e, &path))?;
    if !sys::private_owned(&info, true) || value.get("device") != Some(&json!(info.st_dev))
        || value.get("inode") != Some(&json!(info.st_ino)) {
        return Err(unexpected("Broker workspace ownership changed"));
    }
    let lease_path = path.join(LEASE);
    let descriptor = sys::open(&lease_path, libc::O_RDWR | libc::O_NOFOLLOW, 0).map_err(|e| Error::with_path(e, &lease_path))?;
    match sys::flock(descriptor.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) {
        Err(e) if e.raw_os_error() == Some(libc::EWOULDBLOCK) => {
            return Ok(json!({"removed": false, "reason": "lease_in_use"}));
        }
        other => other?,
    }
    let entries: Vec<PathBuf> = std::fs::read_dir(&path)?.map(|e| e.map(|e| e.path())).collect::<std::io::Result<_>>()?;
    for entry in &entries {
        let info = sys::lstat(entry).map_err(|e| Error::with_path(e, entry))?;
        let name = entry.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let kind = if name == "broker.sock" { sys::is_sock(info.st_mode) } else { sys::is_reg(info.st_mode) };
        if !FILES.contains(&name) || !kind || info.st_uid != sys::getuid() || info.st_mode & 0o077 != 0 {
            return Err(unexpected("Broker workspace contains an unexpected entry"));
        }
    }
    // Lease is removed last so an interrupted cleanup can still be retried.
    for entry in &entries {
        if entry.file_name().and_then(|n| n.to_str()) != Some(LEASE) {
            std::fs::remove_file(entry).map_err(|e| Error::with_path(e, entry))?;
        }
    }
    std::fs::remove_file(&lease_path).map_err(|e| Error::with_path(e, &lease_path))?;
    std::fs::remove_dir(&path).map_err(|e| Error::with_path(e, &path))?;
    drop(descriptor);
    Ok(json!({"removed": true}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::sync::Mutex;

    // A fork (pre_exec) briefly duplicates every open lease; serialize the
    // tests so one test's child cannot hold the other's lease description.
    static SERIAL: Mutex<()> = Mutex::new(());

    #[test]
    fn inherited_child_lease_survives_parent_close() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let mut workspace = BrokerWorkspace::new(root).unwrap();
        write_state(&workspace.path.join("certificate.der"), &json!({"fixture": true})).unwrap();
        let lease = workspace.lease_fd().unwrap();
        let mut command = Command::new("/bin/cat");
        command.stdin(Stdio::piped()).stdout(Stdio::null());
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(lease, libc::F_GETFD);
                libc::fcntl(lease, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        workspace.close();
        assert_eq!(cleanup(root).unwrap()["reason"], "lease_in_use");
        assert!(workspace.path.join("certificate.der").exists());
        drop(child.stdin.take());
        child.wait().unwrap();
        assert_eq!(cleanup(root).unwrap()["removed"], true);
        assert!(!workspace.path.exists());
        assert_eq!(cleanup(root).unwrap()["reason"], "already_absent");
    }

    #[test]
    fn unexpected_file_prevents_any_removal() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let mut workspace = BrokerWorkspace::new(root).unwrap();
        workspace.close();
        let unexpected = workspace.path.join("user-file");
        std::fs::write(&unexpected, "preserve").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&unexpected, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(cleanup(root).unwrap_err().to_string(), "Broker workspace contains an unexpected entry");
        assert!(unexpected.exists());
        std::fs::remove_file(&unexpected).unwrap();
        assert_eq!(cleanup(root).unwrap()["removed"], true);
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(cleanup(empty.path()).unwrap()["reason"], "untracked");
    }
}
