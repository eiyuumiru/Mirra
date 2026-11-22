//! Bound diagnostic append logs, retaining one tail backup per file.
//!
//! Rotation uses copy-and-truncate on the existing inode. This may lose a line
//! written during rotation; these files must never carry protocol or state data.
//! The live file is inspected once per second, so bursts can exceed the threshold
//! until the next inspection. Native writers must prove O_APPEND before use.
use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::error::{Error, Result};
use crate::event::Event;
use crate::sys;

/// `open(path, O_WRONLY|O_CREAT|O_EXCL|O_APPEND, 0o600)` as a `File`.
pub fn open_append(path: &Path) -> std::io::Result<File> {
    sys::open(path, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_APPEND, 0o600).map(File::from)
}

/// `proc_pidfdinfo(PROC_PIDFDVNODEINFO)`: whether a native descriptor uses O_APPEND.
pub fn native_fd_is_append(pid: i32, fd: i32) -> Result<bool> {
    let mut buffer = vec![0u8; 4096];
    let count = unsafe { libc::proc_pidfdinfo(pid, fd, 1, buffer.as_mut_ptr().cast(), buffer.len() as i32) };
    if count < 24 {
        return Err(Error::last_os("Cannot inspect native diagnostic descriptor"));
    }
    // proc_fileinfo is the first member; fi_openflags is uint32_t.
    let flags = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    Ok(flags & libc::O_APPEND as u32 != 0)
}

struct Entry {
    path: PathBuf,
    fd: OwnedFd,
    inode: u64,
    device: i64,
    rotations: u64,
}

struct Inner {
    limit: u64,
    entries: Mutex<Vec<Entry>>,
    error: Mutex<Option<String>>,
}

impl Inner {
    fn rotate_if_needed(&self) -> Result<()> {
        let mut entries = self.entries.lock().unwrap();
        for entry in entries.iter_mut() {
            let current = sys::lstat(&entry.path).map_err(|e| Error::with_path(e, &entry.path))?;
            if (current.st_dev as i64, current.st_ino) != (entry.device, entry.inode) {
                return Err(Error::runtime("Diagnostic path changed during the session"));
            }
            let size = sys::fstat(entry.fd.as_raw_fd())?.st_size as u64;
            if size <= self.limit {
                continue;
            }
            let tail = sys::pread(entry.fd.as_raw_fd(), self.limit as usize, size - self.limit)?;
            let parent = entry.path.parent().unwrap_or(Path::new("."));
            let (temporary, replacement) = crate::state::named_temporary(parent, ".log-rotation-")?;
            sys::write_all(temporary.as_raw_fd(), &tail)?;
            sys::fsync(temporary.as_raw_fd())?;
            drop(temporary);
            let mut backup = entry.path.file_name().unwrap_or_default().to_os_string();
            backup.push(".1");
            std::fs::rename(&replacement, entry.path.with_file_name(backup))?;
            sys::ftruncate(entry.fd.as_raw_fd(), 0)?;
            entry.rotations += 1;
        }
        Ok(())
    }
}

pub type ErrorCallback = Box<dyn Fn() + Send + Sync>;

/// Background (1 s) size enforcement for watched append logs.
pub struct BoundedLogs {
    inner: Arc<Inner>,
    stop: Event,
    finished: Option<mpsc::Receiver<()>>,
}

impl BoundedLogs {
    /// Default limit is 2 MiB (`BoundedLogs()` in Python).
    pub fn new(limit: u64, on_error: Option<ErrorCallback>) -> Result<Self> {
        if limit < 1024 {
            return Err(Error::value("Log limit must be at least 1024 bytes"));
        }
        let inner = Arc::new(Inner { limit, entries: Mutex::new(Vec::new()), error: Mutex::new(None) });
        let stop = Event::new();
        let (done, finished) = mpsc::channel::<()>();
        let (worker, flag) = (inner.clone(), stop.clone());
        std::thread::Builder::new().name("diagnostic-log-limits".into()).spawn(move || {
            let _done = done;
            while !flag.wait(Some(Duration::from_secs(1))) {
                if let Err(error) = worker.rotate_if_needed() {
                    if error.is_os_error() || matches!(error, Error::Runtime(_)) {
                        *worker.error.lock().unwrap() = Some(error.to_string());
                        if let Some(callback) = &on_error {
                            callback();
                        }
                        return;
                    }
                }
            }
        })?;
        Ok(BoundedLogs { inner, stop, finished: Some(finished) })
    }

    pub fn default_limit() -> Result<Self> {
        Self::new(2 * 1024 * 1024, None)
    }

    pub fn limit(&self) -> u64 {
        self.inner.limit
    }

    /// Error recorded by the background thread, if any.
    pub fn error(&self) -> Option<String> {
        self.inner.error.lock().unwrap().clone()
    }

    fn watch(&self, path: &Path) -> Result<()> {
        let descriptor = sys::open(path, libc::O_RDWR | libc::O_APPEND | libc::O_NOFOLLOW, 0).map_err(|e| Error::with_path(e, path))?;
        let info = sys::fstat(descriptor.as_raw_fd())?;
        if !sys::is_reg(info.st_mode) || info.st_uid != sys::getuid() {
            return Err(Error::value("Diagnostic log must be a regular file owned by this user"));
        }
        let mut entries = self.inner.entries.lock().unwrap();
        if entries.iter().any(|e| e.path == path) {
            return Ok(());
        }
        entries.push(Entry { path: path.to_path_buf(), fd: descriptor, inode: info.st_ino, device: info.st_dev as i64, rotations: 0 });
        Ok(())
    }

    /// Watch `path` written by this process through `stream` (must be O_APPEND).
    pub fn watch_stream(&self, path: &Path, stream: &impl AsRawFd) -> Result<()> {
        self.watch_fd(path, stream.as_raw_fd())
    }

    pub fn watch_fd(&self, path: &Path, fd: RawFd) -> Result<()> {
        if sys::fcntl_getfl(fd)? & libc::O_APPEND == 0 {
            return Err(Error::value("Diagnostic writer must use O_APPEND"));
        }
        self.watch(path)
    }

    /// Watch `path` written by descriptor `fd` of native process `pid`.
    pub fn watch_native(&self, path: &Path, pid: i32, fd: i32) -> Result<()> {
        if !native_fd_is_append(pid, fd)? {
            return Err(Error::value("Native diagnostic writer does not use O_APPEND"));
        }
        self.watch(path)
    }

    pub fn rotate_if_needed(&self) -> Result<()> {
        self.inner.rotate_if_needed()
    }

    /// Stop maintenance, rotate once more, close descriptors and report
    /// `{"limit_bytes_per_file", "backups_per_file": 1, "rotations": {name: n}, "error"}`
    /// (or `{"error": "Diagnostic log maintenance did not stop"}`).
    pub fn close(&mut self) -> Value {
        self.stop.set();
        if let Some(finished) = self.finished.take() {
            if let Err(mpsc::RecvTimeoutError::Timeout) = finished.recv_timeout(Duration::from_secs(5)) {
                let message = "Diagnostic log maintenance did not stop".to_string();
                *self.inner.error.lock().unwrap() = Some(message.clone());
                return json!({"error": message});
            }
        }
        if let Err(error) = self.inner.rotate_if_needed() {
            *self.inner.error.lock().unwrap() = Some(error.to_string());
        }
        let mut entries = self.inner.entries.lock().unwrap();
        let mut rotations = Map::new();
        for entry in entries.iter() {
            rotations.insert(entry.path.file_name().unwrap_or_default().to_string_lossy().into_owned(), Value::from(entry.rotations));
        }
        entries.clear();
        json!({"limit_bytes_per_file": self.inner.limit, "backups_per_file": 1,
            "rotations": rotations, "error": *self.inner.error.lock().unwrap()})
    }
}

impl Drop for BoundedLogs {
    fn drop(&mut self) {
        self.stop.set();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn rotation_preserves_writer_inode_and_new_writes_append_without_holes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("diagnostics.log");
        let mut manager = BoundedLogs::new(1024, None).unwrap();
        let mut writer = open_append(&path).unwrap();
        manager.watch_stream(&path, &writer).unwrap();
        let inode = writer.metadata().unwrap().ino();
        writer.write_all(&[b"a".repeat(2048), b"last\n".to_vec()].concat()).unwrap();
        manager.rotate_if_needed().unwrap();
        writer.write_all(b"next\n").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"next\n");
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
        let backup = std::fs::read(temp.path().join("diagnostics.log.1")).unwrap();
        assert_eq!(backup.len(), 1024);
        assert!(backup.ends_with(b"last\n"));
        let report = manager.close();
        assert_eq!(report, json!({"limit_bytes_per_file": 1024, "backups_per_file": 1,
            "rotations": {"diagnostics.log": 1}, "error": null}));
    }

    #[test]
    fn nonappend_writer_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let mut manager = BoundedLogs::new(1024, None).unwrap();
        let path = temp.path().join("wrong.log");
        let writer = File::create(&path).unwrap();
        let error = manager.watch_stream(&path, &writer).unwrap_err();
        assert!(error.to_string().contains("O_APPEND"));
        assert_eq!(error.type_name(), "ValueError");
        manager.close();
        assert!(BoundedLogs::new(1023, None).is_err());
    }

    #[test]
    fn replaced_path_is_not_truncated() {
        let temp = tempfile::tempdir().unwrap();
        let mut manager = BoundedLogs::new(1024, None).unwrap();
        let path = temp.path().join("original.log");
        let writer = open_append(&path).unwrap();
        manager.watch_stream(&path, &writer).unwrap();
        std::fs::rename(&path, temp.path().join("original.old")).unwrap();
        std::fs::write(&path, "replacement".repeat(200)).unwrap();
        let error = manager.rotate_if_needed().unwrap_err();
        assert!(error.to_string().contains("path changed"));
        assert_eq!(error.type_name(), "RuntimeError");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "replacement".repeat(200));
        assert_eq!(manager.close()["error"], "Diagnostic path changed during the session");
    }

    #[test]
    fn own_descriptor_reports_append_through_proc_info() {
        let temp = tempfile::tempdir().unwrap();
        let appending = open_append(&temp.path().join("a.log")).unwrap();
        let plain = File::create(temp.path().join("b.log")).unwrap();
        let pid = std::process::id() as i32;
        assert!(native_fd_is_append(pid, appending.as_raw_fd()).unwrap());
        assert!(!native_fd_is_append(pid, plain.as_raw_fd()).unwrap());
    }
}
