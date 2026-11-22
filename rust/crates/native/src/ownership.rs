//! Private journal for recovering an abandoned, app-specific launch adapter
//! (port of `scripts/ownership.py`). The journal lives at
//! `~/Library/Caches/Mirra/launch.json`, shared with the Python service.
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use mirra_core::paths::resolve;
use mirra_core::state::named_temporary;
use mirra_core::{sys, Error, Result};
use serde_json::{json, Map, Value};

use crate::util::{self, BirthProbe};

pub struct LaunchOwnerJournal {
    pub runtime_root: PathBuf,
    pub path: PathBuf,
    birth: BirthProbe,
}

impl LaunchOwnerJournal {
    pub fn new(runtime_root: &Path) -> Self {
        Self::with_home(runtime_root, &util::home())
    }

    /// Journal under `<home>/Library/Caches/Mirra/launch.json`.
    pub fn with_home(runtime_root: &Path, home: &Path) -> Self {
        LaunchOwnerJournal { runtime_root: resolve(runtime_root), path: home.join("Library/Caches/Mirra/launch.json"),
            birth: util::real_birth() }
    }

    /// Replace `process_birth` (tests).
    pub fn with_birth_probe(mut self, birth: BirthProbe) -> Self {
        self.birth = birth;
        self
    }

    pub fn read(&self) -> Result<Option<Map<String, Value>>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let info = sys::lstat(&self.path).map_err(|e| Error::with_path(e, &self.path))?;
        if !sys::private_owned(&info, false) {
            return Err(Error::runtime("Launch ownership journal has unexpected permissions"));
        }
        let Value::Object(data) = util::read_json(&self.path)? else {
            return Err(Error::runtime("Invalid launch ownership journal"));
        };
        let directory = match data.get("directory") {
            None => Some(resolve(Path::new(""))),
            Some(Value::String(text)) => Some(resolve(Path::new(text))),
            Some(_) => None,
        };
        let inside = directory.as_ref().is_some_and(|d| {
            d.parent() == Some(self.runtime_root.as_path())
                && d.file_name().is_some_and(|n| n.to_string_lossy().starts_with("native-"))
        });
        if !util::eq_int(data.get("schema_version"), 1) || !inside {
            return Err(Error::runtime("Launch ownership journal is outside this runtime directory"));
        }
        let valid = match data.get("owner_birth") {
            Some(Value::Array(birth)) if birth.len() == 4 => {
                let numbers: Vec<Option<i64>> = birth.iter().map(|v| util::strict_int(Some(v))).collect();
                numbers.iter().all(Option::is_some) && numbers[0].unwrap() > 0 && numbers[1].unwrap() == sys::getuid() as i64
            }
            _ => false,
        };
        if !valid {
            return Err(Error::runtime("Launch ownership journal has an invalid process identity"));
        }
        Ok(Some(data))
    }

    /// The journal of a controller that is no longer running; an
    /// observation error does not authorize recovery.
    pub fn abandoned(&self) -> Result<Option<Map<String, Value>>> {
        let Some(data) = self.read()? else { return Ok(None) };
        let recorded = &data["owner_birth"];
        let current = (self.birth)(recorded[0].as_i64().unwrap_or(0) as i32)?;
        if let Some(current) = current {
            if mirra_core::retention::birth_json(&current) == *recorded {
                return Err(Error::runtime("The existing native launch controller is still running"));
            }
        }
        Ok(Some(data))
    }

    pub fn publish(&self, directory: &Path, environment: &Map<String, Value>) -> Result<()> {
        if self.path.exists() {
            return Err(Error::runtime("Previous launch ownership must be resolved first"));
        }
        let Some(birth) = (self.birth)(util::own_pid())? else {
            return Err(Error::runtime("Cannot record the current controller identity"));
        };
        let data = json!({"schema_version": 1, "owner_birth": mirra_core::retention::birth_json(&birth),
            "directory": util::text(&resolve(directory)),
            "helper_socket": environment.get("MIRRA_BIND_SOCKET").cloned().unwrap_or(Value::Null)});
        let parent = self.path.parent().unwrap();
        util::mkdir_private(parent)?;
        let (file, pending) = named_temporary(parent, ".launch-owner-").map_err(|e| Error::with_path(e, parent))?;
        let mut text = mirra_core::pyjson::dumps(&data);
        text.push('\n');
        sys::write_all(file.as_raw_fd(), text.as_bytes())?;
        sys::fsync(file.as_raw_fd())?;
        drop(file);
        std::fs::rename(&pending, &self.path).map_err(|e| Error::with_path(e, &pending))
    }

    pub fn clear(&self, directory: &Path) -> Result<()> {
        if let Some(data) = self.read()? {
            let recorded = resolve(Path::new(data["directory"].as_str().unwrap_or("")));
            if recorded != resolve(directory) {
                return Err(Error::runtime("Refusing to remove another controller's ownership journal"));
            }
            std::fs::remove_file(&self.path).map_err(|e| Error::with_path(e, &self.path))?;
        }
        Ok(())
    }
}

/// Remove only the validated socket/alias directories created by native
/// support (`/tmp/mb-*/c -> <container>/mb-*`, socket `s`).
pub fn cleanup_abandoned_socket(value: Option<&str>) -> Result<()> {
    cleanup_abandoned_socket_in(value, &util::home())
}

pub fn cleanup_abandoned_socket_in(value: Option<&str>, home: &Path) -> Result<()> {
    let Some(value) = value.filter(|v| !v.is_empty()) else { return Ok(()) };
    let address = Path::new(value);
    let alias = address.parent().unwrap_or(Path::new(""));
    let short = alias.parent().unwrap_or(Path::new(""));
    let container = resolve(&home.join("Library/Containers/com.apple.ScreenContinuity/Data/tmp"));
    let name = |p: &Path| p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if name(address) != "s" || name(alias) != "c" || resolve(short.parent().unwrap_or(Path::new(""))) != resolve(Path::new("/tmp"))
        || !name(short).starts_with("mb-") {
        return Err(Error::runtime("Abandoned helper path is not a managed socket"));
    }
    if std::fs::metadata(short).is_err() {
        return Ok(());
    }
    let is_link = |p: &Path| sys::lstat(p).map(|i| sys::is_lnk(i.st_mode)).unwrap_or(false);
    let owner = |p: &Path| sys::stat(p).map(|i| i.st_uid).map_err(|e| Error::with_path(e, p));
    if is_link(short) || owner(short)? != sys::getuid() {
        return Err(Error::runtime("Abandoned helper directory ownership changed"));
    }
    let rmdir = |p: &Path| std::fs::remove_dir(p).map_err(|e| Error::with_path(e, p));
    if !is_link(alias) {
        if std::fs::metadata(alias).is_err() {
            return rmdir(short);
        }
        return Err(Error::runtime("Abandoned helper alias is not a symlink"));
    }
    let private = resolve(alias);
    if private.parent() != Some(container.as_path()) || !name(&private).starts_with("mb-") {
        return Err(Error::runtime("Abandoned helper alias points outside the app container"));
    }
    if std::fs::metadata(&private).is_ok() {
        if is_link(&private) || owner(&private)? != sys::getuid() {
            return Err(Error::runtime("Abandoned helper container ownership changed"));
        }
        let socket = private.join("s");
        if std::fs::metadata(&socket).is_ok() {
            let info = sys::lstat(&socket).map_err(|e| Error::with_path(e, &socket))?;
            if !sys::is_sock(info.st_mode) || info.st_uid != sys::getuid() {
                return Err(Error::runtime("Abandoned helper path is not an owned socket"));
            }
            std::fs::remove_file(&socket).map_err(|e| Error::with_path(e, &socket))?;
        }
        rmdir(&private)?;
    }
    std::fs::remove_file(alias).map_err(|e| Error::with_path(e, alias))?;
    rmdir(short)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    type Observed = Arc<Mutex<Result<Option<(i32, u32, u64, u64)>, String>>>;

    struct Fixture {
        _temp: tempfile::TempDir,
        root: PathBuf,
        directory: PathBuf,
        journal: LaunchOwnerJournal,
        birth: Observed,
    }

    fn fixture() -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        let directory = root.join("runtime/native-test");
        std::fs::create_dir_all(&directory).unwrap();
        let birth = Arc::new(Mutex::new(Ok(Some((util::own_pid(), sys::getuid(), 100, 1)))));
        let probe = birth.clone();
        let journal = LaunchOwnerJournal::with_home(&root.join("runtime"), &root).with_birth_probe(Arc::new(move |_| {
            probe.lock().unwrap().clone().map_err(|m| Error::os_message(libc::EIO, m))
        }));
        journal.publish(&directory, &Map::new()).unwrap();
        Fixture { _temp: temp, root, directory, journal, birth }
    }

    #[test]
    fn live_controller_cannot_be_recovered() {
        let f = fixture();
        let error = f.journal.abandoned().unwrap_err();
        assert!(error.to_string().contains("still running"));
        assert!(f.journal.path.exists());
        let text = std::fs::read_to_string(&f.journal.path).unwrap();
        assert!(text.starts_with("{\"schema_version\": 1, \"owner_birth\": ["), "{}", text);
        assert!(text.ends_with("\"helper_socket\": null}\n"));
    }

    #[test]
    fn reused_pid_is_distinguished_from_the_original_owner() {
        let f = fixture();
        *f.birth.lock().unwrap() = Ok(Some((util::own_pid(), sys::getuid(), 200, 2)));
        let data = f.journal.abandoned().unwrap().unwrap();
        assert_eq!(data["directory"], util::text(&resolve(&f.directory)));
    }

    #[test]
    fn observation_error_does_not_authorize_recovery() {
        let f = fixture();
        *f.birth.lock().unwrap() = Err("temporary observation failure".into());
        assert!(f.journal.abandoned().unwrap_err().is_os_error());
        assert!(f.journal.path.exists());
    }

    #[test]
    fn wrong_runtime_directory_is_rejected() {
        let f = fixture();
        let mut data = util::read_json(&f.journal.path).unwrap();
        data["directory"] = Value::from(util::text(&f.root.join("unrelated")));
        std::fs::write(&f.journal.path, mirra_core::pyjson::dumps(&data)).unwrap();
        util::chmod(&f.journal.path, 0o600).unwrap();
        assert!(f.journal.abandoned().unwrap_err().to_string().contains("outside"));
    }

    #[test]
    fn clear_refuses_another_directory_and_publish_refuses_existing() {
        let f = fixture();
        assert!(f.journal.publish(&f.directory, &Map::new()).is_err());
        assert!(f.journal.clear(&f.root.join("runtime/native-other")).is_err());
        f.journal.clear(&f.directory).unwrap();
        assert!(!f.journal.path.exists());
    }

    #[test]
    fn abandoned_socket_paths_are_validated_before_removal() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        assert!(cleanup_abandoned_socket_in(Some("/tmp/other/c/s"), home).is_err());
        assert!(cleanup_abandoned_socket_in(Some("/var/mb-x/c/s"), home).is_err());
        cleanup_abandoned_socket_in(None, home).unwrap();
        // A missing short directory is already clean.
        cleanup_abandoned_socket_in(Some("/tmp/mb-mirra-test-absent-0/c/s"), home).unwrap();
        let container = home.join("Library/Containers/com.apple.ScreenContinuity/Data/tmp");
        std::fs::create_dir_all(&container).unwrap();
        let private = container.join("mb-test");
        std::fs::create_dir(&private).unwrap();
        let short = tempfile::Builder::new().prefix("mb-").tempdir_in("/tmp").unwrap().keep();
        std::os::unix::fs::symlink(&private, short.join("c")).unwrap();
        // Bound through the short alias, as native support does (sun_path limit).
        let listener = std::os::unix::net::UnixListener::bind(short.join("c/s")).unwrap();
        assert!(private.join("s").exists());
        cleanup_abandoned_socket_in(Some(&format!("{}/c/s", short.display())), home).unwrap();
        drop(listener);
        assert!(!private.exists());
        assert!(!short.exists());
        // An alias pointing outside the container is preserved.
        let short = tempfile::Builder::new().prefix("mb-").tempdir_in("/tmp").unwrap().keep();
        std::os::unix::fs::symlink(home, short.join("c")).unwrap();
        assert!(cleanup_abandoned_socket_in(Some(&format!("{}/c/s", short.display())), home).is_err());
        std::fs::remove_file(short.join("c")).unwrap();
        std::fs::remove_dir(&short).unwrap();
    }
}
