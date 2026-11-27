//! Atomic private state updates; readers never see a partially written record.
use std::ffi::OsString;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::sys;

const CHARACTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789_";

/// Create `dir/<prefix>XXXXXXXX` exclusively with mode 0600, like
/// `tempfile.NamedTemporaryFile(prefix=..., dir=..., delete=False)`.
pub fn named_temporary(directory: &Path, prefix: &str) -> io::Result<(std::fs::File, PathBuf)> {
    let directory = if directory.as_os_str().is_empty() { Path::new(".") } else { directory };
    let mut last = io::Error::from_raw_os_error(libc::EEXIST);
    for _ in 0..10000 {
        let mut name = prefix.as_bytes().to_vec();
        name.extend((0..8).map(|_| CHARACTERS[sys::random_below(CHARACTERS.len() as u32) as usize]));
        let path = directory.join(OsString::from_vec(name));
        match sys::open(&path, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW, 0o600) {
            Ok(fd) => return Ok((std::fs::File::from(fd), path)),
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

/// Write `json.dumps(value, indent=2) + "\n"` to a private temporary file in
/// the destination directory, fsync it, and atomically rename it into place.
pub fn write_state(path: &Path, value: &Value) -> io::Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let (file, temporary) = named_temporary(parent, ".state-")?;
    let mut text = crate::pyjson::dumps_pretty(value);
    text.push('\n');
    let written = sys::write_all(file.as_raw_fd(), text.as_bytes()).and_then(|_| sys::fsync(file.as_raw_fd()));
    drop(file);
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    let renamed = std::fs::rename(&temporary, path);
    if renamed.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    renamed
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn writes_private_pretty_json_atomically() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.json");
        std::fs::write(&path, "old").unwrap();
        write_state(&path, &json!({"schema_version": 1, "path": "/tmp/é", "values": [1, 2]})).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(),
            "{\n  \"schema_version\": 1,\n  \"path\": \"/tmp/\\u00e9\",\n  \"values\": [\n    1,\n    2\n  ]\n}\n");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
        assert!(write_state(&temp.path().join("missing/state.json"), &json!({})).is_err());
    }
}
