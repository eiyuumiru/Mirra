//! `pathlib` semantics: `expanduser`, `absolute`, and non-strict `resolve`.
use std::collections::HashMap;
use std::ffi::{CStr, OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

fn bytes(path: &Path) -> &[u8] {
    path.as_os_str().as_bytes()
}

fn from_bytes(value: Vec<u8>) -> PathBuf {
    PathBuf::from(OsString::from_vec(value))
}

fn home_of(user: Option<&[u8]>) -> Option<Vec<u8>> {
    unsafe {
        let entry = match user {
            None => {
                if let Some(home) = std::env::var_os("HOME") {
                    return Some(home.into_vec());
                }
                libc::getpwuid(libc::getuid())
            }
            Some(name) => {
                let name = std::ffi::CString::new(name).ok()?;
                libc::getpwnam(name.as_ptr())
            }
        };
        if entry.is_null() || (*entry).pw_dir.is_null() {
            return None;
        }
        Some(CStr::from_ptr((*entry).pw_dir).to_bytes().to_vec())
    }
}

/// `Path.expanduser()`.
pub fn expanduser(path: &Path) -> PathBuf {
    let raw = bytes(path);
    if !raw.starts_with(b"~") {
        return path.to_path_buf();
    }
    let end = raw.iter().position(|b| *b == b'/').unwrap_or(raw.len());
    let user = if end == 1 { None } else { Some(&raw[1..end]) };
    let Some(mut home) = home_of(user) else { return path.to_path_buf() };
    while home.len() > 1 && home.ends_with(b"/") {
        home.pop();
    }
    if home == b"/" && end < raw.len() {
        home.clear();
    }
    let mut value = home;
    value.extend_from_slice(&raw[end..]);
    if value.is_empty() {
        value.push(b'/');
    }
    normalize(&from_bytes(value))
}

/// `PurePath` normalization: collapse `//` and drop `.` components.
pub fn normalize(path: &Path) -> PathBuf {
    let raw = bytes(path);
    let absolute = raw.starts_with(b"/");
    let parts: Vec<&[u8]> = raw.split(|b| *b == b'/').filter(|p| !p.is_empty() && *p != b".").collect();
    let mut value = Vec::new();
    if absolute {
        value.push(b'/');
    }
    value.extend_from_slice(&parts.join(&b'/'));
    if value.is_empty() {
        value.push(b'.');
    }
    from_bytes(value)
}

/// `Path.absolute()`: prefix the working directory, no symlink resolution.
pub fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        normalize(path)
    } else {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        if bytes(&normalize(path)) == b"." {
            return cwd;
        }
        normalize(&cwd.join(path))
    }
}

fn join(base: &[u8], name: &[u8]) -> Vec<u8> {
    if name.starts_with(b"/") {
        return name.to_vec();
    }
    let mut value = base.to_vec();
    if !(value.is_empty() || value.ends_with(b"/")) {
        value.push(b'/');
    }
    value.extend_from_slice(name);
    value
}

fn split(path: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let i = path.iter().rposition(|b| *b == b'/').map(|i| i + 1).unwrap_or(0);
    let (mut head, tail) = (path[..i].to_vec(), path[i..].to_vec());
    if !head.is_empty() && head.iter().any(|b| *b != b'/') {
        while head.ends_with(b"/") {
            head.pop();
        }
    }
    (head, tail)
}

// posixpath._joinrealpath (non-strict)
fn join_realpath(mut path: Vec<u8>, rest: &[u8], seen: &mut HashMap<Vec<u8>, Option<Vec<u8>>>) -> (Vec<u8>, bool) {
    let mut rest: &[u8] = rest;
    if rest.starts_with(b"/") {
        rest = &rest[1..];
        path = b"/".to_vec();
    }
    while !rest.is_empty() {
        let (name, remaining) = match rest.iter().position(|b| *b == b'/') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, &b""[..]),
        };
        rest = remaining;
        if name.is_empty() || name == b"." {
            continue;
        }
        if name == b".." {
            if !path.is_empty() {
                let (head, tail) = split(&path);
                path = head;
                if tail == b".." {
                    path = join(&join(&path, b".."), b"..");
                }
            } else {
                path = b"..".to_vec();
            }
            continue;
        }
        let newpath = join(&path, name);
        let is_link = crate::sys::lstat(Path::new(OsStr::from_bytes(&newpath)))
            .map(|info| crate::sys::is_lnk(info.st_mode))
            .unwrap_or(false);
        if !is_link {
            path = newpath;
            continue;
        }
        if let Some(known) = seen.get(&newpath) {
            match known {
                Some(resolved) => {
                    path = resolved.clone();
                    continue;
                }
                None => return (join(&newpath, rest), false),
            }
        }
        seen.insert(newpath.clone(), None);
        let target = match std::fs::read_link(OsStr::from_bytes(&newpath)) {
            Ok(target) => target.into_os_string().into_vec(),
            Err(_) => {
                path = newpath;
                continue;
            }
        };
        let (resolved, ok) = join_realpath(path, &target, seen);
        if !ok {
            return (join(&resolved, rest), false);
        }
        seen.insert(newpath, Some(resolved.clone()));
        path = resolved;
    }
    (path, true)
}

/// `Path.resolve()` (non-strict): absolute, symlinks of existing parts resolved.
pub fn resolve(path: &Path) -> PathBuf {
    let absolute = absolute(path);
    let (value, _) = join_realpath(Vec::new(), bytes(&absolute), &mut HashMap::new());
    if value.is_empty() {
        return PathBuf::from("/");
    }
    from_bytes(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_links_and_missing_parts() {
        let temp = tempfile::tempdir().unwrap();
        let real = std::fs::canonicalize(temp.path()).unwrap();
        std::os::unix::fs::symlink(real.join("target"), real.join("link")).unwrap();
        std::fs::create_dir(real.join("target")).unwrap();
        assert_eq!(resolve(&temp.path().join("link/missing/../x")), real.join("target/x"));
        assert_eq!(resolve(Path::new("/tmp")), PathBuf::from("/private/tmp"));
        assert_eq!(normalize(Path::new("a//./b/")), PathBuf::from("a/b"));
    }
}
