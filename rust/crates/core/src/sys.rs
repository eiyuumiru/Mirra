//! Thin libc wrappers for descriptor-relative filesystem operations
//! (Python's `dir_fd=` / `follow_symlinks=False` calls) and process info.
use std::ffi::{CStr, CString, OsStr, OsString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

pub fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

pub fn set_errno(value: i32) {
    unsafe { *libc::__error() = value };
}

pub fn strerror(errno: i32) -> String {
    unsafe {
        let text = libc::strerror(errno);
        if text.is_null() {
            return format!("Unknown error {}", errno);
        }
        CStr::from_ptr(text).to_string_lossy().into_owned()
    }
}

pub fn getuid() -> u32 {
    unsafe { libc::getuid() }
}

pub fn cstring(value: impl AsRef<OsStr>) -> io::Result<CString> {
    CString::new(value.as_ref().as_bytes()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

fn check(result: libc::c_int) -> io::Result<libc::c_int> {
    if result < 0 { Err(io::Error::last_os_error()) } else { Ok(result) }
}

fn retry<F: FnMut() -> libc::c_int>(mut call: F) -> io::Result<libc::c_int> {
    loop {
        let result = call();
        if result >= 0 {
            return Ok(result);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error);
        }
    }
}

pub fn open(path: &Path, flags: libc::c_int, mode: libc::mode_t) -> io::Result<OwnedFd> {
    let name = cstring(path)?;
    let fd = retry(|| unsafe { libc::open(name.as_ptr(), flags | libc::O_CLOEXEC, mode as libc::c_uint) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn openat(dir: RawFd, name: impl AsRef<OsStr>, flags: libc::c_int, mode: libc::mode_t) -> io::Result<OwnedFd> {
    let name = cstring(name)?;
    let fd = retry(|| unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC, mode as libc::c_uint) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    let mut info: libc::stat = unsafe { std::mem::zeroed() };
    check(unsafe { libc::fstat(fd, &mut info) })?;
    Ok(info)
}

/// `os.stat(name, dir_fd=dir, follow_symlinks=False)`
pub fn lstatat(dir: RawFd, name: impl AsRef<OsStr>) -> io::Result<libc::stat> {
    let name = cstring(name)?;
    let mut info: libc::stat = unsafe { std::mem::zeroed() };
    check(unsafe { libc::fstatat(dir, name.as_ptr(), &mut info, libc::AT_SYMLINK_NOFOLLOW) })?;
    Ok(info)
}

pub fn lstat(path: &Path) -> io::Result<libc::stat> {
    let name = cstring(path)?;
    let mut info: libc::stat = unsafe { std::mem::zeroed() };
    check(unsafe { libc::lstat(name.as_ptr(), &mut info) })?;
    Ok(info)
}

pub fn stat(path: &Path) -> io::Result<libc::stat> {
    let name = cstring(path)?;
    let mut info: libc::stat = unsafe { std::mem::zeroed() };
    check(unsafe { libc::stat(name.as_ptr(), &mut info) })?;
    Ok(info)
}

pub fn unlinkat(dir: RawFd, name: impl AsRef<OsStr>) -> io::Result<()> {
    let name = cstring(name)?;
    check(unsafe { libc::unlinkat(dir, name.as_ptr(), 0) }).map(|_| ())
}

/// `os.link(src, dst, src_dir_fd=dir, dst_dir_fd=dir, follow_symlinks=False)`
pub fn linkat(dir: RawFd, source: impl AsRef<OsStr>, target: impl AsRef<OsStr>) -> io::Result<()> {
    let source = cstring(source)?;
    let target = cstring(target)?;
    check(unsafe { libc::linkat(dir, source.as_ptr(), dir, target.as_ptr(), 0) }).map(|_| ())
}

pub fn dup(fd: RawFd) -> io::Result<OwnedFd> {
    let copy = check(unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(copy) })
}

/// `os.listdir(fd)`: names in an open directory, excluding `.` and `..`.
pub fn list_dir_fd(fd: RawFd) -> io::Result<Vec<OsString>> {
    let copy = dup(fd)?;
    let raw = copy.as_raw_fd();
    let dir = unsafe { libc::fdopendir(raw) };
    if dir.is_null() {
        return Err(io::Error::last_os_error());
    }
    std::mem::forget(copy); // closedir owns it now
    let mut names = Vec::new();
    unsafe { libc::rewinddir(dir) };
    let result = loop {
        set_errno(0);
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            let error = errno();
            break if error == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(error)) };
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(OsString::from_vec(name.to_vec()));
        }
    };
    unsafe { libc::closedir(dir) };
    result.map(|_| names)
}

pub fn pread(fd: RawFd, count: usize, offset: u64) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; count];
    let read = loop {
        let n = unsafe { libc::pread(fd, buffer.as_mut_ptr().cast(), count, offset as libc::off_t) };
        if n >= 0 {
            break n as usize;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error);
        }
    };
    buffer.truncate(read);
    Ok(buffer)
}

/// One `os.write` call; returns the number of bytes written.
pub fn write(fd: RawFd, data: &[u8]) -> io::Result<usize> {
    loop {
        let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error);
        }
    }
}

pub fn write_all(fd: RawFd, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        let n = write(fd, data)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "failed to write whole buffer"));
        }
        data = &data[n..];
    }
    Ok(())
}

pub fn ftruncate(fd: RawFd, size: u64) -> io::Result<()> {
    retry(|| unsafe { libc::ftruncate(fd, size as libc::off_t) }).map(|_| ())
}

pub fn flock(fd: RawFd, operation: libc::c_int) -> io::Result<()> {
    retry(|| unsafe { libc::flock(fd, operation) }).map(|_| ())
}

pub fn fsync(fd: RawFd) -> io::Result<()> {
    retry(|| unsafe { libc::fsync(fd) }).map(|_| ())
}

pub fn fcntl_getfl(fd: RawFd) -> io::Result<libc::c_int> {
    check(unsafe { libc::fcntl(fd, libc::F_GETFL) })
}

pub fn is_dir(mode: libc::mode_t) -> bool {
    mode & libc::S_IFMT == libc::S_IFDIR
}
pub fn is_reg(mode: libc::mode_t) -> bool {
    mode & libc::S_IFMT == libc::S_IFREG
}
pub fn is_lnk(mode: libc::mode_t) -> bool {
    mode & libc::S_IFMT == libc::S_IFLNK
}
pub fn is_sock(mode: libc::mode_t) -> bool {
    mode & libc::S_IFMT == libc::S_IFSOCK
}

/// Regular file/directory owned by this user without group/other bits.
pub fn private_owned(info: &libc::stat, directory: bool) -> bool {
    let kind = if directory { is_dir(info.st_mode) } else { is_reg(info.st_mode) };
    kind && info.st_uid == getuid() && info.st_mode & 0o077 == 0
}

/// Seconds since the epoch as Python's `st_mtime` float.
pub fn mtime(info: &libc::stat) -> f64 {
    info.st_mtime as f64 + info.st_mtime_nsec as f64 / 1e9
}

/// Uniform random integer in `0..bound` from the system CSPRNG.
pub fn random_below(bound: u32) -> u32 {
    unsafe { libc::arc4random_uniform(bound) }
}
