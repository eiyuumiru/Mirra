//! Dated app logs and seven-day retention, limited to Mirra's log filenames.
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::LazyLock;

use chrono::{DateTime, Local, NaiveDate, TimeDelta};
use regex::Regex;
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::sys;

pub const RETENTION_DAYS: i64 = 7;
pub const SOURCES: [&str; 4] = ["app", "setup", "control", "native"];
pub static MANAGED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A(app|setup|control|native)(?:-(\d{4}-\d{2}-\d{2}))?\.log(?:\.1)?\z").unwrap()
});

/// `date.today()` (local time).
pub fn today() -> NaiveDate {
    Local::now().date_naive()
}

/// Local calendar date of a POSIX timestamp (`datetime.fromtimestamp(t).date()`).
pub fn local_day(timestamp: f64) -> Option<NaiveDate> {
    let seconds = timestamp.floor();
    let nanos = ((timestamp - seconds) * 1e9) as u32;
    DateTime::from_timestamp(seconds as i64, nanos.min(999_999_999)).map(|t| t.with_timezone(&Local).date_naive())
}

/// `setup.log` → `setup-YYYY-MM-DD.log` for the managed sources; other names unchanged.
pub fn dated_name(name: &str, day: NaiveDate) -> String {
    match name.strip_suffix(".log") {
        Some(source) if SOURCES.contains(&source) => format!("{}-{}.log", source, day.format("%Y-%m-%d")),
        _ => name.to_string(),
    }
}

pub fn file_day(name: &str, info: &libc::stat) -> Option<NaiveDate> {
    let captures = MANAGED.captures(name)?;
    match captures.get(2) {
        Some(day) => NaiveDate::parse_from_str(day.as_str(), "%Y-%m-%d").ok().filter(|_| day.as_str().is_ascii()),
        None => local_day(sys::mtime(info)),
    }
}

/// Unlink expired, private regular logs relative to an open directory.
pub fn prune(folder: RawFd, today: NaiveDate) -> Result<Vec<String>> {
    let cutoff = today - TimeDelta::days(RETENTION_DAYS);
    let mut removed = Vec::new();
    for name in sys::list_dir_fd(folder)? {
        let Some(name) = name.to_str().map(str::to_string) else { continue };
        if !MANAGED.is_match(&name) {
            continue;
        }
        let step = (|| -> std::io::Result<()> {
            let info = sys::lstatat(folder, &name)?;
            if !sys::private_owned(&info, false) {
                return Ok(());
            }
            if let Some(day) = file_day(&name, &info) {
                if day <= cutoff {
                    sys::unlinkat(folder, &name)?;
                    removed.push(name.clone());
                }
            }
            Ok(())
        })();
        match step {
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
            other => other?,
        }
    }
    Ok(removed)
}

/// Preserve old undated logs under their last recording date; never overwrite.
/// Returns `[{"from": name, "to": dated}]`.
pub fn migrate_legacy_fd(base: RawFd) -> Result<Vec<Value>> {
    let folder = sys::dup(base)?;
    migrate(&folder)
}

pub fn migrate_legacy(base: &Path) -> Result<Vec<Value>> {
    let folder = sys::open(base, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW, 0).map_err(|e| Error::with_path(e, base))?;
    migrate(&folder)
}

fn migrate(folder: &OwnedFd) -> Result<Vec<Value>> {
    let fd = folder.as_raw_fd();
    let info = sys::fstat(fd)?;
    if info.st_uid != sys::getuid() || info.st_mode & 0o077 != 0 {
        return Err(Error::value("Log directory must be private"));
    }
    let mut renamed = Vec::new();
    for source in SOURCES {
        for suffix in ["", ".1"] {
            let name = format!("{}.log{}", source, suffix);
            let step = (|| -> std::io::Result<Option<String>> {
                let info = sys::lstatat(fd, &name)?;
                if !sys::private_owned(&info, false) {
                    return Ok(None);
                }
                let day = local_day(sys::mtime(&info)).unwrap_or_else(today);
                let target = dated_name(&format!("{}.log", source), day) + suffix;
                // link/unlink preserves the inode for a writer that is finishing,
                // and fails if the dated destination already exists.
                sys::linkat(fd, &name, &target)?;
                sys::unlinkat(fd, &name)?;
                Ok(Some(target))
            })();
            match step {
                Ok(Some(target)) => renamed.push(json!({"from": name, "to": target})),
                Ok(None) => {}
                Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT) | Some(libc::EEXIST)) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    Ok(renamed)
}
